//! Running-service attribution policy. Source adapters supply evidence, never policy.
use crate::attribution::AttributionStore;
use crate::attribution_gate::AttributionGate;
use async_trait::async_trait;
use devres_domain::{Error, Result, attribution::*};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};
use tokio::sync::{Mutex, Notify};
use tokio_util::sync::CancellationToken;

/// Implemented by trusted source adapters. No caller URL is an acquisition recipe.
#[async_trait]
pub trait AttributionAcquirer: Send + Sync {
    fn targets(&self, provider: &str, value: &Value) -> Result<Vec<AttributionTarget>>;
    async fn repair(
        &self,
        target: &AttributionTarget,
        cancel: CancellationToken,
    ) -> Result<AttributionGeneration>;
    /// Current source visibility is independent of immutable qualification.
    async fn ensure_public(&self, _subject: &AttributionSubject) -> Result<()> {
        Ok(())
    }
}

pub const ATTRIBUTION_PROVIDERS: [&str; 9] = [
    "rfc",
    "crates",
    "rustsec",
    "mdn",
    "whatwg",
    "w3c",
    "chromium",
    "npm",
    "wikipedia",
];

/// A single supervised repair lane bounds work; SQL claims coalesce readers/sweeps.
pub struct AttributionRuntime {
    store: Arc<dyn AttributionStore>,
    acquirer: Arc<dyn AttributionAcquirer>,
    enabled: Vec<String>,
    wake: Notify,
    sweep_gaps: Mutex<BTreeMap<String, String>>,
    admission_gap: Mutex<Option<AttributionFailure>>,
    delegate: Option<Arc<dyn crate::acquisition::AcquisitionDelegate>>,
}
impl AttributionRuntime {
    pub fn new(
        store: Arc<dyn AttributionStore>,
        acquirer: Arc<dyn AttributionAcquirer>,
        enabled: Vec<String>,
    ) -> Result<Self> {
        if enabled
            .iter()
            .any(|p| !ATTRIBUTION_PROVIDERS.contains(&p.as_str()))
        {
            return Err(Error::invalid("Unknown attribution provider."));
        }
        Ok(Self {
            store,
            acquirer,
            enabled,
            wake: Notify::new(),
            sweep_gaps: Mutex::new(BTreeMap::new()),
            admission_gap: Mutex::new(None),
            delegate: None,
        })
    }

    pub fn with_delegate(
        mut self,
        delegate: Arc<dyn crate::acquisition::AcquisitionDelegate>,
    ) -> Self {
        self.delegate = Some(delegate);
        self
    }
    pub async fn enqueue_public(&self, target: &AttributionTarget) -> Result<()> {
        if !ATTRIBUTION_PROVIDERS.contains(&target.subject.provider.as_str()) {
            return Err(Error::invalid("Unknown attribution provider."));
        }
        self.store.attribution_enqueue(target, 1).await?;
        self.wake.notify_one();
        Ok(())
    }
    pub async fn run(&self, cancel: CancellationToken) -> Result<()> {
        let mut provider = 0;
        let mut admission = 0_u64;
        loop {
            // Poll one bounded page per turn, including disabled sources: enumeration
            // is local and never grants permission to acquire their evidence.
            tokio::select! {
                biased;
                _ = cancel.cancelled() => return Ok(()),
                result = self.store.attribution_sweep_page(ATTRIBUTION_PROVIDERS[provider]) => {
                    match result {
                        Ok(_) => {self.sweep_gaps.lock().await.remove(ATTRIBUTION_PROVIDERS[provider]);},
                        Err(error) if error.code == "capacity" => {
                            self.sweep_gaps.lock().await.insert(ATTRIBUTION_PROVIDERS[provider].into(), "capacity".into());
                        },
                        Err(error) => return Err(error),
                    }
                }
            }
            provider = (provider + 1) % ATTRIBUTION_PROVIDERS.len();
            let claim_started = std::time::Instant::now();
            let claim = tokio::select! {
                biased;
                _ = cancel.cancelled() => return Ok(()),
                result = self.store.attribution_claim(&self.enabled, devres_domain::unix_now(), admission) => result,
            };
            tracing::debug!(
                target: "devres_private_timings",
                attribution_stage = "claim",
                elapsed_micros = u64::try_from(claim_started.elapsed().as_micros()).unwrap_or(u64::MAX),
                success = claim.is_ok(),
                "attribution operation"
            );
            let job = match claim {
                Ok(job) => {
                    *self.admission_gap.lock().await = None;
                    job
                }
                Err(error) if error.code == "capacity" => {
                    *self.admission_gap.lock().await = Some(AttributionFailure::new(
                        AttributionPhase::Scheduling,
                        AttributionFailureReason::AdmissionDeferred,
                        AttributionDisposition::Retry,
                    ));
                    tokio::select! {
                        biased;
                        _ = cancel.cancelled() => return Ok(()),
                        _ = tokio::time::sleep(Duration::from_secs(1)) => {},
                    }
                    continue;
                }
                Err(error) => return Err(error),
            };
            if let Some(job) = job {
                let repair_started = std::time::Instant::now();
                admission = admission.wrapping_add(1);
                let acquisition_cancel = cancel.child_token();
                let acquisition = self
                    .acquirer
                    .repair(&job.target, acquisition_cancel.clone());
                tokio::pin!(acquisition);
                let result = tokio::select! {
                    biased;
                    _ = cancel.cancelled() => {
                        acquisition_cancel.cancel();
                        let _ = acquisition.await;
                        self.store.attribution_fail_classified(&job, Some(devres_domain::unix_now()), "cancelled", &AttributionFailure::new(
                            AttributionPhase::Acquisition, AttributionFailureReason::Cancelled, AttributionDisposition::Cancelled,
                        )).await?;
                        return Ok(());
                    },
                    _ = tokio::time::sleep(Duration::from_secs(240)) => {
                        acquisition_cancel.cancel();
                        let _ = acquisition.await;
                        Err(Error::unavailable("Attribution repair deadline exceeded."))
                    },
                    result = &mut acquisition => result,
                };
                // Only a fixed provider label and outcome are observable. Never
                // attach subject keys, source evidence or request/audit inputs.
                let provider = ATTRIBUTION_PROVIDERS
                    .iter()
                    .copied()
                    .find(|provider| *provider == job.target.subject.provider)
                    .unwrap_or("unknown");
                tracing::debug!(
                    target: "devres_private_timings",
                    attribution_stage = "acquisition",
                    provider,
                    elapsed_micros = u64::try_from(repair_started.elapsed().as_micros()).unwrap_or(u64::MAX),
                    success = result.is_ok(),
                    "attribution operation"
                );
                match result {
                    Ok(generation) => {
                        if generation.subject != job.target.subject
                            || generation.policy_epoch != ATTRIBUTION_POLICY_EPOCH
                            || generation.policy_fingerprint != ATTRIBUTION_POLICY_FINGERPRINT
                            || generation.notices.is_empty()
                            || generation.receipts.is_empty()
                        {
                            return Err(Error::integrity(
                                "Attribution acquisition identity mismatch.",
                            ));
                        }
                        let completion = self.store.attribution_complete(&job, &generation).await;
                        tracing::debug!(
                            target: "devres_private_timings",
                            attribution_stage = "completion",
                            provider,
                            elapsed_micros = u64::try_from(repair_started.elapsed().as_micros()).unwrap_or(u64::MAX),
                            success = completion.is_ok(),
                            "attribution operation"
                        );
                        match completion {
                            Ok(()) => {}
                            Err(error) if error.code == "capacity" => {
                                self.store
                                    .attribution_fail_classified(
                                        &job,
                                        None,
                                        "capacity",
                                        &AttributionFailure::new(
                                            AttributionPhase::Publication,
                                            AttributionFailureReason::PayloadBound,
                                            AttributionDisposition::Blocked,
                                        ),
                                    )
                                    .await?;
                            }
                            Err(error) if error.code == "unavailable" => {
                                // A canonical alias may still have a fenced lease
                                // from the previous owner. Preserve this job and
                                // retry after that lease rather than stopping serving.
                                self.store
                                    .attribution_fail_classified(
                                        &job,
                                        Some(devres_domain::unix_now().saturating_add(300)),
                                        "publication_deferred",
                                        &AttributionFailure::new(
                                            AttributionPhase::Publication,
                                            AttributionFailureReason::PublicationDeferred,
                                            AttributionDisposition::Retry,
                                        ),
                                    )
                                    .await?;
                            }
                            Err(error) => return Err(error),
                        }
                    }
                    Err(error) => {
                        let classification = repair_failure(&error);
                        // HTTP attempts remain owned by source I/O; durable retries
                        // survive outages without reclassifying deterministic gaps.
                        let retry = (classification.disposition != AttributionDisposition::Blocked)
                            .then(|| {
                                devres_domain::unix_now().saturating_add(
                                    60_i64.saturating_mul(1_i64 << job.attempts.min(10)),
                                )
                            });
                        let code = if error.code == "integrity" {
                            "integrity"
                        } else if retry.is_some() {
                            "retryable"
                        } else {
                            "blocked"
                        };
                        self.store
                            .attribution_fail_classified(&job, retry, code, &classification)
                            .await?;
                    }
                }
            }
            tokio::select! {
                biased;
                _ = cancel.cancelled() => return Ok(()),
                _ = self.wake.notified() => {},
                _ = tokio::time::sleep(Duration::from_secs(1)) => {},
            }
        }
    }
}

fn repair_failure(error: &Error) -> AttributionFailure {
    if let Some(classification) = AttributionFailure::from_error(error) {
        return classification;
    }
    let (reason, disposition) = match error.code.as_str() {
        "unavailable" => (
            AttributionFailureReason::Unclassified,
            AttributionDisposition::Retry,
        ),
        "capacity" => (
            AttributionFailureReason::Unclassified,
            AttributionDisposition::Retry,
        ),
        "not_found" => (
            AttributionFailureReason::SourceGone,
            AttributionDisposition::Blocked,
        ),
        "integrity" | "invalid_input" => (
            AttributionFailureReason::InvalidEvidence,
            AttributionDisposition::Blocked,
        ),
        "cancelled" => (
            AttributionFailureReason::Cancelled,
            AttributionDisposition::Cancelled,
        ),
        _ => (
            AttributionFailureReason::Unclassified,
            AttributionDisposition::Blocked,
        ),
    };
    AttributionFailure::new(AttributionPhase::Acquisition, reason, disposition)
}

fn current(value: &QualifiedAttribution, subject: &AttributionSubject) -> bool {
    value.generation.subject == *subject
        && value.generation.policy_epoch == ATTRIBUTION_POLICY_EPOCH
        && value.generation.policy_fingerprint == ATTRIBUTION_POLICY_FINGERPRINT
        && !value.generation.notices.is_empty()
        && !value.generation.receipts.is_empty()
}
fn readable(generations: &[QualifiedAttribution]) -> Result<String> {
    let mut seen = BTreeSet::new();
    let mut text = String::new();
    for generation in generations {
        for notice in &generation.generation.notices {
            let entry = format!("{}\n{}", notice.source_url, notice.text);
            if seen.insert(entry.clone()) {
                if text.len().saturating_add(entry.len()).saturating_add(2) > 4 * 1024 * 1024 {
                    return Err(Error::capacity(
                        "Required attribution exceeds its output bound.",
                    ));
                }
                if !text.is_empty() {
                    text.push_str("\n\n");
                }
                text.push_str(&entry);
            }
        }
    }
    Ok(text)
}

#[async_trait]
impl AttributionGate for AttributionRuntime {
    async fn qualify(&self, provider: &str, value: &Value) -> Result<Value> {
        let audit = provider.starts_with("audit:");
        let provider = provider.strip_prefix("audit:").unwrap_or(provider);
        let provider = match provider {
            "crate" => "crates",
            "advisory" => "rustsec",
            p => p,
        };
        let targets = self.acquirer.targets(provider, value)?;
        if targets.is_empty() {
            return Err(Error::unavailable(
                "Attribution evidence is unavailable for this content.",
            ));
        }
        if targets.len() > 128 {
            return Err(Error::capacity("Attribution subject bound exceeded."));
        }
        let mut generations = Vec::with_capacity(targets.len());
        let mut pending = false;
        let mut subjects = Vec::new();
        let mut seen = BTreeSet::new();
        for target in targets {
            let identity = serde_json::to_string(&target.subject)
                .map_err(|_| Error::integrity("Invalid attribution subject."))?;
            if !seen.insert(identity) {
                continue;
            }
            self.acquirer.ensure_public(&target.subject).await?;
            match self.store.attribution_ready(&target.subject).await? {
                Some(generation) if current(&generation, &target.subject) => {
                    self.acquirer.ensure_public(&target.subject).await?;
                    generations.push(generation)
                }
                _ => {
                    subjects.push(target.subject.clone());
                    // The compiler never receives request-only audit input. Audits
                    // must pass public snapshot evidence and cannot schedule repairs.
                    if !audit {
                        if let Some(delegate) = &self.delegate {
                            delegate
                                .effect(crate::acquisition::WriterEffect::AttributionEnqueue {
                                    target,
                                })
                                .await?;
                        } else {
                            self.store.attribution_enqueue(&target, 1).await?;
                        }
                    }
                    pending = true;
                }
            }
        }
        if pending {
            self.wake.notify_one();
            return Err(
                Error::unavailable("Required attribution repair is pending or blocked.")
                    .with_details(json!({"attribution_status":"unavailable","subjects":subjects})),
            );
        }
        let notice = readable(&generations)?;
        let uris: Vec<_> = generations
            .iter()
            .map(|g| format!("devres://attribution/{}", g.id))
            .collect();
        for generation in &generations {
            self.acquirer
                .ensure_public(&generation.generation.subject)
                .await?;
        }
        Ok(
            json!({"status":"ready","policy_epoch":ATTRIBUTION_POLICY_EPOCH,
            "policy_fingerprint":ATTRIBUTION_POLICY_FINGERPRINT,
            "readable_notice":notice,"resource_uri":uris.first(),
            "resource_uris":uris,"generations":generations.iter().map(public_generation).collect::<Vec<_>>()}),
        )
    }
    async fn bundle(&self, id: &str, offset: usize, limit: usize) -> Result<Value> {
        if !devres_domain::valid_content_id(id) || limit == 0 || limit > 65536 {
            return Err(Error::invalid("Invalid attribution resource page."));
        }
        let generation = self.store.attribution_bundle(id).await?;
        self.acquirer
            .ensure_public(&generation.generation.subject)
            .await?;
        // Historical notice URIs are immutable evidence. They remain readable
        // under a registered policy even when that policy no longer qualifies
        // copied research content. Storage verifies the sealed generation.
        if generation.id != id
            || !ATTRIBUTION_POLICY_MANIFESTS.iter().any(|policy| {
                policy.epoch == generation.generation.policy_epoch
                    && policy.fingerprint == generation.generation.policy_fingerprint
            })
            || generation.generation.notices.is_empty()
            || generation.generation.receipts.is_empty()
        {
            return Err(Error::unavailable("Attribution policy is unsupported."));
        }
        let text = readable(std::slice::from_ref(&generation))?;
        if offset > text.len() || !text.is_char_boundary(offset) {
            return Err(Error::invalid("Invalid attribution byte offset."));
        }
        let mut end = offset.saturating_add(limit).min(text.len());
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        if end == offset && offset < text.len() {
            return Err(Error::invalid(
                "Attribution page limit cannot contain the next UTF-8 character.",
            ));
        }
        self.acquirer
            .ensure_public(&generation.generation.subject)
            .await?;
        Ok(
            json!({"contents":[{"uri":format!("devres://attribution/{id}"),
            "mimeType":"text/plain","text":&text[offset..end],
            "_meta":{"attribution":{"id":generation.id,"subject":generation.generation.subject,
                "policy_epoch":generation.generation.policy_epoch},"offset":offset,"total_bytes":text.len(),
                "next_offset":if end<text.len(){Some(end)}else{None}}}]}),
        )
    }
    async fn status(&self) -> Result<Value> {
        if let Some(delegate) = &self.delegate {
            return delegate.attribution_status().await;
        }
        let mut status = self.store.attribution_status().await?;
        status["enabled_providers"] = json!(self.enabled);
        status["policy_epoch"] = json!(ATTRIBUTION_POLICY_EPOCH);
        status["disabled_providers"] = json!(
            ATTRIBUTION_PROVIDERS
                .iter()
                .filter(|p| !self.enabled.iter().any(|e| e == **p))
                .collect::<Vec<_>>()
        );
        let admission_gap = *self.admission_gap.lock().await;
        status["admission_gap"] = json!(admission_gap);
        let gaps = self.sweep_gaps.lock().await;
        status["scan_gaps"] = json!(*gaps);
        if !gaps.is_empty() || admission_gap.is_some() {
            status["complete"] = json!(false);
            status["repair_complete_for_enqueued_targets"] = json!(false);
        }
        Ok(status)
    }
}

fn public_generation(value: &QualifiedAttribution) -> Value {
    json!({"id":value.id,"subject":value.generation.subject,
        "notices":value.generation.notices.iter().map(|notice| json!({
            "source_url":notice.source_url,"license":notice.license,
            "copyright":notice.copyright,"text":notice.text})).collect::<Vec<_>>()})
}

#[cfg(test)]
#[path = "attribution_runtime_tests.rs"]
mod tests;
