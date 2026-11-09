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
}

pub const ATTRIBUTION_PROVIDERS: [&str; 8] = [
    "rfc", "crates", "rustsec", "mdn", "whatwg", "w3c", "chromium", "npm",
];

/// A single supervised repair lane bounds work; SQL claims coalesce readers/sweeps.
pub struct AttributionRuntime {
    store: Arc<dyn AttributionStore>,
    acquirer: Arc<dyn AttributionAcquirer>,
    enabled: Vec<String>,
    wake: Notify,
    sweep_gaps: Mutex<BTreeMap<String, String>>,
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
            let job = self
                .store
                .attribution_claim(&self.enabled, devres_domain::unix_now())
                .await?;
            if let Some(job) = job {
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
                        self.store.attribution_fail(&job, Some(devres_domain::unix_now()), "cancelled").await?;
                        return Ok(());
                    },
                    _ = tokio::time::sleep(Duration::from_secs(240)) => {
                        acquisition_cancel.cancel();
                        let _ = acquisition.await;
                        Err(Error::unavailable("Attribution repair deadline exceeded."))
                    },
                    result = &mut acquisition => result,
                };
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
                        match self.store.attribution_complete(&job, &generation).await {
                            Ok(()) => {}
                            Err(error) if error.code == "capacity" => {
                                self.store.attribution_fail(&job, None, "capacity").await?;
                            }
                            Err(error) if error.code == "unavailable" => {
                                // A canonical alias may still have a fenced lease
                                // from the previous owner. Preserve this job and
                                // retry after that lease rather than stopping serving.
                                self.store
                                    .attribution_fail(
                                        &job,
                                        Some(devres_domain::unix_now().saturating_add(300)),
                                        "publication_deferred",
                                    )
                                    .await?;
                            }
                            Err(error) => return Err(error),
                        }
                    }
                    Err(error) => {
                        // Source I/O owns finite HTTP retries. Supervised transient
                        // repairs remain recoverable after a long upstream outage;
                        // their durable backoff caps at 1,024 minutes.
                        let retry =
                            matches!(error.code.as_str(), "unavailable" | "capacity").then(|| {
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
                        self.store.attribution_fail(&job, retry, code).await?;
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
            match self.store.attribution_ready(&target.subject).await? {
                Some(generation) if current(&generation, &target.subject) => {
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
        if !current(&generation, &generation.generation.subject) {
            return Err(Error::unavailable("Attribution policy is obsolete."));
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
        let gaps = self.sweep_gaps.lock().await;
        status["scan_gaps"] = json!(*gaps);
        if !gaps.is_empty() {
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
