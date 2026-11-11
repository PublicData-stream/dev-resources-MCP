//! Source admission bridge for application-owned attribution repair policy.
use async_trait::async_trait;
use devres_application::attribution::AttributionStore;
use devres_application::attribution_runtime::AttributionAcquirer;
use devres_domain::{Result, attribution::*};
use serde_json::Value;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

pub struct AttributionAdapter {
    broker: Arc<crate::bulk::BulkBroker>,
    store: Arc<dyn AttributionStore>,
    wikipedia: Option<Arc<dyn devres_application::wikipedia::WikipediaStore>>,
}
impl AttributionAdapter {
    pub fn new(broker: Arc<crate::bulk::BulkBroker>, store: Arc<dyn AttributionStore>) -> Self {
        Self {
            broker,
            store,
            wikipedia: None,
        }
    }
    pub fn with_wikipedia(
        mut self,
        store: Arc<dyn devres_application::wikipedia::WikipediaStore>,
    ) -> Self {
        self.wikipedia = Some(store);
        self
    }
    fn repair_source<'a>(
        &'a self,
        target: &'a AttributionTarget,
        cancel: CancellationToken,
        depth: usize,
    ) -> futures::future::BoxFuture<'a, Result<AttributionGeneration>> {
        Box::pin(async move {
            if depth > 8 {
                return Err(devres_domain::Error::capacity(
                    "Attribution dependency depth exceeded.",
                ));
            }
            if let Some(ready) = self.store.attribution_ready(&target.subject).await? {
                return Ok(ready.generation);
            }
            if target.subject.provider == "wikipedia"
                && target.evidence.get("dependencies").is_none()
            {
                return crate::wikipedia::attribution::repair(
                    self.wikipedia.as_deref().ok_or_else(|| {
                        devres_domain::Error::unavailable(
                            "Wikipedia attribution store unavailable.",
                        )
                    })?,
                    target,
                    cancel,
                )
                .await;
            }
            let Some(dependencies) = target
                .evidence
                .get("dependencies")
                .and_then(Value::as_array)
            else {
                return crate::attribution_providers::repair(target, &self.broker, cancel).await;
            };
            if dependencies.is_empty() || dependencies.len() > 128 {
                return Err(devres_domain::Error::capacity(
                    "Attribution dependency bound exceeded.",
                ));
            }
            let mut generation = AttributionGeneration {
                subject: target.subject.clone(),
                policy_epoch: ATTRIBUTION_POLICY_EPOCH,
                policy_fingerprint: ATTRIBUTION_POLICY_FINGERPRINT.into(),
                notices: Vec::new(),
                receipts: Vec::new(),
            };
            let mut charge = 0_usize;
            for dependency in dependencies {
                if cancel.is_cancelled() {
                    return Err(devres_domain::Error::new(
                        "cancelled",
                        "Attribution repair cancelled.",
                    ));
                }
                let child: AttributionTarget =
                    serde_json::from_value(dependency.clone()).map_err(|_| {
                        devres_domain::Error::integrity("Invalid attribution dependency.")
                    })?;
                let proof = self
                    .repair_source(&child, cancel.child_token(), depth + 1)
                    .await?;
                let bytes = serde_json::to_vec(&proof)
                    .map_err(|_| devres_domain::Error::integrity("Invalid attribution proof."))?
                    .len();
                charge = charge
                    .checked_add(bytes.saturating_mul(3))
                    .filter(|n| *n <= 8 * 1024 * 1024)
                    .ok_or_else(|| {
                        devres_domain::Error::capacity("Attribution proof budget exceeded.")
                    })?;
                generation.notices.extend(proof.notices.clone());
                generation.receipts.extend(
                    proof
                        .receipts
                        .iter()
                        .filter(|receipt| receipt["kind"] != "dependency_generation")
                        .cloned(),
                );
                generation.receipts.push(serde_json::json!({"kind":"dependency_generation","target":child,"generation":proof}));
                if generation.notices.len() > 128 || generation.receipts.len() > 256 {
                    return Err(devres_domain::Error::capacity(
                        "Attribution proof count exceeded.",
                    ));
                }
            }
            Ok(generation)
        })
    }
}
#[async_trait]
impl AttributionAcquirer for AttributionAdapter {
    fn targets(&self, provider: &str, value: &Value) -> Result<Vec<AttributionTarget>> {
        crate::attribution_providers::targets(provider, value)
    }
    async fn ensure_public(&self, subject: &AttributionSubject) -> Result<()> {
        if subject.provider != "wikipedia" {
            return Ok(());
        }
        crate::wikipedia::attribution::ensure_public(
            self.wikipedia.as_deref().ok_or_else(|| {
                devres_domain::Error::unavailable("Wikipedia visibility store unavailable.")
            })?,
            subject,
        )
        .await
    }
    async fn repair(
        &self,
        target: &AttributionTarget,
        cancel: CancellationToken,
    ) -> Result<AttributionGeneration> {
        if target
            .evidence
            .get("table")
            .and_then(Value::as_str)
            .is_some()
        {
            let compiled = crate::attribution_providers::retained_target(
                ATTRIBUTION_POLICY_EPOCH,
                ATTRIBUTION_POLICY_FINGERPRINT,
                target,
            )?
            .ok_or_else(|| {
                devres_domain::Error::new(
                    "attribution_blocked",
                    "Retained attribution source mapping is incomplete.",
                )
            })?;
            let mut generation = self.repair_source(&compiled, cancel, 0).await?;
            // The original sealed occurrence stays the job identity. The compiler's
            // exact source mapping is retained in the generation's acquisition proof.
            generation
                .receipts
                .push(serde_json::json!({"kind":"retained_subject_binding",
                "source_target":compiled,"retained_subject":target.subject}));
            generation.subject = target.subject.clone();
            return Ok(generation);
        }
        self.repair_source(target, cancel, 0).await
    }
}
