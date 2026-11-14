//! Durable public-evidence repair ports. Adapters own acquisition and publication.
use async_trait::async_trait;
use devres_domain::{Result, attribution::*};
use serde_json::Value;

#[async_trait]
pub trait AttributionStore: Send + Sync {
    /// Verify a compact immutable-origin witness using local retained evidence only.
    /// Stores without that evidence must reject witnesses rather than trust references.
    async fn attribution_verify_target(&self, target: &AttributionTarget) -> Result<()> {
        if target.evidence.get("origin_witness").is_some() {
            return Err(devres_domain::Error::unavailable(
                "Attribution origin verification is unavailable.",
            ));
        }
        Ok(())
    }
    async fn attribution_enqueue(&self, target: &AttributionTarget, priority: u8) -> Result<()>;
    async fn attribution_ready(
        &self,
        subject: &AttributionSubject,
    ) -> Result<Option<QualifiedAttribution>>;
    async fn attribution_claim(
        &self,
        enabled: &[String],
        now: i64,
        admission: u64,
    ) -> Result<Option<AttributionJob>>;
    async fn attribution_complete(
        &self,
        job: &AttributionJob,
        generation: &AttributionGeneration,
    ) -> Result<()>;
    async fn attribution_fail(
        &self,
        job: &AttributionJob,
        retry_at: Option<i64>,
        code: &str,
    ) -> Result<()>;
    /// Preserve a finite cause without storing upstream messages or bodies.
    async fn attribution_fail_classified(
        &self,
        job: &AttributionJob,
        retry_at: Option<i64>,
        code: &str,
        _classification: &AttributionFailure,
    ) -> Result<()> {
        self.attribution_fail(job, retry_at, code).await
    }
    /// Atomically queues a bounded source page and advances its durable cutoff/cursor.
    async fn attribution_sweep_page(&self, provider: &str) -> Result<Vec<AttributionTarget>>;
    async fn attribution_bundle(&self, id: &str) -> Result<QualifiedAttribution>;
    async fn attribution_status(&self) -> Result<Value>;
}
