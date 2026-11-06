//! Durable public-evidence repair ports. Adapters own acquisition and publication.
use async_trait::async_trait;
use devres_domain::{Result, attribution::*};
use serde_json::Value;

#[async_trait]
pub trait AttributionStore: Send + Sync {
    async fn attribution_enqueue(&self, target: &AttributionTarget, priority: u8) -> Result<()>;
    async fn attribution_ready(
        &self,
        subject: &AttributionSubject,
    ) -> Result<Option<QualifiedAttribution>>;
    async fn attribution_claim(
        &self,
        enabled: &[String],
        now: i64,
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
    /// Atomically queues a bounded source page and advances its durable cutoff/cursor.
    async fn attribution_sweep_page(&self, provider: &str) -> Result<Vec<AttributionTarget>>;
    async fn attribution_bundle(&self, id: &str) -> Result<QualifiedAttribution>;
    async fn attribution_status(&self) -> Result<Value>;
}
