//! Public-output attribution policy shared by all MCP transports.
use async_trait::async_trait;
use devres_domain::Result;
use serde_json::Value;

/// Only public source evidence is passed to this port. Implementations must not
/// persist a request, query, audit report, or caller-to-source association.
#[async_trait]
pub trait AttributionGate: Send + Sync {
    /// Return a qualified attribution object or withhold copied content.
    /// `audit:rustsec` and `audit:npm` contain public snapshot evidence only and
    /// must never enqueue repair work based on a private audit request.
    async fn qualify(&self, provider: &str, evidence: &Value) -> Result<Value>;
    /// Read an immutable complete notice bundle using UTF-8 byte pagination.
    async fn bundle(&self, id: &str, offset: usize, limit: usize) -> Result<Value>;
    /// Aggregate operational state, without public source bodies or request data.
    async fn status(&self) -> Result<Value>;
}
