//! Public-output attribution policy shared by all MCP transports.
use async_trait::async_trait;
use devres_domain::Result;
use serde_json::Value;

/// Exact public evidence for a member of a retained RFC Editor export.
#[derive(Debug, PartialEq, Eq)]
pub struct RfcErrataMember<'a> {
    pub export_capture: &'a str,
    pub export_body: &'a str,
    pub member_body: &'a str,
    pub rfc: u32,
    pub errata_id: u64,
}

/// Only public source evidence is passed to this port. Implementations must not
/// persist a request, query, audit report, or caller-to-source association.
#[async_trait]
pub trait AttributionGate: Send + Sync {
    /// Return a qualified attribution object or withhold copied content.
    /// `audit:rustsec` and `audit:npm` contain public snapshot evidence only and
    /// must never enqueue repair work based on a private audit request.
    async fn qualify(&self, provider: &str, evidence: &Value) -> Result<Value>;
    /// Read a ready generation for this exact member if the active policy
    /// qualifies all its prose. Return the public attribution object with its
    /// readable notice and resource URI. None permits returning its official
    /// link. Serving this link needs no aggregate prose acquisition or repair.
    async fn qualify_rfc_erratum(&self, _member: &RfcErrataMember<'_>) -> Result<Option<Value>> {
        Ok(None)
    }
    /// Read an immutable complete notice bundle using UTF-8 byte pagination.
    async fn bundle(&self, id: &str, offset: usize, limit: usize) -> Result<Value>;
    /// Aggregate operational state, without public source bodies or request data.
    async fn status(&self) -> Result<Value>;
}
