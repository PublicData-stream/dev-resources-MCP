//! Private exact retained-advisory recovery. No public tools or source requests.
use devres_domain::{Error, Result};
use serde::{Deserialize, Serialize};

#[path = "collection_recovery_diagnostics.rs"]
pub mod diagnostics;

pub const NPM_RECOVERY_RECIPE: &str = "npm-materialization-deadline-v1";
/// Immutable recipe identity; later live processors must register retained dispatch.
pub const NPM_RECOVERY_PROCESSOR_VERSION: u32 = 1;

/// Operator checkpoint evidence bound again to the exact database/archive.
/// This binding does not repeat the coordinated backup or restoration rehearsal.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryCheckpoint {
    pub version: u32,
    pub schema: i32,
    pub store_id: String,
    pub archive_epoch: i64,
    pub system_identifier: String,
    pub coordinated: bool,
    pub restoration_verified: bool,
    #[serde(default)]
    pub receipt_digest: String,
}

#[derive(Clone, Debug)]
pub struct CollectionRecoveryOptions {
    pub job_id: String,
    pub revision: u64,
    pub recipe: String,
    pub expected_state: Option<String>,
    pub operation_id: Option<String>,
}

impl CollectionRecoveryOptions {
    pub fn validate(&self, apply: bool) -> Result<()> {
        let hash = |v: &str| v.starts_with("blake3:") && crate::integrity::valid_hash(v);
        if !hash(&self.job_id)
            || self.revision == 0
            || self.revision > i64::MAX as u64
            || self.recipe != NPM_RECOVERY_RECIPE
            || self.expected_state.as_deref().is_some_and(|v| !hash(v))
            || self.operation_id.as_deref().is_some_and(|v| !hash(v))
            || apply && (self.expected_state.is_none() || self.operation_id.is_none())
        {
            return Err(Error::invalid(
                "Invalid exact collection recovery selection.",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecoveryEvidenceReceipt {
    pub version: u32,
    pub job_id: String,
    pub revision: u64,
    pub state_digest: String,
    pub artifact_digest: String,
    pub artifact_bytes: u64,
    pub members: u64,
    pub next_member: u64,
    pub records: u64,
    pub gaps: u64,
    pub expanded_bytes: u64,
    pub prefix_digest: String,
    pub evidence_digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionRecoveryReport {
    pub version: u32,
    pub job_id: String,
    pub revision: u64,
    pub recipe: String,
    pub state_digest: String,
    pub eligible: bool,
    pub outcome: String,
    pub reason: String,
    pub operation_id: Option<String>,
    pub publication_snapshot: Option<String>,
}

pub use crate::storage::collection_recovery::{
    apply_npm_recovery, diagnose_npm_recovery, diagnose_npm_recovery_with_diagnostics,
    inspect_npm_recovery_operation, run_npm_recovery, verify_npm_recovery_evidence,
};
