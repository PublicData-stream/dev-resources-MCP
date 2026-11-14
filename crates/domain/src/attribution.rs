//! Versioned attribution evidence for public sources; never caller inventories.
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const ATTRIBUTION_POLICY_EPOCH: u32 = 2;
/// Named immutable qualification manifest. Changes require a new epoch.
pub const ATTRIBUTION_POLICY_FINGERPRINT: &str =
    "devres-attribution-v2:verified-forward-origins:member-scopes:readable-notices";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttributionSubject {
    pub provider: String,
    pub namespace: String,
    pub key: String,
    pub fingerprint: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttributionTarget {
    pub subject: AttributionSubject,
    pub evidence: Value,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttributionNotice {
    pub source_url: String,
    pub license: Option<String>,
    pub copyright: Option<String>,
    pub text: String,
    pub evidence: Value,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttributionGeneration {
    pub subject: AttributionSubject,
    pub policy_epoch: u32,
    pub policy_fingerprint: String,
    pub notices: Vec<AttributionNotice>,
    pub receipts: Vec<Value>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualifiedAttribution {
    pub id: String,
    pub generation: AttributionGeneration,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttributionJob {
    pub target: AttributionTarget,
    pub claim: String,
    pub attempts: u32,
}

/// Registered immutable policy manifests. Future versions retain every earlier
/// entry so historical evidence can be verified while new readiness is repaired.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttributionPolicyManifest {
    pub epoch: u32,
    pub fingerprint: &'static str,
}
pub const ATTRIBUTION_POLICY_MANIFESTS: &[AttributionPolicyManifest] = &[
    AttributionPolicyManifest {
        epoch: 1,
        fingerprint: "devres-attribution-v1:exact-reacquisition:member-scopes:readable-notices",
    },
    AttributionPolicyManifest {
        epoch: ATTRIBUTION_POLICY_EPOCH,
        fingerprint: ATTRIBUTION_POLICY_FINGERPRINT,
    },
];
pub const ATTRIBUTION_REQUIRED_POLICY: AttributionPolicyManifest = AttributionPolicyManifest {
    epoch: ATTRIBUTION_POLICY_EPOCH,
    fingerprint: ATTRIBUTION_POLICY_FINGERPRINT,
};

/// Sanitized operational classification, independent of immutable rights policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributionPhase {
    Mapping,
    Acquisition,
    Qualification,
    Publication,
    Scheduling,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributionFailureReason {
    Unclassified,
    UpstreamUnavailable,
    SourceGone,
    UnsupportedSource,
    MissingNotice,
    UnqualifiedScope,
    InvalidEvidence,
    SourceMismatch,
    PayloadBound,
    ParserBusy,
    PublicationDeferred,
    AdmissionDeferred,
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributionDisposition {
    Retry,
    Blocked,
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttributionFailure {
    pub phase: AttributionPhase,
    pub reason: AttributionFailureReason,
    pub disposition: AttributionDisposition,
}

impl AttributionFailure {
    pub const fn new(
        phase: AttributionPhase,
        reason: AttributionFailureReason,
        disposition: AttributionDisposition,
    ) -> Self {
        Self {
            phase,
            reason,
            disposition,
        }
    }

    /// Only this finite metadata crosses attribution acquisition boundaries.
    pub fn attach(self, error: crate::Error) -> crate::Error {
        error.with_details(serde_json::json!({"attribution_failure":self}))
    }

    pub fn from_error(error: &crate::Error) -> Option<Self> {
        serde_json::from_value(error.details.as_ref()?.get("attribution_failure")?.clone()).ok()
    }
}
