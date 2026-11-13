//! Closed, public-source-only collector diagnostics. Never copy arbitrary error details.
use devres_domain::Error;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    RetrievalAdmission,
    Revalidation,
    IndexSelection,
    IndexAdmission,
    IndexManifest,
    IndexEngine,
    IndexReader,
    IndexSearch,
    IndexSnippet,
    BulkOperation,
    CatalogLookup,
    CatalogAcquisition,
    CatalogBody,
    CatalogRetention,
    CatalogValidation,
    CatalogPublication,
    PublicationAcquisition,
    SourceValidation,
    LicenseQualification,
    RawRetention,
    Projection,
    IndexPublication,
    ViewPublication,
    InventoryRestore,
    InventoryAcquisition,
    InventoryImport,
    InventoryPublication,
    RetainedLookup,
    ArtifactVerification,
    HttpAcquisition,
    HttpBody,
    ArtifactRetention,
    ArtifactPublication,
    Materialization,
    CsvParsing,
    MetadataStaging,
    EnrichmentPublication,
    GitAdvertisement,
    GitUploadPack,
    GitTransfer,
    GitProcess,
    GitEvidence,
    Traversal,
    SitemapDiscovery,
    StatusRead,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LimitKind {
    CompressedBytes,
    ExpandedBytes,
    CsvRowBytes,
    CsvFieldBytes,
    CsvColumns,
    TarMembers,
    StorageBatchBytes,
    FreeReserve,
    ArchiveQuota,
    CacheWorkingSet,
    Deadline,
    ArtifactBytes,
    CatalogPages,
    CatalogStandards,
    TreeDepth,
    MetadataBytes,
    ProviderAttempts,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Limit {
    pub kind: LimitKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub phase: Phase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<Limit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
}

/// Read only this typed namespace; unrelated details must never enter public status.
pub fn context(error: &Error) -> Option<Context> {
    let value = error.details.as_ref()?.get("collector")?;
    let context: Context = serde_json::from_value(value.clone()).ok()?;
    if context
        .http_status
        .is_some_and(|status| !(100..=599).contains(&status))
    {
        return None;
    }
    Some(context)
}

pub fn at_phase(error: Error, phase: Phase) -> Error {
    if let Some(context) = context(&error) {
        return with_context(error, context);
    }
    with_context(
        error,
        Context {
            phase,
            limit: None,
            http_status: None,
        },
    )
}

/// Attach diagnostics without changing metadata used by the original error's callers.
/// Status and persistence must still read only the typed `context` projection.
pub fn attach_phase(mut error: Error, phase: Phase) -> Error {
    let context = context(&error).unwrap_or(Context {
        phase,
        limit: None,
        http_status: None,
    });
    if error.details.is_none() {
        error.details = Some(serde_json::json!({}));
    }
    if let Some(serde_json::Value::Object(details)) = error.details.as_mut() {
        details.insert("collector".into(), serde_json::json!(context));
    }
    error
}

pub fn limited(
    error: Error,
    phase: Phase,
    kind: LimitKind,
    observed: Option<u64>,
    maximum: Option<u64>,
) -> Error {
    with_context(
        error,
        Context {
            phase,
            limit: Some(Limit {
                kind,
                observed,
                maximum,
            }),
            http_status: None,
        },
    )
}

pub fn http_failure(error: Error, phase: Phase, status: u16) -> Error {
    with_context(
        error,
        Context {
            phase,
            limit: None,
            http_status: (100..=599).contains(&status).then_some(status),
        },
    )
}

fn with_context(mut error: Error, context: Context) -> Error {
    // Replace rather than merge arbitrary nested details, including external input.
    error.details = Some(serde_json::json!({"collector": context}));
    error
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ProgressKind {
    Pages,
    Standards,
    Rows,
    Batches,
    Bytes,
    ExpandedBytes,
    Members,
    Documents,
    ExcludedSubtrees,
    TraversalGaps,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Failure {
    pub code: String,
    pub observed_at: i64,
    pub phase: Phase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<Limit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
}

impl Failure {
    pub fn from_error(error: &Error, fallback: Phase, observed_at: i64) -> Self {
        let context = context(error).unwrap_or(Context {
            phase: fallback,
            limit: None,
            http_status: None,
        });
        Self {
            code: safe_code(&error.code).into(),
            observed_at,
            phase: context.phase,
            limit: context.limit,
            http_status: context.http_status,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct CollectorStatus {
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<Phase>,
    pub progress: BTreeMap<ProgressKind, u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_success_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<Failure>,
}

impl CollectorStatus {
    pub fn begin(&mut self, phase: Phase) {
        self.active = true;
        self.phase = Some(phase);
        self.retry_at = None;
    }
    pub fn progress(&mut self, kind: ProgressKind, value: u64) {
        self.progress.insert(kind, value);
    }
    pub fn succeed(&mut self, now: i64) {
        self.active = false;
        self.last_success_at = Some(now);
        self.retry_at = None;
        // Historical failure remains distinct from the most recent successful operation.
    }
    pub fn fail(&mut self, error: &Error, fallback: Phase, now: i64, retry_at: Option<i64>) {
        let failure = Failure::from_error(error, fallback, now);
        self.active = false;
        self.phase = Some(failure.phase);
        self.retry_at = retry_at;
        self.failure = Some(failure);
    }
}

pub fn safe_code(code: &str) -> &'static str {
    match code {
        "invalid_input" => "invalid_input",
        "unavailable" => "unavailable",
        "not_found" => "not_found",
        "capacity" => "capacity",
        "integrity" => "integrity",
        "cancelled" => "cancelled",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn additive_context_preserves_error_contract_but_failure_projects_only_closed_fields() {
        let siblings = serde_json::json!({"retry_at":123,"attribution_failure":{"reason":"retained"},"private":"credential","collector":{"phase":"http_body","limit":{"kind":"compressed_bytes","maximum":10}}});
        let error = attach_phase(
            Error::new("external", "original message").with_details(siblings.clone()),
            Phase::ArtifactPublication,
        );
        assert_eq!(error.details, Some(siblings));
        assert_eq!(error.message, "original message");
        let failure = Failure::from_error(&error, Phase::SourceValidation, 99);
        assert_eq!(failure.phase, Phase::HttpBody);
        assert_eq!(failure.code, "other");
        assert_eq!(failure.observed_at, 99);
        let encoded = serde_json::to_string(&failure).unwrap();
        assert!(!encoded.contains("private"));
        assert!(!encoded.contains("credential"));
        assert!(!encoded.contains("retry_at"));
        assert!(!encoded.contains("attribution_failure"));
    }

    #[test]
    fn additive_context_replaces_invalid_context_and_preserves_non_object_details() {
        let error = attach_phase(Error::capacity("bounded").with_details(serde_json::json!({"retry_at":10,"collector":{"phase":"http_body","body":"private"}})), Phase::RetrievalAdmission);
        assert_eq!(context(&error).unwrap().phase, Phase::RetrievalAdmission);
        assert_eq!(error.details.as_ref().unwrap()["retry_at"], 10);
        assert!(
            error.details.as_ref().unwrap()["collector"]
                .get("body")
                .is_none()
        );
        let error = attach_phase(
            Error::unavailable("original").with_details(serde_json::json!([1, 2])),
            Phase::RetainedLookup,
        );
        assert_eq!(error.details, Some(serde_json::json!([1, 2])));
    }
    #[test]
    fn status_does_not_copy_external_errors_or_stale_activity() {
        let error = Error::new("secret-code", "secret-body").with_details(serde_json::json!({"url":"private-url","collector":{"phase":"csv_parsing","body":"private-row"}}));
        let error = at_phase(error, Phase::MetadataStaging);
        let mut status = CollectorStatus::default();
        status.begin(Phase::CsvParsing);
        status.fail(&error, Phase::CsvParsing, 10, Some(70));
        status.begin(Phase::CsvParsing);
        status.succeed(80);
        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("secret"));
        assert!(!json.contains("private"));
        assert!(!status.active);
        assert_eq!(status.last_success_at, Some(80));
        assert!(status.retry_at.is_none());
        assert_eq!(
            status.failure.as_ref().unwrap().phase,
            Phase::MetadataStaging
        );
        assert_eq!(status.failure.as_ref().unwrap().code, "other");
    }
    #[test]
    fn innermost_typed_limit_survives_outer_phase() {
        let error = limited(
            Error::capacity("bounded"),
            Phase::HttpBody,
            LimitKind::CompressedBytes,
            Some(11),
            Some(10),
        );
        let error = at_phase(error, Phase::ArtifactRetention);
        let context = context(&error).unwrap();
        assert_eq!(context.phase, Phase::HttpBody);
        assert_eq!(context.limit.unwrap().maximum, Some(10));
    }
    #[test]
    fn preserving_inner_context_strips_unrelated_siblings() {
        let error = Error::capacity("bounded").with_details(serde_json::json!({"collector":{"phase":"csv_parsing"},"source_body":"private-row","credential":"private-key"}));
        let error = at_phase(error, Phase::MetadataStaging);
        assert_eq!(context(&error).unwrap().phase, Phase::CsvParsing);
        let details = error.details.unwrap().to_string();
        assert!(!details.contains("private"));
        assert!(!details.contains("credential"));
    }
}
