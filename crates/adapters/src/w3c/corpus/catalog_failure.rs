//! Private, closed failed-attempt evidence. Public collector context stays unchanged.
use super::{catalog_acquisition::CatalogWork, *};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Operation {
    Checkpoint,
    Acquisition,
    PageValidation,
    PageRetention,
    ArtifactVerification,
    Reconciliation,
    Publication,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Reason {
    CheckpointLookup,
    CheckpointDigest,
    CheckpointDecode,
    CheckpointAncestry,
    DuplicateIdentity,
    CountLimit,
    CheckpointCount,
    PageLimit,
    Acquisition,
    CollectorStateWrite,
    ParsePage { reason: catalog::CatalogParseReason },
    Pagination,
    EmptyCatalog,
    ArtifactRead,
    ArtifactDescriptor,
    Reconciliation,
    EvidenceWrite,
    StateWrite,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Attempt {
    pub version: u32,
    pub operation: Operation,
    pub reason: Reason,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub row: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<i64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "closed_artifact"
    )]
    pub artifact: Option<BulkArtifact>,
}

fn closed_artifact<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<BulkArtifact>, D::Error> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Descriptor {
        body_hash: String,
        bytes: u64,
        relative_path: String,
    }
    Ok(
        Option::<Descriptor>::deserialize(deserializer)?.map(|value| BulkArtifact {
            body_hash: value.body_hash,
            bytes: value.bytes,
            relative_path: value.relative_path,
        }),
    )
}

impl Attempt {
    pub fn new() -> Self {
        Self {
            version: 1,
            operation: Operation::Checkpoint,
            reason: Reason::CheckpointLookup,
            page: None,
            row: None,
            observed_at: None,
            artifact: None,
        }
    }

    pub fn enter(&mut self, operation: Operation, reason: Reason) {
        *self = Self {
            operation,
            reason,
            ..Self::new()
        };
    }

    fn validate(&self, work: &CatalogWork) -> Result<()> {
        let operation_valid = match self.operation {
            Operation::Checkpoint => matches!(
                self.reason,
                Reason::CheckpointLookup
                    | Reason::CheckpointDigest
                    | Reason::CheckpointDecode
                    | Reason::CheckpointAncestry
                    | Reason::DuplicateIdentity
                    | Reason::CountLimit
                    | Reason::CheckpointCount
            ),
            Operation::Acquisition => matches!(
                self.reason,
                Reason::Acquisition | Reason::PageLimit | Reason::CollectorStateWrite
            ),
            Operation::PageValidation => matches!(
                self.reason,
                Reason::ParsePage { .. }
                    | Reason::Pagination
                    | Reason::DuplicateIdentity
                    | Reason::CountLimit
                    | Reason::CollectorStateWrite
            ),
            Operation::PageRetention => {
                matches!(self.reason, Reason::EvidenceWrite | Reason::StateWrite)
            }
            Operation::ArtifactVerification => matches!(
                self.reason,
                Reason::EmptyCatalog | Reason::ArtifactRead | Reason::ArtifactDescriptor
            ),
            Operation::Reconciliation => self.reason == Reason::Reconciliation,
            Operation::Publication => matches!(
                self.reason,
                Reason::EvidenceWrite | Reason::StateWrite | Reason::CollectorStateWrite
            ),
        };
        if self.version != 1
            || !operation_valid
            || self.page.is_some_and(|page| {
                page == 0 || page > 1000 || page as usize > work.pages.len() + 1
            })
            || self
                .row
                .is_some_and(|row| row == 0 || row as usize > catalog::MAX_CATALOG)
            || (self.row.is_some() && self.operation != Operation::PageValidation)
            || (self.artifact.is_some() && self.observed_at.is_none())
        {
            return Err(Error::integrity("Invalid W3C failed-attempt evidence."));
        }
        if let Some(artifact) = &self.artifact
            && (artifact.bytes > 8 * 1024 * 1024
                || !crate::integrity::valid_hash(&artifact.body_hash)
                || artifact.relative_path
                    != crate::integrity::relative_path(&artifact.body_hash)?.to_string_lossy())
        {
            return Err(Error::integrity("Invalid W3C failed-attempt artifact."));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CatalogFailure {
    pub version: u32,
    pub work: CatalogWork,
    pub code: String,
    pub context: Option<collection::Context>,
    pub observed_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt: Option<Attempt>,
}

impl CatalogFailure {
    pub fn decode(value: Value) -> Result<Self> {
        let failure: Self = decode(value)?;
        failure.validate()?;
        Ok(failure)
    }

    pub fn validate(&self) -> Result<()> {
        if self.work.version != 1
            || self.work.pages.len() > 1000
            || !crate::integrity::valid_hash(&self.work.generation)
            || self
                .work
                .pages
                .iter()
                .any(|page| !crate::integrity::valid_hash(page))
            || self
                .work
                .predecessor
                .as_ref()
                .is_some_and(|id| !crate::integrity::valid_hash(id))
            || !matches!(self.code.as_str(), "integrity" | "invalid_input")
            || self
                .context
                .as_ref()
                .and_then(|c| c.http_status)
                .is_some_and(|status| !(100..=599).contains(&status))
            || !matches!(
                (self.version, self.attempt.is_some()),
                (1, false) | (2, true)
            )
        {
            return Err(Error::integrity("Invalid retained W3C catalog failure."));
        }
        if let Some(attempt) = &self.attempt {
            attempt.validate(&self.work)?;
        }
        Ok(())
    }
}

pub(super) fn diagnose(value: Value) -> Result<(Value, Option<BulkArtifact>)> {
    let failure = CatalogFailure::decode(value)?;
    let artifact = failure
        .attempt
        .as_ref()
        .and_then(|attempt| attempt.artifact.clone());
    let attempt = failure.attempt.as_ref().map(|attempt| {
        json!({
            "version":attempt.version,"operation":attempt.operation,"reason":attempt.reason,
            "page":attempt.page,"row":attempt.row,"observed_at":attempt.observed_at,
            "body_digest":attempt.artifact.as_ref().map(|artifact| &artifact.body_hash),
            "body_bytes":attempt.artifact.as_ref().map(|artifact| artifact.bytes)
        })
    });
    Ok((
        json!({
            "version":failure.version,"code":failure.code,"context":failure.context,
            "observed_at":failure.observed_at,
            "work":{"generation":failure.work.generation,"started_at":failure.work.started_at,
                "predecessor":failure.work.predecessor,"pages":failure.work.pages,
                "standards":failure.work.standards,"complete":failure.work.complete},
            "attempt":attempt,
            "attempted_payload_unlinked":failure.attempt.as_ref().is_none_or(|attempt| attempt.artifact.is_none())
        }),
        artifact,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Value {
        json!({
            "version":2,
            "work":{"version":1,"generation":inventory::digest(b"generation"),"started_at":1,"predecessor":null,"pages":[],"standards":0,"complete":false},
            "code":"integrity","context":{"phase":"catalog_validation"},"observed_at":2,
            "attempt":{"version":1,"operation":"page_validation","reason":{"kind":"parse_page","reason":"title"},"page":1,"row":1,"observed_at":2}
        })
    }

    #[test]
    fn failed_attempt_versions_fields_and_positions_are_closed() {
        let valid = fixture();
        CatalogFailure::decode(valid.clone()).unwrap();
        let mut legacy = valid.clone();
        legacy["version"] = json!(1);
        legacy.as_object_mut().unwrap().remove("attempt");
        assert!(CatalogFailure::decode(legacy).unwrap().attempt.is_none());
        for (path, value) in [
            (vec!["version"], json!(3)),
            (vec!["version"], json!(1)),
            (vec!["attempt", "version"], json!(2)),
            (vec!["attempt", "page"], json!(0)),
            (vec!["attempt", "page"], json!(2)),
            (vec!["attempt", "row"], json!(10001)),
            (vec!["attempt", "operation"], json!("publication")),
            (
                vec!["attempt", "reason", "reason"],
                json!("upstream error text"),
            ),
            (
                vec!["attempt", "reason", "extra"],
                json!("upstream error text"),
            ),
            (vec!["attempt", "header"], json!("upstream header")),
            (
                vec!["work", "predecessor"],
                json!("arbitrary upstream text"),
            ),
            (vec!["work", "pages"], json!(["arbitrary upstream text"])),
            (vec!["context", "http_status"], json!(999)),
        ] {
            let mut invalid = valid.clone();
            let mut slot = &mut invalid;
            for key in path {
                slot = &mut slot[key];
            }
            *slot = value;
            assert!(CatalogFailure::decode(invalid).is_err());
        }
    }

    #[test]
    fn private_diagnosis_returns_allowlisted_metadata_and_reports_legacy_gap() {
        let mut value = fixture();
        let digest = inventory::digest(b"attempted page");
        value["attempt"]["artifact"] = json!({"body_hash":digest,"bytes":14,
            "relative_path":crate::integrity::relative_path(&digest).unwrap().to_string_lossy()});
        let (safe, artifact) = diagnose(value.clone()).unwrap();
        assert_eq!(safe["attempt"]["body_digest"], digest);
        assert_eq!(safe["attempt"]["body_bytes"], 14);
        assert_eq!(safe["attempted_payload_unlinked"], false);
        assert_eq!(artifact.unwrap().body_hash, digest);
        assert!(
            !serde_json::to_string(&safe)
                .unwrap()
                .contains("relative_path")
        );
        value["attempt"]["artifact"]["header"] = json!("must not be accepted");
        assert!(diagnose(value.clone()).is_err());
        value["version"] = json!(1);
        value.as_object_mut().unwrap().remove("attempt");
        let (safe, artifact) = diagnose(value).unwrap();
        assert_eq!(safe["attempted_payload_unlinked"], true);
        assert!(safe["attempt"].is_null());
        assert!(artifact.is_none());
    }
}
