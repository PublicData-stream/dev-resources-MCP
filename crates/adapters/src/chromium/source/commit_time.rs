//! Resolve only Gitiles' ambiguous fixed-zone display using an exact Git object.
//! Object bytes, messages and committer identities are never retained by this proof.
use super::{
    Commit, CommitFields, MAX_RAW_COMMIT_ENCODED_BYTES, Operation, SourceResponse,
    ValidationReason, commit_fields, diagnostic_oid, hash_mismatch, malformed, object_oid,
    parse_date, valid_oid, validation, validation_reason,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use devres_application::collection::{self, Phase};
use devres_domain::{Error, Result};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawTimestampProof {
    pub version: u32,
    pub selected_oid: String,
    pub encoded_bytes: u64,
    pub encoded_digest: String,
    pub epoch: i64,
}
impl RawTimestampProof {
    pub(crate) fn validate(&self, commit: &Commit) -> Result<()> {
        if self.version != 1
            || !valid_oid(&self.selected_oid)
            || self.selected_oid != commit.revision
            || self.epoch != commit.committed_at
            || self.encoded_bytes == 0
            || self.encoded_bytes > MAX_RAW_COMMIT_ENCODED_BYTES as u64
            || !self.encoded_digest.starts_with("blake3:")
            || !crate::integrity::valid_hash(&self.encoded_digest)
        {
            return Err(malformed());
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct CommitResolution {
    pub commit: Commit,
    pub timestamp_proof: Option<RawTimestampProof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawCommitAttempt {
    version: u32,
    encoded_bytes: u64,
    encoded_digest: String,
}
impl RawCommitAttempt {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.version != 1
            || self.encoded_bytes > MAX_RAW_COMMIT_ENCODED_BYTES as u64
            || !self.encoded_digest.starts_with("blake3:")
            || !crate::integrity::valid_hash(&self.encoded_digest)
        {
            return Err(malformed());
        }
        Ok(())
    }
}
pub(crate) fn raw_commit_attempt(error: &Error) -> Option<RawCommitAttempt> {
    let attempt: RawCommitAttempt = serde_json::from_value(
        error
            .details
            .as_ref()?
            .get("chromium_raw_commit_attempt")?
            .clone(),
    )
    .ok()?;
    attempt.validate().ok()?;
    Some(attempt)
}

fn annotate(mut error: Error, reason: ValidationReason, encoded: Option<&[u8]>) -> Error {
    let context = collection::context(&error);
    let claimed = diagnostic_oid(&error, "chromium_claimed_oid");
    let computed = diagnostic_oid(&error, "chromium_computed_oid");
    let mut details = serde_json::json!({"chromium_validation_reason":reason});
    if let Some(context) = context {
        details["collector"] = serde_json::json!(context);
    }
    if let Some(id) = claimed {
        details["chromium_claimed_oid"] = serde_json::json!(id);
    }
    if let Some(id) = computed {
        details["chromium_computed_oid"] = serde_json::json!(id);
    }
    if let Some(encoded) = encoded {
        details["chromium_raw_commit_attempt"] = serde_json::json!(RawCommitAttempt {
            version: 1,
            encoded_bytes: encoded.len() as u64,
            encoded_digest: crate::integrity::hash(encoded),
        });
    }
    error.details = Some(details);
    error
}

fn fixed_zone_calendar(value: &str) -> bool {
    if !value.is_ascii()
        || value.is_empty()
        || value.len() > 128
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && !b" :".contains(&byte))
    {
        return false;
    }
    let fields = value.split_ascii_whitespace().collect::<Vec<_>>();
    if fields.len() != 5
        || !matches!(
            fields[0],
            "Mon" | "Tue" | "Wed" | "Thu" | "Fri" | "Sat" | "Sun"
        )
        || !(1..=2).contains(&fields[2].len())
        || !fields[2].bytes().all(|byte| byte.is_ascii_digit())
        || fields[3].len() != 8
        || fields[3].as_bytes()[2] != b':'
        || fields[3].as_bytes()[5] != b':'
        || !fields[3].bytes().enumerate().all(|(offset, byte)| {
            if matches!(offset, 2 | 5) {
                byte == b':'
            } else {
                byte.is_ascii_digit()
            }
        })
        || fields[4].len() != 4
        || !fields[4].bytes().all(|byte| byte.is_ascii_digit())
    {
        return false;
    }
    // Validate calendar ranges using the established parser. The result is discarded:
    // this does not interpret the absent zone. Only the verified object supplies epoch.
    parse_date(&format!("{value} +0000")).is_ok()
}

fn raw_epoch(raw: &[u8], fields: &CommitFields) -> Result<i64> {
    let end = raw
        .windows(2)
        .position(|bytes| bytes == b"\n\n")
        .ok_or_else(|| validation(malformed(), ValidationReason::RawCommitHeaders))?;
    let mut tree = None;
    let mut parents = Vec::new();
    let mut epoch = None;
    for line in raw[..end].split(|byte| *byte == b'\n') {
        if let Some(value) = line.strip_prefix(b"tree ") {
            let value = std::str::from_utf8(value)
                .ok()
                .filter(|value| valid_oid(value))
                .ok_or_else(|| validation(malformed(), ValidationReason::RawCommitHeaders))?;
            if tree.replace(value).is_some() {
                return Err(validation(malformed(), ValidationReason::RawCommitHeaders));
            }
        } else if let Some(value) = line.strip_prefix(b"parent ") {
            if parents.len() >= 1024 {
                return Err(validation(
                    Error::capacity("Raw commit parent count exceeds its bound."),
                    ValidationReason::Capacity,
                ));
            }
            parents.push(
                std::str::from_utf8(value)
                    .ok()
                    .filter(|value| valid_oid(value))
                    .ok_or_else(|| validation(malformed(), ValidationReason::RawCommitHeaders))?,
            );
        } else if let Some(value) = line.strip_prefix(b"committer ") {
            if epoch.is_some() {
                return Err(validation(malformed(), ValidationReason::RawCommitHeaders));
            }
            let mut pieces = value.rsplitn(3, |byte| *byte == b' ');
            let zone = pieces.next().ok_or_else(malformed)?;
            let seconds = pieces.next().ok_or_else(malformed)?;
            let identity = pieces.next().ok_or_else(malformed)?;
            if identity.last() != Some(&b'>')
                || !identity.contains(&b'<')
                || zone.len() != 5
                || !matches!(zone[0], b'+' | b'-')
                || !zone[1..].iter().all(u8::is_ascii_digit)
            {
                return Err(validation(malformed(), ValidationReason::RawCommitEpoch));
            }
            let zone_hours = std::str::from_utf8(&zone[1..3])
                .ok()
                .and_then(|s| s.parse::<u8>().ok())
                .ok_or_else(malformed)?;
            let zone_minutes = std::str::from_utf8(&zone[3..5])
                .ok()
                .and_then(|s| s.parse::<u8>().ok())
                .ok_or_else(malformed)?;
            if zone_hours > 23 || zone_minutes > 59 {
                return Err(validation(malformed(), ValidationReason::RawCommitEpoch));
            }
            let text = std::str::from_utf8(seconds)
                .map_err(|_| validation(malformed(), ValidationReason::RawCommitEpoch))?;
            let parsed = text
                .parse::<i64>()
                .map_err(|_| validation(malformed(), ValidationReason::RawCommitEpoch))?;
            if parsed.to_string() != text {
                return Err(validation(malformed(), ValidationReason::RawCommitEpoch));
            }
            epoch = Some(parsed);
        }
    }
    if tree != Some(fields.tree.as_str())
        || parents
            .iter()
            .copied()
            .ne(fields.parents.iter().map(String::as_str))
    {
        return Err(validation(malformed(), ValidationReason::RawCommitIdentity));
    }
    epoch.ok_or_else(|| validation(malformed(), ValidationReason::RawCommitHeaders))
}

fn prove(fields: CommitFields, encoded: &[u8]) -> Result<CommitResolution> {
    if encoded.len() > MAX_RAW_COMMIT_ENCODED_BYTES {
        return Err(validation(
            Error::capacity("Raw commit proof exceeds its byte bound."),
            ValidationReason::Capacity,
        ));
    }
    let compact = encoded
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    let raw = STANDARD
        .decode(compact)
        .map_err(|_| validation(malformed(), ValidationReason::RawCommitEncoding))?;
    let computed = object_oid("commit", &raw);
    if computed != fields.revision {
        return Err(hash_mismatch(
            ValidationReason::RawCommitObjectHash,
            &fields.revision,
            &computed,
        ));
    }
    let epoch = raw_epoch(&raw, &fields)?;
    let proof = RawTimestampProof {
        version: 1,
        selected_oid: fields.revision.clone(),
        encoded_bytes: encoded.len() as u64,
        encoded_digest: crate::integrity::hash(encoded),
        epoch,
    };
    let commit = fields.with_epoch(epoch);
    proof.validate(&commit)?;
    Ok(CommitResolution {
        commit,
        timestamp_proof: Some(proof),
    })
}

/// Shared collection/probe path. No timezone is inferred for an unresolved display.
pub async fn resolve_commit<F, Fut>(
    component: &str,
    selected: &str,
    bytes: &[u8],
    cancel: &CancellationToken,
    fetch: F,
) -> Result<CommitResolution>
where
    F: FnOnce(Operation) -> Fut,
    Fut: std::future::Future<Output = Result<SourceResponse>>,
{
    if cancel.is_cancelled() {
        return Err(Error::new(
            "cancelled",
            "Commit timestamp verification canceled.",
        ));
    }
    let fields = commit_fields(component, bytes)?;
    if !valid_oid(selected) || fields.revision != selected {
        return Err(validation(malformed(), ValidationReason::SelectedIdentity));
    }
    match parse_date(&fields.date) {
        Ok(epoch) => {
            return Ok(CommitResolution {
                commit: fields.with_epoch(epoch),
                timestamp_proof: None,
            });
        }
        Err(error)
            if !matches!(component, "src" | "site") || !fixed_zone_calendar(&fields.date) =>
        {
            return Err(validation(error, ValidationReason::CommitDate));
        }
        Err(_) => {}
    }
    let response = tokio::select! { biased;
        _ = cancel.cancelled() => return Err(Error::new("cancelled", "Commit timestamp verification canceled.")),
        result = fetch(Operation::RawCommit {component:component.into(),revision:selected.into()}) => result.map_err(|error| annotate(error,ValidationReason::RawCommitAcquisition,None))?,
    };
    if response.status != 200 {
        return Err(annotate(
            collection::http_failure(
                Error::unavailable("Raw commit proof is unavailable."),
                Phase::PublicationAcquisition,
                response.status,
            ),
            ValidationReason::RawCommitAcquisition,
            None,
        ));
    }
    if cancel.is_cancelled() {
        return Err(Error::new(
            "cancelled",
            "Commit timestamp verification canceled.",
        ));
    }
    prove(fields, &response.bytes).map_err(|error| {
        let reason = validation_reason(&error);
        // Oversized responses are rejected without admitting their impossible descriptor.
        annotate(
            error,
            reason,
            (response.bytes.len() <= MAX_RAW_COMMIT_ENCODED_BYTES)
                .then_some(response.bytes.as_slice()),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        future,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    fn response(bytes: Vec<u8>) -> SourceResponse {
        SourceResponse {
            status: 200,
            bytes,
            observed_at: 42,
            source_url: "https://fixtures.invalid/private-metadata".into(),
            next: None,
            retry_at: None,
        }
    }
    fn fixture(date: &str, epoch: &str, duplicate: bool) -> (String, Vec<u8>, Vec<u8>) {
        let tree = "ab".repeat(20);
        let parents = ["cd".repeat(20), "ef".repeat(20)];
        let committer =
            format!("committer Synthetic Private Name <private-email.invalid> {epoch} -0700\n");
        let mut raw = format!(
            "tree {tree}\nparent {}\nparent {}\nauthor Synthetic <synthetic.invalid> 0 +0000\n{committer}",
            parents[0], parents[1]
        );
        if duplicate {
            raw.push_str(&committer);
        }
        raw.push_str("\nInert private synthetic message. Never execute or retain.\n");
        let selected = object_oid("commit", raw.as_bytes());
        let data = serde_json::to_vec(&serde_json::json!({"commit":selected,"tree":tree,"parents":parents,"committer":{"time":date}})).unwrap();
        (selected, data, STANDARD.encode(raw).into_bytes())
    }
    async fn run(selected: &str, data: &[u8], encoded: Vec<u8>) -> Result<CommitResolution> {
        resolve_commit("src", selected, data, &CancellationToken::new(), |_| {
            future::ready(Ok(response(encoded)))
        })
        .await
    }

    #[tokio::test]
    async fn exact_observed_five_token_metadata_requires_selected_raw_proof() {
        for (component, selected, date) in [
            (
                "src",
                "8082e984dac3db1947e3daf26bd5a4fd5c949d81",
                "Thu Nov 12 17:00:30 2026",
            ),
            (
                "site",
                "8dc34bc900a80ee817d5e967ef22fb8f30175c5b",
                "Wed Nov 11 18:19:18 2026",
            ),
        ] {
            let data = serde_json::to_vec(&serde_json::json!({"commit":selected,"tree":"ab".repeat(20),"parents":[],"committer":{"time":date}})).unwrap();
            assert_eq!(
                validation_reason(&super::super::parse_commit(component, &data).unwrap_err()),
                ValidationReason::CommitDate
            );
            let calls = AtomicUsize::new(0);
            let error = resolve_commit(
                component,
                selected,
                &data,
                &CancellationToken::new(),
                |operation| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(
                        operation,
                        Operation::RawCommit {
                            component: component.into(),
                            revision: selected.into()
                        }
                    );
                    assert_eq!(
                        operation.url().unwrap(),
                        format!(
                            "{}/+/{selected}?format=TEXT",
                            super::super::component_base(component).unwrap()
                        )
                    );
                    let mut unavailable = response(Vec::new());
                    unavailable.status = 403;
                    future::ready(Ok(unavailable))
                },
            )
            .await
            .unwrap_err();
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(collection::context(&error).unwrap().http_status, Some(403));
            assert_eq!(
                validation_reason(&error),
                ValidationReason::RawCommitAcquisition
            );
        }
    }

    #[tokio::test]
    async fn verified_epoch_is_independent_of_missing_display_zone_and_preserves_git_identity() {
        for date in ["Thu Nov 12 17:00:30 2026", "Wed Nov 11 18:19:18 2026"] {
            // Deliberately different from interpreting either display as UTC.
            let (selected, data, encoded) = fixture(date, "1794495630", false);
            let resolved = run(&selected, &data, encoded.clone()).await.unwrap();
            assert_eq!(resolved.commit.revision, selected);
            assert_eq!(resolved.commit.tree, "ab".repeat(20));
            assert_eq!(resolved.commit.parents, ["cd".repeat(20), "ef".repeat(20)]);
            assert_eq!(resolved.commit.committed_at, 1_794_495_630);
            let proof = resolved.timestamp_proof.unwrap();
            proof.validate(&resolved.commit).unwrap();
            assert_eq!(proof.encoded_digest, crate::integrity::hash(&encoded));
            let safe = serde_json::to_string(&proof).unwrap();
            assert!(!safe.contains("Private"));
            assert!(!safe.contains("private-email"));
            assert!(!safe.contains("message"));
            assert!(!safe.contains("body"));
        }
    }

    #[tokio::test]
    async fn proof_rejects_wrong_object_tree_parent_order_epoch_envelope_and_bounds() {
        let (selected, data, encoded) = fixture("Thu Nov 12 17:00:30 2026", "1794502830", false);
        let other = fixture("Thu Nov 12 17:00:30 2026", "1794502831", false).2;
        assert_eq!(
            validation_reason(&run(&selected, &data, other).await.unwrap_err()),
            ValidationReason::RawCommitObjectHash
        );
        for field in ["tree", "parents"] {
            let mut changed: serde_json::Value = serde_json::from_slice(&data).unwrap();
            if field == "tree" {
                changed[field] = serde_json::json!("00".repeat(20));
            } else {
                changed[field] = serde_json::json!(["ef".repeat(20), "cd".repeat(20)]);
            }
            assert_eq!(
                validation_reason(
                    &run(
                        &selected,
                        &serde_json::to_vec(&changed).unwrap(),
                        encoded.clone()
                    )
                    .await
                    .unwrap_err()
                ),
                ValidationReason::RawCommitIdentity
            );
        }
        for (epoch, duplicate, reason) in [
            ("1794502830", true, ValidationReason::RawCommitHeaders),
            ("not-numeric", false, ValidationReason::RawCommitEpoch),
            (
                "9223372036854775808",
                false,
                ValidationReason::RawCommitEpoch,
            ),
            ("+1794502830", false, ValidationReason::RawCommitEpoch),
        ] {
            let (id, json, raw) = fixture("Thu Nov 12 17:00:30 2026", epoch, duplicate);
            assert_eq!(
                validation_reason(&run(&id, &json, raw).await.unwrap_err()),
                reason
            );
        }
        let error = run(&selected, &data, b"not-base64!".to_vec())
            .await
            .unwrap_err();
        assert_eq!(
            validation_reason(&error),
            ValidationReason::RawCommitEncoding
        );
        assert!(raw_commit_attempt(&error).is_some());
        let error = run(
            &selected,
            &data,
            vec![b'A'; MAX_RAW_COMMIT_ENCODED_BYTES + 1],
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, "capacity");
        assert!(raw_commit_attempt(&error).is_none());
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert_eq!(
            resolve_commit("src", &selected, &data, &cancelled, |_| future::ready(Err(
                Error::integrity("must not fetch")
            )))
            .await
            .unwrap_err()
            .code,
            "cancelled"
        );
    }

    #[tokio::test]
    async fn strict_formats_and_invalid_unicode_do_not_invoke_raw_fallback() {
        for (date, expected) in [
            ("Thu Jan 01 01:00:00 1970 +0100", Some(0)),
            ("2026-10-27T00:00:00Z", Some(1_793_059_200)),
            ("Thu Nov 12 17:00:30 202é", None),
            ("Thu Nov 12 17:00:💾 2026", None),
            ("Thu Feb 30 17:00:30 2026", None),
            ("2026-é1-01T00:00:00Z", None),
        ] {
            let (id, data, _) = fixture(date, "1794502830", false);
            let resolved = resolve_commit("src", &id, &data, &CancellationToken::new(), |_| {
                future::ready(Err(Error::integrity("Unexpected raw acquisition.")))
            })
            .await;
            if let Some(epoch) = expected {
                let resolved = resolved.unwrap();
                assert_eq!(resolved.commit.committed_at, epoch);
                assert!(resolved.timestamp_proof.is_none());
            } else {
                assert_eq!(
                    validation_reason(&resolved.unwrap_err()),
                    ValidationReason::CommitDate
                );
            }
        }
        assert!(
            Operation::RawCommit {
                component: "chrome-archive".into(),
                revision: "ab".repeat(20)
            }
            .url()
            .is_err()
        );
    }

    #[tokio::test]
    async fn cancelled_raw_acquisition_stops_without_a_proof_or_implicit_timestamp() {
        let (id, data, _) = fixture("Thu Nov 12 17:00:30 2026", "1794502830", false);
        let cancel = CancellationToken::new();
        let stop = cancel.clone();
        let entered = Arc::new(tokio::sync::Notify::new());
        let notified = entered.clone();
        let task = tokio::spawn(async move {
            resolve_commit("src", &id, &data, &stop, |_| async move {
                notified.notify_one();
                future::pending::<Result<SourceResponse>>().await
            })
            .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), entered.notified())
            .await
            .unwrap();
        cancel.cancel();
        let error = tokio::time::timeout(std::time::Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(error.code, "cancelled");
    }
}
