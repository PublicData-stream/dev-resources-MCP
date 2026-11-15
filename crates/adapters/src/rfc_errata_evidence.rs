//! Local errata evidence packaging checks. Completeness never authorizes publication.
use crate::{integrity, local_evidence::read_private_input};
use devres_domain::{Error, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::Path};
use tokio_util::sync::CancellationToken;

const MAX_TOTAL: u64 = 64 * 1024 * 1024;
const MAX_DEPENDENCY: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceRole {
    Terms,
    Applicability,
    OriginalNotice,
    Authorship,
    QuotedScope,
    ContributedScope,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceDependency {
    pub role: EvidenceRole,
    pub body: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ErrataEvidenceManifest {
    pub version: u32,
    pub export_capture: String,
    pub export_body: String,
    /// Hash of the exact raw JSON member slice, including its original formatting.
    pub member_body: String,
    pub errata_id: u64,
    pub rfc: u64,
    pub report_date: Option<String>,
    pub stream: Option<String>,
    pub contributor: Option<String>,
    pub dependencies: Vec<EvidenceDependency>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceOutcome {
    CompleteForReview,
    Incomplete,
}

#[derive(Debug, Serialize)]
pub struct ErrataEvidenceReport {
    pub version: u32,
    pub manifest_digest: String,
    pub export_capture: String,
    pub export_body: String,
    pub member_body: String,
    pub errata_id: u64,
    pub rfc: u64,
    pub policy_epoch: u32,
    pub publication_authorized: bool,
    pub outcome: EvidenceOutcome,
    pub missing: Vec<&'static str>,
    pub verified_dependencies: Vec<EvidenceRole>,
    pub archive_binding_checked: bool,
    pub applicability_approved: bool,
}

fn invalid() -> Error {
    Error::integrity("RFC errata evidence identity or dependency is invalid.")
}
fn hash(value: &str) -> bool {
    value.starts_with("blake3:") && integrity::valid_hash(value)
}
fn valid_date(value: &str) -> bool {
    let parts: Vec<_> = value.split('-').collect();
    if parts.len() != 3
        || parts[0].len() != 4
        || parts[1].len() != 2
        || parts[2].len() != 2
        || !parts.iter().all(|s| s.bytes().all(|b| b.is_ascii_digit()))
    {
        return false;
    }
    let (Ok(y), Ok(m), Ok(d)) = (
        parts[0].parse::<u32>(),
        parts[1].parse::<usize>(),
        parts[2].parse::<u32>(),
    ) else {
        return false;
    };
    let leap = y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400));
    let days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    y >= 1969 && (1..=12).contains(&m) && d > 0 && d <= days[m - 1]
}

/// Files in the private bundle are named by their bare BLAKE3 digest. No URL is fetched.
pub fn verify_errata_evidence(
    bundle: &Path,
    manifest: &ErrataEvidenceManifest,
    cancel: &CancellationToken,
) -> Result<ErrataEvidenceReport> {
    let started = std::time::Instant::now();
    let check = || -> Result<()> {
        if cancel.is_cancelled() {
            return Err(Error::new(
                "cancelled",
                "Errata evidence verification canceled.",
            ));
        }
        if started.elapsed() >= std::time::Duration::from_secs(300) {
            return Err(Error::capacity("Errata evidence deadline exceeded."));
        }
        Ok(())
    };
    check()?;
    if manifest.version != 1
        || !hash(&manifest.export_capture)
        || !hash(&manifest.export_body)
        || !hash(&manifest.member_body)
        || manifest.errata_id == 0
        || manifest.rfc == 0
        || manifest.rfc > 99999
        || manifest.dependencies.len() > 6
    {
        return Err(invalid());
    }
    let mut seen = BTreeSet::new();
    for dep in &manifest.dependencies {
        if !hash(&dep.body) || !seen.insert(dep.role) {
            return Err(invalid());
        }
    }
    let export = read_private_input(&bundle.join(&manifest.export_body[7..]), MAX_TOTAL)?;
    if integrity::hash(&export) != manifest.export_body {
        return Err(invalid());
    }
    let records = crate::rfc::source::parse_errata(&export)?;
    let raws: Vec<&serde_json::value::RawValue> =
        serde_json::from_slice(&export).map_err(|_| invalid())?;
    let selected = records
        .iter()
        .zip(raws)
        .find(|(record, _)| {
            record["errata_id"]
                .as_u64()
                .or_else(|| record["errata_id"].as_str()?.parse().ok())
                == Some(manifest.errata_id)
        })
        .ok_or_else(invalid)?;
    if integrity::hash(selected.1.get().as_bytes()) != manifest.member_body {
        return Err(invalid());
    }
    let expected_doc = format!("RFC{:05}", manifest.rfc);
    let expected_short = format!("RFC{}", manifest.rfc);
    if !matches!(selected.0["doc-id"].as_str(),Some(s) if s==expected_doc || s==expected_short) {
        return Err(invalid());
    }
    let mut missing = Vec::new();
    match manifest.report_date.as_deref() {
        Some(date) if valid_date(date) && selected.0["submit_date"].as_str() == Some(date) => {}
        Some(_) => return Err(invalid()),
        None => missing.push("report_date"),
    }
    match manifest.stream.as_deref() {
        Some("ietf" | "irtf" | "iab" | "independent" | "editorial") => {}
        Some(_) => return Err(invalid()),
        None => missing.push("stream"),
    }
    match manifest.contributor.as_deref() {
        Some(name)
            if !name.trim().is_empty()
                && name.len() <= 4096
                && selected.0["submitter_name"].as_str() == Some(name) => {}
        Some(_) => return Err(invalid()),
        None => missing.push("contributor"),
    }
    let mut bytes = export.len() as u64;
    for dep in &manifest.dependencies {
        check()?;
        let remaining = MAX_TOTAL
            .checked_sub(bytes)
            .ok_or_else(|| Error::capacity("Errata evidence exceeds byte budget."))?;
        let data = read_private_input(&bundle.join(&dep.body[7..]), MAX_DEPENDENCY.min(remaining))?;
        bytes = bytes.saturating_add(data.len() as u64);
        if data.is_empty() || integrity::hash(&data) != dep.body {
            return Err(invalid());
        }
    }
    for (role, reason) in [
        (EvidenceRole::Terms, "terms"),
        (EvidenceRole::Applicability, "applicability"),
        (EvidenceRole::OriginalNotice, "original_notice"),
        (EvidenceRole::Authorship, "authorship"),
        (EvidenceRole::QuotedScope, "quoted_scope"),
        (EvidenceRole::ContributedScope, "contributed_scope"),
    ] {
        if !seen.contains(&role) {
            missing.push(reason);
        }
    }
    check()?;
    Ok(ErrataEvidenceReport {
        version: 1,
        manifest_digest: integrity::canonical_hash(
            &serde_json::to_value(manifest).map_err(|_| invalid())?,
        )?,
        export_capture: manifest.export_capture.clone(),
        export_body: manifest.export_body.clone(),
        member_body: manifest.member_body.clone(),
        errata_id: manifest.errata_id,
        rfc: manifest.rfc,
        policy_epoch: 2,
        publication_authorized: false,
        outcome: if missing.is_empty() {
            EvidenceOutcome::CompleteForReview
        } else {
            EvidenceOutcome::Incomplete
        },
        missing,
        verified_dependencies: seen.into_iter().collect(),
        archive_binding_checked: false,
        applicability_approved: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn fixture() -> (tempfile::TempDir, ErrataEvidenceManifest) {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let raw = r#"{"errata_id":"1234","doc-id":"RFC09000","errata_status_code":"Verified","errata_type_code":"Technical","submit_date":"2024-02-29","submitter_name":"private-name-sentinel","correct_text":"private-prose-sentinel"}"#;
        let export = format!("[{raw}]");
        let body = integrity::hash(export.as_bytes());
        let path = root.path().join(&body[7..]);
        std::fs::write(&path, export).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut dependencies = Vec::new();
        for role in [
            EvidenceRole::Terms,
            EvidenceRole::Applicability,
            EvidenceRole::OriginalNotice,
            EvidenceRole::Authorship,
            EvidenceRole::QuotedScope,
            EvidenceRole::ContributedScope,
        ] {
            let data = format!("untrusted declared evidence {role:?}");
            let body = integrity::hash(data.as_bytes());
            let path = root.path().join(&body[7..]);
            std::fs::write(&path, data).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
            dependencies.push(EvidenceDependency { role, body });
        }
        (
            root,
            ErrataEvidenceManifest {
                version: 1,
                export_capture: integrity::hash(b"unverified capture identity"),
                export_body: body,
                member_body: integrity::hash(raw.as_bytes()),
                errata_id: 1234,
                rfc: 9000,
                report_date: Some("2024-02-29".into()),
                stream: Some("ietf".into()),
                contributor: Some("private-name-sentinel".into()),
                dependencies,
            },
        )
    }
    #[test]
    fn complete_packaging_never_approves_policy_or_echoes_source() {
        let (root, m) = fixture();
        let report = verify_errata_evidence(root.path(), &m, &CancellationToken::new()).unwrap();
        assert_eq!(report.outcome, EvidenceOutcome::CompleteForReview);
        assert!(!report.publication_authorized);
        assert!(!report.applicability_approved);
        assert!(!report.archive_binding_checked);
        let text = serde_json::to_string(&report).unwrap();
        assert!(!text.contains("private-name-sentinel"));
        assert!(!text.contains("private-prose-sentinel"));
    }
    #[test]
    fn rejects_changed_member_export_date_identity_and_dependencies() {
        let (root, m) = fixture();
        let cancel = CancellationToken::new();
        for mutate in [0, 1, 2, 3, 4] {
            let mut bad = m.clone();
            match mutate {
                0 => bad.member_body = integrity::hash(b"changed"),
                1 => bad.export_body = integrity::hash(b"missing"),
                2 => bad.report_date = Some("2023-02-29".into()),
                3 => bad.rfc = 9001,
                _ => bad.dependencies.push(bad.dependencies[0].clone()),
            };
            assert!(verify_errata_evidence(root.path(), &bad, &cancel).is_err());
        }
        cancel.cancel();
        assert!(verify_errata_evidence(root.path(), &m, &cancel).is_err());
    }
    #[test]
    fn missing_evidence_is_incomplete_not_permission() {
        let (root, mut m) = fixture();
        m.dependencies.clear();
        m.stream = None;
        m.contributor = None;
        m.report_date = None;
        let report = verify_errata_evidence(root.path(), &m, &CancellationToken::new()).unwrap();
        assert_eq!(report.outcome, EvidenceOutcome::Incomplete);
        assert_eq!(report.missing.len(), 9);
        assert!(!report.publication_authorized);
    }
}
