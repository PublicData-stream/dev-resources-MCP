//! Immutable redistribution recipe for the reviewed RFC 9525 erratum member.
use crate::{
    integrity,
    local_evidence::read_private_input,
    rfc::corpus::ERRATA_URL,
    rfc_errata_evidence::{ErrataEvidenceManifest, EvidenceRole, selected_member},
};
use devres_application::attribution_gate::RfcErrataMember;
use devres_domain::{
    Capture, Error, Result,
    attribution::{
        ATTRIBUTION_POLICY_V3, AttributionGeneration, AttributionNotice, AttributionSubject,
        AttributionTarget,
    },
};
use serde_json::json;
use std::{collections::BTreeMap, path::Path};
use tokio_util::sync::CancellationToken;

pub(crate) const NAMESPACE: &str = "errata-member";
pub(crate) const RECEIPT_KIND: &str = "retained_rfc_erratum_terms_v1";
pub(crate) const SNAPSHOT: &str =
    "blake3:9077e62009237b595fbdb59abecb4dd033a57f695d75ce0ed77da8ee5d2bdbd0";
pub(crate) const EXPORT_CAPTURE: &str =
    "blake3:20f58039b1c862f35a4b416b6695a8b51169ce3297bfa21762e1596ba5b59af9";
pub(crate) const EXPORT_BODY: &str =
    "blake3:c494ef35fddcafebb7d958c2c0ce2d38c1e258e445022ab8a8ae198ef73d8090";
const MEMBER_BODY: &str = "blake3:16bbccf2d5554fd6be2b62ac095e96924ff8c8442c26a5c989380cbf61fc5e43";
const MANIFEST_BODY: &str =
    "blake3:59ad2053833db9bb49c05b43ca0df3a9cc6ca9afd74ca64d879f0ef9452bb939";
const ORIGINAL_NOTICE_BODY: &str =
    "blake3:d5674a6cbd8c0704bdb0e9d904f7d7cdd7b29453f3dda4feaa20d3fcb5ec9e6d";
const REVIEWED_DEPENDENCIES: [(EvidenceRole, &str); 6] = [
    (
        EvidenceRole::Terms,
        "blake3:2c99878171b6740dcb03827b84e24c2526086adc3b45fe990e9bb6aba162c156",
    ),
    (
        EvidenceRole::Applicability,
        "blake3:2d4e029e7867060c76753ffa66dacce46f952d79092a3b2236a8b269b291e62e",
    ),
    (EvidenceRole::OriginalNotice, ORIGINAL_NOTICE_BODY),
    (
        EvidenceRole::Authorship,
        "blake3:cd59e39e350e1955ea292a8b90ac12c75dcb27c9387011dd65718146bfec1044",
    ),
    (
        EvidenceRole::QuotedScope,
        "blake3:019b66b321898048362808c751f031cdd264bbfb5af7c13b16e24629565466a3",
    ),
    (
        EvidenceRole::ContributedScope,
        "blake3:35759ed0fb10d9baa8d79db93ca107f778aba55cc5382b32223a90557d635d40",
    ),
];
const RFC: u32 = 9525;
const ERRATUM: u64 = 8173;
const REPORT_DATE: &str = "2024-11-11";
const CONTRIBUTOR: &str = "Shushang Wen";
const RFC_URL: &str = "https://www.rfc-editor.org/rfc/rfc9525.html#section-6.1.2";
const ERRATUM_URL: &str = "https://www.rfc-editor.org/errata/eid8173";
const TERMS_URL: &str = "https://trustee.ietf.org/documents/trust-legal-provisions/tlp-5/";
const RFC_ATTRIBUTION: &str = "Original excerpt from IETF RFC 9525, Service Identity in TLS, section 6.1.2, by P. Saint-Andre and R. Salz.\n\n";
const CONTRIBUTION_ATTRIBUTION: &str = "Correction and notes reproduced from IETF/RFC Editor Erratum 8173 for RFC 9525, reported by Shushang Wen on 2024-11-11 and held for document update. The fields reproduce the submitted erratum. Redistribution follows section 3(c)(iii) of corrected IETF Trust Legal Provisions 5.0.";
const FIELDS: [&str; 3] = ["orig_text", "correct_text", "notes"];
const MAX_EXPORT: usize = 64 * 1024 * 1024;
const MAX_DEPENDENCY: u64 = 1024 * 1024;

fn invalid() -> Error {
    Error::integrity("The reviewed RFC erratum evidence does not match the approved recipe.")
}

pub(crate) fn pilot_target() -> Result<AttributionTarget> {
    let evidence = json!({
        "version": 1,
        "snapshot": SNAPSHOT,
        "export_capture": EXPORT_CAPTURE,
        "export_body": EXPORT_BODY,
        "member_body": MEMBER_BODY,
        "rfc": RFC,
        "errata_id": ERRATUM,
        "source_url": ERRATUM_URL,
        "manifest_body": MANIFEST_BODY,
        "qualified_fields": FIELDS,
        "reviewed_dependencies": BTreeMap::from(REVIEWED_DEPENDENCIES),
    });
    Ok(AttributionTarget {
        subject: AttributionSubject {
            provider: "rfc".into(),
            namespace: NAMESPACE.into(),
            key: "rfc:errata:9525:8173".into(),
            fingerprint: integrity::canonical_hash(&evidence)?,
        },
        evidence,
    })
}

pub(crate) fn approved_target(member: &RfcErrataMember<'_>) -> Result<Option<AttributionTarget>> {
    if member.export_capture == EXPORT_CAPTURE
        && member.export_body == EXPORT_BODY
        && member.member_body == MEMBER_BODY
        && member.rfc == RFC
        && member.errata_id == ERRATUM
    {
        return pilot_target().map(Some);
    }
    Ok(None)
}

pub(crate) fn verify_target(target: &AttributionTarget) -> Result<()> {
    if *target != pilot_target()? {
        return Err(invalid());
    }
    Ok(())
}

pub(crate) fn verify_capture(capture: &Capture) -> Result<()> {
    if capture.id != EXPORT_CAPTURE
        || capture.key != "rfc:errata"
        || capture.source_url != ERRATA_URL
        || capture.media_type != "application/json"
        || capture.body_hash != EXPORT_BODY
    {
        return Err(invalid());
    }
    Ok(())
}

pub(crate) fn verify_bound_export(
    export: &[u8],
    target: &AttributionTarget,
    check: impl Fn() -> Result<()>,
) -> Result<()> {
    check()?;
    verify_target(target)?;
    if export.len() > MAX_EXPORT {
        return Err(Error::capacity("RFC errata export exceeds its byte bound."));
    }
    let mut digest = blake3::Hasher::new();
    for chunk in export.chunks(64 * 1024) {
        check()?;
        digest.update(chunk);
    }
    if format!("{}{}", integrity::BLAKE3_PREFIX, digest.finalize().to_hex()) != EXPORT_BODY {
        return Err(invalid());
    }
    let (record, member_body) = selected_member(export, ERRATUM, u64::from(RFC), &check)?;
    if member_body != MEMBER_BODY
        || record["submit_date"] != REPORT_DATE
        || record["submitter_name"] != CONTRIBUTOR
        || record["errata_status_code"] != "Held for Document Update"
        || record["errata_type_code"] != "Editorial"
        || FIELDS.iter().any(|field| {
            record[*field]
                .as_str()
                .is_none_or(|text| text.trim().is_empty())
        })
    {
        return Err(invalid());
    }
    check()
}

/// The reviewed offline bundle. Archive binding is checked independently by the writer.
pub struct ReviewedRfcErratum {
    original_notice: String,
}

impl ReviewedRfcErratum {
    pub fn load(bundle: &Path, cancel: &CancellationToken) -> Result<Self> {
        let check = || {
            if cancel.is_cancelled() {
                return Err(Error::new(
                    "cancelled",
                    "RFC erratum evidence loading canceled.",
                ));
            }
            Ok(())
        };
        check()?;
        let raw = read_private_input(&bundle.join("manifest.json"), 64 * 1024)?;
        integrity::verify(MANIFEST_BODY, &raw)?;
        let manifest: ErrataEvidenceManifest =
            serde_json::from_slice(&raw).map_err(|_| invalid())?;
        let dependencies = manifest
            .dependencies
            .iter()
            .map(|dependency| (dependency.role, dependency.body.as_str()))
            .collect::<BTreeMap<_, _>>();
        if manifest.version != 1
            || manifest.export_capture != EXPORT_CAPTURE
            || manifest.export_body != EXPORT_BODY
            || manifest.member_body != MEMBER_BODY
            || manifest.rfc != u64::from(RFC)
            || manifest.errata_id != ERRATUM
            || manifest.report_date.as_deref() != Some(REPORT_DATE)
            || manifest.stream.as_deref() != Some("ietf")
            || manifest.contributor.as_deref() != Some(CONTRIBUTOR)
            || manifest.dependencies.len() != REVIEWED_DEPENDENCIES.len()
            || dependencies != BTreeMap::from(REVIEWED_DEPENDENCIES)
        {
            return Err(invalid());
        }
        let mut original_notice = None;
        for (role, digest) in REVIEWED_DEPENDENCIES {
            check()?;
            let path = bundle.join(integrity::digest_hex(digest)?);
            let bytes = read_private_input(&path, MAX_DEPENDENCY)?;
            integrity::verify(digest, &bytes)?;
            if role == EvidenceRole::OriginalNotice {
                original_notice = Some(String::from_utf8(bytes).map_err(|_| invalid())?);
            }
        }
        check()?;
        Ok(Self {
            original_notice: original_notice.ok_or_else(invalid)?,
        })
    }

    pub(crate) fn generation(&self, target: &AttributionTarget) -> Result<AttributionGeneration> {
        verify_target(target)?;
        Ok(build_generation(target, &self.original_notice))
    }
}

fn build_generation(target: &AttributionTarget, original_notice: &str) -> AttributionGeneration {
    let notice_evidence = |source, fields: &[&str]| {
        json!({
            "version": 1,
            "source": source,
            "terms_url": TERMS_URL,
            "member_body": MEMBER_BODY,
            "manifest_body": MANIFEST_BODY,
            "fields": fields,
        })
    };
    AttributionGeneration {
        subject: target.subject.clone(),
        policy_epoch: ATTRIBUTION_POLICY_V3.epoch,
        policy_fingerprint: ATTRIBUTION_POLICY_V3.fingerprint.into(),
        notices: vec![
            AttributionNotice {
                source_url: RFC_URL.into(),
                license: None,
                copyright: None,
                text: format!("{RFC_ATTRIBUTION}{original_notice}"),
                evidence: notice_evidence("ietf_rfc_excerpt", &FIELDS[..1]),
            },
            AttributionNotice {
                source_url: ERRATUM_URL.into(),
                license: None,
                copyright: None,
                text: format!("{CONTRIBUTION_ATTRIBUTION}\n{TERMS_URL}"),
                evidence: notice_evidence("ietf_erratum_contribution", &FIELDS[1..]),
            },
        ],
        receipts: vec![json!({
            "kind": RECEIPT_KIND,
            "version": 1,
            "policy_epoch": ATTRIBUTION_POLICY_V3.epoch,
            "policy_fingerprint": ATTRIBUTION_POLICY_V3.fingerprint,
            "subject_fingerprint": target.subject.fingerprint,
            "evidence": target.evidence,
        })],
    }
}

pub(crate) fn verify_generation(value: &AttributionGeneration) -> Result<()> {
    verify_generation_notice(value, ORIGINAL_NOTICE_BODY)
}

fn verify_generation_notice(value: &AttributionGeneration, notice_digest: &str) -> Result<()> {
    let [rfc_notice, _] = value.notices.as_slice() else {
        return Err(invalid());
    };
    let original = rfc_notice
        .text
        .strip_prefix(RFC_ATTRIBUTION)
        .ok_or_else(invalid)?;
    if original.len() as u64 > MAX_DEPENDENCY {
        return Err(invalid());
    }
    integrity::verify(notice_digest, original.as_bytes())?;
    if *value != build_generation(&pilot_target()?, original) {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_only_the_approved_export_and_member() {
        let reviewed = RfcErrataMember {
            export_capture: EXPORT_CAPTURE,
            export_body: EXPORT_BODY,
            member_body: MEMBER_BODY,
            rfc: RFC,
            errata_id: ERRATUM,
        };
        let target = pilot_target().unwrap();
        assert_eq!(approved_target(&reviewed).unwrap(), Some(target.clone()));
        for other in [
            RfcErrataMember {
                export_capture: EXPORT_BODY,
                ..reviewed
            },
            RfcErrataMember {
                export_body: MEMBER_BODY,
                ..reviewed
            },
            RfcErrataMember {
                member_body: EXPORT_BODY,
                ..reviewed
            },
            RfcErrataMember {
                rfc: RFC + 1,
                ..reviewed
            },
            RfcErrataMember {
                errata_id: ERRATUM + 1,
                ..reviewed
            },
        ] {
            assert_eq!(approved_target(&other).unwrap(), None);
        }
        let mut altered = target;
        altered.evidence["qualified_fields"] = json!(["orig_text"]);
        altered.subject.fingerprint = integrity::canonical_hash(&altered.evidence).unwrap();
        assert!(verify_target(&altered).is_err());
    }

    #[test]
    fn rejects_substituted_export_and_unreviewed_notice() {
        let target = pilot_target().unwrap();
        assert!(verify_bound_export(b"[]", &target, || Ok(())).is_err());
        assert_eq!(
            verify_bound_export(b"[]", &target, || Err(Error::new("cancelled", "Stopped.")))
                .unwrap_err()
                .code,
            "cancelled"
        );
        let generation = build_generation(&target, "unreviewed fixture notice");
        assert!(verify_generation(&generation).is_err());
        assert_eq!(generation.receipts[0]["kind"], RECEIPT_KIND);
        assert!(generation.receipts[0].get("status").is_none());
    }

    #[test]
    fn matches_complete_generation_and_rejects_changed_notice_or_receipt() {
        let target = pilot_target().unwrap();
        let notice = "Synthetic copyright notice for this fixture.\n";
        let notice_digest = integrity::hash(notice.as_bytes());
        let generation = build_generation(&target, notice);
        verify_generation_notice(&generation, &notice_digest).unwrap();

        let mut altered = generation.clone();
        altered.notices[0].text.push(' ');
        assert!(verify_generation_notice(&altered, &notice_digest).is_err());
        let mut altered = generation.clone();
        altered.notices[1].text.clear();
        assert!(verify_generation_notice(&altered, &notice_digest).is_err());
        let mut altered = generation.clone();
        altered.receipts[0]["evidence"]["member_body"] = json!(EXPORT_BODY);
        assert!(verify_generation_notice(&altered, &notice_digest).is_err());
        let mut altered = generation.clone();
        altered.receipts[0]["status"] = json!(200);
        assert!(verify_generation_notice(&altered, &notice_digest).is_err());
        let mut altered = generation;
        altered.policy_fingerprint = "unregistered-fixture".into();
        assert!(verify_generation_notice(&altered, &notice_digest).is_err());
    }
}
