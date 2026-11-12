//! One serialization envelope for parser admission and persisted enrichment.
use devres_domain::{Error, Result};
use serde_json::{Value, json};

pub(crate) const MAX_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_ROWS: usize = 1000;
const SIZED_INTEGRITY: &str =
    "blake3:0000000000000000000000000000000000000000000000000000000000000000";

pub(crate) fn row(id: &str, value: &Value, integrity: &str) -> Result<Value> {
    if !integrity.starts_with("blake3:") || !devres_domain::valid_content_id(integrity) {
        return Err(Error::integrity("Invalid enrichment integrity envelope."));
    }
    Ok(json!({"id":id,"value":value,"integrity":integrity}))
}

pub(crate) fn row_bytes(id: &str, value: &Value) -> Result<usize> {
    // Tagged BLAKE3 seals have a fixed serialized length. Use the same envelope
    // as storage so escaping, field names and seal overhead are all admitted.
    serde_json::to_vec(&row(id, value, SIZED_INTEGRITY)?)
        .map(|bytes| bytes.len())
        .map_err(|_| Error::integrity("Invalid enrichment serialization."))
}

/// V2 changes admission only; its selected values remain exact immutable strings.
pub(crate) fn selection(
    capture: &str,
) -> Result<devres_application::crate_corpus::EnrichmentSelection> {
    if !crate::integrity::valid_hash(capture) {
        return Err(Error::invalid("Invalid enrichment capture identity."));
    }
    let bytes = serde_json::to_vec(&json!([
        "crate-enrichment-derivation-v1",
        capture,
        super::dump::PROCESSOR
    ]))
    .map_err(|_| Error::integrity("Invalid enrichment derivation identity."))?;
    Ok(devres_application::crate_corpus::EnrichmentSelection {
        capture: capture.to_owned(),
        derivation: Some(crate::integrity::hash(&bytes)),
    })
}
pub(crate) fn validate_selection(
    selection: &devres_application::crate_corpus::EnrichmentSelection,
) -> Result<()> {
    if selection.derivation.is_none() {
        if crate::integrity::valid_hash(&selection.capture) {
            return Ok(());
        }
    } else if *selection == self::selection(&selection.capture)? {
        return Ok(());
    }
    Err(Error::integrity(
        "Enrichment derivation differs from its processor and capture.",
    ))
}

pub(crate) const MAX_READ_BYTES: usize = 2 * 1024 * 1024;
/// Only this closed metadata-read capacity class can become an index coverage gap.
pub(crate) fn read_limit(kind: &'static str) -> Error {
    Error::capacity("Metadata enrichment read bound exceeded.")
        .with_details(json!({"crate_enrichment_read_limit":kind}))
}
pub(crate) fn read_gap(error: &Error) -> Option<&'static str> {
    if error.code != "capacity" {
        return None;
    }
    let details = error.details.as_ref()?.as_object()?;
    if details.len() != 1 {
        return None;
    }
    match details.get("crate_enrichment_read_limit")?.as_str()? {
        "bytes" => Some("metadata_enrichment_exceeds_2MiB"),
        "relations" => Some("metadata_enrichment_relations_exceed_1024"),
        _ => None,
    }
}
