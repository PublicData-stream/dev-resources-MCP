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
