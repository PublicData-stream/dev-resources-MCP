//! Inert, bounded projections of licensed W3C publication and repository evidence.
//! Parsing performs no filesystem or network I/O and evaluates no inspected code.
use devres_domain::{Error, Result};
use serde_json::Value;
use std::{
    cell::Cell,
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;

pub use crate::standards_processing::{
    MAX_INPUT, ProcessedDocument, ProcessingGap, Reference, Section, Symbol,
};
mod structured;
mod tabular;
mod xml;

const MAX_STRUCTURED_INPUT: usize = 4 * 1024 * 1024;
const MAX_ITEMS: usize = 100_000;
const MAX_SCALAR: usize = 64 * 1024;
const MAX_KEY: usize = 4096;

struct Budget {
    deadline: Instant,
    cancel: CancellationToken,
    nodes: Cell<usize>,
    exhausted: Cell<bool>,
}
impl Budget {
    fn new(cancel: CancellationToken) -> Self {
        Self {
            deadline: Instant::now() + Duration::from_secs(15),
            cancel,
            nodes: Cell::new(0),
            exhausted: Cell::new(false),
        }
    }
    fn check(&self) -> Result<()> {
        if self.cancel.is_cancelled() {
            return Err(Error::new("cancelled", "W3C processing canceled."));
        }
        if Instant::now() >= self.deadline {
            return Err(limit());
        }
        Ok(())
    }
    fn node(&self) -> Result<()> {
        self.check()?;
        let Some(count) = self.nodes.get().checked_add(1).filter(|v| *v <= MAX_ITEMS) else {
            self.exhausted.set(true);
            return Err(limit());
        };
        self.nodes.set(count);
        Ok(())
    }
}
fn limit() -> Error {
    Error::capacity("W3C processing bounds exceeded.")
}
fn malformed() -> Error {
    Error::integrity("Malformed W3C source representation.")
}
fn diagnostic(mut error: Error) -> Error {
    error.message = error.message.replace("WHATWG", "W3C");
    error
}
fn raw_gap(format: &str, code: &str, message: &str) -> ProcessedDocument {
    let mut document = ProcessedDocument {
        format: format.into(),
        ..Default::default()
    };
    document.gap(code, message);
    document
}
fn plain(
    path: &str,
    source: &str,
    format: &str,
    gap: Option<(&str, &str)>,
    budget: &Budget,
) -> Result<ProcessedDocument> {
    let title = path.rsplit('/').next().unwrap_or(path).to_owned();
    let mut sections = Vec::new();
    // UTF-8 safe source chunks bound both individual objects and paging overhead.
    let mut start = 0;
    while start < source.len() {
        budget.check()?;
        let mut end = start.saturating_add(MAX_SCALAR).min(source.len());
        while !source.is_char_boundary(end) {
            end -= 1;
        }
        if sections.len() >= MAX_ITEMS {
            return Err(limit());
        }
        sections.push(Section {
            anchor: format!("source-{}", sections.len()),
            title: title.clone(),
            text: source[start..end].into(),
        });
        start = end;
    }
    let mut document = ProcessedDocument {
        format: format.into(),
        title,
        text: source.into(),
        sections,
        ..Default::default()
    };
    if let Some((code, message)) = gap {
        document.gap(code, message);
    }
    if source.trim().is_empty() {
        document.gap(
            "publication_unavailable",
            "The captured representation contains no published specification content.",
        );
    }
    document.validate().map_err(diagnostic)?;
    Ok(document)
}
fn data_document(
    path: &str,
    value: Value,
    format: &str,
    budget: &Budget,
) -> Result<ProcessedDocument> {
    let mut document = ProcessedDocument {
        format: format.into(),
        title: path.rsplit('/').next().unwrap_or(path).into(),
        ..Default::default()
    };
    fn walk(
        value: &Value,
        pointer: String,
        doc: &mut ProcessedDocument,
        budget: &Budget,
        emitted_bytes: &mut usize,
    ) -> Result<()> {
        budget.check()?;
        if pointer.len() > MAX_KEY || doc.sections.len() >= MAX_ITEMS {
            return Err(limit());
        }
        let title = if pointer.is_empty() {
            "/".into()
        } else {
            pointer.clone()
        };
        let text = match value {
            Value::Object(_) => "object".to_owned(),
            Value::Array(_) => "array".to_owned(),
            Value::String(value) => value.clone(),
            value => value.to_string(),
        };
        if text.len() > MAX_SCALAR {
            return Err(limit());
        }
        *emitted_bytes = emitted_bytes
            .checked_add(title.len().saturating_mul(3))
            .and_then(|value| value.checked_add(text.len().saturating_mul(2)))
            .and_then(|value| value.checked_add(16))
            .filter(|value| *value <= MAX_INPUT * 3)
            .ok_or_else(limit)?;
        if !doc.text.is_empty() {
            doc.text.push('\n');
        }
        doc.text.push_str(&title);
        doc.text.push_str(": ");
        doc.text.push_str(&text);
        doc.sections.push(Section {
            anchor: format!("data:{pointer}"),
            title,
            text,
        });
        match value {
            Value::Object(map) => {
                for (key, value) in map {
                    let key = key.replace('~', "~0").replace('/', "~1");
                    walk(
                        value,
                        format!("{pointer}/{key}"),
                        doc,
                        budget,
                        emitted_bytes,
                    )?;
                }
            }
            Value::Array(values) => {
                for (index, value) in values.iter().enumerate() {
                    walk(
                        value,
                        format!("{pointer}/{index}"),
                        doc,
                        budget,
                        emitted_bytes,
                    )?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    walk(&value, String::new(), &mut document, budget, &mut 0)?;
    document.gap("structured_semantics_unasserted", "Structural source navigation does not assert schema validation, JSON-LD expansion, graph inference, or executable semantics.");
    document.validate().map_err(diagnostic)?;
    Ok(document)
}

/// Pure projection; original bytes remain the caller's independently retained evidence.
pub fn process_document(
    path: &str,
    bytes: &[u8],
    cancel: CancellationToken,
) -> Result<ProcessedDocument> {
    if bytes.len() > MAX_INPUT || path.len() > MAX_KEY {
        return Err(limit());
    }
    let budget = Budget::new(cancel.clone());
    budget.check()?;
    let source = match std::str::from_utf8(bytes) {
        Ok(source) if !source.contains('\0') => source,
        _ => {
            return Ok(raw_gap(
                "raw",
                "unsupported_encoding",
                "Projection requires supported UTF-8 text; exact original bytes remain separate raw evidence.",
            ));
        }
    };
    let lower = path.to_ascii_lowercase();
    let extension = lower.rsplit('.').next().unwrap_or("");
    let structured = matches!(
        extension,
        "xhtml"
            | "xht"
            | "xml"
            | "svg"
            | "xsd"
            | "rdf"
            | "rng"
            | "json"
            | "jsonld"
            | "json-ld"
            | "yaml"
            | "yml"
            | "csv"
            | "tsv"
    );
    if structured && bytes.len() > MAX_STRUCTURED_INPUT {
        return plain(
            path,
            source,
            "text",
            Some((
                "structured_projection_limit",
                "Structural parsing exceeded its input bound; only bounded source-text navigation is provided.",
            )),
            &budget,
        );
    }
    let result = match extension {
        "xhtml" | "xht" => xml::project(path, source, true, &budget),
        "xml" | "svg" | "xsd" | "rdf" | "rng" => xml::project(path, source, false, &budget),
        "json" | "jsonld" | "json-ld" => structured::json(bytes, &budget)
            .and_then(|value| data_document(path, value, "json", &budget)),
        "yaml" | "yml" => structured::yaml(source, &budget)
            .and_then(|value| data_document(path, value, "yaml", &budget)),
        "csv" | "tsv" => tabular::project(path, source, extension == "tsv", &budget),
        "ttl" | "n3" | "nt" | "nq" | "trig" | "abnf" | "bnf" | "ebnf" | "rnc" | "dtd"
        | "grammar" | "webidl" => {
            if extension == "webidl" {
                crate::standards_processing::process_document("source.idl", bytes, cancel)
                    .map_err(diagnostic)
            } else {
                plain(
                    path,
                    source,
                    "text",
                    Some((
                        "structured_semantics_unasserted",
                        "The original source is projected as text; RDF, schema, and grammar semantics are unasserted.",
                    )),
                    &budget,
                )
            }
        }
        _ => match crate::standards_processing::process_document(path, bytes, cancel) {
            Ok(document) => Ok(document),
            Err(error) if error.code == "invalid_input" => Ok(raw_gap(
                "raw",
                "unsupported_format",
                "No supported inert projection exists for this representation; original bytes remain separate raw evidence.",
            )),
            Err(error) => Err(diagnostic(error)),
        },
    };
    let document = match result {
        Err(error) if structured && error.code == "capacity" => {
            budget.check()?;
            plain(
                path,
                source,
                "text",
                Some((
                    "structured_projection_limit",
                    "Structural parsing exceeded a processing bound; only bounded source-text navigation is provided.",
                )),
                &budget,
            )?
        }
        Err(error) if error.code == "unresolved_xml_entity" => raw_gap(
            "xml",
            "unresolved_xml_entity",
            "Custom XML entities and internal entity declarations are not expanded; source bytes remain separate raw evidence.",
        ),
        value => value?,
    };
    budget.check()?;
    document.validate().map_err(diagnostic)?;
    Ok(document)
}

/// Uses the fixed first-party helper and retains the shared helper's process limits.
pub async fn process_pdf(bytes: &[u8], cancel: CancellationToken) -> Result<ProcessedDocument> {
    crate::standards_processing::process_pdf(bytes, cancel)
        .await
        .map_err(diagnostic)
}

#[cfg(test)]
mod tests;
