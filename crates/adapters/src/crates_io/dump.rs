//! Streaming import of the public crates.io CSV dump. SQL is inert evidence.
//!
//! Raw artifacts are retained by the caller. Rows are staged under their artifact
//! and become enrichment only after the complete tar/gzip stream passes checks.
use devres_application::collection::{self, CollectorStatus, LimitKind, Phase, ProgressKind};
use devres_application::crate_corpus::CrateCorpusStore;
#[cfg(test)]
use devres_application::crate_corpus::EnrichmentSelection;
use devres_domain::{Error, Result};
use flate2::read::MultiGzDecoder;
use serde_json::{Map, Value, json};
use std::{
    collections::{BTreeMap, HashSet},
    io::{self, BufRead, BufReader, Read},
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

const MAX_EXPANDED: u64 = 512 * 1024 * 1024 * 1024;
const MAX_ROW: usize = 2 * 1024 * 1024;
const MAX_FIELD: usize = 1024 * 1024;
const MAX_METADATA: usize = 1024 * 1024;
pub const PROCESSOR: &str = "crates-dump-v2";
const MAX_COLUMNS: usize = 128;
const MAX_BATCH: usize = super::enrichment::MAX_BYTES;
const CHUNK: usize = 64 * 1024;
const MAX_MEMBERS: usize = 1000;

fn malformed() -> Error {
    Error::integrity("Malformed public crates.io database dump.")
}
fn bounds(kind: LimitKind, observed: u64, maximum: u64) -> Error {
    collection::limited(
        Error::capacity("Database dump processing bounds exceeded."),
        Phase::CsvParsing,
        kind,
        Some(observed),
        Some(maximum),
    )
}
pub(crate) type Diagnostics = Arc<Mutex<CollectorStatus>>;
struct Budget {
    cancel: CancellationToken,
    deadline: Instant,
    diagnostics: Option<Diagnostics>,
    csv_diagnostic: Arc<Mutex<Option<CsvDiagnostic>>>,
    csv_measurement: Arc<Mutex<Option<CsvMeasurement>>>,
    measure_first_rejection: bool,
    legacy_admission: bool,
    inspection: bool,
    max_expanded: u64,
    max_compressed: u64,
}
impl Budget {
    fn progress(&self, kind: ProgressKind, value: u64) {
        if let Some(diagnostics) = &self.diagnostics
            && let Ok(mut status) = diagnostics.lock()
        {
            status.progress(kind, value);
        }
    }
    fn check(&self) -> Result<()> {
        if self.cancel.is_cancelled() {
            return Err(Error::new(
                "cancelled",
                "Database dump import was canceled.",
            ));
        }
        if Instant::now() >= self.deadline {
            return Err(collection::limited(
                Error::capacity("Database dump processing deadline exceeded."),
                Phase::CsvParsing,
                LimitKind::Deadline,
                None,
                None,
            ));
        }
        Ok(())
    }
}
struct Expanded<'a, R> {
    inner: R,
    bytes: u64,
    budget: &'a Budget,
    failed: Option<Error>,
}
impl<R: Read> Read for Expanded<'_, R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if let Err(e) = self.budget.check() {
            self.failed = Some(e);
            return Err(io::Error::other("dump budget"));
        }
        let max = out.len().min(CHUNK).min(
            self.budget
                .max_expanded
                .saturating_sub(self.bytes)
                .saturating_add(1) as usize,
        );
        let n = self.inner.read(&mut out[..max])?;
        self.bytes += n as u64;
        self.budget
            .progress(ProgressKind::ExpandedBytes, self.bytes);
        if self.bytes > self.budget.max_expanded {
            self.failed = Some(bounds(
                LimitKind::ExpandedBytes,
                self.bytes,
                self.budget.max_expanded,
            ));
            return Err(io::Error::other("dump expansion"));
        }
        Ok(n)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum QuoteState {
    Start,
    Plain,
    Quoted,
    AfterQuote,
}
/// csv-core intentionally accepts malformed CSV. This companion finite-state
/// check admits conventional quoted CSV only, including embedded CR/LF.
struct Grammar {
    state: QuoteState,
    raw: usize,
    completed_raw: usize,
    pending_cr: bool,
}
impl Grammar {
    fn new() -> Self {
        Self {
            state: QuoteState::Start,
            raw: 0,
            completed_raw: 0,
            pending_cr: false,
        }
    }
    fn end_record(&mut self, delimiter: u8) {
        if self.pending_cr && delimiter == b'\n' && self.raw == 1 {
            self.completed_raw += 1;
        } else {
            self.completed_raw = self.raw;
        }
        self.pending_cr = delimiter == b'\r';
        self.raw = 0;
    }
    fn feed(&mut self, bytes: &[u8]) -> Result<()> {
        for &b in bytes {
            self.raw += 1;
            if self.raw > MAX_ROW {
                return Err(bounds(
                    LimitKind::CsvRowBytes,
                    self.raw as u64,
                    MAX_ROW as u64,
                ));
            }
            match (self.state, b) {
                (QuoteState::Start, b'"') => self.state = QuoteState::Quoted,
                (QuoteState::Start, b',') => {}
                (QuoteState::Start, b'\r' | b'\n') => {
                    self.end_record(b);
                }
                (QuoteState::Start, _) => self.state = QuoteState::Plain,
                (QuoteState::Plain, b'"') => return Err(malformed()),
                (QuoteState::Plain, b',') => self.state = QuoteState::Start,
                (QuoteState::Plain, b'\r' | b'\n') => {
                    self.state = QuoteState::Start;
                    self.end_record(b);
                }
                (QuoteState::Plain, _) => {}
                (QuoteState::Quoted, b'"') => self.state = QuoteState::AfterQuote,
                (QuoteState::Quoted, _) => {}
                (QuoteState::AfterQuote, b'"') => self.state = QuoteState::Quoted,
                (QuoteState::AfterQuote, b',') => self.state = QuoteState::Start,
                (QuoteState::AfterQuote, b'\r' | b'\n') => {
                    self.state = QuoteState::Start;
                    self.end_record(b);
                }
                (QuoteState::AfterQuote, _) => return Err(malformed()),
            }
        }
        Ok(())
    }
    fn finish(&self) -> Result<()> {
        if self.state == QuoteState::Quoted {
            Err(malformed())
        } else {
            Ok(())
        }
    }
}

fn columns(table: &str) -> Option<(&'static [&'static str], &'static [&'static str])> {
    Some(match table {
        "crates" => (
            &["id", "name"],
            &[
                "id",
                "name",
                "updated_at",
                "created_at",
                "description",
                "homepage",
                "documentation",
                "readme",
                "repository",
                "max_upload_size",
                "max_features",
                "trustpub_only",
            ],
        ),
        "versions" => (
            &["id", "crate_id", "num"],
            &[
                "id",
                "crate_id",
                "num",
                "num_no_build",
                "updated_at",
                "created_at",
                "downloads",
                "features",
                "yanked",
                "license",
                "crate_size",
                "published_by",
                "tar_sha256",
                "links",
                "rust_version",
                "has_lib",
                "bin_names",
                "edition",
                "description",
                "homepage",
                "documentation",
                "repository",
                "categories",
                "keywords",
                "zip_sha256",
                "zip_json_sha256",
            ],
        ),
        "keywords" => (
            &["id", "keyword"],
            &["id", "keyword", "crates_cnt", "created_at"],
        ),
        "categories" => (
            &["id", "category", "slug"],
            &[
                "id",
                "category",
                "slug",
                "description",
                "crates_cnt",
                "created_at",
                "path",
            ],
        ),
        "crates_keywords" => (&["crate_id", "keyword_id"], &["crate_id", "keyword_id"]),
        "crates_categories" => (&["crate_id", "category_id"], &["crate_id", "category_id"]),
        "dependencies" => (
            &["id", "version_id", "crate_id", "req"],
            &[
                "id",
                "version_id",
                "crate_id",
                "req",
                "optional",
                "default_features",
                "features",
                "target",
                "kind",
                "explicit_name",
            ],
        ),
        "crate_downloads" => (&["crate_id", "downloads"], &["crate_id", "downloads"]),
        _ => return None,
    })
}
fn numeric<'a>(row: &'a Map<String, Value>, key: &str) -> Result<&'a str> {
    let value = row.get(key).and_then(Value::as_str).ok_or_else(malformed)?;
    if value.is_empty()
        || !value.bytes().all(|b| b.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
        || value.parse::<i64>().is_err()
    {
        return Err(malformed());
    }
    Ok(value)
}
fn row_key(table: &str, row: &Map<String, Value>) -> Result<String> {
    for key in ["id", "crate_id", "version_id", "keyword_id", "category_id"] {
        if row.contains_key(key) {
            numeric(row, key)?;
        }
    }
    match table {
        "crates" => crate::crates_io::packages::validate_name(
            row.get("name")
                .and_then(Value::as_str)
                .ok_or_else(malformed)?,
        )
        .map_err(|_| malformed())?,
        "versions" => {
            crate::crates_io::packages::validate_version(
                row.get("num")
                    .and_then(Value::as_str)
                    .ok_or_else(malformed)?,
            )
            .map_err(|_| malformed())?;
        }
        _ => {}
    }
    Ok(match table {
        "crates_keywords" => format!(
            "{}:{}",
            numeric(row, "crate_id")?,
            numeric(row, "keyword_id")?
        ),
        "crates_categories" => format!(
            "{}:{}",
            numeric(row, "crate_id")?,
            numeric(row, "category_id")?
        ),
        "crate_downloads" => numeric(row, "crate_id")?.to_owned(),
        _ => numeric(row, "id")?.to_owned(),
    })
}
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CsvTable {
    Crates,
    Versions,
    Keywords,
    Categories,
    CratesKeywords,
    CratesCategories,
    Dependencies,
    CrateDownloads,
}
impl CsvTable {
    fn parse(table: &str) -> Option<Self> {
        Some(match table {
            "crates" => Self::Crates,
            "versions" => Self::Versions,
            "keywords" => Self::Keywords,
            "categories" => Self::Categories,
            "crates_keywords" => Self::CratesKeywords,
            "crates_categories" => Self::CratesCategories,
            "dependencies" => Self::Dependencies,
            "crate_downloads" => Self::CrateDownloads,
            _ => return None,
        })
    }
}
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CsvReason {
    FieldBytes,
    RowBytes,
    Columns,
    Quoting,
    Utf8,
    Nul,
    Header,
    Identity,
    Validation,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CsvDiagnostic {
    pub version: u32,
    pub table: CsvTable,
    /// Zero is the header; data records start at one.
    pub row: u64,
    /// Zero-based column position; never an upstream header string.
    pub column: u64,
    pub selected: bool,
    pub reason: CsvReason,
    pub observed: Option<u64>,
    pub maximum: Option<u64>,
}

/// A closed classification of the original rejected field; upstream names are never copied.
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CsvFieldKind {
    Features,
    Readme,
    Description,
    OtherSelected,
    Ignored,
}
impl CsvFieldKind {
    fn classify(name: Option<&str>, selected: bool) -> Self {
        if !selected {
            return Self::Ignored;
        }
        match name {
            Some("features") => Self::Features,
            Some("readme") => Self::Readme,
            Some("description") => Self::Description,
            _ => Self::OtherSelected,
        }
    }
}
/// Diagnostic-only continuation of one rejected record. Incomplete counts are lower bounds.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CsvMeasurement {
    pub version: u32,
    pub original: CsvDiagnostic,
    pub field_kind: CsvFieldKind,
    pub original_threshold: u64,
    pub field_bytes: u64,
    pub raw_row_bytes: u64,
    pub decoded_row_bytes: u64,
    pub field_complete: bool,
    pub field_valid: bool,
    pub row_complete: bool,
    pub row_valid: bool,
    pub failure: Option<CsvDiagnostic>,
}
fn diagnostic_error(mut diagnostic: CsvDiagnostic, error: &Error) -> CsvDiagnostic {
    if let Some(context) = collection::context(error)
        && let Some(limit) = context.limit
    {
        diagnostic.reason = match limit.kind {
            LimitKind::CsvFieldBytes => CsvReason::FieldBytes,
            LimitKind::CsvRowBytes => CsvReason::RowBytes,
            LimitKind::CsvColumns => CsvReason::Columns,
            _ => CsvReason::Validation,
        };
        diagnostic.observed = limit.observed;
        diagnostic.maximum = limit.maximum;
    }
    diagnostic
}

/// Validate UTF-8 incrementally, retaining at most one incomplete scalar.
#[derive(Default)]
struct FieldUtf8 {
    tail: Vec<u8>,
}
impl FieldUtf8 {
    fn feed(&mut self, bytes: &[u8]) -> Result<()> {
        let mut joined = std::mem::take(&mut self.tail);
        joined.extend_from_slice(bytes);
        match std::str::from_utf8(&joined) {
            Ok(_) => {}
            Err(error) if error.error_len().is_none() => {
                self.tail.extend_from_slice(&joined[error.valid_up_to()..]);
            }
            Err(_) => return Err(malformed()),
        }
        Ok(())
    }
    fn finish(&self) -> Result<()> {
        if self.tail.is_empty() {
            Ok(())
        } else {
            Err(malformed())
        }
    }
}

fn csv<R: Read>(
    input: R,
    table: &str,
    budget: &Budget,
    mut emit: impl FnMut(String, Value) -> Result<()>,
) -> Result<Value> {
    let (required, allowed) = columns(table).ok_or_else(malformed)?;
    let mut input = BufReader::with_capacity(CHUNK, input);
    let mut parser = csv_core::Reader::new();
    let mut grammar = Grammar::new();
    let mut output = [0u8; CHUNK];
    let mut value = Vec::new();
    let mut utf8 = FieldUtf8::default();
    let mut field_bytes = 0usize;
    let mut row_bytes = 0usize;
    let mut fields = 0usize;
    let mut rows = 0u64;
    let mut row = Map::new();
    let mut header: Option<Vec<String>> = None;
    let mut header_values = Vec::new();
    let mut diagnostic = CsvDiagnostic {
        version: 1,
        table: CsvTable::parse(table).ok_or_else(malformed)?,
        row: 0,
        column: 0,
        selected: true,
        reason: CsvReason::Validation,
        observed: None,
        maximum: None,
    };
    let mut measurement: Option<CsvMeasurement> = None;
    let mut original_rejection: Option<Error> = None;
    let result = (|| -> Result<Value> {
        loop {
            diagnostic.row = if header.is_none() { 0 } else { rows + 1 };
            diagnostic.column = fields as u64;
            let selected = header.as_ref().is_none_or(|names| {
                names
                    .get(fields)
                    .is_some_and(|name| allowed.contains(&name.as_str()))
            });
            diagnostic.selected = selected;
            budget.check()?;
            diagnostic.reason = CsvReason::Validation;
            let available = input.fill_buf().map_err(|_| malformed())?;
            // After the first rejection only the rejected record is examined. A
            // byte at a time makes a later malformed/bound failure's prefix exact.
            let limit = if measurement.is_some() {
                1
            } else if budget.inspection
                && budget.measure_first_rejection
                && (selected || budget.legacy_admission)
            {
                // Stop the lookahead precisely at the first excess decoded byte.
                // A later malformed suffix must not hide the original threshold.
                MAX_FIELD.saturating_sub(field_bytes).saturating_add(1)
            } else {
                available.len()
            };
            let bytes = &available[..available.len().min(limit)];
            let eof = bytes.is_empty();
            let (status, nin, nout) = parser.read_field(bytes, &mut output);
            field_bytes += nout;
            row_bytes += nout;
            diagnostic.reason = CsvReason::Quoting;
            grammar.feed(&bytes[..nin])?;
            if eof {
                grammar.finish()?;
            }
            input.consume(nin);
            let field_end = matches!(status, csv_core::ReadFieldResult::Field { .. });
            let row_end = matches!(
                status,
                csv_core::ReadFieldResult::Field { record_end: true }
            );
            let mut raw_row_bytes = if row_end && !eof {
                grammar.completed_raw
            } else {
                grammar.raw
            };
            // csv-core can leave LF pending after a CR terminator. Account for
            // that same record's LF without parsing the following record.
            if budget.inspection
                && budget.measure_first_rejection
                && row_end
                && grammar.pending_cr
                && input.fill_buf().map_err(|_| malformed())?.first() == Some(&b'\n')
            {
                raw_row_bytes += 1;
            }
            if row_bytes > MAX_ROW {
                return Err(bounds(
                    LimitKind::CsvRowBytes,
                    row_bytes.max(raw_row_bytes) as u64,
                    MAX_ROW as u64,
                ));
            }
            if (selected || budget.legacy_admission)
                && field_bytes > MAX_FIELD
                && measurement.is_none()
            {
                let error = bounds(
                    LimitKind::CsvFieldBytes,
                    field_bytes as u64,
                    MAX_FIELD as u64,
                );
                if !(budget.inspection && budget.measure_first_rejection) {
                    return Err(error);
                }
                let original = diagnostic_error(diagnostic.clone(), &error);
                measurement = Some(CsvMeasurement {
                    version: 1,
                    original,
                    field_kind: CsvFieldKind::classify(
                        header
                            .as_ref()
                            .and_then(|names| names.get(fields))
                            .map(String::as_str),
                        selected,
                    ),
                    original_threshold: MAX_FIELD as u64,
                    field_bytes: field_bytes as u64,
                    raw_row_bytes: raw_row_bytes as u64,
                    decoded_row_bytes: row_bytes as u64,
                    field_complete: false,
                    field_valid: false,
                    row_complete: false,
                    row_valid: false,
                    failure: None,
                });
                original_rejection = Some(error);
            }
            if let Some(observation) = &mut measurement {
                observation.raw_row_bytes = raw_row_bytes as u64;
                observation.decoded_row_bytes = row_bytes as u64;
                if raw_row_bytes > MAX_ROW {
                    return Err(bounds(
                        LimitKind::CsvRowBytes,
                        raw_row_bytes as u64,
                        MAX_ROW as u64,
                    ));
                }
                if observation.original.column == fields as u64 && !observation.field_complete {
                    observation.field_bytes = field_bytes as u64;
                    observation.field_complete = field_end;
                }
                observation.row_complete = row_end;
            }
            diagnostic.reason = CsvReason::Nul;
            if output[..nout].contains(&0) {
                return Err(malformed());
            }
            diagnostic.reason = CsvReason::Utf8;
            utf8.feed(&output[..nout])?;
            if selected {
                value.extend_from_slice(&output[..nout]);
            }
            match status {
                csv_core::ReadFieldResult::End => break,
                csv_core::ReadFieldResult::Field { record_end } => {
                    utf8.finish()?;
                    if let Some(observation) = &mut measurement
                        && observation.original.column == fields as u64
                    {
                        observation.field_valid = true;
                    }
                    fields += 1;
                    if fields > MAX_COLUMNS {
                        return Err(bounds(
                            LimitKind::CsvColumns,
                            fields as u64,
                            MAX_COLUMNS as u64,
                        ));
                    }
                    if let Some(names) = &header {
                        if selected {
                            let name = names.get(fields - 1).ok_or_else(malformed)?;
                            let text = String::from_utf8(std::mem::take(&mut value))
                                .map_err(|_| malformed())?;
                            row.insert(name.clone(), json!(text));
                        }
                    } else {
                        diagnostic.reason = CsvReason::Header;
                        let text = String::from_utf8(std::mem::take(&mut value))
                            .map_err(|_| malformed())?;
                        if text.is_empty()
                            || text.len() > 128
                            || !text
                                .bytes()
                                .all(|b| b.is_ascii_lowercase() || b == b'_' || b.is_ascii_digit())
                        {
                            return Err(malformed());
                        }
                        header_values.push(text);
                    }
                    field_bytes = 0;
                    utf8 = FieldUtf8::default();
                    if record_end {
                        if let Some(names) = &header {
                            if fields != names.len() {
                                diagnostic.reason = CsvReason::Columns;
                                return Err(malformed());
                            }
                            diagnostic.reason = CsvReason::Identity;
                            let key = row_key(table, &row)?;
                            let value = Value::Object(std::mem::take(&mut row));
                            if !budget.inspection {
                                emit(key, value)?;
                            }
                            rows += 1;
                        } else {
                            let unique = header_values
                                .iter()
                                .map(String::as_str)
                                .collect::<HashSet<_>>();
                            if unique.len() != header_values.len()
                                || required.iter().any(|name| !unique.contains(name))
                            {
                                return Err(malformed());
                            }
                            header = Some(std::mem::take(&mut header_values));
                        }
                        if let Some(observation) = &mut measurement {
                            observation.row_valid = true;
                            return Err(original_rejection.clone().ok_or_else(malformed)?);
                        }
                        fields = 0;
                        row_bytes = 0;
                    }
                }
                csv_core::ReadFieldResult::InputEmpty | csv_core::ReadFieldResult::OutputFull => {}
            }
        }
        let header = header.as_ref().ok_or_else(malformed)?;
        Ok(
            json!({"rows":rows,"columns":header,"value_encoding":"CSV fields retained as strings; no SQL execution or inferred null semantics"}),
        )
    })();
    if let Some(mut observation) = measurement {
        if !observation.row_valid {
            // A failing feed may stop inside its single-byte step. Keep the
            // observed prefix counts, never call a truncated record complete.
            if !observation.row_complete {
                observation.raw_row_bytes = observation.raw_row_bytes.max(grammar.raw as u64);
            }
            observation.decoded_row_bytes = row_bytes as u64;
            if !observation.field_complete && observation.original.column == fields as u64 {
                observation.field_bytes = field_bytes as u64;
            }
            if let Err(error) = &result
                && matches!(error.code.as_str(), "integrity" | "capacity")
            {
                let failure = diagnostic_error(diagnostic.clone(), error);
                if matches!(
                    failure.reason,
                    CsvReason::RowBytes
                        | CsvReason::Columns
                        | CsvReason::Quoting
                        | CsvReason::Utf8
                        | CsvReason::Nul
                        | CsvReason::Header
                        | CsvReason::Identity
                ) {
                    observation.failure = Some(failure);
                }
            }
        }
        if let Ok(mut retained) = budget.csv_diagnostic.lock() {
            *retained = Some(observation.original.clone());
        }
        if let Ok(mut retained) = budget.csv_measurement.lock() {
            *retained = Some(observation);
        }
    } else if let Err(error) = &result
        && matches!(error.code.as_str(), "integrity" | "capacity")
        && let Ok(mut retained) = budget.csv_diagnostic.lock()
    {
        *retained = Some(diagnostic_error(diagnostic, error));
    }
    result
}

struct Batch {
    kind: String,
    rows: Vec<(String, Value)>,
}
struct Batches<'a> {
    sender: &'a mpsc::Sender<Batch>,
    kind: String,
    rows: Vec<(String, Value)>,
    bytes: usize,
    budget: &'a Budget,
}
impl Batches<'_> {
    fn push(&mut self, key: String, value: Value) -> Result<()> {
        self.budget.check()?;
        let size = super::enrichment::row_bytes(&key, &value)?;
        if size > MAX_BATCH - 2 {
            return Err(bounds(
                LimitKind::StorageBatchBytes,
                size as u64 + 2,
                MAX_BATCH as u64,
            ));
        }
        if !self.rows.is_empty()
            && (self.rows.len() >= super::enrichment::MAX_ROWS
                || self.bytes + size + self.rows.len() + 2 > MAX_BATCH)
        {
            self.flush()?;
        }
        self.bytes += size;
        self.rows.push((key, value));
        Ok(())
    }
    fn flush(&mut self) -> Result<()> {
        self.budget.check()?;
        if !self.rows.is_empty() {
            self.sender
                .blocking_send(Batch {
                    kind: self.kind.clone(),
                    rows: std::mem::take(&mut self.rows),
                })
                .map_err(|_| Error::new("cancelled", "Database dump consumer stopped."))?;
            self.bytes = 0;
        }
        Ok(())
    }
}
fn date_root(s: &str) -> bool {
    s.len() >= 10
        && s.len() <= 32
        && s.as_bytes().get(4) == Some(&b'-')
        && s.as_bytes().get(7) == Some(&b'-')
        && s.bytes().enumerate().all(|(i, b)| {
            if i == 4 || i == 7 {
                b == b'-'
            } else if i < 10 {
                b.is_ascii_digit()
            } else {
                b.is_ascii_digit() || b == b'-'
            }
        })
}
fn relative<'a>(path: &'a str, layout: &mut Option<String>) -> Result<&'a str> {
    if !crate::archive::valid_relative_path(path) {
        return Err(malformed());
    }
    let (root, relative) = match path.split_once('/') {
        Some((root, rest)) if date_root(root) => (root, rest),
        _ if date_root(path) => (path, ""),
        _ => ("", path),
    };
    if let Some(previous) = layout {
        if previous != root {
            return Err(malformed());
        }
    } else {
        *layout = Some(root.to_owned());
    }
    if relative.split('/').count() > 2 {
        return Err(malformed());
    }
    Ok(relative)
}
fn drain(reader: &mut impl Read, budget: &Budget) -> Result<()> {
    let mut chunk = [0u8; CHUNK];
    loop {
        budget.check()?;
        if reader.read(&mut chunk).map_err(|_| malformed())? == 0 {
            return Ok(());
        }
    }
}
fn process(
    path: PathBuf,
    artifact: &str,
    budget: &Budget,
    sender: &mpsc::Sender<Batch>,
) -> Result<Value> {
    budget.check()?;
    let input = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| Error::unavailable("Database dump artifact could not be opened."))?;
    let metadata = input.metadata().map_err(|_| malformed())?;
    if !metadata.is_file() {
        return Err(Error::integrity(
            "Database dump artifact is not a regular file.",
        ));
    }
    if metadata.len() > budget.max_compressed {
        return Err(bounds(
            LimitKind::CompressedBytes,
            metadata.len(),
            budget.max_compressed,
        ));
    }
    let mut expanded = Expanded {
        inner: MultiGzDecoder::new(BufReader::with_capacity(
            CHUNK,
            input.take(budget.max_compressed),
        )),
        bytes: 0,
        budget,
        failed: None,
    };
    let mut tables = BTreeMap::new();
    let mut metadata = None;
    let mut seen = HashSet::new();
    let mut layout = None;
    let parsing = (|| -> Result<()> {
        let mut archive = tar::Archive::new(&mut expanded);
        for (count, entry) in archive
            .entries()
            .map_err(|_| malformed())?
            .raw(true)
            .enumerate()
        {
            budget.check()?;
            if count >= MAX_MEMBERS {
                return Err(bounds(
                    LimitKind::TarMembers,
                    count as u64 + 1,
                    MAX_MEMBERS as u64,
                ));
            }
            budget.progress(ProgressKind::Members, count as u64 + 1);
            let mut entry = entry.map_err(|_| malformed())?;
            let kind = entry.header().entry_type();
            if !kind.is_file() && !kind.is_dir() {
                return Err(Error::integrity(
                    "Database dump links and special members are unsupported.",
                ));
            }
            let raw = entry.path_bytes();
            let original = std::str::from_utf8(&raw).map_err(|_| malformed())?;
            let name = original.strip_suffix('/').unwrap_or(original).to_owned();
            let name = relative(&name, &mut layout)?;
            if !seen.insert(name.to_owned()) {
                return Err(Error::integrity("Duplicate database dump member."));
            }
            if kind.is_dir() {
                if !name.is_empty() && name != "data" {
                    return Err(malformed());
                }
                if entry.size() != 0 {
                    return Err(malformed());
                }
                continue;
            }
            if let Some(table) = name
                .strip_prefix("data/")
                .and_then(|s| s.strip_suffix(".csv"))
            {
                if table.is_empty() || !table.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') {
                    return Err(malformed());
                }
                if columns(table).is_some() {
                    let mut batches = Batches {
                        sender,
                        kind: table.into(),
                        rows: Vec::new(),
                        bytes: 0,
                        budget,
                    };
                    let summary = csv(&mut entry, table, budget, |key, row| {
                        if budget.inspection {
                            Ok(())
                        } else {
                            batches.push(key, row)
                        }
                    })?;
                    batches.flush()?;
                    tables.insert(table.to_owned(), summary);
                } else {
                    drain(&mut entry, budget)?;
                }
            } else if name == "metadata.json" {
                if entry.size() > MAX_METADATA as u64 {
                    return Err(bounds(
                        LimitKind::MetadataBytes,
                        entry.size(),
                        MAX_METADATA as u64,
                    ));
                }
                let mut body = Vec::new();
                entry.read_to_end(&mut body).map_err(|_| malformed())?;
                let value: Value = serde_json::from_slice(&body).map_err(|_| malformed())?;
                if !value.is_object() {
                    return Err(malformed());
                }
                metadata = Some(value);
            } else if !name.contains('/')
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
            {
                drain(&mut entry, budget)?;
            } else {
                return Err(malformed());
            }
        }
        Ok(())
    })();
    if let Err(error) = parsing {
        return Err(expanded.failed.take().unwrap_or(error));
    }
    // Force all concatenated gzip members/trailers through their CRC checks.
    let validation = (|| -> Result<()> {
        let mut chunk = [0u8; CHUNK];
        loop {
            budget.check()?;
            let n = expanded.read(&mut chunk).map_err(|_| malformed())?;
            if n == 0 {
                break;
            }
            if chunk[..n].iter().any(|b| *b != 0) {
                return Err(malformed());
            }
        }
        Ok(())
    })();
    if let Err(error) = validation {
        return Err(expanded.failed.take().unwrap_or(error));
    }
    if !tables.contains_key("crates") || !tables.contains_key("versions") {
        return Err(Error::integrity(
            "Required crates.io dump tables are missing.",
        ));
    }
    Ok(
        json!({"artifact":artifact,"metadata":metadata,"tables":tables,"expanded_bytes":expanded.bytes,"processor":PROCESSOR,"sql_executed":false}),
    )
}

/// Read-only legacy-admission diagnosis of one retained dump. No staging or fetch occurs.
#[derive(Debug, serde::Serialize)]
pub struct DumpInspection {
    pub complete: bool,
    pub code: Option<String>,
    pub csv: Option<CsvDiagnostic>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub measurement: Option<CsvMeasurement>,
}
pub fn inspect_dump(
    path: PathBuf,
    cancel: CancellationToken,
    deadline: Instant,
    max_compressed: u64,
    max_expanded: u64,
) -> Result<DumpInspection> {
    inspect_dump_mode(path, cancel, deadline, max_compressed, max_expanded, false)
}
/// Measure only the first rejected record; this never changes runtime admission.
pub fn measure_first_rejection(
    path: PathBuf,
    cancel: CancellationToken,
    deadline: Instant,
    max_compressed: u64,
    max_expanded: u64,
) -> Result<DumpInspection> {
    inspect_dump_mode(path, cancel, deadline, max_compressed, max_expanded, true)
}
fn inspect_dump_mode(
    path: PathBuf,
    cancel: CancellationToken,
    deadline: Instant,
    max_compressed: u64,
    max_expanded: u64,
    measure_first_rejection: bool,
) -> Result<DumpInspection> {
    let metadata = std::fs::symlink_metadata(&path)
        .map_err(|_| Error::unavailable("Retained dump is unavailable."))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(Error::integrity("Retained dump is not a regular artifact."));
    }
    if metadata.len() > max_compressed {
        return Err(bounds(
            LimitKind::CompressedBytes,
            metadata.len(),
            max_compressed,
        ));
    }
    let diagnostic = Arc::new(Mutex::new(None));
    let measurement = Arc::new(Mutex::new(None));
    let budget = Budget {
        cancel,
        deadline,
        diagnostics: None,
        csv_diagnostic: diagnostic.clone(),
        csv_measurement: measurement.clone(),
        measure_first_rejection,
        legacy_admission: true,
        inspection: true,
        max_expanded: max_expanded.min(MAX_EXPANDED),
        max_compressed,
    };
    let (sender, _receiver) = mpsc::channel(1);
    let result = process(path, "retained-inspection", &budget, &sender);
    let csv = diagnostic
        .lock()
        .map_err(|_| Error::unavailable("Dump diagnostic is unavailable."))?
        .clone();
    let measured = measurement
        .lock()
        .map_err(|_| Error::unavailable("Dump measurement is unavailable."))?
        .clone();
    Ok(DumpInspection {
        complete: result.is_ok(),
        code: result
            .err()
            .map(|error| collection::safe_code(&error.code).to_owned()),
        csv,
        measurement: measured,
    })
}

pub async fn import_dump(
    path: PathBuf,
    artifact: String,
    store: Arc<dyn CrateCorpusStore>,
    shutdown: CancellationToken,
) -> Result<Value> {
    import_dump_observed(path, artifact, store, shutdown, None).await
}

pub(crate) async fn import_dump_observed(
    path: PathBuf,
    artifact: String,
    store: Arc<dyn CrateCorpusStore>,
    shutdown: CancellationToken,
    diagnostics: Option<Diagnostics>,
) -> Result<Value> {
    let selection = super::enrichment::selection(&artifact)?;
    let import_deadline = Instant::now() + Duration::from_secs(24 * 3600);
    let cancel = shutdown.child_token();
    let _guard = cancel.clone().drop_guard();
    let (sender, mut receiver) = mpsc::channel::<Batch>(2);
    let worker_artifact = artifact.clone();
    let worker_cancel = cancel.clone();
    let worker_diagnostics = diagnostics.clone();
    let csv_diagnostic = Arc::new(Mutex::new(None));
    let worker_csv_diagnostic = csv_diagnostic.clone();
    let worker = tokio::task::spawn_blocking(move || {
        let budget = Budget {
            cancel: worker_cancel,
            deadline: import_deadline,
            diagnostics: worker_diagnostics.clone(),
            csv_diagnostic: worker_csv_diagnostic,
            csv_measurement: Arc::new(Mutex::new(None)),
            measure_first_rejection: false,
            legacy_admission: false,
            inspection: false,
            max_expanded: MAX_EXPANDED,
            max_compressed: crate::bulk::MAX_ARTIFACT_BYTES,
        };
        if let Some(diagnostics) = &worker_diagnostics
            && let Ok(mut status) = diagnostics.lock()
        {
            status.begin(Phase::Materialization);
        }
        let _archive_lease = crate::durable_archive::materialize_file(
            &path,
            crate::bulk::MAX_ARTIFACT_BYTES,
            budget.deadline,
            &budget.cancel,
        )
        .map_err(|error| collection::at_phase(error, Phase::Materialization))?;
        if let Some(diagnostics) = &worker_diagnostics
            && let Ok(mut status) = diagnostics.lock()
        {
            status.begin(Phase::CsvParsing);
        }
        process(path, &worker_artifact, &budget, &sender)
            .map_err(|error| collection::at_phase(error, Phase::CsvParsing))
    });
    let mut rows = 0u64;
    let mut batches = 0u64;
    let staged: Result<()> = async {
        while let Some(batch) = receiver.recv().await {
            if shutdown.is_cancelled() {
                return Err(Error::new(
                    "cancelled",
                    "Database dump import was canceled.",
                ));
            }
            store
                .put_selected_enrichment(&selection, &batch.kind, &batch.rows)
                .await
                .map_err(|error| collection::at_phase(error, Phase::MetadataStaging))?;
            rows = rows.saturating_add(batch.rows.len() as u64);
            batches = batches.saturating_add(1);
            if let Some(diagnostics) = &diagnostics
                && let Ok(mut status) = diagnostics.lock()
            {
                status.progress(ProgressKind::Rows, rows);
                status.progress(ProgressKind::Batches, batches);
            }
        }
        Ok(())
    }
    .await;
    drop(receiver);
    let parsed = super::corpus::finish_parser(staged, worker, &cancel).await;
    if parsed.is_err() {
        let failure = csv_diagnostic
            .lock()
            .map_err(|_| Error::unavailable("Dump diagnostic is unavailable."))?
            .clone();
        if let Some(failure) = failure {
            let value = serde_json::to_value(failure).map_err(|_| malformed())?;
            store
                .record_dump_failure(&artifact, &value)
                .await
                .map_err(|error| collection::at_phase(error, Phase::ArtifactRetention))?;
        }
    }
    let summary = parsed?;
    if shutdown.is_cancelled() {
        return Err(Error::new(
            "cancelled",
            "Database dump import was canceled.",
        ));
    }
    if let Some(diagnostics) = &diagnostics
        && let Ok(mut status) = diagnostics.lock()
    {
        status.begin(Phase::EnrichmentPublication);
    }
    let result = {
        let commit_cancel = cancel.child_token();
        let commit = store.commit_selected_enrichment_with_cancel(
            &selection,
            &summary,
            commit_cancel.clone(),
        );
        tokio::pin!(commit);
        tokio::select! { biased;
            _ = shutdown.cancelled() => {
                commit_cancel.cancel();
                let _ = commit.await;
                Err(Error::new("cancelled", "Database dump import was canceled."))
            },
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(import_deadline)) => {
                commit_cancel.cancel();
                let _ = commit.await;
                Err(collection::limited(Error::capacity("Database dump processing deadline exceeded."), Phase::EnrichmentPublication, LimitKind::Deadline, None, None))
            },
            result = &mut commit => result,
        }
    };
    result.map_err(|error| collection::at_phase(error, Phase::EnrichmentPublication))?;
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    fn budget() -> Budget {
        Budget {
            cancel: CancellationToken::new(),
            deadline: Instant::now() + Duration::from_secs(10),
            diagnostics: None,
            csv_diagnostic: Arc::new(Mutex::new(None)),
            csv_measurement: Arc::new(Mutex::new(None)),
            measure_first_rejection: false,
            legacy_admission: false,
            inspection: false,
            max_expanded: MAX_EXPANDED,
            max_compressed: crate::bulk::MAX_ARTIFACT_BYTES,
        }
    }
    fn measurement_budget() -> Budget {
        Budget {
            inspection: true,
            legacy_admission: true,
            measure_first_rejection: true,
            deadline: Instant::now() + Duration::from_secs(30),
            ..budget()
        }
    }
    fn measure_csv(input: &[u8], table: &str) -> (Error, CsvMeasurement) {
        let budget = measurement_budget();
        let mut emitted = 0;
        let error = csv(input, table, &budget, |_, _| {
            emitted += 1;
            Ok(())
        })
        .unwrap_err();
        assert_eq!(
            emitted, 0,
            "diagnostic measurement must never emit even preceding valid rows"
        );
        let measurement = budget.csv_measurement.lock().unwrap().clone().unwrap();
        assert_eq!(
            budget.csv_diagnostic.lock().unwrap().as_ref(),
            Some(&measurement.original)
        );
        (error, measurement)
    }
    #[test]
    fn measurement_completes_only_the_rejected_quoted_record_and_preserves_runtime_limit() {
        let features = format!("{{\"x\":\"{}\"}}", "s".repeat(1_108_848 - 8));
        for ending in ["\n", "\r\n", ""] {
            let escaped = features.replace('"', "\"\"");
            let record = format!("7,1,1.2.3,\"{escaped}\",safe{ending}");
            let next = if ending.is_empty() {
                ""
            } else {
                "bad\"next-record\n"
            };
            let input = format!(
                "id,crate_id,num,features,description\n6,1,1.2.2,small,previous\n{record}{next}"
            );
            let (error, measurement) = measure_csv(input.as_bytes(), "versions");
            assert_eq!(error.code, "capacity");
            assert_eq!(
                (measurement.original.row, measurement.original.column),
                (2, 3)
            );
            assert!(measurement.original.selected);
            assert_eq!(measurement.field_kind, CsvFieldKind::Features);
            assert_eq!(measurement.original_threshold, MAX_FIELD as u64);
            assert_eq!(measurement.field_bytes, features.len() as u64);
            assert_eq!(measurement.raw_row_bytes, record.len() as u64);
            assert_eq!(
                measurement.decoded_row_bytes,
                (1 + 1 + 5 + features.len() + 4) as u64
            );
            assert!(
                measurement.field_complete
                    && measurement.field_valid
                    && measurement.row_complete
                    && measurement.row_valid
            );
            assert!(measurement.failure.is_none());
            assert!(
                !serde_json::to_string(&measurement)
                    .unwrap()
                    .contains("previous")
            );
        }
        let input = format!(
            "id,crate_id,num,features\n7,1,1.2.3,{}\n",
            "x".repeat(1_108_848)
        );
        let runtime = Budget {
            measure_first_rejection: true,
            ..budget()
        };
        assert_eq!(
            csv(input.as_bytes(), "versions", &runtime, |_, _| Ok(()))
                .unwrap_err()
                .code,
            "capacity"
        );
        assert!(
            runtime.csv_measurement.lock().unwrap().is_none(),
            "inspection opt-in must never raise runtime admission"
        );
    }
    #[test]
    fn measurement_records_first_concrete_malformed_reason_after_threshold() {
        let large = "x".repeat(1_108_848);
        for (tail, reason) in [
            (b"\"junk\n".to_vec(), CsvReason::Quoting),
            (vec![0, b'"', b'\n'], CsvReason::Nul),
            (vec![0xff, b'"', b'\n'], CsvReason::Utf8),
            (Vec::new(), CsvReason::Quoting),
        ] {
            let mut input = format!("id,crate_id,num,features\n7,1,1.2.3,\"{large}").into_bytes();
            input.extend(tail);
            let (error, measurement) = measure_csv(&input, "versions");
            assert_eq!(error.code, "integrity");
            assert_eq!(measurement.original.reason, CsvReason::FieldBytes);
            assert_eq!(measurement.failure.as_ref().unwrap().reason, reason);
            assert!(!measurement.row_valid);
            assert!(!measurement.field_valid);
        }
        for (prefix, suffix, reason) in [
            ("bad,1,1.2.3,", "\n", CsvReason::Identity),
            ("7,1,1.2.3,", ",extra\n", CsvReason::Columns),
        ] {
            let input = format!("id,crate_id,num,features\n{prefix}{large}{suffix}");
            let (_, measurement) = measure_csv(input.as_bytes(), "versions");
            assert!(
                measurement.field_complete && measurement.field_valid && measurement.row_complete
            );
            assert!(!measurement.row_valid);
            assert_eq!(measurement.failure.unwrap().reason, reason);
        }
    }
    #[test]
    fn measurement_stops_incomplete_at_unchanged_raw_and_decoded_row_bounds() {
        let features = "x".repeat(1_108_848);
        let prefix = format!("7,1,1.2.3,{features},");
        let padding = MAX_ROW - prefix.len() - 1;
        for extra in [0, 1] {
            let record = format!("{prefix}{}\n", "y".repeat(padding + extra));
            let input = format!("id,crate_id,num,features,ignored\n{record}");
            let (_, measurement) = measure_csv(input.as_bytes(), "versions");
            assert!(measurement.field_complete && measurement.field_valid);
            assert_eq!(measurement.field_bytes, features.len() as u64);
            assert_eq!(measurement.raw_row_bytes, (MAX_ROW + extra) as u64);
            assert_eq!(measurement.row_complete, extra == 0);
            assert_eq!(measurement.row_valid, extra == 0);
            if extra == 1 {
                assert_eq!(measurement.failure.unwrap().reason, CsvReason::RowBytes);
            }
        }
        // CSV escaping reaches the raw bound while the decoded field remains smaller.
        let quoted = format!(
            "id,crate_id,num,features\n7,1,1.2.3,\"{}{}\"\n",
            features,
            "\"\"".repeat(600_000)
        );
        let (_, measurement) = measure_csv(quoted.as_bytes(), "versions");
        assert_eq!(measurement.raw_row_bytes, (MAX_ROW + 1) as u64);
        assert!(measurement.decoded_row_bytes < MAX_ROW as u64);
        assert!(!measurement.field_complete && !measurement.row_complete && !measurement.row_valid);
        assert_eq!(measurement.failure.unwrap().reason, CsvReason::RowBytes);
    }
    #[test]
    fn measurement_cancellation_keeps_incomplete_counts_without_a_fabricated_failure() {
        struct CancelAfter {
            inner: Cursor<Vec<u8>>,
            token: CancellationToken,
            remaining: usize,
        }
        impl Read for CancelAfter {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                let limit = out.len().min(self.remaining);
                let read = self.inner.read(&mut out[..limit])?;
                self.remaining -= read;
                if self.remaining == 0 {
                    self.token.cancel();
                }
                Ok(read)
            }
        }
        let budget = measurement_budget();
        let input = format!(
            "id,crate_id,num,features\n7,1,1.2.3,{}\n",
            "x".repeat(1_800_000)
        );
        let reader = CancelAfter {
            inner: Cursor::new(input.into_bytes()),
            token: budget.cancel.clone(),
            remaining: 1_200_000,
        };
        let mut emitted = 0;
        assert_eq!(
            csv(reader, "versions", &budget, |_, _| {
                emitted += 1;
                Ok(())
            })
            .unwrap_err()
            .code,
            "cancelled"
        );
        assert_eq!(emitted, 0);
        let measured = budget.csv_measurement.lock().unwrap().clone().unwrap();
        assert!(measured.field_bytes > MAX_FIELD as u64);
        assert!(
            !measured.field_complete
                && !measured.field_valid
                && !measured.row_complete
                && !measured.row_valid
        );
        assert!(measured.failure.is_none());
    }
    fn encoded_batch_bytes(batch: &Batch) -> usize {
        let seal = format!("blake3:{}", "a".repeat(64));
        let rows: Vec<_> = batch
            .rows
            .iter()
            .map(|(id, value)| super::super::enrichment::row(id, value, &seal).unwrap())
            .collect();
        serde_json::to_vec(&rows).unwrap().len()
    }
    #[test]
    fn persisted_envelope_counts_escaping_integrity_and_splits_before_storage_limit() {
        let (sender, mut receiver) = mpsc::channel(2);
        let budget = budget();
        let mut batches = Batches {
            sender: &sender,
            kind: "crates".into(),
            rows: Vec::new(),
            bytes: 0,
            budget: &budget,
        };
        for id in 1..=1000 {
            batches.push(format!("{id}\"\\\n"), json!({"id":id.to_string(),"name":format!("synthetic{id}"),"description":"x".repeat(8300)})).unwrap();
        }
        batches.flush().unwrap();
        drop(sender);
        let first = receiver.blocking_recv().unwrap();
        let second = receiver.blocking_recv().unwrap();
        assert_eq!(first.rows.len() + second.rows.len(), 1000);
        assert!(encoded_batch_bytes(&first) <= MAX_BATCH);
        assert!(encoded_batch_bytes(&second) <= MAX_BATCH);
        assert!(receiver.blocking_recv().is_none());
    }
    #[test]
    fn exact_envelope_limit_is_admitted_and_one_more_byte_splits() {
        for extra in [0, 1] {
            let (sender, mut receiver) = mpsc::channel(2);
            let budget = budget();
            let mut batches = Batches {
                sender: &sender,
                kind: "crates".into(),
                rows: Vec::new(),
                bytes: 0,
                budget: &budget,
            };
            for id in 0..7 {
                batches
                    .push(
                        id.to_string(),
                        json!({"description":"x".repeat(1024 * 1024)}),
                    )
                    .unwrap();
            }
            let empty = json!({"description":""});
            let padding = MAX_BATCH
                - batches.bytes
                - 7
                - 2
                - super::super::enrichment::row_bytes("last", &empty).unwrap();
            batches
                .push(
                    "last".into(),
                    json!({"description":"x".repeat(padding + extra)}),
                )
                .unwrap();
            batches.flush().unwrap();
            drop(sender);
            let first = receiver.blocking_recv().unwrap();
            if extra == 0 {
                assert_eq!(encoded_batch_bytes(&first), MAX_BATCH);
                assert!(receiver.blocking_recv().is_none());
            } else {
                assert_eq!(first.rows.len(), 7);
                assert!(encoded_batch_bytes(&receiver.blocking_recv().unwrap()) <= MAX_BATCH);
            }
        }
    }
    fn archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut tar = tar::Builder::new(gzip);
        for (path, bytes) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(&mut header, *path, Cursor::new(bytes))
                .unwrap();
        }
        tar.into_inner().unwrap().finish().unwrap()
    }
    fn run(bytes: &[u8]) -> (Result<Value>, Vec<Batch>) {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), bytes).unwrap();
        let (sender, mut receiver) = mpsc::channel(2);
        let path = file.path().to_owned();
        let worker =
            std::thread::spawn(move || process(path, "public-artifact", &budget(), &sender));
        let mut out = Vec::new();
        while let Some(batch) = receiver.blocking_recv() {
            out.push(batch);
        }
        (worker.join().unwrap(), out)
    }
    #[test]
    fn quoted_csv_fields_cross_chunks_and_filter_private_columns() {
        let description = format!("{}\nline, with \"quoted\" text", "word ".repeat(15_000));
        let escaped = description.replace('"', "\"\"");
        let input = format!("id,name,description,token\n1,synthetic,\"{escaped}\",private-token\n");
        let mut rows = Vec::new();
        let summary = csv(input.as_bytes(), "crates", &budget(), |key, row| {
            rows.push((key, row));
            Ok(())
        })
        .unwrap();
        assert_eq!(summary["rows"], 1);
        assert_eq!(rows[0].0, "1");
        assert_eq!(rows[0].1["description"], description);
        assert!(rows[0].1.get("token").is_none());
    }
    #[test]
    fn csv_rejects_malformed_quotes_columns_identity_and_bounds() {
        for input in [
            "id,description\n1,missing-name\n",
            "id,name\n1,\"unterminated",
            "id,name\n1,bad\"quote\n",
            "id,name\n1,\"x\"junk\n",
            "id,id,name\n1,1,dup\n",
            "id,name\n-1,no\n",
            "id,name\n1,../bad\n",
        ] {
            assert_eq!(
                csv(input.as_bytes(), "crates", &budget(), |_, _| Ok(()))
                    .unwrap_err()
                    .code,
                "integrity",
                "{input}"
            );
        }
        let input = format!(
            "id,name,description\n1,synthetic,{}\n",
            "x".repeat(MAX_FIELD + 1)
        );
        assert_eq!(
            csv(input.as_bytes(), "crates", &budget(), |_, _| Ok(()))
                .unwrap_err()
                .code,
            "capacity"
        );
        let input = format!(
            "id,name,{}\n",
            (0..128)
                .map(|i| format!("extra{i}"))
                .collect::<Vec<_>>()
                .join(",")
        );
        assert_eq!(
            csv(input.as_bytes(), "crates", &budget(), |_, _| Ok(()))
                .unwrap_err()
                .code,
            "capacity"
        );
        let b = budget();
        b.cancel.cancel();
        assert_eq!(
            csv(
                b"id,name\n1,synthetic\n".as_slice(),
                "crates",
                &b,
                |_, _| Ok(())
            )
            .unwrap_err()
            .code,
            "cancelled"
        );
        assert!(
            b.csv_diagnostic.lock().unwrap().is_none(),
            "cancellation has no parser input failure discriminator"
        );
    }
    #[test]
    fn streaming_projection_preserves_selected_values_and_discards_only_ignored_fields() {
        for size in [MAX_FIELD, MAX_FIELD + 1, 1_108_848] {
            let ignored = "x".repeat(size);
            let selected = format!("{}💾", "s".repeat(MAX_FIELD - 4));
            // Exercise the two bounds independently; two near-limit fields would exceed the row cap.
            for (column, value) in [
                ("description", selected.as_str()),
                ("private_column", ignored.as_str()),
            ] {
                let input = format!("id,name,{column}\n1,synthetic,{value}\n");
                let mut output = Vec::new();
                csv(input.as_bytes(), "crates", &budget(), |_, row| {
                    output.push(row);
                    Ok(())
                })
                .unwrap();
                assert_eq!(output.len(), 1);
                if column == "description" {
                    assert_eq!(output[0][column], selected);
                } else {
                    assert!(output[0].get(column).is_none());
                }
            }
        }
        let input = format!(
            "id,name,description\n1,synthetic,{}\n",
            "x".repeat(MAX_FIELD + 1)
        );
        let observed = budget();
        let error = csv(input.as_bytes(), "crates", &observed, |_, _| Ok(())).unwrap_err();
        assert_eq!(
            collection::context(&error).unwrap().limit.unwrap().kind,
            LimitKind::CsvFieldBytes
        );
        let diagnostic = observed.csv_diagnostic.lock().unwrap().clone().unwrap();
        assert!(diagnostic.selected);
        assert_eq!(
            (diagnostic.row, diagnostic.column, diagnostic.reason),
            (1, 2, CsvReason::FieldBytes)
        );
    }
    #[test]
    fn ignored_fields_still_validate_utf8_nul_quotes_and_both_row_bounds() {
        for suffix in [vec![0xff], vec![0], b"bad\"quote".to_vec()] {
            let mut input = b"id,name,ignored\n1,synthetic,".to_vec();
            input.extend_from_slice(&suffix);
            input.push(b'\n');
            assert_eq!(
                csv(input.as_slice(), "crates", &budget(), |_, _| Ok(()))
                    .unwrap_err()
                    .code,
                "integrity"
            );
        }
        let prefix = "1,synthetic,";
        let size = MAX_ROW - prefix.len() - 1;
        let valid = format!("id,name,ignored\n{prefix}{}\n", "x".repeat(size));
        csv(valid.as_bytes(), "crates", &budget(), |_, _| Ok(())).unwrap();
        let oversized = format!("id,name,ignored\n{prefix}{}\n", "x".repeat(size + 1));
        let error = csv(oversized.as_bytes(), "crates", &budget(), |_, _| Ok(())).unwrap_err();
        assert_eq!(
            collection::context(&error).unwrap().limit.unwrap().kind,
            LimitKind::CsvRowBytes
        );
        // Escaping can exceed the raw bound even when decoded data fits.
        let escaped = format!(
            "id,name,ignored\n1,synthetic,\"{}\"\n",
            "\"\"".repeat(MAX_ROW / 2)
        );
        assert_eq!(
            csv(escaped.as_bytes(), "crates", &budget(), |_, _| Ok(()))
                .unwrap_err()
                .code,
            "capacity"
        );
    }
    #[test]
    fn selected_escaping_preserves_exact_values_under_existing_staging_envelope() {
        let selected = "\x01".repeat(800_000);
        let ignored = "x".repeat(1_108_848);
        let input = format!("id,name,description,ignored\n1,synthetic,{selected},{ignored}\n");
        let mut emitted = Vec::new();
        csv(input.as_bytes(), "crates", &budget(), |_, value| {
            emitted.push(value);
            Ok(())
        })
        .unwrap();
        assert_eq!(emitted.len(), 1);
        assert_eq!(emitted[0]["description"], selected);
        assert!(emitted[0].get("ignored").is_none());
        let persisted = super::super::enrichment::row_bytes("1", &emitted[0]).unwrap();
        assert!(persisted > super::super::enrichment::MAX_READ_BYTES);
        assert!(persisted < MAX_BATCH);
    }
    #[test]
    fn retained_inspection_identifies_old_ignored_field_rejection_without_staging() {
        let input = format!("id,name,ignored\n1,synthetic,{}\n", "x".repeat(1_108_848));
        let bytes = archive(&[
            ("data/crates.csv", input.as_bytes()),
            ("data/versions.csv", b"id,crate_id,num\n2,1,1.2.3\n"),
        ]);
        let file = tempfile::NamedTempFile::new_in("/tmp").unwrap();
        std::fs::write(file.path(), bytes).unwrap();
        let report = inspect_dump(
            file.path().to_owned(),
            CancellationToken::new(),
            Instant::now() + Duration::from_secs(10),
            4 * 1024 * 1024,
            8 * 1024 * 1024,
        )
        .unwrap();
        assert!(!report.complete);
        assert_eq!(report.code.as_deref(), Some("capacity"));
        let diagnostic = report.csv.unwrap();
        assert_eq!(diagnostic.table, CsvTable::Crates);
        assert_eq!((diagnostic.row, diagnostic.column), (1, 2));
        assert!(!diagnostic.selected);
        assert_eq!(diagnostic.reason, CsvReason::FieldBytes);
        assert!(diagnostic.observed.unwrap() > MAX_FIELD as u64);
        let (result, batches) = run(&archive(&[
            ("data/crates.csv", input.as_bytes()),
            ("data/versions.csv", b"id,crate_id,num\n2,1,1.2.3\n"),
        ]));
        assert!(result.is_ok());
        assert_eq!(
            batches.iter().map(|batch| batch.rows.len()).sum::<usize>(),
            2
        );
    }

    #[test]
    fn complete_archive_imports_relations_and_never_executes_sql() {
        let bytes = archive(&[
            (
                "2026-10-24-020000/data/crates.csv",
                b"id,name,description\n1,synthetic,=never-evaluate()\n",
            ),
            (
                "2026-10-24-020000/data/versions.csv",
                b"id,crate_id,num\n2,1,1.2.3\n",
            ),
            (
                "2026-10-24-020000/data/crates_keywords.csv",
                b"crate_id,keyword_id\n1,4\n",
            ),
            (
                "2026-10-24-020000/import.sql",
                b"DROP DATABASE important; SELECT dangerous();",
            ),
            (
                "2026-10-24-020000/metadata.json",
                br#"{"timestamp":"2026-10-24T02:00:00Z","crates_io_commit":"synthetic"}"#,
            ),
        ]);
        let (summary, batches) = run(&bytes);
        let summary = summary.unwrap();
        assert_eq!(summary["sql_executed"], false);
        assert_eq!(summary["tables"]["versions"]["rows"], 1);
        assert_eq!(summary["metadata"]["timestamp"], "2026-10-24T02:00:00Z");
        assert_eq!(batches.len(), 3);
        assert_eq!(batches[2].rows[0].0, "1:4");
        assert_eq!(batches[0].rows[0].1["description"], "=never-evaluate()");
    }
    #[test]
    fn missing_tables_duplicates_specials_bad_paths_and_gzip_fail_closed() {
        let bytes = archive(&[("data/crates.csv", b"id,name\n1,synthetic\n")]);
        assert_eq!(run(&bytes).0.unwrap_err().code, "integrity");
        let bytes = archive(&[
            ("data/crates.csv", b"id,name\n1,synthetic\n"),
            ("data/crates.csv", b"id,name\n1,synthetic\n"),
        ]);
        assert!(run(&bytes).0.is_err());
        let bytes = archive(&[("bad-root/data/crates.csv", b"id,name\n1,synthetic\n")]);
        assert!(run(&bytes).0.is_err());
        let bytes = archive(&[
            ("data/crates.csv", b"id,name\n1,synthetic\n"),
            ("data/versions.csv", b"id,crate_id,num\n2,1,1.2.3\n"),
        ]);
        let mut broken = bytes.clone();
        let n = broken.len();
        broken[n - 8] ^= 0x40;
        assert!(run(&broken).0.is_err());
        assert!(run(&bytes[..bytes.len() - 4]).0.is_err());
        let gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut tar = tar::Builder::new(gzip);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        header.set_link_name("/outside").unwrap();
        header.set_cksum();
        tar.append_data(&mut header, "data/crates.csv", io::empty())
            .unwrap();
        let bytes = tar.into_inner().unwrap().finish().unwrap();
        assert!(run(&bytes).0.is_err());
    }
    #[test]
    fn batches_bound_backpressure_and_cancellation_between_batches() {
        let mut crates = String::from("id,name\n");
        for id in 1..=2501 {
            crates.push_str(&format!("{id},synthetic{id}\n"));
        }
        let bytes = archive(&[
            ("data/crates.csv", crates.as_bytes()),
            ("data/versions.csv", b"id,crate_id,num\n1,1,1.2.3\n"),
        ]);
        let (summary, batches) = run(&bytes);
        assert!(summary.is_ok());
        assert_eq!(batches.len(), 4);
        assert!(batches.iter().all(|batch| batch.rows.len() <= 1000));
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), &bytes).unwrap();
        let (sender, mut receiver) = mpsc::channel(2);
        let path = file.path().to_owned();
        let cancel = CancellationToken::new();
        let worker_cancel = cancel.clone();
        let worker = std::thread::spawn(move || {
            process(
                path,
                "artifact",
                &Budget {
                    cancel: worker_cancel,
                    deadline: Instant::now() + Duration::from_secs(10),
                    ..budget()
                },
                &sender,
            )
        });
        receiver.blocking_recv().unwrap();
        cancel.cancel();
        drop(receiver);
        assert_eq!(worker.join().unwrap().unwrap_err().code, "cancelled");
    }
}

#[cfg(test)]
mod publication_tests {
    use super::*;
    use devres_application::crate_corpus::{
        Artifact, CollectionJob, ContentFilter, ContentRecord, Inventory, Snapshot, VersionRecord,
    };
    use devres_domain::Capture;
    use std::io::Cursor;
    use tokio::sync::Mutex;
    struct Sink {
        committed: Mutex<String>,
        staged: Mutex<usize>,
        fail: bool,
        gate: Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>,
        commit_gate: Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>,
    }
    fn unused() -> Error {
        Error::unavailable("Unused fixture port")
    }
    #[async_trait::async_trait]
    impl CrateCorpusStore for Sink {
        async fn begin_inventory(&self, _: &str, _: i64) -> Result<Inventory> {
            Err(unused())
        }
        async fn pending_inventory(&self) -> Result<Option<Inventory>> {
            Err(unused())
        }
        async fn latest_inventory(&self) -> Result<Option<Inventory>> {
            Err(unused())
        }
        async fn stage_crate(&self, _: &str, _: &str, _: &[VersionRecord], _: &str) -> Result<()> {
            Err(unused())
        }
        async fn commit_inventory(&self, _: &str, _: &str) -> Result<Inventory> {
            Err(unused())
        }
        async fn versions(
            &self,
            _: &str,
            _: Option<&str>,
            _: Option<&str>,
            _: usize,
        ) -> Result<Vec<VersionRecord>> {
            Err(unused())
        }
        async fn save_artifact(&self, _: &Artifact, _: bool) -> Result<()> {
            Err(unused())
        }
        async fn artifact(&self, _: &str) -> Result<Option<Artifact>> {
            Err(unused())
        }
        async fn latest_artifact(&self, _: &str) -> Result<Option<Artifact>> {
            Err(unused())
        }
        async fn import_metadata(
            &self,
            _: &str,
            _: &str,
            _: &str,
            _: &str,
            _: &[u8],
            _: i64,
        ) -> Result<Capture> {
            Err(unused())
        }
        async fn save_text(&self, _: &str, _: &str, _: &str, _: Value, _: i64) -> Result<Capture> {
            Err(unused())
        }
        async fn schedule(&self, _: &[CollectionJob], _: i64) -> Result<()> {
            Err(unused())
        }
        async fn recover_interrupted_jobs(&self) -> Result<()> {
            Ok(())
        }
        async fn claim(&self, _: i64, _: &str) -> Result<Option<CollectionJob>> {
            Err(unused())
        }
        async fn finish(&self, _: &str, _: Option<&str>, _: Option<&str>, _: i64) -> Result<()> {
            Err(unused())
        }
        async fn stage_content(&self, _: &str, _: &[ContentRecord]) -> Result<()> {
            Err(unused())
        }
        async fn commit_content(&self, _: &str, _: Value) -> Result<()> {
            Err(unused())
        }
        async fn contents(
            &self,
            _: i64,
            _: &ContentFilter,
            _: Option<&str>,
            _: usize,
        ) -> Result<Vec<ContentRecord>> {
            Err(unused())
        }
        async fn put_enrichment(&self, _: &str, _: &str, rows: &[(String, Value)]) -> Result<()> {
            let first = {
                let mut staged = self.staged.lock().await;
                let first = *staged == 0;
                *staged += rows.len();
                first
            };
            if first && let Some((entered, release)) = &self.gate {
                entered.notify_one();
                release.notified().await;
            }
            if self.fail {
                Err(Error::unavailable("Fixture storage failure"))
            } else {
                Ok(())
            }
        }
        async fn put_selected_enrichment(
            &self,
            selection: &EnrichmentSelection,
            kind: &str,
            rows: &[(String, Value)],
        ) -> Result<()> {
            self.put_enrichment(&selection.capture, kind, rows).await
        }
        async fn commit_selected_enrichment(
            &self,
            selection: &EnrichmentSelection,
            _: &Value,
        ) -> Result<()> {
            self.commit_enrichment(&selection.capture).await
        }
        async fn commit_enrichment(&self, artifact: &str) -> Result<()> {
            if let Some((entered, release)) = &self.commit_gate {
                entered.notify_one();
                release.notified().await;
            }
            *self.committed.lock().await = artifact.into();
            Ok(())
        }
        async fn enrichment(&self, _: Option<&str>, _: &str, _: &str) -> Result<Value> {
            Err(unused())
        }
        async fn publish_snapshot(&self, _: &str, _: Value, _: i64) -> Result<Snapshot> {
            Err(unused())
        }
        async fn snapshot(&self, _: Option<&str>) -> Result<Option<Snapshot>> {
            Err(unused())
        }
        async fn status(&self) -> Result<Value> {
            Err(unused())
        }
    }
    fn dump(valid: bool) -> Vec<u8> {
        let gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut tar = tar::Builder::new(gzip);
        let entries = [
            ("data/crates.csv", b"id,name\n1,synthetic\n".as_slice()),
            (
                "data/versions.csv",
                b"id,crate_id,num\n2,1,1.2.3\n".as_slice(),
            ),
        ];
        for (path, bytes) in entries.iter().take(if valid { 2 } else { 1 }) {
            let mut h = tar::Header::new_gnu();
            h.set_size(bytes.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            tar.append_data(&mut h, *path, Cursor::new(bytes)).unwrap();
        }
        tar.into_inner().unwrap().finish().unwrap()
    }
    #[tokio::test]
    async fn commit_occurs_only_after_complete_success_and_storage_errors_preserve_previous() {
        for (valid, fail) in [(true, false), (false, false), (true, true)] {
            let file = tempfile::NamedTempFile::new().unwrap();
            std::fs::write(file.path(), dump(valid)).unwrap();
            let store = Arc::new(Sink {
                committed: Mutex::new("previous".into()),
                staged: Mutex::new(0),
                fail,
                gate: None,
                commit_gate: None,
            });
            let result = import_dump(
                file.path().into(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                store.clone(),
                CancellationToken::new(),
            )
            .await;
            assert_eq!(result.is_ok(), valid && !fail);
            if fail {
                assert_eq!(
                    collection::context(result.as_ref().unwrap_err())
                        .unwrap()
                        .phase,
                    Phase::MetadataStaging
                );
            }
            assert_eq!(
                *store.committed.lock().await,
                if valid && !fail {
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                } else {
                    "previous"
                }
            );
            assert!(*store.staged.lock().await > 0);
        }
    }
    #[tokio::test]
    async fn import_progress_is_visible_before_the_complete_head_is_published() {
        let file = tempfile::NamedTempFile::new_in("/tmp").unwrap();
        std::fs::write(file.path(), dump(true)).unwrap();
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let store = Arc::new(Sink {
            committed: Mutex::new("previous".into()),
            staged: Mutex::new(0),
            fail: false,
            gate: Some((entered.clone(), release.clone())),
            commit_gate: None,
        });
        let diagnostics = Arc::new(std::sync::Mutex::new(CollectorStatus::default()));
        let path = file.path().to_owned();
        let worker_store = store.clone();
        let observed = diagnostics.clone();
        let worker = tokio::spawn(async move {
            import_dump_observed(
                path,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                worker_store,
                CancellationToken::new(),
                Some(observed),
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .unwrap();
        assert_eq!(*store.committed.lock().await, "previous");
        {
            let status = diagnostics.lock().unwrap();
            assert!(status.active);
            assert!(status.progress[&ProgressKind::ExpandedBytes] > 0);
        }
        release.notify_one();
        tokio::time::timeout(Duration::from_secs(5), worker)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(diagnostics.lock().unwrap().progress[&ProgressKind::Rows], 2);
        assert_eq!(
            *store.committed.lock().await,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
    }
    #[tokio::test]
    async fn shutdown_during_stalled_publication_preserves_previous_head() {
        let file = tempfile::NamedTempFile::new_in("/tmp").unwrap();
        std::fs::write(file.path(), dump(true)).unwrap();
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let store = Arc::new(Sink {
            committed: Mutex::new("previous".into()),
            staged: Mutex::new(0),
            fail: false,
            gate: None,
            commit_gate: Some((entered.clone(), release)),
        });
        let cancel = CancellationToken::new();
        let worker_cancel = cancel.clone();
        let path = file.path().to_owned();
        let worker_store = store.clone();
        let task = tokio::spawn(async move {
            import_dump(path, "a".repeat(64), worker_store, worker_cancel).await
        });
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .unwrap();
        cancel.cancel();
        let error = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(error.code, "cancelled");
        assert_eq!(*store.committed.lock().await, "previous");
        assert_eq!(*store.staged.lock().await, 2);
    }
}
