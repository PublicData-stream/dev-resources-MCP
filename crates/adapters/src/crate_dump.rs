//! Streaming import of the public crates.io CSV dump. SQL is inert evidence.
//!
//! Raw artifacts are retained by the caller. Rows are staged under their artifact
//! and become enrichment only after the complete tar/gzip stream passes checks.
use devres_application::crate_corpus::CrateCorpusStore;
use devres_domain::{Error, Result};
use flate2::read::MultiGzDecoder;
use serde_json::{Map, Value, json};
use std::{
    collections::{BTreeMap, HashSet},
    fs::File,
    io::{self, BufRead, BufReader, Read},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

const MAX_EXPANDED: u64 = 512 * 1024 * 1024 * 1024;
const MAX_ROW: usize = 2 * 1024 * 1024;
const MAX_FIELD: usize = 1024 * 1024;
const MAX_COLUMNS: usize = 128;
const MAX_BATCH: usize = 8 * 1024 * 1024;
const CHUNK: usize = 64 * 1024;
const MAX_MEMBERS: usize = 1000;

fn malformed() -> Error {
    Error::integrity("Malformed public crates.io database dump.")
}
fn bounds() -> Error {
    Error::capacity("Database dump processing bounds exceeded.")
}
struct Budget {
    cancel: CancellationToken,
    deadline: Instant,
}
impl Budget {
    fn check(&self) -> Result<()> {
        if self.cancel.is_cancelled() {
            return Err(Error::new(
                "cancelled",
                "Database dump import was canceled.",
            ));
        }
        if Instant::now() >= self.deadline {
            return Err(bounds());
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
        let max = out
            .len()
            .min(CHUNK)
            .min(MAX_EXPANDED.saturating_sub(self.bytes).saturating_add(1) as usize);
        let n = self.inner.read(&mut out[..max])?;
        self.bytes += n as u64;
        if self.bytes > MAX_EXPANDED {
            self.failed = Some(bounds());
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
}
impl Grammar {
    fn new() -> Self {
        Self {
            state: QuoteState::Start,
            raw: 0,
        }
    }
    fn feed(&mut self, bytes: &[u8]) -> Result<()> {
        for &b in bytes {
            self.raw += 1;
            if self.raw > MAX_ROW {
                return Err(bounds());
            }
            match (self.state, b) {
                (QuoteState::Start, b'"') => self.state = QuoteState::Quoted,
                (QuoteState::Start, b',') => {}
                (QuoteState::Start, b'\r' | b'\n') => {
                    self.raw = 0;
                }
                (QuoteState::Start, _) => self.state = QuoteState::Plain,
                (QuoteState::Plain, b'"') => return Err(malformed()),
                (QuoteState::Plain, b',') => self.state = QuoteState::Start,
                (QuoteState::Plain, b'\r' | b'\n') => {
                    self.state = QuoteState::Start;
                    self.raw = 0;
                }
                (QuoteState::Plain, _) => {}
                (QuoteState::Quoted, b'"') => self.state = QuoteState::AfterQuote,
                (QuoteState::Quoted, _) => {}
                (QuoteState::AfterQuote, b'"') => self.state = QuoteState::Quoted,
                (QuoteState::AfterQuote, b',') => self.state = QuoteState::Start,
                (QuoteState::AfterQuote, b'\r' | b'\n') => {
                    self.state = QuoteState::Start;
                    self.raw = 0;
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
        "crates" => crate::cargo::validate_name(
            row.get("name")
                .and_then(Value::as_str)
                .ok_or_else(malformed)?,
        )
        .map_err(|_| malformed())?,
        "versions" => {
            crate::cargo::validate_version(
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
    let mut output = vec![0u8; MAX_ROW + 1];
    let mut ends = [0usize; MAX_COLUMNS + 1];
    let mut written = 0;
    let mut fields = 0;
    let mut rows = 0u64;
    let mut header: Option<Vec<String>> = None;
    loop {
        budget.check()?;
        let bytes = input.fill_buf().map_err(|_| malformed())?;
        let eof = bytes.is_empty();
        let (status, nin, nout, nends) =
            parser.read_record(bytes, &mut output[written..], &mut ends[fields..]);
        grammar.feed(&bytes[..nin])?;
        if eof {
            grammar.finish()?;
        }
        input.consume(nin);
        written += nout;
        fields += nends;
        if written > MAX_ROW || fields > MAX_COLUMNS {
            return Err(bounds());
        }
        let mut start = 0;
        for &end in &ends[..fields] {
            if end < start || end - start > MAX_FIELD {
                return Err(bounds());
            }
            start = end;
        }
        if written.saturating_sub(start) > MAX_FIELD {
            return Err(bounds());
        }
        match status {
            csv_core::ReadRecordResult::End => break,
            csv_core::ReadRecordResult::Record => {
                let mut start = 0;
                let mut values = Vec::with_capacity(fields);
                for &end in &ends[..fields] {
                    let value =
                        std::str::from_utf8(&output[start..end]).map_err(|_| malformed())?;
                    if value.contains('\0') {
                        return Err(malformed());
                    }
                    values.push(value);
                    start = end;
                }
                if let Some(header) = &header {
                    if values.len() != header.len() {
                        return Err(malformed());
                    }
                    let mut row = Map::new();
                    for (name, value) in header.iter().zip(values) {
                        if allowed.contains(&name.as_str()) {
                            row.insert(name.clone(), json!(value));
                        }
                    }
                    let key = row_key(table, &row)?;
                    emit(key, Value::Object(row))?;
                    rows += 1;
                } else {
                    if values.is_empty()
                        || values.iter().any(|v| {
                            v.is_empty()
                                || v.len() > 128
                                || !v.bytes().all(|b| {
                                    b.is_ascii_lowercase() || b == b'_' || b.is_ascii_digit()
                                })
                        })
                    {
                        return Err(malformed());
                    }
                    let unique = values.iter().copied().collect::<HashSet<_>>();
                    if unique.len() != values.len()
                        || required.iter().any(|field| !unique.contains(field))
                    {
                        return Err(malformed());
                    }
                    header = Some(values.into_iter().map(str::to_owned).collect());
                }
                written = 0;
                fields = 0;
            }
            csv_core::ReadRecordResult::OutputFull | csv_core::ReadRecordResult::OutputEndsFull => {
                return Err(bounds());
            }
            csv_core::ReadRecordResult::InputEmpty => {}
        }
    }
    let header = header.ok_or_else(malformed)?;
    Ok(
        json!({"rows":rows,"columns":header,"value_encoding":"CSV fields retained as strings; no SQL execution or inferred null semantics"}),
    )
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
        let size = serde_json::to_vec(&value).map_err(|_| malformed())?.len() + key.len();
        if size > MAX_BATCH {
            return Err(bounds());
        }
        if !self.rows.is_empty() && (self.rows.len() >= 1000 || self.bytes + size > MAX_BATCH) {
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
    let input = File::open(path)
        .map_err(|_| Error::unavailable("Database dump artifact could not be opened."))?;
    let mut expanded = Expanded {
        inner: MultiGzDecoder::new(BufReader::with_capacity(CHUNK, input)),
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
                return Err(bounds());
            }
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
                    let summary =
                        csv(&mut entry, table, budget, |key, row| batches.push(key, row))?;
                    batches.flush()?;
                    tables.insert(table.to_owned(), summary);
                } else {
                    drain(&mut entry, budget)?;
                }
            } else if name == "metadata.json" {
                if entry.size() > MAX_FIELD as u64 {
                    return Err(bounds());
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
        json!({"artifact":artifact,"metadata":metadata,"tables":tables,"expanded_bytes":expanded.bytes,"processor":"crates-dump-v1","sql_executed":false}),
    )
}

pub async fn import_dump(
    path: PathBuf,
    artifact: String,
    store: Arc<dyn CrateCorpusStore>,
    shutdown: CancellationToken,
) -> Result<Value> {
    let cancel = shutdown.child_token();
    let _guard = cancel.clone().drop_guard();
    let (sender, mut receiver) = mpsc::channel::<Batch>(2);
    let worker_artifact = artifact.clone();
    let worker_cancel = cancel.clone();
    let worker = tokio::task::spawn_blocking(move || {
        let budget = Budget {
            cancel: worker_cancel,
            deadline: Instant::now() + Duration::from_secs(24 * 3600),
        };
        process(path, &worker_artifact, &budget, &sender)
    });
    while let Some(batch) = receiver.recv().await {
        if shutdown.is_cancelled() {
            return Err(Error::new(
                "cancelled",
                "Database dump import was canceled.",
            ));
        }
        store
            .put_enrichment(&artifact, &batch.kind, &batch.rows)
            .await?;
    }
    let summary = worker
        .await
        .map_err(|_| Error::unavailable("Database dump worker failed."))??;
    if shutdown.is_cancelled() {
        return Err(Error::new(
            "cancelled",
            "Database dump import was canceled.",
        ));
    }
    store.commit_enrichment(&artifact).await?;
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
            *self.staged.lock().await += rows.len();
            if self.fail {
                Err(Error::unavailable("Fixture storage failure"))
            } else {
                Ok(())
            }
        }
        async fn commit_enrichment(&self, artifact: &str) -> Result<()> {
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
            });
            let result = import_dump(
                file.path().into(),
                "new-public-artifact".into(),
                store.clone(),
                CancellationToken::new(),
            )
            .await;
            assert_eq!(result.is_ok(), valid && !fail);
            assert_eq!(
                *store.committed.lock().await,
                if valid && !fail {
                    "new-public-artifact"
                } else {
                    "previous"
                }
            );
            assert!(*store.staged.lock().await > 0);
        }
    }
}
