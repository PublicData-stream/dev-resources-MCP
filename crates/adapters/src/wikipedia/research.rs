//! Capture-fixed Wikipedia research; only explicit upstream search schedules I/O.
use super::WikipediaCorpus;
use crate::research::text_page;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use devres_domain::{Error, Result};
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;

const MAX_SCAN: usize = 100 * 1024 * 1024;
const MAX_EXCERPTS: usize = 32768;
const MAX_ROWS: usize = 100;

pub struct WikipediaResearch {
    corpus: Arc<WikipediaCorpus>,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Input {
    title: Option<String>,
    category: Option<String>,
    current: Option<bool>,
    page_id: Option<u64>,
    capture: Option<String>,
    snapshot: Option<String>,
    representation: Option<String>,
    query: Option<String>,
    mode: Option<String>,
    pattern: Option<String>,
    before: Option<String>,
    after: Option<String>,
    cursor: Option<String>,
    #[serde(default)]
    offset: usize,
    #[serde(default)]
    after_page_id: u64,
    limit: Option<usize>,
    #[serde(default)]
    case_sensitive: bool,
    #[serde(default)]
    literal: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    version: u8,
    snapshot: String,
    fingerprint: String,
    page: u64,
    line: usize,
    skip: usize,
    historical: bool,
}
fn invalid() -> Error {
    Error::invalid("Invalid Wikipedia research arguments.")
}
fn retained() -> Error {
    Error::integrity("Invalid retained Wikipedia research evidence.")
}
fn check(deadline: Instant, cancel: &CancellationToken) -> Result<()> {
    if cancel.is_cancelled() {
        return Err(Error::new("cancelled", "Wikipedia research canceled."));
    }
    if Instant::now() >= deadline {
        return Err(Error::capacity("Wikipedia research deadline exceeded."));
    }
    Ok(())
}
fn meta(value: &Value) -> &Value {
    value.get("capture").unwrap_or(value)
}
fn id(value: &Value) -> Result<&str> {
    meta(value)["id"].as_str().ok_or_else(retained)
}
fn page_id(value: &Value) -> Result<u64> {
    meta(value)["page_id"].as_u64().ok_or_else(retained)
}
fn revision(value: &Value) -> Result<u64> {
    meta(value)["revision_id"].as_u64().ok_or_else(retained)
}
fn public_meta(value: &Value) -> Value {
    let source = meta(value);
    let mut output = json!({});
    for key in [
        "id",
        "page_id",
        "revision_id",
        "title",
        "representation",
        "source_url",
        "observed_at",
        "validated_at",
        "expires_at",
        "current",
        "body_hash",
        "license",
        "format_coverage",
        "snapshot",
        "stale",
        "available_formats",
        "categories",
        "processing_gaps",
        "observed_newer_revision",
        "update_pending",
        "acquisition_policy_epoch",
        "acquisition_policy_fingerprint",
    ] {
        if let Some(value) = source.get(key) {
            output[key] = value.clone();
        }
    }
    if output["body_hash"].is_null() {
        output["body_hash"] = source
            .pointer("/artifact/body_hash")
            .cloned()
            .unwrap_or(Value::Null);
    }
    output
}
fn public_document(document: &mut Value) {
    let capture = public_meta(document);
    document["source_evidence"] = json!({"provider":"wikipedia","page_id":capture["page_id"],"revision_id":capture["revision_id"],"source_url":capture["source_url"],"body_hash":capture["body_hash"],"capture":capture["id"],"license":capture["license"],"wikipedia_evidence":capture});
    document["capture"] = capture;
    if let Some(object) = document.as_object_mut() {
        object.remove("text");
        object.remove("projection");
    }
}
fn cutoff(view: &Value) -> Result<i64> {
    view["cutoff"].as_i64().ok_or_else(retained)
}
fn limit(input: &Input, default: usize, max: usize) -> Result<usize> {
    let limit = input.limit.unwrap_or(default);
    if !(1..=max).contains(&limit) {
        return Err(invalid());
    }
    Ok(limit)
}
fn selector(input: &Input) -> Value {
    let mut value = json!({});
    for (key, item) in [
        ("title", input.title.as_ref()),
        ("capture", input.capture.as_ref()),
        ("snapshot", input.snapshot.as_ref()),
    ] {
        if let Some(item) = item {
            value[key] = json!(item);
        }
    }
    if let Some(page) = input.page_id {
        value["page_id"] = json!(page);
    }
    value
}
fn bounded_excerpt(text: &str, max: usize) -> &str {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}
fn encode(cursor: &Cursor) -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(serde_json::to_vec(cursor).map_err(|_| retained())?))
}
fn decode(cursor: &str) -> Result<Cursor> {
    if cursor.len() > 4096 {
        return Err(invalid());
    }
    let bytes = URL_SAFE_NO_PAD.decode(cursor).map_err(|_| invalid())?;
    serde_json::from_slice(&bytes).map_err(|_| invalid())
}
fn fingerprint(input: &Input, tool: &str) -> Result<String> {
    let value = json!({"tool":tool,"query":input.query,"pattern":input.pattern,"case_sensitive":input.case_sensitive,"literal":input.literal,"title":input.title,"page_id":input.page_id});
    Ok(crate::integrity::hash(
        &serde_json::to_vec(&value).map_err(|_| invalid())?,
    ))
}
fn regex(pattern: &str, case_sensitive: bool, literal: bool) -> Result<Regex> {
    if pattern.is_empty() || pattern.len() > 4096 {
        return Err(invalid());
    }
    let escaped = literal.then(|| regex::escape(pattern));
    RegexBuilder::new(escaped.as_deref().unwrap_or(pattern))
        .case_insensitive(!case_sensitive)
        .size_limit(2 * 1024 * 1024)
        .dfa_size_limit(2 * 1024 * 1024)
        .build()
        .map_err(|_| Error::invalid("Invalid or excessively complex Rust regex pattern."))
}
struct ScanBatch {
    rows: Vec<Value>,
    scanned: usize,
    excerpt_bytes: usize,
    next_line: Option<usize>,
    skipped: usize,
}
struct ScanLimits {
    start: usize,
    bytes: usize,
    rows: usize,
    excerpts: usize,
    skip: usize,
}
struct CancelOnDrop(CancellationToken);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
async fn scan_document(
    matcher: Regex,
    text: String,
    limits: ScanLimits,
    cancel: CancellationToken,
    deadline: Instant,
) -> Result<ScanBatch> {
    static SCANNERS: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
    let permit = SCANNERS
        .get_or_init(|| Arc::new(tokio::sync::Semaphore::new(1)))
        .clone()
        .try_acquire_owned()
        .map_err(|_| Error::capacity("Wikipedia regex processing capacity exhausted."))?;
    let token = cancel.child_token();
    let guard = CancelOnDrop(token.clone());
    let work = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let mut batch = ScanBatch {
            rows: Vec::new(),
            scanned: 0,
            excerpt_bytes: 0,
            next_line: None,
            skipped: 0,
        };
        for (index, line) in text.split('\n').enumerate().skip(limits.start) {
            check(deadline, &token)?;
            if line.len() > 1024 * 1024 {
                return Err(Error::capacity("Wikipedia regex line exceeds 1 MiB."));
            }
            if batch.scanned.saturating_add(line.len()) > limits.bytes {
                batch.next_line = Some(index + 1);
                break;
            }
            batch.scanned += line.len();
            if let Some(found) = matcher.find(line) {
                check(deadline, &token)?;
                if batch.skipped < limits.skip {
                    batch.skipped += 1;
                    continue;
                }
                let mut from = found.start().saturating_sub(80);
                while !line.is_char_boundary(from) {
                    from += 1;
                }
                let excerpt = bounded_excerpt(&line[from..], 320);
                if batch.excerpt_bytes.saturating_add(excerpt.len()) > limits.excerpts
                    || batch.rows.len() >= limits.rows
                {
                    batch.next_line = Some(index + 1);
                    break;
                }
                batch.excerpt_bytes += excerpt.len();
                batch.rows.push(json!({"line":index+1,"excerpt":excerpt,"match_start_byte":found.start(),"match_end_byte":found.end()}));
            }
        }
        Ok::<_, Error>(batch)
    });
    let result = tokio::time::timeout(deadline.saturating_duration_since(Instant::now()), work)
        .await
        .map_err(|_| Error::capacity("Wikipedia regex processing deadline exceeded."))?
        .map_err(|_| Error::unavailable("Wikipedia regex worker failed."))?;
    drop(guard);
    result
}

impl WikipediaResearch {
    pub fn new(corpus: Arc<WikipediaCorpus>) -> Self {
        Self { corpus }
    }
    /// Recheck after attribution awaits and immediately before releasing content.
    pub async fn ensure_output_visible(&self, value: &Value) -> Result<()> {
        let mut pending = vec![(value, 0usize, false)];
        let mut visited = 0usize;
        let mut identities = std::collections::BTreeSet::new();
        while let Some((value, depth, wikipedia_context)) = pending.pop() {
            visited += 1;
            if visited > 10_000 || depth > 32 {
                return Err(Error::capacity(
                    "Wikipedia visibility output traversal exceeds its bound.",
                ));
            }
            match value {
                Value::Object(object) => {
                    if object.get("body_public") == Some(&Value::Bool(false)) {
                        continue;
                    }
                    let wikipedia_context = wikipedia_context
                        || object.get("source").and_then(Value::as_str) == Some("wikipedia")
                        || object.get("provider").and_then(Value::as_str) == Some("wikipedia")
                        || object
                            .get("source_url")
                            .and_then(Value::as_str)
                            .is_some_and(|source| source.starts_with("https://en.wikipedia.org/"));
                    if wikipedia_context
                        && let (Some(page), Some(revision)) = (
                            object.get("page_id").and_then(Value::as_u64),
                            object.get("revision_id").and_then(Value::as_u64),
                        )
                    {
                        identities.insert((page, revision));
                    }
                    pending.extend(
                        object
                            .values()
                            .map(|value| (value, depth + 1, wikipedia_context)),
                    );
                }
                Value::Array(items) => pending.extend(
                    items
                        .iter()
                        .map(|value| (value, depth + 1, wikipedia_context)),
                ),
                _ => {}
            }
        }
        if identities.is_empty() {
            return Ok(());
        }
        for _ in 0..2 {
            let epoch = self.corpus.visibility_epoch().await?;
            for &(page, revision) in &identities {
                self.corpus.ensure_visible(page, revision).await?;
            }
            if epoch == self.corpus.visibility_epoch().await? {
                return Ok(());
            }
        }
        Err(Error::unavailable(
            "Wikipedia visibility changed while preparing the response.",
        ))
    }
    pub async fn call(&self, name: &str, value: Value, cancel: CancellationToken) -> Result<Value> {
        let schema = schemas()
            .into_iter()
            .find(|schema| schema["name"].as_str() == Some(name))
            .ok_or_else(invalid)?;
        let arguments = value.as_object().ok_or_else(invalid)?;
        let properties = schema["inputSchema"]["properties"]
            .as_object()
            .ok_or_else(invalid)?;
        if arguments.keys().any(|key| !properties.contains_key(key)) {
            return Err(invalid());
        }
        let input: Input = serde_json::from_value(value).map_err(|_| invalid())?;
        if matches!(
            name,
            "wikipedia.get" | "wikipedia.metadata" | "wikipedia.references" | "wikipedia.history"
        ) && [
            input.title.is_some(),
            input.page_id.is_some(),
            input.capture.is_some(),
        ]
        .into_iter()
        .filter(|present| *present)
        .count()
            != 1
        {
            return Err(invalid());
        }
        if input.page_id == Some(0)
            || input
                .capture
                .as_ref()
                .into_iter()
                .chain(input.snapshot.as_ref())
                .any(|id| !devres_domain::valid_content_id(id))
        {
            return Err(invalid());
        }
        let deadline = Instant::now() + Duration::from_secs(15);
        check(deadline, &cancel)?;
        match name {
            "wikipedia.corpus_status" => self.corpus.status().await,
            "wikipedia.search" if input.mode.as_deref() == Some("upstream") => {
                if input.snapshot.is_some()
                    || input.cursor.is_some()
                    || input.offset != 0
                    || input.case_sensitive
                {
                    return Err(invalid());
                }
                let query = input.query.as_deref().ok_or_else(invalid)?;
                if query.is_empty() || query.len() > 1024 {
                    return Err(invalid());
                }
                self.corpus
                    .upstream_search(query, limit(&input, 20, 100)?, cancel)
                    .await
            }
            "wikipedia.search" | "wikipedia.rg" => self.scan(name, &input, cancel, deadline).await,
            "wikipedia.catalog_search" => self.catalog(&input, cancel, deadline).await,
            "wikipedia.get" => {
                let representation = input.representation.as_deref().unwrap_or("text");
                if !matches!(representation, "text" | "markdown" | "html" | "wikitext") {
                    return Err(invalid());
                }
                if input.snapshot.is_none() && input.capture.is_none() {
                    self.corpus
                        .request_selector(input.title.clone(), input.page_id, cancel.clone())
                        .await?;
                }
                let mut document = self
                    .corpus
                    .research_document(&selector(&input), representation)
                    .await?;
                self.visible(&document).await?;
                let text = document["text"].as_str().ok_or_else(retained)?;
                let page = text_page(text, input.offset, limit(&input, 32768, 32768)?)?;
                public_document(&mut document);
                document["page"] = page;
                Ok(document)
            }
            "wikipedia.metadata" => {
                let mut document = self.corpus.research_metadata(&selector(&input)).await?;
                self.visible(&document).await?;
                public_document(&mut document);
                Ok(document)
            }
            "wikipedia.references" => {
                let mut document = self
                    .corpus
                    .research_document(&selector(&input), "text")
                    .await?;
                self.visible(&document).await?;
                let references = document
                    .pointer("/projection/references")
                    .cloned()
                    .unwrap_or_else(|| json!([]));
                public_document(&mut document);
                if name == "wikipedia.references" {
                    let rows = references.as_array().ok_or_else(retained)?;
                    let end = input
                        .offset
                        .saturating_add(limit(&input, 20, 100)?)
                        .min(rows.len());
                    if input.offset > rows.len() {
                        return Err(invalid());
                    }
                    document["items"] = json!(&rows[input.offset..end]);
                    document["next_offset"] = json!((end < rows.len()).then_some(end));
                }
                Ok(document)
            }
            "wikipedia.history" => self.history(&input, cancel, deadline).await,
            "wikipedia.snapshots" => self.snapshots(&input).await,
            "wikipedia.compare" => self.compare(&input, cancel, deadline).await,
            _ => Err(Error::invalid("Unknown Wikipedia tool.")),
        }
    }
    async fn visible(&self, document: &Value) -> Result<()> {
        self.corpus
            .ensure_visible(page_id(document)?, revision(document)?)
            .await
    }
    async fn catalog(
        &self,
        input: &Input,
        cancel: CancellationToken,
        deadline: Instant,
    ) -> Result<Value> {
        let view = self.corpus.research_view(&selector(input)).await?;
        let page_limit = limit(input, 20, 100)?;
        let rows=self.corpus.research_catalog(&json!({"snapshot":view["id"],"after_page_id":input.after_page_id,"limit":page_limit})).await?;
        let query = input.query.as_deref().unwrap_or("").to_lowercase();
        if input
            .category
            .as_ref()
            .is_some_and(|category| !category.starts_with("Category:") || category.len() > 512)
        {
            return Err(invalid());
        }
        let more = rows.len() == page_limit;
        let mut output = Vec::new();
        let mut after = input.after_page_id;
        for row in rows {
            check(deadline, &cancel)?;
            after = page_id(&row)?;
            let visible = match self.visible(&row).await {
                Ok(()) => true,
                Err(error) if error.code == "wikipedia_withheld" => false,
                Err(error) => return Err(error),
            };
            if visible
                && input
                    .current
                    .is_none_or(|current| meta(&row)["current"].as_bool() == Some(current))
                && input.category.as_ref().is_none_or(|category| {
                    meta(&row)["categories"]
                        .as_array()
                        .is_some_and(|categories| {
                            categories
                                .iter()
                                .any(|value| value.as_str() == Some(category))
                        })
                })
                && meta(&row)["title"]
                    .as_str()
                    .unwrap_or_default()
                    .to_lowercase()
                    .contains(&query)
            {
                output.push(public_meta(&row));
            }
        }
        Ok(
            json!({"snapshot":view,"items":output,"next_after_page_id":more.then_some(after),"coverage":"One bounded catalog page; conjunctive metadata filters can return an empty page before the end."}),
        )
    }
    async fn scan(
        &self,
        tool: &str,
        input: &Input,
        cancel: CancellationToken,
        deadline: Instant,
    ) -> Result<Value> {
        if input.mode.as_deref().is_some_and(|mode| mode != "local") {
            return Err(invalid());
        }
        let matcher = if tool == "wikipedia.rg" {
            regex(
                input.pattern.as_deref().ok_or_else(invalid)?,
                input.case_sensitive,
                input.literal,
            )?
        } else {
            let query = input.query.as_deref().ok_or_else(invalid)?;
            if query.is_empty() || query.len() > 1024 {
                return Err(invalid());
            }
            regex(query, input.case_sensitive, true)?
        };
        let fingerprint = fingerprint(input, tool)?;
        if input.offset > 1_000_000 || input.cursor.is_some() && input.offset != 0 {
            return Err(invalid());
        }
        let old = input.cursor.as_deref().map(decode).transpose()?;
        let historical = old
            .as_ref()
            .map_or(input.snapshot.is_some(), |cursor| cursor.historical);
        let mut skip = old.as_ref().map_or(input.offset, |cursor| cursor.skip);
        if let Some(cursor) = &old
            && (cursor.version != 1
                || cursor.fingerprint != fingerprint
                || cursor.historical && input.snapshot.as_deref() != Some(cursor.snapshot.as_str())
                || input
                    .snapshot
                    .as_ref()
                    .is_some_and(|id| id != &cursor.snapshot))
        {
            return Err(Error::invalid(
                "Wikipedia cursor belongs to another query or snapshot.",
            ));
        }
        let requested = old
            .as_ref()
            .map(|v| json!({"snapshot":v.snapshot}))
            .unwrap_or_else(|| selector(input));
        let view = self.corpus.research_view(&requested).await?;
        let snapshot = view["id"].as_str().ok_or_else(retained)?.to_owned();
        let mut page = old.as_ref().map_or(input.after_page_id, |v| v.page);
        let mut line_start = old.as_ref().map_or(0, |v| v.line);
        let mut scanned = 0usize;
        let mut projection_gaps = 0usize;
        let mut excerpts = 0usize;
        let mut output = Vec::new();
        let mut complete = true;
        let mut next = None;
        'catalog: loop {
            check(deadline, &cancel)?;
            let after = if line_start > 0 {
                page.saturating_sub(1)
            } else {
                page
            };
            let rows = self
                .corpus
                .research_catalog(&json!({"snapshot":snapshot,"after_page_id":after,"limit":100}))
                .await?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                check(deadline, &cancel)?;
                let current = page_id(&row)?;
                if row.get("projection").is_some_and(Value::is_null) {
                    projection_gaps += 1;
                    page = current;
                    line_start = 0;
                    continue;
                }
                if input.page_id.is_some_and(|wanted| wanted != current) {
                    page = current;
                    line_start = 0;
                    continue;
                }
                let mut document = match self
                    .corpus
                    .research_document(&json!({"capture":id(&row)?,"snapshot":snapshot,"require_current":!historical}), "text")
                    .await
                {
                    Ok(document) => document,
                    Err(error)
                        if matches!(
                            error.code.as_str(),
                            "not_found" | "wikipedia_withheld" | "withheld"
                        ) =>
                    {
                        page = current;
                        line_start = 0;
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                self.visible(&document).await?;
                let text = match document
                    .as_object_mut()
                    .and_then(|object| object.remove("text"))
                {
                    Some(Value::String(text)) => text,
                    _ => return Err(retained()),
                };
                let start = if current == page {
                    line_start.saturating_sub(1)
                } else {
                    0
                };
                let batch = scan_document(
                    matcher.clone(),
                    text,
                    ScanLimits {
                        start,
                        bytes: MAX_SCAN.saturating_sub(scanned),
                        rows: limit(input, 20, MAX_ROWS)?.saturating_sub(output.len()),
                        excerpts: MAX_EXCERPTS.saturating_sub(excerpts),
                        skip,
                    },
                    cancel.clone(),
                    deadline,
                )
                .await?;
                scanned += batch.scanned;
                excerpts += batch.excerpt_bytes;
                skip = skip.saturating_sub(batch.skipped);
                for mut found in batch.rows {
                    found["capture"] = public_meta(&document);
                    found["resource_uri"] = document["resource_uri"].clone();
                    output.push(found);
                }
                if let Some(line) = batch.next_line {
                    complete = false;
                    next = Some(Cursor {
                        version: 1,
                        snapshot: snapshot.clone(),
                        fingerprint: fingerprint.clone(),
                        page: current,
                        line,
                        skip,
                        historical,
                    });
                    break 'catalog;
                }
                page = current;
                line_start = 0;
            }
        }
        // A current moderation change overrides every frozen snapshot and cursor.
        for row in &output {
            self.visible(row).await?;
        }
        Ok(
            json!({"snapshot":view,"items":output,"scanned_bytes":scanned,"projection_gaps":projection_gaps,"complete":complete,"next_cursor":next.as_ref().map(encode).transpose()?,"algorithm":if tool=="wikipedia.rg"&&!input.literal{"rust_regex_readable_text"}else{"literal_readable_text"},"coverage":"Captured readable text only; upstream articles and unsupported projections are not searched."}),
        )
    }
    async fn history(
        &self,
        input: &Input,
        cancel: CancellationToken,
        deadline: Instant,
    ) -> Result<Value> {
        let selected = self.corpus.research_metadata(&selector(input)).await?;
        self.visible(&selected).await?;
        let page = page_id(&selected)?;
        let view = self.corpus.research_view(&selector(input)).await?;
        let mut position = i64::try_from(input.offset).map_err(|_| invalid())?;
        let mut rows = Vec::new();
        let mut withheld_count = 0;
        while rows.len() < limit(input, 20, 100)? {
            check(deadline, &cancel)?;
            let batch = self
                .corpus
                .store()
                .wiki_page_captures(page, position, 100, cutoff(&view)?)
                .await?;
            if batch.is_empty() {
                break;
            }
            for row in batch {
                position = row.sequence;
                if row.data["page_id"].as_u64() == Some(page) {
                    let mut item = public_meta(&row.data);
                    match self.visible(&item).await {
                        Ok(()) => {}
                        Err(error) if error.code == "wikipedia_withheld" => {
                            withheld_count += 1;
                            continue;
                        }
                        Err(error) => return Err(error),
                    }
                    item["body_public"] = json!(true);
                    rows.push(item);
                    if rows.len() == limit(input, 20, 100)? {
                        break;
                    }
                }
            }
        }
        Ok(
            json!({"snapshot":view,"page_id":page,"items":rows,"next_offset":position,"withheld_count":withheld_count,"coverage":"Observed captures only; this is not upstream revision-history backfill."}),
        )
    }
    async fn snapshots(&self, input: &Input) -> Result<Value> {
        let rows = self
            .corpus
            .store()
            .wiki_rows(
                "snapshots",
                i64::try_from(input.offset).map_err(|_| invalid())?,
                limit(input, 20, 100)?,
                None,
            )
            .await?;
        let next = rows.last().map(|row| row.sequence);
        Ok(
            json!({"items":rows.into_iter().map(|row|row.data).collect::<Vec<_>>(),"next_offset":next}),
        )
    }
    async fn compare(
        &self,
        input: &Input,
        cancel: CancellationToken,
        deadline: Instant,
    ) -> Result<Value> {
        let before = input.before.as_ref().ok_or_else(invalid)?;
        let after = input.after.as_ref().ok_or_else(invalid)?;
        let representation = input.representation.as_deref().unwrap_or("text");
        if !matches!(representation, "text" | "wikitext" | "metadata") {
            return Err(invalid());
        }
        let left = if representation == "metadata" {
            self.corpus
                .research_metadata(&json!({"capture":before}))
                .await?
        } else {
            self.corpus
                .research_document(&json!({"capture":before}), representation)
                .await?
        };
        let right = if representation == "metadata" {
            self.corpus
                .research_metadata(&json!({"capture":after}))
                .await?
        } else {
            self.corpus
                .research_document(&json!({"capture":after}), representation)
                .await?
        };
        self.visible(&left).await?;
        self.visible(&right).await?;
        if page_id(&left)? != page_id(&right)? {
            return Err(Error::invalid(
                "Wikipedia comparison captures must identify the same page.",
            ));
        }
        if representation == "metadata" {
            return Ok(
                json!({"before":public_meta(&left),"after":public_meta(&right),"changed":public_meta(&left)!=public_meta(&right),"algorithm":"exact_metadata_equality"}),
            );
        }
        let a = left["text"].as_str().ok_or_else(retained)?;
        let b = right["text"].as_str().ok_or_else(retained)?;
        if a.len().saturating_add(b.len()) > MAX_SCAN {
            return Err(Error::capacity(
                "Wikipedia comparison input exceeds 100 MiB.",
            ));
        }
        let mut changes = Vec::new();
        let mut output_bytes = 0usize;
        let mut next = None;
        let mut a = a.split('\n').skip(input.offset);
        let mut b = b.split('\n').skip(input.offset);
        let mut reached_eof = false;
        let mut scanned_lines = 0usize;
        for relative in 0..200_000usize {
            let index = input.offset.checked_add(relative).ok_or_else(invalid)?;
            check(deadline, &cancel)?;
            let old = a.next();
            let new = b.next();
            if old.is_none() && new.is_none() {
                reached_eof = true;
                break;
            }
            scanned_lines += 1;
            if old == new {
                continue;
            }
            if changes.len() >= limit(input, 20, 100)? {
                next = Some(index);
                break;
            }
            let before_truncated = old.is_some_and(|value| value.len() > 1024);
            let after_truncated = new.is_some_and(|value| value.len() > 1024);
            let old = old.map(|v| bounded_excerpt(v, 1024));
            let new = new.map(|v| bounded_excerpt(v, 1024));
            output_bytes += old.map_or(0, str::len) + new.map_or(0, str::len);
            if output_bytes > MAX_EXCERPTS {
                next = Some(index);
                break;
            }
            changes.push(json!({"line":index+1,"before":old,"after":new,"before_truncated":before_truncated,"after_truncated":after_truncated}));
        }
        if next.is_none() && !reached_eof && scanned_lines == 200_000 {
            next = Some(input.offset.saturating_add(scanned_lines));
        }
        self.visible(&left).await?;
        self.visible(&right).await?;
        Ok(
            json!({"before":public_meta(&left),"after":public_meta(&right),"items":changes,"next_offset":next,"algorithm":"positional_line_changes","excerpt_limit_bytes":1024,"complete":next.is_none(),"interpretation":"Observed positional line changes; not an edit-distance or semantic diff."}),
        )
    }
    pub async fn resource(&self, uri: &str, cancel: CancellationToken) -> Result<Value> {
        if uri.len() > 16384 {
            return Err(invalid());
        }
        let url = url::Url::parse(uri).map_err(|_| invalid())?;
        if url.scheme() != "devres"
            || url.host_str() != Some("wikipedia")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.port().is_some()
            || url.fragment().is_some()
        {
            return Err(invalid());
        }
        let parts = url
            .path()
            .trim_start_matches('/')
            .split('/')
            .collect::<Vec<_>>();
        if parts.len() != 2 || !devres_domain::valid_content_id(parts[0]) {
            return Err(invalid());
        }
        let mut input = json!({"capture":parts[0],"representation":parts[1]});
        let mut seen = std::collections::BTreeSet::new();
        for (key, value) in url.query_pairs() {
            if !seen.insert(key.to_string()) || !matches!(key.as_ref(), "offset" | "limit") {
                return Err(invalid());
            }
            input[&*key] = json!(value.parse::<usize>().map_err(|_| invalid())?);
        }
        let output = self.call("wikipedia.get", input, cancel).await?;
        Ok(
            json!({"contents":[{"uri":uri,"mimeType":"text/plain","text":output["page"]["text"],"_meta":{"source_evidence":output}}]}),
        )
    }
}

pub fn schemas() -> Vec<Value> {
    let title = json!({"type":"string","minLength":1,"maxLength":512});
    let hash = json!({"type":"string","pattern":"^(blake3:)?[0-9a-f]{64}$"});
    let mut schemas = Vec::new();
    let definitions = [
        (
            "search",
            "Search retained readable Wikipedia text by default; mode upstream explicitly searches Wikimedia metadata.",
            vec![
                "query",
                "mode",
                "snapshot",
                "cursor",
                "offset",
                "limit",
                "case_sensitive",
            ],
            vec!["query"],
        ),
        (
            "catalog_search",
            "Browse a bounded frozen article catalog with conjunctive title, category and Current filters.",
            vec![
                "query",
                "category",
                "current",
                "snapshot",
                "after_page_id",
                "limit",
            ],
            vec![],
        ),
        (
            "get",
            "Read an exact captured English Wikipedia article as text, derived Markdown, HTML source, or wikitext; offsets count UTF-8 bytes.",
            vec![
                "title",
                "page_id",
                "capture",
                "snapshot",
                "representation",
                "offset",
                "limit",
            ],
            vec![],
        ),
        (
            "metadata",
            "Read captured article identity, source times, freshness and format coverage.",
            vec!["title", "page_id", "capture", "snapshot"],
            vec![],
        ),
        (
            "references",
            "List inert captured article references; targets are never fetched.",
            vec!["title", "page_id", "capture", "snapshot", "offset", "limit"],
            vec![],
        ),
        (
            "history",
            "List locally observed article captures; unobserved upstream revisions are not backfilled.",
            vec!["title", "page_id", "capture", "snapshot", "offset", "limit"],
            vec![],
        ),
        (
            "snapshots",
            "List immutable locally published Wikipedia catalog snapshots.",
            vec!["offset", "limit"],
            vec![],
        ),
        (
            "compare",
            "Compare two captures of the same article with bounded positional text changes or exact metadata equality.",
            vec!["before", "after", "representation", "offset", "limit"],
            vec!["before", "after"],
        ),
        (
            "rg",
            "Search retained readable article lines using a bounded Rust regex or literal:true at a frozen snapshot; never executes a command.",
            vec![
                "pattern",
                "literal",
                "snapshot",
                "cursor",
                "limit",
                "case_sensitive",
                "page_id",
            ],
            vec!["pattern"],
        ),
        (
            "corpus_status",
            "Inspect aggregate collection, stream, freshness, gaps and publication status without administrative controls.",
            vec![],
            vec![],
        ),
    ];
    for (operation, description, fields, required) in definitions {
        let mut properties = json!({});
        for field in &fields {
            properties[*field] = match *field {
                "title" | "category" => title.clone(),
                "current" => json!({"type":"boolean"}),
                "capture" | "snapshot" | "before" | "after" => hash.clone(),
                "page_id" => json!({"type":"integer","minimum":1}),
                "offset" | "after_page_id" => json!({"type":"integer","minimum":0}),
                "limit" => {
                    json!({"type":"integer","minimum":1,"maximum":if operation=="get"{32768}else{100}})
                }
                "mode" => json!({"enum":["local","upstream"],"default":"local"}),
                "representation" => {
                    if operation == "compare" {
                        json!({"enum":["text","wikitext","metadata"],"default":"text"})
                    } else {
                        json!({"enum":["text","markdown","html","wikitext"],"default":"text"})
                    }
                }
                "case_sensitive" | "literal" => json!({"type":"boolean","default":false}),
                "pattern" => json!({"type":"string","minLength":1,"maxLength":4096}),
                "cursor" => {
                    json!({"type":"string","minLength":1,"maxLength":4096,"description":"Frozen continuation. Historical continuations also require the same explicit snapshot."})
                }
                _ => json!({"type":"string","minLength":1,"maxLength":1024}),
            };
        }
        let mut input = json!({"type":"object","properties":properties,"required":required,"additionalProperties":false});
        if matches!(operation, "get" | "metadata" | "references" | "history") {
            input["oneOf"] =
                json!([{"required":["title"]},{"required":["page_id"]},{"required":["capture"]}]);
        }
        schemas.push(json!({"name":format!("wikipedia.{operation}"),"description":description,"inputSchema":input,"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":true}}));
    }
    schemas
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use devres_application::acquisition::{Acquisition, AcquisitionDelegate, WriterEffect};
    use devres_application::wikipedia::{Row, State, WikipediaConfig, WikipediaStore, Write};
    use std::collections::BTreeMap;
    use tokio::sync::Mutex;
    async fn scan_fixture_guard() -> tokio::sync::OwnedMutexGuard<()> {
        static LOCK: OnceLock<Arc<Mutex<()>>> = OnceLock::new();
        LOCK.get_or_init(|| Arc::new(Mutex::new(())))
            .clone()
            .lock_owned()
            .await
    }
    struct DemandDelegate {
        store: Arc<MemoryStore>,
        rows: Vec<Write>,
        view: Value,
        calls: std::sync::atomic::AtomicUsize,
    }
    #[async_trait]
    impl AcquisitionDelegate for DemandDelegate {
        async fn wikipedia_request(&self, title: Option<String>, page: Option<u64>) -> Result<()> {
            if title.as_deref() != Some("Fixture") && page != Some(7) {
                return Err(invalid());
            }
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let alias = format!("title:{}", crate::integrity::hash(b"Fixture"));
            self.store
                .wiki_commit(
                    &self.rows,
                    &[
                        State {
                            key: "snapshot:default".into(),
                            data: self.view.clone(),
                            due_at: None,
                        },
                        State {
                            key: alias,
                            data: json!(7),
                            due_at: None,
                        },
                        State {
                            key: "page:7".into(),
                            data: json!({"page_id":7,"current":false,"current_revision":2}),
                            due_at: None,
                        },
                    ],
                )
                .await
        }
        async fn acquire(&self, _: Acquisition) -> Result<devres_domain::Capture> {
            Err(Error::unavailable("Fixture acquisition unavailable."))
        }
        async fn effect(&self, _: WriterEffect) -> Result<()> {
            Err(Error::unavailable("Fixture effect unavailable."))
        }
    }

    #[derive(Default)]
    struct MemoryStore {
        rows: Mutex<Vec<(String, Row)>>,
        states: Mutex<BTreeMap<String, State>>,
    }
    #[async_trait]
    impl WikipediaStore for MemoryStore {
        async fn wiki_get(&self, kind: &str, key: &str) -> Result<Option<Row>> {
            Ok(self
                .rows
                .lock()
                .await
                .iter()
                .find(|(k, row)| k == kind && row.key == key)
                .map(|(_, row)| row.clone()))
        }
        async fn wiki_rows(
            &self,
            kind: &str,
            after: i64,
            limit: usize,
            cutoff: Option<i64>,
        ) -> Result<Vec<Row>> {
            Ok(self
                .rows
                .lock()
                .await
                .iter()
                .filter(|(k, row)| {
                    k == kind
                        && row.sequence > after
                        && cutoff.is_none_or(|cutoff| row.sequence <= cutoff)
                })
                .take(limit)
                .map(|(_, row)| row.clone())
                .collect())
        }
        async fn wiki_cutoff(&self) -> Result<i64> {
            Ok(self
                .rows
                .lock()
                .await
                .last()
                .map_or(0, |(_, row)| row.sequence))
        }
        async fn wiki_catalog(&self, after: u64, limit: usize, cutoff: i64) -> Result<Vec<Row>> {
            let mut latest = BTreeMap::new();
            for (kind, row) in self.rows.lock().await.iter() {
                if kind == "captures"
                    && row.sequence <= cutoff
                    && row.data["representation"] == "html"
                {
                    let page = row.data["page_id"].as_u64().unwrap();
                    if page > after {
                        latest.insert(page, row.clone());
                    }
                }
            }
            Ok(latest.into_values().take(limit).collect())
        }
        async fn wiki_page_captures(
            &self,
            page: u64,
            after: i64,
            limit: usize,
            cutoff: i64,
        ) -> Result<Vec<Row>> {
            Ok(self
                .rows
                .lock()
                .await
                .iter()
                .filter(|(kind, row)| {
                    kind == "captures"
                        && row.sequence > after
                        && row.sequence <= cutoff
                        && row.data["page_id"] == page
                })
                .take(limit)
                .map(|(_, row)| row.clone())
                .collect())
        }
        async fn wiki_state(&self, key: &str) -> Result<Option<Value>> {
            Ok(self
                .states
                .lock()
                .await
                .get(key)
                .map(|state| state.data.clone()))
        }
        async fn wiki_states(&self, prefix: &str, after: &str, limit: usize) -> Result<Vec<State>> {
            Ok(self
                .states
                .lock()
                .await
                .values()
                .filter(|state| state.key.starts_with(prefix) && state.key.as_str() > after)
                .take(limit)
                .cloned()
                .collect())
        }
        async fn wiki_due(&self, prefix: &str, now: i64, limit: usize) -> Result<Vec<State>> {
            Ok(self
                .states
                .lock()
                .await
                .values()
                .filter(|state| {
                    state.key.starts_with(prefix) && state.due_at.is_some_and(|due| due <= now)
                })
                .take(limit)
                .cloned()
                .collect())
        }
        async fn wiki_commit(&self, writes: &[Write], states: &[State]) -> Result<()> {
            let mut rows = self.rows.lock().await;
            for write in writes {
                let sequence = rows.last().map_or(1, |(_, row)| row.sequence + 1);
                rows.push((
                    write.kind.clone(),
                    Row {
                        sequence,
                        key: write.key.clone(),
                        data: write.data.clone(),
                    },
                ));
            }
            let mut stored = self.states.lock().await;
            for state in states {
                stored.insert(state.key.clone(), state.clone());
            }
            Ok(())
        }
    }
    async fn fixture() -> (
        tempfile::TempDir,
        Arc<MemoryStore>,
        WikipediaResearch,
        Vec<String>,
        String,
    ) {
        use crate::bulk::{BulkArtifactStore, BulkBroker, BulkConfig};
        use crate::wikipedia::{
            cache::CacheMetadata, corpus::ArticleCapture, processing::process_html,
        };
        let root = tempfile::Builder::new()
            .prefix("devres-wiki-research-")
            .tempdir_in("/tmp")
            .unwrap();
        let raw_path = root.path().join("wikipedia/raw-artifacts");
        std::fs::create_dir_all(&raw_path).unwrap();
        let raw = BulkArtifactStore::new(&raw_path, 64 * 1024 * 1024).unwrap();
        let store = Arc::new(MemoryStore::default());
        let mut ids = Vec::new();
        for (revision, text) in [
            (
                1,
                "<h1>Fixture</h1><p>Rust first</p><p>Rust second</p><a href=\"https://example.com/\">Reference</a>",
            ),
            (2, "<h1>Fixture</h1><p>Rust changed</p><p>Rust second</p>"),
        ] {
            let artifact = raw
                .capture_bytes(text.as_bytes().to_vec(), CancellationToken::new())
                .await
                .unwrap();
            let projection = process_html(text.as_bytes(), CancellationToken::new()).unwrap();
            let projected = raw
                .capture_bytes(
                    serde_json::to_vec(&projection).unwrap(),
                    CancellationToken::new(),
                )
                .await
                .unwrap();
            let id = crate::integrity::hash(text.as_bytes());
            let capture = ArticleCapture {
                id: id.clone(),
                page_id: 7,
                revision_id: revision,
                title: "Fixture".into(),
                representation: "html".into(),
                source_url:
                    "https://en.wikipedia.org/w/rest.php/v1/page/Fixture/with_html?redirect=no"
                        .into(),
                artifact,
                projection: Some(projected),
                observed_at: revision as i64,
                validated_at: revision as i64,
                expires_at: i64::MAX,
                current: Some(false),
                categories: vec!["Category:Science".into()],
                processing_gaps: vec![],
                cache: CacheMetadata::default(),
                license: json!({"id":"https://creativecommons.org/licenses/by-sa/4.0/","url":"https://creativecommons.org/licenses/by-sa/4.0/"}),
                acquisition_policy_epoch: devres_domain::attribution::ATTRIBUTION_POLICY_EPOCH,
                acquisition_policy_fingerprint:
                    devres_domain::attribution::ATTRIBUTION_POLICY_FINGERPRINT.into(),
            };
            store
                .wiki_commit(
                    &[Write {
                        kind: "captures".into(),
                        key: id.clone(),
                        data: serde_json::to_value(capture).unwrap(),
                    }],
                    &[],
                )
                .await
                .unwrap();
            ids.push(id);
        }
        let snapshot = crate::integrity::hash(b"fixture snapshot");
        let view = json!({"id":snapshot,"cutoff":2,"published_at":3});
        store
            .wiki_commit(
                &[Write {
                    kind: "snapshots".into(),
                    key: snapshot.clone(),
                    data: view.clone(),
                }],
                &[
                    State {
                        key: "visibility:epoch".into(),
                        data: json!(0),
                        due_at: None,
                    },
                    State {
                        key: "snapshot:default".into(),
                        data: view,
                        due_at: None,
                    },
                ],
            )
            .await
            .unwrap();
        let corpus = WikipediaCorpus::new_reader(
            store.clone(),
            Arc::new(BulkBroker::new(BulkConfig::default()).unwrap()),
            root.path(),
            WikipediaConfig::default(),
        )
        .unwrap();
        (
            root,
            store,
            WikipediaResearch::new(Arc::new(corpus)),
            ids,
            snapshot,
        )
    }
    #[test]
    fn regex_complexity_invalid_patterns_and_query_bound_cursor() {
        assert!(regex("[", false, false).is_err());
        assert!(regex(&"a".repeat(4097), false, false).is_err());
        assert!(regex("rust", false, false).unwrap().is_match("Rust"));
        assert!(regex("a.b", true, false).unwrap().is_match("aXb"));
        assert!(!regex("a.b", true, true).unwrap().is_match("aXb"));
        assert!(regex("a.b", true, true).unwrap().is_match("a.b"));
        assert!(regex(&".".repeat(4096), true, true).is_ok());
        assert!(regex(&".".repeat(4097), true, true).is_err());
        let input = Input {
            query: Some("rust".into()),
            ..Default::default()
        };
        let cursor = Cursor {
            version: 1,
            snapshot: "a".repeat(64),
            fingerprint: fingerprint(&input, "wikipedia.search").unwrap(),
            page: 7,
            line: 3,
            skip: 0,
            historical: true,
        };
        let decoded = decode(&encode(&cursor).unwrap()).unwrap();
        assert_eq!(decoded.page, 7);
        assert_eq!(decoded.line, 3);
        assert_ne!(
            decoded.fingerprint,
            fingerprint(
                &Input {
                    query: Some("python".into()),
                    ..Default::default()
                },
                "wikipedia.search"
            )
            .unwrap()
        );
    }
    #[test]
    fn unicode_excerpt_and_exact_tool_group() {
        assert_eq!(bounded_excerpt("한글", 4), "한");
        assert_eq!(schemas().len(), 10);
        assert!(
            schemas()
                .iter()
                .all(|schema| schema["name"].as_str().unwrap().starts_with("wikipedia."))
        );
    }
    #[tokio::test]
    async fn frozen_tools_pagination_regex_compare_and_resources() {
        let _guard = scan_fixture_guard().await;
        let (_root, _store, research, ids, snapshot) = fixture().await;
        let token = CancellationToken::new();
        let first = research
            .call(
                "wikipedia.get",
                json!({"capture":ids[0],"limit":12}),
                token.clone(),
            )
            .await
            .unwrap();
        assert!(first["capture"].get("artifact").is_none());
        assert_eq!(first["source_evidence"]["wikipedia_evidence"]["id"], ids[0]);
        let next = first["page"]["next_offset"].as_u64().unwrap();
        let second = research
            .call(
                "wikipedia.get",
                json!({"capture":ids[0],"offset":next,"limit":32768}),
                token.clone(),
            )
            .await
            .unwrap();
        assert!(
            second["page"]["text"]
                .as_str()
                .unwrap()
                .contains("Rust second")
        );
        let matches = research
            .call(
                "wikipedia.rg",
                json!({"pattern":"Rust","snapshot":snapshot,"limit":1}),
                token.clone(),
            )
            .await
            .unwrap();
        assert_eq!(matches["items"].as_array().unwrap().len(), 1);
        let cursor = matches["next_cursor"].as_str().unwrap();
        assert!(
            research
                .call(
                    "wikipedia.rg",
                    json!({"pattern":"Rust","literal":true,"snapshot":snapshot,"cursor":cursor}),
                    token.clone()
                )
                .await
                .is_err()
        );
        let regex_result = research
            .call(
                "wikipedia.rg",
                json!({"pattern":"Rust.changed","snapshot":snapshot}),
                token.clone(),
            )
            .await
            .unwrap();
        let literal_result = research
            .call(
                "wikipedia.rg",
                json!({"pattern":"Rust.changed","literal":true,"snapshot":snapshot}),
                token.clone(),
            )
            .await
            .unwrap();
        assert_eq!(regex_result["items"].as_array().unwrap().len(), 1);
        assert!(literal_result["items"].as_array().unwrap().is_empty());
        let continued = research
            .call(
                "wikipedia.rg",
                json!({"pattern":"Rust","snapshot":snapshot,"cursor":cursor,"limit":1}),
                token.clone(),
            )
            .await
            .unwrap();
        assert_ne!(matches["items"][0]["line"], continued["items"][0]["line"]);
        assert!(
            research
                .call(
                    "wikipedia.rg",
                    json!({"pattern":"Python","cursor":cursor}),
                    token.clone()
                )
                .await
                .is_err()
        );
        assert!(
            research
                .call(
                    "wikipedia.get",
                    json!({"capture":ids[0],"title":"Fixture"}),
                    token.clone()
                )
                .await
                .is_err()
        );
        assert!(
            research
                .call(
                    "wikipedia.get",
                    json!({"capture":ids[0],"pattern":"ignored"}),
                    token.clone()
                )
                .await
                .is_err()
        );
        let changes = research
            .call(
                "wikipedia.compare",
                json!({"before":ids[0],"after":ids[1]}),
                token.clone(),
            )
            .await
            .unwrap();
        assert!(!changes["items"].as_array().unwrap().is_empty());
        let refs = research
            .call(
                "wikipedia.references",
                json!({"capture":ids[0]}),
                token.clone(),
            )
            .await
            .unwrap();
        assert_eq!(refs["items"].as_array().unwrap().len(), 1);
        let resource = research
            .resource(&format!("devres://wikipedia/{}/markdown", ids[0]), token)
            .await
            .unwrap();
        assert!(
            resource["contents"][0]["text"]
                .as_str()
                .unwrap()
                .contains("# Fixture")
        );
    }
    #[tokio::test]
    async fn withholding_applies_to_historical_bodies_metadata_and_history() {
        let (_root, store, research, ids, _snapshot) = fixture().await;
        let already_built = research
            .call(
                "wikipedia.get",
                json!({"capture":ids[0]}),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        store
            .wiki_commit(
                &[],
                &[State {
                    key: "visibility:page:7".into(),
                    data: json!({"blocked":true}),
                    due_at: None,
                }],
            )
            .await
            .unwrap();
        assert_eq!(
            research
                .ensure_output_visible(&already_built)
                .await
                .unwrap_err()
                .code,
            "wikipedia_withheld"
        );
        for capture in &ids {
            assert!(
                research
                    .call(
                        "wikipedia.get",
                        json!({"capture":capture}),
                        CancellationToken::new()
                    )
                    .await
                    .is_err()
            );
            assert!(
                research
                    .resource(
                        &format!("devres://wikipedia/{capture}/html"),
                        CancellationToken::new()
                    )
                    .await
                    .is_err()
            );
        }
        let metadata = research
            .call(
                "wikipedia.metadata",
                json!({"capture":ids[0]}),
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(metadata.code, "wikipedia_withheld");
        let history = research
            .call(
                "wikipedia.history",
                json!({"capture":ids[0]}),
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(history.code, "wikipedia_withheld");
    }
    #[tokio::test]
    async fn current_search_cursor_does_not_bypass_expiry_and_explicit_snapshot_is_historical() {
        let _guard = scan_fixture_guard().await;
        let (_root, store, research, ids, snapshot) = fixture().await;
        let first = research
            .call(
                "wikipedia.rg",
                json!({"pattern":"Rust","limit":1}),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        let cursor = first["next_cursor"].as_str().unwrap();
        let mut tampered = decode(cursor).unwrap();
        tampered.historical = true;
        assert!(
            research
                .call(
                    "wikipedia.rg",
                    json!({"pattern":"Rust","cursor":encode(&tampered).unwrap()}),
                    CancellationToken::new()
                )
                .await
                .is_err()
        );
        {
            let mut rows = store.rows.lock().await;
            let (_, row) = rows.iter_mut().find(|(_, row)| row.key == ids[1]).unwrap();
            row.data["expires_at"] = json!(devres_domain::unix_now() - 1000);
        }
        assert!(
            research
                .call(
                    "wikipedia.rg",
                    json!({"pattern":"Rust","cursor":cursor}),
                    CancellationToken::new()
                )
                .await
                .is_err()
        );
        assert!(
            research
                .call(
                    "wikipedia.rg",
                    json!({"pattern":"Rust","snapshot":snapshot}),
                    CancellationToken::new()
                )
                .await
                .is_ok()
        );
    }
    #[tokio::test]
    async fn catalog_metadata_filters_are_conjunctive_and_offset_skips_matches() {
        let _guard = scan_fixture_guard().await;
        let (_root, _store, research, _ids, snapshot) = fixture().await;
        let accepted = research
            .call(
                "wikipedia.catalog_search",
                json!({"query":"Fixture","category":"Category:Science","current":false}),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(accepted["items"].as_array().unwrap().len(), 1);
        assert!(accepted["next_after_page_id"].is_null());
        for args in [
            json!({"query":"Fixture","category":"Category:Technology"}),
            json!({"query":"Other","category":"Category:Science"}),
            json!({"current":true}),
        ] {
            let rejected = research
                .call("wikipedia.catalog_search", args, CancellationToken::new())
                .await
                .unwrap();
            assert!(rejected["items"].as_array().unwrap().is_empty());
        }
        let second = research
            .call(
                "wikipedia.search",
                json!({"query":"Rust","snapshot":snapshot,"offset":1}),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(second["items"].as_array().unwrap().len(), 1);
        assert!(
            second["items"][0]["excerpt"]
                .as_str()
                .unwrap()
                .contains("Rust second")
        );
    }
    #[tokio::test]
    async fn initial_reader_demand_precedes_snapshot_selection_for_titles_and_page_ids() {
        use crate::bulk::{BulkBroker, BulkConfig};
        for (initial, input) in [
            (None, json!({"title":"Fixture"})),
            (
                Some(json!({"id":"empty","cutoff":0,"published_at":0})),
                json!({"page_id":7}),
            ),
        ] {
            let (root, store, _research, _ids, _snapshot) = fixture().await;
            let rows = std::mem::take(&mut *store.rows.lock().await)
                .into_iter()
                .map(|(kind, row)| Write {
                    kind,
                    key: row.key,
                    data: row.data,
                })
                .collect::<Vec<_>>();
            let view = store.wiki_state("snapshot:default").await.unwrap().unwrap();
            if let Some(initial) = initial {
                store
                    .wiki_commit(
                        &[],
                        &[State {
                            key: "snapshot:default".into(),
                            data: initial,
                            due_at: None,
                        }],
                    )
                    .await
                    .unwrap();
            } else {
                store.states.lock().await.remove("snapshot:default");
            }
            let delegate = Arc::new(DemandDelegate {
                store: store.clone(),
                rows,
                view,
                calls: std::sync::atomic::AtomicUsize::new(0),
            });
            let corpus = WikipediaCorpus::new_reader(
                store.clone(),
                Arc::new(BulkBroker::new(BulkConfig::default()).unwrap()),
                root.path(),
                WikipediaConfig::default(),
            )
            .unwrap()
            .with_delegate(Some(delegate.clone()));
            let document = corpus.research_document(&input, "text").await.unwrap();
            assert_eq!(document["capture"]["revision_id"], 2);
            assert_eq!(document["snapshot"]["cutoff"], 2);
            assert_eq!(delegate.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
            let research = WikipediaResearch::new(Arc::new(corpus));
            assert!(
                research
                    .call("wikipedia.get", input, CancellationToken::new())
                    .await
                    .is_ok()
            );
        }
    }
    #[tokio::test]
    async fn fresh_capture_with_observed_newer_event_is_labeled_pending() {
        let (_root, store, research, ids, _snapshot) = fixture().await;
        store
            .wiki_commit(
                &[],
                &[State {
                    key: "page:7".into(),
                    data: json!({"current":false,"current_revision":2,"dirty_revision":3}),
                    due_at: None,
                }],
            )
            .await
            .unwrap();
        let document = research
            .corpus
            .research_document(&json!({"capture":ids[1],"require_current":true}), "text")
            .await
            .unwrap();
        assert_eq!(document["stale"], true);
        assert_eq!(document["capture"]["observed_newer_revision"], true);
        assert_eq!(document["capture"]["update_pending"], true);
        store
            .wiki_commit(
                &[],
                &[
                    State {
                        key: "page:7".into(),
                        data: json!({"current":false,"current_revision":3,"dirty_revision":null}),
                        due_at: None,
                    },
                    State {
                        key: "events:7".into(),
                        data: json!({"last_event_revision":3,"dirty_revision":null}),
                        due_at: None,
                    },
                ],
            )
            .await
            .unwrap();
        let html_behind_source = research
            .corpus
            .research_document(&json!({"capture":ids[1],"require_current":true}), "text")
            .await
            .unwrap();
        assert_eq!(
            html_behind_source["capture"]["observed_newer_revision"],
            true
        );
        assert_eq!(html_behind_source["capture"]["update_pending"], true);
    }
    #[tokio::test]
    async fn projection_gap_retains_html_and_is_visible_in_metadata_and_search_coverage() {
        let _guard = scan_fixture_guard().await;
        let (_root, store, research, ids, snapshot) = fixture().await;
        {
            let mut rows = store.rows.lock().await;
            let (_, row) = rows.iter_mut().find(|(_, row)| row.key == ids[1]).unwrap();
            row.data["projection"] = Value::Null;
            row.data["processing_gaps"] = json!(["fixture_projection_bound"]);
        }
        let raw = research
            .call(
                "wikipedia.get",
                json!({"capture":ids[1],"representation":"html"}),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert!(raw["page"]["text"].as_str().unwrap().contains("<h1>"));
        assert!(
            research
                .call(
                    "wikipedia.get",
                    json!({"capture":ids[1]}),
                    CancellationToken::new()
                )
                .await
                .is_err()
        );
        let metadata = research
            .call(
                "wikipedia.metadata",
                json!({"capture":ids[1]}),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(
            metadata["capture"]["processing_gaps"],
            json!(["fixture_projection_bound"])
        );
        let searched = research
            .call(
                "wikipedia.search",
                json!({"query":"Rust","snapshot":snapshot}),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(searched["projection_gaps"], 1);
        assert!(searched["items"].as_array().unwrap().is_empty());
    }
    #[tokio::test]
    async fn source_only_article_metadata_and_history_do_not_require_html() {
        use crate::bulk::BulkArtifactStore;
        let (root, store, research, ids, snapshot) = fixture().await;
        let raw = BulkArtifactStore::new(
            root.path().join("wikipedia/raw-artifacts"),
            64 * 1024 * 1024,
        )
        .unwrap();
        let source = raw
            .capture_bytes(
                b"Fixture article wikitext".to_vec(),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        {
            let mut rows = store.rows.lock().await;
            for (_, row) in rows.iter_mut().filter(|(kind, _)| kind == "captures") {
                row.data["representation"] = json!("wikitext");
                row.data["source_url"] =
                    json!("https://en.wikipedia.org/w/rest.php/v1/page/Fixture?redirect=no");
                row.data["artifact"] = serde_json::to_value(&source).unwrap();
                row.data["projection"] = Value::Null;
            }
        }
        store
            .wiki_commit(
                &[],
                &[State {
                    key: format!("title:{}", crate::integrity::hash(b"Fixture")),
                    data: json!(7),
                    due_at: None,
                }],
            )
            .await
            .unwrap();
        let metadata = research
            .call(
                "wikipedia.metadata",
                json!({"title":"Fixture"}),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(metadata["capture"]["representation"], "wikitext");
        let history = research
            .call(
                "wikipedia.history",
                json!({"title":"Fixture"}),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(history["items"].as_array().unwrap().len(), 2);
        let selected = json!({"title":"Fixture","snapshot":snapshot});
        assert!(
            research
                .corpus
                .research_document(&selected, "text")
                .await
                .is_err()
        );
        let original = research
            .corpus
            .research_document(&selected, "wikitext")
            .await
            .unwrap();
        assert_eq!(original["text"], "Fixture article wikitext");
        assert_eq!(
            research
                .call(
                    "wikipedia.get",
                    json!({"capture":ids[1],"representation":"wikitext"}),
                    CancellationToken::new()
                )
                .await
                .unwrap()["page"]["text"],
            "Fixture article wikitext"
        );
        assert!(
            research
                .call(
                    "wikipedia.metadata",
                    json!({"title":"Fixture","snapshot":"a".repeat(64)}),
                    CancellationToken::new()
                )
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn snapshot_cutoff_cannot_be_ignored_and_read_does_not_acquire() {
        let (_root, store, research, ids, _snapshot) = fixture().await;
        let snapshot = crate::integrity::hash(b"earlier snapshot");
        store
            .wiki_commit(
                &[Write {
                    kind: "snapshots".into(),
                    key: snapshot.clone(),
                    data: json!({"id":snapshot,"cutoff":1,"published_at":1}),
                }],
                &[],
            )
            .await
            .unwrap();
        assert!(
            research
                .call(
                    "wikipedia.get",
                    json!({"capture":ids[1],"snapshot":snapshot}),
                    CancellationToken::new()
                )
                .await
                .is_err()
        );
        let frozen = research
            .call(
                "wikipedia.get",
                json!({"page_id":7,"snapshot":snapshot}),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(frozen["capture"]["revision_id"], 1);
        assert!(
            research
                .call(
                    "wikipedia.get",
                    json!({"page_id":7,"snapshot":"b".repeat(64)}),
                    CancellationToken::new()
                )
                .await
                .is_err()
        );
    }
}
