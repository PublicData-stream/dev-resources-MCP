//! Bounded local advisory research over immutable public snapshots.
use crate::research::{capture_json, text_page};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use devres_application::advisory::{AdvisoryRecord, AdvisoryRow, AdvisorySnapshot, AdvisoryStore};
use devres_domain::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    sync::{Arc, LazyLock},
    time::{Duration, Instant},
};

const MAX_SCAN: usize = 1000;
const MAX_CURSOR: usize = 16384;
const PROCESSING_TIME: Duration = Duration::from_secs(15);
static SEARCH_ADMISSION: LazyLock<Arc<tokio::sync::Semaphore>> =
    LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(2)));
static READ_ADMISSION: LazyLock<Arc<tokio::sync::Semaphore>> =
    LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(2)));

async fn admit_reads() -> Result<tokio::sync::OwnedSemaphorePermit> {
    tokio::time::timeout(PROCESSING_TIME, READ_ADMISSION.clone().acquire_owned())
        .await
        .map_err(|_| Error::capacity("Advisory read admission deadline exceeded."))?
        .map_err(|_| Error::capacity("Advisory read admission is closed."))
}

pub struct AdvisoryResearch {
    store: Arc<dyn AdvisoryStore>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
struct Filters {
    name: Option<String>,
    id: Option<String>,
    alias: Option<String>,
    classification: Option<String>,
    category: Option<String>,
    informational: Option<String>,
    os: Option<String>,
    arch: Option<String>,
    date_from: Option<String>,
    date_through: Option<String>,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Input {
    id: Option<String>,
    format: Option<String>,
    snapshot: Option<String>,
    query: String,
    filters: Filters,
    cursor: Option<String>,
    offset: usize,
    limit: Option<usize>,
    kind: Option<String>,
    #[serde(rename = "ref")]
    reference: Option<String>,
    history_snapshot: Option<i64>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    version: u8,
    fingerprint: String,
    snapshot: Option<String>,
    cutoff: Option<i64>,
    after: i64,
    within: usize,
}

impl Input {
    fn format(&self) -> Result<&str> {
        let format = self.format.as_deref().unwrap_or("rustsec");
        if !matches!(format, "rustsec" | "osv") {
            return Err(Error::invalid("Advisory format must be rustsec or osv."));
        }
        Ok(format)
    }
    fn id(&self) -> Result<&str> {
        let id = self
            .id
            .as_deref()
            .ok_or_else(|| Error::invalid("Advisory ID is required."))?;
        canonical_id(id)?;
        Ok(id)
    }
    fn limit(&self, text: bool) -> Result<usize> {
        let limit = self.limit.unwrap_or(if text { 32768 } else { 20 });
        if limit == 0
            || limit > if text { 32768 } else { 100 }
            || (!text && self.offset > 10000)
            || (self.cursor.is_some() && self.offset != 0)
        {
            return Err(Error::invalid("Advisory page exceeds supported bounds."));
        }
        Ok(limit)
    }
    fn validate(&self) -> Result<()> {
        self.format()?;
        if self.snapshot.as_ref().is_some_and(|id| !valid_hash(id))
            || self.history_snapshot.is_some_and(|v| v < 0)
            || self.cursor.as_ref().is_some_and(|v| v.len() > MAX_CURSOR)
            || self.reference.as_ref().is_some_and(|v| !valid_ref(v))
        {
            return Err(Error::invalid("Invalid advisory snapshot, cursor, or ref."));
        }
        for value in [
            Some(&self.query),
            self.filters.name.as_ref(),
            self.filters.id.as_ref(),
            self.filters.alias.as_ref(),
            self.filters.classification.as_ref(),
            self.filters.category.as_ref(),
            self.filters.informational.as_ref(),
            self.filters.os.as_ref(),
            self.filters.arch.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            if value.chars().count() > 256 || value.chars().any(char::is_control) {
                return Err(Error::invalid(
                    "Advisory query or filter exceeds supported bounds.",
                ));
            }
        }
        if let Some(name) = &self.filters.name {
            crate::crates_io::packages::validate_name(name)?;
        }
        if let Some(id) = &self.filters.id {
            canonical_id(id)?;
        }
        if self
            .filters
            .classification
            .as_deref()
            .is_some_and(|v| !matches!(v, "vulnerability" | "informational" | "withdrawn"))
        {
            return Err(Error::invalid("Invalid advisory classification filter."));
        }
        for date in [&self.filters.date_from, &self.filters.date_through]
            .into_iter()
            .flatten()
        {
            validate_date(date)?;
        }
        if self
            .filters
            .date_from
            .as_ref()
            .zip(self.filters.date_through.as_ref())
            .is_some_and(|(a, b)| a > b)
        {
            return Err(Error::invalid("Advisory date bounds are reversed."));
        }
        Ok(())
    }
    fn fingerprint(&self, tool: &str) -> Result<String> {
        let format = if tool == "advisory.snapshots" {
            json!(self.format)
        } else {
            json!(self.format()?)
        };
        let value = json!({"tool":tool,"id":self.id,"format":format,"query":self.query,
            "filters":self.filters,"ref":self.reference,"kind":self.kind.as_deref().unwrap_or("commits")});
        let bytes = serde_json::to_vec(&value)
            .map_err(|_| Error::integrity("Advisory query identity failed."))?;
        Ok(crate::integrity::hash(&bytes))
    }
    fn cursor(&self, tool: &str) -> Result<Option<Cursor>> {
        let Some(encoded) = &self.cursor else {
            return Ok(None);
        };
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| Error::invalid("Invalid advisory cursor."))?;
        let cursor: Cursor = serde_json::from_slice(&bytes)
            .map_err(|_| Error::invalid("Invalid advisory cursor."))?;
        let expected = match cursor.version {
            1 => {
                let format = if tool == "advisory.snapshots" {
                    json!(self.format)
                } else {
                    json!(self.format()?)
                };
                let value = json!({"tool":tool,"id":self.id,"format":format,"query":self.query,
                    "filters":self.filters,"ref":self.reference,"kind":self.kind.as_deref().unwrap_or("commits")});
                crate::integrity::legacy_hash(
                    &serde_json::to_vec(&value)
                        .map_err(|_| Error::integrity("Advisory query identity failed."))?,
                )
            }
            2 => self.fingerprint(tool)?,
            _ => return Err(Error::invalid("Unsupported advisory cursor version.")),
        };
        if cursor.fingerprint != expected
            || cursor.after < 0
            || cursor.within > 100
            || cursor.cutoff.is_some_and(|v| v < 0)
            || self
                .snapshot
                .as_ref()
                .is_some_and(|id| cursor.snapshot.as_ref() != Some(id))
            || self
                .history_snapshot
                .is_some_and(|cutoff| cursor.cutoff != Some(cutoff))
        {
            return Err(Error::invalid(
                "Advisory cursor belongs to a different query or snapshot.",
            ));
        }
        Ok(Some(cursor))
    }
}

impl AdvisoryResearch {
    pub fn new(store: Arc<dyn AdvisoryStore>) -> Self {
        Self { store }
    }

    pub async fn call(&self, tool: &str, value: Value) -> Result<Value> {
        let fields: &[&str] = match tool {
            "advisory.get" => &["id", "format", "snapshot", "offset", "limit"],
            "advisory.catalog_search" => &[
                "query", "filters", "format", "snapshot", "offset", "limit", "cursor",
            ],
            "advisory.history" => &[
                "id",
                "format",
                "ref",
                "history_snapshot",
                "offset",
                "limit",
                "cursor",
            ],
            "advisory.snapshots" => &[
                "kind",
                "format",
                "ref",
                "history_snapshot",
                "offset",
                "limit",
                "cursor",
            ],
            "advisory.corpus_status" => &[],
            _ => return Err(Error::not_found("Unknown advisory research tool.")),
        };
        if value
            .as_object()
            .is_none_or(|v| v.keys().any(|key| !fields.contains(&key.as_str())))
        {
            return Err(Error::invalid(
                "Arguments do not match the advisory tool schema.",
            ));
        }
        let input: Input = serde_json::from_value(value)
            .map_err(|_| Error::invalid("Arguments do not match the advisory tool schema."))?;
        input.validate()?;
        let _read_permit = admit_reads().await?;
        match tool {
            "advisory.get" => self.get(&input).await,
            "advisory.catalog_search" => self.catalog(&input).await,
            "advisory.history" => self.history(&input).await,
            "advisory.snapshots" => self.snapshots(&input).await,
            "advisory.corpus_status" => self.store.advisory_status().await,
            _ => Err(Error::not_found("Unknown advisory research tool.")),
        }
    }

    async fn snapshot(&self, id: Option<&str>, format: &str) -> Result<AdvisorySnapshot> {
        let snapshot = self
            .store
            .advisory_snapshot(id, format)
            .await?
            .ok_or_else(|| {
                if id.is_some() {
                    Error::not_found("Advisory snapshot is absent or has a different format.")
                } else {
                    Error::unavailable("No advisory snapshot is published.")
                }
            })?;
        if snapshot.format != format {
            return Err(Error::invalid("Advisory snapshot has a different format."));
        }
        if id.is_none() && !snapshot.assessment_complete(devres_domain::unix_now()) {
            return Err(Error::unavailable(
                "Default advisory snapshot is expired or incomplete; select historical evidence explicitly.",
            ));
        }
        Ok(snapshot)
    }

    async fn get(&self, input: &Input) -> Result<Value> {
        let id = input.id()?;
        let snapshot = self
            .snapshot(input.snapshot.as_deref(), input.format()?)
            .await?;
        let record = find_record(&snapshot, id)
            .ok_or_else(|| Error::not_found("Advisory is absent from the selected snapshot."))?;
        let page = text_page(&record.body, input.offset, input.limit(true)?)?;
        Ok(
            json!({"advisory":record.metadata,"id":record.id,"format":record.format,"path":record.path,
            "body_hash":record.body_hash,"page":page,"snapshot":snapshot_metadata(&snapshot),
            "source_url":source_url(&snapshot,record),"resource_uri":resource_uri(&snapshot,record)}),
        )
    }

    async fn catalog(&self, input: &Input) -> Result<Value> {
        let limit = input.limit(false)?;
        let cursor = input.cursor("advisory.catalog_search")?;
        let selected = cursor
            .as_ref()
            .and_then(|v| v.snapshot.as_deref())
            .or(input.snapshot.as_deref());
        let permit = SEARCH_ADMISSION
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::capacity("Advisory search capacity exhausted."))?;
        let snapshot = self.snapshot(selected, input.format()?).await?;
        let offset = cursor.as_ref().map_or(input.offset, |v| v.after as usize);
        let input = input.clone();
        tokio::task::spawn_blocking(move || {
        let _permit=permit;
        let deadline = Instant::now() + PROCESSING_TIME;
        let mut matches = Vec::new();
        for record in &snapshot.records {
            if Instant::now() >= deadline { return Err(Error::capacity("Advisory search processing deadline exceeded.")); }
            if record_matches(record, &input) { matches.push(record); }
        }
        matches.sort_by(|a,b| a.id.cmp(&b.id).then_with(|| a.path.cmp(&b.path)));
        let offset=offset.min(matches.len());
        let next = offset.saturating_add(limit).min(matches.len());
        let next_cursor = if next < matches.len() {
            Some(encode_cursor(Cursor { version:2, fingerprint:input.fingerprint("advisory.catalog_search")?,
                snapshot:Some(snapshot.id.clone()), cutoff:None, after:next as i64, within:0 })?)
        } else { None };
        let items = matches[offset..next].iter().map(|record| record_summary(&snapshot,record)).collect::<Vec<_>>();
        Ok(json!({"items":items,"total":matches.len(),"offset":offset,"next_offset":if next < matches.len() && next <= 10000 {Some(next)}else{None},
            "next_cursor":next_cursor,"snapshot":snapshot_metadata(&snapshot)}))
        }).await.map_err(|_|Error::unavailable("Advisory search worker failed."))?
    }

    async fn view(&self, input: &Input, cursor: Option<&Cursor>) -> Result<i64> {
        let highwater = self.store.advisory_cutoff().await?;
        let cutoff = cursor
            .and_then(|v| v.cutoff)
            .or(input.history_snapshot)
            .unwrap_or(highwater);
        if cutoff < 0 || cutoff > highwater {
            return Err(Error::invalid("Advisory history snapshot is invalid."));
        }
        Ok(cutoff)
    }

    async fn rows(
        &self,
        kind: &str,
        input: &Input,
        cutoff: i64,
        after: i64,
        limit: usize,
    ) -> Result<Vec<AdvisoryRow>> {
        if kind == "commits"
            && let Some(reference) = input.reference.as_deref()
        {
            return self
                .store
                .advisory_ref_rows(reference, cutoff, after, limit)
                .await;
        }
        self.store
            .advisory_rows(kind, Some(cutoff), after, limit)
            .await
    }

    async fn snapshots(&self, input: &Input) -> Result<Value> {
        let limit = input.limit(false)?;
        let kind = input.kind.as_deref().unwrap_or("commits");
        if !matches!(kind, "refs" | "commits") {
            return Err(Error::invalid(
                "Advisory snapshot kind must be refs or commits.",
            ));
        }
        let cursor = input.cursor("advisory.snapshots")?;
        let cutoff = self.view(input, cursor.as_ref()).await?;
        let mut after = cursor.as_ref().map_or(0, |v| v.after);
        let mut skip = input.offset;
        let mut items = Vec::new();
        let deadline = Instant::now() + PROCESSING_TIME;
        let mut exhausted = false;
        let mut scanned = 0;
        while items.len() < limit && scanned < MAX_SCAN.saturating_add(input.offset) {
            if Instant::now() >= deadline {
                return Err(Error::capacity("Advisory discovery deadline exceeded."));
            }
            let batch = self.rows(kind, input, cutoff, after, 1).await?;
            let Some(row) = batch.into_iter().next() else {
                exhausted = true;
                break;
            };
            after = row.sequence;
            scanned += 1;
            let mut data = if kind == "commits" {
                self.store
                    .advisory_commit(&row.key, Some(cutoff))
                    .await?
                    .ok_or_else(|| {
                        Error::integrity("Advisory graph row is absent at its selected cutoff.")
                    })?
                    .data
            } else {
                row.data
            };
            if kind == "refs" {
                if let Some(format) = input.format.as_deref() {
                    let refs = data
                        .get_mut("refs")
                        .and_then(Value::as_array_mut)
                        .ok_or_else(|| Error::integrity("Invalid stored advisory refs."))?;
                    refs.retain(|item| item["snapshots"][format].as_str().is_some());
                    if refs.is_empty() {
                        continue;
                    }
                }
                if let Some(reference) = &input.reference {
                    let refs = data
                        .get_mut("refs")
                        .and_then(Value::as_array_mut)
                        .ok_or_else(|| Error::integrity("Invalid stored advisory refs."))?;
                    refs.retain(|item| item["name"].as_str() == Some(reference));
                    if refs.is_empty() {
                        continue;
                    }
                }
            } else if let Some(format) = input.format.as_deref()
                && data["snapshots"][format].as_str().is_none()
            {
                continue;
            }
            if skip > 0 {
                skip -= 1;
                continue;
            }
            if let Some(object) = data.as_object_mut() {
                object.insert("sequence".into(), json!(row.sequence));
            }
            items.push(data);
        }
        let more = !exhausted && !self.rows(kind, input, cutoff, after, 1).await?.is_empty();
        if more && skip > 0 {
            return Err(Error::capacity(
                "Advisory discovery offset exceeds the bounded scan; use cursor continuation from offset zero.",
            ));
        }
        let next_cursor = if more {
            Some(encode_cursor(Cursor {
                version: 2,
                fingerprint: input.fingerprint("advisory.snapshots")?,
                snapshot: None,
                cutoff: Some(cutoff),
                after,
                within: 0,
            })?)
        } else {
            None
        };
        Ok(
            json!({"kind":kind,"items":items,"history_snapshot":cutoff,"next_cursor":next_cursor,
            "total":null,"scanned":scanned,"history_scope":"advertised_branches_and_tags_and_retained_ancestry"}),
        )
    }

    async fn history(&self, input: &Input) -> Result<Value> {
        let id = input.id()?;
        let format = input.format()?;
        let limit = input.limit(false)?;
        let cursor = input.cursor("advisory.history")?;
        let cutoff = self.view(input, cursor.as_ref()).await?;
        let mut after = cursor.as_ref().map_or(0, |v| v.after);
        let mut within = cursor.as_ref().map_or(0, |v| v.within);
        let mut skip = input.offset;
        let mut items = Vec::new();
        let mut gaps = 0usize;
        let mut scanned = 0;
        let mut exhausted = false;
        let deadline = Instant::now() + PROCESSING_TIME;
        while items.len() < limit && scanned < MAX_SCAN.saturating_add(input.offset) {
            if Instant::now() >= deadline {
                return Err(Error::capacity(
                    "Advisory history processing deadline exceeded.",
                ));
            }
            let row_after = if within > 0 {
                after.saturating_sub(1)
            } else {
                after
            };
            let batch = self.rows("commits", input, cutoff, row_after, 1).await?;
            let Some(row) = batch.into_iter().next() else {
                exhausted = true;
                break;
            };
            let events = self
                .commit_events(&row, id, format, &mut gaps, cutoff)
                .await?;
            scanned += 1;
            let start = if row.sequence == after { within } else { 0 };
            for (index, event) in events.iter().enumerate().skip(start) {
                if skip > 0 {
                    skip -= 1;
                    continue;
                }
                items.push(event.clone());
                if items.len() == limit {
                    after = row.sequence;
                    within = if index + 1 < events.len() {
                        index + 1
                    } else {
                        0
                    };
                    break;
                }
            }
            if items.len() < limit {
                after = row.sequence;
                within = 0;
            }
        }
        let more = within > 0
            || (!exhausted
                && !self
                    .rows("commits", input, cutoff, after, 1)
                    .await?
                    .is_empty());
        if more && skip > 0 {
            return Err(Error::capacity(
                "Advisory history offset exceeds the bounded scan; use cursor continuation from offset zero.",
            ));
        }
        let next_cursor = if more {
            Some(encode_cursor(Cursor {
                version: 2,
                fingerprint: input.fingerprint("advisory.history")?,
                snapshot: None,
                cutoff: Some(cutoff),
                after,
                within,
            })?)
        } else {
            None
        };
        Ok(
            json!({"id":id,"format":format,"items":items,"history_snapshot":cutoff,"next_cursor":next_cursor,
            "total":null,"scanned":scanned,"projection_gaps":gaps,"history_scope":"parent_relative_git_changes"}),
        )
    }

    async fn commit_events(
        &self,
        row: &AdvisoryRow,
        id: &str,
        format: &str,
        gaps: &mut usize,
        cutoff: i64,
    ) -> Result<Vec<Value>> {
        let row = self
            .store
            .advisory_commit(&row.key, Some(cutoff))
            .await?
            .ok_or_else(|| {
                Error::integrity("Advisory graph row is absent at its selected cutoff.")
            })?;
        let Some(child_id) = row.data["snapshots"][format].as_str() else {
            *gaps += 1;
            return Ok(Vec::new());
        };
        let child = self.snapshot(Some(child_id), format).await?;
        let child_record = find_record(&child, id);
        let parents = row.data["parents"]
            .as_array()
            .ok_or_else(|| Error::integrity("Invalid stored advisory parents."))?;
        if parents.len() > 100 {
            return Err(Error::capacity(
                "Advisory merge exceeds parent processing limit.",
            ));
        }
        let mut events = Vec::new();
        if parents.is_empty() {
            if let Some(record) = child_record {
                events.push(history_event(
                    None,
                    0,
                    "added",
                    None,
                    Some(record),
                    &child,
                    None,
                ));
            } else if !child.complete {
                *gaps += 1;
            }
            return Ok(events);
        }
        for (index, parent) in parents.iter().enumerate() {
            let revision = parent
                .as_str()
                .ok_or_else(|| Error::integrity("Invalid stored advisory parent."))?;
            let parent_row = self.store.advisory_commit(revision, Some(cutoff)).await?;
            let parent_id = parent_row
                .as_ref()
                .filter(|v| v.sequence <= cutoff)
                .and_then(|v| v.data["snapshots"][format].as_str());
            let Some(parent_id) = parent_id else {
                *gaps += 1;
                continue;
            };
            let parent_snapshot = self.snapshot(Some(parent_id), format).await?;
            let before = find_record(&parent_snapshot, id);
            let change = match (before, child_record) {
                (None, None) => {
                    if !parent_snapshot.complete || !child.complete {
                        *gaps += 1;
                    }
                    continue;
                }
                (None, Some(_)) if parent_snapshot.complete => "added",
                (Some(_), None) if child.complete => "removed",
                (Some(a), Some(b)) if a.body_hash != b.body_hash => "changed",
                (Some(a), Some(b)) if a.path != b.path => "path_changed",
                (Some(_), Some(_)) => continue,
                _ => {
                    *gaps += 1;
                    "unassessed"
                }
            };
            events.push(history_event(
                Some(revision),
                index,
                change,
                before,
                child_record,
                &child,
                Some(&parent_snapshot),
            ));
        }
        Ok(events)
    }

    pub async fn read_resource(&self, uri: &str) -> Result<Value> {
        if uri.len() > 16384 || uri.chars().any(char::is_control) {
            return Err(Error::invalid("Invalid advisory resource URI."));
        }
        let url =
            url::Url::parse(uri).map_err(|_| Error::invalid("Invalid advisory resource URI."))?;
        if url.scheme() != "devres"
            || url.host_str() != Some("advisory")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.port().is_some()
            || url.fragment().is_some()
        {
            return Err(Error::invalid("Invalid advisory resource URI."));
        }
        let parts = url
            .path()
            .trim_start_matches('/')
            .split('/')
            .collect::<Vec<_>>();
        if parts.len() != 3 || url.path().contains('%') {
            return Err(Error::invalid("Invalid advisory resource path."));
        }
        let mut input = Input {
            id: Some(parts[1].into()),
            format: Some(parts[0].into()),
            snapshot: Some(parts[2].into()),
            ..Default::default()
        };
        let mut seen = std::collections::HashSet::new();
        for (key, value) in url.query_pairs() {
            if !seen.insert(key.to_string()) {
                return Err(Error::invalid("Duplicate advisory resource parameter."));
            }
            match key.as_ref() {
                "offset" => {
                    input.offset = value
                        .parse()
                        .map_err(|_| Error::invalid("Invalid advisory text offset."))?
                }
                "limit" => {
                    input.limit = Some(
                        value
                            .parse()
                            .map_err(|_| Error::invalid("Invalid advisory text limit."))?,
                    )
                }
                _ => return Err(Error::invalid("Unsupported advisory resource parameter.")),
            }
        }
        input.validate()?;
        let _read_permit = admit_reads().await?;
        let result = self.get(&input).await?;
        Ok(json!({"contents":[{"uri":uri,"mimeType":"text/plain","text":result["page"]["text"]}]}))
    }
}

pub(crate) fn snapshot_metadata(snapshot: &AdvisorySnapshot) -> Value {
    let now = devres_domain::unix_now();
    let mut result = json!({"id":snapshot.id,"revision":snapshot.revision,"format":snapshot.format,
        "created_at":snapshot.created_at,"validated_at":snapshot.validated_at,"committed_at":snapshot.committed_at,
        "historical":snapshot.historical,"stale":snapshot.stale(now),"expired":snapshot.validated_at.is_none_or(|time|time>now||now.saturating_sub(time)>7*86400),
        "complete":snapshot.complete,"assessment_complete":snapshot.assessment_complete(now),"coverage":snapshot.coverage,"parents":snapshot.parents,
        "captures":snapshot.captures.iter().map(|v|capture_json(v,86400)).collect::<Vec<_>>(),
        "source_url":synthetic_source(snapshot).map(str::to_owned).unwrap_or_else(||format!("https://github.com/rustsec/advisory-db/tree/{}",snapshot.revision)),
        "license_notice":"RustSec CC0-1.0 except attributed GHSA imports under CC-BY-4.0; original record notices apply."});
    for capture in &snapshot.captures {
        if capture.key == "rustsec:head" {
            result["head_capture"] = capture_json(capture, 86400);
        } else if capture.key.starts_with("rustsec:bundle:") {
            result["bundle_capture"] = capture_json(capture, 365 * 86400);
        }
    }
    result
}

fn valid_hash(value: &str) -> bool {
    crate::integrity::valid_hash(value)
}
fn valid_ref(value: &str) -> bool {
    (value.starts_with("refs/heads/") || value.starts_with("refs/tags/"))
        && value.len() <= 1024
        && !value.ends_with('/')
        && !value.ends_with('.')
        && !value.contains("..")
        && !value.contains("@{")
        && !value
            .split('/')
            .any(|part| part.starts_with('.') || part.ends_with(".lock"))
        && !value.contains("//")
        && !value
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || "~^:?*[\\".contains(c))
}
fn canonical_id(value: &str) -> Result<()> {
    let parts = value.split('-').collect::<Vec<_>>();
    if parts.len() != 3
        || parts[0] != "RUSTSEC"
        || parts[1].len() != 4
        || parts[2].len() != 4
        || !parts[1]
            .bytes()
            .chain(parts[2].bytes())
            .all(|v| v.is_ascii_digit())
    {
        return Err(Error::invalid(
            "A canonical RUSTSEC-YYYY-NNNN ID is required.",
        ));
    }
    Ok(())
}
fn validate_date(date: &str) -> Result<()> {
    let bytes = date.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes
            .iter()
            .enumerate()
            .any(|(i, v)| i != 4 && i != 7 && !v.is_ascii_digit())
    {
        return Err(Error::invalid("Advisory date bounds must be YYYY-MM-DD."));
    }
    let year = date[..4]
        .parse::<u32>()
        .map_err(|_| Error::invalid("Invalid advisory date."))?;
    let month = date[5..7]
        .parse::<u32>()
        .map_err(|_| Error::invalid("Invalid advisory date."))?;
    let day = date[8..]
        .parse::<u32>()
        .map_err(|_| Error::invalid("Invalid advisory date."))?;
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => 0,
    };
    if year == 0 || day == 0 || day > days {
        return Err(Error::invalid("Invalid advisory date."));
    }
    Ok(())
}
fn encode_cursor(cursor: Cursor) -> Result<String> {
    let bytes = serde_json::to_vec(&cursor)
        .map_err(|_| Error::integrity("Advisory cursor encoding failed."))?;
    let encoded = URL_SAFE_NO_PAD.encode(bytes);
    if encoded.len() > MAX_CURSOR {
        return Err(Error::capacity("Advisory cursor exceeds its byte limit."));
    }
    Ok(encoded)
}
fn find_record<'a>(snapshot: &'a AdvisorySnapshot, id: &str) -> Option<&'a AdvisoryRecord> {
    snapshot.records.iter().find(|v| v.id == id)
}
fn source_url(snapshot: &AdvisorySnapshot, record: &AdvisoryRecord) -> String {
    if let Some(source) = synthetic_source(snapshot) {
        return source.to_owned();
    }
    format!(
        "https://github.com/rustsec/advisory-db/blob/{}/{}",
        snapshot.revision, record.path
    )
}
fn synthetic_source(snapshot: &AdvisorySnapshot) -> Option<&str> {
    if snapshot.coverage["synthetic"] == true {
        snapshot.coverage["source_url"].as_str()
    } else {
        None
    }
}
fn resource_uri(snapshot: &AdvisorySnapshot, record: &AdvisoryRecord) -> String {
    format!(
        "devres://advisory/{}/{}/{}",
        record.format, record.id, snapshot.id
    )
}
fn record_summary(snapshot: &AdvisorySnapshot, record: &AdvisoryRecord) -> Value {
    let mut metadata = record.metadata.clone();
    if let Some(object) = metadata.as_object_mut() {
        object.remove("original");
        object.insert("body_hash".into(), json!(record.body_hash));
        object.insert("path".into(), json!(record.path));
        object.insert("resource_uri".into(), json!(resource_uri(snapshot, record)));
    }
    metadata
}
fn has_string(value: &Value, expected: &str) -> bool {
    value
        .as_array()
        .is_some_and(|values| values.iter().any(|v| v.as_str() == Some(expected)))
}
fn platform_matches(metadata: &Value, key: &str, expected: &str) -> bool {
    if metadata["applicability_known"] == false {
        return false;
    }
    let field = &metadata["affected"][key];
    field.is_null()
        || field.as_array().is_some_and(|values| {
            values.is_empty() || values.iter().any(|v| v.as_str() == Some(expected))
        })
}
fn record_matches(record: &AdvisoryRecord, input: &Input) -> bool {
    let metadata = &record.metadata;
    let filters = &input.filters;
    if filters
        .name
        .as_ref()
        .is_some_and(|v| &record.package != v && !has_string(&metadata["packages"], v))
        || filters.id.as_ref().is_some_and(|v| &record.id != v)
        || filters
            .alias
            .as_ref()
            .is_some_and(|v| !has_string(&metadata["aliases"], v))
        || filters
            .classification
            .as_ref()
            .is_some_and(|v| metadata["classification"].as_str() != Some(v))
        || filters
            .category
            .as_ref()
            .is_some_and(|v| !has_string(&metadata["categories"], v))
        || filters
            .informational
            .as_ref()
            .is_some_and(|v| metadata["informational"].as_str() != Some(v))
        || filters
            .os
            .as_ref()
            .is_some_and(|v| !platform_matches(metadata, "os", v))
        || filters
            .arch
            .as_ref()
            .is_some_and(|v| !platform_matches(metadata, "arch", v))
    {
        return false;
    }
    let date = metadata["date"]
        .as_str()
        .or_else(|| metadata["published"].as_str())
        .and_then(|v| v.get(..10));
    if filters
        .date_from
        .as_ref()
        .is_some_and(|v| date.is_none_or(|date| date < v.as_str()))
        || filters
            .date_through
            .as_ref()
            .is_some_and(|v| date.is_none_or(|date| date > v.as_str()))
    {
        return false;
    }
    let text = format!(
        "{} {} {} {} {} {}",
        record.id,
        record.package,
        metadata["title"],
        record.body,
        metadata["aliases"],
        metadata["categories"]
    )
    .to_lowercase();
    input
        .query
        .to_lowercase()
        .split_whitespace()
        .all(|term| text.contains(term))
}
fn history_event(
    parent: Option<&str>,
    parent_index: usize,
    change: &str,
    before: Option<&AdvisoryRecord>,
    after: Option<&AdvisoryRecord>,
    snapshot: &AdvisorySnapshot,
    parent_snapshot: Option<&AdvisorySnapshot>,
) -> Value {
    json!({"revision":snapshot.revision,"parent":parent,"parent_index":parent_index,"change":change,
        "snapshot":snapshot.id,"parent_snapshot":parent_snapshot.map(|v|v.id.as_str()),"committed_at":snapshot.committed_at,
        "historical":snapshot.historical,"projection_complete":snapshot.complete&&parent_snapshot.is_none_or(|v|v.complete),
        "before":before.map(|v|json!({"path":v.path,"body_hash":v.body_hash,"classification":v.metadata["classification"]})),
        "after":after.map(|v|json!({"path":v.path,"body_hash":v.body_hash,"classification":v.metadata["classification"]}))})
}

pub(crate) fn schemas() -> Vec<Value> {
    let text = json!({"type":"string","minLength":1,"maxLength":256});
    let snapshot = json!({"type":"string","pattern":"^(blake3:)?[0-9a-f]{64}$"});
    let format = json!({"enum":["rustsec","osv"],"default":"rustsec"});
    let offset = json!({"type":"integer","minimum":0,"maximum":10000,"default":0});
    let limit = json!({"type":"integer","minimum":1,"maximum":100,"default":20});
    let cursor = json!({"type":"string","minLength":1,"maxLength":16384});
    let history = json!({"type":"integer","minimum":0});
    let reference = json!({"type":"string","minLength":11,"maxLength":1024});
    let canonical = json!({"type":"string","pattern":"^RUSTSEC-[0-9]{4}-[0-9]{4}$"});
    let filters = json!({"type":"object","properties":{"name":text,"id":canonical,"alias":text,
        "classification":{"enum":["vulnerability","informational","withdrawn"]},"category":text,"informational":text,
        "os":text,"arch":text,"date_from":{"type":"string","pattern":"^[0-9]{4}-[0-9]{2}-[0-9]{2}$"},
        "date_through":{"type":"string","pattern":"^[0-9]{4}-[0-9]{2}-[0-9]{2}$"}},"additionalProperties":false});
    let definitions = [
        (
            "advisory.get",
            "Read original advisory text and structured metadata from one immutable local snapshot.",
            json!({"id":canonical,"format":format,"snapshot":snapshot,"offset":{"type":"integer","minimum":0},"limit":{"type":"integer","minimum":1,"maximum":32768,"default":32768}}),
            vec!["id"],
        ),
        (
            "advisory.catalog_search",
            "Browse local advisory snapshots with conjunctive metadata filters. Platform filters include unrestricted advisories.",
            json!({"query":{"type":"string","maxLength":256,"default":""},"filters":filters,"format":format,"snapshot":snapshot,"offset":offset,"limit":limit,"cursor":cursor}),
            vec![],
        ),
        (
            "advisory.history",
            "Read parent-relative changes across retained Git history. History views and cursors freeze imported coverage.",
            json!({"id":canonical,"format":format,"ref":reference,"history_snapshot":history,"offset":offset,"limit":limit,"cursor":cursor}),
            vec!["id"],
        ),
        (
            "advisory.snapshots",
            "Discover immutable commit snapshots and observed refs from retained branches and tags.",
            json!({"kind":{"enum":["refs","commits"],"default":"commits"},"format":{"enum":["rustsec","osv"]},"ref":reference,"history_snapshot":history,"offset":offset,"limit":limit,"cursor":cursor}),
            vec![],
        ),
        (
            "advisory.corpus_status",
            "Inspect aggregate advisory acquisition, processing, freshness and history coverage without administrative controls.",
            json!({}),
            vec![],
        ),
    ];
    definitions.into_iter().map(|(name,description,properties,required)|json!({"name":name,"description":description,
        "inputSchema":{"type":"object","properties":properties,"required":required,"additionalProperties":false},
        "annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}})).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::collections::{BTreeMap, BTreeSet};
    use tokio::sync::Mutex;

    #[derive(Default)]
    struct Data {
        snapshots: BTreeMap<String, AdvisorySnapshot>,
        defaults: BTreeMap<String, String>,
        rows: Vec<(String, AdvisoryRow)>,
        states: BTreeMap<String, Value>,
    }
    #[derive(Default)]
    struct Memory(Mutex<Data>);
    #[async_trait]
    impl AdvisoryStore for Memory {
        async fn publish_advisory_snapshot(
            &self,
            snapshot: &AdvisorySnapshot,
            make_default: bool,
        ) -> Result<()> {
            let mut data = self.0.lock().await;
            if make_default {
                data.defaults
                    .insert(snapshot.format.clone(), snapshot.id.clone());
            }
            data.snapshots
                .entry(snapshot.id.clone())
                .or_insert_with(|| snapshot.clone());
            Ok(())
        }
        async fn advisory_snapshot(
            &self,
            id: Option<&str>,
            format: &str,
        ) -> Result<Option<AdvisorySnapshot>> {
            let data = self.0.lock().await;
            let id = id.or_else(|| data.defaults.get(format).map(String::as_str));
            Ok(id
                .and_then(|id| data.snapshots.get(id))
                .filter(|v| v.format == format)
                .cloned())
        }
        async fn advisory_rows(
            &self,
            kind: &str,
            cutoff: Option<i64>,
            after: i64,
            limit: usize,
        ) -> Result<Vec<AdvisoryRow>> {
            Ok(self
                .0
                .lock()
                .await
                .rows
                .iter()
                .filter(|(k, row)| {
                    k == kind && row.sequence > after && cutoff.is_none_or(|v| row.sequence <= v)
                })
                .take(limit)
                .map(|(_, v)| v.clone())
                .collect())
        }
        async fn put_advisory_row(&self, kind: &str, key: &str, value: &Value) -> Result<()> {
            let mut data = self.0.lock().await;
            if !data.rows.iter().any(|(k, row)| k == kind && row.key == key) {
                let sequence = data.rows.len() as i64 + 1;
                data.rows.push((
                    kind.into(),
                    AdvisoryRow {
                        sequence,
                        key: key.into(),
                        data: value.clone(),
                    },
                ));
            }
            Ok(())
        }
        async fn advisory_row(&self, kind: &str, key: &str) -> Result<Option<AdvisoryRow>> {
            Ok(self
                .0
                .lock()
                .await
                .rows
                .iter()
                .find(|(k, row)| k == kind && row.key == key)
                .map(|(_, v)| v.clone()))
        }
        async fn advisory_cutoff(&self) -> Result<i64> {
            Ok(self.0.lock().await.rows.len() as i64)
        }
        async fn advisory_ref_rows(
            &self,
            reference: &str,
            cutoff: i64,
            after: i64,
            limit: usize,
        ) -> Result<Vec<AdvisoryRow>> {
            let data = self.0.lock().await;
            let observation = data
                .rows
                .iter()
                .rev()
                .find(|(kind, row)| kind == "refs" && row.sequence <= cutoff)
                .ok_or_else(|| Error::not_found("No ref observation."))?;
            let tip = observation.1.data["refs"]
                .as_array()
                .and_then(|refs| refs.iter().find(|v| v["name"].as_str() == Some(reference)))
                .and_then(|v| v["peeled_commit"].as_str())
                .ok_or_else(|| Error::not_found("Unknown ref."))?;
            let mut seen = BTreeSet::new();
            let mut todo = vec![tip.to_owned()];
            while let Some(revision) = todo.pop() {
                if !seen.insert(revision.clone()) {
                    continue;
                }
                if let Some((_, row)) = data
                    .rows
                    .iter()
                    .find(|(kind, row)| kind == "commits" && row.key == revision)
                {
                    for parent in row.data["parents"].as_array().into_iter().flatten() {
                        if let Some(parent) = parent.as_str() {
                            todo.push(parent.to_owned());
                        }
                    }
                }
            }
            Ok(data
                .rows
                .iter()
                .filter(|(kind, row)| {
                    kind == "commits"
                        && row.sequence > after
                        && row.sequence <= cutoff
                        && seen.contains(&row.key)
                })
                .take(limit)
                .map(|(_, row)| row.clone())
                .collect())
        }
        async fn advisory_state(&self, key: &str) -> Result<Option<Value>> {
            Ok(self.0.lock().await.states.get(key).cloned())
        }
        async fn set_advisory_state(&self, key: &str, value: &Value) -> Result<()> {
            self.0.lock().await.states.insert(key.into(), value.clone());
            Ok(())
        }
        async fn advisory_status(&self) -> Result<Value> {
            Ok(json!({"snapshots":self.0.lock().await.snapshots.len()}))
        }
    }
    fn record(id: &str, body: &str) -> AdvisoryRecord {
        AdvisoryRecord {
            id: id.into(),
            package: "example".into(),
            format: "rustsec".into(),
            path: format!("crates/example/{id}.md"),
            body: body.into(),
            body_hash: crate::integrity::hash(body.as_bytes()),
            metadata: json!({"id":id,"package":"example","title":"Synthetic advisory","classification":"vulnerability","date":"2024-02-29",
                "aliases":["CVE-2024-1234","GHSA-abcd-abcd-abcd"],"categories":["memory-corruption"],"informational":null,"affected":{"os":[],"arch":[]},"original":{"fixture":true}}),
        }
    }
    fn snapshot(tag: char, records: Vec<AdvisoryRecord>) -> AdvisorySnapshot {
        AdvisorySnapshot {
            id: tag.to_string().repeat(64),
            revision: tag.to_string().repeat(40),
            format: "rustsec".into(),
            created_at: devres_domain::unix_now(),
            validated_at: Some(devres_domain::unix_now()),
            historical: false,
            complete: true,
            records,
            captures: Vec::new(),
            coverage: json!({"parsed":true}),
            parents: Vec::new(),
            committed_at: 1700000000,
        }
    }
    async fn add_commit(store: &Memory, snapshot: &AdvisorySnapshot, parents: &[&str]) {
        store
            .publish_advisory_snapshot(snapshot, false)
            .await
            .unwrap();
        store.put_advisory_row("commits",&snapshot.revision,&json!({"revision":snapshot.revision,"parents":parents,"snapshots":{"rustsec":snapshot.id}})).await.unwrap();
    }

    #[tokio::test]
    async fn catalog_aliases_platforms_and_conjunctive_filters_are_local() {
        let store = Arc::new(Memory::default());
        let unrestricted = record("RUSTSEC-2024-0001", "Unrestricted fixture");
        let mut linux = record("RUSTSEC-2024-0002", "Linux fixture");
        linux.metadata["affected"]["os"] = json!(["linux"]);
        let mut unknown = record("RUSTSEC-2024-0003", "Unknown fixture");
        unknown.metadata["applicability_known"] = json!(false);
        store
            .publish_advisory_snapshot(&snapshot('a', vec![unrestricted, linux, unknown]), true)
            .await
            .unwrap();
        let research = AdvisoryResearch::new(store);
        let result=research.call("advisory.catalog_search",json!({"query":"CVE-2024-1234","filters":{"os":"windows","category":"memory-corruption","date_from":"2024-02-29","date_through":"2024-02-29"}})).await.unwrap();
        assert_eq!(result["total"], 1);
        assert_eq!(result["items"][0]["id"], "RUSTSEC-2024-0001");
        assert!(result["items"][0].get("original").is_none());
        assert!(
            research
                .call(
                    "advisory.catalog_search",
                    json!({"filters":{"date_from":"2023-02-29"}})
                )
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn catalog_cursor_pins_refresh_and_allows_page_size_changes() {
        let store = Arc::new(Memory::default());
        let original = snapshot(
            'a',
            vec![
                record("RUSTSEC-2024-0003", "third"),
                record("RUSTSEC-2024-0001", "first"),
                record("RUSTSEC-2024-0002", "second"),
            ],
        );
        store
            .publish_advisory_snapshot(&original, true)
            .await
            .unwrap();
        let research = AdvisoryResearch::new(store.clone());
        let first = research
            .call("advisory.catalog_search", json!({"limit":1}))
            .await
            .unwrap();
        assert_eq!(first["items"][0]["id"], "RUSTSEC-2024-0001");
        let mut legacy_cursor: Cursor = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(first["next_cursor"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        legacy_cursor.fingerprint = Input::default()
            .fingerprint("advisory_catalog_search")
            .unwrap();
        let legacy_cursor = encode_cursor(legacy_cursor).unwrap();
        let rejected = research
            .call("advisory.catalog_search", json!({"cursor":legacy_cursor}))
            .await
            .unwrap_err();
        assert_eq!(rejected.code, "invalid_input");
        assert_eq!(
            rejected.message,
            "Advisory cursor belongs to a different query or snapshot."
        );
        store
            .publish_advisory_snapshot(&snapshot('b', vec![]), true)
            .await
            .unwrap();
        let next = research
            .call(
                "advisory.catalog_search",
                json!({"cursor":first["next_cursor"],"limit":2,"snapshot":original.id}),
            )
            .await
            .unwrap();
        assert_eq!(next["snapshot"]["id"], original.id);
        assert_eq!(next["items"].as_array().unwrap().len(), 2);
        assert_eq!(next["items"][1]["id"], "RUSTSEC-2024-0003");
        assert!(
            research
                .call(
                    "advisory.catalog_search",
                    json!({"cursor":first["next_cursor"],"query":"changed"})
                )
                .await
                .is_err()
        );
        assert!(
            research
                .call(
                    "advisory.catalog_search",
                    json!({"cursor":first["next_cursor"],"offset":1})
                )
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn historical_detail_and_typed_resources_preserve_utf8_and_format() {
        let store = Arc::new(Memory::default());
        let mut historical = snapshot('a', vec![record("RUSTSEC-2024-0001", "é한 text")]);
        historical.historical = true;
        historical.validated_at = None;
        store
            .publish_advisory_snapshot(&historical, true)
            .await
            .unwrap();
        let research = AdvisoryResearch::new(store);
        assert_eq!(
            research
                .call("advisory.get", json!({"id":"RUSTSEC-2024-0001"}))
                .await
                .unwrap_err()
                .code,
            "unavailable"
        );
        let result = research
            .call(
                "advisory.get",
                json!({"id":"RUSTSEC-2024-0001","snapshot":historical.id,"limit":2}),
            )
            .await
            .unwrap();
        assert_eq!(result["page"]["text"], "é");
        assert_eq!(result["page"]["next_offset"], 2);
        assert_eq!(result["advisory"]["original"]["fixture"], true);
        let uri = format!(
            "{}?offset=2&limit=3",
            result["resource_uri"].as_str().unwrap()
        );
        assert_eq!(
            research.read_resource(&uri).await.unwrap()["contents"][0]["text"],
            "한"
        );
        assert!(
            research
                .read_resource(&format!("{uri}&offset=2"))
                .await
                .is_err()
        );
        assert!(
            research
                .call(
                    "advisory.get",
                    json!({"id":"RUSTSEC-2024-0001","format":"osv","snapshot":historical.id})
                )
                .await
                .is_err()
        );
        assert!(
            research
                .call(
                    "advisory.get",
                    json!({"id":"RUSTSEC-2024-0001","snapshot":historical.id,"offset":1})
                )
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn history_distinguishes_merge_parents_withdrawal_and_removal() {
        let store = Arc::new(Memory::default());
        let a = snapshot('a', vec![record("RUSTSEC-2024-0001", "original")]);
        let b = snapshot('b', vec![record("RUSTSEC-2024-0001", "branch")]);
        let c = snapshot('c', vec![record("RUSTSEC-2024-0001", "merged")]);
        let mut d = snapshot('d', vec![record("RUSTSEC-2024-0001", "withdrawn metadata")]);
        d.records[0].metadata["classification"] = json!("withdrawn");
        let e = snapshot('e', vec![]);
        add_commit(&store, &a, &[]).await;
        add_commit(&store, &b, &[&a.revision]).await;
        add_commit(&store, &c, &[&a.revision, &b.revision]).await;
        add_commit(&store, &d, &[&c.revision]).await;
        add_commit(&store, &e, &[&d.revision]).await;
        let research = AdvisoryResearch::new(store);
        let first = research
            .call(
                "advisory.history",
                json!({"id":"RUSTSEC-2024-0001","limit":3}),
            )
            .await
            .unwrap();
        assert_eq!(first["items"][0]["change"], "added");
        assert_eq!(first["items"][2]["revision"], c.revision);
        assert_eq!(first["items"][2]["parent_index"], 0);
        let next = research
            .call(
                "advisory.history",
                json!({"id":"RUSTSEC-2024-0001","limit":10,"cursor":first["next_cursor"]}),
            )
            .await
            .unwrap();
        assert_eq!(next["items"][0]["revision"], c.revision);
        assert_eq!(next["items"][0]["parent_index"], 1);
        assert_eq!(next["items"][1]["change"], "changed");
        assert_eq!(next["items"][1]["after"]["classification"], "withdrawn");
        assert_eq!(next["items"][2]["change"], "removed");
    }

    #[tokio::test]
    async fn discovery_and_history_views_do_not_drift_after_backfill() {
        let store = Arc::new(Memory::default());
        let a = snapshot('a', vec![record("RUSTSEC-2024-0001", "original")]);
        let b = snapshot('b', vec![record("RUSTSEC-2024-0001", "second")]);
        let c = snapshot('c', vec![record("RUSTSEC-2024-0001", "third")]);
        add_commit(&store, &a, &[]).await;
        add_commit(&store, &b, &[&a.revision]).await;
        let research = AdvisoryResearch::new(store.clone());
        let first = research
            .call("advisory.snapshots", json!({"limit":1}))
            .await
            .unwrap();
        add_commit(&store, &c, &[&b.revision]).await;
        let next = research
            .call("advisory.snapshots", json!({"cursor":first["next_cursor"]}))
            .await
            .unwrap();
        assert_eq!(next["history_snapshot"], first["history_snapshot"]);
        assert_eq!(next["items"].as_array().unwrap().len(), 1);
        assert_eq!(next["items"][0]["revision"], b.revision);
        assert!(next["next_cursor"].is_null());
        let history = research
            .call(
                "advisory.history",
                json!({"id":"RUSTSEC-2024-0001","history_snapshot":first["history_snapshot"]}),
            )
            .await
            .unwrap();
        assert_eq!(history["items"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn exact_ref_selection_uses_ancestry_in_frozen_observation() {
        let store = Arc::new(Memory::default());
        let a = snapshot('a', vec![]);
        let b = snapshot('b', vec![]);
        let c = snapshot('c', vec![]);
        add_commit(&store, &a, &[]).await;
        add_commit(&store, &b, &[&a.revision]).await;
        add_commit(&store, &c, &[&a.revision]).await;
        store
            .put_advisory_row(
                "refs",
                "observation",
                &json!({"refs":[{"name":"refs/heads/main","peeled_commit":b.revision}]}),
            )
            .await
            .unwrap();
        let research = AdvisoryResearch::new(store);
        let result = research
            .call("advisory.snapshots", json!({"ref":"refs/heads/main"}))
            .await
            .unwrap();
        assert_eq!(result["items"].as_array().unwrap().len(), 2);
        assert_eq!(result["items"][1]["revision"], b.revision);
    }

    #[tokio::test]
    async fn malformed_inputs_fail_before_store_work() {
        let research = AdvisoryResearch::new(Arc::new(Memory::default()));
        for input in [
            json!({"kind":"unknown"}),
            json!({"ref":"refs/heads/../secret"}),
            json!({"history_snapshot":-1}),
            json!({"cursor":"!"}),
            json!({"offset":10001}),
        ] {
            assert_eq!(
                research
                    .call("advisory.snapshots", input)
                    .await
                    .unwrap_err()
                    .code,
                "invalid_input"
            );
        }
        assert!(
            research
                .call(
                    "advisory.corpus_status",
                    json!({"lockfile":"private sentinel"})
                )
                .await
                .is_err()
        );
        assert!(
            research
                .call(
                    "advisory.catalog_search",
                    json!({"filters":{"unexpected":"x"}})
                )
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn sparse_offsets_fail_explicitly_instead_of_losing_unconsumed_skip() {
        let store = Arc::new(Memory::default());
        let empty = snapshot('a', vec![]);
        store
            .publish_advisory_snapshot(&empty, false)
            .await
            .unwrap();
        for index in 0..MAX_SCAN + 4 {
            let revision = format!("{index:040x}");
            store
                .put_advisory_row(
                    "commits",
                    &revision,
                    &json!({"revision":revision,"parents":[],"snapshots":{"rustsec":empty.id}}),
                )
                .await
                .unwrap();
            store
                .put_advisory_row(
                    "refs",
                    &format!("view-{index}"),
                    &json!({"refs":[{"name":"refs/heads/main","snapshots":{"rustsec":empty.id}}]}),
                )
                .await
                .unwrap();
        }
        let populated = snapshot('b', vec![record("RUSTSEC-2024-0001", "late advisory")]);
        add_commit(&store, &populated, &[]).await;
        store
            .put_advisory_row(
                "refs",
                "last-view",
                &json!({"refs":[{"name":"refs/heads/osv","snapshots":{"osv":"c".repeat(64)}}]}),
            )
            .await
            .unwrap();
        let research = AdvisoryResearch::new(store);
        for (tool, input) in [
            (
                "advisory.snapshots",
                json!({"kind":"refs","format":"osv","offset":1}),
            ),
            (
                "advisory.history",
                json!({"id":"RUSTSEC-2024-0001","offset":1}),
            ),
        ] {
            assert_eq!(
                research.call(tool, input).await.unwrap_err().code,
                "capacity"
            );
        }
    }

    #[tokio::test]
    async fn synthetic_evidence_preserves_its_declared_provenance() {
        let store = Arc::new(Memory::default());
        let mut fixture = snapshot(
            'a',
            vec![record("RUSTSEC-2024-0001", "Synthetic public fixture")],
        );
        fixture.coverage =
            json!({"synthetic":true,"source_url":"https://fixtures.invalid/synthetic-advisory"});
        store
            .publish_advisory_snapshot(&fixture, false)
            .await
            .unwrap();
        let result = AdvisoryResearch::new(store)
            .call(
                "advisory.get",
                json!({"id":"RUSTSEC-2024-0001","snapshot":fixture.id}),
            )
            .await
            .unwrap();
        assert_eq!(
            result["source_url"],
            "https://fixtures.invalid/synthetic-advisory"
        );
        assert_eq!(
            result["snapshot"]["source_url"],
            "https://fixtures.invalid/synthetic-advisory"
        );
        fixture.coverage["synthetic"] = json!(false);
        assert!(
            snapshot_metadata(&fixture)["source_url"]
                .as_str()
                .unwrap()
                .contains("github.com/rustsec/advisory-db/tree/")
        );
    }

    #[tokio::test]
    async fn processing_generations_overlay_new_views_without_changing_frozen_cursors() {
        let store = Arc::new(Memory::default());
        let parent_v1 = snapshot('a', vec![record("RUSTSEC-2024-0001", "original parent")]);
        let child_v1 = snapshot('b', vec![record("RUSTSEC-2024-0001", "changed child")]);
        add_commit(&store, &parent_v1, &[]).await;
        add_commit(&store, &child_v1, &[&parent_v1.revision]).await;
        let research = AdvisoryResearch::new(store.clone());
        let old_discovery = research
            .call("advisory.snapshots", json!({"limit":1}))
            .await
            .unwrap();
        let old_history = research
            .call(
                "advisory.history",
                json!({"id":"RUSTSEC-2024-0001","limit":1}),
            )
            .await
            .unwrap();
        assert_eq!(old_discovery["history_snapshot"], 2);
        assert_eq!(old_history["history_snapshot"], 2);

        let mut parent_v2 = parent_v1.clone();
        parent_v2.id = "c".repeat(64);
        parent_v2.coverage["processor_version"] = json!(2);
        let mut child_v2 = child_v1.clone();
        child_v2.id = "d".repeat(64);
        child_v2.coverage["processor_version"] = json!(2);
        store
            .publish_advisory_snapshot(&parent_v2, false)
            .await
            .unwrap();
        store
            .publish_advisory_snapshot(&child_v2, false)
            .await
            .unwrap();
        for processed in [&parent_v2, &child_v2] {
            store.put_advisory_row("processing", &format!("{}:2", processed.revision),
                &json!({"revision":processed.revision,"processor_version":2,"snapshots":{"rustsec":processed.id},"projection_complete":true})).await.unwrap();
        }

        let frozen_discovery = research
            .call(
                "advisory.snapshots",
                json!({"cursor":old_discovery["next_cursor"]}),
            )
            .await
            .unwrap();
        assert_eq!(frozen_discovery["history_snapshot"], 2);
        assert_eq!(
            frozen_discovery["items"][0]["snapshots"]["rustsec"],
            child_v1.id
        );
        assert_eq!(frozen_discovery["items"][0]["sequence"], 2);
        let frozen_history = research
            .call(
                "advisory.history",
                json!({"id":"RUSTSEC-2024-0001","cursor":old_history["next_cursor"]}),
            )
            .await
            .unwrap();
        assert_eq!(frozen_history["items"][0]["snapshot"], child_v1.id);
        assert_eq!(frozen_history["items"][0]["parent_snapshot"], parent_v1.id);

        let latest_discovery = research
            .call("advisory.snapshots", json!({}))
            .await
            .unwrap();
        assert_eq!(latest_discovery["items"].as_array().unwrap().len(), 2);
        assert_eq!(
            latest_discovery["items"][0]["snapshots"]["rustsec"],
            parent_v2.id
        );
        assert_eq!(
            latest_discovery["items"][1]["snapshots"]["rustsec"],
            child_v2.id
        );
        assert_eq!(latest_discovery["items"][1]["processor_version"], 2);
        assert_eq!(latest_discovery["items"][1]["sequence"], 2);
        let latest_history = research
            .call("advisory.history", json!({"id":"RUSTSEC-2024-0001"}))
            .await
            .unwrap();
        assert_eq!(latest_history["items"][0]["snapshot"], parent_v2.id);
        assert_eq!(latest_history["items"][1]["snapshot"], child_v2.id);
        assert_eq!(latest_history["items"][1]["parent_snapshot"], parent_v2.id);
        assert_eq!(latest_history["items"][1]["change"], "changed");
    }

    #[tokio::test]
    async fn raw_graph_without_eligible_projection_is_a_reported_history_gap() {
        let store = Arc::new(Memory::default());
        let revision = "a".repeat(40);
        store
            .put_advisory_row(
                "commits",
                &revision,
                &json!({"revision":revision,"parents":[],"processor_version":2}),
            )
            .await
            .unwrap();
        let result = AdvisoryResearch::new(store)
            .call("advisory.history", json!({"id":"RUSTSEC-2024-0001"}))
            .await
            .unwrap();
        assert!(result["items"].as_array().unwrap().is_empty());
        assert_eq!(result["projection_gaps"], 1);
        assert!(result["next_cursor"].is_null());
    }
}
