//! Fixed-origin, documentation-only Chromium acquisition. Responses are evidence,
//! never executable instructions or permission to admit another destination.
use crate::bulk::{BulkBroker, BulkRequest, BulkSource};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use devres_domain::{Error, Result, Validators};
use futures::StreamExt as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha1::{Digest as _, Sha1};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

pub const MAX_METADATA_BYTES: usize = 64 * 1024 * 1024;
const MAX_ENTRIES: usize = 1_000_000;
const ARCHIVE_API: &str = "https://api.github.com/repos/GoogleChrome/developer.chrome.com";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    CurrentRef {
        component: String,
    },
    Refs {
        component: String,
    },
    RefsNamespace {
        component: String,
        namespace: String,
    },
    RefsPage {
        component: String,
        page: u32,
    },
    Commit {
        component: String,
        revision: String,
    },
    Tag {
        component: String,
        revision: String,
    },
    Tree {
        component: String,
        revision: String,
        path: String,
    },
    Blob {
        component: String,
        revision: String,
        path: String,
    },
    Sitemap {
        path: String,
    },
    Page {
        path: String,
    },
    SitePage {
        path: String,
    },
}
fn invalid() -> Error {
    Error::invalid("Invalid Chromium source operation.")
}
fn malformed() -> Error {
    Error::integrity("Malformed Chromium source evidence.")
}
pub fn valid_oid(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn valid_path(path: &str) -> bool {
    path.len() <= 4096
        && !path.starts_with('/')
        && !path.ends_with('/')
        && !path
            .chars()
            .any(|c| c.is_control() || matches!(c, '\\' | '%' | '?' | '#'))
        && (path.is_empty()
            || path
                .split('/')
                .all(|p| !p.is_empty() && !matches!(p, "." | "..")))
}
fn component_base(component: &str) -> Result<&'static str> {
    match component {
        "src" => Ok("https://chromium.googlesource.com/chromium/src"),
        "site" => Ok("https://chromium.googlesource.com/website"),
        "chrome-archive" => Ok(ARCHIVE_API),
        _ => Err(invalid()),
    }
}
fn encoded_path(path: &str) -> String {
    let mut url = url::Url::parse("https://chromium.invalid/").expect("fixed URL");
    url.set_path(path);
    url.path().trim_start_matches('/').to_owned()
}
impl Operation {
    pub fn url(&self) -> Result<String> {
        match self {
            Self::CurrentRef { component } => {
                let base = component_base(component)?;
                if component == "chrome-archive" {
                    Ok(format!("{base}/git/ref/heads/main"))
                } else {
                    Ok(format!("{base}/+refs/heads/main?format=JSON"))
                }
            }
            Self::Refs { component } => Self::RefsPage {
                component: component.clone(),
                page: 1,
            }
            .url(),
            Self::RefsNamespace {
                component,
                namespace,
            } => {
                let base = component_base(component)?;
                if !matches!(namespace.as_str(), "heads" | "tags" | "branch-heads")
                    || component == "chrome-archive"
                {
                    return Err(invalid());
                }
                Ok(format!("{base}/+refs/{namespace}?format=JSON"))
            }
            Self::RefsPage { component, page } => {
                if *page == 0 {
                    return Err(invalid());
                }
                let base = component_base(component)?;
                if component == "chrome-archive" {
                    Ok(format!("{base}/git/refs?per_page=100&page={page}"))
                } else if *page == 1 {
                    Ok(format!("{base}/+refs/heads?format=JSON"))
                } else {
                    Err(invalid())
                }
            }
            Self::Commit {
                component,
                revision,
            } => {
                if !valid_oid(revision) {
                    return Err(invalid());
                }
                let base = component_base(component)?;
                if component == "chrome-archive" {
                    Ok(format!("{base}/commits/{revision}"))
                } else {
                    Ok(format!("{base}/+/{revision}?format=JSON"))
                }
            }
            Self::Tag {
                component,
                revision,
            } => {
                if component != "chrome-archive" || !valid_oid(revision) {
                    return Err(invalid());
                }
                Ok(format!("{ARCHIVE_API}/git/tags/{revision}"))
            }
            Self::Tree {
                component,
                revision,
                path,
            } => {
                if !valid_oid(revision) || !valid_path(path) {
                    return Err(invalid());
                }
                let base = component_base(component)?;
                if component == "chrome-archive" {
                    if !path.is_empty() {
                        return Err(invalid());
                    }
                    Ok(format!("{base}/git/trees/{revision}"))
                } else {
                    let path = encoded_path(path);
                    Ok(if path.is_empty() {
                        format!("{base}/+/{revision}/?format=JSON")
                    } else {
                        format!("{base}/+/{revision}/{path}/?format=JSON")
                    })
                }
            }
            Self::Blob {
                component,
                revision,
                path,
            } => {
                if !valid_oid(revision) || !valid_path(path) || path.is_empty() {
                    return Err(invalid());
                }
                let base = component_base(component)?;
                let path = encoded_path(path);
                if component == "chrome-archive" {
                    Ok(format!("{base}/contents/{path}?ref={revision}"))
                } else {
                    Ok(format!("{base}/+/{revision}/{path}?format=TEXT"))
                }
            }
            Self::Sitemap { path } => {
                if !valid_path(path)
                    || path.contains('/')
                    || !(path == "sitemap.xml"
                        || path.starts_with("sitemap_") && path.ends_with(".xml"))
                {
                    return Err(invalid());
                }
                Ok(format!("https://developer.chrome.com/{path}"))
            }
            Self::Page { path } => {
                if !valid_path(path.trim_end_matches('/'))
                    || path.is_empty()
                    || path.ends_with("//")
                {
                    return Err(invalid());
                }
                let first = path.split('/').next().unwrap_or("");
                if !matches!(
                    first,
                    "docs" | "blog" | "case-studies" | "articles" | "new" | "release-notes"
                ) {
                    return Err(invalid());
                }
                Ok(format!(
                    "https://developer.chrome.com/{}?hl=en",
                    encoded_path(path)
                ))
            }
            Self::SitePage { path } => {
                if !valid_path(path) || path.is_empty() {
                    return Err(invalid());
                }
                Ok(format!("https://www.chromium.org/{}/", encoded_path(path)))
            }
        }
    }
    pub fn host(&self) -> &'static str {
        match self {
            Self::Sitemap { .. } | Self::Page { .. } => "developer.chrome.com",
            Self::SitePage { .. } => "www.chromium.org",
            Self::CurrentRef { component }
            | Self::Refs { component }
            | Self::RefsNamespace { component, .. }
            | Self::RefsPage { component, .. }
            | Self::Commit { component, .. }
            | Self::Tag { component, .. }
            | Self::Tree { component, .. }
            | Self::Blob { component, .. }
                if component == "chrome-archive" =>
            {
                "api.github.com"
            }
            _ => "chromium.googlesource.com",
        }
    }
    pub fn media_type(&self) -> &'static str {
        match self {
            Self::Page { .. } | Self::SitePage { .. } => "text/html",
            Self::Sitemap { .. } => "application/xml",
            Self::Blob { component, .. } if component != "chrome-archive" => "text/plain",
            _ => "application/json",
        }
    }
    pub(crate) fn retry_at(
        &self,
        headers: &reqwest::header::HeaderMap,
        status: u16,
    ) -> Result<Option<i64>> {
        if !matches!(status, 403 | 429) {
            return Ok(None);
        }
        let now = devres_domain::unix_now();
        let mut deferred = now + if status == 403 { 3600 } else { 60 };
        if let Some(value) = headers.get("x-ratelimit-reset") {
            let reset = value
                .to_str()
                .ok()
                .and_then(|s| s.parse::<i64>().ok())
                .filter(|n| *n >= now && *n <= now + 86400)
                .ok_or_else(malformed)?;
            deferred = reset;
        }
        if let Some(value) = headers.get(reqwest::header::RETRY_AFTER) {
            let value = value.to_str().map_err(|_| malformed())?;
            let timestamp = if let Ok(seconds) = value.parse::<u64>() {
                if seconds > 86400 {
                    return Err(malformed());
                }
                now + seconds as i64
            } else {
                let date = httpdate::parse_http_date(value).map_err(|_| malformed())?;
                i64::try_from(
                    date.duration_since(std::time::UNIX_EPOCH)
                        .map_err(|_| malformed())?
                        .as_secs(),
                )
                .map_err(|_| malformed())?
            };
            if timestamp > now + 86400 {
                return Err(malformed());
            }
            deferred = deferred.max(timestamp);
        }
        Ok(Some(deferred.max(now + 1)))
    }
    /// Only a same-operation numeric page is accepted from an upstream Link.
    pub(crate) fn next_page(&self, headers: &reqwest::header::HeaderMap) -> Result<Option<u32>> {
        let component = match self {
            Self::Refs { component } | Self::RefsPage { component, .. } => component,
            _ => return Ok(None),
        };
        if component != "chrome-archive" {
            return Ok(None);
        }
        let current = match self {
            Self::RefsPage { page, .. } => *page,
            _ => 1,
        };
        let Some(header) = headers.get(reqwest::header::LINK) else {
            return Ok(None);
        };
        let header = header.to_str().map_err(|_| malformed())?;
        if header.len() > 8192 {
            return Err(malformed());
        }
        for item in header.split(',') {
            let Some((target, relation)) = item.trim().split_once(';') else {
                return Err(malformed());
            };
            if !relation.split(';').any(|s| s.trim() == "rel=\"next\"") {
                continue;
            }
            let target = target
                .strip_prefix('<')
                .and_then(|s| s.strip_suffix('>'))
                .ok_or_else(malformed)?;
            let url = url::Url::parse(target).map_err(|_| malformed())?;
            let expected = current.checked_add(1).ok_or_else(malformed)?;
            let allowed = Self::RefsPage {
                component: component.clone(),
                page: expected,
            }
            .url()?;
            if url.as_str() != allowed {
                return Err(malformed());
            }
            return Ok(Some(expected));
        }
        Ok(None)
    }
}

pub struct SourceResponse {
    pub status: u16,
    pub bytes: Vec<u8>,
    pub observed_at: i64,
    pub source_url: String,
    pub next: Option<String>,
    pub retry_at: Option<i64>,
}
pub struct ChromiumSource {
    broker: Arc<BulkBroker>,
}
impl ChromiumSource {
    pub fn new(broker: Arc<BulkBroker>) -> Result<Self> {
        Ok(Self { broker })
    }
    pub async fn fetch(
        &self,
        operation: &Operation,
        cancel: CancellationToken,
    ) -> Result<SourceResponse> {
        let source_url = operation.url()?;
        let response = self
            .broker
            .open(
                BulkRequest {
                    source: BulkSource::Chromium(operation.clone()),
                    validators: Validators::default(),
                    max_bytes: MAX_METADATA_BYTES as u64,
                    deadline: Instant::now() + Duration::from_secs(120),
                    body: Vec::new(),
                },
                cancel.clone(),
            )
            .await?;
        let mut stream = response.stream;
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            if cancel.is_cancelled() {
                return Err(Error::new("cancelled", "Chromium acquisition canceled."));
            }
            let chunk = chunk?;
            if bytes
                .len()
                .checked_add(chunk.len())
                .is_none_or(|n| n > MAX_METADATA_BYTES)
            {
                return Err(Error::capacity(
                    "Chromium source response exceeds its byte bound.",
                ));
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(SourceResponse {
            status: response.status,
            bytes,
            observed_at: devres_domain::unix_now(),
            source_url,
            next: response.next_page.map(|p| p.to_string()),
            retry_at: response.retry_at,
        })
    }
}

pub fn json(bytes: &[u8]) -> Result<Value> {
    if bytes.len() > MAX_METADATA_BYTES {
        return Err(Error::capacity("Chromium metadata exceeds its byte bound."));
    }
    let bytes = if bytes.starts_with(b")]}'\n") {
        &bytes[5..]
    } else {
        bytes
    };
    serde_json::from_slice(bytes).map_err(|_| malformed())
}
fn oid<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| valid_oid(s))
        .ok_or_else(malformed)
}
pub fn parse_refs(component: &str, bytes: &[u8]) -> Result<BTreeMap<String, String>> {
    component_base(component)?;
    let data = json(bytes)?;
    let mut refs = BTreeMap::new();
    let admitted = |name: &str| {
        name.starts_with("refs/heads/")
            || name.starts_with("refs/tags/")
            || name.starts_with("refs/branch-heads/")
    };
    if component == "chrome-archive" {
        let single;
        let entries = if let Some(array) = data.as_array() {
            array
        } else {
            if !data.is_object() || data.get("ref").is_none() {
                return Err(malformed());
            }
            single = vec![data.clone()];
            &single
        };
        if entries.len() > MAX_ENTRIES {
            return Err(Error::capacity("Chromium ref page exceeds its bound."));
        }
        for item in entries {
            let name = item["ref"].as_str().ok_or_else(malformed)?;
            if admitted(name) {
                refs.insert(name.to_owned(), oid(&item["object"], "sha")?.to_owned());
            }
        }
    } else {
        let entries = data.as_object().ok_or_else(malformed)?;
        if entries.get("value").is_some() {
            refs.insert("refs/heads/main".into(), oid(&data, "value")?.into());
            return Ok(refs);
        }
        if entries.len() > MAX_ENTRIES {
            return Err(Error::capacity("Chromium ref page exceeds its bound."));
        }
        for (name, item) in entries {
            if name == "HEAD" || admitted(name) {
                if name.len() > 4096 || name.chars().any(char::is_control) {
                    return Err(malformed());
                }
                let revision = if item.get("peeled").is_some() {
                    oid(item, "peeled")?
                } else {
                    oid(item, "value")?
                };
                refs.insert(name.clone(), revision.to_owned());
            }
        }
    }
    Ok(refs)
}
/// Annotated tag objects require explicit bounded peeling before commit traversal.
pub fn annotated_tags(component: &str, bytes: &[u8]) -> Result<BTreeMap<String, String>> {
    component_base(component)?;
    if component != "chrome-archive" {
        return Ok(BTreeMap::new());
    }
    let data = json(bytes)?;
    if data.get("ref").and_then(Value::as_str) == Some("refs/heads/main") {
        return Ok(BTreeMap::new());
    }
    let entries = data.as_array().ok_or_else(malformed)?;
    let mut tags = BTreeMap::new();
    for item in entries {
        if item["object"]["type"] == "tag" {
            let name = item["ref"]
                .as_str()
                .filter(|s| {
                    s.starts_with("refs/tags/")
                        && s.len() <= 4096
                        && !s.chars().any(char::is_control)
                })
                .ok_or_else(malformed)?;
            tags.insert(name.into(), oid(&item["object"], "sha")?.into());
        }
    }
    Ok(tags)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tag {
    pub revision: String,
    pub target: String,
    pub kind: String,
}
pub fn parse_tag(component: &str, bytes: &[u8]) -> Result<Tag> {
    if component != "chrome-archive" {
        return Err(invalid());
    }
    let data = json(bytes)?;
    let kind = data["object"]["type"]
        .as_str()
        .filter(|s| matches!(*s, "tag" | "commit"))
        .ok_or_else(malformed)?
        .into();
    Ok(Tag {
        revision: oid(&data, "sha")?.into(),
        target: oid(&data["object"], "sha")?.into(),
        kind,
    })
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Commit {
    pub revision: String,
    pub tree: String,
    pub parents: Vec<String>,
    pub committed_at: i64,
}
pub fn parse_commit(component: &str, bytes: &[u8]) -> Result<Commit> {
    component_base(component)?;
    let data = json(bytes)?;
    let archive = component == "chrome-archive";
    let revision = oid(&data, if archive { "sha" } else { "commit" })?.to_owned();
    let tree = if archive {
        oid(&data["commit"]["tree"], "sha")?
    } else {
        oid(&data, "tree")?
    }
    .to_owned();
    let list = data["parents"].as_array().ok_or_else(malformed)?;
    if list.len() > 1024 {
        return Err(Error::capacity("Chromium parent count exceeds its bound."));
    }
    let parents = list
        .iter()
        .map(|p| {
            if archive {
                oid(p, "sha").map(str::to_owned)
            } else {
                p.as_str()
                    .filter(|s| valid_oid(s))
                    .map(str::to_owned)
                    .ok_or_else(malformed)
            }
        })
        .collect::<Result<Vec<_>>>()?;
    let date = if archive {
        data["commit"]["committer"]["date"].as_str()
    } else {
        data["committer"]["time"].as_str()
    }
    .ok_or_else(malformed)?;
    Ok(Commit {
        revision,
        tree,
        parents,
        committed_at: parse_date(date)?,
    })
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub mode: u32,
    pub kind: String,
    pub oid: String,
    pub name: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Directory {
    pub id: String,
    pub entries: Vec<Entry>,
}
pub fn parse_tree(component: &str, bytes: &[u8]) -> Result<Directory> {
    component_base(component)?;
    let data = json(bytes)?;
    let archive = component == "chrome-archive";
    if data.get("truncated").and_then(Value::as_bool) == Some(true) {
        return Err(Error::capacity("Chromium directory listing is truncated."));
    }
    let id = oid(&data, if archive { "sha" } else { "id" })?.to_owned();
    let list = data[if archive { "tree" } else { "entries" }]
        .as_array()
        .ok_or_else(malformed)?;
    if list.len() > MAX_ENTRIES {
        return Err(Error::capacity(
            "Chromium directory listing exceeds its bound.",
        ));
    }
    let mut entries = Vec::with_capacity(list.len());
    for item in list {
        let name = item[if archive { "path" } else { "name" }]
            .as_str()
            .filter(|n| valid_path(n) && !n.is_empty() && !n.contains('/'))
            .ok_or_else(malformed)?
            .to_owned();
        let mode = if archive {
            u32::from_str_radix(item["mode"].as_str().ok_or_else(malformed)?, 8)
                .map_err(|_| malformed())?
        } else {
            u32::try_from(item["mode"].as_u64().ok_or_else(malformed)?).map_err(|_| malformed())?
        };
        let kind = item["type"]
            .as_str()
            .filter(|k| matches!(*k, "blob" | "tree" | "commit"))
            .ok_or_else(malformed)?
            .to_owned();
        if !matches!(
            (mode, kind.as_str()),
            (0o100644 | 0o100755 | 0o120000, "blob") | (0o040000, "tree") | (0o160000, "commit")
        ) {
            return Err(malformed());
        }
        entries.push(Entry {
            mode,
            kind,
            oid: oid(item, if archive { "sha" } else { "id" })?.to_owned(),
            name,
        });
    }
    // Git tree order compares directory names as if followed by '/'. JSON order
    // is not sufficient evidence: reconstruct from exact names/modes/object IDs.
    entries.sort_by_cached_key(|e| {
        if e.kind == "tree" {
            format!("{}/", e.name)
        } else {
            e.name.clone()
        }
    });
    if entries.windows(2).any(|p| p[0].name == p[1].name) {
        return Err(malformed());
    }
    let mut content = Vec::new();
    for entry in &entries {
        content.extend_from_slice(format!("{:o} {}\0", entry.mode, entry.name).as_bytes());
        content.extend_from_slice(&hex::decode(&entry.oid).map_err(|_| malformed())?);
    }
    if object_oid("tree", &content) != id {
        return Err(Error::integrity("Chromium Git tree object hash mismatch."));
    }
    Ok(Directory { id, entries })
}
pub fn object_oid(kind: &str, bytes: &[u8]) -> String {
    let mut hash = Sha1::new();
    hash.update(format!("{kind} {}\0", bytes.len()).as_bytes());
    hash.update(bytes);
    hex::encode(hash.finalize())
}
pub fn decode_blob(component: &str, bytes: &[u8], expected_oid: &str) -> Result<Vec<u8>> {
    component_base(component)?;
    if !valid_oid(expected_oid) || bytes.len() > MAX_METADATA_BYTES {
        return Err(malformed());
    }
    let data;
    let encoded = if component == "chrome-archive" {
        data = json(bytes)?;
        if data["encoding"] != "base64" || oid(&data, "sha")? != expected_oid {
            return Err(malformed());
        }
        data["content"].as_str().ok_or_else(malformed)?.as_bytes()
    } else {
        bytes
    };
    let compact: Vec<u8> = encoded
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    let decoded = STANDARD.decode(compact).map_err(|_| malformed())?;
    if object_oid("blob", &decoded) != expected_oid {
        return Err(Error::integrity("Chromium Git blob object hash mismatch."));
    }
    Ok(decoded)
}

fn parse_date(value: &str) -> Result<i64> {
    if !value.is_ascii() {
        return Err(malformed());
    }
    let (year, month, day, clock, zone) = if value.as_bytes().get(4) == Some(&b'-') {
        if value.len() != 20 || !value.ends_with('Z') || value.as_bytes().get(10) != Some(&b'T') {
            return Err(malformed());
        }
        (
            &value[..4],
            value[5..7].parse::<u32>().map_err(|_| malformed())?,
            &value[8..10],
            &value[11..19],
            0i64,
        )
    } else {
        let p: Vec<_> = value.split_whitespace().collect();
        if p.len() != 6 {
            return Err(malformed());
        }
        let month = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ]
        .iter()
        .position(|m| *m == p[1])
        .ok_or_else(malformed)? as u32
            + 1;
        let z = p[5].as_bytes();
        if z.len() != 5 || !matches!(z[0], b'+' | b'-') || !z[1..].iter().all(u8::is_ascii_digit) {
            return Err(malformed());
        }
        let zh = p[5][1..3].parse::<i64>().map_err(|_| malformed())?;
        let zm = p[5][3..5].parse::<i64>().map_err(|_| malformed())?;
        if zh > 23 || zm > 59 {
            return Err(malformed());
        }
        (
            p[4],
            month,
            p[2],
            p[3],
            (zh * 3600 + zm * 60) * if z[0] == b'-' { -1 } else { 1 },
        )
    };
    let year = year.parse::<i64>().map_err(|_| malformed())?;
    let day = day.parse::<u32>().map_err(|_| malformed())?;
    let p: Vec<_> = clock.split(':').collect();
    if p.len() != 3 {
        return Err(malformed());
    }
    let hour = p[0].parse::<i64>().map_err(|_| malformed())?;
    let minute = p[1].parse::<i64>().map_err(|_| malformed())?;
    let second = p[2].parse::<i64>().map_err(|_| malformed())?;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
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
    if !(1970..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || day == 0
        || day > days[(month - 1) as usize]
        || hour > 23
        || minute > 59
        || second > 59
        || hour < 0
        || minute < 0
        || second < 0
    {
        return Err(malformed());
    }
    let y = year - i64::from(month <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = i64::from(month);
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Ok((era * 146097 + doe - 719468) * 86400 + hour * 3600 + minute * 60 + second - zone)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    const OID: &str = "1111111111111111111111111111111111111111";
    #[test]
    fn fixed_operations_reject_destination_and_revision_injection() {
        for component in ["https://localhost/", "src?evil=1", "other"] {
            assert!(
                Operation::Refs {
                    component: component.into()
                }
                .url()
                .is_err()
            );
        }
        for path in [
            "../secret",
            "//evil.example/a",
            "docs/../../etc/passwd",
            "a%2fb",
            "a?x=y",
            "a\\b",
            "a#x",
        ] {
            assert!(
                Operation::Blob {
                    component: "src".into(),
                    revision: OID.into(),
                    path: path.into()
                }
                .url()
                .is_err()
            );
        }
        assert!(
            Operation::Commit {
                component: "src".into(),
                revision: "main".into()
            }
            .url()
            .is_err()
        );
        assert!(
            Operation::Page {
                path: "https://localhost/x".into()
            }
            .url()
            .is_err()
        );
        assert!(
            Operation::Sitemap {
                path: "docs/a.xml".into()
            }
            .url()
            .is_err()
        );
        assert_eq!(
            Operation::Blob {
                component: "src".into(),
                revision: OID.into(),
                path: "docs/a b.md".into()
            }
            .url()
            .unwrap(),
            format!(
                "https://chromium.googlesource.com/chromium/src/+/{OID}/docs/a%20b.md?format=TEXT"
            )
        );
    }
    #[test]
    fn refs_admit_release_heads_and_peel_tags_without_reviews() {
        let data = json!({"HEAD":{"value":OID},"refs/heads/main":{"value":OID},"refs/branch-heads/100":{"value":OID},"refs/tags/v1":{"value":"2222222222222222222222222222222222222222","peeled":OID},"refs/changes/1":{"value":OID}});
        let parsed = parse_refs("src", &serde_json::to_vec(&data).unwrap()).unwrap();
        assert_eq!(parsed.len(), 4);
        assert_eq!(parsed["refs/tags/v1"], OID);
        assert!(!parsed.contains_key("refs/changes/1"));
    }
    #[test]
    fn gitiles_prefix_and_parent_order_survive_normalization() {
        let second = "2222222222222222222222222222222222222222";
        let data = json!({"commit":OID,"tree":OID,"parents":[second,OID],"committer":{"time":"Thu Jan 01 01:00:00 1970 +0100"}});
        let mut bytes = b")]}'\n".to_vec();
        bytes.extend(serde_json::to_vec(&data).unwrap());
        let commit = parse_commit("src", &bytes).unwrap();
        assert_eq!(commit.parents, [second, OID]);
        assert_eq!(commit.committed_at, 0);
        assert_eq!(parse_date("2026-10-27T00:00:00Z").unwrap(), 1_793_059_200);
        assert!(parse_date("2026-02-30T00:00:00Z").is_err());
        assert!(parse_date("2026-é1-01T00:00:00Z").is_err());
    }
    #[test]
    fn blobs_require_selected_oid_and_correct_envelope() {
        let body = b"# public source\n";
        let hash = object_oid("blob", body);
        let encoded = STANDARD.encode(body);
        assert_eq!(decode_blob("src", encoded.as_bytes(), &hash).unwrap(), body);
        assert!(decode_blob("src", encoded.as_bytes(), OID).is_err());
        let data = json!({"encoding":"base64","content":format!("{}\n",encoded),"sha":hash});
        assert_eq!(
            decode_blob("chrome-archive", &serde_json::to_vec(&data).unwrap(), &hash).unwrap(),
            body
        );
        assert!(
            decode_blob(
                "chrome-archive",
                &serde_json::to_vec(&json!({"encoding":"none","sha":hash,"content":""})).unwrap(),
                &hash
            )
            .is_err()
        );
    }
    #[test]
    fn trees_reconstruct_git_order_and_refuse_truncation_or_mutation() {
        let mut tree = b"100644 a\0".to_vec();
        tree.extend(hex::decode(OID).unwrap());
        let hash = object_oid("tree", &tree);
        let data = json!({"id":hash,"entries":[{"mode":33188,"type":"blob","id":OID,"name":"a"}]});
        assert_eq!(
            parse_tree("src", &serde_json::to_vec(&data).unwrap())
                .unwrap()
                .entries[0]
                .name,
            "a"
        );
        let mut wrong = data.clone();
        wrong["entries"][0]["name"] = json!("b");
        assert!(parse_tree("src", &serde_json::to_vec(&wrong).unwrap()).is_err());
        let data = json!({"sha":hash,"truncated":true,"tree":[]});
        assert!(parse_tree("chrome-archive", &serde_json::to_vec(&data).unwrap()).is_err());
    }
    #[test]
    fn pagination_admits_only_exact_next_operation() {
        let op = Operation::Refs {
            component: "chrome-archive".into(),
        };
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::LINK,
            format!("<{ARCHIVE_API}/git/refs?per_page=100&page=2>; rel=\"next\"")
                .parse()
                .unwrap(),
        );
        assert_eq!(op.next_page(&headers).unwrap(), Some(2));
        headers.insert(
            reqwest::header::LINK,
            "<https://127.0.0.1/secret>; rel=\"next\"".parse().unwrap(),
        );
        assert!(op.next_page(&headers).is_err());
    }
}

#[cfg(test)]
mod network_tests {
    use super::*;
    #[test]
    fn exhausted_rate_headers_produce_bounded_deferral() {
        let operation = Operation::Refs {
            component: "chrome-archive".into(),
        };
        let now = devres_domain::unix_now();
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "x-ratelimit-reset",
            (now + 1800).to_string().parse().unwrap(),
        );
        assert_eq!(operation.retry_at(&headers, 403).unwrap(), Some(now + 1800));
        headers.insert(reqwest::header::RETRY_AFTER, "3600".parse().unwrap());
        assert!(operation.retry_at(&headers, 429).unwrap().unwrap() >= now + 3600);
        assert_eq!(operation.retry_at(&headers, 200).unwrap(), None);
        headers.insert(
            reqwest::header::RETRY_AFTER,
            "99999999999999".parse().unwrap(),
        );
        assert!(operation.retry_at(&headers, 429).is_err());
    }
    #[tokio::test]
    async fn redirects_do_not_expand_sources_and_attempt_budget_is_shared() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = axum::Router::new().fallback(axum::routing::get(|| async {
            (
                axum::http::StatusCode::FOUND,
                [(axum::http::header::LOCATION, "http://127.0.0.1/private")],
            )
        }));
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let broker = Arc::new(
            BulkBroker::fixture(format!("http://{address}").parse().unwrap())
                .unwrap()
                .with_attempt_budget(1)
                .unwrap(),
        );
        let source = ChromiumSource::new(broker.clone()).unwrap();
        let response = source
            .fetch(
                &Operation::Page {
                    path: "docs/devtools/overview".into(),
                },
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(response.status, 302);
        assert!(response.bytes.is_empty());
        assert_eq!(broker.attempt_count(), 1);
        assert_eq!(
            source
                .fetch(
                    &Operation::Sitemap {
                        path: "sitemap.xml".into()
                    },
                    CancellationToken::new()
                )
                .await
                .err()
                .unwrap()
                .code,
            "capacity"
        );
        task.abort();
    }
}

#[cfg(test)]
mod scoped_history_tests {
    use super::*;
    use serde_json::json;
    const OID: &str = "1111111111111111111111111111111111111111";
    #[test]
    fn current_bootstrap_and_history_never_request_review_namespaces() {
        assert_eq!(
            Operation::CurrentRef {
                component: "src".into()
            }
            .url()
            .unwrap(),
            "https://chromium.googlesource.com/chromium/src/+refs/heads/main?format=JSON"
        );
        for namespace in ["heads", "tags", "branch-heads"] {
            assert_eq!(
                Operation::RefsNamespace {
                    component: "src".into(),
                    namespace: namespace.into()
                }
                .url()
                .unwrap(),
                format!(
                    "https://chromium.googlesource.com/chromium/src/+refs/{namespace}?format=JSON"
                )
            );
        }
        assert!(
            Operation::RefsNamespace {
                component: "src".into(),
                namespace: "changes".into()
            }
            .url()
            .is_err()
        );
        assert_eq!(
            parse_refs("src", &serde_json::to_vec(&json!({"value":OID})).unwrap()).unwrap()["refs/heads/main"],
            OID
        );
        let data = json!({"ref":"refs/heads/main","object":{"sha":OID,"type":"commit"}});
        assert_eq!(
            parse_refs("chrome-archive", &serde_json::to_vec(&data).unwrap()).unwrap()["refs/heads/main"],
            OID
        );
    }
    #[test]
    fn annotated_tags_preserve_tag_objects_for_explicit_peeling() {
        let data = json!([{"ref":"refs/tags/v1","object":{"sha":OID,"type":"tag"}}]);
        assert_eq!(
            annotated_tags("chrome-archive", &serde_json::to_vec(&data).unwrap()).unwrap()["refs/tags/v1"],
            OID
        );
        let target = "2222222222222222222222222222222222222222";
        let tag = parse_tag(
            "chrome-archive",
            &serde_json::to_vec(&json!({"sha":OID,"object":{"sha":target,"type":"commit"}}))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(tag.revision, OID);
        assert_eq!(tag.target, target);
        assert_eq!(tag.kind, "commit");
        assert!(
            parse_tag(
                "chrome-archive",
                &serde_json::to_vec(&json!({"sha":OID,"object":{"sha":target,"type":"blob"}}))
                    .unwrap()
            )
            .is_err()
        );
    }
}
