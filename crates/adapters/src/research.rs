//! Read-only tool composition. Submitted audit data never enters retrieval/storage.

use crate::{advisory, cargo, rfc, rfc_corpus::RfcCorpus, rfc_tools};
use devres_application::Retrieval;
use devres_domain::{Capture, Error, Result, StoredCapture};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

pub struct Research {
    retrieval: Arc<Retrieval>,
    advisory: advisory::Advisories,
    corpus: Option<std::sync::Arc<RfcCorpus>>,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Page {
    #[serde(default)]
    pub offset: usize,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    20
}

impl Default for Page {
    fn default() -> Self {
        Self {
            offset: 0,
            limit: 20,
        }
    }
}

impl Page {
    pub fn checked(self) -> Result<Self> {
        if self.limit == 0 || self.limit > 100 || self.offset > 1_000_000 {
            return Err(Error::invalid(
                "Page limit must be 1..100 and offset at most 1000000.",
            ));
        }
        Ok(self)
    }
}

pub(crate) fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or(0)
}

pub(crate) fn capture_json(capture: &Capture, ttl: u64) -> Value {
    let resource_uri = if matches!(
        capture.media_type.as_str(),
        "application/gzip" | "application/pdf"
    ) {
        None
    } else {
        Some(format!("devres://capture/{}", capture.id))
    };
    json!({"id":capture.id,"body_hash":capture.body_hash,"source_url":capture.source_url,
        "retrieved_at":capture.retrieved_at,"validated_at":capture.validated_at,
        "stale":now().saturating_sub(capture.validated_at) > ttl as i64,
        "resource_uri":resource_uri})
}

pub(crate) fn decode<T: serde::de::DeserializeOwned>(input: Value) -> Result<T> {
    serde_json::from_value(input)
        .map_err(|_| Error::invalid("Arguments do not match the tool input schema."))
}

pub(crate) fn text_page(text: &str, offset: usize, limit: usize) -> Result<Value> {
    if limit == 0 || limit > 32768 || offset > text.len() || !text.is_char_boundary(offset) {
        return Err(Error::invalid(
            "Text offset must be a UTF-8 byte boundary and limit must be 1..32768.",
        ));
    }
    let mut end = offset.saturating_add(limit).min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    if end == offset && offset < text.len() {
        return Err(Error::invalid(
            "Text limit is smaller than the next UTF-8 character.",
        ));
    }
    Ok(
        json!({"text":&text[offset..end],"offset":offset,"next_offset":if end < text.len() { Some(end) } else { None },"total_bytes":text.len()}),
    )
}

impl Research {
    pub async fn new(retrieval: Arc<Retrieval>) -> Result<Self> {
        Ok(Self {
            advisory: advisory::Advisories::new(retrieval.clone()),
            retrieval,
            corpus: None,
        })
    }

    pub fn with_corpus(mut self, corpus: std::sync::Arc<RfcCorpus>) -> Self {
        self.corpus = Some(corpus);
        self
    }

    pub async fn refresh_advisories(&self) -> Result<Value> {
        self.advisory.refresh().await
    }

    pub async fn call(&self, tool: &str, input: Value) -> Result<Value> {
        if matches!(
            tool,
            "rfc_metadata"
                | "rfc_catalog_search"
                | "rfc_fulltext_search"
                | "rfc_format_get"
                | "rfc_errata"
                | "rfc_series_get"
                | "rfc_corpus_status"
        ) {
            return rfc_tools::call(
                self.corpus
                    .as_deref()
                    .ok_or_else(|| Error::unavailable("RFC corpus storage is not configured."))?,
                tool,
                input,
            )
            .await;
        }
        match tool {
            "rfc_search" => rfc::search(&self.retrieval, decode(input)?).await,
            "rfc_get" => rfc::get(&self.retrieval, decode(input)?).await,
            "crate_search" => cargo::search(&self.retrieval, decode(input)?).await,
            "crate_metadata" => cargo::metadata(&self.retrieval, decode(input)?).await,
            "crate_source_list" => cargo::source_list(&self.retrieval, decode(input)?).await,
            "crate_source_read" => cargo::source_read(&self.retrieval, decode(input)?).await,
            "advisory_lookup" => self.advisory.lookup(decode(input)?).await,
            "audit_lockfile" => self.advisory.audit(decode(input)?).await,
            "search" => self.search(decode(input)?).await,
            "fetch" => self.fetch(decode(input)?).await,
            _ => Err(Error::not_found("Unknown research tool.")),
        }
    }

    async fn search(&self, input: SearchInput) -> Result<Value> {
        let page = Page {
            offset: input.offset,
            limit: input.limit,
        }
        .checked()?;
        if input.sources.is_empty() || input.sources.len() > 3 {
            return Err(Error::invalid("Select one to three sources."));
        }
        let mut results = Vec::new();
        let mut unique = std::collections::HashSet::new();
        for source in input.sources {
            if !unique.insert(source.clone()) {
                return Err(Error::invalid("Duplicate search source."));
            }
            let output = match source.as_str() {
                "rfc" => {
                    rfc::search(
                        &self.retrieval,
                        rfc::SearchInput {
                            query: input.query.clone(),
                            status: None,
                            offset: page.offset,
                            limit: page.limit,
                            capture: None,
                        },
                    )
                    .await
                }
                "cargo" => {
                    cargo::search(
                        &self.retrieval,
                        cargo::SearchInput {
                            query: input.query.clone(),
                            offset: page.offset,
                            limit: page.limit,
                            capture: None,
                        },
                    )
                    .await
                }
                "rustsec" => self.advisory.search(&input.query, page).await,
                _ => {
                    return Err(Error::invalid(
                        "Search sources are rfc, cargo, and rustsec.",
                    ));
                }
            };
            match output {
                Ok(value) => results.push(json!({"source":source,"result":value})),
                Err(error) => results.push(json!({"source":source,"error":error.to_string()})),
            }
        }
        Ok(json!({"sources":results}))
    }

    async fn fetch(&self, input: FetchInput) -> Result<Value> {
        if input.id.starts_with("devres://") {
            let mut uri =
                url::Url::parse(&input.id).map_err(|_| Error::invalid("Invalid resource URI."))?;
            if input.offset.is_some() || input.limit.is_some() {
                let pairs = uri
                    .query_pairs()
                    .filter(|(key, _)| {
                        !(key == "offset" && input.offset.is_some()
                            || key == "limit" && input.limit.is_some())
                    })
                    .map(|(key, value)| (key.into_owned(), value.into_owned()))
                    .collect::<Vec<_>>();
                uri.set_query(None);
                let mut query = uri.query_pairs_mut();
                for (key, value) in pairs {
                    query.append_pair(&key, &value);
                }
                if let Some(offset) = input.offset {
                    query.append_pair("offset", &offset.to_string());
                }
                if let Some(limit) = input.limit {
                    query.append_pair("limit", &limit.to_string());
                }
            }
            let value = self.read_resource(uri.as_str()).await?;
            return Ok(value);
        }
        if let Some(number) = input.id.strip_prefix("rfc:") {
            let number = number
                .parse()
                .map_err(|_| Error::invalid("RFC IDs use rfc:<number>."))?;
            return rfc::get(
                &self.retrieval,
                rfc::GetInput {
                    number,
                    offset: input.offset.unwrap_or(0),
                    limit: input.limit.unwrap_or(32768),
                    capture: None,
                },
            )
            .await;
        }
        if let Some(name_version) = input.id.strip_prefix("crate:") {
            let (name, version) = name_version
                .split_once('@')
                .ok_or_else(|| Error::invalid("Crate IDs use crate:<name>@<version>."))?;
            return cargo::metadata(
                &self.retrieval,
                cargo::MetadataInput {
                    name: name.to_owned(),
                    version: version.to_owned(),
                    capture: None,
                },
            )
            .await;
        }
        Err(Error::invalid(
            "Fetch requires an RFC ID, exact crate version, or capture-fixed resource URI.",
        ))
    }

    /// Only durable public captures are reachable. No submitted audit is addressable.
    pub async fn read_resource(&self, uri: &str) -> Result<Value> {
        if uri.len() > 16384 {
            return Err(Error::invalid("Resource URI is too long."));
        }
        let url = url::Url::parse(uri).map_err(|_| Error::invalid("Invalid resource URI."))?;
        if url.scheme() != "devres"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.port().is_some()
            || url.fragment().is_some()
        {
            return Err(Error::invalid("Invalid capture resource URI."));
        }
        if url.host_str() == Some("source") {
            let input = cargo::source_input_from_uri(&url)?;
            let output = cargo::source_read(&self.retrieval, input).await?;
            return Ok(
                json!({"contents":[{"uri":uri,"mimeType":"text/plain","text":output["page"]["text"]}]}),
            );
        }
        if url.host_str() == Some("rfc") {
            let input = rfc_tools::format_from_uri(&url)?;
            let value = rfc_tools::format_get(
                self.corpus
                    .as_deref()
                    .ok_or_else(|| Error::unavailable("RFC corpus storage is not configured."))?,
                input,
            )
            .await?;
            return Ok(if value["format"] == "pdf" {
                json!({"contents":[{"uri":uri,"mimeType":"application/pdf","blob":value["page"]["data"]}]})
            } else {
                json!({"contents":[{"uri":uri,"mimeType":"text/plain","text":value["page"]["text"]}]})
            });
        }
        if url.host_str() != Some("capture") {
            return Err(Error::invalid("Unsupported resource namespace."));
        }
        let capture_id = url
            .path()
            .strip_prefix('/')
            .filter(|v| !v.is_empty() && !v.contains('/'))
            .ok_or_else(|| Error::invalid("Invalid capture identifier."))?;
        let mut offset = 0;
        let mut limit = 32768;
        let mut seen = std::collections::HashSet::new();
        for (key, value) in url.query_pairs() {
            if !seen.insert(key.to_string()) {
                return Err(Error::invalid("Duplicate resource page parameter."));
            }
            match key.as_ref() {
                "offset" => {
                    offset = value
                        .parse()
                        .map_err(|_| Error::invalid("Invalid resource offset."))?
                }
                "limit" => {
                    limit = value
                        .parse()
                        .map_err(|_| Error::invalid("Invalid resource limit."))?
                }
                _ => return Err(Error::invalid("Unknown resource page parameter.")),
            }
        }
        let stored = self.retrieval.read_capture(capture_id).await?;
        if matches!(
            stored.capture.media_type.as_str(),
            "application/pdf" | "application/gzip"
        ) {
            return Err(Error::invalid(
                "Binary captures must be read through a typed source tool.",
            ));
        }
        let text = std::str::from_utf8(&stored.body).map_err(|_| {
            Error::invalid("Binary captures must be read through a typed source tool.")
        })?;
        let page = text_page(text, offset, limit)?;
        Ok(
            json!({"contents":[{"uri":uri,"mimeType":stored.capture.media_type,"text":page["text"]}]}),
        )
    }

    pub fn tool_schemas() -> Vec<Value> {
        schemas()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchInput {
    query: String,
    #[serde(default = "default_sources")]
    sources: Vec<String>,
    #[serde(default)]
    offset: usize,
    #[serde(default = "default_limit")]
    limit: usize,
}
fn default_sources() -> Vec<String> {
    vec!["rfc".into(), "cargo".into()]
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FetchInput {
    id: String,
    #[serde(default)]
    offset: Option<usize>,
    #[serde(default)]
    limit: Option<usize>,
}
pub(crate) fn text_limit() -> usize {
    32768
}
pub(crate) fn list_limit() -> usize {
    20
}

pub(crate) fn ensure_capture(capture: &StoredCapture, expected_key: &str) -> Result<()> {
    if capture.capture.key != expected_key {
        return Err(Error::invalid(
            "Capture belongs to a different source or query.",
        ));
    }
    Ok(())
}

fn schemas() -> Vec<Value> {
    let text = json!({"type":"string","minLength":1,"maxLength":256});
    let capture = json!({"type":"string","minLength":1,"maxLength":128});
    let offset = json!({"type":"integer","minimum":0,"maximum":1000000});
    let limit = json!({"type":"integer","minimum":1,"maximum":100,"default":20});
    let text_offset = json!({"type":"integer","minimum":0});
    let text_limit = json!({"type":"integer","minimum":1,"maximum":32768,"default":32768});
    let mut tools = Vec::new();
    let mut add = |name: &str, description: &str, properties: Value, required: Vec<&str>| {
        tools.push(json!({"name":name,"description":description,"inputSchema":{"type":"object","properties":properties,"required":required,"additionalProperties":false},"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":true}}))
    };
    add(
        "search",
        "Search RFC metadata, crates.io packages, or RustSec advisories. Sources are independent; errors and freshness are explicit.",
        json!({"query":text,"sources":{"type":"array","items":{"enum":["rfc","cargo","rustsec"]},"minItems":1,"maxItems":3,"uniqueItems":true},"offset":offset,"limit":limit}),
        vec!["query"],
    );
    add(
        "fetch",
        "Retrieve rfc:<number>, crate:<name>@<version>, or a capture-fixed devres resource URI. Text offsets count UTF-8 bytes.",
        json!({"id":{"type":"string","minLength":1,"maxLength":16384},"offset":text_offset,"limit":text_limit}),
        vec!["id"],
    );
    add(
        "rfc_search",
        "Search the official RFC index by number, title, abstract and status. Reuse capture for stable pagination.",
        json!({"query":text,"status":text,"offset":offset,"limit":limit,"capture":capture}),
        vec!["query"],
    );
    add(
        "rfc_get",
        "Read a selected RFC's published text in bounded UTF-8 pages; reuse capture for stable pagination.",
        json!({"number":{"type":"integer","minimum":1,"maximum":999999},"offset":text_offset,"limit":text_limit,"capture":capture}),
        vec!["number"],
    );
    add(
        "crate_search",
        "Search crates.io packages. Reuse capture for the same bounded upstream result page.",
        json!({"query":text,"offset":offset,"limit":limit,"capture":capture}),
        vec!["query"],
    );
    add(
        "crate_metadata",
        "Inspect an exact crates.io version including dependency declarations, features, yanked state and archive checksum.",
        json!({"name":text,"version":text,"capture":capture}),
        vec!["name", "version"],
    );
    add(
        "crate_source_list",
        "List verified published source archive files. Capture IDs bind the index and archive for stable paging.",
        json!({"name":text,"version":text,"metadata_capture":capture,"archive_capture":capture,"offset":offset,"limit":limit}),
        vec!["name", "version"],
    );
    add(
        "crate_source_read",
        "Read a verified published source file without executing or extracting it. Offsets count UTF-8 bytes.",
        json!({"name":text,"version":text,"path":{"type":"string","minLength":1,"maxLength":4096},"metadata_capture":capture,"archive_capture":capture,"offset":text_offset,"limit":text_limit}),
        vec!["name", "version", "path"],
    );
    add(
        "advisory_lookup",
        "Match RustSec advisories to a crates.io package/version. Reports stale, withdrawn and informational advisory state explicitly.",
        json!({"name":text,"version":text,"advisory_snapshot":capture,"offset":offset,"limit":limit}),
        vec!["name", "version"],
    );
    add(
        "audit_lockfile",
        "Audit supplied Cargo.lock against a captured RustSec database. Input, dependency lists and results remain request-local. Resubmit input and advisory_snapshot for pagination.",
        json!({"lockfile":{"type":"string","minLength":1,"maxLength":1048576},"advisory_snapshot":capture,"offset":offset,"limit":limit}),
        vec!["lockfile"],
    );
    tools.extend(rfc_tools::schemas());
    tools
}
