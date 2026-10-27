//! Read-only tool composition. Submitted audit data never enters retrieval/storage.

use crate::{
    crates_io::packages as cargo, rfc::corpus::RfcCorpus, rfc::source as rfc,
    rfc::tools as rfc_tools, rustsec::advisory,
};
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
    advisory_research: Option<crate::rustsec::research::AdvisoryResearch>,
    corpus: Option<std::sync::Arc<RfcCorpus>>,
    crate_corpus: Option<std::sync::Arc<crate::crates_io::CrateCorpus>>,
    mdn_research: Option<Arc<crate::mdn::research::MdnResearch>>,
    whatwg_research: Option<Arc<crate::whatwg::research::WhatwgResearch>>,
    w3c_research: Option<Arc<crate::w3c::research::W3cResearch>>,
    chromium_research: Option<Arc<crate::chromium::research::ChromiumResearch>>,
    npm: crate::npm::NpmPackages,
    npm_corpus: Option<Arc<crate::npm::NpmCorpus>>,
    npm_research: Option<Arc<crate::npm::research::NpmResearch>>,
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
        "application/gzip" | "application/pdf" | "application/zip"
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
            npm: crate::npm::NpmPackages::new(retrieval.clone()),
            npm_corpus: None,
            npm_research: None,
            advisory: advisory::Advisories::new(retrieval.clone()),
            advisory_research: None,
            retrieval,
            corpus: None,
            crate_corpus: None,
            mdn_research: None,
            whatwg_research: None,
            w3c_research: None,
            chromium_research: None,
        })
    }

    pub fn with_corpus(mut self, corpus: std::sync::Arc<RfcCorpus>) -> Self {
        self.corpus = Some(corpus);
        self
    }
    pub fn with_crate_corpus(
        mut self,
        corpus: std::sync::Arc<crate::crates_io::CrateCorpus>,
    ) -> Self {
        self.crate_corpus = Some(corpus);
        self
    }
    pub fn with_advisory_corpus(mut self, corpus: Arc<crate::rustsec::AdvisoryCorpus>) -> Self {
        self.advisory_research = Some(crate::rustsec::research::AdvisoryResearch::new(
            corpus.store.clone(),
        ));
        self.advisory = self.advisory.with_corpus(corpus);
        self
    }

    pub fn with_mdn_research(mut self, research: Arc<crate::mdn::research::MdnResearch>) -> Self {
        self.mdn_research = Some(research);
        self
    }

    pub async fn refresh_advisories(&self) -> Result<Value> {
        self.advisory.refresh().await
    }

    pub fn with_whatwg_corpus(mut self, corpus: Arc<crate::whatwg::WhatwgCorpus>) -> Self {
        self.whatwg_research = Some(Arc::new(crate::whatwg::research::WhatwgResearch::new(
            corpus,
        )));
        self
    }

    pub fn with_w3c_corpus(mut self, corpus: Arc<crate::w3c::W3cCorpus>) -> Self {
        self.w3c_research = Some(Arc::new(crate::w3c::research::W3cResearch::new(corpus)));
        self
    }

    pub fn with_chromium_corpus(mut self, corpus: Arc<crate::chromium::ChromiumCorpus>) -> Self {
        self.chromium_research = Some(Arc::new(crate::chromium::research::ChromiumResearch::new(
            corpus,
        )));
        self
    }

    pub fn with_npm_corpus(mut self, corpus: Arc<crate::npm::NpmCorpus>) -> Self {
        self.npm_research = Some(Arc::new(crate::npm::research::NpmResearch::new(
            corpus.clone(),
        )));
        self.npm_corpus = Some(corpus);
        self
    }

    pub async fn call(&self, tool: &str, input: Value) -> Result<Value> {
        if crate::npm::schemas()
            .iter()
            .any(|schema| schema["name"] == tool)
        {
            return self.npm.call(tool, input).await;
        }
        if tool == "npm_audit_lockfile" {
            return crate::npm::audit::audit(
                input,
                self.npm_corpus
                    .clone()
                    .ok_or_else(|| Error::unavailable("npm advisory storage is not configured."))?,
            )
            .await;
        }
        if crate::npm::research::schemas()
            .iter()
            .any(|schema| schema["name"] == tool)
        {
            return self
                .npm_research
                .as_ref()
                .ok_or_else(|| Error::unavailable("npm corpus storage is not configured."))?
                .call(tool, input)
                .await;
        }
        if crate::chromium::research::schemas()
            .iter()
            .any(|schema| schema["name"] == tool)
        {
            return self
                .chromium_research
                .as_ref()
                .ok_or_else(|| Error::unavailable("Chromium corpus storage is not configured."))?
                .call(tool, input)
                .await;
        }
        if crate::w3c::research::schemas()
            .iter()
            .any(|schema| schema["name"] == tool)
        {
            return self
                .w3c_research
                .as_ref()
                .ok_or_else(|| Error::unavailable("W3C corpus storage is not configured."))?
                .call(tool, input)
                .await;
        }
        if crate::whatwg::research::schemas()
            .iter()
            .any(|schema| schema["name"] == tool)
        {
            return self
                .whatwg_research
                .as_ref()
                .ok_or_else(|| Error::unavailable("WHATWG corpus storage is not configured."))?
                .call(tool, input)
                .await;
        }
        if crate::mdn::research::schemas()
            .iter()
            .any(|schema| schema["name"] == tool)
        {
            return self
                .mdn_research
                .as_ref()
                .ok_or_else(|| Error::unavailable("MDN corpus storage is not configured."))?
                .call(tool, input)
                .await;
        }
        if crate::rustsec::research::schemas()
            .iter()
            .any(|schema| schema["name"] == tool)
        {
            return self
                .advisory_research
                .as_ref()
                .ok_or_else(|| Error::unavailable("Advisory corpus storage is not configured."))?
                .call(tool, input)
                .await;
        }
        if crate::crates_io::research::schemas()
            .iter()
            .any(|s| s["name"].as_str() == Some(tool))
        {
            let corpus = self
                .crate_corpus
                .as_ref()
                .ok_or_else(|| Error::unavailable("Crate corpus storage is not configured."))?;
            if tool == "crate_corpus_status" {
                let _: EmptyInput = decode(input)?;
                return corpus.status().await;
            }
            return corpus.research().call(tool, input).await;
        }
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
        if input.sources.is_empty() || input.sources.len() > 8 {
            return Err(Error::invalid("Select one to eight sources."));
        }
        let mut results = Vec::new();
        let mut unique = std::collections::HashSet::new();
        for source in input.sources {
            if !unique.insert(source.clone()) {
                return Err(Error::invalid("Duplicate search source."));
            }
            let output = match source.as_str() {
                "npm" => {
                    self.npm
                        .call(
                            "npm_search",
                            json!({"query":input.query,"offset":page.offset,"limit":page.limit}),
                        )
                        .await
                }
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
                "chromium" => match self.chromium_research.as_ref() {
                    Some(research) => research
                        .call(
                            "chromium_search",
                            json!({"query":input.query,"offset":page.offset,"limit":page.limit}),
                        )
                        .await,
                    None => Err(Error::unavailable(
                        "Chromium corpus storage is not configured.",
                    )),
                },
                "w3c" => match self.w3c_research.as_ref() {
                    Some(research) => research
                        .call(
                            "w3c_search",
                            json!({"query":input.query,"offset":page.offset,"limit":page.limit}),
                        )
                        .await,
                    None => Err(Error::unavailable("W3C corpus storage is not configured.")),
                },
                "whatwg" => match self.whatwg_research.as_ref() {
                    Some(research) => research
                        .call(
                            "whatwg_search",
                            json!({"query":input.query,"offset":page.offset,"limit":page.limit}),
                        )
                        .await,
                    None => Err(Error::unavailable(
                        "WHATWG corpus storage is not configured.",
                    )),
                },
                "mdn" => match self.mdn_research.as_ref() {
                    Some(research) => research
                        .call(
                            "mdn_search",
                            json!({"query":input.query,"offset":page.offset,"limit":page.limit}),
                        )
                        .await,
                    None => Err(Error::unavailable("MDN corpus storage is not configured.")),
                },
                _ => {
                    return Err(Error::invalid(
                        "Search sources are rfc, cargo, rustsec, mdn, whatwg, w3c, chromium, and npm.",
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
        if let Some(id) = input.id.strip_prefix("npm:") {
            let (name, version) = id
                .rsplit_once('@')
                .filter(|(name, version)| !name.is_empty() && !version.is_empty())
                .ok_or_else(|| Error::invalid("npm IDs use npm:<name>@<version>."))?;
            return self
                .npm
                .call("npm_metadata", json!({"name":name,"version":version}))
                .await;
        }
        if let Some(id) = input.id.strip_prefix("chromium:") {
            let (document, anchor) = id.split_once('#').map_or((id, None), |(s, a)| (s, Some(a)));
            let (component, path) = document.split_once('/').ok_or_else(|| {
                Error::invalid("Chromium IDs use chromium:<component>/<path>#<anchor>.")
            })?;
            let mut args = json!({"component":component,"path":path,"offset":input.offset.unwrap_or(0),"limit":input.limit.unwrap_or(32768)});
            if let Some(anchor) = anchor {
                args["anchor"] = json!(anchor);
            }
            return self
                .chromium_research
                .as_ref()
                .ok_or_else(|| Error::unavailable("Chromium corpus storage is not configured."))?
                .call("chromium_get", args)
                .await;
        }
        if let Some(id) = input.id.strip_prefix("w3c:") {
            let (specification, anchor) =
                id.split_once('#').map_or((id, None), |(s, a)| (s, Some(a)));
            let mut args = json!({"specification":specification,"offset":input.offset.unwrap_or(0),"limit":input.limit.unwrap_or(32768)});
            if let Some(anchor) = anchor {
                args["anchor"] = json!(anchor);
            }
            return self
                .w3c_research
                .as_ref()
                .ok_or_else(|| Error::unavailable("W3C corpus storage is not configured."))?
                .call("w3c_get", args)
                .await;
        }
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
        if let Some(feature) = input.id.strip_prefix("mdn-compat:") {
            return self
                .mdn_research
                .as_ref()
                .ok_or_else(|| Error::unavailable("MDN corpus storage is not configured."))?
                .call("mdn_compat_get", json!({"feature":feature,"offset":input.offset.unwrap_or(0),"limit":input.limit.unwrap_or(20)}))
                .await;
        }
        if let Some(id) = input.id.strip_prefix("whatwg:") {
            let (standard, anchor) = id.split_once('#').map_or((id, None), |(s, a)| (s, Some(a)));
            let mut args = json!({"standard":standard,"offset":input.offset.unwrap_or(0),"limit":input.limit.unwrap_or(32768)});
            if let Some(anchor) = anchor {
                args["anchor"] = json!(anchor);
            }
            return self
                .whatwg_research
                .as_ref()
                .ok_or_else(|| Error::unavailable("WHATWG corpus storage is not configured."))?
                .call("whatwg_get", args)
                .await;
        }
        if let Some(slug) = input.id.strip_prefix("mdn:") {
            return self.mdn_research.as_ref().ok_or_else(|| Error::unavailable("MDN corpus storage is not configured."))?.call("mdn_get",json!({"slug":slug,"offset":input.offset.unwrap_or(0),"limit":input.limit.unwrap_or(32768)})).await;
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
        if url.host_str() == Some("chromium") {
            return self
                .chromium_research
                .as_ref()
                .ok_or_else(|| Error::unavailable("Chromium corpus storage is not configured."))?
                .read_resource(uri)
                .await;
        }
        if url.host_str() == Some("npm-source") {
            return self
                .npm
                .call("npm_source_read", crate::npm::source_input_from_uri(uri)?)
                .await;
        }
        if url.host_str() == Some("npm") {
            return self
                .npm_research
                .as_ref()
                .ok_or_else(|| Error::unavailable("npm corpus storage is not configured."))?
                .read_resource(uri)
                .await;
        }
        if url.host_str() == Some("mdn") {
            return self
                .mdn_research
                .as_ref()
                .ok_or_else(|| Error::unavailable("MDN corpus storage is not configured."))?
                .read_resource(uri)
                .await;
        }
        if url.host_str() == Some("whatwg") {
            return self
                .whatwg_research
                .as_ref()
                .ok_or_else(|| Error::unavailable("WHATWG corpus storage is not configured."))?
                .read_resource(uri)
                .await;
        }
        if url.host_str() == Some("w3c") {
            return self
                .w3c_research
                .as_ref()
                .ok_or_else(|| Error::unavailable("W3C corpus storage is not configured."))?
                .read_resource(uri)
                .await;
        }
        if url.host_str() == Some("source") {
            let input = cargo::source_input_from_uri(&url)?;
            let output = cargo::source_read(&self.retrieval, input).await?;
            return Ok(
                json!({"contents":[{"uri":uri,"mimeType":"text/plain","text":output["page"]["text"]}]}),
            );
        }
        if url.host_str() == Some("advisory") {
            return self
                .advisory_research
                .as_ref()
                .ok_or_else(|| Error::unavailable("Advisory corpus storage is not configured."))?
                .read_resource(uri)
                .await;
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
            "application/pdf" | "application/gzip" | "application/zip"
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
        "Search RFC metadata, crates.io packages, RustSec advisories, local MDN documents, WHATWG or W3C standards. Sources are independent; errors and freshness are explicit.",
        json!({"query":text,"sources":{"type":"array","items":{"enum":["rfc","cargo","rustsec","mdn","whatwg","w3c","chromium","npm"]},"minItems":1,"maxItems":8,"uniqueItems":true},"offset":offset,"limit":limit}),
        vec!["query"],
    );
    add(
        "fetch",
        "Retrieve rfc:<number>, crate:<name>@<version>, npm:<name>@<version>, mdn:<slug>, mdn-compat:<feature>, whatwg:<standard>#<anchor>, w3c:<shortname>#<anchor>, chromium:<component>/<path>#<anchor>, or an immutable devres resource URI. Text offsets count UTF-8 bytes.",
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
        json!({"name":text,"version":text,"advisory_snapshot":capture,"format":{"enum":["rustsec","osv"],"default":"rustsec"},"offset":offset,"limit":limit}),
        vec!["name", "version"],
    );
    add(
        "audit_lockfile",
        "Audit supplied Cargo.lock against a captured RustSec database. Input, dependency lists and results remain request-local. Resubmit input and advisory_snapshot for pagination.",
        json!({"lockfile":{"type":"string","minLength":1,"maxLength":1048576},"advisory_snapshot":capture,"format":{"enum":["rustsec","osv"],"default":"rustsec"},"offset":offset,"limit":limit}),
        vec!["lockfile"],
    );
    tools.extend(rfc_tools::schemas());
    tools.extend(crate::crates_io::research::schemas());
    tools.extend(crate::rustsec::research::schemas());
    tools.extend(crate::mdn::research::schemas());
    tools.extend(crate::whatwg::research::schemas());
    tools.extend(crate::w3c::research::schemas());
    tools.extend(crate::chromium::research::schemas());
    tools.extend(crate::npm::schemas());
    tools.extend(crate::npm::research::schemas());
    tools.extend(crate::npm::audit::schemas());
    tools
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyInput {}
