//! Read-only tool composition. Submitted audit data never enters retrieval/storage.

use crate::{
    crates_io::packages as cargo, rfc::corpus::RfcCorpus, rfc::source as rfc,
    rfc::tools as rfc_tools, rustsec::advisory,
};
#[path = "research_search.rs"]
mod search_scheduling;

use devres_application::{Retrieval, attribution_gate::AttributionGate};
use devres_domain::{Capture, Error, Result, StoredCapture};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

pub struct Research {
    retrieval: Arc<Retrieval>,
    attribution_gate: Option<Arc<dyn AttributionGate>>,
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
            attribution_gate: None,
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

    /// Production composition installs this gate before registering any tools.
    pub fn with_attribution_gate(mut self, gate: Arc<dyn AttributionGate>) -> Self {
        self.attribution_gate = Some(gate);
        self
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

    /// Invoke with the request's existing absolute deadline; no new wire parameters.
    pub async fn call_with_context(
        &self,
        tool: &str,
        input: Value,
        cancel: tokio_util::sync::CancellationToken,
        deadline: tokio::time::Instant,
    ) -> Result<Value> {
        if tool == "search" {
            let output = self
                .search_with_context(decode(input)?, cancel.clone(), deadline)
                .await?;
            return tokio::select! {
                biased;
                _ = cancel.cancelled() => Err(Error::new("cancelled", "Request cancelled.")),
                result = tokio::time::timeout_at(deadline, self.qualify_output("search", "mixed", output)) =>
                    result.map_err(|_| Error::unavailable("Attribution qualification deadline exceeded."))?,
            };
        }
        tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(Error::new("cancelled", "Request cancelled.")),
            result = self.call(tool, input) => result,
        }
    }

    pub async fn call(&self, tool: &str, input: Value) -> Result<Value> {
        let provider = if tool == "fetch" {
            input
                .get("id")
                .and_then(Value::as_str)
                .map(provider_for_identifier)
                .unwrap_or("unknown")
        } else {
            provider_for_tool(tool)
        }
        .to_owned();
        // Resource fetches run the exact same resource gate, rather than deriving
        // a second subject from their serialized page or notice attachments.
        let resource_fetch = tool == "fetch"
            && input
                .get("id")
                .and_then(Value::as_str)
                .is_some_and(|id| id.starts_with("devres://"));
        let output = self.call_unqualified(tool, input).await?;
        if resource_fetch {
            return Ok(output);
        }
        self.qualify_output(tool, &provider, output).await
    }

    async fn qualify_output(&self, tool: &str, provider: &str, mut output: Value) -> Result<Value> {
        let Some(gate) = &self.attribution_gate else {
            return Ok(output);
        };
        if !output.is_object() {
            return Err(Error::integrity("Invalid public tool representation."));
        }
        if tool.ends_with(".corpus_status") {
            output["attribution"] = gate.status().await?;
            return Ok(output);
        }
        if metadata_only_discovery(tool, &output) {
            output["attribution"] = json!({"status":"metadata_only","copied_content":false});
            return Ok(output);
        }
        let attribution = if matches!(tool, "audit.lockfile" | "npm.audit_lockfile") {
            self.qualify_audit(tool, &output, gate.as_ref()).await?
        } else {
            gate.qualify(provider, &output).await?
        };
        output["attribution"] = attribution;
        Ok(output)
    }

    async fn qualify_audit(
        &self,
        tool: &str,
        output: &Value,
        gate: &dyn AttributionGate,
    ) -> Result<Value> {
        // The report stays in request memory. Select only immutable public
        // records again by their source identifiers, without dependency fields.
        let ids = audit_advisory_ids(output)?;
        if ids.is_empty() {
            return Ok(json!({"status":"metadata_only","copied_content":false}));
        }
        let snapshot = output
            .pointer("/snapshot/id")
            .and_then(Value::as_str)
            .filter(|id| devres_domain::valid_content_id(id))
            .ok_or_else(|| {
                Error::unavailable("Public advisory snapshot attribution is unavailable.")
            })?;
        let mut records = Vec::with_capacity(ids.len());
        for id in ids {
            let record = if tool == "audit.lockfile" {
                let format = output
                    .pointer("/snapshot/format")
                    .and_then(Value::as_str)
                    .unwrap_or("rustsec");
                self.advisory_research
                    .as_ref()
                    .ok_or_else(|| {
                        Error::unavailable("Public advisory source storage is unavailable.")
                    })?
                    .call(
                        "advisory.get",
                        json!({"id":id,"snapshot":snapshot,"format":format,"limit":1}),
                    )
                    .await?
            } else {
                self.npm_research
                    .as_ref()
                    .ok_or_else(|| {
                        Error::unavailable("Public npm advisory source storage is unavailable.")
                    })?
                    .call(
                        "npm.advisory_get",
                        json!({"id":id,"snapshot":snapshot,"limit":1}),
                    )
                    .await?
            };
            records.push(resource_evidence(&record));
        }
        // audit:* is read-only: no matching subset, inventory or report may
        // create persistent targets, repairs, or caller-to-advisory associations.
        gate.qualify(
            if tool == "audit.lockfile" {
                "audit:rustsec"
            } else {
                "audit:npm"
            },
            &json!({"records":records}),
        )
        .await
    }

    async fn call_unqualified(&self, tool: &str, input: Value) -> Result<Value> {
        if crate::npm::schemas()
            .iter()
            .any(|schema| schema["name"] == tool)
        {
            return self.npm.call(tool, input).await;
        }
        if tool == "npm.audit_lockfile" {
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
            if tool == "crate.corpus_status" {
                let _: EmptyInput = decode(input)?;
                return corpus.status().await;
            }
            return corpus.research().call(tool, input).await;
        }
        if matches!(
            tool,
            "rfc.metadata"
                | "rfc.catalog_search"
                | "rfc.fulltext_search"
                | "rfc.format_get"
                | "rfc.errata"
                | "rfc.series_get"
                | "rfc.corpus_status"
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
            "rfc.search" => rfc::search(&self.retrieval, decode(input)?).await,
            "rfc.get" => rfc::get(&self.retrieval, decode(input)?).await,
            "crate.search" => cargo::search(&self.retrieval, decode(input)?).await,
            "crate.metadata" => cargo::metadata(&self.retrieval, decode(input)?).await,
            "crate.source_list" => cargo::source_list(&self.retrieval, decode(input)?).await,
            "crate.source_read" => cargo::source_read(&self.retrieval, decode(input)?).await,
            "advisory.lookup" => {
                self.advisory_summary_sources(self.advisory.lookup(decode(input)?).await?)
                    .await
            }
            "audit.lockfile" => self.advisory.audit(decode(input)?).await,
            "search" => self.search(decode(input)?).await,
            "fetch" => self.fetch(decode(input)?).await,
            _ => Err(Error::not_found("Unknown research tool.")),
        }
    }

    async fn advisory_summary_sources(&self, mut output: Value) -> Result<Value> {
        let Some(research) = &self.advisory_research else {
            return Ok(output);
        };
        let Some(snapshot) = output
            .pointer("/snapshot/id")
            .and_then(Value::as_str)
            .map(str::to_owned)
        else {
            return Ok(output);
        };
        let format = output
            .pointer("/snapshot/format")
            .and_then(Value::as_str)
            .unwrap_or("rustsec")
            .to_owned();
        if let Some(items) = output.get_mut("items").and_then(Value::as_array_mut) {
            if items.len() > 100 {
                return Err(Error::capacity(
                    "Advisory provenance page exceeds its bound.",
                ));
            }
            for item in items {
                let id = item
                    .get("id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| Error::integrity("Public advisory identity missing."))?
                    .to_owned();
                let record = research
                    .call(
                        "advisory.get",
                        json!({"id":id,"snapshot":snapshot,"format":format,"limit":1}),
                    )
                    .await?;
                item["source_capture"] = resource_evidence(&record);
            }
        }
        Ok(output)
    }

    async fn search(&self, input: SearchInput) -> Result<Value> {
        self.search_with_context(
            input,
            tokio_util::sync::CancellationToken::new(),
            tokio::time::Instant::now() + std::time::Duration::from_secs(75),
        )
        .await
    }

    async fn search_with_context(
        &self,
        input: SearchInput,
        cancel: tokio_util::sync::CancellationToken,
        deadline: tokio::time::Instant,
    ) -> Result<Value> {
        let page = Page {
            offset: input.offset,
            limit: input.limit,
        }
        .checked()?;
        search_scheduling::collect(input.sources, cancel, deadline, |source| {
            self.search_source(source, input.query.clone(), page)
        })
        .await
    }

    async fn search_source(&self, source: String, query: String, page: Page) -> Result<Value> {
        match source.as_str() {
            "npm" => {
                self.npm
                    .call(
                        "npm.search",
                        json!({"query":query,"offset":page.offset,"limit":page.limit}),
                    )
                    .await
            }
            "rfc" => {
                rfc::search(
                    &self.retrieval,
                    rfc::SearchInput {
                        query: query.clone(),
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
                        query: query.clone(),
                        offset: page.offset,
                        limit: page.limit,
                        capture: None,
                    },
                )
                .await
            }
            "rustsec" => {
                self.advisory_summary_sources(self.advisory.search(&query, page).await?)
                    .await
            }
            "chromium" => match self.chromium_research.as_ref() {
                Some(research) => {
                    research
                        .call(
                            "chromium.search",
                            json!({"query":query,"offset":page.offset,"limit":page.limit}),
                        )
                        .await
                }
                None => Err(Error::unavailable(
                    "Chromium corpus storage is not configured.",
                )),
            },
            "w3c" => match self.w3c_research.as_ref() {
                Some(research) => {
                    research
                        .call(
                            "w3c.search",
                            json!({"query":query,"offset":page.offset,"limit":page.limit}),
                        )
                        .await
                }
                None => Err(Error::unavailable("W3C corpus storage is not configured.")),
            },
            "whatwg" => match self.whatwg_research.as_ref() {
                Some(research) => {
                    research
                        .call(
                            "whatwg.search",
                            json!({"query":query,"offset":page.offset,"limit":page.limit}),
                        )
                        .await
                }
                None => Err(Error::unavailable(
                    "WHATWG corpus storage is not configured.",
                )),
            },
            "mdn" => match self.mdn_research.as_ref() {
                Some(research) => {
                    research
                        .call(
                            "mdn.search",
                            json!({"query":query,"offset":page.offset,"limit":page.limit}),
                        )
                        .await
                }
                None => Err(Error::unavailable("MDN corpus storage is not configured.")),
            },
            _ => Err(Error::invalid(
                "Search sources are rfc, cargo, rustsec, mdn, whatwg, w3c, chromium, and npm.",
            )),
        }
    }

    async fn fetch(&self, input: FetchInput) -> Result<Value> {
        if let Some(id) = input.id.strip_prefix("npm:") {
            let (name, version) = id
                .rsplit_once('@')
                .filter(|(name, version)| !name.is_empty() && !version.is_empty())
                .ok_or_else(|| Error::invalid("npm IDs use npm:<name>@<version>."))?;
            return self
                .npm
                .call("npm.metadata", json!({"name":name,"version":version}))
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
                .call("chromium.get", args)
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
                .call("w3c.get", args)
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
                .call("mdn.compat_get", json!({"feature":feature,"offset":input.offset.unwrap_or(0),"limit":input.limit.unwrap_or(20)}))
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
                .call("whatwg.get", args)
                .await;
        }
        if let Some(slug) = input.id.strip_prefix("mdn:") {
            return self.mdn_research.as_ref().ok_or_else(|| Error::unavailable("MDN corpus storage is not configured."))?.call("mdn.get",json!({"slug":slug,"offset":input.offset.unwrap_or(0),"limit":input.limit.unwrap_or(32768)})).await;
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
        if url.host_str() == Some("attribution") {
            let id = url
                .path()
                .strip_prefix('/')
                .filter(|id| devres_domain::valid_content_id(id))
                .ok_or_else(|| Error::invalid("Invalid attribution generation."))?;
            let (offset, limit) = resource_page(&url)?;
            return self
                .attribution_gate
                .as_ref()
                .ok_or_else(|| Error::unavailable("Attribution storage is not configured."))?
                .bundle(id, offset, limit)
                .await;
        }
        let output = self.read_resource_unqualified(uri).await?;
        let Some(gate) = &self.attribution_gate else {
            return Ok(output);
        };
        let provider = provider_for_resource(url.host_str().unwrap_or("unknown"));
        let attribution = gate.qualify(provider, &output).await?;
        attach_resource_attribution(output, attribution)
    }

    async fn read_resource_unqualified(&self, uri: &str) -> Result<Value> {
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
            let mut output = self
                .npm
                .call("npm.source_read", crate::npm::source_input_from_uri(uri)?)
                .await?;
            // The direct adapter historically returned source_read fields here.
            // Retain them while adding the valid MCP resource envelope.
            output["contents"] = json!([{"uri":uri,"mimeType":"text/plain","text":output["page"]["text"],"_meta":{"source_evidence":resource_evidence(&output)}}]);
            return Ok(output);
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
                json!({"contents":[{"uri":uri,"mimeType":"text/plain","text":output["page"]["text"],"_meta":{"source_evidence":resource_evidence(&output)}}]}),
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
                json!({"contents":[{"uri":uri,"mimeType":"application/pdf","blob":value["page"]["data"],"_meta":{"source_evidence":resource_evidence(&value)}}]})
            } else {
                json!({"contents":[{"uri":uri,"mimeType":"text/plain","text":value["page"]["text"],"_meta":{"source_evidence":resource_evidence(&value)}}]})
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
            json!({"contents":[{"uri":uri,"mimeType":stored.capture.media_type,"text":page["text"],"_meta":{"source_evidence":{"capture":capture_json(&stored.capture,0),"source_key":stored.capture.key,"media_type":stored.capture.media_type}}}]}),
        )
    }

    pub fn tool_schemas() -> Vec<Value> {
        schemas()
    }
}

/// Source evidence excludes the copied page, preserving identity and notices
/// without duplicating a maximum-sized body inside MCP metadata.
pub(crate) fn resource_evidence(output: &Value) -> Value {
    let mut evidence = output.clone();
    if let Some(object) = evidence.as_object_mut() {
        object.remove("page");
        object.remove("contents");
        object.remove("original");
        object.remove("resolved");
        object.remove("contracts");
        if let Some(advisory) = object.get_mut("advisory").and_then(Value::as_object_mut) {
            for field in ["original", "description", "details", "summary"] {
                advisory.remove(field);
            }
        }
        if let Some(advisory) = object
            .get_mut("source_capture")
            .and_then(|source| source.get_mut("advisory"))
            .and_then(Value::as_object_mut)
        {
            for field in ["original", "description", "details", "summary"] {
                advisory.remove(field);
            }
        }
    }
    evidence
}

/// Empty search pages and natural version facts do not reproduce upstream
/// prose. This is a narrow schema-aware exception, never targets-empty success.
fn metadata_only_discovery(tool: &str, output: &Value) -> bool {
    fn copied(value: &Value, depth: usize) -> bool {
        if depth > 24 {
            return true;
        }
        match value {
            Value::Object(object) => object.iter().any(|(key, value)| {
                let populated = !value.is_null()
                    && value.as_str() != Some("")
                    && value.as_array().is_none_or(|values| !values.is_empty());
                (populated
                    && matches!(
                        key.as_str(),
                        "text"
                            | "body"
                            | "description"
                            | "summary"
                            | "title"
                            | "abstract"
                            | "abstract_text"
                            | "snippet"
                            | "content"
                            | "original"
                            | "resolved"
                            | "contracts"
                            | "source_text"
                            | "license_text"
                            | "notice"
                    ))
                    || copied(value, depth + 1)
            }),
            Value::Array(values) => values.iter().any(|value| copied(value, depth + 1)),
            _ => false,
        }
    }
    fn natural_metadata(value: &Value, key: &str, depth: usize) -> bool {
        if depth > 24 {
            return false;
        }
        match value {
            Value::Null | Value::Bool(_) | Value::Number(_) => true,
            Value::String(text) => {
                matches!(
                    key,
                    "id" | "revision"
                        | "format"
                        | "source_url"
                        | "url"
                        | "resource_uri"
                        | "body_hash"
                        | "name"
                        | "version"
                        | "path"
                        | "repository"
                        | "kind"
                        | "source_key"
                        | "snapshot"
                        | "view"
                        | "parents"
                        | "ref"
                        | "status"
                        | "reason"
                        | "source"
                        | "next_cursor"
                        | "index"
                        | "manifest"
                        | "head"
                        | "inventory"
                        | "lane"
                        | "artifact_capture"
                ) && text.len() <= 16384
                    && text
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b":/._@?%#=+-".contains(&byte))
            }
            Value::Array(values) => values
                .iter()
                .all(|value| natural_metadata(value, key, depth + 1)),
            Value::Object(values) => values
                .iter()
                .all(|(key, value)| natural_metadata(value, key, depth + 1)),
        }
    }
    fn natural_fields(row: &Value) -> bool {
        let name = row.get("name").and_then(Value::as_str).unwrap_or_default();
        let version = row
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if name.is_empty()
            || crate::npm::processing::validate_name(name).is_err()
            || semver::Version::parse(version).is_err()
        {
            return false;
        }
        if !row.get("license").is_none_or(|value| {
            value.is_null()
                || value.as_str().is_some_and(|value| {
                    matches!(
                        value,
                        "" | "MIT"
                            | "Apache-2.0"
                            | "ISC"
                            | "BSD-2-Clause"
                            | "BSD-3-Clause"
                            | "CC0-1.0"
                            | "MPL-2.0"
                            | "Unlicense"
                    )
                })
        }) {
            return false;
        }
        if !row.get("engines").is_none_or(|value| {
            value.is_null()
                || value.as_object().is_some_and(|engines| {
                    engines.iter().all(|(engine, value)| {
                        matches!(
                            engine.as_str(),
                            "node" | "npm" | "yarn" | "pnpm" | "bun" | "deno"
                        ) && value.as_str().is_some_and(|value| {
                            value.len() <= 128
                                && value.bytes().all(|byte| {
                                    byte.is_ascii_digit() || b".*^~<>=| -".contains(&byte)
                                })
                        })
                    })
                })
        }) {
            return false;
        }
        if !row.get("dist").is_none_or(|value| {
            value.is_null()
                || value.as_object().is_some_and(|dist| {
                    dist.iter().all(|(key, value)| match key.as_str() {
                        "tarball" => value.as_str().is_some_and(|url| {
                            crate::npm::source::Operation::Archive {
                                name: name.into(),
                                version: version.into(),
                                url: url.into(),
                            }
                            .url()
                            .is_ok()
                        }),
                        "integrity" => value.as_str().is_some_and(|value| {
                            value.len() <= 256
                                && (value.starts_with("sha512-") || value.starts_with("sha256-"))
                                && value.bytes().all(|byte| {
                                    byte.is_ascii_alphanumeric() || b"+/=_-".contains(&byte)
                                })
                        }),
                        "shasum" => value.as_str().is_some_and(|value| {
                            value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
                        }),
                        "fileCount" | "unpackedSize" => value.as_u64().is_some(),
                        _ => false,
                    })
                })
        }) {
            return false;
        }
        if !row.get("metadata_capture").is_none_or(|value| {
            value.is_null() || value.as_str().is_some_and(devres_domain::valid_content_id)
        }) {
            return false;
        }
        true
    }
    if copied(output, 0) {
        return false;
    }
    if matches!(tool, "npm.versions" | "crate.versions") {
        if !output.as_object().is_some_and(|headers| {
            headers
                .iter()
                .filter(|(key, _)| !matches!(key.as_str(), "items" | "results"))
                .all(|(key, value)| natural_metadata(value, key, 0))
        }) {
            return false;
        }
        let rows = output
            .get("items")
            .or_else(|| output.get("results"))
            .and_then(Value::as_array);
        return rows.is_some_and(|rows| {
            rows.len() <= 100
                && rows.iter().all(|row| {
                    natural_fields(row)
                        && row.as_object().is_some_and(|row| {
                            row.keys().all(|key| {
                                matches!(
                                    key.as_str(),
                                    "name"
                                        | "version"
                                        | "description"
                                        | "license"
                                        | "keywords"
                                        | "deprecated"
                                        | "engines"
                                        | "dist"
                                        | "metadata_capture"
                                        | "yanked"
                                        | "checksum"
                                        | "id"
                                        | "source_capture"
                                )
                            })
                        })
                        && row.get("keywords").is_none_or(|value| {
                            value.is_null() || value.as_array().is_some_and(Vec::is_empty)
                        })
                        && row.get("deprecated").is_none_or(|value| {
                            value.is_null() || value.is_boolean() || value.as_str() == Some("")
                        })
                })
        });
    }
    if !(tool.ends_with(".search")
        || tool.ends_with(".catalog_search")
        || tool.ends_with(".content_search")
        || tool.ends_with(".api_search")
        || tool.ends_with(".symbol_search")
        || tool.ends_with(".compat_search")
        || matches!(tool, "advisory.lookup" | "npm.advisory_lookup"))
    {
        return false;
    }
    let mut collection = false;
    for field in ["items", "results", "matches"] {
        if let Some(value) = output.get(field) {
            collection = true;
            if !value.as_array().is_some_and(Vec::is_empty) {
                return false;
            }
        }
    }
    collection
        && output
            .get("total")
            .is_some_and(|total| total.as_u64() == Some(0))
        && natural_metadata(output, "", 0)
}

fn audit_advisory_ids(output: &Value) -> Result<Vec<String>> {
    let mut ids = std::collections::BTreeSet::new();
    for finding in output
        .get("findings")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let advisory = &finding["advisory"];
        let copied = advisory.as_object().is_some_and(|fields| {
            fields.iter().any(|(field, value)| {
                !value.is_null()
                    && value.as_str() != Some("")
                    && (!matches!(
                        field.as_str(),
                        "id" | "aliases"
                            | "packages"
                            | "package"
                            | "classification"
                            | "matching_complete"
                            | "license"
                            | "attribution_url"
                            | "url"
                            | "rights_gap"
                            | "published"
                            | "modified"
                            | "withdrawn"
                            | "date"
                            | "patched"
                            | "unaffected"
                            | "affected"
                            | "categories"
                            | "keywords"
                            | "informational"
                            | "format"
                    ) || matches!(
                        field.as_str(),
                        "title" | "summary" | "description" | "details"
                    ))
            })
        });
        if !copied {
            continue;
        }
        let id = advisory
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| Error::unavailable("Copied advisory source identity is unavailable."))?;
        ids.insert(id.to_owned());
        for id in finding
            .get("source_advisory_ids")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(id) = id.as_str() {
                ids.insert(id.to_owned());
            }
        }
        if ids.len() > 128 {
            return Err(Error::capacity(
                "Public advisory attribution selection exceeds its bound.",
            ));
        }
    }
    Ok(ids.into_iter().collect())
}

fn provider_for_tool(tool: &str) -> &str {
    match tool.split('.').next().unwrap_or(tool) {
        "crate" => "crates",
        "advisory" | "audit" => "rustsec",
        "search" => "mixed",
        provider => provider,
    }
}
fn provider_for_resource(host: &str) -> &str {
    match host {
        "source" => "crates",
        "advisory" => "rustsec",
        "npm-source" => "npm",
        provider => provider,
    }
}
fn provider_for_identifier(id: &str) -> &str {
    match id.split(':').next().unwrap_or(id) {
        "crate" => "crates",
        "mdn-compat" => "mdn",
        provider => provider,
    }
}
fn resource_page(url: &url::Url) -> Result<(usize, usize)> {
    let (mut offset, mut limit) = (0, 32768);
    let mut seen = std::collections::HashSet::new();
    for (key, value) in url.query_pairs() {
        if !seen.insert(key.to_string()) {
            return Err(Error::invalid("Duplicate resource page parameter."));
        }
        let parsed = value
            .parse()
            .map_err(|_| Error::invalid("Invalid resource page parameter."))?;
        match key.as_ref() {
            "offset" => offset = parsed,
            "limit" => limit = parsed,
            _ => return Err(Error::invalid("Unknown resource page parameter.")),
        }
    }
    if limit == 0 || limit > 32768 {
        return Err(Error::invalid("Resource limit must be 1..32768."));
    }
    Ok((offset, limit))
}
fn attach_resource_attribution(mut output: Value, attribution: Value) -> Result<Value> {
    let contents = output
        .get_mut("contents")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| Error::integrity("Invalid public resource representation."))?;
    let mut metadata_attribution = attribution.clone();
    if let Some(fields) = metadata_attribution.as_object_mut() {
        fields.remove("readable_notice");
        if let Some(generations) = fields.get_mut("generations").and_then(Value::as_array_mut) {
            for generation in generations {
                if let Some(notices) = generation.get_mut("notices").and_then(Value::as_array_mut) {
                    for notice in notices {
                        if let Some(notice) = notice.as_object_mut() {
                            notice.remove("text");
                        }
                    }
                }
            }
        }
    }
    for item in contents.iter_mut() {
        let object = item
            .as_object_mut()
            .ok_or_else(|| Error::integrity("Invalid public resource item."))?;
        let metadata = object.entry("_meta").or_insert_with(|| json!({}));
        let metadata = metadata
            .as_object_mut()
            .ok_or_else(|| Error::integrity("Invalid public resource metadata."))?;
        metadata.insert("attribution".into(), metadata_attribution.clone());
    }
    let notice = attribution
        .get("readable_notice")
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| Error::integrity("Qualified attribution notice missing."))?;
    let uri = attribution
        .get("resource_uri")
        .and_then(Value::as_str)
        .filter(|uri| uri.starts_with("devres://attribution/"))
        .ok_or_else(|| Error::integrity("Qualified attribution reference missing."))?;
    contents.push(json!({"uri":uri,"mimeType":"text/plain","text":notice}));
    output["attribution"] = attribution;
    Ok(output)
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
    [
        "rfc", "cargo", "rustsec", "mdn", "whatwg", "w3c", "chromium", "npm",
    ]
    .map(str::to_owned)
    .to_vec()
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
        "Search all eight developer source families by default: RFC metadata, Cargo and npm package discovery, RustSec advisories, and retained MDN, WHATWG, W3C and Chromium content. Select sources to narrow the search. Results, ranking, paging and errors remain source-specific. Use dedicated research tools for package full-text, compatibility, symbols and history.",
        json!({"query":text,"sources":{"type":"array","description":"Omitted sources search rfc, cargo, rustsec, mdn, whatwg, w3c, chromium and npm in that order. Explicit selection searches only those families in the requested order.","items":{"enum":["rfc","cargo","rustsec","mdn","whatwg","w3c","chromium","npm"]},"minItems":1,"maxItems":8,"uniqueItems":true},"offset":offset,"limit":limit}),
        vec!["query"],
    );
    add(
        "fetch",
        "Retrieve rfc:<number>, crate:<name>@<version>, npm:<name>@<version>, mdn:<slug>, mdn-compat:<feature>, whatwg:<standard>#<anchor>, w3c:<shortname>#<anchor>, chromium:<component>/<path>#<anchor>, or an immutable devres resource URI. Text offsets count UTF-8 bytes.",
        json!({"id":{"type":"string","minLength":1,"maxLength":16384},"offset":text_offset,"limit":text_limit}),
        vec!["id"],
    );
    add(
        "rfc.search",
        "Search official RFC index metadata in index order, not relevance order. Use specific terms or rfc.fulltext_search for ranked retained text. Reuse capture for stable pagination.",
        json!({"query":text,"status":text,"offset":offset,"limit":limit,"capture":capture}),
        vec!["query"],
    );
    add(
        "rfc.get",
        "Read a selected RFC's published text in bounded UTF-8 pages; reuse capture for stable pagination.",
        json!({"number":{"type":"integer","minimum":1,"maximum":999999},"offset":text_offset,"limit":text_limit,"capture":capture}),
        vec!["number"],
    );
    add(
        "crate.search",
        "Search crates.io packages. Reuse capture for the same bounded upstream result page.",
        json!({"query":text,"offset":offset,"limit":limit,"capture":capture}),
        vec!["query"],
    );
    add(
        "crate.metadata",
        "Inspect an exact crates.io version including dependency declarations, features, yanked state and archive checksum.",
        json!({"name":text,"version":text,"capture":capture}),
        vec!["name", "version"],
    );
    add(
        "crate.source_list",
        "List verified published source archive files. Capture IDs bind the index and archive for stable paging.",
        json!({"name":text,"version":text,"metadata_capture":capture,"archive_capture":capture,"offset":offset,"limit":limit}),
        vec!["name", "version"],
    );
    add(
        "crate.source_read",
        "Read a verified published source file without executing or extracting it. Offsets count UTF-8 bytes.",
        json!({"name":text,"version":text,"path":{"type":"string","minLength":1,"maxLength":4096},"metadata_capture":capture,"archive_capture":capture,"offset":text_offset,"limit":text_limit}),
        vec!["name", "version", "path"],
    );
    add(
        "advisory.lookup",
        "Match RustSec advisories to a crates.io package/version. Reports stale, withdrawn and informational advisory state explicitly.",
        json!({"name":text,"version":text,"advisory_snapshot":capture,"format":{"enum":["rustsec","osv"],"default":"rustsec"},"offset":offset,"limit":limit}),
        vec!["name", "version"],
    );
    add(
        "audit.lockfile",
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

#[cfg(test)]
mod attribution_boundary_tests {
    use super::*;

    #[test]
    fn only_empty_discovery_and_version_facts_bypass_content_qualification() {
        assert!(metadata_only_discovery(
            "npm.versions",
            &json!({"items":[{"name":"fixture","version":"1.0.0","description":null,"license":"ISC"}],"total":1})
        ));
        assert!(!metadata_only_discovery(
            "npm.versions",
            &json!({"items":[{"name":"fixture","version":"1.0.0","description":"copied upstream prose"}],"total":1})
        ));
        assert!(metadata_only_discovery(
            "advisory.lookup",
            &json!({"items":[],"total":0,"snapshot":{"id":"public"}})
        ));
        assert!(!metadata_only_discovery(
            "advisory.lookup",
            &json!({"items":[{"summary":"copied advisory"}],"total":1})
        ));
        assert!(!metadata_only_discovery(
            "mdn.get",
            &json!({"items":[],"total":0})
        ));
        assert!(!metadata_only_discovery(
            "audit.lockfile",
            &json!({"items":[],"total":0})
        ));
        assert!(!metadata_only_discovery(
            "npm.versions",
            &json!({"items":[{"name":"fixture","version":"1","unknown_copy":"upstream content"}]})
        ));
        assert!(!metadata_only_discovery(
            "advisory.lookup",
            &json!({"items":[],"total":0,"snapshot":{"unrecognized_copy":"Original upstream prose"}})
        ));
        assert!(!metadata_only_discovery(
            "npm.versions",
            &json!({"items":[{"name":"fixture","version":"1.0.0"}],"snapshot":{"message":"Original upstream prose"}})
        ));
        for row in [
            json!({"name":"fixture","version":"1.0.0","license":"Copyright original authors. Redistribution terms follow."}),
            json!({"name":"fixture","version":"1.0.0","engines":{"notice":"copied upstream prose"}}),
            json!({"name":"fixture","version":"1.0.0","dist":{"notice":"copied upstream prose"}}),
        ] {
            assert!(!metadata_only_discovery(
                "npm.versions",
                &json!({"items":[row]})
            ));
        }
    }

    #[test]
    fn audits_reselect_only_public_advisory_ids_without_inventory_associations() {
        let ids=audit_advisory_ids(&json!({
            "snapshot":{"id":"public-snapshot"},
            "findings":[{"package":"private-package-marker","version":"private-version-marker","advisory":{"id":"GHSA-public-source-id","summary":"Original public advisory summary"},"source_advisory_ids":["GHSA-other-public-id"]},
                {"package":"private-unknown-marker","advisory":{"id":"unresolved-rights-id","summary":null}}],
            "lockfile":"private-lockfile-marker","entry_count":27
        })).unwrap();
        assert_eq!(ids, vec!["GHSA-other-public-id", "GHSA-public-source-id"]);
        let serialized = serde_json::to_string(&ids).unwrap();
        for private in [
            "private-package-marker",
            "private-version-marker",
            "private-unknown-marker",
            "private-lockfile-marker",
            "entry_count",
        ] {
            assert!(!serialized.contains(private));
        }
        assert!(
            audit_advisory_ids(&json!({"findings":[],"entry_count":42}))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn resource_evidence_preserves_original_identity_without_copying_page_bytes() {
        let evidence = resource_evidence(&json!({
            "capture":{"id":"immutable","body_hash":"digest","source_url":"https://source.invalid/exact"},
            "license":{"notice":"original notice"},
            "advisory":{"id":"public","license":"CC0-1.0","original":{"description":"unpaged full source body"}},
            "page":{"text":"copied excerpt","offset":100},
            "contents":[{"text":"copied excerpt"}]
        }));
        assert_eq!(evidence["capture"]["id"], "immutable");
        assert_eq!(evidence["license"]["notice"], "original notice");
        assert!(evidence.get("page").is_none());
        assert!(evidence.get("contents").is_none());
        assert!(evidence["advisory"].get("original").is_none());
        assert_eq!(evidence["advisory"]["license"], "CC0-1.0");
        assert!(!evidence.to_string().contains("unpaged full source body"));
    }

    #[test]
    fn source_and_fetch_aliases_use_the_same_provider_policy() {
        for (tool, id, provider) in [
            ("crate.source_read", "crate:itoa@1.0.15", "crates"),
            ("mdn.get", "mdn:Web/API", "mdn"),
            ("rfc.get", "rfc:9000", "rfc"),
            ("whatwg.get", "whatwg:html", "whatwg"),
            ("w3c.get", "w3c:fixture", "w3c"),
            ("chromium.get", "chromium:src/docs/example.md", "chromium"),
            ("npm.document_get", "npm:fixture@1.0.0", "npm"),
        ] {
            assert_eq!(provider_for_tool(tool), provider);
            assert_eq!(provider_for_identifier(id), provider);
        }
        assert_eq!(provider_for_resource("source"), "crates");
        assert_eq!(provider_for_resource("npm-source"), "npm");
        assert_eq!(provider_for_resource("advisory"), "rustsec");
        assert_eq!(provider_for_tool("advisory.get"), "rustsec");
        assert_eq!(provider_for_identifier("mdn-compat:api.fetch"), "mdn");
    }
}
