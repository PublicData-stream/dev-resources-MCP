//! Local, capture-fixed WHATWG research. No public operation acquires upstream data.
use crate::{
    research::{decode, text_page},
    whatwg::WhatwgCorpus,
    whatwg::processing::ProcessedDocument,
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use devres_application::whatwg::{Catalog, Member, Snapshot, View};
use devres_domain::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;

const MAX_SCAN: usize = 1_000_000;
const MAX_OUTPUT: usize = 64 * 1024 * 1024;
fn twenty() -> usize {
    20
}
fn text_limit() -> usize {
    32768
}
fn technical() -> String {
    "technical".into()
}
fn text_representation() -> String {
    "text".into()
}
fn digest(value: &impl Serialize) -> Result<String> {
    Ok(crate::integrity::hash(&serde_json::to_vec(value).map_err(
        |_| Error::integrity("Invalid WHATWG evidence."),
    )?))
}
fn fingerprint(value: &impl Serialize, cursor: Option<&str>) -> Result<String> {
    let bytes =
        serde_json::to_vec(value).map_err(|_| Error::integrity("Invalid query identity."))?;
    let version = if let Some(cursor) = cursor {
        if cursor.len() > 16_384 {
            return Err(Error::invalid("Cursor exceeds its bound."));
        }
        let data = URL_SAFE_NO_PAD
            .decode(cursor)
            .map_err(|_| Error::invalid("Invalid query cursor."))?;
        let value: Value =
            serde_json::from_slice(&data).map_err(|_| Error::invalid("Invalid query cursor."))?;
        value
            .get("version")
            .map_or(Some(0), Value::as_u64)
            .ok_or_else(|| Error::invalid("Invalid cursor version."))?
    } else {
        2
    };
    match version {
        0 => Ok(crate::integrity::legacy_hash(&bytes)),
        2 => Ok(crate::integrity::hash(&bytes)),
        _ => Err(Error::invalid("Unsupported cursor version.")),
    }
}
fn retained<T: serde::de::DeserializeOwned>(value: Value) -> Result<T> {
    serde_json::from_value(value).map_err(|_| Error::integrity("Invalid retained WHATWG evidence."))
}
fn valid_hash(id: &str) -> bool {
    crate::integrity::valid_hash(id)
}
fn check(deadline: Instant, cancel: &CancellationToken) -> Result<()> {
    if cancel.is_cancelled() {
        return Err(Error::new("cancelled", "WHATWG research canceled."));
    }
    if Instant::now() >= deadline {
        return Err(Error::capacity(
            "WHATWG research processing bound exceeded.",
        ));
    }
    Ok(())
}
struct CancelOnDrop(CancellationToken);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Selector {
    standard: Option<String>,
    snapshot: Option<String>,
    view: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchInput {
    standard: Option<String>,
    snapshot: Option<String>,
    view: Option<String>,
    query: Option<String>,
    edition: Option<String>,
    path: Option<String>,
    kind: Option<String>,
    #[serde(default = "technical")]
    mode: String,
    #[serde(default)]
    offset: usize,
    #[serde(default = "twenty")]
    limit: usize,
    cursor: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GetInput {
    standard: String,
    snapshot: Option<String>,
    view: Option<String>,
    path: Option<String>,
    anchor: Option<String>,
    section_index: Option<usize>,
    #[serde(default = "text_representation")]
    representation: String,
    #[serde(default)]
    offset: usize,
    #[serde(default = "text_limit")]
    limit: usize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListInput {
    standard: Option<String>,
    snapshot: Option<String>,
    view: Option<String>,
    query: Option<String>,
    kind: Option<String>,
    name: Option<String>,
    anchor: Option<String>,
    path: Option<String>,
    direction: Option<String>,
    target: Option<String>,
    #[serde(default)]
    offset: usize,
    #[serde(default = "twenty")]
    limit: usize,
    cursor: Option<String>,
    history_snapshot: Option<i64>,
    history_type: Option<String>,
    repository: Option<String>,
    #[serde(rename = "ref")]
    reference: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SymbolGetInput {
    standard: String,
    snapshot: Option<String>,
    view: Option<String>,
    path: Option<String>,
    symbol_index: Option<usize>,
    kind: Option<String>,
    name: Option<String>,
    anchor: Option<String>,
    #[serde(default)]
    offset: usize,
    #[serde(default = "text_limit")]
    limit: usize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompareInput {
    standard: String,
    before: String,
    after: String,
    anchor: Option<String>,
    path: Option<String>,
    #[serde(default = "text_representation")]
    mode: String,
    #[serde(default)]
    offset: usize,
    #[serde(default = "twenty")]
    limit: usize,
    cursor: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyInput {}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    #[serde(default)]
    version: u8,
    fingerprint: String,
    position: usize,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryCursor {
    #[serde(default)]
    version: u8,
    fingerprint: String,
    after: i64,
    cutoff: i64,
    skip: usize,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RefHistoryCursor {
    #[serde(default)]
    version: u8,
    fingerprint: String,
    after: i64,
    entry: usize,
    cutoff: i64,
    skip: usize,
}
fn position(fingerprint: &str, offset: usize, cursor: Option<&str>, limit: usize) -> Result<usize> {
    if !(1..=100).contains(&limit) || offset > 10_000 {
        return Err(Error::invalid(
            "WHATWG lists require limit 1..100 and offset at most 10000.",
        ));
    }
    let Some(cursor) = cursor else {
        return Ok(offset);
    };
    if cursor.len() > 16_384 || offset != 0 {
        return Err(Error::invalid("Invalid WHATWG cursor continuation."));
    }
    let c: Cursor = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(cursor)
            .map_err(|_| Error::invalid("Invalid WHATWG cursor."))?,
    )
    .map_err(|_| Error::invalid("Invalid WHATWG cursor."))?;
    if c.fingerprint != fingerprint || c.position > MAX_SCAN {
        return Err(Error::invalid(
            "WHATWG cursor does not match the selected evidence and query.",
        ));
    }
    Ok(c.position)
}
fn page(items: Vec<Value>, fingerprint: String, start: usize, limit: usize) -> Result<Value> {
    if start > items.len() {
        return Err(Error::invalid("WHATWG page is outside selected results."));
    }
    let end = start.saturating_add(limit).min(items.len());
    let next = if end < items.len() {
        Some(
            URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(&Cursor {
                    version: if fingerprint.starts_with("blake3:") {
                        2
                    } else {
                        0
                    },
                    fingerprint,
                    position: end,
                })
                .map_err(|_| Error::integrity("Invalid WHATWG cursor encoding."))?,
            ),
        )
    } else {
        None
    };
    Ok(json!({"items":items[start..end],"offset":start,"total":items.len(),"next_cursor":next}))
}
fn public_snapshot(snapshot: &Snapshot, historical: bool) -> Value {
    json!({"snapshot":snapshot.id,"standard":snapshot.standard,"repository":snapshot.repository,
        "revision":snapshot.revision,"representation":snapshot.representation,"processor_version":snapshot.processor_version,
        "validated_at":snapshot.validated_at,"stale":devres_domain::unix_now().saturating_sub(snapshot.validated_at)>86400,
        "historical":historical,"coverage":snapshot.coverage,"source_url":snapshot.source_url})
}
fn public_selection(snapshot: &Snapshot, historical: bool, view: Option<&View>) -> Value {
    let mut result = public_snapshot(snapshot, historical);
    if let Some(view) = view {
        let validated = view
            .validations
            .get(&snapshot.standard)
            .copied()
            .unwrap_or(snapshot.validated_at);
        result["view"] = json!(view.id);
        result["validated_at"] = json!(validated);
        result["stale"] = json!(devres_domain::unix_now().saturating_sub(validated) > 86400);
    }
    result
}
fn resource(
    snapshot: &Snapshot,
    representation: &str,
    path: &str,
    section_index: Option<usize>,
) -> String {
    let id = URL_SAFE_NO_PAD.encode(path.as_bytes());
    let mut uri = format!(
        "devres://whatwg/{}/{}/{representation}/{id}",
        snapshot.standard, snapshot.id
    );
    if let Some(index) = section_index {
        uri.push_str(&format!("?section_index={index}"));
    }
    uri
}
fn symbol_resource(snapshot: &Snapshot, path: &str, symbol_index: usize) -> String {
    format!(
        "{}?symbol_index={symbol_index}",
        resource(snapshot, "symbol", path, None)
    )
}
fn comparison_path(snapshot: &Snapshot, path: &str) -> String {
    if snapshot.representation != "source" {
        let mut parts = path.splitn(3, '/');
        if matches!(parts.next(), Some("commit-snapshots" | "review-drafts"))
            && parts.next().is_some()
            && let Some(relative) = parts.next()
        {
            return relative.to_owned();
        }
    }
    path.to_owned()
}
fn source_license(snapshot: &Snapshot) -> Value {
    json!({"attribution":"Original publication and repository contributors","notice":"Preserve the original notices in this captured publication or repository revision; no blanket license is inferred.","source_url":snapshot.source_url,"revision":snapshot.revision,"service_license_applies_to_source":false})
}

pub struct WhatwgResearch {
    corpus: Arc<WhatwgCorpus>,
}
impl WhatwgResearch {
    pub fn new(corpus: Arc<WhatwgCorpus>) -> Self {
        Self { corpus }
    }
    pub async fn call(&self, tool: &str, input: Value) -> Result<Value> {
        let cancel = CancellationToken::new();
        let _guard = CancelOnDrop(cancel.clone());
        match tool {
            "whatwg.corpus_status" => {
                let _: EmptyInput = decode(input)?;
                self.corpus.status().await
            }
            "whatwg.get" => self.get(decode(input)?, cancel).await,
            "whatwg.search" => self.search(decode(input)?, cancel).await,
            "whatwg.symbol_get" => self.symbol_get(decode(input)?, cancel).await,
            "whatwg.compare" => self.compare(decode(input)?, cancel).await,
            "whatwg.catalog_search"
            | "whatwg.symbol_search"
            | "whatwg.references"
            | "whatwg.snapshots"
            | "whatwg.history" => self.list(tool, decode(input)?, cancel).await,
            _ => Err(Error::not_found("Unknown WHATWG research tool.")),
        }
    }
    async fn selections(&self, selector: &Selector) -> Result<(Option<View>, Vec<Snapshot>)> {
        if let Some(id) = &selector.snapshot {
            if selector.view.is_some() {
                return Err(Error::invalid(
                    "Choose a WHATWG view or a document snapshot.",
                ));
            }
            let s = self.corpus.snapshot(id).await?;
            if selector
                .standard
                .as_ref()
                .is_some_and(|standard| standard != &s.standard)
            {
                return Err(Error::invalid(
                    "WHATWG snapshot belongs to a different standard.",
                ));
            }
            return Ok((None, vec![s]));
        }
        let view = self.corpus.view(selector.view.as_deref()).await?;
        let mut selected = Vec::new();
        for standard in view.snapshots.keys() {
            if selector.standard.as_ref().is_none_or(|s| s == standard) {
                if selector.view.is_none()
                    && devres_domain::unix_now()
                        .saturating_sub(view.validations.get(standard).copied().unwrap_or(0))
                        > 7 * 86400
                {
                    return Err(Error::unavailable(
                        "Selected WHATWG default evidence is older than seven days; select a historical view explicitly.",
                    ));
                }
                selected.push(self.corpus.select(standard, None, Some(&view.id)).await?);
            }
        }
        if selector.standard.is_some() && selected.is_empty() {
            return Err(Error::unavailable(
                "Selected WHATWG standard has no published snapshot.",
            ));
        }
        Ok((Some(view), selected))
    }
    async fn documents(
        &self,
        snapshot: &Snapshot,
        cancel: &CancellationToken,
        exact_path: Option<&str>,
    ) -> Result<Vec<(Member, ProcessedDocument)>> {
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut result = Vec::new();
        let mut offset = 0;
        let mut bytes = 0;
        loop {
            check(deadline, cancel)?;
            let members = match exact_path {
                Some(path) if offset == 0 => self
                    .corpus
                    .member(snapshot, path)
                    .await?
                    .into_iter()
                    .collect(),
                Some(_) => Vec::new(),
                None => self.corpus.members(snapshot, offset, 1000).await?,
            };
            if members.is_empty() {
                break;
            }
            offset += members.len();
            if offset > MAX_SCAN {
                return Err(Error::capacity(
                    "WHATWG snapshot membership bound exceeded.",
                ));
            }
            for member in members {
                check(deadline, cancel)?;
                if member.projection.is_none() {
                    continue;
                }
                if let Some(value) = self.corpus.projection(snapshot, &member.path).await? {
                    let document: ProcessedDocument = retained(value)?;
                    bytes += document.text.len();
                    if bytes > MAX_OUTPUT {
                        return Err(Error::capacity("WHATWG research text budget exceeded."));
                    }
                    result.push((member, document));
                }
            }
        }
        Ok(result)
    }
    async fn get(&self, input: GetInput, cancel: CancellationToken) -> Result<Value> {
        if !matches!(input.representation.as_str(), "text" | "source" | "bytes") {
            return Err(Error::invalid(
                "WHATWG representation must be text, source or bytes.",
            ));
        }
        if input.section_index.is_some()
            && (input.path.is_none() || input.anchor.is_some() || input.representation != "text")
        {
            return Err(Error::invalid(
                "A WHATWG section index requires a path and projected text, without an anchor selector.",
            ));
        }
        let (selected_view, mut selected_snapshots) = self
            .selections(&Selector {
                standard: Some(input.standard.clone()),
                snapshot: input.snapshot.clone(),
                view: input.view.clone(),
            })
            .await?;
        let snapshot = selected_snapshots
            .pop()
            .ok_or_else(|| Error::unavailable("WHATWG selected evidence is unavailable."))?;
        let path = if let Some(path) = input.path {
            path
        } else {
            let members = self.corpus.members(&snapshot, 0, 1000).await?;
            let candidates: Vec<_> = members.iter().filter(|m| m.projection.is_some()).collect();
            let preferred = candidates.iter().find(|m| {
                m.path == "publication.html"
                    || m.path == "index.html"
                    || m.path == "index.bs"
                    || m.path == "source"
            });
            preferred
                .or_else(|| {
                    if candidates.len() == 1 {
                        candidates.first()
                    } else {
                        None
                    }
                })
                .map(|m| m.path.clone())
                .ok_or_else(|| {
                    Error::invalid(
                        "Select an explicit WHATWG source path from search or snapshot discovery.",
                    )
                })?
        };
        if !crate::whatwg::inventory::valid_path(&path) {
            return Err(Error::invalid("Invalid WHATWG member path."));
        }
        let member = self.corpus.member(&snapshot, &path).await?.ok_or_else(|| {
            Error::not_found("WHATWG member is absent from the selected snapshot.")
        })?;
        let mut section_index = input.section_index;
        let mut symbol_index = None;
        let mut selected_anchor = input.anchor.clone();
        let page = if input.representation == "bytes" || input.representation == "source" {
            if input.anchor.is_some() {
                return Err(Error::invalid("Anchors apply to projected WHATWG text."));
            }
            let raw = self
                .corpus
                .raw_page(&snapshot, &path, input.offset as u64, input.limit)
                .await?;
            if input.representation == "bytes" {
                raw
            } else {
                let bytes = STANDARD
                    .decode(
                        raw["base64"]
                            .as_str()
                            .ok_or_else(|| Error::integrity("WHATWG raw page is missing bytes."))?,
                    )
                    .map_err(|_| Error::integrity("Invalid WHATWG raw page encoding."))?;
                let text = match std::str::from_utf8(&bytes) {
                    Ok(text) => text,
                    Err(error) if error.error_len().is_none() && error.valid_up_to() > 0 => {
                        std::str::from_utf8(&bytes[..error.valid_up_to()])
                            .map_err(|_| Error::integrity("Invalid WHATWG source page."))?
                    }
                    Err(_) => {
                        return Err(Error::invalid(
                            "Source offset must be a UTF-8 boundary and limit must fit a character; binary source uses representation=bytes.",
                        ));
                    }
                };
                let next = input.offset + text.len();
                json!({"text":text,"offset":raw["offset"],"next_offset":if Some(next as u64)<raw["total_bytes"].as_u64(){Some(next)}else{None},"total_bytes":raw["total_bytes"],"body_hash":raw["body_hash"]})
            }
        } else {
            check(Instant::now() + Duration::from_secs(15), &cancel)?;
            let doc: ProcessedDocument = retained(
                self.corpus
                    .projection(&snapshot, &path)
                    .await?
                    .ok_or_else(|| {
                        Error::unavailable(
                            "WHATWG projection is unavailable; raw evidence remains readable.",
                        )
                    })?,
            )?;
            let text = if let Some(index) = input.section_index {
                let section = doc.sections.get(index).ok_or_else(|| {
                    Error::not_found("WHATWG section index is absent from the selected document.")
                })?;
                selected_anchor = Some(section.anchor.clone());
                section.text.as_str()
            } else if let Some(anchor) = &input.anchor {
                let matches: Vec<_> = doc
                    .sections
                    .iter()
                    .enumerate()
                    .filter(|(_, s)| &s.anchor == anchor)
                    .collect();
                if matches.len() == 1 {
                    section_index = Some(matches[0].0);
                    matches[0].1.text.as_str()
                } else {
                    let symbols: Vec<_> = doc
                        .symbols
                        .iter()
                        .enumerate()
                        .filter(|(_, s)| &s.anchor == anchor)
                        .collect();
                    if !matches.is_empty() || symbols.len() != 1 {
                        return Err(Error::invalid(
                            "WHATWG anchor is absent or ambiguous in this representation.",
                        ));
                    }
                    symbol_index = Some(symbols[0].0);
                    symbols[0].1.text.as_str()
                }
            } else {
                doc.text.as_str()
            };
            let mut result = text_page(text, input.offset, input.limit)?;
            result["processing_gaps"] = json!(doc.gaps);
            result
        };
        Ok(
            json!({"selection":public_selection(&snapshot,input.snapshot.is_some()||input.view.is_some(),selected_view.as_ref()),"path":path,"anchor":selected_anchor,"section_index":section_index,"symbol_index":symbol_index,"representation":input.representation,"page":page,
            "resource_uri":if let Some(index)=symbol_index {symbol_resource(&snapshot,&path,index)} else {resource(&snapshot,&input.representation,&path,section_index)},"license":source_license(&snapshot),"gaps":member.gaps,"citation":{"source_url":snapshot.source_url,"revision":snapshot.revision,"path":path,"object_hash":member.oid,"projection":member.projection,"notices":"Original versioned repository and publication notices apply."}}),
        )
    }
    async fn search(&self, input: SearchInput, cancel: CancellationToken) -> Result<Value> {
        let selector = Selector {
            standard: input.standard.clone(),
            snapshot: input.snapshot.clone(),
            view: input.view.clone(),
        };
        let (view, snapshots) = self.selections(&selector).await?;
        let mut members = BTreeSet::new();
        for snapshot in &snapshots {
            members.extend(self.corpus.search_members(snapshot).await?);
        }
        let reference = if let Some(view) = &view {
            view.index.clone()
        } else {
            snapshots
                .first()
                .ok_or_else(|| Error::unavailable("WHATWG snapshot is unavailable."))?
                .index
                .clone()
        };
        let identity = view
            .as_ref()
            .map(|v| v.id.clone())
            .or_else(|| snapshots.first().map(|s| s.id.clone()));
        let mut filters = BTreeMap::new();
        for (key, value) in [
            ("standard", input.standard),
            ("edition", input.edition),
            ("path", input.path),
            ("kind", input.kind),
        ] {
            if let Some(value) = value {
                filters.insert(key.to_owned(), value);
            }
        }
        let spec = crate::whatwg::index::SearchSpec {
            query: input.query,
            snapshot: identity.clone(),
            mode: input.mode,
            filters,
            offset: input.offset,
            limit: input.limit,
            cursor: input.cursor,
        };
        let mut result = self
            .corpus
            .index()
            .search(&reference, members, spec, cancel)
            .await?;
        result["view"] = json!(view.as_ref().map(|v| &v.id));
        result["selections"] = json!(
            snapshots
                .iter()
                .map(|s| public_selection(
                    s,
                    selector.snapshot.is_some() || selector.view.is_some(),
                    view.as_ref()
                ))
                .collect::<Vec<_>>()
        );
        Ok(result)
    }
    async fn symbol_get(&self, input: SymbolGetInput, cancel: CancellationToken) -> Result<Value> {
        if input.name.is_none() && input.anchor.is_none() && input.symbol_index.is_none() {
            return Err(Error::invalid(
                "Select a WHATWG symbol name, anchor or document-local index.",
            ));
        }
        if input.symbol_index.is_some() && input.path.is_none() {
            return Err(Error::invalid(
                "A WHATWG symbol index requires an explicit document path.",
            ));
        }
        let (selected_view, mut selected_snapshots) = self
            .selections(&Selector {
                standard: Some(input.standard.clone()),
                snapshot: input.snapshot.clone(),
                view: input.view.clone(),
            })
            .await?;
        let snapshot = selected_snapshots
            .pop()
            .ok_or_else(|| Error::unavailable("WHATWG selected evidence is unavailable."))?;
        let mut selected = None;
        for (member, doc) in self
            .documents(&snapshot, &cancel, input.path.as_deref())
            .await?
        {
            if input.path.as_ref().is_some_and(|p| p != &member.path) {
                continue;
            }
            for (symbol_index, symbol) in doc.symbols.into_iter().enumerate() {
                if input
                    .symbol_index
                    .is_some_and(|index| index != symbol_index)
                    || input.kind.as_ref().is_some_and(|k| k != &symbol.kind)
                    || input.name.as_ref().is_some_and(|n| n != &symbol.name)
                    || input.anchor.as_ref().is_some_and(|a| a != &symbol.anchor)
                {
                    continue;
                }
                if selected.is_some() {
                    return Err(Error::invalid(
                        "WHATWG symbol is ambiguous; select path, kind and anchor.",
                    ));
                }
                selected = Some((
                    member.path.clone(),
                    symbol_index,
                    symbol,
                    member.gaps.clone(),
                    doc.gaps.clone(),
                ));
            }
        }
        let (path, symbol_index, symbol, gaps, processing_gaps) = selected.ok_or_else(|| {
            Error::not_found("WHATWG symbol is absent from the selected snapshot.")
        })?;
        Ok(
            json!({"selection":public_selection(&snapshot,input.snapshot.is_some()||input.view.is_some(),selected_view.as_ref()),"path":path,
            "kind":symbol.kind,"name":symbol.name,"anchor":symbol.anchor,"scope":symbol.scope,"symbol_index":symbol_index,"page":text_page(&symbol.text,input.offset,input.limit)?,
            "resource_uri":symbol_resource(&snapshot,&path,symbol_index),"license":source_license(&snapshot),"gaps":gaps,"processing_gaps":processing_gaps}),
        )
    }
    async fn list(&self, tool: &str, input: ListInput, cancel: CancellationToken) -> Result<Value> {
        let deadline = Instant::now() + Duration::from_secs(15);
        if tool == "whatwg.catalog_search" {
            return self.catalog_search(input).await;
        }
        let selector = Selector {
            standard: if tool == "whatwg.references"
                && input.direction.as_deref() == Some("incoming")
                && input.snapshot.is_none()
            {
                None
            } else {
                input.standard.clone()
            },
            snapshot: input.snapshot.clone(),
            view: input.view.clone(),
        };
        if matches!(tool, "whatwg.snapshots" | "whatwg.history") {
            return self.discovery(tool, input, cancel).await;
        }
        let (view, snapshots) = self.selections(&selector).await?;
        let identity = view
            .as_ref()
            .map(|v| &v.id)
            .or_else(|| snapshots.first().map(|s| &s.id));
        let fingerprint = fingerprint(
            &(
                tool,
                identity,
                &input.standard,
                &input.query,
                &input.kind,
                &input.name,
                &input.anchor,
                &input.path,
                &input.direction,
                &input.target,
            ),
            input.cursor.as_deref(),
        )?;
        let start = position(
            &fingerprint,
            input.offset,
            input.cursor.as_deref(),
            input.limit,
        )?;
        let mut items = Vec::new();
        if tool == "whatwg.references"
            && !matches!(
                input.direction.as_deref().unwrap_or("outgoing"),
                "incoming" | "outgoing"
            )
        {
            return Err(Error::invalid(
                "Reference direction must be incoming or outgoing.",
            ));
        }
        for snapshot in &snapshots {
            for (member, doc) in self
                .documents(snapshot, &cancel, input.path.as_deref())
                .await?
            {
                check(deadline, &cancel)?;
                if input.path.as_ref().is_some_and(|path| path != &member.path) {
                    continue;
                }
                if tool == "whatwg.references" {
                    for reference in doc.references {
                        let incoming = input.direction.as_deref() == Some("incoming");
                        if input.anchor.as_ref().is_some_and(|a| {
                            if incoming {
                                reference
                                    .target
                                    .rsplit_once('#')
                                    .is_none_or(|(_, t)| t != a)
                            } else {
                                &reference.source_anchor != a
                            }
                        }) {
                            continue;
                        }
                        if input
                            .target
                            .as_ref()
                            .is_some_and(|t| &reference.target != t)
                        {
                            continue;
                        }
                        let resolved = resolve_reference(&reference.target, snapshot, &snapshots);
                        if incoming
                            && input.standard.as_ref().is_some_and(|standard| {
                                resolved["standard"].as_str() != Some(standard.as_str())
                            })
                        {
                            continue;
                        }
                        let value = json!({"standard":snapshot.standard,"snapshot":snapshot.id,"path":member.path,"reference":reference,"resolution":resolved});
                        if matches_query(&value, input.query.as_deref()) {
                            items.push(value);
                        }
                    }
                } else {
                    for (symbol_index, symbol) in doc.symbols.into_iter().enumerate() {
                        if input.kind.as_ref().is_some_and(|k| &symbol.kind != k)
                            || input.name.as_ref().is_some_and(|n| &symbol.name != n)
                            || input.anchor.as_ref().is_some_and(|a| &symbol.anchor != a)
                        {
                            continue;
                        }
                        let value = json!({"standard":snapshot.standard,"snapshot":snapshot.id,"path":member.path,"symbol_index":symbol_index,"symbol":{"kind":symbol.kind,"name":symbol.name,"anchor":symbol.anchor,"scope":symbol.scope,"text_bytes":symbol.text.len()},"resource_uri":symbol_resource(snapshot,&member.path,symbol_index)});
                        if matches_query(&value, input.query.as_deref()) {
                            items.push(value);
                        }
                    }
                }
                if items.len() > MAX_SCAN
                    || serde_json::to_vec(&items)
                        .map_err(|_| Error::integrity("Invalid WHATWG result."))?
                        .len()
                        > MAX_OUTPUT
                {
                    return Err(Error::capacity(
                        "WHATWG result enumeration exceeds its bound.",
                    ));
                }
            }
        }
        items.sort_by_key(Value::to_string);
        let mut result = page(items, fingerprint, start, input.limit)?;
        result["view"] = json!(view.as_ref().map(|v| &v.id));
        result["selections"] = json!(
            snapshots
                .iter()
                .map(|s| public_selection(
                    s,
                    selector.snapshot.is_some() || selector.view.is_some(),
                    view.as_ref()
                ))
                .collect::<Vec<_>>()
        );
        Ok(result)
    }
    async fn catalog_search(&self, input: ListInput) -> Result<Value> {
        if input.snapshot.is_some() {
            return Err(Error::invalid(
                "Catalog research accepts an immutable view, not a document snapshot.",
            ));
        }
        let view = if let Some(id) = input.view.as_deref() {
            Some(self.corpus.view(Some(id)).await?)
        } else {
            self.corpus.view(None).await.ok()
        };
        let catalog = if let Some(view) = &view {
            retained::<Catalog>(
                self.corpus
                    .store()
                    .whatwg_get("catalogs", &view.catalog)
                    .await?
                    .ok_or_else(|| Error::integrity("WHATWG catalog missing."))?
                    .data,
            )?
        } else {
            self.corpus.catalog().await?
        };
        if input.view.is_none()
            && devres_domain::unix_now().saturating_sub(catalog.observed_at) > 7 * 86400
        {
            return Err(Error::unavailable(
                "WHATWG default catalog is older than seven days.",
            ));
        }
        let fingerprint = fingerprint(
            &("catalog", &catalog.id, &input.standard, &input.query),
            input.cursor.as_deref(),
        )?;
        let start = position(
            &fingerprint,
            input.offset,
            input.cursor.as_deref(),
            input.limit,
        )?;
        let mut items = Vec::new();
        for standard in catalog.standards {
            if input.standard.as_ref().is_some_and(|s| s != &standard.id) {
                continue;
            }
            let value = json!({"standard":standard,"snapshot":view.as_ref().and_then(|v|v.snapshots.get(&standard.id)),"validated_at":view.as_ref().and_then(|v|v.validations.get(&standard.id))});
            if matches_query(&value, input.query.as_deref()) {
                items.push(value);
            }
        }
        let mut result = page(items, fingerprint, start, input.limit)?;
        result["catalog"] = json!(catalog.id);
        result["view"] = json!(view.as_ref().map(|v| &v.id));
        result["catalog_gaps"] = json!(catalog.gaps);
        Ok(result)
    }
    async fn discovery(
        &self,
        tool: &str,
        input: ListInput,
        cancel: CancellationToken,
    ) -> Result<Value> {
        if input.history_type.as_deref() == Some("refs") {
            if tool != "whatwg.history" {
                return Err(Error::invalid("Ref observations belong to whatwg.history."));
            }
            return self.ref_history(input, cancel).await;
        }
        if input.reference.is_some() {
            return Err(Error::invalid(
                "Git ref filtering requires history_type=refs.",
            ));
        }
        if input
            .history_type
            .as_ref()
            .is_some_and(|kind| kind != "revisions")
        {
            return Err(Error::invalid(
                "WHATWG history_type must be revisions or refs.",
            ));
        }
        if !(1..=100).contains(&input.limit)
            || input.offset > 10_000
            || input.cursor.as_ref().is_some_and(|c| c.len() > 16384)
        {
            return Err(Error::invalid("Invalid WHATWG discovery page."));
        }
        let cursor: Option<HistoryCursor> = input
            .cursor
            .as_ref()
            .map(|c| {
                serde_json::from_slice(
                    &URL_SAFE_NO_PAD
                        .decode(c)
                        .map_err(|_| Error::invalid("Invalid WHATWG history cursor."))?,
                )
                .map_err(|_| Error::invalid("Invalid WHATWG history cursor."))
            })
            .transpose()?;
        let cutoff = match (&cursor, input.history_snapshot) {
            (Some(c), Some(cutoff)) if c.cutoff != cutoff => {
                return Err(Error::invalid(
                    "WHATWG history cutoff differs from the cursor.",
                ));
            }
            (Some(c), _) => c.cutoff,
            (_, Some(cutoff)) => cutoff,
            _ => self.corpus.store().whatwg_cutoff().await?,
        };
        if cutoff < 0 || cutoff > self.corpus.store().whatwg_cutoff().await? {
            return Err(Error::invalid("Invalid WHATWG history cutoff."));
        }
        let fingerprint = fingerprint(
            &(
                tool,
                cutoff,
                &input.standard,
                &input.repository,
                &input.query,
                &input.path,
            ),
            input.cursor.as_deref(),
        )?;
        let mut after = if let Some(c) = &cursor {
            if c.skip > 10_000
                || c.fingerprint != fingerprint
                || c.after < 0
                || c.after > cutoff
                || input.offset != 0
            {
                return Err(Error::invalid(
                    "WHATWG history cursor does not match this query.",
                ));
            }
            c.after
        } else {
            0
        };
        let mut skip = cursor.as_ref().map_or(input.offset, |c| c.skip);
        let mut items = Vec::new();
        let mut scanned = 0;
        let deadline = Instant::now() + Duration::from_secs(15);
        while items.len() < input.limit && scanned < 500 {
            check(deadline, &cancel)?;
            let rows = self
                .corpus
                .store()
                .whatwg_rows("snapshots", after, 100, Some(cutoff))
                .await?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                after = row.sequence;
                scanned += 1;
                let snapshot: Snapshot = retained(row.data)?;
                if input
                    .repository
                    .as_ref()
                    .is_some_and(|repository| repository != &snapshot.repository)
                {
                    continue;
                }
                if input
                    .standard
                    .as_ref()
                    .is_some_and(|s| s != &snapshot.standard)
                {
                    continue;
                }
                let mut value = public_snapshot(&snapshot, true);
                value["parents"] = json!(snapshot.parents);
                value["committed_at"] = if snapshot.representation == "source" {
                    json!(snapshot.committed_at)
                } else {
                    Value::Null
                };
                if snapshot.representation != "source" {
                    value["observed_at"] = json!(snapshot.committed_at);
                }
                value["inventory"] = json!(snapshot.inventory);
                if !matches_query(&value, input.query.as_deref()) {
                    continue;
                }
                if skip > 0 {
                    skip -= 1;
                    continue;
                }
                if tool == "whatwg.history" {
                    if snapshot.parents.len() > 100 {
                        return Err(Error::capacity("WHATWG history parent bound exceeded."));
                    }
                    let mut changes = Vec::new();
                    for parent in &snapshot.parents {
                        check(deadline, &cancel)?;
                        let previous = self
                            .parent_snapshot(&snapshot, parent, cutoff, &cancel)
                            .await?;
                        let change = if let Some(previous) = previous {
                            self.member_changes(
                                &previous,
                                &snapshot,
                                input.path.as_deref(),
                                &cancel,
                            )
                            .await?
                        } else {
                            json!({"coverage":"parent_snapshot_unavailable"})
                        };
                        changes.push(json!({"parent":parent,"changes":change}));
                    }
                    value["parent_changes"] = json!(changes);
                }
                items.push(value);
                if items.len() == input.limit || scanned >= 500 {
                    break;
                }
            }
        }
        let more = !self
            .corpus
            .store()
            .whatwg_rows("snapshots", after, 1, Some(cutoff))
            .await?
            .is_empty();
        let next = if more {
            Some(
                URL_SAFE_NO_PAD.encode(
                    serde_json::to_vec(&HistoryCursor {
                        version: if fingerprint.starts_with("blake3:") {
                            2
                        } else {
                            0
                        },
                        fingerprint,
                        after,
                        cutoff,
                        skip,
                    })
                    .map_err(|_| Error::integrity("Invalid WHATWG history cursor."))?,
                ),
            )
        } else {
            None
        };
        Ok(json!({"items":items,"history_snapshot":cutoff,"next_cursor":next,"scanned":scanned}))
    }
    async fn ref_history(&self, input: ListInput, cancel: CancellationToken) -> Result<Value> {
        if input.standard.is_some() {
            return Err(Error::invalid(
                "Select ref observations by repository; standard mappings can change historically.",
            ));
        }
        if input.path.is_some() {
            return Err(Error::invalid(
                "Git ref observations have no document path filter.",
            ));
        }
        if !(1..=100).contains(&input.limit)
            || input.offset > 10_000
            || input.cursor.as_ref().is_some_and(|c| c.len() > 16384)
        {
            return Err(Error::invalid("Invalid WHATWG ref page."));
        }
        let cursor: Option<RefHistoryCursor> = input
            .cursor
            .as_ref()
            .map(|c| {
                serde_json::from_slice(
                    &URL_SAFE_NO_PAD
                        .decode(c)
                        .map_err(|_| Error::invalid("Invalid WHATWG ref cursor."))?,
                )
                .map_err(|_| Error::invalid("Invalid WHATWG ref cursor."))
            })
            .transpose()?;
        let cutoff = match (&cursor, input.history_snapshot) {
            (Some(c), Some(cutoff)) if cutoff != c.cutoff => {
                return Err(Error::invalid("WHATWG ref cutoff differs from the cursor."));
            }
            (Some(c), _) => c.cutoff,
            (_, Some(cutoff)) => cutoff,
            _ => self.corpus.store().whatwg_cutoff().await?,
        };
        if cutoff < 0 || cutoff > self.corpus.store().whatwg_cutoff().await? {
            return Err(Error::invalid("Invalid WHATWG history cutoff."));
        }
        let fingerprint = fingerprint(
            &(
                "refs",
                cutoff,
                &input.repository,
                &input.reference,
                &input.query,
            ),
            input.cursor.as_deref(),
        )?;
        if let Some(c) = &cursor
            && (c.fingerprint != fingerprint
                || c.after < 0
                || c.after > cutoff
                || c.entry > 10_000
                || c.skip > 10_000
                || input.offset != 0)
        {
            return Err(Error::invalid(
                "WHATWG ref cursor does not match the query.",
            ));
        }
        let mut after = cursor.as_ref().map_or(0, |c| c.after);
        let mut entry = cursor.as_ref().map_or(0, |c| c.entry);
        let mut skip = cursor.as_ref().map_or(input.offset, |c| c.skip);
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut scanned = 0;
        let mut items = Vec::new();
        'scan: while items.len() < input.limit && scanned < 500 {
            check(deadline, &cancel)?;
            let rows = self
                .corpus
                .store()
                .whatwg_rows("observations", after, 4, Some(cutoff))
                .await?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                scanned += 1;
                check(deadline, &cancel)?;
                let observation: crate::whatwg::git::Observation = retained(row.data)?;
                let repository = observation.repo.as_str();
                if input
                    .repository
                    .as_ref()
                    .is_some_and(|repo| repo != &repository)
                {
                    after = row.sequence;
                    entry = 0;
                    continue;
                }
                for (i, reference) in observation.refs.iter().enumerate().skip(entry) {
                    check(deadline, &cancel)?;
                    if i + 1 < observation.refs.len() {
                        after = row.sequence - 1;
                        entry = i + 1;
                    } else {
                        after = row.sequence;
                        entry = 0;
                    }
                    if input
                        .reference
                        .as_ref()
                        .is_some_and(|name| name != &reference.name)
                    {
                        continue;
                    }
                    let item = json!({"observation":row.key,"sequence":row.sequence,"repository":repository,"observed_at":observation.observed_at,"ref":reference,"current_ref":observation.current_ref,"manifest":observation.manifest.body_hash,"retained_roots":observation.roots.len()});
                    if !matches_query(&item, input.query.as_deref()) {
                        continue;
                    }
                    if skip > 0 {
                        skip -= 1;
                        continue;
                    }
                    items.push(item);
                    if items.len() == input.limit {
                        break 'scan;
                    }
                }
                after = row.sequence;
                entry = 0;
                if scanned >= 500 {
                    break 'scan;
                }
            }
        }
        let more = entry > 0
            || !self
                .corpus
                .store()
                .whatwg_rows("observations", after, 1, Some(cutoff))
                .await?
                .is_empty();
        let next = if more {
            Some(
                URL_SAFE_NO_PAD.encode(
                    serde_json::to_vec(&RefHistoryCursor {
                        version: if fingerprint.starts_with("blake3:") {
                            2
                        } else {
                            0
                        },
                        fingerprint,
                        after,
                        entry,
                        cutoff,
                        skip,
                    })
                    .map_err(|_| Error::integrity("Invalid WHATWG ref cursor."))?,
                ),
            )
        } else {
            None
        };
        Ok(
            json!({"history_type":"refs","history_snapshot":cutoff,"items":items,"next_cursor":next,"scanned":scanned,"coverage":"Observed advertised refs only; earlier observations retain deleted refs."}),
        )
    }
    async fn parent_snapshot(
        &self,
        selected: &Snapshot,
        revision: &str,
        cutoff: i64,
        cancel: &CancellationToken,
    ) -> Result<Option<Snapshot>> {
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut after = 0;
        let mut found = None;
        loop {
            check(deadline, cancel)?;
            let rows = self
                .corpus
                .store()
                .whatwg_rows("snapshots", after, 100, Some(cutoff))
                .await?;
            if rows.is_empty() {
                return Ok(found);
            }
            for row in rows {
                check(deadline, cancel)?;
                after = row.sequence;
                let candidate: Snapshot = retained(row.data)?;
                if candidate.standard == selected.standard
                    && candidate.repository == selected.repository
                    && candidate.revision == revision
                    && candidate.representation == selected.representation
                    && candidate.processor_version == selected.processor_version
                    && candidate.id.starts_with("blake3:") == selected.id.starts_with("blake3:")
                {
                    found = Some(candidate);
                }
            }
        }
    }
    async fn member_changes(
        &self,
        before: &Snapshot,
        after: &Snapshot,
        path: Option<&str>,
        cancel: &CancellationToken,
    ) -> Result<Value> {
        let left = self.member_map(before, cancel).await?;
        let right = self.member_map(after, cancel).await?;
        let mut changes = Vec::new();
        for key in left.keys().chain(right.keys()).collect::<BTreeSet<_>>() {
            if path.is_some_and(|p| p != key) {
                continue;
            }
            let old = left.get(key);
            let new = right.get(key);
            if old != new {
                changes.push(json!({"path":key,"change":if old.is_none(){"added"}else if new.is_none(){"removed"}else{"changed"},"before":old,"after":new}));
            }
            if changes.len() > 1000 {
                return Err(Error::capacity(
                    "WHATWG comparison exceeds its change bound; select a path.",
                ));
            }
        }
        Ok(json!(changes))
    }
    async fn member_map(
        &self,
        snapshot: &Snapshot,
        cancel: &CancellationToken,
    ) -> Result<BTreeMap<String, String>> {
        let mut result = BTreeMap::new();
        let mut offset = 0;
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            check(deadline, cancel)?;
            let rows = self.corpus.members(snapshot, offset, 1000).await?;
            if rows.is_empty() {
                break;
            }
            offset += rows.len();
            if offset > MAX_SCAN {
                return Err(Error::capacity(
                    "WHATWG comparison membership bound exceeded.",
                ));
            }
            for row in rows {
                result.insert(comparison_path(snapshot, &row.path), row.oid);
            }
        }
        Ok(result)
    }
    async fn compare(&self, mut input: CompareInput, cancel: CancellationToken) -> Result<Value> {
        let before = self
            .corpus
            .select(&input.standard, Some(&input.before), None)
            .await?;
        let after = self
            .corpus
            .select(&input.standard, Some(&input.after), None)
            .await?;
        if before.representation != after.representation {
            return Err(Error::invalid(
                "WHATWG comparisons require the same standard and representation family.",
            ));
        }
        if before.representation != "source"
            && let Some(path) = input.path.clone()
            && (self.corpus.member(&before, &path).await?.is_some()
                || self.corpus.member(&after, &path).await?.is_some())
        {
            input.path = Some(comparison_path(&before, &path));
        }
        if !matches!(input.mode.as_str(), "text" | "symbols" | "source") {
            return Err(Error::invalid(
                "WHATWG comparison mode must be text, symbols or source.",
            ));
        }
        if input.mode == "source" && input.anchor.is_some() {
            return Err(Error::invalid(
                "Source comparisons select a path; anchors apply to projected text or symbols.",
            ));
        }
        if input.mode != "source" {
            self.compare_coverage(&before, &after, input.path.as_deref(), &cancel)
                .await?;
        }
        let fingerprint = fingerprint(
            &(
                &before.id,
                &after.id,
                &input.mode,
                &input.anchor,
                &input.path,
            ),
            input.cursor.as_deref(),
        )?;
        let start = position(
            &fingerprint,
            input.offset,
            input.cursor.as_deref(),
            input.limit,
        )?;
        let changes = if input.mode == "source" {
            retained::<Vec<Value>>(
                self.member_changes(&before, &after, input.path.as_deref(), &cancel)
                    .await?,
            )?
        } else {
            let left = self.comparable(&before, &input, &cancel).await?;
            let right = self.comparable(&after, &input, &cancel).await?;
            let mut result = Vec::new();
            for key in left.keys().chain(right.keys()).collect::<BTreeSet<_>>() {
                let a = left.get(key);
                let b = right.get(key);
                if a != b {
                    result.push(json!({"identity":key,"change":if a.is_none(){"added"}else if b.is_none(){"removed"}else{"changed"},"before_hash":a.map(digest).transpose()?,"after_hash":b.map(digest).transpose()?}));
                }
            }
            result
        };
        let mut result = page(changes, fingerprint, start, input.limit)?;
        result["before"] = public_snapshot(&before, true);
        result["after"] = public_snapshot(&after, true);
        result["mode"] = json!(input.mode);
        result["interpretation"] =
            json!("Observed representation changes; no normative or compatibility verdict.");
        Ok(result)
    }
    async fn compare_coverage(
        &self,
        before: &Snapshot,
        after: &Snapshot,
        path: Option<&str>,
        cancel: &CancellationToken,
    ) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut sides = Vec::new();
        for snapshot in [before, after] {
            let mut members = BTreeMap::new();
            let mut offset = 0;
            loop {
                check(deadline, cancel)?;
                let rows = self.corpus.members(snapshot, offset, 1000).await?;
                if rows.is_empty() {
                    break;
                }
                offset += rows.len();
                if offset > MAX_SCAN {
                    return Err(Error::capacity(
                        "WHATWG comparison membership exceeds its bound.",
                    ));
                }
                for member in rows {
                    let logical_path = comparison_path(snapshot, &member.path);
                    if path.is_none_or(|path| path == member.path || path == logical_path) {
                        members.insert(logical_path, member.projection.is_some());
                    }
                }
            }
            sides.push(members);
        }
        for key in sides[0]
            .keys()
            .chain(sides[1].keys())
            .collect::<BTreeSet<_>>()
        {
            let a = sides[0].get(key);
            let b = sides[1].get(key);
            if (path.is_some() && (a == Some(&false) || b == Some(&false)))
                || (a.is_some() && b.is_some() && a != b)
            {
                return Err(Error::unavailable(
                    "Selected WHATWG comparison has an unprocessed side; use original-source comparison or a qualified path.",
                ));
            }
        }
        Ok(())
    }
    async fn comparable(
        &self,
        snapshot: &Snapshot,
        input: &CompareInput,
        cancel: &CancellationToken,
    ) -> Result<BTreeMap<String, Vec<String>>> {
        let mut result: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (member, doc) in self.documents(snapshot, cancel, None).await? {
            let logical_path = comparison_path(snapshot, &member.path);
            if input
                .path
                .as_ref()
                .is_some_and(|p| p != &member.path && p != &logical_path)
            {
                continue;
            }
            if input.mode == "symbols" {
                for symbol in doc.symbols {
                    if input.anchor.as_ref().is_none_or(|a| a == &symbol.anchor) {
                        result
                            .entry(format!(
                                "{}#{}:{}:{}",
                                logical_path, symbol.anchor, symbol.kind, symbol.name
                            ))
                            .or_default()
                            .push(symbol.text);
                    }
                }
            } else {
                for section in doc.sections {
                    if input.anchor.as_ref().is_none_or(|a| a == &section.anchor) {
                        result
                            .entry(format!("{}#{}", logical_path, section.anchor))
                            .or_default()
                            .push(section.text);
                    }
                }
            }
        }
        Ok(result)
    }
    pub async fn read_resource(&self, uri: &str) -> Result<Value> {
        let url =
            url::Url::parse(uri).map_err(|_| Error::invalid("Invalid WHATWG resource URI."))?;
        if url.scheme() != "devres"
            || url.host_str() != Some("whatwg")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.port().is_some()
            || url.fragment().is_some()
        {
            return Err(Error::invalid("Invalid WHATWG resource URI."));
        }
        let parts: Vec<_> = url.path().trim_start_matches('/').split('/').collect();
        if parts.len() != 4 || !valid_hash(parts[1]) {
            return Err(Error::invalid(
                "WHATWG resources bind standard, snapshot, representation and encoded path.",
            ));
        }
        let path = String::from_utf8(
            URL_SAFE_NO_PAD
                .decode(parts[3])
                .map_err(|_| Error::invalid("Invalid WHATWG resource path."))?,
        )
        .map_err(|_| Error::invalid("Invalid WHATWG resource path."))?;
        if URL_SAFE_NO_PAD.encode(path.as_bytes()) != parts[3] {
            return Err(Error::invalid("Noncanonical WHATWG resource path."));
        }
        let mut input =
            json!({"standard":parts[0],"snapshot":parts[1],"representation":parts[2],"path":path});
        let mut seen = BTreeSet::new();
        for (key, value) in url.query_pairs() {
            if !seen.insert(key.to_string()) {
                return Err(Error::invalid("Duplicate WHATWG resource option."));
            }
            match key.as_ref() {
                "offset" | "limit" => {
                    input[key.as_ref()] = json!(
                        value
                            .parse::<usize>()
                            .map_err(|_| Error::invalid("Invalid WHATWG resource page."))?
                    );
                }
                "section_index" if parts[2] == "text" => {
                    input["section_index"] = json!(
                        value
                            .parse::<usize>()
                            .map_err(|_| Error::invalid("Invalid WHATWG section index."))?
                    );
                }
                "symbol_index" if parts[2] == "symbol" => {
                    input["symbol_index"] = json!(
                        value
                            .parse::<usize>()
                            .map_err(|_| Error::invalid("Invalid WHATWG symbol index."))?
                    );
                }
                "anchor" => input["anchor"] = json!(value.as_ref()),
                "name" | "kind" if parts[2] == "symbol" => {
                    input[key.as_ref()] = json!(value.as_ref())
                }
                _ => return Err(Error::invalid("Unknown WHATWG resource option.")),
            }
        }
        let output = if parts[2] == "symbol" {
            input.as_object_mut().map(|m| m.remove("representation"));
            self.call("whatwg.symbol_get", input).await?
        } else {
            self.call("whatwg.get", input).await?
        };
        let processing_gaps = output
            .get("processing_gaps")
            .unwrap_or(&output["page"]["processing_gaps"]);
        let metadata = json!({"provenance":output["selection"],"source_url":output["selection"]["source_url"],"source_path":output["path"],"license":output["license"],"gaps":{"member":output["gaps"],"processing":processing_gaps,"coverage":output["selection"]["coverage"]}});
        Ok(if parts[2] == "bytes" {
            json!({"contents":[{"uri":uri,"mimeType":"application/octet-stream","blob":output["page"]["base64"],"_meta":metadata}]})
        } else {
            json!({"contents":[{"uri":uri,"mimeType":"text/plain","text":output["page"]["text"],"_meta":metadata}]})
        })
    }
}
fn matches_query(value: &Value, query: Option<&str>) -> bool {
    query.is_none_or(|q| {
        let text = value.to_string().to_lowercase();
        q.split_whitespace()
            .all(|term| text.contains(&term.to_lowercase()))
    })
}
fn resolve_reference(target: &str, source: &Snapshot, snapshots: &[Snapshot]) -> Value {
    if let Some(anchor) = target.strip_prefix('#') {
        return json!({"standard":source.standard,"snapshot":source.id,"anchor":anchor,"state":"same_document_anchor_unverified"});
    }
    if let Ok(url) = url::Url::parse(target) {
        for snapshot in snapshots {
            if url.host_str() == Some(format!("{}.spec.whatwg.org", snapshot.standard).as_str())
                || (snapshot.standard == "nfc"
                    && url.host_str() == Some("w3c-cg.github.io")
                    && url.path().starts_with("/web-nfc/"))
                || (snapshot.representation != "source"
                    && url::Url::parse(&snapshot.source_url)
                        .is_ok_and(|u| u.host_str() == url.host_str()))
            {
                return json!({"standard":snapshot.standard,"snapshot":snapshot.id,"anchor":url.fragment(),"state":"captured_standard_anchor_unverified"});
            }
        }
    }
    json!({"state":"unresolved_external","target":target})
}
pub fn schemas() -> Vec<Value> {
    let id = json!({"type":"string","minLength":1,"maxLength":256});
    let hash = json!({"type":"string","pattern":"^(blake3:)?[0-9a-f]{64}$"});
    let path = json!({"type":"string","minLength":1,"maxLength":4096});
    let query = json!({"type":"string","minLength":1,"maxLength":256});
    let common = json!({"standard":id,"snapshot":hash,"view":hash,"query":query,"offset":{"type":"integer","minimum":0,"maximum":10000,"default":0},"limit":{"type":"integer","minimum":1,"maximum":100,"default":20},"cursor":{"type":"string","maxLength":16384}});
    let mut tools = Vec::new();
    let mut add = |name: &str, description: &str, properties: Value, required: Vec<&str>| {
        tools.push(json!({"name":name,"description":description,"inputSchema":{"type":"object","properties":properties,"required":required,"additionalProperties":false},"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}}));
    };
    let mut catalog_properties = common.clone();
    if let Some(map) = catalog_properties.as_object_mut() {
        map.remove("snapshot");
    }
    add(
        "whatwg.catalog_search",
        "Search the captured WHATWG standards catalog; publication and processing gaps remain explicit. Select a view for historical catalog evidence.",
        catalog_properties,
        vec![],
    );
    let mut search = common.clone();
    search["mode"] = json!({"enum":["technical","english"],"default":"technical"});
    for key in ["edition", "path", "kind"] {
        search[key] = path.clone();
    }
    add(
        "whatwg.search",
        "Search immutable WHATWG sections using selected-corpus BM25. Defaults use canonical current editions; reuse view/snapshot and cursor.",
        search,
        vec!["query"],
    );
    let get = json!({"standard":id,"snapshot":hash,"view":hash,"path":path,"anchor":path,"section_index":{"type":"integer","minimum":0,"description":"Zero-based position in this captured document's ordered sections; requires path and excludes anchor."},"representation":{"enum":["text","source","bytes"],"default":"text"},"offset":{"type":"integer","minimum":0,"default":0},"limit":{"type":"integer","minimum":1,"maximum":32768,"default":32768}});
    add(
        "whatwg.get",
        "Read capture-fixed specification text, an anchored section, original source, or base64 bytes. Text offsets count UTF-8 bytes.",
        get,
        vec!["standard"],
    );
    for (name, description) in [(
        "whatwg.symbol_search",
        "Search original definitions, Web IDL declarations and explicitly marked algorithms.",
    )] {
        let mut props = common.clone();
        props["kind"] = json!({"enum":["definition","idl","algorithm"]});
        for key in ["name", "anchor", "path"] {
            props[key] = path.clone();
        }
        add(name, description, props, vec![]);
    }
    let symbol_get = json!({"standard":id,"snapshot":hash,"view":hash,"path":path,"symbol_index":{"type":"integer","minimum":0,"description":"Zero-based position in this captured document's ordered symbols; requires path and is local to the selected snapshot."},"name":path,"anchor":path,"kind":{"enum":["definition","idl","algorithm"]},"offset":{"type":"integer","minimum":0,"default":0},"limit":{"type":"integer","minimum":1,"maximum":32768,"default":32768}});
    add(
        "whatwg.symbol_get",
        "Read one unambiguous captured symbol in bounded UTF-8 pages with original text and provenance.",
        symbol_get,
        vec!["standard"],
    );
    let mut refs = common.clone();
    refs["direction"] = json!({"enum":["incoming","outgoing"],"default":"outgoing"});
    for key in ["target", "anchor", "path"] {
        refs[key] = path.clone();
    }
    add(
        "whatwg.references",
        "Inspect captured incoming/outgoing links. Target resolution uses selected evidence only; external references are never fetched.",
        refs,
        vec![],
    );
    for (name, description) in [
        (
            "whatwg.snapshots",
            "Discover immutable source/publication snapshots with a frozen history cutoff.",
        ),
        (
            "whatwg.history",
            "Inspect retained revisions and changes against each ordered parent; missing parent projections remain explicit.",
        ),
    ] {
        let mut props = common.clone();
        props["history_snapshot"] = json!({"type":"integer","minimum":0});
        props["path"] = path.clone();
        if name == "whatwg.history" {
            props["history_type"] = json!({"enum":["revisions","refs"],"default":"revisions"});
            props["repository"] = json!({"type":"string","minLength":1,"maxLength":256});
            props["ref"] = json!({"type":"string","minLength":1,"maxLength":1024});
        }
        if let Some(m) = props.as_object_mut() {
            m.remove("snapshot");
            m.remove("view");
        }
        add(name, description, props, vec![]);
    }
    let mut compare = common;
    let map = compare.as_object_mut();
    if let Some(map) = map {
        map.remove("snapshot");
        map.remove("view");
        map.remove("query");
    }
    compare["before"] = hash.clone();
    compare["after"] = hash;
    compare["anchor"] = path.clone();
    compare["path"] = path;
    compare["mode"] = json!({"enum":["text","symbols","source"],"default":"text"});
    add(
        "whatwg.compare",
        "Compare two immutable snapshots of the same standard and representation family; no normative verdict is inferred.",
        compare,
        vec!["standard", "before", "after"],
    );
    add(
        "whatwg.corpus_status",
        "Inspect separate WHATWG acquisition, ancestry, projection, indexing and freshness coverage. No collection controls are exposed.",
        json!({}),
        vec![],
    );
    for tool in &mut tools {
        match tool["name"].as_str() {
            Some("whatwg.get") => {
                tool["inputSchema"]["allOf"] = json!([{"if":{"required":["section_index"]},"then":{"required":["path"],"not":{"required":["anchor"]},"properties":{"representation":{"const":"text"}}}}]);
            }
            Some("whatwg.symbol_get") => {
                tool["inputSchema"]["allOf"] =
                    json!([{"if":{"required":["symbol_index"]},"then":{"required":["path"]}}]);
            }
            _ => {}
        }
    }
    tools
}

#[cfg(test)]
#[path = "research/tests.rs"]
mod tests;

#[cfg(test)]
mod cursor_digest_tests {
    use super::*;
    #[test]
    fn cursor_versions_bind_the_original_query_algorithm() {
        let selected = ("history", "frozen-snapshot", "path");
        let bytes = serde_json::to_vec(&selected).expect("query");
        let canonical = fingerprint(&selected, None).expect("new identity");
        assert_eq!(canonical, crate::integrity::hash(&bytes));
        let old = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "fingerprint":crate::integrity::legacy_hash(&bytes), "position":10
            }))
            .expect("old cursor"),
        );
        assert_eq!(
            fingerprint(&selected, Some(&old)).expect("legacy identity"),
            crate::integrity::legacy_hash(&bytes)
        );
        let new = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "version":2, "fingerprint":canonical, "position":10
            }))
            .expect("new cursor"),
        );
        assert_eq!(
            fingerprint(&selected, Some(&new)).expect("new continuation"),
            canonical
        );
        let unknown = URL_SAFE_NO_PAD.encode(br#"{"version":99}"#);
        assert!(fingerprint(&selected, Some(&unknown)).is_err());
    }
}
