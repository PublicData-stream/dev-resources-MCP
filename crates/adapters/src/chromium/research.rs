//! Local, capture-fixed Chromium research. No public operation acquires upstream data.
use crate::{
    chromium::ChromiumCorpus,
    chromium::processing::ProcessedDocument,
    research::{decode, text_page},
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use devres_application::chromium::{Catalog, Component, Member, Snapshot, View};
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
        |_| Error::integrity("Invalid Chromium evidence."),
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
    serde_json::from_value(value)
        .map_err(|_| Error::integrity("Invalid retained Chromium evidence."))
}
fn valid_hash(id: &str) -> bool {
    crate::integrity::valid_hash(id)
}
fn check(deadline: Instant, cancel: &CancellationToken) -> Result<()> {
    if cancel.is_cancelled() {
        return Err(Error::new("cancelled", "Chromium research canceled."));
    }
    if Instant::now() >= deadline {
        return Err(Error::capacity(
            "Chromium research processing bound exceeded.",
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
    component: Option<String>,
    snapshot: Option<String>,
    view: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchInput {
    component: Option<String>,
    snapshot: Option<String>,
    view: Option<String>,
    query: Option<String>,
    representation: Option<String>,
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
    component: String,
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
    component: Option<String>,
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
    component: String,
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
    component: String,
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
    page: usize,
    entry: usize,
    cutoff: i64,
    skip: usize,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogCursor {
    #[serde(default)]
    version: u8,
    fingerprint: String,
    component: usize,
    member_offset: usize,
    skip: usize,
}
fn position(fingerprint: &str, offset: usize, cursor: Option<&str>, limit: usize) -> Result<usize> {
    if !(1..=100).contains(&limit) || offset > 10_000 {
        return Err(Error::invalid(
            "Chromium lists require limit 1..100 and offset at most 10000.",
        ));
    }
    let Some(cursor) = cursor else {
        return Ok(offset);
    };
    if cursor.len() > 16_384 || offset != 0 {
        return Err(Error::invalid("Invalid Chromium cursor continuation."));
    }
    let c: Cursor = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(cursor)
            .map_err(|_| Error::invalid("Invalid Chromium cursor."))?,
    )
    .map_err(|_| Error::invalid("Invalid Chromium cursor."))?;
    if c.fingerprint != fingerprint || c.position > MAX_SCAN {
        return Err(Error::invalid(
            "Chromium cursor does not match the selected evidence and query.",
        ));
    }
    Ok(c.position)
}
fn page(items: Vec<Value>, fingerprint: String, start: usize, limit: usize) -> Result<Value> {
    if start > items.len() {
        return Err(Error::invalid("Chromium page is outside selected results."));
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
                .map_err(|_| Error::integrity("Invalid Chromium cursor encoding."))?,
            ),
        )
    } else {
        None
    };
    Ok(json!({"items":items[start..end],"offset":start,"total":items.len(),"next_cursor":next}))
}
fn public_snapshot(snapshot: &Snapshot, historical: bool) -> Value {
    json!({"snapshot":snapshot.id,"component":snapshot.component,"repository":snapshot.repository,
        "revision":snapshot.revision,"representation":snapshot.representation,"processor_version":snapshot.processor_version,
        "validated_at":snapshot.validated_at,"stale":devres_domain::unix_now().saturating_sub(snapshot.validated_at)>86400,
        "historical":historical,"coverage":snapshot.coverage,"source_url":snapshot.source_url,
        "source_metadata":source_metadata(snapshot),"license":source_license(snapshot),
        "verification":snapshot.coverage["verification"]})
}
fn public_selection(snapshot: &Snapshot, historical: bool, view: Option<&View>) -> Value {
    let mut result = public_snapshot(snapshot, historical);
    if let Some(view) = view {
        let validated = view
            .validations
            .get(&snapshot.component)
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
        "devres://chromium/{}/{}/{representation}/{id}",
        snapshot.component, snapshot.id
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
fn comparison_path(_snapshot: &Snapshot, path: &str) -> String {
    path.to_owned()
}

const DERIVED_NOTICE: &str = "Text, excerpts, indexing and comparisons are derived by dev-resources-MCP from the identified source; this output is not an official Chromium or Chrome publication.";
fn require_content_license(snapshot: &Snapshot) -> Result<()> {
    if snapshot.coverage["license"]["decision"].as_str() != Some("approved") {
        return Err(Error::unavailable(
            "Chromium content license is unresolved or blocked; only catalog metadata is available.",
        ));
    }
    Ok(())
}
fn source_license(snapshot: &Snapshot) -> Value {
    license_metadata(
        snapshot,
        &snapshot.coverage["license"],
        &snapshot.source_url,
    )
}
fn license_metadata(snapshot: &Snapshot, license: &Value, source_url: &str) -> Value {
    json!({"attribution":"Original publication and repository contributors", "evidence":license,
        "notice":"Preserve the original notices in this captured publication or repository revision; no blanket license is inferred.",
        "derived_notice":DERIVED_NOTICE,"source_url":source_url,"revision":snapshot.revision,
        "service_license_applies_to_source":false})
}
fn member_license<'a>(snapshot: &'a Snapshot, member: &'a Member) -> &'a Value {
    static UNRESOLVED: std::sync::LazyLock<Value> = std::sync::LazyLock::new(
        || json!({"decision":"unresolved","gap":"qualified_member_capture_unavailable"}),
    );
    if member.raw.is_none() {
        return &UNRESOLVED;
    }
    member
        .raw
        .as_ref()
        .and_then(|raw| raw.get("license"))
        .unwrap_or(&snapshot.coverage["license"])
}
fn member_source_url<'a>(snapshot: &'a Snapshot, member: &'a Member) -> &'a str {
    member
        .raw
        .as_ref()
        .and_then(|raw| raw.get("source_url"))
        .and_then(Value::as_str)
        .unwrap_or(&snapshot.source_url)
}
fn require_member_license(snapshot: &Snapshot, member: &Member) -> Result<()> {
    if member_license(snapshot, member)["decision"] != "approved" {
        return Err(Error::unavailable(
            "Chromium member license is unresolved or blocked; copied content is unavailable.",
        ));
    }
    Ok(())
}
fn source_metadata(snapshot: &Snapshot) -> Value {
    evidence_metadata(
        snapshot,
        &snapshot.coverage["license"],
        &snapshot.source_url,
    )
}
fn evidence_metadata(snapshot: &Snapshot, license: &Value, source_url: &str) -> Value {
    let status = license["publication_status"]
        .as_str()
        .filter(|status| !status.is_empty())
        .map(|status| json!(status))
        .unwrap_or_else(|| snapshot.coverage["publication_status"].clone());
    json!({"component":snapshot.component,"source_url":source_url,
        "revision":snapshot.revision,"copyright":license["copyright"],
        "publication_status":status,"publication_role":snapshot.coverage["publication_role"],
        "license":license_metadata(snapshot,license,source_url),"derived_notice":DERIVED_NOTICE})
}
fn member_metadata(snapshot: &Snapshot, member: &Member) -> Value {
    let mut metadata = evidence_metadata(
        snapshot,
        member_license(snapshot, member),
        member_source_url(snapshot, member),
    );
    metadata["source_path"] = json!(member.path);
    metadata["object_hash"] = json!(member.oid);
    metadata["publication"] = member
        .raw
        .as_ref()
        .map(|raw| raw["publication"].clone())
        .unwrap_or(Value::Null);
    metadata
}
fn member_citation(snapshot: &Snapshot, member: &Member) -> Value {
    json!({"source_url":member_source_url(snapshot,member),"revision":snapshot.revision,
        "path":member.path,"object_hash":member.oid,"projection":member.projection,
        "publication":member.raw.as_ref().map(|raw|raw["publication"].clone())})
}

fn annotate_output(output: &mut Value) {
    let mut sources = Vec::new();
    for key in ["selection", "before", "after"] {
        if let Some(selection) = output.get(key).filter(|selection| selection.is_object()) {
            sources.push(selection.clone());
        }
    }
    if let Some(selections) = output.get("selections").and_then(Value::as_array) {
        sources.extend(selections.iter().cloned());
    }
    for field in ["items", "results"] {
        if let Some(items) = output.get_mut(field).and_then(Value::as_array_mut) {
            for item in items {
                let selected = sources
                    .iter()
                    .filter(|source| {
                        let snapshot_matches = item
                            .get("snapshot")
                            .and_then(Value::as_str)
                            .is_none_or(|id| source["snapshot"].as_str() == Some(id));
                        let component = item.get("component");
                        let component_matches = component
                            .and_then(Value::as_str)
                            .is_none_or(|id| source["component"].as_str() == Some(id));
                        snapshot_matches && component_matches
                    })
                    .map(|source| source["source_metadata"].clone())
                    .collect::<Vec<_>>();
                let selected = if let Some(metadata) = item.get("source_metadata") {
                    vec![metadata.clone()]
                } else if item.get("before_source").is_some() || item.get("after_source").is_some()
                {
                    ["before_source", "after_source"]
                        .iter()
                        .filter_map(|key| item.get(*key).filter(|value| value.is_object()).cloned())
                        .collect()
                } else {
                    selected
                };
                if item.is_object() && !selected.is_empty() {
                    item["sources"] = json!(selected);
                }
            }
        }
    }
    if let Some(selection) = output.get("selection").cloned() {
        if output.get("source_metadata").is_none() {
            output["source_metadata"] = selection["source_metadata"].clone();
        }
        if output.get("page").is_some_and(Value::is_object) {
            output["page"]["source_metadata"] = output["source_metadata"].clone();
            output["page"]["derived_notice"] = json!(DERIVED_NOTICE);
        }
    }
    output["derived_notice"] = json!(DERIVED_NOTICE);
    if let Some(metadata) = output.get("source_metadata").cloned() {
        output["sources"] = json!([metadata]);
    } else if !sources.is_empty() {
        output["sources"] = json!(
            sources
                .iter()
                .map(|source| &source["source_metadata"])
                .collect::<Vec<_>>()
        );
    }
}

#[derive(Clone)]
struct CapturedTarget {
    component: String,
    snapshot: String,
    path: String,
    anchors: Option<BTreeMap<String, usize>>,
    anchors_loaded: bool,
}
type ReferenceTargets = BTreeMap<String, Option<CapturedTarget>>;
fn decoded_anchor(fragment: &str) -> Option<String> {
    if fragment.len() > 16384 {
        return None;
    }
    let bytes = fragment.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut at = 0;
    let digit = |value: u8| match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    };
    while at < bytes.len() {
        if bytes[at] == b'%' {
            let hi = digit(*bytes.get(at + 1)?)?;
            let lo = digit(*bytes.get(at + 2)?)?;
            decoded.push(hi * 16 + lo);
            at += 3;
        } else {
            decoded.push(bytes[at]);
            at += 1;
        }
    }
    let anchor = String::from_utf8(decoded).ok()?;
    (!anchor.chars().any(char::is_control)).then_some(anchor)
}
fn repository_target(component: &str, path: &str, anchor: Option<&str>) -> Option<url::Url> {
    let mut url = url::Url::parse(&format!(
        "devres://chromium-reference/{component}/{}",
        URL_SAFE_NO_PAD.encode(path.as_bytes())
    ))
    .ok()?;
    url.set_fragment(anchor);
    Some(url)
}
fn reference_url(snapshot: &Snapshot, member: &Member, target: &str) -> Option<url::Url> {
    if snapshot.component != "chrome"
        && let Some((path, anchor)) =
            crate::chromium::processing::resolve_reference(&member.path, target)
    {
        return repository_target(&snapshot.component, &path, anchor.as_deref());
    }
    url::Url::parse(target)
        .or_else(|_| {
            url::Url::parse(member_source_url(snapshot, member)).and_then(|base| base.join(target))
        })
        .ok()
}
fn resolve_member_reference(
    target: &str,
    snapshot: &Snapshot,
    member: &Member,
    targets: &ReferenceTargets,
    source_anchors: &BTreeMap<String, usize>,
) -> Value {
    if let Some(fragment) = target.strip_prefix('#') {
        let Some(anchor) = decoded_anchor(fragment) else {
            return json!({"state":"invalid_captured_anchor","target":target});
        };
        let state = if anchor.is_empty() {
            "captured_document"
        } else {
            match source_anchors.get(&anchor).copied().unwrap_or(0) {
                0 => "unresolved_captured_anchor",
                1 => "captured_anchor",
                _ => "ambiguous_captured_anchor",
            }
        };
        return json!({"component":snapshot.component,"snapshot":snapshot.id,"path":member.path,"anchor":anchor,"state":state});
    }
    let Some(mut url) = reference_url(snapshot, member, target) else {
        return json!({"state":"unresolved_external","target":target});
    };
    let anchor = match url.fragment() {
        Some(fragment) => match decoded_anchor(fragment) {
            Some(anchor) => Some(anchor),
            None => return json!({"state":"invalid_captured_anchor","target":target}),
        },
        None => None,
    };
    url.set_fragment(None);
    match targets.get(url.as_str()) {
        Some(Some(document)) => {
            let state = match anchor.as_deref() {
                None | Some("") => "captured_document",
                Some(anchor) => match &document.anchors {
                    None => "captured_document_projection_unavailable",
                    Some(anchors) => match anchors.get(anchor).copied().unwrap_or(0) {
                        0 => "unresolved_captured_anchor",
                        1 => "captured_anchor",
                        _ => "ambiguous_captured_anchor",
                    },
                },
            };
            json!({"component":document.component,"snapshot":document.snapshot,"path":document.path,"anchor":anchor,"state":state})
        }
        Some(None) => json!({"state":"ambiguous_captured_document","target":target}),
        None => json!({"state":"unresolved_external","target":target}),
    }
}

pub struct ChromiumResearch {
    corpus: Arc<ChromiumCorpus>,
}
impl ChromiumResearch {
    pub fn new(corpus: Arc<ChromiumCorpus>) -> Self {
        Self { corpus }
    }
    pub async fn call(&self, tool: &str, input: Value) -> Result<Value> {
        let historical = input.get("snapshot").and_then(Value::as_str).is_some()
            || input.get("view").and_then(Value::as_str).is_some();
        let cancel = CancellationToken::new();
        let _guard = CancelOnDrop(cancel.clone());
        let mut output = match tool {
            "chromium.corpus_status" => {
                let _: EmptyInput = decode(input)?;
                self.corpus.status().await
            }
            "chromium.get" => self.get(decode(input)?, cancel).await,
            "chromium.search" => self.search(decode(input)?, cancel).await,
            "chromium.symbol_get" => self.symbol_get(decode(input)?, cancel).await,
            "chromium.compare" => self.compare(decode(input)?, cancel).await,
            "chromium.catalog_search"
            | "chromium.symbol_search"
            | "chromium.references"
            | "chromium.snapshots"
            | "chromium.history" => self.list(tool, decode(input)?, cancel).await,
            _ => Err(Error::not_found("Unknown Chromium research tool.")),
        }?;
        if let Some(id) = output
            .get("view")
            .and_then(Value::as_str)
            .or_else(|| output["selection"]["view"].as_str())
            .map(str::to_owned)
        {
            let view = self.corpus.view(Some(&id)).await?;
            let catalog: Catalog = retained(
                self.corpus
                    .store()
                    .chromium_get("catalogs", &view.catalog)
                    .await?
                    .ok_or_else(|| Error::integrity("Chromium selected catalog is missing."))?
                    .data,
            )?;
            if !historical
                && devres_domain::unix_now().saturating_sub(catalog.observed_at) > 7 * 86400
            {
                return Err(Error::unavailable(
                    "Chromium default catalog is older than seven days; select a historical view explicitly.",
                ));
            }
            let missing = catalog
                .components
                .iter()
                .filter(|component| {
                    component.id != "chrome-archive" && !view.snapshots.contains_key(&component.id)
                })
                .map(|component| component.id.clone())
                .collect::<Vec<_>>();
            let expired = if historical {
                Vec::new()
            } else {
                view.validations
                    .iter()
                    .filter(|(_, validated)| {
                        devres_domain::unix_now().saturating_sub(**validated) > 7 * 86400
                    })
                    .map(|(component, _)| component.clone())
                    .collect::<Vec<_>>()
            };
            output["selection_coverage"] = json!({"catalog":catalog.id,
                "catalog_components":catalog.components.len(),"view_components":view.snapshots.len(),
                "missing_components":missing.iter().take(100).collect::<Vec<_>>(),
                "missing_components_total":missing.len(),"missing_components_truncated":missing.len()>100,
                "expired_default_components":expired,"historical_only_components":["chrome-archive"],
                "catalog_validated_at":catalog.observed_at,
                "catalog_stale":devres_domain::unix_now().saturating_sub(catalog.observed_at)>86400,
                "catalog_gaps":catalog.gaps.iter().take(100).collect::<Vec<_>>(),"catalog_gap_count":catalog.gaps.len()});
        }
        annotate_output(&mut output);
        Ok(output)
    }
    async fn selections(&self, selector: &Selector) -> Result<(Option<View>, Vec<Snapshot>)> {
        if let Some(id) = &selector.snapshot {
            if selector.view.is_some() {
                return Err(Error::invalid(
                    "Choose a Chromium view or a document snapshot.",
                ));
            }
            let s = self.corpus.snapshot(id).await?;
            if selector
                .component
                .as_ref()
                .is_some_and(|component| component != &s.component)
            {
                return Err(Error::invalid(
                    "Chromium snapshot belongs to a different component.",
                ));
            }
            require_content_license(&s)?;
            return Ok((None, vec![s]));
        }
        let view = self.corpus.view(selector.view.as_deref()).await?;
        let mut selected = Vec::new();
        for component in view.snapshots.keys() {
            if selector.component.as_ref().is_none_or(|s| s == component) {
                if selector.view.is_none()
                    && devres_domain::unix_now()
                        .saturating_sub(view.validations.get(component).copied().unwrap_or(0))
                        > 7 * 86400
                {
                    if selector.component.is_some() {
                        return Err(Error::unavailable(
                            "Selected Chromium default evidence is older than seven days; select a historical snapshot/view explicitly.",
                        ));
                    }
                    continue;
                }
                let snapshot = self.corpus.select(component, None, Some(&view.id)).await?;
                require_content_license(&snapshot)?;
                selected.push(snapshot);
            }
        }
        if selected.is_empty() {
            return Err(Error::unavailable(
                "Selected Chromium component has no published snapshot.",
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
                    "Chromium snapshot membership bound exceeded.",
                ));
            }
            for member in members {
                check(deadline, cancel)?;
                if member.projection.is_none() {
                    continue;
                }
                require_member_license(snapshot, &member)?;
                if let Some(value) = self.corpus.projection(snapshot, &member.path).await? {
                    let document: ProcessedDocument = retained(value)?;
                    bytes += document.text.len();
                    if bytes > MAX_OUTPUT {
                        return Err(Error::capacity("Chromium research text budget exceeded."));
                    }
                    result.push((member, document));
                }
            }
        }
        Ok(result)
    }
    async fn get(&self, input: GetInput, cancel: CancellationToken) -> Result<Value> {
        if input.path.is_none() {
            return Err(Error::invalid(
                "Chromium retrieval requires an explicit document path.",
            ));
        }
        if !matches!(input.representation.as_str(), "text" | "source" | "bytes") {
            return Err(Error::invalid(
                "Chromium representation must be text, source or bytes.",
            ));
        }
        if input.section_index.is_some()
            && (input.path.is_none() || input.anchor.is_some() || input.representation != "text")
        {
            return Err(Error::invalid(
                "A Chromium section index requires a path and projected text, without an anchor selector.",
            ));
        }
        let (selected_view, mut selected_snapshots) = self
            .selections(&Selector {
                component: Some(input.component.clone()),
                snapshot: input.snapshot.clone(),
                view: input.view.clone(),
            })
            .await?;
        let snapshot = selected_snapshots
            .pop()
            .ok_or_else(|| Error::unavailable("Chromium selected evidence is unavailable."))?;
        let path = if let Some(path) = input.path {
            path
        } else {
            let canonical = if snapshot.representation == "source" {
                None
            } else {
                url::Url::parse(&snapshot.source_url).ok().map(|url| {
                    let path = url.path().trim_start_matches('/');
                    if path.is_empty() || path.ends_with('/') {
                        format!("{path}index.{}", snapshot.representation)
                    } else {
                        path.to_owned()
                    }
                })
            };
            let canonical = if let Some(path) = canonical {
                self.corpus.member(&snapshot, &path).await?.map(|_| path)
            } else {
                None
            };
            if let Some(path) = canonical {
                path
            } else {
                let members = self.corpus.members(&snapshot, 0, 1000).await?;
                let candidates: Vec<_> =
                    members.iter().filter(|m| m.projection.is_some()).collect();
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
                            "Select an explicit Chromium source path from search or snapshot discovery.",
                        )
                    })?
            }
        };
        if !crate::chromium::inventory::valid_path(&path) {
            return Err(Error::invalid("Invalid Chromium member path."));
        }
        let member = self.corpus.member(&snapshot, &path).await?.ok_or_else(|| {
            Error::not_found("Chromium member is absent from the selected snapshot.")
        })?;
        require_member_license(&snapshot, &member)?;
        let mut section_index = input.section_index;
        let mut symbol_index = None;
        let mut selected_anchor = input.anchor.clone();
        let page = if input.representation == "bytes" || input.representation == "source" {
            if input.anchor.is_some() {
                return Err(Error::invalid("Anchors apply to projected Chromium text."));
            }
            let raw = self
                .corpus
                .raw_page(&snapshot, &path, input.offset as u64, input.limit)
                .await?;
            if input.representation == "bytes" {
                raw
            } else {
                let bytes =
                    STANDARD
                        .decode(raw["base64"].as_str().ok_or_else(|| {
                            Error::integrity("Chromium raw page is missing bytes.")
                        })?)
                        .map_err(|_| Error::integrity("Invalid Chromium raw page encoding."))?;
                let text = match std::str::from_utf8(&bytes) {
                    Ok(text) => text,
                    Err(error) if error.error_len().is_none() && error.valid_up_to() > 0 => {
                        std::str::from_utf8(&bytes[..error.valid_up_to()])
                            .map_err(|_| Error::integrity("Invalid Chromium source page."))?
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
                            "Chromium projection is unavailable; raw evidence remains readable.",
                        )
                    })?,
            )?;
            let text = if let Some(index) = input.section_index {
                let section = doc.sections.get(index).ok_or_else(|| {
                    Error::not_found("Chromium section index is absent from the selected document.")
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
                            "Chromium anchor is absent or ambiguous in this representation.",
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
            "resource_uri":if let Some(index)=symbol_index {symbol_resource(&snapshot,&path,index)} else {resource(&snapshot,&input.representation,&path,section_index)},"license":license_metadata(&snapshot,member_license(&snapshot,&member),member_source_url(&snapshot,&member)),"source_metadata":member_metadata(&snapshot,&member),"gaps":member.gaps,"citation":member_citation(&snapshot,&member)}),
        )
    }
    async fn search(&self, input: SearchInput, cancel: CancellationToken) -> Result<Value> {
        let selector = Selector {
            component: input.component.clone(),
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
                .ok_or_else(|| Error::unavailable("Chromium snapshot is unavailable."))?
                .index
                .clone()
        };
        let identity = view
            .as_ref()
            .map(|v| v.id.clone())
            .or_else(|| snapshots.first().map(|s| s.id.clone()));
        let mut filters = BTreeMap::new();
        for (key, value) in [
            ("component", input.component),
            ("edition", input.representation),
            ("path", input.path),
            ("kind", input.kind),
        ] {
            if let Some(value) = value {
                filters.insert(key.to_owned(), value);
            }
        }
        let spec = crate::chromium::index::SearchSpec {
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
        if let Some(hits) = result.get_mut("results").and_then(Value::as_array_mut) {
            for hit in hits {
                let component = hit
                    .get("component")
                    .and_then(Value::as_str)
                    .ok_or_else(|| Error::integrity("Chromium search hit component is missing."))?;
                let snapshot = snapshots
                    .iter()
                    .find(|snapshot| snapshot.component == component)
                    .ok_or_else(|| {
                        Error::integrity("Chromium search hit is outside selected evidence.")
                    })?;
                let path = hit["path"]
                    .as_str()
                    .ok_or_else(|| Error::integrity("Chromium search hit path is missing."))?
                    .to_owned();
                let member = self
                    .corpus
                    .member(snapshot, &path)
                    .await?
                    .ok_or_else(|| Error::integrity("Chromium search hit member is absent."))?;
                require_member_license(snapshot, &member)?;
                hit["source_metadata"] = member_metadata(snapshot, &member);
                hit["license"] = license_metadata(
                    snapshot,
                    member_license(snapshot, &member),
                    member_source_url(snapshot, &member),
                );
                hit["snapshot"] = json!(snapshot.id);
                hit["resource_uri"] = json!(resource(snapshot, "text", &path, None));
                hit["citation"] = member_citation(snapshot, &member);
            }
        }
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
                "Select a Chromium symbol name, anchor or document-local index.",
            ));
        }
        if input.symbol_index.is_some() && input.path.is_none() {
            return Err(Error::invalid(
                "A Chromium symbol index requires an explicit document path.",
            ));
        }
        let (selected_view, mut selected_snapshots) = self
            .selections(&Selector {
                component: Some(input.component.clone()),
                snapshot: input.snapshot.clone(),
                view: input.view.clone(),
            })
            .await?;
        let snapshot = selected_snapshots
            .pop()
            .ok_or_else(|| Error::unavailable("Chromium selected evidence is unavailable."))?;
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
                        "Chromium symbol is ambiguous; select path, kind and anchor.",
                    ));
                }
                selected = Some((
                    member.clone(),
                    symbol_index,
                    symbol,
                    member.gaps.clone(),
                    doc.gaps.clone(),
                ));
            }
        }
        let (member, symbol_index, symbol, gaps, processing_gaps) = selected.ok_or_else(|| {
            Error::not_found("Chromium symbol is absent from the selected snapshot.")
        })?;
        Ok(
            json!({"selection":public_selection(&snapshot,input.snapshot.is_some()||input.view.is_some(),selected_view.as_ref()),"path":member.path,
            "kind":symbol.kind,"name":symbol.name,"anchor":symbol.anchor,"scope":symbol.scope,"symbol_index":symbol_index,"page":text_page(&symbol.text,input.offset,input.limit)?,
            "resource_uri":symbol_resource(&snapshot,&member.path,symbol_index),"license":license_metadata(&snapshot,member_license(&snapshot,&member),member_source_url(&snapshot,&member)),"source_metadata":member_metadata(&snapshot,&member),"gaps":gaps,"processing_gaps":processing_gaps,"citation":member_citation(&snapshot,&member)}),
        )
    }
    async fn reference_targets(
        &self,
        snapshots: &[Snapshot],
        cancel: &CancellationToken,
    ) -> Result<ReferenceTargets> {
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut targets = ReferenceTargets::new();
        let mut scanned = 0usize;
        let mut bytes = 0usize;
        for snapshot in snapshots {
            let mut offset = 0;
            loop {
                check(deadline, cancel)?;
                let members = self.corpus.members(snapshot, offset, 1000).await?;
                if members.is_empty() {
                    break;
                }
                offset += members.len();
                scanned = scanned
                    .checked_add(members.len())
                    .filter(|n| *n <= MAX_SCAN)
                    .ok_or_else(|| {
                        Error::capacity("Chromium reference membership exceeds its bound.")
                    })?;
                for member in members {
                    check(deadline, cancel)?;
                    if member.raw.is_none()
                        || member_license(snapshot, &member)["decision"] != "approved"
                    {
                        continue;
                    }
                    let Ok(mut url) = url::Url::parse(member_source_url(snapshot, &member)) else {
                        continue;
                    };
                    url.set_fragment(None);
                    bytes = bytes
                        .checked_add(
                            url.as_str().len()
                                + member.path.len()
                                + snapshot.component.len()
                                + snapshot.id.len()
                                + 128,
                        )
                        .filter(|bytes| *bytes <= MAX_OUTPUT)
                        .ok_or_else(|| {
                            Error::capacity("Chromium reference target metadata exceeds its bound.")
                        })?;
                    let target = CapturedTarget {
                        component: snapshot.component.clone(),
                        snapshot: snapshot.id.clone(),
                        path: member.path.clone(),
                        anchors: None,
                        anchors_loaded: member.projection.is_none(),
                    };
                    let mut keys = vec![url.to_string()];
                    if snapshot.component != "chrome"
                        && let Some(local) =
                            repository_target(&snapshot.component, &member.path, None)
                    {
                        keys.push(local.to_string());
                    }
                    for key in keys {
                        bytes = bytes
                            .checked_add(key.len() + member.path.len() + 128)
                            .filter(|n| *n <= MAX_OUTPUT)
                            .ok_or_else(|| {
                                Error::capacity(
                                    "Chromium reference target metadata exceeds its bound.",
                                )
                            })?;
                        match targets.entry(key) {
                            std::collections::btree_map::Entry::Vacant(entry) => {
                                entry.insert(Some(target.clone()));
                            }
                            std::collections::btree_map::Entry::Occupied(mut entry) => {
                                entry.insert(None);
                            }
                        }
                    }
                }
            }
        }
        Ok(targets)
    }
    async fn reference_anchor_targets(
        &self,
        target: &url::Url,
        snapshots: &[Snapshot],
        targets: &mut ReferenceTargets,
        anchor_bytes: &mut usize,
        cancel: &CancellationToken,
    ) -> Result<()> {
        let mut url = target.clone();
        if url.fragment().is_none_or(str::is_empty) {
            return Ok(());
        }
        url.set_fragment(None);
        let Some(Some(document)) = targets.get_mut(url.as_str()) else {
            return Ok(());
        };
        if document.anchors_loaded {
            return Ok(());
        }
        let snapshot = snapshots
            .iter()
            .find(|snapshot| snapshot.id == document.snapshot)
            .ok_or_else(|| {
                Error::integrity("Chromium reference target is outside selected evidence.")
            })?;
        let deadline = Instant::now() + Duration::from_secs(15);
        check(deadline, cancel)?;
        if let Some(value) = self.corpus.projection(snapshot, &document.path).await? {
            let projection: ProcessedDocument = retained(value)?;
            let mut anchors = BTreeMap::<String, usize>::new();
            for anchor in projection
                .sections
                .iter()
                .map(|section| &section.anchor)
                .chain(projection.symbols.iter().map(|symbol| &symbol.anchor))
            {
                check(deadline, cancel)?;
                *anchor_bytes = anchor_bytes
                    .checked_add(anchor.len() + 48)
                    .filter(|bytes| *bytes <= MAX_OUTPUT)
                    .ok_or_else(|| {
                        Error::capacity("Chromium referenced anchor cache exceeds its bound.")
                    })?;
                *anchors.entry(anchor.clone()).or_default() += 1;
            }
            document.anchors = Some(anchors);
        }
        document.anchors_loaded = true;
        Ok(())
    }
    async fn list(&self, tool: &str, input: ListInput, cancel: CancellationToken) -> Result<Value> {
        let deadline = Instant::now() + Duration::from_secs(15);
        if tool == "chromium.catalog_search" {
            return self.catalog_search(input).await;
        }
        let selector = Selector {
            component: if tool == "chromium.references"
                && input.direction.as_deref() == Some("incoming")
                && input.snapshot.is_none()
            {
                None
            } else {
                input.component.clone()
            },
            snapshot: input.snapshot.clone(),
            view: input.view.clone(),
        };
        if matches!(tool, "chromium.snapshots" | "chromium.history") {
            return self.discovery(tool, input, cancel).await;
        }
        let (view, snapshots) = self.selections(&selector).await?;
        let mut reference_targets = if tool == "chromium.references" {
            self.reference_targets(&snapshots, &cancel).await?
        } else {
            ReferenceTargets::new()
        };
        let mut referenced_anchor_bytes = 0usize;
        let identity = view
            .as_ref()
            .map(|v| &v.id)
            .or_else(|| snapshots.first().map(|s| &s.id));
        let fingerprint = fingerprint(
            &(
                tool,
                identity,
                &input.component,
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
        if tool == "chromium.references"
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
                if tool == "chromium.references" {
                    let mut source_anchors = BTreeMap::<String, usize>::new();
                    let mut source_anchor_bytes = 0usize;
                    for anchor in doc
                        .sections
                        .iter()
                        .map(|s| &s.anchor)
                        .chain(doc.symbols.iter().map(|s| &s.anchor))
                    {
                        check(deadline, &cancel)?;
                        source_anchor_bytes = source_anchor_bytes
                            .checked_add(anchor.len() + 48)
                            .filter(|bytes| *bytes <= MAX_OUTPUT)
                            .ok_or_else(|| {
                                Error::capacity(
                                    "Chromium source anchor metadata exceeds its bound.",
                                )
                            })?;
                        *source_anchors.entry(anchor.clone()).or_default() += 1;
                    }
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
                        if !reference.target.starts_with('#')
                            && let Some(target) =
                                reference_url(snapshot, &member, &reference.target)
                        {
                            self.reference_anchor_targets(
                                &target,
                                &snapshots,
                                &mut reference_targets,
                                &mut referenced_anchor_bytes,
                                &cancel,
                            )
                            .await?;
                        }
                        let resolved = resolve_member_reference(
                            &reference.target,
                            snapshot,
                            &member,
                            &reference_targets,
                            &source_anchors,
                        );
                        if incoming
                            && input.component.as_ref().is_some_and(|component| {
                                resolved["component"].as_str() != Some(component.as_str())
                            })
                        {
                            continue;
                        }
                        let value = json!({"component":snapshot.component,"snapshot":snapshot.id,"path":member.path,"reference":reference,"resolution":resolved,"source_metadata":member_metadata(snapshot,&member),"citation":member_citation(snapshot,&member)});
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
                        let value = json!({"component":snapshot.component,"snapshot":snapshot.id,"path":member.path,"symbol_index":symbol_index,"symbol":{"kind":symbol.kind,"name":symbol.name,"anchor":symbol.anchor,"scope":symbol.scope,"text_bytes":symbol.text.len()},"resource_uri":symbol_resource(snapshot,&member.path,symbol_index),"source_metadata":member_metadata(snapshot,&member),"citation":member_citation(snapshot,&member)});
                        if matches_query(&value, input.query.as_deref()) {
                            items.push(value);
                        }
                    }
                }
                if items.len() > MAX_SCAN
                    || serde_json::to_vec(&items)
                        .map_err(|_| Error::integrity("Invalid Chromium result."))?
                        .len()
                        > MAX_OUTPUT
                {
                    return Err(Error::capacity(
                        "Chromium result enumeration exceeds its bound.",
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
        if !(1..=100).contains(&input.limit)
            || input.offset > 10000
            || input
                .cursor
                .as_ref()
                .is_some_and(|cursor| cursor.len() > 16384)
        {
            return Err(Error::invalid("Invalid Chromium document catalog page."));
        }
        let (view, snapshots) = if let Some(id) = input.snapshot.as_deref() {
            if input.view.is_some() {
                return Err(Error::invalid(
                    "Choose a Chromium view or document snapshot.",
                ));
            }
            let snapshot = self.corpus.snapshot(id).await?;
            if input
                .component
                .as_ref()
                .is_some_and(|component| component != &snapshot.component)
            {
                return Err(Error::invalid(
                    "Chromium snapshot belongs to a different component.",
                ));
            }
            (None, vec![snapshot])
        } else if self
            .corpus
            .store()
            .chromium_state("default")
            .await?
            .is_some()
            || input.view.is_some()
        {
            self.selections(&Selector {
                component: input.component.clone(),
                snapshot: None,
                view: input.view.clone(),
            })
            .await?
        } else {
            (None, Vec::new())
        };
        let catalog = if let Some(view) = &view {
            retained::<Catalog>(
                self.corpus
                    .store()
                    .chromium_get("catalogs", &view.catalog)
                    .await?
                    .ok_or_else(|| Error::integrity("Chromium catalog missing."))?
                    .data,
            )?
        } else if let Some(snapshot) = snapshots.first() {
            Catalog {
                id: digest(&("snapshot-component", &snapshot.id))?,
                observed_at: snapshot.validated_at,
                components: vec![Component {
                    id: snapshot.component.clone(),
                    title: snapshot.component.clone(),
                    url: snapshot.source_url.clone(),
                    repository: snapshot.repository.clone(),
                    metadata: json!({"snapshot":snapshot.id,"representation":snapshot.representation,"historical_only":snapshot.component=="chrome-archive"}),
                }],
                gaps: Vec::new(),
            }
        } else {
            self.corpus.catalog().await?
        };
        let identity = (
            view.as_ref().map(|view| &view.id),
            snapshots
                .iter()
                .map(|snapshot| &snapshot.id)
                .collect::<Vec<_>>(),
        );
        let fingerprint = fingerprint(
            &(
                "documents",
                identity,
                &input.component,
                &input.path,
                &input.kind,
                &input.query,
            ),
            input.cursor.as_deref(),
        )?;
        let cursor: Option<CatalogCursor> = input
            .cursor
            .as_ref()
            .map(|cursor| {
                let decoded = URL_SAFE_NO_PAD
                    .decode(cursor)
                    .map_err(|_| Error::invalid("Invalid Chromium catalog cursor."))?;
                serde_json::from_slice::<CatalogCursor>(&decoded)
                    .map_err(|_| Error::invalid("Invalid Chromium catalog cursor."))
            })
            .transpose()?;
        if let Some(cursor) = &cursor
            && (cursor.fingerprint != fingerprint
                || cursor.component > snapshots.len()
                || cursor.member_offset > MAX_SCAN
                || cursor.skip > 10000
                || input.offset != 0)
        {
            return Err(Error::invalid(
                "Chromium catalog cursor does not match the selected evidence and query.",
            ));
        }
        let mut component_at = cursor.as_ref().map_or(0, |cursor| cursor.component);
        let mut member_offset = cursor.as_ref().map_or(0, |cursor| cursor.member_offset);
        let mut skip = cursor.as_ref().map_or(input.offset, |cursor| cursor.skip);
        let mut scanned = 0;
        let mut items = Vec::new();
        let mut output_bytes = 0usize;
        let deadline = Instant::now() + Duration::from_secs(15);
        let cancel = CancellationToken::new();
        'scan: while component_at < snapshots.len() && scanned < 1000 && items.len() < input.limit {
            check(deadline, &cancel)?;
            let snapshot = &snapshots[component_at];
            let members = self.corpus.members(snapshot, member_offset, 1000).await?;
            if members.is_empty() {
                component_at += 1;
                member_offset = 0;
                continue;
            }
            for member in members {
                check(deadline, &cancel)?;
                if scanned >= 1000 {
                    break 'scan;
                }
                member_offset += 1;
                scanned += 1;
                if input
                    .path
                    .as_ref()
                    .is_some_and(|path| !member.path.starts_with(path))
                    || input.kind.as_ref().is_some_and(|kind| kind != &member.kind)
                {
                    continue;
                }
                let title = if let Some(projection) = &member.projection {
                    self.corpus
                        .store()
                        .chromium_get("projections", projection)
                        .await?
                        .map(|row| row.data["title"].clone())
                        .unwrap_or(Value::Null)
                } else {
                    Value::Null
                };
                let item = json!({"component":snapshot.component,"snapshot":snapshot.id,"path":member.path,"title":title,"kind":member.kind,"object_hash":member.oid,"projected":member.projection.is_some(),"gaps":member.gaps,"source_metadata":member_metadata(snapshot,&member),"license":license_metadata(snapshot,member_license(snapshot,&member),member_source_url(snapshot,&member)),"citation":member_citation(snapshot,&member)});
                if matches_query(&item, input.query.as_deref()) {
                    if skip > 0 {
                        skip -= 1;
                    } else {
                        output_bytes = output_bytes
                            .checked_add(
                                serde_json::to_vec(&item)
                                    .map_err(|_| {
                                        Error::integrity("Invalid Chromium catalog item.")
                                    })?
                                    .len(),
                            )
                            .filter(|bytes| *bytes <= MAX_OUTPUT)
                            .ok_or_else(|| {
                                Error::capacity("Chromium catalog output bound exceeded.")
                            })?;
                        items.push(item);
                    }
                }
                if items.len() == input.limit || scanned >= 1000 {
                    break 'scan;
                }
            }
        }
        let next = if component_at < snapshots.len() {
            Some(
                URL_SAFE_NO_PAD.encode(
                    serde_json::to_vec(&CatalogCursor {
                        version: if fingerprint.starts_with("blake3:") {
                            2
                        } else {
                            0
                        },
                        fingerprint,
                        component: component_at,
                        member_offset,
                        skip,
                    })
                    .map_err(|_| Error::integrity("Invalid Chromium catalog cursor."))?,
                ),
            )
        } else {
            None
        };
        Ok(
            json!({"catalog":catalog.id,"components":catalog.components,"catalog_gaps":catalog.gaps,"items":items,"scanned":scanned,"next_cursor":next,"view":view.as_ref().map(|view|&view.id),"selections":snapshots.iter().map(|snapshot|public_selection(snapshot,input.snapshot.is_some()||input.view.is_some(),view.as_ref())).collect::<Vec<_>>() }),
        )
    }
    async fn discovery(
        &self,
        tool: &str,
        input: ListInput,
        cancel: CancellationToken,
    ) -> Result<Value> {
        if input.history_type.as_deref() == Some("refs") {
            if tool != "chromium.history" {
                return Err(Error::invalid(
                    "Ref observations belong to chromium.history.",
                ));
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
                "Chromium history_type must be revisions or refs.",
            ));
        }
        if !(1..=100).contains(&input.limit)
            || input.offset > 10_000
            || input.cursor.as_ref().is_some_and(|c| c.len() > 16384)
        {
            return Err(Error::invalid("Invalid Chromium discovery page."));
        }
        let cursor: Option<HistoryCursor> = input
            .cursor
            .as_ref()
            .map(|c| {
                serde_json::from_slice(
                    &URL_SAFE_NO_PAD
                        .decode(c)
                        .map_err(|_| Error::invalid("Invalid Chromium history cursor."))?,
                )
                .map_err(|_| Error::invalid("Invalid Chromium history cursor."))
            })
            .transpose()?;
        let cutoff = match (&cursor, input.history_snapshot) {
            (Some(c), Some(cutoff)) if c.cutoff != cutoff => {
                return Err(Error::invalid(
                    "Chromium history cutoff differs from the cursor.",
                ));
            }
            (Some(c), _) => c.cutoff,
            (_, Some(cutoff)) => cutoff,
            _ => self.corpus.store().chromium_cutoff().await?,
        };
        if cutoff < 0 || cutoff > self.corpus.store().chromium_cutoff().await? {
            return Err(Error::invalid("Invalid Chromium history cutoff."));
        }
        let fingerprint = fingerprint(
            &(
                tool,
                cutoff,
                &input.component,
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
                    "Chromium history cursor does not match this query.",
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
                .chromium_rows("snapshots", after, 100, Some(cutoff))
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
                    .component
                    .as_ref()
                    .is_some_and(|s| s != &snapshot.component)
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
                if tool == "chromium.history" {
                    if snapshot.parents.len() > 100 {
                        return Err(Error::capacity("Chromium history parent bound exceeded."));
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
            .chromium_rows("snapshots", after, 1, Some(cutoff))
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
                    .map_err(|_| Error::integrity("Invalid Chromium history cursor."))?,
                ),
            )
        } else {
            None
        };
        Ok(json!({"items":items,"history_snapshot":cutoff,"next_cursor":next,"scanned":scanned}))
    }
    async fn ref_history(&self, input: ListInput, cancel: CancellationToken) -> Result<Value> {
        if input.path.is_some() {
            return Err(Error::invalid(
                "Git ref observations have no document path filter.",
            ));
        }
        if !(1..=100).contains(&input.limit)
            || input.offset > 10_000
            || input.cursor.as_ref().is_some_and(|c| c.len() > 16384)
        {
            return Err(Error::invalid("Invalid Chromium ref page."));
        }
        let cursor: Option<RefHistoryCursor> = input
            .cursor
            .as_ref()
            .map(|c| {
                serde_json::from_slice(
                    &URL_SAFE_NO_PAD
                        .decode(c)
                        .map_err(|_| Error::invalid("Invalid Chromium ref cursor."))?,
                )
                .map_err(|_| Error::invalid("Invalid Chromium ref cursor."))
            })
            .transpose()?;
        let cutoff = match (&cursor, input.history_snapshot) {
            (Some(c), Some(cutoff)) if cutoff != c.cutoff => {
                return Err(Error::invalid(
                    "Chromium ref cutoff differs from the cursor.",
                ));
            }
            (Some(c), _) => c.cutoff,
            (_, Some(cutoff)) => cutoff,
            _ => self.corpus.store().chromium_cutoff().await?,
        };
        if cutoff < 0 || cutoff > self.corpus.store().chromium_cutoff().await? {
            return Err(Error::invalid("Invalid Chromium history cutoff."));
        }
        let fingerprint = fingerprint(
            &(
                "refs",
                cutoff,
                &input.component,
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
                || c.entry > 500
                || c.skip > 10_000
                || input.offset != 0)
        {
            return Err(Error::invalid(
                "Chromium ref cursor does not match the query.",
            ));
        }
        let mut after = cursor.as_ref().map_or(0, |c| c.after);
        let mut entry = cursor.as_ref().map_or(0, |c| c.entry);
        let mut page_position = cursor.as_ref().map_or(0, |c| c.page);
        let mut skip = cursor.as_ref().map_or(input.offset, |c| c.skip);
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut scanned = 0;
        let mut items = Vec::new();
        'scan: while items.len() < input.limit && scanned < 500 {
            check(deadline, &cancel)?;
            let rows = self
                .corpus
                .store()
                .chromium_rows("observations", after, 4, Some(cutoff))
                .await?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                scanned += 1;
                check(deadline, &cancel)?;
                let observation = row.data;
                let repository = observation["repository"].as_str().unwrap_or("");
                if input
                    .repository
                    .as_ref()
                    .is_some_and(|repo| repo != repository)
                    || input.component.as_ref().is_some_and(|component| {
                        observation["component"].as_str() != Some(component)
                    })
                {
                    after = row.sequence;
                    entry = 0;
                    page_position = 0;
                    continue;
                }
                let page_ids = observation["ref_pages"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default();
                let page_count = page_ids.len().max(1);
                if page_position >= page_count {
                    return Err(Error::invalid(
                        "Chromium ref cursor page is outside its observation.",
                    ));
                }
                let page_start = page_position;
                for page_at in page_start..page_count {
                    check(deadline, &cancel)?;
                    let data = if page_ids.is_empty() {
                        observation["refs"].clone()
                    } else {
                        let key = page_ids[page_at]
                            .as_str()
                            .filter(|id| valid_hash(id))
                            .ok_or_else(|| {
                                Error::integrity("Invalid Chromium ref page identity.")
                            })?;
                        self.corpus
                            .store()
                            .chromium_get("ref-pages", key)
                            .await?
                            .ok_or_else(|| Error::integrity("Missing Chromium ref page."))?
                            .data
                    };
                    let refs = data
                        .as_array()
                        .ok_or_else(|| Error::integrity("Invalid Chromium ref observation."))?;
                    if refs.len() > 500 || entry > refs.len() {
                        return Err(Error::integrity("Chromium ref page exceeds its bound."));
                    }
                    for (i, reference) in refs.iter().enumerate().skip(entry) {
                        check(deadline, &cancel)?;
                        scanned += 1;
                        after = row.sequence - 1;
                        page_position = page_at;
                        entry = i + 1;
                        let matched = input
                            .reference
                            .as_ref()
                            .is_none_or(|name| reference["name"].as_str() == Some(name));
                        let item = json!({"observation":row.key,"sequence":row.sequence,"repository":repository,"component":observation["component"],"observed_at":observation["observed_at"],"ref":reference,"current_revision":observation["current_revision"]});
                        if matched && matches_query(&item, input.query.as_deref()) {
                            if skip > 0 {
                                skip -= 1;
                            } else {
                                items.push(item);
                            }
                        }
                        if items.len() == input.limit || scanned >= 500 {
                            break 'scan;
                        }
                    }
                    entry = 0;
                }
                after = row.sequence;
                entry = 0;
                page_position = 0;
                if scanned >= 500 {
                    break 'scan;
                }
            }
        }
        let more = entry > 0
            || page_position > 0
            || !self
                .corpus
                .store()
                .chromium_rows("observations", after, 1, Some(cutoff))
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
                        page: page_position,
                        entry,
                        cutoff,
                        skip,
                    })
                    .map_err(|_| Error::integrity("Invalid Chromium ref cursor."))?,
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
                .chromium_rows("snapshots", after, 100, Some(cutoff))
                .await?;
            if rows.is_empty() {
                return Ok(found);
            }
            for row in rows {
                check(deadline, cancel)?;
                after = row.sequence;
                let candidate: Snapshot = retained(row.data)?;
                if candidate.component == selected.component
                    && candidate.repository == selected.repository
                    && candidate.revision == revision
                    && candidate.representation == selected.representation
                    && candidate.processor_version == selected.processor_version
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
        let left = self.member_map(before, path, cancel).await?;
        let right = self.member_map(after, path, cancel).await?;
        let mut changes = Vec::new();
        for key in left.keys().chain(right.keys()).collect::<BTreeSet<_>>() {
            if path.is_some_and(|p| p != key) {
                continue;
            }
            let old = left.get(key);
            let new = right.get(key);
            if old.map(|member| &member.oid) != new.map(|member| &member.oid) {
                changes.push(json!({"path":key,"change":if old.is_none(){"added"}else if new.is_none(){"removed"}else{"changed"},"before":old.map(|member|&member.oid),"after":new.map(|member|&member.oid),"before_source":old.map(|member|member_metadata(before,member)),"after_source":new.map(|member|member_metadata(after,member))}));
            }
            if changes.len() > 1000 {
                return Err(Error::capacity(
                    "Chromium comparison exceeds its change bound; select a path.",
                ));
            }
        }
        Ok(json!(changes))
    }
    async fn member_map(
        &self,
        snapshot: &Snapshot,
        path: Option<&str>,
        cancel: &CancellationToken,
    ) -> Result<BTreeMap<String, Member>> {
        let mut result = BTreeMap::new();
        if let Some(path) = path {
            check(Instant::now() + Duration::from_secs(15), cancel)?;
            if let Some(member) = self.corpus.member(snapshot, path).await? {
                require_member_license(snapshot, &member)?;
                result.insert(comparison_path(snapshot, &member.path), member);
            }
            return Ok(result);
        }
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
                    "Chromium comparison membership bound exceeded.",
                ));
            }
            for row in rows {
                require_member_license(snapshot, &row)?;
                result.insert(comparison_path(snapshot, &row.path), row);
            }
        }
        Ok(result)
    }
    async fn compare(&self, input: CompareInput, cancel: CancellationToken) -> Result<Value> {
        let before = self
            .corpus
            .select(&input.component, Some(&input.before), None)
            .await?;
        let after = self
            .corpus
            .select(&input.component, Some(&input.after), None)
            .await?;
        require_content_license(&before)?;
        require_content_license(&after)?;
        if before.representation != after.representation {
            return Err(Error::invalid(
                "Chromium comparisons require the same component and representation family.",
            ));
        }
        if !matches!(input.mode.as_str(), "text" | "symbols" | "source") {
            return Err(Error::invalid(
                "Chromium comparison mode must be text, symbols or source.",
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
                if a.map(|(text, _)| text) != b.map(|(text, _)| text) {
                    result.push(json!({"identity":key,"change":if a.is_none(){"added"}else if b.is_none(){"removed"}else{"changed"},"before_hash":a.map(|(text,_)|digest(text)).transpose()?,"after_hash":b.map(|(text,_)|digest(text)).transpose()?,"before_source":a.map(|(_,source)|source),"after_source":b.map(|(_,source)|source)}));
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
            if let Some(path) = path {
                check(deadline, cancel)?;
                if let Some(member) = self.corpus.member(snapshot, path).await? {
                    members.insert(
                        comparison_path(snapshot, &member.path),
                        member.projection.is_some(),
                    );
                }
                sides.push(members);
                continue;
            }
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
                        "Chromium comparison membership exceeds its bound.",
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
                    "Selected Chromium comparison has an unprocessed side; use original-source comparison or a qualified path.",
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
    ) -> Result<BTreeMap<String, (Vec<String>, Value)>> {
        let mut result: BTreeMap<String, (Vec<String>, Value)> = BTreeMap::new();
        for (member, doc) in self
            .documents(snapshot, cancel, input.path.as_deref())
            .await?
        {
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
                            .or_insert_with(|| (Vec::new(), member_metadata(snapshot, &member)))
                            .0
                            .push(symbol.text);
                    }
                }
            } else {
                for section in doc.sections {
                    if input.anchor.as_ref().is_none_or(|a| a == &section.anchor) {
                        result
                            .entry(format!("{}#{}", logical_path, section.anchor))
                            .or_insert_with(|| (Vec::new(), member_metadata(snapshot, &member)))
                            .0
                            .push(section.text);
                    }
                }
            }
        }
        Ok(result)
    }
    pub async fn read_resource(&self, uri: &str) -> Result<Value> {
        if uri.len() > 16384 {
            return Err(Error::invalid("Chromium resource URI is too long."));
        }
        let url =
            url::Url::parse(uri).map_err(|_| Error::invalid("Invalid Chromium resource URI."))?;
        if url.scheme() != "devres"
            || url.host_str() != Some("chromium")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.port().is_some()
            || url.fragment().is_some()
        {
            return Err(Error::invalid("Invalid Chromium resource URI."));
        }
        let parts: Vec<_> = url.path().trim_start_matches('/').split('/').collect();
        if parts.len() != 4 || !valid_hash(parts[1]) {
            return Err(Error::invalid(
                "Chromium resources bind component, snapshot, representation and encoded path.",
            ));
        }
        let path = String::from_utf8(
            URL_SAFE_NO_PAD
                .decode(parts[3])
                .map_err(|_| Error::invalid("Invalid Chromium resource path."))?,
        )
        .map_err(|_| Error::invalid("Invalid Chromium resource path."))?;
        if URL_SAFE_NO_PAD.encode(path.as_bytes()) != parts[3] {
            return Err(Error::invalid("Noncanonical Chromium resource path."));
        }
        let mut input =
            json!({"component":parts[0],"snapshot":parts[1],"representation":parts[2],"path":path});
        let mut seen = BTreeSet::new();
        for (key, value) in url.query_pairs() {
            if !seen.insert(key.to_string()) {
                return Err(Error::invalid("Duplicate Chromium resource option."));
            }
            match key.as_ref() {
                "offset" | "limit" => {
                    input[key.as_ref()] = json!(
                        value
                            .parse::<usize>()
                            .map_err(|_| Error::invalid("Invalid Chromium resource page."))?
                    );
                }
                "section_index" if parts[2] == "text" => {
                    input["section_index"] = json!(
                        value
                            .parse::<usize>()
                            .map_err(|_| Error::invalid("Invalid Chromium section index."))?
                    );
                }
                "symbol_index" if parts[2] == "symbol" => {
                    input["symbol_index"] = json!(
                        value
                            .parse::<usize>()
                            .map_err(|_| Error::invalid("Invalid Chromium symbol index."))?
                    );
                }
                "anchor" => input["anchor"] = json!(value.as_ref()),
                "name" | "kind" if parts[2] == "symbol" => {
                    input[key.as_ref()] = json!(value.as_ref())
                }
                _ => return Err(Error::invalid("Unknown Chromium resource option.")),
            }
        }
        let output = if parts[2] == "symbol" {
            input.as_object_mut().map(|m| m.remove("representation"));
            self.call("chromium.symbol_get", input).await?
        } else {
            self.call("chromium.get", input).await?
        };
        let processing_gaps = output
            .get("processing_gaps")
            .unwrap_or(&output["page"]["processing_gaps"]);
        let metadata = json!({"provenance":output["selection"],"source_url":output["source_metadata"]["source_url"],"source_path":output["path"],"source_metadata":output["source_metadata"],"derived_notice":DERIVED_NOTICE,"license":output["license"],"gaps":{"member":output["gaps"],"processing":processing_gaps,"coverage":output["selection"]["coverage"]}});
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

pub fn schemas() -> Vec<Value> {
    let id = json!({"type":"string","enum":["src","site","chrome","chrome-archive"]});
    let hash = json!({"type":"string","pattern":"^(blake3:)?[0-9a-f]{64}$"});
    let path = json!({"type":"string","minLength":1,"maxLength":4096});
    let query = json!({"type":"string","minLength":1,"maxLength":256});
    let common = json!({"component":id,"snapshot":hash,"view":hash,"query":query,"offset":{"type":"integer","minimum":0,"maximum":10000,"default":0},"limit":{"type":"integer","minimum":1,"maximum":100,"default":20},"cursor":{"type":"string","maxLength":16384}});
    let mut tools = Vec::new();
    let mut add = |name: &str, description: &str, properties: Value, required: Vec<&str>| {
        tools.push(json!({"name":name,"description":description,"inputSchema":{"type":"object","properties":properties,"required":required,"additionalProperties":false},"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}}));
    };
    let mut catalog_properties = common.clone();
    catalog_properties["path"] = path.clone();
    catalog_properties["kind"] = path.clone();
    add(
        "chromium.catalog_search",
        "Search immutable Chromium document metadata and component coverage; select a snapshot or view for historical evidence. Path filters select a document prefix.",
        catalog_properties,
        vec![],
    );
    let mut search = common.clone();
    search["mode"] = json!({"enum":["technical","english"],"default":"technical"});
    for key in ["representation", "path", "kind"] {
        search[key] = path.clone();
    }
    add(
        "chromium.search",
        "Search immutable Chromium sections using selected-corpus BM25. Defaults select available current source components; reuse view/snapshot and cursor.",
        search,
        vec!["query"],
    );
    let get = json!({"component":id,"snapshot":hash,"view":hash,"path":path,"anchor":path,"section_index":{"type":"integer","minimum":0,"description":"Zero-based position in this captured document's ordered sections; requires path and excludes anchor."},"representation":{"enum":["text","source","bytes"],"default":"text"},"offset":{"type":"integer","minimum":0,"default":0},"limit":{"type":"integer","minimum":1,"maximum":32768,"default":32768}});
    add(
        "chromium.get",
        "Read capture-fixed component text, an anchored section, original source, or base64 bytes. Text offsets count UTF-8 bytes.",
        get,
        vec!["component", "path"],
    );
    for (name, description) in [(
        "chromium.symbol_search",
        "Search original definitions, Web IDL declarations and explicitly marked algorithms.",
    )] {
        let mut props = common.clone();
        props["kind"] = json!({"enum":["definition","idl","algorithm","api"]});
        for key in ["name", "anchor", "path"] {
            props[key] = path.clone();
        }
        add(name, description, props, vec![]);
    }
    let symbol_get = json!({"component":id,"snapshot":hash,"view":hash,"path":path,"symbol_index":{"type":"integer","minimum":0,"description":"Zero-based position in this captured document's ordered symbols; requires path and is local to the selected snapshot."},"name":path,"anchor":path,"kind":{"enum":["definition","idl","algorithm","api"]},"offset":{"type":"integer","minimum":0,"default":0},"limit":{"type":"integer","minimum":1,"maximum":32768,"default":32768}});
    add(
        "chromium.symbol_get",
        "Read one unambiguous captured symbol in bounded UTF-8 pages with original text and provenance.",
        symbol_get,
        vec!["component"],
    );
    let mut refs = common.clone();
    refs["direction"] = json!({"enum":["incoming","outgoing"],"default":"outgoing"});
    for key in ["target", "anchor", "path"] {
        refs[key] = path.clone();
    }
    add(
        "chromium.references",
        "Inspect captured incoming/outgoing links. Target resolution uses selected evidence only; external references are never fetched.",
        refs,
        vec![],
    );
    for (name, description) in [
        (
            "chromium.snapshots",
            "Discover immutable source/publication snapshots with a frozen history cutoff.",
        ),
        (
            "chromium.history",
            "Inspect retained revisions and changes against each ordered parent; missing parent projections remain explicit.",
        ),
    ] {
        let mut props = common.clone();
        props["history_snapshot"] = json!({"type":"integer","minimum":0});
        props["path"] = path.clone();
        if name == "chromium.history" {
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
        "chromium.compare",
        "Compare two immutable snapshots of the same component and representation family; no compatibility verdict is inferred.",
        compare,
        vec!["component", "before", "after"],
    );
    add(
        "chromium.corpus_status",
        "Inspect separate Chromium acquisition, ancestry, projection, indexing and freshness coverage. No collection controls are exposed.",
        json!({}),
        vec![],
    );
    for tool in &mut tools {
        if tool["inputSchema"]["properties"].get("snapshot").is_some()
            && tool["inputSchema"]["properties"].get("view").is_some()
        {
            tool["inputSchema"]["not"] = json!({"required":["snapshot","view"]});
        }
        match tool["name"].as_str() {
            Some("chromium.get") => {
                tool["inputSchema"]["allOf"] = json!([{"if":{"required":["section_index"]},"then":{"required":["path"],"not":{"required":["anchor"]},"properties":{"representation":{"const":"text"}}}}]);
            }
            Some("chromium.symbol_get") => {
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
