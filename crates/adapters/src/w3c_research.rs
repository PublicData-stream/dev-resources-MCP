//! Local, capture-fixed W3C research. No public operation acquires upstream data.
use crate::{
    W3cCorpus,
    research::{decode, text_page},
    w3c_processing::ProcessedDocument,
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use devres_application::w3c::{Catalog, Member, Snapshot, View};
use devres_domain::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
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
    Ok(hex::encode(Sha256::digest(
        serde_json::to_vec(value).map_err(|_| Error::integrity("Invalid W3C evidence."))?,
    )))
}
fn retained<T: serde::de::DeserializeOwned>(value: Value) -> Result<T> {
    serde_json::from_value(value).map_err(|_| Error::integrity("Invalid retained W3C evidence."))
}
fn valid_hash(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn check(deadline: Instant, cancel: &CancellationToken) -> Result<()> {
    if cancel.is_cancelled() {
        return Err(Error::new("cancelled", "W3C research canceled."));
    }
    if Instant::now() >= deadline {
        return Err(Error::capacity("W3C research processing bound exceeded."));
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
    #[serde(rename = "specification")]
    standard: Option<String>,
    snapshot: Option<String>,
    view: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchInput {
    #[serde(rename = "specification")]
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
    #[serde(rename = "specification")]
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
    #[serde(rename = "specification")]
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
    #[serde(rename = "specification")]
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
    #[serde(rename = "specification")]
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
    fingerprint: String,
    position: usize,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryCursor {
    fingerprint: String,
    after: i64,
    cutoff: i64,
    skip: usize,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RefHistoryCursor {
    fingerprint: String,
    after: i64,
    entry: usize,
    cutoff: i64,
    skip: usize,
}
fn position(fingerprint: &str, offset: usize, cursor: Option<&str>, limit: usize) -> Result<usize> {
    if !(1..=100).contains(&limit) || offset > 10_000 {
        return Err(Error::invalid(
            "W3C lists require limit 1..100 and offset at most 10000.",
        ));
    }
    let Some(cursor) = cursor else {
        return Ok(offset);
    };
    if cursor.len() > 16_384 || offset != 0 {
        return Err(Error::invalid("Invalid W3C cursor continuation."));
    }
    let c: Cursor = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(cursor)
            .map_err(|_| Error::invalid("Invalid W3C cursor."))?,
    )
    .map_err(|_| Error::invalid("Invalid W3C cursor."))?;
    if c.fingerprint != fingerprint || c.position > MAX_SCAN {
        return Err(Error::invalid(
            "W3C cursor does not match the selected evidence and query.",
        ));
    }
    Ok(c.position)
}
fn page(items: Vec<Value>, fingerprint: String, start: usize, limit: usize) -> Result<Value> {
    if start > items.len() {
        return Err(Error::invalid("W3C page is outside selected results."));
    }
    let end = start.saturating_add(limit).min(items.len());
    let next = if end < items.len() {
        Some(
            URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(&Cursor {
                    fingerprint,
                    position: end,
                })
                .map_err(|_| Error::integrity("Invalid W3C cursor encoding."))?,
            ),
        )
    } else {
        None
    };
    Ok(json!({"items":items[start..end],"offset":start,"total":items.len(),"next_cursor":next}))
}
fn public_snapshot(snapshot: &Snapshot, historical: bool) -> Value {
    json!({"snapshot":snapshot.id,"specification":snapshot.standard,"repository":snapshot.repository,
        "revision":snapshot.revision,"representation":snapshot.representation,"processor_version":snapshot.processor_version,
        "validated_at":snapshot.validated_at,"stale":devres_domain::unix_now().saturating_sub(snapshot.validated_at)>86400,
        "historical":historical,"coverage":snapshot.coverage,"source_url":snapshot.source_url,
        "source_metadata":source_metadata(snapshot),"license":source_license(snapshot),
        "catalog_latest_publication":snapshot.coverage["latest_publication"],
        "effective_publication":snapshot.coverage["effective_publication"],
        "fallback_reason":snapshot.coverage["fallback_reason"]})
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
        "devres://w3c/{}/{}/{representation}/{id}",
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
    if snapshot.representation == "source" {
        return path.to_owned();
    }
    if let Ok(url) = url::Url::parse(&snapshot.source_url) {
        let source_path = url.path().trim_start_matches('/');
        let parts = source_path
            .split('/')
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>();
        let root = if parts.first() == Some(&"TR") && parts.len() >= 2 {
            let dated = parts[1].len() == 4 && parts[1].bytes().all(|byte| byte.is_ascii_digit());
            let length = if dated && parts.len() >= 3 { 3 } else { 2 };
            Some(parts[..length].join("/"))
        } else {
            source_path
                .rsplit_once('/')
                .map(|(directory, _)| directory.to_owned())
                .filter(|directory| !directory.is_empty())
        };
        if let Some(root) = root {
            if path == root {
                return format!("index.{}", snapshot.representation);
            }
            if let Some(relative) = path
                .strip_prefix(&root)
                .and_then(|relative| relative.strip_prefix('/'))
                && !relative.is_empty()
            {
                return relative.to_owned();
            }
        }
    }
    // Retained synthetic or imported snapshots can retain these older edition conventions.
    let mut parts = path.splitn(3, '/');
    if matches!(parts.next(), Some("commit-snapshots" | "review-drafts"))
        && parts.next().is_some()
        && let Some(relative) = parts.next()
    {
        return relative.to_owned();
    }
    path.to_owned()
}

const DERIVED_NOTICE: &str = "Text, excerpts, indexing and comparisons are derived by dev-resources-MCP from the identified source; this output is not an official W3C publication.";
fn require_content_license(snapshot: &Snapshot) -> Result<()> {
    if snapshot.coverage["license"]["decision"].as_str() != Some("approved") {
        return Err(Error::unavailable(
            "W3C content license is unresolved or blocked; only catalog metadata is available.",
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
            "W3C member license is unresolved or blocked; copied content is unavailable.",
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
    json!({"specification":snapshot.standard,"source_url":source_url,
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
                        let specification =
                            item.get("specification").or_else(|| item.get("standard"));
                        let specification_matches = specification
                            .and_then(Value::as_str)
                            .is_none_or(|id| source["specification"].as_str() == Some(id));
                        snapshot_matches && specification_matches
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
                if let Some(map) = item.as_object_mut()
                    && let Some(standard) = map.remove("standard")
                {
                    map.insert("specification".into(), standard);
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

struct CapturedTarget {
    specification: String,
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
        return json!({"specification":snapshot.standard,"snapshot":snapshot.id,"path":member.path,"anchor":anchor,"state":state});
    }
    let resolved = url::Url::parse(target).or_else(|_| {
        url::Url::parse(member_source_url(snapshot, member)).and_then(|base| base.join(target))
    });
    let Ok(mut url) = resolved else {
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
            json!({"specification":document.specification,"snapshot":document.snapshot,"path":document.path,"anchor":anchor,"state":state})
        }
        Some(None) => json!({"state":"ambiguous_captured_document","target":target}),
        None => json!({"state":"unresolved_external","target":target}),
    }
}

pub struct W3cResearch {
    corpus: Arc<W3cCorpus>,
}
impl W3cResearch {
    pub fn new(corpus: Arc<W3cCorpus>) -> Self {
        Self { corpus }
    }
    pub async fn call(&self, tool: &str, input: Value) -> Result<Value> {
        let historical = input.get("snapshot").and_then(Value::as_str).is_some()
            || input.get("view").and_then(Value::as_str).is_some();
        let cancel = CancellationToken::new();
        let _guard = CancelOnDrop(cancel.clone());
        let mut output = match tool {
            "w3c_corpus_status" => {
                let _: EmptyInput = decode(input)?;
                self.corpus.status().await
            }
            "w3c_get" => self.get(decode(input)?, cancel).await,
            "w3c_search" => self.search(decode(input)?, cancel).await,
            "w3c_symbol_get" => self.symbol_get(decode(input)?, cancel).await,
            "w3c_compare" => self.compare(decode(input)?, cancel).await,
            "w3c_catalog_search" | "w3c_symbol_search" | "w3c_references" | "w3c_snapshots"
            | "w3c_history" => self.list(tool, decode(input)?, cancel).await,
            _ => Err(Error::not_found("Unknown W3C research tool.")),
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
                    .w3c_get("catalogs", &view.catalog)
                    .await?
                    .ok_or_else(|| Error::integrity("W3C selected catalog is missing."))?
                    .data,
            )?;
            if !historical
                && devres_domain::unix_now().saturating_sub(catalog.observed_at) > 7 * 86400
            {
                return Err(Error::unavailable(
                    "W3C default catalog is older than seven days; select a historical view explicitly.",
                ));
            }
            let missing = catalog
                .standards
                .iter()
                .filter(|specification| !view.snapshots.contains_key(&specification.id))
                .map(|specification| specification.id.clone())
                .collect::<Vec<_>>();
            output["selection_coverage"] = json!({"catalog":catalog.id,
                "catalog_specifications":catalog.standards.len(),"view_specifications":view.snapshots.len(),
                "missing_specifications":missing.iter().take(100).collect::<Vec<_>>(),
                "missing_specifications_total":missing.len(),"missing_specifications_truncated":missing.len()>100,
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
                return Err(Error::invalid("Choose a W3C view or a document snapshot."));
            }
            let s = self.corpus.snapshot(id).await?;
            if selector
                .standard
                .as_ref()
                .is_some_and(|standard| standard != &s.standard)
            {
                return Err(Error::invalid(
                    "W3C snapshot belongs to a different specification.",
                ));
            }
            require_content_license(&s)?;
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
                        "Selected W3C default evidence is older than seven days; select a historical view explicitly.",
                    ));
                }
                let snapshot = self.corpus.select(standard, None, Some(&view.id)).await?;
                require_content_license(&snapshot)?;
                selected.push(snapshot);
            }
        }
        if selector.standard.is_some() && selected.is_empty() {
            return Err(Error::unavailable(
                "Selected W3C specification has no published snapshot.",
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
                return Err(Error::capacity("W3C snapshot membership bound exceeded."));
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
                        return Err(Error::capacity("W3C research text budget exceeded."));
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
                "W3C representation must be text, source or bytes.",
            ));
        }
        if input.section_index.is_some()
            && (input.path.is_none() || input.anchor.is_some() || input.representation != "text")
        {
            return Err(Error::invalid(
                "A W3C section index requires a path and projected text, without an anchor selector.",
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
            .ok_or_else(|| Error::unavailable("W3C selected evidence is unavailable."))?;
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
                            "Select an explicit W3C source path from search or snapshot discovery.",
                        )
                    })?
            }
        };
        if !crate::w3c_inventory::valid_path(&path) {
            return Err(Error::invalid("Invalid W3C member path."));
        }
        let member =
            self.corpus.member(&snapshot, &path).await?.ok_or_else(|| {
                Error::not_found("W3C member is absent from the selected snapshot.")
            })?;
        require_member_license(&snapshot, &member)?;
        let mut section_index = input.section_index;
        let mut symbol_index = None;
        let mut selected_anchor = input.anchor.clone();
        let page = if input.representation == "bytes" || input.representation == "source" {
            if input.anchor.is_some() {
                return Err(Error::invalid("Anchors apply to projected W3C text."));
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
                            .ok_or_else(|| Error::integrity("W3C raw page is missing bytes."))?,
                    )
                    .map_err(|_| Error::integrity("Invalid W3C raw page encoding."))?;
                let text = match std::str::from_utf8(&bytes) {
                    Ok(text) => text,
                    Err(error) if error.error_len().is_none() && error.valid_up_to() > 0 => {
                        std::str::from_utf8(&bytes[..error.valid_up_to()])
                            .map_err(|_| Error::integrity("Invalid W3C source page."))?
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
                            "W3C projection is unavailable; raw evidence remains readable.",
                        )
                    })?,
            )?;
            let text = if let Some(index) = input.section_index {
                let section = doc.sections.get(index).ok_or_else(|| {
                    Error::not_found("W3C section index is absent from the selected document.")
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
                            "W3C anchor is absent or ambiguous in this representation.",
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
                .ok_or_else(|| Error::unavailable("W3C snapshot is unavailable."))?
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
        let spec = crate::w3c_index::SearchSpec {
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
                let specification = hit
                    .get("standard")
                    .or_else(|| hit.get("specification"))
                    .and_then(Value::as_str)
                    .ok_or_else(|| Error::integrity("W3C search hit specification is missing."))?;
                let snapshot = snapshots
                    .iter()
                    .find(|snapshot| snapshot.standard == specification)
                    .ok_or_else(|| {
                        Error::integrity("W3C search hit is outside selected evidence.")
                    })?;
                let path = hit["path"]
                    .as_str()
                    .ok_or_else(|| Error::integrity("W3C search hit path is missing."))?
                    .to_owned();
                let member = self
                    .corpus
                    .member(snapshot, &path)
                    .await?
                    .ok_or_else(|| Error::integrity("W3C search hit member is absent."))?;
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
                "Select a W3C symbol name, anchor or document-local index.",
            ));
        }
        if input.symbol_index.is_some() && input.path.is_none() {
            return Err(Error::invalid(
                "A W3C symbol index requires an explicit document path.",
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
            .ok_or_else(|| Error::unavailable("W3C selected evidence is unavailable."))?;
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
                        "W3C symbol is ambiguous; select path, kind and anchor.",
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
        let (member, symbol_index, symbol, gaps, processing_gaps) = selected
            .ok_or_else(|| Error::not_found("W3C symbol is absent from the selected snapshot."))?;
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
            if snapshot.representation == "source" {
                continue;
            }
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
                        Error::capacity("W3C reference membership exceeds its bound.")
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
                                + snapshot.standard.len()
                                + snapshot.id.len()
                                + 128,
                        )
                        .filter(|bytes| *bytes <= MAX_OUTPUT)
                        .ok_or_else(|| {
                            Error::capacity("W3C reference target metadata exceeds its bound.")
                        })?;
                    let target = CapturedTarget {
                        specification: snapshot.standard.clone(),
                        snapshot: snapshot.id.clone(),
                        path: member.path,
                        anchors: None,
                        anchors_loaded: member.projection.is_none(),
                    };
                    match targets.entry(url.to_string()) {
                        std::collections::btree_map::Entry::Vacant(entry) => {
                            entry.insert(Some(target));
                        }
                        std::collections::btree_map::Entry::Occupied(mut entry) => {
                            entry.insert(None);
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
                Error::integrity("W3C reference target is outside selected evidence.")
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
                        Error::capacity("W3C referenced anchor cache exceeds its bound.")
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
        if tool == "w3c_catalog_search" {
            return self.catalog_search(input).await;
        }
        let selector = Selector {
            standard: if tool == "w3c_references"
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
        if matches!(tool, "w3c_snapshots" | "w3c_history") {
            return self.discovery(tool, input, cancel).await;
        }
        let (view, snapshots) = self.selections(&selector).await?;
        let mut reference_targets = if tool == "w3c_references" {
            self.reference_targets(&snapshots, &cancel).await?
        } else {
            ReferenceTargets::new()
        };
        let mut referenced_anchor_bytes = 0usize;
        let identity = view
            .as_ref()
            .map(|v| &v.id)
            .or_else(|| snapshots.first().map(|s| &s.id));
        let fingerprint = digest(&(
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
        ))?;
        let start = position(
            &fingerprint,
            input.offset,
            input.cursor.as_deref(),
            input.limit,
        )?;
        let mut items = Vec::new();
        if tool == "w3c_references"
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
                if tool == "w3c_references" {
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
                                Error::capacity("W3C source anchor metadata exceeds its bound.")
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
                            && let Ok(target) = url::Url::parse(&reference.target).or_else(|_| {
                                url::Url::parse(member_source_url(snapshot, &member))
                                    .and_then(|base| base.join(&reference.target))
                            })
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
                            && input.standard.as_ref().is_some_and(|standard| {
                                resolved["specification"].as_str() != Some(standard.as_str())
                            })
                        {
                            continue;
                        }
                        let value = json!({"specification":snapshot.standard,"snapshot":snapshot.id,"path":member.path,"reference":reference,"resolution":resolved,"source_metadata":member_metadata(snapshot,&member),"citation":member_citation(snapshot,&member)});
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
                        let value = json!({"specification":snapshot.standard,"snapshot":snapshot.id,"path":member.path,"symbol_index":symbol_index,"symbol":{"kind":symbol.kind,"name":symbol.name,"anchor":symbol.anchor,"scope":symbol.scope,"text_bytes":symbol.text.len()},"resource_uri":symbol_resource(snapshot,&member.path,symbol_index),"source_metadata":member_metadata(snapshot,&member),"citation":member_citation(snapshot,&member)});
                        if matches_query(&value, input.query.as_deref()) {
                            items.push(value);
                        }
                    }
                }
                if items.len() > MAX_SCAN
                    || serde_json::to_vec(&items)
                        .map_err(|_| Error::integrity("Invalid W3C result."))?
                        .len()
                        > MAX_OUTPUT
                {
                    return Err(Error::capacity("W3C result enumeration exceeds its bound."));
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
            match self.corpus.store().w3c_state("default").await? {
                Some(_) => Some(self.corpus.view(None).await?),
                None => None,
            }
        };
        let catalog = if let Some(view) = &view {
            retained::<Catalog>(
                self.corpus
                    .store()
                    .w3c_get("catalogs", &view.catalog)
                    .await?
                    .ok_or_else(|| Error::integrity("W3C catalog missing."))?
                    .data,
            )?
        } else {
            self.corpus.catalog().await?
        };
        if input.view.is_none()
            && devres_domain::unix_now().saturating_sub(catalog.observed_at) > 7 * 86400
        {
            return Err(Error::unavailable(
                "W3C default catalog is older than seven days.",
            ));
        }
        let fingerprint = digest(&("catalog", &catalog.id, &input.standard, &input.query))?;
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
            let value = json!({"specification":standard,"snapshot":view.as_ref().and_then(|v|v.snapshots.get(&standard.id)),"validated_at":view.as_ref().and_then(|v|v.validations.get(&standard.id))});
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
            if tool != "w3c_history" {
                return Err(Error::invalid("Ref observations belong to w3c_history."));
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
                "W3C history_type must be revisions or refs.",
            ));
        }
        if !(1..=100).contains(&input.limit)
            || input.offset > 10_000
            || input.cursor.as_ref().is_some_and(|c| c.len() > 16384)
        {
            return Err(Error::invalid("Invalid W3C discovery page."));
        }
        let cursor: Option<HistoryCursor> = input
            .cursor
            .as_ref()
            .map(|c| {
                serde_json::from_slice(
                    &URL_SAFE_NO_PAD
                        .decode(c)
                        .map_err(|_| Error::invalid("Invalid W3C history cursor."))?,
                )
                .map_err(|_| Error::invalid("Invalid W3C history cursor."))
            })
            .transpose()?;
        let cutoff = match (&cursor, input.history_snapshot) {
            (Some(c), Some(cutoff)) if c.cutoff != cutoff => {
                return Err(Error::invalid(
                    "W3C history cutoff differs from the cursor.",
                ));
            }
            (Some(c), _) => c.cutoff,
            (_, Some(cutoff)) => cutoff,
            _ => self.corpus.store().w3c_cutoff().await?,
        };
        if cutoff < 0 || cutoff > self.corpus.store().w3c_cutoff().await? {
            return Err(Error::invalid("Invalid W3C history cutoff."));
        }
        let fingerprint = digest(&(
            tool,
            cutoff,
            &input.standard,
            &input.repository,
            &input.query,
            &input.path,
        ))?;
        let mut after = if let Some(c) = &cursor {
            if c.skip > 10_000
                || c.fingerprint != fingerprint
                || c.after < 0
                || c.after > cutoff
                || input.offset != 0
            {
                return Err(Error::invalid(
                    "W3C history cursor does not match this query.",
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
                .w3c_rows("snapshots", after, 100, Some(cutoff))
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
                if tool == "w3c_history" {
                    if snapshot.parents.len() > 100 {
                        return Err(Error::capacity("W3C history parent bound exceeded."));
                    }
                    let mut changes = Vec::new();
                    for parent in &snapshot.parents {
                        check(deadline, &cancel)?;
                        let previous = self
                            .corpus
                            .snapshot_for_revision(
                                &snapshot.standard,
                                &snapshot.repository,
                                parent,
                                &snapshot.representation,
                            )
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
            .w3c_rows("snapshots", after, 1, Some(cutoff))
            .await?
            .is_empty();
        let next = if more {
            Some(
                URL_SAFE_NO_PAD.encode(
                    serde_json::to_vec(&HistoryCursor {
                        fingerprint,
                        after,
                        cutoff,
                        skip,
                    })
                    .map_err(|_| Error::integrity("Invalid W3C history cursor."))?,
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
            return Err(Error::invalid("Invalid W3C ref page."));
        }
        let cursor: Option<RefHistoryCursor> = input
            .cursor
            .as_ref()
            .map(|c| {
                serde_json::from_slice(
                    &URL_SAFE_NO_PAD
                        .decode(c)
                        .map_err(|_| Error::invalid("Invalid W3C ref cursor."))?,
                )
                .map_err(|_| Error::invalid("Invalid W3C ref cursor."))
            })
            .transpose()?;
        let cutoff = match (&cursor, input.history_snapshot) {
            (Some(c), Some(cutoff)) if cutoff != c.cutoff => {
                return Err(Error::invalid("W3C ref cutoff differs from the cursor."));
            }
            (Some(c), _) => c.cutoff,
            (_, Some(cutoff)) => cutoff,
            _ => self.corpus.store().w3c_cutoff().await?,
        };
        if cutoff < 0 || cutoff > self.corpus.store().w3c_cutoff().await? {
            return Err(Error::invalid("Invalid W3C history cutoff."));
        }
        let fingerprint = digest(&(
            "refs",
            cutoff,
            &input.repository,
            &input.reference,
            &input.query,
        ))?;
        if let Some(c) = &cursor
            && (c.fingerprint != fingerprint
                || c.after < 0
                || c.after > cutoff
                || c.entry > 10_000
                || c.skip > 10_000
                || input.offset != 0)
        {
            return Err(Error::invalid("W3C ref cursor does not match the query."));
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
                .w3c_rows("observations", after, 4, Some(cutoff))
                .await?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                scanned += 1;
                check(deadline, &cancel)?;
                let observation: crate::w3c_git::Observation = retained(row.data)?;
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
                .w3c_rows("observations", after, 1, Some(cutoff))
                .await?
                .is_empty();
        let next = if more {
            Some(
                URL_SAFE_NO_PAD.encode(
                    serde_json::to_vec(&RefHistoryCursor {
                        fingerprint,
                        after,
                        entry,
                        cutoff,
                        skip,
                    })
                    .map_err(|_| Error::integrity("Invalid W3C ref cursor."))?,
                ),
            )
        } else {
            None
        };
        Ok(
            json!({"history_type":"refs","history_snapshot":cutoff,"items":items,"next_cursor":next,"scanned":scanned,"coverage":"Observed advertised refs only; earlier observations retain deleted refs."}),
        )
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
            if old.map(|member| &member.oid) != new.map(|member| &member.oid) {
                changes.push(json!({"path":key,"change":if old.is_none(){"added"}else if new.is_none(){"removed"}else{"changed"},"before":old.map(|member|&member.oid),"after":new.map(|member|&member.oid),"before_source":old.map(|member|member_metadata(before,member)),"after_source":new.map(|member|member_metadata(after,member))}));
            }
            if changes.len() > 1000 {
                return Err(Error::capacity(
                    "W3C comparison exceeds its change bound; select a path.",
                ));
            }
        }
        Ok(json!(changes))
    }
    async fn member_map(
        &self,
        snapshot: &Snapshot,
        cancel: &CancellationToken,
    ) -> Result<BTreeMap<String, Member>> {
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
                return Err(Error::capacity("W3C comparison membership bound exceeded."));
            }
            for row in rows {
                require_member_license(snapshot, &row)?;
                result.insert(comparison_path(snapshot, &row.path), row);
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
        require_content_license(&before)?;
        require_content_license(&after)?;
        if before.representation != after.representation {
            return Err(Error::invalid(
                "W3C comparisons require the same specification and representation family.",
            ));
        }
        if before.representation != "source"
            && let Some(path) = input.path.clone()
            && (self.corpus.member(&before, &path).await?.is_some()
                || self.corpus.member(&after, &path).await?.is_some())
        {
            let owner = if self.corpus.member(&before, &path).await?.is_some() {
                &before
            } else {
                &after
            };
            input.path = Some(comparison_path(owner, &path));
        }
        if !matches!(input.mode.as_str(), "text" | "symbols" | "source") {
            return Err(Error::invalid(
                "W3C comparison mode must be text, symbols or source.",
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
        let fingerprint = digest(&(
            &before.id,
            &after.id,
            &input.mode,
            &input.anchor,
            &input.path,
        ))?;
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
                        "W3C comparison membership exceeds its bound.",
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
                    "Selected W3C comparison has an unprocessed side; use original-source comparison or a qualified path.",
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
        let url = url::Url::parse(uri).map_err(|_| Error::invalid("Invalid W3C resource URI."))?;
        if url.scheme() != "devres"
            || url.host_str() != Some("w3c")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.port().is_some()
            || url.fragment().is_some()
        {
            return Err(Error::invalid("Invalid W3C resource URI."));
        }
        let parts: Vec<_> = url.path().trim_start_matches('/').split('/').collect();
        if parts.len() != 4 || !valid_hash(parts[1]) {
            return Err(Error::invalid(
                "W3C resources bind specification, snapshot, representation and encoded path.",
            ));
        }
        let path = String::from_utf8(
            URL_SAFE_NO_PAD
                .decode(parts[3])
                .map_err(|_| Error::invalid("Invalid W3C resource path."))?,
        )
        .map_err(|_| Error::invalid("Invalid W3C resource path."))?;
        if URL_SAFE_NO_PAD.encode(path.as_bytes()) != parts[3] {
            return Err(Error::invalid("Noncanonical W3C resource path."));
        }
        let mut input = json!({"specification":parts[0],"snapshot":parts[1],"representation":parts[2],"path":path});
        let mut seen = BTreeSet::new();
        for (key, value) in url.query_pairs() {
            if !seen.insert(key.to_string()) {
                return Err(Error::invalid("Duplicate W3C resource option."));
            }
            match key.as_ref() {
                "offset" | "limit" => {
                    input[key.as_ref()] = json!(
                        value
                            .parse::<usize>()
                            .map_err(|_| Error::invalid("Invalid W3C resource page."))?
                    );
                }
                "section_index" if parts[2] == "text" => {
                    input["section_index"] = json!(
                        value
                            .parse::<usize>()
                            .map_err(|_| Error::invalid("Invalid W3C section index."))?
                    );
                }
                "symbol_index" if parts[2] == "symbol" => {
                    input["symbol_index"] = json!(
                        value
                            .parse::<usize>()
                            .map_err(|_| Error::invalid("Invalid W3C symbol index."))?
                    );
                }
                "anchor" => input["anchor"] = json!(value.as_ref()),
                "name" | "kind" if parts[2] == "symbol" => {
                    input[key.as_ref()] = json!(value.as_ref())
                }
                _ => return Err(Error::invalid("Unknown W3C resource option.")),
            }
        }
        let output = if parts[2] == "symbol" {
            input.as_object_mut().map(|m| m.remove("representation"));
            self.call("w3c_symbol_get", input).await?
        } else {
            self.call("w3c_get", input).await?
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
#[cfg(test)]
fn resolve_reference(target: &str, source: &Snapshot, snapshots: &[Snapshot]) -> Value {
    if let Some(anchor) = target.strip_prefix('#') {
        return json!({"specification":source.standard,"snapshot":source.id,"anchor":anchor,"state":"same_document_anchor_unverified"});
    }
    if let Ok(mut target_url) = url::Url::parse(target) {
        let anchor = target_url.fragment().map(str::to_owned);
        target_url.set_fragment(None);
        for snapshot in snapshots {
            // W3C publications share www.w3.org: host equality alone cannot identify a report.
            if snapshot.representation == "source" {
                continue;
            }
            if let Ok(mut publication_url) = url::Url::parse(&snapshot.source_url) {
                publication_url.set_fragment(None);
                if publication_url == target_url {
                    return json!({"specification":snapshot.standard,"snapshot":snapshot.id,"anchor":anchor,"state":"captured_document_anchor_unverified"});
                }
            }
        }
    }
    json!({"state":"unresolved_external","target":target})
}

pub fn schemas() -> Vec<Value> {
    let id = json!({"type":"string","minLength":1,"maxLength":256});
    let hash = json!({"type":"string","pattern":"^[a-f0-9]{64}$"});
    let path = json!({"type":"string","minLength":1,"maxLength":4096});
    let query = json!({"type":"string","minLength":1,"maxLength":256});
    let common = json!({"specification":id,"snapshot":hash,"view":hash,"query":query,"offset":{"type":"integer","minimum":0,"maximum":10000,"default":0},"limit":{"type":"integer","minimum":1,"maximum":100,"default":20},"cursor":{"type":"string","maxLength":16384}});
    let mut tools = Vec::new();
    let mut add = |name: &str, description: &str, properties: Value, required: Vec<&str>| {
        tools.push(json!({"name":name,"description":description,"inputSchema":{"type":"object","properties":properties,"required":required,"additionalProperties":false},"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}}));
    };
    let mut catalog_properties = common.clone();
    if let Some(map) = catalog_properties.as_object_mut() {
        map.remove("snapshot");
    }
    add(
        "w3c_catalog_search",
        "Search the captured W3C specifications catalog; publication and processing gaps remain explicit. Select a view for historical catalog evidence.",
        catalog_properties,
        vec![],
    );
    let mut search = common.clone();
    search["mode"] = json!({"enum":["technical","english"],"default":"technical"});
    for key in ["edition", "path", "kind"] {
        search[key] = path.clone();
    }
    add(
        "w3c_search",
        "Search immutable W3C sections using selected-corpus BM25. Defaults use canonical current editions; reuse view/snapshot and cursor.",
        search,
        vec!["query"],
    );
    let get = json!({"specification":id,"snapshot":hash,"view":hash,"path":path,"anchor":path,"section_index":{"type":"integer","minimum":0,"description":"Zero-based position in this captured document's ordered sections; requires path and excludes anchor."},"representation":{"enum":["text","source","bytes"],"default":"text"},"offset":{"type":"integer","minimum":0,"default":0},"limit":{"type":"integer","minimum":1,"maximum":32768,"default":32768}});
    add(
        "w3c_get",
        "Read capture-fixed specification text, an anchored section, original source, or base64 bytes. Text offsets count UTF-8 bytes.",
        get,
        vec!["specification"],
    );
    for (name, description) in [(
        "w3c_symbol_search",
        "Search original definitions, Web IDL declarations and explicitly marked algorithms.",
    )] {
        let mut props = common.clone();
        props["kind"] = json!({"enum":["definition","idl","algorithm"]});
        for key in ["name", "anchor", "path"] {
            props[key] = path.clone();
        }
        add(name, description, props, vec![]);
    }
    let symbol_get = json!({"specification":id,"snapshot":hash,"view":hash,"path":path,"symbol_index":{"type":"integer","minimum":0,"description":"Zero-based position in this captured document's ordered symbols; requires path and is local to the selected snapshot."},"name":path,"anchor":path,"kind":{"enum":["definition","idl","algorithm"]},"offset":{"type":"integer","minimum":0,"default":0},"limit":{"type":"integer","minimum":1,"maximum":32768,"default":32768}});
    add(
        "w3c_symbol_get",
        "Read one unambiguous captured symbol in bounded UTF-8 pages with original text and provenance.",
        symbol_get,
        vec!["specification"],
    );
    let mut refs = common.clone();
    refs["direction"] = json!({"enum":["incoming","outgoing"],"default":"outgoing"});
    for key in ["target", "anchor", "path"] {
        refs[key] = path.clone();
    }
    add(
        "w3c_references",
        "Inspect captured incoming/outgoing links. Target resolution uses selected evidence only; external references are never fetched.",
        refs,
        vec![],
    );
    for (name, description) in [
        (
            "w3c_snapshots",
            "Discover immutable source/publication snapshots with a frozen history cutoff.",
        ),
        (
            "w3c_history",
            "Inspect retained revisions and changes against each ordered parent; missing parent projections remain explicit.",
        ),
    ] {
        let mut props = common.clone();
        props["history_snapshot"] = json!({"type":"integer","minimum":0});
        props["path"] = path.clone();
        if name == "w3c_history" {
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
        "w3c_compare",
        "Compare two immutable snapshots of the same specification and representation family; no normative verdict is inferred.",
        compare,
        vec!["specification", "before", "after"],
    );
    add(
        "w3c_corpus_status",
        "Inspect separate W3C acquisition, ancestry, projection, indexing and freshness coverage. No collection controls are exposed.",
        json!({}),
        vec![],
    );
    for tool in &mut tools {
        match tool["name"].as_str() {
            Some("w3c_get") => {
                tool["inputSchema"]["allOf"] = json!([{"if":{"required":["section_index"]},"then":{"required":["path"],"not":{"required":["anchor"]},"properties":{"representation":{"const":"text"}}}}]);
            }
            Some("w3c_symbol_get") => {
                tool["inputSchema"]["allOf"] =
                    json!([{"if":{"required":["symbol_index"]},"then":{"required":["path"]}}]);
            }
            _ => {}
        }
    }
    tools
}

#[cfg(test)]
#[path = "w3c_research_tests.rs"]
mod tests;
