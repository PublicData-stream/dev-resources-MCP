//! Fixed official metadata discovery. Neither source expands the API corpus by itself.
use crate::w3c_catalog;
use devres_application::w3c::{Catalog, Standard};
use devres_domain::{Error, Result};
use html5ever::{
    tendril::StrTendril,
    tokenizer::{
        BufferQueue, TagKind, Token, TokenSink, TokenSinkResult, Tokenizer, TokenizerOpts,
        states::RawKind,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;

pub const POLICY_VERSION: u32 = 1;
pub const MAX_TR_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_BROWSER_BYTES: usize = 8 * 1024 * 1024;
const MAX_ITEMS: usize = 10_000;
const MAX_STRING: usize = 4096;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryOperation {
    TrIndex,
    BrowserSpecs,
}
impl DiscoveryOperation {
    pub fn url(&self) -> Result<String> {
        Ok(match self {
            Self::TrIndex => "https://www.w3.org/TR/",
            Self::BrowserSpecs => "https://w3c.github.io/browser-specs/index.json",
        }
        .into())
    }
    pub fn host(&self) -> &'static str {
        match self {
            Self::TrIndex => "www.w3.org",
            Self::BrowserSpecs => "w3c.github.io",
        }
    }
    pub fn media_type(&self) -> &'static str {
        match self {
            Self::TrIndex => "text/html",
            Self::BrowserSpecs => "application/json",
        }
    }
    pub fn max_bytes(&self) -> usize {
        match self {
            Self::TrIndex => MAX_TR_BYTES,
            Self::BrowserSpecs => MAX_BROWSER_BYTES,
        }
    }
}
fn malformed() -> Error {
    Error::integrity("Malformed W3C discovery metadata.")
}
fn capacity() -> Error {
    Error::capacity("W3C discovery metadata exceeds its processing bound.")
}
fn check(cancel: &CancellationToken, deadline: Instant) -> Result<()> {
    if cancel.is_cancelled() {
        return Err(Error::new("cancelled", "W3C discovery canceled."));
    }
    if Instant::now() >= deadline {
        return Err(capacity());
    }
    Ok(())
}
fn slug(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|v| v.is_ascii_alphanumeric() || b"-_".contains(&v))
}
fn canonical_report(value: &str) -> Option<(String, String)> {
    let mut url = w3c_catalog::public_https(value).ok()?;
    if !matches!(url.host_str(), Some("www.w3.org" | "w3.org")) || url.fragment().is_some() {
        return None;
    }
    let parts: Vec<_> = url.path().trim_matches('/').split('/').collect();
    if parts.len() != 2 || parts[0] != "TR" || !slug(parts[1]) {
        return None;
    }
    let shortname = parts[1].to_owned();
    url.set_host(Some("www.w3.org")).ok()?;
    url.set_path(&format!("/TR/{shortname}/"));
    Some((shortname, url.to_string()))
}
fn normalize(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}
fn append_bounded(output: &mut String, text: &str, limit: usize) {
    let remaining = limit.saturating_sub(output.len());
    let mut end = text.len().min(remaining);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    output.push_str(&text[..end]);
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct TrReport {
    pub shortname: String,
    pub url: String,
    pub title: String,
    pub status_context: String,
}
#[derive(Default)]
struct TrState {
    reports: BTreeMap<String, TrReport>,
    anchor: Option<(String, String)>,
    current: Option<String>,
    raw_hidden: Option<String>,
    template_depth: usize,
    excluded_depth: usize,
    tokens: usize,
    completed: usize,
    failed: bool,
}
struct TrSink<'a> {
    state: RefCell<TrState>,
    cancel: &'a CancellationToken,
    deadline: Instant,
}
impl TokenSink for TrSink<'_> {
    type Handle = ();
    fn process_token(&self, token: Token, _: u64) -> TokenSinkResult<()> {
        let mut state = self.state.borrow_mut();
        state.tokens += 1;
        if !matches!(token, Token::ParseError(_) | Token::EOFToken) {
            state.completed += 1;
        }
        if state.failed || state.tokens > 4_000_000 || check(self.cancel, self.deadline).is_err() {
            state.failed = true;
            return TokenSinkResult::Continue;
        }
        if let Token::TagToken(tag) = &token {
            if tag.attrs.len() > 128
                || tag.name.len() > 256
                || tag
                    .attrs
                    .iter()
                    .map(|a| a.name.local.len() + a.value.len())
                    .sum::<usize>()
                    > 128 * 1024
            {
                state.failed = true;
                return TokenSinkResult::Continue;
            }
            if state.raw_hidden.as_deref() == Some(&*tag.name) && tag.kind == TagKind::EndTag {
                state.raw_hidden = None;
                return TokenSinkResult::Continue;
            }
            if state.raw_hidden.is_none() && tag.kind == TagKind::StartTag {
                let raw = match &*tag.name {
                    "script" => Some(RawKind::ScriptData),
                    "style" | "iframe" | "noscript" | "noembed" | "noframes" | "xmp" => {
                        Some(RawKind::Rawtext)
                    }
                    "textarea" | "title" => Some(RawKind::Rcdata),
                    _ => None,
                };
                if let Some(raw) = raw {
                    state.raw_hidden = Some(tag.name.to_string());
                    return TokenSinkResult::RawData(raw);
                }
            }
            if &*tag.name == "template" {
                if tag.kind == TagKind::StartTag {
                    state.template_depth = state.template_depth.saturating_add(1);
                } else {
                    state.template_depth = state.template_depth.saturating_sub(1);
                }
            }
            if matches!(&*tag.name, "pre" | "code") {
                if tag.kind == TagKind::StartTag {
                    state.excluded_depth = state.excluded_depth.saturating_add(1);
                } else {
                    state.excluded_depth = state.excluded_depth.saturating_sub(1);
                }
            }
        }
        if state.raw_hidden.is_some() || state.template_depth > 0 || state.excluded_depth > 0 {
            return TokenSinkResult::Continue;
        }
        match token {
            Token::TagToken(tag) if &*tag.name == "a" && tag.kind == TagKind::StartTag => {
                state.anchor = None;
                if let Some(href) = tag
                    .attrs
                    .iter()
                    .find(|a| &*a.name.local == "href")
                    .map(|a| &*a.value)
                    && href.len() <= MAX_STRING
                    && let Ok(url) =
                        url::Url::parse("https://www.w3.org/TR/").and_then(|base| base.join(href))
                    && let Some((shortname, canonical)) = canonical_report(url.as_str())
                {
                    if !state.reports.contains_key(&shortname) && state.reports.len() >= MAX_ITEMS {
                        state.failed = true;
                        return TokenSinkResult::Continue;
                    }
                    state.reports.entry(shortname.clone()).or_insert(TrReport {
                        shortname: shortname.clone(),
                        url: canonical,
                        title: String::new(),
                        status_context: String::new(),
                    });
                    state.current = Some(shortname.clone());
                    state.anchor = Some((shortname, String::new()));
                }
            }
            Token::TagToken(tag) if &*tag.name == "a" && tag.kind == TagKind::EndTag => {
                if let Some((shortname, title)) = state.anchor.take()
                    && let Some(report) = state.reports.get_mut(&shortname)
                    && report.title.is_empty()
                {
                    report.title = normalize(&title);
                }
            }
            Token::CharacterTokens(text) => {
                if let Some((_, title)) = &mut state.anchor {
                    append_bounded(title, &text, MAX_STRING);
                } else if let Some(current) = state.current.clone()
                    && let Some(report) = state.reports.get_mut(&current)
                {
                    append_bounded(&mut report.status_context, &text, 1024);
                }
            }
            _ => {}
        }
        TokenSinkResult::Continue
    }
}
pub(crate) fn tr_reports(
    bytes: &[u8],
    cancel: &CancellationToken,
) -> Result<BTreeMap<String, TrReport>> {
    if bytes.len() > MAX_TR_BYTES {
        return Err(capacity());
    }
    let source = std::str::from_utf8(bytes).map_err(|_| malformed())?;
    let deadline = Instant::now() + Duration::from_secs(15);
    check(cancel, deadline)?;
    let tokenizer = Tokenizer::new(
        TrSink {
            state: RefCell::new(TrState::default()),
            cancel,
            deadline,
        },
        TokenizerOpts::default(),
    );
    let input = BufferQueue::default();
    let mut offset = 0;
    let mut pending = 0;
    while offset < source.len() {
        check(cancel, deadline)?;
        let mut end = offset.saturating_add(4096).min(source.len());
        while !source.is_char_boundary(end) {
            end -= 1;
        }
        let completed = tokenizer.sink.state.borrow().completed;
        input.push_back(StrTendril::from_slice(&source[offset..end]));
        let _ = tokenizer.feed(&input);
        if tokenizer.sink.state.borrow().completed == completed {
            pending += end - offset;
        } else {
            pending = 0;
        }
        if pending > 128 * 1024 {
            return Err(capacity());
        }
        if tokenizer.sink.state.borrow().failed {
            check(cancel, deadline)?;
            return Err(capacity());
        }
        offset = end;
    }
    tokenizer.end();
    check(cancel, deadline)?;
    let mut state = tokenizer.sink.state.into_inner();
    if state.failed {
        return Err(capacity());
    }
    if let Some((shortname, title)) = state.anchor.take()
        && let Some(report) = state.reports.get_mut(&shortname)
        && report.title.is_empty()
    {
        report.title = normalize(&title);
    }
    if state.reports.is_empty() {
        return Err(malformed());
    }
    for report in state.reports.values_mut() {
        report.status_context = normalize(&report.status_context);
    }
    Ok(state.reports)
}
pub(crate) fn reconcile_tr(
    catalog: &mut Catalog,
    bytes: &[u8],
    evidence: &Value,
    cancel: &CancellationToken,
) -> Result<()> {
    let reports = tr_reports(bytes, cancel)?;
    let api_ids: BTreeSet<_> = catalog.standards.iter().map(|s| s.id.clone()).collect();
    let tr_ids: BTreeSet<_> = reports.keys().cloned().collect();
    let api_only: Vec<_> = api_ids.difference(&tr_ids).cloned().collect();
    let tr_only: Vec<_> = tr_ids.difference(&api_ids).cloned().collect();
    for standard in &mut catalog.standards {
        if let Some(report) = reports.get(&standard.id) {
            standard.metadata["tr_index"] = json!({"policy_version":POLICY_VERSION,"evidence":evidence,"report":report,"role":"independent_listing_observation"});
        }
    }
    if !api_only.is_empty() || !tr_only.is_empty() {
        catalog.gaps.push(json!({"kind":"tr_api_inventory_mismatch","api_only_count":api_only.len(),"tr_only_count":tr_only.len(),"api_only":api_only.iter().take(100).collect::<Vec<_>>(),"tr_only":tr_only.iter().take(100).collect::<Vec<_>>(),"truncated":api_only.len()>100 || tr_only.len()>100,"evidence":evidence,"interpretation":"Listing scope and observation times can differ; unmatched rows never expand source admission."}));
    }
    Ok(())
}
fn bounded_text(value: Option<&Value>) -> Option<&str> {
    value.and_then(Value::as_str).filter(|value| {
        !value.is_empty() && value.len() <= MAX_STRING && !value.chars().any(char::is_control)
    })
}
fn same_report(standard: &Standard, value: &str) -> bool {
    canonical_report(value).is_some_and(|(_, candidate)| {
        canonical_report(&standard.url).is_some_and(|(_, expected)| candidate == expected)
    }) || ["latest_tr_url", "publication_url"]
        .iter()
        .any(|key| standard.metadata[*key].as_str() == Some(value))
}
fn source_mapping(repository: &str, source_path: Option<&str>, evidence: &Value) -> Result<Value> {
    let (repo, mut mapping) = w3c_catalog::repository_mapping(repository)?;
    if let Some(path) = source_path {
        if !crate::w3c_inventory::valid_path(path) || path.len() > MAX_STRING {
            return Err(malformed());
        }
        let prefix = path.rsplit_once('/').map_or("", |(prefix, _)| prefix);
        mapping["kind"] = json!("explicit_source_path");
        mapping["prefix"] = json!(prefix);
        mapping["entrypoint"] = json!(path);
    }
    mapping["evidence_url"] = json!(DiscoveryOperation::BrowserSpecs.url()?);
    mapping["discovery_evidence"] = evidence.clone();
    Ok(json!({"repository":repo.as_str(),"source_mapping":mapping}))
}
/// Refine an already publisher-admitted repository; discovery hints alone never clone a source.
pub(crate) fn apply_mapping_hint(standard: &mut Standard) -> Result<()> {
    let candidate = standard.metadata["browser_specs"]["mapping_candidate"].clone();
    let Some(repository) = candidate["repository"].as_str() else {
        return Ok(());
    };
    if standard.repository.is_empty() {
        return Ok(());
    }
    let admitted = crate::w3c_git::Repo::new(&standard.repository)?;
    if admitted.as_str() != repository {
        standard.metadata["browser_specs"]["mapping_gap"] =
            json!("conflicts_with_publisher_repository");
        return Ok(());
    }
    let proposed = &candidate["source_mapping"];
    let current = &standard.metadata["source_mapping"];
    let prefix = current["prefix"].as_str().unwrap_or("");
    let proposed_prefix = proposed["prefix"].as_str().unwrap_or("");
    let proposed_entry = proposed["entrypoint"].as_str().unwrap_or("");
    let compatible = current.is_null()
        || current["kind"] == "unresolved"
        || current["kind"] == "repository_root"
        || prefix == proposed_prefix
        || !proposed_entry.is_empty() && prefix == proposed_entry;
    if !compatible {
        standard.metadata["browser_specs"]["mapping_gap"] =
            json!("conflicts_with_publisher_source_path");
        return Ok(());
    }
    let mut mapping = proposed.clone();
    if mapping["ref"].is_null() && !current["ref"].is_null() {
        mapping["ref"] = current["ref"].clone();
    }
    mapping["qualification"] = json!("publisher_repository_with_supplemental_source_path");
    standard.metadata["source_mapping"] = mapping;
    standard.metadata["browser_specs"]["mapping_applied"] = json!(true);
    Ok(())
}
pub(crate) fn enrich_browser_specs(
    catalog: &mut Catalog,
    bytes: &[u8],
    evidence: &Value,
    cancel: &CancellationToken,
) -> Result<()> {
    if bytes.len() > MAX_BROWSER_BYTES {
        return Err(capacity());
    }
    let deadline = Instant::now() + Duration::from_secs(15);
    check(cancel, deadline)?;
    let rows: Vec<Value> = serde_json::from_slice(bytes).map_err(|_| malformed())?;
    check(cancel, deadline)?;
    if rows.len() > MAX_ITEMS {
        return Err(capacity());
    }
    let mut seen = BTreeSet::new();
    let mut originals: BTreeMap<String, Standard> = BTreeMap::new();
    let mut conflicts = Vec::new();
    for row in rows {
        check(cancel, deadline)?;
        if row["organization"].as_str() != Some("W3C") {
            continue;
        }
        let Some(shortname) = bounded_text(row.get("shortname")).filter(|v| slug(v)) else {
            continue;
        };
        let Some(report_url) = bounded_text(row.get("url")) else {
            continue;
        };
        let selected = catalog
            .standards
            .iter()
            .position(|s| s.id == shortname)
            .or_else(|| {
                catalog
                    .standards
                    .iter()
                    .position(|s| same_report(s, report_url))
            });
        let Some(index) = selected else {
            continue;
        };
        let standard = &mut catalog.standards[index];
        if !same_report(standard, report_url) {
            conflicts.push(json!({"specification":standard.id,"kind":"browser_specs_report_url_conflict","row_shortname":shortname}));
            continue;
        }
        if !seen.insert(standard.id.clone()) {
            conflicts.push(json!({"specification":standard.id,"kind":"browser_specs_duplicate_report_mapping"}));
            if let Some(original) = originals.get(&standard.id) {
                *standard = original.clone();
            }
            standard.metadata["browser_specs"] = json!({"policy_version":POLICY_VERSION,"evidence":evidence,"mapping_gap":"duplicate_report_mapping"});
            continue;
        }
        originals.insert(standard.id.clone(), standard.clone());
        let nightly = &row["nightly"];
        let nightly_url =
            bounded_text(nightly.get("url")).filter(|url| w3c_catalog::public_https(url).is_ok());
        let repository = bounded_text(nightly.get("repository"));
        let source_path = bounded_text(nightly.get("sourcePath"));
        let descriptor = json!({"shortname":shortname,"url":report_url,"organization":"W3C","nightly":{"url":nightly_url,"repository":repository,"sourcePath":source_path}});
        standard.metadata["browser_specs"] = json!({"policy_version":POLICY_VERSION,"evidence":evidence,"descriptor":descriptor,"role":"supplemental_mapping_not_inventory_authority"});
        let invalid_descriptor = (!nightly["repository"].is_null() && repository.is_none())
            || (!nightly["sourcePath"].is_null() && source_path.is_none())
            || (!nightly["url"].is_null() && nightly_url.is_none());
        if invalid_descriptor {
            standard.metadata["browser_specs"]["mapping_gap"] = json!("invalid_source_descriptor");
        } else if let Some(repository) = repository {
            match source_mapping(repository, source_path, evidence) {
                Ok(candidate) => {
                    standard.metadata["browser_specs"]["mapping_candidate"] = candidate
                }
                Err(error) => {
                    standard.metadata["browser_specs"]["mapping_gap"] = json!({"code":error.code,"reason":"unsupported_or_unqualified_source_descriptor"})
                }
            }
        }
        if !invalid_descriptor {
            apply_mapping_hint(standard)?;
        }
        if let Some(gap) = standard.metadata["browser_specs"].get("mapping_gap") {
            conflicts.push(json!({"specification":standard.id,"kind":"browser_specs_source_mapping_gap","gap":gap}));
        }
    }
    if !conflicts.is_empty() {
        catalog.gaps.push(json!({"kind":"browser_specs_mapping_gaps","count":conflicts.len(),"items":conflicts.iter().take(100).collect::<Vec<_>>(),"truncated":conflicts.len()>100,"evidence":evidence}));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn specification(id: &str) -> Standard {
        Standard {
            id: id.into(),
            title: format!("Synthetic {id}"),
            url: format!("https://www.w3.org/TR/{id}/"),
            repository: String::new(),
            metadata: json!({}),
        }
    }
    fn catalog() -> Catalog {
        Catalog {
            id: "api-catalog-identity".into(),
            observed_at: 123,
            standards: vec![specification("css-color-4")],
            gaps: vec![],
        }
    }
    fn evidence() -> Value {
        json!({"source_url":"https://w3c.github.io/browser-specs/index.json","body_hash":"synthetic-body-hash","observed_at":456})
    }
    fn descriptor() -> Value {
        json!({"shortname":"css-color-4","organization":"W3C","url":"https://www.w3.org/TR/css-color-4/","nightly":{"url":"https://drafts.csswg.org/css-color-4/","repository":"https://github.com/w3c/csswg-drafts","sourcePath":"css-color-4/Overview.bs"}})
    }
    #[test]
    fn operations_have_only_fixed_official_metadata_destinations() {
        assert_eq!(
            DiscoveryOperation::TrIndex.url().unwrap(),
            "https://www.w3.org/TR/"
        );
        assert_eq!(
            DiscoveryOperation::BrowserSpecs.url().unwrap(),
            "https://w3c.github.io/browser-specs/index.json"
        );
        assert_eq!(DiscoveryOperation::BrowserSpecs.host(), "w3c.github.io");
        assert_eq!(DiscoveryOperation::TrIndex.media_type(), "text/html");
        assert_eq!(
            DiscoveryOperation::BrowserSpecs.max_bytes(),
            8 * 1024 * 1024
        );
    }
    #[test]
    fn real_shaped_tr_listing_preserves_status_context_and_excludes_inert_markup() {
        let html=br#"<h1>W3C standards and drafts</h1><script>var hidden="<a href='/TR/script-only/'>bad</a>";</script><template><a href='/TR/template-only/'>bad</a></template><pre><a href='/TR/example-only/'>bad</a></pre><h2>CSS Color</h2><h3><a href='https://www.w3.org/TR/css-color-4/'>CSS Color Module Level 4</a></h3><p>Candidate Standard</p><p>26 October 2026</p><h3><a href='/TR/WCAG22/'>Web Content Accessibility Guidelines (WCAG) 2.2</a></h3><p>Standard</p><a href='/TR/2023/REC-WCAG22-20231005/'>Dated edition</a><a href='https://example.org/TR/foreign/'>External</a>"#;
        let reports = tr_reports(html, &CancellationToken::new()).unwrap();
        assert_eq!(reports.len(), 2);
        assert_eq!(reports["css-color-4"].title, "CSS Color Module Level 4");
        assert!(
            reports["css-color-4"]
                .status_context
                .contains("Candidate Standard")
        );
        assert!(reports["WCAG22"].status_context.contains("Standard"));
    }
    #[test]
    fn reconciliation_accounts_for_differences_without_admitting_extra_reports() {
        let mut catalog = catalog();
        catalog.standards.push(specification("retired-report"));
        reconcile_tr(&mut catalog,b"<a href='/TR/css-color-4/'>CSS Color4</a><p>Candidate Standard</p><a href='/TR/not-in-api/'>Extra</a>",&evidence(),&CancellationToken::new()).unwrap();
        assert_eq!(catalog.id, "api-catalog-identity");
        assert_eq!(catalog.observed_at, 123);
        assert_eq!(catalog.standards.len(), 2);
        assert_eq!(catalog.gaps[0]["api_only_count"], 1);
        assert_eq!(catalog.gaps[0]["tr_only_count"], 1);
        assert_eq!(catalog.gaps[0]["api_only"], json!(["retired-report"]));
        assert_eq!(
            catalog.standards[0].metadata["tr_index"]["evidence"]["body_hash"],
            "synthetic-body-hash"
        );
    }
    #[test]
    fn browser_specs_is_only_a_matched_metadata_hint_until_publisher_admission() {
        let mut catalog = catalog();
        let mut whatwg = descriptor();
        whatwg["organization"] = json!("WHATWG");
        whatwg["shortname"] = json!("html");
        whatwg["url"] = json!("https://html.spec.whatwg.org/");
        let mut cg = descriptor();
        cg["shortname"] = json!("cg-only");
        cg["url"] = json!("https://w3c.github.io/cg-only/");
        let rows = serde_json::to_vec(&json!([descriptor(), whatwg, cg])).unwrap();
        enrich_browser_specs(&mut catalog, &rows, &evidence(), &CancellationToken::new()).unwrap();
        assert_eq!(catalog.standards.len(), 1);
        assert!(catalog.standards[0].repository.is_empty());
        assert_eq!(
            catalog.standards[0].metadata["browser_specs"]["mapping_candidate"]["repository"],
            "https://github.com/w3c/csswg-drafts.git"
        );
        assert!(catalog.standards[0].metadata["source_mapping"].is_null());
        assert_eq!(
            catalog.standards[0].metadata["browser_specs"]["evidence"]["observed_at"],
            456
        );
        assert!(catalog.gaps.is_empty());
    }
    #[test]
    fn corroborated_shared_repository_receives_scoped_entrypoint_and_original_admission() {
        let mut catalog = catalog();
        let standard = &mut catalog.standards[0];
        standard.repository = "https://github.com/w3c/csswg-drafts.git".into();
        standard.metadata = json!({"source_mapping":{"kind":"repository_root","prefix":"","ref":"main"},"repository_admission":{"publication":"original-publisher-capture"}});
        enrich_browser_specs(
            &mut catalog,
            &serde_json::to_vec(&json!([descriptor()])).unwrap(),
            &evidence(),
            &CancellationToken::new(),
        )
        .unwrap();
        let standard = &catalog.standards[0];
        assert_eq!(standard.metadata["source_mapping"]["prefix"], "css-color-4");
        assert_eq!(
            standard.metadata["source_mapping"]["entrypoint"],
            "css-color-4/Overview.bs"
        );
        assert_eq!(standard.metadata["source_mapping"]["ref"], "main");
        assert_eq!(
            standard.metadata["repository_admission"]["publication"],
            "original-publisher-capture"
        );
        assert_eq!(
            standard.metadata["source_mapping"]["discovery_evidence"]["body_hash"],
            "synthetic-body-hash"
        );
    }
    #[test]
    fn publisher_repository_and_explicit_path_conflicts_preserve_existing_mappings() {
        for (repository, prefix, expected) in [
            (
                "https://github.com/w3c/other.git",
                "existing",
                "conflicts_with_publisher_repository",
            ),
            (
                "https://github.com/w3c/csswg-drafts.git",
                "different-report",
                "conflicts_with_publisher_source_path",
            ),
        ] {
            let mut catalog = catalog();
            catalog.standards[0].repository = repository.into();
            catalog.standards[0].metadata =
                json!({"source_mapping":{"kind":"explicit_source_path","prefix":prefix}});
            enrich_browser_specs(
                &mut catalog,
                &serde_json::to_vec(&json!([descriptor()])).unwrap(),
                &evidence(),
                &CancellationToken::new(),
            )
            .unwrap();
            assert_eq!(
                catalog.standards[0].metadata["source_mapping"]["prefix"],
                prefix
            );
            assert_eq!(
                catalog.standards[0].metadata["browser_specs"]["mapping_gap"],
                expected
            );
            assert_eq!(catalog.gaps[0]["count"], 1);
        }
    }
    #[test]
    fn duplicates_conflicting_urls_and_unsafe_source_paths_never_choose_an_arbitrary_mapping() {
        let mut catalog = catalog();
        catalog.standards[0].repository = "https://github.com/w3c/csswg-drafts.git".into();
        catalog.standards[0].metadata =
            json!({"source_mapping":{"kind":"repository_root","prefix":""}});
        let original = catalog.standards[0].metadata["source_mapping"].clone();
        let mut second = descriptor();
        second["nightly"]["sourcePath"] = json!("different/Overview.bs");
        enrich_browser_specs(
            &mut catalog,
            &serde_json::to_vec(&json!([descriptor(), second])).unwrap(),
            &evidence(),
            &CancellationToken::new(),
        )
        .unwrap();
        assert_eq!(catalog.standards[0].metadata["source_mapping"], original);
        assert_eq!(
            catalog.standards[0].metadata["browser_specs"]["mapping_gap"],
            "duplicate_report_mapping"
        );
        let mut catalog = super::tests::catalog();
        let mut wrong = descriptor();
        wrong["url"] = json!("https://www.w3.org/TR/different/");
        enrich_browser_specs(
            &mut catalog,
            &serde_json::to_vec(&json!([wrong])).unwrap(),
            &evidence(),
            &CancellationToken::new(),
        )
        .unwrap();
        assert!(catalog.standards[0].metadata["browser_specs"].is_null());
        assert_eq!(catalog.gaps[0]["count"], 1);
        let mut catalog = super::tests::catalog();
        let mut unsafe_path = descriptor();
        unsafe_path["nightly"]["sourcePath"] = json!("../secret");
        enrich_browser_specs(
            &mut catalog,
            &serde_json::to_vec(&json!([unsafe_path])).unwrap(),
            &evidence(),
            &CancellationToken::new(),
        )
        .unwrap();
        assert!(catalog.standards[0].metadata["browser_specs"]["mapping_candidate"].is_null());
        assert_eq!(catalog.gaps[0]["count"], 1);
    }
    #[test]
    fn malformed_metadata_and_cancellation_fail_with_sanitized_errors() {
        assert!(
            tr_reports(
                b"<html><h1>No reports</h1></html>",
                &CancellationToken::new()
            )
            .is_err()
        );
        assert!(
            enrich_browser_specs(
                &mut catalog(),
                b"not-json",
                &evidence(),
                &CancellationToken::new()
            )
            .is_err()
        );
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert_eq!(
            tr_reports(b"<a href='/TR/foo/'>Foo</a>", &cancel)
                .unwrap_err()
                .code,
            "cancelled"
        );
        assert_eq!(
            enrich_browser_specs(&mut catalog(), b"[]", &evidence(), &cancel)
                .unwrap_err()
                .code,
            "cancelled"
        );
        let oversized = vec![b' '; MAX_BROWSER_BYTES + 1];
        assert_eq!(
            enrich_browser_specs(
                &mut catalog(),
                &oversized,
                &evidence(),
                &CancellationToken::new()
            )
            .unwrap_err()
            .code,
            "capacity"
        );
    }
}
