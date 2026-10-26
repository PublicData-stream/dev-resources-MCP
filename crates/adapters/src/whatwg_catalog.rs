//! Official-catalog parsing and typed publication destinations. No document executes.
use crate::whatwg_git::Repo;
use devres_application::whatwg::{Catalog, Standard};
use devres_domain::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use url::Url;

pub const CATALOG_REPOSITORY: &str = "whatwg/sg";
pub const CATALOG_PATH: &str = "db.json";
pub const METADATA_VERSION: u32 = 2;

pub fn publication_host(host: &str) -> bool {
    host.strip_suffix(".spec.whatwg.org")
        .is_some_and(valid_slug)
        || host == "w3c-cg.github.io"
}
fn valid_slug(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Constructed only from catalogue-qualified publication discovery, never tool input.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicationUrl {
    url: String,
    host: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicationKind {
    Html,
    Pdf,
    Text,
    Json,
    Raw,
}
impl PublicationKind {
    pub fn representation(self) -> &'static str {
        match self {
            Self::Html => "html",
            Self::Pdf => "pdf",
            Self::Text => "text",
            Self::Json => "json",
            Self::Raw => "raw",
        }
    }
    pub fn media_type(self) -> &'static str {
        match self {
            Self::Html => "text/html",
            Self::Pdf => "application/pdf",
            Self::Text => "text/plain",
            Self::Json => "application/json",
            Self::Raw => "application/octet-stream",
        }
    }
    pub fn has_projection(self) -> bool {
        matches!(self, Self::Html | Self::Pdf | Self::Text)
    }
}
impl PublicationUrl {
    pub fn kind(&self) -> PublicationKind {
        let Ok(url) = Url::parse(&self.url) else {
            return PublicationKind::Raw;
        };
        let path = url.path().to_ascii_lowercase();
        if path.ends_with(".pdf") {
            PublicationKind::Pdf
        } else if path.ends_with(".txt") || path.ends_with(".idl") {
            PublicationKind::Text
        } else if path.ends_with(".json") {
            PublicationKind::Json
        } else if path.ends_with('/') || path.ends_with(".html") || path.ends_with(".htm") {
            PublicationKind::Html
        } else {
            PublicationKind::Raw
        }
    }
    pub fn media_type(&self) -> &'static str {
        self.kind().media_type()
    }
    pub(crate) fn new(value: &str) -> Result<Self> {
        if value.len() > 4096
            || value.trim() != value
            || value.contains('\\')
            || value.chars().any(char::is_control)
            || value.contains('%')
            || value.contains("..")
        {
            return Err(Error::invalid("Invalid WHATWG publication URL."));
        }
        let mut url =
            Url::parse(value).map_err(|_| Error::invalid("Invalid WHATWG publication URL."))?;
        let host = url.host_str().unwrap_or_default().to_owned();
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.port().is_some()
            || url.query().is_some()
            || !publication_host(&host)
            || url.path().contains("..")
            || url.path().contains("//")
            || (host == "w3c-cg.github.io" && !url.path().starts_with("/web-nfc/"))
        {
            return Err(Error::invalid(
                "WHATWG publication destination is not permitted.",
            ));
        }
        url.set_fragment(None);
        Ok(Self {
            url: url.to_string(),
            host,
        })
    }
    pub fn as_str(&self) -> &str {
        &self.url
    }
    pub fn host(&self) -> &str {
        &self.host
    }
    pub fn validate(&self) -> Result<()> {
        let checked = Self::new(&self.url)?;
        if checked.host != self.host {
            return Err(Error::integrity("Invalid retained WHATWG destination."));
        }
        Ok(())
    }
}

fn explicit_repository(row: &Value) -> Result<Option<String>> {
    for key in ["repository", "source_repository", "repo"] {
        if let Some(value) = row.get(key) {
            let value = value
                .as_str()
                .ok_or_else(|| Error::integrity("Invalid WHATWG repository metadata."))?;
            let identity = if let Some(identity) = value.strip_prefix("https://github.com/") {
                identity.trim_end_matches('/').trim_end_matches(".git")
            } else {
                value
            };
            let repo = Repo::new(identity)?;
            return Ok(Some(repo.as_str()));
        }
    }
    Ok(None)
}

/// Preserve original catalogue metadata; the host, not workstream, owns identity.
pub fn parse(bytes: &[u8], observed_at: i64) -> Result<Catalog> {
    if bytes.len() > 4 * 1024 * 1024 {
        return Err(Error::capacity("WHATWG catalog exceeds its bound."));
    }
    let data: Value =
        serde_json::from_slice(bytes).map_err(|_| Error::integrity("Malformed WHATWG catalog."))?;
    let workstreams = data["workstreams"]
        .as_array()
        .ok_or_else(|| Error::integrity("WHATWG workstreams missing."))?;
    if workstreams.len() > 256 {
        return Err(Error::capacity(
            "WHATWG workstream count exceeds its bound.",
        ));
    }
    let mut standards = Vec::new();
    let mut seen = BTreeSet::new();
    let mut gaps = Vec::new();
    for workstream in workstreams {
        let rows = workstream["standards"]
            .as_array()
            .ok_or_else(|| Error::integrity("WHATWG standards missing."))?;
        for row in rows {
            if standards.len() >= 256 {
                return Err(Error::capacity("WHATWG catalog count exceeds its bound."));
            }
            let href = row["href"]
                .as_str()
                .ok_or_else(|| Error::integrity("WHATWG standard URL missing."))?;
            let url = PublicationUrl::new(href)?;
            let id = url
                .host()
                .strip_suffix(".spec.whatwg.org")
                .filter(|id| valid_slug(id))
                .ok_or_else(|| Error::integrity("WHATWG catalog identity is not a standard host."))?
                .to_owned();
            if !seen.insert(id.clone()) {
                return Err(Error::integrity("Duplicate WHATWG standard identity."));
            }
            let title = row["name"]
                .as_str()
                .filter(|s| !s.is_empty() && s.len() <= 1024)
                .ok_or_else(|| Error::integrity("WHATWG standard name missing."))?
                .to_owned();
            let repository = explicit_repository(row)?.unwrap_or_else(|| {
                if id == "nfc" {
                    "w3c-cg/web-nfc".into()
                } else {
                    format!("whatwg/{id}")
                }
            });
            Repo::new(&repository)?;
            let mut metadata = row.clone();
            if id == "nfc" {
                metadata["publication_url"] = json!("https://w3c-cg.github.io/web-nfc/");
                metadata["listed_publication_url"] = json!(href);
                metadata["predecessor_publication_url"] =
                    json!("https://w3c-cg.github.io/web-nfc/");
                metadata["repository_policy"] = json!("reviewed_predecessor_mapping");
            } else {
                metadata["repository_policy"] = json!(if explicit_repository(row)?.is_some() {
                    "explicit_catalog_metadata"
                } else {
                    "whatwg_standard_host"
                });
            }
            standards.push(Standard {
                id,
                title,
                url: url.as_str().into(),
                repository,
                metadata,
            });
        }
    }
    if standards.is_empty() {
        return Err(Error::integrity("Empty WHATWG catalog."));
    }
    standards.sort_by(|a, b| a.id.cmp(&b.id));
    if !seen.contains("nfc") {
        gaps.push(json!({"code":"predecessor_absent","standard":"nfc"}));
    }
    let id = crate::whatwg_inventory::digest(
        &serde_json::to_vec(&(bytes, observed_at))
            .map_err(|_| Error::integrity("Invalid WHATWG catalog identity."))?,
    );
    Ok(Catalog {
        id,
        observed_at,
        standards,
        gaps,
    })
}

pub fn current_publication(standard: &Standard) -> Result<PublicationUrl> {
    if let Some(url) = standard.metadata["publication_url"].as_str() {
        return PublicationUrl::new(url);
    }
    let url = PublicationUrl::new(&standard.url)?;
    // HTML's full single-page edition supplies all sections; preserve multipage too.
    if standard.id == "html" {
        return PublicationUrl::new("https://html.spec.whatwg.org/");
    }
    Ok(url)
}

/// Follow only advertised publication classes on this standard's qualified host.
pub fn advertised(
    standard: &Standard,
    base: &PublicationUrl,
    links: &[String],
) -> Vec<PublicationUrl> {
    if base.kind() != PublicationKind::Html {
        return Vec::new();
    }
    let Ok(origin) = Url::parse(base.as_str()) else {
        return Vec::new();
    };
    let mut found = std::collections::BTreeMap::new();
    for link in links {
        let Ok(url) = origin.join(link) else {
            continue;
        };
        if url.host_str() != Some(base.host()) {
            continue;
        }
        let path = url.path();
        let publication = path.ends_with(".pdf")
            || path.contains("/review-drafts/")
            || path.contains("/commit-snapshots/")
            || path == "/dev/"
            || path == "/multipage/"
            || path == "/single-page.html"
            || path == "/single-page/"
            || (path.starts_with("/multipage/") && path.ends_with(".html"))
            || (standard.id == "bluetooth" && matches!(path, "/scanning.html" | "/tests.html"));
        if !publication {
            continue;
        }
        if let Ok(value) = PublicationUrl::new(url.as_str()) {
            found.insert(value.as_str().to_owned(), value);
        }
    }
    if let Ok(original) = PublicationUrl::new(&standard.url) {
        found.insert(original.as_str().to_owned(), original);
    }
    found.into_values().collect()
}

#[derive(Default, Debug)]
pub struct PublicationMetadata {
    pub links: Vec<String>,
    pub repositories: Vec<String>,
}
/// Extract source-repository metadata and header links, never arbitrary body repositories.
pub fn publication_metadata(
    bytes: &[u8],
    cancel: &tokio_util::sync::CancellationToken,
) -> Result<PublicationMetadata> {
    use html5ever::{
        tendril::StrTendril,
        tokenizer::{
            BufferQueue, TagKind, Token, TokenSink, TokenSinkResult, Tokenizer, TokenizerOpts,
        },
    };
    use std::cell::RefCell;
    struct State {
        result: PublicationMetadata,
        heading: bool,
        tokens: usize,
        error: bool,
        completed: usize,
        link_keys: BTreeSet<String>,
        link_bytes: usize,
        definition: Option<String>,
        source_context: bool,
        body_started: bool,
        template_depth: usize,
        raw_hidden: Option<String>,
        header_tag: Option<String>,
        header_depth: usize,
        anchor_repository: Option<String>,
        anchor_label: String,
    }
    struct Sink<'a> {
        state: RefCell<State>,
        cancel: &'a tokio_util::sync::CancellationToken,
    }
    impl TokenSink for Sink<'_> {
        type Handle = ();
        fn process_token(&self, token: Token, _: u64) -> TokenSinkResult<()> {
            let mut state = self.state.borrow_mut();
            state.tokens += 1;
            if !matches!(token, Token::ParseError(_) | Token::EOFToken) {
                state.completed += 1;
            }
            if self.cancel.is_cancelled() || state.tokens > 4_000_000 {
                state.error = true;
                return TokenSinkResult::Continue;
            }
            if let Token::TagToken(tag) = &token {
                if state.raw_hidden.as_deref() == Some(&*tag.name) && tag.kind == TagKind::EndTag {
                    state.raw_hidden = None;
                    return TokenSinkResult::Continue;
                }
                if state.raw_hidden.is_none() && tag.kind == TagKind::StartTag {
                    let raw = match &*tag.name {
                        "script" => Some(html5ever::tokenizer::states::RawKind::ScriptData),
                        "style" | "iframe" | "xmp" | "noembed" | "noframes" | "noscript" => {
                            Some(html5ever::tokenizer::states::RawKind::Rawtext)
                        }
                        "title" | "textarea" => Some(html5ever::tokenizer::states::RawKind::Rcdata),
                        _ => None,
                    };
                    if let Some(raw) = raw {
                        state.raw_hidden = Some(tag.name.to_string());
                        return TokenSinkResult::RawData(raw);
                    }
                }
            }
            if state.raw_hidden.is_some() {
                return TokenSinkResult::Continue;
            }
            if let Token::TagToken(tag) = &token
                && &*tag.name == "template"
            {
                if tag.kind == TagKind::StartTag {
                    state.template_depth = state.template_depth.saturating_add(1);
                } else {
                    state.template_depth = state.template_depth.saturating_sub(1);
                }
            }
            if state.template_depth > 0 {
                return TokenSinkResult::Continue;
            }
            if let Token::TagToken(tag) = &token
                && tag.kind == TagKind::EndTag
            {
                if &*tag.name == "a"
                    && let Some(identity) = state.anchor_repository.take()
                {
                    let label = state.anchor_label.to_ascii_lowercase();
                    let source = label
                        .split_whitespace()
                        .map(|word| word.trim_matches(|c: char| !c.is_alphanumeric()))
                        .any(|word| matches!(word, "repository" | "source" | "contribute"));
                    if source && state.header_depth > 0 && !state.heading {
                        state.result.repositories.push(identity);
                    }
                    state.anchor_label.clear();
                }
                if state.header_tag.as_deref() == Some(&*tag.name) {
                    state.header_depth = state.header_depth.saturating_sub(1);
                    if state.header_depth == 0 {
                        state.header_tag = None;
                        state.anchor_repository = None;
                        state.anchor_label.clear();
                    }
                }
            }
            if !state.heading
                && state.anchor_repository.is_some()
                && let Token::CharacterTokens(text) = &token
            {
                if state.anchor_label.len() + text.len() <= 1024 {
                    state.anchor_label.push_str(text);
                } else {
                    state.error = true;
                }
            }
            if !state.heading
                && let Token::CharacterTokens(text) = &token
                && let Some(definition) = &mut state.definition
            {
                if definition.len() + text.len() <= 1024 {
                    definition.push_str(text);
                } else {
                    state.error = true;
                }
            }
            if let Token::TagToken(tag) = &token
                && tag.kind == TagKind::StartTag
                && !matches!(
                    &*tag.name,
                    "html" | "head" | "meta" | "link" | "base" | "template"
                )
            {
                state.body_started = true;
            }
            if let Token::TagToken(tag) = &token
                && tag.kind == TagKind::StartTag
                && &*tag.name == "dd"
                && let Some(label) = state.definition.take()
            {
                let label = label.to_ascii_lowercase();
                state.source_context = matches!(
                    label.trim().trim_end_matches(':').trim(),
                    "participate"
                        | "source"
                        | "source code"
                        | "source repository"
                        | "repository"
                        | "feedback"
                );
            }
            if let Token::TagToken(tag) = &token
                && tag.kind == TagKind::EndTag
                && matches!(&*tag.name, "dd" | "dl")
            {
                state.source_context = false;
            }
            if let Token::TagToken(tag) = &token
                && tag.kind == TagKind::EndTag
                && &*tag.name == "dt"
            {
                let label = state
                    .definition
                    .take()
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                state.source_context = matches!(
                    label.trim().trim_end_matches(':').trim(),
                    "participate"
                        | "source"
                        | "source code"
                        | "source repository"
                        | "repository"
                        | "feedback"
                );
            }
            if let Token::TagToken(tag) = &token
                && tag.kind == TagKind::StartTag
            {
                if &*tag.name == "dt" && !state.heading {
                    state.definition = Some(String::new());
                    state.source_context = false;
                }

                let attribute = |name: &str| {
                    tag.attrs
                        .iter()
                        .find(|a| &*a.name.local == name)
                        .map(|a| a.value.as_ref())
                };
                if state.header_tag.as_deref() == Some(&*tag.name) {
                    state.header_depth += 1;
                } else if state.header_depth == 0
                    && matches!(&*tag.name, "header" | "div")
                    && (attribute("id") == Some("head")
                        || attribute("class").is_some_and(|classes| {
                            classes
                                .split_ascii_whitespace()
                                .any(|class| class == "head")
                        }))
                {
                    state.header_tag = Some(tag.name.to_string());
                    state.header_depth = 1;
                }
                if &*tag.name == "h2" {
                    state.heading = true;
                    state.definition = None;
                    state.source_context = false;
                }
                if tag.attrs.len() > 128
                    || tag.name.len() > 256
                    || tag
                        .attrs
                        .iter()
                        .map(|a| a.name.local.len() + a.value.len())
                        .sum::<usize>()
                        > 128 * 1024
                {
                    state.error = true;
                    return TokenSinkResult::Continue;
                }
                if &*tag.name == "a"
                    && let Some(href) = attribute("href")
                    && href.len() <= 4096
                {
                    let candidate = href.split('#').next().unwrap_or_default();
                    let candidate_path = candidate.split('?').next().unwrap_or_default();
                    let publication = candidate_path.contains("review-drafts/")
                        || candidate_path.contains("commit-snapshots/")
                        || candidate_path.contains("multipage/")
                        || candidate_path.ends_with(".html")
                        || candidate_path.ends_with(".pdf")
                        || candidate_path.ends_with("/dev/")
                        || candidate_path.ends_with("/single-page/");
                    if publication && state.link_keys.insert(candidate.to_owned()) {
                        state.link_bytes += candidate.len();
                        if state.link_keys.len() > 100_000 || state.link_bytes > 8 * 1024 * 1024 {
                            state.error = true;
                        }
                    }
                    if !state.heading
                        && (state.source_context
                            || attribute("rel").is_some_and(|rel| {
                                rel.split_ascii_whitespace()
                                    .any(|v| matches!(v, "source" | "repository"))
                            }))
                        && let Some(identity) = repository_url(href)
                    {
                        state.result.repositories.push(identity);
                    } else if !state.heading
                        && state.header_depth > 0
                        && let Some(identity) = repository_url(href)
                    {
                        state.anchor_repository = Some(identity);
                        state.anchor_label.clear();
                    }
                }
                if &*tag.name == "meta"
                    && !state.body_started
                    && !state.heading
                    && attribute("name").is_some_and(|s| {
                        matches!(s, "repository" | "source-repository" | "github-repository")
                    })
                    && let Some(content) = attribute("content")
                    && let Some(identity) = repository_url(content)
                {
                    state.result.repositories.push(identity);
                }
            }
            TokenSinkResult::Continue
        }
    }
    if bytes.len() > 64 * 1024 * 1024 {
        return Err(Error::capacity(
            "WHATWG metadata extraction input exceeds its bound.",
        ));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error::integrity("WHATWG publication is not UTF-8."))?;
    let tokenizer = Tokenizer::new(
        Sink {
            state: RefCell::new(State {
                result: PublicationMetadata::default(),
                heading: false,
                tokens: 0,
                error: false,
                completed: 0,
                link_keys: BTreeSet::new(),
                link_bytes: 0,
                definition: None,
                source_context: false,
                body_started: false,
                template_depth: 0,
                raw_hidden: None,
                header_tag: None,
                header_depth: 0,
                anchor_repository: None,
                anchor_label: String::new(),
            }),
            cancel,
        },
        TokenizerOpts::default(),
    );
    let input = BufferQueue::default();
    let mut offset = 0;
    let mut pending = 0;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while offset < text.len() {
        if cancel.is_cancelled() {
            return Err(Error::new(
                "cancelled",
                "WHATWG metadata extraction canceled.",
            ));
        }
        let mut end = (offset + 4096).min(text.len());
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        if std::time::Instant::now() >= deadline {
            return Err(Error::capacity(
                "WHATWG publication metadata time bound exceeded.",
            ));
        }
        let completed = tokenizer.sink.state.borrow().completed;
        input.push_back(StrTendril::from_slice(&text[offset..end]));
        let _ = tokenizer.feed(&input);
        if tokenizer.sink.state.borrow().completed == completed {
            pending += end - offset;
        } else {
            pending = 0;
        }
        if pending > 128 * 1024 {
            return Err(Error::capacity(
                "WHATWG publication metadata lexical bound exceeded.",
            ));
        }
        offset = end;
        if tokenizer.sink.state.borrow().error {
            return Err(Error::capacity(
                "WHATWG publication metadata exceeds its bound.",
            ));
        }
    }
    tokenizer.end();
    let mut result = tokenizer.sink.state.borrow_mut();
    if result.error {
        return Err(Error::capacity(
            "WHATWG publication metadata exceeds its bound.",
        ));
    }
    result.result.links = std::mem::take(&mut result.link_keys).into_iter().collect();
    result.result.repositories.sort();
    result.result.repositories.dedup();
    Ok(std::mem::take(&mut result.result))
}
fn repository_url(value: &str) -> Option<String> {
    let url = Url::parse(value).ok()?;
    if url.scheme() != "https"
        || url.host_str() != Some("github.com")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    Repo::new(url.path().trim_matches('/').trim_end_matches(".git"))
        .ok()
        .map(|r| r.as_str())
}

/// Review draft filenames are an official publication inventory, unlike guessed commit URLs.
pub fn source_publications(standard: &Standard, paths: &[String]) -> Result<Vec<PublicationUrl>> {
    let base = current_publication(standard)?;
    let origin = Url::parse(base.as_str())
        .map_err(|_| Error::integrity("Invalid WHATWG standard origin."))?;
    let mut urls = Vec::new();
    for path in paths {
        let Some(name) = path.strip_prefix("review-drafts/") else {
            continue;
        };
        let Some(date) = name
            .strip_suffix(".bs")
            .or_else(|| name.strip_suffix(".wattsi"))
        else {
            continue;
        };
        let bytes = date.as_bytes();
        if bytes.len() != 7
            || bytes[4] != b'-'
            || !bytes[..4].iter().chain(&bytes[5..]).all(u8::is_ascii_digit)
            || !date[5..]
                .parse::<u8>()
                .is_ok_and(|month| (1..=12).contains(&month))
        {
            continue;
        }
        let url = origin
            .join(&format!("/review-drafts/{date}/"))
            .map_err(|_| Error::integrity("Invalid WHATWG review draft publication."))?;
        urls.push(PublicationUrl::new(url.as_str())?);
    }
    Ok(urls)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn standard_identity_and_foreign_repository_require_catalog_metadata() {
        let body=br#"{"workstreams":[{"id":"fetch","standards":[{"name":"Cookie Store","href":"https://cookiestore.spec.whatwg.org/"},{"name":"Foreign","href":"https://foreign.spec.whatwg.org/","repository":"https://github.com/example/standard.git"},{"name":"Web NFC","href":"https://nfc.spec.whatwg.org/"}]}]}"#;
        let catalog = parse(body, 42).expect("catalog");
        assert_eq!(catalog.standards[0].id, "cookiestore");
        assert_eq!(catalog.standards[0].repository, "whatwg/cookiestore");
        assert_eq!(catalog.standards[1].repository, "example/standard");
        assert_eq!(catalog.standards[2].repository, "w3c-cg/web-nfc");
        for url in [
            "https://evil.invalid/",
            "http://dom.spec.whatwg.org/",
            "https://user@dom.spec.whatwg.org/",
            "https://w3c-cg.github.io/other/",
            "https://dom.spec.whatwg.org/%2e%2e/private",
        ] {
            assert!(PublicationUrl::new(url).is_err(), "{url}");
        }
    }
    #[test]
    fn publication_routes_preserve_media_and_capture_family_without_pruning_data() {
        for (path, kind, representation, media) in [
            ("/", PublicationKind::Html, "html", "text/html"),
            (
                "/review-drafts/2026-07/",
                PublicationKind::Html,
                "html",
                "text/html",
            ),
            ("/chapter.HTM", PublicationKind::Html, "html", "text/html"),
            ("/print.PDF", PublicationKind::Pdf, "pdf", "application/pdf"),
            (
                "/review-drafts/2026-07/data.txt",
                PublicationKind::Text,
                "text",
                "text/plain",
            ),
            ("/api.IDL", PublicationKind::Text, "text", "text/plain"),
            (
                "/review-drafts/2026-07/data.json",
                PublicationKind::Json,
                "json",
                "application/json",
            ),
            (
                "/opaque.bin",
                PublicationKind::Raw,
                "raw",
                "application/octet-stream",
            ),
        ] {
            let url = PublicationUrl::new(&format!("https://encoding.spec.whatwg.org{path}"))
                .expect("qualified URL");
            assert_eq!(url.kind(), kind);
            assert_eq!(kind.representation(), representation);
            assert_eq!(url.media_type(), media);
        }
        let standard = Standard {
            id: "encoding".into(),
            title: "Encoding".into(),
            url: "https://encoding.spec.whatwg.org/".into(),
            repository: "whatwg/encoding".into(),
            metadata: json!({}),
        };
        let base = PublicationUrl::new(&standard.url).expect("base");
        let links = vec![
            "/review-drafts/2026-07/data.txt".into(),
            "/review-drafts/2026-07/data.json".into(),
        ];
        let discovered = advertised(&standard, &base, &links);
        assert!(discovered.iter().any(|u| u.kind() == PublicationKind::Text));
        assert!(discovered.iter().any(|u| u.kind() == PublicationKind::Json));
        assert!(
            advertised(
                &standard,
                &PublicationUrl::new(
                    "https://encoding.spec.whatwg.org/review-drafts/2026-07/data.txt"
                )
                .expect("text"),
                &links
            )
            .is_empty()
        );
    }
    #[test]
    fn source_metadata_ignores_tests_scripts_templates_and_body_examples() {
        let bytes=br#"<!doctype html><meta name=repository content=https://github.com/owner/explicit><script><meta name=repository content=https://github.com/evil/script></script><template><meta name=repository content=https://github.com/evil/template></template><body><dl><dt>Participate:<dd><a href=https://github.com/foreign/standard>Source</a><dt>Tests:</dt><dd><a href=https://github.com/test/suite>Tests</a></dd><dt>Resources:</dt><dd><a href=https://github.com/evil/resource>Resource</a></dd></dl><h2 id=body>Body</h2><meta name=repository content=https://github.com/evil/body><a href=https://github.com/evil/example>Example</a>"#;
        let metadata = publication_metadata(bytes, &tokio_util::sync::CancellationToken::new())
            .expect("metadata");
        assert_eq!(
            metadata.repositories,
            vec!["foreign/standard", "owner/explicit"]
        );
        assert!(
            !metadata
                .links
                .iter()
                .any(|link| link.contains("evil/script"))
        );
    }
    #[test]
    fn large_inert_data_href_and_body_definitions_do_not_hide_publications() {
        let body = format!(
            "<body><dl><dt>Participate:<dd><a href=https://github.com/whatwg/html>GitHub</a></dl><h2>Body</h2><dt>{}</dt><a href=\"data:application/xml-dtd;base64,{}\">DTD</a><a href=/review-drafts/2026-07/#anchor>Draft</a><a href=/review-drafts/2026-07/#another>Draft</a>",
            "ordinary body definition ".repeat(100),
            "A".repeat(79_900)
        );
        let metadata =
            publication_metadata(body.as_bytes(), &tokio_util::sync::CancellationToken::new())
                .expect("bounded inert tag");
        assert_eq!(metadata.repositories, vec!["whatwg/html"]);
        assert_eq!(metadata.links, vec!["/review-drafts/2026-07/"]);
        let too_large = format!(
            "<a href=\"data:text/plain,{}\">inert</a>",
            "A".repeat(129 * 1024)
        );
        assert_eq!(
            publication_metadata(
                too_large.as_bytes(),
                &tokio_util::sync::CancellationToken::new()
            )
            .expect_err("bounded token")
            .code,
            "capacity"
        );
    }
    #[test]
    fn modern_header_source_labels_exclude_test_and_body_repositories() {
        let source=br#"<header id=head class=head><nav><a href=https://github.com/foreign/standard><strong>Contribute on GitHub</strong><code>foreign/standard repository</code></a><a href=https://github.com/tests/suite>Tests</a></nav></header><p><a href=https://github.com/body/example>Source repository</a></p><h2>Body</h2>"#;
        let metadata = publication_metadata(source, &tokio_util::sync::CancellationToken::new())
            .expect("header metadata");
        assert_eq!(metadata.repositories, vec!["foreign/standard"]);
    }
    #[test]
    #[ignore = "opt-in local retained public HTML; no provider traffic"]
    fn retained_html_metadata_replay() {
        let path = std::env::var("DEVRES_WHATWG_METADATA_HTML").expect("retained HTML path");
        let body = std::fs::read(path).expect("retained public HTML");
        let metadata = publication_metadata(&body, &tokio_util::sync::CancellationToken::new())
            .expect("complete retained publication discovery");
        assert!(
            metadata
                .repositories
                .iter()
                .any(|repository| repository == "whatwg/html")
        );
        assert!(!metadata.links.is_empty());
    }
    #[test]
    fn draft_inventory_and_multipage_discovery_remain_source_qualified() {
        let standard = Standard {
            id: "dom".into(),
            title: "DOM".into(),
            url: "https://dom.spec.whatwg.org/".into(),
            repository: "whatwg/dom".into(),
            metadata: json!({}),
        };
        let urls = source_publications(
            &standard,
            &[
                "review-drafts/2026-06.bs".into(),
                "review-drafts/2026-99.bs".into(),
                "review-drafts/arbitrary.wattsi".into(),
            ],
        )
        .expect("drafts");
        assert_eq!(urls.len(), 1);
        assert_eq!(
            urls[0].as_str(),
            "https://dom.spec.whatwg.org/review-drafts/2026-06/"
        );
        let base = PublicationUrl::new("https://dom.spec.whatwg.org/").expect("base");
        let urls = advertised(
            &standard,
            &base,
            &[
                "https://evil.invalid/review-drafts/2026-06/".into(),
                "/multipage/infrastructure.html".into(),
            ],
        );
        assert!(
            urls.iter()
                .any(|u| u.as_str().ends_with("/multipage/infrastructure.html"))
        );
        assert!(urls.iter().all(|u| u.host() == "dom.spec.whatwg.org"));
    }
}
