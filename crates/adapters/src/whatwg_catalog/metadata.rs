use super::{
    AdvertisementRole, ExclusionRole, PublicationAdvertisement, PublicationExclusion,
    PublicationMetadata, repository_url,
};
use devres_domain::{Error, Result};
use html5ever::{
    tendril::StrTendril,
    tokenizer::{
        BufferQueue, TagKind, Token, TokenSink, TokenSinkResult, Tokenizer, TokenizerOpts,
    },
};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;

const MAX_BYTES: usize = 8 * 1024 * 1024;
const MAX_ITEMS: usize = 100_000;
const MAX_ANCHOR: usize = 4096;

fn capacity() -> Error {
    Error::capacity("WHATWG publication metadata exceeds its bound.")
}
fn cancelled() -> Error {
    Error::new("cancelled", "WHATWG metadata extraction canceled.")
}
fn source_label(label: &str) -> bool {
    matches!(
        label.trim().trim_end_matches(':').trim(),
        "participate" | "source" | "source code" | "source repository" | "repository" | "feedback"
    )
}
fn bounded_anchor(value: Option<&str>) -> Option<&str> {
    value.filter(|value| value.len() <= MAX_ANCHOR && !value.chars().any(char::is_control))
}
fn link_path(href: &str) -> &str {
    let href = href.split('?').next().unwrap_or_default();
    if let Some((_, rest)) = href.split_once("://") {
        rest.find('/').map_or("/", |at| &rest[at..])
    } else {
        href
    }
}
fn known_asset(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    path.starts_with("images/")
        || path.contains("/images/")
        || [
            ".svg", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".ico", ".css", ".js",
            ".woff", ".woff2", ".ttf",
        ]
        .iter()
        .any(|suffix| path.ends_with(suffix))
}
struct Container {
    tag: String,
    navigation: bool,
    example: bool,
}
struct Pending {
    explicit: bool,
    navigation: bool,
    ordinary_body: bool,
    example_only: bool,
    bare_local: bool,
    source_anchor: Option<String>,
}
#[derive(Default)]
struct State {
    links: BTreeSet<String>,
    repositories: BTreeSet<String>,
    ids: BTreeSet<String>,
    pending: BTreeMap<String, Pending>,
    link_bytes: usize,
    id_bytes: usize,
    pending_bytes: usize,
    containers: Vec<Container>,
    heading_anchor: Option<String>,
    content_started: bool,
    body_started: bool,
    header_finished: bool,
    header_tag: Option<String>,
    header_depth: usize,
    definition: Option<String>,
    source_context: bool,
    anchor_repository: Option<String>,
    anchor_label: String,
    raw_hidden: Option<String>,
    template_depth: usize,
    tokens: usize,
    completed: usize,
    error: bool,
}
impl State {
    fn header_admission(&self) -> bool {
        self.header_depth > 0 || (!self.header_finished && !self.content_started)
    }
    fn fail(&mut self) {
        self.error = true;
    }
    fn id(&mut self, id: &str) {
        if self.ids.contains(id) {
            return;
        }
        if self.ids.len() >= MAX_ITEMS || self.id_bytes.saturating_add(id.len()) > MAX_BYTES {
            self.fail();
            return;
        }
        self.id_bytes += id.len();
        self.ids.insert(id.to_owned());
    }
    fn link(&mut self, href: &str, explicit: bool, source_anchor: Option<&str>, candidate: bool) {
        if !self.links.contains(href) {
            if self.links.len() >= MAX_ITEMS
                || self.link_bytes.saturating_add(href.len()) > MAX_BYTES
            {
                self.fail();
                return;
            }
            self.link_bytes += href.len();
            self.links.insert(href.to_owned());
        }
        // Raw hrefs remain intact above; network destinations retain their 4-KiB bound.
        if !candidate || href.len() > MAX_ANCHOR || href.starts_with('#') {
            return;
        }
        let bare_local = !href.contains(['#', '?', '/', ':', '.']);
        let href = href.split('#').next().unwrap_or_default();
        if href.is_empty() {
            return;
        }
        let path = link_path(href);
        let lower = path.to_ascii_lowercase();
        let bare = !path.contains(['/', '?', ':']) && !path.contains('.');
        let relevant = explicit
            || bare
            || known_asset(path)
            || path.contains("review-drafts/")
            || path.contains("commit-snapshots/")
            || path.contains("multipage/")
            || lower.ends_with("/dev/")
            || lower.ends_with("/single-page/")
            || [".html", ".htm", ".pdf", ".txt", ".idl", ".json"]
                .iter()
                .any(|suffix| lower.ends_with(suffix));
        if !relevant {
            return;
        }
        let navigation = self.containers.iter().any(|container| container.navigation);
        let example = self.containers.iter().any(|container| container.example);
        let ordinary_body = self.header_depth == 0 && !navigation;
        if let Some(previous) = self.pending.get_mut(href) {
            previous.explicit |= explicit && !example;
            previous.navigation |= navigation;
            previous.ordinary_body &= ordinary_body;
            previous.example_only &= example;
            previous.bare_local &= bare_local;
            return;
        }
        let anchor = source_anchor.or(self.heading_anchor.as_deref());
        let cost = href.len().saturating_add(anchor.map_or(0, str::len));
        if self.pending.len() >= MAX_ITEMS || self.pending_bytes.saturating_add(cost) > MAX_BYTES {
            self.fail();
            return;
        }
        self.pending_bytes += cost;
        self.pending.insert(
            href.to_owned(),
            Pending {
                explicit: explicit && !example,
                navigation,
                ordinary_body,
                example_only: example,
                bare_local,
                source_anchor: anchor.map(str::to_owned),
            },
        );
    }
}
struct Sink<'a> {
    state: RefCell<State>,
    cancel: &'a CancellationToken,
}
impl TokenSink for Sink<'_> {
    type Handle = ();
    fn process_token(&self, token: Token, _: u64) -> TokenSinkResult<()> {
        let mut state = self.state.borrow_mut();
        if state.error {
            return TokenSinkResult::Continue;
        }
        state.tokens += 1;
        if !matches!(token, Token::ParseError(_) | Token::EOFToken) {
            state.completed += 1;
        }
        if self.cancel.is_cancelled() || state.tokens > 4_000_000 {
            state.fail();
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
                state.fail();
                return TokenSinkResult::Continue;
            }
            if state.raw_hidden.as_deref() == Some(&*tag.name) && tag.kind == TagKind::EndTag {
                state.raw_hidden = None;
                return TokenSinkResult::Continue;
            }
            if state.raw_hidden.is_none() && tag.kind == TagKind::StartTag {
                use html5ever::tokenizer::states::RawKind;
                let raw = match &*tag.name {
                    "script" => Some(RawKind::ScriptData),
                    "style" | "iframe" | "xmp" | "noembed" | "noframes" | "noscript" => {
                        Some(RawKind::Rawtext)
                    }
                    "title" | "textarea" => Some(RawKind::Rcdata),
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
        }
        if state.raw_hidden.is_some() || state.template_depth > 0 {
            return TokenSinkResult::Continue;
        }
        if let Token::CharacterTokens(text) = &token {
            if let Some(definition) = state.definition.as_mut() {
                if definition.len().saturating_add(text.len()) <= 1024 {
                    definition.push_str(text);
                } else {
                    state.fail();
                }
            }
            if state.anchor_repository.is_some() {
                if state.anchor_label.len().saturating_add(text.len()) <= 1024 {
                    state.anchor_label.push_str(text);
                } else {
                    state.fail();
                }
            }
        }
        let Token::TagToken(tag) = token else {
            return TokenSinkResult::Continue;
        };
        if tag.kind == TagKind::EndTag {
            if &*tag.name == "a"
                && let Some(repository) = state.anchor_repository.take()
            {
                let source = state
                    .anchor_label
                    .to_ascii_lowercase()
                    .split_whitespace()
                    .any(|word| {
                        matches!(
                            word.trim_matches(|c: char| !c.is_alphanumeric()),
                            "repository" | "source" | "contribute"
                        )
                    });
                if source && state.header_depth > 0 {
                    state.repositories.insert(repository);
                }
                state.anchor_label.clear();
            }
            if &*tag.name == "dt"
                && let Some(label) = state.definition.take()
            {
                state.source_context = source_label(&label.to_ascii_lowercase());
            }
            if matches!(&*tag.name, "dd" | "dl") {
                state.source_context = false;
                if &*tag.name == "dl" {
                    state.definition = None;
                }
            }
            if state.header_tag.as_deref() == Some(&*tag.name) {
                state.header_depth = state.header_depth.saturating_sub(1);
                if state.header_depth == 0 {
                    state.header_tag = None;
                    state.header_finished = true;
                    state.definition = None;
                    state.source_context = false;
                    state.anchor_repository = None;
                    state.anchor_label.clear();
                }
            }
            if let Some(at) = state
                .containers
                .iter()
                .rposition(|container| container.tag == *tag.name)
            {
                state.containers.truncate(at);
            }
            return TokenSinkResult::Continue;
        }
        let attr = |name: &str| {
            tag.attrs
                .iter()
                .find(|a| &*a.name.local == name)
                .map(|a| a.value.as_ref())
        };
        let class = attr("class").unwrap_or_default();
        let classes = |needle| class.split_ascii_whitespace().any(|value| value == needle);
        if state.header_tag.as_deref() == Some(&*tag.name) {
            state.header_depth += 1;
        } else if state.header_depth == 0
            && !state.header_finished
            && !state.content_started
            && matches!(&*tag.name, "header" | "div")
            && (attr("id") == Some("head") || classes("head"))
        {
            state.header_tag = Some(tag.name.to_string());
            state.header_depth = 1;
        }
        if matches!(&*tag.name, "h2" | "h3" | "h4" | "h5" | "h6") && state.header_depth == 0 {
            state.content_started = true;
            state.definition = None;
            state.source_context = false;
            state.anchor_repository = None;
            state.anchor_label.clear();
        }
        if let Some(id) = bounded_anchor(attr("id")) {
            state.id(id);
        }
        if matches!(&*tag.name, "h1" | "h2" | "h3" | "h4" | "h5" | "h6") {
            state.heading_anchor = bounded_anchor(attr("id")).map(str::to_owned);
        }
        if matches!(
            &*tag.name,
            "div" | "header" | "nav" | "ol" | "ul" | "section" | "main"
        ) {
            if state.containers.len() >= 256 {
                state.fail();
                return TokenSinkResult::Continue;
            }
            state.containers.push(Container {
                tag: tag.name.to_string(),
                navigation: &*tag.name == "nav"
                    || classes("toc")
                    || attr("role") == Some("navigation"),
                example: classes("example"),
            });
        }
        if &*tag.name == "dt" && state.header_admission() {
            state.definition = Some(String::new());
            state.source_context = false;
        }
        if &*tag.name == "dd"
            && let Some(label) = state.definition.take()
        {
            state.source_context = source_label(&label.to_ascii_lowercase());
        }
        if let Some(href) = attr("href") {
            let rel = attr("rel").unwrap_or_default();
            let explicit = rel.split_ascii_whitespace().any(|role| {
                [
                    "alternate",
                    "canonical",
                    "publication",
                    "version",
                    "latest-version",
                ]
                .iter()
                .any(|expected| role.eq_ignore_ascii_case(expected))
            });
            state.link(
                href,
                explicit,
                bounded_anchor(attr("id")),
                matches!(&*tag.name, "a" | "link"),
            );
            if &*tag.name == "a" && state.header_admission() {
                if (state.source_context
                    || rel.split_ascii_whitespace().any(|role| {
                        role.eq_ignore_ascii_case("source")
                            || role.eq_ignore_ascii_case("repository")
                    }))
                    && let Some(repository) = repository_url(href)
                {
                    state.repositories.insert(repository);
                } else if state.header_depth > 0
                    && let Some(repository) = repository_url(href)
                {
                    state.anchor_repository = Some(repository);
                    state.anchor_label.clear();
                }
            }
        }
        if &*tag.name == "meta"
            && !state.body_started
            && state.header_admission()
            && attr("name").is_some_and(|name| {
                matches!(
                    name,
                    "repository" | "source-repository" | "github-repository"
                )
            })
            && let Some(repository) = attr("content").and_then(repository_url)
        {
            state.repositories.insert(repository);
        }
        if !matches!(
            &*tag.name,
            "html" | "head" | "meta" | "link" | "base" | "template"
        ) {
            state.body_started = true;
        }
        TokenSinkResult::Continue
    }
}

pub(super) fn extract(bytes: &[u8], cancel: &CancellationToken) -> Result<PublicationMetadata> {
    if cancel.is_cancelled() {
        return Err(cancelled());
    }
    if bytes.len() > 64 * 1024 * 1024 {
        return Err(capacity());
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error::integrity("WHATWG publication is not UTF-8."))?;
    let tokenizer = Tokenizer::new(
        Sink {
            state: RefCell::new(State::default()),
            cancel,
        },
        TokenizerOpts::default(),
    );
    let input = BufferQueue::default();
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut offset = 0;
    let mut pending = 0;
    while offset < text.len() {
        if cancel.is_cancelled() {
            return Err(cancelled());
        }
        if Instant::now() >= deadline {
            return Err(capacity());
        }
        let mut end = (offset + 4096).min(text.len());
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        let completed = tokenizer.sink.state.borrow().completed;
        input.push_back(StrTendril::from_slice(&text[offset..end]));
        let _ = tokenizer.feed(&input);
        if cancel.is_cancelled() {
            return Err(cancelled());
        }
        if tokenizer.sink.state.borrow().completed == completed {
            pending += end - offset;
        } else {
            pending = 0;
        }
        if pending > 128 * 1024 || tokenizer.sink.state.borrow().error {
            return Err(capacity());
        }
        offset = end;
    }
    tokenizer.end();
    if cancel.is_cancelled() {
        return Err(cancelled());
    }
    let mut state = tokenizer.sink.state.borrow_mut();
    if state.error {
        return Err(capacity());
    }
    let mut result = PublicationMetadata {
        links: std::mem::take(&mut state.links).into_iter().collect(),
        repositories: std::mem::take(&mut state.repositories)
            .into_iter()
            .collect(),
        ..Default::default()
    };
    for (href, pending) in std::mem::take(&mut state.pending) {
        if cancel.is_cancelled() {
            return Err(cancelled());
        }
        if Instant::now() >= deadline {
            return Err(capacity());
        }
        let path = link_path(&href).to_ascii_lowercase();
        let asset = known_asset(&path) && (pending.ordinary_body || pending.example_only);
        let role = if pending.example_only {
            None
        } else if pending.explicit {
            Some(AdvertisementRole::ExplicitRepresentation)
        } else if asset {
            None
        } else if path.ends_with(".pdf") {
            Some(AdvertisementRole::ExplicitRepresentation)
        } else if super::edition_path(path.trim_start_matches("../")) {
            Some(AdvertisementRole::EditionNavigation)
        } else if path.ends_with(".txt") || path.ends_with(".idl") || path.ends_with(".json") {
            Some(AdvertisementRole::PublishedSupportData)
        } else if path.ends_with(".html") || path.ends_with(".htm") {
            Some(AdvertisementRole::DocumentNavigation)
        } else {
            None
        };
        if let Some(role) = role {
            result
                .advertisements
                .push(PublicationAdvertisement { href, role });
        } else if asset {
            result.exclusions.push(PublicationExclusion {
                href,
                role: ExclusionRole::EmbeddedAsset,
                source_anchor: pending.source_anchor,
                target_anchor: None,
            });
        } else if pending.example_only {
            result.exclusions.push(PublicationExclusion {
                href,
                role: ExclusionRole::ExampleReference,
                source_anchor: pending.source_anchor,
                target_anchor: None,
            });
        } else if pending.ordinary_body
            && !pending.navigation
            && pending.bare_local
            && state.ids.contains(&href)
        {
            result.exclusions.push(PublicationExclusion {
                target_anchor: Some(href.clone()),
                href,
                role: ExclusionRole::MalformedLocalReference,
                source_anchor: pending.source_anchor,
            });
        }
    }
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .filter(|n| *n <= MAX_BYTES)
                .ok_or_else(|| std::io::Error::other("metadata byte bound"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(Counter(0), &result).map_err(|_| {
        if cancel.is_cancelled() {
            cancelled()
        } else {
            capacity()
        }
    })?;
    if cancel.is_cancelled() {
        return Err(cancelled());
    }
    Ok(result)
}
