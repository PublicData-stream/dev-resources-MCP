use super::{
    Budget, MAX_INPUT, MAX_ITEMS, ProcessedDocument, Reference, Section, Symbol, limit, safe_target,
};
use devres_domain::{Error, Result};
use html5ever::{
    tendril::StrTendril,
    tokenizer::{
        BufferQueue, TagKind, Token, TokenSink, TokenSinkResult, Tokenizer, TokenizerOpts,
        states::RawKind,
    },
};
use sha2::{Digest as _, Sha256};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
};

// The canonical HTML publication contains a 79,937-byte inert data-URI tag.
// Bound lexical buffering independently from the 4-KiB public reference limit.
const MAX_LEXICAL_BYTES: usize = 128 * 1024;

struct Frame {
    name: String,
    start: usize,
    kind: Option<String>,
    anchor: String,
    scope: Option<String>,
    target: Option<String>,
}
#[derive(Default)]
struct State {
    doc: ProcessedDocument,
    stack: Vec<Frame>,
    section: Option<(usize, String, String, u8)>,
    section_levels: Vec<u8>,
    symbol_contexts: Vec<String>,
    tokens: usize,
    completed: usize,
    fragments: usize,
    anchors: BTreeSet<String>,
    explicit_anchors: BTreeSet<String>,
    generated: BTreeSet<String>,
    script_tail: String,
    error: Option<Error>,
}
fn heading(name: &str) -> bool {
    matches!(name, "h1" | "h2" | "h3" | "h4" | "h5" | "h6")
}
fn hidden(name: &str) -> bool {
    matches!(
        name,
        "head" | "script" | "style" | "template" | "noscript" | "iframe" | "noembed" | "noframes"
    )
}
fn void(name: &str) -> bool {
    matches!(
        name,
        "area"
            | "base"
            | "br"
            | "col"
            | "embed"
            | "hr"
            | "img"
            | "input"
            | "link"
            | "meta"
            | "param"
            | "source"
            | "track"
            | "wbr"
    )
}
fn block(name: &str) -> bool {
    heading(name)
        || matches!(
            name,
            "p" | "div"
                | "section"
                | "pre"
                | "li"
                | "dt"
                | "dd"
                | "br"
                | "tr"
                | "td"
                | "th"
                | "ol"
                | "ul"
                | "dl"
        )
}
impl State {
    fn inert(&self) -> bool {
        self.stack.iter().any(|frame| hidden(&frame.name))
    }
    fn newline(&mut self) {
        if !self.doc.text.ends_with('\n') {
            self.doc.text.push('\n');
        }
    }
    fn close_frame(&mut self, budget: &Budget) -> Result<()> {
        let Some(frame) = self.stack.pop() else {
            return Ok(());
        };
        if hidden(&frame.name) || self.inert() {
            return Ok(());
        }
        if !heading(&frame.name) && frame.kind.is_none() && frame.target.is_none() {
            return Ok(());
        }
        let text = self
            .doc
            .text
            .get(frame.start..)
            .ok_or_else(super::malformed)?
            .trim()
            .to_owned();
        self.fragments = self.fragments.saturating_add(text.len());
        if self.fragments > MAX_INPUT * 2 {
            return Err(limit());
        }
        if heading(&frame.name) {
            if self.doc.title.is_empty() {
                self.doc.title = text.clone();
            }
            if let Some(section) = self.section.as_mut() {
                section.2 = text;
            }
        } else if let Some(kind) = frame.kind {
            if !text.is_empty() {
                if kind == "idl" {
                    let declarations = idl_declarations(&text, budget)?;
                    if declarations.is_empty() {
                        self.doc.gap("unparsed_idl","An IDL block has no recognized declaration; original block remains in document text.");
                    }
                    for (name, text) in declarations {
                        self.symbol_contexts.push(
                            self.section
                                .as_ref()
                                .map(|s| s.1.clone())
                                .unwrap_or_default(),
                        );
                        self.doc.symbols.push(Symbol {
                            kind: kind.clone(),
                            name,
                            anchor: frame.anchor.clone(),
                            text,
                            scope: frame.scope.clone(),
                        });
                    }
                } else {
                    // Labels share the search title's UTF-8 byte bound. The
                    // complete algorithm/definition remains in `text`.
                    let mut end = text.len().min(4096);
                    while !text.is_char_boundary(end) {
                        end -= 1;
                    }
                    let name = text[..end].to_owned();
                    self.symbol_contexts.push(
                        self.section
                            .as_ref()
                            .map(|s| s.1.clone())
                            .unwrap_or_default(),
                    );
                    self.doc.symbols.push(Symbol {
                        kind,
                        name,
                        anchor: frame.anchor,
                        text,
                        scope: frame.scope,
                    });
                }
            }
        } else if let Some(target) = frame.target {
            self.doc.references.push(Reference {
                source_anchor: self
                    .section
                    .as_ref()
                    .map(|s| s.1.clone())
                    .unwrap_or_default(),
                target,
                label: text,
            });
        }
        if self.doc.symbols.len() > MAX_ITEMS || self.doc.references.len() > MAX_ITEMS {
            return Err(limit());
        }
        Ok(())
    }
    fn close_at(&mut self, at: usize, budget: &Budget) -> Result<()> {
        while self.stack.len() > at {
            self.close_frame(budget)?;
        }
        Ok(())
    }
    fn flush_section(&mut self) -> Result<()> {
        if let Some((start, anchor, title, level)) = self.section.take() {
            let text = self
                .doc
                .text
                .get(start..)
                .ok_or_else(super::malformed)?
                .trim()
                .to_owned();
            self.doc.sections.push(Section {
                anchor,
                title,
                text,
            });
            self.section_levels.push(level);
            if self.doc.sections.len() > MAX_ITEMS {
                return Err(limit());
            }
        }
        Ok(())
    }
    fn stable_generated_anchors(&mut self, budget: &Budget) -> Result<()> {
        if self.section_levels.len() != self.doc.sections.len()
            || self.symbol_contexts.len() != self.doc.symbols.len()
        {
            return Err(super::malformed());
        }
        let mut counters = BTreeMap::new();
        let mut remap = BTreeMap::new();
        let mut parents: Vec<(u8, String)> = Vec::new();
        for (section, level) in self.doc.sections.iter_mut().zip(&self.section_levels) {
            budget.check()?;
            if *level > 0 {
                while parents.last().is_some_and(|(parent, _)| parent >= level) {
                    parents.pop();
                }
            }
            let old = section.anchor.clone();
            if self.generated.contains(&old) {
                let context = parents
                    .last()
                    .map(|(_, anchor)| anchor.as_str())
                    .unwrap_or_default();
                section.anchor = generated_anchor(
                    &mut counters,
                    &self.explicit_anchors,
                    &format!("heading-{level}"),
                    &section.title,
                    None,
                    context,
                )?;
            }
            remap.insert(old, section.anchor.clone());
            if *level > 0 {
                parents.push((*level, section.anchor.clone()));
            }
        }
        for (symbol, context) in self.doc.symbols.iter_mut().zip(&self.symbol_contexts) {
            budget.check()?;
            if self.generated.contains(&symbol.anchor) {
                let context = remap.get(context).map(String::as_str).unwrap_or(context);
                symbol.anchor = generated_anchor(
                    &mut counters,
                    &self.explicit_anchors,
                    &format!("symbol-{}", symbol.kind),
                    &symbol.name,
                    symbol.scope.as_deref(),
                    context,
                )?;
            }
        }
        for reference in &mut self.doc.references {
            budget.check()?;
            if let Some(anchor) = remap.get(&reference.source_anchor) {
                reference.source_anchor = anchor.clone();
            }
        }
        Ok(())
    }
}
fn generated_anchor(
    counters: &mut BTreeMap<String, usize>,
    reserved: &BTreeSet<String>,
    kind: &str,
    name: &str,
    scope: Option<&str>,
    context: &str,
) -> Result<String> {
    let mut digest = Sha256::new();
    digest.update([u8::from(scope.is_some())]);
    for part in [kind, name, scope.unwrap_or_default(), context] {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part.as_bytes());
    }
    let hash = hex::encode(digest.finalize());
    loop {
        let occurrence = {
            let count = counters.entry(hash.clone()).or_default();
            *count = count.checked_add(1).ok_or_else(limit)?;
            *count
        };
        if counters.len() > MAX_ITEMS * 2 || occurrence > MAX_ITEMS {
            return Err(limit());
        }
        let candidate = format!("source-{kind}-{hash}-{occurrence}");
        if !reserved.contains(&candidate) {
            return Ok(candidate);
        }
    }
}
pub(super) fn idl_declarations(text: &str, budget: &Budget) -> Result<Vec<(String, String)>> {
    // This is an observed declaration inventory, not Web IDL validation or binding generation.
    let bytes = text.as_bytes();
    let mut at = 0;
    let mut words = Vec::new();
    while at < bytes.len() {
        budget.check()?;
        if bytes[at..].starts_with(b"//") {
            at += 2;
            while at < bytes.len() && bytes[at] != b'\n' {
                if at & 4095 == 0 {
                    budget.check()?;
                }
                at += 1;
            }
            continue;
        }
        if bytes[at..].starts_with(b"/*") {
            at += 2;
            while at + 1 < bytes.len() && !bytes[at..].starts_with(b"*/") {
                if at & 4095 == 0 {
                    budget.check()?;
                }
                at += 1;
            }
            at = (at + 2).min(bytes.len());
            continue;
        }
        if matches!(bytes[at], b'\'' | b'"') {
            let quote = bytes[at];
            at += 1;
            while at < bytes.len() {
                if at & 4095 == 0 {
                    budget.check()?;
                }
                if bytes[at] == b'\\' {
                    at = (at + 2).min(bytes.len());
                } else if bytes[at] == quote {
                    at += 1;
                    break;
                } else {
                    at += 1;
                }
            }
            continue;
        }
        if bytes[at].is_ascii_alphabetic() || bytes[at] == b'_' {
            let start = at;
            at += 1;
            while at < bytes.len() && (bytes[at].is_ascii_alphanumeric() || bytes[at] == b'_') {
                if at & 4095 == 0 {
                    budget.check()?;
                }
                at += 1;
            }
            words.push((start, &text[start..at]));
        } else {
            if bytes[at] == b';' {
                words.push((at, ";"));
            }
            at += 1;
        }
        if words.len() > 1_000_000 {
            return Err(limit());
        }
    }
    let mut declarations = Vec::new();
    let mut pending_typedef: Option<(usize, &str)> = None;
    for (i, (start, word)) in words.iter().enumerate() {
        budget.check()?;
        if *word == ";" {
            if let Some((start, name)) = pending_typedef.take() {
                declarations.push((start, name.to_owned()));
            }
            if declarations.len() > MAX_ITEMS {
                return Err(limit());
            }
            continue;
        }
        if let Some((_, name)) = pending_typedef.as_mut() {
            if *word == "typedef" {
                return Err(super::malformed());
            }
            *name = word;
            continue;
        }
        if matches!(
            *word,
            "interface" | "dictionary" | "namespace" | "enum" | "callback"
        ) {
            let mut next = i + 1;
            if words.get(next).is_some_and(|(_, word)| *word == "mixin") {
                next += 1;
            }
            if *word == "callback"
                && words
                    .get(next)
                    .is_some_and(|(_, word)| *word == "interface")
            {
                continue;
            }
            if let Some((_, name)) = words.get(next) {
                declarations.push((*start, (*name).to_owned()));
            }
        }
        if *word == "typedef" {
            pending_typedef = Some((*start, "typedef"));
        }
        if declarations.len() > MAX_ITEMS {
            return Err(limit());
        }
    }
    Ok(declarations
        .iter()
        .enumerate()
        .map(|(i, (start, name))| {
            let end = declarations
                .get(i + 1)
                .map(|item| item.0)
                .unwrap_or(text.len());
            (name.clone(), text[*start..end].trim().into())
        })
        .collect())
}
struct Sink<'a> {
    state: RefCell<State>,
    budget: &'a Budget,
}
impl TokenSink for Sink<'_> {
    type Handle = ();
    fn process_token(&self, token: Token, _line: u64) -> TokenSinkResult<()> {
        let mut state = self.state.borrow_mut();
        if state.error.is_some() {
            return TokenSinkResult::Continue;
        }
        if let Err(error) = self.budget.check() {
            state.error = Some(error);
            return TokenSinkResult::Continue;
        }
        state.tokens += 1;
        if state.tokens > 4_000_000 {
            state.error = Some(limit());
            return TokenSinkResult::Continue;
        }
        if !matches!(token, Token::ParseError(_) | Token::EOFToken) {
            state.completed += 1;
        }
        let result = (|| -> Result<TokenSinkResult<()>> {
            match token {
                Token::TagToken(tag) => {
                    let name = tag.name.to_string();
                    if tag.attrs.len() > 128
                        || tag
                            .attrs
                            .iter()
                            .map(|a| a.name.local.len() + a.value.len())
                            .sum::<usize>()
                            > MAX_LEXICAL_BYTES
                    {
                        return Err(limit());
                    }
                    if tag.kind == TagKind::EndTag {
                        if let Some(at) = state.stack.iter().rposition(|frame| frame.name == name) {
                            state.close_at(at, self.budget)?;
                        }
                        if block(&name) && !state.inert() {
                            state.newline();
                        }
                        return Ok(TokenSinkResult::Continue);
                    }
                    if name == "body"
                        && let Some(at) = state.stack.iter().rposition(|frame| frame.name == "head")
                    {
                        state.close_at(at, self.budget)?;
                    }
                    // HTML specification sources routinely omit optional end tags.
                    let implied = state.stack.iter().rposition(|frame| match name.as_str() {
                        "li" => frame.name == "li",
                        "dt" | "dd" => matches!(frame.name.as_str(), "dt" | "dd"),
                        "tr" => frame.name == "tr",
                        "td" | "th" => matches!(frame.name.as_str(), "td" | "th"),
                        _ => {
                            heading(&name) && heading(&frame.name)
                                || block(&name) && frame.name == "p"
                        }
                    });
                    if let Some(at) = implied {
                        state.close_at(at, self.budget)?;
                    }
                    let attr = |key: &str| {
                        tag.attrs
                            .iter()
                            .find(|a| &*a.name.local == key)
                            .map(|a| a.value.to_string())
                    };
                    if name == "script" {
                        state.script_tail.clear();
                        if attr("src").is_some_and(|src| {
                            let src = src.to_ascii_lowercase();
                            src.contains("/respec/")
                                || src.contains("respec-")
                                || src.ends_with("/respec.js")
                        }) {
                            state.doc.gap("unexpanded_respec","The capture depends on ReSpec rendering; scripts remain inert and generated text, bibliography and link expansion are unasserted.");
                        }
                    }
                    let inert = hidden(&name) || state.inert();
                    if !inert && block(&name) {
                        state.newline();
                    }
                    let start = state.doc.text.len();
                    let explicit_anchor = attr("id");
                    if let Some(anchor) = &explicit_anchor {
                        state.explicit_anchors.insert(anchor.clone());
                        if state.explicit_anchors.len() > MAX_ITEMS * 2 {
                            return Err(limit());
                        }
                    }
                    let mut anchor = explicit_anchor.unwrap_or_else(|| {
                        if heading(&name) {
                            state
                                .stack
                                .iter()
                                .rev()
                                .find(|frame| frame.name == "section" && !frame.anchor.is_empty())
                                .map(|frame| frame.anchor.clone())
                                .unwrap_or_default()
                        } else {
                            String::new()
                        }
                    });
                    let class = attr("class").unwrap_or_default();
                    let is_idl = class.split_whitespace().any(|c| c == "idl")
                        && (matches!(name.as_str(), "pre" | "xmp")
                            || name == "code"
                                && state
                                    .stack
                                    .iter()
                                    .any(|frame| matches!(frame.name.as_str(), "pre" | "xmp")));
                    if is_idl && anchor.is_empty() {
                        anchor = state
                            .stack
                            .iter()
                            .rev()
                            .find(|frame| {
                                matches!(frame.name.as_str(), "pre" | "xmp")
                                    && !frame.anchor.is_empty()
                            })
                            .map(|frame| frame.anchor.clone())
                            .unwrap_or_default();
                    }
                    let kind = if is_idl {
                        Some("idl")
                    } else if attr("data-algorithm").is_some() || attr("algorithm").is_some() {
                        Some("algorithm")
                    } else if name == "dfn" {
                        Some("definition")
                    } else {
                        None
                    };
                    if !inert && (heading(&name) || kind.is_some()) {
                        if anchor.is_empty() {
                            // Internal placeholders cannot collide with retained source IDs:
                            // source NUL characters are rejected before tokenization.
                            anchor = format!("\0generated:{}", state.tokens);
                            state.generated.insert(anchor.clone());
                            if state.generated.len() > MAX_ITEMS * 2 {
                                return Err(limit());
                            }
                            state.doc.gap("unasserted_anchor","Source-only/generated identifiers use local projection anchors; published URL identity is unasserted.");
                        } else if !state.anchors.insert(anchor.clone()) {
                            state.doc.gap("duplicate_anchor","The captured source contains duplicate identifiers; ambiguous identifiers are not unique section identities.");
                        }
                    }
                    if !inert && heading(&name) {
                        if state.section.is_none() && !state.doc.text[..start].trim().is_empty() {
                            let text = state.doc.text[..start].trim().to_owned();
                            state.doc.sections.push(Section {
                                anchor: "source-preamble".into(),
                                title: "Preamble".into(),
                                text,
                            });
                            state.section_levels.push(0);
                            state.doc.gap("unasserted_anchor","Source-only/generated identifiers use local projection anchors; published URL identity is unasserted.");
                        }
                        state.flush_section()?;
                        let level = match name.as_str() {
                            "h1" => 1,
                            "h2" => 2,
                            "h3" => 3,
                            "h4" => 4,
                            "h5" => 5,
                            _ => 6,
                        };
                        state.section = Some((start, anchor.clone(), String::new(), level));
                    }
                    let target = if !inert && name == "a" {
                        attr("href")
                            .filter(|target| safe_target(target))
                            .or_else(|| {
                                attr("data-cite")
                                    .filter(|cite| {
                                        !cite.is_empty()
                                            && cite.len() <= 4096
                                            && !cite.chars().any(char::is_control)
                                    })
                                    .map(|cite| format!("respec-cite:unresolved:{cite}"))
                            })
                    } else {
                        None
                    };
                    if !inert
                        && name == "a"
                        && (target.is_none()
                            || target
                                .as_ref()
                                .is_some_and(|target| target.starts_with("respec-cite:")))
                        && (attr("data-x").is_some()
                            || attr("data-link-type").is_some()
                            || attr("for").is_some()
                            || attr("data-cite").is_some())
                    {
                        state.doc.gap("unresolved_source_reference","A source shorthand reference has no captured rendered URL; link resolution is unasserted.");
                    }
                    if !void(&name) {
                        if state.stack.len() >= 256 {
                            return Err(limit());
                        }
                        state.stack.push(Frame {
                            name: name.clone(),
                            start,
                            kind: if inert { None } else { kind.map(str::to_owned) },
                            anchor,
                            scope: attr("data-dfn-for").or_else(|| attr("for")),
                            target,
                        });
                    }
                    return Ok(match name.as_str() {
                        "script" => TokenSinkResult::RawData(RawKind::ScriptData),
                        "style" | "iframe" | "xmp" | "noembed" | "noframes" | "noscript" => {
                            TokenSinkResult::RawData(RawKind::Rawtext)
                        }
                        "title" | "textarea" => TokenSinkResult::RawData(RawKind::Rcdata),
                        _ => TokenSinkResult::Continue,
                    });
                }
                Token::CharacterTokens(text) => {
                    if state.stack.iter().any(|frame| frame.name == "script") {
                        let prefix: String = text.chars().take(32).collect();
                        if text.contains("respecConfig")
                            || format!("{}{prefix}", state.script_tail).contains("respecConfig")
                        {
                            state.doc.gap("unexpanded_respec","The capture depends on ReSpec rendering; scripts remain inert and generated text, bibliography and link expansion are unasserted.");
                        }
                        state.script_tail = text
                            .chars()
                            .rev()
                            .take(32)
                            .collect::<String>()
                            .chars()
                            .rev()
                            .collect();
                    }
                    if !state.inert() {
                        if state.doc.text.len().saturating_add(text.len()) > MAX_INPUT {
                            return Err(limit());
                        }
                        state.doc.text.push_str(&text);
                    }
                }
                Token::NullCharacterToken => return Err(super::malformed()),
                _ => {}
            }
            Ok(TokenSinkResult::Continue)
        })();
        match result {
            Ok(result) => result,
            Err(error) => {
                state.error = Some(error);
                TokenSinkResult::Continue
            }
        }
    }
}
pub(super) fn project(source: &str, budget: &Budget) -> Result<ProcessedDocument> {
    let tokenizer = Tokenizer::new(
        Sink {
            state: RefCell::new(State::default()),
            budget,
        },
        TokenizerOpts::default(),
    );
    let input = BufferQueue::default();
    let mut offset = 0;
    let mut pending = 0;
    while offset < source.len() {
        budget.check()?;
        let mut end = (offset + 4096).min(source.len());
        while !source.is_char_boundary(end) {
            end -= 1;
        }
        let completed = tokenizer.sink.state.borrow().completed;
        input.push_back(StrTendril::from_slice(&source[offset..end]));
        let _ = tokenizer.feed(&input);
        let mut state = tokenizer.sink.state.borrow_mut();
        if let Some(error) = state.error.take() {
            return Err(error);
        }
        if state.completed == completed {
            pending += end - offset;
        } else {
            pending = 0;
        }
        if pending > MAX_LEXICAL_BYTES {
            return Err(limit());
        }
        offset = end;
    }
    tokenizer.end();
    let mut state = tokenizer.sink.state.into_inner();
    if let Some(error) = state.error.take() {
        return Err(error);
    }
    state.close_at(0, budget)?;
    state.flush_section()?;
    if state.doc.sections.is_empty() && !state.doc.text.trim().is_empty() {
        state.doc.sections.push(Section {
            anchor: "document".into(),
            title: state.doc.title.clone(),
            text: state.doc.text.trim().into(),
        });
        state.section_levels.push(0);
    }
    state.stable_generated_anchors(budget)?;
    state.doc.text = state.doc.text.trim().into();
    if state
        .doc
        .gaps
        .iter()
        .any(|gap| gap.code == "unexpanded_respec")
    {
        for section in &state.doc.sections {
            let mut remaining = section.text.as_str();
            while let Some(at) = remaining.find("[[") {
                budget.check()?;
                remaining = &remaining[at + 2..];
                let bounded = &remaining[..remaining
                    .char_indices()
                    .nth(512)
                    .map(|(at, _)| at)
                    .unwrap_or(remaining.len())];
                if let Some(end) = bounded.find("]]") {
                    let citation = bounded[..end].trim_start_matches('[').trim();
                    if !citation.is_empty() && !citation.chars().any(char::is_control) {
                        state.doc.references.push(Reference {
                            source_anchor: section.anchor.clone(),
                            target: format!("respec-biblio:unresolved:{citation}"),
                            label: citation.into(),
                        });
                        if state.doc.references.len() > MAX_ITEMS {
                            return Err(limit());
                        }
                    }
                    remaining = &remaining[end + 2..];
                }
            }
        }
    }
    Ok(state.doc)
}

pub(super) fn project_bikeshed(source: &str, budget: &Budget) -> Result<ProcessedDocument> {
    // Bikeshed accepts Markdown-style headings in otherwise HTML-like source.
    // Preserve HTML blocks and their examples verbatim; no upstream renderer runs.
    let mut normalized = String::new();
    let mut raw: Option<&str> = None;
    for line in source.split_inclusive('\n') {
        budget.check()?;
        let lower = line.to_ascii_lowercase();
        if raw.is_none() {
            raw = ["pre", "xmp", "script", "style", "textarea"]
                .into_iter()
                .find(|tag| lower.contains(&format!("<{tag}")));
        }
        if raw.is_none() {
            let trimmed = line.trim_end();
            let marks = trimmed.bytes().take_while(|byte| *byte == b'#').count();
            if (1..=6).contains(&marks) && trimmed.as_bytes().get(marks) == Some(&b' ') {
                let mut title = trimmed[marks + 1..].trim();
                let mut anchor = None;
                if let Some((heading, id)) = title.rsplit_once(" {#")
                    && let Some(id) = id.strip_suffix('}')
                    && id.len() <= 4096
                    && id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_:.".contains(&b))
                {
                    title = heading;
                    anchor = Some(id);
                }
                normalized.push_str(&format!("<h{marks}"));
                if let Some(anchor) = anchor {
                    normalized.push_str(" id=\"");
                    normalized.push_str(anchor);
                    normalized.push('"');
                }
                normalized.push('>');
                normalized.push_str(title);
                normalized.push_str(&format!("</h{marks}>\n"));
            } else {
                normalized.push_str(line);
            }
        } else {
            normalized.push_str(line);
        }
        if let Some(tag) = raw
            && lower.contains(&format!("</{tag}>"))
        {
            raw = None;
        }
        if normalized.len() > MAX_INPUT * 2 {
            return Err(limit());
        }
    }
    project(&normalized, budget)
}

#[cfg(test)]
mod tests {
    use tokio_util::sync::CancellationToken;
    #[test]
    fn unicode_symbol_labels_obey_index_byte_bound_without_losing_text() {
        use crate::whatwg_index::{IndexDocument, WhatwgIndex};
        for text in [
            format!("{}\u{2019} suffix", "a".repeat(4095)),
            format!("{}\u{2019} suffix", "a".repeat(4093)),
            format!("{} remaining normative text", "\u{754c}".repeat(2000)),
        ] {
            let source =
                format!("<h1 id=standard>Standard</h1><div algorithm id=steps>{text}</div>");
            let doc = super::super::process_document(
                "index.bs",
                source.as_bytes(),
                CancellationToken::new(),
            )
            .unwrap();
            let symbol = &doc.symbols[0];
            assert!(symbol.name.len() <= 4096);
            assert!(text.starts_with(&symbol.name));
            assert_eq!(symbol.text, text);
            assert!(doc.text.contains(&text));
            let next = text[symbol.name.len()..].chars().next();
            assert!(next.is_some_and(|next| symbol.name.len() + next.len_utf8() > 4096));
            WhatwgIndex::validate_document(
                &IndexDocument {
                    id: "a".repeat(64),
                    standard: "bluetooth".into(),
                    edition: "source".into(),
                    path: "index.bs".into(),
                    title: symbol.name.clone(),
                    text: symbol.text.clone(),
                    kind: "symbol".into(),
                    metadata: serde_json::json!({"anchor":symbol.anchor,"symbol_kind":symbol.kind,"name":symbol.name,"scope":symbol.scope}),
                },
                &CancellationToken::new(),
            )
            .unwrap();
        }
    }
    #[test]
    fn multiple_idl_declarations_and_bikeshed_headings() {
        let doc=super::super::process_document("api.bs",b"## APIs {#apis}\n<pre class=idl>\ninterface First {};\n// interface Fake {};\ninterface Second {};\ntypedef DOMString Name;\n</pre>\n",CancellationToken::new()).unwrap();
        assert_eq!(doc.sections[0].anchor, "apis");
        let names = doc
            .symbols
            .iter()
            .map(|symbol| symbol.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["First", "Second", "Name"]);
    }
    #[test]
    fn malformed_typedef_inventory_is_bounded_and_cancelable() {
        let source = format!("<pre class=idl>{}</pre>", "typedef ".repeat(100_000));
        let error =
            super::super::process_document("api.bs", source.as_bytes(), CancellationToken::new())
                .unwrap_err();
        assert_eq!(error.code, "integrity");
        let cancel = CancellationToken::new();
        cancel.cancel();
        let budget = super::Budget::new(cancel);
        assert_eq!(
            super::idl_declarations("interface Example {};", &budget)
                .unwrap_err()
                .code,
            "cancelled"
        );
    }
    #[test]
    fn respec_source_keeps_data_and_explicit_generated_gaps() {
        let doc=super::super::process_document("index.html",br#"<script>var respecConfig = { secret: "not text" };</script><script src="https://www.w3.org/Tools/respec/respec-w3c-common"></script><section id="references"><h2>References</h2><p>[[[NFC-STANDARDS]]] <a data-cite="INFRA#strings">strings</a></section>"#,CancellationToken::new()).unwrap();
        assert!(doc.gaps.iter().any(|gap| gap.code == "unexpanded_respec"));
        assert!(!doc.text.contains("not text"));
        assert!(
            doc.references
                .iter()
                .any(|reference| reference.target == "respec-biblio:unresolved:NFC-STANDARDS")
        );
        assert!(
            doc.references
                .iter()
                .any(|reference| reference.target == "respec-cite:unresolved:INFRA#strings")
        );
        assert_eq!(doc.sections[0].anchor, "references");
        let rendered = super::super::process_document(
            "index.html",
            br#"<script src="/html-dfn.js"></script><h1 id="standard">Standard</h1>"#,
            CancellationToken::new(),
        )
        .unwrap();
        assert!(
            !rendered
                .gaps
                .iter()
                .any(|gap| gap.code == "unexpanded_respec")
        );
    }
    #[test]
    fn text_before_first_heading_has_searchable_section_membership() {
        let doc = super::super::process_document(
            "index.html",
            b"<p>Abstract preamble evidence.</p><h2 id=body>Body</h2><p>Details.</p>",
            CancellationToken::new(),
        )
        .unwrap();
        assert_eq!(doc.sections[0].anchor, "source-preamble");
        assert!(doc.sections[0].text.contains("Abstract preamble evidence"));
        assert_eq!(doc.sections[1].anchor, "body");
    }
    #[test]
    fn canonical_sized_inert_data_uri_does_not_hide_following_content() {
        let prefix = "data:application/xml-dtd;base64,";
        let href = format!("{prefix}{}", "A".repeat(79_926 - prefix.len()));
        let source = format!(
            "<h1 id=standard>Standard</h1><a href=\"{href}\">inert data label</a><p>Following normative text.</p>"
        );
        let doc = super::super::process_document(
            "index.html",
            source.as_bytes(),
            CancellationToken::new(),
        )
        .unwrap();
        assert!(doc.text.contains("inert data label"));
        assert!(doc.text.contains("Following normative text."));
        assert!(doc.references.is_empty());
        let excessive = format!(
            "<a href=\"{prefix}{}\">label</a>",
            "A".repeat(super::MAX_LEXICAL_BYTES)
        );
        assert_eq!(
            super::super::process_document(
                "index.html",
                excessive.as_bytes(),
                CancellationToken::new()
            )
            .unwrap_err()
            .code,
            "capacity"
        );
    }
    #[test]
    fn generated_code_idl_inside_pre_preserves_published_anchor() {
        let source=b"<h1 id=standard>Standard</h1><pre id=api><code class=idl>interface Example {}; partial interface Example {}; interface mixin Common {};</code></pre><p>Inline <code class=idl>Example</code> mention.</p>";
        let doc =
            super::super::process_document("index.html", source, CancellationToken::new()).unwrap();
        let symbols = doc
            .symbols
            .iter()
            .filter(|symbol| symbol.kind == "idl")
            .collect::<Vec<_>>();
        assert_eq!(
            symbols
                .iter()
                .map(|symbol| symbol.name.as_str())
                .collect::<Vec<_>>(),
            vec!["Example", "Example", "Common"]
        );
        assert!(symbols.iter().all(|symbol| symbol.anchor == "api"));
        assert!(!doc.gaps.iter().any(|gap| gap.code == "unparsed_idl"));
    }
    #[test]
    fn generated_anchors_survive_unrelated_prefix_edits_and_remap_references() {
        let original = "<h1>Catalog</h1><h2>Events</h2><dfn for=Window>event</dfn><a href=\"#published\">link</a><h2 id=source-line-1-2>Published</h2>";
        let prefixed =
            format!("<p>Unrelated introduction.</p><h1>Other</h1><p>Other text.</p>{original}");
        let parse = |source: &str| {
            super::super::process_document("source", source.as_bytes(), CancellationToken::new())
                .unwrap()
        };
        let left = parse(original);
        let right = parse(&prefixed);
        for section in &left.sections {
            let matching = right
                .sections
                .iter()
                .find(|candidate| candidate.title == section.title)
                .unwrap();
            assert_eq!(section.anchor, matching.anchor);
        }
        assert_eq!(left.symbols[0].anchor, right.symbols[0].anchor);
        assert_eq!(
            left.references[0].source_anchor,
            right.references[0].source_anchor
        );
        assert_eq!(left.references[0].source_anchor, left.sections[1].anchor);
        assert_eq!(left.sections[2].anchor, "source-line-1-2");
        assert!(
            left.sections
                .iter()
                .all(|section| !section.anchor.contains('\0'))
        );
        assert!(left.gaps.iter().any(|gap| gap.code == "unasserted_anchor"));
    }
    #[test]
    fn identical_generated_symbols_are_disambiguated_without_global_ordinals() {
        let source=b"<h1>Catalog</h1><h2>Events</h2><dfn for=Window>event</dfn><dfn for=Window>event</dfn><pre class=idl>interface Example {}; partial interface Example {};</pre>";
        let doc =
            super::super::process_document("source", source, CancellationToken::new()).unwrap();
        assert_ne!(doc.symbols[0].anchor, doc.symbols[1].anchor);
        let idl = doc
            .symbols
            .iter()
            .filter(|symbol| symbol.kind == "idl")
            .collect::<Vec<_>>();
        assert_eq!(idl.len(), 2);
        assert_ne!(idl[0].anchor, idl[1].anchor);
    }
    #[test]
    fn generated_ids_reserve_all_explicit_source_ids_and_use_section_reference_context() {
        let original = "<h1>Catalog</h1><dfn><a href=\"#published\">term</a></dfn>";
        let parse = |source: &str| {
            super::super::process_document("source", source.as_bytes(), CancellationToken::new())
                .unwrap()
        };
        let first = parse(original);
        let reserved = first.symbols[0].anchor.clone();
        let second = parse(&format!("<span id=\"{reserved}\"></span>{original}"));
        assert_ne!(second.symbols[0].anchor, reserved);
        assert_eq!(
            second.references[0].source_anchor,
            second.sections[0].anchor
        );
        assert_ne!(second.references[0].source_anchor, second.symbols[0].anchor);
        assert!(
            second
                .sections
                .iter()
                .all(|section| !section.anchor.contains('\0'))
        );
        assert!(
            second
                .symbols
                .iter()
                .all(|symbol| !symbol.anchor.contains('\0'))
        );
        assert!(
            second
                .references
                .iter()
                .all(|reference| !reference.source_anchor.contains('\0'))
        );
    }
}
