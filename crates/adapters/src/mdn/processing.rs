//! Pure, bounded MDN projections. Source text, macros and examples are inert data.
//!
//! Includes are resolved only by the caller against the already selected Git tree.
//! This module performs no I/O and never evaluates JavaScript or template source.
use devres_domain::{Error, Result};
use pulldown_cmark::{Event as MarkdownEvent, Options, Parser as MarkdownParser, Tag, TagEnd};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

#[path = "processing/bcd.rs"]
mod bcd;
#[path = "processing/html.rs"]
mod html;
#[path = "processing/structured.rs"]
mod structured;
pub use bcd::{BcdBrowser, BcdDocument, BcdFeature, ResolvedSupport, process_bcd, resolve_support};

pub use devres_application::mdn::PROCESSOR_VERSION;
pub const MAX_MEMBER: usize = 4 * 1024 * 1024;
const MAX_FRONT_MATTER: usize = 64 * 1024;
const MAX_MACROS: usize = 10_000;
const MAX_ITEMS: usize = 20_000;

pub struct ProcessingBudget {
    pub deadline: Instant,
    pub cancel: CancellationToken,
}
impl ProcessingBudget {
    pub fn new(cancel: CancellationToken) -> Self {
        Self {
            deadline: Instant::now() + Duration::from_secs(15),
            cancel,
        }
    }
    pub fn check(&self) -> Result<()> {
        if self.cancel.is_cancelled() {
            return Err(Error::new("cancelled", "MDN processing canceled."));
        }
        if Instant::now() >= self.deadline {
            return Err(limit());
        }
        Ok(())
    }
}
fn malformed() -> Error {
    Error::integrity("Malformed MDN source representation.")
}
fn limit() -> Error {
    Error::capacity("MDN processing bounds exceeded.")
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessingGap {
    pub code: String,
    pub detail: String,
}
impl ProcessingGap {
    fn new(code: &str, detail: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            detail: detail.into(),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Dependency {
    pub path: String,
    pub identity: String,
}
#[derive(Clone, Debug)]
pub struct IncludedDocument {
    pub path: String,
    pub body: Vec<u8>,
    pub identity: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcessedDocument {
    pub slug: String,
    pub title: String,
    pub page_type: Option<String>,
    pub status: Vec<String>,
    pub compatibility_keys: Vec<String>,
    pub spec_urls: Vec<String>,
    pub headings: Vec<String>,
    pub links: Vec<String>,
    pub text: String,
    pub metadata: Value,
    pub macros: Vec<String>,
    pub gaps: Vec<ProcessingGap>,
    pub dependencies: Vec<Dependency>,
}

fn strings(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}
fn valid_identity(s: &str) -> bool {
    !s.is_empty() && s.len() <= 4096 && !s.chars().any(char::is_control)
}
fn safe_link(s: &str) -> bool {
    if !valid_identity(s) || s.contains('\\') {
        return false;
    }
    if s.starts_with('#') || (s.starts_with('/') && !s.starts_with("//")) {
        return true;
    }
    url::Url::parse(s).is_ok_and(|u| {
        matches!(u.scheme(), "http" | "https") && u.username().is_empty() && u.password().is_none()
    })
}
fn push(out: &mut String, text: &str) -> Result<()> {
    if out.len().saturating_add(text.len()) > MAX_MEMBER {
        return Err(limit());
    }
    out.push_str(text);
    Ok(())
}
fn front_matter<'a>(source: &'a str, budget: &ProcessingBudget) -> Result<(Value, &'a str)> {
    let source = source.strip_prefix('\u{feff}').unwrap_or(source);
    let Some(first_end) = source.find('\n') else {
        return Ok((json!({}), source));
    };
    if source[..first_end].trim_end_matches('\r') != "---" {
        return Ok((json!({}), source));
    }
    let mut start = first_end + 1;
    for line in source[start..].split_inclusive('\n') {
        budget.check()?;
        if start > MAX_FRONT_MATTER {
            return Err(limit());
        }
        if line.trim_end_matches(['\r', '\n']) == "---" {
            let metadata = structured::yaml(&source[first_end + 1..start], budget)?;
            if !metadata.is_object() {
                return Err(malformed());
            }
            return Ok((metadata, &source[start + line.len()..]));
        }
        start += line.len();
    }
    Err(malformed())
}

/// Process one retained article. The resolver receives a canonical repository path.
pub fn process_document(
    path: &str,
    bytes: &[u8],
    resolver: &mut dyn FnMut(&str) -> Result<Option<IncludedDocument>>,
    budget: &ProcessingBudget,
) -> Result<ProcessedDocument> {
    budget.check()?;
    if bytes.len() > MAX_MEMBER {
        return Err(limit());
    }
    if !valid_identity(path) {
        return Err(malformed());
    }
    let source = std::str::from_utf8(bytes).map_err(|_| malformed())?;
    if source.contains('\0') {
        return Err(malformed());
    }
    let (metadata, body) = front_matter(source, budget)?;
    let inferred = path.strip_prefix("files/en-us/").and_then(|p| {
        p.strip_suffix("/index.md")
            .or_else(|| p.strip_suffix("/index.html"))
    });
    let slug = metadata
        .get("slug")
        .and_then(Value::as_str)
        .or(inferred)
        .filter(|s| valid_identity(s))
        .ok_or_else(malformed)?
        .to_owned();
    let mut doc = ProcessedDocument {
        title: metadata
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or(&slug)
            .to_owned(),
        slug,
        page_type: metadata
            .get("page-type")
            .and_then(Value::as_str)
            .map(str::to_owned),
        status: strings(metadata.get("status")),
        compatibility_keys: strings(metadata.get("browser-compat")),
        spec_urls: strings(metadata.get("spec-urls")),
        headings: Vec::new(),
        links: Vec::new(),
        text: String::new(),
        metadata,
        macros: Vec::new(),
        gaps: Vec::new(),
        dependencies: Vec::new(),
    };
    // Preserve the full raw front matter, but do not silently count a field as
    // processed when its historical or malformed shape is unsupported.
    for field in ["title", "short-title", "slug", "page-type"] {
        if doc
            .metadata
            .get(field)
            .is_some_and(|value| !value.is_string())
        {
            doc.gaps
                .push(ProcessingGap::new("unsupported_front_matter_type", field));
        }
    }
    for field in ["browser-compat", "spec-urls", "sidebar"] {
        if doc.metadata.get(field).is_some_and(|value| {
            !value.is_string()
                && !value
                    .as_array()
                    .is_some_and(|items| items.iter().all(Value::is_string))
        }) {
            doc.gaps
                .push(ProcessingGap::new("unsupported_front_matter_type", field));
        }
    }
    if doc.metadata.get("status").is_some_and(|value| {
        !value
            .as_array()
            .is_some_and(|items| items.iter().all(Value::is_string))
    }) {
        doc.gaps.push(ProcessingGap::new(
            "unsupported_front_matter_type",
            "status",
        ));
    }
    if doc.metadata.get("slug").is_none() {
        doc.gaps.push(ProcessingGap::new(
            "inferred_slug",
            "Slug inferred from retained source path.",
        ));
    }
    let mut expansion = Expansion {
        resolver,
        budget,
        stack: vec![path.to_owned()],
        includes: 0,
        macros: 0,
    };
    let expanded = expansion.expand(body, &mut doc)?;
    let html_source = path.ends_with(".html") || path.ends_with(".htm");
    let (text, headings, links) = if html_source {
        html::project(&expanded, budget)?
    } else {
        markdown(&expanded, budget)?
    };
    doc.text = text;
    doc.headings = headings;
    doc.links.extend(links);
    doc.links.retain(|s| safe_link(s));
    doc.links.sort();
    doc.links.dedup();
    doc.compatibility_keys.sort();
    doc.compatibility_keys.dedup();
    doc.dependencies
        .sort_by(|a, b| (&a.path, &a.identity).cmp(&(&b.path, &b.identity)));
    doc.dependencies.dedup();
    doc.gaps
        .sort_by(|a, b| (&a.code, &a.detail).cmp(&(&b.code, &b.detail)));
    doc.gaps.dedup();
    budget.check()?;
    Ok(doc)
}

fn markdown(source: &str, budget: &ProcessingBudget) -> Result<(String, Vec<String>, Vec<String>)> {
    // Feed raw HTML and escaped Markdown text through one tokenizer so script/template
    // visibility persists across inline events without interpreting code examples.
    let mut markup = String::new();
    let mut links = Vec::new();
    let mut events = 0;
    for event in MarkdownParser::new_ext(
        source,
        Options::ENABLE_TABLES
            | Options::ENABLE_STRIKETHROUGH
            | Options::ENABLE_TASKLISTS
            | Options::ENABLE_FOOTNOTES,
    ) {
        budget.check()?;
        events += 1;
        if events > 500_000 {
            return Err(limit());
        }
        match event {
            MarkdownEvent::Start(Tag::Heading { .. }) => push(&mut markup, "<h2>")?,
            MarkdownEvent::Start(Tag::Link { dest_url, .. } | Tag::Image { dest_url, .. }) => {
                if links.len() >= MAX_ITEMS {
                    return Err(limit());
                }
                if safe_link(&dest_url) {
                    links.push(dest_url.into_string());
                }
            }
            MarkdownEvent::Text(t)
            | MarkdownEvent::Code(t)
            | MarkdownEvent::FootnoteReference(t)
            | MarkdownEvent::InlineMath(t)
            | MarkdownEvent::DisplayMath(t) => {
                for ch in t.chars() {
                    match ch {
                        '&' => push(&mut markup, "&amp;")?,
                        '<' => push(&mut markup, "&lt;")?,
                        '>' => push(&mut markup, "&gt;")?,
                        _ => {
                            let mut bytes = [0; 4];
                            push(&mut markup, ch.encode_utf8(&mut bytes))?;
                        }
                    }
                }
            }
            MarkdownEvent::Html(t) | MarkdownEvent::InlineHtml(t) => push(&mut markup, &t)?,
            MarkdownEvent::End(TagEnd::Heading(_)) => push(&mut markup, "</h2>")?,
            MarkdownEvent::End(
                TagEnd::Paragraph
                | TagEnd::CodeBlock
                | TagEnd::Item
                | TagEnd::TableCell
                | TagEnd::TableRow,
            )
            | MarkdownEvent::SoftBreak
            | MarkdownEvent::HardBreak
            | MarkdownEvent::Rule => push(&mut markup, "\n")?,
            MarkdownEvent::TaskListMarker(v) => push(&mut markup, if v { "[x] " } else { "[ ] " })?,
            _ => {}
        }
    }
    let (text, headings, html_links) = html::project(&markup, budget)?;
    links.extend(html_links);
    if links.len() > MAX_ITEMS {
        return Err(limit());
    }
    Ok((text, headings, links))
}

struct Expansion<'a> {
    resolver: &'a mut dyn FnMut(&str) -> Result<Option<IncludedDocument>>,
    budget: &'a ProcessingBudget,
    stack: Vec<String>,
    includes: usize,
    macros: usize,
}
impl Expansion<'_> {
    fn expand(&mut self, source: &str, doc: &mut ProcessedDocument) -> Result<String> {
        // Source offset ranges prevent template interpretation inside code examples.
        let mut protected = Vec::new();
        let mut start = None;
        for (event, range) in MarkdownParser::new(source).into_offset_iter() {
            match event {
                MarkdownEvent::Start(Tag::CodeBlock(_)) => start = Some(range.start),
                MarkdownEvent::End(TagEnd::CodeBlock) => {
                    if let Some(at) = start.take() {
                        protected.push(at..range.end);
                    }
                }
                MarkdownEvent::Code(_) => protected.push(range),
                _ => {}
            }
        }
        // Legacy HTML examples and hidden active elements are data too. Merge
        // their lexical ranges with Markdown code ranges before scanning macros.
        let lowered = source.to_ascii_lowercase();
        for name in [
            "pre", "code", "script", "style", "template", "textarea", "iframe",
        ] {
            let opening = format!("<{name}");
            let closing = format!("</{name}");
            let mut offset = 0;
            while let Some(at) = lowered[offset..].find(&opening).map(|at| offset + at) {
                self.budget.check()?;
                let boundary = at + opening.len();
                if lowered
                    .as_bytes()
                    .get(boundary)
                    .is_some_and(|b| !b.is_ascii_whitespace() && *b != b'>' && *b != b'/')
                {
                    offset = boundary;
                    continue;
                }
                let end = lowered[boundary..]
                    .find(&closing)
                    .and_then(|at| {
                        let close = boundary + at + closing.len();
                        lowered[close..].find('>').map(|at| close + at + 1)
                    })
                    .unwrap_or(source.len());
                protected.push(at..end);
                offset = end;
            }
        }
        protected.sort_by_key(|range| range.start);
        let mut merged: Vec<std::ops::Range<usize>> = Vec::new();
        for range in protected {
            if let Some(last) = merged.last_mut()
                && range.start <= last.end
            {
                last.end = last.end.max(range.end);
            } else {
                merged.push(range);
            }
        }
        let protected = merged;
        let mut out = String::new();
        let mut offset = 0;
        let mut code_at = 0;
        while let Some(at) = source[offset..].find("{{").map(|at| offset + at) {
            self.budget.check()?;
            while code_at < protected.len() && protected[code_at].end <= at {
                code_at += 1;
            }
            if protected
                .get(code_at)
                .is_some_and(|range| range.contains(&at))
            {
                let end = protected[code_at].end;
                push(&mut out, &source[offset..end])?;
                offset = end;
                continue;
            }
            push(&mut out, &source[offset..at])?;
            let Some((end, name, args)) = macro_call(source, at) else {
                doc.gaps.push(ProcessingGap::new(
                    "malformed_macro",
                    "Unterminated or unsupported macro syntax.",
                ));
                push(&mut out, &source[at..])?;
                return Ok(out);
            };
            self.macros += 1;
            if self.macros > MAX_MACROS {
                return Err(limit());
            }
            if !doc.macros.contains(&name) {
                doc.macros.push(name.clone());
            }
            let normalized = name.to_ascii_lowercase();
            if matches!(normalized.as_str(), "include" | "page") {
                self.include(&name, &args, doc, &mut out)?;
            } else if matches!(
                normalized.as_str(),
                "compat" | "browsercompat" | "compatibilitytable"
            ) {
                if let Some(key) = args.first().filter(|key| valid_identity(key)) {
                    doc.compatibility_keys.push(key.clone());
                }
                push(
                    &mut out,
                    "\n[Compatibility data: see the pinned compatibility snapshot.]\n",
                )?;
            } else if let Some(label) = status_label(&normalized) {
                push(&mut out, label)?;
            } else if let Some((label, link)) = reference(&normalized, &args) {
                push(&mut out, &literal(&label))?;
                doc.links.push(link);
            } else {
                doc.gaps
                    .push(ProcessingGap::new("unsupported_macro", name.clone()));
                push(&mut out, &format!("[Inert MDN macro: {name}]"))?;
            }
            offset = end;
        }
        push(&mut out, &source[offset..])?;
        Ok(out)
    }
    fn include(
        &mut self,
        name: &str,
        args: &[String],
        doc: &mut ProcessedDocument,
        out: &mut String,
    ) -> Result<()> {
        let Some(path) = args.first().and_then(|s| include_path(s)) else {
            doc.gaps
                .push(ProcessingGap::new("unsupported_include", name));
            push(out, "[Unresolved MDN include]")?;
            return Ok(());
        };
        if args.len() > 1 && args[1..].iter().any(|s| !s.is_empty()) {
            doc.gaps
                .push(ProcessingGap::new("unsupported_include_section", path));
            push(out, "[Unsupported scoped MDN include]")?;
            return Ok(());
        }
        if self.stack.len() >= 16 || self.includes >= 128 {
            doc.gaps.push(ProcessingGap::new("include_limit", path));
            push(out, "[MDN include limit]")?;
            return Ok(());
        }
        if self.stack.contains(&path) {
            doc.gaps.push(ProcessingGap::new("include_cycle", path));
            push(out, "[Cyclic MDN include]")?;
            return Ok(());
        }
        self.includes += 1;
        let included = (self.resolver)(&path)?;
        self.budget.check()?;
        // Record missing dependencies too, so a newly appearing target invalidates this projection.
        doc.dependencies.push(Dependency {
            path: path.clone(),
            identity: included
                .as_ref()
                .map(|v| v.identity.clone())
                .unwrap_or_default(),
        });
        let Some(included) = included else {
            doc.gaps.push(ProcessingGap::new("missing_include", path));
            push(out, "[Missing MDN include]")?;
            return Ok(());
        };
        if included.path != path || !valid_identity(&included.identity) {
            return Err(malformed());
        }
        if included.body.len() > MAX_MEMBER {
            return Err(limit());
        }
        let source = std::str::from_utf8(&included.body).map_err(|_| malformed())?;
        let (_, body) = front_matter(source, self.budget)?;
        self.stack.push(path);
        let expanded = self.expand(body, doc);
        self.stack.pop();
        push(out, "\n")?;
        push(out, &expanded?)?;
        push(out, "\n")
    }
}
fn include_path(s: &str) -> Option<String> {
    let target = s
        .strip_prefix("/en-US/docs/")
        .or_else(|| s.strip_prefix("/en-us/docs/"))
        .or_else(|| s.strip_prefix("/docs/"))
        .unwrap_or(s);
    if target.is_empty()
        || target.len() > 2048
        || target.chars().any(char::is_control)
        || target.contains(['\\', '?', '#', ':', '%'])
        || target
            .split('/')
            .any(|s| s.is_empty() || s == "." || s == "..")
    {
        return None;
    }
    let target = if target.starts_with("files/en-us/") {
        target.to_owned()
    } else {
        format!("files/en-us/{}/index.md", target.to_ascii_lowercase())
    };
    if !target.starts_with("files/en-us/")
        || !(target.ends_with("/index.md") || target.ends_with("/index.html"))
    {
        return None;
    }
    Some(target)
}
fn status_label(s: &str) -> Option<&'static str> {
    match s {
        "deprecated_header" | "deprecated_inline" => Some("[Deprecated]"),
        "experimental_header" | "experimental_inline" => Some("[Experimental]"),
        "non-standard_header" | "non-standard_inline" | "nonstandard_inline" => {
            Some("[Non-standard]")
        }
        "securecontext_header" | "securecontext_inline" | "securecontext" => {
            Some("[Secure context required]")
        }
        "optional_inline" => Some("[Optional]"),
        "readonlyinline" => Some("[Read only]"),
        "availableinworkers" => Some("[Available in workers]"),
        _ => None,
    }
}
fn literal(text: &str) -> String {
    let mut out = String::new();
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\\' | '[' | ']' | '*' | '_' | '`' | '!' => {
                out.push('\\');
                out.push(ch);
            }
            _ => out.push(ch),
        }
    }
    out
}
fn reference(name: &str, args: &[String]) -> Option<(String, String)> {
    let original = args.first()?;
    if !valid_identity(original)
        || original.contains(['\\', '?'])
        || original.split('/').any(|s| s == "..")
    {
        return None;
    }
    let (target, fragment) = original
        .split_once('#')
        .map(|(target, fragment)| (target, Some(fragment)))
        .unwrap_or((original, None));
    let mut label = args.get(1).cloned().unwrap_or_else(|| original.clone());
    let (prefix, target) = match name {
        "domxref" => ("Web/API/", target.replace('.', "/")),
        "jsxref"
            if [
                "Operators/",
                "Statements/",
                "Functions/",
                "Classes/",
                "Lexical_grammar",
            ]
            .iter()
            .any(|prefix| target.starts_with(prefix)) =>
        {
            ("Web/JavaScript/Reference/", target.to_owned())
        }
        "jsxref" => (
            "Web/JavaScript/Reference/Global_Objects/",
            target.replace('.', "/"),
        ),
        "cssxref" => ("Web/CSS/", target.to_owned()),
        "htmlelement" => ("Web/HTML/Reference/Elements/", target.to_owned()),
        "htmlattrxref" => {
            label = args.get(2).cloned().unwrap_or_else(|| original.clone());
            if let Some(element) = args.get(1).filter(|s| !s.is_empty()) {
                if !valid_identity(element) || element.contains(['/', '\\', '?', '#', ':']) {
                    return None;
                }
                (
                    "Web/HTML/Reference/Elements/",
                    format!("{element}#{target}"),
                )
            } else {
                ("Web/HTML/Reference/Global_attributes/", target.to_owned())
            }
        }
        "svgelement" => ("Web/SVG/Reference/Element/", target.to_owned()),
        "svgattr" => ("Web/SVG/Reference/Attribute/", target.to_owned()),
        "httpheader" => ("Web/HTTP/Reference/Headers/", target.to_owned()),
        "httpmethod" => ("Web/HTTP/Reference/Methods/", target.to_owned()),
        "httpstatus" => ("Web/HTTP/Reference/Status/", target.to_owned()),
        "glossary" => ("Glossary/", target.to_owned()),
        "webextapixref" => (
            "Mozilla/Add-ons/WebExtensions/API/",
            target.replace('.', "/"),
        ),
        _ => return None,
    };
    let (target, generated_fragment) = target
        .split_once('#')
        .map(|(t, f)| (t, Some(f)))
        .unwrap_or((&target, None));
    let mut url = url::Url::parse("https://developer.mozilla.org/en-US/docs/").ok()?;
    {
        let mut segments = url.path_segments_mut().ok()?;
        segments.pop_if_empty();
        for segment in prefix
            .split('/')
            .chain(target.split('/'))
            .filter(|s| !s.is_empty())
        {
            segments.push(segment);
        }
    }
    url.set_fragment(fragment.or(generated_fragment));
    Some((label, url.into()))
}

fn macro_call(source: &str, at: usize) -> Option<(usize, String, Vec<String>)> {
    let mut quote = None;
    let mut escaped = false;
    let mut end = None;
    for (offset, ch) in source[at + 2..].char_indices() {
        if offset > 16_384 {
            return None;
        }
        if escaped {
            escaped = false;
            continue;
        }
        if let Some(q) = quote {
            if ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
            continue;
        }
        if ch == '\'' || ch == '"' {
            quote = Some(ch);
            continue;
        }
        if ch == '}' && source[at + 2 + offset..].starts_with("}}") {
            end = Some(at + 2 + offset);
            break;
        }
    }
    let end = end?;
    let inner = source[at + 2..end].trim();
    let (name, args) = if let Some(open) = inner.find('(') {
        if !inner.ends_with(')') {
            return None;
        }
        (
            inner[..open].trim(),
            arguments(&inner[open + 1..inner.len() - 1])?,
        )
    } else {
        (inner, Vec::new())
    };
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return None;
    }
    Some((end + 2, name.to_owned(), args))
}
fn arguments(s: &str) -> Option<Vec<String>> {
    if s.trim().is_empty() {
        return Some(Vec::new());
    }
    let mut result = Vec::new();
    let mut text = String::new();
    let mut quote = None;
    let mut escaped = false;
    for ch in s.chars() {
        if escaped {
            if !matches!(ch, '\\' | '\'' | '"' | '/') {
                return None;
            }
            text.push(ch);
            escaped = false;
            continue;
        }
        if let Some(q) = quote {
            if ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            } else {
                text.push(ch);
            }
        } else if ch == '\'' || ch == '"' {
            quote = Some(ch);
        } else if ch == ',' {
            result.push(text.trim().to_owned());
            text.clear();
            if result.len() >= 32 {
                return None;
            }
        } else if ch.is_ascii_alphanumeric() || ch.is_whitespace() || matches!(ch, '-' | '.' | '_')
        {
            text.push(ch);
        } else {
            return None;
        }
    }
    if quote.is_some() || escaped {
        return None;
    }
    result.push(text.trim().to_owned());
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn run(s: &str) -> Result<ProcessedDocument> {
        process_document(
            "files/en-us/web/api/test/index.md",
            s.as_bytes(),
            &mut |_| Ok(None),
            &ProcessingBudget::new(CancellationToken::new()),
        )
    }
    #[test]
    fn metadata_examples_and_macros_are_inert() {
        let doc = run("---\ntitle: Test\nslug: Web/API/Test\npage-type: guide\nbrowser-compat: [api.Test]\n---\n# Heading\n{{domxref('Window', 'window')}} {{experimental_inline}}\n```js\n{{include('Web/Evil')}}\n```\n{{EmbedLiveSample('x')}}\n<script>steal()</script><p>Visible</p>").expect("valid fixture");
        assert_eq!(doc.slug, "Web/API/Test");
        assert!(doc.text.contains("{{include('Web/Evil')}}"));
        assert!(doc.text.contains("[Experimental]"));
        assert!(!doc.text.contains("steal()"));
        assert!(doc.text.contains("Visible"));
        assert!(doc.links.iter().any(|s| s.ends_with("/Web/API/Window")));
        assert!(doc.gaps.iter().any(|g| g.code == "unsupported_macro"));
    }
    #[test]
    fn includes_record_dependencies_and_cycles() {
        let body = b"---\ntitle: A\nslug: A\n---\n{{include('B')}}";
        let doc = process_document(
            "files/en-us/a/index.md",
            body,
            &mut |path| {
                Ok(Some(IncludedDocument {
                    path: path.into(),
                    identity: "blob-b".into(),
                    body: b"---\nslug: B\n---\nIncluded {{include('A')}}".to_vec(),
                }))
            },
            &ProcessingBudget::new(CancellationToken::new()),
        )
        .expect("bounded include");
        assert!(doc.text.contains("Included"));
        assert_eq!(doc.dependencies.len(), 1);
        assert!(doc.gaps.iter().any(|g| g.code == "include_cycle"));
    }
    #[test]
    fn reject_yaml_aliases_duplicates_and_path_escape() {
        assert!(run("---\nslug: Test\nslug: Other\n---\nx").is_err());
        assert!(run("---\nslug: &a Test\ntitle: *a\n---\nx").is_err());
        let doc = run("---\nslug: Test\n---\n{{include('../escape')}}")
            .expect("inert unsupported include");
        assert_eq!(doc.dependencies.len(), 0);
        assert!(doc.gaps.iter().any(|g| g.code == "unsupported_include"));
    }
    #[test]
    fn missing_include_and_cancellation_are_explicit() {
        let doc =
            run("---\nslug: Test\n---\n{{include('Missing')}}").expect("missing include is a gap");
        assert_eq!(doc.dependencies[0].identity, "");
        assert_eq!(doc.gaps[0].code, "missing_include");
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert!(
            process_document("a", b"x", &mut |_| Ok(None), &ProcessingBudget::new(cancel)).is_err()
        );
    }
    #[test]
    fn html_examples_and_hidden_macros_never_resolve_includes() {
        let source = b"---\nslug: Test\ntitle: Test\n---\n<pre>{{include('Example')}}</pre><script>{{include('Secret')}}</script><p>Visible</p>";
        let doc = process_document(
            "files/en-us/test/index.html",
            source,
            &mut |_| panic!("example/hidden macro must not resolve"),
            &ProcessingBudget::new(CancellationToken::new()),
        )
        .expect("inert HTML");
        assert!(doc.text.contains("{{include('Example')}}"));
        assert!(!doc.text.contains("Secret"));
        assert!(doc.text.contains("Visible"));
        assert!(doc.dependencies.is_empty());
    }
    #[test]
    fn reference_labels_and_scoped_includes_preserve_meaning() {
        let doc = run("---\nslug: Test\n---\n{{domxref('Window.fetch')}} {{cssxref(':focus')}} {{jsxref('Operators/typeof')}} {{domxref('Window','<b>literal</b>')}} {{page('Web/API/Test','Section')}}").expect("macros");
        assert!(doc.text.contains("Window.fetch"));
        assert!(doc.text.contains("<b>literal</b>"));
        assert!(
            doc.links
                .iter()
                .any(|s| s.ends_with("/Web/JavaScript/Reference/Operators/typeof"))
        );
        assert!(doc.links.iter().any(|s| s.contains("Web/CSS/")));
        assert!(
            doc.gaps
                .iter()
                .any(|g| g.code == "unsupported_include_section")
        );
    }
}

#[cfg(test)]
mod metadata_shape_tests {
    use super::*;
    #[test]
    fn known_front_matter_shape_gaps_preserve_original_metadata() {
        let source = b"---\ntitle: [wrong]\nslug: Test\npage-type: false\nbrowser-compat: {}\nstatus: [experimental, 42]\nspec-urls: 17\nunknown-extra: {retained: true}\n---\nVisible article.";
        let doc = process_document(
            "files/en-us/test/index.md",
            source,
            &mut |_| Ok(None),
            &ProcessingBudget::new(CancellationToken::new()),
        )
        .expect("retained unsupported metadata");
        assert_eq!(doc.metadata["browser-compat"], json!({}));
        assert_eq!(doc.metadata["unknown-extra"]["retained"], true);
        assert!(doc.gaps.iter().any(
            |gap| gap.code == "unsupported_front_matter_type" && gap.detail == "browser-compat"
        ));
        assert!(
            doc.gaps
                .iter()
                .any(|gap| gap.code == "unsupported_front_matter_type" && gap.detail == "status")
        );
        assert!(
            doc.gaps
                .iter()
                .any(|gap| gap.code == "unsupported_front_matter_type" && gap.detail == "title")
        );
        assert!(doc.gaps.iter().any(|gap|gap.code=="unsupported_front_matter_type"&&gap.detail=="page-type"));
        assert!(doc.gaps.iter().any(|gap|gap.code=="unsupported_front_matter_type"&&gap.detail=="spec-urls"));
        assert!(doc.text.contains("Visible article"));
    }
}
