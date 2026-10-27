//! Chromium-only inert projections and repository-relative references. Upstream
//! generators, templates, examples and build systems are never evaluated.
pub use crate::standards_processing::{
    MAX_INPUT, ProcessedDocument, ProcessingGap, Reference, Section, Symbol,
};
use devres_domain::{Error, Result};
use html5ever::{
    tendril::StrTendril,
    tokenizer::{
        BufferQueue, TagKind, Token, TokenSink, TokenSinkResult, Tokenizer, TokenizerOpts,
        states::RawKind,
    },
};
use pulldown_cmark::{Event, Options, Parser, Tag, TagEnd};
use std::{
    cell::RefCell,
    collections::BTreeSet,
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;
pub const CLASSIFIER_VERSION: u32 = 1;
pub const PROCESSOR_VERSION: u32 = 1;
const MAX_ITEMS: usize = 100_000;

/// File type alone cannot turn a browser test vector or vendored source into
/// documentation. Explicit source mappings can separately qualify such a path.
pub fn candidate(path: &str) -> bool {
    if !crate::chromium::source::valid_path(path) || path.is_empty() {
        return false;
    }
    let lower = path.to_ascii_lowercase();
    let parts: Vec<_> = lower.split('/').collect();
    if parts.iter().any(|p| {
        matches!(
            *p,
            "testdata"
                | "test_data"
                | "test-data"
                | "fixtures"
                | "web_tests"
                | "generated"
                | "gen"
                | "vendor"
                | "node_modules"
                | "_assets"
                | "_includes"
                | "_stylesheets"
        )
    }) {
        return false;
    }
    // Blink is a first-party documentation source despite its repository path.
    if parts.first() == Some(&"third_party") && parts.get(1) != Some(&"blink") {
        return false;
    }
    let name = parts.last().copied().unwrap_or("");
    if name.ends_with(".md")
        || name.ends_with(".markdown")
        || ["readme", "install", "changelog"]
            .iter()
            .any(|prefix| name == *prefix || name.starts_with(&format!("{prefix}.")))
    {
        return true;
    }
    let doc_namespace = parts
        .iter()
        .any(|p| matches!(*p, "doc" | "docs" | "documentation"));
    doc_namespace
        && [
            ".html",
            ".htm",
            ".xhtml",
            ".txt",
            ".rst",
            ".adoc",
            ".asciidoc",
        ]
        .iter()
        .any(|suffix| name.ends_with(suffix))
}
pub fn notice(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or("").to_ascii_lowercase();
    crate::chromium::source::valid_path(path)
        && ["license", "copying", "notice", "authors"]
            .iter()
            .any(|prefix| name == *prefix || name.starts_with(&format!("{prefix}.")))
}

/// Resolve a captured literal reference within its own repository. `//foo` is
/// Chromium's repository-root syntax, not authority to fetch another host.
pub fn resolve_reference(path: &str, target: &str) -> Option<(String, Option<String>)> {
    if !crate::chromium::source::valid_path(path)
        || target.is_empty()
        || target.len() > 4096
        || target.chars().any(|c| c.is_control() || c == '\\')
    {
        return None;
    }
    if url::Url::parse(target).is_ok() || target.contains('?') {
        return None;
    }
    let (target, anchor) = match target.split_once('#') {
        Some((p, a)) => (p, Some(a.to_owned())),
        None => (target, None),
    };
    if target.contains('%') || target.contains(':') {
        return None;
    }
    let mut parts: Vec<&str> = if target.starts_with('/') {
        Vec::new()
    } else {
        path.rsplit_once('/')
            .map(|(p, _)| p.split('/').collect())
            .unwrap_or_default()
    };
    if target.is_empty() {
        return Some((path.to_owned(), anchor));
    }
    for part in target.trim_start_matches('/').split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            p => parts.push(p),
        }
    }
    let normalized = parts.join("/");
    if !crate::chromium::source::valid_path(&normalized) || normalized.is_empty() {
        return None;
    }
    Some((normalized, anchor))
}
fn check(cancel: &CancellationToken, start: Instant) -> Result<()> {
    if cancel.is_cancelled() {
        return Err(Error::new("cancelled", "Chromium processing canceled."));
    }
    if start.elapsed() > Duration::from_secs(15) {
        return Err(Error::capacity("Chromium processing bounds exceeded."));
    }
    Ok(())
}
fn gap(doc: &mut ProcessedDocument, code: &str, message: &str) {
    if !doc.gaps.iter().any(|g| g.code == code) {
        doc.gaps.push(ProcessingGap {
            code: code.into(),
            message: message.into(),
        });
    }
}
fn diagnostic(mut error: Error) -> Error {
    error.message = error.message.replace("WHATWG", "Chromium");
    error
}
fn plain(path: &str, source: &str, format: &str) -> ProcessedDocument {
    let title = path.rsplit('/').next().unwrap_or(path).to_owned();
    ProcessedDocument {
        format: format.into(),
        title: title.clone(),
        text: source.into(),
        sections: vec![Section {
            anchor: "document".into(),
            title,
            text: source.into(),
        }],
        ..Default::default()
    }
}
fn frontmatter(source: &str) -> (&str, Option<String>, bool) {
    if !source.starts_with("---\n") && !source.starts_with("---\r\n") {
        return (source, None, false);
    }
    let mut bytes = 0;
    let mut title = None;
    for (index, line) in source.split_inclusive('\n').enumerate() {
        bytes += line.len();
        if bytes > 64 * 1024 {
            return (source, None, true);
        }
        if index > 0 && matches!(line.trim(), "---" | "...") {
            return (&source[bytes..], title, false);
        }
        if let Some(value) = line.trim().strip_prefix("title:") {
            let value = value.trim();
            if value.len() <= 4096 && !value.starts_with(['!', '&', '*', '{', '[', '|', '>']) {
                title = Some(value.trim_matches(['\'', '"']).to_owned());
            }
        }
    }
    (source, None, true)
}
fn prose_to_markdown(
    source: &str,
    format: &str,
    cancel: &CancellationToken,
    start: Instant,
) -> Result<(String, bool)> {
    let lines: Vec<_> = source.lines().collect();
    if lines.len() > MAX_ITEMS {
        return Err(Error::capacity("Chromium prose line bound exceeded."));
    }
    let mut result = String::new();
    let mut unsupported = false;
    let mut index = 0;
    while index < lines.len() {
        check(cancel, start)?;
        let line = lines[index];
        if format == "rst" && index + 1 < lines.len() {
            let underline = lines[index + 1].trim();
            if underline.len() >= line.trim().len()
                && !line.trim().is_empty()
                && underline.chars().all(|c| c == '=' || c == '-' || c == '~')
                && !underline.is_empty()
            {
                result.push_str(if underline.starts_with('=') {
                    "# "
                } else if underline.starts_with('-') {
                    "## "
                } else {
                    "### "
                });
                result.push_str(line);
                result.push('\n');
                index += 2;
                continue;
            }
        }
        if format == "asciidoc" && line.starts_with('=') {
            let count = line.bytes().take_while(|b| *b == b'=').count();
            if count <= 6 && line.as_bytes().get(count) == Some(&b' ') {
                result.push_str(&"#".repeat(count));
                result.push_str(&line[count..]);
                result.push('\n');
                index += 1;
                continue;
            }
        }
        if line.trim_start().starts_with(".. ")
            || line.contains("include::")
            || line.contains("{%")
            || line.contains("{{")
        {
            unsupported = true;
        }
        // Preserve indented literal blocks/code as text. No directive is evaluated.
        result.push_str(line);
        result.push('\n');
        index += 1;
        if result.len() > MAX_INPUT {
            return Err(Error::capacity("Chromium prose input exceeds its bound."));
        }
    }
    Ok((result, unsupported))
}

fn markdown_references(
    source: &str,
    cancel: &CancellationToken,
    start: Instant,
) -> Result<Vec<Reference>> {
    let mut references = Vec::new();
    let mut link: Option<(String, String)> = None;
    let mut events = 0;
    for event in Parser::new_ext(
        source,
        Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH | Options::ENABLE_HEADING_ATTRIBUTES,
    ) {
        events += 1;
        if events > 4_000_000 {
            return Err(Error::capacity("Chromium Markdown event bound exceeded."));
        }
        check(cancel, start)?;
        match event {
            Event::Start(Tag::Link { dest_url, .. }) => {
                let literal = dest_url.to_string();
                if literal.len() <= 4096 && !literal.chars().any(char::is_control) {
                    link = Some((literal, String::new()));
                }
            }
            Event::Text(text) | Event::Code(text) => {
                if let Some((_, label)) = &mut link
                    && label.len() + text.len() <= 4096
                {
                    label.push_str(&text);
                }
            }
            Event::End(TagEnd::Link) => {
                if let Some((target, label)) = link.take() {
                    references.push(Reference {
                        source_anchor: "document".into(),
                        target,
                        label,
                    });
                }
            }
            _ => {}
        }
        if references.len() > MAX_ITEMS {
            return Err(Error::capacity("Chromium reference bound exceeded."));
        }
    }
    Ok(references)
}
fn markdown_html_markup(
    source: &str,
    cancel: &CancellationToken,
    start: Instant,
) -> Result<String> {
    let mut markup = String::new();
    for (count, event) in Parser::new_ext(
        source,
        Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH | Options::ENABLE_HEADING_ATTRIBUTES,
    )
    .enumerate()
    {
        check(cancel, start)?;
        if count > 4_000_000 {
            return Err(Error::capacity("Chromium Markdown event bound exceeded."));
        }
        // Raw HTML is markup. Markdown code/text events are examples or prose,
        // even when their bytes resemble an HTML API declaration.
        if let Event::Html(html) | Event::InlineHtml(html) = event {
            if markup
                .len()
                .checked_add(html.len() + 1)
                .is_none_or(|n| n > MAX_INPUT)
            {
                return Err(Error::capacity("Chromium HTML markup bound exceeded."));
            }
            markup.push_str(&html);
            markup.push('\n');
        }
    }
    Ok(markup)
}
#[derive(Default)]
struct HtmlReferences {
    references: Vec<Reference>,
    apis: Vec<Symbol>,
    active: Vec<(String, String)>,
    hidden: usize,
    code: usize,
    error: bool,
}
struct Sink<'a> {
    state: RefCell<HtmlReferences>,
    cancel: &'a CancellationToken,
    start: Instant,
}
impl TokenSink for Sink<'_> {
    type Handle = ();
    fn process_token(&self, token: Token, _line: u64) -> TokenSinkResult<()> {
        let mut state = self.state.borrow_mut();
        if check(self.cancel, self.start).is_err() {
            state.error = true;
            return TokenSinkResult::Continue;
        }
        match token {
            Token::TagToken(tag) => {
                let name: &str = tag.name.as_ref();
                let hidden = matches!(
                    name,
                    "script" | "style" | "template" | "noscript" | "iframe"
                );
                if tag.kind == TagKind::EndTag {
                    if hidden {
                        state.hidden = state.hidden.saturating_sub(1);
                    }
                    if matches!(name, "pre" | "code") {
                        state.code = state.code.saturating_sub(1);
                    }
                    if name == "a"
                        && state.hidden == 0
                        && let Some((target, label)) = state.active.pop()
                    {
                        state.references.push(Reference {
                            source_anchor: "document".into(),
                            target,
                            label,
                        });
                    }
                    return TokenSinkResult::Continue;
                }
                if hidden {
                    state.hidden = state.hidden.saturating_add(1);
                    return if matches!(name, "script" | "style") {
                        TokenSinkResult::RawData(if name == "script" {
                            RawKind::ScriptData
                        } else {
                            RawKind::Rawtext
                        })
                    } else {
                        TokenSinkResult::Continue
                    };
                }
                if state.hidden > 0 {
                    return TokenSinkResult::Continue;
                }
                if matches!(name, "pre" | "code") {
                    state.code = state.code.saturating_add(1);
                }
                if state.code > 0 {
                    return TokenSinkResult::Continue;
                }
                if name == "a"
                    && let Some(attr) = tag.attrs.iter().find(|a| &*a.name.local == "href")
                {
                    let target = attr.value.to_string();
                    if target.len() <= 4096
                        && !target.chars().any(char::is_control)
                        && state.active.len() < 256
                    {
                        state.active.push((target, String::new()));
                    }
                }
                if let Some(attr) = tag.attrs.iter().find(|a| &*a.name.local == "data-api-name") {
                    let name = attr.value.to_string();
                    let anchor = tag
                        .attrs
                        .iter()
                        .find(|a| &*a.name.local == "id")
                        .map(|a| a.value.to_string())
                        .unwrap_or_else(|| "document".into());
                    if !name.is_empty() && name.len() <= 4096 && anchor.len() <= 4096 {
                        state.apis.push(Symbol {
                            kind: "api".into(),
                            name: name.clone(),
                            anchor,
                            text: name,
                            scope: None,
                        });
                    }
                }
                if state.references.len() + state.apis.len() > MAX_ITEMS {
                    state.error = true;
                }
            }
            Token::CharacterTokens(text) if state.hidden == 0 => {
                for (_, label) in &mut state.active {
                    if label.len() + text.len() <= 4096 {
                        label.push_str(&text);
                    }
                }
            }
            _ => {}
        }
        TokenSinkResult::Continue
    }
}
fn html_references(
    source: &str,
    cancel: &CancellationToken,
    start: Instant,
) -> Result<HtmlReferences> {
    let sink = Sink {
        state: RefCell::new(HtmlReferences::default()),
        cancel,
        start,
    };
    let tokenizer = Tokenizer::new(sink, TokenizerOpts::default());
    let input = BufferQueue::default();
    // Feeding bounded character chunks prevents unbounded intermediate input
    // buffers; the shared projector independently bounds lexical constructs.
    let mut offset = 0;
    while offset < source.len() {
        check(cancel, start)?;
        let mut end = (offset + 4096).min(source.len());
        while !source.is_char_boundary(end) {
            end -= 1;
        }
        input.push_back(StrTendril::from_slice(&source[offset..end]));
        let _ = tokenizer.feed(&input);
        offset = end;
    }
    tokenizer.end();
    let state = tokenizer.sink.state.into_inner();
    if state.error {
        return Err(Error::capacity("Chromium HTML reference bounds exceeded."));
    }
    Ok(state)
}
pub fn process_document(
    path: &str,
    bytes: &[u8],
    cancel: CancellationToken,
) -> Result<ProcessedDocument> {
    let start = Instant::now();
    check(&cancel, start)?;
    if bytes.len() > MAX_INPUT || !crate::chromium::source::valid_path(path) {
        return Err(Error::capacity("Chromium processing bounds exceeded."));
    }
    let source = std::str::from_utf8(bytes)
        .map_err(|_| Error::integrity("Chromium documentation is not UTF-8."))?;
    if source.contains('\0') {
        return Err(Error::integrity(
            "Chromium documentation contains NUL bytes.",
        ));
    }
    let lower = path.to_ascii_lowercase();
    let format = if lower.ends_with(".rst") {
        "rst"
    } else if lower.ends_with(".adoc") || lower.ends_with(".asciidoc") {
        "asciidoc"
    } else if lower.ends_with(".html") || lower.ends_with(".htm") || lower.ends_with(".xhtml") {
        "html"
    } else if lower.ends_with(".md")
        || lower.ends_with(".markdown")
        || lower
            .rsplit('/')
            .next()
            .is_some_and(|n| n.starts_with("readme"))
    {
        "markdown"
    } else {
        "text"
    };
    let (source, title, frontmatter_gap) = if format == "markdown" {
        frontmatter(source)
    } else {
        (source, None, false)
    };
    let mut directive_gap = false;
    let converted;
    let (process_path, process_source) = match format {
        "rst" | "asciidoc" => {
            let (text, gap) = prose_to_markdown(source, format, &cancel, start)?;
            converted = text;
            directive_gap = gap;
            ("document.md", converted.as_str())
        }
        "html" => ("document.html", source),
        "markdown" => ("document.md", source),
        _ => ("document.txt", source),
    };
    let mut doc = crate::standards_processing::process_document(
        process_path,
        process_source.as_bytes(),
        cancel.clone(),
    )
    .map_err(diagnostic)?;
    if doc.sections.is_empty() {
        doc = plain(path, source, format);
    }
    doc.format = format.into();
    if let Some(title) = title.filter(|t| !t.is_empty()) {
        doc.title = title;
    }
    let supplemental = if format == "html" {
        let extra = html_references(process_source, &cancel, start)?;
        doc.symbols.extend(extra.apis);
        extra.references
    } else if matches!(format, "markdown" | "rst" | "asciidoc") {
        let mut refs = markdown_references(process_source, &cancel, start)?;
        let markup = markdown_html_markup(process_source, &cancel, start)?;
        let extra = html_references(&markup, &cancel, start)?;
        refs.extend(extra.references);
        doc.symbols.extend(extra.apis);
        refs
    } else {
        Vec::new()
    };
    let mut seen: BTreeSet<_> = doc
        .references
        .iter()
        .map(|r| (r.target.clone(), r.label.clone()))
        .collect();
    for reference in supplemental {
        if (resolve_reference(path, &reference.target).is_some()
            || url::Url::parse(&reference.target).is_ok_and(|u| {
                matches!(u.scheme(), "http" | "https")
                    && u.username().is_empty()
                    && u.password().is_none()
            }))
            && seen.insert((reference.target.clone(), reference.label.clone()))
        {
            doc.references.push(reference);
        }
    }
    if frontmatter_gap {
        gap(
            &mut doc,
            "frontmatter_unsupported",
            "Unclosed or oversized front matter remains original source text.",
        );
    }
    if directive_gap
        || source.contains("{%")
        || source.contains("{{")
        || source.contains("[TOC]")
        || source.contains("<!-- include")
    {
        gap(
            &mut doc,
            "generated_construct",
            "Unresolved generator or include directives remain inert source evidence.",
        );
    }
    if matches!(format, "rst" | "asciidoc") {
        gap(
            &mut doc,
            "prose_subset",
            "This inert prose projection supports a bounded syntax subset; it does not run a renderer.",
        );
    }
    check(&cancel, start)?;
    doc.validate().map_err(diagnostic)?;
    Ok(doc)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn classifier_discovers_component_docs_but_not_test_vectors() {
        for path in [
            "README.md",
            "components/network/README.md",
            "third_party/blink/renderer/README.md",
            "docs/guide.rst",
            "components/a/docs/ref.html",
        ] {
            assert!(candidate(path), "{path}");
        }
        for path in [
            "third_party/lib/README.md",
            "third_party/blink/web_tests/foo.md",
            "components/a/testdata/page.html",
            "components/a/page.html",
            "gen/README.md",
            "node_modules/a/README.md",
            "docs/../private.md",
        ] {
            assert!(!candidate(path), "{path}");
        }
        assert!(notice("third_party/a/LICENSE.txt"));
    }
    #[test]
    fn relative_resolution_is_bounded_and_preserves_fragments() {
        assert_eq!(
            resolve_reference("docs/guide/a.md", "../b.md#part"),
            Some(("docs/b.md".into(), Some("part".into())))
        );
        assert_eq!(
            resolve_reference("docs/a.md", "//components/a/README.md"),
            Some(("components/a/README.md".into(), None))
        );
        assert_eq!(
            resolve_reference("docs/a.md", "#a"),
            Some(("docs/a.md".into(), Some("a".into())))
        );
        for target in [
            "../../private",
            "javascript:alert(1)",
            "../%2e%2e/private",
            "https://example.org/a",
            "//../a",
        ] {
            assert_eq!(resolve_reference("docs/a.md", target), None, "{target}");
        }
    }
    #[test]
    fn markdown_retains_parent_links_without_executing_content() {
        let bytes=b"---\ntitle: Captured guide\n---\n# Guide\n\n[Parent](../README.md#intro) [Root](//components/a.md)\n\n<script>hiddenPayload()</script>\n\n`<script>literal()</script>`\n";
        let doc = process_document("docs/a.md", bytes, CancellationToken::new()).unwrap();
        assert_eq!(doc.title, "Captured guide");
        assert!(!doc.text.contains("hiddenPayload"));
        assert!(doc.text.contains("literal()"));
        assert!(
            doc.references
                .iter()
                .any(|r| r.target == "../README.md#intro")
        );
        assert!(
            doc.references
                .iter()
                .any(|r| r.target == "//components/a.md")
        );
    }
    #[test]
    fn html_api_markup_is_explicit_and_scripts_remain_hidden() {
        let doc=process_document("docs/a.html",b"<h1>API</h1><section id=send data-api-name=send><p>Send data</p></section><script><a href=../hidden>hidden</a></script><a href=../README.md>parent</a>",CancellationToken::new()).unwrap();
        assert!(
            doc.symbols
                .iter()
                .any(|s| s.kind == "api" && s.name == "send")
        );
        assert!(doc.references.iter().any(|r| r.target == "../README.md"));
        assert!(!doc.references.iter().any(|r| r.target.contains("hidden")));
    }
    #[test]
    fn unsupported_generators_are_qualified_gaps_and_never_evaluated() {
        let doc = process_document(
            "docs/a.rst",
            b"Heading\n=======\n\n.. include:: /etc/passwd\n\nLiteral text\n",
            CancellationToken::new(),
        )
        .unwrap();
        assert!(doc.sections.iter().any(|s| s.title == "Heading"));
        assert!(doc.gaps.iter().any(|g| g.code == "generated_construct"));
        assert!(doc.gaps.iter().any(|g| g.code == "prose_subset"));
        assert!(!doc.text.contains("root:x:"));
    }
    #[test]
    fn malformed_and_canceled_inputs_fail_explicitly() {
        assert!(process_document("docs/a.md", &[0xff], CancellationToken::new()).is_err());
        assert!(process_document("docs/a.md", b"a\0b", CancellationToken::new()).is_err());
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert_eq!(
            process_document("docs/a.md", b"# A", cancel)
                .unwrap_err()
                .code,
            "cancelled"
        );
    }
}

#[cfg(test)]
mod code_example_tests {
    use super::*;
    #[test]
    fn markdown_examples_cannot_fabricate_api_symbols_or_references() {
        let source=b"# Real documentation\n\n```html\n<section id=fake data-api-name=Fenced><a href=../fake.md>fake</a></section>\n```\n\n`<span data-api-name=Inline>literal</span>`\n\n<section id=real data-api-name=Real><p>Actual API markup</p></section>\n";
        let document =
            process_document("docs/example.md", source, CancellationToken::new()).unwrap();
        let apis: Vec<_> = document
            .symbols
            .iter()
            .filter(|s| s.kind == "api")
            .map(|s| s.name.as_str())
            .collect();
        assert_eq!(apis, ["Real"]);
        assert!(!document.references.iter().any(|r| r.target == "../fake.md"));
    }
    #[test]
    fn html_preformatted_examples_cannot_fabricate_api_symbols() {
        let source=b"<h1>Examples</h1><pre><code><span data-api-name=Fake>example</span></code></pre><section id=actual data-api-name=Actual>actual</section>";
        let document =
            process_document("docs/example.html", source, CancellationToken::new()).unwrap();
        let apis: Vec<_> = document
            .symbols
            .iter()
            .filter(|s| s.kind == "api")
            .map(|s| s.name.as_str())
            .collect();
        assert_eq!(apis, ["Actual"]);
    }
}
