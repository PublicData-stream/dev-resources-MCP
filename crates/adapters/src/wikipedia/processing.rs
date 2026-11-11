//! Bounded HTML-to-text/Markdown projection. Captured markup never causes I/O.
use devres_domain::{Error, Result};
use html5ever::{
    tendril::StrTendril,
    tokenizer::{
        BufferQueue, TagKind, Token, TokenSink, TokenSinkResult, Tokenizer, TokenizerOpts,
    },
};
use serde::{Deserialize, Serialize};
use std::{
    cell::RefCell,
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;

pub const MAX_HTML_BYTES: usize = 8 * 1024 * 1024;
const MAX_OUTPUT: usize = 24 * 1024 * 1024;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Projection {
    pub title: String,
    pub text: String,
    pub markdown: String,
    pub sections: Vec<Section>,
    pub references: Vec<Reference>,
    pub gaps: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Section {
    pub anchor: String,
    pub title: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Reference {
    pub target: String,
    pub label: String,
}

struct Frame {
    name: String,
    hidden: bool,
    start: usize,
    target: Option<String>,
    anchor: String,
    code: Option<String>,
    math: Option<(Option<String>, String)>,
    tex: Option<String>,
}
#[derive(Default)]
struct State {
    output: Projection,
    stack: Vec<Frame>,
    tokens: usize,
    metadata_bytes: usize,
    error: Option<Error>,
}
struct Sink {
    state: RefCell<State>,
    cancel: CancellationToken,
    deadline: Instant,
}

fn limit() -> Error {
    Error::capacity("Wikipedia HTML projection exceeds processing bounds.")
}
fn hidden(name: &str) -> bool {
    matches!(
        name,
        "head"
            | "script"
            | "style"
            | "template"
            | "noscript"
            | "iframe"
            | "object"
            | "embed"
            | "noembed"
            | "noframes"
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
fn heading(name: &str) -> Option<usize> {
    match name {
        "h1" => Some(1),
        "h2" => Some(2),
        "h3" => Some(3),
        "h4" => Some(4),
        "h5" => Some(5),
        "h6" => Some(6),
        _ => None,
    }
}
fn block(name: &str) -> bool {
    heading(name).is_some()
        || matches!(
            name,
            "p" | "div"
                | "section"
                | "article"
                | "pre"
                | "ul"
                | "ol"
                | "li"
                | "dl"
                | "dt"
                | "dd"
                | "tr"
                | "table"
                | "blockquote"
        )
}
fn newline(value: &mut String) {
    if !value.is_empty() && !value.ends_with('\n') {
        value.push('\n');
    }
}
fn bounded_label(value: &str) -> String {
    let mut end = value.len().min(4096);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}
fn escaped(out: &mut String, text: &str) {
    for c in text.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '\\' | '`' | '*' | '_' | '[' | ']' | '#' | '!' | '|' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
}
fn code(out: &mut String, text: &str, block: bool) {
    let longest = text.split(|c| c != '`').map(str::len).max().unwrap_or(0);
    let fence = "`".repeat(longest.saturating_add(1).max(if block { 3 } else { 1 }));
    if block {
        newline(out);
        out.push_str(&fence);
        out.push('\n');
        out.push_str(text);
        newline(out);
        out.push_str(&fence);
        out.push('\n');
    } else {
        out.push_str(&fence);
        out.push(' ');
        // A paragraph break cannot terminate this code span and expose raw HTML.
        for character in text.chars() {
            out.push(if matches!(character, '\n' | '\r') {
                ' '
            } else {
                character
            });
        }
        out.push(' ');
        out.push_str(&fence);
    }
}
fn safe_target(value: &str) -> Option<String> {
    if value.is_empty()
        || value.len() > 4096
        || value.chars().any(char::is_control)
        || value.contains('\\')
    {
        return None;
    }
    let base = url::Url::parse("https://en.wikipedia.org/wiki/").ok()?;
    let url = base.join(value).ok()?;
    if !matches!(url.scheme(), "https" | "http")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return None;
    }
    let target = if value.starts_with('#') {
        format!("#{}", url.fragment().unwrap_or_default())
    } else {
        url.to_string()
    };
    Some(target.replace('(', "%28").replace(')', "%29"))
}
impl State {
    fn gap(&mut self, gap: &str) {
        if !self.output.gaps.iter().any(|v| v == gap) {
            self.output.gaps.push(gap.into());
        }
    }
    fn inert(&self) -> bool {
        self.stack.iter().any(|v| v.hidden)
    }
    fn boundary(&mut self) {
        newline(&mut self.output.text);
        newline(&mut self.output.markdown);
    }
    fn characters(&mut self, value: &str) {
        if self.inert() {
            return;
        }
        if let Some(frame) = self.stack.iter_mut().rev().find(|v| v.tex.is_some()) {
            if let Some(raw) = &mut frame.tex {
                raw.push_str(value);
            }
            return;
        }
        if let Some(frame) = self.stack.iter_mut().rev().find(|v| v.math.is_some()) {
            if let Some((_, raw)) = &mut frame.math {
                raw.push_str(value);
            }
            return;
        }
        self.output.text.push_str(value);
        if let Some(frame) = self.stack.iter_mut().rev().find(|v| v.code.is_some()) {
            if let Some(raw) = &mut frame.code {
                raw.push_str(value);
            }
        } else {
            escaped(&mut self.output.markdown, value);
        }
    }
    fn close(&mut self, index: usize) {
        while self.stack.len() > index {
            let Some(frame) = self.stack.pop() else { break };
            if frame.hidden {
                continue;
            }
            if let Some(tex) = frame.tex
                && let Some(math) = self
                    .stack
                    .iter_mut()
                    .rev()
                    .find_map(|frame| frame.math.as_mut())
                && math.0.is_none()
            {
                math.0 = Some(tex);
            }
            if let Some((alt, raw)) = frame.math {
                let text = alt.unwrap_or_else(|| {
                    self.gap("mathml_without_tex_alttext");
                    raw
                });
                self.output.text.push_str(&text);
                code(&mut self.output.markdown, &text, false);
            }
            if let Some(raw) = frame.code {
                code(&mut self.output.markdown, &raw, frame.name == "pre");
            }
            if heading(&frame.name).is_some() {
                let title = bounded_label(
                    self.output
                        .text
                        .get(frame.start..)
                        .unwrap_or_default()
                        .trim(),
                );
                if self.output.title.is_empty() {
                    self.output.title = title.clone();
                }
                self.metadata_bytes = self
                    .metadata_bytes
                    .saturating_add(frame.anchor.len() + title.len());
                self.output.sections.push(Section {
                    anchor: frame.anchor,
                    title,
                });
            }
            if let Some(target) = frame.target {
                let label = bounded_label(
                    self.output
                        .text
                        .get(frame.start..)
                        .unwrap_or_default()
                        .trim(),
                );
                self.output.markdown.push_str("](");
                self.output.markdown.push_str(&target);
                self.output.markdown.push(')');
                self.metadata_bytes = self
                    .metadata_bytes
                    .saturating_add(target.len() + label.len());
                self.output.references.push(Reference { target, label });
            }
            if block(&frame.name) {
                self.boundary();
            }
            if matches!(frame.name.as_str(), "td" | "th") {
                self.output.text.push('\t');
                self.output.markdown.push_str(" | ");
            }
        }
    }
    fn checked(&self) -> Result<()> {
        let captured = self
            .stack
            .iter()
            .map(|v| {
                v.code.as_ref().map_or(0, String::len)
                    + v.tex.as_ref().map_or(0, String::len)
                    + v.math.as_ref().map_or(0, |(_, s)| s.len())
            })
            .sum::<usize>();
        if self.output.text.len() + self.output.markdown.len() + captured + self.metadata_bytes
            > MAX_OUTPUT
            || self.output.sections.len() > 100_000
            || self.output.references.len() > 100_000
            || self.stack.len() > 256
        {
            return Err(limit());
        }
        Ok(())
    }
}
impl TokenSink for Sink {
    type Handle = ();
    fn process_token(&self, token: Token, _: u64) -> TokenSinkResult<()> {
        let mut state = self.state.borrow_mut();
        if state.error.is_some() {
            return TokenSinkResult::Continue;
        }
        let result = (|| -> Result<()> {
            if self.cancel.is_cancelled() {
                return Err(Error::new("cancelled", "Wikipedia projection canceled."));
            }
            state.tokens += 1;
            if state.tokens > 500_000 || Instant::now() >= self.deadline {
                return Err(limit());
            }
            match token {
                Token::CharacterTokens(text) => state.characters(&text),
                Token::NullCharacterToken => {
                    return Err(Error::integrity(
                        "Wikipedia HTML contains a null character.",
                    ));
                }
                Token::TagToken(tag) => {
                    let name = tag.name.to_string();
                    if tag.attrs.len() > 128
                        || tag
                            .attrs
                            .iter()
                            .map(|v| v.name.local.len() + v.value.len())
                            .sum::<usize>()
                            > 65536
                    {
                        return Err(limit());
                    }
                    if tag.kind == TagKind::EndTag {
                        if let Some(index) = state.stack.iter().rposition(|v| v.name == name) {
                            state.close(index);
                        }
                    } else {
                        let inert = state.inert() || hidden(&name);
                        let attribute = |name: &str| {
                            tag.attrs
                                .iter()
                                .find(|a| &*a.name.local == name)
                                .map(|a| a.value.to_string())
                        };
                        let inside_code = state
                            .stack
                            .iter()
                            .any(|v| v.code.is_some() || v.math.is_some());
                        let target = if name == "a" && !inert && !inside_code {
                            attribute("href").and_then(|value| safe_target(&value))
                        } else {
                            None
                        };
                        if !inert && !inside_code {
                            if block(&name) || name == "br" {
                                state.boundary();
                            }
                            if let Some(level) = heading(&name) {
                                state.output.markdown.push_str(&"#".repeat(level));
                                state.output.markdown.push(' ');
                            }
                            if name == "li" {
                                state.output.markdown.push_str("- ");
                            }
                            if target.is_some() {
                                state.output.markdown.push('[');
                            }
                            if matches!(name.as_str(), "td" | "th") {
                                state.gap("table_rendered_as_delimited_rows");
                            }
                            if name == "img" {
                                if let Some(alt) = attribute("alt") {
                                    state.characters(&alt);
                                }
                                state.gap("media_not_fetched");
                            }
                        }
                        if !void(&name) && !tag.self_closing {
                            let tex = (!inert
                                && name == "annotation"
                                && attribute("encoding").is_some_and(|value| {
                                    matches!(value.as_str(), "application/x-tex" | "text/x-tex")
                                }))
                            .then(String::new);
                            let frame = Frame {
                                name: name.clone(),
                                hidden: inert,
                                start: state.output.text.len(),
                                target,
                                anchor: attribute("id").unwrap_or_default(),
                                code: (!inert
                                    && !inside_code
                                    && matches!(name.as_str(), "pre" | "code"))
                                .then(String::new),
                                math: (!inert && !inside_code && name == "math")
                                    .then(|| (attribute("alttext"), String::new())),
                                tex,
                            };
                            state.stack.push(frame);
                        }
                    }
                }
                _ => {}
            }
            state.checked()
        })();
        if let Err(error) = result {
            state.error = Some(error);
        }
        TokenSinkResult::Continue
    }
}

pub fn process_html(bytes: &[u8], cancel: CancellationToken) -> Result<Projection> {
    if bytes.len() > MAX_HTML_BYTES {
        return Err(limit());
    }
    let source =
        std::str::from_utf8(bytes).map_err(|_| Error::integrity("Wikipedia HTML is not UTF-8."))?;
    let sink = Sink {
        state: RefCell::new(State::default()),
        cancel,
        deadline: Instant::now() + Duration::from_secs(15),
    };
    let tokenizer = Tokenizer::new(sink, TokenizerOpts::default());
    let queue = BufferQueue::default();
    // Incremental feeding keeps ordinary token buffering bounded by source admission.
    let mut offset = 0;
    while offset < source.len() {
        let mut end = offset.saturating_add(4096).min(source.len());
        while !source.is_char_boundary(end) {
            end -= 1;
        }
        queue.push_back(StrTendril::from_slice(&source[offset..end]));
        let _ = tokenizer.feed(&queue);
        if tokenizer.sink.state.borrow().error.is_some() {
            break;
        }
        offset = end;
    }
    tokenizer.end();
    let mut state = tokenizer.sink.state.into_inner();
    if let Some(error) = state.error {
        return Err(error);
    }
    state.close(0);
    state.checked()?;
    Ok(state.output)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inert_markup_links_math_and_code() {
        let doc=process_html(br#"<h1 id="a">Title</h1><script>secret()</script><p>Hello <a href="https://example.com/a(b)">reference</a><a href="javascript:evil()">plain</a></p><math alttext="x^2"><mi>x</mi></math><pre>&lt;script&gt;``test</pre><img src="https://evil.invalid/file" alt="diagram">"#,CancellationToken::new()).unwrap();
        assert!(!doc.text.contains("secret"));
        assert!(!doc.markdown.contains("javascript:"));
        assert!(doc.markdown.contains("```\n<script>``test"));
        assert!(doc.text.contains("x^2"));
        assert!(doc.markdown.contains("a%28b%29"));
        assert_eq!(doc.references.len(), 1);
        assert!(doc.gaps.iter().any(|v| v == "media_not_fetched"));
    }
    #[test]
    fn unicode_and_cancellation() {
        let text = format!("<p>{}</p>", "한".repeat(4096));
        let doc = process_html(text.as_bytes(), CancellationToken::new()).unwrap();
        assert_eq!(doc.text.trim(), "한".repeat(4096));
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert_eq!(
            process_html(b"<p>hi</p>", cancel).unwrap_err().code,
            "cancelled"
        );
    }
    #[test]
    fn tex_annotation_fallback_is_inert_and_unsafe_links_stay_plain() {
        let doc=process_html(br#"<math><semantics><mi>x</mi><annotation encoding="application/x-tex">x^2</annotation></semantics></math><a href="data:text/html,secret">label</a>"#,CancellationToken::new()).unwrap();
        assert!(doc.text.contains("x^2"));
        assert!(!doc.markdown.contains("data:"));
        assert!(doc.references.is_empty());
    }
}
