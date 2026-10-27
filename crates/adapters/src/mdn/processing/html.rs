//! HTML tokenizer only: no DOM, assets, scripts, rendering or URL fetching.
use super::{MAX_ITEMS, MAX_MEMBER, ProcessingBudget, limit, malformed, safe_link};
use devres_domain::{Error, Result};
use html5ever::{
    tendril::StrTendril,
    tokenizer::{
        BufferQueue, TagKind, Token, TokenSink, TokenSinkResult, Tokenizer, TokenizerOpts,
        states::RawKind,
    },
};
use std::cell::RefCell;

#[derive(Default)]
struct State {
    stack: Vec<String>,
    text: String,
    headings: Vec<String>,
    links: Vec<String>,
    heading: Option<String>,
    tokens: usize,
    completed: usize,
    error: Option<Error>,
}
struct Sink<'a> {
    state: RefCell<State>,
    budget: &'a ProcessingBudget,
}
fn hidden(s: &str) -> bool {
    matches!(
        s,
        "script"
            | "style"
            | "head"
            | "template"
            | "noscript"
            | "iframe"
            | "xmp"
            | "noembed"
            | "noframes"
    )
}
fn void(s: &str) -> bool {
    matches!(
        s,
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
fn heading(s: &str) -> bool {
    matches!(s, "h1" | "h2" | "h3" | "h4" | "h5" | "h6")
}
fn block(s: &str) -> bool {
    heading(s)
        || matches!(
            s,
            "p" | "div" | "pre" | "li" | "br" | "tr" | "td" | "th" | "hr"
        )
}
impl TokenSink for Sink<'_> {
    type Handle = ();
    fn process_token(&self, token: Token, _: u64) -> TokenSinkResult<()> {
        let mut s = self.state.borrow_mut();
        if s.error.is_some() {
            return TokenSinkResult::Continue;
        }
        if let Err(e) = self.budget.check() {
            s.error = Some(e);
            return TokenSinkResult::Continue;
        }
        s.tokens += 1;
        if s.tokens > 500_000 {
            s.error = Some(limit());
            return TokenSinkResult::Continue;
        }
        if !matches!(token, Token::ParseError(_) | Token::EOFToken) {
            s.completed += 1;
        }
        match token {
            Token::TagToken(tag) => {
                let name: &str = tag.name.as_ref();
                if tag.attrs.len() > 128
                    || name.len() > 256
                    || tag
                        .attrs
                        .iter()
                        .map(|a| a.value.len() + a.name.local.len())
                        .sum::<usize>()
                        > 16_384
                {
                    s.error = Some(limit());
                    return TokenSinkResult::Continue;
                }
                if tag.kind == TagKind::StartTag {
                    if name == "body"
                        && let Some(at) = s.stack.iter().rposition(|n| n == "head")
                    {
                        s.stack.truncate(at);
                    }
                    let inert = hidden(name) || s.stack.iter().any(|n| hidden(n));
                    if !inert {
                        if heading(name) {
                            s.heading = Some(String::new());
                        }
                        if name == "a"
                            && let Some(href) = tag
                                .attrs
                                .iter()
                                .find(|a| &*a.name.local == "href")
                                .map(|a| a.value.to_string())
                            && safe_link(&href)
                        {
                            s.links.push(href);
                        }
                        if block(name) {
                            s.text.push('\n');
                        }
                    }
                    if !void(name) {
                        if s.stack.len() >= 256 {
                            s.error = Some(limit());
                            return TokenSinkResult::Continue;
                        }
                        s.stack.push(name.to_owned());
                    }
                    return match name {
                        "script" => TokenSinkResult::RawData(RawKind::ScriptData),
                        "style" | "iframe" | "xmp" | "noembed" | "noframes" | "noscript" => {
                            TokenSinkResult::RawData(RawKind::Rawtext)
                        }
                        "title" | "textarea" => TokenSinkResult::RawData(RawKind::Rcdata),
                        _ => TokenSinkResult::Continue,
                    };
                }
                if heading(name)
                    && let Some(h) = s.heading.take()
                {
                    s.headings.push(h.trim().to_owned());
                }
                if let Some(at) = s.stack.iter().rposition(|n| n == name) {
                    s.stack.truncate(at);
                }
                if block(name) && !s.stack.iter().any(|n| hidden(n)) {
                    s.text.push('\n');
                }
            }
            Token::CharacterTokens(t) if !s.stack.iter().any(|n| hidden(n)) => {
                if s.text.len().saturating_add(t.len()) > MAX_MEMBER {
                    s.error = Some(limit());
                    return TokenSinkResult::Continue;
                }
                s.text.push_str(&t);
                if let Some(h) = &mut s.heading {
                    h.push_str(&t);
                }
            }
            Token::NullCharacterToken => s.error = Some(malformed()),
            _ => {}
        }
        if s.text.len() > MAX_MEMBER || s.headings.len() > MAX_ITEMS || s.links.len() > MAX_ITEMS {
            s.error = Some(limit());
        }
        TokenSinkResult::Continue
    }
}
pub(super) fn project(
    source: &str,
    budget: &ProcessingBudget,
) -> Result<(String, Vec<String>, Vec<String>)> {
    if source.len() > MAX_MEMBER || source.contains('\0') {
        return Err(limit());
    }
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
        if let Some(e) = state.error.take() {
            return Err(e);
        }
        if state.completed == completed {
            pending += end - offset;
        } else {
            pending = 0;
        }
        if pending > 16_384 {
            return Err(limit());
        }
        offset = end;
    }
    tokenizer.end();
    let mut state = tokenizer.sink.state.into_inner();
    if let Some(e) = state.error.take() {
        return Err(e);
    }
    Ok((state.text.trim().to_owned(), state.headings, state.links))
}
