//! Explicit document notice extraction. Incidental body links never authorize copying.
use super::{DOCUMENT_LICENSE, PublicationUrl};
use html5ever::{
    tendril::StrTendril,
    tokenizer::{
        BufferQueue, TagKind, Token, TokenSink, TokenSinkResult, Tokenizer, TokenizerOpts,
    },
};
use serde_json::{Value, json};
use std::cell::RefCell;
use std::time::{Duration, Instant};
struct Frame {
    name: String,
    notice: bool,
    title: bool,
    document_title: bool,
    status: bool,
    hidden: bool,
    exclusion_root: bool,
}
#[derive(Default)]
struct State {
    stack: Vec<Frame>,
    title: String,
    document_title: String,
    status: String,
    copyright: String,
    licenses: Vec<String>,
    tokens: usize,
    failed: bool,
    failure_reason: Option<&'static str>,
}
impl State {
    fn fail(&mut self, reason: &'static str) {
        self.failed = true;
        self.failure_reason.get_or_insert(reason);
    }
    fn exclusion_floor(&self) -> usize {
        self.stack
            .iter()
            .rposition(|frame| frame.exclusion_root)
            .map_or(0, |at| at + 1)
    }
    fn close_scoped(&mut self, names: &[&str], scopes: &[&str]) {
        let floor = self.exclusion_floor();
        let scope = self
            .stack
            .iter()
            .enumerate()
            .skip(floor)
            .rfind(|(_, frame)| scopes.contains(&frame.name.as_str()))
            .map_or(floor, |(at, _)| at + 1);
        if let Some(at) = self
            .stack
            .iter()
            .enumerate()
            .skip(scope)
            .rfind(|(_, frame)| names.contains(&frame.name.as_str()))
            .map(|(at, _)| at)
        {
            self.stack.truncate(at);
        }
    }
    fn optional_start(&mut self, name: &str) {
        if matches!(
            name,
            "address"
                | "article"
                | "aside"
                | "blockquote"
                | "div"
                | "dl"
                | "dt"
                | "dd"
                | "fieldset"
                | "figcaption"
                | "figure"
                | "footer"
                | "form"
                | "h1"
                | "h2"
                | "h3"
                | "h4"
                | "h5"
                | "h6"
                | "header"
                | "hgroup"
                | "hr"
                | "li"
                | "main"
                | "menu"
                | "nav"
                | "ol"
                | "p"
                | "pre"
                | "section"
                | "table"
                | "tbody"
                | "thead"
                | "tfoot"
                | "tr"
                | "td"
                | "th"
                | "ul"
                | "details"
                | "summary"
        ) {
            self.close_scoped(&["p"], &["table", "td", "th", "button", "select"]);
        }
        match name {
            "li" => self.close_scoped(&["li"], &["ul", "ol", "menu"]),
            "dt" | "dd" => self.close_scoped(&["dt", "dd"], &["dl"]),
            "tr" => self.close_scoped(&["tr"], &["table"]),
            "td" | "th" => self.close_scoped(&["td", "th"], &["tr", "table"]),
            "thead" | "tbody" | "tfoot" => {
                self.close_scoped(&["thead", "tbody", "tfoot"], &["table"])
            }
            "colgroup" => self.close_scoped(&["colgroup"], &["table"]),
            "option" => self.close_scoped(&["option"], &["select", "datalist", "optgroup"]),
            "optgroup" => self.close_scoped(&["optgroup"], &["select"]),
            "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => {
                self.close_scoped(&["h1", "h2", "h3", "h4", "h5", "h6"], &[])
            }
            "body" => self.close_scoped(&["head"], &[]),
            _ => {}
        }
    }
}
struct Sink {
    state: RefCell<State>,
    base: url::Url,
    deadline: Instant,
    cancel: tokio_util::sync::CancellationToken,
}
impl TokenSink for Sink {
    type Handle = ();
    fn process_token(&self, token: Token, _: u64) -> TokenSinkResult<()> {
        let mut s = self.state.borrow_mut();
        s.tokens += 1;
        if s.failed {
            return TokenSinkResult::Continue;
        }
        if self.cancel.is_cancelled() {
            s.fail("license_preflight_cancelled");
            return TokenSinkResult::Continue;
        }
        if s.tokens > 4_000_000 {
            s.fail("license_token_limit");
            return TokenSinkResult::Continue;
        }
        if Instant::now() >= self.deadline {
            s.fail("license_processing_deadline");
            return TokenSinkResult::Continue;
        }
        match token {
            Token::TagToken(tag) if tag.kind == TagKind::StartTag => {
                s.optional_start(&tag.name);
                let attr = |name: &str| {
                    tag.attrs
                        .iter()
                        .find(|a| &*a.name.local == name)
                        .map(|a| &*a.value)
                };
                let classes = attr("class").unwrap_or("");
                let id = attr("id").unwrap_or("");
                let inherited_notice = s.stack.iter().any(|f| f.notice);
                let inherited_hidden = s.stack.iter().any(|f| f.hidden);
                let notice = inherited_notice
                    || classes
                        .split_whitespace()
                        .any(|c| matches!(c, "copyright" | "copyright-notice"))
                    || matches!(id, "copyright" | "copyright-notice");
                let exclusion_root = classes.split_whitespace().any(|class| class == "example")
                    || matches!(
                        &*tag.name,
                        "script"
                            | "style"
                            | "template"
                            | "noscript"
                            | "textarea"
                            | "xmp"
                            | "iframe"
                            | "noembed"
                            | "noframes"
                            | "pre"
                            | "code"
                            | "samp"
                            | "svg"
                            | "math"
                    );
                let hidden = inherited_hidden || exclusion_root;
                let explicit =
                    attr("rel").is_some_and(|v| v.split_whitespace().any(|v| v == "license"));
                if !hidden
                    && (notice || explicit)
                    && matches!(&*tag.name, "a" | "link")
                    && let Some(href) = attr("href")
                    && let Ok(url) = self.base.join(href)
                {
                    if s.licenses.len() < 32 && href.len() <= 4096 {
                        s.licenses.push(url.to_string());
                    } else {
                        s.fail("license_link_limit");
                    }
                }
                let foreign = s
                    .stack
                    .iter()
                    .any(|frame| matches!(frame.name.as_str(), "svg" | "math"))
                    || matches!(&*tag.name, "svg" | "math");
                if !(tag.self_closing && foreign)
                    && !matches!(
                        &*tag.name,
                        "meta"
                            | "link"
                            | "br"
                            | "img"
                            | "hr"
                            | "input"
                            | "source"
                            | "area"
                            | "base"
                            | "wbr"
                            | "embed"
                            | "param"
                            | "col"
                            | "basefont"
                            | "bgsound"
                            | "frame"
                            | "keygen"
                    )
                {
                    if s.stack.len() >= 256 {
                        s.fail("license_stack_depth_limit");
                    } else {
                        s.stack.push(Frame {
                            name: tag.name.to_string(),
                            notice,
                            title: &*tag.name == "h1",
                            document_title: &*tag.name == "title",
                            status: id == "w3c-state"
                                || classes.split_whitespace().any(|c| c == "w3c-state"),
                            hidden,
                            exclusion_root,
                        });
                    }
                }
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
                    return TokenSinkResult::RawData(raw);
                }
            }
            Token::TagToken(tag) if tag.kind == TagKind::EndTag => {
                if let Some(i) = s.stack.iter().rposition(|f| f.name == *tag.name) {
                    let barrier = s.stack.iter().rposition(|frame| frame.exclusion_root);
                    if barrier.is_none_or(|floor| i >= floor) {
                        s.stack.truncate(i);
                    }
                }
            }
            Token::CharacterTokens(t) if !s.stack.iter().any(|f| f.hidden) => {
                let notice = s.stack.iter().any(|f| f.notice);
                let title = s.stack.iter().any(|f| f.title);
                let status = s.stack.iter().any(|f| f.status);
                if notice {
                    s.copyright.push_str(&t);
                }
                if title {
                    s.title.push_str(&t);
                }
                if s.stack.iter().any(|f| f.document_title) {
                    s.document_title.push_str(&t);
                }
                if status {
                    s.status.push_str(&t);
                }
                if s.copyright.len() > 32768 {
                    s.fail("copyright_notice_byte_limit");
                }
                if s.title.len() > 4096 || s.document_title.len() > 4096 || s.status.len() > 4096 {
                    s.fail("license_title_or_status_byte_limit");
                }
            }
            _ => {}
        }
        TokenSinkResult::Continue
    }
}
fn unresolved_reason(url: &PublicationUrl, reason: &str) -> Value {
    json!({"decision":"unresolved","reason":reason,"evidence":{"source_url":url.as_str()}})
}
fn normalized(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}
pub(super) fn extract(url: &PublicationUrl, bytes: &[u8]) -> Value {
    extract_cancel(url, bytes, tokio_util::sync::CancellationToken::new())
}
pub(super) fn extract_cancel(
    url: &PublicationUrl,
    bytes: &[u8],
    cancel: tokio_util::sync::CancellationToken,
) -> Value {
    let unresolved = || unresolved_reason(url, "explicit_document_license_notice_required");
    let Ok(source) = std::str::from_utf8(bytes) else {
        return unresolved_reason(url, "license_encoding_unsupported");
    };
    if source.len() > 64 * 1024 * 1024 {
        return unresolved_reason(url, "license_inspection_byte_limit");
    }
    let Ok(base) = url::Url::parse(url.as_str()) else {
        return unresolved();
    };
    let tokenizer = Tokenizer::new(
        Sink {
            state: RefCell::new(State::default()),
            base,
            deadline: Instant::now() + Duration::from_secs(15),
            cancel,
        },
        TokenizerOpts::default(),
    );
    let input = BufferQueue::default();
    let mut offset = 0;
    let mut pending = 0;
    while offset < source.len() {
        let mut end = (offset + 4096).min(source.len());
        while !source.is_char_boundary(end) {
            end -= 1;
        }
        let before = tokenizer.sink.state.borrow().tokens;
        input.push_back(StrTendril::from_slice(&source[offset..end]));
        let _ = tokenizer.feed(&input);
        if tokenizer.sink.state.borrow().tokens == before {
            pending += end - offset;
        } else {
            pending = 0;
        }
        if pending > 128 * 1024 {
            return unresolved_reason(url, "license_lexical_buffer_limit");
        }
        let state = tokenizer.sink.state.borrow();
        if state.failed {
            return unresolved_reason(
                url,
                state.failure_reason.unwrap_or("license_processing_limit"),
            );
        }
        offset = end;
    }
    tokenizer.end();
    let state = tokenizer.sink.state.borrow();
    if state.failed {
        return unresolved_reason(
            url,
            state.failure_reason.unwrap_or("license_processing_limit"),
        );
    }
    let license = state.licenses.iter().find(|u| {
        [
            DOCUMENT_LICENSE,
            "https://www.w3.org/copyright/software-license-2023/",
            "https://www.w3.org/copyright/software-license/",
            "https://www.w3.org/Consortium/Legal/copyright-software",
            "https://www.w3.org/Consortium/Legal/2015/doc-license",
            "https://www.w3.org/Consortium/Legal/2015/copyright-software-and-document",
            "https://www.w3.org/Consortium/Legal/2002/copyright-documents-20021231",
            "https://www.w3.org/Consortium/Legal/copyright-documents",
        ]
        .iter()
        .any(|known| {
            u.replacen("http://www.w3.org/", "https://www.w3.org/", 1)
                .trim_end_matches('/')
                == known.trim_end_matches('/')
        })
    });
    let Some(license) = license else {
        return unresolved_reason(url, "recognized_license_notice_absent");
    };
    let copyright = normalized(&state.copyright);
    if copyright.is_empty() {
        return unresolved_reason(url, "copyright_notice_absent");
    }
    let title = if state.title.trim().is_empty() {
        normalized(&state.document_title)
    } else {
        normalized(&state.title)
    };
    if title.is_empty() {
        return unresolved_reason(url, "document_title_absent");
    }
    let status = normalized(&state.status);
    let derived = format!(
        "Copyright © 2023 W3C®. This software or document includes material copied from or derived from {title} ({}). Original publication status: {status}. This service provides an extracted projection; the original publication remains authoritative.",
        url.as_str()
    );
    let software = license.trim_end_matches('/')
        == "https://www.w3.org/copyright/software-license-2023"
        || license.trim_end_matches('/')
            == "https://www.w3.org/Consortium/Legal/copyright-software"
        || license.trim_end_matches('/') == "https://www.w3.org/copyright/software-license";
    let notice = if software {
        super::W3C_SOFTWARE_NOTICE.to_owned()
    } else {
        format!("{copyright}\nGoverning document terms: {license}\n{derived}")
    };
    let code_license = state
        .licenses
        .iter()
        .find(|u| u.trim_end_matches('/') == "https://www.w3.org/copyright/software-license-2023");
    json!({"decision":"approved","license_url":license,"canonical_terms_url":if software{Value::String("https://www.w3.org/copyright/software-license-2023/".into())}else{Value::String(license.to_string())},"terms_profile":{"version":1,"verified_as_of":"2026-10-26","basis":"fixed reviewed W3C governing URI profile; latest software alias resolved to the 2023 terms during review"},"license_family":if software{"software_and_document"}else{"document"},"code_component_license_url":code_license,"title":title,"publication_status":status,"copyright":copyright,"notice":notice,"derived_notice":derived,"evidence":{"source_url":url.as_str(),"body_hash":crate::w3c_inventory::digest(bytes),"qualification":"explicit_document_notice"}})
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn incidental_link_never_approves() {
        let u = PublicationUrl::new("https://www.w3.org/TR/example/").unwrap();
        assert_eq!(
            extract(
                &u,
                format!(
                    "<h1>Example</h1><p>See <a href='{DOCUMENT_LICENSE}'>license example</a></p>"
                )
                .as_bytes()
            )["decision"],
            "unresolved"
        );
    }
    #[test]
    fn raw_text_notice_examples_never_approve() {
        let u = PublicationUrl::new("https://www.w3.org/TR/example/").unwrap();
        for tag in ["textarea", "xmp", "iframe", "script", "pre", "code"] {
            let body = format!(
                "<h1>Example</h1><{tag}><p class=copyright>Copyright W3C <a href='/copyright/document-license-2023/'>License</a></p></{tag}>"
            );
            assert_eq!(
                extract(&u, body.as_bytes())["decision"],
                "unresolved",
                "{tag}"
            );
        }
    }
    #[test]
    fn relative_notice_preserves_original_status_and_copyright() {
        let u = PublicationUrl::new("https://www.w3.org/TR/example/").unwrap();
        let v=extract(&u,b"<h1>Example Standard</h1><p class=w3c-state>W3C Working Draft</p><p class=copyright>Copyright 2026 W3C. <a href='/copyright/document-license-2023/'>Document License</a></p>");
        assert_eq!(v["decision"], "approved");
        assert_eq!(v["publication_status"], "W3C Working Draft");
        assert!(v["copyright"].as_str().unwrap().contains("2026"));
    }
}
#[cfg(test)]
mod family_tests {
    use super::*;
    #[test]
    fn document_notice_does_not_receive_software_grant() {
        let url = PublicationUrl::new("https://www.w3.org/TR/example/").unwrap();
        let doc=extract(&url,b"<h1>Example</h1><h2 id=w3c-state>W3C Working Draft</h2><p class=copyright>Copyright 2026 W3C <a href='/copyright/document-license-2023/'>Document License</a></p>");
        assert_eq!(doc["license_family"], "document");
        assert_eq!(doc["publication_status"], "W3C Working Draft");
        assert!(
            !doc["notice"]
                .as_str()
                .unwrap()
                .contains("Permission to copy, modify")
        );
        let software=extract(&url,b"<h1>Example</h1><p class=copyright>Copyright 2026 W3C <a href='/copyright/software-license-2023/'>Software and Document License</a></p>");
        assert_eq!(software["license_family"], "software_and_document");
        assert!(
            software["notice"]
                .as_str()
                .unwrap()
                .contains("Permission to copy, modify")
        );
    }
}
#[cfg(test)]
mod latest_alias_tests {
    use super::*;
    #[test]
    fn reviewed_latest_software_alias_retains_literal_and_profile_provenance() {
        let url = PublicationUrl::new("https://www.w3.org/TR/example/").unwrap();
        let doc=extract(&url,b"<h1>Example</h1><p class=copyright>Copyright 2026 W3C <a href='https://www.w3.org/copyright/software-license/'>Permissive Document License</a></p>");
        assert_eq!(doc["decision"], "approved");
        assert_eq!(
            doc["license_url"],
            "https://www.w3.org/copyright/software-license/"
        );
        assert_eq!(
            doc["canonical_terms_url"],
            "https://www.w3.org/copyright/software-license-2023/"
        );
        assert_eq!(doc["terms_profile"]["verified_as_of"], "2026-10-26");
        assert!(
            doc["notice"]
                .as_str()
                .unwrap()
                .contains("Permission to copy, modify")
        );
    }
}

#[cfg(test)]
mod optional_end_tag_tests {
    use super::*;
    #[test]
    fn ordinary_large_tables_with_optional_end_tags_preserve_the_header_notice() {
        let url = PublicationUrl::new("https://www.w3.org/TR/example/").unwrap();
        let mut source = String::from(
            "<!doctype html><html><head><title>Example Standard</title></head><body><h1>Example Standard</h1><h2 id=w3c-state>W3C Working Draft</h2><p class=copyright>Copyright © 2026 W3C <a href='/copyright/software-license/'>Permissive Document License</a><table><tbody>",
        );
        for _ in 0..1000 {
            source.push_str("<tr><td>Property<td>Value");
        }
        source.push_str("</table><p>Following text</body></html>");
        let license = extract(&url, source.as_bytes());
        assert_eq!(license["decision"], "approved", "{license}");
        assert_eq!(
            license["copyright"],
            "Copyright © 2026 W3C Permissive Document License"
        );
    }
}

#[cfg(test)]
mod scoped_recovery_tests {
    use super::*;
    fn notice() -> String {
        String::from(
            "<html><body><h1>Example</h1><p class=copyright>Copyright 2026 W3C <a href='/copyright/software-license/'>Permissive Document License</a>",
        )
    }
    #[test]
    fn nested_list_definition_and_table_scopes_do_not_accumulate_optional_frames() {
        let url = PublicationUrl::new("https://www.w3.org/TR/example/").unwrap();
        let mut source = notice();
        source.push_str("<ul><li>Outer<ul>");
        for _ in 0..1000 {
            source.push_str("<li>Inner");
        }
        source.push_str("</ul><li>Next outer</ul><dl><dt>Outer<dd>Description<dl>");
        for _ in 0..1000 {
            source.push_str("<dt>Term<dd>Description");
        }
        source.push_str("</dl><dd>Next outer description</dl><table><tr><td>Outer<table><tbody>");
        for _ in 0..1000 {
            source.push_str("<tr><th>Heading<td>Cell");
        }
        source.push_str("</table><td>Next outer cell<tr><td>Last row</table></body></html>");
        let license = extract(&url, source.as_bytes());
        assert_eq!(license["decision"], "approved", "{license}");
        assert_eq!(
            license["copyright"],
            "Copyright 2026 W3C Permissive Document License"
        );
    }
    #[test]
    fn recovery_never_escapes_excluded_examples_or_mismatched_pre_ancestors() {
        let url = PublicationUrl::new("https://www.w3.org/TR/example/").unwrap();
        for excluded in [
            "<div class=example><ul><li>Example<li>Another</ul>",
            "<div><pre></div>",
            "<ul><li class=example><ul><li>Nested</ul><li>Example",
            "<table><tr class=example><td>Example<tr><td>Example",
        ] {
            let source = format!(
                "<h1>Example</h1>{excluded}<p class=copyright>Copyright 2026 W3C <a href='/copyright/software-license/'>Permissive Document License</a></p>"
            );
            let license = extract(&url, source.as_bytes());
            assert_eq!(license["decision"], "unresolved", "{excluded}: {license}");
        }
    }
    #[test]
    fn many_self_closing_foreign_elements_do_not_grow_the_html_stack() {
        let url = PublicationUrl::new("https://www.w3.org/TR/example/").unwrap();
        let mut source = notice();
        source.push_str("<div><svg>");
        for _ in 0..1000 {
            source.push_str("<path d='M0 0' />");
        }
        source.push_str("</svg></div></body></html>");
        assert_eq!(extract(&url, source.as_bytes())["decision"], "approved");
    }
    #[test]
    fn limit_diagnostics_are_distinct_and_do_not_echo_source_content() {
        let url = PublicationUrl::new("https://www.w3.org/TR/example/").unwrap();
        let source = format!("{}{}", notice(), "<div>".repeat(300));
        let limited = extract(&url, source.as_bytes());
        assert_eq!(limited["decision"], "unresolved");
        assert_eq!(limited["reason"], "license_stack_depth_limit");
        assert!(!limited.to_string().contains("Copyright 2026"));
        let absent = extract(&url, b"<h1>Example</h1><p>No notice</p>");
        assert_eq!(absent["reason"], "recognized_license_notice_absent");
        let source = format!("{}<div title=\\\"{}", notice(), "x".repeat(150000));
        assert_eq!(
            extract(&url, source.as_bytes())["reason"],
            "license_lexical_buffer_limit"
        );
    }
}
