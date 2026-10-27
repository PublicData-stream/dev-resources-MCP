//! Notice-based source qualification. Unknown terms never authorize a body capture.
use super::*;
use html5ever::{
    tendril::StrTendril,
    tokenizer::{
        BufferQueue, TagKind, Token, TokenSink, TokenSinkResult, Tokenizer, TokenizerOpts,
        states::RawKind,
    },
};
use std::cell::RefCell;
#[derive(Default)]
struct NoticeState {
    stack: Vec<(String, bool, bool)>,
    text: String,
    tokens: usize,
    failed: bool,
}
struct NoticeSink(RefCell<NoticeState>);
impl TokenSink for NoticeSink {
    type Handle = ();
    fn process_token(&self, token: Token, _line: u64) -> TokenSinkResult<()> {
        let mut state = self.0.borrow_mut();
        state.tokens += 1;
        if state.tokens > 1_000_000 {
            state.failed = true;
            return TokenSinkResult::Continue;
        }
        match token {
            Token::TagToken(tag) => {
                let name = tag.name.to_string();
                if tag.kind == TagKind::StartTag {
                    let parent = state
                        .stack
                        .last()
                        .map(|x| (x.1, x.2))
                        .unwrap_or((false, false));
                    let qualified = matches!(name.as_str(), "footer" | "devsite-content-footer")
                        || tag.attrs.iter().any(|a| {
                            &*a.name.local == "class"
                                && a.value.split_whitespace().any(|v| {
                                    matches!(
                                        v,
                                        "devsite-license"
                                            | "sidebar-license"
                                            | "license"
                                            | "footer"
                                    )
                                })
                        });
                    let active = parent.0 || qualified;
                    let hidden = parent.1
                        || matches!(
                            name.as_str(),
                            "code" | "pre" | "script" | "style" | "template"
                        );
                    if active && !hidden {
                        for attr in &tag.attrs {
                            if &*attr.name.local == "href"
                                && attr.value.len() < 4096
                                && state.text.len() + attr.value.len() < 65536
                            {
                                state.text.push(' ');
                                state.text.push_str(&attr.value);
                                state.text.push(' ');
                            }
                        }
                    }
                    let raw = match name.as_str() {
                        "script" => Some(RawKind::ScriptData),
                        "style" => Some(RawKind::Rawtext),
                        _ => None,
                    };
                    if !tag.self_closing
                        && !matches!(
                            name.as_str(),
                            "br" | "hr"
                                | "img"
                                | "input"
                                | "meta"
                                | "link"
                                | "wbr"
                                | "source"
                                | "area"
                                | "base"
                                | "embed"
                                | "param"
                                | "track"
                        )
                    {
                        if state.stack.len() < 128 {
                            state.stack.push((name, active, hidden));
                        } else {
                            state.failed = true;
                        }
                    }
                    if let Some(raw) = raw {
                        return TokenSinkResult::RawData(raw);
                    }
                } else if let Some(index) = state.stack.iter().rposition(|entry| entry.0 == name) {
                    state.stack.truncate(index);
                }
            }
            Token::CharacterTokens(text) if state.stack.last().is_some_and(|x| x.1 && !x.2) => {
                if state.text.len() + text.len() <= 65536 {
                    state.text.push_str(&text);
                } else {
                    state.failed = true;
                }
            }
            _ => {}
        }
        TokenSinkResult::Continue
    }
}
fn chrome_notice(html: &str) -> Option<String> {
    let sink = NoticeSink(RefCell::new(NoticeState::default()));
    let tokenizer = Tokenizer::new(sink, TokenizerOpts::default());
    let input = BufferQueue::default();
    input.push_back(StrTendril::from_slice(html));
    let _ = tokenizer.feed(&input);
    tokenizer.end();
    let state = tokenizer.sink.0.into_inner();
    if state.failed { None } else { Some(state.text) }
}

pub(super) fn qualify(component: &str, notice: &str, source_url: &str) -> Value {
    let selected = if component == "chrome" {
        chrome_notice(notice).unwrap_or_default()
    } else if component == "site" && notice.contains('<') {
        let selected = chrome_notice(notice).unwrap_or_default();
        if selected.trim().is_empty()
            && source_url.contains("/site/_includes/")
            && source_url.to_ascii_lowercase().contains("footer")
        {
            chrome_notice(&format!("<footer>{notice}</footer>")).unwrap_or_default()
        } else {
            selected
        }
    } else {
        notice.to_owned()
    };
    let lower = selected
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    let applicable = lower.contains("content of this page is licensed under")
        || lower.contains("content of this site is licensed under");
    let mut licenses = if applicable
        && (lower.contains("creativecommons.org/licenses/by-sa/4.0")
            || lower.contains("creative commons attribution-sharealike 4.0"))
    {
        vec!["CC-BY-SA-4.0"]
    } else if applicable
        && (lower.contains("creativecommons.org/licenses/by/2.5")
            || lower.contains("creative commons attribution 2.5"))
    {
        vec!["CC-BY-2.5"]
    } else if applicable
        && (lower.contains("creativecommons.org/licenses/by/4.0")
            || lower.contains("creative commons attribution 4.0"))
    {
        vec!["CC-BY-4.0"]
    } else if lower.contains("redistribution and use in source and binary forms")
        && lower.contains("this software is provided")
        && lower.contains("copyright")
    {
        if lower.contains("neither the name") {
            vec!["BSD-3-Clause"]
        } else {
            vec!["BSD-2-Clause"]
        }
    } else if lower.contains("licensed under the apache license, version 2.0")
        || (lower.contains("apache license") && lower.contains("version 2.0, january 2004"))
    {
        vec!["Apache-2.0"]
    } else if lower.contains("permission is hereby granted, free of charge")
        && lower.contains("the software is provided")
    {
        vec!["MIT"]
    } else {
        Vec::new()
    };
    if applicable
        && (lower.contains("code samples are licensed") || lower.contains("examples are licensed"))
    {
        if lower.contains("apache 2.0") || lower.contains("apache.org/licenses/license-2.0") {
            licenses.push("Apache-2.0");
        }
        if lower.contains("bsd license") {
            licenses.push("BSD");
        }
    }
    if component == "chrome" && !applicable {
        licenses.clear();
    }
    if licenses.is_empty() {
        return json!({"decision":"unresolved","component":component,"source_url":source_url,"notice_hash":inventory::digest(notice.as_bytes()),"gap":"license_scope_unresolved"});
    }
    // A versioned notice is retained verbatim, never replaced by a current policy.
    let notice_excerpt: String = selected.chars().take(32768).collect();
    json!({"decision":"approved","component":component,"licenses":licenses,"source_url":source_url,"notice_hash":inventory::digest(notice.as_bytes()),"notice":notice_excerpt,"attribution":"Derived from the identified upstream source; original notices and separate code/prose terms apply.","derivation":"Inert text, section and symbol projection; authoritative original remains the cited source."})
}

pub(super) fn unresolved(component: &str, scope: &str) -> Value {
    json!({"decision":"unresolved","component":component,"scope":scope,"gap":"license_scope_unresolved"})
}

pub(super) fn license_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == "license"
        || lower.starts_with("license.")
        || lower == "copying"
        || lower == "notice"
        || lower == "license-md"
        || lower == "license_md"
}

pub(super) fn body_license(parent: &Value, bytes: &[u8], source_url: &str) -> Value {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return parent.clone();
    };
    // Explicit per-file SPDX exceptions override inherited qualification. Unknown
    // expressions fail closed; an unrelated license link in prose does not.
    for line in text.lines().take(64) {
        if let Some((_, expression)) = line.split_once("SPDX-License-Identifier:") {
            let expression = expression
                .trim()
                .trim_end_matches("-->")
                .trim()
                .trim_end_matches("*/")
                .trim();
            if matches!(
                expression,
                "BSD-3-Clause"
                    | "BSD-2-Clause"
                    | "Apache-2.0"
                    | "MIT"
                    | "CC-BY-4.0"
                    | "CC-BY-SA-4.0"
                    | "CC-BY-2.5"
                    | "CC0-1.0"
            ) {
                let mut license = parent.clone();
                license["decision"] = json!("approved");
                license["licenses"] = json!([expression]);
                license["source_url"] = json!(source_url);
                license["per_file_spdx"] = json!(expression);
                return license;
            }
            return json!({"decision":"unresolved","source_url":source_url,"gap":"license_scope_unresolved","per_file_spdx":expression});
        }
    }
    let header = text
        .lines()
        .take(32)
        .collect::<Vec<_>>()
        .join("\n")
        .to_ascii_lowercase();
    if header.contains("no redistribution")
        || header.contains("no copying")
        || header.contains("proprietary")
        || header.contains("not licensed for")
        || (header.contains("all rights reserved")
            && !header.contains("bsd-style license")
            && !header.contains("redistribution and use"))
    {
        return json!({"decision":"unresolved","source_url":source_url,"gap":"per_file_license_exception"});
    }
    parent.clone()
}
