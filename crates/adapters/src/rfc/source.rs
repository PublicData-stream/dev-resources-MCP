//! RFC index metadata and plain-text retrieval from RFC Editor.

use crate::{
    archive,
    research::{Page, capture_json, ensure_capture, list_limit, text_limit, text_page},
};
use async_trait::async_trait;
use devres_application::{ResponseValidator, Retrieval};
use devres_domain::{Error, FetchRequest, FetchResponse, Result};
use quick_xml::{NsReader, Reader, events::Event, name::ResolveResult};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    cell::RefCell,
    collections::HashSet,
    time::{Duration, Instant},
};

const INDEX_URL: &str = "https://www.rfc-editor.org/rfc-index.xml";
const INDEX_KEY: &str = "rfc:index";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchInput {
    pub query: String,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub offset: usize,
    #[serde(default = "list_limit")]
    pub limit: usize,
    #[serde(default)]
    pub capture: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetInput {
    pub number: u32,
    #[serde(default)]
    pub offset: usize,
    #[serde(default = "text_limit")]
    pub limit: usize,
    #[serde(default)]
    pub capture: Option<String>,
}

const MAX_INDEX: usize = 64 * 1024 * 1024;
const MAX_TEXT: usize = 16 * 1024 * 1024;
const MAX_ENTRY: usize = 256 * 1024;

#[derive(Default, Clone, Serialize, Deserialize, Debug)]
#[serde(default)]
pub struct Record {
    pub number: u32,
    pub title: String,
    pub abstract_text: String,
    pub status: String,
    pub published: String,
    pub publication: Option<String>,
    pub authors: Vec<String>,
    pub keywords: Vec<String>,
    pub stream: String,
    pub area: String,
    pub working_group: String,
    pub doi: String,
    pub formats: Vec<String>,
    pub unsupported_formats: Vec<String>,
    pub series: Vec<String>,
    pub updates: Vec<String>,
    pub obsoletes: Vec<String>,
    pub updated_by: Vec<String>,
    pub obsoleted_by: Vec<String>,
}

#[derive(Default)]
struct Node {
    name: String,
    text: String,
    children: Vec<Node>,
}

fn normalized(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

impl Node {
    fn child(&self, name: &str) -> Result<Option<&Self>> {
        let mut nodes = self.children.iter().filter(|node| node.name == name);
        let first = nodes.next();
        if nodes.next().is_some() {
            return Err(Error::integrity("Duplicate RFC metadata field."));
        }
        Ok(first)
    }
    fn scalar(&self, name: &str) -> Result<String> {
        let node = self.child(name)?;
        if node.is_some_and(|node| !node.children.is_empty())
            && !matches!(name, "title" | "abstract")
        {
            return Err(Error::integrity("Nested RFC scalar metadata."));
        }
        Ok(node.map(|node| normalized(&node.text)).unwrap_or_default())
    }
}

fn rfc_number(value: &str) -> Result<u32> {
    let digits = value
        .strip_prefix("RFC")
        .ok_or_else(|| Error::integrity("Invalid RFC identity."))?;
    if digits.is_empty() || digits.len() > 6 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::integrity("Invalid RFC identity."));
    }
    digits
        .parse::<u32>()
        .ok()
        .filter(|number| (1..=999999).contains(number))
        .ok_or_else(|| Error::integrity("Invalid RFC identity."))
}

fn relationships(node: &Node, name: &str) -> Result<Vec<String>> {
    let Some(group) = node.child(name)? else {
        return Ok(Vec::new());
    };
    let mut values = Vec::new();
    for child in &group.children {
        if child.name != "doc-id" || !child.children.is_empty() {
            return Err(Error::integrity("Invalid RFC relationship field."));
        }
        let value = normalized(&child.text);
        rfc_number(&value)?;
        if !values.contains(&value) {
            values.push(value);
        }
    }
    Ok(values)
}

fn record_from_node(node: Node) -> Result<Record> {
    let number = rfc_number(&node.scalar("doc-id")?)?;
    let title = node.scalar("title")?;
    if title.is_empty() {
        return Err(Error::integrity("RFC index entry lacks a title."));
    }
    let mut record = Record {
        number,
        title,
        abstract_text: node.scalar("abstract")?,
        status: node.scalar("current-status")?,
        stream: node.scalar("stream")?,
        area: node.scalar("area")?,
        working_group: node.scalar("wg_acronym")?,
        doi: node.scalar("doi")?,
        updates: relationships(&node, "updates")?,
        obsoletes: relationships(&node, "obsoletes")?,
        updated_by: relationships(&node, "updated-by")?,
        obsoleted_by: relationships(&node, "obsoleted-by")?,
        ..Record::default()
    };
    if let Some(date) = node.child("date")? {
        let month = date.scalar("month")?;
        let year = date.scalar("year")?;
        record.published = normalized(&format!("{month} {year}"));
        if !year.is_empty()
            && (year.len() != 4
                || year
                    .parse::<u16>()
                    .ok()
                    .is_none_or(|value| !(1900..=9999).contains(&value)))
        {
            return Err(Error::integrity("Invalid RFC publication year."));
        }
        let months = [
            "January",
            "February",
            "March",
            "April",
            "May",
            "June",
            "July",
            "August",
            "September",
            "October",
            "November",
            "December",
        ];
        if let Some(index) = months
            .iter()
            .position(|value| value.eq_ignore_ascii_case(&month))
            && !year.is_empty()
        {
            record.publication = Some(format!("{year}-{:02}", index + 1));
        }
    }
    for author in node.children.iter().filter(|child| child.name == "author") {
        let name = author.scalar("name")?;
        if !name.is_empty() {
            record.authors.push(name);
        }
    }
    if let Some(keywords) = node.child("keywords")? {
        record.keywords = keywords
            .children
            .iter()
            .filter(|child| child.name == "kw")
            .map(|child| normalized(&child.text))
            .filter(|value| !value.is_empty())
            .collect();
    }
    if let Some(format) = node.child("format")? {
        for child in format
            .children
            .iter()
            .filter(|child| child.name == "file-format")
        {
            let original = normalized(&child.text);
            let value = match original.to_ascii_lowercase().as_str() {
                "ascii" | "text" | "txt" => "txt",
                "html" => "html",
                "xml" => "xml",
                "pdf" => "pdf",
                _ => {
                    if !original.is_empty() && !record.unsupported_formats.contains(&original) {
                        record.unsupported_formats.push(original);
                    }
                    continue;
                }
            }
            .to_owned();
            if !record.formats.contains(&value) {
                record.formats.push(value);
            }
        }
    }
    for tag in ["is-also", "see-also"] {
        if let Some(group) = node.child(tag)? {
            for child in group.children.iter().filter(|child| child.name == "doc-id") {
                let value = normalized(&child.text);
                if let Some(digits) = ["STD", "BCP", "FYI"]
                    .into_iter()
                    .find_map(|prefix| value.strip_prefix(prefix))
                {
                    if digits.is_empty()
                        || digits.len() > 6
                        || !digits.bytes().all(|byte| byte.is_ascii_digit())
                        || digits.parse::<u32>().ok() == Some(0)
                    {
                        return Err(Error::integrity("Invalid RFC series identity."));
                    }
                    if !record.series.contains(&value) {
                        record.series.push(value);
                    }
                }
            }
        }
    }
    Ok(record)
}

pub fn parse_index(bytes: &[u8]) -> Result<Vec<Record>> {
    parse_index_until(bytes, Instant::now() + Duration::from_secs(15))
}

fn parse_index_until(bytes: &[u8], deadline: Instant) -> Result<Vec<Record>> {
    if bytes.len() > MAX_INDEX {
        return Err(Error::capacity("RFC index exceeds byte limit."));
    }
    let xml =
        std::str::from_utf8(bytes).map_err(|_| Error::integrity("RFC index is not UTF-8."))?;
    let mut reader = NsReader::from_str(xml);
    reader.config_mut().expand_empty_elements = true;
    let mut names = Vec::<String>::new();
    let mut entry = Vec::<Node>::new();
    let mut entry_bytes = 0usize;
    let mut entry_nodes = 0usize;
    let mut root_seen = false;
    let mut root_namespace = None::<String>;
    let mut records = Vec::new();
    loop {
        if Instant::now() >= deadline {
            return Err(Error::capacity("RFC index parser time budget exceeded."));
        }
        let (namespace, event) = reader
            .read_resolved_event()
            .map_err(|_| Error::integrity("Malformed RFC index XML."))?;
        match event {
            Event::Start(element) => {
                let namespace = match namespace {
                    ResolveResult::Unbound => String::new(),
                    ResolveResult::Bound(namespace)
                        if matches!(
                            namespace.as_ref(),
                            "https://www.rfc-editor.org/rfc-index"
                                | "http://www.rfc-editor.org/rfc-index"
                        ) =>
                    {
                        namespace.as_ref().to_owned()
                    }
                    _ => return Err(Error::integrity("Unsupported RFC index namespace.")),
                };
                if root_namespace
                    .as_ref()
                    .is_some_and(|root| root != &namespace)
                {
                    return Err(Error::integrity(
                        "RFC index namespace changed within its root.",
                    ));
                }
                if root_namespace.is_none() {
                    root_namespace = Some(namespace);
                }
                let name = element.local_name().as_ref().to_owned();
                if names.len() >= 64 {
                    return Err(Error::capacity("RFC index XML nesting exceeds limit."));
                }
                if names.is_empty() {
                    if root_seen || name != "rfc-index" {
                        return Err(Error::integrity("Invalid RFC index root."));
                    }
                    root_seen = true;
                }
                if name == "rfc-entry" && (names.len() != 1 || names[0] != "rfc-index") {
                    return Err(Error::integrity(
                        "RFC entries must be direct index children.",
                    ));
                }
                if name == "rfc-entry" || !entry.is_empty() {
                    if entry.is_empty() {
                        entry_bytes = 0;
                        entry_nodes = 0;
                    }
                    entry_nodes += 1;
                    if entry_nodes > 4096 {
                        return Err(Error::capacity("RFC index entry has too many fields."));
                    }
                    entry.push(Node {
                        name: name.clone(),
                        ..Node::default()
                    });
                }
                names.push(name);
            }
            Event::End(element) => {
                let local = element.local_name();
                if names.last().map(String::as_str) != Some(local.as_ref()) {
                    return Err(Error::integrity("Unmatched RFC index element."));
                }
                names.pop();
                if let Some(node) = entry.pop() {
                    if let Some(parent) = entry.last_mut() {
                        if node.name == "p" {
                            parent.text.push(' ');
                        }
                        parent.text.push_str(&node.text);
                        if node.name == "p" {
                            parent.text.push(' ');
                        }
                        parent.children.push(node);
                    } else {
                        records.push(record_from_node(node)?);
                        if records.len() > 50000 {
                            return Err(Error::capacity("RFC index exceeds record limit."));
                        }
                    }
                }
            }
            Event::Text(event) => {
                let decoded = event.xml10_content();
                let text = quick_xml::escape::unescape(&decoded)
                    .map_err(|_| Error::integrity("Invalid RFC index text entity."))?;
                append_index_text(&mut entry, &names, &text, &mut entry_bytes)?;
            }
            Event::CData(event) => {
                if names.is_empty() {
                    return Err(Error::integrity("CDATA outside RFC index root."));
                }
                append_index_text(&mut entry, &names, &event.xml10_content(), &mut entry_bytes)?
            }
            Event::GeneralRef(event) => {
                let text = quick_xml::escape::unescape(&format!("&{};", event.as_ref()))
                    .map_err(|_| Error::integrity("Unsupported RFC index entity."))?
                    .into_owned();
                append_index_text(&mut entry, &names, &text, &mut entry_bytes)?;
            }
            Event::DocType(_) => {
                return Err(Error::integrity(
                    "RFC index document types are unsupported.",
                ));
            }
            Event::Eof => break,
            _ => {}
        }
    }
    if !root_seen || !names.is_empty() || records.is_empty() {
        return Err(Error::integrity("Incomplete or empty RFC index."));
    }
    records.sort_by_key(|record| record.number);
    if records
        .windows(2)
        .any(|pair| pair[0].number == pair[1].number)
    {
        return Err(Error::integrity("Duplicate RFC index identity."));
    }
    Ok(records)
}

fn append_index_text(
    entry: &mut [Node],
    names: &[String],
    text: &str,
    total: &mut usize,
) -> Result<()> {
    if let Some(node) = entry.last_mut() {
        *total = total.saturating_add(text.len());
        if *total > MAX_ENTRY {
            return Err(Error::capacity("RFC index entry exceeds text limit."));
        }
        node.text.push_str(text);
    } else if names.is_empty() && !text.trim().is_empty() {
        return Err(Error::integrity("Text outside RFC index root."));
    }
    Ok(())
}

pub async fn search(retrieval: &Retrieval, input: SearchInput) -> Result<Value> {
    if input.query.trim().is_empty()
        || input.query.chars().count() > 256
        || input
            .status
            .as_ref()
            .is_some_and(|v| v.chars().count() > 256 || v.is_empty())
    {
        return Err(Error::invalid(
            "RFC query and optional status must contain 1..256 characters.",
        ));
    }
    let page = Page {
        offset: input.offset,
        limit: input.limit,
    }
    .checked()?;
    let mut capture = match input.capture {
        Some(id) => {
            let stored = retrieval.read_capture(&id).await?;
            ensure_capture(&stored, INDEX_KEY)?;
            stored
        }
        None => {
            retrieval
                .get_validated(
                    FetchRequest {
                        key: INDEX_KEY.into(),
                        url: INDEX_URL.into(),
                        ttl_secs: 86400,
                        max_bytes: 64 * 1024 * 1024,
                        media_type: "application/xml".into(),
                    },
                    &Validator,
                )
                .await?
        }
    };
    let permit = archive::admit()?;
    let bytes = std::mem::take(&mut capture.body);
    let (items, total) = tokio::task::spawn_blocking(move || -> Result<_> {
        let _permit = permit;
        let deadline = Instant::now() + Duration::from_secs(15);
        let records = parse_index_until(&bytes, deadline)?;
        let terms = input.query.to_lowercase().split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        let mut total = 0usize;
        let mut items = Vec::new();
        for record in records {
            if Instant::now() >= deadline { return Err(Error::capacity("RFC search processing time budget exceeded.")); }
            let searchable = format!("rfc{} {} {} {}", record.number, record.title, record.abstract_text, record.status).to_lowercase();
            if terms.iter().all(|term| searchable.contains(term)) && input.status.as_ref().is_none_or(|status| record.status.eq_ignore_ascii_case(status)) {
                if total >= page.offset && items.len() < page.limit {
                    items.push(json!({"id":format!("rfc:{}",record.number),"url":format!("https://www.rfc-editor.org/rfc/rfc{}.txt",record.number),"metadata":record}));
                }
                total += 1;
            }
        }
        Ok((items, total))
    }).await.map_err(|_| Error::unavailable("RFC index parser worker failed."))??;
    Ok(
        json!({"items":items,"total":total,"offset":page.offset,"next_offset":if page.offset.saturating_add(page.limit)<total {Some(page.offset+page.limit)}else{None},"capture":capture_json(&capture.capture,86400),"search_scope":"official_index_metadata","license_notice":"RFC documents retain their individual notices and applicable IETF Trust terms."}),
    )
}

pub async fn get(retrieval: &Retrieval, input: GetInput) -> Result<Value> {
    if input.number == 0 || input.number > 999999 {
        return Err(Error::invalid("RFC number must be 1..999999."));
    }
    if input.limit == 0 || input.limit > 32768 {
        return Err(Error::invalid("Text limit must be 1..32768."));
    }
    let key = format!("rfc:text:{}", input.number);
    let capture = match input.capture {
        Some(id) => {
            let stored = retrieval.read_capture(&id).await?;
            ensure_capture(&stored, &key)?;
            stored
        }
        None => {
            retrieval
                .get_validated(
                    FetchRequest {
                        key,
                        url: format!("https://www.rfc-editor.org/rfc/rfc{}.txt", input.number),
                        ttl_secs: 86400,
                        max_bytes: 16 * 1024 * 1024,
                        media_type: "text/plain".into(),
                    },
                    &Validator,
                )
                .await?
        }
    };
    validate_representation("txt", &capture.body)?;
    let text = std::str::from_utf8(&capture.body)
        .map_err(|_| Error::integrity("RFC text is not UTF-8."))?;
    let page = text_page(text, input.offset, input.limit)?;
    Ok(
        json!({"id":format!("rfc:{}",input.number),"page":page,"capture":capture_json(&capture.capture,86400),"resource_uri":format!("devres://capture/{}?offset={}&limit={}",capture.capture.id,input.offset,input.limit),"license_notice":"Preserve this RFC's embedded copyright and license notices; repository licensing does not replace them."}),
    )
}

/// Validation runs before durable source-head promotion, with owned bytes and
/// parser admission retained by the blocking worker if its caller is cancelled.
pub(crate) struct Validator;
#[async_trait]
impl ResponseValidator for Validator {
    async fn validate(
        &self,
        request: &FetchRequest,
        response: FetchResponse,
    ) -> Result<FetchResponse> {
        let permit = archive::admit()?;
        let key = request.key.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            if key == INDEX_KEY {
                parse_index(&response.body)?;
            } else if key == "rfc:errata" {
                parse_errata(&response.body)?;
            } else {
                let format = if key.starts_with("rfc:text:") {
                    "txt"
                } else {
                    key.rsplit(':')
                        .next()
                        .ok_or_else(|| Error::invalid("Invalid RFC source identity."))?
                };
                validate_representation(format, &response.body)?;
            }
            Ok(response)
        })
        .await
        .map_err(|_| Error::unavailable("RFC validation worker failed."))?
    }
}

fn utf8(bytes: &[u8]) -> Result<&str> {
    std::str::from_utf8(bytes).map_err(|_| Error::integrity("RFC representation is not UTF-8."))
}

pub(crate) fn validate_representation(format: &str, bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() {
        return Err(Error::integrity("Empty RFC representation."));
    }
    if bytes.len() > MAX_TEXT {
        return Err(Error::capacity("RFC representation exceeds 16 MiB."));
    }
    match format {
        "txt" => {
            let text = utf8(bytes)?;
            let beginning = text.trim_start_matches(['\u{feff}', ' ', '\t', '\r', '\n']);
            if beginning.is_empty() || beginning.starts_with('<') || text.contains('\0') {
                return Err(Error::integrity(
                    "RFC text endpoint did not return published plain text.",
                ));
            }
        }
        "xml" => {
            xml_text(bytes, false)?;
        }
        "html" => {
            html_text(bytes, false, Instant::now() + Duration::from_secs(15))?;
        }
        "pdf" => {
            if !bytes.starts_with(b"%PDF-")
                || !bytes[bytes.len().saturating_sub(2048)..]
                    .windows(5)
                    .any(|window| window == b"%%EOF")
            {
                return Err(Error::integrity(
                    "RFC PDF endpoint did not return a PDF representation.",
                ));
            }
        }
        _ => return Err(Error::invalid("RFC format must be txt, html, xml, or pdf.")),
    }
    Ok(())
}

/// RFC XML is never resolved against a DTD, URL, file, or external entity.
/// A document type can be retained in raw captures; unresolved custom entities
/// explicitly prevent derived-text extraction instead of dropping their content.
fn xml_text(bytes: &[u8], extract: bool) -> Result<String> {
    let xml = utf8(bytes)?;
    let mut reader = Reader::from_str(xml);
    reader.config_mut().expand_empty_elements = true;
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut stack = Vec::<String>::new();
    let mut root_seen = false;
    let mut nodes = 0usize;
    let mut output = String::new();
    loop {
        if Instant::now() >= deadline {
            return Err(Error::capacity("RFC XML processing deadline exceeded."));
        }
        match reader
            .read_event()
            .map_err(|_| Error::integrity("Malformed RFC XML."))?
        {
            Event::Start(event) => {
                let name = event.local_name().as_ref().to_owned();
                if stack.is_empty() {
                    if root_seen || name != "rfc" {
                        return Err(Error::integrity("Invalid RFC XML root."));
                    }
                    root_seen = true;
                }
                nodes += 1;
                if stack.len() >= 64 || nodes > 200_000 {
                    return Err(Error::capacity("RFC XML structural limit exceeded."));
                }
                if extract
                    && matches!(
                        name.as_str(),
                        "t" | "section"
                            | "name"
                            | "li"
                            | "dt"
                            | "dd"
                            | "artwork"
                            | "sourcecode"
                            | "blockquote"
                    )
                {
                    output.push('\n');
                }
                stack.push(name);
            }
            Event::End(event) => {
                let name = event.local_name();
                if stack.last().map(String::as_str) != Some(name.as_ref()) {
                    return Err(Error::integrity("Unmatched RFC XML element."));
                }
                stack.pop();
                if extract
                    && matches!(
                        name.as_ref(),
                        "t" | "section"
                            | "name"
                            | "li"
                            | "dt"
                            | "dd"
                            | "artwork"
                            | "sourcecode"
                            | "blockquote"
                    )
                {
                    output.push('\n');
                }
            }
            Event::Text(event) => {
                let decoded = event.xml10_content();
                let text = quick_xml::escape::unescape(&decoded)
                    .map_err(|_| Error::integrity("Invalid RFC XML entity."))?;
                if stack.is_empty() && !text.trim().is_empty() {
                    return Err(Error::integrity("Text outside RFC XML root."));
                }
                if extract {
                    output.push_str(&text);
                }
            }
            Event::CData(event) => {
                if stack.is_empty() {
                    return Err(Error::integrity("CDATA outside RFC XML root."));
                }
                if extract {
                    output.push_str(&event.xml10_content());
                }
            }
            Event::GeneralRef(event) => {
                if extract {
                    let text = quick_xml::escape::unescape(&format!("&{};", event.as_ref()))
                        .map_err(|_| {
                            Error::integrity("Unresolved RFC XML entity prevents text extraction.")
                        })?
                        .into_owned();
                    output.push_str(&text);
                }
            }
            Event::DocType(_) if root_seen => {
                return Err(Error::integrity(
                    "RFC XML document type must precede its root.",
                ));
            }
            Event::Eof => break,
            _ => {}
        }
        if output.len() > MAX_TEXT {
            return Err(Error::capacity("Derived RFC text exceeds 16 MiB."));
        }
    }
    if !root_seen || !stack.is_empty() {
        return Err(Error::integrity("Incomplete RFC XML."));
    }
    Ok(output)
}

const HTML_CHUNK: usize = 4096;
const HTML_TOKEN: usize = 16 * 1024;

struct HtmlState {
    stack: Vec<String>,
    output: String,
    text_bytes: usize,
    tokens: usize,
    nodes: usize,
    completed: usize,
    html_seen: bool,
    error: Option<Error>,
}
struct HtmlSink {
    state: RefCell<HtmlState>,
    deadline: Instant,
    collect: bool,
}

fn html_block(name: &str) -> bool {
    matches!(
        name,
        "p" | "div"
            | "section"
            | "article"
            | "li"
            | "dt"
            | "dd"
            | "pre"
            | "blockquote"
            | "h1"
            | "h2"
            | "h3"
            | "h4"
            | "h5"
            | "h6"
            | "br"
            | "tr"
    )
}
fn html_hidden(name: &str) -> bool {
    matches!(name, "script" | "style" | "head" | "template" | "noscript")
}
fn html_void(name: &str) -> bool {
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

impl html5ever::tokenizer::TokenSink for HtmlSink {
    type Handle = ();
    fn process_token(
        &self,
        token: html5ever::tokenizer::Token,
        _: u64,
    ) -> html5ever::tokenizer::TokenSinkResult<()> {
        use html5ever::tokenizer::{TagKind, Token, TokenSinkResult, states::RawKind};
        let mut state = self.state.borrow_mut();
        // Character/error callbacks must return Continue: html5ever asserts this.
        // Once a failure is recorded the remaining bounded input chunk is ignored.
        if state.error.is_some() {
            return TokenSinkResult::Continue;
        }
        state.tokens += 1;
        if Instant::now() >= self.deadline || state.tokens > 500_000 {
            state.error = Some(Error::capacity("RFC HTML token/deadline limit exceeded."));
            return TokenSinkResult::Continue;
        }
        if !matches!(token, Token::ParseError(_) | Token::EOFToken) {
            state.completed += 1;
        }
        match token {
            Token::TagToken(tag) => {
                state.nodes += 1;
                let name: &str = tag.name.as_ref();
                let bytes = name.len()
                    + tag
                        .attrs
                        .iter()
                        .map(|attribute| attribute.name.local.len() + attribute.value.len())
                        .sum::<usize>();
                if state.nodes > 200_000
                    || tag.attrs.len() > 128
                    || name.len() > 256
                    || bytes > HTML_TOKEN
                {
                    state.error = Some(Error::capacity("RFC HTML tag/attribute limit exceeded."));
                    return TokenSinkResult::Continue;
                }
                if tag.kind == TagKind::StartTag {
                    if name == "html" {
                        state.html_seen = true;
                    }
                    // HTML permits the head end tag to be omitted before body.
                    if name == "body"
                        && let Some(at) = state.stack.iter().rposition(|name| name == "head")
                    {
                        state.stack.truncate(at);
                    }
                    if html_block(name)
                        && !state.stack.iter().any(|name| html_hidden(name))
                        && self.collect
                    {
                        state.output.push('\n');
                    }
                    if !html_void(name)
                        && (!tag.self_closing
                            || html_hidden(name)
                            || matches!(name, "title" | "textarea"))
                    {
                        if state.stack.len() >= 256 {
                            state.error = Some(Error::capacity("RFC HTML nesting exceeds limit."));
                            return TokenSinkResult::Continue;
                        }
                        state.stack.push(name.to_owned());
                    }
                    return match name {
                        "script" => TokenSinkResult::RawData(RawKind::ScriptData),
                        "style" | "noscript" | "xmp" | "iframe" | "noembed" | "noframes" => {
                            TokenSinkResult::RawData(RawKind::Rawtext)
                        }
                        "title" | "textarea" => TokenSinkResult::RawData(RawKind::Rcdata),
                        "plaintext" => TokenSinkResult::Plaintext,
                        _ => TokenSinkResult::Continue,
                    };
                }
                if let Some(at) = state.stack.iter().rposition(|open| open == name) {
                    state.stack.truncate(at);
                }
                if html_block(name)
                    && !state.stack.iter().any(|name| html_hidden(name))
                    && self.collect
                {
                    state.output.push('\n');
                }
            }
            Token::CharacterTokens(text) => {
                state.text_bytes = state.text_bytes.saturating_add(text.len());
                if state.text_bytes > MAX_TEXT {
                    state.error = Some(Error::capacity("Derived RFC HTML text exceeds 16 MiB."));
                } else if self.collect && !state.stack.iter().any(|name| html_hidden(name)) {
                    state.output.push_str(&text);
                }
            }
            Token::DoctypeToken(doctype) => {
                let bytes = doctype.name.as_ref().map_or(0, |value| value.len())
                    + doctype.public_id.as_ref().map_or(0, |value| value.len())
                    + doctype.system_id.as_ref().map_or(0, |value| value.len());
                if bytes > HTML_TOKEN {
                    state.error = Some(Error::capacity("RFC HTML doctype exceeds token limit."));
                }
            }
            Token::NullCharacterToken => {
                state.error = Some(Error::integrity("RFC HTML contains a null character."))
            }
            Token::CommentToken(text) if text.len() > HTML_TOKEN => {
                state.error = Some(Error::capacity("RFC HTML comment exceeds token limit."))
            }
            _ => {}
        }
        if state.output.len() > MAX_TEXT {
            state.error = Some(Error::capacity("Derived RFC HTML text exceeds 16 MiB."));
        }
        TokenSinkResult::Continue
    }
}

/// Tokenize UTF-8 chunks directly, without constructing a DOM or loading resources.
/// The unfinished-token budget also bounds names, attributes, comments, and numeric
/// character references before html5ever emits them to the sink.
fn html_text(bytes: &[u8], collect: bool, deadline: Instant) -> Result<String> {
    use html5ever::{
        tendril::StrTendril,
        tokenizer::{BufferQueue, Tokenizer, TokenizerOpts},
    };
    if bytes.is_empty() || bytes.len() > MAX_TEXT {
        return Err(Error::capacity("RFC HTML body exceeds bounds."));
    }
    let text = utf8(bytes)?;
    let beginning = text.trim_start_matches(['\u{feff}', ' ', '\t', '\r', '\n']);
    let prefix = beginning
        .chars()
        .take(32)
        .collect::<String>()
        .to_ascii_lowercase();
    if !(prefix.starts_with("<!doctype html")
        || prefix.starts_with("<html")
        || prefix.starts_with("<?xml"))
    {
        return Err(Error::integrity(
            "RFC HTML endpoint did not return an HTML document.",
        ));
    }
    let sink = HtmlSink {
        state: RefCell::new(HtmlState {
            stack: Vec::new(),
            output: String::new(),
            text_bytes: 0,
            tokens: 0,
            nodes: 0,
            completed: 0,
            html_seen: false,
            error: None,
        }),
        deadline,
        collect,
    };
    let tokenizer = Tokenizer::new(sink, TokenizerOpts::default());
    let input = BufferQueue::default();
    let mut offset = 0usize;
    let mut pending_bytes = 0usize;
    while offset < text.len() {
        if Instant::now() >= deadline {
            return Err(Error::capacity("RFC HTML processing deadline exceeded."));
        }
        let mut end = (offset + HTML_CHUNK).min(text.len());
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        let completed = tokenizer.sink.state.borrow().completed;
        input.push_back(StrTendril::from_slice(&text[offset..end]));
        let _ = tokenizer.feed(&input);
        let mut state = tokenizer.sink.state.borrow_mut();
        if let Some(error) = state.error.take() {
            return Err(error);
        }
        if state.completed == completed {
            pending_bytes += end - offset;
        } else {
            pending_bytes = 0;
        }
        if pending_bytes > HTML_TOKEN {
            return Err(Error::capacity("RFC HTML unfinished token exceeds 16 KiB."));
        }
        offset = end;
    }
    tokenizer.end();
    let mut state = tokenizer.sink.state.borrow_mut();
    if let Some(error) = state.error.take() {
        return Err(error);
    }
    if !state.html_seen {
        return Err(Error::integrity("RFC HTML lacks its document element."));
    }
    Ok(std::mem::take(&mut state.output))
}

pub(crate) fn extract_text(format: &str, bytes: &[u8]) -> Result<String> {
    if format == "html" {
        let text = html_text(bytes, true, Instant::now() + Duration::from_secs(15))?;
        if text.trim().is_empty() {
            return Err(Error::integrity(
                "RFC representation has no extractable text.",
            ));
        }
        return Ok(text);
    }
    validate_representation(format, bytes)?;
    let text = match format {
        "txt" => utf8(bytes)?.to_owned(),
        "xml" => xml_text(bytes, true)?,
        "html" => html_text(bytes, true, Instant::now() + Duration::from_secs(15))?,
        "pdf" => {
            return Err(Error::invalid(
                "PDF text extraction is unsupported; use the captured PDF bytes.",
            ));
        }
        _ => return Err(Error::invalid("Unsupported RFC text format.")),
    };
    if text.trim().is_empty() {
        return Err(Error::integrity(
            "RFC representation has no extractable text.",
        ));
    }
    Ok(text)
}

pub(crate) fn parse_errata(bytes: &[u8]) -> Result<Vec<Value>> {
    if bytes.len() > MAX_INDEX {
        return Err(Error::capacity("RFC errata exceeds byte limit."));
    }
    let deadline = Instant::now() + Duration::from_secs(15);
    struct BoundedRecords<'a> {
        deadline: Instant,
        capacity: &'a std::cell::Cell<bool>,
    }
    impl<'de> serde::de::Visitor<'de> for BoundedRecords<'_> {
        type Value = Vec<Value>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a bounded RFC errata array")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut sequence: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            let mut records = Vec::new();
            while let Some(raw) = sequence.next_element::<&'de serde_json::value::RawValue>()? {
                if records.len() >= 50000
                    || raw.get().len() > MAX_ENTRY
                    || Instant::now() >= self.deadline
                {
                    self.capacity.set(true);
                    return Err(serde::de::Error::custom("RFC errata capacity exceeded"));
                }
                let record: Value =
                    serde_json::from_str(raw.get()).map_err(serde::de::Error::custom)?;
                if record.as_object().is_some_and(|object| object.len() > 64) {
                    self.capacity.set(true);
                    return Err(serde::de::Error::custom(
                        "RFC errata field capacity exceeded",
                    ));
                }
                records.push(record);
            }
            Ok(records)
        }
    }
    let capacity = std::cell::Cell::new(false);
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let records = serde::Deserializer::deserialize_seq(
        &mut decoder,
        BoundedRecords {
            deadline,
            capacity: &capacity,
        },
    )
    .map_err(|_| {
        if capacity.get() {
            Error::capacity("RFC errata exceeds processing bounds.")
        } else {
            Error::integrity("Malformed RFC errata JSON.")
        }
    })?;
    decoder
        .end()
        .map_err(|_| Error::integrity("Trailing RFC errata JSON."))?;
    let mut ids = HashSet::new();
    for record in &records {
        if Instant::now() >= deadline {
            return Err(Error::capacity("RFC errata processing deadline exceeded."));
        }
        let object = record
            .as_object()
            .ok_or_else(|| Error::integrity("RFC errata record is not an object."))?;
        let identity = object
            .get("errata_id")
            .and_then(|value| {
                value.as_u64().or_else(|| {
                    let digits = value.as_str()?;
                    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
                        return None;
                    }
                    digits.parse().ok()
                })
            })
            .filter(|value| *value > 0)
            .ok_or_else(|| Error::integrity("Invalid RFC errata identity."))?;
        if !ids.insert(identity) {
            return Err(Error::integrity("Duplicate RFC errata identity."));
        }
        rfc_number(
            object
                .get("doc-id")
                .and_then(Value::as_str)
                .ok_or_else(|| Error::integrity("RFC errata lacks an RFC identity."))?,
        )?;
        for field in ["errata_status_code", "errata_type_code"] {
            if object
                .get(field)
                .and_then(Value::as_str)
                .is_none_or(|value| value.trim().is_empty() || value.len() > 128)
            {
                return Err(Error::integrity("Invalid RFC errata classification."));
            }
        }
        let mut pending = vec![(record, 0usize)];
        let mut nodes = 0usize;
        let mut text_bytes = 0usize;
        while let Some((value, depth)) = pending.pop() {
            nodes += 1;
            if depth > 64 || nodes > 4096 {
                return Err(Error::capacity(
                    "RFC errata record exceeds structure limit.",
                ));
            }
            match value {
                Value::String(text) => text_bytes = text_bytes.saturating_add(text.len()),
                Value::Array(values) => {
                    pending.extend(values.iter().map(|value| (value, depth + 1)))
                }
                Value::Object(values) => {
                    text_bytes =
                        text_bytes.saturating_add(values.keys().map(String::len).sum::<usize>());
                    pending.extend(values.values().map(|value| (value, depth + 1)));
                }
                _ => {}
            }
            if text_bytes > MAX_ENTRY {
                return Err(Error::capacity("RFC errata record exceeds text limit."));
            }
        }
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_relationships_and_missing_abstract() {
        let index = br#"<rfc-index><rfc-entry><doc-id>RFC9000</doc-id><title>QUIC &amp; Transport</title><date><month>May</month><year>2021</year></date><current-status>PROPOSED STANDARD</current-status><updates><doc-id>RFC8999</doc-id></updates><updated-by><doc-id>RFC9001</doc-id></updated-by></rfc-entry></rfc-index>"#;
        let records = parse_index(index).unwrap();
        assert_eq!(records[0].title, "QUIC & Transport");
        assert_eq!(records[0].updates, vec!["RFC8999"]);
        assert_eq!(records[0].updated_by, vec!["RFC9001"]);
        assert_eq!(records[0].abstract_text, "");
    }
    #[test]
    fn rejects_external_entities_and_duplicate_identity() {
        assert!(parse_index(br#"<!DOCTYPE x SYSTEM "file:///etc/passwd"><rfc-index/>"#).is_err());
        let entry = "<rfc-entry><doc-id>RFC1</doc-id><title>A</title></rfc-entry>";
        assert!(parse_index(format!("<rfc-index>{entry}{entry}</rfc-index>").as_bytes()).is_err());
    }

    #[test]
    fn preserves_adjacent_entities_and_inline_abstract_markup() {
        let index=br#"<rfc-index><rfc-entry><doc-id>RFC1</doc-id><title>A&amp;B&#x21;</title><abstract><p>One <em>two</em>.</p><p>Three.</p></abstract></rfc-entry></rfc-index>"#;
        let records = parse_index(index).unwrap();
        assert_eq!(records[0].title, "A&B!");
        assert_eq!(records[0].abstract_text, "One two. Three.");
    }
}

#[cfg(test)]
#[path = "source/tests.rs"]
mod processing_tests;
