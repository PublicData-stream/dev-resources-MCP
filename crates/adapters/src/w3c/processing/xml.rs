//! Namespace-aware streaming XML; declarations and links are never dereferenced.
use super::{
    Budget, MAX_INPUT, MAX_ITEMS, MAX_KEY, MAX_SCALAR, ProcessedDocument, Reference, Section,
    diagnostic, limit, malformed,
};
use devres_domain::{Error, Result};
use quick_xml::{NsReader, XmlVersion, events::Event, name::ResolveResult};

const XHTML: &str = "http://www.w3.org/1999/xhtml";
struct Frame {
    anchor: String,
    name: String,
    start: usize,
    hidden: bool,
    emitted: String,
    targets: Vec<String>,
}
fn entity() -> Error {
    Error::new(
        "unresolved_xml_entity",
        "Custom XML entities are not expanded.",
    )
}
fn hidden(local: &str) -> bool {
    matches!(
        local,
        "script" | "style" | "template" | "noscript" | "iframe" | "object" | "embed"
    )
}
fn safe_target(target: &str) -> bool {
    if target.is_empty()
        || target.len() > MAX_KEY
        || target.chars().any(char::is_control)
        || target.contains('\\')
        || target.starts_with("//")
    {
        return false;
    }
    match url::Url::parse(target) {
        Ok(url) => {
            matches!(url.scheme(), "https" | "http")
                && url.username().is_empty()
                && url.password().is_none()
        }
        Err(url::ParseError::RelativeUrlWithoutBase) => !target.split('/').any(|part| part == ".."),
        _ => false,
    }
}
fn append(
    text: &str,
    document: &mut ProcessedDocument,
    html: &mut String,
    xhtml: bool,
    hidden: bool,
) -> Result<()> {
    if hidden {
        return Ok(());
    }
    if text.len() > MAX_SCALAR || document.text.len().saturating_add(text.len()) > MAX_INPUT * 3 {
        return Err(limit());
    }
    document.text.push_str(text);
    if xhtml {
        html.push_str(&quick_xml::escape::escape(text));
    }
    Ok(())
}
fn finish(
    frame: Frame,
    document: &mut ProcessedDocument,
    html: &mut String,
    xhtml: bool,
    emitted_bytes: &mut usize,
) -> Result<()> {
    if frame.hidden {
        return Ok(());
    }
    if xhtml {
        html.push_str("</");
        html.push_str(&frame.emitted);
        html.push('>');
    }
    let text = document
        .text
        .get(frame.start..)
        .ok_or_else(malformed)?
        .trim();
    let label: String = text.chars().take(1024).collect();
    let references_bytes = frame.targets.iter().try_fold(0_usize, |bytes, target| {
        bytes
            .checked_add(frame.anchor.len())
            .and_then(|bytes| bytes.checked_add(target.len()))
            .and_then(|bytes| bytes.checked_add(label.len()))
            .ok_or_else(limit)
    })?;
    let bytes = frame
        .anchor
        .len()
        .saturating_add(frame.name.len())
        .saturating_add(text.len())
        .saturating_add(references_bytes);
    *emitted_bytes = emitted_bytes
        .checked_add(bytes)
        .filter(|v| *v <= MAX_INPUT * 3)
        .ok_or_else(limit)?;
    if document.sections.len() >= MAX_ITEMS
        || document
            .references
            .len()
            .saturating_add(frame.targets.len())
            > MAX_ITEMS
    {
        return Err(limit());
    }
    for target in frame.targets {
        document.references.push(Reference {
            source_anchor: frame.anchor.clone(),
            target,
            label: label.clone(),
        });
    }
    document.sections.push(Section {
        anchor: frame.anchor,
        title: frame.name,
        text: text.into(),
    });
    document.text.push('\n');
    Ok(())
}
pub(super) fn project(
    path: &str,
    source: &str,
    xhtml: bool,
    budget: &Budget,
) -> Result<ProcessedDocument> {
    let mut reader = NsReader::from_str(source);
    reader.config_mut().check_end_names = true;
    reader.resolver_mut().set_max_namespace_bindings(256);
    let mut document = ProcessedDocument {
        format: if xhtml { "xhtml" } else { "xml" }.into(),
        title: path.rsplit('/').next().unwrap_or(path).into(),
        ..Default::default()
    };
    let mut stack: Vec<Frame> = Vec::new();
    let mut html = String::new();
    let mut ordinal = 0;
    let mut roots = 0;
    let mut emitted_bytes = 0;
    let mut doctype = false;
    loop {
        budget.node()?;
        let (resolved, event) = reader.read_resolved_event().map_err(|_| malformed())?;
        let namespace = match resolved {
            ResolveResult::Bound(namespace) => namespace.as_ref().to_owned(),
            ResolveResult::Unbound => String::new(),
            ResolveResult::Unknown(_) => return Err(malformed()),
        };
        let empty = matches!(&event, Event::Empty(_));
        match event {
            Event::Start(element) | Event::Empty(element) => {
                // NsReader emits Empty without pushing an element onto our stack.
                if stack.len() >= 64 {
                    return Err(limit());
                }
                if stack.is_empty() {
                    roots += 1;
                    if roots > 1 {
                        return Err(malformed());
                    }
                }
                ordinal += 1;
                let local_name = element.local_name();
                let local = local_name.as_ref();
                if local.len() > MAX_KEY || namespace.len() > MAX_KEY {
                    return Err(limit());
                }
                let suppressed = stack.last().is_some_and(|frame| frame.hidden)
                    || hidden(&local.to_ascii_lowercase());
                let emitted = if namespace.is_empty() || namespace == XHTML {
                    local.to_ascii_lowercase()
                } else {
                    "span".to_owned()
                };
                let mut anchor = format!("xml-element-{ordinal}");
                let mut id_seen = false;
                let mut attributes = Vec::new();
                let mut targets = Vec::new();
                for (attribute_count, attribute) in
                    element.attributes().with_checks(true).enumerate()
                {
                    budget.node()?;
                    if attribute_count >= 128 {
                        return Err(limit());
                    }
                    let attribute = attribute.map_err(|_| malformed())?;
                    let key = attribute.key.as_ref();
                    let (attribute_namespace, attribute_local) =
                        reader.resolver().resolve_attribute(attribute.key);
                    let attribute_namespace = match attribute_namespace {
                        ResolveResult::Bound(namespace) => namespace.as_ref().to_owned(),
                        ResolveResult::Unbound => String::new(),
                        ResolveResult::Unknown(_) => return Err(malformed()),
                    };
                    let attribute_local = attribute_local.as_ref();
                    let id = (attribute_namespace.is_empty() && attribute_local == "id")
                        || (attribute_namespace == "http://www.w3.org/XML/1998/namespace"
                            && attribute_local == "id");
                    let value = attribute
                        .normalized_value(XmlVersion::Implicit1_0)
                        .map_err(|_| entity())?
                        .into_owned();
                    if local.eq_ignore_ascii_case("script")
                        && key == "src"
                        && value.to_ascii_lowercase().contains("respec")
                    {
                        document.gap("unexpanded_respec", "ReSpec source is retained as inert data; generated sections and references are not executed or expanded.");
                    }
                    if key.len() > MAX_KEY || value.len() > MAX_SCALAR || attributes.len() >= 128 {
                        return Err(limit());
                    }
                    if id {
                        if id_seen {
                            return Err(malformed());
                        }
                        if value.len() > MAX_KEY {
                            return Err(limit());
                        }
                        anchor = value.clone();
                        id_seen = true;
                    }
                    let link = (attribute_namespace.is_empty() && attribute_local == "href")
                        || (attribute_namespace == "http://www.w3.org/1999/xlink"
                            && attribute_local == "href")
                        || (attribute_namespace == "http://www.w3.org/1999/02/22-rdf-syntax-ns#"
                            && matches!(attribute_local, "resource" | "about"));
                    if link && safe_target(&value) {
                        targets.push(value.clone());
                    }
                    if attribute_namespace.is_empty()
                        && matches!(
                            key,
                            "id" | "class"
                                | "href"
                                | "data-dfn-for"
                                | "data-dfn-type"
                                | "data-lt"
                                | "algorithm"
                                | "data-algorithm"
                                | "data-cite"
                        )
                    {
                        attributes.push((key.to_owned(), value));
                    } else if id {
                        attributes.push(("id".into(), value));
                    }
                }
                if xhtml && !suppressed {
                    html.push('<');
                    html.push_str(&emitted);
                    for (key, value) in attributes {
                        html.push(' ');
                        html.push_str(&key);
                        html.push_str("=\"");
                        html.push_str(&quick_xml::escape::escape(value));
                        html.push('"');
                    }
                    html.push('>');
                }
                let frame = Frame {
                    anchor,
                    name: if namespace.is_empty() {
                        local.into()
                    } else {
                        format!("{{{namespace}}}{local}")
                    },
                    start: document.text.len(),
                    hidden: suppressed,
                    emitted,
                    targets,
                };
                if empty {
                    finish(frame, &mut document, &mut html, xhtml, &mut emitted_bytes)?;
                } else {
                    stack.push(frame);
                }
            }
            Event::End(_) => {
                let frame = stack.pop().ok_or_else(malformed)?;
                finish(frame, &mut document, &mut html, xhtml, &mut emitted_bytes)?;
            }
            Event::Text(text) => {
                let decoded = text.xml10_content();
                if stack.last().is_some_and(|frame| frame.emitted == "script")
                    && decoded.contains("respecConfig")
                {
                    document.gap("unexpanded_respec", "ReSpec source is retained as inert data; generated sections and references are not executed or expanded.");
                }
                let decoded = quick_xml::escape::unescape(&decoded).map_err(|_| entity())?;
                if stack.is_empty() && !decoded.trim().is_empty() {
                    return Err(malformed());
                }
                append(
                    &decoded,
                    &mut document,
                    &mut html,
                    xhtml,
                    stack.last().is_some_and(|frame| frame.hidden),
                )?;
            }
            Event::CData(text) => {
                if stack.is_empty() {
                    return Err(malformed());
                }
                append(
                    &text.xml10_content(),
                    &mut document,
                    &mut html,
                    xhtml,
                    stack.last().is_some_and(|frame| frame.hidden),
                )?;
            }
            Event::GeneralRef(reference) => {
                if stack.is_empty() {
                    return Err(malformed());
                }
                let decoded = quick_xml::escape::unescape(&format!("&{};", reference.as_ref()))
                    .map_err(|_| entity())?
                    .into_owned();
                append(
                    &decoded,
                    &mut document,
                    &mut html,
                    xhtml,
                    stack.last().is_some_and(|frame| frame.hidden),
                )?;
            }
            Event::DocType(declaration) => {
                if roots > 0 || doctype {
                    return Err(malformed());
                }
                doctype = true;
                if declaration.as_ref().contains('[') {
                    return Err(entity());
                }
                document.gap(
                    "inert_xml_doctype",
                    "The XML doctype is retained as evidence and is never loaded or resolved.",
                );
            }
            Event::Decl(declaration) => {
                if roots > 0 {
                    return Err(malformed());
                }
                if let Some(encoding) = declaration.encoding() {
                    let encoding = encoding.map_err(|_| malformed())?;
                    if !encoding.eq_ignore_ascii_case("utf-8")
                        && !encoding.eq_ignore_ascii_case("us-ascii")
                    {
                        return Ok(super::raw_gap(
                            "xml",
                            "unsupported_encoding",
                            "The declared XML encoding is unsupported; original bytes remain separate raw evidence.",
                        ));
                    }
                }
            }
            Event::Eof => break,
            _ => {}
        }
        if html.len() > MAX_INPUT * 3 {
            return Err(limit());
        }
    }
    if roots != 1 || !stack.is_empty() {
        return Err(malformed());
    }
    if xhtml {
        let mut projected = crate::standards_processing::process_document(
            "publication.html",
            html.as_bytes(),
            budget.cancel.clone(),
        )
        .map_err(diagnostic)?;
        projected.format = "xhtml".into();
        for gap in document.gaps {
            projected.gap(&gap.code, &gap.message);
        }
        // Foreign-namespace XML links remain evidence even when their elements
        // have no corresponding HTML anchor/link semantics.
        for reference in document.references {
            if !projected
                .references
                .iter()
                .any(|existing| existing.target == reference.target)
            {
                projected.references.push(reference);
            }
        }
        return Ok(projected);
    }
    document.gap("structured_semantics_unasserted", "XML text/element navigation does not assert schema validation, SVG rendering, XSLT execution, or RDF graph semantics.");
    if document.text.trim().is_empty() {
        document.gap(
            "publication_unavailable",
            "The captured representation contains no published specification content.",
        );
    }
    document.validate().map_err(diagnostic)?;
    Ok(document)
}
