//! RFC index metadata and plain-text retrieval from RFC Editor.

use crate::{
    archive,
    research::{Page, capture_json, ensure_capture, list_limit, text_limit, text_page},
};
use devres_application::Retrieval;
use devres_domain::{Error, FetchRequest, Result};
use quick_xml::{Reader, events::Event};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

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

#[derive(Default, Serialize, Debug)]
pub struct Record {
    pub number: u32,
    pub title: String,
    pub abstract_text: String,
    pub status: String,
    pub published: String,
    pub updates: Vec<String>,
    pub obsoletes: Vec<String>,
    pub updated_by: Vec<String>,
    pub obsoleted_by: Vec<String>,
}

fn append(target: &mut String, value: &str) {
    if !target.is_empty() {
        target.push(' ');
    }
    target.push_str(value);
}

pub fn parse_index(bytes: &[u8]) -> Result<Vec<Record>> {
    let xml =
        std::str::from_utf8(bytes).map_err(|_| Error::integrity("RFC index is not UTF-8."))?;
    let mut reader = Reader::from_str(xml);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    reader.config_mut().trim_text(false);
    let mut stack = Vec::<String>::new();
    let mut records = Vec::new();
    let mut current = None::<Record>;
    loop {
        if std::time::Instant::now() >= deadline {
            return Err(Error::capacity("RFC index parser time budget exceeded."));
        }
        match reader.read_event() {
            Ok(Event::Start(event)) => {
                let name = event.local_name().as_ref().to_owned();
                if stack.len() >= 64 {
                    return Err(Error::capacity("RFC index XML nesting exceeds limit."));
                }
                if name == "rfc-entry" {
                    if current.is_some() {
                        return Err(Error::integrity("Nested RFC index entry."));
                    }
                    current = Some(Record::default());
                }
                if name == "p"
                    && stack.iter().any(|v| v == "abstract")
                    && let Some(record) = current.as_mut()
                {
                    record.abstract_text.push(' ');
                }
                stack.push(name);
            }
            Ok(Event::End(event)) => {
                if event.local_name().as_ref() == "rfc-entry" {
                    let mut record = current
                        .take()
                        .ok_or_else(|| Error::integrity("Unmatched RFC index entry."))?;
                    if record.number == 0 || record.title.is_empty() {
                        return Err(Error::integrity("RFC index entry lacks identity or title."));
                    }
                    for text in [
                        &mut record.title,
                        &mut record.abstract_text,
                        &mut record.status,
                        &mut record.published,
                    ] {
                        *text = text.split_whitespace().collect::<Vec<_>>().join(" ");
                    }
                    records.push(record);
                    if records.len() > 50_000 {
                        return Err(Error::capacity("RFC index exceeds record limit."));
                    }
                }
                stack.pop();
            }
            Ok(Event::Text(event)) => {
                let decoded = event.xml10_content();
                let text = quick_xml::escape::unescape(&decoded)
                    .map_err(|_| Error::integrity("Invalid RFC index text entity."))?;
                if let Some(record) = current.as_mut() {
                    record_text(record, &stack, &text)?;
                }
            }
            Ok(Event::CData(event)) => {
                let text = event.xml10_content();
                if let Some(record) = current.as_mut() {
                    record_text(record, &stack, &text)?;
                }
            }
            Ok(Event::GeneralRef(event)) => {
                let entity = event.as_ref();
                let encoded = format!("&{entity};");
                let text = quick_xml::escape::unescape(&encoded)
                    .map_err(|_| Error::integrity("Unsupported RFC index entity."))?;
                if let Some(record) = current.as_mut() {
                    record_text(record, &stack, &text)?;
                }
            }
            Ok(Event::DocType(_)) => {
                return Err(Error::integrity(
                    "RFC index document types are unsupported.",
                ));
            }
            Ok(Event::Eof) => break,
            Err(_) => return Err(Error::integrity("Malformed RFC index XML.")),
            _ => {}
        }
    }
    if !stack.is_empty() || records.is_empty() {
        return Err(Error::integrity("Incomplete or empty RFC index."));
    }
    records.sort_by_key(|v| v.number);
    if records
        .windows(2)
        .any(|pair| pair[0].number == pair[1].number)
    {
        return Err(Error::integrity("Duplicate RFC index identity."));
    }
    Ok(records)
}

fn record_text(record: &mut Record, stack: &[String], text: &str) -> Result<()> {
    let tag = stack.last().map(String::as_str).unwrap_or("");
    let parent = stack.iter().rev().nth(1).map(String::as_str).unwrap_or("");
    if tag == "doc-id" {
        let text = text.trim();
        if parent == "rfc-entry" {
            record.number = text
                .strip_prefix("RFC")
                .and_then(|v| v.parse().ok())
                .ok_or_else(|| Error::integrity("Invalid RFC number in index."))?;
        } else {
            let relationship = match parent {
                "updates" => Some(&mut record.updates),
                "obsoletes" => Some(&mut record.obsoletes),
                "updated-by" => Some(&mut record.updated_by),
                "obsoleted-by" => Some(&mut record.obsoleted_by),
                _ => None,
            };
            if let Some(relationship) = relationship {
                relationship.push(text.to_owned());
            }
        }
    } else if stack.iter().any(|v| v == "abstract") {
        record.abstract_text.push_str(text);
    } else if tag == "title" {
        record.title.push_str(text);
    } else if tag == "current-status" {
        record.status.push_str(text);
    } else if parent == "date" && (tag == "month" || tag == "year") {
        append(&mut record.published, text);
    }
    if record.title.len() + record.abstract_text.len() > 256 * 1024 {
        return Err(Error::capacity("RFC index entry exceeds text limit."));
    }
    Ok(())
}

pub async fn search(retrieval: &Retrieval, input: SearchInput) -> Result<Value> {
    if input.query.trim().is_empty()
        || input.query.len() > 256
        || input.status.as_ref().is_some_and(|v| v.len() > 128)
    {
        return Err(Error::invalid("RFC query must contain 1..256 bytes."));
    }
    let page = Page {
        offset: input.offset,
        limit: input.limit,
    }
    .checked()?;
    let permit = archive::admit()?;
    let mut capture = match input.capture {
        Some(id) => {
            let stored = retrieval.read_capture(&id).await?;
            ensure_capture(&stored, INDEX_KEY)?;
            stored
        }
        None => {
            retrieval
                .get(FetchRequest {
                    key: INDEX_KEY.into(),
                    url: INDEX_URL.into(),
                    ttl_secs: 86400,
                    max_bytes: 64 * 1024 * 1024,
                    media_type: "application/xml".into(),
                })
                .await?
        }
    };
    let bytes = std::mem::take(&mut capture.body);
    let records = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        parse_index(&bytes)
    })
    .await
    .map_err(|_| Error::unavailable("RFC index parser worker failed."))??;
    let terms = input
        .query
        .to_lowercase()
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let matched = records
        .into_iter()
        .filter(|record| {
            let searchable = format!(
                "rfc{} {} {} {}",
                record.number, record.title, record.abstract_text, record.status
            )
            .to_lowercase();
            terms.iter().all(|term| searchable.contains(term))
                && input
                    .status
                    .as_ref()
                    .is_none_or(|status| record.status.eq_ignore_ascii_case(status))
        })
        .collect::<Vec<_>>();
    let items = matched.iter().skip(page.offset).take(page.limit).map(|record| json!({"id":format!("rfc:{}",record.number),"url":format!("https://www.rfc-editor.org/rfc/rfc{}.txt",record.number),"metadata":record})).collect::<Vec<_>>();
    Ok(
        json!({"items":items,"total":matched.len(),"offset":page.offset,"next_offset":if page.offset.saturating_add(page.limit)<matched.len() {Some(page.offset+page.limit)}else{None},"capture":capture_json(&capture.capture,86400),"search_scope":"official_index_metadata","license_notice":"RFC documents retain their individual notices and applicable IETF Trust terms."}),
    )
}

pub async fn get(retrieval: &Retrieval, input: GetInput) -> Result<Value> {
    if input.number == 0 || input.number > 999999 {
        return Err(Error::invalid("RFC number must be 1..999999."));
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
                .get(FetchRequest {
                    key,
                    url: format!("https://www.rfc-editor.org/rfc/rfc{}.txt", input.number),
                    ttl_secs: 86400,
                    max_bytes: 16 * 1024 * 1024,
                    media_type: "text/plain".into(),
                })
                .await?
        }
    };
    let text = std::str::from_utf8(&capture.body)
        .map_err(|_| Error::integrity("RFC text is not UTF-8."))?;
    if text
        .trim_start_matches(['\u{feff}', ' ', '\t', '\r', '\n'])
        .starts_with('<')
    {
        return Err(Error::integrity(
            "RFC text endpoint returned markup instead of published plain text.",
        ));
    }
    let page = text_page(text, input.offset, input.limit)?;
    Ok(
        json!({"id":format!("rfc:{}",input.number),"page":page,"capture":capture_json(&capture.capture,86400),"resource_uri":format!("devres://capture/{}?offset={}&limit={}",capture.capture.id,input.offset,input.limit),"license_notice":"Preserve this RFC's embedded copyright and license notices; repository licensing does not replace them."}),
    )
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
