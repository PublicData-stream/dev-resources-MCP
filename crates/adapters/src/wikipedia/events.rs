//! Bounded SSE framing and privacy-preserving recentchange projection.
use crate::bulk::BulkStream;
use devres_domain::{Error, Result};
use serde::{Deserialize, Serialize};

pub const MAX_LINE_BYTES: usize = 64 * 1024;
pub const MAX_EVENT_BYTES: usize = 1024 * 1024;
pub const MAX_RESUME_BYTES: usize = 16 * 1024;

pub struct Connection {
    pub status: u16,
    pub retry_at: Option<i64>,
    pub stream: BulkStream,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Change {
    pub event_id: Option<String>,
    pub timestamp: i64,
    pub title: String,
    pub page_id: Option<u64>,
    pub revision_id: Option<u64>,
    pub kind: ChangeKind,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChangeKind {
    Edit,
    New,
    Move { new_title: String },
    Delete,
    Restore,
    RevisionVisibility { revision_ids: Vec<u64> },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SseEvent {
    pub id: Option<String>,
    pub retry_millis: Option<u64>,
    pub change: Option<Change>,
}

#[derive(Default)]
pub struct SseParser {
    line: Vec<u8>,
    data: String,
    event_type: String,
    last_id: Option<String>,
    retry_millis: Option<u64>,
    event_bytes: usize,
    started: bool,
    after_cr: bool,
}
impl SseParser {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn last_event_id(&self) -> Option<&str> {
        self.last_id.as_deref()
    }
    pub fn push(&mut self, input: &[u8]) -> Result<Vec<SseEvent>> {
        if input.len() > 8 * MAX_EVENT_BYTES {
            return Err(Error::capacity("Wikipedia SSE chunk exceeds its bound."));
        }
        let mut output = Vec::new();
        for &byte in input {
            if self.after_cr {
                self.after_cr = false;
                if byte == b'\n' {
                    continue;
                }
            }
            if byte == b'\r' || byte == b'\n' {
                self.after_cr = byte == b'\r';
                self.process_line(&mut output)?;
            } else {
                if self.line.len() >= MAX_LINE_BYTES {
                    return Err(Error::capacity("Wikipedia SSE line exceeds its bound."));
                }
                self.line.push(byte);
            }
        }
        Ok(output)
    }
    /// SSE only dispatches blank-line-terminated events. EOF discards a partial event.
    pub fn finish(&mut self) {
        self.line.clear();
        self.data.clear();
        self.event_type.clear();
        self.event_bytes = 0;
    }
    fn process_line(&mut self, output: &mut Vec<SseEvent>) -> Result<()> {
        let bytes = std::mem::take(&mut self.line);
        let mut line = std::str::from_utf8(&bytes)
            .map_err(|_| Error::integrity("Invalid Wikipedia SSE text."))?;
        if !self.started {
            self.started = true;
            line = line.strip_prefix('\u{feff}').unwrap_or(line);
        }
        if line.is_empty() {
            if !self.data.is_empty() {
                if self.event_type == "error" {
                    return Err(Error::unavailable("Wikipedia stream reported an error."));
                }
                let change = if self.event_type.is_empty() || self.event_type == "message" {
                    parse_change(self.data.trim_end_matches('\n'))?
                } else {
                    None
                };
                if output.len() >= 4096 {
                    return Err(Error::capacity("Wikipedia SSE dispatch exceeds its bound."));
                }
                output.push(SseEvent {
                    id: self.last_id.clone(),
                    retry_millis: self.retry_millis,
                    change,
                });
            }
            self.data.clear();
            self.event_type.clear();
            self.event_bytes = 0;
            return Ok(());
        }
        self.event_bytes = self
            .event_bytes
            .checked_add(line.len() + 1)
            .filter(|length| *length <= MAX_EVENT_BYTES)
            .ok_or_else(|| Error::capacity("Wikipedia SSE event exceeds its bound."))?;
        if line.starts_with(':') {
            return Ok(());
        }
        let (name, value) = line.split_once(':').map_or((line, ""), |(name, value)| {
            (name, value.strip_prefix(' ').unwrap_or(value))
        });
        match name {
            "data" => {
                self.data.push_str(value);
                self.data.push('\n');
            }
            "event" => {
                if value.len() > 256 {
                    return Err(Error::capacity(
                        "Wikipedia SSE event type exceeds its bound.",
                    ));
                }
                self.event_type = value.into();
            }
            "id" if !value.contains('\0') => {
                validate_resume_id(value)?;
                self.last_id = Some(value.into());
            }
            "retry" if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) => {
                self.retry_millis = value.parse::<u64>().ok();
                // Effective even if this connection closes before a data event.
                if self.retry_millis.is_some() {
                    if output.len() >= 4096 {
                        return Err(Error::capacity("Wikipedia SSE dispatch exceeds its bound."));
                    }
                    output.push(SseEvent {
                        id: None,
                        retry_millis: self.retry_millis,
                        change: None,
                    });
                }
            }
            _ => {}
        }
        Ok(())
    }
}

/// EventStreams accepts topic assignments in this header. Admit only the selected
/// public recentchange topics, never arbitrary caller-selected stream names.
pub fn validate_resume_id(value: &str) -> Result<()> {
    if value.is_empty() {
        return Ok(());
    }
    if value.len() > MAX_RESUME_BYTES || value.chars().any(char::is_control) {
        return Err(invalid_resume());
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Assignment {
        topic: String,
        partition: u32,
        timestamp: Option<u64>,
        offset: Option<i64>,
    }
    let assignments: Vec<Assignment> = serde_json::from_str(value).map_err(|_| invalid_resume())?;
    if assignments.is_empty()
        || assignments.len() > 64
        || assignments.iter().any(|assignment| {
            !matches!(
                assignment.topic.as_str(),
                "eqiad.mediawiki.recentchange" | "codfw.mediawiki.recentchange"
            ) || assignment.partition > 1023
                || assignment.timestamp.is_some() == assignment.offset.is_some()
                || assignment.timestamp.is_some_and(|timestamp| timestamp > i64::MAX as u64)
                // -1 is Kafka's end position. EventStreams includes this for an
                // as-yet-unobserved datacenter alongside timestamp assignments.
                || assignment.offset.is_some_and(|offset| offset < -1)
        })
    {
        return Err(invalid_resume());
    }
    Ok(())
}
fn invalid_resume() -> Error {
    Error::invalid("Invalid Wikipedia stream resume position.")
}

#[derive(Deserialize)]
struct Meta {
    domain: Option<String>,
    id: Option<String>,
}
#[derive(Deserialize)]
struct Revision {
    new: Option<u64>,
}
#[derive(Deserialize)]
struct RecentChange {
    meta: Meta,
    wiki: Option<String>,
    server_name: Option<String>,
    timestamp: Option<i64>,
    title: Option<String>,
    namespace: Option<i64>,
    #[serde(alias = "pageid")]
    page_id: Option<u64>,
    revision: Option<Revision>,
    #[serde(rename = "type")]
    change_type: Option<String>,
    log_type: Option<String>,
    log_action: Option<String>,
    log_params: Option<serde_json::Value>,
}
fn parse_change(input: &str) -> Result<Option<Change>> {
    #[derive(Deserialize)]
    struct Domain {
        domain: Option<String>,
    }
    #[derive(Deserialize)]
    struct Identity {
        meta: Domain,
        wiki: Option<String>,
        server_name: Option<String>,
    }
    let identity: Identity = serde_json::from_str(input)
        .map_err(|_| Error::integrity("Invalid Wikipedia change event."))?;
    if identity.meta.domain.as_deref() == Some("canary")
        || identity.wiki.as_deref() != Some("enwiki")
        || identity.server_name.as_deref() != Some("en.wikipedia.org")
        || identity.meta.domain.as_deref() != Some("en.wikipedia.org")
    {
        return Ok(None);
    }
    // The serde projection deliberately has no user, comment, IP or URL fields.
    let event: RecentChange = serde_json::from_str(input)
        .map_err(|_| Error::integrity("Invalid Wikipedia change event."))?;
    if event.meta.domain.as_deref() == Some("canary") {
        return Ok(None);
    }
    if event.wiki.as_deref() != Some("enwiki")
        || event.server_name.as_deref() != Some("en.wikipedia.org")
        || event.meta.domain.as_deref() != Some("en.wikipedia.org")
    {
        return Ok(None);
    }
    let Some(title) = event.title else {
        return Ok(None);
    };
    super::source::validate_title(&title)
        .map_err(|_| Error::integrity("Invalid Wikipedia change title."))?;
    let Some(timestamp) = event.timestamp.filter(|timestamp| *timestamp >= 0) else {
        return Ok(None);
    };
    let kind = match event.change_type.as_deref() {
        Some("edit") if event.namespace == Some(0) => ChangeKind::Edit,
        Some("new") if event.namespace == Some(0) => ChangeKind::New,
        Some("log") => match (event.log_type.as_deref(), event.log_action.as_deref()) {
            (Some("move"), Some("move" | "move_redir")) => {
                let Some(new_title) = event
                    .log_params
                    .as_ref()
                    .and_then(|params| params.get("target_title"))
                    .and_then(serde_json::Value::as_str)
                else {
                    return Ok(None);
                };
                super::source::validate_title(new_title)
                    .map_err(|_| Error::integrity("Invalid Wikipedia move title."))?;
                ChangeKind::Move {
                    new_title: new_title.into(),
                }
            }
            (Some("delete" | "suppress"), Some("delete")) => ChangeKind::Delete,
            (Some("delete"), Some("restore")) => ChangeKind::Restore,
            (Some("delete" | "suppress"), Some("revision")) => {
                let revision_ids = revision_ids(event.log_params.as_ref())?;
                ChangeKind::RevisionVisibility { revision_ids }
            }
            _ => return Ok(None),
        },
        _ => return Ok(None),
    };
    let event_id = event
        .meta
        .id
        .filter(|id| id.len() <= 256 && !id.chars().any(char::is_control));
    Ok(Some(Change {
        event_id,
        timestamp,
        title,
        page_id: event.page_id,
        revision_id: event.revision.and_then(|revision| revision.new),
        kind,
    }))
}
fn revision_ids(params: Option<&serde_json::Value>) -> Result<Vec<u64>> {
    let Some(ids) = params.and_then(|value| value.get("ids")) else {
        return Ok(Vec::new());
    };
    let items: Vec<u64> = if let Some(items) = ids.as_array() {
        if items.len() > 1000 {
            return Err(Error::capacity(
                "Wikipedia revision visibility event exceeds its bound.",
            ));
        }
        items
            .iter()
            .map(|item| item.as_u64().filter(|id| *id > 0).ok_or_else(invalid_ids))
            .collect::<Result<_>>()?
    } else if let Some(text) = ids.as_str() {
        text.split('|')
            .take(1001)
            .map(|value| {
                value
                    .parse::<u64>()
                    .ok()
                    .filter(|id| *id > 0)
                    .ok_or_else(invalid_ids)
            })
            .collect::<Result<_>>()?
    } else {
        return Err(invalid_ids());
    };
    if items.len() > 1000 {
        return Err(Error::capacity(
            "Wikipedia revision visibility event exceeds its bound.",
        ));
    }
    Ok(items)
}
fn invalid_ids() -> Error {
    Error::integrity("Invalid Wikipedia revision visibility event.")
}

#[cfg(test)]
mod tests {
    use super::*;
    fn event() -> serde_json::Value {
        serde_json::json!({"meta":{"domain":"en.wikipedia.org","id":"public-id"},"wiki":"enwiki","server_name":"en.wikipedia.org","title":"Rust","namespace":0,"timestamp":100,"revision":{"new":3},"type":"edit","user":"private-editor","comment":"private-comment"})
    }
    #[test]
    fn fragmented_utf8_crlf_and_private_fields() {
        let mut parser = SseParser::new();
        let mut value = event();
        value["title"] = "Café".into();
        let wire = format!("\u{feff}: heartbeat\r\nretry: 5000\r\ndata: {value}\r\n\r\n");
        let mut events = Vec::new();
        for byte in wire.bytes() {
            events.extend(parser.push(&[byte]).expect("fragment"));
        }
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].retry_millis, Some(5000));
        assert_eq!(events[1].change.as_ref().expect("change").title, "Café");
        let serialized = serde_json::to_string(&events[1].change).expect("serialize");
        assert!(!serialized.contains("private-editor"));
        assert!(!serialized.contains("private-comment"));
    }
    #[test]
    fn bounded_framing_filters_and_safe_resume() {
        assert!(
            SseParser::new()
                .push(&vec![b'x'; MAX_LINE_BYTES + 1])
                .is_err()
        );
        let mut canary = event();
        canary["meta"]["domain"] = "canary".into();
        let output = SseParser::new()
            .push(format!("data: {canary}\n\n").as_bytes())
            .expect("canary");
        assert!(output[0].change.is_none());
        assert!(
            validate_resume_id(r#"[{"topic":"eqiad.private","partition":0,"timestamp":100}]"#)
                .is_err()
        );
        assert!(
            validate_resume_id(
                r#"[{"topic":"eqiad.mediawiki.recentchange","partition":0,"timestamp":100}]"#
            )
            .is_ok()
        );
        assert!(validate_resume_id("bad\r\nheader").is_err());
    }
    #[test]
    fn documented_mixed_timestamp_and_end_offset_resume_ids_are_opaque_and_valid() {
        // Wikitech EventStreams HTTP Service / Response Format, including the
        // inactive datacenter sentinel. No real event body is retained here.
        let id = r#"[{"topic":"eqiad.mediawiki.recentchange","partition":0,"timestamp":1532031066001},{"topic":"codfw.mediawiki.recentchange","partition":0,"offset":-1}]"#;
        validate_resume_id(id).expect("documented mixed assignments");
        let value = event();
        let mut parser = SseParser::new();
        let output = parser
            .push(format!(":ok\n\nevent: message\nid: {id}\ndata: {value}\n\n").as_bytes())
            .expect("mixed ID frame");
        assert_eq!(output.len(), 1);
        assert_eq!(output[0].id.as_deref(), Some(id));
        assert_eq!(
            output[0].change.as_ref().expect("English event").title,
            "Rust"
        );
        for bad in [
            r#"[{"topic":"eqiad.mediawiki.recentchange","partition":0,"timestamp":1,"offset":1}]"#,
            r#"[{"topic":"eqiad.mediawiki.recentchange","partition":0,"offset":-3}]"#,
            r#"[{"topic":"eqiad.private","partition":0,"offset":-1}]"#,
        ] {
            assert!(validate_resume_id(bad).is_err());
        }
    }
    #[test]
    fn log_namespace_minus_one_is_not_dropped_and_irrelevant_logs_do_not_withdraw() {
        let mut value = event();
        value["namespace"] = (-1).into();
        value["type"] = "log".into();
        value["log_type"] = "delete".into();
        value["log_action"] = "delete".into();
        assert_eq!(
            parse_change(&value.to_string())
                .expect("delete")
                .expect("projected")
                .kind,
            ChangeKind::Delete
        );
        value["log_action"] = "event".into();
        assert!(
            parse_change(&value.to_string())
                .expect("log visibility")
                .is_none()
        );
        value["log_action"] = "revision".into();
        value["log_params"] = serde_json::json!({"ids":"1|2"});
        assert_eq!(
            parse_change(&value.to_string())
                .expect("revision")
                .expect("projected")
                .kind,
            ChangeKind::RevisionVisibility {
                revision_ids: vec![1, 2]
            }
        );
    }
    #[test]
    fn foreign_schema_variations_are_filtered_before_english_field_projection() {
        let foreign = serde_json::json!({"meta":{"domain":"www.wikidata.org"},"wiki":"wikidatawiki","server_name":"www.wikidata.org","revision":{"new":"foreign-variation"},"log_params":{"unnecessary":"not retained"}});
        assert!(
            parse_change(&foreign.to_string())
                .expect("foreign filtering")
                .is_none()
        );
        let canary =
            serde_json::json!({"meta":{"domain":"canary"},"revision":"intentionally unrelated"});
        assert!(
            parse_change(&canary.to_string())
                .expect("canary filtering")
                .is_none()
        );
    }
}
