//! Typed English Wikipedia operations. Neither callers nor source data select origins.
use super::{cache::CacheMetadata, events::Connection};
use crate::bulk::BulkBroker;
use devres_domain::{Error, Result, Validators};
use serde::{Deserialize, Serialize};
use std::{future::Future, pin::Pin, sync::Arc};
use tokio_util::sync::CancellationToken;

pub const ARTICLE_BYTES: usize = 16 * 1024 * 1024;
pub const METADATA_BYTES: usize = 8 * 1024 * 1024;
pub const STREAM_URL: &str = "https://stream.wikimedia.org/v2/stream/recentchange";
const ORIGIN: &str = "https://en.wikipedia.org";

/// The observer must hand ownership of persistence off synchronously, before
/// returning this acknowledgement future. Dropping a caller may drop the ack.
pub type PolicyReceipt = Pin<Box<dyn Future<Output = Result<()>> + Send>>;
pub type PolicyObserver = Arc<dyn Fn(i64) -> Result<PolicyReceipt> + Send + Sync>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Operation {
    ArticleHtml {
        title: String,
    },
    ArticleSource {
        title: String,
    },
    Search {
        query: String,
        limit: usize,
    },
    Category {
        title: String,
        continuation: Option<String>,
    },
    Metadata {
        titles: Vec<String>,
        page_ids: Vec<u64>,
    },
    CurrentAliases {
        continuation: Option<String>,
    },
}
impl Operation {
    pub fn is_action(&self) -> bool {
        matches!(
            self,
            Self::Category { .. } | Self::Metadata { .. } | Self::CurrentAliases { .. }
        )
    }
    pub fn max_bytes(&self) -> usize {
        match self {
            Self::ArticleHtml { .. } | Self::ArticleSource { .. } => ARTICLE_BYTES,
            Self::Search { .. } => 2 * 1024 * 1024,
            _ => METADATA_BYTES,
        }
    }
    pub fn url(&self) -> Result<String> {
        let mut url = url::Url::parse(ORIGIN).map_err(|_| invalid())?;
        match self {
            Self::ArticleHtml { title } | Self::ArticleSource { title } => {
                validate_title(title)?;
                url.path_segments_mut()
                    .map_err(|_| invalid())?
                    .extend(["w", "rest.php", "v1", "page", title]);
                if matches!(self, Self::ArticleHtml { .. }) {
                    url.path_segments_mut()
                        .map_err(|_| invalid())?
                        .push("with_html");
                }
                // Make wiki redirects explicit, so the broker can validate every hop.
                url.query_pairs_mut().append_pair("redirect", "no");
            }
            Self::Search { query, limit } => {
                if query.is_empty()
                    || query.len() > 1024
                    || query.chars().any(char::is_control)
                    || !(1..=100).contains(limit)
                {
                    return Err(invalid());
                }
                url.set_path("/w/rest.php/v1/search/page");
                url.query_pairs_mut()
                    .append_pair("q", query)
                    .append_pair("limit", &limit.to_string());
            }
            Self::Category {
                title,
                continuation,
            } => {
                validate_title(title)?;
                if !title.starts_with("Category:") {
                    return Err(invalid());
                }
                url.set_path("/w/api.php");
                action_defaults(&mut url);
                url.query_pairs_mut()
                    .append_pair("list", "categorymembers")
                    .append_pair("cmtitle", title)
                    .append_pair("cmtype", "page|subcat")
                    .append_pair("cmlimit", "500")
                    .append_pair("cmprop", "ids|title|type");
                if let Some(value) = continuation {
                    validate_continuation(value)?;
                    url.query_pairs_mut().append_pair("cmcontinue", value);
                }
            }
            Self::Metadata { titles, page_ids } => {
                if titles.is_empty() == page_ids.is_empty() || titles.len().max(page_ids.len()) > 50
                {
                    return Err(invalid());
                }
                url.set_path("/w/api.php");
                action_defaults(&mut url);
                url.query_pairs_mut().append_pair("redirects", "1");
                if !titles.is_empty() {
                    for title in titles {
                        validate_title(title)?;
                    }
                    url.query_pairs_mut()
                        .append_pair("titles", &titles.join("|"));
                } else {
                    if page_ids.contains(&0) {
                        return Err(invalid());
                    }
                    url.query_pairs_mut().append_pair(
                        "pageids",
                        &page_ids
                            .iter()
                            .map(u64::to_string)
                            .collect::<Vec<_>>()
                            .join("|"),
                    );
                }
                url.query_pairs_mut()
                    .append_pair("prop", "templates|info|revisions|categories")
                    .append_pair("tlnamespace", "10")
                    .append_pair("tllimit", "500")
                    .append_pair("rvprop", "ids|timestamp")
                    .append_pair("cllimit", "500")
                    .append_pair("clprop", "hidden");
            }
            Self::CurrentAliases { continuation } => {
                url.set_path("/w/api.php");
                action_defaults(&mut url);
                url.query_pairs_mut()
                    .append_pair("prop", "redirects")
                    .append_pair("titles", "Template:Current")
                    .append_pair("rdnamespace", "10")
                    .append_pair("rdlimit", "500");
                if let Some(value) = continuation {
                    validate_continuation(value)?;
                    url.query_pairs_mut().append_pair("rdcontinue", value);
                }
            }
        }
        Ok(url.into())
    }
}
fn action_defaults(url: &mut url::Url) {
    url.query_pairs_mut()
        .append_pair("action", "query")
        .append_pair("format", "json")
        .append_pair("formatversion", "2")
        .append_pair("maxage", "60")
        .append_pair("smaxage", "60")
        .append_pair("maxlag", "5");
}
pub fn validate_title(title: &str) -> Result<()> {
    if title.is_empty()
        || title.len() > 1024
        || title.chars().any(char::is_control)
        || title.contains(['|', '#', '[', ']', '{', '}', '<', '>', '\\'])
        || matches!(title, "." | "..")
    {
        return Err(invalid());
    }
    Ok(())
}
fn validate_continuation(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 8192 || value.chars().any(char::is_control) {
        return Err(invalid());
    }
    Ok(())
}
fn invalid() -> Error {
    Error::invalid("Invalid Wikipedia source operation.")
}

pub struct Response {
    pub effective_url: String,
    pub status: u16,
    pub body: Vec<u8>,
    pub validators: Validators,
    pub cache: CacheMetadata,
    pub retry_at: Option<i64>,
    pub action_slow_until: Option<i64>,
    /// Allowlisted Action API error code only; upstream messages are discarded.
    pub api_error: Option<String>,
}
#[derive(Clone)]
pub struct WikipediaSource {
    broker: Arc<BulkBroker>,
}
impl WikipediaSource {
    pub fn new(broker: Arc<BulkBroker>) -> Self {
        Self { broker }
    }
    pub fn ensure_network_ready(&self) -> Result<()> {
        self.broker.ensure_wikipedia_network_ready()
    }
    pub fn network_ready(&self) -> bool {
        self.ensure_network_ready().is_ok()
    }
    pub fn authenticated(&self) -> bool {
        self.broker.wikipedia_authenticated()
    }
    pub(crate) fn policy_floor(&self) -> Arc<std::sync::atomic::AtomicI64> {
        self.broker.wikipedia_policy_floor()
    }
    pub(crate) async fn fetch_with_policy<F, Fut>(
        &self,
        operation: Operation,
        validators: Validators,
        cancel: CancellationToken,
        before_attempt: F,
        observer: PolicyObserver,
    ) -> Result<Response>
    where
        F: Fn() -> Fut + Send + Sync,
        Fut: Future<Output = Result<()>> + Send,
    {
        self.broker
            .fetch_wikipedia_with_observer(
                operation,
                validators,
                cancel,
                before_attempt,
                Some(observer),
            )
            .await
    }
    pub(crate) async fn stream_with_policy(
        &self,
        last_event_id: Option<String>,
        cancel: CancellationToken,
        observer: PolicyObserver,
    ) -> Result<Connection> {
        self.broker
            .open_wikipedia_stream_with_observer(last_event_id, cancel, Some(observer))
            .await
    }
    pub async fn fetch(
        &self,
        operation: Operation,
        validators: Validators,
        cancel: CancellationToken,
    ) -> Result<Response> {
        self.broker
            .fetch_wikipedia(operation, validators, cancel)
            .await
    }
    /// Persistent application admission is invoked for every actual network hop.
    pub async fn fetch_with_admission<F, Fut>(
        &self,
        operation: Operation,
        validators: Validators,
        cancel: CancellationToken,
        before_attempt: F,
    ) -> Result<Response>
    where
        F: Fn() -> Fut + Send + Sync,
        Fut: std::future::Future<Output = Result<()>> + Send,
    {
        self.broker
            .fetch_wikipedia_with_admission(operation, validators, cancel, before_attempt)
            .await
    }
    pub async fn stream(
        &self,
        last_event_id: Option<String>,
        cancel: CancellationToken,
    ) -> Result<Connection> {
        self.broker
            .open_wikipedia_stream(last_event_id, cancel)
            .await
    }
}

/// A positive match is useful even while aliases are incomplete. A negative is
/// valid only for the requested revision and complete template/alias evidence.
pub fn parse_current(
    metadata: &serde_json::Value,
    page_id: u64,
    revision_id: u64,
    aliases: &[String],
    aliases_complete: bool,
) -> Option<bool> {
    let page = metadata
        .get("query")?
        .get("pages")?
        .as_array()?
        .iter()
        .find(|page| page.get("pageid").and_then(serde_json::Value::as_u64) == Some(page_id))?;
    if page.get("lastrevid").and_then(serde_json::Value::as_u64) != Some(revision_id)
        || page
            .get("revisions")?
            .as_array()?
            .first()?
            .get("revid")?
            .as_u64()?
            != revision_id
    {
        return None;
    }
    if page
        .get("templates")
        .is_some_and(|templates| !templates.is_array())
    {
        return None;
    }
    let templates = page.get("templates").and_then(serde_json::Value::as_array);
    if templates.is_some_and(|items| {
        items.iter().any(|item| {
            item.get("title")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|title| {
                    title == "Template:Current" || aliases.iter().any(|alias| title == alias)
                })
        })
    }) {
        return Some(true);
    }
    if metadata.get("continue").is_some()
        || metadata.get("warnings").is_some()
        || !aliases_complete
        || page.get("missing").is_some()
        || page.get("invalid").is_some()
    {
        return None;
    }
    Some(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_urls_cannot_supply_new_origins_or_parameters() {
        let operation = Operation::ArticleHtml {
            title: "Rust (programming language)/https://evil.invalid?x=1".into(),
        };
        let url = url::Url::parse(&operation.url().expect("url")).expect("parsed");
        assert_eq!(url.host_str(), Some("en.wikipedia.org"));
        assert_eq!(url.query(), Some("redirect=no"));
        assert!(url.path().contains("https:%2F%2Fevil.invalid%3Fx=1"));
        assert!(
            Operation::Metadata {
                titles: vec!["A|B".into()],
                page_ids: vec![]
            }
            .url()
            .is_err()
        );
        assert!(
            Operation::Metadata {
                titles: vec!["A".into()],
                page_ids: vec![1]
            }
            .url()
            .is_err()
        );
        assert!(
            Operation::Category {
                title: "Science".into(),
                continuation: None
            }
            .url()
            .is_err()
        );
    }
    #[test]
    fn current_negative_requires_complete_matching_metadata() {
        let mut value = serde_json::json!({"query":{"pages":[{"pageid":1,"lastrevid":4,"revisions":[{"revid":4}],"templates":[{"title":"Template:Flux"}]}]}});
        assert_eq!(parse_current(&value, 1, 4, &[], false), None);
        assert_eq!(
            parse_current(&value, 1, 4, &["Template:Flux".into()], true),
            Some(true)
        );
        assert_eq!(parse_current(&value, 1, 4, &[], true), Some(false));
        assert_eq!(parse_current(&value, 1, 5, &[], true), None);
        value["continue"] = serde_json::json!({"tlcontinue":"next"});
        assert_eq!(parse_current(&value, 1, 4, &[], true), None);
    }
}
