//! English Wikipedia acquisition configuration and durable publication boundary.
use async_trait::async_trait;
use devres_domain::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const WRITE_ROWS: usize = 100;
pub const WRITE_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct WikipediaConfig {
    pub enabled: bool,
    pub category_roots: Vec<String>,
    pub excluded_categories: Vec<String>,
    pub normal_debounce_secs: u64,
    pub normal_min_refresh_secs: u64,
    pub normal_fallback_secs: u64,
    pub current_debounce_secs: u64,
    pub current_min_refresh_secs: u64,
    pub current_fallback_secs: u64,
    pub category_reconcile_secs: u64,
    pub collection_interval_secs: u64,
    pub publication_interval_secs: u64,
    pub requests_per_second: u32,
    pub min_free_bytes: u64,
    pub max_archive_storage_bytes: Option<u64>,
}

impl Default for WikipediaConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            category_roots: [
                "Science",
                "Technology",
                "Engineering",
                "Mathematics",
                "Artificial intelligence",
                "Computer architecture",
            ]
            .map(|name| format!("Category:{name}"))
            .to_vec(),
            excluded_categories: Vec::new(),
            normal_debounce_secs: 300,
            normal_min_refresh_secs: 300,
            normal_fallback_secs: 86400,
            current_debounce_secs: 30,
            current_min_refresh_secs: 60,
            current_fallback_secs: 300,
            category_reconcile_secs: 86400,
            collection_interval_secs: 1,
            publication_interval_secs: 300,
            requests_per_second: 1,
            min_free_bytes: 1024 * 1024 * 1024,
            max_archive_storage_bytes: None,
        }
    }
}

impl WikipediaConfig {
    pub fn validate(&self) -> Result<()> {
        if [
            self.normal_debounce_secs,
            self.normal_min_refresh_secs,
            self.normal_fallback_secs,
            self.current_debounce_secs,
            self.current_min_refresh_secs,
            self.current_fallback_secs,
            self.category_reconcile_secs,
            self.collection_interval_secs,
            self.publication_interval_secs,
        ]
        .iter()
        .any(|value| !(1..=31_622_400).contains(value))
            || !(1..=3).contains(&self.requests_per_second)
            || self.min_free_bytes < 64 * 1024 * 1024
            || self
                .max_archive_storage_bytes
                .is_some_and(|limit| limit < self.min_free_bytes)
            || self.category_roots.is_empty()
            || self.category_roots.len() > 100
            || self.excluded_categories.len() > 1000
            || self
                .category_roots
                .iter()
                .chain(&self.excluded_categories)
                .any(|name| {
                    !name.starts_with("Category:")
                        || name.len() <= 9
                        || name.len() > 512
                        || name.chars().any(char::is_control)
                        || name.contains(['#', '|', '[', ']', '{', '}'])
                })
        {
            return Err(Error::invalid(
                "Invalid Wikipedia collection configuration.",
            ));
        }
        Ok(())
    }
}

/// Application-owned refresh and stale-service policy. Adapters supply HTTP
/// freshness evidence; neither demand nor an event may override its floor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RefreshProfile {
    pub debounce_secs: u64,
    pub minimum_secs: u64,
    pub fallback_secs: u64,
    pub stale_grace_secs: i64,
}
impl WikipediaConfig {
    pub fn profile(&self, current: Option<bool>) -> RefreshProfile {
        if current == Some(false) {
            RefreshProfile {
                debounce_secs: self.normal_debounce_secs,
                minimum_secs: self.normal_min_refresh_secs,
                fallback_secs: self.normal_fallback_secs,
                stale_grace_secs: 86400,
            }
        } else {
            RefreshProfile {
                debounce_secs: self.current_debounce_secs,
                minimum_secs: self.current_min_refresh_secs,
                fallback_secs: self.current_fallback_secs,
                stale_grace_secs: 900,
            }
        }
    }
}
impl RefreshProfile {
    pub fn endpoint_not_before(self, last_validation: i64, upstream_fresh_until: i64) -> i64 {
        upstream_fresh_until.max(last_validation.saturating_add(self.minimum_secs as i64))
    }
    pub fn permits_current_read(
        self,
        now: i64,
        expires_at: i64,
        upstream_allows_stale: bool,
    ) -> bool {
        now < expires_at
            || upstream_allows_stale && now <= expires_at.saturating_add(self.stale_grace_secs)
    }
}
#[cfg(test)]
mod freshness_policy_tests {
    use super::*;
    #[test]
    fn profiles_preserve_upstream_floor_and_fail_closed_for_unknown_current() {
        let config = WikipediaConfig::default();
        let normal = config.profile(Some(false));
        let current = config.profile(Some(true));
        assert_eq!(config.profile(None), current);
        assert_eq!(current.endpoint_not_before(100, 10_000), 10_000);
        assert_eq!(normal.endpoint_not_before(100, 101), 400);
        assert!(normal.permits_current_read(1000 + 86400, 1000, true));
        assert!(!normal.permits_current_read(1001 + 86400, 1000, true));
        assert!(!current.permits_current_read(1000 + 901, 1000, true));
        assert!(!normal.permits_current_read(1000, 1000, false));
        assert!(normal.permits_current_read(999, 1000, false));
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Row {
    pub sequence: i64,
    pub key: String,
    pub data: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Write {
    pub kind: String,
    pub key: String,
    pub data: Value,
}

/// Mutable private scheduling or visibility state. Null is a retained tombstone.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub key: String,
    pub data: Value,
    pub due_at: Option<i64>,
}

/// The writer commits work, moderation state and its stream checkpoint together.
/// Immutable evidence is append-only; readers have no publication authority.
#[async_trait]
pub trait WikipediaStore: Send + Sync {
    async fn wiki_get(&self, kind: &str, key: &str) -> Result<Option<Row>>;
    async fn wiki_rows(
        &self,
        kind: &str,
        after: i64,
        limit: usize,
        cutoff: Option<i64>,
    ) -> Result<Vec<Row>>;
    async fn wiki_cutoff(&self) -> Result<i64>;
    async fn wiki_catalog(&self, after_page_id: u64, limit: usize, cutoff: i64)
    -> Result<Vec<Row>>;
    async fn wiki_page_captures(
        &self,
        page_id: u64,
        after: i64,
        limit: usize,
        cutoff: i64,
    ) -> Result<Vec<Row>>;
    async fn wiki_state(&self, key: &str) -> Result<Option<Value>>;
    async fn wiki_states(&self, prefix: &str, after: &str, limit: usize) -> Result<Vec<State>>;
    async fn wiki_due(&self, prefix: &str, now: i64, limit: usize) -> Result<Vec<State>>;
    async fn wiki_commit(&self, rows: &[Write], states: &[State]) -> Result<()>;
}

/// Bound serialization before constructing SQL bindings or entering a transaction.
pub fn validate_writes(rows: &[Write], states: &[State]) -> Result<()> {
    use std::io;
    struct Counter(usize);
    impl io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .filter(|size| *size <= WRITE_BYTES)
                .ok_or_else(|| io::Error::other("Wikipedia write bound"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    if rows.len().saturating_add(states.len()) > WRITE_ROWS {
        return Err(Error::capacity(
            "Wikipedia transaction exceeds its row bound.",
        ));
    }
    serde_json::to_writer(&mut Counter(0), &(rows, states))
        .map_err(|_| Error::capacity("Wikipedia transaction exceeds its byte bound."))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn defaults_enable_bounded_recursive_collection() {
        let config = WikipediaConfig::default();
        assert!(config.enabled);
        assert_eq!(config.category_roots.len(), 6);
        assert!(config.validate().is_ok());
        for rate in [0, 4, 200] {
            let mut invalid = config.clone();
            invalid.requests_per_second = rate;
            assert!(invalid.validate().is_err());
        }
        let mut invalid = config;
        invalid.category_roots = vec!["Category:".into()];
        assert!(invalid.validate().is_err());
    }
    #[test]
    fn transaction_bound_applies_to_state_and_evidence_together() {
        let state = State {
            key: "stream".into(),
            data: Value::Null,
            due_at: None,
        };
        assert!(validate_writes(&[], &vec![state.clone(); WRITE_ROWS]).is_ok());
        assert!(validate_writes(&[], &vec![state; WRITE_ROWS + 1]).is_err());
        assert!(
            validate_writes(
                &[Write {
                    kind: "capture".into(),
                    key: "x".into(),
                    data: Value::String("x".repeat(WRITE_BYTES))
                }],
                &[]
            )
            .is_err()
        );
    }
}
