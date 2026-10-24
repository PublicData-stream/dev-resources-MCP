//! Public advisory evidence and policy. Caller lockfiles never enter these ports.
use async_trait::async_trait;
use devres_domain::{Capture, Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdvisoryRecord {
    pub id: String,
    pub package: String,
    pub format: String,
    pub path: String,
    pub body: String,
    pub body_hash: String,
    pub metadata: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdvisorySnapshot {
    pub id: String,
    pub revision: String,
    pub format: String,
    pub created_at: i64,
    pub validated_at: Option<i64>,
    pub historical: bool,
    pub complete: bool,
    pub records: Vec<AdvisoryRecord>,
    pub captures: Vec<Capture>,
    pub coverage: Value,
    pub parents: Vec<String>,
    pub committed_at: i64,
}

impl AdvisorySnapshot {
    pub fn assessment_complete(&self, now: i64) -> bool {
        self.complete
            && !self.historical
            && self
                .validated_at
                .is_some_and(|time| time <= now && now.saturating_sub(time) <= 7 * 86400)
    }
    pub fn stale(&self, now: i64) -> bool {
        self.validated_at
            .is_none_or(|time| time > now || now.saturating_sub(time) > 86400)
    }
}

/// Sequence-bound public rows for ref observations and commit discovery.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdvisoryRow {
    pub sequence: i64,
    pub key: String,
    pub data: Value,
}

/// Every method accepts public-source evidence only. Writes are owner-fenced.
#[async_trait]
pub trait AdvisoryStore: Send + Sync {
    async fn publish_advisory_snapshot(
        &self,
        snapshot: &AdvisorySnapshot,
        make_default: bool,
    ) -> Result<()>;
    async fn advisory_snapshot(
        &self,
        id: Option<&str>,
        format: &str,
    ) -> Result<Option<AdvisorySnapshot>>;
    async fn advisory_rows(
        &self,
        kind: &str,
        cutoff: Option<i64>,
        after: i64,
        limit: usize,
    ) -> Result<Vec<AdvisoryRow>>;
    async fn advisory_row(&self, kind: &str, key: &str) -> Result<Option<AdvisoryRow>>;
    async fn advisory_rows_by_keys(&self, kind: &str, keys: &[String]) -> Result<Vec<AdvisoryRow>> {
        if keys.len() > 16 {
            return Err(Error::invalid("Advisory cache batch exceeds 16 records."));
        }
        let mut rows = Vec::new();
        for key in keys {
            if let Some(row) = self.advisory_row(kind, key).await? {
                rows.push(row);
            }
        }
        Ok(rows)
    }
    async fn advisory_cutoff(&self) -> Result<i64>;
    async fn advisory_ref_rows(
        &self,
        ref_name: &str,
        cutoff: i64,
        after: i64,
        limit: usize,
    ) -> Result<Vec<AdvisoryRow>>;
    async fn put_advisory_row(&self, kind: &str, key: &str, data: &Value) -> Result<()>;
    async fn advisory_state(&self, key: &str) -> Result<Option<Value>>;
    async fn set_advisory_state(&self, key: &str, data: &Value) -> Result<()>;
    async fn advisory_status(&self) -> Result<Value>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RustSecConfig {
    pub enabled: bool,
    pub current_refresh_secs: u64,
    pub history_refresh_secs: u64,
    pub collection_interval_secs: u64,
    pub max_git_bytes: u64,
    pub min_free_bytes: u64,
    pub max_archive_storage_bytes: Option<u64>,
}
impl Default for RustSecConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            current_refresh_secs: 3600,
            history_refresh_secs: 86400,
            collection_interval_secs: 1,
            max_git_bytes: 8 * 1024 * 1024 * 1024,
            min_free_bytes: 1024 * 1024 * 1024,
            max_archive_storage_bytes: None,
        }
    }
}
impl RustSecConfig {
    pub fn validate(&self) -> Result<()> {
        if [
            self.current_refresh_secs,
            self.history_refresh_secs,
            self.collection_interval_secs,
        ]
        .into_iter()
        .any(|v| !(1..=31622400).contains(&v))
            || !(1024 * 1024..=128 * 1024 * 1024 * 1024).contains(&self.max_git_bytes)
            || self.min_free_bytes < 64 * 1024 * 1024
            || self
                .max_archive_storage_bytes
                .is_some_and(|v| v < self.min_free_bytes)
        {
            return Err(Error::invalid("Invalid RustSec collection limits."));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn freshness_boundaries_and_history_do_not_depend_on_import_time() {
        let mut snapshot = AdvisorySnapshot {
            id: "a".repeat(64),
            revision: "b".repeat(40),
            format: "rustsec".into(),
            created_at: 900_000,
            validated_at: Some(100),
            historical: false,
            complete: true,
            records: vec![],
            captures: vec![],
            coverage: Value::Null,
            parents: vec![],
            committed_at: 0,
        };
        assert!(!snapshot.stale(100 + 86400));
        assert!(snapshot.stale(101 + 86400));
        assert!(snapshot.assessment_complete(100 + 7 * 86400));
        assert!(!snapshot.assessment_complete(101 + 7 * 86400));
        assert!(!snapshot.assessment_complete(99));
        snapshot.historical = true;
        assert!(!snapshot.assessment_complete(100));
        snapshot.historical = false;
        snapshot.complete = false;
        assert!(!snapshot.assessment_complete(100));
    }
    #[test]
    fn collection_defaults_and_invalid_limits_are_explicit() {
        let mut config = RustSecConfig::default();
        assert!(config.enabled);
        assert_eq!(config.current_refresh_secs, 3600);
        assert_eq!(config.history_refresh_secs, 86400);
        config.validate().unwrap();
        config.current_refresh_secs = 0;
        assert!(config.validate().is_err());
    }
}
