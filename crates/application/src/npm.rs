//! Public npm evidence and owner-fenced publication ports. Caller lockfiles never enter these ports.
use async_trait::async_trait;
use devres_domain::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const PROCESSOR_VERSION: u32 = 1;
pub const MAX_PACKAGES: usize = 10_000;
pub const MAX_ROW_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct NpmConfig {
    pub enabled: bool,
    pub packages: Vec<String>,
    pub advisories_enabled: bool,
    pub metadata_refresh_secs: u64,
    pub advisory_refresh_secs: u64,
    pub collection_interval_secs: u64,
    pub publication_interval_secs: u64,
    pub max_processing_workers: usize,
    pub registry_requests_per_second: u32,
    pub advisory_requests_per_second: u32,
    pub min_free_bytes: u64,
    pub max_archive_storage_bytes: Option<u64>,
}
impl Default for NpmConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            packages: Vec::new(),
            advisories_enabled: true,
            metadata_refresh_secs: 3600,
            advisory_refresh_secs: 3600,
            collection_interval_secs: 1,
            publication_interval_secs: 300,
            max_processing_workers: 1,
            registry_requests_per_second: 1,
            advisory_requests_per_second: 1,
            min_free_bytes: 1024 * 1024 * 1024,
            max_archive_storage_bytes: None,
        }
    }
}
impl NpmConfig {
    pub fn validate(&self) -> Result<()> {
        let mut names = std::collections::BTreeSet::new();
        if self.packages.len() > MAX_PACKAGES
            || self
                .packages
                .iter()
                .any(|name| !valid_name(name) || !names.insert(name))
            || [
                self.metadata_refresh_secs,
                self.advisory_refresh_secs,
                self.collection_interval_secs,
                self.publication_interval_secs,
            ]
            .iter()
            .any(|v| !(1..=31_622_400).contains(v))
            || !(1..=2).contains(&self.max_processing_workers)
            || !(1..=1000).contains(&self.registry_requests_per_second)
            || !(1..=1000).contains(&self.advisory_requests_per_second)
            || self.min_free_bytes < 64 * 1024 * 1024
            || self
                .max_archive_storage_bytes
                .is_some_and(|v| v < self.min_free_bytes)
        {
            return Err(Error::invalid("Invalid npm collection configuration."));
        }
        Ok(())
    }
}

fn valid_name(name: &str) -> bool {
    let part = |value: &str| {
        !value.is_empty()
            && !value.starts_with(['.', '_'])
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b))
    };
    if name.len() > 214 {
        return false;
    }
    if let Some(scoped) = name.strip_prefix('@') {
        scoped
            .split_once('/')
            .is_some_and(|(scope, package)| part(scope) && part(package) && !package.contains('/'))
    } else {
        part(name)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Row {
    pub sequence: i64,
    pub key: String,
    pub data: Value,
}

/// Only public upstream evidence and private operator scheduling state are admitted.
#[async_trait]
pub trait NpmStore: Send + Sync {
    /// Complete retained rows for private integrity verification, including aliases.
    async fn npm_migration_rows(
        &self,
        _kind: &str,
        _after: i64,
        _limit: usize,
    ) -> Result<Vec<Row>> {
        Err(devres_domain::Error::unavailable(
            "Migration verification unavailable.",
        ))
    }

    /// Private offline migration inventory; never exposed through MCP.
    async fn npm_migration_kinds(&self) -> Result<Vec<String>> {
        Err(devres_domain::Error::unavailable(
            "Migration enumeration unavailable.",
        ))
    }
    async fn npm_migration_state_keys(&self, _after: &str, _limit: usize) -> Result<Vec<String>> {
        Err(devres_domain::Error::unavailable(
            "Migration enumeration unavailable.",
        ))
    }

    async fn npm_get(&self, kind: &str, key: &str) -> Result<Option<Row>>;
    async fn npm_put(&self, kind: &str, key: &str, data: &Value) -> Result<i64>;
    async fn npm_cutoff(&self) -> Result<i64>;
    /// JSON containment is a bounded public-evidence selection; never persists query input.
    async fn npm_rows(
        &self,
        kind: &str,
        after: i64,
        limit: usize,
        cutoff: Option<i64>,
        filter: Option<&Value>,
    ) -> Result<Vec<Row>>;
    async fn npm_state(&self, key: &str) -> Result<Option<Value>>;
    async fn npm_set_state(&self, key: &str, data: &Value) -> Result<()>;
    /// Publish a bounded index batch and every deduplication marker in one owner transaction.
    async fn npm_commit_index(&self, index: &Value, ids: &[String]) -> Result<()>;
    /// Activate a fully staged rebuild with server-side membership accounting.
    async fn npm_commit_rebuilt_index(&self, index: &Value, build: &str) -> Result<()>;
    /// Atomically inserts an immutable snapshot and changes its validated default.
    async fn npm_publish(&self, lane: &str, snapshot: &Value) -> Result<()>;
    async fn npm_statistics(&self) -> Result<Value>;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn defaults_have_no_package_catalog_and_keep_advisories_independent() {
        let config = NpmConfig::default();
        assert!(config.packages.is_empty() && config.enabled && config.advisories_enabled);
        config.validate().unwrap();
        let mut bad = config.clone();
        bad.packages = vec!["same".into(), "same".into()];
        assert!(bad.validate().is_err());
        let mut bad = config;
        bad.max_archive_storage_bytes = Some(1);
        assert!(bad.validate().is_err());
    }
}
