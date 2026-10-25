//! MDN public evidence, immutable inventories, and collection policy.
use async_trait::async_trait;
use devres_domain::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const PROCESSOR_VERSION: u32 = 3;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct MdnConfig {
    pub enabled: bool,
    pub ref_refresh_secs: u64,
    pub collection_interval_secs: u64,
    pub publication_interval_secs: u64,
    pub max_processing_workers: usize,
    pub max_git_bytes: u64,
    pub min_free_bytes: u64,
    pub max_archive_storage_bytes: Option<u64>,
}
impl Default for MdnConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ref_refresh_secs: 3600,
            collection_interval_secs: 1,
            publication_interval_secs: 300,
            max_processing_workers: 1,
            max_git_bytes: 8 * 1024 * 1024 * 1024,
            min_free_bytes: 1024 * 1024 * 1024,
            max_archive_storage_bytes: None,
        }
    }
}
impl MdnConfig {
    pub fn validate(&self) -> Result<()> {
        if [
            self.ref_refresh_secs,
            self.collection_interval_secs,
            self.publication_interval_secs,
        ]
        .iter()
        .any(|s| !(1..=31_622_400).contains(s))
            || !(1..=2).contains(&self.max_processing_workers)
            || !(1024 * 1024..=128 * 1024 * 1024 * 1024).contains(&self.max_git_bytes)
            || self.min_free_bytes < 64 * 1024 * 1024
            || self
                .max_archive_storage_bytes
                .is_some_and(|q| q < self.min_free_bytes)
        {
            return Err(Error::invalid("Invalid MDN collection limits."));
        }
        Ok(())
    }
}

/// Small public evidence row; sequence freezes discovery and cursor cutoffs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MdnRow {
    pub sequence: i64,
    pub key: String,
    pub data: Value,
}

pub const MDN_WRITE_BATCH_ROWS: usize = 1000;
pub const MDN_WRITE_BATCH_BYTES: usize = 16 * 1024 * 1024;

/// Bounded immutable public evidence prepared before its publication pointer moves.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MdnWrite {
    pub kind: String,
    pub key: String,
    pub data: Value,
}

/// Count the actual serialized envelopes without allocating another batch body.
pub fn validate_mdn_writes(rows: &[MdnWrite]) -> Result<()> {
    use std::io::{self, Write};
    if rows.len() > MDN_WRITE_BATCH_ROWS {
        return Err(Error::capacity(
            "MDN immutable write batch exceeds its row bound.",
        ));
    }
    struct Counter(usize);
    impl Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .filter(|n| *n <= MDN_WRITE_BATCH_BYTES)
                .ok_or_else(|| io::Error::other("MDN write batch size"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    for row in rows {
        serde_json::to_writer(&mut counter, row)
            .map_err(|_| Error::capacity("MDN immutable write batch exceeds its byte bound."))?;
    }
    Ok(())
}

/// Content-addressed directory. Unchanged subtrees are shared across commits.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct InventoryNode {
    pub children: BTreeMap<String, String>,
    /// Hash-radix directory partitions keep wide Git directories structurally shared.
    #[serde(default)]
    pub buckets: BTreeMap<String, String>,
    pub member: Option<Member>,
    pub members: u64,
    pub searchable: u64,
    pub gaps: u64,
    #[serde(default)]
    pub kinds: BTreeMap<String, u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Member {
    pub path: String,
    pub oid: String,
    pub mode: String,
    pub kind: String,
    pub projection: Option<String>,
    pub raw: Option<Value>,
    pub gaps: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Snapshot {
    pub id: String,
    pub repository: String,
    pub revision: String,
    pub tree: String,
    pub parents: Vec<String>,
    pub committed_at: i64,
    pub inventory: String,
    pub processor_version: u32,
    pub index: Value,
    pub coverage: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct View {
    pub id: String,
    pub content: String,
    pub compatibility: String,
    pub content_observation: String,
    pub compatibility_observation: String,
    pub validated_at: i64,
}

/// Public source evidence only. Immutable rows reject replacement; state is private.
#[async_trait]
pub trait MdnStore: Send + Sync {
    async fn mdn_cutoff(&self) -> Result<i64>;
    async fn mdn_get(&self, kind: &str, key: &str) -> Result<Option<MdnRow>>;
    async fn mdn_get_many(&self, kind: &str, keys: &[String]) -> Result<Vec<MdnRow>> {
        let mut rows = Vec::new();
        for key in keys {
            if let Some(row) = self.mdn_get(kind, key).await? {
                rows.push(row);
            }
        }
        Ok(rows)
    }
    async fn mdn_put(&self, kind: &str, key: &str, data: &Value) -> Result<i64>;
    /// Production stores commit this group in one owner-fenced transaction.
    /// The fallback may leave replayable unreferenced evidence on failure; callers
    /// publish a root/default pointer only after the entire group succeeds.
    async fn mdn_put_many(&self, rows: &[MdnWrite]) -> Result<()> {
        validate_mdn_writes(rows)?;
        for row in rows {
            self.mdn_put(&row.kind, &row.key, &row.data).await?;
        }
        Ok(())
    }
    async fn mdn_rows(
        &self,
        kind: &str,
        after: i64,
        limit: usize,
        cutoff: Option<i64>,
    ) -> Result<Vec<MdnRow>>;
    async fn mdn_state(&self, key: &str) -> Result<Option<Value>>;
    async fn mdn_set_state(&self, key: &str, data: &Value) -> Result<()>;
    /// Atomically publish a verified immutable pair and move the default pointer.
    async fn mdn_publish_view(&self, view: &View) -> Result<()>;
}
