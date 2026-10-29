//! Public Chromium evidence contracts and bounded collection policy.
use async_trait::async_trait;
use devres_domain::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const PROCESSOR_VERSION: u32 = 1;
pub const CHROMIUM_WRITE_BATCH_ROWS: usize = 1000;
pub const CHROMIUM_WRITE_BATCH_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ChromiumConfig {
    pub enabled: bool,
    pub catalog_refresh_secs: u64,
    pub ref_refresh_secs: u64,
    pub publication_refresh_secs: u64,
    pub collection_interval_secs: u64,
    pub publication_interval_secs: u64,
    pub max_processing_workers: usize,
    pub min_free_bytes: u64,
    pub max_archive_storage_bytes: Option<u64>,
}
impl Default for ChromiumConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            catalog_refresh_secs: 3600,
            ref_refresh_secs: 3600,
            publication_refresh_secs: 86400,
            collection_interval_secs: 1,
            publication_interval_secs: 300,
            max_processing_workers: 1,
            min_free_bytes: 1024 * 1024 * 1024,
            max_archive_storage_bytes: None,
        }
    }
}
impl ChromiumConfig {
    pub fn validate(&self) -> Result<()> {
        if [
            self.catalog_refresh_secs,
            self.ref_refresh_secs,
            self.publication_refresh_secs,
            self.collection_interval_secs,
            self.publication_interval_secs,
        ]
        .iter()
        .any(|v| !(1..=31_622_400).contains(v))
            || !(1..=2).contains(&self.max_processing_workers)
            || self.min_free_bytes < 64 * 1024 * 1024
            || self
                .max_archive_storage_bytes
                .is_some_and(|v| v < self.min_free_bytes)
        {
            return Err(Error::invalid("Invalid Chromium collection limits."));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Component {
    pub id: String,
    pub title: String,
    pub url: String,
    pub repository: String,
    pub metadata: Value,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Catalog {
    pub id: String,
    pub observed_at: i64,
    pub components: Vec<Component>,
    pub gaps: Vec<Value>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Row {
    pub sequence: i64,
    pub key: String,
    pub data: Value,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Write {
    pub kind: String,
    pub key: String,
    pub data: Value,
}

pub fn validate_chromium_writes(rows: &[Write]) -> Result<()> {
    use std::io;
    struct Counter(usize);
    impl io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .filter(|v| *v <= CHROMIUM_WRITE_BATCH_BYTES)
                .ok_or_else(|| io::Error::other("Chromium write batch size"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    if rows.len() > CHROMIUM_WRITE_BATCH_ROWS {
        return Err(Error::capacity(
            "Chromium immutable write batch exceeds its row bound.",
        ));
    }
    let mut counter = Counter(0);
    for row in rows {
        serde_json::to_writer(&mut counter, row).map_err(|_| {
            Error::capacity("Chromium immutable write batch exceeds its byte bound.")
        })?;
    }
    Ok(())
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct InventoryNode {
    pub children: BTreeMap<String, String>,
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
    pub component: String,
    pub repository: String,
    pub revision: String,
    pub tree: String,
    pub parents: Vec<String>,
    pub committed_at: i64,
    pub inventory: String,
    pub processor_version: u32,
    pub index: Value,
    pub coverage: Value,
    pub source_url: String,
    pub representation: String,
    pub validated_at: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct View {
    pub id: String,
    pub catalog: String,
    pub snapshots: BTreeMap<String, String>,
    pub index: Value,
    pub validations: BTreeMap<String, i64>,
    pub validated_at: i64,
}

#[async_trait]
pub trait ChromiumStore: Send + Sync {
    /// Complete retained rows for private integrity verification, including aliases.
    async fn chromium_migration_rows(
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
    async fn chromium_migration_kinds(&self) -> Result<Vec<String>> {
        Err(devres_domain::Error::unavailable(
            "Migration enumeration unavailable.",
        ))
    }
    async fn chromium_migration_state_keys(
        &self,
        _after: &str,
        _limit: usize,
    ) -> Result<Vec<String>> {
        Err(devres_domain::Error::unavailable(
            "Migration enumeration unavailable.",
        ))
    }

    async fn chromium_existing(
        &self,
        kind: &str,
        keys: &[String],
    ) -> Result<std::collections::BTreeSet<String>> {
        Ok(self
            .chromium_get_many(kind, keys)
            .await?
            .into_iter()
            .map(|row| row.key)
            .collect())
    }
    /// Small aggregate counters. Production stores maintain these with immutable inserts.
    async fn chromium_statistics(&self) -> Result<Value> {
        let mut snapshots = 0_u64;
        let mut publications = 0_u64;
        let mut gaps = 0_u64;
        let mut index_gaps = 0_u64;
        for kind in ["snapshots", "publications"] {
            let mut after = 0;
            loop {
                let rows = self.chromium_rows(kind, after, 1000, None).await?;
                if rows.is_empty() {
                    break;
                }
                for row in rows {
                    after = row.sequence;
                    if kind == "snapshots" {
                        snapshots += 1;
                        gaps += row.data["coverage"]["projection_gaps"]
                            .as_u64()
                            .unwrap_or(0);
                        index_gaps += row.data["coverage"]["index_gaps"].as_u64().unwrap_or(0);
                    } else {
                        publications += 1;
                    }
                }
            }
        }
        Ok(
            serde_json::json!({"snapshots":snapshots,"publications":publications,"projection_gaps":gaps,"index_gaps":index_gaps}),
        )
    }
    async fn chromium_cutoff(&self) -> Result<i64>;
    async fn chromium_get(&self, kind: &str, key: &str) -> Result<Option<Row>>;
    async fn chromium_get_many(&self, kind: &str, keys: &[String]) -> Result<Vec<Row>> {
        if keys.len() > CHROMIUM_WRITE_BATCH_ROWS {
            return Err(Error::capacity("Chromium batch read exceeds its bound."));
        }
        let mut result = Vec::new();
        for key in keys {
            if let Some(row) = self.chromium_get(kind, key).await? {
                result.push(row);
            }
        }
        Ok(result)
    }
    async fn chromium_put(&self, kind: &str, key: &str, data: &Value) -> Result<i64>;
    async fn chromium_put_many(&self, rows: &[Write]) -> Result<()> {
        validate_chromium_writes(rows)?;
        for row in rows {
            self.chromium_put(&row.kind, &row.key, &row.data).await?;
        }
        Ok(())
    }
    async fn chromium_rows(
        &self,
        kind: &str,
        after: i64,
        limit: usize,
        cutoff: Option<i64>,
    ) -> Result<Vec<Row>>;
    async fn chromium_state(&self, key: &str) -> Result<Option<Value>>;
    async fn chromium_set_state(&self, key: &str, data: &Value) -> Result<()>;
    async fn chromium_publish_view(&self, view: &View) -> Result<()>;
}
