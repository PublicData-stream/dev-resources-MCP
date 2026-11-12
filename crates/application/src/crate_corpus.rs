//! Paged, owner-fenced crate corpus contracts. No caller audit data enters these ports.
use async_trait::async_trait;
use devres_domain::{Capture, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Inventory {
    pub id: String,
    pub sequence: i64,
    pub revision: String,
    pub created_at: i64,
    pub validated_at: i64,
    pub cursor: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VersionRecord {
    pub name: String,
    pub version: String,
    pub metadata_capture: String,
    pub record: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_status: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Artifact {
    pub capture: Capture,
    pub bytes: u64,
    pub provenance: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CollectionJob {
    pub key: String,
    pub kind: String,
    pub name: String,
    pub version: String,
    pub target: String,
    pub checksum: String,
    pub metadata_capture: String,
    pub attempts: u32,
    pub artifact: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContentRecord {
    pub id: String,
    pub name: String,
    pub version: String,
    pub target: String,
    pub path: String,
    pub kind: String,
    pub capture: String,
    pub metadata_capture: String,
    pub archive_capture: String,
    pub attributes: Value,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ContentFilter {
    pub name: Option<String>,
    pub version: Option<String>,
    pub target: Option<String>,
    pub path: Option<String>,
    pub kind: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ContentDeltaQuery {
    pub cutoff: i64,
    pub name: String,
    pub from_version: String,
    pub to_version: String,
    pub target: Option<String>,
    pub kind: String,
    pub after: Option<String>,
    pub limit: usize,
}

/// Private immutable processor selection; public citations continue naming the raw capture.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrichmentSelection {
    pub capture: String,
    pub derivation: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Snapshot {
    pub id: String,
    pub inventory: Inventory,
    pub content_sequence: i64,
    pub enrichment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrichment_derivation: Option<String>,
    pub index_manifest: Value,
    pub coverage: Value,
    pub created_at: i64,
}

impl Snapshot {
    pub fn enrichment_selection(&self) -> Option<EnrichmentSelection> {
        self.enrichment.as_ref().map(|capture| EnrichmentSelection {
            capture: capture.clone(),
            derivation: self.enrichment_derivation.clone(),
        })
    }

    /// Preserve the public status shape while persisting the private processor binding.
    pub fn public_value(&self) -> Result<Value> {
        let mut value = serde_json::to_value(self)
            .map_err(|_| devres_domain::Error::integrity("Invalid snapshot serialization."))?;
        if let Some(object) = value.as_object_mut() {
            object.remove("enrichment_derivation");
        }
        Ok(value)
    }
}

/// All batches are bounded. Expensive I/O and source parsing happen outside transactions.
#[async_trait]
pub trait CrateCorpusStore: Send + Sync {
    async fn begin_inventory(&self, revision: &str, now: i64) -> Result<Inventory>;
    async fn pending_inventory(&self) -> Result<Option<Inventory>>;
    async fn latest_inventory(&self) -> Result<Option<Inventory>>;
    async fn stage_crate(
        &self,
        inventory: &str,
        name: &str,
        versions: &[VersionRecord],
        cursor: &str,
    ) -> Result<()>;
    async fn commit_inventory(&self, inventory: &str, manifest: &str) -> Result<Inventory>;
    async fn versions(
        &self,
        inventory: &str,
        name: Option<&str>,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<VersionRecord>>;
    async fn version(
        &self,
        _inventory: &str,
        _name: &str,
        _version: &str,
    ) -> Result<Option<VersionRecord>> {
        Err(devres_domain::Error::unavailable(
            "Exact corpus version lookup is unavailable.",
        ))
    }
    async fn save_artifact(&self, artifact: &Artifact, http: bool) -> Result<()>;
    async fn artifact(&self, id: &str) -> Result<Option<Artifact>>;
    async fn latest_artifact(&self, key: &str) -> Result<Option<Artifact>>;
    async fn import_metadata(
        &self,
        name: &str,
        revision: &str,
        path: &str,
        oid: &str,
        body: &[u8],
        now: i64,
    ) -> Result<Capture>;
    async fn save_text(
        &self,
        key: &str,
        source_url: &str,
        text: &str,
        provenance: Value,
        now: i64,
    ) -> Result<Capture>;
    async fn schedule(&self, jobs: &[CollectionJob], due_at: i64) -> Result<()>;
    /// Requeue interrupted claims before starting the sole collector group, under its owner fence.
    /// Callers must first cancel and fully drain their previous group. Retry evidence is retained.
    async fn recover_interrupted_jobs(&self) -> Result<()>;
    async fn claim(&self, now: i64, kind: &str) -> Result<Option<CollectionJob>>;
    async fn finish(
        &self,
        key: &str,
        artifact: Option<&str>,
        error: Option<&str>,
        next_due: i64,
    ) -> Result<()>;
    async fn stage_content(&self, generation: &str, records: &[ContentRecord]) -> Result<()>;
    async fn commit_content(&self, generation: &str, summary: Value) -> Result<()>;
    async fn contents(
        &self,
        cutoff: i64,
        filter: &ContentFilter,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ContentRecord>>;
    async fn content_deltas(&self, _query: &ContentDeltaQuery) -> Result<Vec<Value>> {
        Err(devres_domain::Error::unavailable(
            "Corpus comparison is unavailable.",
        ))
    }
    async fn projection_status(
        &self,
        _cutoff: i64,
        _name: &str,
        _version: &str,
        _kind: &str,
        _target: Option<&str>,
    ) -> Result<Vec<Value>> {
        Err(devres_domain::Error::unavailable(
            "Corpus processing coverage is unavailable.",
        ))
    }
    async fn put_enrichment(
        &self,
        artifact: &str,
        kind: &str,
        rows: &[(String, Value)],
    ) -> Result<()>;
    async fn commit_enrichment(&self, artifact: &str) -> Result<()>;
    async fn enrichment(&self, artifact: Option<&str>, name: &str, version: &str) -> Result<Value>;
    /// Private closed parser metadata only; adapters validate its versioned representation.
    async fn record_dump_failure(&self, _artifact: &str, _diagnostic: &Value) -> Result<()> {
        Ok(())
    }
    async fn put_selected_enrichment(
        &self,
        selection: &EnrichmentSelection,
        kind: &str,
        rows: &[(String, Value)],
    ) -> Result<()> {
        if selection.derivation.is_some() {
            return Err(devres_domain::Error::unavailable(
                "Versioned enrichment storage is unavailable.",
            ));
        }
        self.put_enrichment(&selection.capture, kind, rows).await
    }
    async fn commit_selected_enrichment(
        &self,
        selection: &EnrichmentSelection,
        _summary: &Value,
    ) -> Result<()> {
        if selection.derivation.is_some() {
            return Err(devres_domain::Error::unavailable(
                "Versioned enrichment storage is unavailable.",
            ));
        }
        self.commit_enrichment(&selection.capture).await
    }
    async fn commit_selected_enrichment_with_cancel(
        &self,
        selection: &EnrichmentSelection,
        summary: &Value,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<()> {
        tokio::select! { biased;
            _ = cancel.cancelled() => Err(devres_domain::Error::new("cancelled", "Enrichment publication canceled.")),
            result = self.commit_selected_enrichment(selection, summary) => result,
        }
    }
    async fn selected_enrichment(
        &self,
        selection: Option<&EnrichmentSelection>,
        name: &str,
        version: &str,
    ) -> Result<Value> {
        if selection.is_some_and(|selection| selection.derivation.is_some()) {
            return Err(devres_domain::Error::unavailable(
                "Versioned enrichment storage is unavailable.",
            ));
        }
        self.enrichment(
            selection.map(|selection| selection.capture.as_str()),
            name,
            version,
        )
        .await
    }
    async fn publish_snapshot(
        &self,
        inventory: &str,
        index_manifest: Value,
        now: i64,
    ) -> Result<Snapshot>;
    async fn prepare_snapshot(&self, _inventory: &str, _now: i64) -> Result<Snapshot> {
        Err(devres_domain::Error::unavailable(
            "Snapshot preparation is unavailable.",
        ))
    }
    async fn commit_snapshot(&self, _snapshot: Snapshot) -> Result<Snapshot> {
        Err(devres_domain::Error::unavailable(
            "Snapshot publication is unavailable.",
        ))
    }
    async fn stage_gap(
        &self,
        _inventory: &str,
        _name: &str,
        _error: &str,
        _cursor: &str,
    ) -> Result<()> {
        Err(devres_domain::Error::unavailable(
            "Inventory gap tracking is unavailable.",
        ))
    }
    async fn snapshot(&self, id: Option<&str>) -> Result<Option<Snapshot>>;
    async fn status(&self) -> Result<Value>;
}
