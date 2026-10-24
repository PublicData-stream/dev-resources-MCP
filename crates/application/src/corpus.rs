//! Durable public RFC corpus contracts, independent of transport and persistence.
use async_trait::async_trait;
use devres_domain::{Capture, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Dataset {
    pub capture: Capture,
    pub records: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JobSpec {
    pub key: String,
    pub number: u32,
    pub format: String,
    pub source_url: String,
    pub assurance: String,
    pub due_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Job {
    pub spec: JobSpec,
    pub attempts: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Document {
    pub number: u32,
    pub format: String,
    pub capture: Capture,
    pub assurance: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Snapshot {
    pub id: String,
    pub catalogue_capture: String,
    pub errata_capture: Option<String>,
    pub documents: Vec<Document>,
    #[serde(default)]
    pub search_documents: Vec<Document>,
    pub coverage: Value,
    pub created_at: i64,
    pub complete: bool,
    pub index_path: Option<String>,
    pub processor_version: u32,
}

/// Mutations are short, fenced operations. Network and parsing never run inside them.
#[async_trait]
pub trait RfcCorpusStore: Send + Sync {
    async fn save_dataset(&self, kind: &str, dataset: &Dataset) -> Result<()>;
    async fn dataset(&self, kind: &str, capture: Option<&str>) -> Result<Option<Dataset>>;
    async fn schedule(&self, jobs: &[JobSpec]) -> Result<()>;
    async fn claim(&self, now: i64) -> Result<Option<Job>>;
    async fn finish(
        &self,
        key: &str,
        capture: Option<&Capture>,
        error: Option<&str>,
        next_due: i64,
    ) -> Result<()>;
    async fn documents(&self) -> Result<Vec<Document>>;
    async fn save_snapshot(&self, snapshot: &Snapshot) -> Result<()>;
    async fn snapshot(&self, id: Option<&str>) -> Result<Option<Snapshot>>;
    async fn status(&self) -> Result<Value>;
}
