//! Private source acquisition contracts. No URLs, caller inventories, or generic tools.
use async_trait::async_trait;
use devres_domain::{Capture, Result, attribution::AttributionTarget};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Acquisition {
    RfcCatalogue,
    RfcErrata,
    RfcRepresentation {
        number: u32,
        format: String,
    },
    CrateSearch {
        query: String,
        page: usize,
    },
    CrateIndex {
        name: String,
    },
    CrateArchive {
        name: String,
        version: String,
        metadata_capture: String,
    },
    NpmSearch {
        query: String,
        offset: usize,
    },
    NpmMetadata {
        name: String,
        version: String,
        source_identity: bool,
    },
    NpmArchive {
        name: String,
        version: String,
        metadata_capture: String,
    },
    RustsecHead {
        force: bool,
    },
    RustsecBundle {
        revision: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum WriterEffect {
    RfcCatalogue,
    RfcErrata,
    RfcRefreshPartial,
    RfcForeground {
        number: u32,
        format: String,
        capture: String,
    },
    AttributionEnqueue {
        target: AttributionTarget,
    },
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceStatus {
    Rfc,
    Crates,
}

#[async_trait]
pub trait AcquisitionDelegate: Send + Sync {
    async fn wikipedia_request(&self, _title: Option<String>, _page_id: Option<u64>) -> Result<()> {
        Err(devres_domain::Error::unavailable(
            "Wikipedia acquisition is unavailable.",
        ))
    }
    async fn wikipedia_search(&self, _query: String, _limit: usize) -> Result<serde_json::Value> {
        Err(devres_domain::Error::unavailable(
            "Wikipedia discovery is unavailable.",
        ))
    }

    async fn acquire(&self, operation: Acquisition) -> Result<Capture>;
    async fn effect(&self, operation: WriterEffect) -> Result<()>;
    async fn source_status(&self, _source: SourceStatus) -> Result<serde_json::Value> {
        Err(devres_domain::Error::unavailable(
            "Source operational state is unavailable.",
        ))
    }
    /// Public aggregate writer state only; no request or audit payload crosses this port.
    async fn attribution_status(&self) -> Result<serde_json::Value> {
        Err(devres_domain::Error::unavailable(
            "Attribution operational state is unavailable.",
        ))
    }
    /// Return the exact immutable snapshot committed by this publication.
    async fn rfc_snapshot(&self) -> Result<String> {
        Err(devres_domain::Error::unavailable(
            "RFC snapshot publication is unavailable.",
        ))
    }
}
