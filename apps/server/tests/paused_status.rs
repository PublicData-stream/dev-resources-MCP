use async_trait::async_trait;
use devres_adapters::{
    Research,
    bulk::{BulkBroker, BulkConfig},
    npm::NpmCorpus,
};
use devres_application::acquisition::{Acquisition, AcquisitionDelegate, WriterEffect};
use devres_application::attribution::AttributionStore;
use devres_application::attribution_gate::AttributionGate;
use devres_application::attribution_runtime::{AttributionAcquirer, AttributionRuntime};
use devres_application::npm::{NpmConfig, NpmStore, Row};
use devres_application::{Cached, Fetcher, Retrieval, Store};
use devres_domain::attribution::*;
use devres_domain::{
    Capture, Error, FetchRequest, FetchResponse, Result, StoredCapture, Validators,
};
use devres_server::{
    config::{WriterAccess, WriterClientConfig},
    writer_rpc::WriterClient,
};
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio_util::sync::CancellationToken;

struct NeverRetrieve;
#[async_trait]
impl Store for NeverRetrieve {
    async fn latest(&self, _: &str) -> Result<Option<Cached>> {
        panic!("unexpected source retrieval")
    }
    async fn capture(&self, _: &str) -> Result<StoredCapture> {
        panic!("unexpected body read")
    }
    async fn publish(&self, _: &FetchRequest, _: FetchResponse, _: i64) -> Result<StoredCapture> {
        panic!("unexpected publication")
    }
    async fn revalidate(&self, _: &str, _: &str, _: Validators, _: i64) -> Result<StoredCapture> {
        panic!("unexpected revalidation")
    }
}
#[async_trait]
impl Fetcher for NeverRetrieve {
    async fn fetch(&self, _: &FetchRequest, _: Option<&Validators>) -> Result<FetchResponse> {
        panic!("unexpected provider request")
    }
}
#[derive(Default)]
struct NpmMemory {
    reads: Mutex<Vec<String>>,
    fail_statistics: bool,
}
#[async_trait]
impl NpmStore for NpmMemory {
    async fn npm_get(&self, _: &str, _: &str) -> Result<Option<Row>> {
        panic!("unexpected evidence lookup")
    }
    async fn npm_put(&self, _: &str, _: &str, _: &Value) -> Result<i64> {
        panic!("unexpected evidence write")
    }
    async fn npm_cutoff(&self) -> Result<i64> {
        panic!("unexpected cutoff")
    }
    async fn npm_rows(
        &self,
        _: &str,
        _: i64,
        _: usize,
        _: Option<i64>,
        _: Option<&Value>,
    ) -> Result<Vec<Row>> {
        panic!("unexpected evidence rows")
    }
    async fn npm_state(&self, key: &str) -> Result<Option<Value>> {
        self.reads.lock().unwrap().push(format!("state:{key}"));
        Ok(None)
    }
    async fn npm_statistics(&self) -> Result<Value> {
        self.reads.lock().unwrap().push("statistics".into());
        if self.fail_statistics {
            Err(Error::unavailable("fixed earlier storage failure"))
        } else {
            Ok(json!({"advisories":3}))
        }
    }
    async fn npm_set_state(&self, _: &str, _: &Value) -> Result<()> {
        panic!("unexpected state write")
    }
    async fn npm_commit_index(&self, _: &Value, _: &[String]) -> Result<()> {
        panic!("unexpected index write")
    }
    async fn npm_commit_rebuilt_index(&self, _: &Value, _: &str) -> Result<()> {
        panic!("unexpected rebuild")
    }
    async fn npm_publish(&self, _: &str, _: &Value) -> Result<()> {
        panic!("unexpected publication")
    }
}
#[derive(Default)]
struct AttributionMemory {
    status_reads: AtomicUsize,
}
#[async_trait]
impl AttributionStore for AttributionMemory {
    async fn attribution_enqueue(&self, _: &AttributionTarget, _: u8) -> Result<()> {
        panic!("unexpected repair enqueue")
    }
    async fn attribution_ready(
        &self,
        _: &AttributionSubject,
    ) -> Result<Option<QualifiedAttribution>> {
        panic!("unexpected qualification")
    }
    async fn attribution_claim(
        &self,
        _: &[String],
        _: i64,
        _: u64,
    ) -> Result<Option<AttributionJob>> {
        panic!("unexpected repair claim")
    }
    async fn attribution_complete(
        &self,
        _: &AttributionJob,
        _: &AttributionGeneration,
    ) -> Result<()> {
        panic!("unexpected repair write")
    }
    async fn attribution_fail(&self, _: &AttributionJob, _: Option<i64>, _: &str) -> Result<()> {
        panic!("unexpected failure write")
    }
    async fn attribution_sweep_page(&self, _: &str) -> Result<Vec<AttributionTarget>> {
        panic!("unexpected sweep")
    }
    async fn attribution_bundle(&self, _: &str) -> Result<QualifiedAttribution> {
        panic!("unexpected notice read")
    }
    async fn attribution_status(&self) -> Result<Value> {
        self.status_reads.fetch_add(1, Ordering::SeqCst);
        Ok(json!({"complete":true}))
    }
}
struct NeverAcquire;
#[async_trait]
impl AttributionAcquirer for NeverAcquire {
    fn targets(&self, _: &str, _: &Value) -> Result<Vec<AttributionTarget>> {
        panic!("unexpected target discovery")
    }
    async fn repair(
        &self,
        _: &AttributionTarget,
        _: CancellationToken,
    ) -> Result<AttributionGeneration> {
        panic!("unexpected repair/provider request")
    }
}
struct StatusDelegate {
    calls: AtomicUsize,
    fail: bool,
}
#[async_trait]
impl AcquisitionDelegate for StatusDelegate {
    async fn acquire(&self, _: Acquisition) -> Result<Capture> {
        panic!("unexpected source acquisition")
    }
    async fn effect(&self, _: WriterEffect) -> Result<()> {
        panic!("unexpected writer effect")
    }
    async fn attribution_status(&self) -> Result<Value> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            Err(Error::unavailable("fixed unavailable delegate"))
        } else {
            Ok(
                json!({"scan_gaps":{"npm":"capacity"},"complete":false,"repair_complete_for_enqueued_targets":false}),
            )
        }
    }
}
fn root(label: &str) -> PathBuf {
    tempfile::Builder::new()
        .prefix(&format!("devres-status-{label}-"))
        .tempdir_in("/tmp")
        .unwrap()
        .keep()
}
async fn research(
    label: &str,
    npm: Arc<NpmMemory>,
    gate: Option<Arc<dyn AttributionGate>>,
) -> (Research, PathBuf) {
    let p = root(label);
    let broker = Arc::new(BulkBroker::new(BulkConfig::default()).unwrap());
    let config = NpmConfig {
        enabled: false,
        advisories_enabled: false,
        ..Default::default()
    };
    let corpus = Arc::new(NpmCorpus::new_reader(npm, broker, &p, config).unwrap());
    let mut research = Research::new(Arc::new(Retrieval::new(
        Arc::new(NeverRetrieve),
        Arc::new(NeverRetrieve),
    )))
    .await
    .unwrap()
    .with_npm_corpus(corpus);
    if let Some(gate) = gate {
        research = research.with_attribution_gate(gate);
    }
    (research, p)
}
fn runtime(
    store: Arc<AttributionMemory>,
    delegate: Option<Arc<dyn AcquisitionDelegate>>,
) -> AttributionRuntime {
    let r = AttributionRuntime::new(store, Arc::new(NeverAcquire), vec![]).unwrap();
    if let Some(d) = delegate {
        r.with_delegate(d)
    } else {
        r
    }
}
#[tokio::test]
async fn paused_npm_status_without_outer_gate_succeeds_and_reads_local_metadata() {
    let npm = Arc::new(NpmMemory::default());
    let (r, p) = research("no-gate", npm.clone(), None).await;
    let out = r
        .call("packages.npm.corpus_status", json!({}))
        .await
        .unwrap();
    assert_eq!(out["collection_enabled"], false);
    assert_eq!(out["counts"]["advisories"], 3);
    assert_eq!(
        *npm.reads.lock().unwrap(),
        [
            "state:status",
            "statistics",
            "state:default-research",
            "state:default-advisories"
        ]
    );
    std::fs::remove_dir_all(p).unwrap();
}
#[tokio::test]
async fn paused_full_research_status_still_calls_unavailable_writer_delegate() {
    let npm = Arc::new(NpmMemory::default());
    let local = Arc::new(AttributionMemory::default());
    let d = Arc::new(StatusDelegate {
        calls: AtomicUsize::new(0),
        fail: true,
    });
    let gate = Arc::new(runtime(local.clone(), Some(d.clone())));
    let (r, p) = research("delegate-fail", npm.clone(), Some(gate)).await;
    assert_eq!(
        r.call("packages.npm.corpus_status", json!({}))
            .await
            .unwrap_err()
            .code,
        "unavailable"
    );
    assert_eq!(d.calls.load(Ordering::SeqCst), 1);
    assert_eq!(local.status_reads.load(Ordering::SeqCst), 0);
    assert_eq!(npm.reads.lock().unwrap().len(), 4);
    std::fs::remove_dir_all(p).unwrap();
}
#[tokio::test]
async fn earlier_npm_failure_prevents_outer_status_delegate_and_has_same_error_code() {
    let npm = Arc::new(NpmMemory {
        fail_statistics: true,
        ..Default::default()
    });
    let d = Arc::new(StatusDelegate {
        calls: AtomicUsize::new(0),
        fail: true,
    });
    let gate = Arc::new(runtime(
        Arc::new(AttributionMemory::default()),
        Some(d.clone()),
    ));
    let (r, p) = research("early-fail", npm.clone(), Some(gate)).await;
    assert_eq!(
        r.call("packages.npm.corpus_status", json!({}))
            .await
            .unwrap_err()
            .code,
        "unavailable"
    );
    assert_eq!(d.calls.load(Ordering::SeqCst), 0);
    assert_eq!(npm.reads.lock().unwrap().len(), 2);
    std::fs::remove_dir_all(p).unwrap();
}
#[tokio::test]
async fn healthy_writer_status_retains_gaps_even_when_reader_enabled_list_is_empty() {
    let d = Arc::new(StatusDelegate {
        calls: AtomicUsize::new(0),
        fail: false,
    });
    let gate = Arc::new(runtime(
        Arc::new(AttributionMemory::default()),
        Some(d.clone()),
    ));
    let (r, p) = research("healthy-writer", Arc::new(NpmMemory::default()), Some(gate)).await;
    let out = r
        .call("packages.npm.corpus_status", json!({}))
        .await
        .unwrap();
    assert_eq!(out["collection_enabled"], false);
    assert_eq!(out["attribution"]["scan_gaps"]["npm"], "capacity");
    assert_eq!(out["attribution"]["complete"], false);
    assert_eq!(d.calls.load(Ordering::SeqCst), 1);
    std::fs::remove_dir_all(p).unwrap();
}
#[tokio::test]
async fn removing_delegate_switches_to_local_store_and_can_lose_writer_only_gaps() {
    let local = Arc::new(AttributionMemory::default());
    let out = runtime(local.clone(), None).status().await.unwrap();
    assert_eq!(out["enabled_providers"], json!([]));
    assert_eq!(out["disabled_providers"].as_array().unwrap().len(), 9);
    assert_eq!(out["complete"], true);
    assert_eq!(local.status_reads.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn actual_writer_client_missing_token_returns_unavailable_before_any_connection() {
    let p = root("missing-token");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!(
        "https://127.0.0.1:{}/v1/acquire",
        listener.local_addr().unwrap().port()
    );
    let client = WriterClient::new(
        WriterClientConfig {
            access: WriterAccess::StatusOnly,
            endpoint,
            token_file: p.join("absent-token"),
            ca_file: None,
        },
        Duration::from_secs(1),
    )
    .unwrap();
    let local = Arc::new(AttributionMemory::default());
    let gate = Arc::new(runtime(local.clone(), Some(Arc::new(client))));
    let (r, q) = research("actual-writer", Arc::new(NpmMemory::default()), Some(gate)).await;
    let e = r
        .call("packages.npm.corpus_status", json!({}))
        .await
        .unwrap_err();
    assert_eq!(e.code, "unavailable");
    assert_eq!(e.message, "Private source acquisition is unavailable.");
    assert!(e.details.is_none());
    assert!(!e.message.contains("absent-token"));
    assert_eq!(local.status_reads.load(Ordering::SeqCst), 0);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
    std::fs::remove_dir_all(p).unwrap();
    std::fs::remove_dir_all(q).unwrap();
}
