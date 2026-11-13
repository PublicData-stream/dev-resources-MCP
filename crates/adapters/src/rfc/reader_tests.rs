//! Regression checks for foreground RFC publication across a read-only process.
use super::*;
use async_trait::async_trait;
use devres_application::{
    Cached, Fetcher, Store,
    acquisition::{Acquisition, AcquisitionDelegate, WriterEffect},
};
use devres_domain::{Capture, FetchResponse, StoredCapture, Validators};
use std::sync::atomic::AtomicBool;

struct ReaderStore {
    writes: AtomicUsize,
    latest_reads: AtomicUsize,
    committed: AtomicBool,
    errata: AtomicBool,
    pinned: Mutex<Vec<String>>,
}
fn snapshot_id() -> String {
    "a".repeat(64)
}
fn capture(kind: &str) -> Capture {
    Capture {
        id: if kind == "errata" {
            "b".repeat(64)
        } else {
            "d".repeat(64)
        },
        key: format!("rfc:{kind}"),
        source_url: if kind == "errata" {
            ERRATA_URL.into()
        } else {
            INDEX_URL.into()
        },
        body_hash: "e".repeat(64),
        media_type: "application/json".into(),
        retrieved_at: unix_now(),
        validated_at: unix_now(),
    }
}
fn snapshot(id: String) -> Snapshot {
    Snapshot {
        id,
        catalogue_capture: capture("catalogue").id,
        errata_capture: Some(capture("errata").id),
        documents: vec![],
        search_documents: vec![],
        coverage: json!({"catalogue_validated_at":unix_now(),"errata_validated_at":unix_now()}),
        created_at: unix_now(),
        complete: false,
        index_path: None,
        processor_version: PROCESSOR_VERSION,
    }
}
impl ReaderStore {
    fn reject(&self) -> Error {
        self.writes.fetch_add(1, Ordering::SeqCst);
        Error::integrity("Read-only store rejected publication.")
    }
}
#[async_trait]
impl RfcCorpusStore for ReaderStore {
    async fn save_dataset(&self, _: &str, _: &Dataset) -> Result<()> {
        Err(self.reject())
    }
    async fn dataset(&self, kind: &str, pin: Option<&str>) -> Result<Option<Dataset>> {
        if kind == "errata" && !self.errata.load(Ordering::SeqCst) {
            return Ok(None);
        }
        let capture = capture(kind);
        if pin.is_some_and(|id| id != capture.id) {
            return Ok(None);
        }
        Ok(Some(Dataset {
            capture,
            records: if kind == "errata" {
                vec![
                    json!({"doc-id":"RFC1","errata_status_code":"Verified","errata_type_code":"Editorial"}),
                ]
            } else {
                vec![]
            },
        }))
    }
    async fn schedule(&self, _: &[JobSpec]) -> Result<()> {
        Err(self.reject())
    }
    async fn claim(&self, _: i64) -> Result<Option<devres_application::corpus::Job>> {
        Err(self.reject())
    }
    async fn finish(
        &self,
        _: &str,
        _: Option<&Capture>,
        _: Option<&devres_application::collection::Failure>,
        _: i64,
    ) -> Result<()> {
        Err(self.reject())
    }
    async fn documents(&self) -> Result<Vec<Document>> {
        Ok(vec![])
    }
    async fn save_snapshot(&self, _: &Snapshot) -> Result<()> {
        Err(self.reject())
    }
    async fn snapshot(&self, id: Option<&str>) -> Result<Option<Snapshot>> {
        if let Some(id) = id {
            self.pinned.lock().await.push(id.into());
            return Ok((id == snapshot_id()).then(|| snapshot(id.into())));
        }
        self.latest_reads.fetch_add(1, Ordering::SeqCst);
        // Model a concurrent new head after the delegated publication. Its ID
        // must never replace the receipt returned for the current operation.
        Ok(self
            .committed
            .load(Ordering::SeqCst)
            .then(|| snapshot("c".repeat(64))))
    }
    async fn status(&self) -> Result<Value> {
        Ok(json!({}))
    }
}
#[async_trait]
impl Store for ReaderStore {
    async fn latest(&self, _: &str) -> Result<Option<Cached>> {
        Ok(None)
    }
    async fn capture(&self, _: &str) -> Result<StoredCapture> {
        Err(Error::unavailable("Unused reader port."))
    }
    async fn publish(&self, _: &FetchRequest, _: FetchResponse, _: i64) -> Result<StoredCapture> {
        Err(self.reject())
    }
    async fn revalidate(&self, _: &str, _: &str, _: Validators, _: i64) -> Result<StoredCapture> {
        Err(self.reject())
    }
}
struct NoNetwork;
#[async_trait]
impl Fetcher for NoNetwork {
    async fn fetch(&self, _: &FetchRequest, _: Option<&Validators>) -> Result<FetchResponse> {
        Err(Error::integrity("Reader attempted provider traffic."))
    }
}
struct Writer {
    store: Arc<ReaderStore>,
    publications: AtomicUsize,
}
#[async_trait]
impl AcquisitionDelegate for Writer {
    async fn acquire(&self, _: Acquisition) -> Result<Capture> {
        Err(Error::integrity("Unexpected capture acquisition."))
    }
    async fn effect(&self, effect: WriterEffect) -> Result<()> {
        match effect {
            WriterEffect::RfcErrata => self.store.errata.store(true, Ordering::SeqCst),
            WriterEffect::RfcCatalogue => {}
            _ => return Err(Error::integrity("Unexpected writer effect.")),
        }
        Ok(())
    }
    async fn rfc_snapshot(&self) -> Result<String> {
        self.publications.fetch_add(1, Ordering::SeqCst);
        self.store.committed.store(true, Ordering::SeqCst);
        Ok(snapshot_id())
    }
}
fn fixture(root: &Path) -> (RfcCorpus, Arc<ReaderStore>, Arc<Writer>) {
    let store = Arc::new(ReaderStore {
        writes: AtomicUsize::new(0),
        latest_reads: AtomicUsize::new(0),
        committed: AtomicBool::new(false),
        errata: AtomicBool::new(false),
        pinned: Mutex::new(vec![]),
    });
    let writer = Arc::new(Writer {
        store: store.clone(),
        publications: AtomicUsize::new(0),
    });
    let retrieval =
        Arc::new(Retrieval::new(store.clone(), Arc::new(NoNetwork)).with_delegate(writer.clone()));
    (
        RfcCorpus::new(retrieval, store.clone(), root, RfcConfig::default()).unwrap(),
        store,
        writer,
    )
}
#[tokio::test]
async fn cold_reader_snapshot_delegates_publication_and_loads_exact_receipt() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let (corpus, store, writer) = fixture(root.path());
    let selected = corpus.selected_snapshot(None).await.unwrap();
    assert_eq!(selected.id, snapshot_id());
    assert_eq!(writer.publications.load(Ordering::SeqCst), 1);
    assert_eq!(store.writes.load(Ordering::SeqCst), 0);
    assert_eq!(store.latest_reads.load(Ordering::SeqCst), 1);
    assert_eq!(*store.pinned.lock().await, vec![snapshot_id()]);
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
}
#[tokio::test]
async fn readonly_errata_fallback_keeps_snapshot_receipt_across_concurrent_new_head() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let (corpus, store, writer) = fixture(root.path());
    let result = crate::rfc::tools::call(&corpus, "rfc.errata", json!({"number":1}))
        .await
        .unwrap();
    assert_eq!(result["snapshot"], snapshot_id());
    assert_eq!(result["items"][0]["doc-id"], "RFC1");
    assert_eq!(writer.publications.load(Ordering::SeqCst), 1);
    assert_eq!(store.writes.load(Ordering::SeqCst), 0);
    assert_eq!(store.latest_reads.load(Ordering::SeqCst), 0);
    assert_eq!(*store.pinned.lock().await, vec![snapshot_id()]);
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
}
