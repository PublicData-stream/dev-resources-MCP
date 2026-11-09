use super::*;
use crate::acquisition::{Acquisition, AcquisitionDelegate, WriterEffect};
use devres_domain::{Capture, FetchResponse};
use std::sync::atomic::AtomicUsize;

fn capture() -> Capture {
    Capture {
        id: "a".repeat(64),
        key: "rfc:text:1".into(),
        source_url: "https://www.rfc-editor.org/rfc/rfc1.txt".into(),
        body_hash: "b".repeat(64),
        media_type: "text/plain".into(),
        retrieved_at: 100,
        validated_at: 200,
    }
}
fn request() -> FetchRequest {
    FetchRequest {
        key: "rfc:text:1".into(),
        url: "https://www.rfc-editor.org/rfc/rfc1.txt".into(),
        ttl_secs: 86400,
        max_bytes: 1024,
        media_type: "text/plain".into(),
    }
}
struct ReaderStore {
    value: StoredCapture,
    reads: AtomicUsize,
    writes: AtomicUsize,
}
#[async_trait]
impl Store for ReaderStore {
    async fn latest(&self, _: &str) -> Result<Option<Cached>> {
        Ok(Some(Cached {
            stored: self.value.clone(),
            validators: Validators::default(),
        }))
    }
    async fn capture(&self, _: &str) -> Result<StoredCapture> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(self.value.clone())
    }
    async fn publish(&self, _: &FetchRequest, _: FetchResponse, _: i64) -> Result<StoredCapture> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        Err(Error::integrity("reader write"))
    }
    async fn revalidate(&self, _: &str, _: &str, _: Validators, _: i64) -> Result<StoredCapture> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        Err(Error::integrity("reader revalidation"))
    }
}
struct NoProvider(AtomicUsize);
#[async_trait]
impl Fetcher for NoProvider {
    async fn fetch(&self, _: &FetchRequest, _: Option<&Validators>) -> Result<FetchResponse> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(Error::integrity("reader contacted provider"))
    }
}
struct Writer {
    receipt: Capture,
    calls: AtomicUsize,
    fail: bool,
}
#[async_trait]
impl AcquisitionDelegate for Writer {
    async fn acquire(&self, operation: Acquisition) -> Result<Capture> {
        assert!(matches!(
            operation,
            Acquisition::RfcRepresentation { number: 1, .. }
        ));
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            Err(Error::unavailable("writer offline"))
        } else {
            Ok(self.receipt.clone())
        }
    }
    async fn effect(&self, _: WriterEffect) -> Result<()> {
        Ok(())
    }
}
struct RfcValidator;
#[async_trait]
impl ResponseValidator for RfcValidator {
    fn acquisition(&self, _: &FetchRequest) -> Result<Option<Acquisition>> {
        Ok(Some(Acquisition::RfcRepresentation {
            number: 1,
            format: "txt".into(),
        }))
    }
    async fn validate(&self, _: &FetchRequest, response: FetchResponse) -> Result<FetchResponse> {
        Ok(response)
    }
}
fn setup(fail: bool) -> (Retrieval, Arc<ReaderStore>, Arc<NoProvider>, Arc<Writer>) {
    let store = Arc::new(ReaderStore {
        value: StoredCapture {
            capture: capture(),
            body: b"retained public bytes".to_vec().into(),
        },
        reads: AtomicUsize::new(0),
        writes: AtomicUsize::new(0),
    });
    let fetcher = Arc::new(NoProvider(AtomicUsize::new(0)));
    let writer = Arc::new(Writer {
        receipt: capture(),
        calls: AtomicUsize::new(0),
        fail,
    });
    (
        Retrieval::new(store.clone(), fetcher.clone()).with_delegate(writer.clone()),
        store,
        fetcher,
        writer,
    )
}
#[tokio::test]
async fn foreground_uses_exact_writer_receipt_without_reader_writes_or_provider_calls() {
    let (retrieval, store, provider, writer) = setup(false);
    let stored = retrieval
        .get_validated(request(), &RfcValidator)
        .await
        .unwrap();
    assert_eq!(stored.capture.id, capture().id);
    assert_eq!(stored.capture.validated_at, 200);
    assert_eq!(stored.body.as_ref(), b"retained public bytes");
    assert_eq!(writer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(store.reads.load(Ordering::SeqCst), 1);
    assert_eq!(store.writes.load(Ordering::SeqCst), 0);
    assert_eq!(provider.0.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn pinned_capture_reads_stay_local_when_writer_is_unavailable() {
    let (retrieval, store, provider, writer) = setup(true);
    retrieval.read_capture(&capture().id).await.unwrap();
    assert_eq!(writer.calls.load(Ordering::SeqCst), 0);
    assert_eq!(store.reads.load(Ordering::SeqCst), 1);
    assert_eq!(provider.0.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn writer_outage_never_falls_through_to_provider_or_reader_publication() {
    let (retrieval, store, provider, writer) = setup(true);
    assert_eq!(
        retrieval
            .get_validated(request(), &RfcValidator)
            .await
            .unwrap_err()
            .code,
        "unavailable"
    );
    assert_eq!(writer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(store.reads.load(Ordering::SeqCst), 0);
    assert_eq!(store.writes.load(Ordering::SeqCst), 0);
    assert_eq!(provider.0.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn writer_receipt_cannot_select_a_different_source() {
    let (retrieval, _, provider, _) = setup(false);
    let mut wrong = request();
    wrong.url = "https://www.rfc-editor.org/rfc/rfc2.txt".into();
    assert_eq!(
        retrieval
            .get_validated(wrong, &RfcValidator)
            .await
            .unwrap_err()
            .code,
        "integrity"
    );
    assert_eq!(provider.0.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn reader_rejects_collection_and_untyped_acquisition() {
    let (retrieval, store, provider, writer) = setup(false);
    assert_eq!(
        retrieval
            .get_background_validated(request(), &RfcValidator)
            .await
            .unwrap_err()
            .code,
        "integrity"
    );
    assert_eq!(
        retrieval.get(request()).await.unwrap_err().code,
        "integrity"
    );
    assert_eq!(writer.calls.load(Ordering::SeqCst), 0);
    assert_eq!(store.writes.load(Ordering::SeqCst), 0);
    assert_eq!(provider.0.load(Ordering::SeqCst), 0);
}
