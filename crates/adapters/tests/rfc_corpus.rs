//! Synthetic RFC corpus integration: all provider access is an in-memory fixture.
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD};
use devres_adapters::{Research, RfcConfig, RfcCorpus};
use devres_application::{
    Cached, Fetcher, Retrieval, Store,
    corpus::{Dataset, Document, Job, JobSpec, RfcCorpusStore, Snapshot},
};
use devres_domain::{
    Capture, Error, FetchRequest, FetchResponse, Result, StoredCapture, Validators,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
    time::Duration,
};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

static FIXTURE_PROCESSORS: Mutex<()> = Mutex::const_new(());

const INDEX: &str = "https://www.rfc-editor.org/rfc-index.xml";
const ERRATA: &str = "https://www.rfc-editor.org/api/v1/errata.json";
const TXT: &str = "https://www.rfc-editor.org/rfc/rfc9000.txt";
const HTML: &str = "https://www.rfc-editor.org/rfc/rfc9000.html";
const PDF: &str = "https://www.rfc-editor.org/rfc/rfc9000.pdf";
const XML_INDEX: &str = r#"<rfc-index xmlns="https://www.rfc-editor.org/rfc-index"><rfc-entry><doc-id>RFC9000</doc-id><title>Transport Protocol</title><author><name>A. Researcher</name></author><keywords><kw>multiplexing</kw></keywords><abstract><p>Research fixture.</p></abstract><date><month>May</month><year>2021</year></date><current-status>PROPOSED STANDARD</current-status><stream>IETF</stream><area>Transport</area><wg_acronym>quic</wg_acronym><is-also><doc-id>STD0001</doc-id><doc-id>BCP0014</doc-id></is-also><format><file-format>TEXT</file-format><file-format>HTML</file-format><file-format>PDF</file-format></format></rfc-entry></rfc-index>"#;
const TEXT: &str = "RFC9000 αβ content. Multiplexed transport and exact research phrase.";
const HTML_TEXT: &str = "<!doctype html><html><body><p>Multiplexed transport and exact research phrase.</p></body></html>";
const PDF_BYTES: &[u8] = b"%PDF-1.7\nsynthetic fixture\n%%EOF\n";

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn errata() -> Value {
    json!({"errata_id":"123","doc-id":"RFC9000","errata_status_code":"Verified","errata_type_code":"Technical","orig_text":"original","correct_text":"corrected","notes":"Synthetic fixture"})
}
#[derive(Clone)]
struct Pending {
    spec: JobSpec,
    attempts: u32,
    running: bool,
    error: Option<String>,
}
#[derive(Default)]
struct State {
    heads: BTreeMap<String, Cached>,
    captures: BTreeMap<String, StoredCapture>,
    datasets: BTreeMap<(String, String), Dataset>,
    dataset_heads: BTreeMap<String, String>,
    jobs: BTreeMap<String, Pending>,
    documents: BTreeMap<String, Document>,
    snapshots: BTreeMap<String, Snapshot>,
    active: Option<String>,
    snapshot_pause: Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>,
}
#[derive(Default)]
struct Memory(Mutex<State>, std::sync::atomic::AtomicBool);
#[async_trait]
impl Store for Memory {
    async fn latest(&self, key: &str) -> Result<Option<Cached>> {
        Ok(self.0.lock().await.heads.get(key).cloned())
    }
    async fn capture(&self, id: &str) -> Result<StoredCapture> {
        self.0
            .lock()
            .await
            .captures
            .get(id)
            .cloned()
            .ok_or_else(|| Error::not_found("Synthetic capture absent."))
    }
    async fn publish(
        &self,
        request: &FetchRequest,
        response: FetchResponse,
        now: i64,
    ) -> Result<StoredCapture> {
        let body_hash = digest(&response.body);
        let id = digest(
            format!(
                "{}\0{}\0{}\0{body_hash}",
                request.key, request.url, request.media_type
            )
            .as_bytes(),
        );
        let mut state = self.0.lock().await;
        let retrieved_at = state
            .captures
            .get(&id)
            .map(|c| c.capture.retrieved_at)
            .unwrap_or(now);
        let stored = StoredCapture {
            capture: Capture {
                id: id.clone(),
                key: request.key.clone(),
                source_url: request.url.clone(),
                body_hash,
                media_type: request.media_type.clone(),
                retrieved_at,
                validated_at: now,
            },
            body: response.body.into(),
        };
        state.captures.insert(id, stored.clone());
        state.heads.insert(
            request.key.clone(),
            Cached {
                stored: stored.clone(),
                validators: response.validators,
            },
        );
        Ok(stored)
    }
    async fn revalidate(
        &self,
        key: &str,
        id: &str,
        validators: Validators,
        now: i64,
    ) -> Result<StoredCapture> {
        let mut state = self.0.lock().await;
        let stored = state
            .captures
            .get_mut(id)
            .ok_or_else(|| Error::not_found("Synthetic capture absent."))?;
        stored.capture.validated_at = now;
        let stored = stored.clone();
        state.heads.insert(
            key.into(),
            Cached {
                stored: stored.clone(),
                validators,
            },
        );
        Ok(stored)
    }
}
#[async_trait]
impl RfcCorpusStore for Memory {
    async fn save_dataset(&self, kind: &str, dataset: &Dataset) -> Result<()> {
        let mut state = self.0.lock().await;
        state
            .datasets
            .insert((kind.into(), dataset.capture.id.clone()), dataset.clone());
        state
            .dataset_heads
            .insert(kind.into(), dataset.capture.id.clone());
        Ok(())
    }
    async fn dataset(&self, kind: &str, capture: Option<&str>) -> Result<Option<Dataset>> {
        let state = self.0.lock().await;
        let id = capture.or_else(|| state.dataset_heads.get(kind).map(String::as_str));
        Ok(id.and_then(|id| state.datasets.get(&(kind.into(), id.into())).cloned()))
    }
    async fn schedule(&self, jobs: &[JobSpec]) -> Result<()> {
        let mut state = self.0.lock().await;
        for spec in jobs {
            state
                .jobs
                .entry(spec.key.clone())
                .or_insert_with(|| Pending {
                    spec: spec.clone(),
                    attempts: 0,
                    running: false,
                    error: None,
                });
        }
        Ok(())
    }
    async fn claim(&self, now: i64) -> Result<Option<Job>> {
        let mut state = self.0.lock().await;
        let Some(job) = state
            .jobs
            .values_mut()
            .find(|job| !job.running && job.spec.due_at <= now)
        else {
            return Ok(None);
        };
        job.running = true;
        job.attempts += 1;
        Ok(Some(Job {
            spec: job.spec.clone(),
            attempts: job.attempts,
        }))
    }
    async fn finish(
        &self,
        key: &str,
        capture: Option<&Capture>,
        error: Option<&str>,
        next_due: i64,
    ) -> Result<()> {
        let mut state = self.0.lock().await;
        let job = state
            .jobs
            .get_mut(key)
            .ok_or_else(|| Error::not_found("Synthetic job absent."))?;
        job.running = false;
        job.spec.due_at = next_due;
        job.error = error.map(str::to_owned);
        let spec = job.spec.clone();
        if let Some(capture) = capture {
            state.documents.insert(
                key.into(),
                Document {
                    number: spec.number,
                    format: spec.format,
                    capture: capture.clone(),
                    assurance: spec.assurance,
                },
            );
        }
        Ok(())
    }
    async fn documents(&self) -> Result<Vec<Document>> {
        Ok(self.0.lock().await.documents.values().cloned().collect())
    }
    async fn save_snapshot(&self, snapshot: &Snapshot) -> Result<()> {
        let pause = self.0.lock().await.snapshot_pause.take();
        if let Some((entered, release)) = pause {
            entered.notify_one();
            release.notified().await;
        }
        if self.1.swap(false, Ordering::SeqCst) {
            return Err(Error::unavailable(
                "Synthetic failure after index publication.",
            ));
        }
        let mut state = self.0.lock().await;
        state
            .snapshots
            .insert(snapshot.id.clone(), snapshot.clone());
        state.active = Some(snapshot.id.clone());
        Ok(())
    }
    async fn snapshot(&self, id: Option<&str>) -> Result<Option<Snapshot>> {
        let state = self.0.lock().await;
        Ok(id
            .or(state.active.as_deref())
            .and_then(|id| state.snapshots.get(id).cloned()))
    }
    async fn status(&self) -> Result<Value> {
        let state = self.0.lock().await;
        Ok(json!({"jobs":state.jobs.len(),"captures":state.captures.len(),"snapshot":state.active}))
    }
}

#[derive(Default)]
struct Fixture {
    responses: Mutex<BTreeMap<String, Vec<u8>>>,
    calls: Mutex<Vec<String>>,
}
#[async_trait]
impl Fetcher for Fixture {
    async fn fetch(&self, request: &FetchRequest, _: Option<&Validators>) -> Result<FetchResponse> {
        self.calls.lock().await.push(request.url.clone());
        Ok(match self.responses.lock().await.get(&request.url) {
            Some(body) => FetchResponse {
                status: 200,
                body: body.clone(),
                validators: Validators::default(),
            },
            None => FetchResponse {
                status: 404,
                body: Vec::new(),
                validators: Validators::default(),
            },
        })
    }
}
struct ControlledClock(AtomicI64);
impl devres_application::Clock for ControlledClock {
    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}
struct Harness {
    store: Arc<Memory>,
    fixture: Arc<Fixture>,
    clock: Arc<ControlledClock>,
    retrieval: Arc<Retrieval>,
    corpus: Arc<RfcCorpus>,
    research: Research,
    root: tempfile::TempDir,
}
impl Harness {
    async fn new(enabled: bool) -> Self {
        let store = Arc::new(Memory::default());
        let fixture = Arc::new(Fixture::default());
        fixture.responses.lock().await.extend([
            (INDEX.into(), XML_INDEX.as_bytes().to_vec()),
            (ERRATA.into(), serde_json::to_vec(&vec![errata()]).unwrap()),
            (TXT.into(), TEXT.as_bytes().to_vec()),
            (HTML.into(), HTML_TEXT.as_bytes().to_vec()),
            (PDF.into(), PDF_BYTES.to_vec()),
        ]);
        let clock = Arc::new(ControlledClock(AtomicI64::new(devres_domain::unix_now())));
        let retrieval = Arc::new(Retrieval::with_clock(
            store.clone(),
            fixture.clone(),
            clock.clone(),
        ));
        let root = tempfile::tempdir().unwrap();
        let corpus = Arc::new(
            RfcCorpus::new(
                retrieval.clone(),
                store.clone(),
                root.path(),
                RfcConfig {
                    enabled,
                    ..RfcConfig::default()
                },
            )
            .unwrap(),
        );
        let research = Research::new(retrieval.clone())
            .await
            .unwrap()
            .with_corpus(corpus.clone());
        Self {
            store,
            fixture,
            clock,
            retrieval,
            corpus,
            research,
            root,
        }
    }
    async fn source(&self, key: &str, url: &str, mime: &str, body: &[u8]) -> StoredCapture {
        self.store
            .publish(
                &FetchRequest {
                    key: key.into(),
                    url: url.into(),
                    ttl_secs: 86400,
                    max_bytes: 64 * 1024 * 1024,
                    media_type: mime.into(),
                },
                FetchResponse {
                    status: 200,
                    body: body.to_vec(),
                    validators: Validators::default(),
                },
                self.clock.now(),
            )
            .await
            .unwrap()
    }
    async fn seed_snapshot(&self, title: &str, id: &str) -> Snapshot {
        let xml = XML_INDEX.replace("Transport Protocol", title);
        let index = self
            .source("rfc:index", INDEX, "application/xml", xml.as_bytes())
            .await;
        let search = self
            .research
            .call(
                "rfc_search",
                json!({"query":"9000","capture":index.capture.id}),
            )
            .await
            .unwrap();
        let record = search["items"][0]["metadata"].clone();
        let catalogue = Dataset {
            capture: index.capture,
            records: vec![record],
        };
        self.store
            .save_dataset("catalogue", &catalogue)
            .await
            .unwrap();
        let errata_capture = self
            .source(
                "rfc:errata",
                ERRATA,
                "application/json",
                &serde_json::to_vec(&vec![errata()]).unwrap(),
            )
            .await;
        self.store
            .save_dataset(
                "errata",
                &Dataset {
                    capture: errata_capture.capture.clone(),
                    records: vec![errata()],
                },
            )
            .await
            .unwrap();
        let mut documents = Vec::new();
        for (key, url, format, mime, body) in [
            ("rfc:text:9000", TXT, "txt", "text/plain", TEXT.as_bytes()),
            (
                "rfc:format:9000:html",
                HTML,
                "html",
                "text/html",
                HTML_TEXT.as_bytes(),
            ),
            (
                "rfc:format:9000:pdf",
                PDF,
                "pdf",
                "application/pdf",
                PDF_BYTES,
            ),
        ] {
            let captured = self.source(key, url, mime, body).await;
            documents.push(Document {
                number: 9000,
                format: format.into(),
                capture: captured.capture,
                assurance: "https".into(),
            });
        }
        let snapshot:Snapshot=serde_json::from_value(json!({"id":id,"catalogue_capture":catalogue.capture.id,"errata_capture":errata_capture.capture.id,"documents":documents,"search_documents":[],"coverage":{"acquisition_complete":true},"created_at":self.clock.now(),"complete":true,"index_path":null,"processor_version":1})).unwrap();
        self.store.save_snapshot(&snapshot).await.unwrap();
        snapshot
    }
}
use devres_application::Clock as _;

#[tokio::test]
async fn additive_metadata_series_errata_filters_and_status_are_snapshot_bound() {
    let _fixture_processors = FIXTURE_PROCESSORS.lock().await;
    let harness = Harness::new(false).await;
    let old = harness
        .seed_snapshot("Transport Protocol", &"a".repeat(64))
        .await;
    let metadata = harness
        .research
        .call("rfc_metadata", json!({"number":9000,"snapshot":old.id}))
        .await
        .unwrap();
    assert_eq!(metadata["metadata"]["authors"], json!(["A. Researcher"]));
    assert_eq!(metadata["metadata"]["publication"], "2021-05");
    let filtered=harness.research.call("rfc_catalog_search",json!({"filters":{"author":"researcher","keyword":"multiplexing","stream":"IETF","area":"Transport","working_group":"quic","published_from":"2021-05","published_through":"2021-05"},"snapshot":old.id})).await.unwrap();
    assert_eq!(filtered["total"], 1);
    let field_name = harness
        .research
        .call(
            "rfc_catalog_search",
            json!({"query":"updated_by","snapshot":old.id}),
        )
        .await
        .unwrap();
    assert_eq!(
        field_name["total"], 0,
        "metadata field names are not source search content"
    );
    let series = harness
        .research
        .call(
            "rfc_series_get",
            json!({"series":"STD","number":1,"snapshot":old.id}),
        )
        .await
        .unwrap();
    assert_eq!(series["items"][0]["number"], 9000);
    let exact_series = harness
        .research
        .call(
            "rfc_catalog_search",
            json!({"filters":{"series":"BCP14"},"snapshot":old.id}),
        )
        .await
        .unwrap();
    assert_eq!(exact_series["total"], 1);
    let different_series = harness
        .research
        .call(
            "rfc_catalog_search",
            json!({"filters":{"series":"BCP1"},"snapshot":old.id}),
        )
        .await
        .unwrap();
    assert_eq!(
        different_series["total"], 0,
        "series filters must match the whole normalized series identity"
    );
    let bcp = harness
        .research
        .call(
            "rfc_series_get",
            json!({"series":"BCP","number":14,"snapshot":old.id}),
        )
        .await
        .unwrap();
    assert_eq!(bcp["items"][0]["number"], 9000);
    let records = harness
        .research
        .call(
            "rfc_errata",
            json!({"number":9000,"status":"Verified","type":"Technical","snapshot":old.id}),
        )
        .await
        .unwrap();
    assert_eq!(records["items"][0], errata());
    let absent = harness
        .research
        .call(
            "rfc_errata",
            json!({"number":9000,"status":"Rejected","snapshot":old.id}),
        )
        .await
        .unwrap();
    assert_eq!(absent["total"], 0);
    let new = harness
        .seed_snapshot("Changed metadata", &"b".repeat(64))
        .await;
    let pinned = harness
        .research
        .call("rfc_metadata", json!({"number":9000,"snapshot":old.id}))
        .await
        .unwrap();
    assert_eq!(pinned["metadata"]["title"], "Transport Protocol");
    let latest = harness
        .research
        .call("rfc_metadata", json!({"number":9000}))
        .await
        .unwrap();
    assert_eq!(latest["metadata"]["title"], "Changed metadata");
    assert_eq!(latest["snapshot"], new.id);
    let status = harness
        .research
        .call("rfc_corpus_status", json!({}))
        .await
        .unwrap();
    assert_eq!(status["collection_enabled"], false);
    assert!(harness.fixture.calls.lock().await.is_empty());
}

#[tokio::test]
async fn typed_format_and_binary_resource_pages_preserve_capture_and_utf8() {
    let _fixture_processors = FIXTURE_PROCESSORS.lock().await;
    let harness = Harness::new(false).await;
    let snapshot = harness
        .seed_snapshot("Transport Protocol", &"c".repeat(64))
        .await;
    harness.fixture.responses.lock().await.clear();
    let legacy = harness
        .research
        .call("rfc_get", json!({"number":9000}))
        .await
        .unwrap();
    assert_eq!(legacy["page"]["text"], TEXT);
    let generic = harness
        .research
        .call("fetch", json!({"id":"rfc:9000"}))
        .await
        .unwrap();
    assert_eq!(generic["page"]["text"], TEXT);
    let text = snapshot
        .documents
        .iter()
        .find(|document| document.format == "txt")
        .unwrap();
    let page = harness
        .research
        .call(
            "rfc_format_get",
            json!({"number":9000,"format":"txt","capture":text.capture.id,"offset":8,"limit":3}),
        )
        .await
        .unwrap();
    assert_eq!(page["page"]["text"], "α");
    assert_eq!(page["page"]["next_offset"], 10);
    let continuation = harness
        .research
        .call(
            "rfc_format_get",
            json!({"number":9000,"format":"txt","capture":text.capture.id,"offset":10,"limit":2}),
        )
        .await
        .unwrap();
    assert_eq!(continuation["page"]["text"], "β");
    let pdf = snapshot
        .documents
        .iter()
        .find(|document| document.format == "pdf")
        .unwrap();
    let binary = harness
        .research
        .call(
            "rfc_format_get",
            json!({"number":9000,"format":"pdf","capture":pdf.capture.id,"offset":1,"limit":7}),
        )
        .await
        .unwrap();
    assert_eq!(
        STANDARD
            .decode(binary["page"]["data"].as_str().unwrap())
            .unwrap(),
        PDF_BYTES[1..8]
    );
    let resource = harness
        .research
        .read_resource(binary["resource_uri"].as_str().unwrap())
        .await
        .unwrap();
    assert_eq!(resource["contents"][0]["mimeType"], "application/pdf");
    assert_eq!(resource["contents"][0]["blob"], binary["page"]["data"]);
    let changed = harness
        .research
        .call(
            "fetch",
            json!({"id":binary["resource_uri"],"offset":2,"limit":3}),
        )
        .await
        .unwrap();
    assert_eq!(
        STANDARD
            .decode(changed["contents"][0]["blob"].as_str().unwrap())
            .unwrap(),
        PDF_BYTES[2..5]
    );
    assert!(
        harness
            .research
            .call(
                "rfc_format_get",
                json!({"number":9001,"format":"pdf","capture":pdf.capture.id})
            )
            .await
            .is_err()
    );
    assert!(
        harness
            .research
            .call(
                "rfc_format_get",
                json!({"number":9000,"format":"txt","capture":pdf.capture.id})
            )
            .await
            .is_err()
    );
    assert!(
        harness
            .research
            .read_resource(&format!("devres://capture/{}", pdf.capture.id))
            .await
            .is_err()
    );
    assert!(harness.fixture.calls.lock().await.is_empty());
}

async fn wait_for<F, Fut>(mut predicate: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if predicate().await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("synthetic corpus worker did not reach expected state");
}
async fn stop(token: CancellationToken, worker: tokio::task::JoinHandle<Result<()>>) {
    token.cancel();
    tokio::time::timeout(Duration::from_secs(5), worker)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn managed_collection_resumes_pending_work_and_keeps_old_fulltext_snapshots() {
    let _fixture_processors = FIXTURE_PROCESSORS.lock().await;
    let harness = Harness::new(true).await;
    let token = CancellationToken::new();
    let worker_corpus = harness.corpus.clone();
    let worker_token = token.clone();
    let worker = tokio::spawn(async move { worker_corpus.run(worker_token).await });
    wait_for(|| async { harness.store.snapshot(None).await.unwrap().is_some() }).await;
    let bootstrap = harness.store.snapshot(None).await.unwrap().unwrap();
    assert!(!bootstrap.complete);
    stop(token, worker).await;
    assert!(
        harness
            .store
            .0
            .lock()
            .await
            .jobs
            .values()
            .any(|job| job.attempts == 0)
    );
    // Start a new supervisor with the same durable store and captured bytes.
    let resumed = Arc::new(
        RfcCorpus::new(
            harness.retrieval.clone(),
            harness.store.clone(),
            harness.root.path(),
            RfcConfig::default(),
        )
        .unwrap(),
    );
    let token = CancellationToken::new();
    let worker_corpus = resumed.clone();
    let worker_token = token.clone();
    let worker = tokio::spawn(async move { worker_corpus.run(worker_token).await });
    wait_for(|| async { harness.store.documents().await.unwrap().len() == 3 }).await;
    stop(token, worker).await;
    // A new supervisor publishes the completed generation immediately, without waiting for the normal snapshot cadence.
    let completed = Arc::new(
        RfcCorpus::new(
            harness.retrieval.clone(),
            harness.store.clone(),
            harness.root.path(),
            RfcConfig::default(),
        )
        .unwrap(),
    );
    let token = CancellationToken::new();
    let worker_corpus = completed.clone();
    let worker_token = token.clone();
    let worker = tokio::spawn(async move { worker_corpus.run(worker_token).await });
    wait_for(|| async {
        harness
            .store
            .snapshot(None)
            .await
            .unwrap()
            .is_some_and(|snapshot| snapshot.complete)
    })
    .await;
    stop(token, worker).await;
    let full = harness.store.snapshot(None).await.unwrap().unwrap();
    let before = harness.fixture.calls.lock().await.len();
    let research = Research::new(harness.retrieval.clone())
        .await
        .unwrap()
        .with_corpus(completed);
    let results = research
        .call(
            "rfc_fulltext_search",
            json!({"query":"multiplexed transport","snapshot":full.id}),
        )
        .await
        .unwrap();
    assert_eq!(results["total"], 1);
    assert_eq!(results["items"][0]["number"], 9000);
    let phrase=research.call("rfc_fulltext_search",json!({"query":"\"exact research phrase\" OR missing -excluded","mode":"english","snapshot":full.id})).await.unwrap();
    assert_eq!(phrase["total"], 1);
    let old = research
        .call(
            "rfc_fulltext_search",
            json!({"query":"multiplexed transport","snapshot":bootstrap.id}),
        )
        .await
        .unwrap();
    assert_eq!(old["total"], 1);
    assert_eq!(harness.fixture.calls.lock().await.len(), before);
    // Revalidation sees a changed body; the previous snapshot still selects its old capture.
    harness.clock.0.fetch_add(90000, Ordering::SeqCst);
    harness.fixture.responses.lock().await.insert(
        TXT.into(),
        b"RFC9000 replacementunique changed body".to_vec(),
    );
    {
        let mut state = harness.store.0.lock().await;
        for job in state.jobs.values_mut() {
            if job.spec.format == "txt" {
                job.spec.due_at = 0;
            }
        }
    }
    let changed = Arc::new(
        RfcCorpus::new(
            harness.retrieval.clone(),
            harness.store.clone(),
            harness.root.path(),
            RfcConfig::default(),
        )
        .unwrap(),
    );
    let token = CancellationToken::new();
    let worker_corpus = changed.clone();
    let worker_token = token.clone();
    let worker = tokio::spawn(async move { worker_corpus.run(worker_token).await });
    wait_for(|| async {
        harness
            .store
            .snapshot(None)
            .await
            .unwrap()
            .is_some_and(|snapshot| snapshot.id != full.id)
    })
    .await;
    stop(token, worker).await;
    let research = Research::new(harness.retrieval.clone())
        .await
        .unwrap()
        .with_corpus(changed);
    let replacement = research
        .call("rfc_fulltext_search", json!({"query":"replacementunique"}))
        .await
        .unwrap();
    assert_eq!(replacement["total"], 1);
    let historical = research
        .call(
            "rfc_fulltext_search",
            json!({"query":"multiplexed transport","snapshot":full.id}),
        )
        .await
        .unwrap();
    assert_eq!(historical["total"], 1);
    let historical_absence = research
        .call(
            "rfc_fulltext_search",
            json!({"query":"replacementunique","snapshot":full.id}),
        )
        .await
        .unwrap();
    assert_eq!(historical_absence["total"], 0);
}

#[tokio::test]
async fn paused_collection_has_no_automatic_provider_access() {
    let _fixture_processors = FIXTURE_PROCESSORS.lock().await;
    let harness = Harness::new(false).await;
    let token = CancellationToken::new();
    let worker_corpus = harness.corpus.clone();
    let worker_token = token.clone();
    let worker = tokio::spawn(async move { worker_corpus.run(worker_token).await });
    tokio::time::sleep(Duration::from_millis(30)).await;
    stop(token, worker).await;
    assert!(harness.fixture.calls.lock().await.is_empty());
    assert!(harness.store.0.lock().await.jobs.is_empty());
}

#[tokio::test]
async fn index_publication_retries_after_database_failure_without_replacing_orphans() {
    let _fixture_processors = FIXTURE_PROCESSORS.lock().await;
    let harness = Harness::new(true).await;
    let one_format = XML_INDEX.replace(
        "<file-format>HTML</file-format><file-format>PDF</file-format>",
        "",
    );
    harness
        .fixture
        .responses
        .lock()
        .await
        .insert(INDEX.into(), one_format.into_bytes());
    harness.store.1.store(true, Ordering::SeqCst);
    let token = CancellationToken::new();
    let worker_corpus = harness.corpus.clone();
    let worker_token = token.clone();
    let worker = tokio::spawn(async move { worker_corpus.run(worker_token).await });
    wait_for(|| async {
        harness
            .store
            .snapshot(None)
            .await
            .unwrap()
            .is_some_and(|snapshot| snapshot.complete)
    })
    .await;
    stop(token, worker).await;
    let snapshot = harness.store.snapshot(None).await.unwrap().unwrap();
    let published = harness.root.path().join(snapshot.index_path.unwrap());
    assert!(published.join("integrity.json").is_file());
    let directories = std::fs::read_dir(harness.root.path().join("rfc-indexes"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir())
        .collect::<Vec<_>>();
    assert_eq!(
        directories.len(),
        2,
        "the failed DB publication must leave one preserved orphan and one successful index"
    );
    assert!(
        directories
            .iter()
            .all(|path| path.join("integrity.json").is_file())
    );
    let documents = harness.store.documents().await.unwrap();
    assert_eq!(documents.len(), 1);
    assert_eq!(
        harness
            .store
            .capture(&documents[0].capture.id)
            .await
            .unwrap()
            .body
            .as_ref(),
        TEXT.as_bytes()
    );
}

#[tokio::test]
async fn unadvertised_text_is_retained_in_raw_and_search_membership() {
    let _fixture_processors = FIXTURE_PROCESSORS.lock().await;
    let harness = Harness::new(false).await;
    let pdf_only = XML_INDEX.replace(
        "<file-format>TEXT</file-format><file-format>HTML</file-format>",
        "",
    );
    harness
        .fixture
        .responses
        .lock()
        .await
        .insert(INDEX.into(), pdf_only.into_bytes());
    harness
        .research
        .call("rfc_format_get", json!({"number":9000,"format":"txt"}))
        .await
        .unwrap();
    let result = harness
        .research
        .call("rfc_fulltext_search", json!({"query":"multiplexed"}))
        .await
        .unwrap();
    assert_eq!(result["total"], 1);
    let snapshot = harness.store.snapshot(None).await.unwrap().unwrap();
    assert_eq!(snapshot.search_documents.len(), 1);
    assert!(
        snapshot
            .documents
            .iter()
            .any(|d| d.capture.id == snapshot.search_documents[0].capture.id)
    );
    assert_eq!(snapshot.coverage["expected_representations"], 1);
    assert_eq!(snapshot.coverage["captured_representations"], 0);
}

#[tokio::test]
async fn expired_default_snapshot_requires_explicit_historical_selection() {
    let _fixture_processors = FIXTURE_PROCESSORS.lock().await;
    let harness = Harness::new(false).await;
    harness
        .clock
        .0
        .store(devres_domain::unix_now() - 8 * 86400, Ordering::SeqCst);
    let snapshot = harness
        .seed_snapshot("Historical metadata", &"e".repeat(64))
        .await;
    let error = harness
        .research
        .call("rfc_metadata", json!({"number":9000}))
        .await
        .unwrap_err();
    assert_eq!(error.code, "unavailable");
    let historical = harness
        .research
        .call(
            "rfc_metadata",
            json!({"number":9000,"snapshot":snapshot.id}),
        )
        .await
        .unwrap();
    assert_eq!(historical["metadata"]["title"], "Historical metadata");
    assert_eq!(historical["freshness"]["expired"], true);
}

#[tokio::test]
async fn concurrent_foreground_capture_is_not_erased_by_snapshot_publication() {
    let _fixture_processors = FIXTURE_PROCESSORS.lock().await;
    let harness = Harness::new(false).await;
    harness
        .research
        .call("rfc_format_get", json!({"number":9000,"format":"txt"}))
        .await
        .unwrap();
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    harness.store.0.lock().await.snapshot_pause = Some((entered.clone(), release.clone()));
    let research = Research::new(harness.retrieval.clone())
        .await
        .unwrap()
        .with_corpus(harness.corpus.clone());
    let pending = tokio::spawn(async move {
        research
            .call("rfc_fulltext_search", json!({"query":"multiplexed"}))
            .await
    });
    tokio::time::timeout(Duration::from_secs(15), entered.notified())
        .await
        .unwrap();
    harness.clock.0.fetch_add(86401, Ordering::SeqCst);
    harness
        .fixture
        .responses
        .lock()
        .await
        .insert(TXT.into(), b"RFC9000 concurrentgenerationword".to_vec());
    harness
        .research
        .call("rfc_format_get", json!({"number":9000,"format":"txt"}))
        .await
        .unwrap();
    release.notify_one();
    pending.await.unwrap().unwrap();
    let result = harness
        .research
        .call(
            "rfc_fulltext_search",
            json!({"query":"concurrentgenerationword"}),
        )
        .await
        .unwrap();
    assert_eq!(
        result["total"], 1,
        "publication must preserve a newer dirty generation"
    );
}

#[tokio::test]
async fn stage_recovery_removes_only_owned_disposable_directories() {
    let harness = Harness::new(false).await;
    let indexes = harness.root.path().join("rfc-indexes");
    let stage = indexes.join(".stage-42-1");
    std::fs::create_dir_all(&stage).unwrap();
    std::fs::write(stage.join("partial"), "synthetic").unwrap();
    let published = indexes.join("f".repeat(64));
    std::fs::create_dir(&published).unwrap();
    std::fs::write(published.join("permanent"), "public").unwrap();
    harness.corpus.recover_stages().await.unwrap();
    assert!(!stage.exists());
    assert!(published.join("permanent").exists());
    #[cfg(unix)]
    {
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("keep"), "public").unwrap();
        std::os::unix::fs::symlink(outside.path(), indexes.join(".stage-42-2")).unwrap();
        assert_eq!(
            harness.corpus.recover_stages().await.unwrap_err().code,
            "integrity"
        );
        assert!(outside.path().join("keep").exists());
    }
}

#[tokio::test]
async fn collection_traverses_multiple_rfc_identities_and_all_advertised_formats() {
    let _fixture_processors = FIXTURE_PROCESSORS.lock().await;
    let harness = Harness::new(true).await;
    let index=XML_INDEX.replace("</rfc-index>","<rfc-entry><doc-id>RFC9001</doc-id><title>Second research fixture</title><format><file-format>TEXT</file-format></format></rfc-entry></rfc-index>");
    harness.fixture.responses.lock().await.extend([
        (INDEX.into(), index.into_bytes()),
        (TXT.into(), format!("{TEXT} traversalfixture").into_bytes()),
        (
            "https://www.rfc-editor.org/rfc/rfc9001.txt".into(),
            b"RFC9001 traversalfixture second document".to_vec(),
        ),
    ]);
    let token = CancellationToken::new();
    let corpus = harness.corpus.clone();
    let signal = token.clone();
    let worker = tokio::spawn(async move { corpus.run(signal).await });
    wait_for(|| async { harness.store.documents().await.unwrap().len() == 4 }).await;
    stop(token, worker).await;
    let result = harness.corpus.rebuild_index().await.unwrap();
    assert_eq!(result["coverage"]["documents"], 2);
    assert_eq!(result["coverage"]["expected_representations"], 4);
    assert_eq!(result["coverage"]["captured_representations"], 4);
    assert_eq!(result["coverage"]["acquisition_complete"], true);
    let found = harness
        .research
        .call("rfc_fulltext_search", json!({"query":"traversalfixture"}))
        .await
        .unwrap();
    assert_eq!(found["total"], 2);
    let numbers = found["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|item| item["number"].as_u64())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(numbers, std::collections::BTreeSet::from([9000, 9001]));
}
