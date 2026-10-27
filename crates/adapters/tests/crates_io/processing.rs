//! Synthetic public registry evidence; no provider access or package execution.
use async_trait::async_trait;
use devres_adapters::Research;
use devres_application::{Cached, Clock, Fetcher, Retrieval, Store};
use devres_domain::{
    Capture, Error, FetchRequest, FetchResponse, Result, StoredCapture, Validators,
};
use flate2::{Compression, write::GzEncoder};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    io::Write,
    sync::{
        Arc,
        atomic::{AtomicI64, AtomicUsize, Ordering},
    },
};
use tokio::sync::{Mutex, Notify};

static SERIAL: Mutex<()> = Mutex::const_new(());

fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[derive(Default)]
struct State {
    heads: HashMap<String, Cached>,
    captures: HashMap<String, StoredCapture>,
    publications: usize,
    revalidations: usize,
}

#[derive(Default)]
struct MemoryStore(Mutex<State>);

#[async_trait]
impl Store for MemoryStore {
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
            .ok_or_else(|| Error::not_found("Fixture absent."))
    }
    async fn publish(
        &self,
        request: &FetchRequest,
        response: FetchResponse,
        now: i64,
    ) -> Result<StoredCapture> {
        let stored = StoredCapture {
            capture: Capture {
                id: hash(format!("{}:{}", request.key, hash(&response.body)).as_bytes()),
                key: request.key.clone(),
                source_url: request.url.clone(),
                body_hash: hash(&response.body),
                media_type: request.media_type.clone(),
                retrieved_at: now,
                validated_at: now,
            },
            body: response.body.into(),
        };
        let mut state = self.0.lock().await;
        state.publications += 1;
        state
            .captures
            .insert(stored.capture.id.clone(), stored.clone());
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
        _: Validators,
        now: i64,
    ) -> Result<StoredCapture> {
        let mut state = self.0.lock().await;
        state.revalidations += 1;
        let cached = state
            .heads
            .get_mut(key)
            .ok_or_else(|| Error::not_found("Fixture absent."))?;
        assert_eq!(cached.stored.capture.id, id);
        cached.stored.capture.validated_at = now;
        Ok(cached.stored.clone())
    }
}

struct TestClock(AtomicI64);
impl Clock for TestClock {
    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

#[derive(Default)]
struct FixtureFetcher {
    responses: Mutex<HashMap<String, (u16, Vec<u8>)>>,
    calls: AtomicUsize,
    gate: Mutex<Option<Arc<Notify>>>,
    started: Notify,
}
impl FixtureFetcher {
    async fn set(&self, key: &str, status: u16, body: Vec<u8>) {
        self.responses
            .lock()
            .await
            .insert(key.into(), (status, body));
    }
}
#[async_trait]
impl Fetcher for FixtureFetcher {
    async fn fetch(&self, request: &FetchRequest, _: Option<&Validators>) -> Result<FetchResponse> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let gate = self.gate.lock().await.take();
        if let Some(gate) = gate {
            self.started.notify_one();
            gate.notified().await;
        }
        tokio::task::yield_now().await;
        let (status, body) = self
            .responses
            .lock()
            .await
            .get(&request.key)
            .cloned()
            .ok_or_else(|| Error::integrity("Unexpected fixture request."))?;
        Ok(FetchResponse {
            status,
            body,
            validators: Validators {
                etag: Some("fixture-etag".into()),
                last_modified: None,
            },
        })
    }
}

async fn fixture() -> (
    Arc<Research>,
    Arc<MemoryStore>,
    Arc<FixtureFetcher>,
    Arc<TestClock>,
) {
    let store = Arc::new(MemoryStore::default());
    let fetcher = Arc::new(FixtureFetcher::default());
    let clock = Arc::new(TestClock(AtomicI64::new(devres_domain::unix_now())));
    let research = Arc::new(
        Research::new(Arc::new(Retrieval::with_clock(
            store.clone(),
            fetcher.clone(),
            clock.clone(),
        )))
        .await
        .unwrap(),
    );
    (research, store, fetcher, clock)
}

fn row(version: &str, checksum: &str) -> Value {
    json!({"name":"example","vers":version,"deps":[],"cksum":checksum,"features":{},"yanked":false})
}
fn search_page(start: usize, count: usize, total: usize) -> Vec<u8> {
    serde_json::to_vec(&json!({"crates":(start..start+count).map(|index| json!({"name":format!("example{index}"),"max_version":"1.0.0","description":"Synthetic fixture"})).collect::<Vec<_>>(),"meta":{"total":total}})).unwrap()
}

fn archive(files: &[(&str, &[u8])], link: bool) -> Vec<u8> {
    let mut tar = tar::Builder::new(Vec::new());
    for (path, bytes) in files {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        if link {
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_link_name("../../secret").unwrap();
        }
        header.set_size(if link { 0 } else { bytes.len() as u64 });
        header.set_cksum();
        tar.append_data(
            &mut header,
            format!("example-1.0.0/{path}"),
            if link { &[][..] } else { bytes },
        )
        .unwrap();
    }
    let mut gzip = GzEncoder::new(Vec::new(), Compression::fast());
    gzip.write_all(&tar.into_inner().unwrap()).unwrap();
    gzip.finish().unwrap()
}

#[tokio::test]
async fn search_validates_whole_provider_page_before_publication_and_pins_boundaries() {
    let _serial = SERIAL.lock().await;
    let (research, store, fetcher, clock) = fixture().await;
    let key = "cargo:search:fixture:1";
    let mut malformed: Value = serde_json::from_slice(&search_page(0, 2, 102)).unwrap();
    malformed["crates"][1]["max_version"] = json!("not-a-version");
    fetcher
        .set(key, 200, serde_json::to_vec(&malformed).unwrap())
        .await;
    let error = research
        .call("crate.search", json!({"query":"fixture","limit":1}))
        .await
        .unwrap_err();
    assert_eq!(error.code, "integrity");
    assert_eq!(store.0.lock().await.publications, 0);

    fetcher.set(key, 200, search_page(0, 100, 102)).await;
    let first = research
        .call(
            "crate.search",
            json!({"query":"fixture","offset":99,"limit":20}),
        )
        .await
        .unwrap();
    assert_eq!(first["items"].as_array().unwrap().len(), 1);
    assert_eq!(first["next_offset"], 100);
    let capture = first["capture"]["id"].as_str().unwrap();
    let calls = fetcher.calls.load(Ordering::SeqCst);
    let pinned = research
        .call(
            "crate.search",
            json!({"query":"fixture","capture":capture,"offset":98,"limit":2}),
        )
        .await
        .unwrap();
    assert_eq!(pinned["items"][0]["name"], "example98");
    assert_eq!(fetcher.calls.load(Ordering::SeqCst), calls);
    assert_eq!(
        research
            .call(
                "crate.search",
                json!({"query":"fixture","capture":capture,"offset":100})
            )
            .await
            .unwrap_err()
            .code,
        "invalid_input"
    );

    fetcher
        .set("cargo:search:fixture:2", 200, search_page(100, 2, 102))
        .await;
    let next = research
        .call("crate.search", json!({"query":"fixture","offset":100}))
        .await
        .unwrap();
    assert_eq!(next["items"][0]["name"], "example100");
    assert!(next["next_offset"].is_null());

    clock.0.fetch_add(3601, Ordering::SeqCst);
    fetcher.set(key, 200, b"not json".to_vec()).await;
    assert_eq!(
        research
            .call("crate.search", json!({"query":"fixture"}))
            .await
            .unwrap_err()
            .code,
        "integrity"
    );
    assert_eq!(store.0.lock().await.heads[key].stored.capture.id, capture);
}

#[tokio::test]
async fn index_validates_every_version_and_preserves_modern_metadata() {
    let _serial = SERIAL.lock().await;
    let (research, store, fetcher, _) = fixture().await;
    let mut modern = row("1.0.0", &"a".repeat(64));
    modern["v"] = json!(2);
    modern["features2"] = json!({"std":["dep:renamed","renamed?/std"]});
    modern["rust_version"] = json!("1.60");
    modern["deps"] = json!([{"name":"renamed","package":"original","req":"^1.2","features":["alloc"],"optional":true,"default_features":false,"target":"cfg(unix)","kind":"build","registry":"https://example.invalid/index"}]);
    modern["future_additive_field"] = json!({"retained":true});
    let mut invalid = row("2.0.0", "wrong-checksum");
    for second in [&invalid, &modern] {
        let body = format!("{}\n{}\n", modern, second).into_bytes();
        fetcher.set("cargo:index:example", 200, body).await;
        assert_eq!(
            research
                .call(
                    "crate.metadata",
                    json!({"name":"example","version":"1.0.0"})
                )
                .await
                .unwrap_err()
                .code,
            "integrity"
        );
        assert_eq!(store.0.lock().await.publications, 0);
    }
    invalid["cksum"] = json!("b".repeat(64));
    invalid["deps"] = json!([{"name":"other","req":"^1","features":[],"optional":false,"default_features":"false"}]);
    fetcher
        .set(
            "cargo:index:example",
            200,
            format!("{modern}\n{invalid}\n").into_bytes(),
        )
        .await;
    assert_eq!(
        research
            .call(
                "crate.metadata",
                json!({"name":"example","version":"1.0.0"})
            )
            .await
            .unwrap_err()
            .code,
        "integrity"
    );
    fetcher
        .set("cargo:index:example", 200, modern.to_string().into_bytes())
        .await;
    let result = research
        .call(
            "crate.metadata",
            json!({"name":"example","version":"1.0.0"}),
        )
        .await
        .unwrap();
    assert_eq!(result["metadata"], modern);
    assert_eq!(
        research
            .call("fetch", json!({"id":"crate:example@1.0.0"}))
            .await
            .unwrap()["metadata"],
        modern
    );
}

#[tokio::test]
async fn verified_archive_resources_remain_fixed_and_invalid_archives_never_publish() {
    let _serial = SERIAL.lock().await;
    let (research, store, fetcher, clock) = fixture().await;
    let bytes = archive(
        &[
            ("src/lib.rs", "héllo source".as_bytes()),
            ("README.md", b"Synthetic"),
        ],
        false,
    );
    let checksum = hash(&bytes);
    let key = format!("cargo:archive:example:1.0.0:{checksum}");
    fetcher
        .set(
            "cargo:index:example",
            200,
            row("1.0.0", &checksum).to_string().into_bytes(),
        )
        .await;
    fetcher.set(&key, 200, b"corrupt archive".to_vec()).await;
    assert_eq!(
        research
            .call(
                "crate.source_list",
                json!({"name":"example","version":"1.0.0"})
            )
            .await
            .unwrap_err()
            .code,
        "integrity"
    );
    assert!(!store.0.lock().await.heads.contains_key(&key));

    fetcher.set(&key, 200, bytes).await;
    let listing = research
        .call(
            "crate.source_list",
            json!({"name":"example","version":"1.0.0"}),
        )
        .await
        .unwrap();
    let metadata = listing["metadata_capture"]["id"].as_str().unwrap();
    let archive_id = listing["archive_capture"]["id"].as_str().unwrap();
    let source = research.call("crate.source_read", json!({"name":"example","version":"1.0.0","path":"src/lib.rs","metadata_capture":metadata,"archive_capture":archive_id,"offset":1,"limit":2})).await.unwrap();
    assert_eq!(source["page"]["text"], "é");
    let uri = source["resource_uri"].as_str().unwrap();
    let before = fetcher.calls.load(Ordering::SeqCst);
    assert_eq!(
        research.read_resource(uri).await.unwrap()["contents"][0]["text"],
        "é"
    );
    assert_eq!(
        research.call("fetch", json!({"id":uri})).await.unwrap()["contents"][0]["text"],
        "é"
    );
    assert_eq!(fetcher.calls.load(Ordering::SeqCst), before);

    clock.0.fetch_add(3601, Ordering::SeqCst);
    let hostile = archive(&[("src/lib.rs", b"")], true);
    let hostile_checksum = hash(&hostile);
    let hostile_key = format!("cargo:archive:example:1.0.0:{hostile_checksum}");
    fetcher
        .set(
            "cargo:index:example",
            200,
            row("1.0.0", &hostile_checksum).to_string().into_bytes(),
        )
        .await;
    fetcher.set(&hostile_key, 200, hostile).await;
    assert_eq!(
        research
            .call(
                "crate.source_list",
                json!({"name":"example","version":"1.0.0"})
            )
            .await
            .unwrap_err()
            .code,
        "integrity"
    );
    assert!(!store.0.lock().await.heads.contains_key(&hostile_key));
    assert_eq!(
        research.read_resource(uri).await.unwrap()["contents"][0]["text"],
        "é"
    );
}

#[tokio::test]
async fn warm_hits_revalidation_stale_fallback_and_coalescing_use_existing_policy() {
    let _serial = SERIAL.lock().await;
    let (research, store, fetcher, clock) = fixture().await;
    let key = "cargo:index:example";
    fetcher
        .set(
            key,
            200,
            row("1.0.0", &"a".repeat(64)).to_string().into_bytes(),
        )
        .await;
    let input = json!({"name":"example","version":"1.0.0"});
    let (first, second) = tokio::join!(
        research.call("crate.metadata", input.clone()),
        research.call("crate.metadata", input.clone())
    );
    let first = first.unwrap();
    assert_eq!(first["capture"]["id"], second.unwrap()["capture"]["id"]);
    assert_eq!(fetcher.calls.load(Ordering::SeqCst), 1);
    clock.0.fetch_add(3601, Ordering::SeqCst);
    fetcher.set(key, 304, Vec::new()).await;
    assert_eq!(
        research
            .call("crate.metadata", input.clone())
            .await
            .unwrap()["capture"]["id"],
        first["capture"]["id"]
    );
    assert_eq!(store.0.lock().await.revalidations, 1);
    clock.0.fetch_add(3601, Ordering::SeqCst);
    fetcher.set(key, 503, Vec::new()).await;
    assert!(research.call("crate.metadata", input.clone()).await.is_ok());
    clock.0.fetch_add(7 * 86400, Ordering::SeqCst);
    assert_eq!(
        research
            .call("crate.metadata", input)
            .await
            .unwrap_err()
            .code,
        "unavailable"
    );
}

#[tokio::test]
async fn malformed_caller_inputs_fail_without_provider_access() {
    let _serial = SERIAL.lock().await;
    let (research, _, fetcher, _) = fixture().await;
    for input in [
        json!({"name":"example","version":"1.0.0","path":"../secret"}),
        json!({"name":"example","version":"1.0.0","path":"src/lib.rs","limit":0}),
        json!({"name":"example","version":"1.0.0","path":"src/lib.rs","offset":4194305}),
        json!({"name":"example","version":"1.0.0","path":"src/lib.rs","metadata_capture":"a".repeat(64)}),
    ] {
        assert_eq!(
            research
                .call("crate.source_read", input)
                .await
                .unwrap_err()
                .code,
            "invalid_input"
        );
    }
    assert_eq!(fetcher.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn canceling_an_owner_releases_admission_and_allows_waiters_to_retry() {
    let _serial = SERIAL.lock().await;
    let (research, store, fetcher, _) = fixture().await;
    fetcher
        .set(
            "cargo:index:example",
            200,
            row("1.0.0", &"a".repeat(64)).to_string().into_bytes(),
        )
        .await;
    *fetcher.gate.lock().await = Some(Arc::new(Notify::new()));
    let owner = {
        let research = research.clone();
        tokio::spawn(async move {
            research
                .call(
                    "crate.metadata",
                    json!({"name":"example","version":"1.0.0"}),
                )
                .await
        })
    };
    fetcher.started.notified().await;
    owner.abort();
    assert!(owner.await.unwrap_err().is_cancelled());
    assert_eq!(store.0.lock().await.publications, 0);
    let input = json!({"name":"example","version":"1.0.0"});
    let (first, second) = tokio::join!(
        research.call("crate.metadata", input.clone()),
        research.call("crate.metadata", input)
    );
    assert!(first.is_ok());
    assert!(second.is_ok());
    assert_eq!(fetcher.calls.load(Ordering::SeqCst), 2);
    assert_eq!(store.0.lock().await.publications, 1);
}

#[tokio::test]
async fn imported_git_metadata_and_archive_pairs_support_network_free_source_resources() {
    let _serial = SERIAL.lock().await;
    let (research, store, fetcher, clock) = fixture().await;
    let bytes = archive(&[("src/lib.rs", b"captured Git-index provenance")], false);
    let checksum = hash(&bytes);
    let revision = "a".repeat(40);
    let metadata = store
        .publish(
            &FetchRequest {
                key: format!("cargo:git-index:example:{revision}"),
                url: format!(
                    "https://github.com/rust-lang/crates.io-index/blob/{revision}/ex/am/example"
                ),
                ttl_secs: 3600,
                max_bytes: 16 * 1024 * 1024,
                media_type: "text/plain".into(),
            },
            FetchResponse {
                status: 200,
                body: row("1.0.0", &checksum).to_string().into_bytes(),
                validators: Validators::default(),
            },
            clock.now(),
        )
        .await
        .unwrap();
    let archive = store
        .publish(
            &FetchRequest {
                key: format!("cargo:archive:example:1.0.0:{checksum}"),
                url: "https://static.crates.io/crates/example/example-1.0.0.crate".into(),
                ttl_secs: 365 * 86400,
                max_bytes: 32 * 1024 * 1024,
                media_type: "application/gzip".into(),
            },
            FetchResponse {
                status: 200,
                body: bytes,
                validators: Validators::default(),
            },
            clock.now(),
        )
        .await
        .unwrap();
    let metadata_result = research
        .call(
            "crate.metadata",
            json!({"name":"example","version":"1.0.0","capture":metadata.capture.id}),
        )
        .await
        .unwrap();
    assert_eq!(
        metadata_result["capture"]["source_url"],
        metadata.capture.source_url
    );
    let listing=research.call("crate.source_list",json!({"name":"example","version":"1.0.0","metadata_capture":metadata.capture.id,"archive_capture":archive.capture.id})).await.unwrap();
    let uri = listing["files"][0]["resource_uri"].as_str().unwrap();
    assert_eq!(
        research.read_resource(uri).await.unwrap()["contents"][0]["text"],
        "captured Git-index provenance"
    );
    assert_eq!(
        research.call("fetch", json!({"id":uri})).await.unwrap()["contents"][0]["text"],
        "captured Git-index provenance"
    );
    assert_eq!(fetcher.calls.load(Ordering::SeqCst), 0);
}
