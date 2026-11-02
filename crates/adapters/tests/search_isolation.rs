//! Generic search composition against synthetic provider responses only.
use async_trait::async_trait;
use devres_adapters::{Research, npm::NpmPackages};
use devres_application::{Cached, Fetcher, Retrieval, Store};
use devres_domain::{
    Capture, Error, FetchRequest, FetchResponse, Result, StoredCapture, Validators,
};
use serde_json::json;
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Mutex, Notify};

static SERIAL: Mutex<()> = Mutex::const_new(());
const NPM_KEY: &str = "npm:search:fixture:0";
const CARGO_KEY: &str = "cargo:search:fixture:1";

#[derive(Default)]
struct MemoryStore(Mutex<HashMap<String, StoredCapture>>);

#[async_trait]
impl Store for MemoryStore {
    async fn latest(&self, _: &str) -> Result<Option<Cached>> {
        Ok(None)
    }

    async fn capture(&self, id: &str) -> Result<StoredCapture> {
        self.0
            .lock()
            .await
            .get(id)
            .cloned()
            .ok_or_else(|| Error::not_found("Fixture capture absent."))
    }

    async fn publish(
        &self,
        request: &FetchRequest,
        response: FetchResponse,
        now: i64,
    ) -> Result<StoredCapture> {
        let body_hash = format!("blake3:{}", blake3::hash(&response.body));
        let id = format!(
            "blake3:{}",
            blake3::hash(format!("{}:{body_hash}", request.key).as_bytes())
        );
        let stored = StoredCapture {
            capture: Capture {
                id: id.clone(),
                key: request.key.clone(),
                source_url: request.url.clone(),
                body_hash,
                media_type: request.media_type.clone(),
                retrieved_at: now,
                validated_at: now,
            },
            body: response.body.into(),
        };
        self.0.lock().await.insert(id, stored.clone());
        Ok(stored)
    }

    async fn revalidate(&self, _: &str, id: &str, _: Validators, _: i64) -> Result<StoredCapture> {
        self.capture(id).await
    }
}

struct FixtureFetcher {
    responses: HashMap<String, (u16, Vec<u8>)>,
    calls: Mutex<Vec<String>>,
}

#[async_trait]
impl Fetcher for FixtureFetcher {
    async fn fetch(&self, request: &FetchRequest, _: Option<&Validators>) -> Result<FetchResponse> {
        self.calls.lock().await.push(request.key.clone());
        let (status, body) = self
            .responses
            .get(&request.key)
            .cloned()
            .ok_or_else(|| Error::integrity("Unexpected fixture provider dispatch."))?;
        Ok(FetchResponse {
            status,
            body,
            validators: Validators::default(),
        })
    }
}

fn cargo_response() -> Vec<u8> {
    serde_json::to_vec(&json!({"crates":[{"name":"fixture","max_version":"1.0.0","description":"Synthetic sibling success"}],"meta":{"total":1}})).unwrap()
}

async fn fixture(npm: (u16, Vec<u8>)) -> (Research, Arc<MemoryStore>, Arc<FixtureFetcher>) {
    let store = Arc::new(MemoryStore::default());
    let fetcher = Arc::new(FixtureFetcher {
        responses: HashMap::from([
            (NPM_KEY.into(), npm),
            (CARGO_KEY.into(), (200, cargo_response())),
            ("rfc:index".into(), (200, br#"<rfc-index><rfc-entry><doc-id>RFC9000</doc-id><title>Synthetic fixture protocol</title></rfc-entry></rfc-index>"#.to_vec())),
        ]),
        calls: Mutex::new(Vec::new()),
    });
    let research = Research::new(Arc::new(Retrieval::new(store.clone(), fetcher.clone())))
        .await
        .unwrap();
    (research, store, fetcher)
}

async fn assert_isolated(npm: (u16, Vec<u8>), expected: &str) {
    let (research, store, fetcher) = fixture(npm).await;
    let result = research
        .call(
            "search",
            json!({"query":"fixture","sources":["npm","cargo","w3c"],"limit":1}),
        )
        .await
        .unwrap();
    let rows = result["sources"].as_array().unwrap();
    assert_eq!(
        rows.iter()
            .map(|row| row["source"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["npm", "cargo", "w3c"]
    );
    assert!(
        rows[0]["error"]
            .as_str()
            .unwrap()
            .starts_with(&format!("{expected}:"))
    );
    assert!(rows[0].get("result").is_none());
    assert_eq!(rows[1]["result"]["items"][0]["name"], "fixture");
    assert!(
        rows[2]["error"]
            .as_str()
            .unwrap()
            .starts_with("unavailable:")
    );
    let calls = fetcher.calls.lock().await;
    assert_eq!(calls.len(), 2);
    assert_eq!(
        calls.iter().filter(|key| key.as_str() == NPM_KEY).count(),
        1
    );
    assert_eq!(
        calls.iter().filter(|key| key.as_str() == CARGO_KEY).count(),
        1
    );
    let captures = store.0.lock().await;
    assert_eq!(
        captures.len(),
        1,
        "failed npm responses must not become captures"
    );
    assert_eq!(captures.values().next().unwrap().capture.key, CARGO_KEY);
}

#[tokio::test]
async fn upstream_npm_failure_statuses_preserve_healthy_sibling_results() {
    let _serial = SERIAL.lock().await;
    // Fetcher is the post-HTTP-attempt boundary: generic composition must not add
    // retries to the HTTP adapter's existing one-retry ownership.
    for status in [429, 503] {
        let (research, store, fetcher) = fixture((status, Vec::new())).await;
        let result = research
            .call(
                "search",
                json!({"query":"fixture","sources":["npm"],"limit":1}),
            )
            .await
            .unwrap();
        assert_eq!(result["sources"].as_array().unwrap().len(), 1);
        assert_eq!(result["sources"][0]["source"], "npm");
        assert!(
            result["sources"][0]["error"]
                .as_str()
                .unwrap()
                .starts_with("unavailable:")
        );
        assert_eq!(fetcher.calls.lock().await.as_slice(), [NPM_KEY]);
        assert!(store.0.lock().await.is_empty());
        assert_isolated((status, Vec::new()), "unavailable").await;
    }
}

#[tokio::test]
async fn malformed_and_oversized_npm_search_bodies_are_source_local() {
    let _serial = SERIAL.lock().await;
    assert_isolated((200, b"malformed registry response".to_vec()), "integrity").await;
    assert_isolated((200, vec![b' '; 2 * 1024 * 1024 + 1]), "capacity").await;
    assert_isolated(
        (
            200,
            br#"{"objects":[],"total":0,"extra":{"duplicate":1,"duplicate":2}}"#.to_vec(),
        ),
        "integrity",
    )
    .await;
}

#[tokio::test]
async fn omitted_sources_dispatch_only_rfc_and_cargo() {
    let _serial = SERIAL.lock().await;
    let (research, _, fetcher) = fixture((503, Vec::new())).await;
    let result = research
        .call("search", json!({"query":"fixture","limit":1}))
        .await
        .unwrap();
    assert_eq!(result["sources"][0]["source"], "rfc");
    assert_eq!(result["sources"][0]["result"]["items"][0]["id"], "rfc:9000");
    assert_eq!(result["sources"][1]["source"], "cargo");
    assert_eq!(
        result["sources"][1]["result"]["items"][0]["name"],
        "fixture"
    );
    assert_eq!(result["sources"].as_array().unwrap().len(), 2);
    let mut calls = fetcher.calls.lock().await.clone();
    calls.sort();
    assert_eq!(calls, [CARGO_KEY, "rfc:index"]);
}

#[tokio::test]
async fn explicit_mdn_selection_never_falls_back_to_remote_npm_or_defaults() {
    let _serial = SERIAL.lock().await;
    let (research, store, fetcher) = fixture((503, Vec::new())).await;
    // No MDN corpus is configured, so its explicit unavailability is the only
    // result; absence must not dispatch a fallback provider.
    let result = research
        .call("search", json!({"query":"fixture","sources":["mdn"]}))
        .await
        .unwrap();
    assert_eq!(result["sources"].as_array().unwrap().len(), 1);
    assert_eq!(result["sources"][0]["source"], "mdn");
    assert!(
        result["sources"][0]["error"]
            .as_str()
            .unwrap()
            .starts_with("unavailable:")
    );
    assert!(fetcher.calls.lock().await.is_empty());
    assert!(store.0.lock().await.is_empty());
}

struct HoldingFetcher {
    calls: AtomicUsize,
    occupied: Notify,
}

#[async_trait]
impl Fetcher for HoldingFetcher {
    async fn fetch(&self, _: &FetchRequest, _: Option<&Validators>) -> Result<FetchResponse> {
        if self.calls.fetch_add(1, Ordering::SeqCst) + 1 == 2 {
            self.occupied.notify_one();
        }
        std::future::pending().await
    }
}

#[tokio::test]
async fn exhausted_npm_parser_admission_returns_a_source_error_before_fetching() {
    let _serial = SERIAL.lock().await;
    let fetcher = Arc::new(HoldingFetcher {
        calls: AtomicUsize::new(0),
        occupied: Notify::new(),
    });
    let retrieval = Arc::new(Retrieval::new(
        Arc::new(MemoryStore::default()),
        fetcher.clone(),
    ));
    let packages = Arc::new(NpmPackages::new(retrieval.clone()));
    let first = packages.clone();
    let first = tokio::spawn(async move {
        first
            .call("npm.search", json!({"query":"occupied-first"}))
            .await
    });
    let second = packages.clone();
    let second = tokio::spawn(async move {
        second
            .call("npm.search", json!({"query":"occupied-second"}))
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), fetcher.occupied.notified())
        .await
        .unwrap();
    let research = Research::new(retrieval).await.unwrap();
    let result = research
        .call("search", json!({"query":"fixture","sources":["npm"]}))
        .await;
    first.abort();
    second.abort();
    assert!(first.await.unwrap_err().is_cancelled());
    assert!(second.await.unwrap_err().is_cancelled());
    let result = result.unwrap();
    assert_eq!(result["sources"][0]["source"], "npm");
    assert!(
        result["sources"][0]["error"]
            .as_str()
            .unwrap()
            .starts_with("capacity:")
    );
    assert_eq!(fetcher.calls.load(Ordering::SeqCst), 2);
}
