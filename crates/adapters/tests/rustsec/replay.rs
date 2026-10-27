//! Offline full-snapshot replay. The operator supplies the two bounded public captures.
use async_trait::async_trait;
use devres_adapters::Research;
use devres_application::{Cached, Fetcher, Retrieval, Store};
use devres_domain::{
    Capture, Error, FetchRequest, FetchResponse, Result, StoredCapture, Validators,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;

#[derive(Default)]
struct Memory(Mutex<HashMap<String, Cached>>);
#[async_trait]
impl Store for Memory {
    async fn latest(&self, key: &str) -> Result<Option<Cached>> {
        Ok(self.0.lock().await.get(key).cloned())
    }
    async fn capture(&self, id: &str) -> Result<StoredCapture> {
        self.0
            .lock()
            .await
            .values()
            .find(|cached| cached.stored.capture.id == id)
            .map(|cached| cached.stored.clone())
            .ok_or_else(|| Error::not_found("Replay capture absent."))
    }
    async fn publish(
        &self,
        request: &FetchRequest,
        response: FetchResponse,
        now: i64,
    ) -> Result<StoredCapture> {
        let hash = hex::encode(Sha256::digest(&response.body));
        let stored = StoredCapture {
            capture: Capture {
                id: hash.clone(),
                key: request.key.clone(),
                source_url: request.url.clone(),
                body_hash: hash,
                media_type: request.media_type.clone(),
                retrieved_at: now,
                validated_at: now,
            },
            body: response.body.into(),
        };
        self.0.lock().await.insert(
            request.key.clone(),
            Cached {
                stored: stored.clone(),
                validators: response.validators,
            },
        );
        Ok(stored)
    }
    async fn revalidate(&self, _: &str, _: &str, _: Validators, _: i64) -> Result<StoredCapture> {
        Err(Error::integrity("Replay does not revalidate."))
    }
}
struct Captures {
    head: Vec<u8>,
    bundle: Vec<u8>,
    revision: String,
}
#[async_trait]
impl Fetcher for Captures {
    async fn fetch(&self, request: &FetchRequest, _: Option<&Validators>) -> Result<FetchResponse> {
        let body = if request.url == "https://api.github.com/repos/RustSec/advisory-db/commits/main"
        {
            self.head.clone()
        } else if request.url
            == format!(
                "https://codeload.github.com/RustSec/advisory-db/tar.gz/{}",
                self.revision
            )
        {
            self.bundle.clone()
        } else {
            return Err(Error::invalid("Unexpected offline replay source."));
        };
        Ok(FetchResponse {
            status: 200,
            body,
            validators: Validators::default(),
        })
    }
}

#[tokio::test]
#[ignore = "requires operator-supplied public captures; DEVRES_RUSTSEC_REPLAY_DIR points to head.json and bundle.tar.gz, no network"]
async fn official_snapshot_replays_through_research_without_network() {
    let root = std::path::PathBuf::from(
        std::env::var_os("DEVRES_RUSTSEC_REPLAY_DIR")
            .expect("Set the local public capture directory."),
    );
    let head = std::fs::read(root.join("head.json")).unwrap();
    let bundle = std::fs::read(root.join("bundle.tar.gz")).unwrap();
    assert!(head.len() <= 4 * 1024 * 1024 && bundle.len() <= 32 * 1024 * 1024);
    let metadata: serde_json::Value = serde_json::from_slice(&head).unwrap();
    let revision = metadata["sha"].as_str().unwrap().to_owned();
    let research = Research::new(Arc::new(Retrieval::new(
        Arc::new(Memory::default()),
        Arc::new(Captures {
            head,
            bundle,
            revision: revision.clone(),
        }),
    )))
    .await
    .unwrap();
    research.refresh_advisories().await.unwrap();
    let result = research
        .call("advisory.lookup", json!({"name":"itoa","version":"1.0.15"}))
        .await
        .unwrap();
    assert_eq!(result["complete"], true);
    assert_eq!(result["snapshot"]["revision"], revision);
}
