//! Synthetic route fixture: the obsolete RFC index path returns a real 404 status.
use async_trait::async_trait;
use devres_adapters::Research;
use devres_application::{Cached, Fetcher, Retrieval, Store};
use devres_domain::{
    Capture, Error, FetchRequest, FetchResponse, Result, StoredCapture, Validators,
};
use serde_json::json;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Default)]
struct Memory(Mutex<Option<Cached>>);
#[async_trait]
impl Store for Memory {
    async fn latest(&self, _: &str) -> Result<Option<Cached>> {
        Ok(self.0.lock().await.clone())
    }
    async fn capture(&self, id: &str) -> Result<StoredCapture> {
        self.0
            .lock()
            .await
            .as_ref()
            .filter(|cached| cached.stored.capture.id == id)
            .map(|cached| cached.stored.clone())
            .ok_or_else(|| Error::not_found("Synthetic capture absent."))
    }
    async fn publish(
        &self,
        request: &FetchRequest,
        response: FetchResponse,
        now: i64,
    ) -> Result<StoredCapture> {
        let stored = StoredCapture {
            capture: Capture {
                id: "a".repeat(64),
                key: request.key.clone(),
                source_url: request.url.clone(),
                body_hash: "b".repeat(64),
                media_type: request.media_type.clone(),
                retrieved_at: now,
                validated_at: now,
            },
            body: response.body.into(),
        };
        *self.0.lock().await = Some(Cached {
            stored: stored.clone(),
            validators: response.validators,
        });
        Ok(stored)
    }
    async fn revalidate(&self, _: &str, _: &str, _: Validators, _: i64) -> Result<StoredCapture> {
        Err(Error::integrity("Fixture does not revalidate."))
    }
}

struct RouteFixture(Arc<Mutex<Vec<String>>>);
#[async_trait]
impl Fetcher for RouteFixture {
    async fn fetch(&self, request: &FetchRequest, _: Option<&Validators>) -> Result<FetchResponse> {
        self.0.lock().await.push(request.url.clone());
        let (status, body) = if request.url == "https://www.rfc-editor.org/rfc-index.xml" {
            (200,br#"<rfc-index xmlns="https://www.rfc-editor.org/rfc-index"><rfc-entry><doc-id>RFC9000</doc-id><title>QUIC: A UDP-Based Multiplexed and Secure Transport</title><abstract><p>Synthetic fixture for multiplexed transport.</p></abstract><current-status>PROPOSED STANDARD</current-status></rfc-entry></rfc-index>"#.to_vec())
        } else {
            (404, b"No index exists at this synthetic route.".to_vec())
        };
        Ok(FetchResponse {
            status,
            body,
            validators: Validators::default(),
        })
    }
}

#[tokio::test]
async fn rfc_search_retrieves_canonical_index_and_reuses_captured_page() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let fetcher = Arc::new(RouteFixture(calls.clone()));
    let obsolete = fetcher
        .fetch(
            &FetchRequest {
                key: "fixture:obsolete".into(),
                url: "https://www.rfc-editor.org/in-notes/rfc-index.xml".into(),
                ttl_secs: 86400,
                max_bytes: 1024,
                media_type: "application/xml".into(),
            },
            None,
        )
        .await
        .unwrap();
    assert_eq!(obsolete.status, 404);
    let research = Research::new(Arc::new(Retrieval::new(
        Arc::new(Memory::default()),
        fetcher,
    )))
    .await
    .unwrap();
    let result = research
        .call(
            "rfc_search",
            json!({"query":"multiplexed","status":"PROPOSED STANDARD"}),
        )
        .await
        .unwrap();
    assert_eq!(result["total"], 1);
    assert_eq!(result["items"][0]["id"], "rfc:9000");
    assert_eq!(
        result["capture"]["source_url"],
        "https://www.rfc-editor.org/rfc-index.xml"
    );
    let next = research
        .call(
            "rfc_search",
            json!({"query":"multiplexed","capture":result["capture"]["id"],"offset":1}),
        )
        .await
        .unwrap();
    assert!(next["items"].as_array().unwrap().is_empty());
    assert_eq!(calls.lock().await.len(), 2); // One deliberate wrong route, one real adapter request.
}
