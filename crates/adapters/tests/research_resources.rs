use async_trait::async_trait;
use devres_adapters::Research;
use devres_application::{Cached, Fetcher, Retrieval, Store};
use devres_domain::{
    Capture, Error, FetchRequest, FetchResponse, Result, StoredCapture, Validators,
};
use serde_json::json;
use std::sync::Arc;

struct PublicFixture(StoredCapture);
#[async_trait]
impl Store for PublicFixture {
    async fn latest(&self, _: &str) -> Result<Option<Cached>> {
        Ok(None)
    }
    async fn capture(&self, id: &str) -> Result<StoredCapture> {
        if id == self.0.capture.id {
            Ok(self.0.clone())
        } else {
            Err(Error::not_found("Fixture absent."))
        }
    }
    async fn publish(&self, _: &FetchRequest, _: FetchResponse, _: i64) -> Result<StoredCapture> {
        Err(Error::integrity("No fixture writes are allowed."))
    }
    async fn revalidate(&self, _: &str, _: &str, _: Validators, _: i64) -> Result<StoredCapture> {
        Err(Error::integrity("No fixture revalidation is allowed."))
    }
}
struct NoNetwork;
#[async_trait]
impl Fetcher for NoNetwork {
    async fn fetch(&self, _: &FetchRequest, _: Option<&Validators>) -> Result<FetchResponse> {
        Err(Error::integrity(
            "Resource reads must not access any provider.",
        ))
    }
}

#[tokio::test]
async fn generic_fetch_preserves_embedded_page_and_applies_explicit_overrides() {
    let captured = StoredCapture {
        capture: Capture {
            id: "a".repeat(64),
            key: "synthetic:public".into(),
            source_url: "https://fixture.invalid/source".into(),
            body_hash: "b".repeat(64),
            media_type: "text/plain".into(),
            retrieved_at: 0,
            validated_at: 0,
        },
        body: b"abcdef".to_vec().into(),
    };
    let research = Research::new(Arc::new(Retrieval::new(
        Arc::new(PublicFixture(captured)),
        Arc::new(NoNetwork),
    )))
    .await
    .unwrap();
    let uri = format!("devres://capture/{}?offset=1&limit=2", "a".repeat(64));
    let unchanged = research.call("fetch", json!({"id":uri})).await.unwrap();
    assert_eq!(unchanged["contents"][0]["text"], "bc");
    let overridden = research
        .call("fetch", json!({"id":uri,"offset":3}))
        .await
        .unwrap();
    assert_eq!(overridden["contents"][0]["text"], "de");
    let changed_limit = research
        .call("fetch", json!({"id":uri,"limit":1}))
        .await
        .unwrap();
    assert_eq!(changed_limit["contents"][0]["text"], "b");
    assert!(
        research
            .call("fetch", json!({"id":uri,"offset":100}))
            .await
            .is_err()
    );
}
