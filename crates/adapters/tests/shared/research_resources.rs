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
async fn zip_captures_never_become_generic_text_resources() {
    let captured = StoredCapture {
        capture: Capture {
            id: "c".repeat(64),
            key: "cargo:docs-html:synthetic:1.0.0".into(),
            source_url: "https://fixtures.invalid/documentation.zip".into(),
            body_hash: "d".repeat(64),
            media_type: "application/zip".into(),
            retrieved_at: 0,
            validated_at: 0,
        },
        body: [b'P', b'K', 5, 6]
            .into_iter()
            .chain([0; 18])
            .collect::<Vec<_>>()
            .into(),
    };
    assert!(std::str::from_utf8(&captured.body).is_ok());
    let research = Research::new(Arc::new(Retrieval::new(
        Arc::new(PublicFixture(captured)),
        Arc::new(NoNetwork),
    )))
    .await
    .unwrap();
    let uri = format!("devres://capture/{}", "c".repeat(64));
    assert_eq!(
        research.read_resource(&uri).await.unwrap_err().code,
        "invalid_input"
    );
    assert_eq!(
        research
            .call("fetch", json!({"id":uri}))
            .await
            .unwrap_err()
            .code,
        "invalid_input"
    );
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

struct FixtureGate {
    deny: bool,
    seen: std::sync::Mutex<Vec<(String, serde_json::Value)>>,
}
#[async_trait]
impl devres_application::attribution_gate::AttributionGate for FixtureGate {
    async fn qualify(
        &self,
        provider: &str,
        evidence: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        self.seen
            .lock()
            .unwrap()
            .push((provider.to_owned(), evidence.clone()));
        if self.deny {
            return Err(Error::unavailable(
                "Required attribution repair is pending.",
            ));
        }
        Ok(
            json!({"readable_notice":"Fixture authors; original license applies.",
            "resource_uri":format!("devres://attribution/{}", "e".repeat(64)),
            "generations":[]}),
        )
    }
    async fn bundle(&self, id: &str, offset: usize, limit: usize) -> Result<serde_json::Value> {
        Ok(
            json!({"contents":[{"uri":format!("devres://attribution/{id}"),"mimeType":"text/plain","text":"fixture notice"}],"offset":offset,"limit":limit}),
        )
    }
    async fn status(&self) -> Result<serde_json::Value> {
        Ok(json!({"ready":1,"pending":0}))
    }
}
fn capture_fixture() -> StoredCapture {
    StoredCapture {
        capture: Capture {
            id: "a".repeat(64),
            key: "rfc:text:9000".into(),
            source_url: "https://www.rfc-editor.org/rfc/rfc9000.txt".into(),
            body_hash: "b".repeat(64),
            media_type: "text/plain".into(),
            retrieved_at: 0,
            validated_at: 0,
        },
        body: b"abcdef".to_vec().into(),
    }
}
async fn gated_research(deny: bool) -> (Research, Arc<FixtureGate>) {
    let gate = Arc::new(FixtureGate {
        deny,
        seen: std::sync::Mutex::new(Vec::new()),
    });
    let research = Research::new(Arc::new(Retrieval::new(
        Arc::new(PublicFixture(capture_fixture())),
        Arc::new(NoNetwork),
    )))
    .await
    .unwrap()
    .with_attribution_gate(gate.clone());
    (research, gate)
}
#[tokio::test]
async fn resource_and_fetch_both_gate_exact_evidence_without_changing_page_bytes() {
    let (research, gate) = gated_research(false).await;
    let uri = format!("devres://capture/{}?offset=1&limit=2", "a".repeat(64));
    for use_fetch in [false, true] {
        let output = if use_fetch {
            research.call("fetch", json!({"id":uri})).await.unwrap()
        } else {
            research.read_resource(&uri).await.unwrap()
        };
        assert_eq!(output["contents"][0]["text"], "bc");
        assert_eq!(output["contents"][0]["mimeType"], "text/plain");
        assert_eq!(
            output["contents"][1]["text"],
            "Fixture authors; original license applies."
        );
        assert_eq!(
            output["contents"][0]["_meta"]["attribution"]["resource_uri"],
            output["attribution"]["resource_uri"]
        );
        assert!(
            output["contents"][0]["_meta"]["attribution"]
                .get("readable_notice")
                .is_none()
        );
    }
    let seen = gate.seen.lock().unwrap();
    assert_eq!(
        seen.len(),
        2,
        "fetch must not bypass or duplicate qualification"
    );
    assert!(seen.iter().all(|(provider, value)| provider == "capture"
        && value["contents"][0]["_meta"]["source_evidence"]["capture"]["body_hash"]
            == "b".repeat(64)));
}
#[tokio::test]
async fn unavailable_attribution_blocks_every_capture_fetch_path() {
    let (research, gate) = gated_research(true).await;
    let uri = format!("devres://capture/{}", "a".repeat(64));
    assert_eq!(
        research.read_resource(&uri).await.unwrap_err().code,
        "unavailable"
    );
    assert_eq!(
        research
            .call("fetch", json!({"id":uri}))
            .await
            .unwrap_err()
            .code,
        "unavailable"
    );
    assert_eq!(gate.seen.lock().unwrap().len(), 2);
}
#[tokio::test]
async fn complete_notice_resources_validate_selectors_and_preserve_paging() {
    let (research, gate) = gated_research(false).await;
    let uri = format!("devres://attribution/{}?offset=5&limit=16", "e".repeat(64));
    let output = research.read_resource(&uri).await.unwrap();
    assert_eq!(output["offset"], 5);
    assert_eq!(output["limit"], 16);
    assert!(
        gate.seen.lock().unwrap().is_empty(),
        "notice reads must not recursively enqueue source repair"
    );
    for query in ["limit=0", "limit=32769", "offset=1&offset=2", "unknown=1"] {
        let invalid = format!("devres://attribution/{}?{query}", "e".repeat(64));
        assert_eq!(
            research.read_resource(&invalid).await.unwrap_err().code,
            "invalid_input"
        );
    }
    assert!(
        research
            .read_resource("devres://attribution/not-an-id")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn capture_fixed_tool_content_is_qualified_before_publication() {
    for deny in [false, true] {
        let (research, gate) = gated_research(deny).await;
        let output = research
            .call(
                "rfc.get",
                json!({"number":9000,"capture":"a".repeat(64),"offset":2,"limit":2}),
            )
            .await;
        if deny {
            assert_eq!(output.unwrap_err().code, "unavailable");
        } else {
            let output = output.unwrap();
            assert_eq!(output["page"]["text"], "cd");
            assert_eq!(output["page"]["offset"], 2);
            assert_eq!(
                output["attribution"]["readable_notice"],
                "Fixture authors; original license applies."
            );
        }
        let seen = gate.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, "rfc");
        assert_eq!(seen[0].1["capture"]["id"], "a".repeat(64));
    }
}

struct LargeNoticeGate;
#[async_trait]
impl devres_application::attribution_gate::AttributionGate for LargeNoticeGate {
    async fn qualify(&self, _: &str, _: &serde_json::Value) -> Result<serde_json::Value> {
        let notice = "N".repeat(50 * 1024);
        Ok(
            json!({"status":"ready","policy_epoch":1,"resource_uri":format!("devres://attribution/{}","e".repeat(64)),"readable_notice":notice,
            "generations":[{"id":"public-generation","notices":[{"source_url":"https://fixtures.invalid/notice","license":"fixture-only","copyright":"Fixture authors","text":notice}]}]}),
        )
    }
    async fn bundle(&self, _: &str, _: usize, _: usize) -> Result<serde_json::Value> {
        Err(Error::not_found("Not needed by this fixture."))
    }
    async fn status(&self) -> Result<serde_json::Value> {
        Ok(json!({}))
    }
}
#[tokio::test]
async fn long_required_notice_fits_without_duplicate_text_in_resource_metadata() {
    let mut capture = capture_fixture();
    capture.body = vec![b'x'; 32768].into();
    let research = Research::new(Arc::new(Retrieval::new(
        Arc::new(PublicFixture(capture)),
        Arc::new(NoNetwork),
    )))
    .await
    .unwrap()
    .with_attribution_gate(Arc::new(LargeNoticeGate));
    let output = research
        .read_resource(&format!("devres://capture/{}", "a".repeat(64)))
        .await
        .unwrap();
    assert_eq!(output["contents"][0]["text"].as_str().unwrap().len(), 32768);
    assert_eq!(
        output["contents"][1]["text"].as_str().unwrap().len(),
        50 * 1024
    );
    assert_eq!(
        output["attribution"]["generations"][0]["notices"][0]["text"]
            .as_str()
            .unwrap()
            .len(),
        50 * 1024
    );
    let notice = &output["contents"][0]["_meta"]["attribution"]["generations"][0]["notices"][0];
    assert_eq!(notice["copyright"], "Fixture authors");
    assert!(notice.get("text").is_none());
    assert!(serde_json::to_vec(&output).unwrap().len() < 256 * 1024);
}
