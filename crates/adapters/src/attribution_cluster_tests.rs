//! First-party fixture acceptance in the disposable, stopped-writer cluster.
use crate::{AttributionAdapter, PgBlobStore, bulk::BulkBroker};
use async_trait::async_trait;
use devres_application::{
    attribution::AttributionStore,
    attribution_gate::AttributionGate,
    attribution_runtime::{AttributionAcquirer, AttributionRuntime},
};
use devres_domain::{Error, Result, attribution::*};
use serde_json::{Value, json};
use std::{collections::BTreeSet, path::PathBuf, sync::Arc};
use tokio_util::sync::CancellationToken;

const RECEIPT: &str = "/tmp/attribution-backlog-receipt.json";
const ORIGIN_RECEIPT: &str = "/tmp/attribution-origins-v2-receipt.json";
const SOURCE: &str = "https://www.rfc-editor.org/rfc/rfc9000.txt";
const BODY: &str = "First-party synthetic attribution backlog acceptance; not upstream evidence.\n\nCopyright Notice\nCopyright (c) IETF Trust and the persons identified as the document authors. All rights reserved. This synthetic example is authored by dev-resources-MCP contributors under AGPL-3.0-only; it is not a license determination for an RFC. UTF-8 notice: 원문.\n\nTable of Contents\n";

async fn store() -> Arc<PgBlobStore> {
    let database = std::env::var("DATABASE_URL").expect("disposable cluster PostgreSQL");
    let root = PathBuf::from(std::env::var("BLOB_DIR").expect("disposable cluster blob root"));
    let s3 = std::env::var_os("DEVRES_TEST_S3_CONFIG")
        .map(|path| toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap());
    Arc::new(
        PgBlobStore::connect_archive_for_maintenance(&database, &root, s3)
            .await
            .unwrap(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires stopped disposable cluster writer and seeded four-provider corpus"]
async fn attribution_origins_v2_cluster_seed() {
    let store = store().await;
    let receipt = store.seed_attribution_origins_fixture().await;
    std::fs::write(ORIGIN_RECEIPT, serde_json::to_vec(&receipt).unwrap()).unwrap();
    store.readback_attribution_origins_fixture(&receipt).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires stopped disposable cluster writer and retained origins-v2 receipt"]
async fn attribution_origins_v2_cluster_readback() {
    let store = store().await;
    let receipt: Value = serde_json::from_slice(&std::fs::read(ORIGIN_RECEIPT).unwrap()).unwrap();
    store.readback_attribution_origins_fixture(&receipt).await;
}

fn target(key: &str) -> AttributionTarget {
    let value = json!({"source_url":SOURCE,"body_hash":crate::integrity::hash(BODY.as_bytes())});
    let mut target = crate::attribution_providers::targets("rfc", &value)
        .unwrap()
        .pop()
        .unwrap();
    target.evidence["fixture_occurrence"] = json!(key);
    target.subject.namespace = "first-party-backlog-fixture".into();
    target.subject.key = key.into();
    target.subject.fingerprint = crate::integrity::canonical_hash(&target.evidence).unwrap();
    target
}

struct PinnedFixture(AttributionTarget);
#[async_trait]
impl AttributionAcquirer for PinnedFixture {
    fn targets(&self, _: &str, _: &Value) -> Result<Vec<AttributionTarget>> {
        Ok(vec![self.0.clone()])
    }
    async fn repair(
        &self,
        _: &AttributionTarget,
        _: CancellationToken,
    ) -> Result<AttributionGeneration> {
        Err(Error::integrity(
            "Readback must not acquire fixture evidence.",
        ))
    }
}

async fn synthetic_generation(
    adapter: &AttributionAdapter,
    target: &AttributionTarget,
) -> AttributionGeneration {
    let mut generation = adapter
        .repair(target, CancellationToken::new())
        .await
        .unwrap();
    // Exercise real exact-body acquisition, but never represent a loopback fixture
    // as a production upstream validation receipt or rights determination.
    for notice in &mut generation.notices {
        notice.evidence["synthetic"] = json!(true);
    }
    for receipt in &mut generation.receipts {
        receipt["kind"] = json!("synthetic_fixture_validation");
        receipt["synthetic"] = json!(true);
        receipt["source_fingerprint"] = json!(target.subject.fingerprint);
    }
    generation
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires stopped disposable cluster writer, PostgreSQL and optional fixture S3"]
async fn attribution_backlog_cluster_seed() {
    let store = store().await;
    let app = axum::Router::new().fallback(|| async { BODY });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let stop = CancellationToken::new();
    let done = stop.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(done.cancelled_owned())
            .await
            .unwrap();
    });
    let broker = Arc::new(
        BulkBroker::fixture(url::Url::parse(&format!("http://{address}")).unwrap()).unwrap(),
    );
    let adapter = AttributionAdapter::new(broker.clone(), store.clone());
    let enabled = vec!["rfc".into()];
    let now = devres_domain::unix_now();
    let expired = target("expired-foreground");
    store.attribution_enqueue(&expired, 1).await.unwrap();
    let stale = store
        .attribution_claim(&enabled, now - 301, 0)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stale.target, expired);

    let retry = target("due-background");
    store.attribution_enqueue(&retry, 0).await.unwrap();
    let retry_job = store
        .attribution_claim(&enabled, now, 4)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retry_job.target, retry);
    let transient = AttributionFailure::new(
        AttributionPhase::Acquisition,
        AttributionFailureReason::UpstreamUnavailable,
        AttributionDisposition::Retry,
    );
    store
        .attribution_fail_classified(&retry_job, Some(now - 1), "retryable", &transient)
        .await
        .unwrap();

    let future = target("future-foreground");
    store.attribution_enqueue(&future, 1).await.unwrap();
    let future_job = store
        .attribution_claim(&enabled, now, 0)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(future_job.target, future);
    store
        .attribution_fail_classified(&future_job, Some(now + 3600), "retryable", &transient)
        .await
        .unwrap();
    for index in 0..32 {
        store
            .attribution_enqueue(&target(&format!("pending-{index}")), 1)
            .await
            .unwrap();
    }
    let gate = AttributionRuntime::new(
        store.clone(),
        Arc::new(PinnedFixture(retry.clone())),
        vec![],
    )
    .unwrap();
    assert_eq!(
        gate.qualify("audit:rfc", &json!({}))
            .await
            .unwrap_err()
            .code,
        "unavailable"
    );

    let mut repaired = BTreeSet::new();
    let mut representatives = Vec::new();
    for admission in 0..15 {
        let job = store
            .attribution_claim(&enabled, now, admission)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(job.target.subject.namespace, "first-party-backlog-fixture");
        assert_ne!(
            job.target, future,
            "future retry escaped its eligibility fence"
        );
        let generation = synthetic_generation(&adapter, &job.target).await;
        if job.target == expired {
            assert!(
                store
                    .attribution_complete(&stale, &generation)
                    .await
                    .is_err()
            );
        }
        store.attribution_complete(&job, &generation).await.unwrap();
        if job.target == expired || job.target == retry {
            repaired.insert(job.target.subject.key.clone());
            representatives.push(
                store
                    .attribution_ready(&job.target.subject)
                    .await
                    .unwrap()
                    .unwrap(),
            );
        }
    }
    assert_eq!(
        repaired,
        BTreeSet::from([expired.subject.key, retry.subject.key])
    );
    assert!(
        store
            .attribution_ready(&future.subject)
            .await
            .unwrap()
            .is_none()
    );
    // Finish this finite first-party fixture through ordinary fenced transitions.
    // Advancing claim time is confined to this test; no production clock changes.
    for admission in 15..64 {
        let Some(job) = store
            .attribution_claim(&enabled, now + 3601, admission)
            .await
            .unwrap()
        else {
            break;
        };
        let generation = synthetic_generation(&adapter, &job.target).await;
        store.attribution_complete(&job, &generation).await.unwrap();
    }
    assert!(
        store
            .attribution_ready(&future.subject)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        broker.attempt_count(),
        1,
        "immutable fixture bytes were reacquired"
    );
    let encoded = serde_json::to_vec(&representatives).unwrap();
    assert!(encoded.len() <= 32768);
    std::fs::write(RECEIPT, encoded).unwrap();
    stop.cancel();
    server.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires stopped disposable cluster writer and retained fixture receipt"]
async fn attribution_backlog_cluster_readback() {
    let encoded = std::fs::read(RECEIPT).unwrap();
    assert!(encoded.len() <= 32768);
    let expected: Vec<QualifiedAttribution> = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(expected.len(), 2);
    let store = store().await;
    for qualified in expected {
        assert_eq!(qualified.generation.policy_epoch, ATTRIBUTION_POLICY_EPOCH);
        assert_eq!(
            qualified.generation.policy_fingerprint,
            ATTRIBUTION_POLICY_FINGERPRINT
        );
        assert_eq!(
            store
                .attribution_ready(&qualified.generation.subject)
                .await
                .unwrap(),
            Some(qualified.clone())
        );
        assert_eq!(
            store.attribution_bundle(&qualified.id).await.unwrap(),
            qualified
        );
        let target = target(&qualified.generation.subject.key);
        assert_eq!(target.subject, qualified.generation.subject);
        let gate = AttributionRuntime::new(store.clone(), Arc::new(PinnedFixture(target)), vec![])
            .unwrap();
        let mut text = String::new();
        let mut offset = 0;
        loop {
            let page = gate.bundle(&qualified.id, offset, 13).await.unwrap();
            text.push_str(page["contents"][0]["text"].as_str().unwrap());
            let Some(next) = page["contents"][0]["_meta"]["next_offset"].as_u64() else {
                break;
            };
            offset = usize::try_from(next).unwrap();
        }
        let notice = &qualified.generation.notices[0];
        assert_eq!(text, format!("{}\n{}", notice.source_url, notice.text));
        assert!(text.contains("not a license determination"));
        assert_eq!(
            gate.qualify("audit:rfc", &json!({})).await.unwrap()["status"],
            "ready"
        );
    }
}
