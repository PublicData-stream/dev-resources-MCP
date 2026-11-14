//! Real adapter/runtime acceptance against a stopped disposable PostgreSQL writer.
//! Every source request is redirected by cfg(test) code to this loopback fixture.
use super::*;
use crate::{AttributionAdapter, PgBlobStore, Research};
use crate::{RustSecRecoveryOptions, RustSecRecoveryOutcome, recover_rustsec_attribution};
use devres_application::{
    Retrieval,
    advisory::{AdvisoryStore, RustSecConfig},
    attribution::AttributionStore,
    attribution_runtime::AttributionRuntime,
};
use sqlx_core::connection::Connection;
use std::path::PathBuf;

const REV: &str = "dddddddddddddddddddddddddddddddddddddddd";
const ID: &str = "RUSTSEC-2026-9001";
const MEMBER: &str = "crates/example/RUSTSEC-2026-9001.md";
const TERMS: &str = "First-party synthetic RustSec fixture notice by dev-resources-MCP contributors. AGPL-3.0-only. This is not upstream evidence or an upstream licensing determination. 원문\n";
const ADVISORY: &str = "```toml\n[advisory]\nid = 'RUSTSEC-2026-9001'\npackage = 'example'\ndate = '2026-01-01'\nlicense = 'CC-BY-4.0'\nurl = 'https://github.com/advisories/GHSA-synthetic-fixture'\n[versions]\npatched = ['>= 1.0.1']\n```\n\n# Synthetic RustSec collector fixture\n\nFirst-party rustsecfixturebody. Never execute inspected package code.\n";

fn bundle_target(snapshot: &devres_application::advisory::AdvisorySnapshot) -> AttributionTarget {
    let capture = snapshot
        .captures
        .iter()
        .find(|capture| capture.key.starts_with("rustsec:bundle:"))
        .expect("pinned original bundle capture");
    targets(
        "rustsec",
        &crate::research::capture_json(capture, 365 * 86400),
    )
    .unwrap()
    .pop()
    .unwrap()
}

fn recovery_options(target: &AttributionTarget) -> RustSecRecoveryOptions {
    RustSecRecoveryOptions {
        target_id: crate::integrity::canonical_hash(
            &json!({"version":1,"policy_epoch":ATTRIBUTION_POLICY_EPOCH,"subject":target.subject}),
        )
        .unwrap(),
        ..Default::default()
    }
}

async fn compose(
    store: Arc<PgBlobStore>,
    broker: Arc<BulkBroker>,
    root: &std::path::Path,
    reader: bool,
) -> (
    Research,
    Arc<crate::rustsec::AdvisoryCorpus>,
    Arc<AttributionRuntime>,
) {
    let retrieval = Arc::new(Retrieval::new(
        store.clone(),
        Arc::new(crate::HttpFetcher::with_broker(broker.clone()).unwrap()),
    ));
    let config = RustSecConfig {
        enabled: false,
        min_free_bytes: 64 * 1024 * 1024,
        ..Default::default()
    };
    let corpus = Arc::new(if reader {
        crate::rustsec::AdvisoryCorpus::new_reader(
            retrieval.clone(),
            store.clone(),
            broker.clone(),
            root,
            config,
        )
        .unwrap()
    } else {
        crate::rustsec::AdvisoryCorpus::new(
            retrieval.clone(),
            store.clone(),
            broker.clone(),
            root,
            config,
        )
        .unwrap()
    });
    let gate = Arc::new(
        AttributionRuntime::new(
            store.clone(),
            Arc::new(AttributionAdapter::new(broker, store)),
            if reader {
                vec![]
            } else {
                vec!["rustsec".into()]
            },
        )
        .unwrap(),
    );
    let research = Research::new(retrieval)
        .await
        .unwrap()
        .with_advisory_corpus(corpus.clone())
        .with_attribution_gate(gate.clone());
    (research, corpus, gate)
}

async fn pages(research: &Research, uris: &Value) -> BTreeMap<String, String> {
    let mut result = BTreeMap::new();
    for uri in uris.as_array().unwrap() {
        let uri = uri.as_str().unwrap();
        let mut text = String::new();
        let mut offset = 0u64;
        loop {
            let page = research
                .read_resource(&format!("{uri}?offset={offset}&limit=31"))
                .await
                .unwrap();
            text.push_str(page["contents"][0]["text"].as_str().unwrap());
            let Some(next) = page["contents"][0]["_meta"]["next_offset"].as_u64() else {
                break;
            };
            assert!(next > offset);
            offset = next;
        }
        assert!(!text.is_empty());
        result.insert(uri.into(), text);
    }
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires stopped disposable cluster writer, PostgreSQL and optional fixture S3"]
async fn rustsec_collector_cluster_seed() {
    let database = std::env::var("DATABASE_URL").expect("disposable PostgreSQL");
    let root = PathBuf::from(std::env::var("BLOB_DIR").expect("disposable blob root"));
    let archive: Option<crate::object_storage::S3Config> =
        std::env::var_os("DEVRES_TEST_S3_CONFIG")
            .map(|path| toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap());
    let head = serde_json::to_vec(&json!({"sha":REV,"parents":[],"files":[]})).unwrap();
    let bundle = super::tests::archive(REV, &[("LICENSE.txt", TERMS), (MEMBER, ADVISORY)]);
    let responses = Arc::new(BTreeMap::from([
        ("/repos/RustSec/advisory-db/commits/main".to_owned(), head),
        (format!("/RustSec/advisory-db/tar.gz/{REV}"), bundle),
        (
            "/repos/rustsec/advisory-db/contents/LICENSE.txt".to_owned(),
            TERMS.as_bytes().to_vec(),
        ),
        (
            format!("/repos/rustsec/advisory-db/contents/{MEMBER}"),
            ADVISORY.as_bytes().to_vec(),
        ),
    ]));
    let app = axum::Router::new().fallback(move |uri: http::Uri| {
        let responses = responses.clone();
        async move {
            match responses.get(uri.path()) {
                Some(body) => (http::StatusCode::OK, body.clone()),
                None => (http::StatusCode::NOT_FOUND, Vec::new()),
            }
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server_stop = CancellationToken::new();
    let done = server_stop.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(done.cancelled_owned())
            .await
            .unwrap()
    });
    let broker = Arc::new(
        BulkBroker::fixture(url::Url::parse(&format!("http://{address}")).unwrap())
            .unwrap()
            .with_attempt_budget(20)
            .unwrap(),
    );
    let (selected_snapshot, selected_recovery) = {
        let store = Arc::new(
            PgBlobStore::connect_archive_for_maintenance(&database, &root, archive.clone())
                .await
                .unwrap(),
        );
        let (_research, corpus, _gate) = compose(store.clone(), broker.clone(), &root, false).await;
        let refreshed = corpus.refresh_current().await.unwrap();
        let snapshot = refreshed["snapshot"]["id"].as_str().unwrap().to_owned();
        let retained = store
            .advisory_snapshot(Some(&snapshot), "rustsec")
            .await
            .unwrap()
            .unwrap();
        let target = bundle_target(&retained);
        let options = recovery_options(&target);
        store.attribution_enqueue(&target, 1).await.unwrap();
        // The normal claim API has provider/status queues. Refuse this fixture
        // before claiming if its indexed foreground head is unrelated work.
        let mut check = sqlx_postgres::PgConnection::connect(&database)
            .await
            .unwrap();
        sqlx_core::query::query("SET default_transaction_read_only=on")
            .execute(&mut check)
            .await
            .unwrap();
        let next:Option<String>=sqlx_core::query_scalar::query_scalar("SELECT id FROM devres_attribution_targets WHERE policy_epoch=$1 AND provider='rustsec' AND status='pending' AND priority=1 AND retry_at<=$2 ORDER BY retry_at,id LIMIT 1")
            .bind(i32::try_from(ATTRIBUTION_POLICY_EPOCH).unwrap()).bind(devres_domain::unix_now()).fetch_optional(&mut check).await.unwrap();
        assert_eq!(
            next.as_deref(),
            Some(options.target_id.as_str()),
            "refuse to claim unrelated fixture queue work"
        );
        drop(check);
        let job = store
            .attribution_claim(&["rustsec".into()], devres_domain::unix_now(), 0)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(job.target, target);
        store
            .attribution_fail_classified(
                &job,
                None,
                "blocked",
                &AttributionFailure::new(
                    AttributionPhase::Mapping,
                    AttributionFailureReason::UnsupportedSource,
                    AttributionDisposition::Blocked,
                ),
            )
            .await
            .unwrap();
        (snapshot, options)
    };
    // Exercise the production maintenance API only after every publication
    // owner has dropped. The journal retains this exact original blocked state.
    let dry = recover_rustsec_attribution(&database, &selected_recovery, false)
        .await
        .unwrap();
    assert_eq!(dry.outcome, RustSecRecoveryOutcome::Eligible);
    let selected_recovery = RustSecRecoveryOptions {
        expected_state: Some(dry.state_digest),
        ..selected_recovery
    };
    let applied = recover_rustsec_attribution(&database, &selected_recovery, true)
        .await
        .unwrap();
    assert_eq!(applied.outcome, RustSecRecoveryOutcome::Applied);
    let (snapshot, expected_get, expected_catalog, expected_notices) = {
        let store = Arc::new(
            PgBlobStore::connect_archive_for_maintenance(&database, &root, archive.clone())
                .await
                .unwrap(),
        );
        let (research, _corpus, gate) = compose(store.clone(), broker.clone(), &root, false).await;
        let snapshot = selected_snapshot;
        assert!(
            store
                .advisory_snapshot(Some(&snapshot), "rustsec")
                .await
                .unwrap()
                .unwrap()
                .complete
        );
        let arguments = json!({"snapshot":snapshot,"limit":1,"filters":{"id":ID}});
        assert_eq!(
            research
                .call("packages.crate.advisory_catalog_search", arguments.clone())
                .await
                .unwrap_err()
                .code,
            "unavailable"
        );
        let stop = CancellationToken::new();
        let task_stop = stop.clone();
        let runtime = gate.clone();
        let worker = tokio::spawn(async move { runtime.run(task_stop).await });
        let catalogue = tokio::time::timeout(Duration::from_secs(45), async {
            loop {
                if let Ok(value) = research
                    .call("packages.crate.advisory_catalog_search", arguments.clone())
                    .await
                {
                    break value;
                }
                assert!(
                    !worker.is_finished(),
                    "synthetic repair worker stopped before qualification"
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("bounded actual attribution repair");
        let detail = research
            .call(
                "packages.crate.advisory_get",
                json!({"snapshot":snapshot,"id":ID,"limit":4096}),
            )
            .await
            .unwrap();
        assert_eq!(detail["page"]["text"], ADVISORY);
        assert_eq!(catalogue["items"][0]["id"], ID);
        assert!(
            detail["attribution"]["readable_notice"]
                .as_str()
                .unwrap()
                .contains("GHSA-synthetic-fixture")
        );
        let notice_pages = pages(&research, &detail["attribution"]["resource_uris"]).await;
        assert!(
            notice_pages
                .values()
                .any(|text| text.contains(TERMS.trim()))
        );
        for generation in detail["attribution"]["generations"].as_array().unwrap() {
            let qualified = store
                .attribution_bundle(generation["id"].as_str().unwrap())
                .await
                .unwrap();
            assert!(
                qualified
                    .generation
                    .notices
                    .iter()
                    .all(|notice| notice.evidence["synthetic"] == true)
            );
        }
        let retained = store
            .advisory_snapshot(Some(&snapshot), "rustsec")
            .await
            .unwrap()
            .unwrap();
        assert!(
            store
                .attribution_ready(&bundle_target(&retained).subject)
                .await
                .unwrap()
                .is_some()
        );
        let journal = recover_rustsec_attribution(&database, &selected_recovery, false).await;
        assert!(
            journal.is_err(),
            "maintenance owner excludes concurrent inspector lifecycle lock"
        );
        stop.cancel();
        worker.await.unwrap().unwrap();
        (snapshot, detail, catalogue, notice_pages)
    };
    // Reopen through the reader composition after dropping every writer handle.
    let attempts = broker.attempt_count();
    let reader_archive = std::env::var_os("DEVRES_TEST_S3_READER_CONFIG")
        .map(|path| toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap())
        .or(archive);
    {
        let store = Arc::new(
            PgBlobStore::connect_reader(&database, &root, reader_archive)
                .await
                .unwrap(),
        );
        let (research, _corpus, _gate) = compose(store, broker.clone(), &root, true).await;
        let detail = research
            .call(
                "packages.crate.advisory_get",
                json!({"snapshot":snapshot,"id":ID,"limit":4096}),
            )
            .await
            .unwrap();
        let catalogue = research
            .call(
                "packages.crate.advisory_catalog_search",
                json!({"snapshot":snapshot,"limit":1,"filters":{"id":ID}}),
            )
            .await
            .unwrap();
        assert_eq!(detail, expected_get);
        assert_eq!(catalogue, expected_catalog);
        assert_eq!(
            pages(&research, &detail["attribution"]["resource_uris"]).await,
            expected_notices
        );
        let resource = research
            .read_resource(detail["resource_uri"].as_str().unwrap())
            .await
            .unwrap();
        assert_eq!(resource["contents"][0]["text"], ADVISORY);
        assert!(resource["contents"].as_array().unwrap().len() > 1);
    }
    assert_eq!(
        broker.attempt_count(),
        attempts,
        "read-only restart acquired provider evidence"
    );
    assert!(attempts <= 20);
    let receipt = json!({"provider":"rustsec","tool":"packages.crate.advisory_get","arguments":{"snapshot":snapshot,"id":ID,"limit":4096},"resource":expected_get["resource_uri"],"expected":"rustsecfixturebody"});
    std::fs::write(
        "/tmp/rustsec-collector-receipt.json",
        serde_json::to_vec(&receipt).unwrap(),
    )
    .unwrap();
    server_stop.cancel();
    server.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires stopped disposable cluster writer and retained RustSec receipt"]
async fn rustsec_collector_cluster_readback() {
    let database = std::env::var("DATABASE_URL").expect("disposable PostgreSQL");
    let root = PathBuf::from(std::env::var("BLOB_DIR").expect("disposable blob root"));
    let encoded = std::fs::read("/tmp/rustsec-collector-receipt.json").unwrap();
    assert!(encoded.len() <= 4096);
    let receipt: Value = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(receipt["provider"], "rustsec");
    assert_eq!(receipt["tool"], "packages.crate.advisory_get");
    assert_eq!(receipt["arguments"]["id"], ID);
    let snapshot = receipt["arguments"]["snapshot"].as_str().unwrap();
    assert_eq!(
        receipt["resource"],
        format!("devres://advisory/rustsec/{ID}/{snapshot}")
    );
    let archive = std::env::var_os("DEVRES_TEST_S3_READER_CONFIG")
        .or_else(|| std::env::var_os("DEVRES_TEST_S3_CONFIG"))
        .map(|path| toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap());
    let store = PgBlobStore::connect_reader(&database, &root, archive)
        .await
        .unwrap();
    let retained = store
        .advisory_snapshot(Some(snapshot), "rustsec")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retained.id, snapshot);
    assert_eq!(retained.revision, REV);
    assert_eq!(
        retained
            .records
            .iter()
            .find(|record| record.id == ID)
            .unwrap()
            .body,
        ADVISORY
    );
    let target = bundle_target(&retained);
    let qualified = store
        .attribution_ready(&target.subject)
        .await
        .unwrap()
        .expect("recovered bundle remains ready");
    assert_eq!(qualified.generation.subject, target.subject);
    let journal = recover_rustsec_attribution(&database, &recovery_options(&target), false)
        .await
        .unwrap();
    assert_eq!(journal.outcome, RustSecRecoveryOutcome::AlreadyApplied);
    assert!(!journal.eligible);
    assert_eq!(
        store
            .advisory_snapshot(Some(snapshot), "rustsec")
            .await
            .unwrap()
            .unwrap()
            .id,
        snapshot
    );
    // No broker, fetcher, listener, writer or synthetic qualification is created.
}
