//! Synthetic acquisition through the production collector; no provider requests.
use super::*;
use axum::{Json, Router, extract::Query, http::StatusCode, routing::get};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const SPEC: &str = "devres-collector-fixture";
const TOKEN: &str = "devrescollectorquartz";
const BODY: &str = "<h1>Synthetic collector report</h1><p class=copyright>Copyright 2026 W3C <a href='https://www.w3.org/copyright/document-license-2023/'>Document License</a></p><h2 id=collector>Collector</h2><p>devrescollectorquartz preserves immutable acquisition evidence.</p>";

fn collector_routes() -> Router {
    collector_routes_with_failure(Arc::new(AtomicBool::new(false)))
}
fn collector_routes_with_failure(failed: Arc<AtomicBool>) -> Router {
    Router::new()
        .route("/specifications", get(move || { let failed=failed.clone(); async move {
            if failed.load(Ordering::SeqCst) { (StatusCode::BAD_GATEWAY,Json(json!({}))) }
            else { (StatusCode::OK,Json(json!({"_links":{"specifications":[{"shortname":SPEC,"title":"Synthetic collector report"}]}}))) }
        } }))
        .route("/specifications/devres-collector-fixture", get(|| async { Json(json!({"shortname":SPEC,"title":"Synthetic collector report"})) }))
        .route("/TR/", get(|| async { "<h3><a href='/TR/devres-collector-fixture/'>Synthetic collector report</a></h3>" }))
        .route("/browser-specs/index.json", get(|| async { Json(json!([])) }))
        .route("/TR/devres-collector-fixture/", get(|| async { BODY }))
}

#[tokio::test]
async fn catalog_checkpoint_resumes_failed_page_and_preserves_oldest_observation() {
    let first_requests = Arc::new(AtomicUsize::new(0));
    let second_fails = Arc::new(AtomicBool::new(true));
    let counter = first_requests.clone();
    let fail = second_fails.clone();
    let app = Router::new().route("/specifications", get(move |Query(query): Query<BTreeMap<String,String>>| {
        let counter = counter.clone(); let fail = fail.clone();
        async move {
            let page = query.get("page").unwrap().as_str();
            if page == "1" {
                counter.fetch_add(1, Ordering::SeqCst);
                (StatusCode::OK, Json(json!({"_links":{"specifications":[{"shortname":"first","title":"First"}],"next":{"href":"https://api.w3.org/specifications?page=2&items=100"}}})))
            } else if fail.load(Ordering::SeqCst) {
                (StatusCode::SERVICE_UNAVAILABLE, Json(json!({})))
            } else {
                (StatusCode::OK, Json(json!({"_links":{"specifications":[{"shortname":"second","title":"Second"}]}})))
            }
        }
    }));
    let (broker, server) = crate::w3c::git::tests::serve_fixture(app).await;
    let (root, store, corpus) = super::tests::corpus_fixture(broker.clone()).await;
    assert!(
        corpus
            .catalog_step(CancellationToken::new())
            .await
            .unwrap()
            .is_none()
    );
    assert!(store.w3c_state("catalog").await.unwrap().is_none());
    let checkpoint = store.w3c_state("catalog-work").await.unwrap().unwrap();
    let id = checkpoint["pages"][0].as_str().unwrap();
    let oldest = store
        .w3c_get("catalog-pages", id)
        .await
        .unwrap()
        .unwrap()
        .data["observed_at"]
        .as_i64()
        .unwrap();
    assert_eq!(
        corpus
            .catalog_step(CancellationToken::new())
            .await
            .unwrap_err()
            .code,
        "unavailable"
    );
    assert_eq!(
        store.w3c_state("catalog-work").await.unwrap().unwrap(),
        checkpoint
    );
    drop(corpus);
    second_fails.store(false, Ordering::SeqCst);
    let restarted = W3cCorpus::new(
        store.clone(),
        broker,
        root.path(),
        W3cConfig {
            min_free_bytes: 64 * 1024 * 1024,
            ..Default::default()
        },
    )
    .unwrap();
    let catalog = restarted
        .catalog_step(CancellationToken::new())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(catalog.observed_at, oldest);
    assert_eq!(catalog.standards.len(), 2);
    assert_eq!(first_requests.load(Ordering::SeqCst), 1);
    restarted
        .verify_catalog_discovery(CancellationToken::new())
        .await
        .unwrap();
    assert!(
        store
            .w3c_state("catalog-work")
            .await
            .unwrap()
            .unwrap()
            .is_null()
    );
    server.abort();
}

#[tokio::test]
async fn production_collector_publishes_licensed_fixture_and_keeps_failed_refresh() {
    let _gate = crate::mdn::index::TEST_GATE.lock().await;
    let failed = Arc::new(AtomicBool::new(false));
    let (broker, server) =
        crate::w3c::git::tests::serve_fixture(collector_routes_with_failure(failed.clone())).await;
    let observed = broker.clone();
    let (_root, store, corpus) = super::tests::corpus_fixture(broker).await;
    corpus.current_step(CancellationToken::new()).await.unwrap();
    let old = corpus.view(None).await.unwrap();
    let snapshot = corpus
        .snapshot(old.snapshots.get(SPEC).unwrap())
        .await
        .unwrap();
    assert!(snapshot.coverage["usable"].as_bool().unwrap());
    assert_eq!(snapshot.coverage["license"]["decision"], "approved");
    let status = corpus.status().await.unwrap();
    assert_eq!(status["collector"]["catalog"]["progress"]["pages"], 1);
    assert!(status["collector"]["current"]["last_success_at"].is_i64());
    let mut stale = corpus.catalog().await.unwrap();
    stale.id = inventory::digest(b"synthetic older published collector catalog");
    stale.observed_at -= 7200;
    store
        .w3c_put("catalogs", &stale.id, &encode(&stale).unwrap())
        .await
        .unwrap();
    store
        .w3c_set_state("catalog", &json!(stale.id))
        .await
        .unwrap();
    failed.store(true, Ordering::SeqCst);
    corpus.current_step(CancellationToken::new()).await.unwrap();
    assert_eq!(corpus.view(None).await.unwrap().snapshots, old.snapshots);
    assert!(corpus.status().await.unwrap()["collector"]["catalog"]["retry_at"].is_i64());
    let attempts = observed.attempt_count();
    corpus.current_step(CancellationToken::new()).await.unwrap();
    assert_eq!(
        observed.attempt_count(),
        attempts,
        "refresh retry backoff must preserve provider admission"
    );
    // A malformed retained selector must fail explicitly rather than turn into an empty catalog.
    store
        .w3c_set_state("catalog", &json!("missing-catalog"))
        .await
        .unwrap();
    assert_eq!(corpus.update_status().await.unwrap_err().code, "integrity");
    assert_eq!(corpus.view(None).await.unwrap().snapshots, old.snapshots);
    server.abort();
}

#[tokio::test]
async fn invalid_catalog_preserves_failed_generation_and_published_catalog() {
    let app = Router::new().route(
        "/specifications",
        get(|| async {
            Json(
                json!({"_links":{"specifications":[{"shortname":"../invalid","title":"Invalid"}]}}),
            )
        }),
    );
    let (broker, server) = crate::w3c::git::tests::serve_fixture(app).await;
    let (_root, store, corpus) = super::tests::corpus_fixture(broker).await;
    assert_eq!(
        corpus
            .catalog_step(CancellationToken::new())
            .await
            .unwrap_err()
            .code,
        "integrity"
    );
    assert_eq!(
        store
            .w3c_rows("catalog-failures", 0, 100, None)
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(
        store
            .w3c_state("catalog-work")
            .await
            .unwrap()
            .unwrap()
            .is_null()
    );
    assert!(store.w3c_state("catalog").await.unwrap().is_none());
    server.abort();
}

#[tokio::test]
async fn disabled_writer_restart_resets_activity_without_reader_writes_or_history_loss() {
    let broker = Arc::new(BulkBroker::new(Default::default()).unwrap());
    let (root, store, corpus) = super::tests::corpus_fixture(broker.clone()).await;
    let mut expected = BTreeMap::new();
    for lane in ["catalog", "current", "history"] {
        let mut status = CollectorStatus::default();
        status.progress(ProgressKind::Pages, 3);
        status.succeed(11);
        status.fail(
            &Error::unavailable("Synthetic prior failure."),
            Phase::CatalogAcquisition,
            20,
            Some(80),
        );
        status.begin(Phase::CatalogAcquisition);
        let value = encode(&status).unwrap();
        store
            .w3c_set_state(&format!("collector-{lane}"), &value)
            .await
            .unwrap();
        expected.insert(lane, value);
    }
    let config = W3cConfig {
        enabled: false,
        min_free_bytes: 64 * 1024 * 1024,
        ..Default::default()
    };
    let reader =
        W3cCorpus::new_reader(store.clone(), broker.clone(), root.path(), config.clone()).unwrap();
    assert!(reader.initialize_status().await.is_err());
    for (lane, value) in &expected {
        assert_eq!(
            store
                .w3c_state(&format!("collector-{lane}"))
                .await
                .unwrap()
                .as_ref(),
            Some(value)
        );
    }
    drop(reader);
    drop(corpus);
    let restarted = W3cCorpus::new(store.clone(), broker.clone(), root.path(), config).unwrap();
    restarted.initialize_status().await.unwrap();
    assert_eq!(
        restarted.status().await.unwrap()["collection_enabled"],
        false
    );
    for (lane, mut value) in expected {
        value["active"] = json!(false);
        assert_eq!(
            store.w3c_state(&format!("collector-{lane}")).await.unwrap(),
            Some(value)
        );
    }
    assert_eq!(broker.attempt_count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires stopped disposable minikube roles and DATABASE_URL/BLOB_DIR"]
async fn w3c_collector_cluster_seed() {
    use devres_application::attribution::AttributionStore;
    use devres_domain::attribution::*;
    let _gate = crate::mdn::index::TEST_GATE.lock().await;
    let root = PathBuf::from(std::env::var("BLOB_DIR").expect("owned fixture BLOB_DIR"));
    let database = std::env::var("DATABASE_URL").expect("owned fixture DATABASE_URL");
    let archive = match std::env::var("DEVRES_TEST_S3_CONFIG") {
        Ok(path) => {
            let bytes = std::fs::read(path).unwrap();
            assert!(bytes.len() <= 64 * 1024);
            Some(toml::from_str(std::str::from_utf8(&bytes).unwrap()).unwrap())
        }
        Err(std::env::VarError::NotPresent) => None,
        Err(error) => panic!("fixture configuration unavailable: {error}"),
    };
    let store = Arc::new(
        crate::PgBlobStore::connect_archive(&database, &root, archive)
            .await
            .unwrap(),
    );
    let (broker, server) = crate::w3c::git::tests::serve_fixture(collector_routes()).await;
    let corpus = Arc::new(
        W3cCorpus::new(
            store.clone(),
            broker,
            &root,
            W3cConfig {
                enabled: false,
                min_free_bytes: 64 * 1024 * 1024,
                ..Default::default()
            },
        )
        .unwrap(),
    );
    corpus
        .acquire_catalog(CancellationToken::new())
        .await
        .unwrap();
    corpus.current_step(CancellationToken::new()).await.unwrap();
    let selected = corpus.select(SPEC, None, None).await.unwrap();
    let arguments = json!({"specification":SPEC,"snapshot":selected.id,"representation":"text"});
    let research = crate::w3c::research::W3cResearch::new(corpus.clone());
    let value = research.call("w3c.get", arguments.clone()).await.unwrap();
    assert!(serde_json::to_string(&value).unwrap().contains(TOKEN));
    let uri = value["resource_uri"].as_str().unwrap().to_owned();
    let resource = research.read_resource(&uri).await.unwrap();
    let mut targets = BTreeMap::new();
    for response in [&value, &resource] {
        for target in crate::attribution_providers::targets("w3c", response).unwrap() {
            targets.insert(serde_json::to_string(&target.subject).unwrap(), target);
        }
    }
    assert!(!targets.is_empty());
    for target in targets.values() {
        store.attribution_enqueue(target, 1).await.unwrap();
    }
    for _ in 0..1024 {
        if targets.is_empty() {
            break;
        }
        let now = devres_domain::unix_now();
        let job = store
            .attribution_claim(&["w3c".into()], now)
            .await
            .unwrap()
            .expect("synthetic attribution job");
        let key = serde_json::to_string(&job.target.subject).unwrap();
        let Some(target) = targets.remove(&key) else {
            store
                .attribution_fail(&job, Some(now + 300), "fixture_deferred")
                .await
                .unwrap();
            continue;
        };
        let notice = "First-party synthetic collector acceptance fixture, AGPL-3.0-only; not upstream licensing evidence.";
        let generation = AttributionGeneration {
            subject: target.subject,
            policy_epoch: ATTRIBUTION_POLICY_EPOCH,
            policy_fingerprint: ATTRIBUTION_POLICY_FINGERPRINT.into(),
            notices: vec![AttributionNotice {
                source_url: "https://fixtures.invalid/devres/collector".into(),
                license: Some("AGPL-3.0-only".into()),
                copyright: Some("dev-resources-MCP synthetic fixture authors".into()),
                text: notice.into(),
                evidence: json!({"synthetic":true,"fixture":"w3c-collector-v1"}),
            }],
            receipts: vec![
                json!({"kind":"synthetic_fixture_validation","synthetic":true,"status":200,"source_url":"https://fixtures.invalid/devres/collector","body_hash":crate::integrity::hash(notice.as_bytes()),"validated_at":now,"policy_epoch":ATTRIBUTION_POLICY_EPOCH,"policy_fingerprint":ATTRIBUTION_POLICY_FINGERPRINT,"source_fingerprint":job.target.subject.fingerprint}),
            ],
        };
        store.attribution_complete(&job, &generation).await.unwrap();
    }
    assert!(targets.is_empty(), "synthetic attribution claim bound");
    let receipt = json!({"provider":"w3c","tool":"w3c.get","arguments":arguments,"resource":uri,"expected":TOKEN});
    std::fs::write(
        "/tmp/w3c-collector-receipt.json",
        serde_json::to_vec(&receipt).unwrap(),
    )
    .unwrap();
    server.abort();
}
