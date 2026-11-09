//! Retained legacy dump compatibility using only a local HTTP fixture.
use super::*;
use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Response, StatusCode},
    routing::get,
};

#[tokio::test]
#[ignore = "requires disposable PostgreSQL; run scripts/test-postgres.sh"]
async fn crate_corpus_captured_inventory_acquisition_research_and_restart_legacy_dump() {
    let base = std::env::var("DEVRES_TEST_DATABASE_URL").expect("disposable PostgreSQL required");
    let admin = sqlx_postgres::PgPool::connect(&base).await.unwrap();
    sqlx_core::query::query("CREATE DATABASE devres_dump_compat_fixture")
        .execute(&admin)
        .await
        .unwrap();
    let mut database = url::Url::parse(&base).unwrap();
    database.set_path("/devres_dump_compat_fixture");
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let store = Arc::new(
        crate::PgBlobStore::connect(database.as_str(), root.path())
            .await
            .unwrap(),
    );
    let requests = Arc::new(AtomicUsize::new(0));
    let counted = requests.clone();
    let router = Router::new().route(
        "/db-dump.tar.gz",
        get(move |headers: HeaderMap| {
            let counted = counted.clone();
            async move {
                assert_eq!(headers.get("if-none-match").unwrap(), "\"legacy\"");
                let position = counted.fetch_add(1, Ordering::SeqCst);
                if position.is_multiple_of(2) {
                    Response::builder()
                        .status(StatusCode::TEMPORARY_REDIRECT)
                        .header(
                            "location",
                            "https://cloudfront-static.crates.io/db-dump.tar.gz",
                        )
                        .body(Body::empty())
                        .unwrap()
                } else if position == 1 {
                    Response::builder()
                        .status(StatusCode::NOT_MODIFIED)
                        .body(Body::empty())
                        .unwrap()
                } else {
                    Response::builder()
                        .status(StatusCode::OK)
                        .header("etag", "\"fresh\"")
                        .body(Body::from("new inert dump fixture"))
                        .unwrap()
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let broker = Arc::new(
        BulkBroker::fixture(url::Url::parse(&format!("http://{address}")).unwrap()).unwrap(),
    );
    let retrieval = Arc::new(Retrieval::new(
        store.clone(),
        Arc::new(crate::crates_io::index::tests::NoNetwork),
    ));
    let corpus = CrateCorpus::new(
        store.clone(),
        retrieval,
        broker,
        root.path(),
        CrateConfig {
            enabled: false,
            min_free_bytes: 64 * 1024 * 1024,
            ..Default::default()
        },
    )
    .unwrap();
    let raw = corpus
        .artifacts
        .capture_bytes(b"old inert dump fixture".to_vec(), CancellationToken::new())
        .await
        .unwrap();
    let old = corpus
        .persist_artifact(
            "cargo:database-dump",
            "https://static.crates.io/db-dump.tar.gz",
            "application/gzip",
            raw,
            json!({"transport":"https","etag":"\"legacy\""}),
            true,
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    let validated = corpus
        .fetch_artifact(
            "cargo:database-dump",
            BulkSource::DatabaseDump,
            None,
            0,
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(validated.capture.id, old.capture.id);
    assert_eq!(validated.capture.source_url, old.capture.source_url);
    assert_eq!(validated.capture.body_hash, old.capture.body_hash);
    tokio::time::sleep(Duration::from_secs(1)).await;
    let fresh = corpus
        .fetch_artifact(
            "cargo:database-dump",
            BulkSource::DatabaseDump,
            None,
            0,
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_ne!(fresh.capture.id, old.capture.id);
    assert_eq!(
        fresh.capture.source_url,
        "https://cloudfront-static.crates.io/db-dump.tar.gz"
    );
    assert_eq!(
        store
            .artifact(&old.capture.id)
            .await
            .unwrap()
            .unwrap()
            .provenance["etag"],
        old.provenance["etag"]
    );
    assert_eq!(requests.load(Ordering::SeqCst), 4);
    server.abort();
    drop(corpus);
    drop(store);
    sqlx_core::query::query("DROP DATABASE devres_dump_compat_fixture WITH(FORCE)")
        .execute(&admin)
        .await
        .unwrap();
}
