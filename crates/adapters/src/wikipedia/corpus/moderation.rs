//! Interleaved upstream I/O and moderation regression fixtures. No live traffic.
use super::*;
use std::sync::atomic::{AtomicBool, AtomicU64};
use tokio::sync::Notify;

#[derive(Default)]
struct BlockingProvider {
    revision: AtomicU64,
    pause_html: AtomicBool,
    oversized: AtomicBool,
    entered: Notify,
    release: Notify,
}
async fn blocking_handle(
    AxumState(provider): AxumState<Arc<BlockingProvider>>,
    uri: Uri,
) -> HttpResponse {
    let revision = provider.revision.load(Ordering::SeqCst);
    let value = if uri.path() == "/w/api.php" {
        json!({"query":{"pages":[{"pageid":1,"ns":0,"title":"Rust","lastrevid":revision,"revisions":[{"revid":revision}]}]}})
    } else {
        if uri.path().ends_with("/with_html") && provider.pause_html.swap(false, Ordering::SeqCst) {
            provider.entered.notify_one();
            provider.release.notified().await;
        }
        let mut value = json!({"id":1,"title":"Rust","latest":{"id":revision},"content_model":"wikitext","license":{"url":"https://creativecommons.org/licenses/by-sa/4.0/"}});
        if uri.path().ends_with("/with_html") {
            value["html"] = if provider.oversized.load(Ordering::SeqCst) {
                json!(format!(
                    "<p>{}</p>",
                    "x".repeat(processing::MAX_HTML_BYTES + 1)
                ))
            } else {
                json!(format!(
                    "<h1>Rust</h1><p>Captured compiler revision {revision}.</p>"
                ))
            };
        } else {
            value["source"] = json!(format!("Captured compiler revision {revision}."));
        }
        value
    };
    HttpResponse::builder()
        .header("content-type", "application/json")
        .header("cache-control", "public,max-age=0")
        .body(Body::from(value.to_string()))
        .expect("fixture response")
}
async fn blocking_fixture() -> (
    tempfile::TempDir,
    Arc<MemoryStore>,
    Arc<BlockingProvider>,
    Arc<WikipediaCorpus>,
    tokio::task::JoinHandle<()>,
) {
    let root = tempfile::Builder::new()
        .prefix("devres-wikipedia-moderation-")
        .tempdir_in("/tmp")
        .expect("root");
    let store = Arc::new(MemoryStore::default());
    let provider = Arc::new(BlockingProvider {
        revision: AtomicU64::new(10),
        ..Default::default()
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let address = listener.local_addr().expect("address");
    let app = Router::new()
        .fallback(blocking_handle)
        .with_state(provider.clone());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("server");
    });
    let broker = Arc::new(
        BulkBroker::fixture(url::Url::parse(&format!("http://{address}")).expect("origin"))
            .expect("broker")
            .with_wikipedia_rate(3)
            .expect("rate"),
    );
    let corpus = Arc::new(
        WikipediaCorpus::new(
            store.clone(),
            broker,
            root.path(),
            WikipediaConfig {
                requests_per_second: 3,
                normal_min_refresh_secs: 1,
                current_min_refresh_secs: 1,
                normal_fallback_secs: 1,
                current_fallback_secs: 1,
                min_free_bytes: 64 * 1024 * 1024,
                ..Default::default()
            },
        )
        .expect("corpus"),
    );
    corpus.initialize_status().await.expect("initialize");
    store
        .wiki_commit(
            &[],
            &[state(
                "aliases".into(),
                json!({"titles":["Template:Current"],"complete":true}),
                None,
            )],
        )
        .await
        .expect("aliases");
    (root, store, provider, corpus, server)
}
async fn change(corpus: &WikipediaCorpus, kind: ChangeKind, timestamp: i64, revision: Option<u64>) {
    corpus
        .accept_stream_event(super::super::super::events::SseEvent {
            id: None,
            retry_millis: None,
            change: Some(Change {
                event_id: Some(format!("fixture-{timestamp}-{kind:?}")),
                timestamp,
                title: "Rust".into(),
                page_id: Some(1),
                revision_id: revision,
                kind,
            }),
        })
        .await
        .expect("event commit");
}
#[tokio::test]
async fn a_new_delete_during_restore_fetch_is_immediate_and_cannot_be_cleared() {
    let (_root, store, provider, corpus, server) = blocking_fixture().await;
    corpus
        .request_article("Rust")
        .await
        .expect("initial capture");
    change(&corpus, ChangeKind::Delete, 100, None).await;
    change(&corpus, ChangeKind::Restore, 101, None).await;
    expire_endpoints(&store).await;
    provider.revision.store(11, Ordering::SeqCst);
    provider.pause_html.store(true, Ordering::SeqCst);
    let worker = corpus.clone();
    let refresh = tokio::spawn(async move { worker.request_article("Rust").await });
    tokio::time::timeout(Duration::from_secs(10), provider.entered.notified())
        .await
        .expect("HTML request entered");
    tokio::time::timeout(
        Duration::from_millis(500),
        change(&corpus, ChangeKind::Delete, 102, None),
    )
    .await
    .expect("moderation must not wait for upstream");
    provider.release.notify_one();
    refresh
        .await
        .expect("join")
        .expect("capture can finish privately");
    assert_eq!(
        corpus
            .ensure_visible(1, 11)
            .await
            .expect_err("new deletion stays blocked")
            .code,
        "wikipedia_withheld"
    );
    let events = store
        .wiki_state("events:1")
        .await
        .expect("state")
        .expect("events");
    assert_eq!(events["last_moderation_kind"], "delete");
    assert_eq!(events["restoration_pending"], false);
    server.abort();
}
#[tokio::test]
async fn dirty_event_during_download_survives_and_labels_old_capture() {
    let (_root, store, provider, corpus, server) = blocking_fixture().await;
    corpus
        .request_article("Rust")
        .await
        .expect("initial capture");
    let first = corpus
        .research_document(&json!({"page_id":1}), "text")
        .await
        .expect("first");
    expire_endpoints(&store).await;
    provider.pause_html.store(true, Ordering::SeqCst);
    let worker = corpus.clone();
    let refresh = tokio::spawn(async move { worker.request_article("Rust").await });
    tokio::time::timeout(Duration::from_secs(10), provider.entered.notified())
        .await
        .expect("HTML request entered");
    change(&corpus, ChangeKind::Edit, 200, Some(20)).await;
    provider.release.notify_one();
    refresh.await.expect("join").expect("refresh");
    assert_eq!(
        store
            .wiki_state("events:1")
            .await
            .expect("state")
            .expect("events")["dirty_revision"],
        20
    );
    assert_eq!(
        store
            .wiki_state("article:1")
            .await
            .expect("state")
            .expect("work")["dirty_revision"],
        20
    );
    let historical = corpus
        .research_document(&json!({"capture":first["capture"]["id"]}), "text")
        .await
        .expect("retained history");
    assert_eq!(historical["update_pending"], true);
    assert_eq!(historical["capture"]["revision_id"], 10);
    server.abort();
}
#[tokio::test]
async fn partial_restore_exposes_only_actually_verified_revision_and_suppression_wins() {
    let (_root, store, provider, corpus, server) = blocking_fixture().await;
    corpus
        .request_article("Rust")
        .await
        .expect("initial capture");
    change(&corpus, ChangeKind::Delete, 100, None).await;
    change(&corpus, ChangeKind::Restore, 101, None).await;
    expire_endpoints(&store).await;
    provider.revision.store(11, Ordering::SeqCst);
    corpus
        .request_article("Rust")
        .await
        .expect("publicly verified restore");
    corpus
        .ensure_visible(1, 11)
        .await
        .expect("verified revision readable");
    assert_eq!(
        corpus
            .ensure_visible(1, 10)
            .await
            .expect_err("unverified history blocked")
            .code,
        "wikipedia_withheld"
    );
    change(
        &corpus,
        ChangeKind::RevisionVisibility {
            revision_ids: vec![11],
        },
        102,
        None,
    )
    .await;
    assert_eq!(
        corpus
            .ensure_visible(1, 11)
            .await
            .expect_err("specific suppression wins")
            .code,
        "wikipedia_withheld"
    );
    change(&corpus, ChangeKind::Delete, 103, None).await;
    let overlay = store
        .wiki_state("visibility:page:1")
        .await
        .expect("state")
        .expect("overlay");
    assert!(overlay["restore_identity"].is_null());
    assert!(overlay["verified_revisions"].is_null());
    server.abort();
}
#[tokio::test]
async fn oversized_projection_keeps_raw_html_and_explicit_gap() {
    let (_root, store, provider, corpus, server) = blocking_fixture().await;
    provider.oversized.store(true, Ordering::SeqCst);
    corpus
        .request_article("Rust")
        .await
        .expect("raw capture survives projection bound");
    let rows = store
        .wiki_rows("captures", 0, 100, None)
        .await
        .expect("captures");
    let html = rows
        .iter()
        .find(|row| row.data["representation"] == "html")
        .expect("HTML retained");
    assert!(html.data["projection"].is_null());
    assert_eq!(html.data["processing_gaps"][0], "capacity");
    let original = corpus
        .research_document(&json!({"capture":html.key}), "html")
        .await
        .expect("raw HTML readable");
    assert!(original["text"].as_str().expect("HTML").len() > processing::MAX_HTML_BYTES);
    assert!(
        corpus
            .research_document(&json!({"capture":html.key}), "text")
            .await
            .is_err()
    );
    server.abort();
}
#[tokio::test]
async fn server_retry_larger_than_a_day_and_poison_recovery_are_persisted() {
    let (_root, store, _provider, corpus, server) = blocking_fixture().await;
    let events = SseParser::new()
        .push(b"retry: 172800001\n\n")
        .expect("retry");
    for event in events {
        corpus
            .accept_stream_event(event)
            .await
            .expect("persist retry");
    }
    assert_eq!(
        store
            .wiki_state("stream:retry-seconds")
            .await
            .expect("state"),
        Some(json!(172801))
    );
    corpus
        .stream_gap("invalid_frame", true)
        .await
        .expect("gap transaction");
    assert!(
        store
            .wiki_state("stream:checkpoint")
            .await
            .expect("state")
            .expect("checkpoint")["id"]
            .is_null()
    );
    assert!(
        !store
            .wiki_due("reconcile:", now(), 100)
            .await
            .expect("due")
            .is_empty()
    );
    server.abort();
}
