use super::*;
use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    extract::State as AxumState,
    http::{HeaderMap, Uri},
    response::Response as HttpResponse,
};
use devres_application::wikipedia::{Row, validate_writes};
use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicUsize, Ordering},
};

#[path = "moderation.rs"]
mod moderation;

#[derive(Default)]
struct Data {
    rows: Vec<(String, Row)>,
    states: BTreeMap<String, State>,
}
#[derive(Default)]
struct MemoryStore(Mutex<Data>, CommitGate);
#[derive(Default)]
struct CommitGate {
    commits: AtomicUsize,
    pause_policy: std::sync::atomic::AtomicBool,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
    admission_reads: AtomicUsize,
    admission_read: tokio::sync::Notify,
}
#[async_trait]
impl WikipediaStore for MemoryStore {
    async fn wiki_get(&self, kind: &str, key: &str) -> Result<Option<Row>> {
        Ok(self
            .0
            .lock()
            .await
            .rows
            .iter()
            .find(|(k, r)| k == kind && r.key == key)
            .map(|(_, r)| r.clone()))
    }
    async fn wiki_rows(
        &self,
        kind: &str,
        after: i64,
        limit: usize,
        cutoff: Option<i64>,
    ) -> Result<Vec<Row>> {
        Ok(self
            .0
            .lock()
            .await
            .rows
            .iter()
            .filter(|(k, r)| {
                k == kind && r.sequence > after && cutoff.is_none_or(|cutoff| r.sequence <= cutoff)
            })
            .take(limit)
            .map(|(_, r)| r.clone())
            .collect())
    }
    async fn wiki_cutoff(&self) -> Result<i64> {
        Ok(self
            .0
            .lock()
            .await
            .rows
            .last()
            .map_or(0, |(_, r)| r.sequence))
    }
    async fn wiki_catalog(&self, after: u64, limit: usize, cutoff: i64) -> Result<Vec<Row>> {
        let mut latest = BTreeMap::new();
        for (kind, row) in &self.0.lock().await.rows {
            if kind == "captures" && row.sequence <= cutoff && row.data["representation"] == "html"
            {
                let pid = row.data["page_id"].as_u64().expect("fixture pid");
                if pid > after {
                    latest.insert(pid, row.clone());
                }
            }
        }
        Ok(latest.into_values().take(limit).collect())
    }
    async fn wiki_page_captures(
        &self,
        page: u64,
        after: i64,
        limit: usize,
        cutoff: i64,
    ) -> Result<Vec<Row>> {
        Ok(self
            .0
            .lock()
            .await
            .rows
            .iter()
            .filter(|(kind, row)| {
                kind == "captures"
                    && row.sequence > after
                    && row.sequence <= cutoff
                    && row.data["page_id"] == page
            })
            .take(limit)
            .map(|(_, row)| row.clone())
            .collect())
    }
    async fn wiki_state(&self, key: &str) -> Result<Option<Value>> {
        if key == "provider:admission" {
            self.1.admission_reads.fetch_add(1, Ordering::SeqCst);
            self.1.admission_read.notify_one();
        }
        Ok(self
            .0
            .lock()
            .await
            .states
            .get(key)
            .map(|state| state.data.clone()))
    }
    async fn wiki_states(&self, prefix: &str, after: &str, limit: usize) -> Result<Vec<State>> {
        Ok(self
            .0
            .lock()
            .await
            .states
            .values()
            .filter(|state| state.key.starts_with(prefix) && state.key.as_str() > after)
            .take(limit)
            .cloned()
            .collect())
    }
    async fn wiki_due(&self, prefix: &str, now: i64, limit: usize) -> Result<Vec<State>> {
        Ok(self
            .0
            .lock()
            .await
            .states
            .values()
            .filter(|state| {
                state.key.starts_with(prefix) && state.due_at.is_some_and(|due| due <= now)
            })
            .take(limit)
            .cloned()
            .collect())
    }
    async fn wiki_commit(&self, writes: &[Write], states: &[State]) -> Result<()> {
        validate_writes(writes, states)?;
        self.1.commits.fetch_add(1, Ordering::SeqCst);
        if states.iter().any(|state| {
            state.key == "provider:admission"
                && state.data["cooldown"]
                    .as_i64()
                    .is_some_and(|until| until > now())
        }) && self.1.pause_policy.swap(false, Ordering::SeqCst)
        {
            self.1.entered.notify_one();
            self.1.release.notified().await;
        }
        let mut data = self.0.lock().await;
        for write in writes {
            if let Some((_, old)) = data
                .rows
                .iter()
                .find(|(kind, row)| kind == &write.kind && row.key == write.key)
            {
                if old.data != write.data {
                    return Err(Error::integrity("Fixture immutable collision."));
                }
                continue;
            }
            let sequence = data.rows.last().map_or(1, |(_, row)| row.sequence + 1);
            data.rows.push((
                write.kind.clone(),
                Row {
                    sequence,
                    key: write.key.clone(),
                    data: write.data.clone(),
                },
            ));
        }
        for state in states {
            data.states.insert(state.key.clone(), state.clone());
        }
        Ok(())
    }
}
#[derive(Default)]
struct Provider {
    mode: AtomicUsize,
    requests: Mutex<Vec<(String, HeaderMap)>>,
}
async fn handle(
    AxumState(provider): AxumState<Arc<Provider>>,
    uri: Uri,
    headers: HeaderMap,
) -> HttpResponse {
    provider
        .requests
        .lock()
        .await
        .push((uri.to_string(), headers));
    let mut response = HttpResponse::builder()
        .header("content-type", "application/json")
        .header("cache-control", "public,max-age=600")
        .header("etag", "\"fixture\"");
    if uri.path() == "/w/api.php" {
        let query: BTreeMap<_, _> =
            url::form_urlencoded::parse(uri.query().unwrap_or("").as_bytes())
                .into_owned()
                .collect();
        let value = if query
            .get("list")
            .is_some_and(|value| value == "categorymembers")
        {
            json!({"query":{"categorymembers":[{"pageid":1,"ns":0,"title":"Rust","type":"page"},{"pageid":99,"ns":14,"title":"Category:Science","type":"subcat"}]}})
        } else if query.get("prop").is_some_and(|value| value == "redirects") {
            json!({"query":{"pages":[{"pageid":100,"title":"Template:Current","redirects":[{"title":"Template:Flux"}]}]}})
        } else if query.get("titles").is_some_and(|title| title == "Missing") {
            json!({"query":{"pages":[{"ns":0,"title":"Missing","missing":true}]}})
        } else if query
            .get("titles")
            .is_some_and(|title| title == "Rust alias")
            && query.get("redirects").is_none_or(|value| value != "1")
        {
            // A real alias page has its own page/revision identity. The source
            // must request redirects=1 before correlating it with canonical REST.
            json!({"query":{"pages":[{"pageid":2,"ns":0,"title":"Rust alias","lastrevid":5,"revisions":[{"revid":5}]}]}})
        } else {
            json!({"query":{"pages":[{"pageid":1,"ns":0,"title":"Rust","lastrevid":10,"revisions":[{"revid":10}],"templates":[{"title":"Template:Infobox"}],"categories":[{"title":"Category:Science"}]}]}})
        };
        return response
            .body(Body::from(value.to_string()))
            .expect("metadata response");
    }
    match provider.mode.load(Ordering::SeqCst) {
        1 => return response.status(304).body(Body::empty()).expect("304"),
        2 => {
            response = response.header("cache-control", "private,no-store");
            return response
                .body(Body::from("forbidden body bytes"))
                .expect("private");
        }
        4 | 5 => {
            let status = if provider.mode.load(Ordering::SeqCst) == 4 {
                200
            } else {
                304
            };
            return response
                .status(status)
                .header("cache-control", "private")
                .body(Body::from("forbidden authenticated bytes"))
                .expect("private response");
        }
        6 | 7 => {
            let status = if provider.mode.load(Ordering::SeqCst) == 6 {
                200
            } else {
                304
            };
            return response
                .status(status)
                .header("vary", "Authorization")
                .body(Body::from("forbidden authenticated bytes"))
                .expect("identity response");
        }
        8 => {
            return response
                .status(401)
                .body(Body::from("Bearer synthetic-corpus-token"))
                .expect("authentication failure");
        }
        9 => {
            return HttpResponse::builder()
                .status(304)
                .header("etag", "\"fixture\"")
                .body(Body::empty())
                .expect("headerless 304");
        }
        10 | 11 => {
            let status = if provider.mode.load(Ordering::SeqCst) == 10 {
                200
            } else {
                304
            };
            return response
                .status(status)
                .header("cache-control", "no-store")
                .body(Body::from("forbidden authenticated bytes"))
                .expect("no-store response");
        }
        12 => {
            return HttpResponse::builder()
                .header("cache-control", "max-age=600")
                .body(Body::from("forbidden authenticated bytes"))
                .expect("no public permission");
        }
        _ => {}
    }
    let mut value = json!({"id":1,"title":"Rust","key":"Rust","latest":{"id":10,"timestamp":"2026-11-11T00:00:00Z"},"content_model":"wikitext","license":{"url":"https://creativecommons.org/licenses/by-sa/4.0/","title":"CC BY-SA 4.0"}});
    if provider.mode.load(Ordering::SeqCst) == 3 {
        value["title"] = json!("Draft:Rust");
    }
    if uri.path().ends_with("/with_html") {
        value["html"] = json!(
            "<html><head><title>Rust</title></head><body><section data-mw-section-id=\"0\"><h1>Rust</h1><p>Rust compiler.</p></section></body></html>"
        );
    } else {
        value["source"] = json!("Rust compiler.");
    }
    response
        .body(Body::from(value.to_string()))
        .expect("article response")
}
async fn fixture() -> (
    tempfile::TempDir,
    Arc<MemoryStore>,
    Arc<Provider>,
    Arc<BulkBroker>,
    WikipediaCorpus,
    tokio::task::JoinHandle<()>,
) {
    fixture_with_identity(None).await
}
async fn fixture_with_identity(
    identity: Option<super::super::identity::WikipediaIdentity>,
) -> (
    tempfile::TempDir,
    Arc<MemoryStore>,
    Arc<Provider>,
    Arc<BulkBroker>,
    WikipediaCorpus,
    tokio::task::JoinHandle<()>,
) {
    let root = tempfile::Builder::new()
        .prefix("devres-wikipedia-pipeline-")
        .tempdir_in("/tmp")
        .expect("root");
    let store = Arc::new(MemoryStore::default());
    let provider = Arc::new(Provider::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let address = listener.local_addr().expect("address");
    let app = Router::new().fallback(handle).with_state(provider.clone());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("fixture server");
    });
    let mut broker =
        BulkBroker::fixture(url::Url::parse(&format!("http://{address}")).expect("origin"))
            .expect("broker");
    if let Some(identity) = identity {
        broker = broker.with_wikipedia_identity(identity);
    }
    let broker = Arc::new(broker);
    let config = WikipediaConfig {
        category_roots: vec!["Category:Science".into()],
        min_free_bytes: 64 * 1024 * 1024,
        ..WikipediaConfig::default()
    };
    let corpus =
        WikipediaCorpus::new(store.clone(), broker.clone(), root.path(), config).expect("corpus");
    (root, store, provider, broker, corpus, server)
}
async fn capture_fixture(corpus: &WikipediaCorpus, store: &MemoryStore) -> Value {
    corpus.initialize_status().await.expect("initialize");
    corpus
        .update_aliases(CancellationToken::new())
        .await
        .expect("aliases");
    let category = store
        .wiki_due("category:", now(), 1)
        .await
        .expect("categories")
        .remove(0);
    corpus
        .collect_category(category, CancellationToken::new())
        .await
        .expect("category");
    let article = store
        .wiki_due("article:", now(), 1)
        .await
        .expect("article")
        .remove(0);
    corpus
        .collect_article(&article.key, article.data, CancellationToken::new())
        .await
        .expect("capture");
    corpus.publish_snapshot().await.expect("snapshot");
    corpus
        .research_document(&json!({"page_id":1}), "text")
        .await
        .expect("read text")
}
async fn expire_endpoints(store: &MemoryStore) {
    let mut data = store.0.lock().await;
    for state in data
        .states
        .values_mut()
        .filter(|state| state.key.starts_with("endpoint:"))
    {
        state.data["cache"]["cache_control"] = json!("public,max-age=0");
        state.data["cache"]["received_at"] = json!(now() - 1000);
        state.data["cache"]["request_sent_at"] = json!(now() - 1000);
        state.data["cache"]["date"] = json!(now() - 1000);
    }
}

fn unidentified_broker() -> Arc<BulkBroker> {
    Arc::new(
        BulkBroker::fixture(url::Url::parse("http://127.0.0.1:9").expect("loopback"))
            .expect("fixture broker")
            .with_wikipedia_identity(super::super::identity::WikipediaIdentity::default()),
    )
}

#[tokio::test]
async fn unidentified_acquisition_never_changes_demand_admission_or_backoff() {
    let root = tempfile::Builder::new()
        .prefix("devres-wiki-unidentified-")
        .tempdir_in("/tmp")
        .expect("root");
    let store = Arc::new(MemoryStore::default());
    let broker = unidentified_broker();
    let corpus = WikipediaCorpus::new(
        store.clone(),
        broker.clone(),
        root.path(),
        WikipediaConfig::default(),
    )
    .expect("offline corpus starts");
    corpus.initialize_status().await.expect("offline status");
    assert!(
        store
            .wiki_state("visibility:epoch")
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .wiki_states("category:", "", 100)
            .await
            .unwrap()
            .is_empty()
    );
    let commits = store.1.commits.load(Ordering::SeqCst);
    for result in [
        corpus.request_article("Rust").await,
        corpus
            .request_selector(None, Some(1), CancellationToken::new())
            .await,
        corpus
            .upstream_search("Rust", 1, CancellationToken::new())
            .await
            .map(|_| ()),
        corpus
            .fetch(
                Operation::ArticleHtml {
                    title: "Rust".into(),
                },
                Validators::default(),
                CancellationToken::new(),
            )
            .await
            .map(|_| ()),
    ] {
        assert_eq!(result.unwrap_err().code, "wikipedia_configuration_required");
    }
    let cancel = CancellationToken::new();
    let collection = corpus.run(cancel.clone());
    let events = corpus.run_events(cancel.clone());
    tokio::pin!(collection, events);
    tokio::select! {
        _ = &mut collection => panic!("unidentified collector must remain idle"),
        _ = &mut events => panic!("unidentified stream must remain idle"),
        _ = tokio::time::sleep(Duration::from_millis(20)) => {}
    }
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(1), async {
        collection.await.expect("collector cancels");
        events.await.expect("stream cancels");
    })
    .await
    .expect("idle workers cancel promptly");
    assert_eq!(broker.attempt_count(), 0);
    assert_eq!(store.1.commits.load(Ordering::SeqCst), commits);
}

#[tokio::test]
async fn unidentified_get_serves_retained_title_with_existing_freshness_and_visibility_rules() {
    let (root, store, provider, _broker, corpus, server) = fixture().await;
    let document = capture_fixture(&corpus, &store).await;
    let capture_id = document["capture"]["id"].as_str().unwrap().to_owned();
    let retained = store
        .wiki_get("captures", &capture_id)
        .await
        .unwrap()
        .unwrap();
    let broker = unidentified_broker();
    let offline = Arc::new(
        WikipediaCorpus::new(
            store.clone(),
            broker.clone(),
            root.path(),
            corpus.config.clone(),
        )
        .expect("offline writer"),
    );
    let research = super::super::research::WikipediaResearch::new(offline.clone());
    let before_requests = provider.requests.lock().await.len();
    let before_commits = store.1.commits.load(Ordering::SeqCst);
    for input in [json!({"title":"Rust"}), json!({"page_id":1})] {
        let output = research
            .call("wikipedia.get", input, CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(output["capture"]["id"], capture_id);
    }
    assert_eq!(store.1.commits.load(Ordering::SeqCst), before_commits);
    let validation_key = format!("validation:{capture_id}");
    offline
        .save(
            &validation_key,
            json!({"validated_at":now()-20,"expires_at":now()-10,"cache":retained.data["cache"]}),
            None,
        )
        .await
        .unwrap();
    let stale = research
        .call(
            "wikipedia.get",
            json!({"title":"Rust"}),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(stale["stale"], true);
    let mut page = store.wiki_state("page:1").await.unwrap().unwrap();
    page["current"] = Value::Null;
    offline.save("page:1", page.clone(), None).await.unwrap();
    offline.save(&validation_key, json!({"validated_at":now()-1000,"expires_at":now()-901,"cache":retained.data["cache"]}), None).await.unwrap();
    assert!(
        research
            .call(
                "wikipedia.get",
                json!({"title":"Rust"}),
                CancellationToken::new()
            )
            .await
            .is_err()
    );
    page["current"] = json!(false);
    offline.save("page:1", page, None).await.unwrap();
    offline.save(&validation_key, json!({"validated_at":now()-90000,"expires_at":now()-86401,"cache":retained.data["cache"]}), None).await.unwrap();
    assert!(
        research
            .call(
                "wikipedia.get",
                json!({"title":"Rust"}),
                CancellationToken::new()
            )
            .await
            .is_err()
    );
    let frozen = research
        .call(
            "wikipedia.get",
            json!({"capture":capture_id}),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(frozen["capture"]["id"], capture_id);
    let mut forbidden_cache = retained.data["cache"].clone();
    forbidden_cache["cache_control"] = json!("private,no-store");
    offline
        .save(
            &validation_key,
            json!({"validated_at":now(),"expires_at":now()+600,"cache":forbidden_cache}),
            None,
        )
        .await
        .unwrap();
    assert!(
        research
            .call(
                "wikipedia.get",
                json!({"title":"Rust"}),
                CancellationToken::new()
            )
            .await
            .is_err()
    );
    assert_eq!(
        research
            .call(
                "wikipedia.get",
                json!({"title":"Missing"}),
                CancellationToken::new()
            )
            .await
            .unwrap_err()
            .code,
        "wikipedia_configuration_required"
    );
    assert_eq!(provider.requests.lock().await.len(), before_requests);
    assert_eq!(broker.attempt_count(), 0);
    server.abort();
}

struct ReadinessDelegate {
    code: &'static str,
    requests: AtomicUsize,
    searches: AtomicUsize,
}
#[async_trait]
impl AcquisitionDelegate for ReadinessDelegate {
    async fn wikipedia_request(&self, _title: Option<String>, _page_id: Option<u64>) -> Result<()> {
        self.requests.fetch_add(1, Ordering::SeqCst);
        Err(Error::new(self.code, "Writer acquisition is blocked."))
    }
    async fn wikipedia_search(&self, _query: String, _limit: usize) -> Result<Value> {
        self.searches.fetch_add(1, Ordering::SeqCst);
        Ok(json!({"delegated":true}))
    }
    async fn acquire(
        &self,
        _operation: devres_application::acquisition::Acquisition,
    ) -> Result<devres_domain::Capture> {
        Err(Error::unavailable("Unused fixture operation."))
    }
    async fn effect(&self, _effect: devres_application::acquisition::WriterEffect) -> Result<()> {
        Err(Error::unavailable("Unused fixture operation."))
    }
}

#[tokio::test]
async fn reader_without_identity_delegates_and_only_readiness_errors_allow_local_fallback() {
    let (root, store, _provider, _broker, corpus, server) = fixture().await;
    capture_fixture(&corpus, &store).await;
    for code in [
        "wikipedia_configuration_required",
        "wikipedia_authentication_failed",
        "unavailable",
    ] {
        let delegate = Arc::new(ReadinessDelegate {
            code,
            requests: AtomicUsize::new(0),
            searches: AtomicUsize::new(0),
        });
        let reader = Arc::new(
            WikipediaCorpus::new_reader(
                store.clone(),
                unidentified_broker(),
                root.path(),
                corpus.config.clone(),
            )
            .unwrap()
            .with_delegate(Some(delegate.clone())),
        );
        assert_eq!(
            reader
                .upstream_search("Rust", 1, CancellationToken::new())
                .await
                .unwrap()["delegated"],
            true
        );
        assert_eq!(delegate.searches.load(Ordering::SeqCst), 1);
        let research = super::super::research::WikipediaResearch::new(reader);
        let result = research
            .call(
                "wikipedia.get",
                json!({"title":"Rust"}),
                CancellationToken::new(),
            )
            .await;
        if code == "unavailable" {
            assert_eq!(result.unwrap_err().code, code);
        } else {
            assert!(result.is_ok());
        }
        assert_eq!(delegate.requests.load(Ordering::SeqCst), 1);
    }
    server.abort();
}

#[tokio::test]
async fn recursive_category_latest_capture_projection_snapshot_and_restart_ttl() {
    let (root, store, provider, broker, corpus, server) = fixture().await;
    let document = capture_fixture(&corpus, &store).await;
    assert!(
        document["text"]
            .as_str()
            .expect("text")
            .contains("Rust compiler.")
    );
    assert_eq!(document["capture"]["current"], false);
    assert_eq!(document["capture"]["revision_id"], 10);
    let count = provider.requests.lock().await.len();
    let restarted = WikipediaCorpus::new(
        store.clone(),
        broker.clone(),
        root.path(),
        corpus.config.clone(),
    )
    .expect("restarted");
    restarted
        .request_article("Rust")
        .await
        .expect("cached demand");
    assert_eq!(
        provider.requests.lock().await.len(),
        count,
        "restart must honor durable upstream TTL"
    );
    restarted
        .request_article("Rust alias")
        .await
        .expect("alias demand");
    let requests = provider.requests.lock().await;
    assert_eq!(
        requests.len(),
        count + 1,
        "new metadata selector may resolve; canonical article TTL is shared"
    );
    assert!(
        requests
            .last()
            .expect("metadata")
            .0
            .starts_with("/w/api.php")
    );
    drop(requests);
    let alias_read = restarted
        .research_document(&json!({"title":"Rust alias"}), "text")
        .await
        .expect("warm alias remains readable");
    assert!(
        alias_read["text"]
            .as_str()
            .expect("alias text")
            .contains("Rust compiler.")
    );
    let reader = WikipediaCorpus::new_reader(store, broker, root.path(), corpus.config.clone())
        .expect("reader");
    let reread = reader
        .research_document(&json!({"capture":document["capture"]["id"]}), "markdown")
        .await
        .expect("capture-fixed read");
    assert!(
        reread["text"]
            .as_str()
            .expect("markdown")
            .contains("Rust compiler.")
    );
    server.abort();
}

#[tokio::test]
async fn conditional_304_preserves_capture_and_private_refresh_withholds_current_after_restart() {
    let (root, store, provider, broker, corpus, server) = fixture().await;
    let original = capture_fixture(&corpus, &store).await;
    let count = provider.requests.lock().await.len();
    let captures = store
        .wiki_rows("captures", 0, 100, None)
        .await
        .expect("captures")
        .len();
    expire_endpoints(&store).await;
    provider.mode.store(1, Ordering::SeqCst);
    corpus.request_article("Rust").await.expect("304 refresh");
    assert_eq!(
        store
            .wiki_rows("captures", 0, 100, None)
            .await
            .expect("captures")
            .len(),
        captures
    );
    let requests = provider.requests.lock().await;
    assert_eq!(requests.len(), count + 2);
    for (_, headers) in &requests[count..] {
        assert_eq!(
            headers
                .get("if-none-match")
                .and_then(|header| header.to_str().ok()),
            Some("\"fixture\"")
        );
    }
    drop(requests);
    let fresh = corpus
        .research_document(&json!({"page_id":1}), "text")
        .await
        .expect("validated read");
    assert_eq!(fresh["capture"]["id"], original["capture"]["id"]);
    expire_endpoints(&store).await;
    provider.mode.store(2, Ordering::SeqCst);
    corpus
        .request_article("Rust")
        .await
        .expect("private policy observation");
    let reader =
        WikipediaCorpus::new_reader(store.clone(), broker, root.path(), corpus.config.clone())
            .expect("restarted reader");
    assert!(
        reader
            .research_document(&json!({"page_id":1}), "text")
            .await
            .is_err()
    );
    let historical = reader
        .research_document(&json!({"capture":original["capture"]["id"]}), "text")
        .await
        .expect("original public observation remains retained");
    assert_eq!(historical["text"], original["text"]);
    assert_eq!(
        store
            .wiki_rows("captures", 0, 100, None)
            .await
            .expect("captures")
            .len(),
        captures,
        "private bytes must never enter capture rows"
    );
    server.abort();
}

#[tokio::test]
async fn rest_rename_without_namespace_cannot_publish_under_stale_mainspace_metadata() {
    let (_root, store, provider, _broker, corpus, server) = fixture().await;
    corpus.initialize_status().await.expect("initialize");
    provider.mode.store(3, Ordering::SeqCst);
    assert!(corpus.request_article("Rust").await.is_err());
    assert!(
        store
            .wiki_rows("captures", 0, 100, None)
            .await
            .expect("captures")
            .is_empty()
    );
    server.abort();
}

#[tokio::test]
async fn restore_without_observed_delete_blocks_until_unconditional_html_verification() {
    let (_root, store, provider, _broker, corpus, server) = fixture().await;
    capture_fixture(&corpus, &store).await;
    corpus
        .ensure_visible(1, 10)
        .await
        .expect("initial public capture");
    let before = provider.requests.lock().await.len();
    corpus
        .accept_stream_event(super::super::events::SseEvent {
            id: None,
            retry_millis: None,
            change: Some(Change {
                event_id: Some("restore-without-local-delete".into()),
                timestamp: 100,
                title: "Rust".into(),
                page_id: Some(1),
                revision_id: None,
                kind: ChangeKind::Restore,
            }),
        })
        .await
        .expect("restore observed");
    assert_eq!(
        corpus
            .ensure_visible(1, 10)
            .await
            .expect_err("restore starts withheld even if deletion was missed")
            .code,
        "wikipedia_withheld"
    );
    assert_eq!(
        provider.requests.lock().await.len(),
        before,
        "event processing performs no provider I/O"
    );
    expire_endpoints(&store).await;
    corpus
        .request_article("Rust")
        .await
        .expect("verified latest restoration");
    corpus
        .ensure_visible(1, 10)
        .await
        .expect("only actual verified revision is public");
    let requests = provider.requests.lock().await;
    let html = requests[before..]
        .iter()
        .find(|(uri, _)| uri.contains("/with_html"))
        .expect("latest HTML verification");
    assert!(
        html.1.get("if-none-match").is_none(),
        "pending restore must obtain actual HTML200 evidence"
    );
    drop(requests);
    server.abort();
}

#[tokio::test]
async fn newly_configured_root_reactivates_but_an_excluded_root_stays_paused() {
    let (root, store, _provider, broker, corpus, server) = fixture().await;
    corpus.initialize_status().await.expect("initial roots");
    let root_key = key("category", "Category:Science");
    store.wiki_commit(&[],&[state(root_key.clone(),json!({"title":"Category:Science","roots":["Category:Science"],"out_of_scope":true}),None)]).await.expect("previously detached root");
    let mut excluded = corpus.config.clone();
    excluded.excluded_categories = vec!["Category:Science".into()];
    let restarted = WikipediaCorpus::new(store.clone(), broker.clone(), root.path(), excluded)
        .expect("excluded writer");
    restarted
        .initialize_status()
        .await
        .expect("excluded initialization");
    assert!(
        store
            .wiki_due("category:", now(), 100)
            .await
            .expect("due roots")
            .is_empty()
    );
    let restarted = WikipediaCorpus::new(store.clone(), broker, root.path(), corpus.config.clone())
        .expect("re-enabled root writer");
    restarted
        .initialize_status()
        .await
        .expect("root reactivation");
    let roots = store
        .wiki_due("category:", now(), 100)
        .await
        .expect("due roots");
    assert!(
        roots
            .iter()
            .any(|root| root.key == root_key && root.data["out_of_scope"] == false)
    );
    server.abort();
}

#[tokio::test]
async fn missing_titles_leave_no_repeating_demand_and_backoff_survives_restart() {
    let (root, store, provider, broker, corpus, server) = fixture().await;
    corpus.initialize_status().await.expect("initialize");
    assert_eq!(
        corpus
            .request_article("Missing")
            .await
            .expect_err("missing article")
            .code,
        "not_found"
    );
    let requests = provider.requests.lock().await.len();
    assert_eq!(requests, 1, "one metadata request proves absence");
    assert!(
        store
            .wiki_due("demand:", now() + 600, 100)
            .await
            .expect("demand queue")
            .is_empty()
    );
    let negative = store
        .wiki_state(&key("negative-title", "Missing"))
        .await
        .expect("negative state")
        .expect("backoff");
    assert!(
        negative["title"].is_null(),
        "negative state stores no raw unknown title"
    );
    assert!(
        negative["not_before"]
            .as_i64()
            .is_some_and(|until| until >= now() + 295)
    );
    let restarted = WikipediaCorpus::new(store.clone(), broker, root.path(), corpus.config.clone())
        .expect("restarted writer");
    assert_eq!(
        restarted
            .request_article("Missing")
            .await
            .expect_err("retained negative cache")
            .code,
        "not_found"
    );
    assert_eq!(
        provider.requests.lock().await.len(),
        requests,
        "restart does not bypass negative cache"
    );
    assert!(
        store
            .wiki_due("demand:", now() + 600, 100)
            .await
            .expect("demand queue")
            .is_empty()
    );
    server.abort();
}

#[tokio::test]
async fn failure_backoff_grows_caps_and_survives_restart_without_clearing_explicit_delay() {
    let (root, store, provider, broker, corpus, server) = fixture().await;
    for (index, delay) in [5, 10, 20, 40, 80, 160, 320, 640, 900, 900]
        .into_iter()
        .enumerate()
    {
        let before = now();
        corpus
            .failed_attempt("http", None)
            .await
            .expect("durable failure");
        let saved = store
            .wiki_state("provider:backoff:http")
            .await
            .expect("backoff read")
            .expect("backoff");
        assert_eq!(saved["failures"], (index + 1).min(9));
        assert!(
            saved["not_before"]
                .as_i64()
                .is_some_and(|until| until >= before + delay && until <= now() + delay)
        );
        let admission = store
            .wiki_state("provider:admission")
            .await
            .expect("admission read")
            .expect("admission");
        assert!(admission["cooldown"].as_i64() >= saved["not_before"].as_i64());
    }
    let explicit = now() + 3600;
    corpus
        .failed_attempt("stream", Some(explicit))
        .await
        .expect("explicit stream delay");
    let restarted = WikipediaCorpus::new(store.clone(), broker, root.path(), corpus.config.clone())
        .expect("restarted writer");
    let saved = store
        .wiki_state("provider:backoff:http")
        .await
        .expect("retained")
        .expect("http state");
    assert_eq!(saved["failures"], 9);
    assert_eq!(
        store
            .wiki_state("provider:backoff:stream")
            .await
            .expect("stream")
            .expect("stream state")["failures"],
        1
    );
    restarted
        .recovered_attempt("http")
        .await
        .expect("successful HTTP resets only its streak");
    assert_eq!(
        store
            .wiki_state("provider:backoff:http")
            .await
            .expect("http")
            .expect("http state")["failures"],
        0
    );
    assert_eq!(
        store
            .wiki_state("provider:backoff:stream")
            .await
            .expect("stream")
            .expect("stream state")["failures"],
        1
    );
    assert!(
        store
            .wiki_state("provider:admission")
            .await
            .expect("admission")
            .expect("state")["cooldown"]
            .as_i64()
            .is_some_and(|until| until >= explicit)
    );
    assert!(
        provider.requests.lock().await.is_empty(),
        "backoff bookkeeping performs no source I/O"
    );
    server.abort();
}

#[tokio::test]
async fn ttl_metadata_cache_hit_does_not_reset_failure_or_erase_retry_after() {
    let (_root, store, provider, _broker, corpus, server) = fixture().await;
    let operation = Operation::Metadata {
        titles: vec!["Rust".into()],
        page_ids: vec![],
    };
    let initial = corpus
        .fetch(
            operation.clone(),
            Validators::default(),
            CancellationToken::new(),
        )
        .await
        .expect("fixture metadata");
    assert_eq!(initial.status, 200);
    let explicit = now() + 3600;
    corpus
        .failed_attempt("http", Some(explicit))
        .await
        .expect("deferred provider");
    let cached = corpus
        .fetch(operation, Validators::default(), CancellationToken::new())
        .await
        .expect("fresh retained metadata");
    assert_eq!(cached.body, initial.body);
    assert_eq!(provider.requests.lock().await.len(), 1);
    assert_eq!(
        store
            .wiki_state("provider:backoff:http")
            .await
            .expect("backoff")
            .expect("state")["failures"],
        1,
        "cached evidence is not new upstream recovery"
    );
    assert!(
        store
            .wiki_state("provider:admission")
            .await
            .expect("admission")
            .expect("state")["cooldown"]
            .as_i64()
            .is_some_and(|until| until >= explicit)
    );
    server.abort();
}

async fn dropped_policy_receipt_fixture(
    action_slow: bool,
    stream: bool,
    long_retry: bool,
    abort_slow_body: bool,
) {
    use std::convert::Infallible;
    let root = tempfile::Builder::new()
        .prefix("devres-wiki-dropped-policy-")
        .tempdir_in("/tmp")
        .expect("root");
    let store = Arc::new(MemoryStore::default());
    store.1.pause_policy.store(true, Ordering::SeqCst);
    let requests = Arc::new(AtomicUsize::new(0));
    let observed = requests.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let origin = url::Url::parse(&format!(
        "http://{}",
        listener.local_addr().expect("address")
    ))
    .expect("origin");
    let handler = move || {
        let observed = observed.clone();
        async move {
            observed.fetch_add(1, Ordering::SeqCst);
            if action_slow {
                tokio::time::sleep(Duration::from_millis(1100)).await;
            }
            let body = futures::stream::once(async {
                Ok::<_, Infallible>(bytes::Bytes::from_static(b"{"))
            })
            .chain(futures::stream::pending::<
                std::result::Result<bytes::Bytes, Infallible>,
            >());
            let mut response = HttpResponse::builder()
                .header(
                    "content-type",
                    if stream {
                        "text/event-stream"
                    } else {
                        "application/json"
                    },
                )
                .header("cache-control", "public,max-age=60");
            if long_retry {
                response = response.header("retry-after", "3600");
            }
            response
                .body(Body::from_stream(body))
                .expect("stalled body")
        }
    };
    let server = tokio::spawn(async move {
        axum::serve(listener, Router::new().fallback(handler))
            .await
            .expect("server");
    });
    let broker = Arc::new(BulkBroker::fixture(origin.clone()).expect("broker"));
    let config = WikipediaConfig {
        min_free_bytes: 64 * 1024 * 1024,
        ..Default::default()
    };
    let corpus = Arc::new(
        WikipediaCorpus::new(store.clone(), broker, root.path(), config.clone()).expect("corpus"),
    );
    let owner = corpus.clone();
    let task = tokio::spawn(async move {
        if stream {
            owner
                .source
                .stream_with_policy(None, CancellationToken::new(), owner.policy_observer())
                .await
                .map(|_| ())
        } else {
            owner
                .fetch(
                    if action_slow || abort_slow_body {
                        Operation::Category {
                            title: "Category:Science".into(),
                            continuation: None,
                        }
                    } else {
                        Operation::ArticleSource {
                            title: "Rust".into(),
                        }
                    },
                    Validators::default(),
                    CancellationToken::new(),
                )
                .await
                .map(|_| ())
        }
    });
    if abort_slow_body {
        tokio::time::timeout(Duration::from_secs(2), async {
            while requests.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("Action request reached the fast-header stalled-body server");
        tokio::time::sleep(Duration::from_millis(1100)).await;
        task.abort();
    }
    tokio::time::timeout(Duration::from_secs(4), store.1.entered.notified())
        .await
        .expect("header receipt handed to storage worker");
    let floor = corpus.source.policy_floor().load(Ordering::Acquire);
    assert!(floor >= now() + if long_retry { 3598 } else { 4 });
    task.abort();
    assert!(task.await.expect_err("caller task dropped").is_cancelled());
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    // The original fetch no longer exists. Its storage-only handoff must still
    // finish after the test allows the blocked durable transaction to proceed.
    store.1.release.notify_one();
    corpus
        .drain_policy_receipts()
        .await
        .expect("dropped caller policy is drained");
    let saved = store
        .wiki_state("provider:admission")
        .await
        .expect("durable policy")
        .expect("state");
    assert!(
        saved["cooldown"]
            .as_i64()
            .is_some_and(|until| until >= floor)
    );
    drop(corpus);
    let fresh_broker =
        Arc::new(BulkBroker::fixture(origin).expect("fresh process-equivalent broker"));
    assert_eq!(
        fresh_broker
            .wikipedia_policy_floor()
            .load(Ordering::Acquire),
        0
    );
    let restarted = Arc::new(
        WikipediaCorpus::new(store.clone(), fresh_broker, root.path(), config)
            .expect("restarted Corpus"),
    );
    let reads = store.1.admission_reads.load(Ordering::SeqCst);
    let token = CancellationToken::new();
    let cancel = token.clone();
    let owner = restarted.clone();
    let admission = tokio::spawn(async move { owner.reserve_attempt(&cancel).await });
    tokio::time::timeout(Duration::from_secs(1), async {
        while store.1.admission_reads.load(Ordering::SeqCst) <= reads {
            store.1.admission_read.notified().await;
        }
    })
    .await
    .expect("restarted admission reads durable state");
    token.cancel();
    assert_eq!(
        admission
            .await
            .expect("admission task")
            .expect_err("durable floor still blocks a new attempt")
            .code,
        "cancelled"
    );
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    server.abort();
}
#[tokio::test]
async fn dropping_actual_fetch_after_retry_headers_preserves_policy_across_corpus_restart() {
    dropped_policy_receipt_fixture(false, false, true, false).await;
}
#[tokio::test]
async fn dropping_slow_action_fetch_preserves_the_five_second_pause() {
    dropped_policy_receipt_fixture(true, false, false, false).await;
}
#[tokio::test]
async fn dropping_slow_action_after_long_retry_headers_preserves_the_longer_pause() {
    dropped_policy_receipt_fixture(true, false, true, false).await;
}
#[tokio::test]
async fn dropping_action_during_slow_body_preserves_the_five_second_pause() {
    dropped_policy_receipt_fixture(false, false, false, true).await;
}
#[tokio::test]
async fn dropping_stream_handshake_after_headers_preserves_policy_across_restart() {
    dropped_policy_receipt_fixture(false, true, true, false).await;
}

fn authenticated_identity() -> super::super::identity::WikipediaIdentity {
    super::super::identity::WikipediaIdentity::new(
        Some("CorpusFixture/1.0 (https://example.org/bot)"),
        Some(b"synthetic-corpus-token"),
    )
    .expect("synthetic identity")
}

fn raw_artifact_manifest(root: &Path) -> BTreeMap<std::path::PathBuf, String> {
    let mut pending = vec![root.join("wikipedia/raw-artifacts")];
    let mut files = BTreeMap::new();
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(directory).expect("artifact directory") {
            let entry = entry.expect("artifact entry");
            if entry.file_type().expect("artifact type").is_dir() {
                pending.push(entry.path());
            } else {
                files.insert(
                    entry.path().strip_prefix(root).unwrap().to_owned(),
                    crate::integrity::hash(&std::fs::read(entry.path()).expect("artifact bytes")),
                );
            }
        }
    }
    files
}

#[tokio::test]
async fn unidentified_get_on_never_published_store_returns_configuration_required() {
    let root = tempfile::Builder::new()
        .prefix("devres-wiki-empty-unidentified-")
        .tempdir_in("/tmp")
        .unwrap();
    let store = Arc::new(MemoryStore::default());
    let broker = unidentified_broker();
    let corpus = Arc::new(
        WikipediaCorpus::new(
            store.clone(),
            broker.clone(),
            root.path(),
            WikipediaConfig::default(),
        )
        .unwrap(),
    );
    let research = super::super::research::WikipediaResearch::new(corpus);
    let error = research
        .call(
            "wikipedia.get",
            json!({"title":"Rust"}),
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, "wikipedia_configuration_required");
    assert_eq!(broker.attempt_count(), 0);
    assert_eq!(store.1.commits.load(Ordering::SeqCst), 0);
    assert!(store.0.lock().await.rows.is_empty());
    assert!(store.0.lock().await.states.is_empty());
}

#[tokio::test]
async fn authenticated_public_200_and_304_publish_then_revalidate_without_new_artifacts() {
    let (root, store, provider, _broker, corpus, server) =
        fixture_with_identity(Some(authenticated_identity())).await;
    let document = capture_fixture(&corpus, &store).await;
    let capture_id = document["capture"]["id"].as_str().unwrap();
    assert!(
        store
            .wiki_get("captures", capture_id)
            .await
            .unwrap()
            .is_some()
    );
    assert!(provider.requests.lock().await.iter().all(|(_, headers)| {
        headers
            .get("authorization")
            .is_some_and(|value| value == "Bearer synthetic-corpus-token")
    }));
    let before_artifacts = raw_artifact_manifest(root.path());
    let before_captures = store
        .wiki_rows("captures", 0, 100, None)
        .await
        .unwrap()
        .len();
    expire_endpoints(&store).await;
    provider.mode.store(1, Ordering::SeqCst);
    corpus
        .request_article("Rust")
        .await
        .expect("public authenticated 304");
    assert!(
        store
            .wiki_state(&format!("validation:{capture_id}"))
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        store
            .wiki_rows("captures", 0, 100, None)
            .await
            .unwrap()
            .len(),
        before_captures
    );
    assert_eq!(raw_artifact_manifest(root.path()), before_artifacts);
    assert!(
        corpus
            .research_document(&json!({"page_id":1}), "text")
            .await
            .is_ok()
    );
    server.abort();
}

#[tokio::test]
async fn authenticated_forbidden_200_and_304_preserve_endpoints_validation_and_artifacts() {
    let (root, store, provider, _broker, corpus, server) =
        fixture_with_identity(Some(authenticated_identity())).await;
    let document = capture_fixture(&corpus, &store).await;
    let capture_id = document["capture"]["id"].as_str().unwrap();
    for mode in [4, 5, 6, 7, 10, 11, 12, 9] {
        expire_endpoints(&store).await;
        if mode == 9 {
            for state in store
                .0
                .lock()
                .await
                .states
                .values_mut()
                .filter(|state| state.key.starts_with("endpoint:"))
            {
                state.data["cache"]["cache_control"] = json!("max-age=0");
            }
        }
        let endpoint_key = key("endpoint", "html:Rust");
        let before_endpoint = store.wiki_state(&endpoint_key).await.unwrap();
        let before_validation = store
            .wiki_state(&format!("validation:{capture_id}"))
            .await
            .unwrap();
        let before_rows = serde_json::to_value(&store.0.lock().await.rows).unwrap();
        let before_view = store.wiki_state("snapshot:default").await.unwrap();
        let before_artifacts = raw_artifact_manifest(root.path());
        provider.mode.store(mode, Ordering::SeqCst);
        assert!(corpus.request_article("Rust").await.is_err(), "mode {mode}");
        assert_eq!(
            store.wiki_state(&endpoint_key).await.unwrap(),
            before_endpoint,
            "mode {mode}"
        );
        assert_eq!(
            store
                .wiki_state(&format!("validation:{capture_id}"))
                .await
                .unwrap(),
            before_validation,
            "mode {mode}"
        );
        assert_eq!(
            serde_json::to_value(&store.0.lock().await.rows).unwrap(),
            before_rows,
            "mode {mode}"
        );
        assert_eq!(
            store.wiki_state("snapshot:default").await.unwrap(),
            before_view,
            "mode {mode}"
        );
        assert_eq!(
            raw_artifact_manifest(root.path()),
            before_artifacts,
            "mode {mode}"
        );
        assert!(
            corpus
                .research_document(&json!({"capture":capture_id}), "text")
                .await
                .is_ok(),
            "mode {mode}"
        );
    }
    server.abort();
}

#[tokio::test]
async fn authenticated_401_latches_without_backoff_and_preserves_local_get() {
    let (_root, store, provider, broker, corpus, server) =
        fixture_with_identity(Some(authenticated_identity())).await;
    let document = capture_fixture(&corpus, &store).await;
    let capture_id = document["capture"]["id"].as_str().unwrap().to_owned();
    expire_endpoints(&store).await;
    let before_backoff = store.wiki_state("provider:backoff:http").await.unwrap();
    provider.mode.store(8, Ordering::SeqCst);
    let error = corpus.request_article("Rust").await.unwrap_err();
    assert_eq!(error.code, "wikipedia_authentication_failed");
    assert!(
        !serde_json::to_string(&error)
            .unwrap()
            .contains("synthetic-corpus-token")
    );
    assert_eq!(
        store.wiki_state("provider:backoff:http").await.unwrap(),
        before_backoff
    );
    let before_attempts = broker.attempt_count();
    let before_commits = store.1.commits.load(Ordering::SeqCst);
    assert_eq!(
        corpus.request_article("Rust").await.unwrap_err().code,
        "wikipedia_authentication_failed"
    );
    assert_eq!(broker.attempt_count(), before_attempts);
    assert_eq!(store.1.commits.load(Ordering::SeqCst), before_commits);
    let research = super::super::research::WikipediaResearch::new(Arc::new(corpus));
    let local = research
        .call(
            "wikipedia.get",
            json!({"title":"Rust"}),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(local["capture"]["id"], capture_id);
    assert_eq!(store.1.commits.load(Ordering::SeqCst), before_commits);
    server.abort();
}
