use super::*;
use async_trait::async_trait;
use devres_application::w3c::{Row, W3cConfig, W3cStore, Write};
use std::sync::Mutex;

#[derive(Default)]
pub(super) struct Memory {
    rows: Mutex<BTreeMap<(String, String), Row>>,
    state: Mutex<BTreeMap<String, Value>>,
}
#[async_trait]
impl W3cStore for Memory {
    async fn w3c_cutoff(&self) -> Result<i64> {
        Ok(self
            .rows
            .lock()
            .unwrap()
            .values()
            .map(|r| r.sequence)
            .max()
            .unwrap_or(0))
    }
    async fn w3c_get(&self, kind: &str, key: &str) -> Result<Option<Row>> {
        Ok(self
            .rows
            .lock()
            .unwrap()
            .get(&(kind.into(), key.into()))
            .cloned())
    }
    async fn w3c_put(&self, kind: &str, key: &str, data: &Value) -> Result<i64> {
        let mut rows = self.rows.lock().unwrap();
        if let Some(old) = rows.get(&(kind.into(), key.into())) {
            if &old.data != data {
                return Err(Error::integrity("immutable collision"));
            }
            return Ok(old.sequence);
        }
        let sequence = rows.len() as i64 + 1;
        rows.insert(
            (kind.into(), key.into()),
            Row {
                sequence,
                key: key.into(),
                data: data.clone(),
            },
        );
        Ok(sequence)
    }
    async fn w3c_put_many(&self, rows: &[Write]) -> Result<()> {
        for row in rows {
            self.w3c_put(&row.kind, &row.key, &row.data).await?;
        }
        Ok(())
    }
    async fn w3c_rows(
        &self,
        kind: &str,
        after: i64,
        limit: usize,
        cutoff: Option<i64>,
    ) -> Result<Vec<Row>> {
        let mut rows: Vec<_> = self
            .rows
            .lock()
            .unwrap()
            .iter()
            .filter(|((k, _), r)| {
                k == kind && r.sequence > after && cutoff.is_none_or(|c| r.sequence <= c)
            })
            .map(|(_, r)| r.clone())
            .collect();
        rows.sort_by_key(|r| r.sequence);
        rows.truncate(limit);
        Ok(rows)
    }
    async fn w3c_state(&self, key: &str) -> Result<Option<Value>> {
        Ok(self.state.lock().unwrap().get(key).cloned())
    }
    async fn w3c_set_state(&self, key: &str, data: &Value) -> Result<()> {
        self.state.lock().unwrap().insert(key.into(), data.clone());
        Ok(())
    }
    async fn w3c_publish_view(&self, view: &View) -> Result<()> {
        let data = json!(view);
        self.w3c_put("views", &view.id, &data).await?;
        self.w3c_set_state("default", &data).await
    }
}

pub(super) async fn corpus_fixture(
    broker: Arc<BulkBroker>,
) -> (tempfile::TempDir, Arc<Memory>, W3cCorpus) {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let store = Arc::new(Memory::default());
    let corpus = W3cCorpus::new(
        store.clone(),
        broker,
        root.path(),
        W3cConfig {
            min_free_bytes: 64 * 1024 * 1024,
            max_git_bytes: 64 * 1024 * 1024,
            ..Default::default()
        },
    )
    .unwrap();
    (root, store, corpus)
}
async fn source_fixture() -> (tempfile::TempDir, Arc<W3cGit>) {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let git = Arc::new(
        W3cGit::new(
            root.path(),
            Repo::new("https://git.example.org/group/spec.git").unwrap(),
            64 * 1024 * 1024,
            64 * 1024 * 1024,
            None,
        )
        .unwrap(),
    );
    crate::w3c::git::tests::fixture_init(&git).await;
    (root, git)
}
#[tokio::test]
async fn approved_git_promotes_but_mixed_historical_license_never_archives_packs() {
    use crate::w3c::git::tests::{MIT_NOTICE, commit_files, fixture_router, serve_fixture, update};
    let _gate = crate::mdn::index::TEST_GATE.lock().await;
    let (_source_root, source) = source_fixture().await;
    let approved = commit_files(
        &source,
        &[
            ("LICENSE", MIT_NOTICE),
            ("index.md", b"# Example\nSynthetic source"),
        ],
        &[],
    )
    .await;
    update(&source, "refs/heads/main", &approved).await;
    let (broker, server) = serve_fixture(fixture_router(source.clone())).await;
    let (_root, store, corpus) = corpus_fixture(broker).await;
    let observation = corpus
        .observe_repository(
            &Repo::new("https://git.example.org/group/spec.git")
                .unwrap()
                .as_str(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(observation.total_commits, 1);
    let durable = corpus
        .git(
            &Repo::new("https://git.example.org/group/spec.git")
                .unwrap()
                .as_str(),
        )
        .unwrap();
    assert!(durable.repository().join("objects/pack").exists());
    assert_eq!(
        store
            .w3c_state(&state_key(
                "repository-license",
                &Repo::new("https://git.example.org/group/spec.git")
                    .unwrap()
                    .as_str()
            ))
            .await
            .unwrap()
            .unwrap()["decision"],
        "approved"
    );
    // A subsequent branch with an unresolved governing notice makes the new pack mixed.
    let blocked = commit_files(
        &source,
        &[
            ("LICENSE", b"All rights reserved. No copying permission."),
            ("index.md", b"blocked source"),
        ],
        &[&approved],
    )
    .await;
    update(&source, "refs/heads/restricted", &blocked).await;
    let old = store
        .w3c_state(&state_key(
            "observation",
            &Repo::new("https://git.example.org/group/spec.git")
                .unwrap()
                .as_str(),
        ))
        .await
        .unwrap();
    assert!(
        corpus
            .observe_repository(
                &Repo::new("https://git.example.org/group/spec.git")
                    .unwrap()
                    .as_str(),
                CancellationToken::new()
            )
            .await
            .is_err()
    );
    assert_eq!(
        store
            .w3c_state(&state_key(
                "observation",
                &Repo::new("https://git.example.org/group/spec.git")
                    .unwrap()
                    .as_str()
            ))
            .await
            .unwrap(),
        old
    );
    assert!(
        durable
            .commit(&blocked, CancellationToken::new())
            .await
            .is_err()
    );
    assert_eq!(
        store
            .w3c_state(&state_key(
                "repository-license",
                &Repo::new("https://git.example.org/group/spec.git")
                    .unwrap()
                    .as_str()
            ))
            .await
            .unwrap()
            .unwrap()["decision"],
        "unresolved"
    );
    server.abort();
}
#[tokio::test]
async fn typed_hal_catalog_and_version_pages_resume_one_edition_at_a_time() {
    use crate::w3c::git::tests::serve_fixture;
    use axum::{Json, Router, routing::get};
    let app=Router::new().route("/specifications",get(||async{Json(json!({"_links":{"specifications":[{"href":"https://api.w3.org/specifications/example","title":"Example Standard"}]}}))}))
 .route("/specifications/example/versions",get(||async{Json(json!({"_links":{"version-history":[{"href":"https://api.w3.org/specifications/example/versions/20260101","title":"First"},{"href":"https://api.w3.org/specifications/example/versions/20260201","title":"Second"}]}}))}))
 .route("/specifications/example/versions/20260101",get(||async{Json(json!({"uri":"https://www.w3.org/TR/2026/WD-example-20260101/","status":"Working Draft"}))}))
 .route("/specifications/example/versions/20260201",get(||async{Json(json!({"uri":"https://www.w3.org/TR/2026/WD-example-20260201/","status":"Working Draft"}))}));
    let (broker, server) = serve_fixture(app).await;
    let (_root, _store, corpus) = corpus_fixture(broker).await;
    let catalog = corpus
        .acquire_catalog(CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(catalog.standards.len(), 1);
    assert_eq!(catalog.standards[0].id, "example");
    let mut standard = catalog.standards[0].clone();
    corpus
        .versions_step(&mut standard, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(standard.metadata["versions"].as_array().unwrap().len(), 1);
    assert_ne!(standard.metadata["versions_complete"], true);
    assert_eq!(standard.metadata["versions_pending_count"], 1);
    assert_eq!(
        corpus
            .store
            .w3c_state(&state_key("versions-pending", &standard.id))
            .await
            .unwrap()
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1
    );
    corpus
        .versions_step(&mut standard, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(standard.metadata["versions"].as_array().unwrap().len(), 2);
    assert_eq!(standard.metadata["versions_complete"], true);
    server.abort();
}
#[tokio::test]
async fn blocked_publication_retains_metadata_and_cannot_false_complete_frozen_current() {
    use crate::w3c::git::tests::serve_fixture;
    use axum::{Router, routing::get};
    let app = Router::new().route(
        "/TR/example/",
        get(|| async { "<h1>Example</h1><p>No notice.</p>" }),
    );
    let (broker, server) = serve_fixture(app).await;
    let (_root, store, corpus) = corpus_fixture(broker).await;
    let standard = Standard {
        id: "example".into(),
        title: "Example".into(),
        url: "https://www.w3.org/TR/example/".into(),
        repository: String::new(),
        metadata: json!({}),
    };
    let publication = corpus
        .capture_publication(
            &standard,
            PublicationUrl::new(&standard.url).unwrap(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert!(publication.artifact.is_none());
    assert_eq!(publication.license["decision"], "unresolved");
    assert!(
        corpus
            .process_publication(&standard, &publication, CancellationToken::new())
            .await
            .unwrap()
            .is_none()
    );
    let catalog = Catalog {
        id: inventory::digest(b"synthetic catalog"),
        observed_at: publication.observed_at,
        standards: vec![standard],
        gaps: Vec::new(),
    };
    store
        .w3c_put("catalogs", &catalog.id, &encode(&catalog).unwrap())
        .await
        .unwrap();
    store
        .w3c_set_state("catalog", &json!(catalog.id))
        .await
        .unwrap();
    let frozen = Frozen {
        id: inventory::digest(b"synthetic frozen"),
        catalog,
        observations: BTreeMap::new(),
        publications: vec![publication.id],
        mode: "current".into(),
        lineage: None,
    };
    let value = encode(&frozen).unwrap();
    store.w3c_put("frozen", &frozen.id, &value).await.unwrap();
    let outcome = corpus
        .accept_frozen_current(&value, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(outcome["complete"], false);
    assert_eq!(outcome["unavailable_publications"], 1);
    assert!(store.w3c_state("default").await.unwrap().is_none());
    server.abort();
}
#[test]
fn report_scopes_do_not_cross_monorepo_neighbors() {
    let standard = Standard {
        id: "first".into(),
        title: "First".into(),
        url: "https://www.w3.org/TR/first/".into(),
        repository: "https://git.example.org/mono.git".into(),
        metadata: json!({"source_mapping":{"kind":"revision_qualified_prefix","prefix":"first"}}),
    };
    assert!(source_path_selected(&standard, "first/index.html"));
    assert!(source_path_selected(&standard, "LICENSE"));
    assert!(!source_path_selected(&standard, "first-other/index.html"));
    assert!(!source_path_selected(&standard, "second/index.html"));
}

#[tokio::test]
async fn moved_monorepo_root_gets_immutable_mapping_successor_and_independent_report_cursors() {
    use crate::w3c::git::tests::{MIT_NOTICE, commit_files, fixture_router, serve_fixture, update};
    let _gate = crate::mdn::index::TEST_GATE.lock().await;
    let (_source_root, source) = source_fixture().await;
    let first=commit_files(&source,&[("LICENSE",MIT_NOTICE),("old/index.bs",b"<pre class=metadata>\nShortname: first\n</pre>\n# First\nOriginal first report."),("first/index.bs",b"<pre class=metadata>\nShortname: unrelated\n</pre>\n# Unrelated\nReferences https://www.w3.org/TR/first/ only."),("second/index.bs",b"<pre class=metadata>\nShortname: second\n</pre>\n# Second\nSecond report.")],&[]).await;
    let second=commit_files(&source,&[("LICENSE",MIT_NOTICE),("first/index.bs",b"<pre class=metadata>\nShortname: first\n</pre>\n# First\nMoved first report."),("second/index.bs",b"<pre class=metadata>\nShortname: second\n</pre>\n# Second\nSecond report changed.")],&[&first]).await;
    update(&source, "refs/heads/main", &second).await;
    let identity = Repo::new("https://git.example.org/group/spec.git")
        .unwrap()
        .as_str();
    let (broker, server) = serve_fixture(fixture_router(source)).await;
    let (_root, store, corpus) = corpus_fixture(broker).await;
    let observation = corpus
        .observe_repository(&identity, CancellationToken::new())
        .await
        .unwrap();
    let license = store
        .w3c_state(&state_key("repository-license", &identity))
        .await
        .unwrap()
        .unwrap();
    let mut standard = Standard {
        id: "first".into(),
        title: "First".into(),
        url: "https://www.w3.org/TR/first/".into(),
        repository: identity.clone(),
        metadata: json!({"source_mapping":{"kind":"candidate_prefix","prefix":"first","evidence_url":"https://www.w3.org/TR/first/"},"repository_license":license,"versions_complete":true}),
    };
    assert!(
        corpus
            .process_commit(&standard, &observation, &first, CancellationToken::new())
            .await
            .unwrap()
    );
    let unresolved = corpus
        .snapshot_for_revision("first", &identity, &first, "source")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(unresolved.coverage["usable"], false);
    assert_eq!(unresolved.coverage["source_mapping"]["kind"], "unresolved");
    standard.metadata["source_mapping"]["prefix"] = json!("old");
    assert!(
        corpus
            .process_commit(&standard, &observation, &first, CancellationToken::new())
            .await
            .unwrap()
    );
    let successor = corpus
        .snapshot_for_revision("first", &identity, &first, "source")
        .await
        .unwrap()
        .unwrap();
    assert_ne!(successor.id, unresolved.id);
    assert!(
        corpus
            .snapshot(&unresolved.id)
            .await
            .unwrap()
            .index
            .is_null()
    );
    assert_eq!(successor.coverage["usable"], true);
    assert!(
        successor.coverage["license"]["notice"]
            .as_str()
            .unwrap()
            .contains("THE SOFTWARE IS PROVIDED")
    );
    assert!(
        corpus
            .member(&successor, "old/index.bs")
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        corpus
            .member(&successor, "second/index.bs")
            .await
            .unwrap()
            .is_none()
    );
    // Both standards must independently process the first ancestor in the same shared mirror.
    standard.metadata["source_mapping"]["prefix"] = json!("first");
    let other = Standard {
        id: "second".into(),
        title: "Second".into(),
        url: "https://www.w3.org/TR/second/".into(),
        repository: identity.clone(),
        metadata: json!({"source_mapping":{"kind":"candidate_prefix","prefix":"second","evidence_url":"https://www.w3.org/TR/second/"},"repository_license":license,"versions_complete":true}),
    };
    let catalog = Catalog {
        id: inventory::digest(b"monorepo test catalog"),
        observed_at: devres_domain::unix_now(),
        standards: vec![standard, other],
        gaps: Vec::new(),
    };
    store
        .w3c_put("catalogs", &catalog.id, &encode(&catalog).unwrap())
        .await
        .unwrap();
    store
        .w3c_set_state("catalog", &json!(catalog.id))
        .await
        .unwrap();
    for s in &catalog.standards {
        store
            .w3c_set_state(
                &state_key("current-attempt", &s.id),
                &json!({"attempted_at":devres_domain::unix_now()}),
            )
            .await
            .unwrap();
    }
    corpus.history_step(CancellationToken::new()).await.unwrap();
    corpus.history_step(CancellationToken::new()).await.unwrap();
    assert!(
        corpus
            .snapshot_for_revision("second", &identity, &first, "source")
            .await
            .unwrap()
            .is_some()
    );
    server.abort();
}
#[test]
fn published_roles_are_w3c_specific_and_historical_status_is_capture_fixed() {
    let mut standard = Standard {
        id: "example".into(),
        title: "Example".into(),
        url: "https://www.w3.org/TR/example/".into(),
        repository: String::new(),
        metadata: json!({"publication_url":"https://www.w3.org/TR/2026/REC-example-20260101/","latest_tr_url":"https://www.w3.org/TR/2026/REC-example-20260101/","editor_draft":"https://drafts.example.org/example/","publication_status":"Recommendation","versions":[{"publication_url":"https://www.w3.org/TR/2025/WD-example-20250101/","status":"Working Draft"}]}),
    };
    let publication = |url: PublicationUrl| Publication {
        id: "fixture".into(),
        standard: "example".into(),
        url,
        observed_at: 1,
        artifact: None,
        status: 200,
        links: Vec::new(),
        gaps: Vec::new(),
        repositories: Vec::new(),
        chunk_hashes: Vec::new(),
        metadata_version: catalog::METADATA_VERSION,
        metadata_parent: None,
        advertisements: Vec::new(),
        exclusions: Vec::new(),
        license: json!({"decision":"approved"}),
    };
    let old = publication(
        PublicationUrl::new("https://www.w3.org/TR/2025/WD-example-20250101/").unwrap(),
    );
    assert_eq!(publication_edition(&standard, &old), "historical-tr");
    assert_eq!(
        catalog::publication_status(&standard, &old.url, &old.license),
        "Working Draft"
    );
    assert!(immutable_dated_publication(&old.url));
    let latest = publication(catalog::current_publication(&standard).unwrap());
    assert_eq!(publication_edition(&standard, &latest), "latest-tr");
    let editor = publication(catalog::editor_publication(&standard).unwrap());
    assert_eq!(publication_edition(&standard, &editor), "editor-draft");
    assert!(!immutable_dated_publication(&editor.url));
    standard.metadata["versions"] = json!([]);
    assert!(catalog::publication_status(&standard, &old.url, &old.license).is_null());
}
#[tokio::test]
async fn current_first_gate_does_not_issue_history_or_git_requests() {
    use crate::w3c::git::tests::serve_fixture;
    use axum::{Router, routing::get};
    use std::sync::atomic::{AtomicUsize, Ordering};
    let requests = Arc::new(AtomicUsize::new(0));
    let seen = requests.clone();
    let app = Router::new().fallback(get(move || {
        let seen = seen.clone();
        async move {
            seen.fetch_add(1, Ordering::SeqCst);
            "unexpected"
        }
    }));
    let (broker, server) = serve_fixture(app).await;
    let (_root, store, corpus) = corpus_fixture(broker).await;
    let standard = Standard {
        id: "pending".into(),
        title: "Pending".into(),
        url: "https://www.w3.org/TR/pending/".into(),
        repository: "https://git.example.org/pending.git".into(),
        metadata: json!({}),
    };
    let catalog = Catalog {
        id: inventory::digest(b"pending catalog"),
        observed_at: devres_domain::unix_now(),
        standards: vec![standard],
        gaps: Vec::new(),
    };
    store
        .w3c_put("catalogs", &catalog.id, &encode(&catalog).unwrap())
        .await
        .unwrap();
    store
        .w3c_set_state("catalog", &json!(catalog.id))
        .await
        .unwrap();
    corpus.history_step(CancellationToken::new()).await.unwrap();
    assert_eq!(requests.load(Ordering::SeqCst), 0);
    server.abort();
}
#[tokio::test]
async fn unchanged_detail_preserves_pending_history_and_new_latest_starts_successor() {
    use crate::w3c::git::tests::serve_fixture;
    use axum::{Json, Router, routing::get};
    use std::sync::atomic::{AtomicBool, Ordering};
    let changed = Arc::new(AtomicBool::new(false));
    let switch = changed.clone();
    let app=Router::new().route("/specifications/example",get(move||{let changed=switch.clone();async move{let version=if changed.load(Ordering::SeqCst){"20260201"}else{"20260101"};Json(json!({"title":"Example","shortname":"example","_links":{"latest-version":{"href":format!("https://api.w3.org/specifications/example/versions/{version}")}}}))}}))
 .route("/specifications/example/versions/20260101",get(||async{Json(json!({"uri":"https://www.w3.org/TR/2026/WD-example-20260101/","status":"Working Draft"}))}))
 .route("/specifications/example/versions/20260201",get(||async{Json(json!({"uri":"https://www.w3.org/TR/2026/WD-example-20260201/","status":"Working Draft"}))}));
    let (broker, server) = serve_fixture(app).await;
    let (_root, store, corpus) = corpus_fixture(broker).await;
    let standard = Standard {
        id: "example".into(),
        title: "Example".into(),
        url: "https://www.w3.org/TR/example/".into(),
        repository: String::new(),
        metadata: json!({"latest_version_api":"https://api.w3.org/specifications/example/versions/20260101","versions_complete":false,"versions_next_page":7,"versions_root":"retained-root","versions_count":12,"versions_pending_count":1}),
    };
    store
        .w3c_set_state(
            &state_key("versions-pending", &standard.id),
            &json!([{"uri":"https://www.w3.org/TR/2025/WD-example-20250101/"}]),
        )
        .await
        .unwrap();
    let same = corpus
        .hydrate_standard(&standard, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(same.metadata["versions_next_page"], 7);
    assert_eq!(same.metadata["versions_root"], "retained-root");
    assert_eq!(
        store
            .w3c_state(&state_key("versions-pending", &standard.id))
            .await
            .unwrap()
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1
    );
    changed.store(true, Ordering::SeqCst);
    let successor = corpus
        .hydrate_standard(&standard, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(successor.metadata["versions_next_page"], 1);
    assert_eq!(successor.metadata["versions_root"], "retained-root");
    assert_eq!(successor.metadata["versions_count"], 12);
    assert!(
        store
            .w3c_state(&state_key("versions-pending", &standard.id))
            .await
            .unwrap()
            .unwrap()
            .as_array()
            .unwrap()
            .is_empty()
    );
    server.abort();
}
#[tokio::test]
async fn full_version_bodies_live_outside_compact_catalog_and_inventory_replays() {
    let (_root, store, corpus) =
        corpus_fixture(Arc::new(BulkBroker::new(Default::default()).unwrap())).await;
    let mut standard = Standard {
        id: "example".into(),
        title: "Example".into(),
        url: "https://www.w3.org/TR/example/".into(),
        repository: String::new(),
        metadata: json!({"versions_has_next":false,"versions_capture":{"body_hash":inventory::digest(b"version page")}}),
    };
    let rows=(1..=40).map(|n|json!({"uri":format!("https://www.w3.org/TR/2026/WD-example-202601{n:02}/"),"status":"Working Draft","large_provider_metadata":"x".repeat(20000)})).collect::<Vec<_>>();
    store
        .w3c_set_state(&state_key("versions-pending", &standard.id), &json!(rows))
        .await
        .unwrap();
    for _ in 0..40 {
        corpus
            .versions_step(&mut standard, CancellationToken::new())
            .await
            .unwrap();
    }
    assert_eq!(standard.metadata["versions"].as_array().unwrap().len(), 8);
    assert_eq!(standard.metadata["versions_count"], 40);
    assert_eq!(corpus.edition_urls(&standard).await.unwrap().len(), 40);
    assert!(serde_json::to_vec(&standard).unwrap().len() < 8192);
    let root = standard.metadata["versions_root"].as_str().unwrap();
    let node = store.w3c_get("edition-nodes", root).await.unwrap().unwrap();
    store
        .w3c_set_state(
            &state_key("versions-root", &standard.id),
            &node.data["previous"],
        )
        .await
        .unwrap();
    standard.metadata["versions_complete"] = json!(false);
    let record = store
        .w3c_get(
            "version-records",
            node.data["entry"]["record"].as_str().unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    store
        .w3c_set_state(
            &state_key("versions-pending", &standard.id),
            &json!([record.data["metadata"]]),
        )
        .await
        .unwrap();
    corpus
        .versions_step(&mut standard, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(standard.metadata["versions_count"], 40);
    assert_eq!(corpus.edition_urls(&standard).await.unwrap().len(), 40);
}
#[tokio::test]
async fn large_licensed_raw_is_retained_beyond_projection_limit() {
    use crate::w3c::git::tests::serve_fixture;
    use axum::{Router, body::Body, routing::get};
    let app = Router::new().route(
        "/TR/example/large.txt",
        get(|| async {
            Body::from_stream(futures::stream::iter(
                (0..65).map(|_| Ok::<_, std::io::Error>(vec![b'x'; 1024 * 1024])),
            ))
        }),
    );
    let (broker, server) = serve_fixture(app).await;
    let (_root, _store, corpus) = corpus_fixture(broker).await;
    let uri = "https://www.w3.org/TR/example/large.txt";
    let standard = Standard {
        id: "example".into(),
        title: "Example".into(),
        url: "https://www.w3.org/TR/example/".into(),
        repository: String::new(),
        metadata: json!({"license":{"decision":"approved","license_url":catalog::DOCUMENT_LICENSE,"copyright":"Synthetic fixture notice","notice":"Synthetic fixture notice"},"licensed_alternates":[uri]}),
    };
    let publication = corpus
        .capture_publication(
            &standard,
            PublicationUrl::new(uri).unwrap(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(
        publication.artifact.as_ref().unwrap().bytes,
        65 * 1024 * 1024
    );
    let snapshot = corpus
        .process_publication(&standard, &publication, CancellationToken::new())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.coverage["usable"], false);
    assert!(
        snapshot.coverage["gaps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|g| g == "projection_input_limit")
    );
    server.abort();
}
#[tokio::test]
async fn moving_editor_revalidates_without_changing_old_capture_and_obeys_due_time() {
    use crate::w3c::git::tests::serve_fixture;
    use axum::{Router, routing::get};
    use std::sync::atomic::{AtomicBool, Ordering};
    let _gate = crate::mdn::index::TEST_GATE.lock().await;
    let changed = Arc::new(AtomicBool::new(false));
    let switch = changed.clone();
    let app=Router::new().route("/example/",get(move||{let changed=switch.clone();async move{let text=if changed.load(Ordering::SeqCst){"new-editor-body"}else{"old-editor-body"};format!("<h1>Example</h1><p class=copyright>Copyright 2026 W3C <a href='https://www.w3.org/copyright/document-license-2023/'>Document License</a></p><h2 id=body>Body</h2><p>{text}</p>")}}));
    let (broker, server) = serve_fixture(app).await;
    let observed = broker.clone();
    let (_root, store, corpus) = corpus_fixture(broker).await;
    let uri = "https://drafts.example.org/example/";
    let standard = Standard {
        id: "example".into(),
        title: "Example".into(),
        url: "https://www.w3.org/TR/example/".into(),
        repository: String::new(),
        metadata: json!({"editor_draft":uri,"versions_complete":true}),
    };
    let mut old = corpus
        .capture_publication(
            &standard,
            PublicationUrl::qualified(uri, &standard.url).unwrap(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    old.id = inventory::digest(b"synthetic old editor observation");
    old.observed_at = devres_domain::unix_now() - 86401;
    store
        .w3c_put("publications", &old.id, &encode(&old).unwrap())
        .await
        .unwrap();
    store
        .w3c_set_state(&state_key("publication", uri), &json!(old.id))
        .await
        .unwrap();
    let old_snapshot = corpus
        .process_publication(&standard, &old, CancellationToken::new())
        .await
        .unwrap()
        .unwrap();
    let catalog = Catalog {
        id: inventory::digest(b"editor test catalog"),
        observed_at: devres_domain::unix_now(),
        standards: vec![standard.clone()],
        gaps: Vec::new(),
    };
    store
        .w3c_put("catalogs", &catalog.id, &encode(&catalog).unwrap())
        .await
        .unwrap();
    store
        .w3c_set_state("catalog", &json!(catalog.id))
        .await
        .unwrap();
    store
        .w3c_set_state(
            &state_key("current-attempt", &standard.id),
            &json!({"attempted_at":devres_domain::unix_now()}),
        )
        .await
        .unwrap();
    changed.store(true, Ordering::SeqCst);
    corpus.history_step(CancellationToken::new()).await.unwrap();
    let latest = store
        .w3c_state(&state_key("publication", uri))
        .await
        .unwrap()
        .unwrap();
    assert_ne!(latest, json!(old.id));
    let publication: Publication = decode(
        store
            .w3c_get("publications", latest.as_str().unwrap())
            .await
            .unwrap()
            .unwrap()
            .data,
    )
    .unwrap();
    let new_snapshot = corpus
        .process_publication(&standard, &publication, CancellationToken::new())
        .await
        .unwrap()
        .unwrap();
    assert_ne!(new_snapshot.id, old_snapshot.id);
    let path = publication_path(uri, "html").unwrap();
    let old_document = corpus
        .projection(&old_snapshot, &path)
        .await
        .unwrap()
        .unwrap();
    let new_document = corpus
        .projection(&new_snapshot, &path)
        .await
        .unwrap()
        .unwrap();
    assert!(
        old_document["text"]
            .as_str()
            .unwrap()
            .contains("old-editor-body")
    );
    assert!(
        new_document["text"]
            .as_str()
            .unwrap()
            .contains("new-editor-body")
    );
    let attempts = observed.attempt_count();
    corpus.history_step(CancellationToken::new()).await.unwrap();
    assert_eq!(observed.attempt_count(), attempts);
    assert!(
        store
            .w3c_state(&state_key("publication-due", &standard.id))
            .await
            .unwrap()
            .unwrap()
            .as_i64()
            .unwrap()
            > devres_domain::unix_now()
    );
    server.abort();
}
