use super::*;
use async_trait::async_trait;
use devres_application::chromium::{ChromiumConfig, ChromiumStore, Row, Write};
use std::sync::Mutex;

#[derive(Default)]
struct Memory {
    rows: Mutex<BTreeMap<(String, String), Row>>,
    state: Mutex<BTreeMap<String, Value>>,
}
#[async_trait]
impl ChromiumStore for Memory {
    async fn chromium_cutoff(&self) -> Result<i64> {
        Ok(self
            .rows
            .lock()
            .unwrap()
            .values()
            .map(|r| r.sequence)
            .max()
            .unwrap_or(0))
    }
    async fn chromium_get(&self, kind: &str, key: &str) -> Result<Option<Row>> {
        Ok(self
            .rows
            .lock()
            .unwrap()
            .get(&(kind.into(), key.into()))
            .cloned())
    }
    async fn chromium_put(&self, kind: &str, key: &str, data: &Value) -> Result<i64> {
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
    async fn chromium_put_many(&self, rows: &[Write]) -> Result<()> {
        for row in rows {
            self.chromium_put(&row.kind, &row.key, &row.data).await?;
        }
        Ok(())
    }
    async fn chromium_rows(
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
    async fn chromium_state(&self, key: &str) -> Result<Option<Value>> {
        Ok(self.state.lock().unwrap().get(key).cloned())
    }
    async fn chromium_set_state(&self, key: &str, data: &Value) -> Result<()> {
        self.state.lock().unwrap().insert(key.into(), data.clone());
        Ok(())
    }
    async fn chromium_publish_view(&self, view: &View) -> Result<()> {
        let data = json!(view);
        self.chromium_put("views", &view.id, &data).await?;
        self.chromium_set_state("default", &data).await
    }
}
async fn fixture() -> (
    tempfile::TempDir,
    Arc<Memory>,
    Arc<ChromiumCorpus>,
    Snapshot,
) {
    use crate::{
        bulk::{BulkArtifactStore, BulkBroker, BulkConfig},
        chromium::index::IndexDocument,
        chromium::inventory,
    };
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(Memory::default());
    let corpus = Arc::new(
        ChromiumCorpus::new(
            store.clone(),
            Arc::new(BulkBroker::new(BulkConfig::default()).unwrap()),
            root.path(),
            ChromiumConfig {
                enabled: false,
                ..Default::default()
            },
        )
        .unwrap(),
    );
    let source=b"<h1 id=component>Synthetic component</h1><h2 id=events>Events</h2><p><dfn id=event>Event</dfn> dispatches an event.</p><pre class=idl>interface Event {}; interface EventTarget {};</pre>";
    let artifact =
        BulkArtifactStore::new(root.path().join("chromium/raw-artifacts"), 64 * 1024 * 1024)
            .unwrap()
            .capture_bytes(source.to_vec(), CancellationToken::new())
            .await
            .unwrap();
    let mut doc = json!(
        crate::chromium::processing::process_document(
            "index.html",
            source,
            CancellationToken::new()
        )
        .unwrap()
    );
    let index_id = digest(&"synthetic-section").unwrap();
    doc["index_ids"] = json!([index_id]);
    let projection = digest(&doc).unwrap();
    store
        .chromium_put("projections", &projection, &doc)
        .await
        .unwrap();
    let empty = inventory::empty(store.as_ref()).await.unwrap();
    let inventory = inventory::update(
        store.as_ref(),
        &empty,
        "index.html",
        Some(Member {
            path: "index.html".into(),
            oid: artifact.body_hash.clone(),
            mode: "100644".into(),
            kind: "blob".into(),
            projection: Some(projection),
            raw: Some(json!({"artifact":artifact})),
            gaps: vec![],
        }),
    )
    .await
    .unwrap();
    let index = corpus
        .index()
        .publish(
            None,
            vec![IndexDocument {
                id: index_id,
                component: "src".into(),
                edition: "source".into(),
                path: "index.html".into(),
                title: "Events".into(),
                text: "dispatches event".into(),
                kind: "section".into(),
                metadata: json!({"anchor":"events","synthetic":true}),
            }],
            CancellationToken::new(),
        )
        .await
        .unwrap();
    let snapshot = Snapshot {
        id: digest(&"fixture-snapshot").unwrap(),
        component: "src".into(),
        repository: "chromium/src".into(),
        revision: "a".repeat(40),
        tree: "b".repeat(40),
        parents: vec![],
        committed_at: 1,
        inventory,
        processor_version: 1,
        index: index.clone(),
        coverage: json!({"synthetic":true,"complete":true,"license":{"decision":"approved","license_url":"https://fixtures.invalid/license","copyright":"Synthetic fixture authors","notice":"Synthetic fixture; not upstream text."},"verification":"synthetic"}),
        source_url: "https://fixtures.invalid/chromium/".into(),
        representation: "source".into(),
        validated_at: devres_domain::unix_now(),
    };
    store
        .chromium_put("snapshots", &snapshot.id, &json!(snapshot))
        .await
        .unwrap();
    let catalog_id = digest(&"synthetic-catalog").unwrap();
    let now = devres_domain::unix_now();
    let catalog = json!({"id":catalog_id,"observed_at":now,"components":[{"id":"src","title":"DOM","url":"https://fixtures.invalid/chromium/","repository":"chromium/src","metadata":{"synthetic":true}}],"gaps":[]});
    store
        .chromium_put("catalogs", &catalog_id, &catalog)
        .await
        .unwrap();
    store
        .chromium_set_state("catalog", &json!(catalog_id))
        .await
        .unwrap();
    let view:View=serde_json::from_value(json!({"id":digest(&"synthetic-view").unwrap(),"catalog":catalog_id,"snapshots":{"src":snapshot.id},"index":index,"validations":{"src":now},"validated_at":now})).unwrap();
    store.chromium_publish_view(&view).await.unwrap();
    (root, store, corpus, snapshot)
}

#[tokio::test]
async fn immutable_text_source_symbol_search_and_resource_roundtrip() {
    let _gate = crate::mdn::index::TEST_GATE.lock().await;
    let (_root, _store, corpus, snapshot) = fixture().await;
    let research = ChromiumResearch::new(corpus);
    let get = research
        .call(
            "chromium.get",
            json!({"component":"src","snapshot":snapshot.id,"path":"index.html","anchor":"events"}),
        )
        .await
        .unwrap();
    assert!(get["page"]["text"].as_str().unwrap().contains("dispatches"));
    let resource = research
        .read_resource(get["resource_uri"].as_str().unwrap())
        .await
        .unwrap();
    assert_eq!(resource["contents"][0]["text"], get["page"]["text"]);
    assert_eq!(
        resource["contents"][0]["_meta"]["provenance"]["snapshot"],
        snapshot.id
    );
    assert_eq!(
        resource["contents"][0]["_meta"]["source_metadata"]["copyright"],
        "Synthetic fixture authors"
    );
    let raw=research.call("chromium.get",json!({"component":"src","snapshot":snapshot.id,"path":"index.html","representation":"bytes","limit":8})).await.unwrap();
    assert_eq!(
        STANDARD
            .decode(raw["page"]["base64"].as_str().unwrap())
            .unwrap(),
        b"<h1 id=c"
    );
    let symbol=research.call("chromium.symbol_get",json!({"component":"src","snapshot":snapshot.id,"path":"index.html","kind":"definition","name":"Event","limit":2})).await.unwrap();
    assert_eq!(symbol["page"]["text"], "Ev");
    assert_eq!(symbol["page"]["next_offset"], 2);
    let result = research
        .call(
            "chromium.search",
            json!({"component":"src","snapshot":snapshot.id,"query":"dispatches"}),
        )
        .await
        .unwrap();
    assert_eq!(result["total"], 1);
    assert_eq!(result["results"][0]["snapshot"], snapshot.id);
}

#[tokio::test]
async fn strict_selectors_and_unresolved_license_cannot_expose_content() {
    let _gate = crate::mdn::index::TEST_GATE.lock().await;
    let (_root, store, corpus, snapshot) = fixture().await;
    let research = ChromiumResearch::new(corpus);
    for input in [
        json!({"component":"src","snapshot":snapshot.id,"path":"index.html","url":"https://evil.invalid"}),
        json!({"component":"src","snapshot":snapshot.id,"view":"b".repeat(64),"path":"index.html"}),
        json!({"component":"site","snapshot":snapshot.id,"path":"index.html"}),
        json!({"component":"src","snapshot":snapshot.id,"path":"../index.html"}),
        json!({"component":"src","snapshot":snapshot.id}),
    ] {
        assert!(research.call("chromium.get", input).await.is_err());
    }
    let mut blocked = snapshot.clone();
    blocked.id = digest(&"blocked-license").unwrap();
    blocked.coverage["license"]["decision"] = json!("unresolved");
    store
        .chromium_put("snapshots", &blocked.id, &json!(blocked))
        .await
        .unwrap();
    for representation in ["text", "source", "bytes"] {
        assert!(research.call("chromium.get",json!({"component":"src","snapshot":blocked.id,"path":"index.html","representation":representation})).await.is_err());
    }
    assert!(
        research
            .call(
                "chromium.search",
                json!({"snapshot":blocked.id,"query":"dispatches"})
            )
            .await
            .is_err()
    );
}

#[tokio::test]
async fn symbol_cursor_is_query_bound_and_allows_changed_page_size() {
    let _gate = crate::mdn::index::TEST_GATE.lock().await;
    let (_root, _store, corpus, snapshot) = fixture().await;
    let research = ChromiumResearch::new(corpus);
    let first = research
        .call(
            "chromium.symbol_search",
            json!({"component":"src","snapshot":snapshot.id,"limit":1}),
        )
        .await
        .unwrap();
    let cursor = first["next_cursor"].as_str().unwrap();
    let second = research
        .call(
            "chromium.symbol_search",
            json!({"component":"src","snapshot":snapshot.id,"limit":100,"cursor":cursor}),
        )
        .await
        .unwrap();
    assert!(!second["items"].as_array().unwrap().is_empty());
    assert!(research.call("chromium.symbol_search",json!({"component":"src","snapshot":snapshot.id,"kind":"definition","cursor":cursor})).await.is_err());
}

#[tokio::test]
async fn partial_default_skips_expired_components_but_explicit_history_is_readable() {
    let _gate = crate::mdn::index::TEST_GATE.lock().await;
    let (_root, store, corpus, snapshot) = fixture().await;
    let mut old = snapshot.clone();
    old.id = digest(&"old-component").unwrap();
    old.component = "site".into();
    old.validated_at = 1;
    store
        .chromium_put("snapshots", &old.id, &json!(old))
        .await
        .unwrap();
    let mut view: View = retained(store.chromium_state("default").await.unwrap().unwrap()).unwrap();
    view.id = digest(&"partial-view").unwrap();
    view.snapshots.insert("site".into(), old.id.clone());
    view.validations.insert("site".into(), 1);
    store.chromium_publish_view(&view).await.unwrap();
    let research = ChromiumResearch::new(corpus);
    let result = research
        .call("chromium.search", json!({"query":"dispatches"}))
        .await
        .unwrap();
    assert_eq!(result["selections"].as_array().unwrap().len(), 1);
    assert_eq!(result["selections"][0]["component"], "src");
    assert!(
        research
            .call(
                "chromium.get",
                json!({"component":"site","path":"index.html"})
            )
            .await
            .is_err()
    );
    assert!(
        research
            .call(
                "chromium.get",
                json!({"component":"site","snapshot":old.id,"path":"index.html"})
            )
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn history_cutoff_and_ref_pages_preserve_filtered_continuations() {
    let _gate = crate::mdn::index::TEST_GATE.lock().await;
    let (_root, store, corpus, _snapshot) = fixture().await;
    let refs=(0..500).map(|i|json!({"name":format!("refs/heads/b{i}"),"revision":"a".repeat(40),"removed":false})).collect::<Vec<_>>();
    let first_id = digest(&refs).unwrap();
    store
        .chromium_put("ref-pages", &first_id, &json!(refs))
        .await
        .unwrap();
    let second =
        json!([{"name":"refs/branch-heads/wanted","revision":"b".repeat(40),"removed":true}]);
    let second_id = digest(&second).unwrap();
    store
        .chromium_put("ref-pages", &second_id, &second)
        .await
        .unwrap();
    store.chromium_put("observations","first",&json!({"component":"src","repository":"chromium/src","observed_at":1,"refs":[],"ref_pages":[first_id,second_id]})).await.unwrap();
    let research = ChromiumResearch::new(corpus);
    let first = research
        .call(
            "chromium.history",
            json!({"component":"src","history_type":"refs","query":"wanted"}),
        )
        .await
        .unwrap();
    assert!(first["items"].as_array().unwrap().is_empty());
    assert!(first["next_cursor"].is_string());
    store.chromium_put("observations","late",&json!({"component":"src","repository":"chromium/src","observed_at":2,"refs":[{"name":"refs/heads/wanted-late","revision":"c".repeat(40)}]})).await.unwrap();
    let second=research.call("chromium.history",json!({"component":"src","history_type":"refs","query":"wanted","cursor":first["next_cursor"]})).await.unwrap();
    assert_eq!(second["history_snapshot"], first["history_snapshot"]);
    assert_eq!(second["items"].as_array().unwrap().len(), 1);
    assert_eq!(second["items"][0]["ref"]["removed"], true);
}

#[tokio::test]
async fn repository_relative_targets_resolve_only_inside_selected_inventory() {
    let _gate = crate::mdn::index::TEST_GATE.lock().await;
    let (_root, _store, corpus, snapshot) = fixture().await;
    let member = corpus
        .member(&snapshot, "index.html")
        .await
        .unwrap()
        .unwrap();
    let mut targets = ReferenceTargets::new();
    let target = CapturedTarget {
        component: "src".into(),
        snapshot: snapshot.id.clone(),
        path: "docs/next.md".into(),
        anchors: Some(BTreeMap::from([("ok".into(), 1)])),
        anchors_loaded: true,
    };
    targets.insert(
        repository_target("src", "docs/next.md", None)
            .unwrap()
            .to_string(),
        Some(target),
    );
    let resolved = resolve_member_reference(
        "//docs/next.md#ok",
        &snapshot,
        &member,
        &targets,
        &BTreeMap::new(),
    );
    assert_eq!(resolved["state"], "captured_anchor");
    assert_eq!(resolved["path"], "docs/next.md");
    assert_eq!(
        resolve_member_reference(
            "../../missing.md",
            &snapshot,
            &member,
            &targets,
            &BTreeMap::new()
        )["state"],
        "unresolved_external"
    );
}

#[tokio::test]
async fn document_catalog_uses_snapshot_membership_and_query_bound_continuation() {
    let _gate = crate::mdn::index::TEST_GATE.lock().await;
    let (_root, _store, corpus, snapshot) = fixture().await;
    let research = ChromiumResearch::new(corpus);
    let first = research
        .call(
            "chromium.catalog_search",
            json!({"component":"src","snapshot":snapshot.id,"query":"index.html","limit":1}),
        )
        .await
        .unwrap();
    assert_eq!(first["items"].as_array().unwrap().len(), 1);
    assert_eq!(first["items"][0]["path"], "index.html");
    assert_eq!(first["items"][0]["snapshot"], snapshot.id);
    let continuation = first["next_cursor"].as_str().unwrap();
    let next=research.call("chromium.catalog_search",json!({"component":"src","snapshot":snapshot.id,"query":"index.html","cursor":continuation,"limit":100})).await.unwrap();
    assert!(next["items"].as_array().unwrap().is_empty());
    assert!(next["next_cursor"].is_null());
    assert!(research.call("chromium.catalog_search",json!({"component":"src","snapshot":snapshot.id,"query":"changed","cursor":continuation})).await.is_err());
}

#[tokio::test]
async fn approved_path_comparison_ignores_unrelated_metadata_only_license_gap() {
    let _gate = crate::mdn::index::TEST_GATE.lock().await;
    let (_root, store, corpus, snapshot) = fixture().await;
    let inventory = crate::chromium::inventory::update(
        store.as_ref(),
        &snapshot.inventory,
        "blocked.md",
        Some(Member {
            path: "blocked.md".into(),
            oid: "b".repeat(40),
            mode: "100644".into(),
            kind: "document".into(),
            projection: None,
            raw: None,
            gaps: vec!["license_scope_unresolved".into()],
        }),
    )
    .await
    .unwrap();
    let mut mixed = snapshot.clone();
    mixed.id = digest(&"mixed-license-snapshot").unwrap();
    mixed.inventory = inventory;
    store
        .chromium_put("snapshots", &mixed.id, &json!(mixed))
        .await
        .unwrap();
    let research = ChromiumResearch::new(corpus);
    let result=research.call("chromium.compare",json!({"component":"src","before":mixed.id,"after":mixed.id,"path":"index.html","mode":"source"})).await.unwrap();
    assert!(result["items"].as_array().unwrap().is_empty());
    assert!(
        research
            .call(
                "chromium.compare",
                json!({"component":"src","before":mixed.id,"after":mixed.id,"mode":"source"})
            )
            .await
            .is_err()
    );
    assert!(research.call("chromium.compare",json!({"component":"src","before":mixed.id,"after":mixed.id,"path":"blocked.md","mode":"source"})).await.is_err());
}
