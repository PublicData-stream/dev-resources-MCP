use super::*;
use async_trait::async_trait;
use devres_application::w3c::{Row, W3cConfig, W3cStore, Write};
use std::sync::Mutex;

#[derive(Default)]
struct Memory {
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
async fn fixture() -> (tempfile::TempDir, Arc<Memory>, Arc<W3cCorpus>, Snapshot) {
    use crate::{
        bulk::{BulkArtifactStore, BulkBroker, BulkConfig},
        w3c::index::IndexDocument,
        w3c::inventory,
    };
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(Memory::default());
    let corpus = Arc::new(
        W3cCorpus::new(
            store.clone(),
            Arc::new(BulkBroker::new(BulkConfig::default()).unwrap()),
            root.path(),
            W3cConfig {
                enabled: false,
                ..Default::default()
            },
        )
        .unwrap(),
    );
    let source=b"<h1 id=standard>Synthetic standard</h1><h2 id=events>Events</h2><p><dfn id=event>Event</dfn> dispatches an event.</p><pre class=idl>interface Event {}; interface EventTarget {};</pre>";
    let artifact = BulkArtifactStore::new(root.path().join("w3c/raw-artifacts"), 64 * 1024 * 1024)
        .unwrap()
        .capture_bytes(source.to_vec(), CancellationToken::new())
        .await
        .unwrap();
    let mut doc = json!(
        crate::w3c::processing::process_document("index.html", source, CancellationToken::new())
            .unwrap()
    );
    let index_id = digest(&"synthetic-section").unwrap();
    doc["index_ids"] = json!([index_id]);
    let projection = digest(&doc).unwrap();
    store
        .w3c_put("projections", &projection, &doc)
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
                standard: "dom".into(),
                edition: "living".into(),
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
        standard: "dom".into(),
        repository: "w3c/dom".into(),
        revision: "a".repeat(40),
        tree: "b".repeat(40),
        parents: vec![],
        committed_at: 1,
        inventory,
        processor_version: 1,
        index: index.clone(),
        coverage: json!({"synthetic":true,"complete":true,"license":{"decision":"approved","license_url":"https://www.w3.org/copyright/document-license-2023/","copyright":"Synthetic fixture authors","notice":"Synthetic fixture; not upstream text."},"publication_status":"REC","publication_role":"latest_tr","latest_publication":"https://www.w3.org/TR/dom/","effective_publication":"https://www.w3.org/TR/dom/"}),
        source_url: "https://www.w3.org/TR/dom/".into(),
        representation: "living".into(),
        validated_at: devres_domain::unix_now(),
    };
    store
        .w3c_put("snapshots", &snapshot.id, &json!(snapshot))
        .await
        .unwrap();
    let catalog_id = digest(&"synthetic-catalog").unwrap();
    let now = devres_domain::unix_now();
    let catalog = json!({"id":catalog_id,"observed_at":now,"standards":[{"id":"dom","title":"DOM","url":"https://www.w3.org/TR/dom/","repository":"w3c/dom","metadata":{"synthetic":true}}],"gaps":[]});
    store
        .w3c_put("catalogs", &catalog_id, &catalog)
        .await
        .unwrap();
    store
        .w3c_set_state("catalog", &json!(catalog_id))
        .await
        .unwrap();
    let view:View=serde_json::from_value(json!({"id":digest(&"synthetic-view").unwrap(),"catalog":catalog_id,"snapshots":{"dom":snapshot.id},"index":index,"validations":{"dom":now},"validated_at":now})).unwrap();
    store.w3c_publish_view(&view).await.unwrap();
    (root, store, corpus, snapshot)
}
#[tokio::test]
async fn historical_notice_selectors_are_callable_without_rewriting_retained_evidence() {
    fn assert_selectors(value: &Value, snapshot: &str) {
        match value {
            Value::Object(fields) => {
                if let Some(selector) = fields.get("source_selector")
                    && selector["snapshot"] == snapshot
                {
                    assert_eq!(selector["tool"], "w3c.get");
                }
                for child in fields.values() {
                    assert_selectors(child, snapshot);
                }
            }
            Value::Array(items) => {
                for child in items {
                    assert_selectors(child, snapshot);
                }
            }
            _ => {}
        }
    }
    let _gate = crate::mdn::index::TEST_GATE.lock().await;
    let (_root, store, corpus, mut snapshot) = fixture().await;
    let research = W3cResearch::new(corpus);
    let original = research.call("w3c.get", json!({"specification":"dom","snapshot":snapshot.id,"path":"index.html","representation":"source"})).await.unwrap();
    snapshot.id = digest(&"historical-notice-selector").unwrap();
    snapshot.coverage["license"]["notices"] = json!([{
        "path":"index.html",
        "source_selector":{"tool":"w3c_get","specification":"dom","snapshot":snapshot.id,"path":"index.html","representation":"source"}
    }]);
    snapshot.coverage["license"]["original_metadata"] = json!({"tool":"w3c_get"});
    let retained = json!(snapshot);
    let retained_bytes = serde_json::to_vec(&retained).unwrap();
    store
        .w3c_put("snapshots", &snapshot.id, &retained)
        .await
        .unwrap();
    let output = research.call("w3c.get", json!({"specification":"dom","snapshot":snapshot.id,"path":"index.html","representation":"source"})).await.unwrap();
    assert_selectors(&output, &snapshot.id);
    assert_eq!(output["page"]["text"], original["page"]["text"]);
    assert_eq!(
        output["selection"]["coverage"]["license"]["notices"][0]["source_selector"]["tool"],
        "w3c.get"
    );
    assert_eq!(
        output["license"]["evidence"]["original_metadata"]["tool"],
        "w3c_get"
    );
    let mut selector = output["license"]["evidence"]["notices"][0]["source_selector"]
        .as_object()
        .unwrap()
        .clone();
    let tool = selector.remove("tool").unwrap();
    let selected = research
        .call(tool.as_str().unwrap(), Value::Object(selector))
        .await
        .unwrap();
    assert_eq!(selected["page"]["text"], original["page"]["text"]);
    assert_eq!(selected["selection"]["snapshot"], snapshot.id);
    let resource = research
        .read_resource(output["resource_uri"].as_str().unwrap())
        .await
        .unwrap();
    assert_selectors(&resource, &snapshot.id);
    assert_eq!(resource["contents"][0]["text"], original["page"]["text"]);
    let stored = store
        .w3c_get("snapshots", &snapshot.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(serde_json::to_vec(&stored.data).unwrap(), retained_bytes);
}

#[tokio::test]
async fn immutable_text_source_symbols_search_and_resource_roundtrip() {
    let _gate = crate::mdn::index::TEST_GATE.lock().await;
    let (_root, _store, corpus, snapshot) = fixture().await;
    let research = W3cResearch::new(corpus);
    let get = research
        .call(
            "w3c.get",
            json!({"specification":"dom","snapshot":snapshot.id,"path":"index.html","anchor":"events"}),
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
        resource["contents"][0]["_meta"]["source_url"],
        snapshot.source_url
    );
    assert!(resource["contents"][0]["_meta"]["license"].is_object());
    let raw=research.call("w3c.get",json!({"specification":"dom","snapshot":snapshot.id,"path":"index.html","representation":"bytes","limit":8})).await.unwrap();
    assert_eq!(
        STANDARD
            .decode(raw["page"]["base64"].as_str().unwrap())
            .unwrap(),
        b"<h1 id=s"
    );
    let symbols = research
        .call(
            "w3c.symbol_search",
            json!({"specification":"dom","snapshot":snapshot.id,"kind":"definition"}),
        )
        .await
        .unwrap();
    assert_eq!(symbols["items"][0]["symbol"]["name"], "Event");
    assert!(symbols["items"][0]["symbol"].get("text").is_none());
    let symbol=research.call("w3c.symbol_get",json!({"specification":"dom","snapshot":snapshot.id,"kind":"definition","name":"Event","limit":2})).await.unwrap();
    assert_eq!(symbol["page"]["text"], "Ev");
    assert_eq!(symbol["page"]["next_offset"], 2);
    let idl = research
        .call(
            "w3c.symbol_get",
            json!({"specification":"dom","snapshot":snapshot.id,"kind":"idl","name":"EventTarget"}),
        )
        .await
        .unwrap();
    let idl_resource = research
        .read_resource(idl["resource_uri"].as_str().unwrap())
        .await
        .unwrap();
    assert_eq!(idl_resource["contents"][0]["text"], idl["page"]["text"]);
    assert!(idl_resource["contents"][0]["_meta"]["license"].is_object());
    assert!(idl_resource["contents"][0]["_meta"]["gaps"]["processing"].is_array());
    let result = research
        .call(
            "w3c.search",
            json!({"specification":"dom","snapshot":snapshot.id,"query":"dispatches"}),
        )
        .await
        .unwrap();
    assert_eq!(result["total"], 1);
    assert!(
        research
            .call(
                "w3c.get",
                json!({"specification":"html","snapshot":snapshot.id,"path":"index.html"})
            )
            .await
            .is_err()
    );
    assert!(
        research
            .read_resource(&format!("{}&evil=1", get["resource_uri"].as_str().unwrap()))
            .await
            .is_err()
    );
    assert!(
        research
            .call("w3c.corpus_status", json!({"url":"https://evil.invalid/"}))
            .await
            .is_err()
    );
}
#[test]
fn cursors_bind_query_but_allow_page_size_changes() {
    let first = page(
        vec![json!(1), json!(2), json!(3)],
        "selected-query".into(),
        0,
        1,
    )
    .unwrap();
    let cursor = first["next_cursor"].as_str().unwrap();
    assert_eq!(position("selected-query", 0, Some(cursor), 2).unwrap(), 1);
    assert!(position("different-query", 0, Some(cursor), 2).is_err());
    assert!(position("selected-query", 1, Some(cursor), 2).is_err());
}
#[tokio::test]
async fn discovery_cursor_carries_frozen_cutoff_through_empty_filtered_pages() {
    let _gate = crate::mdn::index::TEST_GATE.lock().await;
    let (_root, store, corpus, snapshot) = fixture().await;
    for number in 0..501 {
        let mut value = json!(snapshot);
        value["standard"] = json!("other");
        value["id"] = json!(digest(&number).unwrap());
        store
            .w3c_put("snapshots", value["id"].as_str().unwrap(), &value)
            .await
            .unwrap();
    }
    let research = W3cResearch::new(corpus);
    let first = research
        .call("w3c.snapshots", json!({"specification":"absent"}))
        .await
        .unwrap();
    assert_eq!(first["items"], json!([]));
    assert!(first["next_cursor"].is_string());
    let mut later = json!(snapshot);
    later["standard"] = json!("absent");
    later["id"] = json!(digest(&"later").unwrap());
    store
        .w3c_put("snapshots", later["id"].as_str().unwrap(), &later)
        .await
        .unwrap();
    let second = research
        .call(
            "w3c.snapshots",
            json!({"specification":"absent","cursor":first["next_cursor"]}),
        )
        .await
        .unwrap();
    assert_eq!(second["history_snapshot"], first["history_snapshot"]);
    assert_eq!(second["items"], json!([]));
    assert!(second["next_cursor"].is_null());
}

#[tokio::test]
async fn successful_view_validation_is_distinct_from_original_snapshot_time() {
    let _gate = crate::mdn::index::TEST_GATE.lock().await;
    let (_root, store, corpus, mut snapshot) = fixture().await;
    snapshot.id = digest(&"old-original-snapshot").unwrap();
    snapshot.validated_at = devres_domain::unix_now() - 8 * 86400;
    store
        .w3c_put("snapshots", &snapshot.id, &json!(snapshot))
        .await
        .unwrap();
    let mut view = corpus.view(None).await.unwrap();
    view.id = digest(&"revalidated-view").unwrap();
    view.snapshots.insert("dom".into(), snapshot.id.clone());
    store.w3c_publish_view(&view).await.unwrap();
    let research = W3cResearch::new(corpus.clone());
    let current = research
        .call(
            "w3c.get",
            json!({"specification":"dom","path":"index.html"}),
        )
        .await
        .unwrap();
    assert_eq!(current["selection"]["stale"], false);
    view.id = digest(&"expired-view").unwrap();
    view.validations.insert("dom".into(), snapshot.validated_at);
    view.validated_at = snapshot.validated_at;
    store.w3c_publish_view(&view).await.unwrap();
    assert!(
        research
            .call(
                "w3c.get",
                json!({"specification":"dom","path":"index.html"})
            )
            .await
            .is_err()
    );
    assert!(
        research
            .call("w3c.search", json!({"specification":"dom","query":"event"}))
            .await
            .is_err()
    );
    let historical = research
        .call(
            "w3c.get",
            json!({"specification":"dom","snapshot":snapshot.id,"path":"index.html"}),
        )
        .await
        .unwrap();
    assert_eq!(historical["selection"]["stale"], true);
    assert!(
        research
            .call("w3c.catalog_search", json!({"snapshot":snapshot.id}))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn github_repository_links_do_not_resolve_by_shared_host() {
    let _gate = crate::mdn::index::TEST_GATE.lock().await;
    let (_root, _store, _corpus, mut snapshot) = fixture().await;
    snapshot.representation = "source".into();
    snapshot.source_url = "https://github.com/w3c/dom/tree/0000".into();
    assert_eq!(
        resolve_reference(
            "https://github.com/w3c/html",
            &snapshot,
            std::slice::from_ref(&snapshot)
        )["state"],
        "unresolved_external"
    );
    assert_eq!(
        resolve_reference(
            "https://www.w3.org/TR/dom/#event",
            &snapshot,
            std::slice::from_ref(&snapshot)
        )["state"],
        "unresolved_external"
    );
    snapshot.representation = "html".into();
    snapshot.source_url = "https://www.w3.org/TR/dom/".into();
    assert_eq!(
        resolve_reference(
            "https://www.w3.org/TR/dom/#event",
            &snapshot,
            std::slice::from_ref(&snapshot)
        )["specification"],
        "dom"
    );
    assert_eq!(
        resolve_reference(
            "https://www.w3.org/TR/other/#event",
            &snapshot,
            std::slice::from_ref(&snapshot)
        )["state"],
        "unresolved_external"
    );
}

#[tokio::test]
async fn ref_observations_page_inside_a_frozen_observation() {
    let _gate = crate::mdn::index::TEST_GATE.lock().await;
    let (_root, store, corpus, _snapshot) = fixture().await;
    let artifact =
        json!({"body_hash":"a".repeat(64),"bytes":0,"relative_path":"synthetic-observation"});
    let mut observation = json!({"repo":crate::w3c::git::Repo::new("w3c/dom").unwrap(),"observed_at":42,
        "refs":[{"name":"refs/heads/main","oid":"a".repeat(40),"object_type":"commit","peeled_commit":"a".repeat(40)},
            {"name":"refs/heads/older","oid":"b".repeat(40),"object_type":"commit","peeled_commit":"b".repeat(40)},
            {"name":"refs/tags/review","oid":"c".repeat(40),"object_type":"commit","peeled_commit":"c".repeat(40)}],
        "roots":[],"manifest":artifact,"commits":artifact,"total_commits":3,"main_revision":"a".repeat(40),"current_ref":"refs/heads/main"});
    store
        .w3c_put("observations", "first-ref-observation", &observation)
        .await
        .unwrap();
    let research = W3cResearch::new(corpus);
    let first = research
        .call(
            "w3c.history",
            json!({"history_type":"refs","repository":"https://github.com/w3c/dom.git","limit":1}),
        )
        .await
        .unwrap();
    assert_eq!(first["items"][0]["ref"]["name"], "refs/heads/main");
    assert!(first["next_cursor"].is_string());
    observation["observed_at"] = json!(43);
    store
        .w3c_put("observations", "later-ref-observation", &observation)
        .await
        .unwrap();
    let second=research.call("w3c.history",json!({"history_type":"refs","repository":"https://github.com/w3c/dom.git","cursor":first["next_cursor"],"limit":100})).await.unwrap();
    assert_eq!(second["history_snapshot"], first["history_snapshot"]);
    assert_eq!(second["items"].as_array().unwrap().len(), 2);
    assert!(second["next_cursor"].is_null());
    assert!(research.call("w3c.history",json!({"history_type":"refs","repository":"https://github.com/w3c/html.git","cursor":first["next_cursor"]})).await.is_err());
}

#[tokio::test]
async fn future_history_and_unapplied_ref_filters_fail_explicitly() {
    let _gate = crate::mdn::index::TEST_GATE.lock().await;
    let (_root, store, corpus, _before) = fixture().await;
    let research = W3cResearch::new(corpus);
    assert!(
        research
            .call("w3c.history", json!({"ref":"refs/heads/main"}))
            .await
            .is_err()
    );
    let future = store.w3c_cutoff().await.unwrap() + 100;
    assert!(
        research
            .call("w3c.history", json!({"history_snapshot":future}))
            .await
            .is_err()
    );
    assert!(
        research
            .call(
                "w3c.history",
                json!({"history_type":"refs","history_snapshot":future})
            )
            .await
            .is_err()
    );
}
#[tokio::test]
async fn failed_projection_is_not_a_removed_section_in_comparison() {
    let _gate = crate::mdn::index::TEST_GATE.lock().await;
    let (_root, store, corpus, before) = fixture().await;
    let mut member = corpus.member(&before, "index.html").await.unwrap().unwrap();
    member.projection = None;
    member.gaps = vec!["processing_capacity".into()];
    let inventory = crate::w3c::inventory::update(
        store.as_ref(),
        &before.inventory,
        "index.html",
        Some(member),
    )
    .await
    .unwrap();
    let mut after = before.clone();
    after.id = digest(&"failed-projection").unwrap();
    after.inventory = inventory;
    after.coverage["projection_gaps"] = json!(1);
    store
        .w3c_put("snapshots", &after.id, &json!(after))
        .await
        .unwrap();
    let research = W3cResearch::new(corpus);
    let error = research
        .call(
            "w3c.compare",
            json!({"specification":"dom","before":before.id,"after":after.id}),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, "unavailable");
    let raw = research
        .call(
            "w3c.compare",
            json!({"specification":"dom","before":before.id,"after":after.id,"mode":"source"}),
        )
        .await
        .unwrap();
    assert_eq!(raw["total"], 0);
}

#[tokio::test]
async fn published_revisions_compare_by_sections_across_versioned_urls() {
    let _gate = crate::mdn::index::TEST_GATE.lock().await;
    let (_root, store, corpus, mut before) = fixture().await;
    before.id = digest(&"living-html").unwrap();
    before.representation = "html".into();
    before.repository = "https://www.w3.org/TR/dom/".into();
    store
        .w3c_put("snapshots", &before.id, &json!(before))
        .await
        .unwrap();
    let mut member = corpus.member(&before, "index.html").await.unwrap().unwrap();
    member.path = "commit-snapshots/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/index.html".into();
    let empty = crate::w3c::inventory::empty(store.as_ref()).await.unwrap();
    let root =
        crate::w3c::inventory::update(store.as_ref(), &empty, &member.path, Some(member.clone()))
            .await
            .unwrap();
    let mut after = before.clone();
    after.id = digest(&"commit-html").unwrap();
    after.inventory = root;
    after.repository =
        "https://www.w3.org/TR/dom/commit-snapshots/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"
            .into();
    after.source_url = after.repository.clone();
    store
        .w3c_put("snapshots", &after.id, &json!(after))
        .await
        .unwrap();
    let research = W3cResearch::new(corpus);
    for mode in ["text", "symbols", "source"] {
        let result=research.call("w3c.compare",json!({"specification":"dom","before":before.id,"after":after.id,"mode":mode,"path":"index.html"})).await.unwrap();
        assert_eq!(result["total"], 0, "{mode}");
    }
    let mut moved_member = member.clone();
    moved_member.path = "review-drafts/2026-06/index.html".into();
    let mut moved = after.clone();
    moved.id = digest(&"review-html").unwrap();
    moved.inventory = crate::w3c::inventory::update(
        store.as_ref(),
        &empty,
        &moved_member.path,
        Some(moved_member.clone()),
    )
    .await
    .unwrap();
    moved.repository = "https://www.w3.org/TR/dom/review-drafts/2026-06/".into();
    moved.source_url = moved.repository.clone();
    store
        .w3c_put("snapshots", &moved.id, &json!(moved))
        .await
        .unwrap();
    for path in [&member.path, &moved_member.path] {
        for mode in ["text", "symbols", "source"] {
            let result=research.call("w3c.compare",json!({"specification":"dom","before":after.id,"after":moved.id,"mode":mode,"path":path})).await.unwrap();
            assert_eq!(result["total"], 0, "{path} {mode}");
        }
    }
    let original = research
        .corpus
        .raw_page(&before, "index.html", 0, 32768)
        .await
        .unwrap();
    let mut bytes = STANDARD
        .decode(original["base64"].as_str().unwrap())
        .unwrap();
    bytes.extend_from_slice(b"<!-- raw-only change -->");
    let artifact = crate::bulk::BulkArtifactStore::new(
        _root.path().join("w3c/raw-artifacts"),
        64 * 1024 * 1024,
    )
    .unwrap()
    .capture_bytes(bytes, CancellationToken::new())
    .await
    .unwrap();
    moved_member.oid = artifact.body_hash.clone();
    moved_member.raw = Some(json!({"artifact":artifact}));
    let mut changed = moved.clone();
    changed.id = digest(&"raw-changed-review").unwrap();
    changed.inventory = crate::w3c::inventory::update(
        store.as_ref(),
        &empty,
        &moved_member.path,
        Some(moved_member.clone()),
    )
    .await
    .unwrap();
    store
        .w3c_put("snapshots", &changed.id, &json!(changed))
        .await
        .unwrap();
    for path in [&member.path, &moved_member.path] {
        let result=research.call("w3c.compare",json!({"specification":"dom","before":after.id,"after":changed.id,"mode":"source","path":path})).await.unwrap();
        assert_eq!(result["total"], 1, "{path}");
    }
}

#[tokio::test]
async fn maximum_unicode_paths_anchors_and_symbol_names_have_bounded_resource_uris() {
    let _gate = crate::mdn::index::TEST_GATE.lock().await;
    let (_root, store, corpus, mut snapshot) = fixture().await;
    let path = format!("{}a.md", "🦀".repeat(1023));
    assert_eq!(path.len(), 4096);
    assert!(crate::w3c::inventory::valid_path(&path));
    let anchor = "🦀".repeat(4095);
    let symbol_anchor = "🧬".repeat(4095);
    let name = "界".repeat(4096);
    let source = format!(
        "<h1 id=start>Bounded fixture</h1><h2 id=\"{anchor}\">Large section</h2><p>fixture text</p><dfn id=\"{symbol_anchor}\">{name}</dfn>"
    );
    let mut document = crate::w3c::processing::process_document(
        "index.html",
        source.as_bytes(),
        CancellationToken::new(),
    )
    .unwrap();
    assert_eq!(document.sections[1].anchor, anchor);
    assert!(document.symbols[0].name.len() <= 4096);
    assert_eq!(document.symbols[0].text, name);
    // Retained processor-2 labels used a character bound. Their longer names
    // must remain readable even after new projections use the byte bound.
    document.symbols[0].name = name.clone();
    let projection = json!(document);
    let projection_id = digest(&projection).unwrap();
    store
        .w3c_put("projections", &projection_id, &projection)
        .await
        .unwrap();
    let mut member = corpus
        .member(&snapshot, "index.html")
        .await
        .unwrap()
        .unwrap();
    member.path = path.clone();
    member.projection = Some(projection_id);
    let empty = crate::w3c::inventory::empty(store.as_ref()).await.unwrap();
    snapshot.id = digest(&"maximum Unicode URI fixture").unwrap();
    snapshot.processor_version = 2;
    snapshot.inventory = crate::w3c::inventory::update(store.as_ref(), &empty, &path, Some(member))
        .await
        .unwrap();
    store
        .w3c_put("snapshots", &snapshot.id, &json!(snapshot))
        .await
        .unwrap();
    let old_query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("anchor", &symbol_anchor)
        .append_pair("name", &name)
        .append_pair("kind", "definition")
        .finish();
    assert!(
        format!("{}?{old_query}", resource(&snapshot, "symbol", &path, None)).len() > 16384,
        "the previous full-selector URI exceeded the actual generic resource routing bound"
    );
    let research = W3cResearch::new(corpus);
    let section = research
        .call(
            "w3c.get",
            json!({"specification":"dom","snapshot":snapshot.id,"path":path,"anchor":anchor}),
        )
        .await
        .unwrap();
    assert_eq!(section["section_index"], 1);
    let direct_section = research
        .call(
            "w3c.get",
            json!({"specification":"dom","snapshot":snapshot.id,"path":path,"section_index":1}),
        )
        .await
        .unwrap();
    assert_eq!(direct_section["page"], section["page"]);
    let symbol = research
        .call(
            "w3c.symbol_get",
            json!({"specification":"dom","snapshot":snapshot.id,"path":path,"name":name}),
        )
        .await
        .unwrap();
    assert_eq!(symbol["symbol_index"], 0);
    let anchored_symbol = research
        .call(
            "w3c.get",
            json!({"specification":"dom","snapshot":snapshot.id,"path":path,"anchor":symbol_anchor}),
        )
        .await
        .unwrap();
    assert_eq!(anchored_symbol["page"]["text"], symbol["page"]["text"]);
    let found = research
        .call(
            "w3c.symbol_search",
            json!({"specification":"dom","snapshot":snapshot.id,"path":path,"kind":"definition"}),
        )
        .await
        .unwrap();
    assert_eq!(found["items"][0]["symbol_index"], 0);
    for selected in [
        &section,
        &direct_section,
        &symbol,
        &anchored_symbol,
        &found["items"][0],
    ] {
        let uri = selected["resource_uri"].as_str().unwrap();
        assert!(
            uri.len() <= 16384,
            "generated URI must pass generic resource routing"
        );
        let parsed = url::Url::parse(uri).unwrap();
        assert!(
            parsed
                .query_pairs()
                .all(|(key, _)| matches!(key.as_ref(), "section_index" | "symbol_index"))
        );
        let read = research.read_resource(uri).await.unwrap();
        let expected = if selected.get("page").is_some() {
            &selected["page"]["text"]
        } else {
            &symbol["page"]["text"]
        };
        assert_eq!(&read["contents"][0]["text"], expected);
        assert_eq!(
            read["contents"][0]["_meta"]["provenance"]["snapshot"],
            snapshot.id
        );
        assert_eq!(
            read["contents"][0]["_meta"]["provenance"]["processor_version"],
            2
        );
        assert_eq!(read["contents"][0]["_meta"]["source_path"], path);
    }
}

#[tokio::test]
async fn resource_ordinals_preserve_legacy_selectors_and_validate_document_bounds() {
    let _gate = crate::mdn::index::TEST_GATE.lock().await;
    let (_root, _store, corpus, snapshot) = fixture().await;
    let research = W3cResearch::new(corpus);
    let section = research
        .call(
            "w3c.get",
            json!({"specification":"dom","snapshot":snapshot.id,"path":"index.html","anchor":"events"}),
        )
        .await
        .unwrap();
    let legacy_section = format!(
        "{}?anchor=events",
        resource(&snapshot, "text", "index.html", None)
    );
    assert_eq!(
        research.read_resource(&legacy_section).await.unwrap()["contents"][0]["text"],
        section["page"]["text"]
    );
    let symbol = research
        .call(
            "w3c.symbol_get",
            json!({"specification":"dom","snapshot":snapshot.id,"name":"EventTarget","kind":"idl"}),
        )
        .await
        .unwrap();
    let legacy_query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("anchor", symbol["anchor"].as_str().unwrap())
        .append_pair("name", "EventTarget")
        .append_pair("kind", "idl")
        .finish();
    let legacy_symbol = format!(
        "{}?{legacy_query}",
        resource(&snapshot, "symbol", "index.html", None)
    );
    assert_eq!(
        research.read_resource(&legacy_symbol).await.unwrap()["contents"][0]["text"],
        symbol["page"]["text"]
    );
    let found = research
        .call(
            "w3c.symbol_search",
            json!({"specification":"dom","snapshot":snapshot.id,"name":"EventTarget","kind":"idl"}),
        )
        .await
        .unwrap();
    assert_eq!(
        found["items"][0]["symbol_index"], symbol["symbol_index"],
        "filtering cannot renumber symbols"
    );
    let indexed=research.call("w3c.symbol_get",json!({"specification":"dom","snapshot":snapshot.id,"path":"index.html","symbol_index":symbol["symbol_index"]})).await.unwrap();
    assert_eq!(indexed["page"], symbol["page"]);
    for (tool, arguments) in [
        ("w3c.get", json!({"section_index":0})),
        (
            "w3c.get",
            json!({"path":"index.html","section_index":0,"anchor":"events"}),
        ),
        (
            "w3c.get",
            json!({"path":"index.html","section_index":0,"representation":"bytes"}),
        ),
        (
            "w3c.get",
            json!({"path":"index.html","section_index":99999}),
        ),
        ("w3c.symbol_get", json!({"symbol_index":0})),
        (
            "w3c.symbol_get",
            json!({"path":"index.html","symbol_index":99999}),
        ),
        (
            "w3c.symbol_get",
            json!({"path":"index.html","symbol_index":0,"name":"EventTarget"}),
        ),
    ] {
        let mut input = arguments;
        input["specification"] = json!("dom");
        input["snapshot"] = json!(snapshot.id);
        assert!(
            research.call(tool, input).await.is_err(),
            "invalid ordinal selection must not fall back"
        );
    }
    for suffix in [
        "?section_index=-1",
        "?section_index=0&anchor=events",
        "?section_index=0&section_index=1",
    ] {
        let uri = format!(
            "{}{suffix}",
            resource(&snapshot, "text", "index.html", None)
        );
        assert!(research.read_resource(&uri).await.is_err());
    }
    for name in ["w3c.get", "w3c.symbol_get"] {
        let schema = schemas()
            .into_iter()
            .find(|schema| schema["name"] == name)
            .unwrap();
        assert!(schema["inputSchema"]["allOf"].is_array());
        assert!(schema["inputSchema"]["properties"].get("allOf").is_none());
        assert_eq!(schema["inputSchema"]["additionalProperties"], false);
    }
}

#[tokio::test]
async fn exact_document_symbol_and_reference_reads_do_not_load_unrelated_bad_projections() {
    let _gate = crate::mdn::index::TEST_GATE.lock().await;
    let (_root, store, corpus, original) = fixture().await;
    for problem in ["missing", "malformed"] {
        let projection = digest(&format!("unrelated-{problem}-projection")).unwrap();
        if problem == "malformed" {
            store
                .w3c_put("projections", &projection, &json!({"format":42}))
                .await
                .unwrap();
        }
        let bad = Member {
            path: "a-unrelated.html".into(),
            oid: "a".repeat(40),
            mode: "100644".into(),
            kind: "blob".into(),
            projection: Some(projection),
            raw: None,
            gaps: vec![],
        };
        let mut snapshot = original.clone();
        snapshot.id = digest(&format!("exact path isolation {problem}")).unwrap();
        snapshot.inventory = crate::w3c::inventory::update(
            store.as_ref(),
            &snapshot.inventory,
            &bad.path,
            Some(bad.clone()),
        )
        .await
        .unwrap();
        store
            .w3c_put("snapshots", &snapshot.id, &json!(snapshot))
            .await
            .unwrap();
        let research = W3cResearch::new(corpus.clone());
        let selected=research.call("w3c.symbol_get",json!({"specification":"dom","snapshot":snapshot.id,"path":"index.html","symbol_index":2})).await.unwrap();
        assert_eq!(selected["name"], "EventTarget");
        let resource = research
            .read_resource(selected["resource_uri"].as_str().unwrap())
            .await
            .unwrap();
        assert_eq!(resource["contents"][0]["text"], selected["page"]["text"]);
        let found = research
            .call(
                "w3c.symbol_search",
                json!({"specification":"dom","snapshot":snapshot.id,"path":"index.html","kind":"idl"}),
            )
            .await
            .unwrap();
        assert_eq!(found["total"], 2);
        let references = research
            .call(
                "w3c.references",
                json!({"specification":"dom","snapshot":snapshot.id,"path":"index.html"}),
            )
            .await
            .unwrap();
        assert_eq!(references["total"], 0);
        assert!(
            research
                .call(
                    "w3c.symbol_search",
                    json!({"specification":"dom","snapshot":snapshot.id})
                )
                .await
                .is_err(),
            "unscoped reads must still report the unrelated retained projection failure"
        );
    }
}

#[tokio::test]
async fn unresolved_license_is_metadata_only_even_for_retained_snapshot_and_raw_pages() {
    let _gate = crate::mdn::index::TEST_GATE.lock().await;
    let (_root, store, corpus, mut snapshot) = fixture().await;
    snapshot.id = digest(&"unresolved-license-snapshot").unwrap();
    snapshot.coverage["license"]["decision"] = json!("unresolved");
    store
        .w3c_put("snapshots", &snapshot.id, &json!(snapshot))
        .await
        .unwrap();
    let research = W3cResearch::new(corpus);
    for (tool, mut input) in [
        ("w3c.get", json!({"representation":"text"})),
        ("w3c.get", json!({"representation":"source"})),
        ("w3c.get", json!({"representation":"bytes"})),
        ("w3c.search", json!({"query":"event"})),
        ("w3c.symbol_get", json!({"name":"Event"})),
        ("w3c.symbol_search", json!({"kind":"idl"})),
        ("w3c.references", json!({})),
    ] {
        input["specification"] = json!("dom");
        input["snapshot"] = json!(snapshot.id);
        let error = research.call(tool, input).await.unwrap_err();
        assert_eq!(error.code, "unavailable", "{tool}");
    }
    let comparison = research
        .call(
            "w3c.compare",
            json!({"specification":"dom","before":snapshot.id,"after":snapshot.id,"mode":"source"}),
        )
        .await
        .unwrap_err();
    assert_eq!(comparison.code, "unavailable");
    let uri = resource(&snapshot, "bytes", "index.html", None);
    assert_eq!(
        research.read_resource(&uri).await.unwrap_err().code,
        "unavailable"
    );
    let discovery = research
        .call("w3c.snapshots", json!({"specification":"dom"}))
        .await
        .unwrap();
    assert!(
        discovery["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["snapshot"] == snapshot.id)
    );
}

#[tokio::test]
async fn copied_pages_search_symbols_comparisons_and_resources_preserve_required_notices() {
    let _gate = crate::mdn::index::TEST_GATE.lock().await;
    let (_root, _store, corpus, snapshot) = fixture().await;
    let research = W3cResearch::new(corpus);
    for (tool, mut input) in [
        ("w3c.get", json!({"limit":8})),
        (
            "w3c.symbol_get",
            json!({"name":"Event","kind":"definition","limit":2}),
        ),
        ("w3c.search", json!({"query":"dispatches"})),
        ("w3c.symbol_search", json!({"kind":"definition"})),
        ("w3c.references", json!({})),
    ] {
        input["specification"] = json!("dom");
        input["snapshot"] = json!(snapshot.id);
        let output = research.call(tool, input).await.unwrap();
        assert_eq!(output["derived_notice"], DERIVED_NOTICE, "{tool}");
        assert_eq!(
            output["sources"][0]["source_url"], snapshot.source_url,
            "{tool}"
        );
        assert_eq!(
            output["sources"][0]["copyright"], "Synthetic fixture authors",
            "{tool}"
        );
        assert_eq!(output["sources"][0]["publication_status"], "REC", "{tool}");
        if let Some(items) = output
            .get("results")
            .or_else(|| output.get("items"))
            .and_then(Value::as_array)
        {
            for item in items {
                assert_eq!(item["sources"][0]["derived_notice"], DERIVED_NOTICE);
                assert!(item.get("standard").is_none());
            }
        }
        if let Some(uri) = output.get("resource_uri").and_then(Value::as_str) {
            let result = research.read_resource(uri).await.unwrap();
            assert_eq!(
                result["contents"][0]["_meta"]["source_metadata"]["publication_status"],
                "REC"
            );
            assert_eq!(
                result["contents"][0]["_meta"]["derived_notice"],
                DERIVED_NOTICE
            );
        }
    }
    let compare=research.call("w3c.compare",json!({"specification":"dom","before":snapshot.id,"after":snapshot.id,"mode":"symbols"})).await.unwrap();
    assert_eq!(compare["sources"].as_array().unwrap().len(), 2);
    assert_eq!(
        compare["before"]["source_metadata"]["derived_notice"],
        DERIVED_NOTICE
    );
    assert_eq!(
        compare["after"]["source_metadata"]["copyright"],
        "Synthetic fixture authors"
    );
}

#[tokio::test]
async fn fallback_reports_latest_and_effective_editions_without_claiming_current_completeness() {
    let _gate = crate::mdn::index::TEST_GATE.lock().await;
    let (_root, store, corpus, mut snapshot) = fixture().await;
    snapshot.id = digest(&"fallback-edition").unwrap();
    snapshot.coverage["latest_publication"] = json!("https://www.w3.org/TR/2026/WD-dom-20261001/");
    snapshot.coverage["effective_publication"] =
        json!("https://www.w3.org/TR/2025/REC-dom-20250101/");
    snapshot.coverage["fallback_reason"] = json!("latest_projection_unavailable");
    snapshot.coverage["complete"] = json!(false);
    store
        .w3c_put("snapshots", &snapshot.id, &json!(snapshot))
        .await
        .unwrap();
    let mut view = corpus.view(None).await.unwrap();
    view.id = digest(&"fallback-view").unwrap();
    view.snapshots.insert("dom".into(), snapshot.id.clone());
    store.w3c_publish_view(&view).await.unwrap();
    let output = W3cResearch::new(corpus)
        .call("w3c.get", json!({"specification":"dom"}))
        .await
        .unwrap();
    assert_ne!(
        output["selection"]["catalog_latest_publication"],
        output["selection"]["effective_publication"]
    );
    assert_eq!(
        output["selection"]["fallback_reason"],
        "latest_projection_unavailable"
    );
    assert_eq!(output["selection"]["coverage"]["complete"], false);
}

#[test]
fn public_schemas_use_specification_and_keep_collection_destinations_private() {
    let definitions = schemas();
    assert_eq!(definitions.len(), 10);
    for descriptor in definitions {
        let properties = descriptor["inputSchema"]["properties"].as_object().unwrap();
        assert!(!properties.contains_key("standard"));
        assert!(!properties.contains_key("url"));
        assert!(!properties.contains_key("enabled"));
        assert_eq!(descriptor["inputSchema"]["additionalProperties"], false);
    }
    assert!(decode::<GetInput>(json!({"standard":"dom"})).is_err());
}

#[tokio::test]
async fn partial_views_report_missing_catalog_members_even_on_zero_result_queries() {
    let _gate = crate::mdn::index::TEST_GATE.lock().await;
    let (_root, store, corpus, _snapshot) = fixture().await;
    let mut catalog = corpus.catalog().await.unwrap();
    catalog.id = digest(&"catalog-with-metadata-only-report").unwrap();
    let mut missing = catalog.standards[0].clone();
    missing.id = "license-unresolved".into();
    missing.metadata = json!({"repository_license":{"decision":"unresolved"}});
    catalog.standards.push(missing);
    store
        .w3c_put("catalogs", &catalog.id, &json!(catalog))
        .await
        .unwrap();
    let mut view = corpus.view(None).await.unwrap();
    view.id = digest(&"partial-catalog-view").unwrap();
    view.catalog = catalog.id.clone();
    store.w3c_publish_view(&view).await.unwrap();
    let output = W3cResearch::new(corpus)
        .call("w3c.search", json!({"query":"no-such-fixture-term"}))
        .await
        .unwrap();
    assert_eq!(output["total"], 0);
    assert_eq!(output["selection_coverage"]["catalog_specifications"], 2);
    assert_eq!(output["selection_coverage"]["view_specifications"], 1);
    assert_eq!(
        output["selection_coverage"]["missing_specifications"],
        json!(["license-unresolved"])
    );
}

#[tokio::test]
async fn old_catalog_cannot_present_fresh_default_content_as_current() {
    let _gate = crate::mdn::index::TEST_GATE.lock().await;
    let (_root, store, corpus, _snapshot) = fixture().await;
    let mut catalog = corpus.catalog().await.unwrap();
    catalog.id = digest(&"expired-catalog").unwrap();
    catalog.observed_at = devres_domain::unix_now() - 8 * 86400;
    store
        .w3c_put("catalogs", &catalog.id, &json!(catalog))
        .await
        .unwrap();
    let mut view = corpus.view(None).await.unwrap();
    view.id = digest(&"expired-catalog-view").unwrap();
    view.catalog = catalog.id.clone();
    store.w3c_publish_view(&view).await.unwrap();
    let research = W3cResearch::new(corpus);
    assert_eq!(
        research
            .call("w3c.get", json!({"specification":"dom"}))
            .await
            .unwrap_err()
            .code,
        "unavailable"
    );
    let historical = research
        .call("w3c.get", json!({"specification":"dom","view":view.id}))
        .await
        .unwrap();
    assert_eq!(historical["selection_coverage"]["catalog_stale"], true);
}

#[tokio::test]
async fn real_tr_edition_roots_and_multipage_paths_compare_without_fabricated_removals() {
    let _gate = crate::mdn::index::TEST_GATE.lock().await;
    let (_root, store, corpus, original) = fixture().await;
    let original_member = corpus
        .member(&original, "index.html")
        .await
        .unwrap()
        .unwrap();
    let empty = crate::w3c::inventory::empty(store.as_ref()).await.unwrap();
    for (number, before_url, after_url, before_path, after_path) in [
        (
            0,
            "https://www.w3.org/TR/dom/",
            "https://www.w3.org/TR/2026/REC-dom-20261001/",
            "TR/dom/index.html",
            "TR/2026/REC-dom-20261001/index.html",
        ),
        (
            1,
            "https://www.w3.org/TR/2025/WD-dom-20250101/",
            "https://www.w3.org/TR/2026/REC-dom-20261001/",
            "TR/2025/WD-dom-20250101/index.html",
            "TR/2026/REC-dom-20261001/index.html",
        ),
        (
            2,
            "https://www.w3.org/TR/2025/WD-dom-20250101/chapter.html",
            "https://www.w3.org/TR/2026/REC-dom-20261001/chapter.html",
            "TR/2025/WD-dom-20250101/chapter.html",
            "TR/2026/REC-dom-20261001/chapter.html",
        ),
    ] {
        let mut sides = Vec::new();
        for (side, url, path) in [
            ("before", before_url, before_path),
            ("after", after_url, after_path),
        ] {
            let mut snapshot = original.clone();
            snapshot.id = digest(&(number, side)).unwrap();
            snapshot.representation = "html".into();
            snapshot.source_url = url.into();
            snapshot.repository = url.into();
            let mut member = original_member.clone();
            member.path = path.into();
            snapshot.inventory =
                crate::w3c::inventory::update(store.as_ref(), &empty, path, Some(member))
                    .await
                    .unwrap();
            store
                .w3c_put("snapshots", &snapshot.id, &json!(snapshot))
                .await
                .unwrap();
            sides.push(snapshot);
        }
        let research = W3cResearch::new(corpus.clone());
        for mode in ["text", "symbols", "source"] {
            for path in [None, Some(before_path), Some(after_path)] {
                let mut input = json!({"specification":"dom","before":sides[0].id,"after":sides[1].id,"mode":mode});
                if let Some(path) = path {
                    input["path"] = json!(path);
                }
                let output = research.call("w3c.compare", input).await.unwrap();
                assert_eq!(output["total"], 0, "{number} {mode} {path:?}");
            }
        }
        let mut broken = sides[1].clone();
        broken.id = digest(&(number, "failed-projection")).unwrap();
        let mut member = corpus.member(&broken, after_path).await.unwrap().unwrap();
        member.projection = None;
        member.gaps.push("processing_capacity".into());
        broken.inventory =
            crate::w3c::inventory::update(store.as_ref(), &empty, after_path, Some(member))
                .await
                .unwrap();
        store
            .w3c_put("snapshots", &broken.id, &json!(broken))
            .await
            .unwrap();
        assert_eq!(
            research
                .call(
                    "w3c.compare",
                    json!({"specification":"dom","before":sides[0].id,"after":broken.id})
                )
                .await
                .unwrap_err()
                .code,
            "unavailable"
        );
    }
    let mut source = original.clone();
    source.representation = "source".into();
    source.source_url = "https://www.w3.org/TR/2026/REC-dom-20261001/".into();
    assert_eq!(
        comparison_path(&source, "TR/2026/REC-dom-20261001/index.html"),
        "TR/2026/REC-dom-20261001/index.html"
    );
}

#[test]
fn historical_original_notice_status_overrides_current_catalog_status() {
    let snapshot = Snapshot {
        id: "a".repeat(64),
        standard: "example".into(),
        repository: String::new(),
        revision: String::new(),
        tree: String::new(),
        parents: vec![],
        committed_at: 0,
        inventory: String::new(),
        processor_version: 1,
        index: Value::Null,
        coverage: json!({"publication_status":"REC","license":{"decision":"approved","publication_status":"Working Draft 2010","copyright":"2010 original authors"}}),
        source_url: "https://www.w3.org/TR/2010/WD-example-20100101/".into(),
        representation: "html".into(),
        validated_at: 0,
    };
    assert_eq!(
        source_metadata(&snapshot)["publication_status"],
        "Working Draft 2010"
    );
}

#[tokio::test]
async fn aggregated_chapter_search_retrieval_symbols_comparison_and_resources_use_chapter_notices()
{
    let _gate = crate::mdn::index::TEST_GATE.lock().await;
    let (root, store, corpus, canonical) = fixture().await;
    let path = "TR/dom/chapter.html";
    let source = b"<h1 id=chapter>Chapter quasar evidence</h1><p>Distinct quasar chapter text.</p><dfn id=chapter-token>ChapterToken</dfn><a href='chapter.html#chapter-token'>chapter token</a><a href='#not-present'>unknown</a><a href='https://www.w3.org/TR/unrelated/#chapter-token'>outside report</a>";
    let artifact = crate::bulk::BulkArtifactStore::new(
        root.path().join("w3c/raw-artifacts"),
        64 * 1024 * 1024,
    )
    .unwrap()
    .capture_bytes(source.to_vec(), CancellationToken::new())
    .await
    .unwrap();
    let mut projection = json!(
        crate::w3c::processing::process_document(path, source, CancellationToken::new()).unwrap()
    );
    let index_id = digest(&"chapter-index-document").unwrap();
    projection["index_ids"] = json!([index_id]);
    let projection_id = digest(&projection).unwrap();
    store
        .w3c_put("projections", &projection_id, &projection)
        .await
        .unwrap();
    let license = json!({"decision":"approved","copyright":"Chapter authors 2026","publication_status":"Chapter Working Draft","notice":"Original chapter notice","license_url":"https://www.w3.org/copyright/document-license-2023/"});
    let member = Member {
        path: path.into(),
        oid: artifact.body_hash.clone(),
        mode: "100644".into(),
        kind: "html".into(),
        projection: Some(projection_id),
        raw: Some(
            json!({"artifact":artifact,"source_url":"https://www.w3.org/TR/dom/chapter.html","license":license,"publication":digest(&"chapter-publication").unwrap()}),
        ),
        gaps: vec![],
    };
    let mut edition = canonical.clone();
    edition.id = digest(&"aggregated-edition").unwrap();
    edition.inventory = crate::w3c::inventory::update(
        store.as_ref(),
        &canonical.inventory,
        path,
        Some(member.clone()),
    )
    .await
    .unwrap();
    edition.index = corpus
        .index()
        .publish(
            Some(&canonical.index),
            vec![crate::w3c::index::IndexDocument {
                id: index_id,
                standard: "dom".into(),
                edition: "living".into(),
                path: path.into(),
                title: "Chapter".into(),
                text: "quasar chapter evidence".into(),
                kind: "section".into(),
                metadata: json!({"anchor":"chapter"}),
            }],
            CancellationToken::new(),
        )
        .await
        .unwrap();
    store
        .w3c_put("snapshots", &edition.id, &json!(edition))
        .await
        .unwrap();
    let mut view = corpus.view(None).await.unwrap();
    view.id = digest(&"aggregated-view").unwrap();
    view.snapshots.insert("dom".into(), edition.id.clone());
    view.index = edition.index.clone();
    store.w3c_publish_view(&view).await.unwrap();
    let research = W3cResearch::new(corpus.clone());
    let found = research
        .call(
            "w3c.search",
            json!({"query":"quasar","specification":"dom"}),
        )
        .await
        .unwrap();
    assert_eq!(found["total"], 1);
    let hit = &found["results"][0];
    assert_eq!(
        hit["citation"]["source_url"],
        "https://www.w3.org/TR/dom/chapter.html"
    );
    assert_eq!(hit["sources"][0]["copyright"], "Chapter authors 2026");
    assert_eq!(hit["citation"]["object_hash"], member.oid);
    for representation in ["text", "source", "bytes"] {
        let detail=research.call("w3c.get",json!({"specification":"dom","snapshot":edition.id,"path":path,"representation":representation})).await.unwrap();
        assert_eq!(
            detail["source_metadata"]["copyright"],
            "Chapter authors 2026"
        );
        assert_eq!(
            detail["source_metadata"]["publication_status"],
            "Chapter Working Draft"
        );
        assert_eq!(
            detail["selection"]["source_metadata"]["copyright"],
            "Synthetic fixture authors"
        );
        let resource = research
            .read_resource(detail["resource_uri"].as_str().unwrap())
            .await
            .unwrap();
        assert_eq!(
            resource["contents"][0]["_meta"]["source_url"],
            "https://www.w3.org/TR/dom/chapter.html"
        );
        assert_eq!(
            resource["contents"][0]["_meta"]["source_metadata"]["copyright"],
            "Chapter authors 2026"
        );
        if representation == "bytes" {
            assert_eq!(
                STANDARD
                    .decode(resource["contents"][0]["blob"].as_str().unwrap())
                    .unwrap(),
                source
            );
        }
    }
    let symbol = research
        .call(
            "w3c.symbol_get",
            json!({"specification":"dom","snapshot":edition.id,"name":"ChapterToken"}),
        )
        .await
        .unwrap();
    assert_eq!(symbol["page"]["text"], "ChapterToken");
    assert_eq!(
        symbol["source_metadata"]["copyright"],
        "Chapter authors 2026"
    );
    let references = research
        .call(
            "w3c.references",
            json!({"specification":"dom","snapshot":edition.id,"path":path}),
        )
        .await
        .unwrap();
    let references = references["items"].as_array().unwrap();
    let chapter = references
        .iter()
        .find(|item| item["reference"]["target"] == "chapter.html#chapter-token")
        .unwrap();
    assert_eq!(chapter["resolution"]["state"], "captured_anchor");
    assert_eq!(chapter["resolution"]["path"], path);
    assert_eq!(
        references
            .iter()
            .find(|item| item["reference"]["target"] == "#not-present")
            .unwrap()["resolution"]["state"],
        "unresolved_captured_anchor"
    );
    assert_eq!(
        references
            .iter()
            .find(|item| item["reference"]["target"]
                == "https://www.w3.org/TR/unrelated/#chapter-token")
            .unwrap()["resolution"]["state"],
        "unresolved_external"
    );
    let mut changed = edition.clone();
    changed.id = digest(&"changed-chapter-edition").unwrap();
    let mut changed_member = member.clone();
    changed_member.oid = digest(&"changed-chapter-bytes").unwrap();
    changed.inventory = crate::w3c::inventory::update(
        store.as_ref(),
        &edition.inventory,
        path,
        Some(changed_member),
    )
    .await
    .unwrap();
    store
        .w3c_put("snapshots", &changed.id, &json!(changed))
        .await
        .unwrap();
    let compare=research.call("w3c.compare",json!({"specification":"dom","before":edition.id,"after":changed.id,"mode":"source","path":path})).await.unwrap();
    assert_eq!(compare["total"], 1);
    assert_eq!(
        compare["items"][0]["before_source"]["copyright"],
        "Chapter authors 2026"
    );
    assert_eq!(
        compare["items"][0]["after_source"]["source_url"],
        "https://www.w3.org/TR/dom/chapter.html"
    );
    let mut blocked = edition.clone();
    blocked.id = digest(&"unlicensed-chapter-edition").unwrap();
    let mut blocked_member = member;
    blocked_member.raw.as_mut().unwrap()["license"]["decision"] = json!("unresolved");
    blocked.inventory = crate::w3c::inventory::update(
        store.as_ref(),
        &edition.inventory,
        path,
        Some(blocked_member),
    )
    .await
    .unwrap();
    store
        .w3c_put("snapshots", &blocked.id, &json!(blocked))
        .await
        .unwrap();
    assert_eq!(research.call("w3c.get",json!({"specification":"dom","snapshot":blocked.id,"path":path,"representation":"bytes"})).await.unwrap_err().code,"unavailable");
}

#[tokio::test]
async fn default_get_selects_canonical_full_tr_path_when_chapters_are_present() {
    let _gate = crate::mdn::index::TEST_GATE.lock().await;
    let (_root, store, corpus, mut snapshot) = fixture().await;
    let original = corpus
        .member(&snapshot, "index.html")
        .await
        .unwrap()
        .unwrap();
    let empty = crate::w3c::inventory::empty(store.as_ref()).await.unwrap();
    let mut root = empty;
    for path in ["TR/dom/index.html", "TR/dom/chapter.html"] {
        let mut member = original.clone();
        member.path = path.into();
        root = crate::w3c::inventory::update(store.as_ref(), &root, path, Some(member))
            .await
            .unwrap();
    }
    snapshot.id = digest(&"canonical-with-chapter-default").unwrap();
    snapshot.inventory = root;
    snapshot.representation = "html".into();
    store
        .w3c_put("snapshots", &snapshot.id, &json!(snapshot))
        .await
        .unwrap();
    let result = W3cResearch::new(corpus)
        .call(
            "w3c.get",
            json!({"specification":"dom","snapshot":snapshot.id}),
        )
        .await
        .unwrap();
    assert_eq!(result["path"], "TR/dom/index.html");
}

#[test]
fn reference_anchor_decoding_preserves_unicode_literal_plus_and_single_percent_pass() {
    assert_eq!(decoded_anchor("%E7%AB%A0"), Some("章".into()));
    assert_eq!(decoded_anchor("a+b"), Some("a+b".into()));
    assert_eq!(decoded_anchor("%2520"), Some("%20".into()));
    for invalid in ["%", "%G0", "%FF", "%00"] {
        assert!(decoded_anchor(invalid).is_none(), "{invalid}");
    }
}
