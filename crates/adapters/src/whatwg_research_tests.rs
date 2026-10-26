use super::*;
use async_trait::async_trait;
use devres_application::whatwg::{Row, WhatwgConfig, WhatwgStore, Write};
use std::sync::Mutex;

#[derive(Default)]
struct Memory {
    rows: Mutex<BTreeMap<(String, String), Row>>,
    state: Mutex<BTreeMap<String, Value>>,
}
#[async_trait]
impl WhatwgStore for Memory {
    async fn whatwg_cutoff(&self) -> Result<i64> {
        Ok(self
            .rows
            .lock()
            .unwrap()
            .values()
            .map(|r| r.sequence)
            .max()
            .unwrap_or(0))
    }
    async fn whatwg_get(&self, kind: &str, key: &str) -> Result<Option<Row>> {
        Ok(self
            .rows
            .lock()
            .unwrap()
            .get(&(kind.into(), key.into()))
            .cloned())
    }
    async fn whatwg_put(&self, kind: &str, key: &str, data: &Value) -> Result<i64> {
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
    async fn whatwg_put_many(&self, rows: &[Write]) -> Result<()> {
        for row in rows {
            self.whatwg_put(&row.kind, &row.key, &row.data).await?;
        }
        Ok(())
    }
    async fn whatwg_rows(
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
    async fn whatwg_state(&self, key: &str) -> Result<Option<Value>> {
        Ok(self.state.lock().unwrap().get(key).cloned())
    }
    async fn whatwg_set_state(&self, key: &str, data: &Value) -> Result<()> {
        self.state.lock().unwrap().insert(key.into(), data.clone());
        Ok(())
    }
    async fn whatwg_publish_view(&self, view: &View) -> Result<()> {
        let data = json!(view);
        self.whatwg_put("views", &view.id, &data).await?;
        self.whatwg_set_state("default", &data).await
    }
}
async fn fixture() -> (tempfile::TempDir, Arc<Memory>, Arc<WhatwgCorpus>, Snapshot) {
    use crate::{
        bulk::{BulkArtifactStore, BulkBroker, BulkConfig},
        whatwg_index::IndexDocument,
        whatwg_inventory as inventory,
    };
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(Memory::default());
    let corpus = Arc::new(
        WhatwgCorpus::new(
            store.clone(),
            Arc::new(BulkBroker::new(BulkConfig::default()).unwrap()),
            root.path(),
            WhatwgConfig {
                enabled: false,
                ..Default::default()
            },
        )
        .unwrap(),
    );
    let source=b"<h1 id=standard>Synthetic standard</h1><h2 id=events>Events</h2><p><dfn id=event>Event</dfn> dispatches an event.</p><pre class=idl>interface Event {}; interface EventTarget {};</pre>";
    let artifact =
        BulkArtifactStore::new(root.path().join("whatwg/raw-artifacts"), 64 * 1024 * 1024)
            .unwrap()
            .capture_bytes(source.to_vec(), CancellationToken::new())
            .await
            .unwrap();
    let mut doc = json!(
        crate::whatwg_processing::process_document("index.html", source, CancellationToken::new())
            .unwrap()
    );
    let index_id = digest(&"synthetic-section").unwrap();
    doc["index_ids"] = json!([index_id]);
    let projection = digest(&doc).unwrap();
    store
        .whatwg_put("projections", &projection, &doc)
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
        repository: "whatwg/dom".into(),
        revision: "a".repeat(40),
        tree: "b".repeat(40),
        parents: vec![],
        committed_at: 1,
        inventory,
        processor_version: 1,
        index: index.clone(),
        coverage: json!({"synthetic":true,"complete":true}),
        source_url: "https://dom.spec.whatwg.org/".into(),
        representation: "living".into(),
        validated_at: devres_domain::unix_now(),
    };
    store
        .whatwg_put("snapshots", &snapshot.id, &json!(snapshot))
        .await
        .unwrap();
    let catalog_id = digest(&"synthetic-catalog").unwrap();
    let now = devres_domain::unix_now();
    let catalog = json!({"id":catalog_id,"observed_at":now,"standards":[{"id":"dom","title":"DOM","url":"https://dom.spec.whatwg.org/","repository":"whatwg/dom","metadata":{"synthetic":true}}],"gaps":[]});
    store
        .whatwg_put("catalogs", &catalog_id, &catalog)
        .await
        .unwrap();
    store
        .whatwg_set_state("catalog", &json!(catalog_id))
        .await
        .unwrap();
    let view:View=serde_json::from_value(json!({"id":digest(&"synthetic-view").unwrap(),"catalog":catalog_id,"snapshots":{"dom":snapshot.id},"index":index,"validations":{"dom":now},"validated_at":now})).unwrap();
    store.whatwg_publish_view(&view).await.unwrap();
    (root, store, corpus, snapshot)
}
#[tokio::test]
async fn immutable_text_source_symbols_search_and_resource_roundtrip() {
    let _gate = crate::mdn_index::TEST_GATE.lock().await;
    let (_root, _store, corpus, snapshot) = fixture().await;
    let research = WhatwgResearch::new(corpus);
    let get = research
        .call(
            "whatwg_get",
            json!({"standard":"dom","snapshot":snapshot.id,"path":"index.html","anchor":"events"}),
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
    let raw=research.call("whatwg_get",json!({"standard":"dom","snapshot":snapshot.id,"path":"index.html","representation":"bytes","limit":8})).await.unwrap();
    assert_eq!(
        STANDARD
            .decode(raw["page"]["base64"].as_str().unwrap())
            .unwrap(),
        b"<h1 id=s"
    );
    let symbols = research
        .call(
            "whatwg_symbol_search",
            json!({"standard":"dom","snapshot":snapshot.id,"kind":"definition"}),
        )
        .await
        .unwrap();
    assert_eq!(symbols["items"][0]["symbol"]["name"], "Event");
    assert!(symbols["items"][0]["symbol"].get("text").is_none());
    let symbol=research.call("whatwg_symbol_get",json!({"standard":"dom","snapshot":snapshot.id,"kind":"definition","name":"Event","limit":2})).await.unwrap();
    assert_eq!(symbol["page"]["text"], "Ev");
    assert_eq!(symbol["page"]["next_offset"], 2);
    let idl = research
        .call(
            "whatwg_symbol_get",
            json!({"standard":"dom","snapshot":snapshot.id,"kind":"idl","name":"EventTarget"}),
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
            "whatwg_search",
            json!({"standard":"dom","snapshot":snapshot.id,"query":"dispatches"}),
        )
        .await
        .unwrap();
    assert_eq!(result["total"], 1);
    assert!(
        research
            .call(
                "whatwg_get",
                json!({"standard":"html","snapshot":snapshot.id,"path":"index.html"})
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
            .call(
                "whatwg_corpus_status",
                json!({"url":"https://evil.invalid/"})
            )
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
    let _gate = crate::mdn_index::TEST_GATE.lock().await;
    let (_root, store, corpus, snapshot) = fixture().await;
    for number in 0..501 {
        let mut value = json!(snapshot);
        value["standard"] = json!("other");
        value["id"] = json!(digest(&number).unwrap());
        store
            .whatwg_put("snapshots", value["id"].as_str().unwrap(), &value)
            .await
            .unwrap();
    }
    let research = WhatwgResearch::new(corpus);
    let first = research
        .call("whatwg_snapshots", json!({"standard":"absent"}))
        .await
        .unwrap();
    assert_eq!(first["items"], json!([]));
    assert!(first["next_cursor"].is_string());
    let mut later = json!(snapshot);
    later["standard"] = json!("absent");
    later["id"] = json!(digest(&"later").unwrap());
    store
        .whatwg_put("snapshots", later["id"].as_str().unwrap(), &later)
        .await
        .unwrap();
    let second = research
        .call(
            "whatwg_snapshots",
            json!({"standard":"absent","cursor":first["next_cursor"]}),
        )
        .await
        .unwrap();
    assert_eq!(second["history_snapshot"], first["history_snapshot"]);
    assert_eq!(second["items"], json!([]));
    assert!(second["next_cursor"].is_null());
}

#[tokio::test]
async fn successful_view_validation_is_distinct_from_original_snapshot_time() {
    let _gate = crate::mdn_index::TEST_GATE.lock().await;
    let (_root, store, corpus, mut snapshot) = fixture().await;
    snapshot.id = digest(&"old-original-snapshot").unwrap();
    snapshot.validated_at = devres_domain::unix_now() - 8 * 86400;
    store
        .whatwg_put("snapshots", &snapshot.id, &json!(snapshot))
        .await
        .unwrap();
    let mut view = corpus.view(None).await.unwrap();
    view.id = digest(&"revalidated-view").unwrap();
    view.snapshots.insert("dom".into(), snapshot.id.clone());
    store.whatwg_publish_view(&view).await.unwrap();
    let research = WhatwgResearch::new(corpus.clone());
    let current = research
        .call("whatwg_get", json!({"standard":"dom","path":"index.html"}))
        .await
        .unwrap();
    assert_eq!(current["selection"]["stale"], false);
    view.id = digest(&"expired-view").unwrap();
    view.validations.insert("dom".into(), snapshot.validated_at);
    view.validated_at = snapshot.validated_at;
    store.whatwg_publish_view(&view).await.unwrap();
    assert!(
        research
            .call("whatwg_get", json!({"standard":"dom","path":"index.html"}))
            .await
            .is_err()
    );
    assert!(
        research
            .call("whatwg_search", json!({"standard":"dom","query":"event"}))
            .await
            .is_err()
    );
    let historical = research
        .call(
            "whatwg_get",
            json!({"standard":"dom","snapshot":snapshot.id,"path":"index.html"}),
        )
        .await
        .unwrap();
    assert_eq!(historical["selection"]["stale"], true);
    assert!(
        research
            .call("whatwg_catalog_search", json!({"snapshot":snapshot.id}))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn github_repository_links_do_not_resolve_by_shared_host() {
    let _gate = crate::mdn_index::TEST_GATE.lock().await;
    let (_root, _store, _corpus, mut snapshot) = fixture().await;
    snapshot.representation = "source".into();
    snapshot.source_url = "https://github.com/whatwg/dom/tree/0000".into();
    assert_eq!(
        resolve_reference(
            "https://github.com/whatwg/html",
            &snapshot,
            std::slice::from_ref(&snapshot)
        )["state"],
        "unresolved_external"
    );
    assert_eq!(
        resolve_reference(
            "https://dom.spec.whatwg.org/#event",
            &snapshot,
            std::slice::from_ref(&snapshot)
        )["standard"],
        "dom"
    );
}

#[tokio::test]
async fn ref_observations_page_inside_a_frozen_observation() {
    let _gate = crate::mdn_index::TEST_GATE.lock().await;
    let (_root, store, corpus, _snapshot) = fixture().await;
    let artifact =
        json!({"body_hash":"a".repeat(64),"bytes":0,"relative_path":"synthetic-observation"});
    let mut observation = json!({"repo":{"owner":"whatwg","name":"dom"},"observed_at":42,
        "refs":[{"name":"refs/heads/main","oid":"a".repeat(40),"object_type":"commit","peeled_commit":"a".repeat(40)},
            {"name":"refs/heads/older","oid":"b".repeat(40),"object_type":"commit","peeled_commit":"b".repeat(40)},
            {"name":"refs/tags/review","oid":"c".repeat(40),"object_type":"commit","peeled_commit":"c".repeat(40)}],
        "roots":[],"manifest":artifact,"commits":artifact,"total_commits":3,"main_revision":"a".repeat(40),"current_ref":"refs/heads/main"});
    store
        .whatwg_put("observations", "first-ref-observation", &observation)
        .await
        .unwrap();
    let research = WhatwgResearch::new(corpus);
    let first = research
        .call(
            "whatwg_history",
            json!({"history_type":"refs","repository":"whatwg/dom","limit":1}),
        )
        .await
        .unwrap();
    assert_eq!(first["items"][0]["ref"]["name"], "refs/heads/main");
    assert!(first["next_cursor"].is_string());
    observation["observed_at"] = json!(43);
    store
        .whatwg_put("observations", "later-ref-observation", &observation)
        .await
        .unwrap();
    let second=research.call("whatwg_history",json!({"history_type":"refs","repository":"whatwg/dom","cursor":first["next_cursor"],"limit":100})).await.unwrap();
    assert_eq!(second["history_snapshot"], first["history_snapshot"]);
    assert_eq!(second["items"].as_array().unwrap().len(), 2);
    assert!(second["next_cursor"].is_null());
    assert!(research.call("whatwg_history",json!({"history_type":"refs","repository":"whatwg/html","cursor":first["next_cursor"]})).await.is_err());
}

#[tokio::test]
async fn future_history_and_unapplied_ref_filters_fail_explicitly() {
    let _gate = crate::mdn_index::TEST_GATE.lock().await;
    let (_root, store, corpus, _before) = fixture().await;
    let research = WhatwgResearch::new(corpus);
    assert!(
        research
            .call("whatwg_history", json!({"ref":"refs/heads/main"}))
            .await
            .is_err()
    );
    let future = store.whatwg_cutoff().await.unwrap() + 100;
    assert!(
        research
            .call("whatwg_history", json!({"history_snapshot":future}))
            .await
            .is_err()
    );
    assert!(
        research
            .call(
                "whatwg_history",
                json!({"history_type":"refs","history_snapshot":future})
            )
            .await
            .is_err()
    );
}
#[tokio::test]
async fn failed_projection_is_not_a_removed_section_in_comparison() {
    let _gate = crate::mdn_index::TEST_GATE.lock().await;
    let (_root, store, corpus, before) = fixture().await;
    let mut member = corpus.member(&before, "index.html").await.unwrap().unwrap();
    member.projection = None;
    member.gaps = vec!["processing_capacity".into()];
    let inventory = crate::whatwg_inventory::update(
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
    after.coverage = json!({"projection_gaps":1,"synthetic":true});
    store
        .whatwg_put("snapshots", &after.id, &json!(after))
        .await
        .unwrap();
    let research = WhatwgResearch::new(corpus);
    let error = research
        .call(
            "whatwg_compare",
            json!({"standard":"dom","before":before.id,"after":after.id}),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, "unavailable");
    let raw = research
        .call(
            "whatwg_compare",
            json!({"standard":"dom","before":before.id,"after":after.id,"mode":"source"}),
        )
        .await
        .unwrap();
    assert_eq!(raw["total"], 0);
}

#[tokio::test]
async fn published_revisions_compare_by_sections_across_versioned_urls() {
    let _gate = crate::mdn_index::TEST_GATE.lock().await;
    let (_root, store, corpus, mut before) = fixture().await;
    before.id = digest(&"living-html").unwrap();
    before.representation = "html".into();
    before.repository = "https://dom.spec.whatwg.org/".into();
    store
        .whatwg_put("snapshots", &before.id, &json!(before))
        .await
        .unwrap();
    let mut member = corpus.member(&before, "index.html").await.unwrap().unwrap();
    member.path = "commit-snapshots/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/index.html".into();
    let empty = crate::whatwg_inventory::empty(store.as_ref())
        .await
        .unwrap();
    let root =
        crate::whatwg_inventory::update(store.as_ref(), &empty, &member.path, Some(member.clone()))
            .await
            .unwrap();
    let mut after = before.clone();
    after.id = digest(&"commit-html").unwrap();
    after.inventory = root;
    after.repository =
        "https://dom.spec.whatwg.org/commit-snapshots/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"
            .into();
    after.source_url = after.repository.clone();
    store
        .whatwg_put("snapshots", &after.id, &json!(after))
        .await
        .unwrap();
    let research = WhatwgResearch::new(corpus);
    for mode in ["text", "symbols", "source"] {
        let result=research.call("whatwg_compare",json!({"standard":"dom","before":before.id,"after":after.id,"mode":mode,"path":"index.html"})).await.unwrap();
        assert_eq!(result["total"], 0, "{mode}");
    }
    let mut moved_member = member.clone();
    moved_member.path = "review-drafts/2026-06/index.html".into();
    let mut moved = after.clone();
    moved.id = digest(&"review-html").unwrap();
    moved.inventory = crate::whatwg_inventory::update(
        store.as_ref(),
        &empty,
        &moved_member.path,
        Some(moved_member.clone()),
    )
    .await
    .unwrap();
    moved.repository = "https://dom.spec.whatwg.org/review-drafts/2026-06/".into();
    moved.source_url = moved.repository.clone();
    store
        .whatwg_put("snapshots", &moved.id, &json!(moved))
        .await
        .unwrap();
    for path in [&member.path, &moved_member.path] {
        for mode in ["text", "symbols", "source"] {
            let result=research.call("whatwg_compare",json!({"standard":"dom","before":after.id,"after":moved.id,"mode":mode,"path":path})).await.unwrap();
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
        _root.path().join("whatwg/raw-artifacts"),
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
    changed.inventory = crate::whatwg_inventory::update(
        store.as_ref(),
        &empty,
        &moved_member.path,
        Some(moved_member.clone()),
    )
    .await
    .unwrap();
    store
        .whatwg_put("snapshots", &changed.id, &json!(changed))
        .await
        .unwrap();
    for path in [&member.path, &moved_member.path] {
        let result=research.call("whatwg_compare",json!({"standard":"dom","before":after.id,"after":changed.id,"mode":"source","path":path})).await.unwrap();
        assert_eq!(result["total"], 1, "{path}");
    }
}

#[tokio::test]
async fn maximum_unicode_paths_anchors_and_symbol_names_have_bounded_resource_uris() {
    let _gate = crate::mdn_index::TEST_GATE.lock().await;
    let (_root, store, corpus, mut snapshot) = fixture().await;
    let path = format!("{}a.md", "🦀".repeat(1023));
    assert_eq!(path.len(), 4096);
    assert!(crate::whatwg_inventory::valid_path(&path));
    let anchor = "🦀".repeat(4095);
    let symbol_anchor = "🧬".repeat(4095);
    let name = "界".repeat(4096);
    let source = format!(
        "<h1 id=start>Bounded fixture</h1><h2 id=\"{anchor}\">Large section</h2><p>fixture text</p><dfn id=\"{symbol_anchor}\">{name}</dfn>"
    );
    let mut document = crate::whatwg_processing::process_document(
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
        .whatwg_put("projections", &projection_id, &projection)
        .await
        .unwrap();
    let mut member = corpus
        .member(&snapshot, "index.html")
        .await
        .unwrap()
        .unwrap();
    member.path = path.clone();
    member.projection = Some(projection_id);
    let empty = crate::whatwg_inventory::empty(store.as_ref())
        .await
        .unwrap();
    snapshot.id = digest(&"maximum Unicode URI fixture").unwrap();
    snapshot.processor_version = 2;
    snapshot.inventory =
        crate::whatwg_inventory::update(store.as_ref(), &empty, &path, Some(member))
            .await
            .unwrap();
    store
        .whatwg_put("snapshots", &snapshot.id, &json!(snapshot))
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
    let research = WhatwgResearch::new(corpus);
    let section = research
        .call(
            "whatwg_get",
            json!({"standard":"dom","snapshot":snapshot.id,"path":path,"anchor":anchor}),
        )
        .await
        .unwrap();
    assert_eq!(section["section_index"], 1);
    let direct_section = research
        .call(
            "whatwg_get",
            json!({"standard":"dom","snapshot":snapshot.id,"path":path,"section_index":1}),
        )
        .await
        .unwrap();
    assert_eq!(direct_section["page"], section["page"]);
    let symbol = research
        .call(
            "whatwg_symbol_get",
            json!({"standard":"dom","snapshot":snapshot.id,"path":path,"name":name}),
        )
        .await
        .unwrap();
    assert_eq!(symbol["symbol_index"], 0);
    let anchored_symbol = research
        .call(
            "whatwg_get",
            json!({"standard":"dom","snapshot":snapshot.id,"path":path,"anchor":symbol_anchor}),
        )
        .await
        .unwrap();
    assert_eq!(anchored_symbol["page"]["text"], symbol["page"]["text"]);
    let found = research
        .call(
            "whatwg_symbol_search",
            json!({"standard":"dom","snapshot":snapshot.id,"path":path,"kind":"definition"}),
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
    let _gate = crate::mdn_index::TEST_GATE.lock().await;
    let (_root, _store, corpus, snapshot) = fixture().await;
    let research = WhatwgResearch::new(corpus);
    let section = research
        .call(
            "whatwg_get",
            json!({"standard":"dom","snapshot":snapshot.id,"path":"index.html","anchor":"events"}),
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
            "whatwg_symbol_get",
            json!({"standard":"dom","snapshot":snapshot.id,"name":"EventTarget","kind":"idl"}),
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
            "whatwg_symbol_search",
            json!({"standard":"dom","snapshot":snapshot.id,"name":"EventTarget","kind":"idl"}),
        )
        .await
        .unwrap();
    assert_eq!(
        found["items"][0]["symbol_index"], symbol["symbol_index"],
        "filtering cannot renumber symbols"
    );
    let indexed=research.call("whatwg_symbol_get",json!({"standard":"dom","snapshot":snapshot.id,"path":"index.html","symbol_index":symbol["symbol_index"]})).await.unwrap();
    assert_eq!(indexed["page"], symbol["page"]);
    for (tool, arguments) in [
        ("whatwg_get", json!({"section_index":0})),
        (
            "whatwg_get",
            json!({"path":"index.html","section_index":0,"anchor":"events"}),
        ),
        (
            "whatwg_get",
            json!({"path":"index.html","section_index":0,"representation":"bytes"}),
        ),
        (
            "whatwg_get",
            json!({"path":"index.html","section_index":99999}),
        ),
        ("whatwg_symbol_get", json!({"symbol_index":0})),
        (
            "whatwg_symbol_get",
            json!({"path":"index.html","symbol_index":99999}),
        ),
        (
            "whatwg_symbol_get",
            json!({"path":"index.html","symbol_index":0,"name":"EventTarget"}),
        ),
    ] {
        let mut input = arguments;
        input["standard"] = json!("dom");
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
    for name in ["whatwg_get", "whatwg_symbol_get"] {
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
    let _gate = crate::mdn_index::TEST_GATE.lock().await;
    let (_root, store, corpus, original) = fixture().await;
    for problem in ["missing", "malformed"] {
        let projection = digest(&format!("unrelated-{problem}-projection")).unwrap();
        if problem == "malformed" {
            store
                .whatwg_put("projections", &projection, &json!({"format":42}))
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
        snapshot.inventory = crate::whatwg_inventory::update(
            store.as_ref(),
            &snapshot.inventory,
            &bad.path,
            Some(bad.clone()),
        )
        .await
        .unwrap();
        store
            .whatwg_put("snapshots", &snapshot.id, &json!(snapshot))
            .await
            .unwrap();
        let research = WhatwgResearch::new(corpus.clone());
        let selected=research.call("whatwg_symbol_get",json!({"standard":"dom","snapshot":snapshot.id,"path":"index.html","symbol_index":2})).await.unwrap();
        assert_eq!(selected["name"], "EventTarget");
        let resource = research
            .read_resource(selected["resource_uri"].as_str().unwrap())
            .await
            .unwrap();
        assert_eq!(resource["contents"][0]["text"], selected["page"]["text"]);
        let found = research
            .call(
                "whatwg_symbol_search",
                json!({"standard":"dom","snapshot":snapshot.id,"path":"index.html","kind":"idl"}),
            )
            .await
            .unwrap();
        assert_eq!(found["total"], 2);
        let references = research
            .call(
                "whatwg_references",
                json!({"standard":"dom","snapshot":snapshot.id,"path":"index.html"}),
            )
            .await
            .unwrap();
        assert_eq!(references["total"], 0);
        assert!(
            research
                .call(
                    "whatwg_symbol_search",
                    json!({"standard":"dom","snapshot":snapshot.id})
                )
                .await
                .is_err(),
            "unscoped reads must still report the unrelated retained projection failure"
        );
    }
}
