use super::*;
use async_trait::async_trait;
use devres_application::{
    Cached, Fetcher, Store,
    crate_corpus::{Artifact, CollectionJob, ContentRecord, Inventory, VersionRecord},
};
use devres_domain::{Capture, FetchRequest, FetchResponse, StoredCapture, Validators};

pub(crate) struct FixtureStore {
    pub snapshot: Mutex<Snapshot>,
    pub qualified: Mutex<bool>,
    pub skipped_binary: Mutex<u64>,
    pub unresolved_references: Mutex<u64>,
    pub versions: Vec<VersionRecord>,
    pub contents: Vec<ContentRecord>,
    pub captures: HashMap<String, StoredCapture>,
    pub artifacts: Mutex<HashMap<String, Artifact>>,
    pub artifact_reads: AtomicU64,
}
fn unused<T>() -> Result<T> {
    Err(Error::unavailable("Unused fixture operation."))
}
#[async_trait]
impl CrateCorpusStore for FixtureStore {
    async fn begin_inventory(&self, _: &str, _: i64) -> Result<Inventory> {
        unused()
    }
    async fn pending_inventory(&self) -> Result<Option<Inventory>> {
        unused()
    }
    async fn latest_inventory(&self) -> Result<Option<Inventory>> {
        Ok(Some(
            self.snapshot
                .lock()
                .map_err(|_| unavailable())?
                .inventory
                .clone(),
        ))
    }
    async fn stage_crate(&self, _: &str, _: &str, _: &[VersionRecord], _: &str) -> Result<()> {
        unused()
    }
    async fn commit_inventory(&self, _: &str, _: &str) -> Result<Inventory> {
        unused()
    }
    async fn versions(
        &self,
        _: &str,
        name: Option<&str>,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<VersionRecord>> {
        Ok(self
            .versions
            .iter()
            .filter(|r| {
                name.is_none_or(|n| n == r.name)
                    && after.is_none_or(|c| format!("{}@{}", r.name, r.version).as_str() > c)
            })
            .take(limit)
            .cloned()
            .collect())
    }
    async fn version(&self, _: &str, name: &str, version: &str) -> Result<Option<VersionRecord>> {
        Ok(self
            .versions
            .iter()
            .find(|r| r.name == name && r.version == version)
            .cloned())
    }
    async fn save_artifact(&self, _: &Artifact, _: bool) -> Result<()> {
        unused()
    }
    async fn artifact(&self, id: &str) -> Result<Option<Artifact>> {
        self.artifact_reads.fetch_add(1, Ordering::Relaxed);
        Ok(self
            .artifacts
            .lock()
            .map_err(|_| unavailable())?
            .get(id)
            .cloned())
    }
    async fn latest_artifact(&self, _: &str) -> Result<Option<Artifact>> {
        unused()
    }
    async fn import_metadata(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: &str,
        _: &[u8],
        _: i64,
    ) -> Result<Capture> {
        unused()
    }
    async fn save_text(&self, _: &str, _: &str, _: &str, _: Value, _: i64) -> Result<Capture> {
        unused()
    }
    async fn schedule(&self, _: &[CollectionJob], _: i64) -> Result<()> {
        unused()
    }
    async fn claim(&self, _: i64, _: &str) -> Result<Option<CollectionJob>> {
        unused()
    }
    async fn finish(&self, _: &str, _: Option<&str>, _: Option<&str>, _: i64) -> Result<()> {
        unused()
    }
    async fn stage_content(&self, _: &str, _: &[ContentRecord]) -> Result<()> {
        unused()
    }
    async fn commit_content(&self, _: &str, _: Value) -> Result<()> {
        unused()
    }
    async fn contents(
        &self,
        _: i64,
        filter: &ContentFilter,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ContentRecord>> {
        Ok(self
            .contents
            .iter()
            .filter(|r| {
                filter.name.as_ref().is_none_or(|v| v == &r.name)
                    && filter.version.as_ref().is_none_or(|v| v == &r.version)
                    && filter.target.as_ref().is_none_or(|v| v == &r.target)
                    && filter.path.as_ref().is_none_or(|v| v == &r.path)
                    && filter.kind.as_ref().is_none_or(|v| v == &r.kind)
                    && after.is_none_or(|v| r.id.as_str() > v)
            })
            .take(limit)
            .cloned()
            .collect())
    }
    async fn content_deltas(
        &self,
        query: &devres_application::crate_corpus::ContentDeltaQuery,
    ) -> Result<Vec<Value>> {
        Ok((0..3).map(|n|json!({"cursor":format!("item{n}"),"path":format!("api{n}"),"target":"fixture-target","change":"changed","from":null,"to":null})).filter(|row|query.after.as_deref().is_none_or(|v|row["cursor"].as_str().unwrap_or_default()>v)).take(query.limit).collect())
    }
    async fn projection_status(
        &self,
        _: i64,
        _: &str,
        version: &str,
        kind: &str,
        target: Option<&str>,
    ) -> Result<Vec<Value>> {
        if !*self.qualified.lock().map_err(|_| unavailable())? {
            return Ok(Vec::new());
        }
        Ok(vec![
            json!({"version":version,"kind":kind,"source_capture":if kind=="json"{if version=="1.9.0"{"8".repeat(64)}else{"3".repeat(64)}}else if version=="1.9.0"{"f".repeat(64)}else{"b".repeat(64)},"target":if kind=="json"{target.unwrap_or("x86_64-unknown-linux-gnu")}else{""},"version_asserted":true,"target_asserted":true,"unresolved_references":*self.unresolved_references.lock().map_err(|_|unavailable())?,"complete_for_eligible_text":true,"skipped_binary":*self.skipped_binary.lock().map_err(|_|unavailable())?,"skipped_oversized":0}),
        ])
    }
    async fn put_enrichment(&self, _: &str, _: &str, _: &[(String, Value)]) -> Result<()> {
        unused()
    }
    async fn commit_enrichment(&self, _: &str) -> Result<()> {
        unused()
    }
    async fn enrichment(&self, _: Option<&str>, _: &str, _: &str) -> Result<Value> {
        Ok(
            json!({"crate":{"description":"synthetic package transport"},"version":{"license":"MIT"},"keywords":["network"],"categories":["development-tools"]}),
        )
    }
    async fn publish_snapshot(&self, _: &str, _: Value, _: i64) -> Result<Snapshot> {
        unused()
    }
    async fn snapshot(&self, id: Option<&str>) -> Result<Option<Snapshot>> {
        let snapshot = self.snapshot.lock().map_err(|_| unavailable())?.clone();
        if id.is_some_and(|id| id != snapshot.id) {
            Ok(None)
        } else {
            Ok(Some(snapshot))
        }
    }
    async fn status(&self) -> Result<Value> {
        Ok(json!({"inventory_complete":true,"fixture":true}))
    }
}
#[async_trait]
impl Store for FixtureStore {
    async fn latest(&self, _: &str) -> Result<Option<Cached>> {
        unused()
    }
    async fn capture(&self, id: &str) -> Result<StoredCapture> {
        self.captures
            .get(id)
            .cloned()
            .ok_or_else(|| Error::not_found("Fixture capture absent."))
    }
    async fn publish(&self, _: &FetchRequest, _: FetchResponse, _: i64) -> Result<StoredCapture> {
        unused()
    }
    async fn revalidate(&self, _: &str, _: &str, _: Validators, _: i64) -> Result<StoredCapture> {
        unused()
    }
}
pub(crate) struct NoNetwork;
#[async_trait]
impl Fetcher for NoNetwork {
    async fn fetch(&self, _: &FetchRequest, _: Option<&Validators>) -> Result<FetchResponse> {
        Err(Error::integrity("Research must not access providers."))
    }
}

pub(crate) fn fixture() -> Arc<FixtureStore> {
    let now = devres_domain::unix_now();
    let inventory = Inventory {
        id: "a".repeat(64),
        sequence: 1,
        revision: "b".repeat(40),
        created_at: now,
        validated_at: now,
        cursor: None,
    };
    let snapshot = Snapshot {
        id: "c".repeat(64),
        inventory,
        content_sequence: 1,
        enrichment: Some("d".repeat(64)),
        index_manifest: Value::Null,
        coverage: json!({"inventory_complete":true}),
        created_at: now,
    };
    let versions=["1.10.0","1.9.0"].into_iter().map(|version|VersionRecord{name:"example".into(),version:version.into(),metadata_capture:"e".repeat(64),metadata_status:None,record:json!({"name":"example","vers":version,"deps":[{"name":"renamed","package":"dependency","req":"^1","optional":true,"default_features":false,"features":[]}],"features":{},"cksum":"f".repeat(64),"yanked":false,"rust_version":"1.60"})}).collect();
    let capture = Capture {
        id: "1".repeat(64),
        key: "cargo:derived:fixture".into(),
        source_url: "https://fixture.invalid/public".into(),
        body_hash: hash(b"transport source fixture"),
        media_type: "text/plain".into(),
        retrieved_at: now,
        validated_at: now,
    };
    let row = ContentRecord {
        id: "2".repeat(64),
        name: "example".into(),
        version: "1.10.0".into(),
        target: "x86_64-unknown-linux-gnu".into(),
        path: "example::send".into(),
        kind: "api".into(),
        capture: capture.id.clone(),
        metadata_capture: "e".repeat(64),
        archive_capture: "3".repeat(64),
        attributes: json!({"format_version":57,"item_kind":"function","signature":{"input":"u8"},"relationships":[]}),
    };
    let captures = HashMap::from([(
        capture.id.clone(),
        StoredCapture {
            capture,
            body: b"transport source fixture".to_vec().into(),
        },
    )]);
    let raw = |id: &str, key: &str, url: &str, media_type: &str| {
        let body_hash = hash(format!("Synthetic raw fixture {key}").as_bytes());
        Artifact {
            capture: Capture {
                id: id.repeat(64),
                key: key.into(),
                source_url: url.into(),
                body_hash,
                media_type: media_type.into(),
                retrieved_at: now,
                validated_at: now,
            },
            bytes: 128,
            provenance: json!({"fixture":true}),
        }
    };
    let artifacts = [
        raw(
            "3",
            "cargo:docs-json:example:1.10.0:x86_64-unknown-linux-gnu",
            "https://docs.rs/crate/example/1.10.0/x86_64-unknown-linux-gnu/json/61.gz",
            "application/gzip",
        ),
        raw(
            "8",
            "cargo:docs-json:example:1.9.0:x86_64-unknown-linux-gnu",
            "https://docs.rs/crate/example/1.9.0/x86_64-unknown-linux-gnu/json/61.gz",
            "application/gzip",
        ),
        raw(
            "9",
            "cargo:docs-html:example:1.10.0",
            "https://docs.rs/crate/example/1.10.0/download",
            "application/zip",
        ),
        raw(
            "b",
            "cargo:archive:example:1.10.0:fixture",
            "https://static.crates.io/crates/example/example-1.10.0.crate",
            "application/gzip",
        ),
        raw(
            "f",
            "cargo:archive:example:1.9.0:fixture",
            "https://static.crates.io/crates/example/example-1.9.0.crate",
            "application/gzip",
        ),
    ]
    .into_iter()
    .map(|artifact| (artifact.capture.id.clone(), artifact))
    .collect();
    Arc::new(FixtureStore {
        snapshot: Mutex::new(snapshot),
        qualified: Mutex::new(true),
        skipped_binary: Mutex::new(0),
        unresolved_references: Mutex::new(0),
        versions,
        contents: {
            let mut readme = row.clone();
            readme.id = "4".repeat(64);
            readme.target = String::new();
            readme.path = "README.md".into();
            readme.kind = "readme".into();
            readme.archive_capture = "b".repeat(64);
            readme.attributes = json!({});
            let mut source = readme.clone();
            source.id = "5".repeat(64);
            source.path = "src/lib.rs".into();
            source.kind = "source".into();
            let mut previous = source.clone();
            previous.id = "6".repeat(64);
            previous.version = "1.9.0".into();
            previous.archive_capture = "f".repeat(64);
            let mut previous_api = row.clone();
            previous_api.id = "7".repeat(64);
            previous_api.version = "1.9.0".into();
            previous_api.archive_capture = "8".repeat(64);
            previous_api.attributes["signature"] = json!({"input":"u16"});
            let mut rustdoc = row.clone();
            rustdoc.id = "a".repeat(64);
            rustdoc.kind = "rustdoc".into();
            rustdoc.path = "example/index.html".into();
            rustdoc.archive_capture = "9".repeat(64);
            vec![row, readme, source, previous, previous_api, rustdoc]
        },
        captures,
        artifacts: Mutex::new(artifacts),
        artifact_reads: AtomicU64::new(0),
    })
}

fn index_document(name: &str, version: &str, text: &str) -> IndexDocument {
    IndexDocument {
        identity: Identity {
            name: name.into(),
            version: version.into(),
            target: String::new(),
            path: String::new(),
            id: format!("{name}@{version}"),
        },
        text: text.into(),
        payload: json!({"class":"version","record":{"name":name,"version":version}}),
        keywords: vec![
            ("class".into(), "version".into()),
            ("name".into(), name.into()),
            ("version".into(), version.into()),
        ],
        yanked: Some(false),
        msrv: None,
    }
}
fn make_index(root: &Path, store: Arc<FixtureStore>, per_shard: usize) -> Value {
    let slots = Arc::new(Semaphore::new(1));
    let permit = slots.try_acquire_owned().unwrap();
    let snapshot = store.snapshot.lock().unwrap().clone();
    let mut builder = Builder::begin(root, store, CancellationToken::new(), permit).unwrap();
    builder.document_limit = per_shard;
    for (name, version, text) in [
        ("example", "1.9.0", "transport transport"),
        ("example", "1.10.0", "transport transport"),
        ("zeta", "1.0.0", "transport source source source source"),
    ] {
        builder.add(index_document(name, version, text)).unwrap();
    }
    builder.finish(&snapshot).unwrap()
}
#[test]
fn global_bm25_and_semver_ties_are_identical_across_shard_boundaries() {
    let root = tempfile::tempdir().unwrap();
    let store = fixture();
    let one = make_index(root.path(), store.clone(), MAX_DOCS);
    let multiple = make_index(root.path(), store, 2);
    assert_eq!(multiple["shards"], 2);
    let spec = SearchSpec {
        query: Some("transport".into()),
        class: Some("version".into()),
        limit: 20,
        ..Default::default()
    };
    let left = search_sync(root.path(), &one, spec.clone(), CancellationToken::new()).unwrap();
    let right = search_sync(root.path(), &multiple, spec, CancellationToken::new()).unwrap();
    assert_eq!(left, right);
    assert_eq!(left["items"][0]["document"]["record"]["version"], "1.10.0");
    let page = search_sync(
        root.path(),
        &multiple,
        SearchSpec {
            class: Some("version".into()),
            name: Some("example".into()),
            offset: 1,
            limit: 1,
            ..Default::default()
        },
        CancellationToken::new(),
    )
    .unwrap();
    assert_eq!(page["items"][0]["document"]["record"]["version"], "1.9.0");
    assert!(
        search_sync(
            root.path(),
            &multiple,
            SearchSpec {
                query: Some("field:transport".into()),
                limit: 1,
                ..Default::default()
            },
            CancellationToken::new()
        )
        .is_err()
    );
}
#[test]
fn corrupted_manifest_fails_closed() {
    let root = tempfile::tempdir().unwrap();
    let manifest = make_index(root.path(), fixture(), 2);
    let path = root
        .path()
        .join(manifest["path"].as_str().unwrap())
        .join("manifest.json");
    fs::write(path, b"corrupt").unwrap();
    assert_eq!(
        search_sync(
            root.path(),
            &manifest,
            SearchSpec {
                limit: 1,
                ..Default::default()
            },
            CancellationToken::new()
        )
        .unwrap_err()
        .code,
        "integrity"
    );
}
#[tokio::test]
async fn build_streams_version_content_and_enrichment_into_indexed_filters() {
    let _serial = super::TEST_BUILD.lock().await;
    let root = tempfile::tempdir().unwrap();
    let store = fixture();
    let snapshot = store.snapshot.lock().unwrap().clone();
    let retrieval = Arc::new(Retrieval::new(store.clone(), Arc::new(NoNetwork)));
    let manifest = build(
        store,
        retrieval,
        root.path().to_path_buf(),
        snapshot,
        CancellationToken::new(),
    )
    .await
    .unwrap();
    let result = search(
        root.path().to_path_buf(),
        manifest,
        SearchSpec {
            class: Some("version".into()),
            license: Some("MIT".into()),
            keyword: Some("network".into()),
            category: Some("development-tools".into()),
            msrv: Some("1.70".into()),
            dependency: Some("dependency".into()),
            limit: 20,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(result["total"], 2);
    assert_eq!(
        result["items"][0]["document"]["record"]["version"],
        "1.10.0"
    );
}

#[tokio::test]
async fn frozen_rebuild_keeps_text_filters_and_rewrites_only_record_references() {
    let _serial = super::TEST_BUILD.lock().await;
    let root = tempfile::tempdir().unwrap();
    let store = fixture();
    let mut snapshot = store.snapshot.lock().unwrap().clone();
    let retrieval = Arc::new(Retrieval::new(store.clone(), Arc::new(NoNetwork)));
    let original = build(
        store.clone(),
        retrieval,
        root.path().to_owned(),
        snapshot.clone(),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    snapshot.id = crate::integrity::hash(b"canonical frozen crate snapshot");
    snapshot.inventory.id = crate::integrity::hash(b"canonical frozen crate inventory");
    let rewrite: PayloadRewrite = Arc::new(|value| {
        if value["class"] == "content" {
            for key in ["id", "capture", "metadata_capture", "archive_capture"] {
                if let Some(old) = value["record"][key].as_str() {
                    value["record"][key] = json!(crate::integrity::hash(old.as_bytes()));
                }
            }
        }
        Ok(())
    });
    let rebuilt = rebuild_frozen(
        store,
        root.path().to_owned(),
        original.clone(),
        snapshot,
        rewrite,
        CancellationToken::new(),
    )
    .await
    .unwrap();
    let spec = SearchSpec {
        class: Some("version".into()),
        license: Some("MIT".into()),
        keyword: Some("network".into()),
        category: Some("development-tools".into()),
        msrv: Some("1.70".into()),
        dependency: Some("dependency".into()),
        limit: 20,
        ..Default::default()
    };
    let before = search_sync(
        root.path(),
        &original,
        spec.clone(),
        CancellationToken::new(),
    )
    .unwrap();
    let after = search_sync(root.path(), &rebuilt, spec, CancellationToken::new()).unwrap();
    assert_eq!(before, after);
    let content = search_sync(
        root.path(),
        &rebuilt,
        SearchSpec {
            class: Some("content".into()),
            limit: 100,
            ..Default::default()
        },
        CancellationToken::new(),
    )
    .unwrap();
    assert!(content["total"].as_u64().unwrap() > 0);
    for item in content["items"].as_array().unwrap() {
        assert!(
            item["document"]["record"]["capture"]
                .as_str()
                .unwrap()
                .starts_with("blake3:")
        );
    }
    assert_eq!(rebuilt["skipped_documents"], original["skipped_documents"]);
}

#[test]
fn one_unindexable_token_is_a_durable_gap_and_keeps_other_documents_searchable() {
    let root = tempfile::tempdir().unwrap();
    let store = fixture();
    let snapshot = store.snapshot.lock().unwrap().clone();
    let permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    let mut builder = Builder::begin(root.path(), store, CancellationToken::new(), permit).unwrap();
    assert!(
        !builder
            .add(index_document(
                "example",
                "1.0.0",
                &"x".repeat(MAX_TOKEN_LEN)
            ))
            .unwrap()
    );
    assert!(
        builder
            .add(index_document("working", "1.0.0", "transport searchable"))
            .unwrap()
    );
    let manifest = builder.finish(&snapshot).unwrap();
    assert_eq!(manifest["skipped_documents"], 1);
    assert_eq!(manifest["complete_search_coverage"], false);
    let result = search_sync(
        root.path(),
        &manifest,
        SearchSpec {
            query: Some("transport".into()),
            limit: 20,
            ..Default::default()
        },
        CancellationToken::new(),
    )
    .unwrap();
    assert_eq!(result["total"], 1);
    assert_eq!(result["search_coverage"]["complete"], false);
    assert!(
        root.path()
            .join(manifest["path"].as_str().unwrap())
            .join("gaps.ndjson")
            .is_file()
    );
}
#[test]
fn canceled_search_rejects_before_opening_any_snapshot_files() {
    let root = tempfile::tempdir().unwrap();
    let cancel = CancellationToken::new();
    cancel.cancel();
    assert_eq!(
        search_sync(
            root.path(),
            &Value::Null,
            SearchSpec {
                limit: 1,
                ..Default::default()
            },
            cancel
        )
        .unwrap_err()
        .code,
        "cancelled"
    );
}

#[test]
fn cursors_cross_shards_and_bind_query_snapshot_with_changeable_page_sizes() {
    let root = tempfile::tempdir().unwrap();
    let manifest = make_index(root.path(), fixture(), 2);
    let first = search_sync(
        root.path(),
        &manifest,
        SearchSpec {
            class: Some("version".into()),
            limit: 1,
            ..Default::default()
        },
        CancellationToken::new(),
    )
    .unwrap();
    let cursor = first["next_cursor"].as_str().unwrap().to_owned();
    let second = search_sync(
        root.path(),
        &manifest,
        SearchSpec {
            class: Some("version".into()),
            limit: 2,
            cursor: Some(cursor.clone()),
            ..Default::default()
        },
        CancellationToken::new(),
    )
    .unwrap();
    assert_eq!(second["items"].as_array().unwrap().len(), 2);
    assert_eq!(second["items"][0]["document"]["record"]["version"], "1.9.0");
    assert!(second["next_cursor"].is_null());
    assert_eq!(
        search_sync(
            root.path(),
            &manifest,
            SearchSpec {
                query: Some("source".into()),
                class: Some("version".into()),
                limit: 1,
                cursor: Some(cursor.clone()),
                ..Default::default()
            },
            CancellationToken::new()
        )
        .unwrap_err()
        .code,
        "invalid_input"
    );
    let mut other = manifest.clone();
    other["digest"] = json!(crate::integrity::hash(b"different index manifest"));
    assert_eq!(
        search_sync(
            root.path(),
            &other,
            SearchSpec {
                class: Some("version".into()),
                limit: 1,
                cursor: Some(cursor),
                ..Default::default()
            },
            CancellationToken::new()
        )
        .unwrap_err()
        .code,
        "invalid_input"
    );
}
#[test]
fn continuation_remains_available_after_the_bounded_offset_window() {
    let root = tempfile::tempdir().unwrap();
    let store = fixture();
    let snapshot = store.snapshot.lock().unwrap().clone();
    let permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    let mut builder = Builder::begin(root.path(), store, CancellationToken::new(), permit).unwrap();
    for patch in 0..10003 {
        builder
            .add(index_document(
                "example",
                &format!("0.0.{patch}"),
                "fixture",
            ))
            .unwrap();
    }
    let manifest = builder.finish(&snapshot).unwrap();
    let first = search_sync(
        root.path(),
        &manifest,
        SearchSpec {
            class: Some("version".into()),
            offset: 10000,
            limit: 1,
            ..Default::default()
        },
        CancellationToken::new(),
    )
    .unwrap();
    assert_eq!(first["items"][0]["document"]["record"]["version"], "0.0.2");
    assert!(first["next_offset"].is_null());
    let tail = search_sync(
        root.path(),
        &manifest,
        SearchSpec {
            class: Some("version".into()),
            limit: 100,
            cursor: Some(first["next_cursor"].as_str().unwrap().into()),
            ..Default::default()
        },
        CancellationToken::new(),
    )
    .unwrap();
    assert_eq!(tail["items"].as_array().unwrap().len(), 2);
    assert!(tail["next_cursor"].is_null());
}

#[tokio::test]
async fn active_and_prepared_readers_survive_historical_cache_eviction() {
    let _serial = super::TEST_BUILD.lock().await;
    let root = tempfile::tempdir().unwrap();
    let active = make_index(root.path(), fixture(), 2);
    prewarm(
        root.path().to_path_buf(),
        active.clone(),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    activate(root.path(), &active).unwrap();
    let candidate = make_index(root.path(), fixture(), 2);
    prewarm(
        root.path().to_path_buf(),
        candidate.clone(),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    for _ in 0..4 {
        let historical = make_index(root.path(), fixture(), 2);
        search_sync(
            root.path(),
            &historical,
            SearchSpec {
                limit: 1,
                ..Default::default()
            },
            CancellationToken::new(),
        )
        .unwrap();
    }
    let key = cache_key(root.path(), &active).unwrap();
    let prepared = cache_key(root.path(), &candidate).unwrap();
    {
        let cache = CACHE.get().unwrap().lock().unwrap();
        assert_eq!(cache.active.as_ref().unwrap().0, key);
        assert_eq!(cache.prepared.as_ref().unwrap().0, prepared);
        assert!(cache.historical.len() <= 2);
    }
    assert_eq!(
        search_sync(
            root.path(),
            &active,
            SearchSpec {
                limit: 1,
                ..Default::default()
            },
            CancellationToken::new()
        )
        .unwrap()["total"],
        3
    );
    activate(root.path(), &candidate).unwrap();
    assert_eq!(
        CACHE
            .get()
            .unwrap()
            .lock()
            .unwrap()
            .active
            .as_ref()
            .unwrap()
            .0,
        prepared
    );
}
