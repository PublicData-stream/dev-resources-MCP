//! Synthetic local-Git corpus acceptance. No public provider requests.
use super::*;
use crate::mdn::git::tests::{commit_files, fixture_init, fixture_server_pair, update};
use async_trait::async_trait;
use devres_application::mdn::MdnRow;
use std::{
    collections::BTreeMap,
    sync::{
        Mutex as StdMutex,
        atomic::{AtomicI64, Ordering},
    },
};

#[derive(Default)]
struct Memory {
    rows: StdMutex<BTreeMap<(String, String), MdnRow>>,
    states: StdMutex<BTreeMap<String, Value>>,
    sequence: AtomicI64,
}
#[async_trait]
impl MdnStore for Memory {
    async fn mdn_cutoff(&self) -> Result<i64> {
        Ok(self.sequence.load(Ordering::Relaxed))
    }
    async fn mdn_get(&self, kind: &str, key: &str) -> Result<Option<MdnRow>> {
        Ok(self
            .rows
            .lock()
            .expect("memory rows")
            .get(&(kind.into(), key.into()))
            .cloned())
    }
    async fn mdn_put(&self, kind: &str, key: &str, data: &Value) -> Result<i64> {
        let mut rows = self.rows.lock().expect("memory rows");
        if let Some(row) = rows.get(&(kind.into(), key.into())) {
            if row.data != *data {
                return Err(Error::integrity("Synthetic immutable evidence collision."));
            }
            return Ok(row.sequence);
        }
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed) + 1;
        rows.insert(
            (kind.into(), key.into()),
            MdnRow {
                sequence,
                key: key.into(),
                data: data.clone(),
            },
        );
        Ok(sequence)
    }
    async fn mdn_rows(
        &self,
        kind: &str,
        after: i64,
        limit: usize,
        cutoff: Option<i64>,
    ) -> Result<Vec<MdnRow>> {
        let mut rows: Vec<_> = self
            .rows
            .lock()
            .expect("memory rows")
            .iter()
            .filter(|((k, _), row)| {
                k == kind
                    && row.sequence > after
                    && cutoff.is_none_or(|cutoff| row.sequence <= cutoff)
            })
            .map(|(_, row)| row.clone())
            .collect();
        rows.sort_by_key(|row| row.sequence);
        rows.truncate(limit);
        Ok(rows)
    }
    async fn mdn_state(&self, key: &str) -> Result<Option<Value>> {
        Ok(self.states.lock().expect("memory state").get(key).cloned())
    }
    async fn mdn_set_state(&self, key: &str, data: &Value) -> Result<()> {
        self.states
            .lock()
            .expect("memory state")
            .insert(key.into(), data.clone());
        Ok(())
    }
    async fn mdn_publish_view(&self, view: &View) -> Result<()> {
        for (id, repo) in [(&view.content, "content"), (&view.compatibility, "compat")] {
            let snapshot: Snapshot = decoded(
                self.mdn_get("snapshots", id)
                    .await?
                    .ok_or_else(|| Error::integrity("Missing fixture snapshot."))?
                    .data,
            )?;
            if snapshot.repository != repo
                || snapshot.index.is_null()
                || snapshot.coverage["accounted"] != true
            {
                return Err(Error::integrity("Incomplete fixture publication."));
            }
        }
        self.mdn_put("views", &view.id, &encoded(view)?).await?;
        self.mdn_set_state("default-view", &json!(view.id)).await
    }
}

const FETCH_PATH: &str = "files/en-us/web/api/fetch/index.md";
const PART_PATH: &str = "files/en-us/web/api/part/index.md";
const LEAF_PATH: &str = "files/en-us/web/api/leaf/index.md";
const WAIT_PATH: &str = "files/en-us/web/api/waiting/index.md";
const LATER_PATH: &str = "files/en-us/web/api/later/index.md";
const FETCH:&[u8]=b"---\ntitle: Fetch API\nslug: Web/API/Fetch\npage-type: web-api-instance-method\nbrowser-compat: api.fetch\n---\nFetch network requests. {{include('Web/API/Part')}}\n{{Compat}}";
const PART: &[u8] = b"---\ntitle: Part\nslug: Web/API/Part\n---\n{{include('Web/API/Leaf')}}";
const LEAF: &[u8] = b"---\ntitle: Leaf\nslug: Web/API/Leaf\n---\nOriginal network evidence.";
const WAIT: &[u8] =
    b"---\ntitle: Waiting\nslug: Web/API/Waiting\n---\n{{include('Web/API/Later')}}";
const BCD:&[u8]=br#"{"api":{"fetch":{"__compat":{"description":"Fetch requests","support":{"chrome":{"version_added":"42"}},"status":{"experimental":false,"standard_track":true,"deprecated":false}}}}}"#;
const CHROME:&[u8]=br#"{"browsers":{"chrome":{"name":"Chrome","type":"desktop","accepts_flags":true,"releases":{"42":{"engine":"Blink","engine_version":"42","status":"retired"}}}}}"#;
fn content_files() -> BTreeMap<&'static str, Vec<u8>> {
    BTreeMap::from([
        (FETCH_PATH, FETCH.to_vec()),
        (PART_PATH, PART.to_vec()),
        (LEAF_PATH, LEAF.to_vec()),
        (WAIT_PATH, WAIT.to_vec()),
        (
            "files/en-us/_redirects.txt",
            b"/en-US/docs/Web/API/OldFetch\t/en-US/docs/Web/API/Fetch\n".to_vec(),
        ),
    ])
}
fn compat_files() -> BTreeMap<&'static str, Vec<u8>> {
    BTreeMap::from([
        ("api/fetch.json", BCD.to_vec()),
        ("browsers/chrome.json", CHROME.to_vec()),
    ])
}
async fn commit_map(source: &MdnGit, files: &BTreeMap<&str, Vec<u8>>, parents: &[&str]) -> String {
    let entries: Vec<_> = files
        .iter()
        .map(|(path, body)| (*path, body.as_slice()))
        .collect();
    commit_files(source, &entries, parents).await
}
struct Fixture {
    _index_gate: tokio::sync::MutexGuard<'static, ()>,
    _root: tempfile::TempDir,
    content: Arc<MdnGit>,
    compat: Arc<MdnGit>,
    corpus: MdnCorpus,
    store: Arc<Memory>,
    server: tokio::task::JoinHandle<()>,
    content_revision: String,
    compat_revision: String,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}
impl Fixture {
    async fn new() -> Self {
        let index_gate = crate::mdn::index::TEST_GATE.lock().await;
        let root = tempfile::tempdir().expect("fixture root");
        let content = Arc::new(
            MdnGit::new(
                &root.path().join("source-content"),
                Repo::Content,
                64 * 1024 * 1024,
                64 * 1024 * 1024,
                None,
            )
            .expect("source"),
        );
        let compat = Arc::new(
            MdnGit::new(
                &root.path().join("source-compat"),
                Repo::Compat,
                64 * 1024 * 1024,
                64 * 1024 * 1024,
                None,
            )
            .expect("source"),
        );
        fixture_init(&content).await;
        fixture_init(&compat).await;
        let content_revision = commit_map(&content, &content_files(), &[]).await;
        let compat_revision = commit_map(&compat, &compat_files(), &[]).await;
        update(&content, "refs/heads/main", &content_revision).await;
        update(&compat, "refs/heads/main", &compat_revision).await;
        let (broker, server) = fixture_server_pair(content.clone(), compat.clone()).await;
        let store = Arc::new(Memory::default());
        let config = MdnConfig {
            enabled: false,
            min_free_bytes: 64 * 1024 * 1024,
            max_git_bytes: 64 * 1024 * 1024,
            publication_interval_secs: 1,
            ..Default::default()
        };
        let target = root.path().join("target");
        std::fs::create_dir_all(&target).expect("target");
        let corpus = MdnCorpus::new(store.clone(), broker, &target, config).expect("corpus");
        let fixture = Self {
            _index_gate: index_gate,
            _root: root,
            content,
            compat,
            corpus,
            store,
            server,
            content_revision,
            compat_revision,
        };
        fixture
            .corpus
            .synchronize(Repo::Content, CancellationToken::new())
            .await
            .expect("capture content");
        fixture
            .corpus
            .synchronize(Repo::Compat, CancellationToken::new())
            .await
            .expect("capture compatibility");
        fixture
    }
    async fn current(&self) {
        for _ in 0..30 {
            if self
                .corpus
                .process_current(CancellationToken::new())
                .await
                .expect("process current")
            {
                return;
            }
        }
        panic!("fixture current failed to converge");
    }
    async fn history(&self) {
        for _ in 0..30 {
            if self
                .corpus
                .process_history(CancellationToken::new())
                .await
                .expect("process history")
            {
                return;
            }
        }
        panic!("fixture history failed to converge");
    }
    async fn publish_content(&self, files: &BTreeMap<&str, Vec<u8>>, parent: &str) -> String {
        let revision = commit_map(&self.content, files, &[parent]).await;
        update(&self.content, "refs/heads/main", &revision).await;
        self.corpus
            .synchronize(Repo::Content, CancellationToken::new())
            .await
            .expect("capture new content");
        self.current().await;
        revision
    }
    async fn text(&self, slug: &str, snapshot: Option<&str>) -> Value {
        let mut input = json!({"slug":slug});
        if let Some(id) = snapshot {
            input["snapshot"] = json!(id);
        }
        self.corpus
            .research()
            .call("mdn_get", input)
            .await
            .expect("get document")
    }
}

#[tokio::test]
async fn mdn_corpus_current_default_search_originals_and_history_are_local() {
    let fixture = Fixture::new().await;
    fixture.current().await;
    let research = fixture.corpus.research();
    let document = fixture.text("Web/API/OldFetch", None).await;
    assert!(
        document["page"]["text"]
            .as_str()
            .expect("text")
            .contains("Original network evidence")
    );
    assert_eq!(
        document["redirects"].as_array().expect("redirects").len(),
        1
    );
    assert_eq!(
        document["compatibility"][0]["original"]["chrome"]["version_added"],
        "42"
    );
    let source = research
        .call(
            "mdn_get",
            json!({"path":FETCH_PATH,"representation":"source"}),
        )
        .await
        .expect("original source");
    assert_eq!(
        source["page"]["text"],
        std::str::from_utf8(FETCH).expect("fixture UTF8")
    );
    let search = research
        .call(
            "mdn_search",
            json!({"query":"network evidence","page_type":"web-api-instance-method"}),
        )
        .await
        .expect("local search");
    assert_eq!(search["results"].as_array().expect("results").len(), 1);
    assert_eq!(search["results"][0]["slug"], "Web/API/Fetch");
    let browser = research
        .call("mdn_browser_get", json!({"browser":"chrome"}))
        .await
        .expect("browser metadata");
    assert_eq!(browser["total"], 1);
    fixture.history().await;
    for (repo, revision) in [
        (Repo::Content, &fixture.content_revision),
        (Repo::Compat, &fixture.compat_revision),
    ] {
        let snapshot = fixture
            .corpus
            .snapshot(repo, revision)
            .await
            .expect("snapshot")
            .expect("published");
        assert!(!snapshot.index.is_null());
        assert_eq!(snapshot.coverage["accounted"], true);
    }
    let changes = research
        .call(
            "mdn_history",
            json!({"repository":"compat","feature":"api.fetch"}),
        )
        .await
        .expect("feature history");
    assert!(
        changes["results"]
            .as_array()
            .expect("changes")
            .iter()
            .any(|row| row["kind"] == "added")
    );
    // Shut down the only provider and prove immutable queries still work.
    fixture.server.abort();
    assert_eq!(
        research
            .call("mdn_compat_get", json!({"feature":"api.fetch"}))
            .await
            .expect("offline compatibility")["original"]["chrome"]["version_added"],
        "42"
    );
}

#[tokio::test]
async fn mdn_corpus_transitive_and_missing_includes_invalidate_unchanged_articles() {
    let fixture = Fixture::new().await;
    fixture.current().await;
    let first = fixture
        .corpus
        .snapshot(Repo::Content, &fixture.content_revision)
        .await
        .expect("snapshot")
        .expect("first");
    let original = fixture.text("Web/API/Fetch", None).await;
    let mut files = content_files();
    files.insert(
        LEAF_PATH,
        b"---\nslug: Web/API/Leaf\ntitle: Leaf\n---\nUpdated network evidence.".to_vec(),
    );
    let second = fixture
        .publish_content(&files, &fixture.content_revision)
        .await;
    let changed = fixture.text("Web/API/Fetch", None).await;
    assert_eq!(
        original["oid"], changed["oid"],
        "including article source was unchanged"
    );
    assert!(
        changed["page"]["text"]
            .as_str()
            .expect("text")
            .contains("Updated network evidence")
    );
    assert!(
        fixture.text("Web/API/Fetch", Some(&first.id)).await["page"]["text"]
            .as_str()
            .expect("text")
            .contains("Original network evidence")
    );
    files.insert(
        LATER_PATH,
        b"---\nslug: Web/API/Later\ntitle: Later\n---\nNewly available inclusion.".to_vec(),
    );
    let third = fixture.publish_content(&files, &second).await;
    let waiting = fixture.text("Web/API/Waiting", None).await;
    assert!(
        waiting["page"]["text"]
            .as_str()
            .expect("text")
            .contains("Newly available inclusion")
    );
    assert!(
        !waiting["gaps"]
            .as_array()
            .expect("gaps")
            .iter()
            .any(|gap| gap == "missing_include")
    );
    files.remove(PART_PATH);
    let fourth = fixture.publish_content(&files, &third).await;
    let removed = fixture.text("Web/API/Fetch", None).await;
    assert!(
        removed["gaps"]
            .as_array()
            .expect("gaps")
            .iter()
            .any(|gap| gap == "missing_include")
    );
    assert!(
        !removed["page"]["text"]
            .as_str()
            .expect("text")
            .contains("Updated network evidence")
    );
    fixture.history().await;
    for revision in [&fixture.content_revision, &second, &third, &fourth] {
        assert!(
            fixture
                .corpus
                .snapshot(Repo::Content, revision)
                .await
                .expect("snapshot")
                .is_some()
        );
    }
}

#[tokio::test]
async fn mdn_corpus_prepared_snapshot_requeues_after_missing_pending_checkpoint() {
    let fixture = Fixture::new().await;
    // Preparation is resumable and may yield at its existing ten-second budget.
    // Reach the prepared checkpoint without running current publication.
    let mut prepared = false;
    for _ in 0..30 {
        prepared = fixture
            .corpus
            .process_commit(
                Repo::Content,
                &fixture.content_revision,
                false,
                CancellationToken::new(),
            )
            .await
            .expect("prepare bounded slice");
        if prepared {
            break;
        }
    }
    assert!(prepared, "fixture preparation failed to converge");
    assert!(
        fixture
            .store
            .mdn_state(&format!(
                "prepared:{}",
                snapshot_key(Repo::Content, &fixture.content_revision)
            ))
            .await
            .expect("retained prepared checkpoint")
            .is_some()
    );
    assert!(
        fixture
            .store
            .mdn_get(
                "snapshot-keys",
                &snapshot_key(Repo::Content, &fixture.content_revision)
            )
            .await
            .expect("alias")
            .is_none()
    );
    assert!(
        fixture
            .store
            .mdn_state("default-view")
            .await
            .expect("default")
            .is_none()
    );
    // Crash after writing prepared:<key>, before the pending enqueue is durable.
    fixture
        .store
        .mdn_set_state("pending", &encoded(&Pending::default()).expect("pending"))
        .await
        .expect("simulate interrupted enqueue");
    fixture.current().await;
    let snapshot = fixture
        .corpus
        .snapshot(Repo::Content, &fixture.content_revision)
        .await
        .expect("snapshot")
        .expect("published");
    assert!(!snapshot.index.is_null());
    assert!(
        fixture
            .store
            .mdn_state("default-view")
            .await
            .expect("default")
            .is_some()
    );
    assert!(
        fixture.text("Web/API/Fetch", None).await["page"]["text"]
            .as_str()
            .expect("text")
            .contains("network")
    );
}

#[tokio::test]
async fn mdn_corpus_malformed_bcd_replaces_no_historical_feature() {
    let fixture = Fixture::new().await;
    fixture.current().await;
    let historical = fixture
        .corpus
        .snapshot(Repo::Compat, &fixture.compat_revision)
        .await
        .expect("snapshot")
        .expect("compatibility");
    let mut files = compat_files();
    files.insert("api/fetch.json",br#"{"api":{"fetch":{"__compat":{"support":{"chrome":{"version_added":"99"}},"support":{}}}}}"#.to_vec());
    let revision = commit_map(&fixture.compat, &files, &[&fixture.compat_revision]).await;
    update(&fixture.compat, "refs/heads/main", &revision).await;
    fixture
        .corpus
        .synchronize(Repo::Compat, CancellationToken::new())
        .await
        .expect("capture invalid source");
    fixture.current().await;
    assert!(
        fixture
            .corpus
            .research()
            .call("mdn_compat_get", json!({"feature":"api.fetch"}))
            .await
            .is_err(),
        "failed projection must not reuse old feature in new snapshot"
    );
    let raw = fixture
        .corpus
        .research()
        .call(
            "mdn_get",
            json!({"repository":"compat","path":"api/fetch.json","representation":"source"}),
        )
        .await
        .expect("retained invalid source");
    assert!(!raw["gaps"].as_array().expect("gaps").is_empty());
    assert!(raw["page"]["text"].as_str().expect("source").contains("99"));
    let old = fixture
        .corpus
        .research()
        .call(
            "mdn_compat_get",
            json!({"feature":"api.fetch","snapshot":historical.id}),
        )
        .await
        .expect("historical feature remains");
    assert_eq!(old["original"]["chrome"]["version_added"], "42");
}

#[tokio::test]
async fn mdn_inventory_wide_directories_repartition_without_rewriting_history() {
    let store = Memory::default();
    let empty = inventory::empty(&store).await.expect("empty");
    let mut root = empty.clone();
    let mut roots = Vec::new();
    for index in 0..300 {
        let path = format!("@features/api.feature_{index:04}");
        root = inventory::update(
            &store,
            &root,
            &path,
            Some(Member {
                path: path.clone(),
                oid: format!("{index:040x}"),
                mode: "100644".into(),
                kind: "feature".into(),
                projection: Some(format!("{index:064x}")),
                raw: None,
                gaps: if index % 7 == 0 {
                    vec!["synthetic_gap".into()]
                } else {
                    Vec::new()
                },
            }),
        )
        .await
        .expect("wide insertion");
        if index == 63 || index == 64 || index == 299 {
            roots.push(root.clone());
        }
    }
    let original = root.clone();
    let node = inventory::node(&store, &root).await.expect("root");
    assert_eq!(node.members, 300);
    assert_eq!(node.searchable, 300);
    assert_eq!(node.gaps, 43);
    let members = inventory::members(&store, &root, 1000)
        .await
        .expect("all members");
    assert_eq!(members.len(), 300);
    let old = inventory::get(&store, &root, "@features/api.feature_0007")
        .await
        .expect("member")
        .expect("old");
    let mut replacement = old.clone();
    replacement.gaps.clear();
    replacement.projection = Some("f".repeat(64));
    root = inventory::update(
        &store,
        &root,
        &replacement.path.clone(),
        Some(replacement.clone()),
    )
    .await
    .expect("replacement");
    root = inventory::update(&store, &root, "@features/api.feature_0001", None)
        .await
        .expect("delete");
    assert_eq!(
        inventory::node(&store, &root)
            .await
            .expect("changed root")
            .members,
        299
    );
    assert_eq!(
        inventory::node(&store, &root)
            .await
            .expect("changed root")
            .gaps,
        42
    );
    assert_eq!(
        inventory::get(&store, &original, &old.path)
            .await
            .expect("historical lookup"),
        Some(old)
    );
    assert_eq!(
        inventory::get(&store, &root, &replacement.path)
            .await
            .expect("current lookup"),
        Some(replacement)
    );
    assert_eq!(
        inventory::members(&store, &roots[0], 1000)
            .await
            .expect("before repartition")
            .len(),
        64
    );
    assert_eq!(
        inventory::members(&store, &roots[1], 1000)
            .await
            .expect("after repartition")
            .len(),
        65
    );
    assert!(
        inventory::members(&store, &empty, 1)
            .await
            .expect("empty history")
            .is_empty()
    );
    assert_eq!(
        inventory::get(&store, &original, "@features/api.feature_0001")
            .await
            .expect("retained deleted member")
            .expect("historical member")
            .path,
        "@features/api.feature_0001"
    );
}

#[tokio::test]
async fn mdn_corpus_mirrors_survive_wide_repository_root_partition() {
    let fixture = Fixture::new().await;
    fixture.current().await;
    let mut files = compat_files();
    let extras: Vec<String> = (0..70)
        .map(|index| format!("root-extra-{index:03}.txt"))
        .collect();
    for extra in &extras {
        files.insert(extra.as_str(), b"Retained synthetic root member.".to_vec());
    }
    files.insert("api/fetch.json",br#"{"api":{"fetch":{"__compat":{"support":{"chrome":{"version_added":"42"},"chrome_android":"mirror"},"status":{"experimental":false,"standard_track":true,"deprecated":false}}}}}"#.to_vec());
    files.insert("browsers/chrome_android.json",br#"{"browsers":{"chrome_android":{"name":"Chrome Android","type":"mobile","upstream":"chrome","accepts_flags":false,"releases":{"42":{"engine":"Blink","engine_version":"42","status":"retired"}}}}}"#.to_vec());
    let revision = commit_map(&fixture.compat, &files, &[&fixture.compat_revision]).await;
    update(&fixture.compat, "refs/heads/main", &revision).await;
    fixture
        .corpus
        .synchronize(Repo::Compat, CancellationToken::new())
        .await
        .expect("capture wide root");
    fixture.current().await;
    let snapshot = fixture
        .corpus
        .snapshot(Repo::Compat, &revision)
        .await
        .expect("snapshot")
        .expect("published");
    assert!(
        !inventory::node(fixture.store.as_ref(), &snapshot.inventory)
            .await
            .expect("root")
            .buckets
            .is_empty(),
        "fixture must partition repository root"
    );
    let support = fixture
        .corpus
        .research()
        .call("mdn_compat_get", json!({"feature":"api.fetch"}))
        .await
        .expect("mirrored feature");
    assert_eq!(support["resolved"]["chrome_android"]["version_added"], "42");
    assert!(support["gaps"].as_array().expect("gaps").is_empty());
}

#[tokio::test]
async fn mdn_corpus_failed_include_projection_recovers_when_only_dependency_changes() {
    let fixture = Fixture::new().await;
    fixture.current().await;
    let mut files = content_files();
    let mut parent = fixture.content_revision.clone();
    for invalid in [
        b"---\nslug: [unterminated\n---\nMalformed inclusion.".to_vec(),
        vec![b'x'; 4 * 1024 * 1024 + 1],
    ] {
        files.insert(PART_PATH, invalid);
        parent = fixture.publish_content(&files, &parent).await;
        assert!(
            fixture
                .corpus
                .research()
                .call("mdn_get", json!({"slug":"Web/API/Fetch"}))
                .await
                .is_err(),
            "failed included member cannot leave stale projected text"
        );
        let source = fixture
            .corpus
            .research()
            .call(
                "mdn_get",
                json!({"path":FETCH_PATH,"representation":"source"}),
            )
            .await
            .expect("including source remains available");
        assert_eq!(
            source["page"]["text"],
            std::str::from_utf8(FETCH).expect("fixture text")
        );
        files.insert(PART_PATH, PART.to_vec());
        parent = fixture.publish_content(&files, &parent).await;
        let repaired = fixture.text("Web/API/Fetch", None).await;
        assert!(
            repaired["page"]["text"]
                .as_str()
                .expect("recovered text")
                .contains("Original network evidence")
        );
        assert_eq!(
            repaired["oid"], source["oid"],
            "only included source changed"
        );
    }
}

#[tokio::test]
async fn mdn_corpus_malformed_bcd_identifiers_are_accounted_and_later_fixed() {
    let fixture = Fixture::new().await;
    fixture.current().await;
    let mut files = compat_files();
    let mut data = json!({"__compat":{"support":{}}});
    for _ in 0..8 {
        data = json!({"x".repeat(511):data});
    }
    data["api"] =
        json!({"bad//key":{"__compat":{"support":{}}},"bad\\key":{"__compat":{"support":{}}}});
    files.insert(
        "api/fetch.json",
        serde_json::to_vec(&data).expect("BCD fixture"),
    );
    let malformed = commit_map(&fixture.compat, &files, &[&fixture.compat_revision]).await;
    update(&fixture.compat, "refs/heads/main", &malformed).await;
    fixture
        .corpus
        .synchronize(Repo::Compat, CancellationToken::new())
        .await
        .expect("capture malformed identifiers");
    fixture.current().await;
    let snapshot = fixture
        .corpus
        .snapshot(Repo::Compat, &malformed)
        .await
        .expect("snapshot")
        .expect("published despite unsupported projection");
    assert_eq!(snapshot.coverage["accounted"], true);
    let raw = fixture
        .corpus
        .research()
        .call(
            "mdn_get",
            json!({"repository":"compat","path":"api/fetch.json","representation":"source"}),
        )
        .await
        .expect("unsupported raw source");
    assert!(
        raw["gaps"]
            .as_array()
            .expect("gaps")
            .iter()
            .any(|gap| gap == "unsupported_feature_identifier")
    );
    files.insert("api/fetch.json", BCD.to_vec());
    let fixed = commit_map(&fixture.compat, &files, &[&malformed]).await;
    update(&fixture.compat, "refs/heads/main", &fixed).await;
    fixture
        .corpus
        .synchronize(Repo::Compat, CancellationToken::new())
        .await
        .expect("capture fixed identifier");
    fixture.current().await;
    fixture.history().await;
    assert_eq!(
        fixture
            .corpus
            .research()
            .call("mdn_compat_get", json!({"feature":"api.fetch"}))
            .await
            .expect("fixed feature")["original"]["chrome"]["version_added"],
        "42"
    );
    assert!(
        fixture
            .corpus
            .snapshot(Repo::Compat, &malformed)
            .await
            .expect("historical malformed accounting")
            .is_some()
    );
}

#[tokio::test]
async fn mdn_corpus_unindexable_article_does_not_poison_snapshot_publication() {
    let fixture = Fixture::new().await;
    fixture.current().await;
    let mut files = content_files();
    let mut long = b"---\ntitle: Unindexable\nslug: Web/API/Unindexable\n---\n".to_vec();
    long.extend(vec![b'x'; 70_000]);
    files.insert("files/en-us/web/api/unindexable/index.md", long);
    let revision = fixture
        .publish_content(&files, &fixture.content_revision)
        .await;
    let snapshot = fixture
        .corpus
        .snapshot(Repo::Content, &revision)
        .await
        .expect("snapshot")
        .expect("new default snapshot");
    assert_eq!(snapshot.coverage["accounted"], true);
    let bad = fixture.text("Web/API/Unindexable", None).await;
    assert!(
        bad["gaps"]
            .as_array()
            .expect("gaps")
            .iter()
            .any(|gap| gap == "search_index_gap")
    );
    assert_eq!(bad["page"]["total_bytes"], 70_000);
    let good = fixture
        .corpus
        .research()
        .call(
            "mdn_search",
            json!({"query":"network","page_type":"web-api-instance-method"}),
        )
        .await
        .expect("other documents remain searchable");
    assert_eq!(good["results"].as_array().expect("results").len(), 1);
    let all = fixture
        .corpus
        .research()
        .call("mdn_search", json!({"query":"Unindexable"}))
        .await
        .expect("gap does not refer to missing index projection");
    assert!(all["results"].as_array().expect("results").is_empty());
}

#[tokio::test]
async fn mdn_corpus_identical_bcd_move_keeps_pinned_source_paths() {
    let fixture = Fixture::new().await;
    fixture.current().await;
    let original = fixture
        .corpus
        .snapshot(Repo::Compat, &fixture.compat_revision)
        .await
        .expect("snapshot")
        .expect("original");
    let mut files = compat_files();
    let body = files.remove("api/fetch.json").expect("original source");
    files.insert("api/moved/fetch.json", body);
    let revision = commit_map(&fixture.compat, &files, &[&fixture.compat_revision]).await;
    update(&fixture.compat, "refs/heads/main", &revision).await;
    fixture
        .corpus
        .synchronize(Repo::Compat, CancellationToken::new())
        .await
        .expect("capture move");
    fixture.current().await;
    fixture.history().await;
    let moved = fixture
        .corpus
        .snapshot(Repo::Compat, &revision)
        .await
        .expect("snapshot")
        .expect("moved");
    for (snapshot, path) in [
        (&original, "api/fetch.json"),
        (&moved, "api/moved/fetch.json"),
    ] {
        let feature = fixture
            .corpus
            .research()
            .call(
                "mdn_compat_get",
                json!({"feature":"api.fetch","snapshot":snapshot.id}),
            )
            .await
            .expect("pinned feature");
        assert_eq!(feature["source_path"], path);
        assert_eq!(feature["original"]["chrome"]["version_added"], "42");
        let search = fixture
            .corpus
            .research()
            .call(
                "mdn_compat_search",
                json!({"feature":"api.fetch","snapshot":snapshot.id}),
            )
            .await
            .expect("pinned search");
        assert_eq!(search["results"].as_array().expect("results").len(), 1);
        assert_eq!(search["results"][0]["path"], path);
        let raw=fixture.corpus.research().call("mdn_get",json!({"repository":"compat","path":path,"snapshot":snapshot.id,"representation":"source"})).await.expect("pinned original");
        assert_eq!(
            raw["page"]["text"],
            std::str::from_utf8(BCD).expect("fixture text")
        );
    }
}

#[tokio::test]
async fn mdn_corpus_duplicate_bcd_identity_remains_ambiguous_until_one_source_is_removed() {
    let fixture = Fixture::new().await;
    fixture.current().await;
    let mut files = compat_files();
    files.insert("api/duplicate.json",br#"{"api":{"fetch":{"__compat":{"support":{"chrome":{"version_added":"99"}},"status":{"experimental":false,"standard_track":true,"deprecated":false}}}}}"#.to_vec());
    let ambiguous_revision = commit_map(&fixture.compat, &files, &[&fixture.compat_revision]).await;
    update(&fixture.compat, "refs/heads/main", &ambiguous_revision).await;
    fixture
        .corpus
        .synchronize(Repo::Compat, CancellationToken::new())
        .await
        .expect("capture duplicate");
    fixture.current().await;
    let ambiguous = fixture
        .corpus
        .snapshot(Repo::Compat, &ambiguous_revision)
        .await
        .expect("snapshot")
        .expect("accounted ambiguity");
    assert_eq!(ambiguous.coverage["accounted"], true);
    let marker_path = format!("@ambiguities/{}", inventory::digest(b"@features/api.fetch"));
    let marker = inventory::get(fixture.store.as_ref(), &ambiguous.inventory, &marker_path)
        .await
        .expect("marker")
        .expect("explicit ambiguity");
    assert_eq!(marker.kind, "ambiguity");
    assert!(
        marker
            .gaps
            .iter()
            .any(|gap| gap == "ambiguous_compatibility_identity")
    );
    assert!(
        fixture
            .corpus
            .research()
            .call("mdn_compat_get", json!({"feature":"api.fetch"}))
            .await
            .is_err(),
        "duplicate sources cannot choose arbitrary support"
    );
    assert!(
        fixture
            .corpus
            .research()
            .call("mdn_compat_search", json!({"feature":"api.fetch"}))
            .await
            .expect("ambiguity search")["results"]
            .as_array()
            .expect("results")
            .is_empty()
    );
    for path in ["api/fetch.json", "api/duplicate.json"] {
        assert!(
            fixture
                .corpus
                .research()
                .call(
                    "mdn_get",
                    json!({"repository":"compat","path":path,"representation":"source"})
                )
                .await
                .expect("duplicate raw remains retained")["page"]["text"]
                .is_string()
        );
    }
    files.remove("api/duplicate.json");
    let fixed_revision = commit_map(&fixture.compat, &files, &[&ambiguous_revision]).await;
    update(&fixture.compat, "refs/heads/main", &fixed_revision).await;
    fixture
        .corpus
        .synchronize(Repo::Compat, CancellationToken::new())
        .await
        .expect("capture unique identity");
    fixture.current().await;
    fixture.history().await;
    assert_eq!(
        fixture
            .corpus
            .research()
            .call("mdn_compat_get", json!({"feature":"api.fetch"}))
            .await
            .expect("unique feature restored")["original"]["chrome"]["version_added"],
        "42"
    );
    assert!(
        fixture
            .corpus
            .research()
            .call(
                "mdn_compat_get",
                json!({"feature":"api.fetch","snapshot":ambiguous.id})
            )
            .await
            .is_err(),
        "historical ambiguity remains fixed"
    );
    assert!(
        inventory::get(fixture.store.as_ref(), &ambiguous.inventory, &marker_path)
            .await
            .expect("historical ambiguity marker")
            .is_some()
    );
}

#[tokio::test]
async fn mdn_corpus_offline_rebuild_preserves_corrupt_historical_index_and_originals() {
    let fixture = Fixture::new().await;
    fixture.current().await;
    fixture.history().await;
    let original = fixture
        .corpus
        .snapshot(Repo::Content, &fixture.content_revision)
        .await
        .expect("snapshot")
        .expect("original");
    let original_default = fixture
        .store
        .mdn_state("default-view")
        .await
        .expect("default")
        .expect("view");
    let target = fixture._root.path().join("target");
    let manifest: Value = serde_json::from_slice(
        &std::fs::read(target.join(original.index["path"].as_str().expect("manifest path")))
            .expect("retained descriptor"),
    )
    .expect("descriptor");
    let shard = manifest["shard"]["id"].as_str().expect("retained shard");
    let damaged = target
        .join("mdn-indexes/shards")
        .join(shard)
        .join("meta.json");
    std::fs::write(&damaged, b"corrupt synthetic historical index")
        .expect("damage disposable fixture index");
    // Evict cached readers through real public index generations, modeling a cold restart.
    for index in 0..5 {
        let document = IndexDocument {
            id: inventory::digest(format!("eviction-{index}").as_bytes()),
            kind: "article".into(),
            slug: format!("Eviction{index}"),
            title: "Disposable cache eviction".into(),
            path: format!("eviction-{index}"),
            text: "Unrelated synthetic projection.".into(),
            metadata: json!({}),
        };
        fixture
            .corpus
            .index
            .publish(None, vec![document], CancellationToken::new())
            .await
            .expect("evict historical cached generation");
    }
    assert!(
        fixture
            .corpus
            .research()
            .call(
                "mdn_search",
                json!({"query":"network","snapshot":original.id})
            )
            .await
            .is_err(),
        "cold damaged index must fail explicitly"
    );
    fixture.server.abort();
    let attempts = fixture.corpus.broker.attempt_count();
    let rebuilt = fixture
        .corpus
        .rebuild_index(CancellationToken::new())
        .await
        .expect("offline rebuild from retained projections");
    assert_eq!(rebuilt["network_requests"], 0);
    assert_eq!(fixture.corpus.broker.attempt_count(), attempts);
    assert_ne!(
        fixture
            .store
            .mdn_state("default-view")
            .await
            .expect("rebuilt default")
            .expect("view"),
        original_default
    );
    let selected = fixture
        .corpus
        .snapshot(Repo::Content, &fixture.content_revision)
        .await
        .expect("snapshot")
        .expect("rebuilt snapshot");
    assert_ne!(selected.id, original.id);
    assert_eq!(selected.coverage["rebuild_of"], original.id);
    assert!(
        !fixture
            .corpus
            .research()
            .call("mdn_search", json!({"query":"network"}))
            .await
            .expect("rebuilt default search")["results"]
            .as_array()
            .expect("results")
            .is_empty()
    );
    let discovery = fixture
        .corpus
        .research()
        .call("mdn_snapshots", json!({"repository":"content"}))
        .await
        .expect("rebuilt discovery");
    assert!(
        discovery["results"]
            .as_array()
            .expect("snapshots")
            .iter()
            .any(|row| row["id"] == selected.id)
    );
    assert!(
        fixture
            .corpus
            .research()
            .call(
                "mdn_search",
                json!({"query":"network","snapshot":original.id})
            )
            .await
            .is_err(),
        "old index is not silently repaired/rebound"
    );
    let raw = fixture
        .corpus
        .research()
        .call(
            "mdn_get",
            json!({"path":FETCH_PATH,"snapshot":original.id,"representation":"source"}),
        )
        .await
        .expect("old original source remains readable");
    assert_eq!(
        raw["page"]["text"],
        std::str::from_utf8(FETCH).expect("fixture source")
    );
    let rebuilt_again = fixture
        .corpus
        .rebuild_index(CancellationToken::new())
        .await
        .expect("second offline repair");
    assert_eq!(
        rebuilt_again["snapshots"], rebuilt["snapshots"],
        "each maintenance pass rebuilds one selected descriptor per source commit, not every prior derived generation"
    );
    assert_eq!(fixture.corpus.broker.attempt_count(), attempts);
    assert!(
        fixture
            .store
            .mdn_get("snapshots", &selected.id)
            .await
            .expect("first repaired generation remains")
            .is_some()
    );
    assert_eq!(
        std::fs::read(&damaged).expect("damaged evidence remains"),
        b"corrupt synthetic historical index"
    );
}

#[tokio::test]
async fn mdn_corpus_history_resets_legacy_processing_generation_without_new_source_traffic() {
    let fixture = Fixture::new().await;
    fixture.current().await;
    for repo in [Repo::Content, Repo::Compat] {
        let observation = fixture
            .corpus
            .observation(repo)
            .await
            .expect("observation")
            .expect("captured");
        fixture.store.mdn_set_state(&format!("{}-history",repo.as_str()),&json!({"observation":observation,"offset":observation.commits.bytes,"processed":observation.total_commits,"complete":true,"processor_version":2})).await.expect("legacy completed checkpoint");
    }
    let attempts = fixture.corpus.broker.attempt_count();
    fixture.server.abort();
    fixture.history().await;
    assert_eq!(fixture.corpus.broker.attempt_count(), attempts);
    for repo in [Repo::Content, Repo::Compat] {
        let state: History = decoded(
            fixture
                .store
                .mdn_state(&format!("{}-history", repo.as_str()))
                .await
                .expect("new checkpoint")
                .expect("state"),
        )
        .expect("history state");
        assert_eq!(state.processor_version, PROCESSOR_VERSION);
        assert!(state.complete);
        assert_eq!(state.processed, state.observation.total_commits);
        assert!(
            fixture
                .store
                .mdn_get(
                    "changes-complete",
                    &snapshot_key(
                        repo,
                        if repo == Repo::Content {
                            &fixture.content_revision
                        } else {
                            &fixture.compat_revision
                        }
                    )
                )
                .await
                .expect("backfill change checkpoint")
                .is_some(),
            "legacy complete flag must not skip current-generation backfill"
        );
    }
}

#[tokio::test]
async fn mdn_corpus_large_redirect_projection_publishes_and_advances() {
    let fixture = Fixture::new().await;
    let mut files = content_files();
    let mut redirects = String::new();
    for index in 0..5_000 {
        redirects.push_str(&format!(
            "/en-US/docs/Web/API/SyntheticAlias{index:04}\t/en-US/docs/Web/API/Fetch\n"
        ));
    }
    assert!(redirects.len() > 128 * 1024);
    assert!(redirects.len() < 4 * 1024 * 1024);
    files.insert("files/en-us/_redirects.txt", redirects.as_bytes().to_vec());
    let first = fixture
        .publish_content(&files, &fixture.content_revision)
        .await;
    let snapshot = fixture
        .corpus
        .snapshot(Repo::Content, &first)
        .await
        .expect("snapshot")
        .expect("large current redirects published");
    assert_eq!(snapshot.coverage["accounted"], true);
    let selected = fixture.text("Web/API/SyntheticAlias4999", None).await;
    assert_eq!(selected["path"], FETCH_PATH);
    assert_eq!(
        selected["redirects"].as_array().expect("redirects").len(),
        1
    );
    redirects.push_str("/en-US/docs/Web/API/SuccessorAlias\t/en-US/docs/Web/API/Fetch\n");
    files.insert("files/en-us/_redirects.txt", redirects.into_bytes());
    let second = fixture.publish_content(&files, &first).await;
    assert!(
        fixture
            .corpus
            .snapshot(Repo::Content, &second)
            .await
            .expect("successor snapshot")
            .is_some()
    );
    assert_eq!(
        fixture.text("Web/API/SuccessorAlias", None).await["path"],
        FETCH_PATH
    );
    assert_eq!(
        fixture
            .text("Web/API/SyntheticAlias4999", Some(&snapshot.id))
            .await["path"],
        FETCH_PATH
    );
}

#[tokio::test]
async fn mdn_corpus_bcd_normalized_output_overflow_is_raw_retained_source_gap() {
    let fixture = Fixture::new().await;
    fixture.current().await;
    let mut files = compat_files();
    let mut leaves = serde_json::Map::new();
    for index in 0..4_000 {
        leaves.insert(
            format!("feature_{index:04}"),
            json!({"__compat":{"support":{}}}),
        );
    }
    let mut root = Value::Object(leaves);
    for index in 0..7 {
        root = Value::Object(serde_json::Map::from_iter([(
            format!("p{index}{}", "x".repeat(470)),
            root,
        )]));
    }
    let bytes = serde_json::to_vec(&Value::Object(serde_json::Map::from_iter([(
        "api".into(),
        root,
    )])))
    .expect("synthetic source");
    assert!(bytes.len() < 4 * 1024 * 1024);
    files.insert("api/expanded.json", bytes.clone());
    let revision = commit_map(&fixture.compat, &files, &[&fixture.compat_revision]).await;
    update(&fixture.compat, "refs/heads/main", &revision).await;
    fixture
        .corpus
        .synchronize(Repo::Compat, CancellationToken::new())
        .await
        .expect("capture expansive source");
    fixture.current().await;
    let snapshot = fixture
        .corpus
        .snapshot(Repo::Compat, &revision)
        .await
        .expect("snapshot")
        .expect("accounted expanded source");
    assert_eq!(snapshot.coverage["accounted"], true);
    let member = inventory::get(
        fixture.store.as_ref(),
        &snapshot.inventory,
        "api/expanded.json",
    )
    .await
    .expect("member")
    .expect("raw member");
    assert!(member.projection.is_none());
    assert!(member.gaps.iter().any(|gap| gap == "capacity"));
    let members = inventory::members(fixture.store.as_ref(), &snapshot.inventory, 10_000)
        .await
        .expect("membership");
    assert_eq!(
        members
            .iter()
            .filter(|member| member.kind == "feature")
            .count(),
        1,
        "no partial synthetic features from the rejected source may be published"
    );
    let ordinary = fixture
        .corpus
        .research()
        .call("mdn_compat_get", json!({"feature":"api.fetch"}))
        .await
        .expect("valid neighbor stays available");
    assert_eq!(ordinary["original"]["chrome"]["version_added"], "42");
    let raw=fixture.corpus.research().call("mdn_get",json!({"repository":"compat","path":"api/expanded.json","representation":"source","limit":32})).await.expect("oversized normalization raw evidence");
    assert_eq!(raw["page"]["total_bytes"], bytes.len());
    assert_eq!(
        raw["page"]["text"],
        std::str::from_utf8(&bytes[..32]).expect("ASCII source")
    );
}

#[tokio::test]
async fn mdn_corpus_style_only_html_edits_share_projection_but_pin_source_and_old_generation() {
    const HTML_PATH: &str = "files/en-us/web/api/stable_style/index.html";
    const ORIGINAL: &[u8] = b"---\ntitle: Stable style\nslug: Web/API/StableStyle\npage-type: guide\n---\n<h1>Stable style</h1><div class=\"note\" style=\"color: red\">Stable semantic content.</div>";
    const RESTYLED: &[u8] = b"---\ntitle: Stable style\nslug: Web/API/StableStyle\npage-type: guide\n---\n<h1>Stable style</h1><div class=\"note\" style=\"color: blue\">Stable semantic content.</div>";
    let fixture = Fixture::new().await;
    fixture.current().await;
    fixture.server.abort();
    let attempts = fixture.corpus.broker.attempt_count();
    // Write only disposable local Git objects after the frozen baseline; no
    // synchronization or provider requests are needed to replay these trees.
    let first_revision = commit_map(
        &fixture.corpus.content,
        &BTreeMap::from([(HTML_PATH, ORIGINAL.to_vec())]),
        &[&fixture.content_revision],
    )
    .await;
    let second_revision = commit_map(
        &fixture.corpus.content,
        &BTreeMap::from([(HTML_PATH, RESTYLED.to_vec())]),
        &[&first_revision],
    )
    .await;
    let mut snapshots = Vec::new();
    for revision in [&first_revision, &second_revision] {
        let mut done = false;
        for _ in 0..30 {
            if fixture
                .corpus
                .process_commit(Repo::Content, revision, false, CancellationToken::new())
                .await
                .expect("process retained HTML")
            {
                done = true;
                break;
            }
        }
        assert!(done, "retained HTML commit finishes within fixture slices");
        fixture
            .corpus
            .flush(CancellationToken::new())
            .await
            .expect("publish retained snapshot");
        snapshots.push(
            fixture
                .corpus
                .snapshot(Repo::Content, revision)
                .await
                .expect("snapshot lookup")
                .expect("published snapshot"),
        );
    }
    let first = &snapshots[0];
    let second = &snapshots[1];
    assert_ne!(first.id, second.id);
    assert_eq!(first.processor_version, 3);
    assert_eq!(second.processor_version, 3);
    let first_member = inventory::get(fixture.store.as_ref(), &first.inventory, HTML_PATH)
        .await
        .expect("first inventory")
        .expect("first article");
    let second_member = inventory::get(fixture.store.as_ref(), &second.inventory, HTML_PATH)
        .await
        .expect("second inventory")
        .expect("second article");
    assert_ne!(first_member.oid, second_member.oid);
    assert_ne!(first_member.raw, second_member.raw);
    assert_eq!(
        first_member.projection, second_member.projection,
        "style-only edits share normalized projections"
    );
    assert_eq!(
        first.index, second.index,
        "no duplicate index generation is needed"
    );
    let projection_id = first_member.projection.as_ref().expect("shared projection");
    let projection = fixture
        .store
        .mdn_get("projections", projection_id)
        .await
        .expect("projection row")
        .expect("retained projection")
        .data;
    assert!(
        projection.get("source_oid").is_none(),
        "source identity is not part of normalized evidence"
    );
    let indexed: IndexDocument = decoded(
        fixture
            .store
            .mdn_get("index-documents", projection_id)
            .await
            .expect("index row")
            .expect("shared index document")
            .data,
    )
    .expect("index document");
    assert_eq!(&indexed.id, projection_id);
    let style_documents = fixture
        .store
        .rows
        .lock()
        .expect("rows")
        .iter()
        .filter(|((kind, _), row)| kind == "index-documents" && row.data["path"] == HTML_PATH)
        .count();
    assert_eq!(
        style_documents, 1,
        "both revisions use the same index document ID"
    );
    let mut text_resources = Vec::new();
    let mut source_resources = Vec::new();
    for (snapshot, member, source) in [
        (first, &first_member, ORIGINAL),
        (second, &second_member, RESTYLED),
    ] {
        let text = fixture
            .text("Web/API/StableStyle", Some(&snapshot.id))
            .await;
        assert_eq!(text["oid"], member.oid);
        assert_eq!(text["document"]["source_oid"], member.oid);
        assert!(
            text["page"]["text"]
                .as_str()
                .expect("normalized text")
                .contains("Stable semantic content.")
        );
        let by_path = fixture
            .corpus
            .research()
            .call("mdn_get", json!({"path":HTML_PATH,"snapshot":snapshot.id}))
            .await
            .expect("pinned path text");
        assert_eq!(by_path["document"]["source_oid"], member.oid);
        let text_uri = text["resource_uri"].as_str().expect("text URI").to_owned();
        let resource = fixture
            .corpus
            .research()
            .read_resource(&text_uri)
            .await
            .expect("pinned text resource");
        assert_eq!(resource["contents"][0]["text"], text["page"]["text"]);
        assert_eq!(
            resource["contents"][0]["_meta"]["provenance"]["snapshot"],
            snapshot.id
        );
        text_resources.push(text_uri);
        let raw = fixture
            .corpus
            .research()
            .call(
                "mdn_get",
                json!({"path":HTML_PATH,"snapshot":snapshot.id,"representation":"source"}),
            )
            .await
            .expect("pinned raw HTML");
        assert_eq!(raw["oid"], member.oid);
        assert_eq!(
            raw["page"]["text"],
            std::str::from_utf8(source).expect("source UTF8")
        );
        let raw_uri = raw["resource_uri"].as_str().expect("source URI").to_owned();
        assert_eq!(
            fixture
                .corpus
                .research()
                .read_resource(&raw_uri)
                .await
                .expect("original resource")["contents"][0]["text"],
            std::str::from_utf8(source).expect("source UTF8")
        );
        source_resources.push(raw_uri);
    }
    assert_ne!(text_resources[0], text_resources[1]);
    assert_ne!(source_resources[0], source_resources[1]);

    // A retained generation-2 snapshot has its original projection and index;
    // selecting its immutable ID must preserve the stored metadata verbatim.
    let mut legacy_projection = projection.clone();
    legacy_projection["processor_version"] = json!(2);
    legacy_projection["source_oid"] = json!(first_member.oid);
    let legacy_id =
        inventory::digest(&serde_json::to_vec(&legacy_projection).expect("legacy encoding"));
    fixture
        .store
        .mdn_put("projections", &legacy_id, &legacy_projection)
        .await
        .expect("retained v2 projection");
    fixture
        .store
        .mdn_put(
            "projection-headers",
            &legacy_id,
            &json!({"slug":"Web/API/StableStyle"}),
        )
        .await
        .expect("retained v2 header");
    let mut legacy_indexed = indexed;
    legacy_indexed.id = legacy_id.clone();
    fixture
        .store
        .mdn_put(
            "index-documents",
            &legacy_id,
            &encoded(&legacy_indexed).expect("legacy document"),
        )
        .await
        .expect("retained v2 index document");
    let mut legacy_member = first_member.clone();
    legacy_member.projection = Some(legacy_id.clone());
    let legacy_inventory = inventory::update(
        fixture.store.as_ref(),
        &first.inventory,
        HTML_PATH,
        Some(legacy_member),
    )
    .await
    .expect("retained v2 inventory");
    let legacy_index = fixture
        .corpus
        .index
        .publish(None, vec![legacy_indexed], CancellationToken::new())
        .await
        .expect("retained v2 index");
    let mut legacy = first.clone();
    legacy.id = inventory::digest(
        &serde_json::to_vec(&("content", &first_revision, 2_u32, &legacy_inventory))
            .expect("legacy identity"),
    );
    legacy.inventory = legacy_inventory;
    legacy.processor_version = 2;
    legacy.index = legacy_index;
    let retained_snapshot = encoded(&legacy).expect("legacy snapshot");
    fixture
        .store
        .mdn_put("snapshots", &legacy.id, &retained_snapshot)
        .await
        .expect("retained v2 snapshot");
    fixture
        .store
        .mdn_put(
            "snapshot-keys",
            &format!("content:{first_revision}:2"),
            &json!(legacy.id),
        )
        .await
        .expect("retained v2 key");
    let old = fixture.text("Web/API/StableStyle", Some(&legacy.id)).await;
    let mut expected_metadata = legacy_projection.clone();
    expected_metadata
        .as_object_mut()
        .expect("legacy metadata")
        .remove("text");
    assert_eq!(old["document"], expected_metadata);
    assert_eq!(old["provenance"]["processor_version"], 2);
    assert_eq!(old["document"]["source_oid"], first_member.oid);
    assert_eq!(
        fixture
            .corpus
            .research()
            .call(
                "mdn_get",
                json!({"snapshot":legacy.id,"path":HTML_PATH,"representation":"source"})
            )
            .await
            .expect("legacy original")["page"]["text"],
        std::str::from_utf8(ORIGINAL).unwrap()
    );
    assert_eq!(
        fixture
            .corpus
            .research()
            .call(
                "mdn_search",
                json!({"snapshot":legacy.id,"query":"semantic"})
            )
            .await
            .expect("legacy index remains readable")["results"]
            .as_array()
            .expect("legacy hits")
            .len(),
        1
    );
    assert_eq!(
        fixture
            .store
            .mdn_get("snapshots", &legacy.id)
            .await
            .expect("retained snapshot")
            .expect("exists")
            .data,
        retained_snapshot
    );
    assert_eq!(
        fixture
            .store
            .mdn_get("projections", &legacy_id)
            .await
            .expect("retained projection")
            .expect("exists")
            .data,
        legacy_projection
    );
    assert_eq!(
        fixture.corpus.broker.attempt_count(),
        attempts,
        "generation processing and pinned reads use no provider requests"
    );
}

#[tokio::test]
async fn mdn_corpus_offline_rebuild_repairs_generation_two_default_without_renewing_sources() {
    let fixture = Fixture::new().await;
    assert!(
        !fixture.corpus.config.enabled,
        "collection remains disabled"
    );
    fixture.current().await;
    let current_view_id = fixture
        .store
        .mdn_state("default-view")
        .await
        .unwrap()
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    let mut old_view: View = decoded(
        fixture
            .store
            .mdn_get("views", &current_view_id)
            .await
            .unwrap()
            .unwrap()
            .data,
    )
    .unwrap();
    let mut originals = Vec::new();
    let mut remove_keys = Vec::new();
    for (repo, id) in [
        (Repo::Content, &old_view.content),
        (Repo::Compat, &old_view.compatibility),
    ] {
        let mut snapshot: Snapshot = decoded(
            fixture
                .store
                .mdn_get("snapshots", id)
                .await
                .unwrap()
                .unwrap()
                .data,
        )
        .unwrap();
        remove_keys.push(("snapshots".to_owned(), snapshot.id.clone()));
        remove_keys.push((
            "snapshot-keys".to_owned(),
            snapshot_key(repo, &snapshot.revision),
        ));
        snapshot.processor_version = 2;
        snapshot.id = inventory::digest(
            &serde_json::to_vec(&(
                repo.as_str(),
                &snapshot.revision,
                2_u32,
                &snapshot.inventory,
            ))
            .unwrap(),
        );
        fixture
            .store
            .mdn_put("snapshots", &snapshot.id, &encoded(&snapshot).unwrap())
            .await
            .unwrap();
        fixture
            .store
            .mdn_put(
                "snapshot-keys",
                &format!("{}:{}:2", repo.as_str(), snapshot.revision),
                &json!(snapshot.id),
            )
            .await
            .unwrap();
        originals.push(snapshot);
    }
    // The disposable store now models an installation whose only published
    // processing generation is 2; generation 3 has never been collected.
    {
        let mut rows = fixture.store.rows.lock().unwrap();
        for key in remove_keys {
            rows.remove(&key);
        }
        rows.retain(|(kind, _), _| kind != "views");
    }
    fixture
        .store
        .states
        .lock()
        .unwrap()
        .retain(|key, _| !key.starts_with("prepared:") && !key.starts_with("work:"));
    old_view.content = originals[0].id.clone();
    old_view.compatibility = originals[1].id.clone();
    old_view.validated_at -= 60;
    old_view.id = inventory::digest(
        &serde_json::to_vec(&(
            &old_view.content,
            &old_view.compatibility,
            &old_view.content_observation,
            &old_view.compatibility_observation,
            old_view.validated_at,
        ))
        .unwrap(),
    );
    fixture.store.mdn_publish_view(&old_view).await.unwrap();
    assert!(
        fixture
            .corpus
            .snapshot(Repo::Content, &fixture.content_revision)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        fixture
            .corpus
            .snapshot(Repo::Compat, &fixture.compat_revision)
            .await
            .unwrap()
            .is_none()
    );
    let old_view_data = encoded(&old_view).unwrap();
    let old_snapshot_data = encoded(&originals[0]).unwrap();
    let target = fixture._root.path().join("target");
    let manifest: Value = serde_json::from_slice(
        &std::fs::read(target.join(originals[0].index["path"].as_str().unwrap())).unwrap(),
    )
    .unwrap();
    let damaged = target
        .join("mdn-indexes/shards")
        .join(manifest["shard"]["id"].as_str().unwrap())
        .join("meta.json");
    std::fs::write(&damaged, b"corrupt legacy default fixture index").unwrap();
    for index in 0..5 {
        fixture
            .corpus
            .index
            .publish(
                None,
                vec![IndexDocument {
                    id: inventory::digest(format!("legacy-default-evict-{index}").as_bytes()),
                    kind: "article".into(),
                    slug: format!("Eviction{index}"),
                    title: "Disposable reader eviction".into(),
                    path: format!("eviction-{index}"),
                    text: "Unrelated synthetic projection.".into(),
                    metadata: json!({}),
                }],
                CancellationToken::new(),
            )
            .await
            .unwrap();
    }
    assert!(
        fixture
            .corpus
            .research()
            .call("mdn_search", json!({"query":"network"}))
            .await
            .is_err()
    );
    fixture.server.abort();
    let attempts = fixture.corpus.broker.attempt_count();
    let rebuilt = fixture
        .corpus
        .rebuild_index(CancellationToken::new())
        .await
        .expect("offline legacy-default repair");
    assert_eq!(rebuilt["snapshots"], 2);
    assert_eq!(rebuilt["network_requests"], 0);
    let selected_id = fixture
        .store
        .mdn_state("default-view")
        .await
        .unwrap()
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    let selected: View = decoded(
        fixture
            .store
            .mdn_get("views", &selected_id)
            .await
            .unwrap()
            .unwrap()
            .data,
    )
    .unwrap();
    assert_ne!(selected.id, old_view.id);
    assert_ne!(selected.content, old_view.content);
    assert_ne!(selected.compatibility, old_view.compatibility);
    assert_eq!(selected.content_observation, old_view.content_observation);
    assert_eq!(
        selected.compatibility_observation,
        old_view.compatibility_observation
    );
    assert_eq!(
        selected.validated_at, old_view.validated_at,
        "derived repair cannot renew source freshness"
    );
    assert_eq!(
        selected.id,
        inventory::digest(
            &serde_json::to_vec(&(
                &selected.content,
                &selected.compatibility,
                &selected.content_observation,
                &selected.compatibility_observation,
                selected.validated_at
            ))
            .unwrap()
        )
    );
    for (id, original) in [
        (&selected.content, &originals[0]),
        (&selected.compatibility, &originals[1]),
    ] {
        let repaired: Snapshot = decoded(
            fixture
                .store
                .mdn_get("snapshots", id)
                .await
                .unwrap()
                .unwrap()
                .data,
        )
        .unwrap();
        assert_eq!(repaired.processor_version, 2);
        assert_eq!(repaired.repository, original.repository);
        assert_eq!(repaired.revision, original.revision);
        assert_eq!(repaired.inventory, original.inventory);
        assert_eq!(repaired.coverage["rebuild_of"], original.id);
        assert_eq!(
            fixture
                .store
                .mdn_state(&format!(
                    "rebuild-alias:{}:{}:2",
                    original.repository, original.revision
                ))
                .await
                .unwrap()
                .unwrap(),
            json!(id)
        );
    }
    assert_eq!(
        fixture
            .store
            .rows
            .lock()
            .unwrap()
            .keys()
            .filter(|(kind, _)| kind == "views")
            .count(),
        2,
        "one repaired view supplements the retained old pair"
    );
    let search = fixture
        .corpus
        .research()
        .call("mdn_search", json!({"query":"network"}))
        .await
        .expect("repaired omitted-snapshot search");
    assert!(
        search["results"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["path"] == FETCH_PATH)
    );
    assert_eq!(
        fixture
            .corpus
            .research()
            .call("mdn_compat_get", json!({"feature":"api.fetch"}))
            .await
            .expect("same compatibility source")["original"]["chrome"]["version_added"],
        "42"
    );
    assert!(
        fixture
            .corpus
            .research()
            .call(
                "mdn_search",
                json!({"query":"network","snapshot":originals[0].id})
            )
            .await
            .is_err(),
        "immutable old pinned index remains broken"
    );
    assert_eq!(
        fixture
            .corpus
            .research()
            .call(
                "mdn_get",
                json!({"path":FETCH_PATH,"snapshot":originals[0].id,"representation":"source"})
            )
            .await
            .expect("retained old raw source")["page"]["text"],
        std::str::from_utf8(FETCH).unwrap()
    );
    assert_eq!(
        fixture
            .store
            .mdn_get("views", &old_view.id)
            .await
            .unwrap()
            .unwrap()
            .data,
        old_view_data
    );
    assert_eq!(
        fixture
            .store
            .mdn_get("snapshots", &originals[0].id)
            .await
            .unwrap()
            .unwrap()
            .data,
        old_snapshot_data
    );
    assert_eq!(
        std::fs::read(&damaged).unwrap(),
        b"corrupt legacy default fixture index"
    );
    // A mismatched private alias cannot swap repositories or processing
    // generations into the existing pair, even in the in-memory fixture store.
    let content_alias = format!("rebuild-alias:content:{}:2", originals[0].revision);
    fixture
        .store
        .mdn_set_state(&content_alias, &json!(selected.compatibility))
        .await
        .unwrap();
    assert_eq!(
        fixture
            .corpus
            .repair_rebuilt_default()
            .await
            .unwrap_err()
            .code,
        "integrity"
    );
    assert_eq!(
        fixture
            .store
            .mdn_state("default-view")
            .await
            .unwrap()
            .unwrap(),
        json!(selected.id)
    );
    let mut wrong_version: Snapshot = decoded(
        fixture
            .store
            .mdn_get("snapshots", &selected.content)
            .await
            .unwrap()
            .unwrap()
            .data,
    )
    .unwrap();
    wrong_version.id = inventory::digest(b"wrong-generation disposable rebuild alias");
    wrong_version.processor_version = 3;
    fixture
        .store
        .mdn_put(
            "snapshots",
            &wrong_version.id,
            &encoded(&wrong_version).unwrap(),
        )
        .await
        .unwrap();
    fixture
        .store
        .mdn_set_state(&content_alias, &json!(wrong_version.id))
        .await
        .unwrap();
    assert_eq!(
        fixture
            .corpus
            .repair_rebuilt_default()
            .await
            .unwrap_err()
            .code,
        "integrity"
    );
    assert_eq!(
        fixture
            .store
            .mdn_state("default-view")
            .await
            .unwrap()
            .unwrap(),
        json!(selected.id)
    );
    fixture
        .store
        .mdn_set_state(&content_alias, &json!(selected.content))
        .await
        .unwrap();
    assert_eq!(fixture.corpus.broker.attempt_count(), attempts);
}
