//! Read-only verification handles never initialize or repair missing retained storage.
use super::*;
use crate::{
    ChromiumConfig, ChromiumCorpus, MdnConfig, MdnCorpus, W3cConfig, W3cCorpus, WhatwgConfig,
    WhatwgCorpus,
};
use async_trait::async_trait;
use serde_json::{Value, json};

struct NoAccess;
fn denied<T>() -> Result<T> {
    Err(Error::integrity(
        "Verification constructor accessed fixture storage.",
    ))
}
#[async_trait]
impl devres_application::mdn::MdnStore for NoAccess {
    async fn mdn_cutoff(&self) -> Result<i64> {
        denied()
    }
    async fn mdn_get(
        &self,
        _kind: &str,
        _key: &str,
    ) -> Result<Option<devres_application::mdn::MdnRow>> {
        denied()
    }
    async fn mdn_put(&self, _kind: &str, _key: &str, _data: &Value) -> Result<i64> {
        denied()
    }
    async fn mdn_rows(
        &self,
        _kind: &str,
        _after: i64,
        _limit: usize,
        _cutoff: Option<i64>,
    ) -> Result<Vec<devres_application::mdn::MdnRow>> {
        denied()
    }
    async fn mdn_state(&self, _key: &str) -> Result<Option<Value>> {
        denied()
    }
    async fn mdn_set_state(&self, _key: &str, _data: &Value) -> Result<()> {
        denied()
    }
    async fn mdn_publish_view(&self, _view: &devres_application::mdn::View) -> Result<()> {
        denied()
    }
}
#[async_trait]
impl devres_application::whatwg::WhatwgStore for NoAccess {
    async fn whatwg_cutoff(&self) -> Result<i64> {
        denied()
    }
    async fn whatwg_get(
        &self,
        _kind: &str,
        _key: &str,
    ) -> Result<Option<devres_application::whatwg::Row>> {
        denied()
    }
    async fn whatwg_put(&self, _kind: &str, _key: &str, _data: &Value) -> Result<i64> {
        denied()
    }
    async fn whatwg_rows(
        &self,
        _kind: &str,
        _after: i64,
        _limit: usize,
        _cutoff: Option<i64>,
    ) -> Result<Vec<devres_application::whatwg::Row>> {
        denied()
    }
    async fn whatwg_state(&self, _key: &str) -> Result<Option<Value>> {
        denied()
    }
    async fn whatwg_set_state(&self, _key: &str, _data: &Value) -> Result<()> {
        denied()
    }
    async fn whatwg_publish_view(&self, _view: &devres_application::whatwg::View) -> Result<()> {
        denied()
    }
}
#[async_trait]
impl devres_application::w3c::W3cStore for NoAccess {
    async fn w3c_cutoff(&self) -> Result<i64> {
        denied()
    }
    async fn w3c_get(
        &self,
        _kind: &str,
        _key: &str,
    ) -> Result<Option<devres_application::w3c::Row>> {
        denied()
    }
    async fn w3c_put(&self, _kind: &str, _key: &str, _data: &Value) -> Result<i64> {
        denied()
    }
    async fn w3c_rows(
        &self,
        _kind: &str,
        _after: i64,
        _limit: usize,
        _cutoff: Option<i64>,
    ) -> Result<Vec<devres_application::w3c::Row>> {
        denied()
    }
    async fn w3c_state(&self, _key: &str) -> Result<Option<Value>> {
        denied()
    }
    async fn w3c_set_state(&self, _key: &str, _data: &Value) -> Result<()> {
        denied()
    }
    async fn w3c_publish_view(&self, _view: &devres_application::w3c::View) -> Result<()> {
        denied()
    }
}
#[async_trait]
impl devres_application::chromium::ChromiumStore for NoAccess {
    async fn chromium_cutoff(&self) -> Result<i64> {
        denied()
    }
    async fn chromium_get(
        &self,
        _kind: &str,
        _key: &str,
    ) -> Result<Option<devres_application::chromium::Row>> {
        denied()
    }
    async fn chromium_put(&self, _kind: &str, _key: &str, _data: &Value) -> Result<i64> {
        denied()
    }
    async fn chromium_rows(
        &self,
        _kind: &str,
        _after: i64,
        _limit: usize,
        _cutoff: Option<i64>,
    ) -> Result<Vec<devres_application::chromium::Row>> {
        denied()
    }
    async fn chromium_state(&self, _key: &str) -> Result<Option<Value>> {
        denied()
    }
    async fn chromium_set_state(&self, _key: &str, _data: &Value) -> Result<()> {
        denied()
    }
    async fn chromium_publish_view(
        &self,
        _view: &devres_application::chromium::View,
    ) -> Result<()> {
        denied()
    }
}
fn entries(root: &Path) -> Vec<std::ffi::OsString> {
    let mut names = std::fs::read_dir(root)
        .expect("fixture root")
        .map(|entry| entry.expect("directory entry").file_name())
        .collect::<Vec<_>>();
    names.sort();
    names
}
fn verification_corpora(root: &Path) {
    let store = Arc::new(NoAccess);
    let broker = Arc::new(BulkBroker::new(BulkConfig::default()).expect("offline broker"));
    MdnCorpus::for_verification(store.clone(), broker.clone(), root, MdnConfig::default())
        .expect("MDN handle");
    WhatwgCorpus::for_verification(store.clone(), broker.clone(), root, WhatwgConfig::default())
        .expect("WHATWG handle");
    W3cCorpus::for_verification(store.clone(), broker.clone(), root, W3cConfig::default())
        .expect("W3C handle");
    ChromiumCorpus::for_verification(store, broker, root, ChromiumConfig::default())
        .expect("Chromium handle");
    crate::npm::index::NpmIndex::for_verification(root).expect("npm handle");
}
#[test]
fn verification_constructors_preserve_empty_and_missing_layouts() {
    let root = tempfile::tempdir_in("/tmp").expect("fixture root");
    let before = entries(root.path());
    verification_corpora(root.path());
    assert_eq!(entries(root.path()), before);
    let missing = root.path().join("missing/root");
    verification_corpora(&missing);
    assert_eq!(entries(root.path()), before);
    assert!(!missing.exists());
}
#[tokio::test]
async fn missing_verification_targets_fail_without_initializing_storage() {
    let root = tempfile::tempdir_in("/tmp").expect("fixture root");
    let before = entries(root.path());
    let hash = crate::integrity::hash(b"missing retained artifact");
    let artifact = BulkArtifact {
        relative_path: crate::integrity::relative_path(&hash)
            .expect("hash path")
            .to_string_lossy()
            .into_owned(),
        body_hash: hash.clone(),
        bytes: 25,
    };
    let stop = CancellationToken::new();
    let raw = BulkArtifactStore::for_verification(root.path().join("raw"), 64 * 1024 * 1024)
        .expect("raw handle");
    assert!(raw.verify(&hash, 1024, stop.clone()).await.is_err());
    let mdn = crate::mdn::git::MdnGit::for_verification(
        root.path(),
        crate::mdn::git::Repo::Content,
        1024 * 1024,
        64 * 1024 * 1024,
    )
    .expect("MDN Git handle");
    assert!(
        mdn.verify_retained_manifest(&artifact, stop.clone())
            .await
            .is_err()
    );
    let whatwg = crate::whatwg::git::WhatwgGit::for_verification(
        root.path(),
        crate::whatwg::git::Repo::new("whatwg/html").expect("repository"),
        1024 * 1024,
        64 * 1024 * 1024,
    )
    .expect("WHATWG Git handle");
    assert!(
        whatwg
            .verify_retained_manifest(&artifact, stop.clone())
            .await
            .is_err()
    );
    let w3c = crate::w3c::git::W3cGit::for_verification(
        root.path(),
        crate::w3c::git::Repo::new("w3c/csswg-drafts").expect("repository"),
        1024 * 1024,
        64 * 1024 * 1024,
    )
    .expect("W3C Git handle");
    assert!(
        w3c.verify_retained_manifest(&artifact, stop.clone())
            .await
            .is_err()
    );
    let suffix = format!("manifests/{}.json", artifact.relative_path);
    let index = crate::mdn::index::MdnIndex::for_verification(root.path()).expect("index handle");
    let reference = json!({"digest": hash, "path": format!("mdn-indexes/{suffix}")});
    assert_eq!(
        index
            .prewarm(&reference, stop.clone())
            .await
            .expect_err("missing index")
            .code,
        "unavailable"
    );
    macro_rules! missing_provider_index {
        ($provider:ident, $ty:ident) => {{
            let index = crate::$provider::index::$ty::for_verification(root.path())
                .expect("provider index handle");
            let reference = json!({"digest": hash,
                "path": format!("{}-indexes/{suffix}", stringify!($provider))});
            assert_eq!(index.prewarm(&reference, stop.clone()).await
                .expect_err("missing provider index").code, "unavailable");
        }};
    }
    missing_provider_index!(npm, NpmIndex);
    missing_provider_index!(whatwg, WhatwgIndex);
    missing_provider_index!(w3c, W3cIndex);
    missing_provider_index!(chromium, ChromiumIndex);
    assert_eq!(entries(root.path()), before);
}
#[tokio::test]
async fn verification_handles_reject_writes_and_recovery_before_io() {
    let root = tempfile::tempdir_in("/tmp").expect("fixture root");
    let before = entries(root.path());
    let raw = BulkArtifactStore::for_verification(root.path().join("missing"), 64 * 1024 * 1024)
        .expect("raw handle");
    assert!(raw.reserve_bytes(1).is_err());
    assert!(raw.recover_stages().await.is_err());
    assert!(
        raw.capture_bytes(b"fixture".to_vec(), CancellationToken::new())
            .await
            .is_err()
    );
    assert!(raw.with_quota(None).is_err());
    let index = crate::mdn::index::MdnIndex::for_verification(root.path()).expect("index handle");
    assert!(index.recover_stages().is_err());
    assert!(
        index
            .publish(None, vec![], CancellationToken::new())
            .await
            .is_err()
    );
    assert_eq!(entries(root.path()), before);
}
#[test]
fn normal_corpus_constructors_keep_initializing_owned_layouts() {
    let root = tempfile::tempdir_in("/tmp").expect("fixture root");
    let store = Arc::new(NoAccess);
    let broker = Arc::new(BulkBroker::new(BulkConfig::default()).expect("offline broker"));
    MdnCorpus::new(
        store.clone(),
        broker.clone(),
        root.path(),
        MdnConfig::default(),
    )
    .expect("normal MDN constructor");
    WhatwgCorpus::new(
        store.clone(),
        broker.clone(),
        root.path(),
        WhatwgConfig::default(),
    )
    .expect("normal WHATWG constructor");
    W3cCorpus::new(
        store.clone(),
        broker.clone(),
        root.path(),
        W3cConfig::default(),
    )
    .expect("normal W3C constructor");
    ChromiumCorpus::new(store, broker, root.path(), ChromiumConfig::default())
        .expect("normal Chromium constructor");
    crate::npm::index::NpmIndex::new(root.path()).expect("normal npm constructor");
    for provider in ["mdn", "whatwg", "w3c", "chromium"] {
        assert!(root.path().join(provider).join("raw-artifacts").is_dir());
    }
    assert!(root.path().join("mdn/content/artifacts").is_dir());
    assert!(root.path().join("mdn/compat/artifacts").is_dir());
    for owned in [
        "mdn-indexes",
        "whatwg-search",
        "w3c-search",
        "chromium-search",
        "npm-search",
    ] {
        assert!(root.path().join(owned).is_dir());
    }
}

#[tokio::test]
async fn verification_index_reopens_cached_manifests_and_detects_missing_or_corrupt_files() {
    let _gate = crate::mdn::index::TEST_GATE.lock().await;
    let root = tempfile::tempdir_in("/tmp").expect("fixture root");
    let normal = crate::mdn::index::MdnIndex::new(root.path()).expect("normal index");
    let stop = CancellationToken::new();
    let reference = normal
        .publish(None, vec![], stop.clone())
        .await
        .expect("empty retained manifest");
    normal
        .prewarm(&reference, stop.clone())
        .await
        .expect("cache retained manifest");
    let readonly =
        crate::mdn::index::MdnIndex::for_verification(root.path()).expect("verification index");
    readonly
        .prewarm(&reference, stop.clone())
        .await
        .expect("valid retained manifest");
    let path = root
        .path()
        .join(reference["path"].as_str().expect("manifest path"));
    std::fs::remove_file(&path).expect("remove disposable fixture manifest");
    assert_eq!(
        readonly
            .prewarm(&reference, stop.clone())
            .await
            .expect_err("missing manifest cannot use cached index")
            .code,
        "unavailable"
    );
    std::fs::write(path, b"corrupt disposable fixture manifest").expect("fixture corruption");
    assert!(readonly.prewarm(&reference, stop).await.is_err());
}

#[tokio::test]
async fn verification_reads_retained_shards_without_creating_missing_tantivy_locks() {
    use std::os::unix::fs::PermissionsExt;
    let _gate = crate::mdn::index::TEST_GATE.lock().await;
    let root = tempfile::tempdir_in("/tmp").expect("fixture root");
    let normal = crate::mdn::index::MdnIndex::new(root.path()).expect("normal index");
    let stop = CancellationToken::new();
    let reference = normal
        .publish(
            None,
            vec![crate::mdn::index::IndexDocument {
                id: crate::integrity::hash(b"fixture document"),
                kind: "page".into(),
                slug: "fixture".into(),
                title: "Fixture".into(),
                path: "fixture.md".into(),
                text: "immutable fixture text".into(),
                metadata: json!({}),
            }],
            stop.clone(),
        )
        .await
        .expect("retained index");
    let original_path = root
        .path()
        .join(reference["path"].as_str().expect("manifest path"));
    let mut manifest: Value =
        serde_json::from_slice(&std::fs::read(original_path).expect("retained manifest"))
            .expect("manifest JSON");
    // Locks are coordination state. This fixture retains every data file while
    // deliberately omitting the disposable metadata lock from its manifest.
    manifest["shard"]["files"]
        .as_object_mut()
        .expect("file descriptors")
        .remove(".tantivy-meta.lock");
    let shard_id = manifest["shard"]["id"].as_str().expect("shard digest");
    let shard = root
        .path()
        .join("mdn-indexes/shards")
        .join(crate::integrity::relative_path(shard_id).expect("shard path"));
    let lock = shard.join(".tantivy-meta.lock");
    if lock.exists() {
        std::fs::remove_file(&lock).expect("remove disposable metadata lock");
    }
    let bytes = serde_json::to_vec(&manifest).expect("manifest serialization");
    let digest = crate::integrity::hash(&bytes);
    let relative = format!(
        "mdn-indexes/manifests/{}.json",
        crate::integrity::relative_path(&digest)
            .expect("manifest digest path")
            .to_string_lossy()
    );
    std::fs::write(root.path().join(&relative), bytes).expect("fixture manifest");
    let reference = json!({"digest": digest, "path": relative});
    let before = entries(&shard);
    std::fs::set_permissions(&shard, std::fs::Permissions::from_mode(0o555))
        .expect("read-only shard directory");
    let readonly =
        crate::mdn::index::MdnIndex::for_verification(root.path()).expect("verification index");
    let result = readonly.document_ids(&reference, 0, 100, stop).await;
    std::fs::set_permissions(&shard, std::fs::Permissions::from_mode(0o755))
        .expect("restore disposable fixture directory");
    let (ids, next) = result.expect("read-only retained shard verification");
    assert_eq!(ids, [crate::integrity::hash(b"fixture document")]);
    assert!(next.is_none());
    assert_eq!(entries(&shard), before);
    assert!(!lock.exists());
}
