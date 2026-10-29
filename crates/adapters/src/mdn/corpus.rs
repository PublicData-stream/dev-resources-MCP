//! Resumable MDN collection; public requests never schedule source acquisition.
use crate::{
    bulk::{BulkArtifactStore, BulkBroker},
    mdn::git::{MdnGit, Observation, Repo, TreeEntry},
    mdn::index::{IndexDocument, MdnIndex},
    mdn::inventory,
    mdn::processing::{self as mdn_processing, IncludedDocument, ProcessingBudget},
    mdn::research::MdnResearch,
};
use devres_application::mdn::{
    MdnConfig, MdnStore, MdnWrite, Member, PROCESSOR_VERSION, Snapshot, View,
};
use devres_domain::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::Arc,
    time::Duration,
};
use tokio::sync::{Mutex, Semaphore};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Serialize, Deserialize)]
struct Work {
    root: String,
    previous: Option<String>,
    offset: usize,
    changed: Vec<String>,
}
#[derive(Clone, Serialize, Deserialize)]
struct History {
    observation: Observation,
    offset: u64,
    processed: usize,
    complete: bool,
    #[serde(default)]
    processor_version: u32,
}
#[derive(Default, Serialize, Deserialize)]
struct Pending {
    snapshots: Vec<String>,
    started_at: i64,
}
pub struct MdnCorpus {
    pub store: Arc<dyn MdnStore>,
    broker: Arc<BulkBroker>,
    config: MdnConfig,
    content: Arc<MdnGit>,
    compat: Arc<MdnGit>,
    raw: Arc<BulkArtifactStore>,
    index: MdnIndex,
    research: Arc<MdnResearch>,
    processing: Mutex<()>,
    processors: Arc<Semaphore>,
}

#[path = "corpus/buffer.rs"]
mod buffer;
#[path = "corpus/migration.rs"]
pub(crate) mod migration;

#[cfg(test)]
#[path = "corpus/tests.rs"]
mod tests;
fn encoded<T: Serialize>(value: &T) -> Result<Value> {
    inventory::value(value)
}
fn decoded<T: serde::de::DeserializeOwned>(value: Value) -> Result<T> {
    inventory::decode(value)
}
#[derive(Default)]
struct EvidenceBatch {
    rows: Vec<MdnWrite>,
    bytes: usize,
}
impl EvidenceBatch {
    async fn push(&mut self, store: &dyn MdnStore, row: MdnWrite) -> Result<()> {
        let bytes = serde_json::to_vec(&row)
            .map_err(|_| Error::integrity("Invalid MDN evidence encoding."))?
            .len();
        if !self.rows.is_empty() && (self.rows.len() >= 128 || self.bytes + bytes > 8 * 1024 * 1024)
        {
            self.flush(store).await?;
        }
        self.bytes += bytes;
        self.rows.push(row);
        Ok(())
    }
    async fn flush(&mut self, store: &dyn MdnStore) -> Result<()> {
        if !self.rows.is_empty() {
            store.mdn_put_many(&self.rows).await?;
            self.rows.clear();
            self.bytes = 0;
        }
        Ok(())
    }
}
fn snapshot_key(repo: Repo, rev: &str) -> String {
    format!("{}:{rev}:{PROCESSOR_VERSION}", repo.as_str())
}
fn work_key(repo: Repo, rev: &str) -> String {
    format!("work:{}:{rev}:{PROCESSOR_VERSION}", repo.as_str())
}
fn observation_key(o: &Observation) -> String {
    inventory::digest(format!("{}:{}", o.repo.as_str(), o.manifest.body_hash).as_bytes())
}
async fn admitted_index(
    mut document: IndexDocument,
    cancel: CancellationToken,
    processors: &Arc<Semaphore>,
) -> Result<Option<IndexDocument>> {
    let permit = processors
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| Error::unavailable("MDN processor admission closed."))?;
    document.id = "0".repeat(64);
    let input = document.clone();
    let stop = cancel.clone();
    match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        MdnIndex::validate_document(&input, &stop)
    })
    .await
    .map_err(|_| Error::unavailable("MDN index validation worker failed."))?
    {
        Ok(()) => Ok(Some(document)),
        Err(error) if error.code == "cancelled" => Err(error),
        Err(_) => Ok(None),
    }
}
impl MdnCorpus {
    /// Construct frozen-graph verification handles without initializing storage.
    pub(crate) fn for_verification(
        store: Arc<dyn MdnStore>,
        broker: Arc<BulkBroker>,
        root: &Path,
        config: MdnConfig,
    ) -> Result<Self> {
        config.validate()?;
        let raw = Arc::new(BulkArtifactStore::for_verification(
            root.join("mdn/raw-artifacts"),
            config.min_free_bytes,
        )?);
        let content = Arc::new(MdnGit::for_verification(
            root,
            Repo::Content,
            config.max_git_bytes,
            config.min_free_bytes,
        )?);
        let compat = Arc::new(MdnGit::for_verification(
            root,
            Repo::Compat,
            config.max_git_bytes,
            config.min_free_bytes,
        )?);
        let research = Arc::new(MdnResearch::for_verification(store.clone(), root)?);
        let processors = Arc::new(Semaphore::new(config.max_processing_workers));
        Ok(Self {
            store,
            broker,
            config,
            content,
            compat,
            raw,
            index: MdnIndex::for_verification(root)?,
            research,
            processing: Mutex::new(()),
            processors,
        })
    }
    pub fn new(
        store: Arc<dyn MdnStore>,
        broker: Arc<BulkBroker>,
        root: &Path,
        config: MdnConfig,
    ) -> Result<Self> {
        config.validate()?;
        std::fs::create_dir_all(root.join("mdn/raw-artifacts"))
            .map_err(|_| Error::unavailable("MDN archive directory unavailable."))?;
        let raw = Arc::new(
            BulkArtifactStore::new(root.join("mdn/raw-artifacts"), config.min_free_bytes)?
                .with_quota(config.max_archive_storage_bytes)?,
        );
        let content = Arc::new(
            MdnGit::new(
                root,
                Repo::Content,
                config.max_git_bytes,
                config.min_free_bytes,
                None,
            )?
            .with_shared_budget(&raw)?,
        );
        let compat = Arc::new(
            MdnGit::new(
                root,
                Repo::Compat,
                config.max_git_bytes,
                config.min_free_bytes,
                None,
            )?
            .with_shared_budget(&raw)?,
        );
        let research = Arc::new(MdnResearch::new(store.clone(), root)?);
        let processors = Arc::new(Semaphore::new(config.max_processing_workers));
        Ok(Self {
            store,
            broker,
            config,
            content,
            compat,
            raw,
            index: MdnIndex::new(root)?,
            research,
            processing: Mutex::new(()),
            processors,
        })
    }
    pub fn research(&self) -> Arc<MdnResearch> {
        self.research.clone()
    }
    pub async fn initialize_status(&self) -> Result<()> {
        self.update_status().await
    }
    fn git(&self, repo: Repo) -> Arc<MdnGit> {
        match repo {
            Repo::Content => self.content.clone(),
            Repo::Compat => self.compat.clone(),
        }
    }
    pub async fn recover(&self, cancel: CancellationToken) -> Result<()> {
        let _guard = self.processing.lock().await;
        self.raw.recover_stages().await?;
        self.index.recover_stages()?;
        for repo in [Repo::Content, Repo::Compat] {
            if let Some(o) = self.observation(repo).await? {
                self.git(repo).restore(&o.manifest, cancel.clone()).await?;
            }
        }
        if let Some(reference) = self.store.mdn_state("index").await? {
            self.index.prewarm(&reference, cancel).await?;
        }
        Ok(())
    }
    async fn observation(&self, repo: Repo) -> Result<Option<Observation>> {
        self.store
            .mdn_state(&format!("{}-observation", repo.as_str()))
            .await?
            .map(decoded)
            .transpose()
    }
    /// Acquire one fixed ref observation. Used by serving and explicit full acceptance.
    pub async fn synchronize(&self, repo: Repo, cancel: CancellationToken) -> Result<Observation> {
        let previous = self.observation(repo).await?;
        let observation = self
            .git(repo)
            .synchronize(
                self.broker.clone(),
                previous.as_ref().map(|o| &o.manifest),
                cancel,
            )
            .await?;
        self.store
            .mdn_put(
                "observations",
                &observation_key(&observation),
                &encoded(&observation)?,
            )
            .await?;
        self.store
            .mdn_set_state(
                &format!("{}-observation", repo.as_str()),
                &encoded(&observation)?,
            )
            .await?;
        Ok(observation)
    }
    async fn snapshot(&self, repo: Repo, rev: &str) -> Result<Option<Snapshot>> {
        let key = snapshot_key(repo, rev);
        if let Some(id) = self
            .store
            .mdn_state(&format!("rebuild-alias:{key}"))
            .await?
            .and_then(|v| v.as_str().map(str::to_owned))
        {
            let row = self
                .store
                .mdn_get("snapshots", &id)
                .await?
                .ok_or_else(|| Error::integrity("Missing rebuilt MDN snapshot."))?;
            let snapshot: Snapshot = decoded(row.data)?;
            if snapshot.repository != repo.as_str() || snapshot.revision != rev {
                return Err(Error::integrity("Rebuilt MDN snapshot identity mismatch."));
            }
            return Ok(Some(snapshot));
        }
        if let Some(row) = self.store.mdn_get("snapshot-keys", &key).await? {
            let id = row
                .data
                .as_str()
                .ok_or_else(|| Error::integrity("Invalid MDN snapshot alias."))?;
            let row = self
                .store
                .mdn_get("snapshots", id)
                .await?
                .ok_or_else(|| Error::integrity("Missing MDN snapshot."))?;
            return Ok(Some(decoded(row.data)?));
        }
        self.store
            .mdn_state(&format!("prepared:{key}"))
            .await?
            .filter(|v| !v.is_null())
            .map(decoded)
            .transpose()
    }
    async fn enqueue(&self, repo: Repo, revision: &str) -> Result<()> {
        let mut pending: Pending = self
            .store
            .mdn_state("pending")
            .await?
            .map(decoded)
            .transpose()?
            .unwrap_or_default();
        let key = snapshot_key(repo, revision);
        if !pending.snapshots.contains(&key) {
            pending.snapshots.push(key);
        }
        if pending.started_at == 0 {
            pending.started_at = devres_domain::unix_now();
        }
        self.store
            .mdn_set_state("pending", &encoded(&pending)?)
            .await
    }
    async fn register_dependent(&self, dependency: &str, path: &str) -> Result<()> {
        let key = format!(
            "dependents:{}",
            crate::integrity::legacy_hash(dependency.as_bytes())
        );
        let mut paths: BTreeSet<String> = self
            .store
            .mdn_state(&key)
            .await?
            .map(decoded)
            .transpose()?
            .unwrap_or_default();
        if paths.insert(path.to_owned()) {
            if paths.len() > 100_000 {
                return Err(Error::capacity("MDN include dependency bound exceeded."));
            }
            self.store.mdn_set_state(&key, &encoded(&paths)?).await?;
        }
        Ok(())
    }
    /// A bounded slice of one commit. Publication waits for the entire tree and index.
    async fn process_commit(
        &self,
        repo: Repo,
        revision: &str,
        history: bool,
        cancel: CancellationToken,
    ) -> Result<bool> {
        if let Some(snapshot) = self.snapshot(repo, revision).await? {
            if snapshot.index.is_null() {
                self.enqueue(repo, revision).await?;
            }
            return if history {
                self.publish_changes(repo, revision, cancel).await
            } else {
                Ok(true)
            };
        }
        let mut cache = inventory::NodeCache::new();
        let git = self.git(repo);
        let commit = git.commit(revision, cancel.clone()).await?;
        let key = work_key(repo, revision);
        let mut work: Work =
            if let Some(value) = self.store.mdn_state(&key).await?.filter(|v| !v.is_null()) {
                decoded(value)?
            } else {
                let parent = match commit.parents.first() {
                    Some(rev) => self.snapshot(repo, rev).await?,
                    None => None,
                };
                Work {
                    root: match &parent {
                        Some(s) => s.inventory.clone(),
                        None => inventory::empty(self.store.as_ref()).await?,
                    },
                    previous: parent.map(|s| s.revision),
                    offset: 0,
                    changed: Vec::new(),
                }
            };
        let operation = cancel.child_token();
        let mut entries = git.records(revision, work.previous.as_deref(), operation.clone())?;
        let started = tokio::time::Instant::now();
        let mut seen = 0;
        let mut finished = true;
        while let Some(entry) = entries.recv().await {
            let entry = entry?;
            seen += 1;
            if seen <= work.offset {
                continue;
            }
            if cancel.is_cancelled() {
                operation.cancel();
                return Err(Error::unavailable("MDN processing canceled."));
            }
            let path = entry.path.clone();
            self.apply_entry(
                &mut cache,
                repo,
                revision,
                &mut work.root,
                entry,
                cancel.clone(),
            )
            .await?;
            work.changed.push(path);
            work.offset = seen;
            if work.changed.len() > 100_000 {
                operation.cancel();
                return Err(Error::capacity("MDN commit change bound exceeded."));
            }
            if seen % 100 == 0 {
                self.store.mdn_set_state(&key, &encoded(&work)?).await?;
            }
            if started.elapsed() >= Duration::from_secs(10) {
                finished = false;
                break;
            }
        }
        operation.cancel();
        drop(entries);
        self.store.mdn_set_state(&key, &encoded(&work)?).await?;
        if !finished {
            return Ok(false);
        }
        // Includes are tied to this committed tree, even if their own source is unchanged.
        if work.previous.is_some() {
            let changed: BTreeSet<_> = work.changed.iter().cloned().collect();
            let mut candidates = BTreeSet::new();
            for path in &changed {
                if let Some(reverse) = self
                    .store
                    .mdn_state(&format!(
                        "dependents:{}",
                        inventory::digest(path.as_bytes())
                    ))
                    .await?
                    && let Some(paths) = reverse.as_array()
                {
                    candidates.extend(paths.iter().filter_map(Value::as_str).map(str::to_owned));
                }
            }
            for path in candidates.difference(&changed) {
                if let Some(member) =
                    inventory::get_cached(self.store.as_ref(), &work.root, path, &mut cache).await?
                    && member.kind == "article"
                {
                    self.apply_entry(
                        &mut cache,
                        repo,
                        revision,
                        &mut work.root,
                        TreeEntry {
                            path: member.path,
                            oid: member.oid,
                            mode: member.mode,
                            kind: "blob".into(),
                            removed: false,
                            raw_path_hex: None,
                        },
                        cancel.clone(),
                    )
                    .await?;
                }
            }
        }
        let root = inventory::node_cached(self.store.as_ref(), &work.root, &mut cache).await?;
        let id = inventory::digest(
            &serde_json::to_vec(&(repo.as_str(), revision, PROCESSOR_VERSION, &work.root))
                .map_err(|_| Error::integrity("Invalid MDN snapshot identity."))?,
        );
        let snapshot = Snapshot {
            id,
            repository: repo.as_str().into(),
            revision: commit.revision.clone(),
            tree: commit.tree.clone(),
            parents: commit.parents.clone(),
            committed_at: commit.committed_at,
            inventory: work.root,
            processor_version: PROCESSOR_VERSION,
            index: Value::Null,
            coverage: json!({"accounted":true,"members":root.members,"raw_members":root.members-root.kinds.get("feature").copied().unwrap_or(0)-root.kinds.get("browser").copied().unwrap_or(0)-root.kinds.get("ambiguity").copied().unwrap_or(0),"searchable":root.searchable,"projection_gaps":root.gaps,"kinds":root.kinds}),
        };
        self.store.mdn_put("commits",&format!("{}:{revision}",repo.as_str()),&json!({"repository":repo.as_str(),"revision":revision,"tree":commit.tree,"parents":commit.parents,"committed_at":commit.committed_at})).await?;
        self.store
            .mdn_set_state(
                &format!("prepared:{}", snapshot_key(repo, revision)),
                &encoded(&snapshot)?,
            )
            .await?;
        self.enqueue(repo, revision).await?;
        self.store.mdn_set_state(&key, &Value::Null).await?;
        drop(cache);
        if history {
            self.publish_changes(repo, revision, cancel).await
        } else {
            Ok(true)
        }
    }
    async fn publish_changes(
        &self,
        repo: Repo,
        revision: &str,
        cancel: CancellationToken,
    ) -> Result<bool> {
        let done_key = snapshot_key(repo, revision);
        if self
            .store
            .mdn_get("changes-complete", &done_key)
            .await?
            .is_some()
        {
            return Ok(true);
        }
        let after = self
            .snapshot(repo, revision)
            .await?
            .ok_or_else(|| Error::integrity("Missing MDN history snapshot."))?;
        if after.parents.len() > 100 {
            return Err(Error::capacity("MDN merge parent bound exceeded."));
        }
        let parents: Vec<Option<&str>> = if after.parents.is_empty() {
            vec![None]
        } else {
            after.parents.iter().map(|s| Some(s.as_str())).collect()
        };
        let started = tokio::time::Instant::now();
        let mut cache = inventory::NodeCache::new();
        for (parent_index, parent) in parents.into_iter().enumerate() {
            let before = match parent {
                Some(p) => match self.snapshot(repo, p).await? {
                    Some(s) => Some(s),
                    None => return Ok(false),
                },
                None => None,
            };
            let checkpoint = format!("changes:{done_key}:{parent_index}");
            let saved = self
                .store
                .mdn_state(&checkpoint)
                .await?
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as usize;
            let operation = cancel.child_token();
            let mut entries = self
                .git(repo)
                .records(revision, parent, operation.clone())?;
            let mut seen = 0;
            let mut writes = EvidenceBatch::default();
            while let Some(entry) = entries.recv().await {
                let entry = entry?;
                seen += 1;
                if seen <= saved {
                    continue;
                }
                let path = &entry.path;
                let old = match &before {
                    Some(s) => {
                        inventory::get_cached(self.store.as_ref(), &s.inventory, path, &mut cache)
                            .await?
                    }
                    None => None,
                };
                let new =
                    inventory::get_cached(self.store.as_ref(), &after.inventory, path, &mut cache)
                        .await?;
                let mut paths = BTreeSet::from([path.to_owned()]);
                for member in [&old, &new]
                    .into_iter()
                    .flatten()
                    .filter(|m| m.kind == "bcd")
                {
                    if let Some(id) = &member.projection
                        && let Some(row) = self.store.mdn_get("projections", id).await?
                    {
                        for (field, prefix) in
                            [("features", "@features"), ("browsers", "@browsers")]
                        {
                            if let Some(keys) = row.data[field].as_array() {
                                for key in keys.iter().filter_map(Value::as_str) {
                                    paths.insert(format!("{prefix}/{key}"));
                                }
                            }
                        }
                    }
                }
                for path in paths {
                    let old = match &before {
                        Some(s) => {
                            inventory::get_cached(
                                self.store.as_ref(),
                                &s.inventory,
                                &path,
                                &mut cache,
                            )
                            .await?
                        }
                        None => None,
                    };
                    let new = inventory::get_cached(
                        self.store.as_ref(),
                        &after.inventory,
                        &path,
                        &mut cache,
                    )
                    .await?;
                    if old == new {
                        continue;
                    }
                    let mut slugs = BTreeSet::new();
                    for m in [&old, &new]
                        .into_iter()
                        .flatten()
                        .filter(|m| m.kind == "article")
                    {
                        if let Some(id) = &m.projection
                            && let Some(row) = self.store.mdn_get("projections", id).await?
                            && let Some(slug) = row.data["slug"].as_str()
                        {
                            slugs.insert(slug.to_owned());
                        }
                    }
                    let slug = slugs.iter().next().cloned();
                    let feature = path.strip_prefix("@features/");
                    let kind = if old.is_none() {
                        "added"
                    } else if new.is_none() {
                        "deleted"
                    } else {
                        "modified"
                    };
                    let data = json!({"repository":repo.as_str(),"revision":revision,"parent":parent,"parent_index":parent_index,"committed_at":after.committed_at,"path":path,"kind":kind,"slug":slug,"slugs":slugs,"feature":feature,"before":old,"after":new});
                    let id = inventory::digest(
                        &serde_json::to_vec(&(
                            repo.as_str(),
                            revision,
                            parent,
                            parent_index,
                            &path,
                            PROCESSOR_VERSION,
                        ))
                        .map_err(|_| Error::integrity("Invalid MDN change identity."))?,
                    );
                    writes
                        .push(
                            self.store.as_ref(),
                            MdnWrite {
                                kind: "changes".into(),
                                key: id,
                                data,
                            },
                        )
                        .await?;
                }
                if seen % 100 == 0 {
                    writes.flush(self.store.as_ref()).await?;
                    self.store.mdn_set_state(&checkpoint, &json!(seen)).await?;
                }
                if started.elapsed() >= Duration::from_secs(10) {
                    operation.cancel();
                    writes.flush(self.store.as_ref()).await?;
                    self.store.mdn_set_state(&checkpoint, &json!(seen)).await?;
                    return Ok(false);
                }
            }
            operation.cancel();
            writes.flush(self.store.as_ref()).await?;
            self.store.mdn_set_state(&checkpoint, &json!(seen)).await?;
        }
        self.store
            .mdn_put("changes-complete", &done_key, &json!(true))
            .await?;
        Ok(true)
    }
    async fn projection(
        &self,
        store: &dyn MdnStore,
        mut data: Value,
        indexed: Option<IndexDocument>,
    ) -> Result<String> {
        data["processor_version"] = json!(PROCESSOR_VERSION);
        let id = inventory::digest(
            &serde_json::to_vec(&data).map_err(|_| Error::integrity("Invalid MDN projection."))?,
        );
        let mut writes = EvidenceBatch::default();
        let mut header = serde_json::Map::new();
        // Slug lookup never needs whole article bodies/metadata. Redirects have a
        // separate bounded source member and can legitimately exceed 128 KiB.
        for key in ["slug", "redirects"] {
            if let Some(v) = data.get(key) {
                header.insert(key.into(), v.clone());
            }
        }
        let header = Value::Object(header);
        writes
            .push(
                store,
                MdnWrite {
                    kind: "projections".into(),
                    key: id.clone(),
                    data,
                },
            )
            .await?;
        writes
            .push(
                store,
                MdnWrite {
                    kind: "projection-headers".into(),
                    key: id.clone(),
                    data: header,
                },
            )
            .await?;
        if let Some(mut doc) = indexed {
            doc.id = id.clone();
            writes
                .push(
                    store,
                    MdnWrite {
                        kind: "index-documents".into(),
                        key: id.clone(),
                        data: encoded(&doc)?,
                    },
                )
                .await?;
        }
        writes.flush(store).await?;
        Ok(id)
    }
    async fn apply_entry(
        &self,
        cache: &mut inventory::NodeCache,
        repo: Repo,
        revision: &str,
        root: &mut String,
        entry: TreeEntry,
        cancel: CancellationToken,
    ) -> Result<()> {
        cache.defer_writes();
        let buffered = buffer::BufferedMdnStore::new(self.store.as_ref());
        let store: &dyn MdnStore = &buffered;
        let published_root = root;
        let mut next_root = published_root.clone();
        let root = &mut next_root;
        let path = if inventory::valid_path(&entry.path) {
            entry.path.clone()
        } else {
            format!("@unsupported/{}", inventory::digest(entry.path.as_bytes()))
        };
        // BCD synthetic members are removed along with their original source file.
        if let Some(old) = inventory::get_cached(store, root, &path, cache).await?
            && old.kind == "bcd"
            && let Some(id) = old.projection
            && let Some(row) = store.mdn_get("projections", &id).await?
        {
            for (field, prefix) in [("features", "@features"), ("browsers", "@browsers")] {
                if let Some(keys) = row.data[field].as_array() {
                    for key in keys.iter().filter_map(Value::as_str) {
                        self.update_identity(
                            store,
                            cache,
                            root,
                            &format!("{prefix}/{key}"),
                            &entry.path,
                            None,
                        )
                        .await?;
                    }
                }
            }
        }
        if entry.removed {
            *root = inventory::update_cached(store, root, &path, None, cache).await?;
            buffered.flush().await?;
            *published_root = next_root;
            return Ok(());
        }
        let git = self.git(repo);
        let regular = entry.raw_path_hex.is_none()
            && entry.kind == "blob"
            && matches!(entry.mode.as_str(), "100644" | "100755");
        let bytes = if entry.kind == "blob" {
            git.blob_size(&entry.oid, cancel.clone()).await?
        } else {
            0
        };
        let mut raw = json!({"git":true,"raw_path_hex":entry.raw_path_hex,"repository":repo.as_str(),"oid":entry.oid,"source_path":entry.path,"bytes":bytes});
        let article = repo == Repo::Content
            && entry.path.starts_with("files/en-us/")
            && (entry.path.ends_with("/index.md") || entry.path.ends_with("/index.html"));
        let bcd = repo == Repo::Compat
            && entry.path.ends_with(".json")
            && !entry.path.starts_with("node_modules/")
            && !entry.path.starts_with(".git")
            && !entry.path.starts_with("test")
            && !entry.path.starts_with("schemas/")
            && !matches!(
                entry.path.as_str(),
                "package.json" | "package-lock.json" | "tsconfig.json"
            );
        let redirects = repo == Repo::Content && entry.path == "files/en-us/_redirects.txt";
        let mut member = Member {
            path: path.clone(),
            oid: entry.oid.clone(),
            mode: entry.mode.clone(),
            kind: if article {
                "article"
            } else if bcd {
                "bcd"
            } else if redirects {
                "redirects"
            } else {
                "retained"
            }
            .into(),
            projection: None,
            raw: Some(raw.clone()),
            gaps: Vec::new(),
        };
        if !regular {
            member.kind = "unsupported-entry".into();
            member.gaps.push("unsupported_git_entry".into());
        } else if article || bcd || redirects {
            if bytes > 4 * 1024 * 1024 {
                member.gaps.push("projection_member_limit".into());
            } else {
                let body = git
                    .read_blob_known_length(&entry.oid, bytes, 4 * 1024 * 1024, cancel.clone())
                    .await?;
                let artifact = self.raw.capture_bytes(body.clone(), cancel.clone()).await?;
                raw = encoded(&artifact)?;
                raw["relative_path"] =
                    json!(format!("mdn/raw-artifacts/{}", artifact.relative_path));
                raw["source_path"] = json!(entry.path);
                member.raw = Some(raw.clone());
                if article {
                    let git = git.clone();
                    let rev = revision.to_owned();
                    let source_path = entry.path.clone();
                    let processing_cancel = cancel.clone();
                    let handle = tokio::runtime::Handle::current();
                    let attempted = Arc::new(std::sync::Mutex::new(BTreeSet::<String>::new()));
                    let attempted_worker = attempted.clone();
                    let processor = self
                        .processors
                        .clone()
                        .acquire_owned()
                        .await
                        .map_err(|_| Error::unavailable("MDN processor admission closed."))?;
                    let result = tokio::task::spawn_blocking(move || {
                        let _processor = processor;
                        let budget = ProcessingBudget::new(processing_cancel.clone());
                        let mut resolver = |requested: &str| -> Result<Option<IncludedDocument>> {
                            let candidate = if requested.starts_with("files/") {
                                requested.to_owned()
                            } else {
                                let slug = requested
                                    .trim_start_matches("/en-US/docs/")
                                    .trim_start_matches("/en-us/docs/")
                                    .trim_matches('/');
                                format!("files/en-us/{}/index.md", slug.to_lowercase())
                            };
                            if !inventory::valid_path(&candidate) {
                                return Err(Error::invalid("Invalid MDN include path."));
                            }
                            attempted_worker
                                .lock()
                                .map_err(|_| {
                                    Error::unavailable("MDN dependency tracking unavailable.")
                                })?
                                .insert(candidate.clone());
                            handle.block_on(async {
                                let Some(entry) = git
                                    .entry(&rev, &candidate, processing_cancel.clone())
                                    .await?
                                else {
                                    return Ok(None);
                                };
                                if entry.kind != "blob"
                                    || !matches!(entry.mode.as_str(), "100644" | "100755")
                                {
                                    return Ok(None);
                                }
                                let body = git
                                    .read_blob(
                                        &entry.oid,
                                        4 * 1024 * 1024,
                                        processing_cancel.clone(),
                                    )
                                    .await?;
                                Ok(Some(IncludedDocument {
                                    path: candidate,
                                    identity: entry.oid,
                                    body,
                                }))
                            })
                        };
                        mdn_processing::process_document(
                            &source_path,
                            &body,
                            &mut resolver,
                            &budget,
                        )
                    })
                    .await
                    .map_err(|_| Error::unavailable("MDN processor worker failed."))?;
                    let attempted = attempted
                        .lock()
                        .map_err(|_| Error::unavailable("MDN dependency tracking unavailable."))?
                        .clone();
                    for dependency in attempted {
                        self.register_dependent(&dependency, &path).await?;
                    }
                    match result {
                        Ok(doc) => {
                            member.gaps = doc.gaps.iter().map(|g| g.code.clone()).collect();
                            for dependency in &doc.dependencies {
                                self.register_dependent(&dependency.path, &path).await?;
                                if dependency.identity.is_empty()
                                    && let Some(base) = dependency.path.strip_suffix("index.md")
                                {
                                    self.register_dependent(&format!("{base}index.html"), &path)
                                        .await?;
                                }
                            }
                            let metadata = json!({"page_type":doc.page_type,"status":doc.status,"compatibility_key":doc.compatibility_keys,"spec_urls":doc.spec_urls});
                            let index = IndexDocument {
                                id: String::new(),
                                kind: "article".into(),
                                slug: doc.slug.clone(),
                                title: doc.title.clone(),
                                path: path.clone(),
                                text: doc.text.clone(),
                                metadata,
                            };
                            let mut data = encoded(&doc)?;
                            data["source_path"] = json!(entry.path);
                            data["processor_version"] = json!(PROCESSOR_VERSION);
                            let index =
                                admitted_index(index, cancel.clone(), &self.processors).await?;
                            if index.is_none() {
                                member.gaps.push("search_index_gap".into());
                                data["index_gap"] = json!(true);
                            }
                            match self.projection(store, data, index).await {
                                Ok(id) => member.projection = Some(id),
                                Err(error)
                                    if error.code == "capacity"
                                        && error.message
                                            == "MDN evidence row exceeds its bound." =>
                                {
                                    member.gaps.push("projection_row_limit".into())
                                }
                                Err(error) => return Err(error),
                            }
                        }
                        Err(error) if error.code == "cancelled" => return Err(error),
                        Err(error) => member.gaps.push(error.code),
                    }
                } else if bcd {
                    let p = entry.path.clone();
                    let c = cancel.clone();
                    let processor = self
                        .processors
                        .clone()
                        .acquire_owned()
                        .await
                        .map_err(|_| Error::unavailable("MDN processor admission closed."))?;
                    let result = tokio::task::spawn_blocking(move || {
                        let _processor = processor;
                        mdn_processing::process_bcd(&p, &body, &ProcessingBudget::new(c))
                    })
                    .await
                    .map_err(|_| Error::unavailable("BCD processor worker failed."))?;
                    match result {
                        Ok(doc) => {
                            let mut features = Vec::new();
                            let mut browsers = Vec::new();
                            member.gaps = doc.gaps.iter().map(|g| g.code.clone()).collect();
                            for feature in doc.features {
                                let key = feature.key.clone();
                                let synthetic = format!("@features/{key}");
                                let index = IndexDocument {
                                    id: String::new(),
                                    kind: "feature".into(),
                                    slug: key.clone(),
                                    title: feature.data["description"]
                                        .as_str()
                                        .unwrap_or(&key)
                                        .to_owned(),
                                    path: entry.path.clone(),
                                    text: format!("{key} {}", feature.data),
                                    metadata: json!({"experimental":feature.data["status"]["experimental"],"deprecated":feature.data["status"]["deprecated"],"standard_track":feature.data["status"]["standard_track"],"feature":key,"browser":feature.data["support"].as_object().map(|s|s.keys().cloned().collect::<Vec<_>>())}),
                                };
                                let index =
                                    admitted_index(index, cancel.clone(), &self.processors).await?;
                                let gap = index.is_none();
                                let id = self
                                    .projection(store, json!({"key":key,"data":feature.data,"index_gap":gap,"source_path":entry.path}), index)
                                    .await?;
                                let m = Member {
                                    path: synthetic.clone(),
                                    oid: entry.oid.clone(),
                                    mode: entry.mode.clone(),
                                    kind: "feature".into(),
                                    projection: Some(id),
                                    raw: Some(raw.clone()),
                                    gaps: if gap {
                                        vec!["search_index_gap".into()]
                                    } else {
                                        Vec::new()
                                    },
                                };
                                self.update_identity(
                                    store,
                                    cache,
                                    root,
                                    &synthetic,
                                    &entry.path,
                                    Some(m),
                                )
                                .await?;
                                features.push(key);
                            }
                            for browser in doc.browsers {
                                let key = browser.key.clone();
                                let synthetic = format!("@browsers/{key}");
                                let id = self
                                    .projection(store, json!({"key":key,"data":browser.data,"source_path":entry.path}), None)
                                    .await?;
                                self.update_identity(
                                    store,
                                    cache,
                                    root,
                                    &synthetic,
                                    &entry.path,
                                    Some(Member {
                                        path: synthetic.clone(),
                                        oid: entry.oid.clone(),
                                        mode: entry.mode.clone(),
                                        kind: "browser".into(),
                                        projection: Some(id),
                                        raw: Some(raw.clone()),
                                        gaps: Vec::new(),
                                    }),
                                )
                                .await?;
                                browsers.push(key);
                            }
                            member.projection = Some(
                                self.projection(
                                    store,
                                    json!({"features":features,"browsers":browsers}),
                                    None,
                                )
                                .await?,
                            );
                        }
                        Err(error) if error.code == "cancelled" => return Err(error),
                        Err(error) => member.gaps.push(error.code),
                    }
                } else {
                    match std::str::from_utf8(&body) {
                        Ok(text) => {
                            let mut redirects = Vec::new();
                            for line in text
                                .lines()
                                .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
                            {
                                let fields: Vec<_> = line.split_whitespace().collect();
                                if fields.len() == 2 {
                                    redirects.push(json!({"from":fields[0],"to":fields[1]}));
                                } else {
                                    member.gaps.push("invalid_redirect".into());
                                }
                            }
                            member.projection = Some(
                                self.projection(store, json!({"redirects":redirects}), None)
                                    .await?,
                            );
                        }
                        Err(_) => member.gaps.push("unsupported_encoding".into()),
                    }
                }
            }
        }
        *root = inventory::update_cached(store, root, &path, Some(member), cache).await?;
        buffered.flush().await?;
        *published_root = next_root;
        Ok(())
    }
    async fn update_identity(
        &self,
        store: &dyn MdnStore,
        cache: &mut inventory::NodeCache,
        root: &mut String,
        path: &str,
        source: &str,
        member: Option<Member>,
    ) -> Result<()> {
        let marker_path = format!("@ambiguities/{}", inventory::digest(path.as_bytes()));
        let marker = inventory::get_cached(store, root, &marker_path, cache).await?;
        let had_marker = marker.is_some();
        let mut candidates: BTreeMap<String, Member> = if let Some(marker) = marker {
            let projection = store
                .mdn_get(
                    "projections",
                    marker
                        .projection
                        .as_deref()
                        .ok_or_else(|| Error::integrity("Missing MDN ambiguity projection."))?,
                )
                .await?
                .ok_or_else(|| Error::integrity("Missing MDN ambiguity evidence."))?;
            decoded(projection.data["candidates"].clone())?
        } else {
            BTreeMap::new()
        };
        if let Some(old) = inventory::get_cached(store, root, path, cache).await? {
            let owner = old
                .raw
                .as_ref()
                .and_then(|r| r["source_path"].as_str())
                .ok_or_else(|| Error::integrity("Missing BCD identity provenance."))?
                .to_owned();
            candidates.insert(owner, old);
        }
        candidates.remove(source);
        if let Some(member) = member {
            candidates.insert(source.to_owned(), member);
        }
        if candidates.len() <= 1 {
            *root =
                inventory::update_cached(store, root, path, candidates.into_values().next(), cache)
                    .await?;
            if had_marker {
                *root = inventory::update_cached(store, root, &marker_path, None, cache).await?;
            }
        } else {
            let id = self
                .projection(
                    store,
                    json!({"identity":path,"candidates":candidates}),
                    None,
                )
                .await?;
            *root = inventory::update_cached(store, root, path, None, cache).await?;
            *root = inventory::update_cached(
                store,
                root,
                &marker_path,
                Some(Member {
                    path: marker_path.clone(),
                    oid: String::new(),
                    mode: String::new(),
                    kind: "ambiguity".into(),
                    projection: Some(id),
                    raw: None,
                    gaps: vec!["ambiguous_compatibility_identity".into()],
                }),
                cache,
            )
            .await?;
        }
        Ok(())
    }
    async fn flush(&self, cancel: CancellationToken) -> Result<()> {
        let pending: Pending = self
            .store
            .mdn_state("pending")
            .await?
            .map(decoded)
            .transpose()?
            .unwrap_or_default();
        if pending.snapshots.is_empty() {
            return self.publish_default().await;
        }
        // A manifest checkpoint is durable before either mutable cursor advances.
        if let Some(checkpoint) = self
            .store
            .mdn_state("index-checkpoint")
            .await?
            .filter(|v| !v.is_null())
        {
            let manifest = checkpoint["manifest"].clone();
            self.index.prewarm(&manifest, cancel.clone()).await?;
            self.store.mdn_set_state("index", &manifest).await?;
            self.store
                .mdn_set_state("index-sequence", &checkpoint["sequence"])
                .await?;
            self.store
                .mdn_set_state("index-checkpoint", &Value::Null)
                .await?;
        }
        let mut reference = self.store.mdn_state("index").await?;
        let mut sequence = self
            .store
            .mdn_state("index-sequence")
            .await?
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        loop {
            let mut documents = Vec::new();
            let mut bytes = 0usize;
            let mut end = sequence;
            while documents.len() < 50_000 && bytes < 32 * 1024 * 1024 {
                let rows = match self.store.mdn_rows("index-documents", end, 250, None).await {
                    Ok(rows) => rows,
                    Err(e) if e.code == "capacity" => {
                        self.store.mdn_rows("index-documents", end, 1, None).await?
                    }
                    Err(e) => return Err(e),
                };
                if rows.is_empty() {
                    break;
                }
                for row in rows {
                    bytes = bytes.saturating_add(
                        serde_json::to_vec(&row.data)
                            .map_err(|_| Error::integrity("Invalid MDN index document."))?
                            .len(),
                    );
                    documents.push(decoded(row.data)?);
                    end = row.sequence;
                    if bytes >= 32 * 1024 * 1024 || documents.len() >= 50_000 {
                        break;
                    }
                }
            }
            if documents.is_empty() && reference.is_some() {
                break;
            }
            let manifest = self
                .index
                .publish(reference.as_ref(), documents, cancel.clone())
                .await?;
            self.store
                .mdn_set_state(
                    "index-checkpoint",
                    &json!({"manifest":manifest,"sequence":end}),
                )
                .await?;
            self.store.mdn_set_state("index", &manifest).await?;
            self.store
                .mdn_set_state("index-sequence", &json!(end))
                .await?;
            self.store
                .mdn_set_state("index-checkpoint", &Value::Null)
                .await?;
            reference = Some(manifest);
            if end == sequence {
                break;
            }
            sequence = end;
        }
        let reference = reference.ok_or_else(|| Error::integrity("Missing MDN index manifest."))?;
        for key in &pending.snapshots {
            if self.store.mdn_get("snapshot-keys", key).await?.is_some() {
                continue;
            }
            let value = self
                .store
                .mdn_state(&format!("prepared:{key}"))
                .await?
                .ok_or_else(|| Error::integrity("Missing prepared MDN snapshot."))?;
            let mut snapshot: Snapshot = decoded(value)?;
            snapshot.index = reference.clone();
            if let Some(retained) = self.store.mdn_get("snapshots", &snapshot.id).await? {
                snapshot = decoded(retained.data)?;
            } else {
                self.store
                    .mdn_put("snapshots", &snapshot.id, &encoded(&snapshot)?)
                    .await?;
            }
            self.store
                .mdn_put("snapshot-keys", key, &json!(snapshot.id))
                .await?;
        }
        self.store
            .mdn_set_state("pending", &encoded(&Pending::default())?)
            .await?;
        self.publish_default().await
    }
    async fn publish_default(&self) -> Result<()> {
        let (Some(content), Some(compat)) = (
            self.observation(Repo::Content).await?,
            self.observation(Repo::Compat).await?,
        ) else {
            return Ok(());
        };
        let (Some(c), Some(b)) = (
            content.main_revision.as_deref(),
            compat.main_revision.as_deref(),
        ) else {
            return Ok(());
        };
        let (Some(c), Some(b)) = (
            self.snapshot(Repo::Content, c).await?,
            self.snapshot(Repo::Compat, b).await?,
        ) else {
            return Ok(());
        };
        if c.index.is_null() || b.index.is_null() {
            return Ok(());
        }
        let validated_at = content.observed_at.min(compat.observed_at);
        let co = observation_key(&content);
        let bo = observation_key(&compat);
        let id = inventory::digest(
            &serde_json::to_vec(&(&c.id, &b.id, &co, &bo, validated_at))
                .map_err(|_| Error::integrity("Invalid MDN view."))?,
        );
        self.store
            .mdn_publish_view(&View {
                id,
                content: c.id,
                compatibility: b.id,
                content_observation: co,
                compatibility_observation: bo,
                validated_at,
            })
            .await
    }
    pub async fn process_current(&self, cancel: CancellationToken) -> Result<bool> {
        let _guard = self.processing.lock().await;
        let mut complete = true;
        for repo in [Repo::Content, Repo::Compat] {
            if let Some(o) = self.observation(repo).await? {
                if let Some(rev) = o.main_revision {
                    complete &= self
                        .process_commit(repo, &rev, false, cancel.clone())
                        .await?;
                }
            } else {
                complete = false;
            }
        }
        let mut needs_publication = false;
        for repo in [Repo::Content, Repo::Compat] {
            if let Some(o) = self.observation(repo).await?
                && let Some(rev) = o.main_revision
            {
                needs_publication |= self
                    .snapshot(repo, &rev)
                    .await?
                    .is_some_and(|s| s.index.is_null());
            }
        }
        if needs_publication {
            self.flush(cancel).await?;
        } else {
            self.publish_default().await?;
        }
        self.update_status().await?;
        Ok(complete)
    }
    /// Repair only the already selected source pair during offline maintenance.
    /// Its observation evidence and freshness remain exactly the same.
    async fn repair_rebuilt_default(&self) -> Result<()> {
        let Some(selected) = self.store.mdn_state("default-view").await? else {
            return Ok(());
        };
        let selected = selected
            .as_str()
            .filter(|id| crate::bulk::valid_hash(id))
            .ok_or_else(|| Error::integrity("Invalid MDN default view identity."))?;
        let row = self
            .store
            .mdn_get("views", selected)
            .await?
            .ok_or_else(|| Error::integrity("Missing MDN default view."))?;
        let mut view: View = decoded(row.data)?;
        let identity = inventory::digest(
            &serde_json::to_vec(&(
                &view.content,
                &view.compatibility,
                &view.content_observation,
                &view.compatibility_observation,
                view.validated_at,
            ))
            .map_err(|_| Error::integrity("Invalid MDN default view."))?,
        );
        if view.id != selected || view.id != identity || view.validated_at <= 0 {
            return Err(Error::integrity("Invalid MDN default view identity."));
        }
        let mut repaired = Vec::with_capacity(2);
        for (id, repository) in [(&view.content, "content"), (&view.compatibility, "compat")] {
            if !crate::bulk::valid_hash(id) {
                return Err(Error::integrity("Invalid MDN default snapshot identity."));
            }
            let row = self
                .store
                .mdn_get("snapshots", id)
                .await?
                .ok_or_else(|| Error::integrity("Missing MDN default snapshot."))?;
            let original: Snapshot = decoded(row.data)?;
            if original.id != *id
                || original.repository != repository
                || original.revision.len() != 40
                || !original
                    .revision
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                || original.index.is_null()
                || original.coverage["accounted"] != true
                || original.coverage["synthetic"] == true
            {
                return Err(Error::integrity("Invalid MDN default snapshot identity."));
            }
            let key = format!(
                "rebuild-alias:{repository}:{}:{}",
                original.revision, original.processor_version
            );
            let alias =
                self.store.mdn_state(&key).await?.ok_or_else(|| {
                    Error::integrity("Missing MDN rebuilt default snapshot alias.")
                })?;
            let alias = alias
                .as_str()
                .filter(|id| crate::bulk::valid_hash(id))
                .ok_or_else(|| Error::integrity("Invalid MDN rebuilt default snapshot alias."))?;
            let row = self
                .store
                .mdn_get("snapshots", alias)
                .await?
                .ok_or_else(|| Error::integrity("Missing MDN rebuilt default snapshot."))?;
            let snapshot: Snapshot = decoded(row.data)?;
            if snapshot.id != alias
                || snapshot.repository != repository
                || snapshot.revision != original.revision
                || snapshot.processor_version != original.processor_version
                || snapshot.inventory != original.inventory
                || snapshot.index.is_null()
                || snapshot.coverage["accounted"] != true
                || snapshot.coverage["synthetic"] == true
            {
                return Err(Error::integrity(
                    "Invalid MDN rebuilt default snapshot evidence.",
                ));
            }
            repaired.push(snapshot.id);
        }
        if view.content == repaired[0] && view.compatibility == repaired[1] {
            return Ok(());
        }
        view.content = repaired.remove(0);
        view.compatibility = repaired.remove(0);
        view.id = inventory::digest(
            &serde_json::to_vec(&(
                &view.content,
                &view.compatibility,
                &view.content_observation,
                &view.compatibility_observation,
                view.validated_at,
            ))
            .map_err(|_| Error::integrity("Invalid MDN rebuilt default view."))?,
        );
        self.store.mdn_publish_view(&view).await
    }

    /// Private offline maintenance: new derived generations never replace history.
    pub async fn rebuild_index(&self, cancel: CancellationToken) -> Result<Value> {
        let _guard = self.processing.lock().await;
        let cutoff = self.store.mdn_cutoff().await?;
        let generation = format!("rebuild-{}-{cutoff}", devres_domain::unix_now());
        let mut sequence = 0;
        let mut reference = None;
        loop {
            let mut documents = Vec::new();
            let mut bytes = 0usize;
            let mut end = sequence;
            while documents.len() < 50_000 && bytes < 32 * 1024 * 1024 {
                let rows = match self
                    .store
                    .mdn_rows("index-documents", end, 250, Some(cutoff))
                    .await
                {
                    Ok(rows) => rows,
                    Err(e) if e.code == "capacity" => {
                        self.store
                            .mdn_rows("index-documents", end, 1, Some(cutoff))
                            .await?
                    }
                    Err(e) => return Err(e),
                };
                if rows.is_empty() {
                    break;
                }
                for row in rows {
                    bytes = bytes.saturating_add(
                        serde_json::to_vec(&row.data)
                            .map_err(|_| Error::integrity("Invalid MDN index evidence."))?
                            .len(),
                    );
                    documents.push(decoded(row.data)?);
                    end = row.sequence;
                    if bytes >= 32 * 1024 * 1024 || documents.len() >= 50_000 {
                        break;
                    }
                }
            }
            if documents.is_empty() && reference.is_some() {
                break;
            }
            reference = Some(
                self.index
                    .publish_generation(reference.as_ref(), documents, cancel.clone(), &generation)
                    .await?,
            );
            if sequence == end {
                break;
            }
            sequence = end;
        }
        let reference =
            reference.ok_or_else(|| Error::unavailable("No retained MDN index evidence."))?;
        self.index.prewarm(&reference, cancel.clone()).await?;
        let mut after = 0;
        let mut count = 0;
        loop {
            let rows = self
                .store
                .mdn_rows("snapshots", after, 250, Some(cutoff))
                .await?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                after = row.sequence;
                let mut snapshot: Snapshot = decoded(row.data)?;
                let key = format!(
                    "{}:{}:{}",
                    snapshot.repository, snapshot.revision, snapshot.processor_version
                );
                let selected = match self
                    .store
                    .mdn_state(&format!("rebuild-alias:{key}"))
                    .await?
                {
                    Some(id) => Some(id),
                    None => self
                        .store
                        .mdn_get("snapshot-keys", &key)
                        .await?
                        .map(|r| r.data),
                };
                if selected.as_ref().and_then(Value::as_str) != Some(snapshot.id.as_str()) {
                    continue;
                }
                let previous = snapshot.id.clone();
                snapshot.id = inventory::digest(
                    &serde_json::to_vec(&(&previous, &generation, &reference))
                        .map_err(|_| Error::integrity("Invalid MDN rebuilt identity."))?,
                );
                snapshot.index = reference.clone();
                snapshot.coverage["rebuild_of"] = json!(previous);
                snapshot.coverage["derived_generation"] = json!(generation);
                self.store
                    .mdn_put("snapshots", &snapshot.id, &encoded(&snapshot)?)
                    .await?;
                self.store
                    .mdn_set_state(
                        &format!(
                            "rebuild-alias:{}:{}:{}",
                            snapshot.repository, snapshot.revision, snapshot.processor_version
                        ),
                        &json!(snapshot.id),
                    )
                    .await?;
                count += 1;
                if cancel.is_cancelled() {
                    return Err(Error::unavailable(
                        "MDN rebuild canceled; retained history preserved.",
                    ));
                }
            }
        }
        self.store
            .mdn_set_state(
                "index-checkpoint",
                &json!({"manifest":reference,"sequence":sequence}),
            )
            .await?;
        self.store.mdn_set_state("index", &reference).await?;
        self.store
            .mdn_set_state("index-sequence", &json!(sequence))
            .await?;
        self.store
            .mdn_set_state("index-checkpoint", &Value::Null)
            .await?;
        self.repair_rebuilt_default().await?;
        self.publish_default().await?;
        self.update_status().await?;
        Ok(
            json!({"generation":generation,"snapshots":count,"index":reference,"network_requests":0}),
        )
    }
    pub async fn process_history(&self, cancel: CancellationToken) -> Result<bool> {
        let _guard = self.processing.lock().await;
        let mut all = true;
        for repo in [Repo::Content, Repo::Compat] {
            // Each source receives a bounded slice even during a large bootstrap.
            let started = tokio::time::Instant::now();
            let Some(latest) = self.observation(repo).await? else {
                all = false;
                continue;
            };
            let state_key = format!("{}-history", repo.as_str());
            let mut state: History = self
                .store
                .mdn_state(&state_key)
                .await?
                .map(decoded)
                .transpose()?
                .unwrap_or(History {
                    observation: latest.clone(),
                    offset: 0,
                    processed: 0,
                    complete: false,
                    processor_version: PROCESSOR_VERSION,
                });
            if state.processor_version != PROCESSOR_VERSION
                || (state.complete && state.observation.manifest != latest.manifest)
            {
                state = History {
                    observation: latest,
                    offset: 0,
                    processed: 0,
                    complete: false,
                    processor_version: PROCESSOR_VERSION,
                };
            }
            if state.complete {
                continue;
            }
            let page = self
                .git(repo)
                .commit_page(&state.observation, state.offset, 100, cancel.clone())
                .await?;
            // Advance only the completed prefix; retained snapshots make replay
            // idempotent after cancellation within a commit.
            let mut completed = 0;
            for commit in &page.commits {
                if !self
                    .process_commit(repo, &commit.revision, true, cancel.clone())
                    .await?
                {
                    break;
                }
                completed += 1;
                if started.elapsed() > Duration::from_secs(10) {
                    break;
                }
            }
            if completed > 0 {
                state.offset = page.offsets[completed - 1];
                state.processed += completed;
            }
            state.complete = state.offset >= state.observation.commits.bytes;
            all &= state.complete;
            self.store
                .mdn_set_state(&state_key, &encoded(&state)?)
                .await?;
        }
        let pending: Pending = self
            .store
            .mdn_state("pending")
            .await?
            .map(decoded)
            .transpose()?
            .unwrap_or_default();
        if all
            || pending.snapshots.len() >= 1000
            || devres_domain::unix_now().saturating_sub(pending.started_at)
                >= self.config.publication_interval_secs as i64
        {
            self.flush(cancel).await?;
        }
        self.update_status().await?;
        Ok(all)
    }
    async fn update_status(&self) -> Result<()> {
        let mut status = json!({"enabled":self.config.enabled,"collection_enabled":self.config.enabled,"processor_version":PROCESSOR_VERSION,"collection_scope":"advertised_heads_tags_and_reachable_ancestry","sources":{},"projection_gaps_are_explicit":true});
        for repo in [Repo::Content, Repo::Compat] {
            let history = self
                .store
                .mdn_state(&format!("{}-history", repo.as_str()))
                .await?;
            let observation = self.observation(repo).await?;
            let history=history.map(|h|json!({"observation":h["observation"]["manifest"]["body_hash"],"processed":h["processed"],"offset":h["offset"],"complete":h["complete"],"total":h["observation"]["total_commits"]}));
            let main = if let Some(revision) =
                observation.as_ref().and_then(|o| o.main_revision.as_ref())
            {
                self.snapshot(repo, revision).await?
            } else {
                None
            };
            status["sources"][repo.as_str()] = json!({"observation":observation.as_ref().map(observation_key),"validated_at":observation.as_ref().map(|o|o.observed_at),"total_commits":observation.as_ref().map(|o|o.total_commits),"history":history,"main_snapshot":main.as_ref().map(|s|&s.id),"main_coverage":main.as_ref().map(|s|&s.coverage)});
        }
        status["default_view"] = self
            .store
            .mdn_state("default-view")
            .await?
            .unwrap_or(Value::Null);
        status["failure"] = self
            .store
            .mdn_state("failure")
            .await?
            .unwrap_or(Value::Null);
        self.store.mdn_set_state("status", &status).await
    }
    async fn failure(&self, lane: &str, error: &Error) -> Result<()> {
        self.store
            .mdn_set_state(
                "failure",
                &json!({"lane":lane,"code":error.code,"at":devres_domain::unix_now()}),
            )
            .await?;
        self.update_status().await
    }
    pub async fn run_current(&self, cancel: CancellationToken) -> Result<()> {
        if let Err(error) = self.recover(cancel.clone()).await {
            if cancel.is_cancelled() {
                return Ok(());
            }
            self.failure("recovery", &error).await?;
        }
        self.update_status().await?;
        loop {
            if cancel.is_cancelled() {
                return Ok(());
            }
            if self.config.enabled {
                for repo in [Repo::Content, Repo::Compat] {
                    let now = devres_domain::unix_now();
                    let retry_key = format!("{}-retry", repo.as_str());
                    let retry = self
                        .store
                        .mdn_state(&retry_key)
                        .await?
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0);
                    if retry <= now
                        && self.observation(repo).await?.is_none_or(|o| {
                            now.saturating_sub(o.observed_at) >= self.config.ref_refresh_secs as i64
                        })
                        && let Err(error) = self.synchronize(repo, cancel.clone()).await
                    {
                        if cancel.is_cancelled() {
                            return Ok(());
                        }
                        self.failure("acquisition", &error).await?;
                        self.store
                            .mdn_set_state(&retry_key, &json!(now + 60))
                            .await?;
                    }
                }
                if let Err(error) = self.process_current(cancel.clone()).await {
                    if cancel.is_cancelled() {
                        return Ok(());
                    }
                    self.failure("current", &error).await?;
                }
            }
            tokio::select! {_ = cancel.cancelled()=>return Ok(()),_ = tokio::time::sleep(Duration::from_secs(self.config.collection_interval_secs))=>{}}
        }
    }
    pub async fn run_history(&self, cancel: CancellationToken) -> Result<()> {
        self.update_status().await?;
        loop {
            if cancel.is_cancelled() {
                return Ok(());
            }
            if self.config.enabled
                && let Err(error) = self.process_history(cancel.clone()).await
            {
                if cancel.is_cancelled() {
                    return Ok(());
                }
                self.failure("history", &error).await?;
            }
            tokio::select! {_ = cancel.cancelled()=>return Ok(()),_ = tokio::time::sleep(Duration::from_secs(self.config.collection_interval_secs))=>{}}
        }
    }
}
