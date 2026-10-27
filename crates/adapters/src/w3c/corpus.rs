//! Resumable W3C acquisition and local immutable research evidence.
use crate::{
    bulk::{self, BulkArtifact, BulkArtifactStore, BulkBroker, BulkRequest, BulkSource},
    w3c::catalog::{self as catalog, PublicationUrl},
    w3c::git::{Observation, Repo, TreeEntry, W3cGit},
    w3c::index::{IndexDocument, W3cIndex},
    w3c::inventory,
    w3c::processing as w3c_processing,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use devres_application::w3c::{
    Catalog, Member, PROCESSOR_VERSION, Snapshot, Standard, View, W3cConfig, W3cStore,
};
use devres_domain::{Error, Result, Validators};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncSeekExt},
    sync::{Mutex, Semaphore},
    time::Instant,
};
use tokio_util::sync::CancellationToken;

const MAX_SOURCE: usize = 64 * 1024 * 1024;
const MAX_PROJECTION: u64 = 256 * 1024 * 1024;
const MAX_PUBLICATIONS: usize = 100_000;
const MAX_MEMBERS: usize = 1_000_000;

mod acquisition;
mod discovery;
mod editions;
mod frozen_editions;
mod recovery;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Publication {
    id: String,
    standard: String,
    url: PublicationUrl,
    observed_at: i64,
    artifact: Option<BulkArtifact>,
    status: u16,
    links: Vec<String>,
    gaps: Vec<String>,
    #[serde(default)]
    repositories: Vec<String>,
    #[serde(default)]
    chunk_hashes: Vec<String>,
    #[serde(default)]
    metadata_version: u32,
    #[serde(default)]
    metadata_parent: Option<String>,
    #[serde(default)]
    license: Value,
    #[serde(default)]
    advertisements: Vec<catalog::PublicationAdvertisement>,
    #[serde(default)]
    exclusions: Vec<catalog::PublicationExclusion>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Frozen {
    id: String,
    catalog: Catalog,
    observations: BTreeMap<String, Observation>,
    publications: Vec<String>,
    mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    lineage: Option<recovery::Lineage>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Work {
    root: String,
    previous: Option<String>,
    offset: usize,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct FreezeWork {
    catalog: Catalog,
    observations: BTreeMap<String, Observation>,
    publications: Vec<String>,
    mode: String,
    #[serde(default)]
    metadata_policy: u32,
    standard_offset: usize,
    queue: VecDeque<(String, PublicationUrl)>,
    seen: BTreeSet<String>,
}

pub struct W3cCorpus {
    store: Arc<dyn W3cStore>,
    broker: Arc<BulkBroker>,
    root: PathBuf,
    config: W3cConfig,
    raw: Arc<BulkArtifactStore>,
    index: W3cIndex,
    processing: Mutex<()>,
    processors: Arc<Semaphore>,
}
fn failure() -> Error {
    Error::unavailable("W3C evidence unavailable.")
}
fn has_index_members(data: &Value) -> bool {
    data["index_count"].as_u64().is_some_and(|n| n > 0)
        || data["index_ids"]
            .as_array()
            .is_some_and(|ids| !ids.is_empty())
}
/// Quota ownership follows every retained artifact directory, including packs
/// captured before their observation/checkpoint was committed. Local discovery
/// registers accounting only; it never admits a repository to network acquisition.
fn register_git_artifact_budgets(
    root: &Path,
    raw: &BulkArtifactStore,
    min_free: u64,
) -> Result<()> {
    let root = root.join("w3c/git");
    if !root.try_exists().map_err(|_| failure())? {
        return Ok(());
    }
    crate::crates_io::git::real_directory(&root)?;
    let mut repositories = 0;
    let mut owners = 0;
    for owner in std::fs::read_dir(&root).map_err(|_| failure())? {
        let owner = owner.map_err(|_| failure())?;
        owners += 1;
        if owners > 4096 {
            return Err(Error::capacity(
                "W3C retained repository owner count exceeds its bound.",
            ));
        }
        if !owner.file_type().map_err(|_| failure())?.is_dir() {
            return Err(Error::integrity("Unowned W3C Git directory member."));
        }
        let owner_name = owner
            .file_name()
            .into_string()
            .map_err(|_| Error::integrity("Invalid W3C retained repository owner."))?;
        for repository in std::fs::read_dir(owner.path()).map_err(|_| failure())? {
            let repository = repository.map_err(|_| failure())?;
            repositories += 1;
            if repositories > 4096 {
                return Err(Error::capacity(
                    "W3C retained repository count exceeds its bound.",
                ));
            }
            if !repository.file_type().map_err(|_| failure())?.is_dir() {
                return Err(Error::integrity("Unowned W3C retained Git directory."));
            }
            let name = repository
                .file_name()
                .into_string()
                .map_err(|_| Error::integrity("Invalid W3C retained repository name."))?;
            if owner_name.len() != 64
                || name.len() != 64
                || !owner_name
                    .bytes()
                    .chain(name.bytes())
                    .all(|b| b.is_ascii_hexdigit())
            {
                return Err(Error::integrity(
                    "Invalid W3C retained repository storage identity.",
                ));
            }
            let marker = repository.path().join("owner-v1");
            let metadata = std::fs::symlink_metadata(&marker).map_err(|_| failure())?;
            if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 8192 {
                return Err(Error::integrity(
                    "Invalid W3C retained Git ownership marker.",
                ));
            }
            let value = std::fs::read_to_string(&marker).map_err(|_| failure())?;
            let identity = value
                .strip_prefix("devres-w3c-")
                .and_then(|s| s.strip_suffix("-v1\n"))
                .ok_or_else(|| Error::integrity("Invalid W3C retained Git ownership marker."))?;
            let repo = Repo::new(identity)?;
            if repo.owner != owner_name || repo.name != name {
                return Err(Error::integrity("W3C retained Git ownership mismatch."));
            }
            let artifacts = repository.path().join("artifacts");
            crate::crates_io::git::real_directory(&artifacts)?;
            let _registered =
                BulkArtifactStore::new(&artifacts, min_free)?.with_shared_budget(raw)?;
        }
    }
    Ok(())
}
fn encode<T: Serialize>(value: &T) -> Result<Value> {
    inventory::value(value)
}
fn decode<T: serde::de::DeserializeOwned>(value: Value) -> Result<T> {
    inventory::decode(value)
}
fn alias(standard: &str, repository: &str, revision: &str, representation: &str) -> Result<String> {
    Ok(inventory::digest(
        &serde_json::to_vec(&(
            standard,
            repository,
            revision,
            representation,
            PROCESSOR_VERSION,
        ))
        .map_err(|_| failure())?,
    ))
}
fn state_key(prefix: &str, identity: &str) -> String {
    format!("{prefix}:{}", inventory::digest(identity.as_bytes()))
}
fn cancelled(cancel: &CancellationToken) -> Result<()> {
    if cancel.is_cancelled() {
        Err(Error::new("cancelled", "W3C collection canceled."))
    } else {
        Ok(())
    }
}

/// Bound database reads without changing the ordered input of immutable shards.
struct IndexDocuments<'a> {
    store: &'a dyn W3cStore,
    ids: &'a [String],
    position: usize,
    buffered: VecDeque<Value>,
}
impl<'a> IndexDocuments<'a> {
    fn new(store: &'a dyn W3cStore, ids: &'a [String]) -> Self {
        Self {
            store,
            ids,
            position: 0,
            buffered: VecDeque::new(),
        }
    }
    async fn next_shard(
        &mut self,
        cancel: &CancellationToken,
    ) -> Result<(Vec<IndexDocument>, Vec<String>)> {
        let mut documents = Vec::new();
        let mut ids = Vec::new();
        let mut bytes = 0;
        while self.position < self.ids.len() {
            cancelled(cancel)?;
            if self.buffered.is_empty() {
                let end = self.ids.len().min(self.position + 128);
                let requested = &self.ids[self.position..end];
                let rows = self
                    .store
                    .w3c_get_many("index-documents", requested)
                    .await?;
                cancelled(cancel)?;
                let mut ordered = BTreeMap::new();
                for row in rows {
                    if !requested.contains(&row.key)
                        || row.data["id"].as_str() != Some(row.key.as_str())
                        || ordered.insert(row.key, row.data).is_some()
                    {
                        return Err(Error::integrity(
                            "W3C selected index document lookup mismatch.",
                        ));
                    }
                }
                for id in requested {
                    self.buffered.push_back(ordered.remove(id).ok_or_else(|| {
                        Error::integrity("W3C selected index document is missing.")
                    })?);
                }
            }
            let data = self.buffered.front().ok_or_else(failure)?;
            let size = serde_json::to_vec(data).map_err(|_| failure())?.len();
            if !documents.is_empty() && (documents.len() >= 5000 || bytes + size > 16 * 1024 * 1024)
            {
                break;
            }
            bytes += size;
            documents.push(decode(self.buffered.pop_front().ok_or_else(failure)?)?);
            ids.push(self.ids[self.position].clone());
            self.position += 1;
        }
        Ok((documents, ids))
    }
}
impl W3cCorpus {
    async fn publication_chunks(
        &self,
        artifact: &BulkArtifact,
        cancel: CancellationToken,
    ) -> Result<Vec<String>> {
        use sha2::{Digest, Sha256};
        let mut file = self
            .raw
            .open(
                &artifact.body_hash,
                bulk::MAX_ARTIFACT_BYTES,
                cancel.clone(),
            )
            .await?;
        let mut whole = Sha256::new();
        let mut chunks = Vec::new();
        let mut remaining = artifact.bytes;
        while remaining > 0 {
            cancelled(&cancel)?;
            let size = remaining.min(4 * 1024 * 1024) as usize;
            let mut bytes = vec![0; size];
            file.read_exact(&mut bytes).await.map_err(|_| failure())?;
            whole.update(&bytes);
            chunks.push(inventory::digest(&bytes));
            remaining -= size as u64;
        }
        if hex::encode(whole.finalize()) != artifact.body_hash {
            return Err(Error::integrity(
                "W3C raw range proof differs from retained artifact.",
            ));
        }
        Ok(chunks)
    }
    async fn publication_page(
        &self,
        artifact: &BulkArtifact,
        chunks: &[String],
        offset: u64,
        limit: usize,
    ) -> Result<Vec<u8>> {
        const BLOCK: u64 = 4 * 1024 * 1024;
        if artifact.bytes > bulk::MAX_ARTIFACT_BYTES
            || artifact.body_hash.len() != 64
            || !artifact.body_hash.bytes().all(|b| b.is_ascii_hexdigit())
            || chunks.len() as u64 != artifact.bytes.div_ceil(BLOCK)
        {
            return Err(Error::integrity("Invalid W3C raw range proof."));
        }
        let path = self.raw.root().join(&artifact.body_hash);
        let metadata = tokio::fs::symlink_metadata(&path)
            .await
            .map_err(|_| failure())?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() != artifact.bytes
        {
            return Err(Error::integrity("Invalid retained W3C raw artifact."));
        }
        let mut file = tokio::fs::File::open(path).await.map_err(|_| failure())?;
        let end = offset.saturating_add(limit as u64).min(artifact.bytes);
        let mut page = Vec::new();
        let mut position = offset;
        while position < end {
            let block = position / BLOCK;
            let start = block * BLOCK;
            let size = (artifact.bytes - start).min(BLOCK) as usize;
            let mut bytes = vec![0; size];
            file.seek(std::io::SeekFrom::Start(start))
                .await
                .map_err(|_| failure())?;
            file.read_exact(&mut bytes).await.map_err(|_| failure())?;
            if chunks.get(block as usize) != Some(&inventory::digest(&bytes)) {
                return Err(Error::integrity("W3C raw range checksum mismatch."));
            }
            let from = (position - start) as usize;
            let to = ((end - start).min(size as u64)) as usize;
            page.extend_from_slice(&bytes[from..to]);
            position = start + to as u64;
        }
        Ok(page)
    }
    async fn publish_snapshot(&self, snapshot: Snapshot, key: &str) -> Result<Snapshot> {
        let snapshot = if let Some(row) = self.store.w3c_get("snapshots", &snapshot.id).await? {
            let retained: Snapshot = decode(row.data)?;
            if retained.standard != snapshot.standard
                || retained.repository != snapshot.repository
                || retained.revision != snapshot.revision
                || retained.inventory != snapshot.inventory
                || retained.processor_version != snapshot.processor_version
            {
                return Err(Error::integrity("W3C snapshot identity collision."));
            }
            retained
        } else {
            snapshot
        };
        self.store
            .w3c_put("snapshots", &snapshot.id, &encode(&snapshot)?)
            .await?;
        if self.store.w3c_get("snapshot-keys", key).await?.is_none() {
            self.store
                .w3c_put("snapshot-keys", key, &json!(snapshot.id))
                .await?;
        }
        self.store
            .w3c_set_state(&state_key("revision-alias", key), &json!(snapshot.id))
            .await?;
        Ok(snapshot)
    }
    async fn projection_members(&self, descriptor: &Value) -> Result<Vec<String>> {
        if let Some(root) = descriptor["index_membership"].as_str() {
            return inventory::sequences(self.store.as_ref(), &[root.into()])
                .await?
                .remove(root)
                .ok_or_else(failure);
        }
        descriptor["index_ids"]
            .as_array()
            .ok_or_else(failure)?
            .iter()
            .map(|v| v.as_str().map(str::to_owned).ok_or_else(failure))
            .collect()
    }
    async fn projection_objects(
        &self,
        kind: &str,
        ids: &[String],
    ) -> Result<BTreeMap<String, Value>> {
        let ids: Vec<String> = ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let mut result = BTreeMap::new();
        let mut bytes = 0;
        for chunk in ids.chunks(500) {
            let rows = self.store.w3c_get_many(kind, chunk).await?;
            if rows.len() != chunk.len() {
                return Err(Error::integrity("W3C shared projection object is missing."));
            }
            for row in rows {
                let encoded = serde_json::to_vec(&row.data).map_err(|_| failure())?;
                bytes += encoded.len();
                if bytes as u64 > MAX_PROJECTION {
                    return Err(Error::capacity(
                        "W3C projection reconstruction exceeds its bound.",
                    ));
                }
                if inventory::digest(&encoded) != row.key {
                    return Err(Error::integrity(
                        "W3C shared projection object hash mismatch.",
                    ));
                }
                result.insert(row.key, row.data);
            }
        }
        Ok(result)
    }
    async fn reconstruct_projection(&self, descriptor: &Value) -> Result<Value> {
        let manifest = &descriptor["manifest"];
        let root = |key: &str| {
            manifest[key]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(failure)
        };
        let roots = vec![
            root("text")?,
            root("sections")?,
            root("symbols")?,
            root("references")?,
            descriptor["index_membership"]
                .as_str()
                .ok_or_else(failure)?
                .into(),
        ];
        let lists = inventory::sequences(self.store.as_ref(), &roots).await?;
        let sections = self
            .projection_objects(
                "projection-sections",
                lists.get(&roots[1]).ok_or_else(failure)?,
            )
            .await?;
        let symbols = self
            .projection_objects(
                "projection-symbols",
                lists.get(&roots[2]).ok_or_else(failure)?,
            )
            .await?;
        let references = self
            .projection_objects(
                "projection-references",
                lists.get(&roots[3]).ok_or_else(failure)?,
            )
            .await?;
        let mut text_roots = vec![roots[0].clone()];
        for object in sections.values().chain(symbols.values()) {
            text_roots.push(object["text"].as_str().ok_or_else(failure)?.into());
        }
        text_roots.sort();
        text_roots.dedup();
        let texts = inventory::sequences(self.store.as_ref(), &text_roots).await?;
        let chunks = self
            .projection_objects(
                "projection-chunks",
                &texts.values().flatten().cloned().collect::<Vec<_>>(),
            )
            .await?;
        let text = |root: &str| -> Result<String> {
            let mut text = String::new();
            for id in texts.get(root).ok_or_else(failure)? {
                let chunk = chunks.get(id).and_then(Value::as_str).ok_or_else(failure)?;
                if text.len() + chunk.len() > MAX_SOURCE {
                    return Err(Error::capacity("W3C reconstructed text exceeds its bound."));
                }
                text.push_str(chunk);
            }
            Ok(text)
        };
        let mut section_values = Vec::new();
        for id in lists.get(&roots[1]).ok_or_else(failure)? {
            let mut object = sections.get(id).ok_or_else(failure)?.clone();
            object["text"] = json!(text(object["text"].as_str().ok_or_else(failure)?)?);
            section_values.push(object);
        }
        let mut symbol_values = Vec::new();
        for id in lists.get(&roots[2]).ok_or_else(failure)? {
            let mut object = symbols.get(id).ok_or_else(failure)?.clone();
            object["text"] = json!(text(object["text"].as_str().ok_or_else(failure)?)?);
            symbol_values.push(object);
        }
        let reference_values = lists
            .get(&roots[3])
            .ok_or_else(failure)?
            .iter()
            .map(|id| references.get(id).cloned().ok_or_else(failure))
            .collect::<Result<Vec<_>>>()?;
        let value = json!({"format":manifest["format"],"title":manifest["title"],"text":text(&roots[0])?,"sections":section_values,"symbols":symbol_values,"references":reference_values,"gaps":manifest["gaps"],"index_ids":lists.get(&roots[4]).ok_or_else(failure)?});
        struct Counter(u64);
        impl std::io::Write for Counter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0 = self
                    .0
                    .checked_add(bytes.len() as u64)
                    .filter(|n| *n <= MAX_PROJECTION)
                    .ok_or_else(|| std::io::Error::other("W3C reconstruction size"))?;
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        serde_json::to_writer(Counter(0), &value)
            .map_err(|_| Error::capacity("W3C reconstructed projection exceeds its byte bound."))?;
        Ok(value)
    }
    async fn usable(&self, snapshot: &Snapshot) -> Result<bool> {
        for member in
            inventory::members(self.store.as_ref(), &snapshot.inventory, MAX_MEMBERS).await?
        {
            if member.gaps.iter().any(|g| {
                matches!(
                    g.as_str(),
                    "publication_unavailable" | "pdf_text_unavailable"
                )
            }) {
                continue;
            }
            if let Some(id) = member.projection {
                let row = self
                    .store
                    .w3c_get("projections", &id)
                    .await?
                    .ok_or_else(failure)?;
                if has_index_members(&row.data) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
    pub fn new(
        store: Arc<dyn W3cStore>,
        broker: Arc<BulkBroker>,
        root: &Path,
        config: W3cConfig,
    ) -> Result<Self> {
        config.validate()?;
        acquisition::cleanup_stale_preflights()?;
        std::fs::create_dir_all(root.join("w3c/raw-artifacts")).map_err(|_| failure())?;
        let raw = Arc::new(
            BulkArtifactStore::new(root.join("w3c/raw-artifacts"), config.min_free_bytes)?
                .with_quota(config.max_archive_storage_bytes)?,
        );
        register_git_artifact_budgets(root, raw.as_ref(), config.min_free_bytes)?;
        let index = W3cIndex::new(root)?;
        let processors = Arc::new(Semaphore::new(config.max_processing_workers));
        Ok(Self {
            store,
            broker,
            root: root.into(),
            config,
            raw,
            index,
            processing: Mutex::new(()),
            processors,
        })
    }
    pub fn store(&self) -> Arc<dyn W3cStore> {
        self.store.clone()
    }
    pub fn index(&self) -> &W3cIndex {
        &self.index
    }
    fn git(&self, repository: &str) -> Result<W3cGit> {
        W3cGit::new(
            &self.root,
            Repo::new(repository)?,
            self.config.max_git_bytes,
            self.config.min_free_bytes,
            None,
        )?
        .with_shared_budget(&self.raw)
    }
    pub async fn initialize_status(&self) -> Result<()> {
        self.update_status().await
    }
    pub async fn catalog(&self) -> Result<Catalog> {
        let id = self
            .store
            .w3c_state("catalog")
            .await?
            .and_then(|v| v.as_str().map(str::to_owned))
            .ok_or_else(failure)?;
        decode(
            self.store
                .w3c_get("catalogs", &id)
                .await?
                .ok_or_else(failure)?
                .data,
        )
    }
    pub async fn snapshot(&self, id: &str) -> Result<Snapshot> {
        let mut snapshot: Snapshot = decode(
            self.store
                .w3c_get("snapshots", id)
                .await?
                .ok_or_else(|| Error::not_found("W3C snapshot not found."))?
                .data,
        )?;
        if let Some(repair) = self
            .store
            .w3c_state(&state_key("snapshot-index", id))
            .await?
        {
            snapshot.index = repair["reference"].clone();
        }
        Ok(snapshot)
    }
    pub async fn snapshot_for_revision(
        &self,
        standard: &str,
        repository: &str,
        revision: &str,
        representation: &str,
    ) -> Result<Option<Snapshot>> {
        let key = alias(standard, repository, revision, representation)?;
        if let Some(value) = self
            .store
            .w3c_state(&state_key("revision-alias", &key))
            .await?
        {
            return Ok(Some(
                self.snapshot(value.as_str().ok_or_else(failure)?).await?,
            ));
        }
        match self.store.w3c_get("snapshot-keys", &key).await? {
            Some(row) => Ok(Some(
                self.snapshot(row.data.as_str().ok_or_else(failure)?)
                    .await?,
            )),
            None => Ok(None),
        }
    }
    pub async fn view(&self, id: Option<&str>) -> Result<View> {
        let mut view: View = match id {
            Some(id) => decode(
                self.store
                    .w3c_get("views", id)
                    .await?
                    .ok_or_else(|| Error::not_found("W3C view not found."))?
                    .data,
            )?,
            None => decode(self.store.w3c_state("default").await?.ok_or_else(failure)?)?,
        };
        if let Some(repair) = self
            .store
            .w3c_state(&state_key("view-index", &view.id))
            .await?
        {
            view.index = repair["reference"].clone();
        }
        Ok(view)
    }
    pub async fn select(
        &self,
        standard: &str,
        snapshot: Option<&str>,
        view: Option<&str>,
    ) -> Result<Snapshot> {
        if snapshot.is_some() && view.is_some() {
            return Err(Error::invalid(
                "W3C snapshot and view selectors are exclusive.",
            ));
        }
        let result =
            if let Some(id) = snapshot {
                self.snapshot(id).await?
            } else {
                let selected = self.view(view).await?;
                if view.is_none()
                    && devres_domain::unix_now().saturating_sub(
                        selected
                            .validations
                            .get(standard)
                            .copied()
                            .unwrap_or(selected.validated_at),
                    ) > 7 * 86400
                {
                    return Err(Error::unavailable(
                        "W3C default evidence is older than seven days.",
                    ));
                }
                self.snapshot(selected.snapshots.get(standard).ok_or_else(|| {
                    Error::not_found("W3C standard is not published in this view.")
                })?)
                .await?
            };
        if result.standard != standard {
            return Err(Error::invalid("W3C snapshot belongs to another standard."));
        }
        Ok(result)
    }
    pub async fn index_reference(&self, view: Option<&str>) -> Result<Value> {
        Ok(self.view(view).await?.index)
    }
    pub async fn members(
        &self,
        snapshot: &Snapshot,
        after: usize,
        limit: usize,
    ) -> Result<Vec<Member>> {
        if limit == 0 || limit > MAX_MEMBERS || after > MAX_MEMBERS {
            return Err(Error::invalid("Invalid W3C member page."));
        }
        let mut members =
            inventory::members(self.store.as_ref(), &snapshot.inventory, MAX_MEMBERS).await?;
        members.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(members.into_iter().skip(after).take(limit).collect())
    }
    pub async fn member(&self, snapshot: &Snapshot, path: &str) -> Result<Option<Member>> {
        inventory::get(self.store.as_ref(), &snapshot.inventory, path).await
    }
    pub async fn projection(&self, snapshot: &Snapshot, path: &str) -> Result<Option<Value>> {
        let Some(member) = self.member(snapshot, path).await? else {
            return Ok(None);
        };
        let Some(id) = member.projection else {
            return Ok(None);
        };
        let row = self
            .store
            .w3c_get("projections", &id)
            .await?
            .ok_or_else(failure)?;
        if row.data.get("manifest").is_some() {
            let mut value = self.reconstruct_projection(&row.data).await?;
            value["projection_id"] = json!(id);
            return Ok(Some(value));
        }
        if row.data.get("artifact").is_none() {
            return Ok(Some(row.data));
        }
        let artifact: BulkArtifact = decode(row.data["artifact"].clone())?;
        let bytes = self
            .artifact_bytes(&artifact, MAX_PROJECTION, CancellationToken::new())
            .await?;
        let mut value: Value = serde_json::from_slice(&bytes)
            .map_err(|_| Error::integrity("Malformed W3C projection."))?;
        value["index_ids"] = row.data["index_ids"].clone();
        value["projection_id"] = json!(id);
        Ok(Some(value))
    }
    pub async fn search_members(&self, snapshot: &Snapshot) -> Result<BTreeSet<String>> {
        let members =
            inventory::members(self.store.as_ref(), &snapshot.inventory, MAX_MEMBERS).await?;
        let mut ids = BTreeSet::new();
        for member in members {
            if let Some(id) = member.projection {
                let row = self
                    .store
                    .w3c_get("projections", &id)
                    .await?
                    .ok_or_else(failure)?;
                for id in self.projection_members(&row.data).await? {
                    ids.insert(id);
                    if ids.len() > MAX_MEMBERS {
                        return Err(Error::capacity(
                            "W3C selected search membership exceeds its bound.",
                        ));
                    }
                }
            }
        }
        Ok(ids)
    }
    async fn artifact_bytes(
        &self,
        artifact: &BulkArtifact,
        max: u64,
        cancel: CancellationToken,
    ) -> Result<Vec<u8>> {
        if artifact.bytes > max {
            return Err(Error::capacity("W3C artifact read exceeds its bound."));
        }
        let file = self
            .raw
            .open(&artifact.body_hash, max, cancel.clone())
            .await?;
        let mut bytes = Vec::new();
        bulk::bounded(&cancel, Instant::now() + Duration::from_secs(60), async {
            file.take(max + 1)
                .read_to_end(&mut bytes)
                .await
                .map_err(|_| failure())?;
            if bytes.len() as u64 != artifact.bytes {
                return Err(Error::integrity("W3C artifact length mismatch."));
            }
            Ok(bytes)
        })
        .await
    }
    pub async fn raw_page(
        &self,
        snapshot: &Snapshot,
        path: &str,
        offset: u64,
        limit: usize,
    ) -> Result<Value> {
        if !(1..=32768).contains(&limit) {
            return Err(Error::invalid("W3C byte limit must be 1..32768."));
        }
        let member = self
            .member(snapshot, path)
            .await?
            .ok_or_else(|| Error::not_found("W3C source member not found."))?;
        let raw = member
            .raw
            .ok_or_else(|| Error::not_found("W3C member has no raw bytes."))?;
        let (bytes, total, body_hash) = if let Some(artifact) = raw.get("artifact") {
            let artifact: BulkArtifact = decode(artifact.clone())?;
            if offset > artifact.bytes {
                return Err(Error::invalid("W3C byte offset exceeds source length."));
            }
            let bytes = if let Some(chunks) = raw.get("chunk_hashes") {
                let chunks: Vec<String> = decode(chunks.clone())?;
                self.publication_page(&artifact, &chunks, offset, limit)
                    .await?
            } else {
                let mut file = self
                    .raw
                    .open(
                        &artifact.body_hash,
                        MAX_PROJECTION,
                        CancellationToken::new(),
                    )
                    .await?;
                file.seek(std::io::SeekFrom::Start(offset))
                    .await
                    .map_err(|_| failure())?;
                let mut bytes = vec![0; limit.min((artifact.bytes - offset) as usize)];
                file.read_exact(&mut bytes).await.map_err(|_| failure())?;
                bytes
            };
            (bytes, artifact.bytes, artifact.body_hash)
        } else {
            let git = self.git(&snapshot.repository)?;
            if !git.repository().is_dir() {
                let manifest: BulkArtifact = decode(raw["manifest"].clone())?;
                git.restore(&manifest, CancellationToken::new()).await?;
            }
            let page = git
                .blob_page(&member.oid, offset, limit, CancellationToken::new())
                .await?;
            (page.bytes, page.total_bytes, page.body_hash)
        };
        let next = offset.saturating_add(bytes.len() as u64);
        Ok(
            json!({"base64":STANDARD.encode(bytes),"offset":offset,"next_offset":if next<total {Some(next)}else{None},"total_bytes":total,"body_hash":body_hash}),
        )
    }
    pub async fn recover(&self, cancel: CancellationToken) -> Result<()> {
        let _guard = self.processing.lock().await;
        self.raw.recover_stages().await?;
        self.index.recover_stages()?;
        if let Some(reference) = self.store.w3c_state("index").await? {
            self.index.prewarm(&reference, cancel.clone()).await?;
        }
        if let Ok(catalog) = self.catalog().await {
            for standard in &catalog.standards {
                cancelled(&cancel)?;
                if let Some(value) = self
                    .store
                    .w3c_state(&state_key("observation", &standard.repository))
                    .await?
                {
                    let observation: Observation = decode(value)?;
                    self.git(&standard.repository)?
                        .restore(&observation.manifest, cancel.clone())
                        .await?;
                }
            }
        }
        Ok(())
    }

    async fn project(
        &self,
        standard: &Standard,
        path: &str,
        edition: &str,
        bytes: Vec<u8>,
        cancel: CancellationToken,
    ) -> Result<(String, Vec<String>)> {
        let id = inventory::digest(
            &serde_json::to_vec(&(
                &standard.id,
                path,
                edition,
                inventory::digest(&bytes),
                PROCESSOR_VERSION,
            ))
            .map_err(|_| failure())?,
        );
        if let Some(row) = self.store.w3c_get("projections", &id).await? {
            let gaps = row.data["gaps"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            return Ok((id, gaps));
        }
        let permit = self
            .processors
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| failure())?;
        let document = if path.to_ascii_lowercase().ends_with(".pdf") {
            let _permit = permit;
            w3c_processing::process_pdf(&bytes, cancel.clone()).await?
        } else {
            let source_path = path.to_owned();
            let stop = cancel.clone();
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                w3c_processing::process_document(&source_path, &bytes, stop)
            })
            .await
            .map_err(|_| failure())??
        };
        cancelled(&cancel)?;
        let mut shared = inventory::ProjectionBatch::new(self.store.as_ref());
        let text_root = shared.text(&document.text).await?;
        let mut section_objects = Vec::new();
        for section in &document.sections {
            let text = shared.text(&section.text).await?;
            section_objects.push(
                shared
                    .put(
                        "projection-sections",
                        json!({"anchor":section.anchor,"title":section.title,"text":text}),
                    )
                    .await?,
            );
        }
        let sections_root = shared.sequence(&section_objects).await?;
        let mut symbol_objects = Vec::new();
        for symbol in &document.symbols {
            let text = shared.text(&symbol.text).await?;
            symbol_objects.push(shared.put("projection-symbols",json!({"kind":symbol.kind,"name":symbol.name,"anchor":symbol.anchor,"scope":symbol.scope,"text":text})).await?);
        }
        let symbols_root = shared.sequence(&symbol_objects).await?;
        let mut reference_objects = Vec::new();
        for reference in &document.references {
            reference_objects.push(
                shared
                    .put("projection-references", encode(reference)?)
                    .await?,
            );
        }
        let references_root = shared.sequence(&reference_objects).await?;
        let manifest = json!({"format":document.format,"title":document.title,"text":text_root,"sections":sections_root,"symbols":symbols_root,"references":references_root,"gaps":document.gaps});
        let mut index_ids = Vec::new();
        let mut gaps: Vec<String> = document.gaps.iter().map(|g| g.code.clone()).collect();
        for section in &document.sections {
            for (chunk, text) in text_chunks(&section.text, 32768).into_iter().enumerate() {
                let document_id = inventory::digest(
                    &serde_json::to_vec(&(
                        &standard.id,
                        path,
                        edition,
                        "section",
                        &section.anchor,
                        &section.title,
                        text,
                        chunk,
                        PROCESSOR_VERSION,
                    ))
                    .map_err(|_| failure())?,
                );
                let index_document = IndexDocument {
                    id: document_id.clone(),
                    standard: standard.id.clone(),
                    edition: edition.into(),
                    path: path.into(),
                    title: section.title.clone(),
                    text: text.into(),
                    kind: "section".into(),
                    metadata: json!({"anchor":section.anchor,"chunk":chunk}),
                };
                match W3cIndex::validate_document(&index_document, &cancel) {
                    Ok(()) => {
                        shared
                            .put_id("index-documents", &document_id, encode(&index_document)?)
                            .await?;
                        index_ids.push(document_id);
                    }
                    Err(error) if error.code == "cancelled" => return Err(error),
                    Err(_) => {
                        gaps.push("index_document_rejected".into());
                    }
                }
            }
        }
        if document.sections.is_empty() {
            for (chunk, text) in text_chunks(&document.text, 32768).into_iter().enumerate() {
                let document_id = inventory::digest(
                    &serde_json::to_vec(&(
                        &standard.id,
                        path,
                        edition,
                        "text",
                        &document.title,
                        text,
                        chunk,
                        PROCESSOR_VERSION,
                    ))
                    .map_err(|_| failure())?,
                );
                let index_document = IndexDocument {
                    id: document_id.clone(),
                    standard: standard.id.clone(),
                    edition: edition.into(),
                    path: path.into(),
                    title: document.title.clone(),
                    text: text.into(),
                    kind: "section".into(),
                    metadata: json!({"anchor":"","chunk":chunk}),
                };
                match W3cIndex::validate_document(&index_document, &cancel) {
                    Ok(()) => {
                        shared
                            .put_id("index-documents", &document_id, encode(&index_document)?)
                            .await?;
                        index_ids.push(document_id);
                    }
                    Err(error) if error.code == "cancelled" => return Err(error),
                    Err(_) => {
                        gaps.push("index_document_rejected".into());
                    }
                }
            }
        }
        for symbol in &document.symbols {
            for (chunk, text) in text_chunks(&symbol.text, 32768).into_iter().enumerate() {
                let document_id = inventory::digest(
                    &serde_json::to_vec(&(
                        &standard.id,
                        path,
                        edition,
                        "symbol",
                        &symbol.kind,
                        &symbol.name,
                        &symbol.scope,
                        &symbol.anchor,
                        text,
                        chunk,
                        PROCESSOR_VERSION,
                    ))
                    .map_err(|_| failure())?,
                );
                let index_document = IndexDocument {
                    id: document_id.clone(),
                    standard: standard.id.clone(),
                    edition: edition.into(),
                    path: path.into(),
                    title: symbol.name.clone(),
                    text: text.into(),
                    kind: "symbol".into(),
                    metadata: json!({"anchor":symbol.anchor,"symbol_kind":symbol.kind,"name":symbol.name,"scope":symbol.scope,"chunk":chunk}),
                };
                match W3cIndex::validate_document(&index_document, &cancel) {
                    Ok(()) => {
                        shared
                            .put_id("index-documents", &document_id, encode(&index_document)?)
                            .await?;
                        index_ids.push(document_id);
                    }
                    Err(error) if error.code == "cancelled" => return Err(error),
                    Err(_) => {
                        gaps.push("index_document_rejected".into());
                    }
                }
            }
        }
        if index_ids.len() > MAX_MEMBERS {
            return Err(Error::capacity(
                "W3C projection search membership exceeds its bound.",
            ));
        }
        gaps.sort();
        gaps.dedup();
        let index_membership = shared.sequence(&index_ids).await?;
        shared.flush().await?;
        self.store.w3c_put("projections",&id,&json!({"manifest":manifest,"index_membership":index_membership,"index_count":index_ids.len(),"gaps":gaps,"format":document.format,"title":document.title,"sections":document.sections.len(),"symbols":document.symbols.len(),"references":document.references.len()})).await?;
        Ok((id, gaps))
    }
    async fn finish_index_checkpoint(
        &self,
        checkpoint: &Value,
        cancel: CancellationToken,
    ) -> Result<()> {
        self.index.prewarm(&checkpoint["reference"], cancel).await?;
        let generation = checkpoint["generation"].as_u64().ok_or_else(failure)?;
        let ids: Vec<String> = decode(checkpoint["ids"].clone())?;
        for chunk in ids.chunks(500) {
            let rows: Vec<devres_application::w3c::Write> = chunk
                .iter()
                .map(|id| devres_application::w3c::Write {
                    kind: "indexed-membership".into(),
                    key: inventory::digest(format!("{generation}:{id}").as_bytes()),
                    data: json!({"generation":generation,"id":id}),
                })
                .collect();
            self.store.w3c_put_many(&rows).await?;
        }
        self.store.w3c_set_state("index-context",&json!({"generation":generation,"count":checkpoint["count"],"reference":checkpoint["reference"]})).await?;
        self.store
            .w3c_set_state("index", &checkpoint["reference"])
            .await?;
        self.store
            .w3c_set_state("index-checkpoint", &Value::Null)
            .await
    }
    async fn root_members(&self, root: &str) -> Result<BTreeSet<String>> {
        let mut result = BTreeSet::new();
        for member in inventory::members(self.store.as_ref(), root, MAX_MEMBERS).await? {
            if let Some(id) = member.projection {
                let row = self
                    .store
                    .w3c_get("projections", &id)
                    .await?
                    .ok_or_else(failure)?;
                for id in self.projection_members(&row.data).await? {
                    result.insert(id);
                    if result.len() > MAX_MEMBERS {
                        return Err(Error::capacity(
                            "W3C index generation membership exceeds its bound.",
                        ));
                    }
                }
            }
        }
        Ok(result)
    }
    /// New generations contain every requested root and current-view member. Old
    /// manifests remain immutable; previously indexed IDs are explicitly reintroduced.
    async fn flush_index(&self, roots: &[String], cancel: CancellationToken) -> Result<Value> {
        if let Some(checkpoint) = self
            .store
            .w3c_state("index-checkpoint")
            .await?
            .filter(|v| !v.is_null())
        {
            self.finish_index_checkpoint(&checkpoint, cancel.clone())
                .await?;
        }
        let mut required = BTreeSet::new();
        let mut roots: BTreeSet<String> = roots.iter().cloned().collect();
        if let Ok(view) = self.view(None).await {
            for id in view.snapshots.values() {
                roots.insert(self.snapshot(id).await?.inventory);
            }
        }
        for root in roots {
            required.extend(self.root_members(&root).await?);
            if required.len() > MAX_MEMBERS {
                return Err(Error::capacity(
                    "W3C active index membership exceeds its bound.",
                ));
            }
        }
        let context = self
            .store
            .w3c_state("index-context")
            .await?
            .unwrap_or_else(|| json!({"generation":0,"count":0,"reference":null}));
        let mut generation = context["generation"].as_u64().ok_or_else(failure)?;
        let mut count = context["count"].as_u64().ok_or_else(failure)?;
        let mut reference = if context["reference"].is_null() {
            None
        } else {
            Some(context["reference"].clone())
        };
        if count >= 2048 {
            generation = generation
                .checked_add(1)
                .ok_or_else(|| Error::capacity("W3C index generation exhausted."))?;
            count = 0;
            reference = None;
            self.store
                .w3c_set_state(
                    "index-context",
                    &json!({"generation":generation,"count":count,"reference":null}),
                )
                .await?;
        }
        let mut missing = Vec::new();
        let required: Vec<String> = required.into_iter().collect();
        for chunk in required.chunks(1000) {
            cancelled(&cancel)?;
            let keys: Vec<String> = chunk
                .iter()
                .map(|id| inventory::digest(format!("{generation}:{id}").as_bytes()))
                .collect();
            let retained = self.store.w3c_existing("indexed-membership", &keys).await?;
            for (id, key) in chunk.iter().zip(keys) {
                if !retained.contains(&key) {
                    missing.push(id.clone());
                }
            }
        }
        let mut pending = IndexDocuments::new(self.store.as_ref(), &missing);
        while pending.position < missing.len() || reference.is_none() {
            cancelled(&cancel)?;
            if count >= 4090 {
                return Err(Error::capacity(
                    "W3C active index requires too many immutable shards.",
                ));
            }
            let (documents, ids) = pending.next_shard(&cancel).await?;
            let published = self
                .index
                .publish_generation(
                    reference.as_ref(),
                    documents,
                    cancel.clone(),
                    &format!("w3c-generation-{generation}"),
                )
                .await?;
            count += 1;
            let checkpoint =
                json!({"reference":published,"generation":generation,"count":count,"ids":ids});
            self.store
                .w3c_set_state("index-checkpoint", &checkpoint)
                .await?;
            self.finish_index_checkpoint(&checkpoint, cancel.clone())
                .await?;
            reference = Some(published);
        }
        reference.ok_or_else(failure)
    }
    async fn process_entry(
        &self,
        standard: &Standard,
        observation: &Observation,
        entry: TreeEntry,
        root: &str,
        cache: &mut inventory::NodeCache,
        cancel: CancellationToken,
    ) -> Result<String> {
        if entry.removed {
            return inventory::update_cached(self.store.as_ref(), root, &entry.path, None, cache)
                .await;
        }
        let git = self.git(&standard.repository)?;
        let mut member = Member {
            path: entry.path.clone(),
            oid: entry.oid.clone(),
            mode: entry.mode.clone(),
            kind: entry.kind.clone(),
            projection: None,
            raw: None,
            gaps: Vec::new(),
        };
        if entry.kind == "blob" && entry.mode != "120000" {
            let length = git.blob_size(&entry.oid, cancel.clone()).await?;
            member.raw = Some(
                json!({"repository":standard.repository,"oid":entry.oid,"bytes":length,"manifest":observation.manifest,"license":standard.metadata["repository_license"]}),
            );
            if supported_path(&entry.path) {
                if length > MAX_SOURCE as u64 {
                    member.gaps.push("projection_input_limit".into());
                } else {
                    let bytes = git
                        .read_blob_known_length(&entry.oid, length, MAX_SOURCE, cancel.clone())
                        .await?;
                    let file_notices = String::from_utf8_lossy(&bytes[..bytes.len().min(32768)])
                        .lines()
                        .filter(|line| {
                            line.contains("Copyright")
                                || line.contains('©')
                                || line.contains("SPDX-License-Identifier:")
                        })
                        .take(32)
                        .map(str::to_owned)
                        .collect::<Vec<_>>()
                        .join("\n");
                    if file_notices.len() > 8192 {
                        return Err(Error::capacity("W3C file notice metadata exceeds bounds."));
                    }
                    if !file_notices.is_empty()
                        && let Some(raw) = member.raw.as_mut()
                    {
                        raw["license"]["file_notice"] = json!(file_notices);
                    }
                    match self
                        .project(standard, &entry.path, "source", bytes, cancel.clone())
                        .await
                    {
                        Ok((id, gaps)) => {
                            let searchable = self
                                .store
                                .w3c_get("projections", &id)
                                .await?
                                .is_some_and(|row| has_index_members(&row.data));
                            if let Some(raw) = member.raw.as_mut() {
                                raw["searchable"] = json!(searchable);
                            }
                            member.projection = Some(id);
                            member.gaps = gaps;
                        }
                        Err(error) if cancel.is_cancelled() || error.code == "cancelled" => {
                            return Err(error);
                        }
                        Err(error)
                            if matches!(
                                error.code.as_str(),
                                "capacity" | "integrity" | "invalid_input"
                            ) =>
                        {
                            member.gaps.push(format!("projection_{}", error.code))
                        }
                        Err(error) => return Err(error),
                    }
                }
            } else {
                member.gaps.push("raw_only_source_format".into());
            }
        } else {
            member.gaps.push(
                if entry.mode == "120000" {
                    "symlink_not_followed"
                } else {
                    "git_member_not_executable"
                }
                .into(),
            );
        }
        if entry.raw_path_hex.is_some() {
            member.gaps.push("unsupported_path_encoding".into());
        }
        inventory::update_cached(self.store.as_ref(), root, &entry.path, Some(member), cache).await
    }
    async fn process_commit(
        &self,
        standard: &Standard,
        observation: &Observation,
        revision: &str,
        cancel: CancellationToken,
    ) -> Result<bool> {
        if let Some(snapshot) = self
            .snapshot_for_revision(&standard.id, &standard.repository, revision, "source")
            .await?
        {
            let old = &snapshot.coverage["source_mapping"];
            let old_mapping = old.get("mapping").unwrap_or(old);
            if old_mapping["kind"] != "unresolved"
                && old_mapping["prefix"] == standard.metadata["source_mapping"]["prefix"]
            {
                return Ok(true);
            }
        }
        if standard.metadata["repository_license"]["decision"] != "approved" {
            return Err(Error::unavailable(
                "W3C source projection requires qualified license and mapping evidence.",
            ));
        }
        let git = self.git(&standard.repository)?;
        let mut scoped = self
            .revision_mapping(standard, observation, revision, cancel.clone())
            .await?;
        if scoped.metadata["source_mapping"]["kind"] != "unresolved" {
            scoped.metadata["repository_license"] = self
                .revision_license(&scoped, revision, cancel.clone())
                .await?;
        }
        let standard = &scoped;
        let commit = git.commit(revision, cancel.clone()).await?;
        if standard.metadata["source_mapping"]["kind"] == "unresolved" {
            let root = inventory::empty(self.store.as_ref()).await?;
            let id = inventory::digest(
                &serde_json::to_vec(&(
                    &standard.id,
                    &standard.repository,
                    revision,
                    &root,
                    PROCESSOR_VERSION,
                ))
                .map_err(|_| failure())?,
            );
            let snapshot = Snapshot {
                id,
                standard: standard.id.clone(),
                repository: standard.repository.clone(),
                revision: revision.into(),
                tree: commit.tree,
                parents: commit.parents,
                committed_at: commit.committed_at,
                inventory: root,
                processor_version: PROCESSOR_VERSION,
                index: Value::Null,
                coverage: json!({"accounted":true,"usable":false,"members":0,"searchable":0,"projection_gaps":1,"index_gaps":0,"gaps":["source_mapping_unresolved_at_revision"],"edition":"source","observation":observation.manifest.body_hash,"license":standard.metadata["repository_license"],"source_mapping":standard.metadata["source_mapping"]}),
                source_url: git_source_url(&standard.repository, revision),
                representation: "source".into(),
                validated_at: observation.observed_at,
            };
            self.publish_snapshot(
                snapshot,
                &alias(&standard.id, &standard.repository, revision, "source")?,
            )
            .await?;
            return Ok(true);
        }
        let key = state_key(
            "work",
            &format!(
                "{}:{}:{revision}:{PROCESSOR_VERSION}",
                standard.id,
                inventory::digest(
                    &serde_json::to_vec(&standard.metadata["source_mapping"])
                        .map_err(|_| failure())?
                )
            ),
        );
        let mut work: Work =
            if let Some(value) = self.store.w3c_state(&key).await?.filter(|v| !v.is_null()) {
                decode(value)?
            } else {
                let parent = if let Some(parent) = commit.parents.first() {
                    self.snapshot_for_revision(&standard.id, &standard.repository, parent, "source")
                        .await?
                        .filter(|snapshot| {
                            snapshot.coverage["source_mapping"]["mapping"]["prefix"]
                                == standard.metadata["source_mapping"]["prefix"]
                                && snapshot.coverage["source_mapping"]["mapping"]["kind"]
                                    != "unresolved"
                        })
                } else {
                    None
                };
                Work {
                    root: if let Some(parent) = &parent {
                        parent.inventory.clone()
                    } else {
                        inventory::empty(self.store.as_ref()).await?
                    },
                    previous: parent.map(|s| s.revision),
                    offset: 0,
                }
            };
        let stop = cancel.child_token();
        let mut entries = git.records(revision, work.previous.as_deref(), stop.clone())?;
        let started = Instant::now();
        let mut seen = 0;
        let mut complete = true;
        let mut cache = inventory::NodeCache::new();
        while let Some(entry) = entries.recv().await {
            let entry = entry?;
            seen += 1;
            if seen <= work.offset {
                continue;
            }
            cancelled(&cancel)?;
            if !source_path_selected(standard, &entry.path) {
                work.offset = seen;
                continue;
            }
            work.root = self
                .process_entry(
                    standard,
                    observation,
                    entry,
                    &work.root,
                    &mut cache,
                    cancel.clone(),
                )
                .await?;
            work.offset = seen;
            if seen % 50 == 0 {
                self.store.w3c_set_state(&key, &encode(&work)?).await?;
            }
            if started.elapsed() >= Duration::from_secs(10) {
                complete = false;
                break;
            }
        }
        stop.cancel();
        drop(entries);
        self.store.w3c_set_state(&key, &encode(&work)?).await?;
        if !complete {
            return Ok(false);
        }
        let node = inventory::node_cached(self.store.as_ref(), &work.root, &mut cache).await?;
        let members = inventory::members(self.store.as_ref(), &work.root, MAX_MEMBERS).await?;
        let index_gaps = members
            .iter()
            .filter(|m| m.gaps.iter().any(|g| g.starts_with("index_")))
            .count();
        let index = self
            .flush_index(std::slice::from_ref(&work.root), cancel.clone())
            .await?;
        let id = inventory::digest(
            &serde_json::to_vec(&(
                &standard.id,
                &standard.repository,
                revision,
                &work.root,
                PROCESSOR_VERSION,
            ))
            .map_err(|_| failure())?,
        );
        let mut source_license = standard.metadata["repository_license"].clone();
        if let Some(notices) = source_license["notices"].as_array_mut() {
            for notice in notices {
                notice["source_selector"] = json!({"tool":"w3c_get","specification":standard.id,"snapshot":id,"path":notice["path"],"representation":"source"});
                if let Some(path) = notice["path"].as_str() {
                    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
                    notice["notice_resource"] = json!(format!(
                        "devres://w3c/{}/{}/source/{}",
                        standard.id,
                        id,
                        URL_SAFE_NO_PAD.encode(path.as_bytes())
                    ));
                }
            }
        }
        let snapshot = Snapshot {
            id: id.clone(),
            standard: standard.id.clone(),
            repository: standard.repository.clone(),
            revision: revision.into(),
            tree: commit.tree,
            parents: commit.parents,
            committed_at: commit.committed_at,
            inventory: work.root,
            processor_version: PROCESSOR_VERSION,
            index,
            coverage: json!({"accounted":true,"usable":node.searchable>0,"members":node.members,"searchable":node.searchable,"projection_gaps":node.gaps,"index_gaps":index_gaps,"kinds":node.kinds,"edition":"source","rendering_gap":"historical_source_is_not_a_rendered_publication","observation":observation.manifest.body_hash,"license":source_license,"source_mapping":{"mapping":standard.metadata["source_mapping"],"revision":revision,"scope":"captured_source_path_at_revision"}}),
            source_url: git_source_url(&standard.repository, revision),
            representation: "source".into(),
            validated_at: observation.observed_at,
        };
        self.publish_snapshot(
            snapshot,
            &alias(&standard.id, &standard.repository, revision, "source")?,
        )
        .await?;
        self.store.w3c_set_state(&key, &Value::Null).await?;
        Ok(true)
    }

    async fn capture_publication(
        &self,
        standard: &Standard,
        url: PublicationUrl,
        cancel: CancellationToken,
    ) -> Result<Publication> {
        self.capture_publication_inner(standard, url, cancel, true)
            .await
    }
    /// Reinterpret retained bytes; no source request or validation timestamp changes.
    async fn repair_publication_metadata(
        &self,
        old: &Publication,
        cancel: CancellationToken,
    ) -> Result<Publication> {
        self.repair_publication_metadata_inner(old, cancel, true)
            .await
    }
    async fn repair_publication_metadata_inner(
        &self,
        old: &Publication,
        cancel: CancellationToken,
        publish_head: bool,
    ) -> Result<Publication> {
        let mut repaired = old.clone();
        repaired.metadata_version = catalog::METADATA_VERSION;
        repaired.metadata_parent = Some(old.id.clone());
        repaired
            .gaps
            .retain(|gap| !gap.starts_with("publication_metadata_"));
        let artifact = old.artifact.as_ref().ok_or_else(|| {
            Error::integrity("W3C metadata repair requires retained source bytes.")
        })?;
        if old.url.kind() != catalog::PublicationKind::Html {
            repaired.links.clear();
            repaired.repositories.clear();
            repaired.advertisements.clear();
            repaired.exclusions.clear();
        } else if artifact.bytes > MAX_SOURCE as u64 {
            repaired
                .gaps
                .push("publication_metadata_input_limit".into());
        } else {
            let bytes = self
                .artifact_bytes(artifact, MAX_SOURCE as u64, cancel.clone())
                .await?;
            let stop = cancel.clone();
            match tokio::task::spawn_blocking(move || catalog::publication_metadata(&bytes, &stop))
                .await
                .map_err(|_| failure())?
            {
                Ok(metadata) => {
                    repaired.links = metadata.links;
                    repaired.repositories = metadata.repositories;
                    repaired.advertisements = metadata.advertisements;
                    repaired.exclusions = metadata.exclusions;
                }
                Err(error) if error.code == "cancelled" => return Err(error),
                Err(error) => {
                    repaired.links.clear();
                    repaired.repositories.clear();
                    repaired.advertisements.clear();
                    repaired.exclusions.clear();
                    repaired
                        .gaps
                        .push(format!("publication_metadata_{}", error.code));
                }
            }
        }
        if repaired.chunk_hashes.is_empty() && artifact.bytes > 0 {
            repaired.chunk_hashes = self.publication_chunks(artifact, cancel).await?;
        }
        repaired.id = inventory::digest(
            &serde_json::to_vec(&(
                &old.id,
                catalog::METADATA_VERSION,
                &repaired.links,
                &repaired.repositories,
                &repaired.advertisements,
                &repaired.exclusions,
                &repaired.gaps,
            ))
            .map_err(|_| failure())?,
        );
        self.store
            .w3c_put("publications", &repaired.id, &encode(&repaired)?)
            .await?;
        if publish_head {
            self.store
                .w3c_set_state(
                    &state_key("publication", repaired.url.as_str()),
                    &json!(repaired.id),
                )
                .await?;
        }
        Ok(repaired)
    }
    fn resolved_standard(&self, standard: &Standard, publication: &Publication) -> Standard {
        let mut resolved = standard.clone();
        let mut mappings = BTreeMap::new();
        for source in &publication.repositories {
            if let Ok((repo, mapping)) = catalog::repository_mapping(source) {
                mappings.insert(repo.as_str(), mapping);
            }
        }
        if mappings.len() == 1
            && let Some((repository, mapping)) = mappings.into_iter().next()
        {
            resolved.repository = repository;
            resolved.metadata["source_mapping"] = mapping;
            resolved.metadata["repository_policy"] = json!("official_publication_header_metadata");
            resolved.metadata["repository_admission"] = json!({"publication":publication.id,"url":publication.url.as_str(),"repository":resolved.repository});
        } else if publication.repositories.len() > 1 {
            resolved.metadata["repository_gap"] =
                json!("ambiguous_publication_source_repositories");
        }
        if let Err(error) = crate::w3c::discovery::apply_mapping_hint(&mut resolved) {
            resolved.metadata["mapping_enrichment_gap"] =
                json!({"code":error.code,"reason":"descriptor_mapping_unavailable"});
        }
        resolved
    }
    async fn retain_resolved_catalog(&self, mut catalog: Catalog) -> Result<Catalog> {
        let original = catalog.id.clone();
        catalog.id = inventory::digest(
            &serde_json::to_vec(&(&catalog.standards, &catalog.gaps, catalog.observed_at))
                .map_err(|_| failure())?,
        );
        self.store
            .w3c_put("catalogs", &catalog.id, &encode(&catalog)?)
            .await?;
        if let Some(row) = self.store.w3c_get("catalog-captures", &original).await? {
            self.store
                .w3c_put("catalog-captures", &catalog.id, &row.data)
                .await?;
        }
        self.store
            .w3c_set_state("catalog", &json!(catalog.id))
            .await?;
        Ok(catalog)
    }
    async fn process_publication(
        &self,
        standard: &Standard,
        publication: &Publication,
        cancel: CancellationToken,
    ) -> Result<Option<Snapshot>> {
        let Some(artifact) = &publication.artifact else {
            return Ok(None);
        };
        let kind = publication.url.kind();
        let representation = kind.representation();
        if let Some(snapshot) = self
            .snapshot_for_revision(
                &standard.id,
                publication.url.as_str(),
                &publication.id,
                representation,
            )
            .await?
        {
            return Ok(Some(snapshot));
        }
        let path = publication_path(publication.url.as_str(), representation)?;
        let edition = publication_edition(standard, publication);
        let mut gaps = publication.gaps.clone();
        if kind != catalog::PublicationKind::Html {
            gaps.retain(|gap| !gap.starts_with("publication_metadata_"));
        }
        let projection = if !kind.has_projection() {
            gaps.push("unsupported_publication_projection".into());
            None
        } else if artifact.bytes > MAX_SOURCE as u64 {
            gaps.push("projection_input_limit".into());
            None
        } else {
            let bytes = self
                .artifact_bytes(artifact, MAX_SOURCE as u64, cancel.clone())
                .await?;
            match self
                .project(standard, &path, &edition, bytes, cancel.clone())
                .await
            {
                Ok((id, more)) => {
                    gaps.extend(more);
                    Some(id)
                }
                Err(error) if error.code == "cancelled" || cancel.is_cancelled() => {
                    return Err(error);
                }
                Err(error)
                    if matches!(
                        error.code.as_str(),
                        "capacity" | "integrity" | "invalid_input"
                    ) =>
                {
                    gaps.push(format!("projection_{}", error.code));
                    None
                }
                Err(error) => return Err(error),
            }
        };
        let member_projection_usable = if gaps.iter().any(|g| {
            matches!(
                g.as_str(),
                "publication_unavailable" | "pdf_text_unavailable"
            )
        }) {
            false
        } else if let Some(id) = &projection {
            self.store
                .w3c_get("projections", id)
                .await?
                .is_some_and(|row| has_index_members(&row.data))
        } else {
            false
        };
        let member = Member {
            path: path.clone(),
            oid: artifact.body_hash.clone(),
            mode: "100644".into(),
            kind: representation.into(),
            projection,
            raw: Some(
                json!({"artifact":artifact,"publication":publication.id,"chunk_hashes":publication.chunk_hashes,"source_url":publication.url.as_str(),"license":publication.license,"searchable":member_projection_usable}),
            ),
            gaps: gaps.clone(),
        };
        let root = inventory::empty(self.store.as_ref()).await?;
        let inventory = inventory::update(self.store.as_ref(), &root, &path, Some(member)).await?;
        let index = self
            .flush_index(std::slice::from_ref(&inventory), cancel)
            .await?;
        let id = inventory::digest(
            &serde_json::to_vec(&(&standard.id, &publication.id, &inventory, PROCESSOR_VERSION))
                .map_err(|_| failure())?,
        );
        let snapshot = Snapshot {
            id: id.clone(),
            standard: standard.id.clone(),
            repository: publication.url.as_str().into(),
            revision: publication.id.clone(),
            tree: artifact.body_hash.clone(),
            parents: Vec::new(),
            committed_at: publication.observed_at,
            inventory,
            processor_version: PROCESSOR_VERSION,
            index,
            coverage: json!({"accounted":true,"usable":member_projection_usable,"members":1,"raw_members":1,"projection_gaps":gaps.len(),"index_gaps":gaps.iter().filter(|g|g.starts_with("index_")).count(),"gaps":gaps,"edition":edition,"publication":publication.id,"published_source_association":"unresolved","listed_publication_url":standard.url,"latest_publication":standard.metadata["latest_tr_url"],"effective_publication":publication.url.as_str(),"publication_status":catalog::publication_status(standard,&publication.url,&publication.license),"publication_role":if publication.url.as_str()==catalog::current_publication(standard)?.as_str(){"latest_tr"}else{"historical_or_editor"},"license":publication.license}),
            source_url: publication.url.as_str().into(),
            representation: representation.into(),
            validated_at: publication.observed_at,
        };
        let snapshot = self
            .publish_snapshot(
                snapshot,
                &alias(
                    &standard.id,
                    publication.url.as_str(),
                    &publication.id,
                    representation,
                )?,
            )
            .await?;
        if self.usable(&snapshot).await? {
            self.store
                .w3c_set_state(
                    &state_key("publication-usable", publication.url.as_str()),
                    &json!(publication.id),
                )
                .await?;
        }
        Ok(Some(snapshot))
    }
    async fn publish_default(&self, catalog: &Catalog, cancel: CancellationToken) -> Result<()> {
        let mut snapshots = BTreeMap::new();
        let mut validations = BTreeMap::new();
        for standard in &catalog.standards {
            let current_key = state_key("current", &standard.id);
            let Some(selected) = self.store.w3c_state(&current_key).await? else {
                continue;
            };
            let Some(id) = selected["snapshot"].as_str() else {
                continue;
            };
            let canonical = self.snapshot(id).await?;
            let edition = self
                .aggregate_edition(standard, &canonical, cancel.clone())
                .await?;
            let observed_validation = selected["validated_at"].as_i64().ok_or_else(failure)?;
            let edition_validation = if edition.id == canonical.id {
                observed_validation
            } else {
                observed_validation.min(edition.validated_at)
            };
            snapshots.insert(standard.id.clone(), edition.id);
            validations.insert(standard.id.clone(), edition_validation);
        }
        if snapshots.is_empty() {
            return Ok(());
        }
        let validated_at = validations
            .values()
            .copied()
            .min()
            .unwrap_or(catalog.observed_at)
            .min(catalog.observed_at);
        let mut roots = Vec::new();
        for id in snapshots.values() {
            roots.push(self.snapshot(id).await?.inventory);
        }
        let index = self.flush_index(&roots, cancel).await?;
        let id = inventory::digest(
            &serde_json::to_vec(&(&catalog.id, &snapshots, &index, &validations, validated_at))
                .map_err(|_| failure())?,
        );
        self.store
            .w3c_publish_view(&View {
                id,
                catalog: catalog.id.clone(),
                snapshots,
                index,
                validations,
                validated_at,
            })
            .await
    }
    async fn update_status(&self) -> Result<()> {
        let catalog = self.catalog().await.ok();
        let statistics = self.store.w3c_statistics().await?;
        let snapshots = statistics["snapshots"].as_u64().unwrap_or(0);
        let projections = statistics["projection_gaps"].as_u64().unwrap_or(0);
        let publications = statistics["publications"].as_u64().unwrap_or(0);
        let view = self.view(None).await.ok();
        self.store.w3c_set_state("status",&json!({"processor_version":PROCESSOR_VERSION,"gap_scope":"all_retained_snapshot_generations","collection_enabled":self.config.enabled,"catalog":catalog.as_ref().map(|c|&c.id),"catalog_standards":catalog.as_ref().map_or(0,|c|c.standards.len()),"snapshots":snapshots,"publications":publications,"projection_gaps":projections,"index_gaps":statistics["index_gaps"],"published_standards":view.as_ref().map_or(0,|v|v.snapshots.len()),"view":view.as_ref().map(|v|&v.id),"validated_at":view.as_ref().map(|v|v.validated_at),"stale":view.as_ref().is_none_or(|v|devres_domain::unix_now().saturating_sub(v.validated_at)>86400),"failure":self.store.w3c_state("failure").await?,"archive_bytes":self.raw.accounted_bytes(),"archive_quota_bytes":self.raw.quota_bytes(),"historical_rendering":"source_snapshots_do_not_imply_rendered_publication_coverage"})).await
    }
    pub async fn status(&self) -> Result<Value> {
        self.store.w3c_state("status").await?.ok_or_else(failure)
    }
}

fn text_chunks(value: &str, max: usize) -> Vec<&str> {
    let mut result = Vec::new();
    let mut offset = 0;
    while offset < value.len() {
        let mut end = (offset + max).min(value.len());
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        result.push(&value[offset..end]);
        offset = end;
    }
    result
}
fn supported_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let basename = lower.rsplit('/').next().unwrap_or(&lower);
    path.rsplit('/').next() == Some("source")
        || [
            ".bs",
            ".wattsi",
            ".html",
            ".htm",
            ".md",
            ".markdown",
            ".txt",
            ".idl",
            ".pdf",
            ".xhtml",
            ".xht",
            ".xml",
            ".svg",
            ".rdf",
            ".xsd",
            ".json",
            ".jsonld",
            ".yaml",
            ".yml",
            ".csv",
            ".tsv",
            ".ttl",
            ".nt",
            ".nq",
            ".trig",
            ".abnf",
            ".bnf",
            ".ebnf",
            ".rnc",
            ".rng",
            ".n3",
            ".json-ld",
            ".dtd",
            ".grammar",
            ".webidl",
        ]
        .iter()
        .any(|extension| lower.ends_with(extension))
        || ["license", "copying", "notice"]
            .iter()
            .any(|prefix| basename.starts_with(prefix))
}

fn git_source_url(repository: &str, revision: &str) -> String {
    format!("{repository}#revision={revision}")
}
fn publication_path(value: &str, representation: &str) -> Result<String> {
    let url = url::Url::parse(value).map_err(|_| failure())?;
    let path = url.path().trim_start_matches('/');
    if path.is_empty() {
        return Ok(format!("index.{representation}"));
    }
    if path.ends_with('/') {
        Ok(format!("{path}index.{representation}"))
    } else {
        Ok(path.into())
    }
}
fn publication_edition(standard: &Standard, publication: &Publication) -> String {
    if catalog::current_publication(standard)
        .ok()
        .is_some_and(|u| u.as_str() == publication.url.as_str())
    {
        return "latest-tr".into();
    }
    if catalog::editor_publication(standard)
        .is_some_and(|u| publication.url.as_str().starts_with(u.as_str()))
    {
        return "editor-draft".into();
    }
    "historical-tr".into()
}

impl W3cCorpus {
    pub async fn freeze(&self, cancel: CancellationToken) -> Result<Value> {
        self.freeze_mode("full", cancel).await
    }
    pub async fn freeze_current(&self, cancel: CancellationToken) -> Result<Value> {
        self.freeze_mode("current", cancel).await
    }
    pub async fn accept_frozen(&self, frozen: &Value, cancel: CancellationToken) -> Result<Value> {
        self.accept_mode(frozen, true, cancel).await
    }
    pub async fn accept_frozen_current(
        &self,
        frozen: &Value,
        cancel: CancellationToken,
    ) -> Result<Value> {
        self.accept_mode(frozen, false, cancel).await
    }
    async fn accept_mode(
        &self,
        value: &Value,
        full: bool,
        cancel: CancellationToken,
    ) -> Result<Value> {
        let _guard = self.processing.lock().await;
        let frozen: Frozen = decode(value.clone())?;
        let retained = self
            .store
            .w3c_get("frozen", &frozen.id)
            .await?
            .ok_or_else(|| Error::integrity("W3C frozen observation is not retained."))?;
        if retained.data != *value || (full && frozen.mode != "full") {
            return Err(Error::integrity("W3C frozen observation mismatch."));
        }
        let mut expected = 0;
        let mut processed = 0;
        let mut projection_gaps = 0_u64;
        let mut index_gaps = 0_u64;
        let mut source_unavailable = 0usize;
        for standard in &frozen.catalog.standards {
            cancelled(&cancel)?;
            let Some(observation) = frozen.observations.get(&standard.id) else {
                if full {
                    source_unavailable += 1;
                }
                continue;
            };
            let git = self.git(&standard.repository)?;
            git.restore(&observation.manifest, cancel.clone()).await?;
            let revision = observation
                .main_revision
                .as_deref()
                .ok_or_else(|| Error::integrity("W3C repository has no current branch."))?;
            while !self
                .process_commit(standard, observation, revision, cancel.clone())
                .await?
            {
                cancelled(&cancel)?;
            }
            if full {
                expected += observation.total_commits;
                let key = state_key(
                    "frozen-history",
                    &format!("{}:{}:{PROCESSOR_VERSION}", frozen.id, standard.id),
                );
                let mut offset = self
                    .store
                    .w3c_state(&key)
                    .await?
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                loop {
                    let page = git
                        .commit_page(observation, offset, 100, cancel.clone())
                        .await?;
                    if page.commits.is_empty() {
                        break;
                    }
                    for (commit, next) in page.commits.iter().zip(page.offsets) {
                        while !self
                            .process_commit(standard, observation, &commit.revision, cancel.clone())
                            .await?
                        {
                            cancelled(&cancel)?;
                        }
                        offset = next;
                        self.store.w3c_set_state(&key, &json!(offset)).await?;
                    }
                }
                let mut verified_offset = 0;
                loop {
                    let page = git
                        .commit_page(observation, verified_offset, 100, cancel.clone())
                        .await?;
                    if page.commits.is_empty() {
                        break;
                    }
                    for commit in &page.commits {
                        if let Some(snapshot) = self
                            .snapshot_for_revision(
                                &standard.id,
                                &standard.repository,
                                &commit.revision,
                                "source",
                            )
                            .await?
                        {
                            processed += 1;
                            projection_gaps +=
                                snapshot.coverage["projection_gaps"].as_u64().unwrap_or(0);
                            index_gaps += snapshot.coverage["index_gaps"].as_u64().unwrap_or(0);
                        }
                    }
                    verified_offset = page.next_offset;
                }
            } else {
                expected += 1;
                if let Some(snapshot) = self
                    .snapshot_for_revision(&standard.id, &standard.repository, revision, "source")
                    .await?
                {
                    processed += 1;
                    projection_gaps += snapshot.coverage["projection_gaps"].as_u64().unwrap_or(0);
                    index_gaps += snapshot.coverage["index_gaps"].as_u64().unwrap_or(0);
                }
            }
        }
        let mut publications_processed = 0;
        let mut unavailable = 0;
        let mut discovery_gaps = 0;
        for id in &frozen.publications {
            cancelled(&cancel)?;
            let publication: Publication = decode(
                self.store
                    .w3c_get("publications", id)
                    .await?
                    .ok_or_else(failure)?
                    .data,
            )?;
            if publication.url.kind() == catalog::PublicationKind::Html {
                discovery_gaps += publication
                    .gaps
                    .iter()
                    .filter(|gap| gap.starts_with("publication_metadata_"))
                    .count();
            }
            let standard = frozen
                .catalog
                .standards
                .iter()
                .find(|s| s.id == publication.standard)
                .ok_or_else(failure)?;
            if let Some(snapshot) = self
                .process_publication(standard, &publication, cancel.clone())
                .await?
            {
                projection_gaps += snapshot.coverage["projection_gaps"].as_u64().unwrap_or(0);
                index_gaps += snapshot.coverage["index_gaps"].as_u64().unwrap_or(0);
                if publication.url.as_str() == catalog::current_publication(standard)?.as_str()
                    && self.usable(&snapshot).await?
                {
                    self.store
                        .w3c_set_state(
                            &state_key("current", &standard.id),
                            &json!({"snapshot":snapshot.id,"validated_at":publication.observed_at}),
                        )
                        .await?;
                }
            } else {
                unavailable += 1;
            }
            publications_processed += 1;
        }
        let frozen_view = self.publish_frozen_default(&frozen, cancel.clone()).await?;
        self.update_status().await?;
        let catalog_gap_count = frozen.catalog.gaps.len();
        let outcome = json!({"complete":frozen_view["complete"]==true && catalog_gap_count==0 && projection_gaps==0 && source_unavailable==0 && processed==expected && publications_processed==frozen.publications.len() && unavailable==0 && index_gaps==0 && discovery_gaps==0,"accounting_complete":source_unavailable==0&&processed==expected&&publications_processed==frozen.publications.len(),"mode":if full{"full"}else{"current"},"processor_version":PROCESSOR_VERSION,"catalog":frozen.catalog.id,"frozen":frozen.id,"standards":frozen.catalog.standards.len(),"source_inventory_gaps":source_unavailable,"git_commits_expected":expected,"git_commits_processed":processed,"publications_expected":frozen.publications.len(),"publications_processed":publications_processed,"unavailable_publications":unavailable,"projection_gaps":projection_gaps,"index_gaps":index_gaps,"discovery_gaps":discovery_gaps,"publication_inventory_complete":discovery_gaps==0 && frozen_view["complete"]==true,"frozen_view":frozen_view,"catalog_reconciliation_complete":catalog_gap_count==0,"catalog_reconciliation_gaps":catalog_gap_count,"catalog_gap_samples":frozen.catalog.gaps.iter().take(100).collect::<Vec<_>>(),"projection_complete":projection_gaps==0,"scope":"frozen_catalog_refs_and_advertised_publications","rendering":"historical_sources_are_distinct_from_official_rendered_publications"});
        self.store
            .w3c_put(
                "acceptance",
                &format!(
                    "{}:{}:{PROCESSOR_VERSION}",
                    frozen.id,
                    if full { "full" } else { "current" }
                ),
                &outcome,
            )
            .await?;
        Ok(outcome)
    }
    async fn history_step(&self, cancel: CancellationToken) -> Result<()> {
        let mut _guard = Some(self.processing.lock().await);
        let Ok(mut catalog) = self.catalog().await else {
            return Ok(());
        };
        for standard in &catalog.standards {
            if self
                .store
                .w3c_state(&state_key("current-attempt", &standard.id))
                .await?
                .is_none()
            {
                return Ok(());
            }
        }
        let mut offset = self
            .store
            .w3c_state("history-offset")
            .await?
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize
            % catalog.standards.len();
        let mut standard = catalog.standards[offset].clone();
        self.versions_step(&mut standard, cancel.clone()).await?;
        let mut frontier = self.publication_frontier(&standard.id).await?;
        for url in catalog::source_publications(&standard, &[])? {
            if catalog::current_publication(&standard)?.as_str() == url.as_str() {
                continue;
            }
            if !frontier.iter().any(|s| s == url.as_str()) {
                frontier.push(url.as_str().into());
            }
        }
        catalog.standards[offset] = standard.clone();
        catalog = self.retain_resolved_catalog(catalog).await?;
        let publication_due = self
            .store
            .w3c_state(&state_key("publication-due", &standard.id))
            .await?
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        if !frontier.is_empty() && devres_domain::unix_now() >= publication_due {
            let url = PublicationUrl::qualified(&frontier[0], &standard.url)?;
            let previous = self
                .store
                .w3c_state(&state_key("publication", url.as_str()))
                .await?
                .and_then(|v| v.as_str().map(str::to_owned));
            let previous: Option<Publication> = match previous {
                Some(id) => self
                    .store
                    .w3c_get("publications", &id)
                    .await?
                    .map(|row| decode(row.data))
                    .transpose()?,
                None => None,
            };
            drop(_guard.take());
            let publication = if let Some(previous) = previous {
                let age = devres_domain::unix_now().saturating_sub(previous.observed_at);
                if previous.status == 200
                    && previous.artifact.is_some()
                    && previous.license["decision"] == "approved"
                    && (immutable_dated_publication(&previous.url)
                        || age < self.config.publication_refresh_secs as i64)
                {
                    Some(previous)
                } else if age
                    >= if previous.status == 200 && previous.artifact.is_some() {
                        self.config.publication_refresh_secs as i64
                    } else if previous.status == 404 {
                        300
                    } else {
                        60
                    }
                {
                    Some(
                        self.capture_publication(&standard, url, cancel.clone())
                            .await?,
                    )
                } else {
                    None
                }
            } else {
                Some(
                    self.capture_publication(&standard, url, cancel.clone())
                        .await?,
                )
            };
            _guard = Some(self.processing.lock().await);
            if let Ok(latest) = self.catalog().await
                && let Some(position) = latest.standards.iter().position(|s| s.id == standard.id)
            {
                catalog = latest;
                offset = position;
                standard = catalog.standards[offset].clone();
            }
            if let Some(publication) = publication {
                let publication = if publication.status == 200
                    && publication.url.kind() == catalog::PublicationKind::Html
                    && publication.metadata_version < catalog::METADATA_VERSION
                {
                    self.repair_publication_metadata(&publication, cancel.clone())
                        .await?
                } else {
                    publication
                };
                if publication.status == 200 {
                    let resolved = self.resolved_standard(&standard, &publication);
                    if resolved.repository != standard.repository
                        || resolved.metadata["source_mapping"]
                            != standard.metadata["source_mapping"]
                    {
                        standard = resolved;
                        catalog.standards[offset] = standard.clone();
                        catalog = self.retain_resolved_catalog(catalog).await?;
                    }
                    self.process_publication(&standard, &publication, cancel.clone())
                        .await?;
                    frontier.remove(0);
                    for url in catalog::qualified_advertised(
                        &standard,
                        &publication.url,
                        &publication.advertisements,
                    ) {
                        if self
                            .store
                            .w3c_state(&state_key("publication", url.as_str()))
                            .await?
                            .is_none()
                            && !frontier.iter().any(|s| s == url.as_str())
                        {
                            frontier.push(url.as_str().into());
                        }
                    }
                } else {
                    frontier.rotate_left(1);
                }
            } else {
                frontier.rotate_left(1);
            }
            self.retain_publication_frontier(&standard.id, &frontier)
                .await?;
            self.store
                .w3c_set_state(
                    &state_key("publication-due", &standard.id),
                    &json!(
                        devres_domain::unix_now()
                            .saturating_add(self.config.publication_interval_secs as i64)
                    ),
                )
                .await?;
        }
        if !standard.repository.is_empty() {
            let shared = catalog
                .standards
                .iter()
                .filter(|s| s.repository == standard.repository)
                .count()
                > 1;
            if shared && standard.metadata["source_mapping"]["kind"] == "repository_root" {
                standard.metadata["source_mapping"] = if let Some(editor) =
                    standard.metadata["editor_draft"]
                        .as_str()
                        .and_then(|v| url::Url::parse(v).ok())
                        .filter(|u| !u.path().trim_matches('/').is_empty())
                {
                    json!({"kind":"candidate_prefix","prefix":editor.path().trim_matches('/'),"evidence_url":editor.as_str()})
                } else {
                    json!({"kind":"unresolved","reason":"shared_repository_requires_explicit_source_prefix"})
                };
            }
            let previous = self
                .store
                .w3c_state(&state_key("observation", &standard.repository))
                .await?;
            let stale = previous
                .as_ref()
                .and_then(|v| v["observed_at"].as_i64())
                .is_none_or(|t| {
                    devres_domain::unix_now().saturating_sub(t)
                        >= self.config.ref_refresh_secs as i64
                });
            if stale {
                drop(_guard.take());
                let observation_result = self
                    .observe_repository(&standard.repository, cancel.clone())
                    .await;
                _guard = Some(self.processing.lock().await);
                if let Ok(latest) = self.catalog().await
                    && let Some(position) =
                        latest.standards.iter().position(|s| s.id == standard.id)
                {
                    catalog = latest;
                    offset = position;
                    let current = &catalog.standards[offset];
                    if current.repository == standard.repository {
                        for key in [
                            "license",
                            "publication_status",
                            "publication_url",
                            "latest_tr_url",
                            "licensed_chapters",
                            "licensed_alternates",
                        ] {
                            if let Some(value) = current.metadata.get(key) {
                                standard.metadata[key] = value.clone();
                            }
                        }
                    }
                }
                if let Err(error) = observation_result {
                    if error.code == "cancelled" {
                        return Err(error);
                    }
                    standard.metadata["repository_gap"] = json!({"code":error.code,"reason":"repository_preflight_or_acquisition_unavailable"});
                }
                if let Some(license) = self
                    .store
                    .w3c_state(&state_key("repository-license", &standard.repository))
                    .await?
                {
                    standard.metadata["repository_license"] = license;
                }
                catalog.standards[offset] = standard.clone();
                catalog = self.retain_resolved_catalog(catalog).await?;
            }
        }
        if let Some(value) = self
            .store
            .w3c_state(&state_key("observation", &standard.repository))
            .await?
        {
            let observation: Observation = decode(value)?;
            let git = self.git(&standard.repository)?;
            let key = state_key(
                "history",
                &format!(
                    "{}:{}:{}:{PROCESSOR_VERSION}",
                    standard.id,
                    inventory::digest(
                        &serde_json::to_vec(&standard.metadata["source_mapping"])
                            .map_err(|_| failure())?
                    ),
                    observation.manifest.body_hash
                ),
            );
            let position = self
                .store
                .w3c_state(&key)
                .await?
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let page = git
                .commit_page(&observation, position, 1, cancel.clone())
                .await?;
            if let Some(commit) = page.commits.first()
                && self
                    .process_commit(&standard, &observation, &commit.revision, cancel.clone())
                    .await?
            {
                self.store
                    .w3c_set_state(&key, &json!(page.next_offset))
                    .await?;
            }
        }
        self.store
            .w3c_set_state(
                "history-offset",
                &json!((offset + 1) % catalog.standards.len()),
            )
            .await?;
        self.update_status().await
    }
    async fn record_failure(&self, lane: &str, error: &Error) -> Result<()> {
        self.store
            .w3c_set_state(
                "failure",
                &json!({"lane":lane,"code":error.code,"observed_at":devres_domain::unix_now()}),
            )
            .await?;
        self.update_status().await
    }
    pub async fn run_current(&self, cancel: CancellationToken) -> Result<()> {
        if let Err(error) = self.recover(cancel.clone()).await {
            if cancel.is_cancelled() {
                return Ok(());
            }
            self.record_failure("recovery", &error).await?;
        }
        loop {
            if cancel.is_cancelled() {
                return Ok(());
            }
            let mut delay = self.config.collection_interval_secs;
            if self.config.enabled
                && let Err(error) = self.current_step(cancel.clone()).await
            {
                if cancel.is_cancelled() {
                    return Ok(());
                }
                self.record_failure("current", &error).await?;
                if let Ok(catalog) = self.catalog().await {
                    let offset = self
                        .store
                        .w3c_state("current-offset")
                        .await?
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    self.store
                        .w3c_set_state(
                            "current-offset",
                            &json!((offset + 1) % (catalog.standards.len() as u64)),
                        )
                        .await?;
                }
                delay = 60;
            }
            tokio::select! {_=cancel.cancelled()=>return Ok(()),_=tokio::time::sleep(Duration::from_secs(delay))=>{}}
        }
    }
    pub async fn run_history(&self, cancel: CancellationToken) -> Result<()> {
        loop {
            if cancel.is_cancelled() {
                return Ok(());
            }
            let mut delay = self.config.collection_interval_secs;
            if self.config.enabled
                && let Err(error) = self.history_step(cancel.clone()).await
            {
                if cancel.is_cancelled() {
                    return Ok(());
                }
                self.record_failure("history", &error).await?;
                if let Ok(catalog) = self.catalog().await {
                    let offset = self
                        .store
                        .w3c_state("history-offset")
                        .await?
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    self.store
                        .w3c_set_state(
                            "history-offset",
                            &json!((offset + 1) % (catalog.standards.len() as u64)),
                        )
                        .await?;
                }
                delay = 60;
            }
            tokio::select! {_=cancel.cancelled()=>return Ok(()),_=tokio::time::sleep(Duration::from_secs(delay))=>{}}
        }
    }
    pub async fn rebuild_index(&self, cancel: CancellationToken) -> Result<Value> {
        let _guard = self.processing.lock().await;
        let cutoff = self.store.w3c_cutoff().await?;
        let generation = self
            .store
            .w3c_state("index-context")
            .await?
            .and_then(|v| v["generation"].as_u64())
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| Error::capacity("W3C index generation exhausted."))?;
        self.store
            .w3c_set_state("index-checkpoint", &Value::Null)
            .await?;
        self.store
            .w3c_set_state(
                "index-context",
                &json!({"generation":generation,"count":0,"reference":null}),
            )
            .await?;
        let mut snapshots = 0;
        let mut views = 0;
        let mut after = 0;
        loop {
            cancelled(&cancel)?;
            let rows = self
                .store
                .w3c_rows("snapshots", after, 100, Some(cutoff))
                .await?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                after = row.sequence;
                let snapshot: Snapshot = decode(row.data)?;
                let reference = self
                    .flush_index(std::slice::from_ref(&snapshot.inventory), cancel.clone())
                    .await?;
                self.store
                    .w3c_set_state(
                        &state_key("snapshot-index", &snapshot.id),
                        &json!({"reference":reference,"generation":generation}),
                    )
                    .await?;
                snapshots += 1;
            }
        }
        after = 0;
        loop {
            let rows = self
                .store
                .w3c_rows("views", after, 100, Some(cutoff))
                .await?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                after = row.sequence;
                let view: View = decode(row.data)?;
                let mut roots = Vec::new();
                for id in view.snapshots.values() {
                    roots.push(self.snapshot(id).await?.inventory);
                }
                let reference = self.flush_index(&roots, cancel.clone()).await?;
                self.store
                    .w3c_set_state(
                        &state_key("view-index", &view.id),
                        &json!({"reference":reference,"generation":generation}),
                    )
                    .await?;
                views += 1;
            }
        }
        if let Ok(catalog) = self.catalog().await {
            self.publish_default(&catalog, cancel.clone()).await?;
        }
        Ok(
            json!({"complete":true,"snapshots":snapshots,"views":views,"history_cutoff":cutoff,"index":self.store.w3c_state("index").await?,"source_validation_unchanged":true,"original_index_evidence_preserved":true}),
        )
    }
}

fn source_path_selected(standard: &Standard, path: &str) -> bool {
    if standard.metadata["source_mapping"]["kind"] == "unresolved" {
        return false;
    }
    let prefix = standard.metadata["source_mapping"]["prefix"]
        .as_str()
        .unwrap_or("")
        .trim_matches('/');
    if prefix.is_empty() {
        return true;
    }
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|suffix| suffix.starts_with('/'))
        || (!path.contains('/')
            && ["license", "licence", "copying", "copyright", "notice"]
                .iter()
                .any(|p| path.to_ascii_lowercase().starts_with(p)))
}

fn immutable_dated_publication(url: &PublicationUrl) -> bool {
    let Ok(url) = url::Url::parse(url.as_str()) else {
        return false;
    };
    matches!(url.host_str(), Some("www.w3.org" | "w3.org"))
        && url
            .path()
            .strip_prefix("/TR/")
            .and_then(|s| s.split('/').next())
            .is_some_and(|year| year.len() == 4 && year.bytes().all(|b| b.is_ascii_digit()))
}

#[cfg(test)]
#[path = "corpus/tests.rs"]
mod tests;
