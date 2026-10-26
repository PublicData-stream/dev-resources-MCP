//! Resumable WHATWG acquisition and local immutable research evidence.
use crate::{
    bulk::{self, BulkArtifact, BulkArtifactStore, BulkBroker, BulkRequest, BulkSource},
    whatwg_catalog::{self as catalog, PublicationUrl},
    whatwg_git::{Observation, Repo, TreeEntry, WhatwgGit},
    whatwg_index::{IndexDocument, WhatwgIndex},
    whatwg_inventory as inventory, whatwg_processing,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use devres_application::whatwg::{
    Catalog, Member, PROCESSOR_VERSION, Snapshot, Standard, View, WhatwgConfig, WhatwgStore,
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
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Frozen {
    id: String,
    catalog: Catalog,
    observations: BTreeMap<String, Observation>,
    publications: Vec<String>,
    mode: String,
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
    standard_offset: usize,
    queue: VecDeque<(String, PublicationUrl)>,
    seen: BTreeSet<String>,
}

pub struct WhatwgCorpus {
    store: Arc<dyn WhatwgStore>,
    broker: Arc<BulkBroker>,
    root: PathBuf,
    config: WhatwgConfig,
    raw: Arc<BulkArtifactStore>,
    index: WhatwgIndex,
    processing: Mutex<()>,
    processors: Arc<Semaphore>,
}
fn failure() -> Error {
    Error::unavailable("WHATWG evidence unavailable.")
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
    let root = root.join("whatwg/git");
    if !root.try_exists().map_err(|_| failure())? {
        return Ok(());
    }
    crate::crate_git::real_directory(&root)?;
    let mut repositories = 0;
    let mut owners = 0;
    for owner in std::fs::read_dir(&root).map_err(|_| failure())? {
        let owner = owner.map_err(|_| failure())?;
        owners += 1;
        if owners > 4096 {
            return Err(Error::capacity(
                "WHATWG retained repository owner count exceeds its bound.",
            ));
        }
        if !owner.file_type().map_err(|_| failure())?.is_dir() {
            return Err(Error::integrity("Unowned WHATWG Git directory member."));
        }
        let owner_name = owner
            .file_name()
            .into_string()
            .map_err(|_| Error::integrity("Invalid WHATWG retained repository owner."))?;
        for repository in std::fs::read_dir(owner.path()).map_err(|_| failure())? {
            let repository = repository.map_err(|_| failure())?;
            repositories += 1;
            if repositories > 4096 {
                return Err(Error::capacity(
                    "WHATWG retained repository count exceeds its bound.",
                ));
            }
            if !repository.file_type().map_err(|_| failure())?.is_dir() {
                return Err(Error::integrity("Unowned WHATWG retained Git directory."));
            }
            let name = repository
                .file_name()
                .into_string()
                .map_err(|_| Error::integrity("Invalid WHATWG retained repository name."))?;
            let identity = Repo::new(&format!("{owner_name}/{name}"))?;
            let marker = repository.path().join("owner-v1");
            let metadata = std::fs::symlink_metadata(&marker)
                .map_err(|_| Error::integrity("WHATWG retained Git ownership is absent."))?;
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.len() > 1024
                || std::fs::read(&marker).map_err(|_| failure())?
                    != format!("devres-whatwg-{}-v1\n", identity.as_str()).as_bytes()
            {
                return Err(Error::integrity("WHATWG retained Git ownership mismatch."));
            }
            let artifacts = repository.path().join("artifacts");
            crate::crate_git::real_directory(&artifacts)?;
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
        Err(Error::new("cancelled", "WHATWG collection canceled."))
    } else {
        Ok(())
    }
}
impl WhatwgCorpus {
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
                "WHATWG raw range proof differs from retained artifact.",
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
            return Err(Error::integrity("Invalid WHATWG raw range proof."));
        }
        let path = self.raw.root().join(&artifact.body_hash);
        let metadata = tokio::fs::symlink_metadata(&path)
            .await
            .map_err(|_| failure())?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() != artifact.bytes
        {
            return Err(Error::integrity("Invalid retained WHATWG raw artifact."));
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
                return Err(Error::integrity("WHATWG raw range checksum mismatch."));
            }
            let from = (position - start) as usize;
            let to = ((end - start).min(size as u64)) as usize;
            page.extend_from_slice(&bytes[from..to]);
            position = start + to as u64;
        }
        Ok(page)
    }
    async fn publish_snapshot(&self, snapshot: Snapshot, key: &str) -> Result<Snapshot> {
        let snapshot = if let Some(row) = self.store.whatwg_get("snapshots", &snapshot.id).await? {
            let retained: Snapshot = decode(row.data)?;
            if retained.standard != snapshot.standard
                || retained.repository != snapshot.repository
                || retained.revision != snapshot.revision
                || retained.inventory != snapshot.inventory
                || retained.processor_version != snapshot.processor_version
            {
                return Err(Error::integrity("WHATWG snapshot identity collision."));
            }
            retained
        } else {
            snapshot
        };
        self.store
            .whatwg_put_many(&[
                devres_application::whatwg::Write {
                    kind: "snapshots".into(),
                    key: snapshot.id.clone(),
                    data: encode(&snapshot)?,
                },
                devres_application::whatwg::Write {
                    kind: "snapshot-keys".into(),
                    key: key.into(),
                    data: json!(snapshot.id),
                },
            ])
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
            let rows = self.store.whatwg_get_many(kind, chunk).await?;
            if rows.len() != chunk.len() {
                return Err(Error::integrity(
                    "WHATWG shared projection object is missing.",
                ));
            }
            for row in rows {
                let encoded = serde_json::to_vec(&row.data).map_err(|_| failure())?;
                bytes += encoded.len();
                if bytes as u64 > MAX_PROJECTION {
                    return Err(Error::capacity(
                        "WHATWG projection reconstruction exceeds its bound.",
                    ));
                }
                if inventory::digest(&encoded) != row.key {
                    return Err(Error::integrity(
                        "WHATWG shared projection object hash mismatch.",
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
                    return Err(Error::capacity(
                        "WHATWG reconstructed text exceeds its bound.",
                    ));
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
                    .ok_or_else(|| std::io::Error::other("WHATWG reconstruction size"))?;
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        serde_json::to_writer(Counter(0), &value).map_err(|_| {
            Error::capacity("WHATWG reconstructed projection exceeds its byte bound.")
        })?;
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
                    .whatwg_get("projections", &id)
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
        store: Arc<dyn WhatwgStore>,
        broker: Arc<BulkBroker>,
        root: &Path,
        config: WhatwgConfig,
    ) -> Result<Self> {
        config.validate()?;
        std::fs::create_dir_all(root.join("whatwg/raw-artifacts")).map_err(|_| failure())?;
        let raw = Arc::new(
            BulkArtifactStore::new(root.join("whatwg/raw-artifacts"), config.min_free_bytes)?
                .with_quota(config.max_archive_storage_bytes)?,
        );
        register_git_artifact_budgets(root, raw.as_ref(), config.min_free_bytes)?;
        let index = WhatwgIndex::new(root)?;
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
    pub fn store(&self) -> Arc<dyn WhatwgStore> {
        self.store.clone()
    }
    pub fn index(&self) -> &WhatwgIndex {
        &self.index
    }
    fn git(&self, repository: &str) -> Result<WhatwgGit> {
        WhatwgGit::new(
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
            .whatwg_state("catalog")
            .await?
            .and_then(|v| v.as_str().map(str::to_owned))
            .ok_or_else(failure)?;
        decode(
            self.store
                .whatwg_get("catalogs", &id)
                .await?
                .ok_or_else(failure)?
                .data,
        )
    }
    pub async fn snapshot(&self, id: &str) -> Result<Snapshot> {
        let mut snapshot: Snapshot = decode(
            self.store
                .whatwg_get("snapshots", id)
                .await?
                .ok_or_else(|| Error::not_found("WHATWG snapshot not found."))?
                .data,
        )?;
        if let Some(repair) = self
            .store
            .whatwg_state(&state_key("snapshot-index", id))
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
        match self.store.whatwg_get("snapshot-keys", &key).await? {
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
                    .whatwg_get("views", id)
                    .await?
                    .ok_or_else(|| Error::not_found("WHATWG view not found."))?
                    .data,
            )?,
            None => decode(
                self.store
                    .whatwg_state("default")
                    .await?
                    .ok_or_else(failure)?,
            )?,
        };
        if let Some(repair) = self
            .store
            .whatwg_state(&state_key("view-index", &view.id))
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
                "WHATWG snapshot and view selectors are exclusive.",
            ));
        }
        let result = if let Some(id) = snapshot {
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
                    "WHATWG default evidence is older than seven days.",
                ));
            }
            self.snapshot(selected.snapshots.get(standard).ok_or_else(|| {
                Error::not_found("WHATWG standard is not published in this view.")
            })?)
            .await?
        };
        if result.standard != standard {
            return Err(Error::invalid(
                "WHATWG snapshot belongs to another standard.",
            ));
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
            return Err(Error::invalid("Invalid WHATWG member page."));
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
            .whatwg_get("projections", &id)
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
            .map_err(|_| Error::integrity("Malformed WHATWG projection."))?;
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
                    .whatwg_get("projections", &id)
                    .await?
                    .ok_or_else(failure)?;
                for id in self.projection_members(&row.data).await? {
                    ids.insert(id);
                    if ids.len() > MAX_MEMBERS {
                        return Err(Error::capacity(
                            "WHATWG selected search membership exceeds its bound.",
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
            return Err(Error::capacity("WHATWG artifact read exceeds its bound."));
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
                return Err(Error::integrity("WHATWG artifact length mismatch."));
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
            return Err(Error::invalid("WHATWG byte limit must be 1..32768."));
        }
        let member = self
            .member(snapshot, path)
            .await?
            .ok_or_else(|| Error::not_found("WHATWG source member not found."))?;
        let raw = member
            .raw
            .ok_or_else(|| Error::not_found("WHATWG member has no raw bytes."))?;
        let (bytes, total, body_hash) = if let Some(artifact) = raw.get("artifact") {
            let artifact: BulkArtifact = decode(artifact.clone())?;
            if offset > artifact.bytes {
                return Err(Error::invalid("WHATWG byte offset exceeds source length."));
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
        if let Some(reference) = self.store.whatwg_state("index").await? {
            self.index.prewarm(&reference, cancel.clone()).await?;
        }
        if let Ok(catalog) = self.catalog().await {
            for standard in &catalog.standards {
                cancelled(&cancel)?;
                if let Some(value) = self
                    .store
                    .whatwg_state(&state_key("observation", &standard.repository))
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
        if let Some(row) = self.store.whatwg_get("projections", &id).await? {
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
            whatwg_processing::process_pdf(&bytes, cancel.clone()).await?
        } else {
            let source_path = path.to_owned();
            let stop = cancel.clone();
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                whatwg_processing::process_document(&source_path, &bytes, stop)
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
                match WhatwgIndex::validate_document(&index_document, &cancel) {
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
                match WhatwgIndex::validate_document(&index_document, &cancel) {
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
                match WhatwgIndex::validate_document(&index_document, &cancel) {
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
                "WHATWG projection search membership exceeds its bound.",
            ));
        }
        gaps.sort();
        gaps.dedup();
        let index_membership = shared.sequence(&index_ids).await?;
        shared.flush().await?;
        self.store.whatwg_put("projections",&id,&json!({"manifest":manifest,"index_membership":index_membership,"index_count":index_ids.len(),"gaps":gaps,"format":document.format,"title":document.title,"sections":document.sections.len(),"symbols":document.symbols.len(),"references":document.references.len()})).await?;
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
            let rows: Vec<devres_application::whatwg::Write> = chunk
                .iter()
                .map(|id| devres_application::whatwg::Write {
                    kind: "indexed-membership".into(),
                    key: inventory::digest(format!("{generation}:{id}").as_bytes()),
                    data: json!({"generation":generation,"id":id}),
                })
                .collect();
            self.store.whatwg_put_many(&rows).await?;
        }
        self.store.whatwg_set_state("index-context",&json!({"generation":generation,"count":checkpoint["count"],"reference":checkpoint["reference"]})).await?;
        self.store
            .whatwg_set_state("index", &checkpoint["reference"])
            .await?;
        self.store
            .whatwg_set_state("index-checkpoint", &Value::Null)
            .await
    }
    async fn root_members(&self, root: &str) -> Result<BTreeSet<String>> {
        let mut result = BTreeSet::new();
        for member in inventory::members(self.store.as_ref(), root, MAX_MEMBERS).await? {
            if let Some(id) = member.projection {
                let row = self
                    .store
                    .whatwg_get("projections", &id)
                    .await?
                    .ok_or_else(failure)?;
                for id in self.projection_members(&row.data).await? {
                    result.insert(id);
                    if result.len() > MAX_MEMBERS {
                        return Err(Error::capacity(
                            "WHATWG index generation membership exceeds its bound.",
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
            .whatwg_state("index-checkpoint")
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
                    "WHATWG active index membership exceeds its bound.",
                ));
            }
        }
        let context = self
            .store
            .whatwg_state("index-context")
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
                .ok_or_else(|| Error::capacity("WHATWG index generation exhausted."))?;
            count = 0;
            reference = None;
            self.store
                .whatwg_set_state(
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
            let retained = self
                .store
                .whatwg_existing("indexed-membership", &keys)
                .await?;
            for (id, key) in chunk.iter().zip(keys) {
                if !retained.contains(&key) {
                    missing.push(id.clone());
                }
            }
        }
        let mut position = 0;
        while position < missing.len() || reference.is_none() {
            cancelled(&cancel)?;
            if count >= 4090 {
                return Err(Error::capacity(
                    "WHATWG active index requires too many immutable shards.",
                ));
            }
            let mut documents = Vec::new();
            let mut ids = Vec::new();
            let mut bytes = 0;
            while let Some(id) = missing.get(position) {
                let row = self
                    .store
                    .whatwg_get("index-documents", id)
                    .await?
                    .ok_or_else(|| {
                        Error::integrity("WHATWG selected index document is missing.")
                    })?;
                let size = serde_json::to_vec(&row.data).map_err(|_| failure())?.len();
                if !documents.is_empty()
                    && (documents.len() >= 5000 || bytes + size > 16 * 1024 * 1024)
                {
                    break;
                }
                bytes += size;
                documents.push(decode(row.data)?);
                ids.push(id.clone());
                position += 1;
            }
            let published = self
                .index
                .publish_generation(
                    reference.as_ref(),
                    documents,
                    cancel.clone(),
                    &format!("whatwg-generation-{generation}"),
                )
                .await?;
            count += 1;
            let checkpoint =
                json!({"reference":published,"generation":generation,"count":count,"ids":ids});
            self.store
                .whatwg_set_state("index-checkpoint", &checkpoint)
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
                json!({"repository":standard.repository,"oid":entry.oid,"bytes":length,"manifest":observation.manifest}),
            );
            if supported_path(&entry.path) {
                if length > MAX_SOURCE as u64 {
                    member.gaps.push("projection_input_limit".into());
                } else {
                    let bytes = git
                        .read_blob_known_length(&entry.oid, length, MAX_SOURCE, cancel.clone())
                        .await?;
                    match self
                        .project(standard, &entry.path, "source", bytes, cancel.clone())
                        .await
                    {
                        Ok((id, gaps)) => {
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
        if self
            .snapshot_for_revision(&standard.id, &standard.repository, revision, "source")
            .await?
            .is_some()
        {
            return Ok(true);
        }
        let git = self.git(&standard.repository)?;
        let commit = git.commit(revision, cancel.clone()).await?;
        let key = state_key(
            "work",
            &format!("{}:{revision}:{PROCESSOR_VERSION}", standard.id),
        );
        let mut work: Work = if let Some(value) = self
            .store
            .whatwg_state(&key)
            .await?
            .filter(|v| !v.is_null())
        {
            decode(value)?
        } else {
            let parent = if let Some(parent) = commit.parents.first() {
                self.snapshot_for_revision(&standard.id, &standard.repository, parent, "source")
                    .await?
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
                self.store.whatwg_set_state(&key, &encode(&work)?).await?;
            }
            if started.elapsed() >= Duration::from_secs(10) {
                complete = false;
                break;
            }
        }
        stop.cancel();
        drop(entries);
        self.store.whatwg_set_state(&key, &encode(&work)?).await?;
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
            coverage: json!({"accounted":true,"usable":node.searchable>0,"members":node.members,"searchable":node.searchable,"projection_gaps":node.gaps,"index_gaps":index_gaps,"kinds":node.kinds,"edition":"source","rendering_gap":"historical_source_is_not_a_rendered_publication","observation":observation.manifest.body_hash}),
            source_url: git_source_url(&standard.repository, revision),
            representation: "source".into(),
            validated_at: observation.observed_at,
        };
        self.publish_snapshot(
            snapshot,
            &alias(&standard.id, &standard.repository, revision, "source")?,
        )
        .await?;
        self.store.whatwg_set_state(&key, &Value::Null).await?;
        Ok(true)
    }

    async fn observe_repository(
        &self,
        identity: &str,
        cancel: CancellationToken,
    ) -> Result<Observation> {
        let git = self.git(identity)?;
        let key = state_key("observation", identity);
        let old: Option<Observation> = self
            .store
            .whatwg_state(&key)
            .await?
            .map(decode)
            .transpose()?;
        let observation = match git
            .synchronize(
                self.broker.clone(),
                old.as_ref().map(|o| &o.manifest),
                cancel,
            )
            .await
        {
            Ok(observation) => observation,
            Err(error) => {
                self.store.whatwg_set_state("failure",&json!({"lane":"git_synchronize","repository":identity,"code":error.code,"message":error.message,"observed_at":devres_domain::unix_now()})).await?;
                return Err(error);
            }
        };
        let id = observation.manifest.body_hash.clone();
        self.store
            .whatwg_put("observations", &id, &encode(&observation)?)
            .await?;
        self.store
            .whatwg_set_state(&key, &encode(&observation)?)
            .await?;
        Ok(observation)
    }
    async fn acquire_catalog(&self, cancel: CancellationToken) -> Result<Catalog> {
        let observation = self
            .observe_repository(catalog::CATALOG_REPOSITORY, cancel.clone())
            .await?;
        let revision = observation
            .main_revision
            .as_deref()
            .ok_or_else(|| Error::integrity("WHATWG catalog has no main revision."))?;
        let git = self.git(catalog::CATALOG_REPOSITORY)?;
        let entry = git
            .entry(revision, catalog::CATALOG_PATH, cancel.clone())
            .await?
            .ok_or_else(|| Error::integrity("WHATWG catalog file is absent."))?;
        if entry.kind != "blob" || entry.mode == "120000" {
            return Err(Error::integrity(
                "WHATWG catalog is not a regular Git blob.",
            ));
        }
        let bytes = git.read_blob(&entry.oid, 4 * 1024 * 1024, cancel).await?;
        let catalog = catalog::parse(&bytes, observation.observed_at)?;
        self.store
            .whatwg_put("catalogs", &catalog.id, &encode(&catalog)?)
            .await?;
        self.store.whatwg_put("catalog-captures",&catalog.id,&json!({"repository":catalog::CATALOG_REPOSITORY,"revision":revision,"path":catalog::CATALOG_PATH,"oid":entry.oid,"manifest":observation.manifest})).await?;
        self.store
            .whatwg_set_state("catalog", &json!(catalog.id))
            .await?;
        Ok(catalog)
    }
    async fn capture_publication(
        &self,
        standard: &Standard,
        url: PublicationUrl,
        cancel: CancellationToken,
    ) -> Result<Publication> {
        url.validate()?;
        let response = self
            .broker
            .open(
                BulkRequest {
                    source: BulkSource::WhatwgPublication(url.clone()),
                    validators: Validators::default(),
                    max_bytes: bulk::MAX_ARTIFACT_BYTES,
                    deadline: Instant::now() + Duration::from_secs(3600),
                    body: Vec::new(),
                },
                cancel.clone(),
            )
            .await?;
        let status = response.status;
        let observed_at = devres_domain::unix_now();
        let (artifact, links, repositories, gaps) = if status == 200 {
            let artifact = self.raw.capture(response, None, cancel.clone()).await?;
            if url.kind() != catalog::PublicationKind::Html {
                (Some(artifact), Vec::new(), Vec::new(), Vec::new())
            } else if artifact.bytes > MAX_SOURCE as u64 {
                (
                    Some(artifact),
                    Vec::new(),
                    Vec::new(),
                    vec!["publication_metadata_input_limit".into()],
                )
            } else {
                let bytes = self
                    .artifact_bytes(&artifact, MAX_SOURCE as u64, cancel.clone())
                    .await?;
                let stop = cancel.clone();
                match tokio::task::spawn_blocking(move || {
                    catalog::publication_metadata(&bytes, &stop)
                })
                .await
                .map_err(|_| failure())?
                {
                    Ok(metadata) => (
                        Some(artifact),
                        metadata.links,
                        metadata.repositories,
                        Vec::new(),
                    ),
                    Err(error) if error.code == "cancelled" => return Err(error),
                    Err(error) => (
                        Some(artifact),
                        Vec::new(),
                        Vec::new(),
                        vec![format!("publication_metadata_{}", error.code)],
                    ),
                }
            }
        } else {
            (
                None,
                Vec::new(),
                Vec::new(),
                vec![format!("publication_http_{status}")],
            )
        };
        let id = inventory::digest(
            &serde_json::to_vec(&(
                &standard.id,
                url.as_str(),
                observed_at,
                &artifact,
                status,
                catalog::METADATA_VERSION,
            ))
            .map_err(|_| failure())?,
        );
        let chunk_hashes = match &artifact {
            Some(artifact) => self.publication_chunks(artifact, cancel).await?,
            None => Vec::new(),
        };
        let publication = Publication {
            id: id.clone(),
            standard: standard.id.clone(),
            url,
            observed_at,
            artifact,
            status,
            links,
            gaps,
            repositories,
            chunk_hashes,
            metadata_version: catalog::METADATA_VERSION,
            metadata_parent: None,
        };
        self.store
            .whatwg_put("publications", &id, &encode(&publication)?)
            .await?;
        self.store
            .whatwg_set_state(
                &state_key("publication", publication.url.as_str()),
                &json!(id),
            )
            .await?;
        Ok(publication)
    }
    /// Reinterpret retained bytes; no source request or validation timestamp changes.
    async fn repair_publication_metadata(
        &self,
        old: &Publication,
        cancel: CancellationToken,
    ) -> Result<Publication> {
        let mut repaired = old.clone();
        repaired.metadata_version = catalog::METADATA_VERSION;
        repaired.metadata_parent = Some(old.id.clone());
        repaired
            .gaps
            .retain(|gap| !gap.starts_with("publication_metadata_"));
        let artifact = old.artifact.as_ref().ok_or_else(|| {
            Error::integrity("WHATWG metadata repair requires retained source bytes.")
        })?;
        if old.url.kind() != catalog::PublicationKind::Html {
            repaired.links.clear();
            repaired.repositories.clear();
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
                }
                Err(error) if error.code == "cancelled" => return Err(error),
                Err(error) => {
                    repaired.links.clear();
                    repaired.repositories.clear();
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
                &repaired.gaps,
            ))
            .map_err(|_| failure())?,
        );
        self.store
            .whatwg_put("publications", &repaired.id, &encode(&repaired)?)
            .await?;
        self.store
            .whatwg_set_state(
                &state_key("publication", repaired.url.as_str()),
                &json!(repaired.id),
            )
            .await?;
        Ok(repaired)
    }
    async fn repair_freeze_metadata(
        &self,
        work: &mut FreezeWork,
        cancel: CancellationToken,
    ) -> Result<()> {
        for offset in 0..work.publications.len() {
            cancelled(&cancel)?;
            let publication: Publication = decode(
                self.store
                    .whatwg_get("publications", &work.publications[offset])
                    .await?
                    .ok_or_else(failure)?
                    .data,
            )?;
            if publication.status != 200
                || publication.metadata_version >= catalog::METADATA_VERSION
                || !publication
                    .gaps
                    .iter()
                    .any(|gap| gap.starts_with("publication_metadata_"))
            {
                continue;
            }
            let repaired = self
                .repair_publication_metadata(&publication, cancel.clone())
                .await?;
            let standard_offset = work
                .catalog
                .standards
                .iter()
                .position(|standard| standard.id == repaired.standard)
                .ok_or_else(failure)?;
            let original = &work.catalog.standards[standard_offset];
            let standard =
                if repaired.url.as_str() == catalog::current_publication(original)?.as_str() {
                    self.resolved_standard(original, &repaired)
                } else {
                    original.clone()
                };
            if work
                .observations
                .get(&standard.id)
                .is_some_and(|observation| observation.repo.as_str() != standard.repository)
            {
                return Err(Error::integrity(
                    "WHATWG repaired metadata conflicts with the frozen source repository observation.",
                ));
            }
            if work.mode == "full" {
                for url in catalog::advertised(&standard, &repaired.url, &repaired.links) {
                    if work.seen.insert(url.as_str().into()) {
                        work.queue.push_back((standard.id.clone(), url));
                    }
                }
            }
            if work.seen.len() > MAX_PUBLICATIONS {
                return Err(Error::capacity(
                    "WHATWG repaired publication inventory exceeds its bound.",
                ));
            }
            work.catalog.standards[standard_offset] = standard;
            work.publications[offset] = repaired.id;
            self.store
                .whatwg_set_state("freezing", &encode(work)?)
                .await?;
        }
        Ok(())
    }
    fn resolved_standard(&self, standard: &Standard, publication: &Publication) -> Standard {
        let mut resolved = standard.clone();
        let repository = if publication
            .repositories
            .iter()
            .any(|r| r == &standard.repository)
        {
            Some(standard.repository.clone())
        } else if publication.repositories.len() == 1 {
            publication.repositories.first().cloned()
        } else {
            None
        };
        if let Some(repository) = repository {
            resolved.repository = repository;
            resolved.metadata["repository_policy"] = json!("official_publication_header_metadata");
            resolved.metadata["repository_admission"] = json!({"publication":publication.id,"url":publication.url.as_str(),"repository":resolved.repository});
        } else if publication.repositories.len() > 1 {
            resolved.metadata["repository_gap"] =
                json!("ambiguous_publication_source_repositories");
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
            .whatwg_put("catalogs", &catalog.id, &encode(&catalog)?)
            .await?;
        if let Some(row) = self.store.whatwg_get("catalog-captures", &original).await? {
            self.store
                .whatwg_put("catalog-captures", &catalog.id, &row.data)
                .await?;
        }
        self.store
            .whatwg_set_state("catalog", &json!(catalog.id))
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
                .whatwg_get("projections", id)
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
                json!({"artifact":artifact,"publication":publication.id,"chunk_hashes":publication.chunk_hashes}),
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
            coverage: json!({"accounted":true,"usable":member_projection_usable,"members":1,"raw_members":1,"projection_gaps":gaps.len(),"index_gaps":gaps.iter().filter(|g|g.starts_with("index_")).count(),"gaps":gaps,"edition":edition,"publication":publication.id,"published_source_association":"unresolved","listed_publication_url":standard.url}),
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
        Ok(Some(snapshot))
    }
    async fn publish_default(&self, catalog: &Catalog, cancel: CancellationToken) -> Result<()> {
        let mut snapshots = BTreeMap::new();
        let mut validations = BTreeMap::new();
        for standard in &catalog.standards {
            let current_key = state_key("current", &standard.id);
            let Some(selected) = self.store.whatwg_state(&current_key).await? else {
                continue;
            };
            let Some(id) = selected["snapshot"].as_str() else {
                continue;
            };
            snapshots.insert(standard.id.clone(), id.to_owned());
            validations.insert(
                standard.id.clone(),
                selected["validated_at"].as_i64().ok_or_else(failure)?,
            );
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
            .whatwg_publish_view(&View {
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
        let statistics = self.store.whatwg_statistics().await?;
        let snapshots = statistics["snapshots"].as_u64().unwrap_or(0);
        let projections = statistics["projection_gaps"].as_u64().unwrap_or(0);
        let publications = statistics["publications"].as_u64().unwrap_or(0);
        let view = self.view(None).await.ok();
        self.store.whatwg_set_state("status",&json!({"collection_enabled":self.config.enabled,"catalog":catalog.as_ref().map(|c|&c.id),"catalog_standards":catalog.as_ref().map_or(0,|c|c.standards.len()),"snapshots":snapshots,"publications":publications,"projection_gaps":projections,"index_gaps":statistics["index_gaps"],"published_standards":view.as_ref().map_or(0,|v|v.snapshots.len()),"view":view.as_ref().map(|v|&v.id),"validated_at":view.as_ref().map(|v|v.validated_at),"stale":view.as_ref().is_none_or(|v|devres_domain::unix_now().saturating_sub(v.validated_at)>86400),"failure":self.store.whatwg_state("failure").await?,"archive_bytes":self.raw.accounted_bytes(),"archive_quota_bytes":self.raw.quota_bytes(),"historical_rendering":"source_snapshots_do_not_imply_rendered_publication_coverage"})).await
    }
    pub async fn status(&self) -> Result<Value> {
        self.store.whatwg_state("status").await?.ok_or_else(failure)
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
        ]
        .iter()
        .any(|extension| lower.ends_with(extension))
        || ["license", "copying", "notice"]
            .iter()
            .any(|prefix| basename.starts_with(prefix))
}

fn git_source_url(repository: &str, revision: &str) -> String {
    format!("https://github.com/{repository}/tree/{revision}")
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
    let url = publication.url.as_str();
    if standard.id == "nfc" && url.starts_with("https://w3c-cg.github.io/") {
        "predecessor"
    } else if url.contains("/review-drafts/") {
        "review-draft"
    } else if url.contains("/commit-snapshots/") {
        "commit-snapshot"
    } else if url.contains("/multipage/") {
        "multipage"
    } else if url.contains("/dev/") {
        "developer"
    } else if publication.url.kind() == catalog::PublicationKind::Pdf {
        "pdf"
    } else {
        "living"
    }
    .into()
}

impl WhatwgCorpus {
    pub async fn freeze(&self, cancel: CancellationToken) -> Result<Value> {
        self.freeze_mode("full", cancel).await
    }
    pub async fn freeze_current(&self, cancel: CancellationToken) -> Result<Value> {
        self.freeze_mode("current", cancel).await
    }
    async fn freeze_mode(&self, mode: &str, cancel: CancellationToken) -> Result<Value> {
        let _guard = self.processing.lock().await;
        let mut work: FreezeWork = if let Some(value) = self
            .store
            .whatwg_state("freezing")
            .await?
            .filter(|v| !v.is_null() && v["mode"] == mode)
        {
            decode(value)?
        } else {
            FreezeWork {
                catalog: self.acquire_catalog(cancel.clone()).await?,
                observations: BTreeMap::new(),
                publications: Vec::new(),
                mode: mode.into(),
                standard_offset: 0,
                queue: VecDeque::new(),
                seen: BTreeSet::new(),
            }
        };
        self.repair_freeze_metadata(&mut work, cancel.clone())
            .await?;
        while work.standard_offset < work.catalog.standards.len() {
            cancelled(&cancel)?;
            let standard = work.catalog.standards[work.standard_offset].clone();
            let current = catalog::current_publication(&standard)?;
            let publication = self
                .capture_publication(&standard, current, cancel.clone())
                .await?;
            work.seen.insert(publication.url.as_str().into());
            work.publications.push(publication.id.clone());
            let resolved = self.resolved_standard(&standard, &publication);
            let observation = self
                .observe_repository(&resolved.repository, cancel.clone())
                .await?;
            if mode == "full" {
                let paths = self
                    .git(&resolved.repository)?
                    .publication_paths(&observation, cancel.clone())
                    .await?;
                for url in catalog::source_publications(&resolved, &paths)? {
                    if work.seen.insert(url.as_str().into()) {
                        work.queue.push_back((resolved.id.clone(), url));
                    }
                }
            }
            work.observations.insert(resolved.id.clone(), observation);
            if mode == "full" {
                for url in catalog::advertised(&resolved, &publication.url, &publication.links) {
                    if work.seen.insert(url.as_str().into()) {
                        work.queue.push_back((resolved.id.clone(), url));
                    }
                }
            } else if standard.url != publication.url.as_str()
                && let Ok(url) = PublicationUrl::new(&standard.url)
                && work.seen.insert(url.as_str().into())
            {
                work.queue.push_back((resolved.id.clone(), url));
            }
            work.catalog.standards[work.standard_offset] = resolved;
            work.standard_offset += 1;
            self.store
                .whatwg_set_state("freezing", &encode(&work)?)
                .await?;
        }
        while let Some((standard_id, url)) = work.queue.front().cloned() {
            cancelled(&cancel)?;
            if work.seen.len() > MAX_PUBLICATIONS {
                return Err(Error::capacity(
                    "WHATWG publication inventory exceeds its bound.",
                ));
            }
            let standard = work
                .catalog
                .standards
                .iter()
                .find(|s| s.id == standard_id)
                .ok_or_else(failure)?;
            let publication = self
                .capture_publication(standard, url, cancel.clone())
                .await?;
            if mode == "full" {
                for url in catalog::advertised(standard, &publication.url, &publication.links) {
                    if work.seen.insert(url.as_str().into()) {
                        work.queue.push_back((standard_id.clone(), url));
                    }
                }
            }
            work.publications.push(publication.id);
            work.queue.pop_front();
            self.store
                .whatwg_set_state("freezing", &encode(&work)?)
                .await?;
        }
        work.catalog = self.retain_resolved_catalog(work.catalog).await?;
        let id = inventory::digest(
            &serde_json::to_vec(&(
                &work.catalog.id,
                &work.observations,
                &work.publications,
                mode,
            ))
            .map_err(|_| failure())?,
        );
        let frozen = Frozen {
            id: id.clone(),
            catalog: work.catalog,
            observations: work.observations,
            publications: work.publications,
            mode: mode.into(),
        };
        let value = encode(&frozen)?;
        self.store.whatwg_put("frozen", &id, &value).await?;
        self.store
            .whatwg_set_state("freezing", &Value::Null)
            .await?;
        Ok(value)
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
            .whatwg_get("frozen", &frozen.id)
            .await?
            .ok_or_else(|| Error::integrity("WHATWG frozen observation is not retained."))?;
        if retained.data != *value || (full && frozen.mode != "full") {
            return Err(Error::integrity("WHATWG frozen observation mismatch."));
        }
        let mut expected = 0;
        let mut processed = 0;
        let mut projection_gaps = 0_u64;
        let mut index_gaps = 0_u64;
        for standard in &frozen.catalog.standards {
            cancelled(&cancel)?;
            let observation = frozen.observations.get(&standard.id).ok_or_else(failure)?;
            let git = self.git(&standard.repository)?;
            git.restore(&observation.manifest, cancel.clone()).await?;
            let revision = observation
                .main_revision
                .as_deref()
                .ok_or_else(|| Error::integrity("WHATWG repository has no current branch."))?;
            while !self
                .process_commit(standard, observation, revision, cancel.clone())
                .await?
            {
                cancelled(&cancel)?;
            }
            let snapshot = self
                .snapshot_for_revision(&standard.id, &standard.repository, revision, "source")
                .await?
                .ok_or_else(failure)?;
            if self
                .store
                .whatwg_state(&state_key("current", &standard.id))
                .await?
                .is_none()
                && self.usable(&snapshot).await?
            {
                self.store
                    .whatwg_set_state(
                        &state_key("current", &standard.id),
                        &json!({"snapshot":snapshot.id,"validated_at":observation.observed_at}),
                    )
                    .await?;
            }
            if full {
                expected += observation.total_commits;
                let key = state_key(
                    "frozen-history",
                    &format!("{}:{}:{PROCESSOR_VERSION}", frozen.id, standard.id),
                );
                let mut offset = self
                    .store
                    .whatwg_state(&key)
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
                        self.store.whatwg_set_state(&key, &json!(offset)).await?;
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
                    .whatwg_get("publications", id)
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
                        .whatwg_set_state(
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
        self.publish_default(&frozen.catalog, cancel.clone())
            .await?;
        self.update_status().await?;
        let outcome = json!({"complete":processed==expected && publications_processed==frozen.publications.len() && unavailable==0 && index_gaps==0 && discovery_gaps==0,"mode":if full{"full"}else{"current"},"processor_version":PROCESSOR_VERSION,"catalog":frozen.catalog.id,"frozen":frozen.id,"standards":frozen.catalog.standards.len(),"git_commits_expected":expected,"git_commits_processed":processed,"publications_expected":frozen.publications.len(),"publications_processed":publications_processed,"unavailable_publications":unavailable,"projection_gaps":projection_gaps,"index_gaps":index_gaps,"discovery_gaps":discovery_gaps,"publication_inventory_complete":discovery_gaps==0,"projection_complete":projection_gaps==0,"scope":"frozen_catalog_refs_and_advertised_publications","rendering":"historical_sources_are_distinct_from_official_rendered_publications"});
        self.store
            .whatwg_put(
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
    async fn current_step(&self, cancel: CancellationToken) -> Result<()> {
        let _guard = self.processing.lock().await;
        let mut catalog = match self.catalog().await {
            Ok(catalog)
                if devres_domain::unix_now().saturating_sub(catalog.observed_at)
                    < self.config.catalog_refresh_secs as i64 =>
            {
                catalog
            }
            _ => self.acquire_catalog(cancel.clone()).await?,
        };
        let offset = self
            .store
            .whatwg_state("current-offset")
            .await?
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize
            % catalog.standards.len();
        let original = catalog.standards[offset].clone();
        self.store
            .whatwg_set_state(
                &state_key("current-attempt", &original.id),
                &json!({"attempted_at":devres_domain::unix_now()}),
            )
            .await?;
        let url = catalog::current_publication(&original)?;
        let previous = self
            .store
            .whatwg_state(&state_key("publication", url.as_str()))
            .await?
            .and_then(|v| v.as_str().map(str::to_owned));
        let previous: Option<Publication> = match previous {
            Some(id) => self
                .store
                .whatwg_get("publications", &id)
                .await?
                .map(|r| decode(r.data))
                .transpose()?,
            None => None,
        };
        let publication = if let Some(publication) = previous.filter(|p| {
            devres_domain::unix_now().saturating_sub(p.observed_at)
                < if p.status == 200 {
                    self.config.publication_refresh_secs as i64
                } else {
                    60
                }
        }) {
            publication
        } else {
            self.capture_publication(&original, url, cancel.clone())
                .await?
        };
        self.store
            .whatwg_set_state(
                &state_key("current-attempt", &original.id),
                &json!({"observed_at":publication.observed_at,"status":publication.status}),
            )
            .await?;
        let standard = self.resolved_standard(&original, &publication);
        if standard.repository != original.repository
            || original.metadata.get("repository_admission").is_none()
        {
            catalog.standards[offset] = standard.clone();
            catalog = self.retain_resolved_catalog(catalog).await?;
        }
        let key = state_key("observation", &standard.repository);
        let observation: Option<Observation> = self
            .store
            .whatwg_state(&key)
            .await?
            .map(decode)
            .transpose()?;
        let observation = if let Some(observation) = observation.filter(|o| {
            devres_domain::unix_now().saturating_sub(o.observed_at)
                < self.config.ref_refresh_secs as i64
        }) {
            observation
        } else {
            self.observe_repository(&standard.repository, cancel.clone())
                .await?
        };
        let revision = observation.main_revision.as_deref().ok_or_else(failure)?;
        if !self
            .process_commit(&standard, &observation, revision, cancel.clone())
            .await?
        {
            return Ok(());
        }
        if let Some(snapshot) = self
            .process_publication(&standard, &publication, cancel.clone())
            .await?
            && self.usable(&snapshot).await?
        {
            self.store
                .whatwg_set_state(
                    &state_key("current", &standard.id),
                    &json!({"snapshot":snapshot.id,"validated_at":publication.observed_at}),
                )
                .await?;
        }
        let mut frontier: Vec<String> = self
            .store
            .whatwg_state(&state_key("frontier", &standard.id))
            .await?
            .map(decode)
            .transpose()?
            .unwrap_or_default();
        let paths = self
            .git(&standard.repository)?
            .publication_paths(&observation, cancel.clone())
            .await?;
        for url in catalog::source_publications(&standard, &paths)? {
            if !frontier.iter().any(|s| s == url.as_str()) {
                frontier.push(url.as_str().into());
            }
        }
        for url in catalog::advertised(&standard, &publication.url, &publication.links) {
            if !frontier.iter().any(|s| s == url.as_str()) {
                frontier.push(url.as_str().into());
            }
        }
        if frontier.len() > MAX_PUBLICATIONS {
            return Err(Error::capacity(
                "WHATWG edition frontier exceeds its bound.",
            ));
        }
        self.store
            .whatwg_set_state(&state_key("frontier", &standard.id), &encode(&frontier)?)
            .await?;
        self.store
            .whatwg_set_state(
                "current-offset",
                &json!((offset + 1) % catalog.standards.len()),
            )
            .await?;
        self.publish_default(&catalog, cancel.clone()).await?;
        self.update_status().await
    }
    async fn history_step(&self, cancel: CancellationToken) -> Result<()> {
        let _guard = self.processing.lock().await;
        let Ok(catalog) = self.catalog().await else {
            return Ok(());
        };
        for standard in &catalog.standards {
            if self
                .store
                .whatwg_state(&state_key("current-attempt", &standard.id))
                .await?
                .is_none()
            {
                return Ok(());
            }
        }
        let offset = self
            .store
            .whatwg_state("history-offset")
            .await?
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize
            % catalog.standards.len();
        let standard = &catalog.standards[offset];
        let frontier_key = state_key("frontier", &standard.id);
        let mut frontier: Vec<String> = self
            .store
            .whatwg_state(&frontier_key)
            .await?
            .map(decode)
            .transpose()?
            .unwrap_or_default();
        if !frontier.is_empty() {
            let url = PublicationUrl::new(&frontier[0])?;
            let previous = self
                .store
                .whatwg_state(&state_key("publication", url.as_str()))
                .await?
                .and_then(|v| v.as_str().map(str::to_owned));
            let previous: Option<Publication> = match previous {
                Some(id) => self
                    .store
                    .whatwg_get("publications", &id)
                    .await?
                    .map(|row| decode(row.data))
                    .transpose()?,
                None => None,
            };
            let publication = if let Some(previous) = previous {
                let age = devres_domain::unix_now().saturating_sub(previous.observed_at);
                if previous.status == 200 {
                    Some(previous)
                } else if age >= if previous.status == 404 { 300 } else { 60 } {
                    Some(
                        self.capture_publication(standard, url, cancel.clone())
                            .await?,
                    )
                } else {
                    None
                }
            } else {
                Some(
                    self.capture_publication(standard, url, cancel.clone())
                        .await?,
                )
            };
            if let Some(publication) = publication {
                if publication.status == 200 {
                    self.process_publication(standard, &publication, cancel.clone())
                        .await?;
                    frontier.remove(0);
                    for url in catalog::advertised(standard, &publication.url, &publication.links) {
                        if self
                            .store
                            .whatwg_state(&state_key("publication", url.as_str()))
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
            self.store
                .whatwg_set_state(&frontier_key, &encode(&frontier)?)
                .await?;
        }
        if let Some(value) = self
            .store
            .whatwg_state(&state_key("observation", &standard.repository))
            .await?
        {
            let observation: Observation = decode(value)?;
            let git = self.git(&standard.repository)?;
            let key = state_key(
                "history",
                &format!("{}:{PROCESSOR_VERSION}", observation.manifest.body_hash),
            );
            let position = self
                .store
                .whatwg_state(&key)
                .await?
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let page = git
                .commit_page(&observation, position, 1, cancel.clone())
                .await?;
            if let Some(commit) = page.commits.first()
                && self
                    .process_commit(standard, &observation, &commit.revision, cancel.clone())
                    .await?
            {
                self.store
                    .whatwg_set_state(&key, &json!(page.next_offset))
                    .await?;
            }
        }
        self.store
            .whatwg_set_state(
                "history-offset",
                &json!((offset + 1) % catalog.standards.len()),
            )
            .await?;
        self.update_status().await
    }
    async fn record_failure(&self, lane: &str, error: &Error) -> Result<()> {
        self.store
            .whatwg_set_state(
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
                        .whatwg_state("current-offset")
                        .await?
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    self.store
                        .whatwg_set_state(
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
                        .whatwg_state("history-offset")
                        .await?
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    self.store
                        .whatwg_set_state(
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
        let cutoff = self.store.whatwg_cutoff().await?;
        let generation = self
            .store
            .whatwg_state("index-context")
            .await?
            .and_then(|v| v["generation"].as_u64())
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| Error::capacity("WHATWG index generation exhausted."))?;
        self.store
            .whatwg_set_state("index-checkpoint", &Value::Null)
            .await?;
        self.store
            .whatwg_set_state(
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
                .whatwg_rows("snapshots", after, 100, Some(cutoff))
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
                    .whatwg_set_state(
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
                .whatwg_rows("views", after, 100, Some(cutoff))
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
                    .whatwg_set_state(
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
            json!({"complete":true,"snapshots":snapshots,"views":views,"history_cutoff":cutoff,"index":self.store.whatwg_state("index").await?,"source_validation_unchanged":true,"original_index_evidence_preserved":true}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use devres_application::whatwg::{Row, Write, validate_whatwg_writes};
    use std::sync::{
        Mutex as StdMutex,
        atomic::{AtomicBool, Ordering},
    };
    #[derive(Default)]
    struct Memory {
        rows: StdMutex<BTreeMap<(String, String), Row>>,
        state: StdMutex<BTreeMap<String, Value>>,
    }
    #[async_trait]
    impl WhatwgStore for Memory {
        async fn whatwg_cutoff(&self) -> Result<i64> {
            Ok(self.rows.lock().expect("rows").len() as i64)
        }
        async fn whatwg_get(&self, kind: &str, key: &str) -> Result<Option<Row>> {
            Ok(self
                .rows
                .lock()
                .expect("rows")
                .get(&(kind.into(), key.into()))
                .cloned())
        }
        async fn whatwg_put(&self, kind: &str, key: &str, data: &Value) -> Result<i64> {
            let mut rows = self.rows.lock().expect("rows");
            if let Some(row) = rows.get(&(kind.into(), key.into())) {
                if row.data != *data {
                    return Err(Error::integrity("immutable collision"));
                }
                return Ok(row.sequence);
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
            validate_whatwg_writes(rows)?;
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
                .expect("rows")
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
            Ok(self.state.lock().expect("state").get(key).cloned())
        }
        async fn whatwg_set_state(&self, key: &str, data: &Value) -> Result<()> {
            self.state
                .lock()
                .expect("state")
                .insert(key.into(), data.clone());
            Ok(())
        }
        async fn whatwg_publish_view(&self, view: &View) -> Result<()> {
            self.whatwg_put("views", &view.id, &encode(view)?).await?;
            self.whatwg_set_state("default", &encode(view)?).await
        }
    }
    #[tokio::test]
    async fn source_history_current_failures_compaction_frozen_replay_and_offline_restore() {
        let _gate = crate::mdn_index::TEST_GATE.lock().await;
        use crate::whatwg_git::tests as git_fixture;
        let source_root = tempfile::tempdir().expect("source");
        let source = Arc::new(
            WhatwgGit::new(
                source_root.path(),
                Repo::new("whatwg/fixture").expect("repository"),
                64 * 1024 * 1024,
                64 * 1024 * 1024,
                None,
            )
            .expect("source Git"),
        );
        git_fixture::fixture_init(&source).await;
        let first=git_fixture::commit_files(&source,&[("dom.bs",b"<h2 id=stable>Stable</h2><p>Stable clause.</p><h2 id=change>Change</h2><p>First clause.</p>"),("LICENSE",b"Synthetic fixture license")],&[]).await;
        git_fixture::update(&source, "refs/heads/main", &first).await;
        let broken = Arc::new(AtomicBool::new(false));
        let reply = broken.clone();
        let router=git_fixture::fixture_router(source.clone()).route("/",axum::routing::get(move ||{let broken=reply.clone();async move {
            let bytes=if broken.load(Ordering::Acquire){vec![0xff]}else{b"<!doctype html><html><head><title>DOM fixture</title></head><body><dl><dt>Participate:<dd><a href=https://github.com/whatwg/fixture>GitHub</a></dl><h2 id=stable>Stable</h2><p>Stable published clause.</p><a href=/review-drafts/2026-07/>Draft</a></body></html>".to_vec()};
            ([(axum::http::header::CONTENT_TYPE,"text/html")],bytes)
        }}));
        let (broker, server) = git_fixture::serve_fixture(router).await;
        let target = tempfile::tempdir().expect("target");
        let store = Arc::new(Memory::default());
        let config = WhatwgConfig {
            enabled: false,
            publication_refresh_secs: 1,
            max_git_bytes: 64 * 1024 * 1024,
            min_free_bytes: 64 * 1024 * 1024,
            ..WhatwgConfig::default()
        };
        let corpus =
            WhatwgCorpus::new(store.clone(), broker.clone(), target.path(), config.clone())
                .expect("corpus");
        let standard = Standard {
            id: "dom".into(),
            title: "DOM fixture".into(),
            url: "https://dom.spec.whatwg.org/".into(),
            repository: "whatwg/fixture".into(),
            metadata: json!({}),
        };
        let catalog = Catalog {
            id: inventory::digest(b"synthetic catalog"),
            observed_at: devres_domain::unix_now(),
            standards: vec![standard.clone()],
            gaps: Vec::new(),
        };
        store
            .whatwg_put("catalogs", &catalog.id, &encode(&catalog).expect("catalog"))
            .await
            .expect("retain catalog");
        store
            .whatwg_set_state("catalog", &json!(catalog.id))
            .await
            .expect("catalog pointer");
        let observation = corpus
            .observe_repository(&standard.repository, CancellationToken::new())
            .await
            .expect("observe");
        while !corpus
            .process_commit(&standard, &observation, &first, CancellationToken::new())
            .await
            .expect("process first")
        {}
        let first_snapshot = corpus
            .snapshot_for_revision("dom", &standard.repository, &first, "source")
            .await
            .expect("snapshot")
            .expect("published snapshot");
        let first_ids = corpus
            .search_members(&first_snapshot)
            .await
            .expect("first members");
        assert!(!first_ids.is_empty());
        corpus
            .current_step(CancellationToken::new())
            .await
            .expect("initial current");
        let prior = corpus.view(None).await.expect("view");
        let prior_id = prior.snapshots["dom"].clone();
        broken.store(true, Ordering::Release);
        tokio::time::sleep(Duration::from_secs(1)).await;
        corpus
            .current_step(CancellationToken::new())
            .await
            .expect("failed projection retained");
        assert_eq!(
            corpus.view(None).await.expect("retained view").snapshots["dom"],
            prior_id
        );
        let second=git_fixture::commit_files(&source,&[("dom.bs",b"<h2 id=stable>Stable</h2><p>Stable clause.</p><h2 id=change>Change</h2><p>Second clause.</p>"),("LICENSE",b"Synthetic fixture license")],&[&first]).await;
        git_fixture::update(&source, "refs/heads/main", &second).await;
        let side = git_fixture::commit_files(
            &source,
            &[
                ("dom.bs", b"<h2 id=side>Branch-only clause</h2>"),
                ("LICENSE", b"Synthetic fixture license"),
            ],
            &[&first],
        )
        .await;
        git_fixture::update(&source, "refs/heads/side", &side).await;
        let observation = corpus
            .observe_repository(&standard.repository, CancellationToken::new())
            .await
            .expect("observe second and unprocessed side branch");
        let mut context = store
            .whatwg_state("index-context")
            .await
            .expect("context")
            .expect("context");
        context["count"] = json!(2048);
        store
            .whatwg_set_state("index-context", &context)
            .await
            .expect("force retained compaction boundary");
        while !corpus
            .process_commit(&standard, &observation, &second, CancellationToken::new())
            .await
            .expect("process second")
        {}
        let second_snapshot = corpus
            .snapshot_for_revision("dom", &standard.repository, &second, "source")
            .await
            .expect("snapshot")
            .expect("published snapshot");
        let second_ids = corpus
            .search_members(&second_snapshot)
            .await
            .expect("second members");
        assert!(
            first_ids.intersection(&second_ids).count() > 0,
            "unchanged sections share index identities"
        );
        assert_eq!(
            store
                .whatwg_state("index-context")
                .await
                .expect("context")
                .expect("context")["generation"],
            1
        );
        let search = corpus
            .index
            .search(
                &first_snapshot.index,
                first_ids,
                crate::whatwg_index::SearchSpec {
                    query: Some("stable".into()),
                    ..Default::default()
                },
                CancellationToken::new(),
            )
            .await
            .expect("old index retained");
        assert!(search["total"].as_u64().expect("count") > 0);
        let current = corpus.snapshot(&prior_id).await.expect("prior snapshot");
        let publication = current.coverage["publication"]
            .as_str()
            .expect("publication")
            .to_owned();
        let frozen = Frozen {
            id: inventory::digest(b"synthetic frozen"),
            catalog: catalog.clone(),
            observations: BTreeMap::from([("dom".into(), observation)]),
            publications: vec![publication],
            mode: "full".into(),
        };
        let legacy_history = state_key("frozen-history", &format!("{}:dom", frozen.id));
        let legacy_offset = frozen.observations["dom"].commits.bytes;
        store
            .whatwg_set_state(&legacy_history, &json!(legacy_offset))
            .await
            .expect("legacy completed v1 checkpoint");
        let legacy_acceptance_key = format!("{}:full", frozen.id);
        let legacy_acceptance = json!({"complete":true,"processor_version":1});
        store
            .whatwg_put("acceptance", &legacy_acceptance_key, &legacy_acceptance)
            .await
            .expect("immutable v1 acceptance evidence");
        assert!(
            corpus
                .snapshot_for_revision("dom", &standard.repository, &side, "source")
                .await
                .expect("side absent")
                .is_none()
        );
        let frozen = encode(&frozen).expect("frozen");
        store
            .whatwg_put("frozen", frozen["id"].as_str().expect("id"), &frozen)
            .await
            .expect("retain frozen");
        let attempts = broker.attempt_count();
        let outcome = corpus
            .accept_frozen(&frozen, CancellationToken::new())
            .await
            .expect("offline acceptance");
        assert_eq!(outcome["complete"], true);
        assert_eq!(outcome["git_commits_processed"], 3);
        assert_eq!(outcome["processor_version"], 2);
        assert_eq!(
            store
                .whatwg_state(&legacy_history)
                .await
                .expect("legacy checkpoint"),
            Some(json!(legacy_offset))
        );
        assert_eq!(
            store
                .whatwg_get("acceptance", &legacy_acceptance_key)
                .await
                .expect("legacy acceptance")
                .expect("retained v1")
                .data,
            legacy_acceptance
        );
        assert_eq!(
            corpus
                .snapshot_for_revision("dom", &standard.repository, &side, "source")
                .await
                .expect("side processed")
                .expect("v2 side")
                .processor_version,
            2
        );
        assert_eq!(
            broker.attempt_count(),
            attempts,
            "frozen replay performs no source traffic"
        );
        let publication_id = current.coverage["publication"]
            .as_str()
            .expect("publication");
        let mut incomplete: Publication = decode(
            store
                .whatwg_get("publications", publication_id)
                .await
                .expect("read publication")
                .expect("publication")
                .data,
        )
        .expect("publication");
        incomplete.id = inventory::digest(b"synthetic metadata discovery gap");
        incomplete.metadata_version = 0;
        incomplete.links.clear();
        incomplete.repositories.clear();
        incomplete.gaps.push("publication_metadata_capacity".into());
        store
            .whatwg_put(
                "publications",
                &incomplete.id,
                &encode(&incomplete).expect("publication"),
            )
            .await
            .expect("retain raw publication with discovery gap");
        let mut incomplete_frozen: Frozen = decode(frozen.clone()).expect("frozen");
        incomplete_frozen.id = inventory::digest(b"synthetic incomplete discovery freeze");
        incomplete_frozen.publications = vec![incomplete.id.clone()];
        let incomplete_frozen = encode(&incomplete_frozen).expect("frozen");
        store
            .whatwg_put(
                "frozen",
                incomplete_frozen["id"].as_str().expect("id"),
                &incomplete_frozen,
            )
            .await
            .expect("retain incomplete inventory");
        let incomplete_outcome = corpus
            .accept_frozen(&incomplete_frozen, CancellationToken::new())
            .await
            .expect("report incomplete discovery");
        assert_eq!(incomplete_outcome["complete"], false);
        assert_eq!(incomplete_outcome["discovery_gaps"], 1);
        assert_eq!(incomplete_outcome["publication_inventory_complete"], false);
        let incomplete_snapshot = corpus
            .snapshot_for_revision("dom", incomplete.url.as_str(), &incomplete.id, "html")
            .await
            .expect("lookup")
            .expect("raw retained snapshot");
        assert!(
            corpus
                .raw_page(&incomplete_snapshot, "index.html", 0, 32768)
                .await
                .expect("raw remains readable")["base64"]
                .as_str()
                .is_some_and(|s| !s.is_empty())
        );
        let original_row = store
            .whatwg_get("publications", &incomplete.id)
            .await
            .expect("original publication")
            .expect("retained original")
            .data;
        let frozen_work: Frozen = decode(incomplete_frozen.clone()).expect("frozen");
        let original_observations = encode(&frozen_work.observations).expect("observations");
        let mut work = FreezeWork {
            catalog: frozen_work.catalog,
            observations: frozen_work.observations,
            publications: frozen_work.publications,
            mode: "full".into(),
            standard_offset: 1,
            queue: VecDeque::new(),
            seen: BTreeSet::from([incomplete.url.as_str().to_owned()]),
        };
        let attempts_before_repair = broker.attempt_count();
        corpus
            .repair_freeze_metadata(&mut work, CancellationToken::new())
            .await
            .expect("offline metadata repair");
        assert_eq!(broker.attempt_count(), attempts_before_repair);
        assert_eq!(
            encode(&work.observations).expect("observations"),
            original_observations
        );
        assert_ne!(work.publications[0], incomplete.id);
        assert!(
            work.queue.iter().any(
                |(_, url)| url.as_str() == "https://dom.spec.whatwg.org/review-drafts/2026-07/"
            )
        );
        let repaired: Publication = decode(
            store
                .whatwg_get("publications", &work.publications[0])
                .await
                .expect("repaired")
                .expect("repaired")
                .data,
        )
        .expect("repaired");
        assert_eq!(repaired.observed_at, incomplete.observed_at);
        assert_eq!(
            encode(&repaired.artifact).expect("artifact"),
            encode(&incomplete.artifact).expect("artifact")
        );
        assert_eq!(
            repaired.metadata_parent.as_deref(),
            Some(incomplete.id.as_str())
        );
        assert_eq!(repaired.metadata_version, catalog::METADATA_VERSION);
        assert!(
            repaired
                .gaps
                .iter()
                .all(|gap| !gap.starts_with("publication_metadata_"))
        );
        assert_eq!(
            store
                .whatwg_get("publications", &incomplete.id)
                .await
                .expect("original")
                .expect("retained")
                .data,
            original_row
        );
        let repository = corpus.git(&standard.repository).expect("git").repository();
        std::fs::remove_dir_all(repository).expect("remove disposable mirror");
        let page = corpus
            .raw_page(&first_snapshot, "dom.bs", 0, 32768)
            .await
            .expect("restore raw offline");
        assert!(
            String::from_utf8(
                STANDARD
                    .decode(page["base64"].as_str().expect("bytes"))
                    .expect("base64")
            )
            .expect("text")
            .contains("First clause")
        );
        drop(corpus);
        let restarted = WhatwgCorpus::new(store, broker, target.path(), config).expect("restart");
        restarted
            .recover(CancellationToken::new())
            .await
            .expect("offline recovery");
        let _ = restarted
            .select("dom", Some(&first_snapshot.id), None)
            .await
            .expect("historical snapshot readable");
        server.abort();
        let _ = server.await;
    }
    #[tokio::test]
    async fn restart_quota_counts_orphaned_owned_repositories_without_observations() {
        let root = tempfile::tempdir().expect("owned corpus root");
        let mut bytes = 0;
        for identity in ["whatwg/first-orphan", "foreign/second-orphan"] {
            let git = WhatwgGit::new(
                root.path(),
                Repo::new(identity).expect("identity"),
                64 * 1024 * 1024,
                64 * 1024 * 1024,
                None,
            )
            .expect("owned Git");
            crate::whatwg_git::tests::fixture_init(&git).await;
            let artifact = git
                .artifacts()
                .capture_bytes(identity.as_bytes().to_vec(), CancellationToken::new())
                .await
                .expect("orphaned permanent pack fixture");
            bytes += artifact.bytes;
        }
        let store = Arc::new(Memory::default());
        let broker = Arc::new(BulkBroker::new(Default::default()).expect("broker"));
        let config = WhatwgConfig {
            enabled: false,
            min_free_bytes: 64 * 1024 * 1024,
            max_archive_storage_bytes: Some(64 * 1024 * 1024),
            ..Default::default()
        };
        let corpus = WhatwgCorpus::new(store.clone(), broker.clone(), root.path(), config.clone())
            .expect("startup accounting");
        assert_eq!(corpus.raw.accounted_bytes(), Some(bytes));
        assert_eq!(store.whatwg_cutoff().await.expect("empty evidence"), 0);
        drop(corpus);
        let restarted =
            WhatwgCorpus::new(store.clone(), broker.clone(), root.path(), config.clone())
                .expect("restart accounting");
        assert_eq!(restarted.raw.accounted_bytes(), Some(bytes));
        drop(restarted);
        std::fs::create_dir_all(root.path().join("whatwg/git/unknown/unowned/artifacts"))
            .expect("unowned fixture");
        assert_eq!(
            WhatwgCorpus::new(store, broker, root.path(), config)
                .err()
                .expect("unowned path rejected")
                .code,
            "integrity"
        );
    }
    #[test]
    fn source_projection_admission_matches_supported_processor_formats() {
        for path in [
            "source",
            "nested/source",
            "index.BS",
            "chapter.WATTSI",
            "page.HTM",
            "guide.MARKDOWN",
            "guide.MD",
            "api.IDL",
            "data.TXT",
            "draft.PDF",
            "NOTICE",
            "nested/NOTICE.txt",
            "license-MIT",
            "COPYING",
        ] {
            assert!(supported_path(path), "{path}");
        }
        for path in ["Source", "package.json", "script.js", "run.sh", "image.png"] {
            assert!(!supported_path(path), "{path}");
        }
    }
    async fn retained_fixture_publication(
        corpus: &WhatwgCorpus,
        standard: &Standard,
        body: &[u8],
    ) -> Publication {
        let artifact = corpus
            .raw
            .capture_bytes(body.to_vec(), CancellationToken::new())
            .await
            .expect("fixture bytes");
        let publication = Publication {
            id: inventory::digest(format!("{}:{}", standard.id, artifact.body_hash).as_bytes()),
            standard: standard.id.clone(),
            url: PublicationUrl::new(&standard.url).expect("URL"),
            observed_at: devres_domain::unix_now(),
            chunk_hashes: corpus
                .publication_chunks(&artifact, CancellationToken::new())
                .await
                .expect("chunks"),
            artifact: Some(artifact),
            status: 200,
            links: Vec::new(),
            gaps: Vec::new(),
            repositories: Vec::new(),
            metadata_version: catalog::METADATA_VERSION,
            metadata_parent: None,
        };
        corpus
            .store
            .whatwg_put(
                "publications",
                &publication.id,
                &encode(&publication).expect("publication"),
            )
            .await
            .expect("fixture retained");
        publication
    }
    #[tokio::test]
    async fn first_default_view_seals_all_current_heads_after_bootstrap_rollover() {
        let _gate = crate::mdn_index::TEST_GATE.lock().await;
        let root = tempfile::tempdir().expect("root");
        let store = Arc::new(Memory::default());
        let broker = Arc::new(BulkBroker::new(Default::default()).expect("broker"));
        let corpus = WhatwgCorpus::new(
            store.clone(),
            broker,
            root.path(),
            WhatwgConfig {
                enabled: false,
                min_free_bytes: 64 * 1024 * 1024,
                ..Default::default()
            },
        )
        .expect("corpus");
        let alpha = Standard {
            id: "alpha".into(),
            title: "Alpha".into(),
            url: "https://alpha.spec.whatwg.org/".into(),
            repository: "whatwg/alpha".into(),
            metadata: json!({}),
        };
        let beta = Standard {
            id: "beta".into(),
            title: "Beta".into(),
            url: "https://beta.spec.whatwg.org/".into(),
            repository: "whatwg/beta".into(),
            metadata: json!({}),
        };
        let a_pub =
            retained_fixture_publication(&corpus, &alpha, b"<h2 id=a>Alpha</h2><p>alphafrozen</p>")
                .await;
        let a = corpus
            .process_publication(&alpha, &a_pub, CancellationToken::new())
            .await
            .expect("alpha")
            .expect("alpha snapshot");
        store
            .whatwg_set_state(
                &state_key("current", "alpha"),
                &json!({"snapshot":a.id,"validated_at":a.validated_at}),
            )
            .await
            .expect("current alpha without view");
        assert!(corpus.view(None).await.is_err());
        let mut context = store
            .whatwg_state("index-context")
            .await
            .expect("context")
            .expect("context");
        context["count"] = json!(2048);
        store
            .whatwg_set_state("index-context", &context)
            .await
            .expect("force rollover");
        let b_pub =
            retained_fixture_publication(&corpus, &beta, b"<h2 id=b>Beta</h2><p>betafrozen</p>")
                .await;
        let b = corpus
            .process_publication(&beta, &b_pub, CancellationToken::new())
            .await
            .expect("beta")
            .expect("beta snapshot");
        store
            .whatwg_set_state(
                &state_key("current", "beta"),
                &json!({"snapshot":b.id,"validated_at":b.validated_at}),
            )
            .await
            .expect("current beta");
        assert_eq!(
            store
                .whatwg_state("index-context")
                .await
                .expect("context")
                .expect("context")["generation"],
            1
        );
        let catalog = Catalog {
            id: inventory::digest(b"two current heads"),
            observed_at: devres_domain::unix_now(),
            standards: vec![alpha, beta],
            gaps: Vec::new(),
        };
        store
            .whatwg_put("catalogs", &catalog.id, &encode(&catalog).expect("catalog"))
            .await
            .expect("catalog");
        corpus
            .publish_default(&catalog, CancellationToken::new())
            .await
            .expect("seal complete union");
        let view = corpus.view(None).await.expect("first view");
        assert_eq!(view.snapshots.len(), 2);
        let mut members = corpus.search_members(&a).await.expect("alpha IDs");
        members.extend(corpus.search_members(&b).await.expect("beta IDs"));
        for (query, standard) in [("alphafrozen", "alpha"), ("betafrozen", "beta")] {
            let result = corpus
                .index
                .search(
                    &view.index,
                    members.clone(),
                    crate::whatwg_index::SearchSpec {
                        query: Some(query.into()),
                        ..Default::default()
                    },
                    CancellationToken::new(),
                )
                .await
                .expect("both bootstrap heads remain searchable");
            assert_eq!(result["total"], 1);
            assert_eq!(result["results"][0]["standard"], standard);
        }
    }
    #[tokio::test]
    async fn advertised_data_formats_keep_raw_identity_without_html_metadata() {
        let _gate = crate::mdn_index::TEST_GATE.lock().await;
        let router=axum::Router::new().route("/review-drafts/{name}",axum::routing::get(|axum::extract::Path(name):axum::extract::Path<String>,headers:axum::http::HeaderMap|async move{
            let (mime,body)=match name.as_str(){
                "data.txt"=>("text/plain",b"<meta name=repository content=https://github.com/evil/example><a href=/review-drafts/fake/>plain literal text</a>".to_vec()),
                "api.idl"=>("text/plain",b"interface Fixture {};".to_vec()),
                "data.json"=>("application/json",serde_json::to_vec(&json!({"example":"<meta name=repository content=https://github.com/evil/example><a href=/review-drafts/fake/>data</a>"})).expect("JSON")),
                _=>("application/octet-stream",vec![0xff,0x00,0x01]),
            };
            if headers.get(axum::http::header::ACCEPT).and_then(|v|v.to_str().ok())!=Some(mime){return(axum::http::StatusCode::BAD_REQUEST,Vec::new());}
            (axum::http::StatusCode::OK,body)
        }));
        let (broker, server) = crate::whatwg_git::tests::serve_fixture(router).await;
        let root = tempfile::tempdir().expect("root");
        let store = Arc::new(Memory::default());
        let corpus = WhatwgCorpus::new(
            store,
            broker,
            root.path(),
            WhatwgConfig {
                enabled: false,
                min_free_bytes: 64 * 1024 * 1024,
                ..Default::default()
            },
        )
        .expect("corpus");
        let standard = Standard {
            id: "encoding".into(),
            title: "Encoding fixture".into(),
            url: "https://encoding.spec.whatwg.org/".into(),
            repository: "whatwg/encoding".into(),
            metadata: json!({}),
        };
        for (name, family, projected) in [
            ("data.txt", "text", true),
            ("api.idl", "text", true),
            ("data.json", "json", false),
            ("opaque.bin", "raw", false),
        ] {
            let url = PublicationUrl::new(&format!(
                "https://encoding.spec.whatwg.org/review-drafts/{name}"
            ))
            .expect("URL");
            let publication = corpus
                .capture_publication(&standard, url, CancellationToken::new())
                .await
                .expect("capture");
            assert_eq!(publication.status, 200);
            assert!(publication.links.is_empty());
            assert!(publication.repositories.is_empty());
            let snapshot = corpus
                .process_publication(&standard, &publication, CancellationToken::new())
                .await
                .expect("process family")
                .expect("snapshot");
            assert_eq!(snapshot.representation, family);
            let path = format!("review-drafts/{name}");
            assert_eq!(
                corpus
                    .projection(&snapshot, &path)
                    .await
                    .expect("projection")
                    .is_some(),
                projected
            );
            assert!(
                corpus
                    .raw_page(&snapshot, &path, 0, 32768)
                    .await
                    .expect("raw bytes")["base64"]
                    .is_string()
            );
            if !projected {
                assert!(
                    snapshot.coverage["gaps"]
                        .as_array()
                        .expect("gaps")
                        .iter()
                        .any(|g| g == "unsupported_publication_projection")
                );
            }
        }
        server.abort();
        let _ = server.await;
    }
}
