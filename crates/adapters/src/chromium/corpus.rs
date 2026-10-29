//! Resumable documentation-only Chromium collection and immutable local evidence.
use crate::{
    bulk::{self, BulkArtifact, BulkArtifactStore, BulkBroker},
    chromium::index::{ChromiumIndex, IndexDocument},
    chromium::inventory,
    chromium::processing as chromium_processing,
    chromium::source::{self as source, ChromiumSource, Commit, Directory, Entry, Operation},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use devres_application::chromium::{
    Catalog, ChromiumConfig, ChromiumStore, Component, Member, PROCESSOR_VERSION, Snapshot, View,
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
use tokio::{
    io::{AsyncReadExt, AsyncSeekExt},
    sync::{Mutex, Semaphore},
    time::Instant,
};
use tokio_util::sync::CancellationToken;

mod collection;
mod licensing;
#[path = "corpus/migration.rs"]
mod migration;
#[cfg(test)]
mod tests;

const MAX_SOURCE: usize = 64 * 1024 * 1024;
const MAX_PROJECTION: u64 = 256 * 1024 * 1024;
// Per-selection/reconstruction admission, not a total-history cutoff.
const MAX_MEMBERS: usize = 1_000_000;
const COMPONENTS: [&str; 4] = ["src", "site", "chrome", "chrome-archive"];

pub struct ChromiumCorpus {
    store: Arc<dyn ChromiumStore>,
    source: ChromiumSource,
    config: ChromiumConfig,
    raw: Arc<BulkArtifactStore>,
    index: ChromiumIndex,
    processing: Mutex<()>,
    processors: Arc<Semaphore>,
}
fn failure() -> Error {
    Error::unavailable("Chromium evidence unavailable.")
}
fn cancelled(cancel: &CancellationToken) -> Result<()> {
    if cancel.is_cancelled() {
        Err(Error::new("cancelled", "Chromium operation canceled."))
    } else {
        Ok(())
    }
}
fn encode<T: Serialize>(value: &T) -> Result<Value> {
    inventory::value(value)
}
fn decode<T: serde::de::DeserializeOwned>(value: Value) -> Result<T> {
    inventory::decode(value)
}
fn state_key(kind: &str, id: &str) -> String {
    // Preserve mutable scheduling lookup names; payloads use BLAKE3 integrity.
    format!("{kind}:{}", crate::integrity::legacy_hash(id.as_bytes()))
}
fn alias(
    component: &str,
    repository: &str,
    revision: &str,
    representation: &str,
) -> Result<String> {
    Ok(inventory::digest(
        &serde_json::to_vec(&(
            component,
            repository,
            revision,
            representation,
            PROCESSOR_VERSION,
        ))
        .map_err(|_| failure())?,
    ))
}
fn text_chunks(value: &str, max: usize) -> Vec<&str> {
    let mut output = Vec::new();
    let mut offset = 0;
    while offset < value.len() {
        let mut end = (offset + max).min(value.len());
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        output.push(&value[offset..end]);
        offset = end;
    }
    output
}
fn component(id: &str) -> Result<Component> {
    let (title, url, repository) = match id {
        "src" => (
            "Chromium source documentation",
            "https://chromium.googlesource.com/chromium/src/+/HEAD/docs/README.md",
            "https://chromium.googlesource.com/chromium/src",
        ),
        "site" => (
            "Chromium project website",
            "https://www.chromium.org/",
            "https://chromium.googlesource.com/website",
        ),
        "chrome" => (
            "Chrome for Developers",
            "https://developer.chrome.com/",
            "https://developer.chrome.com/",
        ),
        "chrome-archive" => (
            "Archived Chrome developer documentation",
            "https://github.com/GoogleChrome/developer.chrome.com",
            "https://github.com/GoogleChrome/developer.chrome.com",
        ),
        _ => return Err(Error::invalid("Unknown Chromium component.")),
    };
    Ok(Component {
        id: id.into(),
        title: title.into(),
        url: url.into(),
        repository: repository.into(),
        metadata: json!({"historical_only":id=="chrome-archive","language":"en","classifier_version":PROCESSOR_VERSION}),
    })
}
impl ChromiumCorpus {
    /// Construct frozen-graph verification handles without initializing storage.
    pub(crate) fn for_verification(
        store: Arc<dyn ChromiumStore>,
        broker: Arc<BulkBroker>,
        root: &Path,
        config: ChromiumConfig,
    ) -> Result<Self> {
        config.validate()?;
        let raw = Arc::new(BulkArtifactStore::for_verification(
            root.join("chromium/raw-artifacts"),
            config.min_free_bytes,
        )?);
        Ok(Self {
            store,
            source: ChromiumSource::new(broker)?,
            index: ChromiumIndex::for_verification(root)?,
            processors: Arc::new(Semaphore::new(config.max_processing_workers)),
            config,
            raw,
            processing: Mutex::new(()),
        })
    }
    pub fn new(
        store: Arc<dyn ChromiumStore>,
        broker: Arc<BulkBroker>,
        root: &Path,
        config: ChromiumConfig,
    ) -> Result<Self> {
        config.validate()?;
        std::fs::create_dir_all(root.join("chromium/raw-artifacts")).map_err(|_| failure())?;
        let raw = Arc::new(
            BulkArtifactStore::new(root.join("chromium/raw-artifacts"), config.min_free_bytes)?
                .with_quota(config.max_archive_storage_bytes)?,
        );
        Ok(Self {
            store,
            source: ChromiumSource::new(broker)?,
            index: ChromiumIndex::new(root)?,
            processors: Arc::new(Semaphore::new(config.max_processing_workers)),
            config,
            raw,
            processing: Mutex::new(()),
        })
    }
    pub fn store(&self) -> Arc<dyn ChromiumStore> {
        self.store.clone()
    }
    pub fn index(&self) -> &ChromiumIndex {
        &self.index
    }
    pub fn artifacts(&self) -> &Arc<BulkArtifactStore> {
        &self.raw
    }
    /// Pure bounded qualification for private probes; this performs no I/O.
    pub fn qualify_license(component: &str, body: &[u8], source_url: &str) -> Result<Value> {
        if body.len() > MAX_SOURCE || source_url.len() > 4096 {
            return Err(Error::capacity("Chromium license input exceeds its bound."));
        }
        let text = std::str::from_utf8(body)
            .map_err(|_| Error::integrity("Chromium license notice is not UTF-8."))?;
        Ok(licensing::qualify(component, text, source_url))
    }
    pub fn config(&self) -> &ChromiumConfig {
        &self.config
    }
    pub async fn initialize_status(&self) -> Result<()> {
        self.update_status().await
    }
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
        let mut whole_blake3 = blake3::Hasher::new();
        let mut chunks = Vec::new();
        let mut remaining = artifact.bytes;
        while remaining > 0 {
            cancelled(&cancel)?;
            let size = remaining.min(4 * 1024 * 1024) as usize;
            let mut bytes = vec![0; size];
            file.read_exact(&mut bytes).await.map_err(|_| failure())?;
            whole.update(&bytes);
            whole_blake3.update(&bytes);
            chunks.push(inventory::digest(&bytes));
            remaining -= size as u64;
        }
        let observed = if artifact.body_hash.starts_with("blake3:") {
            format!("blake3:{}", whole_blake3.finalize().to_hex())
        } else {
            hex::encode(whole.finalize())
        };
        if observed != artifact.body_hash {
            return Err(Error::integrity(
                "Chromium raw range proof differs from retained artifact.",
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
            || !crate::integrity::valid_hash(&artifact.body_hash)
            || chunks.len() as u64 != artifact.bytes.div_ceil(BLOCK)
        {
            return Err(Error::integrity("Invalid Chromium raw range proof."));
        }
        let path = self
            .raw
            .root()
            .join(crate::integrity::relative_path(&artifact.body_hash)?);
        if !artifact.body_hash.starts_with("blake3:") {
            let legacy_path = path.clone();
            tokio::task::spawn_blocking(move || {
                crate::integrity::verify_legacy_file(
                    &legacy_path,
                    std::time::Instant::now() + Duration::from_secs(15),
                )
            })
            .await
            .map_err(|_| failure())??;
        }
        let metadata = tokio::fs::symlink_metadata(&path)
            .await
            .map_err(|_| failure())?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() != artifact.bytes
        {
            return Err(Error::integrity("Invalid retained Chromium raw artifact."));
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
            if chunks
                .get(block as usize)
                .is_none_or(|expected| crate::integrity::verify(expected, &bytes).is_err())
            {
                return Err(Error::integrity("Chromium raw range checksum mismatch."));
            }
            let from = (position - start) as usize;
            let to = ((end - start).min(size as u64)) as usize;
            page.extend_from_slice(&bytes[from..to]);
            position = start + to as u64;
        }
        Ok(page)
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
            let rows = self.store.chromium_get_many(kind, chunk).await?;
            if rows.len() != chunk.len() {
                return Err(Error::integrity(
                    "Chromium shared projection object is missing.",
                ));
            }
            for row in rows {
                let encoded = serde_json::to_vec(&row.data).map_err(|_| failure())?;
                bytes += encoded.len();
                if bytes as u64 > MAX_PROJECTION {
                    return Err(Error::capacity(
                        "Chromium projection reconstruction exceeds its bound.",
                    ));
                }
                if crate::integrity::verify(&row.key, &encoded).is_err() {
                    return Err(Error::integrity(
                        "Chromium shared projection object hash mismatch.",
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
                        "Chromium reconstructed text exceeds its bound.",
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
                    .ok_or_else(|| std::io::Error::other("Chromium reconstruction size"))?;
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        serde_json::to_writer(Counter(0), &value).map_err(|_| {
            Error::capacity("Chromium reconstructed projection exceeds its byte bound.")
        })?;
        Ok(value)
    }
    pub async fn catalog(&self) -> Result<Catalog> {
        let id = self
            .store
            .chromium_state("catalog")
            .await?
            .and_then(|v| v.as_str().map(str::to_owned))
            .ok_or_else(failure)?;
        decode(
            self.store
                .chromium_get("catalogs", &id)
                .await?
                .ok_or_else(failure)?
                .data,
        )
    }
    pub async fn snapshot(&self, id: &str) -> Result<Snapshot> {
        let snapshot: Snapshot = decode(
            self.store
                .chromium_get("snapshots", id)
                .await?
                .ok_or_else(|| Error::not_found("Chromium snapshot not found."))?
                .data,
        )?;
        Ok(snapshot)
    }
    pub async fn snapshot_for_revision(
        &self,
        component: &str,
        repository: &str,
        revision: &str,
        representation: &str,
    ) -> Result<Option<Snapshot>> {
        let key = alias(component, repository, revision, representation)?;
        if let Some(value) = self
            .store
            .chromium_state(&state_key("revision-alias", &key))
            .await?
        {
            return Ok(Some(
                self.snapshot(value.as_str().ok_or_else(failure)?).await?,
            ));
        }
        match self.store.chromium_get("snapshot-keys", &key).await? {
            Some(row) => Ok(Some(
                self.snapshot(row.data.as_str().ok_or_else(failure)?)
                    .await?,
            )),
            None => Ok(None),
        }
    }
    pub async fn view(&self, id: Option<&str>) -> Result<View> {
        let view: View = match id {
            Some(id) => decode(
                self.store
                    .chromium_get("views", id)
                    .await?
                    .ok_or_else(|| Error::not_found("Chromium view not found."))?
                    .data,
            )?,
            None => decode(
                self.store
                    .chromium_state("default")
                    .await?
                    .ok_or_else(failure)?,
            )?,
        };
        Ok(view)
    }
    pub async fn select(
        &self,
        component: &str,
        snapshot: Option<&str>,
        view: Option<&str>,
    ) -> Result<Snapshot> {
        if snapshot.is_some() && view.is_some() {
            return Err(Error::invalid(
                "Chromium snapshot and view selectors are exclusive.",
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
                        .get(component)
                        .copied()
                        .unwrap_or(selected.validated_at),
                ) > 7 * 86400
            {
                return Err(Error::unavailable(
                    "Chromium default evidence is older than seven days.",
                ));
            }
            self.snapshot(selected.snapshots.get(component).ok_or_else(|| {
                Error::not_found("Chromium component is not published in this view.")
            })?)
            .await?
        };
        if result.component != component {
            return Err(Error::invalid(
                "Chromium snapshot belongs to another component.",
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
            return Err(Error::invalid("Invalid Chromium member page."));
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
            .chromium_get("projections", &id)
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
            .map_err(|_| Error::integrity("Malformed Chromium projection."))?;
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
                    .chromium_get("projections", &id)
                    .await?
                    .ok_or_else(failure)?;
                for id in self.projection_members(&row.data).await? {
                    ids.insert(id);
                    if ids.len() > MAX_MEMBERS {
                        return Err(Error::capacity(
                            "Chromium selected search membership exceeds its bound.",
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
            return Err(Error::capacity("Chromium artifact read exceeds its bound."));
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
                return Err(Error::integrity("Chromium artifact length mismatch."));
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
            return Err(Error::invalid("Chromium byte limit must be 1..32768."));
        }
        let member = self
            .member(snapshot, path)
            .await?
            .ok_or_else(|| Error::not_found("Chromium source member not found."))?;
        let raw = member
            .raw
            .ok_or_else(|| Error::not_found("Chromium member has no raw bytes."))?;
        let (bytes, total, body_hash) = if let Some(artifact) = raw.get("artifact") {
            let artifact: BulkArtifact = decode(artifact.clone())?;
            if offset > artifact.bytes {
                return Err(Error::invalid(
                    "Chromium byte offset exceeds source length.",
                ));
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
            return Err(Error::integrity(
                "Chromium raw artifact descriptor missing.",
            ));
        };
        let next = offset.saturating_add(bytes.len() as u64);
        Ok(
            json!({"base64":STANDARD.encode(bytes),"offset":offset,"next_offset":if next<total {Some(next)}else{None},"total_bytes":total,"body_hash":body_hash}),
        )
    }
    async fn project(
        &self,
        component: &Component,
        path: &str,
        edition: &str,
        bytes: Vec<u8>,
        cancel: CancellationToken,
    ) -> Result<(String, Vec<String>)> {
        let id = inventory::digest(
            &serde_json::to_vec(&(
                &component.id,
                path,
                edition,
                inventory::digest(&bytes),
                PROCESSOR_VERSION,
            ))
            .map_err(|_| failure())?,
        );
        if let Some(row) = self.store.chromium_get("projections", &id).await? {
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
        let source_path = if edition == "html" {
            format!("{path}.html")
        } else {
            path.to_owned()
        };
        let stop = cancel.clone();
        let document = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            chromium_processing::process_document(&source_path, &bytes, stop)
        })
        .await
        .map_err(|_| failure())??;
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
                        &component.id,
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
                    component: component.id.clone(),
                    edition: edition.into(),
                    path: path.into(),
                    title: section.title.clone(),
                    text: text.into(),
                    kind: "section".into(),
                    metadata: json!({"anchor":section.anchor,"chunk":chunk}),
                };
                match ChromiumIndex::validate_document(&index_document, &cancel) {
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
                        &component.id,
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
                    component: component.id.clone(),
                    edition: edition.into(),
                    path: path.into(),
                    title: document.title.clone(),
                    text: text.into(),
                    kind: "section".into(),
                    metadata: json!({"anchor":"","chunk":chunk}),
                };
                match ChromiumIndex::validate_document(&index_document, &cancel) {
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
                        &component.id,
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
                    component: component.id.clone(),
                    edition: edition.into(),
                    path: path.into(),
                    title: symbol.name.clone(),
                    text: text.into(),
                    kind: "symbol".into(),
                    metadata: json!({"anchor":symbol.anchor,"symbol_kind":symbol.kind,"name":symbol.name,"scope":symbol.scope,"chunk":chunk}),
                };
                match ChromiumIndex::validate_document(&index_document, &cancel) {
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
                "Chromium projection search membership exceeds its bound.",
            ));
        }
        gaps.sort();
        gaps.dedup();
        let index_membership = shared.sequence(&index_ids).await?;
        shared.flush().await?;
        self.store.chromium_put("projections",&id,&json!({"manifest":manifest,"index_membership":index_membership,"index_count":index_ids.len(),"gaps":gaps,"format":document.format,"title":document.title,"sections":document.sections.len(),"symbols":document.symbols.len(),"references":document.references.len()})).await?;
        Ok((id, gaps))
    }
    pub async fn status(&self) -> Result<Value> {
        self.store
            .chromium_state("status")
            .await?
            .ok_or_else(failure)
    }
}
