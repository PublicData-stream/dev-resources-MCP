//! Bounded immutable crate search shards with snapshot-wide BM25 statistics.
use devres_application::{
    Retrieval,
    crate_corpus::{ContentFilter, CrateCorpusStore, Snapshot},
};
use devres_domain::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{
    cmp::Ordering as CmpOrdering,
    collections::{BTreeMap, HashMap},
    fs::{self, File, OpenOptions},
    io::{BufRead, Read, Write},
    ops::Bound,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tantivy::{
    Index, IndexReader, IndexWriter, Searcher, TantivyDocument, Term,
    collector::{Count, TopDocs},
    indexer::IndexWriterOptions,
    query::{
        AllQuery, Bm25StatisticsProvider, BooleanQuery, Occur, PhraseQuery, Query, RangeQuery,
        TermQuery,
    },
    schema::{
        FAST, Field, INDEXED, IndexRecordOption, STORED, STRING, Schema, TextFieldIndexing,
        TextOptions, Value as _,
    },
    tokenizer::{
        Language, LowerCaser, MAX_TOKEN_LEN, SimpleTokenizer, Stemmer, StopWordFilter,
        TextAnalyzer, TokenStream,
    },
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;

const MAX_DOCS: usize = 50_000;
const MAX_TEXT: usize = 4 * 1024 * 1024;
const MAX_SHARD: u64 = 32 * 1024 * 1024 * 1024;
const MAX_FILES: usize = 10_000;
const MAX_SHARDS: usize = 4096;
const MAX_MANIFEST: usize = 2 * 1024 * 1024;
static IDS: AtomicU64 = AtomicU64::new(0);
static WRITER: OnceLock<Arc<Semaphore>> = OnceLock::new();
static READERS: OnceLock<Arc<Semaphore>> = OnceLock::new();
#[cfg(test)]
static OPEN_COUNTS: Mutex<BTreeMap<PathBuf, (u64, u64)>> = Mutex::new(BTreeMap::new());

fn unavailable() -> Error {
    Error::unavailable("Crate search index unavailable.")
}
fn integrity() -> Error {
    Error::integrity("Crate search index integrity failed.")
}
fn capacity() -> Error {
    Error::capacity("Crate search processing bounds exceeded.")
}
fn hash(bytes: &[u8]) -> String {
    crate::integrity::hash(bytes)
}
fn valid_hash(s: &str) -> bool {
    crate::integrity::valid_hash(s)
}
fn reference_digest(reference: &Value) -> Result<&str> {
    match (reference.get("digest"), reference.get("sha256")) {
        (Some(digest), None) => digest
            .as_str()
            .filter(|s| s.starts_with("blake3:") && valid_hash(s))
            .ok_or_else(integrity),
        (None, Some(digest)) => digest
            .as_str()
            .filter(|s| !s.starts_with("blake3:") && valid_hash(s))
            .ok_or_else(integrity),
        _ => Err(integrity()),
    }
}

fn index_suffix(id: &str) -> Result<String> {
    Ok(crate::integrity::relative_path(id)?
        .to_string_lossy()
        .into_owned())
}
fn path_id(path: &str) -> Result<String> {
    let id = path
        .strip_prefix("blake3/")
        .map_or_else(|| path.to_owned(), |hex| format!("blake3:{hex}"));
    if !valid_hash(&id) || index_suffix(&id)? != path {
        return Err(integrity());
    }
    Ok(id)
}
fn check(cancel: &CancellationToken, deadline: Instant) -> Result<()> {
    if cancel.is_cancelled() {
        return Err(Error::new("cancelled", "Crate indexing canceled."));
    }
    if Instant::now() >= deadline {
        return Err(capacity());
    }
    Ok(())
}
fn field(schema: &Schema, name: &str) -> Result<Field> {
    schema.get_field(name).map_err(|_| integrity())
}
fn schema() -> Schema {
    let mut s = Schema::builder();
    for key in [
        "class",
        "name",
        "version",
        "target",
        "path",
        "kind",
        "dependency",
        "license",
        "keyword",
        "category",
    ] {
        s.add_text_field(key, STRING);
    }
    s.add_u64_field("yanked", INDEXED | FAST);
    s.add_u64_field("msrv", INDEXED | FAST);
    s.add_text_field("tie", STRING | FAST);
    s.add_text_field("payload", STORED);
    for name in ["technical", "english"] {
        s.add_text_field(
            name,
            TextOptions::default().set_stored().set_indexing_options(
                TextFieldIndexing::default()
                    .set_tokenizer(name)
                    .set_index_option(IndexRecordOption::WithFreqsAndPositions),
            ),
        );
    }
    s.build()
}
fn analyzer(mode: &str) -> Result<TextAnalyzer> {
    let builder = TextAnalyzer::builder(SimpleTokenizer::default()).filter(LowerCaser);
    if mode == "technical" {
        Ok(builder.build())
    } else if mode == "english" {
        Ok(builder
            .filter(StopWordFilter::new(Language::English).ok_or_else(unavailable)?)
            .filter(Stemmer::new(Language::English))
            .build())
    } else {
        Err(Error::invalid("Search mode must be technical or english."))
    }
}
fn register(index: &Index) -> Result<()> {
    for mode in ["technical", "english"] {
        index.tokenizers().register(mode, analyzer(mode)?);
    }
    Ok(())
}
fn msrv(value: &str) -> Result<u64> {
    let parts: Vec<_> = value.split('.').collect();
    if !(2..=3).contains(&parts.len()) {
        return Err(Error::invalid(
            "MSRV requires major.minor or major.minor.patch.",
        ));
    }
    let mut n = [0u64; 3];
    for (slot, value) in n.iter_mut().zip(parts) {
        *slot = value.parse().map_err(|_| Error::invalid("Invalid MSRV."))?;
        if *slot > 0x1fffff {
            return Err(Error::invalid("MSRV component exceeds index range."));
        }
    }
    Ok((n[0] << 42) | (n[1] << 21) | n[2])
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
struct Identity {
    name: String,
    version: String,
    target: String,
    path: String,
    id: String,
}
impl Identity {
    fn compare(&self, other: &Self) -> CmpOrdering {
        self.name
            .cmp(&other.name)
            .then_with(|| {
                match (
                    semver::Version::parse(&self.version),
                    semver::Version::parse(&other.version),
                ) {
                    (Ok(a), Ok(b)) => b.cmp(&a),
                    _ => self.version.cmp(&other.version),
                }
            })
            .then(self.target.cmp(&other.target))
            .then(self.path.cmp(&other.path))
            .then(self.id.cmp(&other.id))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Rank {
    score: f32,
    key: Identity,
}
impl PartialEq for Rank {
    fn eq(&self, other: &Self) -> bool {
        self.score == other.score && self.key == other.key
    }
}
impl PartialOrd for Rank {
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrdering> {
        self.score
            .partial_cmp(&other.score)
            .map(|order| order.then_with(|| other.key.compare(&self.key)))
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct Digest {
    bytes: u64,
    #[serde(alias = "sha256")]
    digest: String,
}
#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct Shard {
    name: String,
    documents: usize,
    files: BTreeMap<String, Digest>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    inventory: String,
    content_sequence: i64,
    enrichment: Option<String>,
    shards: Vec<Shard>,
    gaps: u64,
    gap_artifact: Option<Digest>,
    gap_samples: Vec<Value>,
}
fn real_directory(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path).map_err(|_| unavailable())?;
    if !m.is_dir() || m.file_type().is_symlink() {
        return Err(integrity());
    }
    Ok(())
}
fn file_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && !name.contains("..")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
fn digest(path: &Path, cancel: &CancellationToken, deadline: Instant) -> Result<Digest> {
    digest_with_algorithm(path, cancel, deadline, false)
}
fn digest_with_algorithm(
    path: &Path,
    cancel: &CancellationToken,
    deadline: Instant,
    legacy: bool,
) -> Result<Digest> {
    let m = fs::symlink_metadata(path).map_err(|_| unavailable())?;
    if !m.is_file() || m.file_type().is_symlink() || m.len() > MAX_SHARD {
        return Err(integrity());
    }
    let mut input = File::open(path).map_err(|_| unavailable())?;
    let mut hash = Sha256::new();
    let mut blake3 = blake3::Hasher::new();
    let mut buffer = [0u8; 65536];
    let mut bytes = 0;
    loop {
        check(cancel, deadline)?;
        let n = input.read(&mut buffer).map_err(|_| unavailable())?;
        if n == 0 {
            break;
        }
        bytes += n as u64;
        if bytes > m.len() {
            return Err(integrity());
        }
        hash.update(&buffer[..n]);
        blake3.update(&buffer[..n]);
    }
    if bytes != m.len() {
        return Err(integrity());
    }
    Ok(Digest {
        bytes,
        digest: if legacy {
            hex::encode(hash.finalize())
        } else {
            format!("blake3:{}", blake3.finalize().to_hex())
        },
    })
}
fn files(path: &Path) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(path).map_err(|_| unavailable())? {
        let entry = entry.map_err(|_| unavailable())?;
        let name = entry.file_name().into_string().map_err(|_| integrity())?;
        if !file_name(&name) || !entry.file_type().map_err(|_| unavailable())?.is_file() {
            return Err(integrity());
        }
        if !name.ends_with(".lock") {
            out.push(name);
        }
        if out.len() > MAX_FILES {
            return Err(capacity());
        }
    }
    out.sort();
    Ok(out)
}

struct Builder {
    storage_root: PathBuf,
    writer: Option<IndexWriter<TantivyDocument>>,
    index: Option<Index>,
    stage: PathBuf,
    destination: PathBuf,
    relative: String,
    shards: Vec<Shard>,
    documents: usize,
    document_limit: usize,
    queued: usize,
    shard_bytes: u64,
    owner: Arc<dyn CrateCorpusStore>,
    _permit: Option<OwnedSemaphorePermit>,
    cancel: CancellationToken,
    published: bool,
    gaps: u64,
    gap_samples: Vec<Value>,
    gap_bytes: u64,
}
impl Drop for Builder {
    fn drop(&mut self) {
        drop(self.writer.take());
        if !self.published {
            let _ = fs::remove_dir_all(&self.stage);
        }
    }
}
impl Builder {
    fn begin(
        root: &Path,
        owner: Arc<dyn CrateCorpusStore>,
        cancel: CancellationToken,
        permit: OwnedSemaphorePermit,
    ) -> Result<Self> {
        Self::begin_admitted(root, owner, cancel, Some(permit))
    }

    fn begin_admitted(
        root: &Path,
        owner: Arc<dyn CrateCorpusStore>,
        cancel: CancellationToken,
        permit: Option<OwnedSemaphorePermit>,
    ) -> Result<Self> {
        crate::durable_archive::admit_write(root, 128 * 1024 * 1024)?;
        let canonical = fs::canonicalize(root).map_err(|_| unavailable())?;
        real_directory(&canonical)?;
        let base = canonical.join("crate-indexes");
        if !base.exists() {
            fs::create_dir(&base).map_err(|_| unavailable())?;
            File::open(&canonical)
                .and_then(|f| f.sync_all())
                .map_err(|_| unavailable())?;
        }
        real_directory(&base)?;
        if fs2::available_space(&base).map_err(|_| unavailable())? < 128 * 1024 * 1024 {
            return Err(capacity());
        }
        let id = hash(
            format!(
                "{}:{}:{}",
                devres_domain::unix_now(),
                std::process::id(),
                IDS.fetch_add(1, Ordering::Relaxed)
            )
            .as_bytes(),
        );
        let suffix = index_suffix(&id)?;
        crate::integrity::ensure_directory_durable(&base.join("blake3"))?;
        real_directory(&base.join("blake3"))?;
        let stage = base.join(format!(".stage-{}", crate::integrity::digest_hex(&id)?));
        fs::create_dir(&stage).map_err(|_| unavailable())?;
        Ok(Self {
            storage_root: canonical,
            writer: None,
            index: None,
            stage,
            destination: base.join(&suffix),
            relative: format!("crate-indexes/{suffix}"),
            shards: Vec::new(),
            documents: 0,
            document_limit: MAX_DOCS,
            queued: 0,
            shard_bytes: 0,
            owner,
            _permit: permit,
            cancel,
            published: false,
            gaps: 0,
            gap_samples: Vec::new(),
            gap_bytes: 0,
        })
    }
    fn open_shard(&mut self) -> Result<()> {
        if self.shards.len() >= MAX_SHARDS {
            return Err(capacity());
        }
        let directory = self.stage.join(format!("shard-{:04}", self.shards.len()));
        fs::create_dir(&directory).map_err(|_| unavailable())?;
        let index = crate::immutable_index::create_staging(&directory, schema())
            .map_err(|_| unavailable())?;
        register(&index)?;
        let options = IndexWriterOptions::builder()
            .num_worker_threads(1)
            .num_merge_threads(1)
            .memory_budget_per_thread(64 * 1024 * 1024)
            .build();
        let writer = index
            .writer_with_options(options)
            .map_err(|_| unavailable())?;
        writer.set_merge_policy(Box::new(tantivy::indexer::NoMergePolicy));
        self.index = Some(index);
        self.writer = Some(writer);
        self.documents = 0;
        self.queued = 0;
        self.shard_bytes = 0;
        Ok(())
    }
    fn skip(&mut self, identity: &Identity, reason: &str) -> Result<bool> {
        let gap = json!({"identity":identity,"code":"capacity","reason":reason});
        let mut bytes = serde_json::to_vec(&gap).map_err(|_| integrity())?;
        bytes.push(b'\n');
        self.gap_bytes = self.gap_bytes.saturating_add(bytes.len() as u64);
        if self.gap_bytes > MAX_SHARD {
            return Err(capacity());
        }
        let mut output = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.stage.join("gaps.ndjson"))
            .map_err(|_| unavailable())?;
        crate::durable_archive::with_write_budget(
            &self.stage.join("gaps.ndjson"),
            bytes.len() as u64,
            || output.write_all(&bytes),
        )
        .map_err(|_| unavailable())?;
        self.gaps += 1;
        if self.gap_samples.len() < 20 {
            self.gap_samples.push(gap);
        }
        Ok(false)
    }
    fn add(&mut self, input: IndexDocument) -> Result<bool> {
        crate::durable_archive::admit_write(&self.storage_root, input.text.len() as u64)?;
        check(&self.cancel, Instant::now() + Duration::from_secs(15))?;
        if input.text.len() > MAX_TEXT {
            return self.skip(&input.identity, "document_text_exceeds_4MiB");
        }
        if fs2::available_space(&self.stage).map_err(|_| unavailable())? < 128 * 1024 * 1024 {
            return Err(capacity());
        }
        if self.writer.is_none() {
            self.open_shard()?;
        }
        if self.documents >= self.document_limit
            || self.shard_bytes.saturating_add(input.text.len() as u64) > 24 * 1024 * 1024 * 1024
        {
            self.finish_shard()?;
            self.open_shard()?;
        }
        let deadline = Instant::now() + Duration::from_secs(15);
        for mode in ["technical", "english"] {
            let mut analyzer = analyzer(mode)?;
            let mut stream = analyzer.token_stream(&input.text);
            while stream.advance() {
                if self.cancel.is_cancelled() {
                    return Err(Error::new("cancelled", "Crate indexing canceled."));
                }
                if Instant::now() >= deadline {
                    return self.skip(&input.identity, "token_processing_deadline");
                }
                if stream.token().text.len() >= MAX_TOKEN_LEN {
                    return self.skip(&input.identity, "token_exceeds_65529_bytes");
                }
            }
        }
        let schema = schema();
        let mut doc = TantivyDocument::default();
        for (key, value) in input.keywords {
            doc.add_text(field(&schema, &key)?, value);
        }
        doc.add_text(
            field(&schema, "tie")?,
            serde_json::to_string(&input.identity).map_err(|_| integrity())?,
        );
        let payload = serde_json::to_string(&input.payload).map_err(|_| integrity())?;
        if payload.len() > 2 * 1024 * 1024 {
            return self.skip(&input.identity, "metadata_payload_exceeds_2MiB");
        }
        doc.add_text(field(&schema, "payload")?, payload);
        for mode in ["technical", "english"] {
            doc.add_text(field(&schema, mode)?, &input.text);
        }
        if let Some(yanked) = input.yanked {
            doc.add_u64(field(&schema, "yanked")?, u64::from(yanked));
        }
        if let Some(version) = input.msrv {
            doc.add_u64(field(&schema, "msrv")?, version);
        }
        let bytes = input.text.len();
        self.writer
            .as_ref()
            .ok_or_else(integrity)?
            .add_document(doc)
            .map_err(|_| unavailable())?;
        self.documents += 1;
        self.queued += bytes;
        self.shard_bytes += bytes as u64;
        if self.queued >= 32 * 1024 * 1024 {
            self.writer
                .as_mut()
                .ok_or_else(integrity)?
                .commit()
                .map_err(|_| unavailable())?;
            self.queued = 0;
        }
        Ok(true)
    }
    fn finish_shard(&mut self) -> Result<()> {
        let Some(mut writer) = self.writer.take() else {
            return Ok(());
        };
        writer.commit().map_err(|_| unavailable())?;
        drop(writer);
        drop(self.index.take());
        let name = format!("shard-{:04}", self.shards.len());
        let path = self.stage.join(&name);
        let mut hashes = BTreeMap::new();
        let mut size = 0;
        let deadline = Instant::now() + Duration::from_secs(300);
        for name in files(&path)? {
            let digest = digest(&path.join(&name), &self.cancel, deadline)?;
            size += digest.bytes;
            if size > MAX_SHARD {
                return Err(capacity());
            }
            File::open(path.join(&name))
                .and_then(|f| f.sync_all())
                .map_err(|_| unavailable())?;
            hashes.insert(name, digest);
        }
        File::open(&path)
            .and_then(|f| f.sync_all())
            .map_err(|_| unavailable())?;
        self.shards.push(Shard {
            name,
            documents: self.documents,
            files: hashes,
        });
        Ok(())
    }
    fn finish(mut self, snapshot: &Snapshot) -> Result<Value> {
        self.finish_shard()?;
        let manifest = Manifest {
            version: 2,
            inventory: snapshot.inventory.id.clone(),
            content_sequence: snapshot.content_sequence,
            enrichment: snapshot.enrichment.clone(),
            shards: self.shards.clone(),
            gaps: self.gaps,
            gap_samples: self.gap_samples.clone(),
            gap_artifact: if self.gaps > 0 {
                let path = self.stage.join("gaps.ndjson");
                File::open(&path)
                    .and_then(|f| f.sync_all())
                    .map_err(|_| unavailable())?;
                Some(digest(
                    &path,
                    &self.cancel,
                    Instant::now() + Duration::from_secs(300),
                )?)
            } else {
                None
            },
        };
        let bytes = serde_json::to_vec(&manifest).map_err(|_| integrity())?;
        if bytes.len() > MAX_MANIFEST {
            return Err(capacity());
        }
        let mut output =
            File::create(self.stage.join("manifest.json")).map_err(|_| unavailable())?;
        crate::durable_archive::with_write_budget(
            &self.stage.join("manifest.json"),
            bytes.len() as u64,
            || output.write_all(&bytes),
        )
        .and_then(|()| output.sync_all())
        .map_err(|_| unavailable())?;
        File::open(&self.stage)
            .and_then(|f| f.sync_all())
            .map_err(|_| unavailable())?;
        fs::rename(&self.stage, &self.destination).map_err(|_| unavailable())?;
        crate::durable_archive::relocate_local_tree(&self.stage, &self.destination)?;
        File::open(self.destination.parent().ok_or_else(integrity)?)
            .and_then(|f| f.sync_all())
            .map_err(|_| unavailable())?;
        self.published = true;
        for shard in &manifest.shards {
            for (name, digest) in &shard.files {
                crate::integrity::record_file(
                    &self.storage_root,
                    &self.destination.join(&shard.name).join(name),
                    &digest.digest,
                    digest.bytes,
                )?;
            }
        }
        if let Some(digest) = &manifest.gap_artifact {
            crate::integrity::record_file(
                &self.storage_root,
                &self.destination.join("gaps.ndjson"),
                &digest.digest,
                digest.bytes,
            )?;
        }
        crate::integrity::record_file(
            &self.storage_root,
            &self.destination.join("manifest.json"),
            &hash(&bytes),
            bytes.len() as u64,
        )?;
        let _ = &self.owner;
        Ok(
            json!({"version":2,"path":self.relative,"digest":hash(&bytes),"inventory":snapshot.inventory.id,"content_sequence":snapshot.content_sequence,"enrichment":snapshot.enrichment,"documents":manifest.shards.iter().map(|s|s.documents as u64).sum::<u64>(),"shards":manifest.shards.len(),"ranking":"snapshot_global_bm25","skipped_documents":manifest.gaps,"gap_samples":manifest.gap_samples,"complete_search_coverage":manifest.gaps==0}),
        )
    }
}
struct IndexDocument {
    identity: Identity,
    text: String,
    payload: Value,
    keywords: Vec<(String, String)>,
    yanked: Option<bool>,
    msrv: Option<u64>,
}

pub async fn build(
    store: Arc<dyn CrateCorpusStore>,
    retrieval: Arc<Retrieval>,
    root: PathBuf,
    snapshot: Snapshot,
    shutdown: CancellationToken,
) -> Result<Value> {
    let permit = WRITER
        .get_or_init(|| Arc::new(Semaphore::new(1)))
        .clone()
        .try_acquire_owned()
        .map_err(|_| capacity())?;
    let owner = store.clone();
    let cancel = shutdown.clone();
    let mut builder =
        tokio::task::spawn_blocking(move || Builder::begin(&root, owner, cancel, permit))
            .await
            .map_err(|_| unavailable())??;
    let mut cursor = None;
    loop {
        check(&shutdown, Instant::now() + Duration::from_secs(15))?;
        let rows = store
            .versions(&snapshot.inventory.id, None, cursor.as_deref(), 100)
            .await?;
        if rows.is_empty() {
            break;
        }
        for row in rows {
            let next = format!("{}@{}", row.name, row.version);
            if cursor.as_ref().is_some_and(|old| old >= &next) {
                return Err(integrity());
            }
            cursor = Some(next);
            let enrichment = store
                .enrichment(snapshot.enrichment.as_deref(), &row.name, &row.version)
                .await?;
            let metadata = &row.record;
            let mut keys = vec![
                ("class".into(), "version".into()),
                ("name".into(), row.name.clone()),
                ("version".into(), row.version.clone()),
                ("kind".into(), "metadata".into()),
            ];
            if let Some(deps) = metadata["deps"].as_array() {
                for dep in deps {
                    if let Some(name) = dep["package"].as_str().or_else(|| dep["name"].as_str()) {
                        keys.push(("dependency".into(), name.into()));
                    }
                }
            }
            if let Some(license) = enrichment["version"]["license"].as_str() {
                keys.push(("license".into(), license.into()));
            }
            for (source, key) in [("keywords", "keyword"), ("categories", "category")] {
                if let Some(values) = enrichment[source].as_array() {
                    for value in values {
                        if let Some(value) = value.as_str() {
                            keys.push((key.into(), value.into()));
                        }
                    }
                }
            }
            let text = format!(
                "{} {} {} {}",
                row.name,
                row.version,
                enrichment["crate"]["description"]
                    .as_str()
                    .unwrap_or_default(),
                enrichment["crate"]["readme"].as_str().unwrap_or_default()
            );
            let identity = Identity {
                name: row.name.clone(),
                version: row.version.clone(),
                target: String::new(),
                path: String::new(),
                id: format!("{}@{}", row.name, row.version),
            };
            let yanked = metadata["yanked"].as_bool();
            let msrv = metadata["rust_version"].as_str().map(msrv).transpose()?;
            let document = IndexDocument {
                identity,
                text,
                payload: json!({"class":"version","record":row,"enrichment":enrichment}),
                keywords: keys,
                yanked,
                msrv,
            };
            builder = tokio::task::spawn_blocking(move || {
                builder.add(document)?;
                Ok::<_, Error>(builder)
            })
            .await
            .map_err(|_| unavailable())??;
        }
    }
    let mut cursor = None;
    loop {
        check(&shutdown, Instant::now() + Duration::from_secs(15))?;
        let rows = store
            .contents(
                snapshot.content_sequence,
                &ContentFilter::default(),
                cursor.as_deref(),
                100,
            )
            .await?;
        if rows.is_empty() {
            break;
        }
        for row in rows {
            if cursor.as_ref().is_some_and(|old| old >= &row.id) {
                return Err(integrity());
            }
            cursor = Some(row.id.clone());
            let capture = retrieval.read_capture(&row.capture).await?;
            if capture.body.len() > MAX_TEXT {
                return Err(capacity());
            }
            let text = std::str::from_utf8(&capture.body)
                .map_err(|_| integrity())?
                .to_owned();
            let identity = Identity {
                name: row.name.clone(),
                version: row.version.clone(),
                target: row.target.clone(),
                path: row.path.clone(),
                id: row.id.clone(),
            };
            let keys = vec![
                ("class".into(), "content".into()),
                ("name".into(), row.name.clone()),
                ("version".into(), row.version.clone()),
                ("target".into(), row.target.clone()),
                ("path".into(), row.path.clone()),
                ("kind".into(), row.kind.clone()),
            ];
            let document = IndexDocument {
                identity,
                text,
                payload: json!({"class":"content","record":row}),
                keywords: keys,
                yanked: None,
                msrv: None,
            };
            builder = tokio::task::spawn_blocking(move || {
                builder.add(document)?;
                Ok::<_, Error>(builder)
            })
            .await
            .map_err(|_| unavailable())??;
        }
    }
    tokio::task::spawn_blocking(move || builder.finish(&snapshot))
        .await
        .map_err(|_| unavailable())?
}

struct Opened {
    _readers: Vec<IndexReader>,
    searchers: Vec<Searcher>,
    gaps: u64,
    _archive_leases: Vec<crate::durable_archive::ArchiveLease>,
}
impl Bm25StatisticsProvider for Opened {
    fn total_num_tokens(&self, field: Field) -> tantivy::Result<u64> {
        self.searchers.iter().try_fold(0, |sum, s| {
            Ok(sum + Bm25StatisticsProvider::total_num_tokens(s, field)?)
        })
    }
    fn total_num_docs(&self) -> tantivy::Result<u64> {
        Ok(self.searchers.iter().map(Searcher::num_docs).sum())
    }
    fn doc_freq(&self, term: &Term) -> tantivy::Result<u64> {
        self.searchers
            .iter()
            .try_fold(0, |sum, s| Ok(sum + s.doc_freq(term)?))
    }
}
#[derive(Default)]
struct ReaderCache {
    active: Option<(String, Arc<Opened>)>,
    prepared: Option<(String, Arc<Opened>)>,
    historical: HashMap<String, Arc<Opened>>,
}
impl ReaderCache {
    fn get(&self, key: &str) -> Option<Arc<Opened>> {
        self.active
            .as_ref()
            .filter(|(id, _)| id == key)
            .or_else(|| self.prepared.as_ref().filter(|(id, _)| id == key))
            .map(|(_, value)| value.clone())
            .or_else(|| self.historical.get(key).cloned())
    }
    fn retain_history(&mut self, key: String, opened: Arc<Opened>) {
        self.historical.insert(key, opened);
        while self.historical.len() > 2 {
            if let Some(key) = self.historical.keys().next().cloned() {
                self.historical.remove(&key);
            }
        }
    }
}
static CACHE: OnceLock<Mutex<ReaderCache>> = OnceLock::new();
fn cache_key(root: &Path, reference: &Value) -> Result<String> {
    let path = reference["path"]
        .as_str()
        .and_then(|s| s.strip_prefix("crate-indexes/"))
        .filter(|s| path_id(s).is_ok())
        .ok_or_else(integrity)?;
    let expected = reference_digest(reference)?;
    Ok(format!(
        "{}:{expected}",
        fs::canonicalize(root)
            .map_err(|_| unavailable())?
            .join("crate-indexes")
            .join(path)
            .display()
    ))
}
/// Pin only after the database atomically publishes this prepared snapshot.
pub fn activate(root: &Path, reference: &Value) -> Result<()> {
    crate::durable_archive::check_available(root)?;
    let key = cache_key(root, reference)?;
    let mut cache = CACHE
        .get_or_init(|| Mutex::new(ReaderCache::default()))
        .lock()
        .map_err(|_| unavailable())?;
    let opened = cache
        .get(&key)
        .ok_or_else(|| Error::unavailable("Published crate index was not prewarmed."))?;
    if let Some((old_key, old)) = cache.active.replace((key.clone(), opened))
        && old_key != key
    {
        cache.retain_history(old_key, old);
    }
    if cache
        .prepared
        .as_ref()
        .is_some_and(|(prepared, _)| prepared == &key)
    {
        cache.prepared = None;
    }
    cache.historical.remove(&key);
    Ok(())
}
fn open(
    root: &Path,
    reference: &Value,
    cancel: &CancellationToken,
    deadline: Instant,
) -> Result<Arc<Opened>> {
    open_inner(root, reference, cancel, deadline, false)
}

fn open_inner(
    root: &Path,
    reference: &Value,
    cancel: &CancellationToken,
    deadline: Instant,
    verification_only: bool,
) -> Result<Arc<Opened>> {
    check(cancel, deadline)?;
    crate::durable_archive::check_available_with_deadline(root, deadline, cancel)?;
    let path = reference["path"].as_str().ok_or_else(unavailable)?;
    let expected = reference_digest(reference)?;
    let id = path
        .strip_prefix("crate-indexes/")
        .filter(|s| path_id(s).is_ok())
        .ok_or_else(integrity)?;
    let base = fs::canonicalize(root)
        .map_err(|_| unavailable())?
        .join("crate-indexes");
    let directory = base.join(id);
    #[cfg(test)]
    {
        let mut counts = OPEN_COUNTS.lock().map_err(|_| unavailable())?;
        counts.entry(directory.clone()).or_default().0 += 1;
    }
    let key = format!("{}:{expected}", directory.display());
    let cache = CACHE.get_or_init(|| Mutex::new(ReaderCache::default()));
    if !verification_only && let Some(opened) = cache.lock().map_err(|_| unavailable())?.get(&key) {
        return Ok(opened);
    }
    #[cfg(test)]
    {
        let mut counts = OPEN_COUNTS.lock().map_err(|_| unavailable())?;
        counts.entry(directory.clone()).or_default().1 += 1;
    }
    let path = directory.join("manifest.json");
    let mut archive_leases = vec![crate::durable_archive::materialize_file(
        &path,
        MAX_MANIFEST as u64,
        deadline,
        cancel,
    )?];
    real_directory(&base)?;
    real_directory(&directory)?;
    let meta = fs::symlink_metadata(&path).map_err(|_| unavailable())?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > MAX_MANIFEST as u64 {
        return Err(integrity());
    }
    let bytes = fs::read(&path).map_err(|_| unavailable())?;
    if !expected.starts_with("blake3:") {
        crate::integrity::verify_legacy_file(&path, deadline)?;
    }
    crate::integrity::verify(expected, &bytes)?;
    let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|_| integrity())?;
    if !matches!(manifest.version, 1 | 2)
        || manifest.shards.len() > MAX_SHARDS
        || reference["inventory"].as_str() != Some(&manifest.inventory)
        || reference["content_sequence"].as_i64() != Some(manifest.content_sequence)
        || reference["enrichment"] != json!(manifest.enrichment)
    {
        return Err(integrity());
    }
    let mut readers = Vec::new();
    let mut searchers = Vec::new();
    for (index, shard) in manifest.shards.iter().enumerate() {
        if shard.name != format!("shard-{index:04}")
            || shard.documents > MAX_DOCS
            || shard.files.len() > MAX_FILES
        {
            return Err(integrity());
        }
        let path = directory.join(&shard.name);
        archive_leases.push(crate::durable_archive::materialize_directory(
            &path, MAX_SHARD, MAX_FILES, deadline, cancel,
        )?);
        real_directory(&path)?;
        if files(&path)? != shard.files.keys().cloned().collect::<Vec<_>>() {
            return Err(integrity());
        }
        let mut size = 0;
        for (name, expected) in &shard.files {
            if !file_name(name)
                || !valid_hash(&expected.digest)
                || manifest.version == 2 && !expected.digest.starts_with("blake3:")
            {
                return Err(integrity());
            }
            if !expected.digest.starts_with("blake3:") {
                crate::integrity::verify_legacy_file(&path.join(name), deadline)?;
            }
            let actual = digest_with_algorithm(
                &path.join(name),
                cancel,
                deadline,
                !expected.digest.starts_with("blake3:"),
            )?;
            size += actual.bytes;
            if size > MAX_SHARD
                || actual.bytes != expected.bytes
                || actual.digest != expected.digest
            {
                return Err(integrity());
            }
        }
        let index = crate::immutable_index::open(&path).map_err(|_| integrity())?;
        if index.schema() != schema() {
            return Err(integrity());
        }
        register(&index)?;
        let reader = index.reader().map_err(|_| unavailable())?;
        let searcher = reader.searcher();
        if searcher.num_docs() != shard.documents as u64 {
            return Err(integrity());
        }
        readers.push(reader);
        searchers.push(searcher);
    }
    if let Some(expected) = &manifest.gap_artifact {
        archive_leases.push(crate::durable_archive::materialize_file(
            &directory.join("gaps.ndjson"),
            MAX_SHARD,
            deadline,
            cancel,
        )?);
        if manifest.version == 2 && !expected.digest.starts_with("blake3:") {
            return Err(integrity());
        }
        if !expected.digest.starts_with("blake3:") {
            crate::integrity::verify_legacy_file(&directory.join("gaps.ndjson"), deadline)?;
        }
        let actual = digest_with_algorithm(
            &directory.join("gaps.ndjson"),
            cancel,
            deadline,
            !expected.digest.starts_with("blake3:"),
        )?;
        if actual.bytes != expected.bytes || actual.digest != expected.digest {
            return Err(integrity());
        }
    } else if manifest.gaps != 0 {
        return Err(integrity());
    }
    let opened = Arc::new(Opened {
        _archive_leases: archive_leases,
        _readers: readers,
        searchers,
        gaps: manifest.gaps,
    });
    if !verification_only {
        let mut cache = cache.lock().map_err(|_| unavailable())?;
        cache.retain_history(key, opened.clone());
    }
    Ok(opened)
}

pub(crate) type PayloadRewrite = Arc<dyn Fn(&mut Value) -> Result<()> + Send + Sync>;

fn from_frozen_payload(payload: Value, text: String) -> Result<IndexDocument> {
    let class = payload["class"].as_str().ok_or_else(integrity)?;
    let record = &payload["record"];
    let name = record["name"].as_str().ok_or_else(integrity)?.to_owned();
    let version = record["version"].as_str().ok_or_else(integrity)?.to_owned();
    let mut identity = Identity {
        name: name.clone(),
        version: version.clone(),
        target: String::new(),
        path: String::new(),
        id: format!("{name}@{version}"),
    };
    let mut keys = vec![
        ("class".into(), class.into()),
        ("name".into(), name),
        ("version".into(), version),
    ];
    let mut yanked = None;
    let mut rust_version = None;
    match class {
        "version" => {
            keys.push(("kind".into(), "metadata".into()));
            let metadata = &record["record"];
            if let Some(deps) = metadata["deps"].as_array() {
                for dep in deps {
                    if let Some(name) = dep["package"].as_str().or_else(|| dep["name"].as_str()) {
                        keys.push(("dependency".into(), name.into()));
                    }
                }
            }
            let enrichment = &payload["enrichment"];
            if let Some(license) = enrichment["version"]["license"].as_str() {
                keys.push(("license".into(), license.into()));
            }
            for (source, key) in [("keywords", "keyword"), ("categories", "category")] {
                if let Some(values) = enrichment[source].as_array() {
                    for value in values {
                        if let Some(value) = value.as_str() {
                            keys.push((key.into(), value.into()));
                        }
                    }
                }
            }
            yanked = metadata["yanked"].as_bool();
            rust_version = metadata["rust_version"].as_str().map(msrv).transpose()?;
        }
        "content" => {
            identity.target = record["target"].as_str().ok_or_else(integrity)?.into();
            identity.path = record["path"].as_str().ok_or_else(integrity)?.into();
            identity.id = record["id"].as_str().ok_or_else(integrity)?.into();
            keys.extend([
                ("target".into(), identity.target.clone()),
                ("path".into(), identity.path.clone()),
                (
                    "kind".into(),
                    record["kind"].as_str().ok_or_else(integrity)?.into(),
                ),
            ]);
        }
        _ => return Err(integrity()),
    }
    Ok(IndexDocument {
        identity,
        text,
        payload,
        keywords: keys,
        yanked,
        msrv: rust_version,
    })
}

/// Rebuild only the exact postings and gaps from one immutable retained generation.
/// The callback rewrites typed service references in payloads, never indexed text.
#[cfg(test)]
pub(crate) async fn rebuild_frozen(
    owner: Arc<dyn CrateCorpusStore>,
    root: PathBuf,
    reference: Value,
    snapshot: Snapshot,
    rewrite: PayloadRewrite,
    cancel: CancellationToken,
) -> Result<Value> {
    struct CancelOnDrop(CancellationToken);
    impl Drop for CancelOnDrop {
        fn drop(&mut self) {
            self.0.cancel();
        }
    }
    let stop = cancel.child_token();
    let _guard = CancelOnDrop(stop.clone());
    let permit = WRITER
        .get_or_init(|| Arc::new(Semaphore::new(1)))
        .clone()
        .try_acquire_owned()
        .map_err(|_| capacity())?;
    let mut task = tokio::task::spawn_blocking(move || {
        rebuild_frozen_sync(
            owner,
            root,
            reference,
            snapshot,
            rewrite,
            stop,
            Some(permit),
        )
    });
    tokio::select! { biased; _ = cancel.cancelled() => { let _ = task.await; Err(Error::new("cancelled", "Crate migration canceled.")) }, result = &mut task => result.map_err(|_| unavailable())? }
}

/// Offline replay shares blocking admission with every other migration phase;
/// serving writer/reader limits remain independent and unchanged.
pub(crate) async fn rebuild_frozen_with_execution(
    owner: Arc<dyn CrateCorpusStore>,
    root: PathBuf,
    reference: Value,
    snapshot: Snapshot,
    rewrite: PayloadRewrite,
    cancel: CancellationToken,
    execution: &crate::MigrationExecution,
) -> Result<Value> {
    let result = execution
        .run(&cancel, move |stop| {
            rebuild_frozen_sync(owner, root, reference, snapshot, rewrite, stop, None)
        })
        .await?;
    if cancel.is_cancelled() {
        return Err(Error::new("cancelled", "Crate migration canceled."));
    }
    Ok(result)
}

/// Requalify a previously prepared replay without creating another canonical
/// generation. Only disposable proof-checked comparison scratch is written.
pub(crate) async fn verify_frozen_replay_with_execution(
    root: PathBuf,
    original: Value,
    canonical: Value,
    snapshot: Snapshot,
    rewrite: PayloadRewrite,
    cancel: CancellationToken,
    execution: &crate::MigrationExecution,
) -> Result<bool> {
    let equivalent = execution
        .run(&cancel, move |token| {
            let mut source = FrozenDocuments::open_admitted(&root, &original, &token, true)?;
            let read_manifest = |reference: &Value| -> Result<Manifest> {
                let path = root
                    .join(reference["path"].as_str().ok_or_else(integrity)?)
                    .join("manifest.json");
                let bytes = fs::read(path).map_err(|_| unavailable())?;
                if bytes.len() > MAX_MANIFEST {
                    return Err(capacity());
                }
                serde_json::from_slice(&bytes).map_err(|_| integrity())
            };
            let source_manifest = read_manifest(&original)?;
            let mut postings = crate::MigrationMap::new();
            let mut expected_count = 0_u64;
            loop {
                let (documents, more) = source.next_page(1000)?;
                for (mut payload, text) in documents {
                    check(&token, Instant::now() + Duration::from_secs(15))?;
                    from_frozen_payload(payload.clone(), text.clone())?;
                    rewrite(&mut payload)?;
                    from_frozen_payload(payload.clone(), text.clone())?;
                    let digest = crate::integrity::canonical_hash_with_cancel(
                        &json!(["crate-frozen-replay-posting-v1", payload, text]),
                        &token,
                    )?;
                    let count = postings
                        .get(&digest)
                        .map(|value| value.parse::<u64>().map_err(|_| integrity()))
                        .transpose()?
                        .unwrap_or(0)
                        .checked_add(1)
                        .ok_or_else(capacity)?;
                    crate::migration_map::insert(&mut postings, digest, count.to_string())?;
                    expected_count = expected_count.checked_add(1).ok_or_else(capacity)?;
                }
                if !more {
                    break;
                }
            }
            drop(source);
            let mut retained = FrozenDocuments::open_admitted(&root, &canonical, &token, true)?;
            let retained_manifest = read_manifest(&canonical)?;
            if retained_manifest.version != 2 {
                return Err(integrity());
            }
            // A valid but unrelated old canonical occurrence is not a corrupt
            // receipt. Keep scanning it so later malformed evidence still fails.
            let mut equivalent = retained_manifest.inventory == snapshot.inventory.id
                && retained_manifest.content_sequence == snapshot.content_sequence
                && retained_manifest.enrichment == snapshot.enrichment
                && retained_manifest.gaps == source_manifest.gaps;
            let mut expected_samples = source_manifest.gap_samples;
            for sample in &mut expected_samples {
                rewrite(sample)?;
            }
            equivalent &= expected_samples == retained_manifest.gap_samples;
            let mut actual_count = 0_u64;
            loop {
                let (documents, more) = retained.next_page(1000)?;
                for (payload, text) in documents {
                    check(&token, Instant::now() + Duration::from_secs(15))?;
                    from_frozen_payload(payload.clone(), text.clone())?;
                    let digest = crate::integrity::canonical_hash_with_cancel(
                        &json!(["crate-frozen-replay-posting-v1", payload, text]),
                        &token,
                    )?;
                    match postings.get(&digest) {
                        Some(value) => {
                            let count = value.parse::<u64>().map_err(|_| integrity())?;
                            if let Some(count) = count.checked_sub(1) {
                                crate::migration_map::insert(
                                    &mut postings,
                                    digest,
                                    count.to_string(),
                                )?;
                            } else {
                                equivalent = false;
                            }
                        }
                        None => equivalent = false,
                    }
                    actual_count = actual_count.checked_add(1).ok_or_else(capacity)?;
                }
                if !more {
                    break;
                }
            }
            postings.ensure_healthy()?;
            equivalent &= actual_count == expected_count;
            let open_gaps =
                |reference: &Value, present: bool| -> Result<Option<std::io::BufReader<File>>> {
                    if !present {
                        return Ok(None);
                    }
                    Ok(Some(std::io::BufReader::new(
                        File::open(
                            root.join(reference["path"].as_str().ok_or_else(integrity)?)
                                .join("gaps.ndjson"),
                        )
                        .map_err(|_| unavailable())?,
                    )))
                };
            let mut source_gaps = open_gaps(&original, source_manifest.gap_artifact.is_some())?;
            let mut retained_gaps =
                open_gaps(&canonical, retained_manifest.gap_artifact.is_some())?;
            let mut source_count = 0_u64;
            let mut retained_count = 0_u64;
            loop {
                check(&token, Instant::now() + Duration::from_secs(15))?;
                let read_gap =
                    |reader: &mut Option<std::io::BufReader<File>>| -> Result<Option<Value>> {
                        let Some(reader) = reader else {
                            return Ok(None);
                        };
                        let mut line = Vec::new();
                        let bytes = reader
                            .take(16 * 1024 + 1)
                            .read_until(b'\n', &mut line)
                            .map_err(|_| unavailable())?;
                        if bytes == 0 {
                            return Ok(None);
                        }
                        if line.len() > 16 * 1024 || !line.ends_with(b"\n") {
                            return Err(integrity());
                        }
                        let value: Value =
                            serde_json::from_slice(&line).map_err(|_| integrity())?;
                        if !value.is_object() {
                            return Err(integrity());
                        }
                        Ok(Some(value))
                    };
                let mut expected = read_gap(&mut source_gaps)?;
                let actual = read_gap(&mut retained_gaps)?;
                if expected.is_none() && actual.is_none() {
                    break;
                }
                if let Some(expected) = &mut expected {
                    rewrite(expected)?;
                    source_count = source_count.checked_add(1).ok_or_else(capacity)?;
                }
                if actual.is_some() {
                    retained_count = retained_count.checked_add(1).ok_or_else(capacity)?;
                }
                equivalent &= expected == actual;
            }
            if source_count != source_manifest.gaps || retained_count != retained_manifest.gaps {
                return Err(integrity());
            }
            check(&token, Instant::now() + Duration::from_secs(15))?;
            Ok(equivalent)
        })
        .await?;
    if cancel.is_cancelled() {
        return Err(Error::new(
            "cancelled",
            "Crate replay verification canceled.",
        ));
    }
    Ok(equivalent)
}

fn rebuild_frozen_sync(
    owner: Arc<dyn CrateCorpusStore>,
    root: PathBuf,
    reference: Value,
    snapshot: Snapshot,
    rewrite: PayloadRewrite,
    stop: CancellationToken,
    permit: Option<OwnedSemaphorePermit>,
) -> Result<Value> {
    let mut reader = FrozenDocuments::open_admitted(&root, &reference, &stop, permit.is_none())?;
    let source = root.join(reference["path"].as_str().ok_or_else(integrity)?);
    let bytes = fs::read(source.join("manifest.json")).map_err(|_| unavailable())?;
    if bytes.len() > MAX_MANIFEST {
        return Err(capacity());
    }
    let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|_| integrity())?;
    let mut builder = Builder::begin_admitted(&root, owner, stop.clone(), permit)?;
    loop {
        check(&stop, Instant::now() + Duration::from_secs(15))?;
        let (documents, has_more) = reader.next_page(1000)?;
        for (mut payload, text) in documents {
            rewrite(&mut payload)?;
            if !builder.add(from_frozen_payload(payload, text)?)? {
                return Err(Error::integrity(
                    "Frozen crate migration changed indexed membership.",
                ));
            }
        }
        if !has_more {
            break;
        }
    }
    builder.gap_samples = manifest.gap_samples;
    for gap in &mut builder.gap_samples {
        rewrite(gap)?;
    }
    if manifest.gaps > 0 {
        let mut input = std::io::BufReader::new(
            File::open(source.join("gaps.ndjson")).map_err(|_| unavailable())?,
        );
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(builder.stage.join("gaps.ndjson"))
            .map_err(|_| unavailable())?;
        loop {
            check(&stop, Instant::now() + Duration::from_secs(15))?;
            let mut line = Vec::new();
            let count = (&mut input)
                .take(16 * 1024 + 1)
                .read_until(b'\n', &mut line)
                .map_err(|_| unavailable())?;
            if count == 0 {
                break;
            }
            if line.len() > 16 * 1024 || !line.ends_with(b"\n") {
                return Err(integrity());
            }
            let mut gap: Value = serde_json::from_slice(&line).map_err(|_| integrity())?;
            rewrite(&mut gap)?;
            let mut encoded = serde_json::to_vec(&gap).map_err(|_| integrity())?;
            encoded.push(b'\n');
            builder.gap_bytes = builder
                .gap_bytes
                .checked_add(encoded.len() as u64)
                .filter(|n| *n <= MAX_SHARD)
                .ok_or_else(capacity)?;
            crate::durable_archive::with_write_budget(
                &builder.stage.join("gaps.ndjson"),
                encoded.len() as u64,
                || output.write_all(&encoded),
            )
            .map_err(|_| unavailable())?;
            builder.gaps = builder.gaps.checked_add(1).ok_or_else(capacity)?;
        }
        output.sync_all().map_err(|_| unavailable())?;
        if builder.gaps != manifest.gaps {
            return Err(integrity());
        }
    }
    builder.finish(&snapshot)
}

/// One immutable generation consumed under the caller's maintenance fence.
/// Keep the verified readers and forward position across blocking page workers;
/// restarting a page would repeat both opening and traversal of its prefix.
pub(crate) struct FrozenDocuments {
    opened: Arc<Opened>,
    payload_field: Field,
    text_field: Field,
    shard: usize,
    next_segment: usize,
    segment_id: u32,
    documents: std::vec::IntoIter<u32>,
    admitted_documents: usize,
    pending: Option<FrozenDocument>,
    first_page_deadline: Option<Instant>,
    failed: bool,
    cancel: CancellationToken,
    _permit: Option<OwnedSemaphorePermit>,
    #[cfg(test)]
    visited_documents: usize,
}

struct FrozenDocument {
    payload: Value,
    text: String,
    // Preserve the original serialized payload size, rather than reserializing
    // its Value and changing the retained export's byte accounting.
    bytes: usize,
}

type FrozenDocumentPage = (Vec<(Value, String)>, bool);

impl FrozenDocuments {
    pub(crate) fn open(root: &Path, reference: &Value, cancel: &CancellationToken) -> Result<Self> {
        Self::open_admitted(root, reference, cancel, false)
    }

    fn open_admitted(
        root: &Path,
        reference: &Value,
        cancel: &CancellationToken,
        offline: bool,
    ) -> Result<Self> {
        let deadline = Instant::now() + Duration::from_secs(15);
        check(cancel, deadline)?;
        let permit = if offline {
            None
        } else {
            Some(
                READERS
                    .get_or_init(|| Arc::new(Semaphore::new(2)))
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| capacity())?,
            )
        };
        let opened = open_inner(root, reference, cancel, deadline, offline)?;
        let schema = schema();
        let payload_field = field(&schema, "payload")?;
        let text_field = field(&schema, "technical")?;
        check(cancel, deadline)?;
        Ok(Self {
            opened,
            payload_field,
            text_field,
            shard: 0,
            next_segment: 0,
            segment_id: 0,
            documents: Vec::new().into_iter(),
            admitted_documents: 0,
            pending: None,
            first_page_deadline: Some(deadline),
            failed: false,
            cancel: cancel.clone(),
            _permit: permit,
            #[cfg(test)]
            visited_documents: 0,
        })
    }

    fn next_document(&mut self, deadline: Instant) -> Result<Option<FrozenDocument>> {
        loop {
            check(&self.cancel, deadline)?;
            let Some(document) = self.documents.next() else {
                let Some(searcher) = self.opened.searchers.get(self.shard) else {
                    return Ok(None);
                };
                let Some(segment) = searcher.segment_readers().get(self.next_segment) else {
                    self.shard += 1;
                    self.next_segment = 0;
                    self.admitted_documents = 0;
                    continue;
                };
                self.segment_id = u32::try_from(self.next_segment).map_err(|_| integrity())?;
                self.next_segment += 1;
                // Only one segment's live IDs are retained, bounded cumulatively
                // per shard. Do not scan max_doc's potentially deleted prefix.
                let mut documents = Vec::new();
                for document in segment.doc_ids_alive() {
                    check(&self.cancel, deadline)?;
                    if self.admitted_documents >= MAX_DOCS {
                        return Err(integrity());
                    }
                    self.admitted_documents += 1;
                    documents.push(document);
                }
                check(&self.cancel, deadline)?;
                self.documents = documents.into_iter();
                continue;
            };
            let searcher = self
                .opened
                .searchers
                .get(self.shard)
                .ok_or_else(integrity)?;
            #[cfg(test)]
            {
                self.visited_documents += 1;
            }
            let stored: TantivyDocument = searcher
                .doc(tantivy::DocAddress::new(self.segment_id, document))
                .map_err(|_| integrity())?;
            let payload = stored
                .get_first(self.payload_field)
                .and_then(|v| v.as_str())
                .ok_or_else(integrity)?;
            let text = stored
                .get_first(self.text_field)
                .and_then(|v| v.as_str())
                .ok_or_else(integrity)?;
            let bytes = payload.len().checked_add(text.len()).ok_or_else(capacity)?;
            if bytes > 16 * 1024 * 1024 {
                return Err(capacity());
            }
            return Ok(Some(FrozenDocument {
                payload: serde_json::from_str(payload).map_err(|_| integrity())?,
                text: text.to_owned(),
                bytes,
            }));
        }
    }

    /// Returns exact retained rows and whether another row remains. An empty
    /// generation returns (empty, false) on its first page.
    pub(crate) fn next_page(&mut self, limit: usize) -> Result<FrozenDocumentPage> {
        if self.failed {
            return Err(integrity());
        }
        let result = self.read_page(limit);
        self.failed = result.is_err();
        result
    }

    fn read_page(&mut self, limit: usize) -> Result<FrozenDocumentPage> {
        if !(1..=1000).contains(&limit) {
            return Err(Error::invalid("Invalid crate index export page."));
        }
        // Initial verification and first-page work share the original budget;
        // subsequent pages retain separate bounds, not a generation-wide timer.
        let deadline = self
            .first_page_deadline
            .take()
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(15));
        let mut bytes = 0usize;
        let mut output = Vec::new();
        while output.len() < limit {
            check(&self.cancel, deadline)?;
            let document = match self.pending.take() {
                Some(document) => Some(document),
                None => self.next_document(deadline)?,
            };
            let Some(document) = document else {
                break;
            };
            if !output.is_empty() && bytes.saturating_add(document.bytes) > 16 * 1024 * 1024 {
                self.pending = Some(document);
                break;
            }
            bytes += document.bytes;
            output.push((document.payload, document.text));
        }
        if self.pending.is_none() {
            // One bounded lookahead distinguishes an exact final full page from
            // a continuation across deleted segments or shard boundaries.
            self.pending = self.next_document(deadline)?;
        }
        check(&self.cancel, deadline)?;
        Ok((output, self.pending.is_some()))
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub(crate) struct SearchSpec {
    pub query: Option<String>,
    pub cursor: Option<String>,
    pub mode: String,
    pub class: Option<String>,
    pub name: Option<String>,
    pub version: Option<String>,
    pub target: Option<String>,
    pub path: Option<String>,
    pub kind: Option<String>,
    pub dependency: Option<String>,
    pub license: Option<String>,
    pub keyword: Option<String>,
    pub category: Option<String>,
    pub msrv: Option<String>,
    pub yanked: Option<bool>,
    pub offset: usize,
    pub limit: usize,
}
fn tokens(text: &str, mode: &str, count: &mut usize) -> Result<Vec<(usize, String)>> {
    let mut analyzer = match mode {
        "technical" => analyzer("technical")?,
        "english" => analyzer("english")?,
        _ => {
            return Err(Error::invalid(
                "Crate search mode must be technical or english.",
            ));
        }
    };
    let mut stream = analyzer.token_stream(text);
    let mut tokens = Vec::new();
    while stream.advance() {
        *count += 1;
        if *count > 64 {
            return Err(Error::capacity(
                "Crate full-text queries are limited to 64 tokens.",
            ));
        }
        let token = stream.token();
        if token.text.len() >= MAX_TOKEN_LEN {
            return Err(Error::capacity(
                "Crate query token exceeds engine length limit.",
            ));
        }
        tokens.push((token.position, token.text.clone()));
    }
    Ok(tokens)
}

fn atom_query(field: Field, tokens: Vec<(usize, String)>, phrase: bool) -> Option<Box<dyn Query>> {
    let terms: Vec<_> = tokens
        .into_iter()
        .map(|(offset, term)| (offset, Term::from_field_text(field, &term)))
        .collect();
    if phrase && terms.len() >= 2 {
        return Some(Box::new(PhraseQuery::new_with_offset(terms)));
    }
    let mut clauses: Vec<(Occur, Box<dyn Query>)> = terms
        .into_iter()
        .map(|(_, term)| {
            (
                Occur::Must,
                Box::new(TermQuery::new(
                    term,
                    IndexRecordOption::WithFreqsAndPositions,
                )) as Box<dyn Query>,
            )
        })
        .collect();
    match clauses.len() {
        0 => None,
        1 => clauses.pop().map(|(_, query)| query),
        _ => Some(Box::new(BooleanQuery::new(clauses))),
    }
}

fn conjunction(mut clauses: Vec<(Occur, Box<dyn Query>)>) -> Result<Box<dyn Query>> {
    if clauses.is_empty() {
        return Err(Error::invalid("Crate query contains no searchable tokens."));
    }
    if clauses.iter().all(|(occur, _)| *occur == Occur::MustNot) {
        clauses.push((Occur::Must, Box::new(AllQuery)));
    }
    Ok(Box::new(BooleanQuery::new(clauses)))
}

fn query(field: Field, input: &str, mode: &str) -> Result<Box<dyn Query>> {
    if input.trim().is_empty() || input.chars().count() > 256 {
        return Err(Error::invalid(
            "Crate full-text query must contain 1..256 characters.",
        ));
    }
    let mut count = 0;
    if mode == "technical" {
        return atom_query(field, tokens(input, mode, &mut count)?, false)
            .ok_or_else(|| Error::invalid("Crate query contains no searchable tokens."));
    }
    if mode != "english" {
        return Err(Error::invalid(
            "Crate search mode must be technical or english.",
        ));
    }
    if input
        .chars()
        .any(|c| ":[]{}()*?^~\\+".contains(c) || c.is_control())
    {
        return Err(Error::invalid("Unsupported Crate English query syntax."));
    }
    let chars: Vec<_> = input.chars().collect();
    let mut cursor = 0;
    let mut groups: Vec<Box<dyn Query>> = Vec::new();
    let mut clauses: Vec<(Occur, Box<dyn Query>)> = Vec::new();
    while cursor < chars.len() {
        if chars[cursor].is_whitespace() {
            cursor += 1;
            continue;
        }
        let excluded = chars[cursor] == '-';
        if excluded {
            cursor += 1;
        }
        if cursor == chars.len() || chars[cursor].is_whitespace() || chars[cursor] == '-' {
            return Err(Error::invalid(
                "Crate exclusions require a term or quoted phrase.",
            ));
        }
        let phrase = chars[cursor] == '"';
        if phrase {
            cursor += 1;
        }
        let start = cursor;
        while cursor < chars.len()
            && if phrase {
                chars[cursor] != '"'
            } else {
                !chars[cursor].is_whitespace()
            }
        {
            if !phrase && chars[cursor] == '"' {
                return Err(Error::invalid("Invalid Crate phrase boundary."));
            }
            cursor += 1;
        }
        let text: String = chars[start..cursor].iter().collect();
        if phrase {
            if cursor == chars.len() {
                return Err(Error::invalid("Unterminated Crate search phrase."));
            }
            cursor += 1;
            if cursor < chars.len() && !chars[cursor].is_whitespace() {
                return Err(Error::invalid("Invalid Crate phrase boundary."));
            }
        }
        if !phrase && !excluded && text == "OR" {
            groups.push(conjunction(std::mem::take(&mut clauses))?);
            continue;
        }
        let normalized = tokens(&text, "english", &mut count)?;
        if let Some(atom) = atom_query(field, normalized, phrase) {
            clauses.push((
                if excluded {
                    Occur::MustNot
                } else {
                    Occur::Must
                },
                atom,
            ));
        } else if phrase || excluded {
            return Err(Error::invalid(
                "Crate phrase or exclusion contains no searchable tokens.",
            ));
        }
    }
    groups.push(conjunction(clauses)?);
    if groups.len() == 1 {
        return groups
            .pop()
            .ok_or_else(|| Error::invalid("Empty Crate query."));
    }
    Ok(Box::new(BooleanQuery::new(
        groups
            .into_iter()
            .map(|group| (Occur::Should, group))
            .collect(),
    )))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Continuation {
    #[serde(default)]
    version: u32,
    fingerprint: String,
    rank: Rank,
}
fn continuation(spec: &SearchSpec, reference: &Value) -> Result<(String, Option<Rank>)> {
    let mut normalized = spec.clone();
    normalized.offset = 0;
    normalized.limit = 0;
    normalized.cursor = None;
    if normalized.mode.is_empty() {
        normalized.mode = "technical".into();
    }
    let fingerprint_bytes =
        serde_json::to_vec(&(reference_digest(reference)?, normalized)).map_err(|_| integrity())?;
    let canonical = reference_digest(reference)?.starts_with("blake3:");
    let fingerprint = if canonical {
        hash(&fingerprint_bytes)
    } else {
        crate::integrity::legacy_hash(&fingerprint_bytes)
    };
    let rank = if let Some(cursor) = &spec.cursor {
        if cursor.len() > 16384 || spec.offset != 0 {
            return Err(Error::invalid(
                "Search cursor exceeds limit or conflicts with offset.",
            ));
        }
        let cursor: Continuation =
            serde_json::from_str(cursor).map_err(|_| Error::invalid("Malformed search cursor."))?;
        if cursor.fingerprint != fingerprint
            || cursor.version != if canonical { 2 } else { 0 }
            || !cursor.rank.score.is_finite()
            || cursor.rank.key.name.len() > 64
            || cursor.rank.key.version.len() > 128
            || cursor.rank.key.path.len() > 4096
            || cursor.rank.key.target.len() > 256
            || cursor.rank.key.id.len() > 8192
        {
            return Err(Error::invalid(
                "Search cursor belongs to another snapshot/query or is invalid.",
            ));
        }
        Some(cursor.rank)
    } else {
        None
    };
    Ok((fingerprint, rank))
}

fn search_sync(
    root: &Path,
    reference: &Value,
    spec: SearchSpec,
    cancel: CancellationToken,
) -> Result<Value> {
    let deadline = Instant::now() + Duration::from_secs(15);
    check(&cancel, deadline)?;
    if spec.limit == 0 || spec.limit > 100 || spec.offset > 10000 {
        return Err(Error::invalid(
            "Crate search limit must be 1..100 and offset at most 10000.",
        ));
    }
    let mode = if spec.mode.is_empty() {
        "technical"
    } else {
        &spec.mode
    };
    let schema = schema();
    let textfield = field(&schema, mode)?;
    let mut clauses: Vec<(Occur, Box<dyn Query>)> = Vec::new();
    if let Some(text) = &spec.query {
        if text
            .chars()
            .any(|c| ":[]{}()*?^~\\".contains(c) || c.is_control())
        {
            return Err(Error::invalid("Unsupported crate search query syntax."));
        }
        clauses.push((Occur::Must, query(textfield, text, mode)?));
    }
    for (key, value) in [
        ("class", spec.class.as_ref()),
        ("name", spec.name.as_ref()),
        ("version", spec.version.as_ref()),
        ("target", spec.target.as_ref()),
        ("path", spec.path.as_ref()),
        ("kind", spec.kind.as_ref()),
        ("dependency", spec.dependency.as_ref()),
        ("license", spec.license.as_ref()),
        ("keyword", spec.keyword.as_ref()),
        ("category", spec.category.as_ref()),
    ] {
        if let Some(value) = value {
            if value.len() > 4096 {
                return Err(Error::invalid("Crate search filter exceeds limit."));
            }
            clauses.push((
                Occur::Must,
                Box::new(TermQuery::new(
                    Term::from_field_text(field(&schema, key)?, value),
                    IndexRecordOption::Basic,
                )),
            ));
        }
    }
    if let Some(yanked) = spec.yanked {
        clauses.push((
            Occur::Must,
            Box::new(TermQuery::new(
                Term::from_field_u64(field(&schema, "yanked")?, u64::from(yanked)),
                IndexRecordOption::Basic,
            )),
        ));
    }
    if let Some(value) = &spec.msrv {
        clauses.push((
            Occur::Must,
            Box::new(RangeQuery::new(
                Bound::Included(Term::from_field_u64(field(&schema, "msrv")?, 0)),
                Bound::Included(Term::from_field_u64(field(&schema, "msrv")?, msrv(value)?)),
            )),
        ));
    }
    let query: Box<dyn Query> = if clauses.is_empty() {
        Box::new(AllQuery)
    } else {
        Box::new(BooleanQuery::new(clauses))
    };
    let (fingerprint, after) = continuation(&spec, reference)?;
    let opened = open(root, reference, &cancel, deadline)?;
    let mut total = 0usize;
    let mut found: Vec<(Rank, usize, tantivy::DocAddress)> = Vec::new();
    let keep = spec.offset.saturating_add(spec.limit).saturating_add(1);
    let scored = spec.query.is_some();
    for (shard_number, searcher) in opened.searchers.iter().enumerate() {
        check(&cancel, deadline)?;
        let broken = Arc::new(AtomicBool::new(false));
        let broken_segment = broken.clone();
        let after = after.clone();
        let top = TopDocs::with_limit(keep).tweak_score(move |segment: &tantivy::SegmentReader| {
            let column = segment.fast_fields().str("tie").ok().flatten();
            let broken = broken_segment.clone();
            let after = after.clone();
            move |doc, score| {
                let mut text = String::new();
                let identity = column
                    .as_ref()
                    .and_then(|c| {
                        c.term_ords(doc)
                            .next()
                            .and_then(|ord| c.ord_to_str(ord, &mut text).ok().filter(|ok| *ok))
                    })
                    .and_then(|_| serde_json::from_str::<Identity>(&text).ok());
                let key = identity.unwrap_or_else(|| {
                    broken.store(true, Ordering::Relaxed);
                    Identity {
                        name: String::new(),
                        version: String::new(),
                        target: String::new(),
                        path: String::new(),
                        id: String::new(),
                    }
                });
                let mut rank = Rank {
                    score: if scored { score } else { 0.0 },
                    key,
                };
                if after.as_ref().is_some_and(|cursor| {
                    rank.partial_cmp(cursor)
                        .is_some_and(|order| order != CmpOrdering::Less)
                }) {
                    rank.score = f32::NEG_INFINITY;
                }
                rank
            }
        });
        let (count, hits) = searcher
            .search_with_statistics_provider(query.as_ref(), &(Count, top), opened.as_ref())
            .map_err(|_| unavailable())?;
        if broken.load(Ordering::Relaxed) {
            return Err(integrity());
        }
        total = total.saturating_add(count);
        for (rank, address) in hits {
            if rank.score.is_finite() {
                found.push((rank, shard_number, address));
            }
        }
        if found
            .iter()
            .map(|(rank, _, _)| {
                rank.key.name.len()
                    + rank.key.version.len()
                    + rank.key.target.len()
                    + rank.key.path.len()
                    + rank.key.id.len()
                    + 128
            })
            .sum::<usize>()
            > 32 * 1024 * 1024
        {
            return Err(capacity());
        }
        found.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(CmpOrdering::Equal));
        found.truncate(keep);
    }
    check(&cancel, deadline)?;
    let more = found.len() > spec.offset.saturating_add(spec.limit);
    let next_rank = if more {
        found
            .get(spec.offset + spec.limit - 1)
            .map(|(rank, _, _)| rank.clone())
    } else {
        None
    };
    let next_cursor = next_rank
        .map(|rank| {
            serde_json::to_string(&Continuation {
                version: if reference_digest(reference)?.starts_with("blake3:") {
                    2
                } else {
                    0
                },
                fingerprint,
                rank,
            })
            .map_err(|_| integrity())
        })
        .transpose()?;
    if next_cursor
        .as_ref()
        .is_some_and(|cursor| cursor.len() > 16384)
    {
        return Err(capacity());
    }
    let mut items = Vec::new();
    let mut output_bytes = 0usize;
    for (rank, shard, address) in found.into_iter().skip(spec.offset).take(spec.limit) {
        check(&cancel, deadline)?;
        let searcher = &opened.searchers[shard];
        let stored: TantivyDocument = searcher.doc(address).map_err(|_| integrity())?;
        let payload = stored
            .get_first(field(&schema, "payload")?)
            .and_then(|v| v.as_str())
            .ok_or_else(integrity)?;
        output_bytes = output_bytes.saturating_add(payload.len() + 1024);
        if output_bytes > 256 * 1024 {
            return Err(capacity());
        }
        let document: Value = serde_json::from_str(payload).map_err(|_| integrity())?;
        let text = stored
            .get_first(field(&schema, "technical")?)
            .and_then(|v| v.as_str())
            .ok_or_else(integrity)?;
        let excerpt: String = text.chars().take(256).collect();
        items.push(json!({"score":rank.score,"document":document,"excerpt":excerpt}));
    }
    Ok(
        json!({"items":items,"total":total,"offset":spec.offset,"next_offset":if spec.cursor.is_none() && more && spec.offset.saturating_add(spec.limit)<=10000 {Some(spec.offset+spec.limit)}else{None},"next_cursor":next_cursor,"ranking":"snapshot_global_bm25","search_coverage":{"skipped_documents":opened.gaps,"complete":opened.gaps==0}}),
    )
}

pub(crate) async fn search(root: PathBuf, reference: Value, spec: SearchSpec) -> Result<Value> {
    let permit = READERS
        .get_or_init(|| Arc::new(Semaphore::new(2)))
        .clone()
        .try_acquire_owned()
        .map_err(|_| capacity())?;
    struct CancelOnDrop(CancellationToken);
    impl Drop for CancelOnDrop {
        fn drop(&mut self) {
            self.0.cancel();
        }
    }
    let cancel = CancellationToken::new();
    let _guard = CancelOnDrop(cancel.clone());
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        search_sync(&root, &reference, spec, cancel)
    })
    .await
    .map_err(|_| unavailable())?
}

/// Background maintenance verifies a large immutable snapshot before publication.
/// Foreground requests still have a separate 15-second cold-open budget.
pub async fn prewarm(root: PathBuf, reference: Value, shutdown: CancellationToken) -> Result<()> {
    let permit = READERS
        .get_or_init(|| Arc::new(Semaphore::new(2)))
        .clone()
        .try_acquire_owned()
        .map_err(|_| capacity())?;
    struct CancelOnDrop(CancellationToken);
    impl Drop for CancelOnDrop {
        fn drop(&mut self) {
            self.0.cancel();
        }
    }
    let cancel = shutdown.child_token();
    let _guard = CancelOnDrop(cancel.clone());
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let opened = open(
            &root,
            &reference,
            &cancel,
            Instant::now() + Duration::from_secs(3600),
        )?;
        check(&cancel, Instant::now() + Duration::from_secs(1))?;
        let key = cache_key(&root, &reference)?;
        CACHE
            .get_or_init(|| Mutex::new(ReaderCache::default()))
            .lock()
            .map_err(|_| unavailable())?
            .prepared = Some((key, opened));
        Ok(())
    })
    .await
    .map_err(|_| unavailable())?
}

#[cfg(test)]
#[path = "index/tests.rs"]
pub(crate) mod tests;

#[cfg(test)]
pub(crate) static TEST_BUILD: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(test)]
mod frozen_tests {
    use super::*;

    type RetainedRows = BTreeMap<String, (Value, String)>;

    fn document(number: usize, text: String) -> IndexDocument {
        from_frozen_payload(
            json!({
                "class":"version",
                "record":{
                    "name":format!("fixture{number:05}"),
                    "version":"1.0.0",
                    "metadata_capture":hash(format!("capture {number}").as_bytes()),
                    "record":{"yanked":false}
                },
                "enrichment":{}
            }),
            text,
        )
        .unwrap()
    }

    fn builder(root: &Path, store: Arc<tests::FixtureStore>) -> Builder {
        let permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        Builder::begin(root, store, CancellationToken::new(), permit).unwrap()
    }

    fn counts(root: &Path, reference: &Value) -> (u64, u64) {
        OPEN_COUNTS
            .lock()
            .unwrap()
            .get(&root.join(reference["path"].as_str().unwrap()))
            .copied()
            .unwrap_or_default()
    }

    fn retained_rows(
        root: &Path,
        reference: &Value,
        page_size: usize,
    ) -> (RetainedRows, usize, usize) {
        let mut reader = FrozenDocuments::open(root, reference, &CancellationToken::new()).unwrap();
        let mut result = BTreeMap::new();
        let mut pages = 0;
        loop {
            let (rows, has_more) = reader.next_page(page_size).unwrap();
            pages += 1;
            assert!(!has_more || !rows.is_empty());
            for (payload, text) in rows {
                let name = payload["record"]["name"].as_str().unwrap().to_owned();
                assert!(result.insert(name, (payload, text)).is_none());
            }
            if !has_more {
                break;
            }
        }
        (result, reader.visited_documents, pages)
    }

    #[tokio::test]
    async fn offline_frozen_rebuilds_share_workers_and_bypass_serving_gates() {
        let _serial = TEST_BUILD.lock().await;
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let store = tests::fixture();
        let snapshot = store.snapshot.lock().unwrap().clone();
        let mut builder = builder(root.path(), store.clone());
        assert!(
            builder
                .add(document(1, "retained transport cats".into()))
                .unwrap()
        );
        assert!(
            builder
                .add(document(2, "retained transport dogs".into()))
                .unwrap()
        );
        let reference = builder.finish(&snapshot).unwrap();
        let writer = WRITER
            .get_or_init(|| Arc::new(Semaphore::new(1)))
            .clone()
            .try_acquire_owned()
            .unwrap();
        let readers = READERS
            .get_or_init(|| Arc::new(Semaphore::new(2)))
            .clone()
            .try_acquire_many_owned(2)
            .unwrap();
        let context =
            crate::MigrationExecution::new(crate::MigrationExecutionOptions::new(2, 1024).unwrap())
                .unwrap();
        let gate = Arc::new(std::sync::Barrier::new(2));
        let rewrite: PayloadRewrite = Arc::new(move |_| {
            gate.wait();
            Ok(())
        });
        let (first, second) = tokio::join!(
            rebuild_frozen_with_execution(
                store.clone(),
                root.path().to_owned(),
                reference.clone(),
                snapshot.clone(),
                rewrite.clone(),
                CancellationToken::new(),
                &context
            ),
            rebuild_frozen_with_execution(
                store.clone(),
                root.path().to_owned(),
                reference.clone(),
                snapshot,
                rewrite,
                CancellationToken::new(),
                &context
            ),
        );
        let first = first.unwrap();
        let second = second.unwrap();
        assert_eq!(context.snapshot().high_water, 2);
        assert_eq!(context.snapshot().active, 0);
        assert_eq!(READERS.get().unwrap().available_permits(), 0);
        assert_eq!(WRITER.get().unwrap().available_permits(), 0);
        drop(readers);
        drop(writer);
        assert_eq!(
            retained_rows(root.path(), &first, 100).0,
            retained_rows(root.path(), &reference, 100).0
        );
        assert_eq!(
            retained_rows(root.path(), &second, 100).0,
            retained_rows(root.path(), &reference, 100).0
        );
    }

    #[tokio::test]
    async fn frozen_rebuild_opens_once_and_preserves_multishard_rows_deletions_and_gaps() {
        let _serial = TEST_BUILD.lock().await;
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let store = tests::fixture();
        let mut snapshot = store.snapshot.lock().unwrap().clone();
        let mut builder = builder(root.path(), store.clone());
        builder.document_limit = 600;
        let mut expected = BTreeMap::new();
        for number in 1..=2507 {
            let input = document(number, format!("original retained transport {number}"));
            expected.insert(
                input.identity.name.clone(),
                (input.payload.clone(), input.text.clone()),
            );
            assert!(builder.add(input).unwrap());
            if number % 200 == 0 {
                builder.writer.as_mut().unwrap().commit().unwrap();
            }
            if number == 300 {
                builder
                    .writer
                    .as_ref()
                    .unwrap()
                    .delete_term(Term::from_field_text(
                        field(&schema(), "name").unwrap(),
                        "fixture00001",
                    ));
                builder.documents -= 1;
                expected.remove("fixture00001");
            }
        }
        assert!(
            !builder
                .add(document(99999, "a".repeat(MAX_TOKEN_LEN)))
                .unwrap()
        );
        let original = builder.finish(&snapshot).unwrap();
        assert!(original["shards"].as_u64().unwrap() > 1);
        let before = counts(root.path(), &original);
        snapshot.id = hash(b"canonical multishard frozen fixture");
        snapshot.inventory.id = hash(b"canonical multishard fixture inventory");
        let rewrite: PayloadRewrite = Arc::new(|payload| {
            if let Some(capture) = payload["record"]["metadata_capture"].as_str() {
                payload["record"]["metadata_capture"] = json!(hash(capture.as_bytes()));
            }
            Ok(())
        });
        let started = Instant::now();
        let rebuilt = rebuild_frozen(
            store.clone(),
            root.path().to_owned(),
            original.clone(),
            snapshot.clone(),
            rewrite.clone(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        let elapsed = started.elapsed();
        let after = counts(root.path(), &original);
        assert_eq!((after.0 - before.0, after.1 - before.1), (1, 1));
        let (source, visited, pages) = retained_rows(root.path(), &original, 237);
        assert_eq!(source, expected);
        assert_eq!(visited, expected.len());
        assert!(pages > 2);
        for (payload, _) in expected.values_mut() {
            rewrite(payload).unwrap();
        }
        let (retained, visited, _) = retained_rows(root.path(), &rebuilt, 237);
        assert_eq!(retained, expected);
        assert_eq!(visited, expected.len());
        assert_eq!(rebuilt["skipped_documents"], 1);
        assert_eq!(rebuilt["gap_samples"], original["gap_samples"]);
        assert_eq!(
            fs::read(
                root.path()
                    .join(original["path"].as_str().unwrap())
                    .join("gaps.ndjson")
            )
            .unwrap(),
            fs::read(
                root.path()
                    .join(rebuilt["path"].as_str().unwrap())
                    .join("gaps.ndjson")
            )
            .unwrap(),
        );
        let before = counts(root.path(), &original);
        let started = Instant::now();
        let replay = rebuild_frozen(
            store,
            root.path().to_owned(),
            original.clone(),
            snapshot.clone(),
            rewrite.clone(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        let replay_elapsed = started.elapsed();
        let after = counts(root.path(), &original);
        let replay_verifications = after.1 - before.1;
        assert_eq!(after.0 - before.0, 1);
        // The existing bounded cache can evict this generation while other
        // fixture readers run. A cursor still opens and verifies at most once.
        assert!(replay_verifications <= 1);
        assert_eq!(retained_rows(root.path(), &replay, 1000).0, expected);
        eprintln!(
            "Crate frozen fixture: {} live rows, {pages} pages; rebuild {elapsed:?}, replay {replay_elapsed:?}; cold open/verification 1/1, replay open/verification 1/{replay_verifications}; exactly {} visits per full cursor",
            expected.len(),
            expected.len(),
        );
        let context =
            crate::MigrationExecution::new(crate::MigrationExecutionOptions::new(2, 1024).unwrap())
                .unwrap();
        let directories = fs::read_dir(root.path().join("crate-indexes"))
            .unwrap()
            .count();
        assert!(
            verify_frozen_replay_with_execution(
                root.path().to_owned(),
                original.clone(),
                rebuilt.clone(),
                snapshot.clone(),
                rewrite.clone(),
                CancellationToken::new(),
                &context,
            )
            .await
            .unwrap()
        );
        assert_eq!(
            fs::read_dir(root.path().join("crate-indexes"))
                .unwrap()
                .count(),
            directories,
            "receipt verification creates no permanent index generation"
        );
        let mut wrong_snapshot = snapshot.clone();
        wrong_snapshot.content_sequence += 1;
        assert!(
            verify_frozen_replay_with_execution(
                root.path().to_owned(),
                original.clone(),
                rebuilt.clone(),
                wrong_snapshot,
                rewrite.clone(),
                CancellationToken::new(),
                &context
            )
            .await
            .is_ok_and(|equivalent| !equivalent),
            "a fully verified unrelated canonical manifest is a semantic nonmatch"
        );
        let manifest: Manifest = serde_json::from_slice(
            &fs::read(
                root.path()
                    .join(rebuilt["path"].as_str().unwrap())
                    .join("manifest.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let shard = &manifest.shards[0];
        let path = root
            .path()
            .join(rebuilt["path"].as_str().unwrap())
            .join(&shard.name)
            .join(shard.files.keys().next().unwrap());
        OpenOptions::new()
            .append(true)
            .open(path)
            .unwrap()
            .write_all(b"changed after receipt")
            .unwrap();
        assert!(
            verify_frozen_replay_with_execution(
                root.path().to_owned(),
                original,
                rebuilt,
                snapshot,
                rewrite,
                CancellationToken::new(),
                &context
            )
            .await
            .is_err(),
            "receipt reuse rehashes canonical bytes after cached reads"
        );
        assert_eq!(context.snapshot().active, 0);
    }

    #[test]
    fn frozen_byte_pages_keep_pending_rows_and_reader_admission() {
        let _serial = TEST_BUILD.blocking_lock();
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let store = tests::fixture();
        let snapshot = store.snapshot.lock().unwrap().clone();
        let mut builder = builder(root.path(), store);
        let text = format!("transport{}", " ".repeat(MAX_TEXT - 10));
        for number in 1..=5 {
            assert!(builder.add(document(number, text.clone())).unwrap());
        }
        let reference = builder.finish(&snapshot).unwrap();
        let stop = CancellationToken::new();
        let mut reader = FrozenDocuments::open(root.path(), &reference, &stop).unwrap();
        let (first, more) = reader.next_page(1000).unwrap();
        assert!(more);
        assert_eq!(first.len(), 3);
        assert_eq!(reader.visited_documents, 4);
        let bytes: usize = first
            .iter()
            .map(|(payload, text)| serde_json::to_vec(payload).unwrap().len() + text.len())
            .sum();
        assert!(bytes <= 16 * 1024 * 1024);
        let (last, more) = reader.next_page(1000).unwrap();
        assert!(!more);
        assert_eq!(last.len(), 2);
        assert_eq!(reader.visited_documents, 5);
        assert!(
            first
                .iter()
                .chain(&last)
                .all(|(_, retained)| retained == &text)
        );
        assert_eq!(
            first
                .into_iter()
                .chain(last)
                .map(|(payload, _)| payload["record"]["name"].as_str().unwrap().to_owned())
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            5
        );
        assert_eq!(reader.next_page(1000).unwrap(), (Vec::new(), false));
        let second = FrozenDocuments::open(root.path(), &reference, &stop).unwrap();
        assert_eq!(
            FrozenDocuments::open(root.path(), &reference, &stop)
                .err()
                .unwrap()
                .code,
            "capacity"
        );
        drop(second);
        drop(reader);
        assert_eq!(READERS.get().unwrap().available_permits(), 2);
    }

    #[test]
    fn frozen_cancellation_deadlines_empty_and_terminal_errors_are_bounded() {
        let _serial = TEST_BUILD.blocking_lock();
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let store = tests::fixture();
        let snapshot = store.snapshot.lock().unwrap().clone();
        let empty = builder(root.path(), store.clone())
            .finish(&snapshot)
            .unwrap();
        let mut reader =
            FrozenDocuments::open(root.path(), &empty, &CancellationToken::new()).unwrap();
        assert_eq!(reader.next_page(1).unwrap(), (Vec::new(), false));
        assert_eq!(reader.visited_documents, 0);
        drop(reader);
        let mut builder = builder(root.path(), store);
        for number in 1..=3 {
            assert!(
                builder
                    .add(document(number, "retained transport".into()))
                    .unwrap()
            );
        }
        let reference = builder.finish(&snapshot).unwrap();
        let stop = CancellationToken::new();
        let mut reader = FrozenDocuments::open(root.path(), &reference, &stop).unwrap();
        assert_eq!(reader.next_page(1).unwrap().0.len(), 1);
        assert_eq!(
            reader.visited_documents, 2,
            "bounded continuation lookahead"
        );
        stop.cancel();
        assert_eq!(reader.next_page(1).unwrap_err().code, "cancelled");
        assert_eq!(reader.visited_documents, 2);
        assert_eq!(reader.next_page(1).unwrap_err().code, "integrity");
        drop(reader);
        assert_eq!(
            FrozenDocuments::open(root.path(), &Value::Null, &stop)
                .err()
                .unwrap()
                .code,
            "cancelled"
        );
        let mut reader =
            FrozenDocuments::open(root.path(), &reference, &CancellationToken::new()).unwrap();
        reader.first_page_deadline = Some(Instant::now() - Duration::from_secs(1));
        assert_eq!(reader.next_page(1).unwrap_err().code, "capacity");
        assert_eq!(reader.visited_documents, 0);
        assert_eq!(reader.next_page(1).unwrap_err().code, "integrity");
        drop(reader);
        for limit in [0, 1001] {
            let mut reader =
                FrozenDocuments::open(root.path(), &reference, &CancellationToken::new()).unwrap();
            assert_eq!(reader.next_page(limit).unwrap_err().code, "invalid_input");
        }
    }

    #[test]
    fn frozen_open_rejects_manifest_and_shard_corruption_before_rows() {
        let _serial = TEST_BUILD.blocking_lock();
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let store = tests::fixture();
        let snapshot = store.snapshot.lock().unwrap().clone();
        for name in ["manifest.json", "shard-0000/meta.json"] {
            let mut builder = builder(root.path(), store.clone());
            builder
                .add(document(1, "retained transport".into()))
                .unwrap();
            let reference = builder.finish(&snapshot).unwrap();
            let path = root
                .path()
                .join(reference["path"].as_str().unwrap())
                .join(name);
            fs::write(path, b"corrupt retained bytes").unwrap();
            assert_eq!(
                FrozenDocuments::open(root.path(), &reference, &CancellationToken::new())
                    .err()
                    .unwrap()
                    .code,
                "integrity"
            );
        }
        assert_eq!(READERS.get().unwrap().available_permits(), 2);
    }

    fn qualify(root: &Path, path: &Path) {
        let (digest, bytes) = crate::integrity::file_digest(
            path,
            MAX_SHARD,
            Instant::now() + Duration::from_secs(15),
        )
        .unwrap();
        let evidence = crate::integrity::FileEvidence {
            version: 1,
            path: path.strip_prefix(root).unwrap().to_str().unwrap().into(),
            digest,
            bytes,
        };
        let descriptor = crate::integrity::evidence_path(root, path).unwrap();
        fs::write(descriptor, serde_json::to_vec(&evidence).unwrap()).unwrap();
    }

    #[test]
    fn frozen_legacy_cursor_requires_manifest_and_file_blake3_evidence() {
        let _serial = TEST_BUILD.blocking_lock();
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let store = tests::fixture();
        let snapshot = store.snapshot.lock().unwrap().clone();
        let mut builder = builder(root.path(), store);
        builder
            .add(document(1, "retained transport".into()))
            .unwrap();
        let mut reference = builder.finish(&snapshot).unwrap();
        let directory = root.path().join(reference["path"].as_str().unwrap());
        let path = directory.join("manifest.json");
        let mut manifest: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        manifest["version"] = json!(1);
        for shard in manifest["shards"].as_array_mut().unwrap() {
            let name = shard["name"].as_str().unwrap().to_owned();
            for (file, descriptor) in shard["files"].as_object_mut().unwrap() {
                descriptor.as_object_mut().unwrap().remove("digest");
                descriptor["sha256"] = json!(crate::integrity::legacy_hash(
                    &fs::read(directory.join(&name).join(file)).unwrap()
                ));
            }
        }
        let bytes = serde_json::to_vec(&manifest).unwrap();
        fs::write(&path, &bytes).unwrap();
        reference.as_object_mut().unwrap().remove("digest");
        reference["sha256"] = json!(crate::integrity::legacy_hash(&bytes));
        let stop = CancellationToken::new();
        assert!(FrozenDocuments::open(root.path(), &reference, &stop).is_err());
        qualify(root.path(), &path);
        let metadata = directory.join("shard-0000/meta.json");
        let evidence_path = crate::integrity::evidence_path(root.path(), &metadata).unwrap();
        fs::remove_file(&evidence_path).unwrap();
        assert!(FrozenDocuments::open(root.path(), &reference, &stop).is_err());
        qualify(root.path(), &metadata);
        let mut evidence: Value =
            serde_json::from_slice(&fs::read(&evidence_path).unwrap()).unwrap();
        evidence["digest"] = json!(hash(b"wrong legacy proof"));
        fs::write(&evidence_path, serde_json::to_vec(&evidence).unwrap()).unwrap();
        assert!(FrozenDocuments::open(root.path(), &reference, &stop).is_err());
        qualify(root.path(), &metadata);
        let mut reader = FrozenDocuments::open(root.path(), &reference, &stop).unwrap();
        let (rows, has_more) = reader.next_page(1).unwrap();
        assert!(!has_more);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1, "retained transport");
    }

    #[tokio::test]
    async fn frozen_rebuild_cancellation_and_rewrite_errors_remove_unpublished_stages() {
        let _serial = TEST_BUILD.lock().await;
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let store = tests::fixture();
        let snapshot = store.snapshot.lock().unwrap().clone();
        let mut builder = builder(root.path(), store.clone());
        builder
            .add(document(1, "retained transport".into()))
            .unwrap();
        let reference = builder.finish(&snapshot).unwrap();
        let failed: PayloadRewrite =
            Arc::new(|_| Err(Error::integrity("Fixture rewrite rejected.")));
        assert_eq!(
            rebuild_frozen(
                store.clone(),
                root.path().to_owned(),
                reference.clone(),
                snapshot.clone(),
                failed,
                CancellationToken::new()
            )
            .await
            .unwrap_err()
            .code,
            "integrity"
        );
        let stop = CancellationToken::new();
        let trigger = stop.clone();
        let cancel: PayloadRewrite = Arc::new(move |_| {
            trigger.cancel();
            Ok(())
        });
        assert_eq!(
            rebuild_frozen(
                store,
                root.path().to_owned(),
                reference.clone(),
                snapshot,
                cancel,
                stop
            )
            .await
            .unwrap_err()
            .code,
            "cancelled"
        );
        assert!(
            fs::read_dir(root.path().join("crate-indexes"))
                .unwrap()
                .all(|entry| !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".stage-"))
        );
        assert_eq!(retained_rows(root.path(), &reference, 1).0.len(), 1);
        assert_eq!(WRITER.get().unwrap().available_permits(), 1);
        assert_eq!(READERS.get().unwrap().available_permits(), 2);
    }
}
