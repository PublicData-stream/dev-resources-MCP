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
    io::{Read, Write},
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
    hex::encode(Sha256::digest(bytes))
}
fn valid_hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
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
    sha256: String,
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
    let m = fs::symlink_metadata(path).map_err(|_| unavailable())?;
    if !m.is_file() || m.file_type().is_symlink() || m.len() > MAX_SHARD {
        return Err(integrity());
    }
    let mut input = File::open(path).map_err(|_| unavailable())?;
    let mut hash = Sha256::new();
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
    }
    if bytes != m.len() {
        return Err(integrity());
    }
    Ok(Digest {
        bytes,
        sha256: hex::encode(hash.finalize()),
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
    _permit: OwnedSemaphorePermit,
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
        let stage = base.join(format!(".stage-{id}"));
        fs::create_dir(&stage).map_err(|_| unavailable())?;
        Ok(Self {
            writer: None,
            index: None,
            stage,
            destination: base.join(&id),
            relative: format!("crate-indexes/{id}"),
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
        let index = Index::create_in_dir(&directory, schema()).map_err(|_| unavailable())?;
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
        output.write_all(&bytes).map_err(|_| unavailable())?;
        self.gaps += 1;
        if self.gap_samples.len() < 20 {
            self.gap_samples.push(gap);
        }
        Ok(false)
    }
    fn add(&mut self, input: IndexDocument) -> Result<bool> {
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
            version: 1,
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
        output
            .write_all(&bytes)
            .and_then(|()| output.sync_all())
            .map_err(|_| unavailable())?;
        File::open(&self.stage)
            .and_then(|f| f.sync_all())
            .map_err(|_| unavailable())?;
        fs::rename(&self.stage, &self.destination).map_err(|_| unavailable())?;
        File::open(self.destination.parent().ok_or_else(integrity)?)
            .and_then(|f| f.sync_all())
            .map_err(|_| unavailable())?;
        self.published = true;
        let _ = &self.owner;
        Ok(
            json!({"version":1,"path":self.relative,"sha256":hash(&bytes),"inventory":snapshot.inventory.id,"content_sequence":snapshot.content_sequence,"enrichment":snapshot.enrichment,"documents":manifest.shards.iter().map(|s|s.documents as u64).sum::<u64>(),"shards":manifest.shards.len(),"ranking":"snapshot_global_bm25","skipped_documents":manifest.gaps,"gap_samples":manifest.gap_samples,"complete_search_coverage":manifest.gaps==0}),
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
        .filter(|s| valid_hash(s))
        .ok_or_else(integrity)?;
    let expected = reference["sha256"]
        .as_str()
        .filter(|s| valid_hash(s))
        .ok_or_else(integrity)?;
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
    check(cancel, deadline)?;
    let path = reference["path"].as_str().ok_or_else(unavailable)?;
    let expected = reference["sha256"]
        .as_str()
        .filter(|s| valid_hash(s))
        .ok_or_else(integrity)?;
    let id = path
        .strip_prefix("crate-indexes/")
        .filter(|s| valid_hash(s))
        .ok_or_else(integrity)?;
    let base = fs::canonicalize(root)
        .map_err(|_| unavailable())?
        .join("crate-indexes");
    real_directory(&base)?;
    let directory = base.join(id);
    real_directory(&directory)?;
    let key = format!("{}:{expected}", directory.display());
    let cache = CACHE.get_or_init(|| Mutex::new(ReaderCache::default()));
    if let Some(opened) = cache.lock().map_err(|_| unavailable())?.get(&key) {
        return Ok(opened);
    }
    let path = directory.join("manifest.json");
    let meta = fs::symlink_metadata(&path).map_err(|_| unavailable())?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > MAX_MANIFEST as u64 {
        return Err(integrity());
    }
    let bytes = fs::read(&path).map_err(|_| unavailable())?;
    if hash(&bytes) != expected {
        return Err(integrity());
    }
    let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|_| integrity())?;
    if manifest.version != 1
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
        real_directory(&path)?;
        if files(&path)? != shard.files.keys().cloned().collect::<Vec<_>>() {
            return Err(integrity());
        }
        let mut size = 0;
        for (name, expected) in &shard.files {
            if !file_name(name) || !valid_hash(&expected.sha256) {
                return Err(integrity());
            }
            let actual = digest(&path.join(name), cancel, deadline)?;
            size += actual.bytes;
            if size > MAX_SHARD
                || actual.bytes != expected.bytes
                || actual.sha256 != expected.sha256
            {
                return Err(integrity());
            }
        }
        let index = Index::open_in_dir(&path).map_err(|_| integrity())?;
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
        let actual = digest(&directory.join("gaps.ndjson"), cancel, deadline)?;
        if actual.bytes != expected.bytes || actual.sha256 != expected.sha256 {
            return Err(integrity());
        }
    } else if manifest.gaps != 0 {
        return Err(integrity());
    }
    let opened = Arc::new(Opened {
        _readers: readers,
        searchers,
        gaps: manifest.gaps,
    });
    let mut cache = cache.lock().map_err(|_| unavailable())?;
    cache.retain_history(key, opened.clone());
    Ok(opened)
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
    let fingerprint = hash(
        &serde_json::to_vec(&(
            reference["sha256"].as_str().ok_or_else(unavailable)?,
            normalized,
        ))
        .map_err(|_| integrity())?,
    );
    let rank = if let Some(cursor) = &spec.cursor {
        if cursor.len() > 16384 || spec.offset != 0 {
            return Err(Error::invalid(
                "Search cursor exceeds limit or conflicts with offset.",
            ));
        }
        let cursor: Continuation =
            serde_json::from_str(cursor).map_err(|_| Error::invalid("Malformed search cursor."))?;
        if cursor.fingerprint != fingerprint
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
            serde_json::to_string(&Continuation { fingerprint, rank }).map_err(|_| integrity())
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
