//! Immutable MDN projection shards with snapshot-selected BM25 statistics.
use devres_domain::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet, HashMap},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, OnceLock, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering as AtomicOrdering},
    },
    time::{Duration, Instant},
};
use tantivy::{
    Index, IndexReader, Searcher, TantivyDocument, Term,
    collector::{Collector, Count, SegmentCollector, TopDocs},
    indexer::IndexWriterOptions,
    query::{
        AllQuery, Bm25StatisticsProvider, BooleanQuery, Occur, PhraseQuery, Query, TermQuery,
        TermSetQuery,
    },
    schema::{
        FAST, Field, IndexRecordOption, STORED, STRING, Schema, TextFieldIndexing, TextOptions,
        Value as _,
    },
    tokenizer::{
        Language, LowerCaser, MAX_TOKEN_LEN, SimpleTokenizer, Stemmer, StopWordFilter,
        TextAnalyzer, TokenStream,
    },
};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

const FORMAT_VERSION: u32 = 2;
const MAX_SHARDS: usize = 4096;
const MAX_DOCS: usize = 50_000;
const MAX_BYTES: u64 = 32 * 1024 * 1024 * 1024;
const MAX_MANIFEST: usize = 2 * 1024 * 1024;
static STAGE: AtomicU64 = AtomicU64::new(0);
static WRITERS: OnceLock<Arc<Semaphore>> = OnceLock::new();
static READERS: OnceLock<Arc<Semaphore>> = OnceLock::new();
#[cfg(test)]
pub(crate) static TEST_GATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
fn failure() -> Error {
    Error::unavailable("MDN search index unavailable.")
}
fn integrity() -> Error {
    Error::integrity("MDN search index integrity failed.")
}
fn capacity() -> Error {
    Error::capacity("MDN search processing bound exceeded.")
}
fn check(cancel: &CancellationToken, deadline: Instant) -> Result<()> {
    if cancel.is_cancelled() {
        return Err(Error::new("cancelled", "MDN search canceled."));
    }
    if Instant::now() >= deadline {
        return Err(capacity());
    }
    Ok(())
}
pub(crate) fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn valid_hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn field(schema: &Schema, name: &str) -> Result<Field> {
    schema.get_field(name).map_err(|_| integrity())
}
fn real_directory(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path).map_err(|_| failure())?;
    if !m.is_dir() || m.file_type().is_symlink() {
        return Err(integrity());
    }
    Ok(())
}
fn safe_file(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && !name.contains("..")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IndexDocument {
    pub id: String,
    pub kind: String,
    pub slug: String,
    pub title: String,
    pub path: String,
    pub text: String,
    pub metadata: Value,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchSpec {
    pub query: Option<String>,
    pub snapshot: Option<String>,
    #[serde(default = "technical")]
    pub mode: String,
    #[serde(default)]
    pub filters: BTreeMap<String, String>,
    #[serde(default)]
    pub offset: usize,
    #[serde(default = "twenty")]
    pub limit: usize,
    pub cursor: Option<String>,
}
impl Default for SearchSpec {
    fn default() -> Self {
        Self {
            query: None,
            snapshot: None,
            mode: technical(),
            filters: BTreeMap::new(),
            offset: 0,
            limit: 20,
            cursor: None,
        }
    }
}
fn technical() -> String {
    "technical".into()
}
fn twenty() -> usize {
    20
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileDigest {
    bytes: u64,
    sha256: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Shard {
    id: String,
    documents: usize,
    files: BTreeMap<String, FileDigest>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    #[serde(default)]
    generation: String,
    parent: Option<Value>,
    shard: Option<Shard>,
}
#[derive(Clone)]
pub struct MdnIndex {
    root: PathBuf,
}

fn schema() -> Schema {
    let mut b = Schema::builder();
    for name in [
        "id",
        "kind",
        "slug",
        "path",
        "page_type",
        "status",
        "compatibility_key",
        "feature",
        "browser",
        "experimental",
        "deprecated",
        "standard_track",
    ] {
        b.add_text_field(name, STRING);
    }
    b.add_u64_field("technical_count", FAST);
    b.add_u64_field("english_count", FAST);
    b.add_text_field("tie", STRING | FAST);
    b.add_text_field("payload", STORED);
    for name in ["technical", "english"] {
        b.add_text_field(
            name,
            TextOptions::default().set_indexing_options(
                TextFieldIndexing::default()
                    .set_tokenizer(name)
                    .set_index_option(IndexRecordOption::WithFreqsAndPositions),
            ),
        );
    }
    b.build()
}
fn analyzer(mode: &str) -> Result<TextAnalyzer> {
    let b = TextAnalyzer::builder(SimpleTokenizer::default()).filter(LowerCaser);
    match mode {
        "technical" => Ok(b.build()),
        "english" => Ok(b
            .filter(StopWordFilter::new(Language::English).ok_or_else(failure)?)
            .filter(Stemmer::new(Language::English))
            .build()),
        _ => Err(Error::invalid(
            "MDN search mode must be technical or english.",
        )),
    }
}
fn register(index: &Index) -> Result<()> {
    for mode in ["technical", "english"] {
        index.tokenizers().register(mode, analyzer(mode)?);
    }
    Ok(())
}
fn digest(path: &Path, cancel: &CancellationToken, deadline: Instant) -> Result<FileDigest> {
    let m = fs::symlink_metadata(path).map_err(|_| failure())?;
    if !m.is_file() || m.file_type().is_symlink() || m.len() > MAX_BYTES {
        return Err(integrity());
    }
    let mut f = File::open(path).map_err(|_| failure())?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 65536];
    let mut bytes = 0u64;
    loop {
        check(cancel, deadline)?;
        let n = f.read(&mut buf).map_err(|_| failure())?;
        if n == 0 {
            break;
        }
        bytes = bytes.saturating_add(n as u64);
        if bytes > m.len() {
            return Err(integrity());
        }
        h.update(&buf[..n]);
    }
    if bytes != m.len() {
        return Err(integrity());
    }
    Ok(FileDigest {
        bytes,
        sha256: hex::encode(h.finalize()),
    })
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| failure())?;
    f.write_all(bytes)
        .and_then(|()| f.sync_all())
        .map_err(|_| failure())
}
struct CancelOnDrop(CancellationToken);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
struct StageGuard(PathBuf);
impl Drop for StageGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn document_payload(input: &IndexDocument) -> Result<String> {
    let snippet: String = input.text.chars().take(240).collect();
    let payload=serde_json::to_string(&json!({"id":input.id,"kind":input.kind,"slug":input.slug,"title":input.title,"path":input.path,"snippet":snippet,"metadata":input.metadata})).map_err(|_|integrity())?;
    if payload.len() > 64 * 1024 {
        return Err(capacity());
    }
    Ok(payload)
}
fn document_counts(input: &IndexDocument, cancel: &CancellationToken) -> Result<[u64; 2]> {
    if !valid_hash(&input.id)
        || input.text.len() > 4 * 1024 * 1024
        || input.slug.len() > 4096
        || input.path.len() > 4096
        || input.title.len() > 4096
    {
        return Err(capacity());
    }
    document_payload(input)?;
    let text = format!("{}\n{}\n{}", input.title, input.slug, input.text);
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut counts = [0u64; 2];
    check(cancel, deadline)?;
    for (i, mode) in ["technical", "english"].iter().enumerate() {
        let mut a = analyzer(mode)?;
        let mut stream = a.token_stream(&text);
        while stream.advance() {
            check(cancel, deadline)?;
            if stream.token().text.len() >= MAX_TOKEN_LEN {
                return Err(capacity());
            }
            counts[i] += 1;
        }
    }
    Ok(counts)
}
impl MdnIndex {
    /// Pure per-document admission; collectors retain source/projection and record a search gap on failure.
    pub fn validate_document(input: &IndexDocument, cancel: &CancellationToken) -> Result<()> {
        document_counts(input, cancel).map(|_| ())
    }
    pub fn new(root: &Path) -> Result<Self> {
        let root = fs::canonicalize(root).map_err(|_| failure())?;
        real_directory(&root)?;
        let base = root.join("mdn-indexes");
        fs::create_dir_all(base.join("manifests")).map_err(|_| failure())?;
        fs::create_dir_all(base.join("shards")).map_err(|_| failure())?;
        for p in [&base, &base.join("manifests"), &base.join("shards")] {
            real_directory(p)?;
        }
        Ok(Self { root })
    }
    /// Called only during fenced startup. Published manifests and shards are never removed.
    pub fn recover_stages(&self) -> Result<()> {
        let base = self.root.join("mdn-indexes");
        real_directory(&base)?;
        for entry in fs::read_dir(&base).map_err(|_| failure())? {
            let entry = entry.map_err(|_| failure())?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let suffix = name
                .strip_prefix(".stage-")
                .or_else(|| name.strip_prefix(".manifest-"));
            let recognized = suffix
                .and_then(|s| s.split_once('-'))
                .is_some_and(|(p, c)| {
                    !p.is_empty()
                        && !c.is_empty()
                        && p.bytes().all(|b| b.is_ascii_digit())
                        && c.bytes().all(|b| b.is_ascii_digit())
                });
            if recognized {
                let metadata = fs::symlink_metadata(entry.path()).map_err(|_| failure())?;
                if metadata.file_type().is_symlink() {
                    return Err(integrity());
                }
                if metadata.is_dir() && name.starts_with(".stage-") {
                    fs::remove_dir_all(entry.path()).map_err(|_| failure())?;
                } else if metadata.is_file() {
                    fs::remove_file(entry.path()).map_err(|_| failure())?;
                }
            }
        }
        File::open(&base)
            .and_then(|f| f.sync_all())
            .map_err(|_| failure())
    }
    pub async fn publish(
        &self,
        previous: Option<&Value>,
        documents: Vec<IndexDocument>,
        cancel: CancellationToken,
    ) -> Result<Value> {
        self.publish_generation(previous, documents, cancel, "")
            .await
    }
    /// A trusted maintenance generation creates fresh immutable shards without replacing old evidence.
    pub async fn publish_generation(
        &self,
        previous: Option<&Value>,
        documents: Vec<IndexDocument>,
        cancel: CancellationToken,
        generation: &str,
    ) -> Result<Value> {
        if generation.len() > 128 || generation.chars().any(char::is_control) {
            return Err(Error::invalid("Invalid MDN index processing generation."));
        }
        let generation = generation.to_owned();
        let permit = WRITERS
            .get_or_init(|| Arc::new(Semaphore::new(1)))
            .clone()
            .try_acquire_owned()
            .map_err(|_| capacity())?;
        let this = self.clone();
        let previous = previous.cloned();
        let stop = cancel.child_token();
        let _cancel_guard = CancelOnDrop(stop.clone());
        let mut task = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            this.publish_sync(previous, documents, &stop, &generation)
        });
        tokio::select! {biased; _=cancel.cancelled()=>{let _=task.await;Err(Error::new("cancelled","MDN indexing canceled."))},result=&mut task=>result.map_err(|_|failure())?}
    }
    fn publish_sync(
        &self,
        previous: Option<Value>,
        documents: Vec<IndexDocument>,
        cancel: &CancellationToken,
        generation: &str,
    ) -> Result<Value> {
        if documents.is_empty()
            && let Some(previous) = previous
        {
            return Ok(previous);
        }
        if documents.len() > MAX_DOCS {
            return Err(capacity());
        }
        let deadline = Instant::now() + Duration::from_secs(3600);
        check(cancel, deadline)?;
        if let Some(reference) = &previous {
            self.open(reference, cancel, deadline)?;
        }
        let base = self.root.join("mdn-indexes");
        if fs2::available_space(&base).map_err(|_| failure())? < 128 * 1024 * 1024 {
            return Err(capacity());
        }
        let mut shard = None;
        if !documents.is_empty() {
            let unique: BTreeSet<_> = documents.iter().map(|d| &d.id).collect();
            if unique.len() != documents.len() {
                return Err(Error::integrity("Duplicate MDN index projection."));
            }
            let mut input_hash = Sha256::new();
            input_hash.update(FORMAT_VERSION.to_be_bytes());
            input_hash.update((generation.len() as u64).to_be_bytes());
            input_hash.update(generation.as_bytes());
            let mut input_bytes = 0usize;
            for document in &documents {
                input_bytes = input_bytes.saturating_add(document.text.len());
                if input_bytes > 64 * 1024 * 1024 {
                    return Err(capacity());
                }
                let encoded = serde_json::to_vec(document).map_err(|_| integrity())?;
                input_hash.update((encoded.len() as u64).to_be_bytes());
                input_hash.update(encoded);
            }
            let id = hex::encode(input_hash.finalize());
            let final_path = base.join("shards").join(&id);
            if final_path.exists() {
                let descriptor = final_path.join("descriptor.json");
                let metadata = fs::symlink_metadata(&descriptor).map_err(|_| failure())?;
                if !metadata.is_file()
                    || metadata.file_type().is_symlink()
                    || metadata.len() > MAX_MANIFEST as u64
                {
                    return Err(integrity());
                }
                let retained: Shard =
                    serde_json::from_slice(&fs::read(descriptor).map_err(|_| failure())?)
                        .map_err(|_| integrity())?;
                if retained.id != id || retained.documents != documents.len() {
                    return Err(integrity());
                }
                self.verify_shard(&retained, cancel, deadline)?;
                shard = Some(retained);
            } else {
                let stage = base.join(format!(
                    ".stage-{}-{}",
                    std::process::id(),
                    STAGE.fetch_add(1, AtomicOrdering::Relaxed)
                ));
                fs::create_dir(&stage).map_err(|_| failure())?;
                let _guard = StageGuard(stage.clone());
                let index = Index::create_in_dir(&stage, schema()).map_err(|_| failure())?;
                register(&index)?;
                let options = IndexWriterOptions::builder()
                    .num_worker_threads(1)
                    .num_merge_threads(1)
                    .memory_budget_per_thread(64 * 1024 * 1024)
                    .build();
                let mut writer = index.writer_with_options(options).map_err(|_| failure())?;
                writer.set_merge_policy(Box::new(tantivy::indexer::NoMergePolicy));
                let s = schema();
                for input in &documents {
                    check(cancel, deadline)?;
                    let counts = document_counts(input, cancel)?;
                    let text = format!("{}\n{}\n{}", input.title, input.slug, input.text);
                    let mut doc = TantivyDocument::default();
                    doc.add_u64(field(&s, "technical_count")?, counts[0]);
                    doc.add_u64(field(&s, "english_count")?, counts[1]);
                    for (name, value) in [
                        ("id", input.id.as_str()),
                        ("kind", input.kind.as_str()),
                        ("slug", input.slug.as_str()),
                        ("path", input.path.as_str()),
                    ] {
                        doc.add_text(field(&s, name)?, value);
                    }
                    let tie = format!("{}\u{001f}{}\u{001f}{}", input.slug, input.path, input.id);
                    doc.add_text(field(&s, "tie")?, &tie);
                    for key in [
                        "page_type",
                        "status",
                        "compatibility_key",
                        "feature",
                        "browser",
                        "experimental",
                        "deprecated",
                        "standard_track",
                    ] {
                        if let Some(value) = input.metadata.get(key) {
                            let values = match value {
                                Value::Array(a) => a.clone(),
                                v => vec![v.clone()],
                            };
                            for value in values {
                                if let Some(value) = value.as_str() {
                                    doc.add_text(field(&s, key)?, value);
                                } else if let Some(value) = value.as_bool() {
                                    doc.add_text(field(&s, key)?, value.to_string());
                                }
                            }
                        }
                    }
                    let payload = document_payload(input)?;
                    doc.add_text(field(&s, "payload")?, payload);
                    for name in ["technical", "english"] {
                        doc.add_text(field(&s, name)?, &text);
                    }
                    writer.add_document(doc).map_err(|_| failure())?;
                }
                writer.commit().map_err(|_| failure())?;
                drop(writer);
                drop(index);
                let mut files = BTreeMap::new();
                let mut total = 0u64;
                for entry in fs::read_dir(&stage).map_err(|_| failure())? {
                    check(cancel, deadline)?;
                    let entry = entry.map_err(|_| failure())?;
                    let name = entry.file_name().to_str().ok_or_else(integrity)?.to_owned();
                    if !safe_file(&name) || files.len() >= 10_000 {
                        return Err(capacity());
                    }
                    let d = digest(&entry.path(), cancel, deadline)?;
                    total = total.saturating_add(d.bytes);
                    if total > MAX_BYTES {
                        return Err(capacity());
                    }
                    File::open(entry.path())
                        .and_then(|f| f.sync_all())
                        .map_err(|_| failure())?;
                    files.insert(name, d);
                }
                let descriptor = Shard {
                    id: id.clone(),
                    documents: documents.len(),
                    files: files.clone(),
                };
                let descriptor_bytes = serde_json::to_vec(&descriptor).map_err(|_| integrity())?;
                if descriptor_bytes.len() > MAX_MANIFEST {
                    return Err(capacity());
                }
                write_new(&stage.join("descriptor.json"), &descriptor_bytes)?;
                File::open(&stage)
                    .and_then(|f| f.sync_all())
                    .map_err(|_| failure())?;
                fs::rename(&stage, &final_path).map_err(|_| failure())?;
                File::open(base.join("shards"))
                    .and_then(|f| f.sync_all())
                    .map_err(|_| failure())?;
                shard = Some(descriptor);
            }
        }
        let manifest = Manifest {
            version: FORMAT_VERSION,
            generation: generation.into(),
            parent: previous,
            shard,
        };
        let bytes = serde_json::to_vec(&manifest).map_err(|_| integrity())?;
        if bytes.len() > MAX_MANIFEST {
            return Err(capacity());
        }
        let id = hash(&bytes);
        let final_path = base.join("manifests").join(format!("{id}.json"));
        if final_path.exists() {
            if fs::read(&final_path).map_err(|_| failure())? != bytes {
                return Err(integrity());
            }
        } else {
            let temporary = base.join(format!(
                ".manifest-{}-{}",
                std::process::id(),
                STAGE.fetch_add(1, AtomicOrdering::Relaxed)
            ));
            write_new(&temporary, &bytes)?;
            fs::hard_link(&temporary, &final_path).map_err(|_| failure())?;
            fs::remove_file(temporary).map_err(|_| failure())?;
            File::open(base.join("manifests"))
                .and_then(|f| f.sync_all())
                .map_err(|_| failure())?;
        }
        let reference = json!({"path":format!("mdn-indexes/manifests/{id}.json"),"sha256":id});
        self.open(&reference, cancel, deadline)?;
        Ok(reference)
    }
    fn verify_shard(
        &self,
        shard: &Shard,
        cancel: &CancellationToken,
        deadline: Instant,
    ) -> Result<PathBuf> {
        if !valid_hash(&shard.id) || shard.documents > MAX_DOCS || shard.files.len() > 10_000 {
            return Err(integrity());
        }
        let path = self.root.join("mdn-indexes/shards").join(&shard.id);
        real_directory(&path)?;
        let mut total = 0u64;
        for (name, expected) in &shard.files {
            if !safe_file(name) || !valid_hash(&expected.sha256) {
                return Err(integrity());
            }
            let found = digest(&path.join(name), cancel, deadline)?;
            if found.bytes != expected.bytes || found.sha256 != expected.sha256 {
                return Err(integrity());
            }
            total = total.saturating_add(found.bytes);
            if total > MAX_BYTES {
                return Err(capacity());
            }
        }
        Ok(path)
    }
    fn open(
        &self,
        reference: &Value,
        cancel: &CancellationToken,
        deadline: Instant,
    ) -> Result<Arc<Opened>> {
        let expected = reference["sha256"]
            .as_str()
            .filter(|s| valid_hash(s))
            .ok_or_else(integrity)?;
        if reference["path"] != format!("mdn-indexes/manifests/{expected}.json") {
            return Err(integrity());
        }
        let key = format!("{}:{expected}", self.root.display());
        let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
        if let Some(found) = cache.lock().map_err(|_| failure())?.get(&key).cloned() {
            return Ok(found);
        }
        let mut current = Some(reference.clone());
        let mut manifests = BTreeSet::new();
        let mut shard_ids = BTreeSet::new();
        let mut shards = Vec::new();
        while let Some(reference) = current {
            check(cancel, deadline)?;
            let id = reference["sha256"]
                .as_str()
                .filter(|s| valid_hash(s))
                .ok_or_else(integrity)?;
            if reference["path"] != format!("mdn-indexes/manifests/{id}.json")
                || !manifests.insert(id.to_owned())
                || manifests.len() > MAX_SHARDS + 1
            {
                return Err(integrity());
            }
            let path = self
                .root
                .join("mdn-indexes/manifests")
                .join(format!("{id}.json"));
            let meta = fs::symlink_metadata(&path).map_err(|_| failure())?;
            if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > MAX_MANIFEST as u64
            {
                return Err(integrity());
            }
            let bytes = fs::read(path).map_err(|_| failure())?;
            if hash(&bytes) != id {
                return Err(integrity());
            }
            let m: Manifest = serde_json::from_slice(&bytes).map_err(|_| integrity())?;
            if m.version != FORMAT_VERSION
                || m.generation.len() > 128
                || m.generation.chars().any(char::is_control)
            {
                return Err(integrity());
            }
            if let Some(shard) = m.shard {
                if !shard_ids.insert(shard.id.clone()) {
                    return Err(integrity());
                }
                let shard_key = format!("{}:{}", self.root.display(), shard.id);
                let shard_cache = SHARD_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
                let retained = shard_cache
                    .lock()
                    .map_err(|_| failure())?
                    .get(&shard_key)
                    .and_then(Weak::upgrade);
                let opened = if let Some(opened) = retained {
                    opened
                } else {
                    let path = self.verify_shard(&shard, cancel, deadline)?;
                    let index = Index::open_in_dir(&path).map_err(|_| integrity())?;
                    if index.schema() != schema() {
                        return Err(integrity());
                    }
                    register(&index)?;
                    let reader = index.reader().map_err(|_| failure())?;
                    let searcher = reader.searcher();
                    if searcher.num_docs() != shard.documents as u64 {
                        return Err(integrity());
                    }
                    let opened = Arc::new(OpenedShard {
                        _reader: reader,
                        searcher,
                    });
                    let mut cache = shard_cache.lock().map_err(|_| failure())?;
                    if cache.len() > MAX_SHARDS * 2 {
                        cache.retain(|_, v| v.strong_count() > 0);
                    }
                    cache.insert(shard_key, Arc::downgrade(&opened));
                    opened
                };
                shards.push(opened);
            }
            current = m.parent;
        }
        let opened = Arc::new(Opened { shards });
        let mut guard = cache.lock().map_err(|_| failure())?;
        if guard.len() >= 4 {
            guard.clear();
        }
        guard.insert(key, opened.clone());
        Ok(opened)
    }
    pub async fn prewarm(&self, reference: &Value, cancel: CancellationToken) -> Result<()> {
        let this = self.clone();
        let reference = reference.clone();
        let stop = cancel.child_token();
        let _cancel_guard = CancelOnDrop(stop.clone());
        tokio::task::spawn_blocking(move || {
            this.open(
                &reference,
                &stop,
                Instant::now() + Duration::from_secs(3600),
            )
            .map(|_| ())
        })
        .await
        .map_err(|_| failure())?
    }
    pub async fn search(
        &self,
        reference: &Value,
        members: BTreeSet<String>,
        spec: SearchSpec,
        cancel: CancellationToken,
    ) -> Result<Value> {
        let permit = READERS
            .get_or_init(|| Arc::new(Semaphore::new(2)))
            .clone()
            .try_acquire_owned()
            .map_err(|_| capacity())?;
        let this = self.clone();
        let reference = reference.clone();
        let stop = cancel.child_token();
        let _cancel_guard = CancelOnDrop(stop.clone());
        let mut task = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            this.search_sync(&reference, members, spec, &stop)
        });
        tokio::select! {biased;_=cancel.cancelled()=>{let _=task.await;Err(Error::new("cancelled","MDN search canceled."))},result=&mut task=>result.map_err(|_|failure())?}
    }
    fn search_sync(
        &self,
        reference: &Value,
        members: BTreeSet<String>,
        spec: SearchSpec,
        cancel: &CancellationToken,
    ) -> Result<Value> {
        let deadline = Instant::now() + Duration::from_secs(15);
        check(cancel, deadline)?;
        if spec.limit == 0
            || spec.limit > 100
            || spec.offset > 10_000
            || members.len() > 1_000_000
            || members.iter().map(String::len).sum::<usize>() > 64 * 1024 * 1024
        {
            return Err(capacity());
        }
        let s = schema();
        let idfield = field(&s, "id")?;
        let member_query: Box<dyn Query> = Box::new(TermSetQuery::new(
            members.iter().map(|id| Term::from_field_text(idfield, id)),
        ));
        let opened = self.open(reference, cancel, deadline)?;
        let mut technical = 0u64;
        let mut english = 0u64;
        let mut count = 0u64;
        for shard in &opened.shards {
            check(cancel, deadline)?;
            let totals = shard
                .searcher
                .search(member_query.as_ref(), &TokenTotals)
                .map_err(|_| integrity())?;
            count = count.checked_add(totals.0).ok_or_else(capacity)?;
            technical = technical.checked_add(totals.1).ok_or_else(capacity)?;
            english = english.checked_add(totals.2).ok_or_else(capacity)?;
        }
        if count != members.len() as u64 {
            return Err(Error::integrity(
                "MDN snapshot references missing or duplicate index projections.",
            ));
        }
        let statistics = SelectedStatistics {
            opened: &opened,
            membership: member_query.box_clone(),
            count,
            technical,
            english,
            cancel,
            deadline,
            frequencies: Mutex::new(BTreeMap::new()),
        };
        let mut clauses = vec![(Occur::Must, member_query)];
        if let Some(text) = &spec.query {
            clauses.push((
                Occur::Must,
                query(field(&s, &spec.mode)?, text, &spec.mode)?,
            ));
        }
        for (name, value) in &spec.filters {
            if ![
                "kind",
                "slug",
                "path",
                "page_type",
                "status",
                "compatibility_key",
                "feature",
                "browser",
                "experimental",
                "deprecated",
                "standard_track",
            ]
            .contains(&name.as_str())
                || value.len() > 4096
                || value.chars().any(char::is_control)
            {
                return Err(Error::invalid("Invalid MDN search filter."));
            }
            clauses.push((
                Occur::Must,
                Box::new(TermQuery::new(
                    Term::from_field_text(field(&s, name)?, value),
                    IndexRecordOption::Basic,
                )),
            ));
        }
        let query = BooleanQuery::new(clauses);
        let fingerprint = hash(
            &serde_json::to_vec(&(
                reference,
                &members,
                &spec.snapshot,
                &spec.query,
                &spec.mode,
                &spec.filters,
            ))
            .map_err(|_| integrity())?,
        );
        let after = if let Some(cursor) = &spec.cursor {
            if cursor.len() > 16384 || spec.offset != 0 {
                return Err(Error::invalid("Invalid MDN search cursor."));
            }
            let continuation: Continuation = serde_json::from_str(cursor)
                .map_err(|_| Error::invalid("Malformed MDN search cursor."))?;
            if continuation.fingerprint != fingerprint
                || !continuation.rank.score.is_finite()
                || continuation.rank.tie.len() > 16384
            {
                return Err(Error::invalid(
                    "MDN cursor belongs to another snapshot or query.",
                ));
            }
            Some(continuation.rank)
        } else {
            None
        };
        let keep = spec.offset + spec.limit + 1;
        let mut found = Vec::new();
        let mut total = 0usize;
        for (shard, opened_shard) in opened.shards.iter().enumerate() {
            let searcher = &opened_shard.searcher;
            check(cancel, deadline)?;
            let broken = Arc::new(AtomicBool::new(false));
            let detect = broken.clone();
            let after = after.clone();
            let scored = spec.query.is_some();
            let top =
                TopDocs::with_limit(keep).tweak_score(move |segment: &tantivy::SegmentReader| {
                    let column = segment.fast_fields().str("tie").ok().flatten();
                    let detect = detect.clone();
                    let after = after.clone();
                    move |doc, score| {
                        let mut tie = String::new();
                        let okay = column
                            .as_ref()
                            .and_then(|c| {
                                c.term_ords(doc)
                                    .next()
                                    .and_then(|ord| c.ord_to_str(ord, &mut tie).ok())
                            })
                            .unwrap_or(false);
                        if !okay {
                            detect.store(true, AtomicOrdering::Relaxed);
                        }
                        let mut rank = Rank {
                            score: if scored { score } else { 0.0 },
                            tie,
                        };
                        if after.as_ref().is_some_and(|a| {
                            rank.partial_cmp(a).is_some_and(|o| o != Ordering::Less)
                        }) {
                            rank.score = f32::NEG_INFINITY;
                        }
                        rank
                    }
                });
            let (count, hits) = searcher
                .search_with_statistics_provider(&query, &(Count, top), &statistics)
                .map_err(|_| failure())?;
            if broken.load(AtomicOrdering::Relaxed) {
                return Err(integrity());
            }
            total = total.saturating_add(count);
            for (rank, address) in hits {
                if rank.score.is_finite() {
                    found.push((rank, shard, address));
                }
            }
            found.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(Ordering::Equal));
            found.truncate(keep);
        }
        let more = found.len() > spec.offset + spec.limit;
        let next_cursor = if more {
            found
                .get(spec.offset + spec.limit - 1)
                .map(|(rank, _, _)| {
                    serde_json::to_string(&Continuation {
                        fingerprint: fingerprint.clone(),
                        rank: rank.clone(),
                    })
                    .map_err(|_| integrity())
                })
                .transpose()?
        } else {
            None
        };
        let mut results = Vec::new();
        for (rank, shard, address) in found.into_iter().skip(spec.offset).take(spec.limit) {
            check(cancel, deadline)?;
            let doc: TantivyDocument = opened.shards[shard]
                .searcher
                .doc(address)
                .map_err(|_| integrity())?;
            let payload = doc
                .get_first(field(&s, "payload")?)
                .and_then(|v| v.as_str())
                .ok_or_else(integrity)?;
            let mut payload: Value = serde_json::from_str(payload).map_err(|_| integrity())?;
            payload["score"] = json!(rank.score);
            results.push(payload);
        }
        Ok(
            json!({"results":results,"total":total,"offset":spec.offset,"next_cursor":next_cursor,"mode":spec.mode}),
        )
    }
}
struct OpenedShard {
    _reader: IndexReader,
    searcher: Searcher,
}
struct Opened {
    shards: Vec<Arc<OpenedShard>>,
}
static SHARD_CACHE: OnceLock<Mutex<HashMap<String, Weak<OpenedShard>>>> = OnceLock::new();
struct TokenTotals;
struct SegmentTotals {
    technical: tantivy::fastfield::Column<u64>,
    english: tantivy::fastfield::Column<u64>,
    total: (u64, u64, u64),
    missing: bool,
}
impl Collector for TokenTotals {
    type Fruit = (u64, u64, u64);
    type Child = SegmentTotals;
    fn for_segment(
        &self,
        _ord: tantivy::SegmentOrdinal,
        segment: &tantivy::SegmentReader,
    ) -> tantivy::Result<Self::Child> {
        Ok(SegmentTotals {
            technical: segment.fast_fields().u64("technical_count")?,
            english: segment.fast_fields().u64("english_count")?,
            total: (0, 0, 0),
            missing: false,
        })
    }
    fn requires_scoring(&self) -> bool {
        false
    }
    fn merge_fruits(&self, fruits: Vec<Self::Fruit>) -> tantivy::Result<Self::Fruit> {
        let mut total = (0u64, 0u64, 0u64);
        for fruit in fruits {
            if fruit.0 == u64::MAX {
                return Err(tantivy::TantivyError::InvalidArgument(
                    "MDN token count missing".into(),
                ));
            }
            total.0 += fruit.0;
            total.1 += fruit.1;
            total.2 += fruit.2;
        }
        Ok(total)
    }
}
impl SegmentCollector for SegmentTotals {
    type Fruit = (u64, u64, u64);
    fn collect(&mut self, doc: tantivy::DocId, _score: tantivy::Score) {
        match (self.technical.first(doc), self.english.first(doc)) {
            (Some(a), Some(b)) => {
                self.total.0 += 1;
                self.total.1 += a;
                self.total.2 += b;
            }
            _ => self.missing = true,
        }
    }
    fn harvest(self) -> Self::Fruit {
        if self.missing {
            (u64::MAX, 0, 0)
        } else {
            self.total
        }
    }
}
static CACHE: OnceLock<Mutex<HashMap<String, Arc<Opened>>>> = OnceLock::new();
struct SelectedStatistics<'a> {
    opened: &'a Opened,
    membership: Box<dyn Query>,
    count: u64,
    technical: u64,
    english: u64,
    cancel: &'a CancellationToken,
    deadline: Instant,
    frequencies: Mutex<BTreeMap<Term, u64>>,
}
impl Bm25StatisticsProvider for SelectedStatistics<'_> {
    fn total_num_tokens(&self, f: Field) -> tantivy::Result<u64> {
        let s = schema();
        if Some(f) == s.get_field("technical").ok() {
            Ok(self.technical)
        } else if Some(f) == s.get_field("english").ok() {
            Ok(self.english)
        } else {
            Ok(0)
        }
    }
    fn total_num_docs(&self) -> tantivy::Result<u64> {
        Ok(self.count)
    }
    fn doc_freq(&self, term: &Term) -> tantivy::Result<u64> {
        let mut frequencies = self.frequencies.lock().map_err(|_| {
            tantivy::TantivyError::InvalidArgument("MDN statistics cache unavailable".into())
        })?;
        if let Some(count) = frequencies.get(term) {
            return Ok(*count);
        }
        let mut total = 0;
        let q = BooleanQuery::new(vec![
            (Occur::Must, self.membership.box_clone()),
            (
                Occur::Must,
                Box::new(TermQuery::new(term.clone(), IndexRecordOption::Basic)),
            ),
        ]);
        for shard in &self.opened.shards {
            let searcher = &shard.searcher;
            if self.cancel.is_cancelled() || Instant::now() >= self.deadline {
                return Err(tantivy::TantivyError::InvalidArgument(
                    "MDN statistics deadline exceeded".into(),
                ));
            }
            total += searcher.search(&q, &Count)? as u64;
        }
        frequencies.insert(term.clone(), total);
        Ok(total)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Rank {
    score: f32,
    tie: String,
}
impl PartialEq for Rank {
    fn eq(&self, o: &Self) -> bool {
        self.score == o.score && self.tie == o.tie
    }
}
impl PartialOrd for Rank {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        self.score
            .partial_cmp(&o.score)
            .map(|n| n.then_with(|| o.tie.cmp(&self.tie)))
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Continuation {
    fingerprint: String,
    rank: Rank,
}

fn tokens(text: &str, mode: &str, count: &mut usize) -> Result<Vec<(usize, String)>> {
    let mut a = analyzer(mode)?;
    let mut stream = a.token_stream(text);
    let mut result = Vec::new();
    while stream.advance() {
        *count += 1;
        if *count > 64 {
            return Err(capacity());
        }
        let t = stream.token();
        if t.text.len() >= MAX_TOKEN_LEN {
            return Err(capacity());
        }
        result.push((t.position, t.text.clone()));
    }
    Ok(result)
}
fn atom(field: Field, tokens: Vec<(usize, String)>, phrase: bool) -> Option<Box<dyn Query>> {
    let terms: Vec<_> = tokens
        .into_iter()
        .map(|(n, t)| (n, Term::from_field_text(field, &t)))
        .collect();
    if phrase && terms.len() >= 2 {
        return Some(Box::new(PhraseQuery::new_with_offset(terms)));
    }
    let clauses: Vec<(Occur, Box<dyn Query>)> = terms
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
    if clauses.is_empty() {
        None
    } else {
        Some(Box::new(BooleanQuery::new(clauses)))
    }
}
fn conjunction(mut clauses: Vec<(Occur, Box<dyn Query>)>) -> Result<Box<dyn Query>> {
    if clauses.is_empty() {
        return Err(Error::invalid("MDN query has no searchable tokens."));
    }
    if clauses.iter().all(|(o, _)| *o == Occur::MustNot) {
        clauses.push((Occur::Must, Box::new(AllQuery)));
    }
    Ok(Box::new(BooleanQuery::new(clauses)))
}
fn query(field: Field, input: &str, mode: &str) -> Result<Box<dyn Query>> {
    if input.trim().is_empty()
        || input.chars().count() > 256
        || input
            .chars()
            .any(|c| c.is_control() || ":[]{}()*?^~\\+".contains(c))
    {
        return Err(Error::invalid("Unsupported MDN query syntax or length."));
    }
    let mut count = 0;
    if mode == "technical" {
        return atom(field, tokens(input, mode, &mut count)?, false)
            .ok_or_else(|| Error::invalid("MDN query has no searchable tokens."));
    }
    if mode != "english" {
        return Err(Error::invalid(
            "MDN search mode must be technical or english.",
        ));
    }
    let chars: Vec<_> = input.chars().collect();
    let mut i = 0;
    let mut groups = Vec::new();
    let mut clauses = Vec::new();
    while i < chars.len() {
        if chars[i].is_whitespace() {
            i += 1;
            continue;
        }
        let excluded = chars[i] == '-';
        if excluded {
            i += 1;
        }
        if i == chars.len() || chars[i].is_whitespace() || chars[i] == '-' {
            return Err(Error::invalid("Invalid MDN exclusion."));
        }
        let phrase = chars[i] == '"';
        if phrase {
            i += 1;
        }
        let start = i;
        while i < chars.len()
            && if phrase {
                chars[i] != '"'
            } else {
                !chars[i].is_whitespace()
            }
        {
            if !phrase && chars[i] == '"' {
                return Err(Error::invalid("Invalid MDN phrase boundary."));
            }
            i += 1;
        }
        let text: String = chars[start..i].iter().collect();
        if phrase {
            if i == chars.len() {
                return Err(Error::invalid("Unterminated MDN phrase."));
            }
            i += 1;
            if i < chars.len() && !chars[i].is_whitespace() {
                return Err(Error::invalid("Invalid MDN phrase boundary."));
            }
        }
        if !phrase && !excluded && text == "OR" {
            groups.push(conjunction(std::mem::take(&mut clauses))?);
            continue;
        }
        if let Some(atom) = atom(field, tokens(&text, mode, &mut count)?, phrase) {
            clauses.push((
                if excluded {
                    Occur::MustNot
                } else {
                    Occur::Must
                },
                atom,
            ));
        } else if phrase || excluded {
            return Err(Error::invalid("MDN phrase or exclusion has no tokens."));
        }
    }
    groups.push(conjunction(clauses)?);
    Ok(Box::new(BooleanQuery::new(
        groups.into_iter().map(|q| (Occur::Should, q)).collect(),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn doc(id: &str, slug: &str, text: &str) -> IndexDocument {
        IndexDocument {
            id: hash(id.as_bytes()),
            kind: "article".into(),
            slug: slug.into(),
            title: slug.into(),
            path: format!("{slug}/index.md"),
            text: text.into(),
            metadata: json!({"status":["experimental"]}),
        }
    }
    #[tokio::test]
    async fn snapshots_filter_history_before_rank_count_and_paging() {
        let _gate = TEST_GATE.lock().await;
        let dir = tempfile::tempdir().expect("temp");
        let index = MdnIndex::new(dir.path()).expect("index");
        let a = doc("old", "A", "fetch old network network");
        let b = doc("new", "B", "fetch new network");
        let first = index
            .publish(None, vec![a.clone()], CancellationToken::new())
            .await
            .expect("first");
        let second = index
            .publish(Some(&first), vec![b.clone()], CancellationToken::new())
            .await
            .expect("second");
        let spec = SearchSpec {
            query: Some("fetch".into()),
            mode: "technical".into(),
            limit: 20,
            ..Default::default()
        };
        let found = index
            .search(
                &second,
                BTreeSet::from([a.id.clone()]),
                spec.clone(),
                CancellationToken::new(),
            )
            .await
            .expect("old");
        assert_eq!(found["total"], 1);
        assert_eq!(found["results"][0]["slug"], "A");
        let original = index
            .search(
                &first,
                BTreeSet::from([a.id.clone()]),
                spec.clone(),
                CancellationToken::new(),
            )
            .await
            .expect("original score");
        assert_eq!(
            found["results"][0]["score"],
            original["results"][0]["score"]
        );
        let found = index
            .search(
                &second,
                BTreeSet::from([b.id]),
                spec,
                CancellationToken::new(),
            )
            .await
            .expect("new");
        assert_eq!(found["total"], 1);
        assert_eq!(found["results"][0]["slug"], "B");
    }
    #[tokio::test]
    async fn cursor_binds_query_membership_and_allows_page_size_change() {
        let _gate = TEST_GATE.lock().await;
        let dir = tempfile::tempdir().expect("temp");
        let index = MdnIndex::new(dir.path()).expect("index");
        let docs = vec![
            doc("a", "A", "fetch network"),
            doc("b", "B", "fetch network"),
            doc("c", "C", "fetch network"),
        ];
        let ids: BTreeSet<String> = docs.iter().map(|d| d.id.clone()).collect();
        let reference = index
            .publish(None, docs, CancellationToken::new())
            .await
            .expect("publish");
        let spec = SearchSpec {
            query: Some("fetch".into()),
            mode: "technical".into(),
            limit: 1,
            ..Default::default()
        };
        let first = index
            .search(
                &reference,
                ids.clone(),
                spec.clone(),
                CancellationToken::new(),
            )
            .await
            .expect("first");
        let cursor = first["next_cursor"].as_str().expect("cursor").to_owned();
        let mut next = spec.clone();
        next.cursor = Some(cursor);
        next.limit = 2;
        let second = index
            .search(
                &reference,
                ids.clone(),
                next.clone(),
                CancellationToken::new(),
            )
            .await
            .expect("second");
        assert_eq!(second["results"].as_array().expect("results").len(), 2);
        assert_eq!(second["results"][0]["slug"], "B");
        next.query = Some("network".into());
        assert!(
            index
                .search(&reference, ids, next, CancellationToken::new())
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn replay_reuses_a_published_shard_and_corruption_fails_closed() {
        let _gate = TEST_GATE.lock().await;
        let dir = tempfile::tempdir().expect("temp");
        let index = MdnIndex::new(dir.path()).expect("index");
        let document = doc("replay", "Replay", "captured immutable text");
        let first = index
            .publish(None, vec![document.clone()], CancellationToken::new())
            .await
            .expect("first");
        let again = index
            .publish(None, vec![document.clone()], CancellationToken::new())
            .await
            .expect("retry");
        assert_eq!(first, again);
        let manifest = dir.path().join(first["path"].as_str().expect("path"));
        let mut bytes = std::fs::read(&manifest).expect("manifest");
        bytes[0] = b'!';
        std::fs::write(&manifest, bytes).expect("corrupt");
        CACHE
            .get()
            .expect("cache")
            .lock()
            .expect("cache lock")
            .clear();
        assert_eq!(
            index
                .search(
                    &first,
                    BTreeSet::from([document.id]),
                    SearchSpec::default(),
                    CancellationToken::new()
                )
                .await
                .expect_err("corrupt")
                .code,
            "integrity"
        );
    }
    #[tokio::test]
    async fn irrelevant_history_keeps_selected_statistics_and_bad_document_is_a_separate_gap() {
        let _gate = TEST_GATE.lock().await;
        let dir = tempfile::tempdir().expect("temp");
        let index = MdnIndex::new(dir.path()).expect("index");
        let selected = doc("selected", "Selected", "fetch network network");
        let first = index
            .publish(None, vec![selected.clone()], CancellationToken::new())
            .await
            .expect("first");
        let ids = BTreeSet::from([selected.id.clone()]);
        let spec = SearchSpec {
            query: Some("fetch".into()),
            ..Default::default()
        };
        let baseline = index
            .search(&first, ids.clone(), spec.clone(), CancellationToken::new())
            .await
            .expect("baseline");
        let mut current = first;
        for batch in 0..8 {
            let documents = (0..16)
                .map(|n| {
                    doc(
                        &format!("irrelevant-{batch}-{n}"),
                        &format!("Other{batch}-{n}"),
                        "fetch fetch unrelated history",
                    )
                })
                .collect();
            current = index
                .publish(Some(&current), documents, CancellationToken::new())
                .await
                .expect("history");
        }
        let observed = index
            .search(&current, ids, spec, CancellationToken::new())
            .await
            .expect("selected");
        assert_eq!(observed["total"], 1);
        assert_eq!(
            observed["results"][0]["score"],
            baseline["results"][0]["score"]
        );
        let mut bad = doc("bad", "Bad", &"x".repeat(MAX_TOKEN_LEN + 1));
        assert_eq!(
            MdnIndex::validate_document(&bad, &CancellationToken::new())
                .expect_err("long token")
                .code,
            "capacity"
        );
        bad.text = "small text".into();
        bad.metadata = json!({"oversized":"x".repeat(70_000)});
        assert!(MdnIndex::validate_document(&bad, &CancellationToken::new()).is_err());
        let good = doc("good", "Good", "searchable good projection");
        MdnIndex::validate_document(&good, &CancellationToken::new()).expect("good admission");
        let reference = index
            .publish(None, vec![good.clone()], CancellationToken::new())
            .await
            .expect("good batch");
        assert_eq!(
            index
                .search(
                    &reference,
                    BTreeSet::from([good.id]),
                    SearchSpec::default(),
                    CancellationToken::new()
                )
                .await
                .expect("good search")["total"],
            1
        );
    }
    #[tokio::test]
    async fn maintenance_generation_preserves_corrupt_history_and_staging_cleanup_is_scoped() {
        let _gate = TEST_GATE.lock().await;
        let dir = tempfile::tempdir().expect("temp");
        let index = MdnIndex::new(dir.path()).expect("index");
        let document = doc("maintenance", "Maintenance", "retained source projection");
        let original = index
            .publish(None, vec![document.clone()], CancellationToken::new())
            .await
            .expect("original");
        let rebuilt = index
            .publish_generation(
                None,
                vec![document.clone()],
                CancellationToken::new(),
                "fresh-maintenance-generation",
            )
            .await
            .expect("rebuild");
        assert_ne!(original, rebuilt);
        let bytes = fs::read(
            dir.path()
                .join(original["path"].as_str().expect("manifest")),
        )
        .expect("manifest");
        let original_manifest: Manifest = serde_json::from_slice(&bytes).expect("descriptor");
        let shard = original_manifest.shard.expect("shard");
        let damaged = dir
            .path()
            .join("mdn-indexes/shards")
            .join(shard.id)
            .join("meta.json");
        fs::write(&damaged, b"corrupt historical index").expect("damage");
        CACHE
            .get()
            .expect("cache")
            .lock()
            .expect("cache lock")
            .clear();
        SHARD_CACHE
            .get()
            .expect("shard cache")
            .lock()
            .expect("shard cache lock")
            .clear();
        let ids = BTreeSet::from([document.id]);
        assert!(
            index
                .search(
                    &original,
                    ids.clone(),
                    SearchSpec::default(),
                    CancellationToken::new()
                )
                .await
                .is_err()
        );
        assert_eq!(
            index
                .search(
                    &rebuilt,
                    ids,
                    SearchSpec::default(),
                    CancellationToken::new()
                )
                .await
                .expect("rebuilt")["total"],
            1
        );
        assert_eq!(
            fs::read(&damaged).expect("preserved"),
            b"corrupt historical index"
        );
        let base = dir.path().join("mdn-indexes");
        fs::create_dir(base.join(".stage-123-4")).expect("stage");
        fs::write(base.join(".stage-123-4/temp"), b"discardable").expect("stage file");
        fs::write(base.join(".manifest-123-5"), b"discardable").expect("manifest stage");
        fs::create_dir(base.join(".stage-operator-kept")).expect("unrecognized");
        index.recover_stages().expect("recover");
        assert!(!base.join(".stage-123-4").exists());
        assert!(!base.join(".manifest-123-5").exists());
        assert!(base.join(".stage-operator-kept").exists());
        assert!(damaged.exists());
    }
    #[test]
    fn restricted_query_rejects_wildcards_and_unclosed_phrases() {
        let s = schema();
        let f = field(&s, "english").expect("field");
        assert!(query(f, "fetch*", "english").is_err());
        assert!(query(f, "\"fetch", "english").is_err());
        assert!(query(f, "\"fetch network\" OR promise -error", "english").is_ok());
    }
}
