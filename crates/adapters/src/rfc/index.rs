//! Immutable, rebuildable RFC search indexes. Source bytes remain in capture storage.
use devres_domain::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};
use tantivy::{
    Index, IndexWriter, Order, TantivyDocument, Term,
    collector::{
        Count, FilterCollector, TopDocs,
        sort_key::{SortBySimilarityScore, SortByStaticFastValue},
    },
    indexer::IndexWriterOptions,
    query::{AllQuery, BooleanQuery, Occur, PhraseQuery, Query, TermQuery},
    schema::{
        FAST, Field, INDEXED, IndexRecordOption, STORED, Schema, TextFieldIndexing, TextOptions,
        Value as _,
    },
    snippet::SnippetGenerator,
    tokenizer::{
        Language, LowerCaser, MAX_TOKEN_LEN, SimpleTokenizer, Stemmer, StopWordFilter,
        TextAnalyzer, TokenStream,
    },
};
use tokio::sync::{Semaphore, SemaphorePermit};

const MAX_TEXT: usize = 16 * 1024 * 1024;
const MAX_DOCUMENTS: usize = 50_000;
const MAX_FILES: usize = 10_000;
const MAX_MANIFEST: u64 = 2 * 1024 * 1024;
const MAX_INDEX_BYTES: u64 = 32 * 1024 * 1024 * 1024;
const MAX_QUEUED_BYTES: usize = 32 * 1024 * 1024;
const INDEX_MEMORY: usize = 64 * 1024 * 1024;
const NUMBER: &str = "number";
const TECHNICAL: &str = "technical";
const ENGLISH: &str = "english";
const MANIFEST: &str = "integrity.json";
static STAGE: AtomicU64 = AtomicU64::new(0);
static WRITERS: Semaphore = Semaphore::const_new(1);
static READERS: Semaphore = Semaphore::const_new(2);
#[cfg(test)]
pub(crate) static TEST_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
#[cfg(test)]
static VERIFY_COUNTS: std::sync::Mutex<BTreeMap<PathBuf, u64>> =
    std::sync::Mutex::new(BTreeMap::new());

pub(crate) struct IndexDocument {
    pub number: u32,
    pub text: String,
}

fn unavailable() -> Error {
    Error::unavailable("RFC search index unavailable.")
}

fn integrity() -> Error {
    Error::integrity("RFC search index integrity verification failed.")
}

fn check_deadline(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        Err(Error::capacity(
            "RFC search processing time budget exceeded.",
        ))
    } else {
        Ok(())
    }
}

fn valid_id(id: &str) -> bool {
    crate::integrity::valid_hash(id)
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
    if !valid_id(&id) || index_suffix(&id)? != path {
        return Err(integrity());
    }
    Ok(id)
}

fn valid_file(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && name != "."
        && !name.contains("..")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

fn real_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| unavailable())?;
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        Ok(())
    } else {
        Err(integrity())
    }
}

fn directory(root: &Path) -> Result<PathBuf> {
    let canonical = fs::canonicalize(root).map_err(|_| unavailable())?;
    real_directory(&canonical)?;
    let indexes = canonical.join("rfc-indexes");
    match fs::create_dir(&indexes) {
        Ok(()) => File::open(&canonical)
            .and_then(|f| f.sync_all())
            .map_err(|_| unavailable())?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(unavailable()),
    }
    real_directory(&indexes)?;
    Ok(indexes)
}

fn selected_directory(root: &Path, relative: &str) -> Result<PathBuf> {
    let id = relative
        .strip_prefix("rfc-indexes/")
        .filter(|id| path_id(id).is_ok())
        .ok_or_else(|| Error::invalid("Invalid RFC search snapshot path."))?;
    let base = fs::canonicalize(root)
        .map_err(|_| unavailable())?
        .join("rfc-indexes");
    real_directory(&base)?;
    let selected = base.join(id);
    real_directory(&selected)?;
    Ok(selected)
}

fn technical_analyzer() -> TextAnalyzer {
    // Deliberately omit RemoveLongFilter: oversized tokens are explicit failures.
    TextAnalyzer::builder(SimpleTokenizer::default())
        .filter(LowerCaser)
        .build()
}

fn english_analyzer() -> Result<TextAnalyzer> {
    let stops = StopWordFilter::new(Language::English).ok_or_else(unavailable)?;
    Ok(TextAnalyzer::builder(SimpleTokenizer::default())
        .filter(LowerCaser)
        .filter(stops)
        .filter(Stemmer::new(Language::English))
        .build())
}

fn register(index: &Index) -> Result<()> {
    index.tokenizers().register(TECHNICAL, technical_analyzer());
    index.tokenizers().register(ENGLISH, english_analyzer()?);
    Ok(())
}

fn schema() -> Schema {
    let mut builder = Schema::builder();
    builder.add_u64_field(NUMBER, INDEXED | FAST | STORED);
    for (name, stored) in [(TECHNICAL, true), (ENGLISH, false)] {
        let options = TextOptions::default().set_indexing_options(
            TextFieldIndexing::default()
                .set_tokenizer(name)
                .set_index_option(IndexRecordOption::WithFreqsAndPositions),
        );
        builder.add_text_field(
            name,
            if stored {
                options.set_stored()
            } else {
                options
            },
        );
    }
    builder.build()
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileDigest {
    bytes: u64,
    #[serde(alias = "sha256")]
    digest: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    files: BTreeMap<String, FileDigest>,
}

fn digest(path: &Path, deadline: Instant) -> Result<FileDigest> {
    digest_with_algorithm(path, deadline, false)
}
fn digest_with_algorithm(path: &Path, deadline: Instant, legacy: bool) -> Result<FileDigest> {
    let (canonical, sha256) = digest_both(path, deadline)?;
    Ok(if legacy {
        FileDigest {
            bytes: canonical.bytes,
            digest: sha256,
        }
    } else {
        canonical
    })
}

// Preserve the actual BLAKE3 digest from the same read that checks a legacy SHA.
fn digest_both(path: &Path, deadline: Instant) -> Result<(FileDigest, String)> {
    let metadata = fs::symlink_metadata(path).map_err(|_| unavailable())?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > MAX_INDEX_BYTES
    {
        return Err(integrity());
    }
    let mut file = File::open(path).map_err(|_| unavailable())?;
    let mut hasher = Sha256::new();
    let mut blake3 = blake3::Hasher::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        check_deadline(deadline)?;
        let read = file.read(&mut buffer).map_err(|_| unavailable())?;
        if read == 0 {
            break;
        }
        bytes = bytes.saturating_add(read as u64);
        if bytes > metadata.len() {
            return Err(integrity());
        }
        hasher.update(&buffer[..read]);
        blake3.update(&buffer[..read]);
    }
    if bytes != metadata.len() {
        return Err(integrity());
    }
    Ok((
        FileDigest {
            bytes,
            digest: format!("blake3:{}", blake3.finalize().to_hex()),
        },
        hex::encode(hasher.finalize()),
    ))
}

fn index_files(path: &Path) -> Result<Vec<String>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(path).map_err(|_| unavailable())? {
        let entry = entry.map_err(|_| unavailable())?;
        let name = entry.file_name().into_string().map_err(|_| integrity())?;
        if !valid_file(&name) {
            return Err(integrity());
        }
        let metadata = fs::symlink_metadata(entry.path()).map_err(|_| unavailable())?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(integrity());
        }
        if name != MANIFEST && !name.ends_with(".lock") {
            files.push(name);
        }
        if files.len() > MAX_FILES {
            return Err(Error::capacity("RFC index file limit exceeded."));
        }
    }
    files.sort();
    Ok(files)
}

#[derive(Clone, Copy)]
struct VerifiedGeneration {
    fingerprint: blake3::Hash,
    manifest: blake3::Hash,
    canonical: bool,
}

fn fingerprint_part(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn verify(path: &Path, deadline: Instant) -> Result<()> {
    verify_generation(path, deadline).map(|_| ())
}

fn verify_generation(path: &Path, deadline: Instant) -> Result<VerifiedGeneration> {
    #[cfg(test)]
    {
        let mut counts = VERIFY_COUNTS.lock().map_err(|_| unavailable())?;
        *counts.entry(path.to_owned()).or_default() += 1;
    }
    let manifest_path = path.join(MANIFEST);
    let metadata = fs::symlink_metadata(&manifest_path).map_err(|_| integrity())?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > MAX_MANIFEST {
        return Err(integrity());
    }
    let bytes = fs::read(&manifest_path).map_err(|_| unavailable())?;
    let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|_| integrity())?;
    if manifest.version == 1 {
        crate::integrity::verify_legacy_file(&manifest_path, deadline)?;
    }
    if !matches!(manifest.version, 1 | 2)
        || manifest.files.len() > MAX_FILES
        || !manifest.files.contains_key("meta.json")
    {
        return Err(integrity());
    }
    let files = index_files(path)?;
    if files.len() != manifest.files.len() {
        return Err(integrity());
    }
    let mut fingerprint = blake3::Hasher::new();
    fingerprint_part(&mut fingerprint, b"devres:rfc:frozen-rebuild:v1;tantivy:0.27.0;technical:simple+lower;english:simple+lower+stop-en+stem-en");
    // Selected directories contain the canonical root and validated relative ID.
    // Distinct roots/paths must never share a migration prototype by accident.
    fingerprint_part(&mut fingerprint, path.as_os_str().as_encoded_bytes());
    fingerprint_part(
        &mut fingerprint,
        &serde_json::to_vec(&schema()).map_err(|_| integrity())?,
    );
    let manifest_digest = blake3::hash(&bytes);
    fingerprint_part(&mut fingerprint, manifest_digest.as_bytes());
    let mut total = 0_u64;
    for name in files {
        let expected = manifest.files.get(&name).ok_or_else(integrity)?;
        if !valid_id(&expected.digest)
            || manifest.version == 2 && !expected.digest.starts_with("blake3:")
        {
            return Err(integrity());
        }
        if !expected.digest.starts_with("blake3:") {
            crate::integrity::verify_legacy_file(&path.join(&name), deadline)?;
        }
        let (actual, sha256) = digest_both(&path.join(&name), deadline)?;
        total = total.saturating_add(actual.bytes);
        if total > MAX_INDEX_BYTES {
            return Err(Error::capacity("RFC index size limit exceeded."));
        }
        let checked_digest = if expected.digest.starts_with("blake3:") {
            &actual.digest
        } else {
            &sha256
        };
        if actual.bytes != expected.bytes || checked_digest != &expected.digest {
            return Err(integrity());
        }
        fingerprint_part(&mut fingerprint, name.as_bytes());
        fingerprint_part(&mut fingerprint, &actual.bytes.to_le_bytes());
        fingerprint_part(&mut fingerprint, actual.digest.as_bytes());
    }
    check_deadline(deadline)?;
    Ok(VerifiedGeneration {
        fingerprint: fingerprint.finalize(),
        manifest: manifest_digest,
        canonical: manifest.version == 2,
    })
}

/// One writer holds at most one source at the call boundary; callers can load captures sequentially.
pub(crate) struct IndexBuilder {
    storage_root: PathBuf,
    writer: Option<IndexWriter<TantivyDocument>>,
    index: Index,
    stage: PathBuf,
    final_path: PathBuf,
    relative: String,
    numbers: BTreeSet<u32>,
    queued_bytes: usize,
    base_generation: Option<VerifiedGeneration>,
    published: bool,
    _permit: SemaphorePermit<'static>,
}

impl IndexBuilder {
    #[cfg(test)]
    pub(crate) fn begin(root: &Path, id: &str) -> Result<Self> {
        Self::begin_from(root, id, None)
    }

    pub(crate) fn begin_from(root: &Path, id: &str, base: Option<&str>) -> Result<Self> {
        if !valid_id(id) {
            return Err(Error::invalid("Invalid RFC search snapshot identifier."));
        }
        let permit = WRITERS
            .try_acquire()
            .map_err(|_| Error::capacity("RFC index writer is busy."))?;
        let directory = directory(root)?;
        let suffix = index_suffix(id)?;
        let final_path = directory.join(&suffix);
        let parent = final_path.parent().ok_or_else(integrity)?;
        crate::integrity::ensure_directory_durable(parent)?;
        real_directory(parent)?;
        if fs::symlink_metadata(&final_path).is_ok() {
            return Err(Error::integrity("RFC search snapshot already exists."));
        }
        if fs2::available_space(&directory).map_err(|_| unavailable())? < INDEX_MEMORY as u64 {
            return Err(Error::capacity(
                "RFC indexing requires free storage headroom.",
            ));
        }
        let stage = directory.join(format!(
            ".stage-{}-{}",
            std::process::id(),
            STAGE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&stage).map_err(|_| unavailable())?;
        let prepared = (|| {
            let mut base_generation = None;
            let index = match base {
                Some(relative) => {
                    let source = selected_directory(root, relative)?;
                    base_generation = Some(verify_generation(
                        &source,
                        Instant::now() + Duration::from_secs(15),
                    )?);
                    for name in index_files(&source)? {
                        let from = source.join(&name);
                        let to = stage.join(&name);
                        if name == "meta.json" || name == ".managed.json" {
                            fs::copy(from, to).map_err(|_| unavailable())?;
                        } else {
                            fs::hard_link(from, to).map_err(|_| unavailable())?;
                        }
                    }
                    Index::open_in_dir(&stage).map_err(|_| integrity())?
                }
                None => Index::create_in_dir(&stage, schema()).map_err(|_| unavailable())?,
            };
            if index.schema() != schema() {
                return Err(integrity());
            }
            register(&index)?;
            let reader = index.reader().map_err(|_| unavailable())?;
            let mut numbers = BTreeSet::new();
            for segment in reader.searcher().segment_readers() {
                let column = segment.fast_fields().u64(NUMBER).map_err(|_| integrity())?;
                for doc in segment.doc_ids_alive() {
                    let number = column
                        .first(doc)
                        .and_then(|n| u32::try_from(n).ok())
                        .ok_or_else(integrity)?;
                    if number == 0 || number > 999999 || !numbers.insert(number) {
                        return Err(integrity());
                    }
                    if numbers.len() > MAX_DOCUMENTS {
                        return Err(Error::capacity("RFC index document limit exceeded."));
                    }
                }
            }
            drop(reader);
            let options = IndexWriterOptions::builder()
                .num_worker_threads(1)
                .num_merge_threads(1)
                .memory_budget_per_thread(INDEX_MEMORY)
                .build();
            let writer = index
                .writer_with_options(options)
                .map_err(|_| unavailable())?;
            // IndexWriter::drop does not join automatic merge tasks. Prevent
            // detached merge writes after cancellation releases the store fence.
            // Full rebuild is the explicit compaction path within file limits.
            writer.set_merge_policy(Box::new(tantivy::indexer::NoMergePolicy));
            Ok((index, writer, numbers, base_generation))
        })();
        match prepared {
            Ok((index, writer, numbers, base_generation)) => Ok(Self {
                storage_root: fs::canonicalize(root).map_err(|_| unavailable())?,
                writer: Some(writer),
                index,
                stage,
                final_path,
                relative: format!("rfc-indexes/{suffix}"),
                numbers,
                queued_bytes: 0,
                base_generation,
                published: false,
                _permit: permit,
            }),
            Err(error) => {
                let _ = fs::remove_dir_all(&stage);
                Err(error)
            }
        }
    }

    pub(crate) fn add_document(&mut self, document: IndexDocument) -> Result<()> {
        if document.number == 0 || document.number > 999999 {
            return Err(Error::invalid("Invalid RFC index document number."));
        }
        if document.text.len() > MAX_TEXT {
            return Err(Error::capacity("RFC searchable text exceeds 16 MiB."));
        }
        if document.text.trim().is_empty() {
            return Err(Error::integrity("RFC searchable text is empty."));
        }
        if self.numbers.len() >= MAX_DOCUMENTS && !self.numbers.contains(&document.number) {
            return Err(Error::capacity("RFC index document limit exceeded."));
        }
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut analyzer = technical_analyzer();
        let mut stream = analyzer.token_stream(&document.text);
        let mut has_tokens = false;
        while stream.advance() {
            has_tokens = true;
            check_deadline(deadline)?;
            if stream.token().text.len() >= MAX_TOKEN_LEN {
                return Err(Error::capacity(
                    "RFC searchable token exceeds engine length limit.",
                ));
            }
        }
        if !has_tokens {
            return Err(Error::integrity("RFC text contains no searchable tokens."));
        }
        if fs2::available_space(&self.stage).map_err(|_| unavailable())? < INDEX_MEMORY as u64 {
            return Err(Error::capacity(
                "RFC indexing requires free storage headroom.",
            ));
        }
        let writer = self.writer.as_mut().ok_or_else(unavailable)?;
        let bytes = document.text.len().saturating_mul(2);
        if self.queued_bytes.saturating_add(bytes) > MAX_QUEUED_BYTES {
            writer.commit().map_err(|_| unavailable())?;
            self.queued_bytes = 0;
        }
        let schema = self.index.schema();
        let number = schema.get_field(NUMBER).map_err(|_| integrity())?;
        let technical = schema.get_field(TECHNICAL).map_err(|_| integrity())?;
        let english = schema.get_field(ENGLISH).map_err(|_| integrity())?;
        let mut stored = TantivyDocument::new();
        stored.add_u64(number, u64::from(document.number));
        stored.add_text(technical, &document.text);
        stored.add_text(english, &document.text);
        writer.delete_term(Term::from_field_u64(number, u64::from(document.number)));
        writer.add_document(stored).map_err(|_| unavailable())?;
        self.numbers.insert(document.number);
        self.queued_bytes = self.queued_bytes.saturating_add(bytes);
        Ok(())
    }

    pub(crate) fn remove_document(&mut self, number: u32) -> Result<()> {
        if number == 0 || number > 999999 {
            return Err(Error::invalid("Invalid RFC index document number."));
        }
        let field = self
            .index
            .schema()
            .get_field(NUMBER)
            .map_err(|_| integrity())?;
        self.writer
            .as_mut()
            .ok_or_else(unavailable)?
            .delete_term(Term::from_field_u64(field, u64::from(number)));
        self.numbers.remove(&number);
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Result<String> {
        let mut writer = self.writer.take().ok_or_else(unavailable)?;
        writer.commit().map_err(|_| unavailable())?;
        writer.wait_merging_threads().map_err(|_| unavailable())?;
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut files = BTreeMap::new();
        let mut total = 0_u64;
        for name in index_files(&self.stage)? {
            let path = self.stage.join(&name);
            File::open(&path)
                .and_then(|file| file.sync_all())
                .map_err(|_| unavailable())?;
            let file_digest = digest(&path, deadline)?;
            total = total.saturating_add(file_digest.bytes);
            if total > MAX_INDEX_BYTES {
                return Err(Error::capacity("RFC index size limit exceeded."));
            }
            files.insert(name, file_digest);
        }
        let descriptor = Manifest { version: 2, files };
        let manifest = serde_json::to_vec(&descriptor).map_err(|_| integrity())?;
        if manifest.len() as u64 > MAX_MANIFEST {
            return Err(Error::capacity("RFC index manifest exceeds limit."));
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.stage.join(MANIFEST))
            .map_err(|_| unavailable())?;
        file.write_all(&manifest)
            .and_then(|()| file.sync_all())
            .map_err(|_| unavailable())?;
        File::open(&self.stage)
            .and_then(|file| file.sync_all())
            .map_err(|_| unavailable())?;
        if fs::symlink_metadata(&self.final_path).is_ok() {
            return Err(Error::integrity("RFC search snapshot already exists."));
        }
        fs::rename(&self.stage, &self.final_path).map_err(|_| unavailable())?;
        // After rename, never remove this directory, even if fsync or DB publication fails.
        self.published = true;
        let parent = self.final_path.parent().ok_or_else(integrity)?;
        File::open(parent)
            .and_then(|file| file.sync_all())
            .map_err(|_| unavailable())?;
        for (name, digest) in &descriptor.files {
            crate::integrity::record_file(
                &self.storage_root,
                &self.final_path.join(name),
                &digest.digest,
                digest.bytes,
            )?;
        }
        crate::integrity::record_file(
            &self.storage_root,
            &self.final_path.join(MANIFEST),
            &crate::integrity::hash(&manifest),
            manifest.len() as u64,
        )?;
        Ok(self.relative.clone())
    }
}

impl Drop for IndexBuilder {
    fn drop(&mut self) {
        // Stop all owned writer threads before deleting only this private stage directory.
        if let Some(writer) = self.writer.take() {
            drop(writer);
        }
        if !self.published {
            let _ = fs::remove_dir_all(&self.stage);
        }
    }
}

#[cfg(test)]
pub(crate) fn build(root: &Path, id: &str, documents: Vec<IndexDocument>) -> Result<String> {
    let mut builder = IndexBuilder::begin(root, id)?;
    for document in documents {
        builder.add_document(document)?;
    }
    builder.finish()
}

fn tokens(text: &str, mode: &str, count: &mut usize) -> Result<Vec<(usize, String)>> {
    let mut analyzer = match mode {
        TECHNICAL => technical_analyzer(),
        ENGLISH => english_analyzer()?,
        _ => {
            return Err(Error::invalid(
                "RFC search mode must be technical or english.",
            ));
        }
    };
    let mut stream = analyzer.token_stream(text);
    let mut tokens = Vec::new();
    while stream.advance() {
        *count += 1;
        if *count > 64 {
            return Err(Error::capacity(
                "RFC full-text queries are limited to 64 tokens.",
            ));
        }
        let token = stream.token();
        if token.text.len() >= MAX_TOKEN_LEN {
            return Err(Error::capacity(
                "RFC query token exceeds engine length limit.",
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
        return Err(Error::invalid("RFC query contains no searchable tokens."));
    }
    if clauses.iter().all(|(occur, _)| *occur == Occur::MustNot) {
        clauses.push((Occur::Must, Box::new(AllQuery)));
    }
    Ok(Box::new(BooleanQuery::new(clauses)))
}

fn query(field: Field, input: &str, mode: &str) -> Result<Box<dyn Query>> {
    if input.trim().is_empty() || input.chars().count() > 256 {
        return Err(Error::invalid(
            "RFC full-text query must contain 1..256 characters.",
        ));
    }
    let mut count = 0;
    if mode == TECHNICAL {
        return atom_query(field, tokens(input, mode, &mut count)?, false)
            .ok_or_else(|| Error::invalid("RFC query contains no searchable tokens."));
    }
    if mode != ENGLISH {
        return Err(Error::invalid(
            "RFC search mode must be technical or english.",
        ));
    }
    if input
        .chars()
        .any(|c| ":[]{}()*?^~\\+".contains(c) || c.is_control())
    {
        return Err(Error::invalid("Unsupported RFC English query syntax."));
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
                "RFC exclusions require a term or quoted phrase.",
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
                return Err(Error::invalid("Invalid RFC phrase boundary."));
            }
            cursor += 1;
        }
        let text: String = chars[start..cursor].iter().collect();
        if phrase {
            if cursor == chars.len() {
                return Err(Error::invalid("Unterminated RFC search phrase."));
            }
            cursor += 1;
            if cursor < chars.len() && !chars[cursor].is_whitespace() {
                return Err(Error::invalid("Invalid RFC phrase boundary."));
            }
        }
        if !phrase && !excluded && text == "OR" {
            groups.push(conjunction(std::mem::take(&mut clauses))?);
            continue;
        }
        let normalized = tokens(&text, ENGLISH, &mut count)?;
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
                "RFC phrase or exclusion contains no searchable tokens.",
            ));
        }
    }
    groups.push(conjunction(clauses)?);
    if groups.len() == 1 {
        return groups
            .pop()
            .ok_or_else(|| Error::invalid("Empty RFC query."));
    }
    Ok(Box::new(BooleanQuery::new(
        groups
            .into_iter()
            .map(|group| (Occur::Should, group))
            .collect(),
    )))
}

/// One fresh canonical prototype from this migration invocation. No open index,
/// reader, writer, descriptors, or document map survives a call boundary.
#[derive(Default)]
pub(crate) struct MigrationRebuildCache {
    entry: Option<MigrationPrototype>,
    #[cfg(test)]
    operations: [usize; 3],
}

struct MigrationPrototype {
    source: blake3::Hash,
    relative: String,
    manifest: blake3::Hash,
}

enum RebuildOperation {
    Built,
    Reused,
    Resumed,
}

fn frozen_membership(reader: &mut FrozenDocuments) -> Result<BTreeMap<u32, String>> {
    let mut membership = BTreeMap::new();
    loop {
        let documents = reader.next_page(1000)?;
        if documents.is_empty() {
            break;
        }
        for document in documents {
            if membership
                .insert(
                    document.number,
                    crate::integrity::hash(document.text.as_bytes()),
                )
                .is_some()
            {
                return Err(integrity());
            }
        }
    }
    Ok(membership)
}

/// Rebuild exactly one frozen index generation using its original admitted text.
/// Standalone callers intentionally cannot reuse prototypes across invocations.
#[cfg(test)]
pub(crate) async fn rebuild_frozen(
    root: PathBuf,
    relative: String,
    id: String,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<String> {
    rebuild_frozen_cached(
        root,
        relative,
        id,
        cancel,
        &mut MigrationRebuildCache::default(),
    )
    .await
}

pub(crate) async fn rebuild_frozen_cached(
    root: PathBuf,
    relative: String,
    id: String,
    cancel: tokio_util::sync::CancellationToken,
    cache: &mut MigrationRebuildCache,
) -> Result<String> {
    struct CancelOnDrop(tokio_util::sync::CancellationToken);
    impl Drop for CancelOnDrop {
        fn drop(&mut self) {
            self.0.cancel();
        }
    }
    let stop = cancel.child_token();
    let _guard = CancelOnDrop(stop.clone());
    // Any failed/canceled operation discards the receipt, rather than retaining
    // a possibly incomplete or externally changed candidate for another call.
    let previous = cache.entry.take();
    let mut task = tokio::task::spawn_blocking(move || {
        migration_cancel(&stop)?;
        let target = format!("rfc-indexes/{}", index_suffix(&id)?);
        // Every snapshot rechecks the complete original generation, including
        // independent legacy evidence and SHA, before considering a cache hit.
        let mut original = FrozenDocuments::open(&root, &relative, &stop)?;
        let source = original.generation.fingerprint;
        if root.join(&target).exists() {
            let original_membership = frozen_membership(&mut original)?;
            drop(original);
            let mut retained = FrozenDocuments::open(&root, &target, &stop)?;
            if original_membership != frozen_membership(&mut retained)? {
                return Err(integrity());
            }
            migration_cancel(&stop)?;
            // Number/text equivalence alone does not prove clean rebuild scoring
            // statistics. An existing target can never seed a new prototype.
            return Ok((target, previous, RebuildOperation::Resumed));
        }
        if let Some(prototype) = previous.filter(|entry| entry.source == source) {
            drop(original);
            // begin_from verifies all current prototype bytes, then copies only
            // writable metadata and hardlinks the permanent immutable shards.
            let builder = IndexBuilder::begin_from(&root, &id, Some(&prototype.relative))?;
            let generation = builder.base_generation.ok_or_else(integrity)?;
            if !generation.canonical || generation.manifest != prototype.manifest {
                return Err(integrity());
            }
            #[cfg(test)]
            migration_test_pause(&target)?;
            migration_cancel(&stop)?;
            let result = builder.finish()?;
            migration_cancel(&stop)?;
            return Ok((result, Some(prototype), RebuildOperation::Reused));
        }
        let mut builder = IndexBuilder::begin_from(&root, &id, None)?;
        let mut membership = BTreeMap::new();
        loop {
            let documents = original.next_page(1000)?;
            if documents.is_empty() {
                break;
            }
            for document in documents {
                migration_cancel(&stop)?;
                if membership
                    .insert(
                        document.number,
                        crate::integrity::hash(document.text.as_bytes()),
                    )
                    .is_some()
                {
                    return Err(integrity());
                }
                builder.add_document(document)?;
            }
        }
        drop(original);
        #[cfg(test)]
        migration_test_pause(&target)?;
        migration_cancel(&stop)?;
        let result = builder.finish()?;
        migration_cancel(&stop)?;
        // Admit only this invocation's newly built, fully verified canonical
        // output, with exact unique live number/text equivalence to the source.
        let mut retained = FrozenDocuments::open(&root, &result, &stop)?;
        if !retained.generation.canonical || membership != frozen_membership(&mut retained)? {
            return Err(integrity());
        }
        migration_cancel(&stop)?;
        let prototype = MigrationPrototype {
            source,
            relative: result.clone(),
            manifest: retained.generation.manifest,
        };
        Ok((result, Some(prototype), RebuildOperation::Built))
    });
    let (result, entry, _operation) = tokio::select! {
        biased;
        _ = cancel.cancelled() => { let _ = task.await; return Err(Error::new("cancelled", "RFC migration canceled.")); },
        result = &mut task => result.map_err(|_| unavailable())??,
    };
    cache.entry = entry;
    #[cfg(test)]
    {
        cache.operations[match _operation {
            RebuildOperation::Built => 0,
            RebuildOperation::Reused => 1,
            RebuildOperation::Resumed => 2,
        }] += 1;
    }
    Ok(result)
}

#[cfg(test)]
struct MigrationTestPause {
    target: String,
    entered: tokio::sync::oneshot::Sender<()>,
    release: std::sync::mpsc::Receiver<()>,
}
#[cfg(test)]
static MIGRATION_TEST_PAUSE: std::sync::Mutex<Option<MigrationTestPause>> =
    std::sync::Mutex::new(None);
#[cfg(test)]
fn migration_test_pause(target: &str) -> Result<()> {
    let pause = {
        let mut hook = MIGRATION_TEST_PAUSE.lock().map_err(|_| unavailable())?;
        if hook.as_ref().is_some_and(|pause| pause.target == target) {
            hook.take()
        } else {
            None
        }
    };
    if let Some(pause) = pause {
        let _ = pause.entered.send(());
        pause
            .release
            .recv_timeout(Duration::from_secs(15))
            .map_err(|_| unavailable())?;
    }
    Ok(())
}

fn migration_cancel(cancel: &tokio_util::sync::CancellationToken) -> Result<()> {
    if cancel.is_cancelled() {
        Err(Error::new("cancelled", "RFC migration canceled."))
    } else {
        Ok(())
    }
}

/// One fully verified immutable generation, consumed only while its caller owns
/// the maintenance fence. Keep its reader and forward cursor across page bounds;
/// reopening a page would rehash every shard and rescan the retained prefix.
pub(crate) struct FrozenDocuments {
    _reader: tantivy::IndexReader,
    generation: VerifiedGeneration,
    searcher: tantivy::Searcher,
    text_field: Field,
    number_field: Field,
    next_segment: usize,
    segment_id: u32,
    documents: std::vec::IntoIter<u32>,
    admitted_documents: usize,
    pending: Option<IndexDocument>,
    first_page_deadline: Option<Instant>,
    cancel: tokio_util::sync::CancellationToken,
    _permit: SemaphorePermit<'static>,
    #[cfg(test)]
    visited_documents: usize,
}

impl FrozenDocuments {
    pub(crate) fn open(
        root: &Path,
        relative: &str,
        cancel: &tokio_util::sync::CancellationToken,
    ) -> Result<Self> {
        migration_cancel(cancel)?;
        let permit = READERS
            .try_acquire()
            .map_err(|_| Error::capacity("RFC index reader capacity exhausted."))?;
        let deadline = Instant::now() + Duration::from_secs(15);
        let path = selected_directory(root, relative)?;
        let generation = verify_generation(&path, deadline)?;
        migration_cancel(cancel)?;
        let index = crate::immutable_index::open(&path).map_err(|_| integrity())?;
        if index.schema() != schema() {
            return Err(integrity());
        }
        let reader = index.reader().map_err(|_| unavailable())?;
        let searcher = reader.searcher();
        if searcher.num_docs() > MAX_DOCUMENTS as u64 {
            return Err(integrity());
        }
        let index_schema = index.schema();
        let text_field = index_schema.get_field(TECHNICAL).map_err(|_| integrity())?;
        let number_field = index_schema.get_field(NUMBER).map_err(|_| integrity())?;
        check_deadline(deadline)?;
        Ok(Self {
            _reader: reader,
            generation,
            searcher,
            text_field,
            number_field,
            next_segment: 0,
            segment_id: 0,
            documents: Vec::new().into_iter(),
            admitted_documents: 0,
            pending: None,
            first_page_deadline: Some(deadline),
            cancel: cancel.clone(),
            _permit: permit,
            #[cfg(test)]
            visited_documents: 0,
        })
    }

    fn next_document(&mut self, deadline: Instant) -> Result<Option<IndexDocument>> {
        loop {
            migration_cancel(&self.cancel)?;
            check_deadline(deadline)?;
            let Some(document) = self.documents.next() else {
                let Some(segment) = self.searcher.segment_readers().get(self.next_segment) else {
                    return Ok(None);
                };
                self.segment_id = u32::try_from(self.next_segment).map_err(|_| integrity())?;
                self.next_segment += 1;
                // Tantivy's alive iterator borrows its segment. Retain only this
                // segment's bounded live IDs, not a raw max_doc scan (which can
                // include a large deleted prefix in older frozen generations).
                let mut documents = Vec::new();
                for document in segment.doc_ids_alive() {
                    migration_cancel(&self.cancel)?;
                    check_deadline(deadline)?;
                    if self.admitted_documents >= MAX_DOCUMENTS {
                        return Err(integrity());
                    }
                    self.admitted_documents += 1;
                    documents.push(document);
                }
                check_deadline(deadline)?;
                self.documents = documents.into_iter();
                continue;
            };
            #[cfg(test)]
            {
                self.visited_documents += 1;
            }
            let stored: TantivyDocument = self
                .searcher
                .doc(tantivy::DocAddress::new(self.segment_id, document))
                .map_err(|_| integrity())?;
            let text = stored
                .get_first(self.text_field)
                .and_then(|v| v.as_str())
                .ok_or_else(integrity)?;
            let number = stored
                .get_first(self.number_field)
                .and_then(|v| v.as_u64())
                .and_then(|v| u32::try_from(v).ok())
                .filter(|v| (1..=999999).contains(v))
                .ok_or_else(integrity)?;
            if text.len() > MAX_TEXT {
                return Err(Error::capacity("RFC index export text exceeds bound."));
            }
            return Ok(Some(IndexDocument {
                number,
                text: text.to_owned(),
            }));
        }
    }

    pub(crate) fn next_page(&mut self, limit: usize) -> Result<Vec<IndexDocument>> {
        if !(1..=1000).contains(&limit) {
            return Err(Error::invalid("Invalid RFC index export page."));
        }
        // Opening/verification and the first page share the original budget.
        // Later pages each retain their own 15s budget; no generation-wide
        // deadline turns a large, valid frozen export into a partial result.
        let deadline = self
            .first_page_deadline
            .take()
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(15));
        let mut bytes = 0usize;
        let mut output = Vec::new();
        while output.len() < limit {
            migration_cancel(&self.cancel)?;
            check_deadline(deadline)?;
            let document = match self.pending.take() {
                Some(document) => Some(document),
                None => self.next_document(deadline)?,
            };
            let Some(document) = document else {
                break;
            };
            if !output.is_empty() && bytes.saturating_add(document.text.len()) > MAX_QUEUED_BYTES {
                // Keep this one <=16 MiB document for the next page, rather
                // than discarding it or decoding it again after the byte bound.
                self.pending = Some(document);
                break;
            }
            bytes += document.text.len();
            output.push(document);
        }
        migration_cancel(&self.cancel)?;
        check_deadline(deadline)?;
        Ok(output)
    }
}

/// Called on an admitted blocking worker. Each reader opens only the selected immutable directory.
pub(crate) fn search(
    root: &Path,
    relative: &str,
    input: &str,
    mode: &str,
    offset: usize,
    limit: usize,
    allowed_numbers: Option<&[u32]>,
) -> Result<Value> {
    if limit == 0 || limit > 100 || offset > 1_000_000 {
        return Err(Error::invalid(
            "RFC search limit must be 1..100 and offset at most 1000000.",
        ));
    }
    if allowed_numbers.is_some_and(|values| values.len() > MAX_DOCUMENTS) {
        return Err(Error::capacity(
            "RFC metadata filter exceeds document limit.",
        ));
    }
    let _permit = READERS
        .try_acquire()
        .map_err(|_| Error::capacity("RFC search reader capacity exhausted."))?;
    let deadline = Instant::now() + Duration::from_secs(15);
    let path = selected_directory(root, relative)?;
    verify(&path, deadline)?;
    let index = crate::immutable_index::open(&path).map_err(|_| integrity())?;
    if index.schema() != schema() {
        return Err(integrity());
    }
    register(&index)?;
    let schema = index.schema();
    let field = schema
        .get_field(mode)
        .map_err(|_| Error::invalid("RFC search mode must be technical or english."))?;
    let query = query(field, input, mode)?;
    let reader = index.reader().map_err(|_| unavailable())?;
    let searcher = reader.searcher();
    if searcher.num_docs() > MAX_DOCUMENTS as u64 {
        return Err(integrity());
    }
    let allowed: Option<HashSet<u64>> =
        allowed_numbers.map(|values| values.iter().map(|n| u64::from(*n)).collect());
    let top = TopDocs::with_limit(limit)
        .and_offset(offset.min(searcher.num_docs() as usize))
        .order_by((
            (SortBySimilarityScore, Order::Desc),
            (SortByStaticFastValue::<u64>::for_field(NUMBER), Order::Asc),
        ));
    let collector = FilterCollector::new(
        NUMBER.to_owned(),
        move |number: u64| allowed.as_ref().is_none_or(|set| set.contains(&number)),
        (Count, top),
    );
    let (total, hits) = searcher
        .search(query.as_ref(), &collector)
        .map_err(|_| unavailable())?;
    check_deadline(deadline)?;
    let mut generator =
        SnippetGenerator::create(&searcher, query.as_ref(), field).map_err(|_| unavailable())?;
    generator.set_max_num_chars(256);
    let text_field = schema.get_field(TECHNICAL).map_err(|_| integrity())?;
    let mut items = Vec::new();
    if offset < total {
        for ((score, number), address) in hits {
            check_deadline(deadline)?;
            let number = number.ok_or_else(integrity)?;
            let stored: TantivyDocument = searcher.doc(address).map_err(|_| integrity())?;
            let text = stored
                .get_first(text_field)
                .and_then(|value| value.as_str())
                .ok_or_else(integrity)?;
            if text.len() > MAX_TEXT {
                return Err(integrity());
            }
            let snippet = generator.snippet(text);
            let excerpt = if snippet.is_empty() {
                text.chars().take(256).collect::<String>()
            } else {
                snippet.fragment().chars().take(256).collect::<String>()
            };
            items.push(json!({"number":number,"score":score,"excerpt":excerpt}));
        }
    }
    check_deadline(deadline)?;
    Ok(
        json!({"items":items,"total":total,"offset":offset,"next_offset":if offset.saturating_add(limit) < total { Some(offset + limit) } else { None }}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn documents(values: &[(u32, &str)]) -> Vec<IndexDocument> {
        values
            .iter()
            .map(|(number, text)| IndexDocument {
                number: *number,
                text: (*text).into(),
            })
            .collect()
    }

    fn qualify_legacy_file(root: &Path, path: &Path) {
        let (digest, bytes) = crate::integrity::file_digest(
            path,
            MAX_INDEX_BYTES,
            Instant::now() + Duration::from_secs(15),
        )
        .unwrap();
        let evidence = crate::integrity::FileEvidence {
            version: 1,
            path: path.strip_prefix(root).unwrap().to_str().unwrap().into(),
            bytes,
            digest,
        };
        let descriptor = crate::integrity::evidence_path(root, path).unwrap();
        fs::create_dir_all(descriptor.parent().unwrap()).unwrap();
        fs::write(descriptor, serde_json::to_vec(&evidence).unwrap()).unwrap();
    }

    fn retained_index_bytes(root: &Path, relative: &str) -> BTreeMap<String, Vec<u8>> {
        let directory = root.join(relative);
        let mut names = index_files(&directory).unwrap();
        names.push(MANIFEST.to_owned());
        names
            .into_iter()
            .map(|name| {
                let bytes = fs::read(directory.join(&name)).unwrap();
                (name, bytes)
            })
            .collect()
    }

    fn verification_count(root: &Path, relative: &str) -> u64 {
        let path = selected_directory(root, relative).unwrap();
        VERIFY_COUNTS
            .lock()
            .unwrap()
            .get(&path)
            .copied()
            .unwrap_or_default()
    }

    fn frozen_text(root: &Path, relative: &str) -> (BTreeMap<u32, String>, usize) {
        let mut reader =
            FrozenDocuments::open(root, relative, &tokio_util::sync::CancellationToken::new())
                .unwrap();
        let mut documents = BTreeMap::new();
        loop {
            let page = reader.next_page(237).unwrap();
            if page.is_empty() {
                break;
            }
            for document in page {
                assert!(documents.insert(document.number, document.text).is_none());
            }
        }
        (documents, reader.visited_documents)
    }

    #[test]
    fn canonical_index_addresses_and_legacy_qualification_are_enforced() {
        let _test = TEST_SERIAL.blocking_lock();
        let root = tempfile::tempdir().unwrap();
        let id = crate::integrity::hash(b"canonical RFC snapshot");
        let relative = build(root.path(), &id, documents(&[(1, "persistent transport")])).unwrap();
        assert!(relative.starts_with("rfc-indexes/blake3/"));
        let directory = root.path().join(&relative);
        let manifest_path = directory.join(MANIFEST);
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        assert_eq!(manifest["version"], 2);
        for descriptor in manifest["files"].as_object().unwrap().values() {
            assert!(
                descriptor["digest"]
                    .as_str()
                    .unwrap()
                    .starts_with("blake3:")
            );
            assert!(descriptor.get("sha256").is_none());
        }
        assert_eq!(
            search(root.path(), &relative, "transport", TECHNICAL, 0, 20, None).unwrap()["total"],
            1
        );
        // A version-1 manifest remains usable only with separately migrated BLAKE3 evidence.
        manifest["version"] = json!(1);
        for (name, descriptor) in manifest["files"].as_object_mut().unwrap() {
            let path = directory.join(name);
            descriptor.as_object_mut().unwrap().remove("digest");
            descriptor["sha256"] = json!(crate::integrity::legacy_hash(&fs::read(&path).unwrap()));
        }
        fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        assert!(search(root.path(), &relative, "transport", TECHNICAL, 0, 20, None).is_err());
        let stop = tokio_util::sync::CancellationToken::new();
        assert!(FrozenDocuments::open(root.path(), &relative, &stop).is_err());
        qualify_legacy_file(root.path(), &manifest_path);
        for name in manifest["files"].as_object().unwrap().keys() {
            qualify_legacy_file(root.path(), &directory.join(name));
        }
        assert_eq!(
            search(root.path(), &relative, "transport", TECHNICAL, 0, 20, None).unwrap()["total"],
            1
        );
        let mut reader = FrozenDocuments::open(root.path(), &relative, &stop).unwrap();
        let page = reader.next_page(1).unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].number, 1);
        assert_eq!(page[0].text, "persistent transport");
        assert!(reader.next_page(1).unwrap().is_empty());
        drop(reader);
        let descriptor =
            crate::integrity::evidence_path(root.path(), &directory.join("meta.json")).unwrap();
        let mut evidence: Value = serde_json::from_slice(&fs::read(&descriptor).unwrap()).unwrap();
        evidence["digest"] = json!(crate::integrity::hash(b"wrong retained bytes"));
        fs::write(descriptor, serde_json::to_vec(&evidence).unwrap()).unwrap();
        assert!(search(root.path(), &relative, "transport", TECHNICAL, 0, 20, None).is_err());
        assert!(FrozenDocuments::open(root.path(), &relative, &stop).is_err());
    }

    #[tokio::test]
    async fn frozen_rebuild_preserves_original_admitted_text_and_resumes() {
        let _test = TEST_SERIAL.lock().await;
        let root = tempfile::tempdir().unwrap();
        let original = build(
            root.path(),
            &crate::integrity::hash(b"original RFC frozen index"),
            documents(&[(12, "original transport"), (13, "original protocol")]),
        )
        .unwrap();
        let canonical = crate::integrity::hash(b"canonical RFC frozen index");
        let rebuilt = rebuild_frozen(
            root.path().to_owned(),
            original.clone(),
            canonical.clone(),
            tokio_util::sync::CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_ne!(original, rebuilt);
        let left = search(root.path(), &original, "original", TECHNICAL, 0, 20, None).unwrap();
        let right = search(root.path(), &rebuilt, "original", TECHNICAL, 0, 20, None).unwrap();
        assert_eq!(left, right);
        assert_eq!(
            rebuild_frozen(
                root.path().to_owned(),
                original,
                canonical,
                tokio_util::sync::CancellationToken::new()
            )
            .await
            .unwrap(),
            rebuilt
        );
    }

    #[tokio::test]
    async fn frozen_rebuild_verifies_once_and_visits_each_live_document_once() {
        let _test = TEST_SERIAL.lock().await;
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let source_id = crate::integrity::hash(b"multi-page RFC source fixture");
        let mut builder = IndexBuilder::begin(root.path(), &source_id).unwrap();
        let mut expected = BTreeMap::new();
        for number in 1..=2507 {
            let text = format!("original frozen transport document {number}");
            builder
                .add_document(IndexDocument {
                    number,
                    text: text.clone(),
                })
                .unwrap();
            expected.insert(number, text);
            if number % 500 == 0 {
                builder.writer.as_mut().unwrap().commit().unwrap();
            }
        }
        // Frozen generations may retain deleted postings and segment boundaries.
        // They must not reappear when the export cursor advances to a new page.
        builder.remove_document(3).unwrap();
        expected.remove(&3);
        builder
            .add_document(IndexDocument {
                number: 1,
                text: "replacement retained transport document".into(),
            })
            .unwrap();
        expected.insert(1, "replacement retained transport document".into());
        let original = builder.finish().unwrap();
        let before = verification_count(root.path(), &original);
        let canonical = crate::integrity::hash(b"multi-page RFC target fixture");
        let started = Instant::now();
        let rebuilt = rebuild_frozen(
            root.path().to_owned(),
            original.clone(),
            canonical.clone(),
            tokio_util::sync::CancellationToken::new(),
        )
        .await
        .unwrap();
        let rebuild_elapsed = started.elapsed();
        assert_eq!(verification_count(root.path(), &original) - before, 1);
        let (retained, visited) = frozen_text(root.path(), &rebuilt);
        assert_eq!(retained, expected);
        assert_eq!(visited, expected.len());
        let (source, visited) = frozen_text(root.path(), &original);
        assert_eq!(source, expected);
        assert_eq!(visited, expected.len());
        let source_before = verification_count(root.path(), &original);
        let target_before = verification_count(root.path(), &rebuilt);
        let started = Instant::now();
        assert_eq!(
            rebuild_frozen(
                root.path().to_owned(),
                original.clone(),
                canonical,
                tokio_util::sync::CancellationToken::new(),
            )
            .await
            .unwrap(),
            rebuilt
        );
        assert_eq!(
            verification_count(root.path(), &original) - source_before,
            1
        );
        assert_eq!(verification_count(root.path(), &rebuilt) - target_before, 1);
        eprintln!(
            "RFC frozen fixture: {} live documents across >2 pages; rebuild {:?}, retry {:?}; verification passes 1/source and 1/retry target",
            expected.len(),
            rebuild_elapsed,
            started.elapsed(),
        );
    }

    async fn cached_fixture_rebuild(
        root: &Path,
        source: &str,
        name: &[u8],
        cache: &mut MigrationRebuildCache,
    ) -> Result<String> {
        rebuild_frozen_cached(
            root.to_owned(),
            source.to_owned(),
            crate::integrity::hash(name),
            tokio_util::sync::CancellationToken::new(),
            cache,
        )
        .await
    }

    fn fixture_target(name: &[u8]) -> String {
        format!(
            "rfc-indexes/{}",
            index_suffix(&crate::integrity::hash(name)).unwrap()
        )
    }

    fn assert_migration_drained(root: &Path) {
        assert_eq!(READERS.available_permits(), 2);
        assert_eq!(WRITERS.available_permits(), 1);
        assert!(
            fs::read_dir(root.join("rfc-indexes"))
                .unwrap()
                .all(|entry| !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".stage-"))
        );
    }

    fn replace_fixture_generation(root: &Path, destination: &str, source: &str) {
        let retained = retained_index_bytes(root, source);
        fs::remove_dir_all(root.join(destination)).unwrap();
        fs::create_dir(root.join(destination)).unwrap();
        for (name, bytes) in retained {
            fs::write(root.join(destination).join(name), bytes).unwrap();
        }
    }

    #[tokio::test]
    async fn migration_cache_reuses_fresh_outputs_and_evicts_one_entry() {
        let _test = TEST_SERIAL.lock().await;
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let source = build(
            root.path(),
            &crate::integrity::hash(b"cache source"),
            documents(&[(1, "secure transport cats"), (2, "secure transport dogs")]),
        )
        .unwrap();
        let other = build(
            root.path(),
            &crate::integrity::hash(b"other source"),
            documents(&[(3, "independent protocol")]),
        )
        .unwrap();
        let mut cache = MigrationRebuildCache::default();
        let prototype = cached_fixture_rebuild(root.path(), &source, b"cache first", &mut cache)
            .await
            .unwrap();
        assert_eq!(cache.operations, [1, 0, 0]);
        let before_bytes = retained_index_bytes(root.path(), &prototype);
        let source_before = verification_count(root.path(), &source);
        let prototype_before = verification_count(root.path(), &prototype);
        let copied = cached_fixture_rebuild(root.path(), &source, b"cache hit", &mut cache)
            .await
            .unwrap();
        assert_eq!(cache.operations, [1, 1, 0]);
        assert_eq!(verification_count(root.path(), &source) - source_before, 1);
        assert_eq!(
            verification_count(root.path(), &prototype) - prototype_before,
            1
        );
        assert_eq!(retained_index_bytes(root.path(), &prototype), before_bytes);
        assert_ne!(copied, prototype);
        assert_eq!(
            frozen_text(root.path(), &copied),
            frozen_text(root.path(), &prototype)
        );
        assert_eq!(
            search(root.path(), &copied, "transport", TECHNICAL, 0, 1, None).unwrap(),
            search(root.path(), &prototype, "transport", TECHNICAL, 0, 1, None).unwrap()
        );
        // Reuse preserves the existing immutable segment files themselves.
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            for name in index_files(&root.path().join(&prototype)).unwrap() {
                if name != "meta.json" && name != ".managed.json" {
                    assert_eq!(
                        fs::metadata(root.path().join(&prototype).join(&name))
                            .unwrap()
                            .ino(),
                        fs::metadata(root.path().join(&copied).join(name))
                            .unwrap()
                            .ino()
                    );
                }
            }
        }
        let old_source = cache.entry.as_ref().unwrap().source;
        cached_fixture_rebuild(root.path(), &other, b"cache evict", &mut cache)
            .await
            .unwrap();
        assert_ne!(cache.entry.as_ref().unwrap().source, old_source);
        cached_fixture_rebuild(root.path(), &source, b"cache return", &mut cache)
            .await
            .unwrap();
        assert_eq!(cache.operations, [3, 1, 0]);
        assert_migration_drained(root.path());
    }

    #[tokio::test]
    async fn migration_cache_never_seeds_from_resumed_deleted_postings() {
        let _test = TEST_SERIAL.lock().await;
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let source = build(
            root.path(),
            &crate::integrity::hash(b"resume source"),
            documents(&[(1, "retained transport"), (2, "retained protocol")]),
        )
        .unwrap();
        let target_id = crate::integrity::hash(b"resume dirty target");
        let mut dirty = IndexBuilder::begin(root.path(), &target_id).unwrap();
        dirty
            .add_document(IndexDocument {
                number: 1,
                text: "deleted old postings and statistics".into(),
            })
            .unwrap();
        dirty
            .add_document(IndexDocument {
                number: 2,
                text: "retained protocol".into(),
            })
            .unwrap();
        dirty.writer.as_mut().unwrap().commit().unwrap();
        dirty
            .add_document(IndexDocument {
                number: 1,
                text: "retained transport".into(),
            })
            .unwrap();
        let dirty = dirty.finish().unwrap();
        let index = crate::immutable_index::open(&root.path().join(&dirty)).unwrap();
        let reader = index.reader().unwrap();
        assert!(
            reader
                .searcher()
                .segment_readers()
                .iter()
                .any(|segment| segment.num_deleted_docs() > 0)
        );
        drop(reader);
        drop(index);
        let mut cache = MigrationRebuildCache::default();
        let resumed = rebuild_frozen_cached(
            root.path().to_owned(),
            source.clone(),
            target_id,
            tokio_util::sync::CancellationToken::new(),
            &mut cache,
        )
        .await
        .unwrap();
        assert_eq!(resumed, dirty);
        assert_eq!(cache.operations, [0, 0, 1]);
        assert!(cache.entry.is_none());
        let clean = cached_fixture_rebuild(root.path(), &source, b"resume new output", &mut cache)
            .await
            .unwrap();
        assert_eq!(cache.operations, [1, 0, 1]);
        assert_eq!(cache.entry.as_ref().unwrap().relative, clean);
        assert_eq!(
            frozen_text(root.path(), &clean).0,
            frozen_text(root.path(), &source).0
        );
        let index = crate::immutable_index::open(&root.path().join(clean)).unwrap();
        let reader = index.reader().unwrap();
        assert!(
            reader
                .searcher()
                .segment_readers()
                .iter()
                .all(|segment| segment.num_deleted_docs() == 0)
        );
        drop(reader);
        assert_migration_drained(root.path());
    }

    #[tokio::test]
    async fn migration_cache_fingerprints_actual_generation_bytes_and_root() {
        let _test = TEST_SERIAL.lock().await;
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let source = build(
            root.path(),
            &crate::integrity::hash(b"reused source path"),
            documents(&[(1, "original transport")]),
        )
        .unwrap();
        let replacement = build(
            root.path(),
            &crate::integrity::hash(b"replacement generation"),
            documents(&[(1, "replacement protocol"), (2, "replacement transport")]),
        )
        .unwrap();
        let mut cache = MigrationRebuildCache::default();
        cached_fixture_rebuild(root.path(), &source, b"generation before", &mut cache)
            .await
            .unwrap();
        let first_fingerprint = cache.entry.as_ref().unwrap().source;
        replace_fixture_generation(root.path(), &source, &replacement);
        let rebuilt = cached_fixture_rebuild(root.path(), &source, b"generation after", &mut cache)
            .await
            .unwrap();
        assert_ne!(cache.entry.as_ref().unwrap().source, first_fingerprint);
        assert_eq!(cache.operations, [2, 0, 0]);
        assert_eq!(
            frozen_text(root.path(), &rebuilt).0,
            frozen_text(root.path(), &replacement).0
        );
        let changed_fingerprint = cache.entry.as_ref().unwrap().source;
        let other_root = tempfile::tempdir_in("/tmp").unwrap();
        fs::create_dir_all(other_root.path().join(&source)).unwrap();
        for (name, bytes) in retained_index_bytes(root.path(), &source) {
            fs::write(other_root.path().join(&source).join(name), bytes).unwrap();
        }
        cached_fixture_rebuild(
            other_root.path(),
            &source,
            b"same bytes different root",
            &mut cache,
        )
        .await
        .unwrap();
        assert_ne!(cache.entry.as_ref().unwrap().source, changed_fingerprint);
        assert_eq!(cache.operations, [3, 0, 0]);
        let root_fingerprint = cache.entry.as_ref().unwrap().source;
        let alias = fixture_target(b"identical bytes distinct relative path");
        fs::create_dir_all(other_root.path().join(&alias)).unwrap();
        for (name, bytes) in retained_index_bytes(other_root.path(), &source) {
            fs::write(other_root.path().join(&alias).join(name), bytes).unwrap();
        }
        cached_fixture_rebuild(
            other_root.path(),
            &alias,
            b"relative path output",
            &mut cache,
        )
        .await
        .unwrap();
        assert_ne!(cache.entry.as_ref().unwrap().source, root_fingerprint);
        assert_eq!(cache.operations, [4, 0, 0]);
        assert_migration_drained(root.path());
    }

    #[tokio::test]
    async fn migration_cache_rejects_corrupt_or_replaced_prototype_without_publication() {
        let _test = TEST_SERIAL.lock().await;
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let source = build(
            root.path(),
            &crate::integrity::hash(b"prototype integrity source"),
            documents(&[(1, "retained transport")]),
        )
        .unwrap();
        let mut cache = MigrationRebuildCache::default();
        let prototype =
            cached_fixture_rebuild(root.path(), &source, b"prototype corrupt", &mut cache)
                .await
                .unwrap();
        fs::write(root.path().join(&prototype).join("meta.json"), b"{}").unwrap();
        assert_eq!(
            cached_fixture_rebuild(
                root.path(),
                &source,
                b"corrupt prototype target",
                &mut cache
            )
            .await
            .unwrap_err()
            .code,
            "integrity"
        );
        assert!(cache.entry.is_none());
        assert!(
            !root
                .path()
                .join(fixture_target(b"corrupt prototype target"))
                .exists()
        );
        assert_migration_drained(root.path());
        let prototype =
            cached_fixture_rebuild(root.path(), &source, b"prototype replaced", &mut cache)
                .await
                .unwrap();
        let replacement = build(
            root.path(),
            &crate::integrity::hash(b"valid alternate prototype"),
            documents(&[(1, "retained transport")]),
        )
        .unwrap();
        // Same live text and valid v2 digests do not authorize replacing the
        // exact fresh prototype generation whose scoring statistics were admitted.
        replace_fixture_generation(root.path(), &prototype, &replacement);
        assert_eq!(
            cached_fixture_rebuild(
                root.path(),
                &source,
                b"replaced prototype target",
                &mut cache
            )
            .await
            .unwrap_err()
            .code,
            "integrity"
        );
        assert!(cache.entry.is_none());
        assert!(
            !root
                .path()
                .join(fixture_target(b"replaced prototype target"))
                .exists()
        );
        assert_migration_drained(root.path());
    }

    #[tokio::test]
    async fn migration_cache_cancellation_drains_rebuild_and_reuse_before_returning() {
        let _test = TEST_SERIAL.lock().await;
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let source = build(
            root.path(),
            &crate::integrity::hash(b"canceled cache source"),
            documents(&[(1, "retained transport")]),
        )
        .unwrap();
        for reuse in [false, true] {
            let mut cache = MigrationRebuildCache::default();
            if reuse {
                cached_fixture_rebuild(
                    root.path(),
                    &source,
                    b"canceled cache prototype",
                    &mut cache,
                )
                .await
                .unwrap();
            }
            let name = if reuse {
                b"cancel reuse".as_slice()
            } else {
                b"cancel rebuild".as_slice()
            };
            let target = fixture_target(name);
            let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            *MIGRATION_TEST_PAUSE.lock().unwrap() = Some(MigrationTestPause {
                target: target.clone(),
                entered: entered_tx,
                release: release_rx,
            });
            let stop = tokio_util::sync::CancellationToken::new();
            let token = stop.clone();
            let root_path = root.path().to_owned();
            let source_path = source.clone();
            let id = crate::integrity::hash(name);
            let task = tokio::spawn(async move {
                let result =
                    rebuild_frozen_cached(root_path, source_path, id, token, &mut cache).await;
                (result, cache)
            });
            tokio::time::timeout(Duration::from_secs(15), entered_rx)
                .await
                .unwrap()
                .unwrap();
            stop.cancel();
            tokio::task::yield_now().await;
            assert!(
                !task.is_finished(),
                "cancellation must drain the blocked writer before returning"
            );
            assert!(!root.path().join(&target).exists());
            release_tx.send(()).unwrap();
            let (result, cache) = tokio::time::timeout(Duration::from_secs(15), task)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(result.unwrap_err().code, "cancelled");
            assert!(cache.entry.is_none());
            assert!(!root.path().join(&target).exists());
            assert_migration_drained(root.path());
        }
    }

    #[tokio::test]
    async fn migration_cache_rechecks_legacy_evidence_and_honors_reader_writer_admission() {
        let _test = TEST_SERIAL.lock().await;
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let source = build(
            root.path(),
            &crate::integrity::legacy_hash(b"cached qualified legacy input"),
            documents(&[(1, "qualified retained transport")]),
        )
        .unwrap();
        let directory = root.path().join(&source);
        let manifest_path = directory.join(MANIFEST);
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        manifest["version"] = json!(1);
        for (name, descriptor) in manifest["files"].as_object_mut().unwrap() {
            descriptor.as_object_mut().unwrap().remove("digest");
            descriptor["sha256"] = json!(crate::integrity::legacy_hash(
                &fs::read(directory.join(name)).unwrap()
            ));
        }
        fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        qualify_legacy_file(root.path(), &manifest_path);
        for name in manifest["files"].as_object().unwrap().keys() {
            qualify_legacy_file(root.path(), &directory.join(name));
        }
        let mut cache = MigrationRebuildCache::default();
        cached_fixture_rebuild(root.path(), &source, b"legacy seed", &mut cache)
            .await
            .unwrap();
        let source_before = verification_count(root.path(), &source);
        cached_fixture_rebuild(root.path(), &source, b"legacy hit", &mut cache)
            .await
            .unwrap();
        assert_eq!(cache.operations, [1, 1, 0]);
        assert_eq!(verification_count(root.path(), &source) - source_before, 1);
        let readers = READERS.try_acquire_many(2).unwrap();
        assert_eq!(
            cached_fixture_rebuild(root.path(), &source, b"reader busy target", &mut cache)
                .await
                .unwrap_err()
                .code,
            "capacity"
        );
        assert!(cache.entry.is_none());
        assert!(
            !root
                .path()
                .join(fixture_target(b"reader busy target"))
                .exists()
        );
        drop(readers);
        cached_fixture_rebuild(root.path(), &source, b"writer admission seed", &mut cache)
            .await
            .unwrap();
        let writer = WRITERS.try_acquire().unwrap();
        assert_eq!(
            cached_fixture_rebuild(root.path(), &source, b"writer busy target", &mut cache)
                .await
                .unwrap_err()
                .code,
            "capacity"
        );
        assert!(cache.entry.is_none());
        assert!(
            !root
                .path()
                .join(fixture_target(b"writer busy target"))
                .exists()
        );
        drop(writer);
        cached_fixture_rebuild(root.path(), &source, b"evidence seed", &mut cache)
            .await
            .unwrap();
        fs::remove_file(
            crate::integrity::evidence_path(root.path(), &directory.join("meta.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            cached_fixture_rebuild(root.path(), &source, b"missing evidence target", &mut cache)
                .await
                .unwrap_err()
                .code,
            "integrity"
        );
        assert!(cache.entry.is_none());
        assert!(
            !root
                .path()
                .join(fixture_target(b"missing evidence target"))
                .exists()
        );
        assert_migration_drained(root.path());
    }

    #[tokio::test]
    async fn migration_cache_rejects_source_corruption_duplicate_membership_and_file_limits() {
        let _test = TEST_SERIAL.lock().await;
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let source = build(
            root.path(),
            &crate::integrity::hash(b"cache invalid source"),
            documents(&[(1, "retained transport")]),
        )
        .unwrap();
        let mut cache = MigrationRebuildCache::default();
        cached_fixture_rebuild(root.path(), &source, b"cache invalid prototype", &mut cache)
            .await
            .unwrap();
        fs::write(root.path().join(&source).join("meta.json"), b"{}").unwrap();
        assert_eq!(
            cached_fixture_rebuild(root.path(), &source, b"cache invalid target", &mut cache)
                .await
                .unwrap_err()
                .code,
            "integrity"
        );
        assert!(cache.entry.is_none());
        assert!(
            !root
                .path()
                .join(fixture_target(b"cache invalid target"))
                .exists()
        );
        let duplicate_id = crate::integrity::hash(b"cache duplicate source");
        let mut duplicate = IndexBuilder::begin(root.path(), &duplicate_id).unwrap();
        let schema = duplicate.index.schema();
        for text in ["first transport", "second protocol"] {
            let mut document = TantivyDocument::new();
            document.add_u64(schema.get_field(NUMBER).unwrap(), 1);
            document.add_text(schema.get_field(TECHNICAL).unwrap(), text);
            document.add_text(schema.get_field(ENGLISH).unwrap(), text);
            duplicate
                .writer
                .as_mut()
                .unwrap()
                .add_document(document)
                .unwrap();
        }
        let duplicate = duplicate.finish().unwrap();
        assert_eq!(
            cached_fixture_rebuild(root.path(), &duplicate, b"duplicate target", &mut cache)
                .await
                .unwrap_err()
                .code,
            "integrity"
        );
        assert!(cache.entry.is_none());
        assert!(
            !root
                .path()
                .join(fixture_target(b"duplicate target"))
                .exists()
        );
        let limited = build(
            root.path(),
            &crate::integrity::hash(b"cache file limit source"),
            documents(&[(1, "bounded transport")]),
        )
        .unwrap();
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(root.path().join(&limited).join(MANIFEST)).unwrap())
                .unwrap();
        let files = manifest["files"].as_object_mut().unwrap();
        for number in 0..=MAX_FILES {
            files.insert(
                format!("extra-{number}"),
                json!({"bytes":0,"digest":crate::integrity::hash(b"")}),
            );
        }
        let bytes = serde_json::to_vec(&manifest).unwrap();
        assert!((bytes.len() as u64) < MAX_MANIFEST);
        fs::write(root.path().join(&limited).join(MANIFEST), bytes).unwrap();
        assert_eq!(
            cached_fixture_rebuild(root.path(), &limited, b"limited target", &mut cache)
                .await
                .unwrap_err()
                .code,
            "integrity"
        );
        assert!(cache.entry.is_none());
        assert!(!root.path().join(fixture_target(b"limited target")).exists());
        assert_migration_drained(root.path());
    }

    #[tokio::test]
    async fn empty_delta_fresh_prototype_preserves_rebuild_queries_and_statistics() {
        let _test = TEST_SERIAL.lock().await;
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let mut source = IndexBuilder::begin(
            root.path(),
            &crate::integrity::legacy_hash(b"deleted segmented legacy source"),
        )
        .unwrap();
        let mut expected = BTreeMap::new();
        for number in 1..=160 {
            let animals = if number % 3 == 0 {
                "cats and dogs"
            } else {
                "only cats"
            };
            let repetitions = "transport ".repeat((number % 5 + 1) as usize);
            let text = format!(
                "RFC {number}: A secure transport permits {animals}. {repetitions}{} The running clients negotiate a reliable protocol. A phrase near the end.",
                "background paragraph without matching words. ".repeat(9)
            );
            source
                .add_document(IndexDocument {
                    number,
                    text: text.clone(),
                })
                .unwrap();
            expected.insert(number, text);
            if number % 20 == 0 {
                source.writer.as_mut().unwrap().commit().unwrap();
            }
        }
        for number in [3, 20, 41, 80, 159] {
            source.remove_document(number).unwrap();
            expected.remove(&number);
        }
        for number in [1, 22, 101] {
            let text = format!(
                "Replacement RFC {number}: secure transport with cats and dogs. The running clients negotiate a reliable protocol. A phrase near the end."
            );
            source
                .add_document(IndexDocument {
                    number,
                    text: text.clone(),
                })
                .unwrap();
            expected.insert(number, text);
        }
        let original = source.finish().unwrap();
        let original_directory = root.path().join(&original);
        let manifest_path = original_directory.join(MANIFEST);
        let mut legacy: Value = serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        legacy["version"] = json!(1);
        for (name, descriptor) in legacy["files"].as_object_mut().unwrap() {
            descriptor.as_object_mut().unwrap().remove("digest");
            descriptor["sha256"] = json!(crate::integrity::legacy_hash(
                &fs::read(original_directory.join(name)).unwrap()
            ));
        }
        fs::write(&manifest_path, serde_json::to_vec(&legacy).unwrap()).unwrap();
        qualify_legacy_file(root.path(), &manifest_path);
        for name in legacy["files"].as_object().unwrap().keys() {
            qualify_legacy_file(root.path(), &original_directory.join(name));
        }
        type SegmentStatistics = (u32, u32, u32, u64, u64);
        type IndexStatistics = (u64, Vec<SegmentStatistics>, Vec<u64>);
        fn statistics(root: &Path, relative: &str) -> IndexStatistics {
            let index = crate::immutable_index::open(&root.join(relative)).unwrap();
            let reader = index.reader().unwrap();
            let searcher = reader.searcher();
            let technical = index.schema().get_field(TECHNICAL).unwrap();
            let english = index.schema().get_field(ENGLISH).unwrap();
            let mut segments: Vec<_> = searcher
                .segment_readers()
                .iter()
                .map(|segment| {
                    (
                        segment.num_docs(),
                        segment.max_doc(),
                        segment.num_deleted_docs(),
                        segment
                            .inverted_index(technical)
                            .unwrap()
                            .total_num_tokens(),
                        segment.inverted_index(english).unwrap().total_num_tokens(),
                    )
                })
                .collect();
            segments.sort_unstable();
            let frequencies = [
                (technical, "transport"),
                (technical, "cats"),
                (english, "transport"),
                (english, "cat"),
                (english, "dog"),
            ]
            .into_iter()
            .map(|(field, term)| {
                searcher
                    .doc_freq(&Term::from_field_text(field, term))
                    .unwrap()
            })
            .collect();
            (searcher.num_docs(), segments, frequencies)
        }

        let legacy_statistics = statistics(root.path(), &original);
        assert!(legacy_statistics.1.len() >= 8);
        assert!(legacy_statistics.1.iter().any(|segment| segment.2 > 0));
        assert_eq!(legacy_statistics.0, expected.len() as u64);
        assert_eq!(frozen_text(root.path(), &original).0, expected);
        let prototype = rebuild_frozen(
            root.path().to_owned(),
            original.clone(),
            crate::integrity::hash(b"fresh canonical prototype"),
            tokio_util::sync::CancellationToken::new(),
        )
        .await
        .unwrap();
        let control = rebuild_frozen(
            root.path().to_owned(),
            original.clone(),
            crate::integrity::hash(b"independent from-empty canonical control"),
            tokio_util::sync::CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_ne!(prototype, control);
        let prototype_bytes = retained_index_bytes(root.path(), &prototype);
        let prototype_statistics = statistics(root.path(), &prototype);
        assert_eq!(prototype_statistics.0, expected.len() as u64);
        assert!(
            prototype_statistics
                .1
                .iter()
                .all(|segment| segment.2 == 0 && segment.0 == segment.1)
        );
        assert_eq!(prototype_statistics, statistics(root.path(), &control));
        assert_eq!(frozen_text(root.path(), &prototype).0, expected);
        assert_eq!(frozen_text(root.path(), &control).0, expected);
        let mut targets = vec![prototype.clone()];
        for identity in [
            b"empty-delta target one".as_slice(),
            b"empty-delta target two".as_slice(),
        ] {
            // Exercise the exact existing helper with no document additions or removals.
            let copied = IndexBuilder::begin_from(
                root.path(),
                &crate::integrity::hash(identity),
                Some(&prototype),
            )
            .unwrap()
            .finish()
            .unwrap();
            assert_ne!(copied, prototype);
            assert_ne!(copied, control);
            assert!(!targets.contains(&copied));
            assert_eq!(frozen_text(root.path(), &copied).0, expected);
            assert_eq!(statistics(root.path(), &copied), prototype_statistics);
            assert_eq!(
                retained_index_bytes(root.path(), &prototype),
                prototype_bytes
            );
            targets.push(copied);
        }
        let filters: [Option<&[u32]>; 2] = [None, Some(&[1, 2, 6, 22, 42, 101, 160])];
        let cases = [
            ("secure transport", TECHNICAL),
            ("phrase near the end", TECHNICAL),
            ("transport dogs", TECHNICAL),
            ("protocol", TECHNICAL),
            ("cat", ENGLISH),
            ("\"running clients\"", ENGLISH),
            ("-dog", ENGLISH),
            ("dog OR only", ENGLISH),
        ];
        let mut compared = 0;
        for (query, mode) in cases {
            for allowed in filters {
                let all = search(root.path(), &control, query, mode, 0, 100, allowed).unwrap();
                assert!(
                    all["total"].as_u64().unwrap() > 0,
                    "fixture query has no hits: {query}"
                );
                for offset in [0, 7, 1000] {
                    let baseline =
                        search(root.path(), &control, query, mode, offset, 7, allowed).unwrap();
                    if offset == 0 {
                        assert_eq!(
                            baseline["items"],
                            json!(
                                &all["items"].as_array().unwrap()
                                    [..all["items"].as_array().unwrap().len().min(7)]
                            )
                        );
                    }
                    for target in &targets {
                        assert_eq!(
                            search(root.path(), target, query, mode, offset, 7, allowed).unwrap(),
                            baseline,
                            "full result mismatch: query={query}, mode={mode}, offset={offset}, target={target}"
                        );
                        compared += 1;
                    }
                }
            }
        }
        assert_eq!(
            retained_index_bytes(root.path(), &prototype),
            prototype_bytes
        );
        assert_eq!(statistics(root.path(), &prototype), prototype_statistics);
        assert_eq!(frozen_text(root.path(), &original).0, expected);
        eprintln!(
            "empty-delta fixture: {} legacy segments, {} retained docs, {} full JSON query/page/filter comparisons, two distinct empty-delta targets; prototype bytes and public Tantivy statistics unchanged",
            legacy_statistics.1.len(),
            expected.len(),
            compared
        );
    }

    #[tokio::test]
    async fn empty_delta_multisegment_prototype_preserves_control_rankings() {
        let _test = TEST_SERIAL.lock().await;
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let mut original_builder = IndexBuilder::begin(
            root.path(),
            &crate::integrity::hash(b"multi-segment fixture source"),
        )
        .unwrap();
        let mut expected = BTreeMap::new();
        let mut input_bytes = 0;
        for number in (1..=2400).rev() {
            let animals = match number % 4 {
                0 => "cats and dogs",
                1 => "only cats today",
                2 => "birds and dogs",
                _ => "only birds today",
            };
            // Every technical document has the same token count and one tieanchor,
            // so this query creates equal-score ties across all segment boundaries.
            let text = format!(
                "tieanchor A secure transport permits {animals}. Running clients negotiate reliable protocol. {}A phrase near the end.",
                "background paragraph without matching words. ".repeat(9)
            );
            input_bytes += text.len();
            expected.insert(number, text.clone());
            original_builder
                .add_document(IndexDocument { number, text })
                .unwrap();
        }
        assert!(input_bytes < 32 * 1024 * 1024);
        let original = original_builder.finish().unwrap();
        let mut exported = Vec::new();
        let mut original_reader = FrozenDocuments::open(
            root.path(),
            &original,
            &tokio_util::sync::CancellationToken::new(),
        )
        .unwrap();
        loop {
            let page = original_reader.next_page(237).unwrap();
            if page.is_empty() {
                break;
            }
            exported.extend(page);
        }
        drop(original_reader);
        assert_eq!(exported.len(), expected.len());
        let exported_numbers: Vec<_> = exported.iter().map(|document| document.number).collect();
        assert_eq!(exported_numbers, (1..=2400).rev().collect::<Vec<_>>());
        let mut prototype_builder = IndexBuilder::begin_from(
            root.path(),
            &crate::integrity::hash(b"fresh manually segmented canonical prototype"),
            None,
        )
        .unwrap();
        for (ordinal, document) in exported.into_iter().enumerate() {
            prototype_builder.add_document(document).unwrap();
            if (ordinal + 1) % 200 == 0 {
                // Test-only forced commits make a compact fixture multi-segment.
                // Production flushes on >32MiB queued doubled text bytes instead.
                prototype_builder.writer.as_mut().unwrap().commit().unwrap();
            }
        }
        let prototype = prototype_builder.finish().unwrap();
        let control = rebuild_frozen(
            root.path().to_owned(),
            original.clone(),
            crate::integrity::hash(b"independent ordinary frozen rebuild control"),
            tokio_util::sync::CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_ne!(prototype, control);

        type SegmentStatistics = (String, u32, u32, u32, u64, u64);
        type AggregateStatistics = (u64, u64, u64, u64, u64, Vec<u64>);
        fn statistics(
            root: &Path,
            relative: &str,
        ) -> (Vec<SegmentStatistics>, AggregateStatistics) {
            let index = crate::immutable_index::open(&root.join(relative)).unwrap();
            let reader = index.reader().unwrap();
            let searcher = reader.searcher();
            let technical = index.schema().get_field(TECHNICAL).unwrap();
            let english = index.schema().get_field(ENGLISH).unwrap();
            let mut segments: Vec<_> = searcher
                .segment_readers()
                .iter()
                .map(|segment| {
                    (
                        format!("{:?}", segment.segment_id()),
                        segment.num_docs(),
                        segment.max_doc(),
                        segment.num_deleted_docs(),
                        segment
                            .inverted_index(technical)
                            .unwrap()
                            .total_num_tokens(),
                        segment.inverted_index(english).unwrap().total_num_tokens(),
                    )
                })
                .collect();
            segments.sort_unstable();
            let max_docs = segments.iter().map(|segment| u64::from(segment.2)).sum();
            let deleted_docs = segments.iter().map(|segment| u64::from(segment.3)).sum();
            let technical_tokens = segments.iter().map(|segment| segment.4).sum();
            let english_tokens = segments.iter().map(|segment| segment.5).sum();
            let frequencies = [
                (technical, "tieanchor"),
                (technical, "transport"),
                (technical, "cats"),
                (technical, "dogs"),
                (technical, "phrase"),
                (english, "tieanchor"),
                (english, "transport"),
                (english, "cat"),
                (english, "dog"),
                (english, "run"),
            ]
            .into_iter()
            .map(|(field, term)| {
                searcher
                    .doc_freq(&Term::from_field_text(field, term))
                    .unwrap()
            })
            .collect();
            (
                segments,
                (
                    searcher.num_docs(),
                    max_docs,
                    deleted_docs,
                    technical_tokens,
                    english_tokens,
                    frequencies,
                ),
            )
        }

        fn ordered_numbers(root: &Path, relative: &str) -> Vec<u32> {
            let mut reader =
                FrozenDocuments::open(root, relative, &tokio_util::sync::CancellationToken::new())
                    .unwrap();
            let mut numbers = Vec::new();
            loop {
                let page = reader.next_page(237).unwrap();
                if page.is_empty() {
                    break;
                }
                numbers.extend(page.into_iter().map(|document| document.number));
            }
            numbers
        }
        assert_eq!(ordered_numbers(root.path(), &control), exported_numbers);
        let prototype_bytes = retained_index_bytes(root.path(), &prototype);
        let prototype_statistics = statistics(root.path(), &prototype);
        let control_statistics = statistics(root.path(), &control);
        assert_eq!(prototype_statistics.0.len(), 12);
        assert_eq!(control_statistics.0.len(), 1);
        assert!(
            prototype_statistics
                .0
                .iter()
                .all(|segment| segment.1 == 200 && segment.2 == 200 && segment.3 == 0)
        );
        assert_eq!(prototype_statistics.1, control_statistics.1);
        assert_eq!(prototype_statistics.1.0, 2400);
        assert_eq!(prototype_statistics.1.2, 0);
        assert_eq!(frozen_text(root.path(), &prototype).0, expected);
        assert_eq!(frozen_text(root.path(), &control).0, expected);
        let mut targets = vec![prototype.clone()];
        for identity in [
            b"multi-segment empty-delta target one".as_slice(),
            b"multi-segment empty-delta target two".as_slice(),
        ] {
            let copied = IndexBuilder::begin_from(
                root.path(),
                &crate::integrity::hash(identity),
                Some(&prototype),
            )
            .unwrap()
            .finish()
            .unwrap();
            assert_ne!(copied, prototype);
            assert_ne!(copied, control);
            assert!(!targets.contains(&copied));
            assert_eq!(frozen_text(root.path(), &copied).0, expected);
            assert_eq!(statistics(root.path(), &copied), prototype_statistics);
            assert_eq!(
                retained_index_bytes(root.path(), &prototype),
                prototype_bytes
            );
            targets.push(copied);
        }
        let filters: [Option<&[u32]>; 2] = [
            None,
            Some(&[1, 2, 4, 100, 199, 200, 201, 399, 400, 401, 1200, 2399, 2400]),
        ];
        let cases = [
            ("tieanchor", TECHNICAL),
            ("secure transport", TECHNICAL),
            ("phrase near the end", TECHNICAL),
            ("transport dogs", TECHNICAL),
            ("cat", ENGLISH),
            ("\"running clients\"", ENGLISH),
            ("-dog", ENGLISH),
            ("dog OR only", ENGLISH),
        ];
        let pages = [
            (0, 7),
            (7, 7),
            (13, 7),
            (99, 7),
            (100, 100),
            (199, 7),
            (200, 7),
            (2393, 7),
            (2399, 7),
            (2400, 7),
        ];
        let mut comparisons = 0;
        for (query, mode) in cases {
            for allowed in filters {
                let all = search(root.path(), &control, query, mode, 0, 100, allowed).unwrap();
                assert!(
                    all["total"].as_u64().unwrap() > 0,
                    "fixture query has no hits: {query}"
                );
                for (offset, limit) in pages {
                    let baseline =
                        search(root.path(), &control, query, mode, offset, limit, allowed).unwrap();
                    for target in &targets {
                        assert_eq!(
                            search(root.path(), target, query, mode, offset, limit, allowed)
                                .unwrap(),
                            baseline,
                            "full result mismatch: query={query}, mode={mode}, offset={offset}, limit={limit}, target={target}"
                        );
                        comparisons += 1;
                    }
                }
            }
        }
        // Exercise complete tied-result pagination, including per-segment top-K
        // truncation, merge truncation and number ordering at adjacent page edges.
        let mut previous_score = None;
        let mut all_numbers = Vec::new();
        for offset in (0..2400).step_by(100) {
            let baseline = search(
                root.path(),
                &control,
                "tieanchor",
                TECHNICAL,
                offset,
                100,
                None,
            )
            .unwrap();
            assert_eq!(baseline["total"], 2400);
            for target in &targets {
                assert_eq!(
                    search(
                        root.path(),
                        target,
                        "tieanchor",
                        TECHNICAL,
                        offset,
                        100,
                        None
                    )
                    .unwrap(),
                    baseline
                );
                comparisons += 1;
            }
            for item in baseline["items"].as_array().unwrap() {
                if let Some(score) = &previous_score {
                    assert_eq!(
                        &item["score"], score,
                        "tie fixture must produce exactly equal scores"
                    );
                }
                previous_score = Some(item["score"].clone());
                all_numbers.push(item["number"].as_u64().unwrap());
            }
        }
        assert_eq!(all_numbers, (1..=2400).collect::<Vec<_>>());
        assert_eq!(
            retained_index_bytes(root.path(), &prototype),
            prototype_bytes
        );
        assert_eq!(statistics(root.path(), &prototype), prototype_statistics);
        eprintln!(
            "multi-segment empty-delta fixture: {} documents, {} text bytes, {} canonical live-only segments versus {} control segment, {} exact JSON comparisons including complete tied pagination; prototype bytes/statistics unchanged",
            expected.len(),
            input_bytes,
            prototype_statistics.0.len(),
            control_statistics.0.len(),
            comparisons
        );
    }

    #[test]
    fn frozen_pages_keep_byte_boundary_document_and_reader_admission() {
        let _test = TEST_SERIAL.blocking_lock();
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let text = format!("transport{}", " ".repeat(11 * 1024 * 1024));
        let original = build(
            root.path(),
            &crate::integrity::hash(b"RFC export byte-boundary fixture"),
            (1..=3)
                .map(|number| IndexDocument {
                    number,
                    text: text.clone(),
                })
                .collect(),
        )
        .unwrap();
        let stop = tokio_util::sync::CancellationToken::new();
        let mut reader = FrozenDocuments::open(root.path(), &original, &stop).unwrap();
        let first = reader.next_page(1000).unwrap();
        assert_eq!(first.len(), 2);
        assert_eq!(reader.visited_documents, 3);
        assert!(first.iter().map(|doc| doc.text.len()).sum::<usize>() <= MAX_QUEUED_BYTES);
        let second = reader.next_page(1000).unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(
            reader.visited_documents, 3,
            "pending text is not decoded again"
        );
        assert!(reader.next_page(1000).unwrap().is_empty());
        assert_eq!(
            first
                .into_iter()
                .chain(second)
                .map(|doc| (doc.number, doc.text))
                .collect::<BTreeMap<_, _>>(),
            (1..=3).map(|number| (number, text.clone())).collect()
        );
        let second_reader = FrozenDocuments::open(root.path(), &original, &stop).unwrap();
        assert_eq!(
            FrozenDocuments::open(root.path(), &original, &stop)
                .err()
                .unwrap()
                .code,
            "capacity"
        );
        drop(second_reader);
        drop(reader);
        assert_eq!(READERS.available_permits(), 2);
    }

    #[test]
    fn frozen_reader_cancellation_and_deadlines_stop_before_more_documents() {
        let _test = TEST_SERIAL.blocking_lock();
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let original = build(
            root.path(),
            &crate::integrity::hash(b"RFC canceled export fixture"),
            documents(&[(1, "retained transport"), (2, "retained protocol")]),
        )
        .unwrap();
        let stop = tokio_util::sync::CancellationToken::new();
        let mut reader = FrozenDocuments::open(root.path(), &original, &stop).unwrap();
        assert_eq!(reader.next_page(1).unwrap().len(), 1);
        stop.cancel();
        assert_eq!(reader.next_page(1).err().unwrap().code, "cancelled");
        assert_eq!(reader.visited_documents, 1);
        drop(reader);
        let mut reader = FrozenDocuments::open(
            root.path(),
            &original,
            &tokio_util::sync::CancellationToken::new(),
        )
        .unwrap();
        reader.first_page_deadline = Some(Instant::now() - Duration::from_secs(1));
        assert_eq!(reader.next_page(1).err().unwrap().code, "capacity");
        assert_eq!(reader.visited_documents, 0);
        assert!(reader.next_page(0).is_err());
        assert!(reader.next_page(1001).is_err());
    }

    #[tokio::test]
    async fn frozen_rebuild_rejects_corrupt_source_or_different_retained_text() {
        let _test = TEST_SERIAL.lock().await;
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let original = build(
            root.path(),
            &crate::integrity::hash(b"RFC source-integrity fixture"),
            documents(&[(1, "original retained transport")]),
        )
        .unwrap();
        let canceled_target = crate::integrity::hash(b"RFC canceled rebuild fixture");
        let stop = tokio_util::sync::CancellationToken::new();
        stop.cancel();
        assert_eq!(
            rebuild_frozen(
                root.path().to_owned(),
                original.clone(),
                canceled_target.clone(),
                stop,
            )
            .await
            .unwrap_err()
            .code,
            "cancelled"
        );
        assert!(
            !root
                .path()
                .join("rfc-indexes")
                .join(index_suffix(&canceled_target).unwrap())
                .exists()
        );
        let target_id = crate::integrity::hash(b"RFC retry-integrity fixture");
        build(
            root.path(),
            &target_id,
            documents(&[(1, "different retained transport")]),
        )
        .unwrap();
        assert_eq!(
            rebuild_frozen(
                root.path().to_owned(),
                original.clone(),
                target_id,
                tokio_util::sync::CancellationToken::new(),
            )
            .await
            .unwrap_err()
            .code,
            "integrity"
        );
        let target_id = crate::integrity::hash(b"RFC incomplete source fixture");
        fs::write(root.path().join(&original).join("meta.json"), b"{}").unwrap();
        assert_eq!(
            rebuild_frozen(
                root.path().to_owned(),
                original,
                target_id.clone(),
                tokio_util::sync::CancellationToken::new(),
            )
            .await
            .unwrap_err()
            .code,
            "integrity"
        );
        assert!(
            !root
                .path()
                .join("rfc-indexes")
                .join(index_suffix(&target_id).unwrap())
                .exists()
        );
        assert!(
            fs::read_dir(root.path().join("rfc-indexes"))
                .unwrap()
                .all(|entry| !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".stage-"))
        );
        assert_eq!(READERS.available_permits(), 2);
        assert_eq!(WRITERS.available_permits(), 1);
    }

    #[test]
    fn repeated_commits_do_not_launch_automatic_merges() {
        let _test = TEST_SERIAL.blocking_lock();
        let root = tempfile::tempdir().unwrap();
        let mut builder = IndexBuilder::begin(root.path(), &"b".repeat(64)).unwrap();
        for number in 1..=20 {
            builder
                .add_document(IndexDocument {
                    number,
                    text: "synthetic persistent transport".into(),
                })
                .unwrap();
            builder.writer.as_mut().unwrap().commit().unwrap();
        }
        let path = builder.finish().unwrap();
        let index = Index::open_in_dir(root.path().join(&path)).unwrap();
        let reader = index.reader().unwrap();
        assert_eq!(
            reader.searcher().segment_readers().len(),
            20,
            "automatic merges must stay disabled across repeated commits"
        );
        assert_eq!(
            search(root.path(), &path, "transport", TECHNICAL, 0, 100, None).unwrap()["total"],
            20
        );
    }

    #[test]
    fn whole_document_modes_filters_and_stable_pages() {
        let _test = TEST_SERIAL.blocking_lock();
        let root = tempfile::tempdir().unwrap();
        let id = "a".repeat(64);
        let path = build(
            root.path(),
            &id,
            documents(&[
                (9, "A secure transport permits cats and dogs."),
                (2, "A secure transport permits cats and dogs."),
                (3, "A secure transport permits only cats."),
            ]),
        )
        .unwrap();
        let first = search(
            root.path(),
            &path,
            "secure transport",
            TECHNICAL,
            0,
            1,
            None,
        )
        .unwrap();
        assert_eq!(first["total"], 3);
        let all = search(
            root.path(),
            &path,
            "secure transport",
            TECHNICAL,
            0,
            100,
            None,
        )
        .unwrap();
        let second = search(
            root.path(),
            &path,
            "secure transport",
            TECHNICAL,
            1,
            1,
            None,
        )
        .unwrap();
        assert_eq!(first["items"][0], all["items"][0]);
        assert_eq!(second["items"][0], all["items"][1]);
        let numbers: Vec<_> = all["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["number"].as_u64().unwrap())
            .collect();
        assert!(
            numbers.iter().position(|n| *n == 2).unwrap()
                < numbers.iter().position(|n| *n == 9).unwrap()
        );
        let filtered = search(
            root.path(),
            &path,
            "secure transport",
            TECHNICAL,
            0,
            20,
            Some(&[9]),
        )
        .unwrap();
        assert_eq!(filtered["total"], 1);
        assert_eq!(filtered["items"][0]["number"], 9);
        assert_eq!(
            search(root.path(), &path, "cat", TECHNICAL, 0, 20, None).unwrap()["total"],
            0
        );
        assert_eq!(
            search(root.path(), &path, "cat", ENGLISH, 0, 20, None).unwrap()["total"],
            3
        );
        assert_eq!(
            search(root.path(), &path, "-dog", ENGLISH, 0, 20, None).unwrap()["total"],
            1
        );
        assert_eq!(
            search(root.path(), &path, "dog OR only", ENGLISH, 0, 20, None).unwrap()["total"],
            3
        );
        assert!(search(root.path(), &path, "the", ENGLISH, 0, 20, None).is_err());
        assert!(
            search(
                root.path(),
                &path,
                "technical:transport",
                ENGLISH,
                0,
                20,
                None
            )
            .is_err()
        );
        assert!(search(root.path(), &path, "\"open", ENGLISH, 0, 20, None).is_err());
        assert_eq!(
            search(root.path(), &path, "transport", TECHNICAL, 100, 20, None).unwrap()["items"],
            json!([])
        );
    }

    #[test]
    fn preserves_far_apart_terms_late_phrases_and_stopword_positions() {
        let _test = TEST_SERIAL.blocking_lock();
        let root = tempfile::tempdir().unwrap();
        let mut text = String::from("firstmarker ");
        text.push_str(&"padding ".repeat(20_000));
        text.push_str("late phrase lastmarker cat and dog");
        let path = build(
            root.path(),
            &"b".repeat(64),
            vec![
                IndexDocument { number: 9000, text },
                IndexDocument {
                    number: 9001,
                    text: "cat dog".into(),
                },
            ],
        )
        .unwrap();
        assert_eq!(
            search(
                root.path(),
                &path,
                "firstmarker lastmarker",
                TECHNICAL,
                0,
                20,
                None
            )
            .unwrap()["total"],
            1
        );
        assert_eq!(
            search(root.path(), &path, "\"late phrase\"", ENGLISH, 0, 20, None).unwrap()["total"],
            1
        );
        assert_eq!(
            search(root.path(), &path, "\"cat and dog\"", ENGLISH, 0, 20, None).unwrap()["total"],
            1
        );
        assert_eq!(
            search(root.path(), &path, "\"cat dog\"", ENGLISH, 0, 20, None).unwrap()["total"],
            1
        );
    }

    #[test]
    fn incremental_updates_leave_prior_snapshot_unchanged() {
        let _test = TEST_SERIAL.blocking_lock();
        let root = tempfile::tempdir().unwrap();
        let first = build(
            root.path(),
            &"c".repeat(64),
            documents(&[(1, "old transport"), (2, "retained transport")]),
        )
        .unwrap();
        let mut builder =
            IndexBuilder::begin_from(root.path(), &"d".repeat(64), Some(&first)).unwrap();
        builder
            .add_document(IndexDocument {
                number: 1,
                text: "new transport".into(),
            })
            .unwrap();
        builder.remove_document(2).unwrap();
        builder
            .add_document(IndexDocument {
                number: 3,
                text: "added transport".into(),
            })
            .unwrap();
        let second = builder.finish().unwrap();
        assert_eq!(
            search(root.path(), &first, "old", TECHNICAL, 0, 20, None).unwrap()["total"],
            1
        );
        assert_eq!(
            search(root.path(), &second, "old", TECHNICAL, 0, 20, None).unwrap()["total"],
            0
        );
        assert_eq!(
            search(root.path(), &second, "transport", TECHNICAL, 0, 20, None).unwrap()["total"],
            2
        );
        assert_eq!(
            search(root.path(), &first, "retained", TECHNICAL, 0, 20, None).unwrap()["total"],
            1
        );
    }

    #[test]
    fn rejects_oversized_tokens_paths_and_corrupt_artifacts() {
        let _test = TEST_SERIAL.blocking_lock();
        let root = tempfile::tempdir().unwrap();
        {
            let mut builder = IndexBuilder::begin(root.path(), &"e".repeat(64)).unwrap();
            assert!(
                builder
                    .add_document(IndexDocument {
                        number: 1,
                        text: "a".repeat(MAX_TOKEN_LEN)
                    })
                    .is_err()
            );
        }
        let path = build(
            root.path(),
            &"f".repeat(64),
            documents(&[(1, "original transport")]),
        )
        .unwrap();
        assert!(
            search(
                root.path(),
                "rfc-indexes/../../etc",
                "transport",
                TECHNICAL,
                0,
                20,
                None
            )
            .is_err()
        );
        let meta = root.path().join(&path).join("meta.json");
        fs::write(meta, b"{}").unwrap();
        assert_eq!(
            search(root.path(), &path, "transport", TECHNICAL, 0, 20, None)
                .unwrap_err()
                .code,
            "integrity"
        );
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlinked_snapshot_files() {
        let _test = TEST_SERIAL.blocking_lock();
        let root = tempfile::tempdir().unwrap();
        let path = build(
            root.path(),
            &"1".repeat(64),
            documents(&[(1, "safe transport")]),
        )
        .unwrap();
        let meta = root.path().join(&path).join("meta.json");
        fs::remove_file(&meta).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", &meta).unwrap();
        assert_eq!(
            search(root.path(), &path, "transport", TECHNICAL, 0, 20, None)
                .unwrap_err()
                .code,
            "integrity"
        );
    }
}
