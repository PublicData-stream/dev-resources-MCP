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
    Ok(FileDigest {
        bytes,
        digest: if legacy {
            hex::encode(hasher.finalize())
        } else {
            format!("blake3:{}", blake3.finalize().to_hex())
        },
    })
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

fn verify(path: &Path, deadline: Instant) -> Result<()> {
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
        let actual = digest_with_algorithm(
            &path.join(name),
            deadline,
            !expected.digest.starts_with("blake3:"),
        )?;
        total = total.saturating_add(actual.bytes);
        if total > MAX_INDEX_BYTES {
            return Err(Error::capacity("RFC index size limit exceeded."));
        }
        if actual.bytes != expected.bytes || actual.digest != expected.digest {
            return Err(integrity());
        }
    }
    Ok(())
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
            let index = match base {
                Some(relative) => {
                    let source = selected_directory(root, relative)?;
                    verify(&source, Instant::now() + Duration::from_secs(15))?;
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
            Ok((index, writer, numbers))
        })();
        match prepared {
            Ok((index, writer, numbers)) => Ok(Self {
                storage_root: fs::canonicalize(root).map_err(|_| unavailable())?,
                writer: Some(writer),
                index,
                stage,
                final_path,
                relative: format!("rfc-indexes/{suffix}"),
                numbers,
                queued_bytes: 0,
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

/// Rebuild exactly one frozen index generation using its original admitted text.
pub(crate) async fn rebuild_frozen(
    root: PathBuf,
    relative: String,
    id: String,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<String> {
    struct CancelOnDrop(tokio_util::sync::CancellationToken);
    impl Drop for CancelOnDrop {
        fn drop(&mut self) {
            self.0.cancel();
        }
    }
    let stop = cancel.child_token();
    let _guard = CancelOnDrop(stop.clone());
    let mut task = tokio::task::spawn_blocking(move || {
        if stop.is_cancelled() {
            return Err(Error::new("cancelled", "RFC migration canceled."));
        }
        let target = format!("rfc-indexes/{}", index_suffix(&id)?);
        if root.join(&target).exists() {
            let mut original = BTreeMap::new();
            let mut retained = BTreeMap::new();
            for (path, output) in [(&relative, &mut original), (&target, &mut retained)] {
                let mut after = 0;
                loop {
                    if stop.is_cancelled() {
                        return Err(Error::new("cancelled", "RFC migration canceled."));
                    }
                    let (documents, next) = export_documents(&root, path, after, 1000)?;
                    for document in documents {
                        if output
                            .insert(
                                document.number,
                                crate::integrity::hash(document.text.as_bytes()),
                            )
                            .is_some()
                        {
                            return Err(integrity());
                        }
                    }
                    match next {
                        Some(next) => after = next,
                        None => break,
                    }
                }
            }
            if original != retained {
                return Err(integrity());
            }
            return Ok(target);
        }
        let mut builder = IndexBuilder::begin_from(&root, &id, None)?;
        let mut after = 0;
        loop {
            if stop.is_cancelled() {
                return Err(Error::new("cancelled", "RFC migration canceled."));
            }
            let (documents, next) = export_documents(&root, &relative, after, 1000)?;
            for document in documents {
                if stop.is_cancelled() {
                    return Err(Error::new("cancelled", "RFC migration canceled."));
                }
                builder.add_document(document)?;
            }
            match next {
                Some(next) => after = next,
                None => break,
            }
        }
        builder.finish()
    });
    tokio::select! { biased; _ = cancel.cancelled() => { let _ = task.await; Err(Error::new("cancelled", "RFC migration canceled.")) }, result = &mut task => result.map_err(|_| unavailable())? }
}

/// Export exact retained text without selecting a moving corpus head.
/// The caller owns the maintenance fence and executes this on a blocking worker.
pub(crate) fn export_documents(
    root: &Path,
    relative: &str,
    after: usize,
    limit: usize,
) -> Result<(Vec<IndexDocument>, Option<usize>)> {
    if !(1..=1000).contains(&limit) {
        return Err(Error::invalid("Invalid RFC index export page."));
    }
    let _permit = READERS
        .try_acquire()
        .map_err(|_| Error::capacity("RFC index reader capacity exhausted."))?;
    let deadline = Instant::now() + Duration::from_secs(15);
    let path = selected_directory(root, relative)?;
    verify(&path, deadline)?;
    let index = crate::immutable_index::open(&path).map_err(|_| integrity())?;
    if index.schema() != schema() {
        return Err(integrity());
    }
    let reader = index.reader().map_err(|_| unavailable())?;
    let searcher = reader.searcher();
    let index_schema = index.schema();
    let text_field = index_schema.get_field(TECHNICAL).map_err(|_| integrity())?;
    let number_field = index_schema.get_field(NUMBER).map_err(|_| integrity())?;
    let mut position = 0usize;
    let mut bytes = 0usize;
    let mut output = Vec::new();
    for (segment_id, segment) in searcher.segment_readers().iter().enumerate() {
        for document in segment.doc_ids_alive() {
            check_deadline(deadline)?;
            if position < after {
                position += 1;
                continue;
            }
            if output.len() == limit {
                return Ok((output, Some(position)));
            }
            let stored: TantivyDocument = searcher
                .doc(tantivy::DocAddress::new(segment_id as u32, document))
                .map_err(|_| integrity())?;
            let text = stored
                .get_first(text_field)
                .and_then(|v| v.as_str())
                .ok_or_else(integrity)?;
            let number = stored
                .get_first(number_field)
                .and_then(|v| v.as_u64())
                .and_then(|v| u32::try_from(v).ok())
                .filter(|v| (1..=999999).contains(v))
                .ok_or_else(integrity)?;
            if text.len() > MAX_TEXT {
                return Err(Error::capacity("RFC index export text exceeds bound."));
            }
            if !output.is_empty() && bytes.saturating_add(text.len()) > 32 * 1024 * 1024 {
                return Ok((output, Some(position)));
            }
            bytes += text.len();
            output.push(IndexDocument {
                number,
                text: text.to_owned(),
            });
            position += 1;
        }
    }
    if after > position {
        return Err(Error::invalid(
            "RFC export cursor exceeds retained membership.",
        ));
    }
    Ok((output, None))
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
        qualify_legacy_file(root.path(), &manifest_path);
        for name in manifest["files"].as_object().unwrap().keys() {
            qualify_legacy_file(root.path(), &directory.join(name));
        }
        assert_eq!(
            search(root.path(), &relative, "transport", TECHNICAL, 0, 20, None).unwrap()["total"],
            1
        );
        let descriptor =
            crate::integrity::evidence_path(root.path(), &directory.join("meta.json")).unwrap();
        let mut evidence: Value = serde_json::from_slice(&fs::read(&descriptor).unwrap()).unwrap();
        evidence["digest"] = json!(crate::integrity::hash(b"wrong retained bytes"));
        fs::write(descriptor, serde_json::to_vec(&evidence).unwrap()).unwrap();
        assert!(search(root.path(), &relative, "transport", TECHNICAL, 0, 20, None).is_err());
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
