//! Disposable, proof-checked spill storage for offline migration working sets.
//!
//! This file is never a source of permanent evidence. Every process reconstructs
//! it from the already verified retained corpus; only its writes use None durability.
use super::{MigrationMap, capacity, unavailable};
use devres_domain::{Error, Result};
use redb::{
    Database, Durability, ReadableDatabase, ReadableTable, TableDefinition, backends::FileBackend,
};
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    fs::OpenOptions,
    ops::Bound,
    os::unix::fs::OpenOptionsExt,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
};

pub(super) const CACHE_BYTES: usize = 8 * 1024 * 1024;
pub(super) const PAGE_BYTES: usize = 8 * 1024 * 1024;
pub(super) const PAGE_ROWS: usize = 128;
pub(super) const BASE_BYTES: usize = 64 * 1024;
pub(super) const SINGLE_RECORD_BYTES: usize = 64 * 1024 * 1024 - CACHE_BYTES - BASE_BYTES;
const MAP: TableDefinition<&str, &[u8]> = TableDefinition::new("mappings");
const SECONDARY: TableDefinition<&str, &[u8]> = TableDefinition::new("legacy_state_keys");
const ALIASES: TableDefinition<(u64, u64), &[u8]> = TableDefinition::new("aliases");
const MAP_DOMAIN: &[u8] = b"devres-migration-scratch-map-v1";
const STATE_DOMAIN: &[u8] = b"devres-migration-scratch-state-v1";
const ALIAS_DOMAIN: &[u8] = b"devres-migration-scratch-alias-v1";

pub type Alias = (String, String, String);

// Fields are dropped in declaration order: close the database before removing
// its private directory. Alias handles and read iterators hold this same Arc.
pub(super) struct Workspace {
    pub(super) db: Database,
    _directory: tempfile::TempDir,
    resident: AtomicUsize,
    resident_rows: AtomicUsize,
    failed: AtomicBool,
    groups: AtomicU64,
}
impl std::fmt::Debug for Workspace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MigrationWorkspace")
            .field("healthy", &!self.failed.load(Ordering::Acquire))
            .finish()
    }
}

fn proof(domain: &[u8], key: &[u8], value: &[u8]) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(&(domain.len() as u64).to_le_bytes());
    hash.update(domain);
    hash.update(&(key.len() as u64).to_le_bytes());
    hash.update(key);
    hash.update(&(value.len() as u64).to_le_bytes());
    hash.update(value);
    *hash.finalize().as_bytes()
}
fn encode(domain: &[u8], key: &[u8], value: &[u8]) -> Result<Vec<u8>> {
    if key
        .len()
        .checked_add(value.len())
        .and_then(|n| n.checked_add(512))
        .is_none_or(|n| n > SINGLE_RECORD_BYTES)
    {
        return Err(capacity());
    }
    let mut bytes = Vec::with_capacity(32 + value.len());
    bytes.extend_from_slice(&proof(domain, key, value));
    bytes.extend_from_slice(value);
    Ok(bytes)
}
fn decode<'a>(domain: &[u8], key: &[u8], bytes: &'a [u8]) -> Result<&'a [u8]> {
    if bytes.len() < 32 || bytes.len() > SINGLE_RECORD_BYTES || key.len() > SINGLE_RECORD_BYTES {
        return Err(Error::integrity("Invalid migration scratch record."));
    }
    let value = &bytes[32..];
    if bytes[..32] != proof(domain, key, value) {
        return Err(Error::integrity("Migration scratch proof failed."));
    }
    Ok(value)
}
fn text(bytes: &[u8]) -> Result<String> {
    String::from_utf8(bytes.to_vec())
        .map_err(|_| Error::integrity("Invalid migration scratch text."))
}
fn field_record(domain: &[u8], key: &[u8], fields: &[&str]) -> Result<Vec<u8>> {
    let header = fields.len().checked_mul(8).ok_or_else(capacity)?;
    let length = fields
        .iter()
        .try_fold(header, |total, field| total.checked_add(field.len()))
        .ok_or_else(capacity)?;
    if key
        .len()
        .checked_add(length)
        .and_then(|n| n.checked_add(512))
        .is_none_or(|n| n > SINGLE_RECORD_BYTES)
    {
        return Err(capacity());
    }
    let mut bytes = Vec::with_capacity(32 + length);
    bytes.resize(32, 0);
    for field in fields {
        bytes.extend_from_slice(&(field.len() as u64).to_le_bytes());
    }
    for field in fields {
        bytes.extend_from_slice(field.as_bytes());
    }
    let digest = proof(domain, key, &bytes[32..]);
    bytes[..32].copy_from_slice(&digest);
    Ok(bytes)
}
fn fields<const N: usize>(bytes: &[u8]) -> Result<[String; N]> {
    let header = N.checked_mul(8).ok_or_else(capacity)?;
    if bytes.len() < header {
        return Err(Error::integrity("Invalid migration scratch fields."));
    }
    let mut lengths = [0_usize; N];
    let mut total = header;
    for (index, length) in lengths.iter_mut().enumerate() {
        let raw: [u8; 8] = bytes[index * 8..index * 8 + 8]
            .try_into()
            .map_err(|_| unavailable())?;
        *length = usize::try_from(u64::from_le_bytes(raw)).map_err(|_| capacity())?;
        total = total.checked_add(*length).ok_or_else(capacity)?;
    }
    if total != bytes.len() {
        return Err(Error::integrity("Invalid migration scratch field lengths."));
    }
    let mut position = header;
    let mut values = Vec::with_capacity(N);
    for length in lengths {
        let end = position.checked_add(length).ok_or_else(capacity)?;
        values.push(text(&bytes[position..end])?);
        position = end;
    }
    values.try_into().map_err(|_| unavailable())
}
fn index_namespace(namespace: &str) -> bool {
    namespace.split_once(':').is_some_and(|(provider, kind)| {
        matches!(provider, "mdn" | "whatwg" | "w3c" | "chromium")
            && matches!(kind, "snapshots" | "views" | "snapshot-keys")
    })
}
fn legacy_index(key: &str) -> Option<(String, &str)> {
    for provider in ["mdn", "whatwg", "w3c", "chromium"] {
        for kind in ["snapshots", "views", "snapshot-keys"] {
            let namespace = format!("{provider}:{kind}");
            if let Some(old) = key.strip_prefix(&format!("{namespace}:")) {
                return Some((namespace, old));
            }
        }
    }
    None
}
fn hash_legacy(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}
fn secondary_key(namespace: &str, hash: &str) -> String {
    format!("{namespace}:{hash}")
}
fn alias_key(group: u64, ordinal: u64) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[..8].copy_from_slice(&group.to_le_bytes());
    bytes[8..].copy_from_slice(&ordinal.to_le_bytes());
    bytes
}

impl Workspace {
    pub(super) fn create(root: &Path) -> Result<Self> {
        let root = root.canonicalize().map_err(|_| unavailable())?;
        if !root.starts_with("/tmp") {
            return Err(Error::invalid("Migration scratch must be below /tmp."));
        }
        let directory = tempfile::Builder::new()
            .prefix("devres-migration-spill-")
            .tempdir_in(root)
            .map_err(|_| unavailable())?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.path().join("working.redb"))
            .map_err(|_| unavailable())?;
        let backend = FileBackend::new(file).map_err(|_| unavailable())?;
        let mut builder = Database::builder();
        builder.set_cache_size(CACHE_BYTES);
        let db = builder
            .create_with_backend(backend)
            .map_err(|_| unavailable())?;
        let mut tx = db.begin_write().map_err(|_| unavailable())?;
        tx.set_durability(Durability::None)
            .map_err(|_| unavailable())?;
        {
            tx.open_table(MAP).map_err(|_| unavailable())?;
        }
        {
            tx.open_table(SECONDARY).map_err(|_| unavailable())?;
        }
        {
            tx.open_table(ALIASES).map_err(|_| unavailable())?;
        }
        tx.commit().map_err(|_| unavailable())?;
        Ok(Self {
            db,
            _directory: directory,
            resident: AtomicUsize::new(CACHE_BYTES + BASE_BYTES),
            resident_rows: AtomicUsize::new(0),
            failed: AtomicBool::new(false),
            groups: AtomicU64::new(1),
        })
    }
    pub(super) fn resident_bytes(&self) -> usize {
        self.resident.load(Ordering::Acquire)
    }
    fn reserve(&self, bytes: usize) -> Result<()> {
        self.resident
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current
                    .checked_add(bytes)
                    .filter(|next| *next <= super::MAX_BYTES)
            })
            .map(|_| ())
            .map_err(|_| capacity())
    }
    fn release(&self, bytes: usize) {
        self.resident.fetch_sub(bytes, Ordering::AcqRel);
    }
    fn reserve_rows(&self, rows: usize) -> Result<()> {
        self.resident_rows
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(rows).filter(|next| {
                    next.checked_add(CACHE_BYTES / 32)
                        .is_some_and(|total| total <= super::MAX_ENTRIES)
                })
            })
            .map(|_| ())
            .map_err(|_| capacity())
    }
    fn release_rows(&self, rows: usize) {
        self.resident_rows.fetch_sub(rows, Ordering::AcqRel);
    }
    pub(super) fn ensure_healthy(&self) -> Result<()> {
        if self.failed.load(Ordering::Acquire) {
            Err(unavailable())
        } else {
            Ok(())
        }
    }
    pub(super) fn latch(&self) {
        self.failed.store(true, Ordering::Release);
    }
    fn checked<T>(&self, operation: impl FnOnce() -> Result<T>) -> Result<T> {
        self.ensure_healthy()?;
        let result = operation();
        if result.is_err() {
            self.latch();
        }
        result
    }
    pub(super) fn get(&self, key: &str) -> Result<Option<String>> {
        self.checked(|| {
            let tx = self.db.begin_read().map_err(|_| unavailable())?;
            let table = tx.open_table(MAP).map_err(|_| unavailable())?;
            table
                .get(key)
                .map_err(|_| unavailable())?
                .map(|value| text(decode(MAP_DOMAIN, key.as_bytes(), value.value())?))
                .transpose()
        })
    }
    pub(super) fn put(&self, key: &str, value: &str) -> Result<bool> {
        self.checked(|| {
            let encoded = encode(MAP_DOMAIN, key.as_bytes(), value.as_bytes())?;
            let mut tx = self.db.begin_write().map_err(|_| unavailable())?;
            tx.set_durability(Durability::None)
                .map_err(|_| unavailable())?;
            let result = (|| {
                let existed = {
                    let mut table = tx.open_table(MAP).map_err(|_| unavailable())?;
                    if let Some(prior) = table.get(key).map_err(|_| unavailable())? {
                        decode(MAP_DOMAIN, key.as_bytes(), prior.value())?;
                    }
                    table
                        .insert(key, encoded.as_slice())
                        .map_err(|_| unavailable())?
                        .is_some()
                };
                if let Some((namespace, old)) = legacy_index(key) {
                    let index = secondary_key(&namespace, &hash_legacy(old));
                    let mut table = tx.open_table(SECONDARY).map_err(|_| unavailable())?;
                    if let Some(prior) = table.get(index.as_str()).map_err(|_| unavailable())? {
                        let prior =
                            fields::<2>(decode(STATE_DOMAIN, index.as_bytes(), prior.value())?)?;
                        if prior[0] != old {
                            return Err(Error::integrity("Ambiguous legacy migration state key."));
                        }
                    }
                    if value.starts_with("blake3:") && crate::integrity::valid_hash(value) {
                        let record = field_record(STATE_DOMAIN, index.as_bytes(), &[old, value])?;
                        table
                            .insert(index.as_str(), record.as_slice())
                            .map_err(|_| unavailable())?;
                    } else {
                        table.remove(index.as_str()).map_err(|_| unavailable())?;
                    }
                }
                Ok(existed)
            })();
            match result {
                Ok(existed) => {
                    tx.commit().map_err(|_| unavailable())?;
                    Ok(existed)
                }
                Err(error) => {
                    tx.abort().map_err(|_| unavailable())?;
                    Err(error)
                }
            }
        })
    }
    pub(super) fn lookup_legacy_key_hash(
        &self,
        namespace: &str,
        hash: &str,
    ) -> Result<Option<String>> {
        self.checked(|| {
            let index = secondary_key(namespace, hash);
            if !index_namespace(namespace)
                || hash.len() != 64
                || !hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            {
                return Ok(None);
            }
            let tx = self.db.begin_read().map_err(|_| unavailable())?;
            let table = tx.open_table(SECONDARY).map_err(|_| unavailable())?;
            let Some(record) = table.get(index.as_str()).map_err(|_| unavailable())? else {
                return Ok(None);
            };
            let [old, canonical] =
                fields::<2>(decode(STATE_DOMAIN, index.as_bytes(), record.value())?)?;
            if hash_legacy(&old) != hash
                || !canonical.starts_with("blake3:")
                || !crate::integrity::valid_hash(&canonical)
            {
                return Err(Error::integrity("Legacy migration scratch index changed."));
            }
            let full_key = format!("{namespace}:{old}");
            let map = tx.open_table(MAP).map_err(|_| unavailable())?;
            let primary = map
                .get(full_key.as_str())
                .map_err(|_| unavailable())?
                .ok_or_else(|| Error::integrity("Legacy migration scratch mapping missing."))?;
            if decode(MAP_DOMAIN, full_key.as_bytes(), primary.value())? != canonical.as_bytes() {
                return Err(Error::integrity(
                    "Legacy migration scratch mapping changed.",
                ));
            }
            Ok(Some(canonical))
        })
    }
    pub(super) fn page(&self, after: Option<&str>) -> Result<VecDeque<(String, String)>> {
        self.checked(|| {
            let tx = self.db.begin_read().map_err(|_| unavailable())?;
            let table = tx.open_table(MAP).map_err(|_| unavailable())?;
            let lower = after.map_or(Bound::Unbounded, Bound::Excluded);
            let mut page = VecDeque::new();
            let mut bytes = 0_usize;
            for item in table
                .range::<&str>((lower, Bound::Unbounded))
                .map_err(|_| unavailable())?
            {
                let (key, record) = item.map_err(|_| unavailable())?;
                let value = decode(MAP_DOMAIN, key.value().as_bytes(), record.value())?;
                let size = key
                    .value()
                    .len()
                    .checked_add(value.len())
                    .and_then(|n| n.checked_add(128))
                    .ok_or_else(capacity)?;
                if !page.is_empty()
                    && (page.len() >= PAGE_ROWS
                        || bytes.checked_add(size).is_none_or(|n| n > PAGE_BYTES))
                {
                    break;
                }
                // A single already-admitted opaque representation is yielded
                // alone, retaining the prior large-record admission behavior.
                page.push_back((key.value().to_owned(), text(value)?));
                bytes = bytes.checked_add(size).ok_or_else(capacity)?;
                if page.len() == PAGE_ROWS || bytes >= PAGE_BYTES {
                    break;
                }
            }
            Ok(page)
        })
    }
    fn group(&self) -> Result<u64> {
        self.ensure_healthy()?;
        self.groups
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
            .map_err(|_| capacity())
    }
    fn push_aliases(&self, group: u64, ordinal: u64, aliases: &[Alias]) -> Result<u64> {
        self.checked(|| {
            if aliases.len() > MigrationAliases::BATCH_ROWS {
                return Err(capacity());
            }
            let next = ordinal
                .checked_add(u64::try_from(aliases.len()).map_err(|_| capacity())?)
                .ok_or_else(capacity)?;
            let mut bytes = 0_usize;
            for alias in aliases {
                let strings = alias
                    .0
                    .len()
                    .checked_add(alias.1.len())
                    .and_then(|n| n.checked_add(alias.2.len()))
                    .ok_or_else(capacity)?;
                // Match field_record's key + field lengths + admission overhead.
                if strings
                    .checked_add(16 + 24 + 512)
                    .is_none_or(|n| n > SINGLE_RECORD_BYTES)
                {
                    return Err(capacity());
                }
                let size = strings.checked_add(72).ok_or_else(capacity)?;
                bytes = bytes.checked_add(size).ok_or_else(capacity)?;
            }
            if aliases.len() > 1 && bytes > MigrationAliases::BATCH_BYTES {
                return Err(capacity());
            }
            if aliases.is_empty() {
                return Ok(next);
            }
            let mut tx = self.db.begin_write().map_err(|_| unavailable())?;
            tx.set_durability(Durability::None)
                .map_err(|_| unavailable())?;
            let result = (|| {
                let mut table = tx.open_table(ALIASES).map_err(|_| unavailable())?;
                for (offset, alias) in aliases.iter().enumerate() {
                    let ordinal = ordinal + offset as u64;
                    let encoded = field_record(
                        ALIAS_DOMAIN,
                        &alias_key(group, ordinal),
                        &[&alias.0, &alias.1, &alias.2],
                    )?;
                    if table
                        .insert((group, ordinal), encoded.as_slice())
                        .map_err(|_| unavailable())?
                        .is_some()
                    {
                        return Err(Error::integrity(
                            "Duplicate migration scratch alias ordinal.",
                        ));
                    }
                }
                Ok(())
            })();
            match result {
                Ok(()) => {
                    tx.commit().map_err(|_| unavailable())?;
                    Ok(next)
                }
                Err(error) => {
                    tx.abort().map_err(|_| unavailable())?;
                    Err(error)
                }
            }
        })
    }
    fn alias_page(&self, group: u64, start: u64, end: u64, count: usize) -> Result<Vec<Alias>> {
        self.checked(|| {
            let tx = self.db.begin_read().map_err(|_| unavailable())?;
            let table = tx.open_table(ALIASES).map_err(|_| unavailable())?;
            let mut page = Vec::new();
            let mut bytes = 0_usize;
            let mut expected = start;
            for row in table
                .range((group, start)..(group, end))
                .map_err(|_| unavailable())?
            {
                let (key, record) = row.map_err(|_| unavailable())?;
                if key.value() != (group, expected) {
                    return Err(Error::integrity(
                        "Migration scratch alias membership changed.",
                    ));
                }
                let value = decode(ALIAS_DOMAIN, &alias_key(group, expected), record.value())?;
                let [kind, old, canonical] = fields::<3>(value)?;
                let alias = (kind, old, canonical);
                let size = alias
                    .0
                    .capacity()
                    .checked_add(alias.1.capacity())
                    .and_then(|n| n.checked_add(alias.2.capacity()))
                    .and_then(|n| n.checked_add(224))
                    .ok_or_else(capacity)?;
                if size > SINGLE_RECORD_BYTES {
                    return Err(capacity());
                }
                if !page.is_empty()
                    && (page.len() >= count
                        || bytes.checked_add(size).is_none_or(|n| n > PAGE_BYTES))
                {
                    break;
                }
                page.push(alias);
                bytes += size;
                expected = expected.checked_add(1).ok_or_else(capacity)?;
                if page.len() >= count || bytes >= PAGE_BYTES {
                    break;
                }
            }
            if page.is_empty() && start < end {
                return Err(Error::integrity("Migration scratch alias missing."));
            }
            Ok(page)
        })
    }
    #[cfg(test)]
    pub(super) fn path(&self) -> std::path::PathBuf {
        self._directory.path().to_owned()
    }
}

/// A provider's derived alias stream shares its migration workspace cache.
pub struct MigrationAliases {
    workspace: Arc<Workspace>,
    group: u64,
    length: u64,
}
impl std::fmt::Debug for MigrationAliases {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MigrationAliases")
            .field("len", &self.length)
            .finish()
    }
}
impl MigrationAliases {
    pub(crate) const BATCH_ROWS: usize = 32;
    pub(crate) const BATCH_BYTES: usize = 256 * 1024;
    pub fn new(map: &mut MigrationMap) -> Result<Self> {
        map.ensure_exclusive()?;
        let workspace = map.workspace()?;
        let group = workspace.group()?;
        Ok(Self {
            workspace,
            group,
            length: 0,
        })
    }
    pub fn push(&mut self, alias: Alias) -> Result<()> {
        self.extend(std::slice::from_ref(&alias))
    }
    /// Append one bounded batch atomically; a large admitted record stands alone.
    pub fn extend(&mut self, aliases: &[Alias]) -> Result<()> {
        self.length = self
            .workspace
            .push_aliases(self.group, self.length, aliases)?;
        Ok(())
    }
    pub fn len(&self) -> usize {
        usize::try_from(self.length).unwrap_or(usize::MAX)
    }
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }
    pub fn ensure_healthy(&self) -> Result<()> {
        self.workspace.ensure_healthy()
    }
    pub fn try_chunks(&self, count: usize) -> impl Iterator<Item = Result<Vec<Alias>>> + '_ {
        AliasChunks {
            workspace: Arc::clone(&self.workspace),
            group: self.group,
            next: 0,
            end: self.length,
            count,
            done: false,
        }
    }
}
struct AliasChunks {
    workspace: Arc<Workspace>,
    group: u64,
    next: u64,
    end: u64,
    count: usize,
    done: bool,
}
impl Iterator for AliasChunks {
    type Item = Result<Vec<Alias>>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        if self.count == 0 || self.count > PAGE_ROWS {
            self.done = true;
            return Some(Err(Error::invalid("Invalid migration alias chunk size.")));
        }
        if let Err(error) = self.workspace.ensure_healthy() {
            self.done = true;
            return Some(Err(error));
        }
        if self.next == self.end {
            self.done = true;
            return None;
        }
        match self
            .workspace
            .alias_page(self.group, self.next, self.end, self.count)
        {
            Ok(page) => {
                self.next += page.len() as u64;
                Some(Ok(page))
            }
            Err(error) => {
                self.done = true;
                Some(Err(error))
            }
        }
    }
}

pub(super) struct MapIter {
    pub(super) workspace: Option<Arc<Workspace>>,
    pub(super) page: VecDeque<(String, String)>,
    pub(super) after: Option<String>,
    pub(super) done: bool,
    pub(super) charged: usize,
    pub(super) charged_rows: usize,
}
impl MapIter {
    fn account(&mut self) -> Result<()> {
        let Some(workspace) = &self.workspace else {
            return Ok(());
        };
        let mut bytes = self
            .page
            .capacity()
            .checked_mul(std::mem::size_of::<(String, String)>())
            .ok_or_else(capacity)?;
        for (key, value) in &self.page {
            bytes = bytes
                .checked_add(key.capacity())
                .and_then(|n| n.checked_add(value.capacity()))
                .ok_or_else(capacity)?;
        }
        bytes = bytes
            .checked_add(self.after.as_ref().map_or(0, String::capacity))
            .ok_or_else(capacity)?;
        let extra_bytes = bytes.saturating_sub(self.charged);
        let rows = self.page.len();
        workspace.reserve(extra_bytes)?;
        if let Err(error) = workspace.reserve_rows(rows.saturating_sub(self.charged_rows)) {
            workspace.release(extra_bytes);
            return Err(error);
        }
        workspace.release(self.charged.saturating_sub(bytes));
        workspace.release_rows(self.charged_rows.saturating_sub(rows));
        self.charged = bytes;
        self.charged_rows = rows;
        Ok(())
    }
    fn fail(&mut self) {
        if let Some(workspace) = &self.workspace {
            workspace.latch();
        }
        self.done = true;
        self.page = VecDeque::new();
        self.after = None;
        if let Some(workspace) = &self.workspace {
            workspace.release(self.charged);
            workspace.release_rows(self.charged_rows);
        }
        self.charged = 0;
        self.charged_rows = 0;
    }
}
impl Drop for MapIter {
    fn drop(&mut self) {
        if let Some(workspace) = &self.workspace {
            workspace.release(self.charged);
            workspace.release_rows(self.charged_rows);
        }
    }
}
impl Iterator for MapIter {
    type Item = (String, String);
    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let workspace = Arc::clone(self.workspace.as_ref()?);
        if self.page.is_empty() {
            match workspace.page(self.after.as_deref()) {
                Ok(page) => {
                    self.page = page;
                    self.after = None;
                }
                Err(_) => {
                    self.fail();
                    return None;
                }
            }
            if self.account().is_err() {
                self.fail();
                return None;
            }
        }
        let item = self.page.pop_front();
        if let Some((key, _)) = &item {
            self.after = Some(key.clone());
        } else {
            self.done = true;
        }
        if self.account().is_err() {
            self.fail();
            return None;
        }
        item
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use redb::{BackendError, StorageBackend};

    #[test]
    fn scratch_tuple_codec_retains_escaped_opaque_fields_and_rejects_lengths() {
        let values = ["\u{0000}\n\"\\opaque", "a:b:blake3:old", "canonical"];
        let encoded = field_record(ALIAS_DOMAIN, b"key", &values).unwrap();
        let decoded = decode(ALIAS_DOMAIN, b"key", &encoded).unwrap();
        assert_eq!(fields::<3>(decoded).unwrap(), values.map(str::to_owned));
        let mut invalid = decoded.to_vec();
        invalid[..8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(fields::<3>(&invalid).is_err());
    }

    #[test]
    fn large_opaque_alias_is_yielded_alone_without_json_expansion() {
        let mut map = MigrationMap::new();
        let mut aliases = MigrationAliases::new(&mut map).unwrap();
        let large = "\u{0000}\"\\".repeat(3 * 1024 * 1024);
        aliases
            .push(("opaque".to_owned(), large.clone(), "canonical".to_owned()))
            .unwrap();
        aliases
            .push((
                "opaque".to_owned(),
                "small".to_owned(),
                "canonical".to_owned(),
            ))
            .unwrap();
        let mut pages = aliases.try_chunks(PAGE_ROWS);
        let first = pages.next().unwrap().unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].1, large);
        assert_eq!(pages.next().unwrap().unwrap()[0].1, "small");
        assert!(pages.next().is_none());
        aliases.ensure_healthy().unwrap();
    }

    #[test]
    fn bounded_alias_batches_preserve_order_proofs_and_singleton_equivalence() {
        let mut map = MigrationMap::new();
        let mut aliases = MigrationAliases::new(&mut map).unwrap();
        let expected: Vec<_> = (0..67)
            .map(|n| ("opaque".into(), format!("old:{n}:\n\""), format!("new:{n}")))
            .collect();
        aliases.extend(&expected[..32]).unwrap();
        aliases.extend(&[]).unwrap();
        aliases.push(expected[32].clone()).unwrap();
        aliases.extend(&expected[33..65]).unwrap();
        aliases.extend(&expected[65..]).unwrap();
        assert_eq!(aliases.len(), expected.len());
        let actual: Vec<_> = aliases
            .try_chunks(7)
            .collect::<Result<Vec<_>>>()
            .unwrap()
            .into_iter()
            .flatten()
            .collect();
        assert_eq!(actual, expected);
    }

    #[test]
    fn rejected_alias_batch_latches_without_advancing_ordinal() {
        for batch in [
            vec![(String::new(), "old".into(), "new".into()); MigrationAliases::BATCH_ROWS + 1],
            vec![
                (
                    String::new(),
                    "x".repeat(MigrationAliases::BATCH_BYTES / 2),
                    "new".into()
                );
                2
            ],
        ] {
            let mut map = MigrationMap::new();
            let mut aliases = MigrationAliases::new(&mut map).unwrap();
            aliases
                .push((String::new(), "prior".into(), "target".into()))
                .unwrap();
            assert_eq!(aliases.extend(&batch).unwrap_err().code, "capacity");
            assert_eq!(aliases.len(), 1);
            assert!(aliases.ensure_healthy().is_err());
            let tx = aliases.workspace.db.begin_read().unwrap();
            assert!(
                tx.open_table(ALIASES)
                    .unwrap()
                    .get((aliases.group, 1))
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[test]
    fn alias_batch_rollback_removes_earlier_inserts_after_later_collision() {
        let mut map = MigrationMap::new();
        let mut aliases = MigrationAliases::new(&mut map).unwrap();
        aliases
            .push((String::new(), "prior".into(), "target".into()))
            .unwrap();
        let encoded = field_record(
            ALIAS_DOMAIN,
            &alias_key(aliases.group, 2),
            &["", "collision", "target"],
        )
        .unwrap();
        let mut tx = aliases.workspace.db.begin_write().unwrap();
        tx.set_durability(Durability::None).unwrap();
        tx.open_table(ALIASES)
            .unwrap()
            .insert((aliases.group, 2), encoded.as_slice())
            .unwrap();
        tx.commit().unwrap();
        let batch = [
            (String::new(), "first".into(), "target".into()),
            (String::new(), "second".into(), "target".into()),
        ];
        assert_eq!(aliases.extend(&batch).unwrap_err().code, "integrity");
        assert_eq!(aliases.len(), 1);
        assert!(aliases.ensure_healthy().is_err());
        let tx = aliases.workspace.db.begin_read().unwrap();
        let table = tx.open_table(ALIASES).unwrap();
        assert!(table.get((aliases.group, 1)).unwrap().is_none());
        assert_eq!(
            table.get((aliases.group, 2)).unwrap().unwrap().value(),
            encoded
        );
    }

    #[test]
    fn iterator_pages_share_one_resident_row_admission_budget() {
        let workspace = Workspace::create(Path::new("/tmp")).unwrap();
        let available = super::super::MAX_ENTRIES - CACHE_BYTES / 32;
        workspace.reserve_rows(available - PAGE_ROWS).unwrap();
        workspace.reserve_rows(PAGE_ROWS).unwrap();
        assert!(workspace.reserve_rows(1).is_err());
        workspace.release_rows(PAGE_ROWS);
        workspace.reserve_rows(PAGE_ROWS).unwrap();
        workspace.release_rows(available);
        assert_eq!(workspace.resident_rows.load(Ordering::Acquire), 0);
    }

    #[derive(Debug)]
    struct FaultBackend {
        file: FileBackend,
        fail_read: Arc<AtomicBool>,
        fail_write: Arc<AtomicBool>,
    }
    impl StorageBackend for FaultBackend {
        fn len(&self) -> std::io::Result<u64> {
            self.file.len()
        }
        fn read(&self, offset: u64, out: &mut [u8]) -> std::io::Result<()> {
            if self.fail_read.load(Ordering::Acquire) {
                return Err(std::io::Error::from_raw_os_error(nix::libc::EIO));
            }
            self.file.read(offset, out)
        }
        fn set_len(&self, len: u64) -> std::io::Result<()> {
            if self.fail_write.load(Ordering::Acquire) {
                return Err(std::io::Error::from_raw_os_error(nix::libc::ENOSPC));
            }
            self.file.set_len(len)
        }
        fn sync_data(&self) -> std::io::Result<()> {
            if self.fail_write.load(Ordering::Acquire) {
                return Err(std::io::Error::from_raw_os_error(nix::libc::ENOSPC));
            }
            self.file.sync_data()
        }
        fn write(&self, offset: u64, data: &[u8]) -> std::io::Result<()> {
            if self.fail_write.load(Ordering::Acquire) {
                return Err(std::io::Error::from_raw_os_error(nix::libc::ENOSPC));
            }
            self.file.write(offset, data)
        }
        fn close(&self) -> std::io::Result<()> {
            self.file.close()
        }
        fn try_lock_range(
            &self,
            start: Bound<u64>,
            end: Bound<u64>,
        ) -> std::result::Result<bool, BackendError> {
            self.file.try_lock_range(start, end)
        }
        fn try_lock_shared_range(
            &self,
            start: Bound<u64>,
            end: Bound<u64>,
        ) -> std::result::Result<bool, BackendError> {
            self.file.try_lock_shared_range(start, end)
        }
        fn lock_range(
            &self,
            start: Bound<u64>,
            end: Bound<u64>,
        ) -> std::result::Result<(), BackendError> {
            self.file.lock_range(start, end)
        }
        fn lock_shared_range(
            &self,
            start: Bound<u64>,
            end: Bound<u64>,
        ) -> std::result::Result<(), BackendError> {
            self.file.lock_shared_range(start, end)
        }
        fn unlock_range(
            &self,
            start: Bound<u64>,
            end: Bound<u64>,
        ) -> std::result::Result<(), BackendError> {
            self.file.unlock_range(start, end)
        }
        fn query_lock_range(
            &self,
            start: Bound<u64>,
            end: Bound<u64>,
        ) -> std::result::Result<bool, BackendError> {
            self.file.query_lock_range(start, end)
        }
    }
    fn fault_workspace() -> (Workspace, Arc<AtomicBool>, Arc<AtomicBool>) {
        let directory = tempfile::Builder::new()
            .prefix("devres-spill-fault-")
            .tempdir_in("/tmp")
            .unwrap();
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(directory.path().join("working.redb"))
            .unwrap();
        let reads = Arc::new(AtomicBool::new(false));
        let writes = Arc::new(AtomicBool::new(false));
        let backend = FaultBackend {
            file: FileBackend::new(file).unwrap(),
            fail_read: reads.clone(),
            fail_write: writes.clone(),
        };
        let mut builder = Database::builder();
        builder.set_cache_size(CACHE_BYTES);
        let db = builder.create_with_backend(backend).unwrap();
        let mut tx = db.begin_write().unwrap();
        tx.set_durability(Durability::None).unwrap();
        {
            tx.open_table(MAP).unwrap();
            tx.open_table(SECONDARY).unwrap();
            tx.open_table(ALIASES).unwrap();
        }
        tx.commit().unwrap();
        (
            Workspace {
                db,
                _directory: directory,
                resident: AtomicUsize::new(CACHE_BYTES + BASE_BYTES),
                resident_rows: AtomicUsize::new(0),
                failed: AtomicBool::new(false),
                groups: AtomicU64::new(1),
            },
            reads,
            writes,
        )
    }
    #[test]
    fn scratch_disk_exhaustion_latches_without_claiming_persistent_progress() {
        let (workspace, _reads, writes) = fault_workspace();
        let directory = workspace.path();
        writes.store(true, Ordering::Release);
        let value = "public-derived-cache".repeat(16 * 1024);
        let mut failed = false;
        for index in 0..80 {
            if workspace.put(&format!("opaque-{index}"), &value).is_err() {
                failed = true;
                break;
            }
        }
        assert!(
            failed,
            "bounded cache must spill dirty pages and surface ENOSPC"
        );
        assert!(workspace.ensure_healthy().is_err());
        assert!(workspace.get("opaque-0").is_err());
        writes.store(false, Ordering::Release);
        drop(workspace);
        assert!(!directory.exists());
    }
    #[test]
    fn uncached_scratch_read_errors_are_latched_before_alias_publication() {
        let (workspace, reads, writes) = fault_workspace();
        // Close the populated database and construct a new page cache. Dirty
        // page eviction is not a guarantee that a particular old page leaves
        // redb's cache, so write volume alone cannot arrange this fault.
        let value = "public-derived-cache".repeat(512 * 1024);
        workspace.put("opaque-0000", &value).unwrap();
        let Workspace { db, _directory, .. } = workspace;
        drop(db);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(_directory.path().join("working.redb"))
            .unwrap();
        let backend = FaultBackend {
            file: FileBackend::new(file).unwrap(),
            fail_read: reads.clone(),
            fail_write: writes,
        };
        let mut builder = Database::builder();
        builder.set_cache_size(CACHE_BYTES);
        let workspace = Workspace {
            db: builder.create_with_backend(backend).unwrap(),
            _directory,
            resident: AtomicUsize::new(CACHE_BYTES + BASE_BYTES),
            resident_rows: AtomicUsize::new(0),
            failed: AtomicBool::new(false),
            groups: AtomicU64::new(1),
        };
        reads.store(true, Ordering::Release);
        assert!(
            workspace.get("opaque-0000").is_err(),
            "reopened scratch has no cached value and must surface backend EIO"
        );
        assert!(workspace.ensure_healthy().is_err());
        assert!(workspace.alias_page(1, 0, 1, 1).is_err());
        reads.store(false, Ordering::Release);
    }
}
