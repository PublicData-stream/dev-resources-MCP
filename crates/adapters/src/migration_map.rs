//! Proof-checked, bounded-resident offline migration identity working sets.
use devres_domain::{Error, Result};
use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
#[path = "migration_aliases.rs"]
mod spill;
pub use spill::MigrationAliases;

const ACCOUNT: &str = "\0devres-migration-working-set-v1";
const MAX_BYTES: usize = 64 * 1024 * 1024;
const MAX_ENTRIES: usize = 1_000_000;

struct State {
    workspace: Mutex<Option<Arc<spill::Workspace>>>,
    root: PathBuf,
    entries: AtomicUsize,
    failed: AtomicBool,
}

/// Derived references spill below /tmp instead of imposing a total history cap.
/// Clones share immutable reads; mutations never duplicate a resident working set.
#[derive(Clone)]
pub struct MigrationMap {
    state: Arc<State>,
}
impl std::fmt::Debug for MigrationMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MigrationMap")
            .field("len", &self.len())
            .field("healthy", &self.ensure_healthy().is_ok())
            .finish()
    }
}
pub(super) fn capacity() -> Error {
    Error::capacity("Migration identity working-set budget exhausted; history is preserved.")
}
pub(super) fn unavailable() -> Error {
    Error::unavailable("Migration scratch storage unavailable; history is preserved.")
}
impl Default for MigrationMap {
    fn default() -> Self {
        Self::new()
    }
}
impl MigrationMap {
    pub fn new() -> Self {
        Self::in_directory(std::env::temp_dir())
    }
    fn in_directory(root: PathBuf) -> Self {
        Self {
            state: Arc::new(State {
                workspace: Mutex::new(None),
                root,
                entries: AtomicUsize::new(0),
                failed: AtomicBool::new(false),
            }),
        }
    }
    pub fn len(&self) -> usize {
        self.state.entries.load(Ordering::Acquire)
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Configured shared cache plus bounded iterator buffers; not process RSS or
    /// the size of the disposable on-disk history. Returned values are scratch.
    pub fn accounted_bytes(&self) -> usize {
        self.state
            .workspace
            .lock()
            .ok()
            .and_then(|guard| guard.as_ref().map(|workspace| workspace.resident_bytes()))
            .unwrap_or(spill::BASE_BYTES)
    }
    pub fn ensure_healthy(&self) -> Result<()> {
        if self.state.failed.load(Ordering::Acquire) {
            return Err(unavailable());
        }
        match self.state.workspace.lock() {
            Ok(guard) => match guard.as_ref() {
                Some(workspace) => workspace.ensure_healthy(),
                None => Ok(()),
            },
            Err(_) => {
                self.state.failed.store(true, Ordering::Release);
                Err(unavailable())
            }
        }
    }
    fn existing_workspace(&self) -> Result<Option<Arc<spill::Workspace>>> {
        self.ensure_healthy()?;
        self.state
            .workspace
            .lock()
            .map(|guard| guard.as_ref().map(Arc::clone))
            .map_err(|_| {
                self.state.failed.store(true, Ordering::Release);
                unavailable()
            })
    }
    fn workspace(&self) -> Result<Arc<spill::Workspace>> {
        self.ensure_healthy()?;
        let mut guard = self.state.workspace.lock().map_err(|_| unavailable())?;
        if let Some(workspace) = guard.as_ref() {
            return Ok(Arc::clone(workspace));
        }
        match spill::Workspace::create(&self.state.root) {
            Ok(workspace) => {
                let workspace = Arc::new(workspace);
                *guard = Some(Arc::clone(&workspace));
                Ok(workspace)
            }
            Err(error) => {
                self.state.failed.store(true, Ordering::Release);
                Err(error)
            }
        }
    }
    fn ensure_exclusive(&self) -> Result<()> {
        self.ensure_healthy()?;
        if Arc::strong_count(&self.state) != 1 {
            return Err(capacity());
        }
        Ok(())
    }
    pub fn get(&self, key: &str) -> Option<String> {
        match self.existing_workspace() {
            Ok(Some(workspace)) => workspace.get(key).ok().flatten(),
            Ok(None) => None,
            Err(_) => {
                self.state.failed.store(true, Ordering::Release);
                None
            }
        }
    }
    pub fn contains_key(&self, key: &str) -> bool {
        self.get(key).is_some()
    }
    pub fn lookup_legacy_key_hash(&self, namespace: &str, hash: &str) -> Option<String> {
        match self.existing_workspace() {
            Ok(Some(workspace)) => workspace
                .lookup_legacy_key_hash(namespace, hash)
                .ok()
                .flatten(),
            Ok(None) => None,
            Err(_) => {
                self.state.failed.store(true, Ordering::Release);
                None
            }
        }
    }
    pub fn iter(&self) -> impl Iterator<Item = (String, String)> + '_ {
        let workspace = match self.existing_workspace() {
            Ok(value) => value,
            Err(_) => {
                self.state.failed.store(true, Ordering::Release);
                None
            }
        };
        spill::MapIter {
            workspace,
            page: std::collections::VecDeque::new(),
            after: None,
            done: false,
            charged: 0,
            charged_rows: 0,
        }
    }
}

pub(crate) fn insert(map: &mut MigrationMap, key: String, value: String) -> Result<()> {
    map.ensure_exclusive()?;
    if key == ACCOUNT {
        return Err(Error::integrity("Reserved migration identity."));
    }
    let workspace = map.workspace()?;
    let existed = workspace.put(&key, &value)?;
    if !existed {
        map.state
            .entries
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
            .map_err(|_| capacity())?;
    }
    // Every cached record contains at least a 32-byte proof. Even a completely
    // occupied 8MiB cache plus a 128-record page is below one million residents.
    if map.accounted_bytes() > MAX_BYTES || spill::CACHE_BYTES / 32 + spill::PAGE_ROWS > MAX_ENTRIES
    {
        return Err(capacity());
    }
    Ok(())
}
/// Confirm the shared scratch remains healthy after a provider drops its alias handle.
pub(crate) fn reset_aliases(map: &mut MigrationMap) -> Result<()> {
    map.ensure_healthy()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;
    use std::collections::BTreeMap;
    fn id(n: u64) -> String {
        let mut value = [0_u8; 32];
        value[..8].copy_from_slice(&n.to_be_bytes());
        hex::encode(value)
    }
    fn canonical(n: u64) -> String {
        format!("blake3:{}", id(n))
    }

    #[test]
    fn spill_replacements_iteration_and_algorithms_preserve_exact_strings() {
        let mut map = MigrationMap::new();
        let mut expected = BTreeMap::new();
        for n in (0..300).rev() {
            for role in ["body", "capture", "mdn:projections"] {
                let key = format!("{role}:{}", id(n));
                let value = canonical(n + 1);
                insert(&mut map, key.clone(), value.clone()).unwrap();
                expected.insert(key, value);
            }
        }
        for n in (0..300).step_by(3) {
            let key = format!("body:{}", id(n));
            let value = format!("opaque/path/{n}");
            insert(&mut map, key.clone(), value.clone()).unwrap();
            expected.insert(key, value);
        }
        for n in (0..300).step_by(6) {
            let key = format!("body:{}", id(n));
            let value = canonical(n + 10);
            insert(&mut map, key.clone(), value.clone()).unwrap();
            expected.insert(key, value);
        }
        let tagged = format!("body:blake3:{}", id(1));
        insert(&mut map, tagged.clone(), canonical(4)).unwrap();
        expected.insert(tagged, canonical(4));
        assert_eq!(map.len(), expected.len());
        assert_eq!(map.iter().collect::<BTreeMap<_, _>>(), expected);
        for (key, value) in expected {
            assert_eq!(map.get(&key), Some(value));
        }
        map.ensure_healthy().unwrap();
        assert!(map.accounted_bytes() <= MAX_BYTES);
    }
    #[test]
    fn clones_remain_readonly_until_callback_reader_is_dropped() {
        let mut map = MigrationMap::new();
        insert(&mut map, "one".into(), "value".into()).unwrap();
        let reader = map.clone();
        assert!(insert(&mut map, "two".into(), "other".into()).is_err());
        assert_eq!(reader.get("one"), Some("value".into()));
        drop(reader);
        insert(&mut map, "two".into(), "other".into()).unwrap();
        assert!(insert(&mut map, ACCOUNT.into(), "invalid".into()).is_err());
    }
    #[test]
    fn alias_groups_are_streamed_and_share_cache_and_cleanup() {
        let mut map = MigrationMap::new();
        insert(&mut map, "one".into(), "value".into()).unwrap();
        let path = map.workspace().unwrap().path();
        let mut first = MigrationAliases::new(&mut map).unwrap();
        let mut second = MigrationAliases::new(&mut map).unwrap();
        for n in 0..1001 {
            first.push(("nodes".into(), id(n), canonical(n))).unwrap();
        }
        second
            .push(("other".into(), "old".into(), canonical(4)))
            .unwrap();
        let mut count = 0;
        for page in first.try_chunks(100) {
            let page = page.unwrap();
            assert!(page.len() <= 100);
            count += page.len();
        }
        assert_eq!(count, 1001);
        assert_eq!(second.try_chunks(100).next().unwrap().unwrap().len(), 1);
        drop(map);
        assert!(path.exists());
        drop(first);
        assert!(path.exists());
        drop(second);
        assert!(!path.exists());
    }
    #[test]
    fn secondary_state_key_index_matches_exact_old_text_and_replacements() {
        let mut map = MigrationMap::new();
        let old = format!("blake3:{}", id(7));
        let hash = hex::encode(sha2::Sha256::digest(old.as_bytes()));
        insert(&mut map, format!("mdn:snapshot-keys:{old}"), canonical(8)).unwrap();
        assert_eq!(
            map.lookup_legacy_key_hash("mdn:snapshot-keys", &hash),
            Some(canonical(8))
        );
        assert!(map.lookup_legacy_key_hash("mdn:views", &hash).is_none());
        insert(&mut map, format!("mdn:snapshot-keys:{old}"), canonical(9)).unwrap();
        assert_eq!(
            map.lookup_legacy_key_hash("mdn:snapshot-keys", &hash),
            Some(canonical(9))
        );
        insert(
            &mut map,
            format!("mdn:snapshot-keys:{old}"),
            "opaque".into(),
        )
        .unwrap();
        assert!(
            map.lookup_legacy_key_hash("mdn:snapshot-keys", &hash)
                .is_none()
        );
        map.ensure_healthy().unwrap();
    }
    #[test]
    fn opaque_legacy_snapshot_keys_are_indexed_without_hex_parsing() {
        let mut map = MigrationMap::new();
        let old = "https://github.com/mdn/content:commit:processor:blake3:selector";
        let hash = hex::encode(sha2::Sha256::digest(old.as_bytes()));
        for provider in ["mdn", "whatwg", "w3c", "chromium"] {
            let role = format!("{provider}:snapshot-keys");
            insert(&mut map, format!("{role}:{old}"), canonical(17)).unwrap();
            assert_eq!(
                map.lookup_legacy_key_hash(&role, &hash),
                Some(canonical(17))
            );
        }
        map.ensure_healthy().unwrap();
    }
    #[test]
    fn initialization_and_record_proof_failures_are_latched() {
        let mut map = MigrationMap::in_directory(PathBuf::from(
            "/definitely-not-a-migration-scratch-directory",
        ));
        assert!(insert(&mut map, "one".into(), "value".into()).is_err());
        assert!(map.ensure_healthy().is_err());
        let mut map = MigrationMap::new();
        insert(&mut map, "one".into(), "value".into()).unwrap();
        let workspace = map.workspace().unwrap();
        let tx = workspace.db.begin_write().unwrap();
        {
            let mut table = tx
                .open_table(redb::TableDefinition::<&str, &[u8]>::new("mappings"))
                .unwrap();
            table.insert("one", &[0_u8; 40][..]).unwrap();
        }
        tx.commit().unwrap();
        assert!(map.get("one").is_none());
        assert!(map.ensure_healthy().is_err());
        assert!(map.iter().next().is_none());
    }
    #[test]
    fn one_large_opaque_value_is_admitted_without_multiplying_page_storage() {
        let mut map = MigrationMap::new();
        let value = "x".repeat(9 * 1024 * 1024);
        insert(&mut map, "opaque".into(), value.clone()).unwrap();
        assert_eq!(map.get("opaque"), Some(value.clone()));
        assert_eq!(map.iter().next(), Some(("opaque".into(), value)));
        assert!(map.accounted_bytes() < MAX_BYTES);
        map.ensure_healthy().unwrap();
    }
    #[test]
    #[ignore = "million-entry spill stress; run serially outside fixture I/O gates"]
    fn more_than_one_million_logical_entries_keep_a_bounded_resident_cache() {
        let mut map = MigrationMap::new();
        for n in 0..1_000_001 {
            insert(&mut map, format!("mdn:nodes:{}", id(n)), canonical(n + 1)).unwrap();
        }
        assert_eq!(map.len(), 1_000_001);
        assert!(map.accounted_bytes() < MAX_BYTES);
        for n in [0, 500_000, 1_000_000] {
            assert_eq!(
                map.get(&format!("mdn:nodes:{}", id(n))),
                Some(canonical(n + 1))
            );
        }
        map.ensure_healthy().unwrap();
    }
}
