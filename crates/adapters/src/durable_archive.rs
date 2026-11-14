//! Backend-owned immutable archive bindings and disposable, leased local materialization.
//! No request-only input reaches this module. Remote bytes precede SQL publication.
use crate::object_storage::{S3Archive, S3Config};
use devres_application::collection::{LimitKind, Phase, limited};
use devres_domain::{Error, Result};
use serde::{Deserialize, Serialize};
use sqlx_core::{connection::Connection, row::Row};
use sqlx_postgres::{PgConnection, PgPool};
use std::os::unix::fs::MetadataExt;
use std::{
    collections::BTreeMap,
    future::Future,
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex, OnceLock, Weak},
    time::Instant,
};
use tokio_util::sync::CancellationToken;

pub(crate) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS devres_archive_control (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 epoch bigint NOT NULL DEFAULT 1 CHECK(epoch>0),
 backend text NOT NULL DEFAULT 'filesystem' CHECK(backend IN ('filesystem','s3')),
 binding text, pending_binding text,
 initializing_s3 boolean NOT NULL DEFAULT false,
 store_id text NOT NULL DEFAULT md5(random()::text || clock_timestamp()::text)
);
INSERT INTO devres_archive_control(singleton) VALUES(true) ON CONFLICT DO NOTHING;
ALTER TABLE devres_archive_control ADD COLUMN IF NOT EXISTS initializing_s3 boolean NOT NULL DEFAULT false;
CREATE SEQUENCE IF NOT EXISTS devres_archive_accounting_seq;
CREATE TABLE IF NOT EXISTS devres_archive_file (
 path text PRIMARY KEY CHECK(octet_length(path)<=16384), digest text NOT NULL CHECK(digest ~ '^blake3:[0-9a-f]{64}$'), bytes bigint NOT NULL CHECK(bytes>=0),
 device text NOT NULL CHECK(device ~ '^[0-9]{1,20}$'), inode text NOT NULL CHECK(inode ~ '^[0-9]{1,20}$'),
 epoch bigint NOT NULL CHECK(epoch>0), complete boolean NOT NULL DEFAULT false,
 evidence text NOT NULL CHECK(octet_length(evidence)<=16384)
);
CREATE INDEX IF NOT EXISTS devres_archive_file_path_c ON devres_archive_file(path COLLATE "C");
CREATE TABLE IF NOT EXISTS devres_archive_transfer (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 source_root text NOT NULL, inventory text NOT NULL, completed boolean NOT NULL DEFAULT false,
 source_protected boolean NOT NULL DEFAULT true
);
ALTER TABLE devres_archive_transfer ADD COLUMN IF NOT EXISTS source_protected boolean NOT NULL DEFAULT true;
"#;
pub(crate) fn config_binding(config: &S3Config) -> Result<String> {
    crate::integrity::canonical_hash(
        &serde_json::json!({"version":1,"endpoint":config.endpoint,"bucket":config.bucket,"region":config.region,"prefix":config.prefix,"path_style":config.path_style}),
    )
}
fn unavailable() -> Error {
    Error::unavailable("Durable object archive unavailable.")
}
fn integrity() -> Error {
    Error::integrity("Immutable archive binding mismatch.")
}
fn capacity() -> Error {
    Error::capacity("Local archive working set exceeds its capacity.")
}
fn materialization_deadline() -> Error {
    limited(
        Error::capacity("Archive materialization deadline exceeded."),
        Phase::Materialization,
        LimitKind::Deadline,
        None,
        None,
    )
}

// A dedicated runtime permits synchronous filesystem consumers on both Tokio and
// blocking threads. It is process-owned, never dropped from an asynchronous task.
fn run<T: Send>(future: impl Future<Output = Result<T>> + Send) -> Result<T> {
    static RUNTIME: OnceLock<std::result::Result<tokio::runtime::Runtime, ()>> = OnceLock::new();
    let runtime = RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|_| ())
    });
    let runtime = runtime.as_ref().map_err(|_| unavailable())?;
    let execute = || {
        std::thread::scope(|scope| {
            std::thread::Builder::new()
                .spawn_scoped(scope, || runtime.block_on(future))
                .map_err(|_| unavailable())?
                .join()
                .map_err(|_| unavailable())?
        })
    };
    if tokio::runtime::Handle::try_current()
        .is_ok_and(|handle| handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
    {
        // Synchronous parsers may be invoked on a runtime worker. Give Tokio a
        // replacement worker while the original reactor drives pooled SQL/HTTP.
        tokio::task::block_in_place(execute)
    } else {
        execute()
    }
}

fn run_bounded<T: Send>(
    deadline: Instant,
    cancel: &CancellationToken,
    future: impl Future<Output = Result<T>> + Send,
) -> Result<T> {
    if Instant::now() >= deadline {
        return Err(materialization_deadline());
    }
    run(async {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(Error::new("cancelled", "Archive materialization canceled.")),
            result = tokio::time::timeout(deadline.saturating_duration_since(Instant::now()), future) => {
                result.map_err(|_| materialization_deadline())?
            }
        }
    })
}

fn lock_cache(archive: &Archive) -> Result<std::sync::MutexGuard<'_, Cache>> {
    let take = || archive.cache.lock().map_err(|_| unavailable());
    if tokio::runtime::Handle::try_current()
        .is_ok_and(|handle| handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
    {
        tokio::task::block_in_place(take)
    } else {
        take()
    }
}

fn lock_materialization<'a>(
    archive: &'a Archive,
    deadline: Instant,
    cancel: &CancellationToken,
) -> Result<std::sync::MutexGuard<'a, Cache>> {
    let acquire = || {
        loop {
            if cancel.is_cancelled() {
                return Err(Error::new("cancelled", "Archive materialization canceled."));
            }
            if Instant::now() >= deadline {
                return Err(materialization_deadline());
            }
            match archive.cache.try_lock() {
                Ok(cache) => return Ok(cache),
                Err(std::sync::TryLockError::Poisoned(_)) => return Err(unavailable()),
                Err(std::sync::TryLockError::WouldBlock) => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
            }
        }
    };
    stage("cache_lock", || {
        if tokio::runtime::Handle::try_current().is_ok_and(|handle| {
            handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread
        }) {
            tokio::task::block_in_place(acquire)
        } else {
            acquire()
        }
    })
}

#[cfg(test)]
mod deadline_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn cancellation_and_expired_deadlines_do_not_poll_remote_work() {
        let polled = AtomicBool::new(false);
        let cancel = CancellationToken::new();
        cancel.cancel();
        let error = run_bounded(
            Instant::now() + std::time::Duration::from_secs(1),
            &cancel,
            async {
                polled.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(error.code, "cancelled");
        assert!(!polled.load(Ordering::SeqCst));
        let error = run_bounded(Instant::now(), &CancellationToken::new(), async {
            polled.store(true, Ordering::SeqCst);
            Ok(())
        })
        .unwrap_err();
        assert_eq!(error.code, "capacity");
        assert!(!polled.load(Ordering::SeqCst));
    }

    #[test]
    fn stalled_remote_work_uses_the_callers_deadline() {
        let result = run_bounded(
            Instant::now() + std::time::Duration::from_millis(10),
            &CancellationToken::new(),
            std::future::pending::<Result<()>>(),
        );
        assert_eq!(result.unwrap_err().code, "capacity");
    }
}

type Registry = Mutex<BTreeMap<PathBuf, Weak<Archive>>>;
fn registry() -> &'static Registry {
    static ROOTS: OnceLock<Registry> = OnceLock::new();
    ROOTS.get_or_init(Mutex::default)
}
fn select(path: &Path) -> Result<Option<Arc<Archive>>> {
    if !path.is_absolute()
        || path
            .components()
            .any(|p| matches!(p, Component::ParentDir | Component::CurDir))
    {
        return Err(integrity());
    }
    let roots = registry().lock().map_err(|_| unavailable())?;
    match roots
        .iter()
        .filter(|(root, _)| path.starts_with(root))
        .max_by_key(|(root, _)| root.components().count())
    {
        Some((_, selected)) => selected.upgrade().map(Some).ok_or_else(unavailable),
        None => Ok(None),
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    version: u32,
    path: String,
    digest: String,
    bytes: u64,
    device: u64,
    inode: u64,
}
impl Binding {
    fn object_key(&self) -> Result<String> {
        Ok(format!(
            "objects/{}",
            crate::integrity::relative_path(&self.digest)?.to_string_lossy()
        ))
    }
    fn encoded(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|_| integrity())
    }
    fn validate(&self) -> Result<()> {
        if self.version != 1
            || !self.digest.starts_with("blake3:")
            || !crate::integrity::valid_hash(&self.digest)
            || !logical_path(&self.path)
        {
            return Err(integrity());
        }
        Ok(())
    }
}
fn logical_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 4096
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
        && !path.contains('\\')
        && !path.chars().any(char::is_control)
        && Path::new(path)
            .components()
            .all(|p| matches!(p, Component::Normal(_)))
}
type PhysicalIdentity = (u64, u64);
type AccountingIdentities = BTreeMap<PathBuf, (PhysicalIdentity, PhysicalIdentity)>;
const MAX_LOCAL_FILES: usize = 262_144;
const MAX_LOCAL_ENTRIES: usize = 1_048_576;

#[derive(Debug, Default)]
struct Cache {
    root: Option<PathBuf>,
    files: BTreeMap<PathBuf, CacheEntry>,
    clock: u64,
    paths: BTreeMap<PathBuf, PhysicalIdentity>,
    objects: BTreeMap<PhysicalIdentity, LocalObject>,
    used_bytes: u64,
    // Full cold-download lengths are reserved before remote I/O. All ordinary
    // write admission includes these bytes until they become observed files.
    reserved_bytes: u64,
    identities: AccountingIdentities,
}
#[derive(Debug)]
struct LocalObject {
    bytes: u64,
    paths: std::collections::BTreeSet<PathBuf>,
}
#[derive(Debug)]
struct CacheEntry {
    pins: usize,
    touched: u64,
}
fn mutable_git(root: &Path, path: &Path) -> bool {
    path.strip_prefix(root).is_ok_and(|relative| relative.components().any(|part| matches!(part, Component::Normal(name) if name == "history.git" || name == "registry.git")))
}
impl Cache {
    fn scan(root: &Path) -> Result<Self> {
        fn visit(
            cache: &mut Cache,
            directory: &Path,
            depth: usize,
            entries: &mut usize,
            deadline: Instant,
        ) -> Result<()> {
            if depth > 128 || Instant::now() >= deadline {
                return Err(capacity());
            }
            for entry in std::fs::read_dir(directory).map_err(|_| unavailable())? {
                *entries = entries
                    .checked_add(1)
                    .filter(|v| *v <= MAX_LOCAL_ENTRIES)
                    .ok_or_else(capacity)?;
                if Instant::now() >= deadline {
                    return Err(capacity());
                }
                let entry = entry.map_err(|_| unavailable())?;
                let path = entry.path();
                if cache
                    .root
                    .as_ref()
                    .is_some_and(|root| mutable_git(root, &path))
                {
                    continue;
                }
                let metadata = std::fs::symlink_metadata(&path).map_err(|_| unavailable())?;
                if metadata.file_type().is_symlink() {
                    return Err(integrity());
                }
                if metadata.is_dir() {
                    visit(cache, &path, depth + 1, entries, deadline)?;
                } else if metadata.is_file() {
                    cache.observe(&path)?;
                } else {
                    return Err(integrity());
                }
            }
            Ok(())
        }
        let mut cache = Self {
            root: Some(root.to_owned()),
            ..Self::default()
        };
        visit(
            &mut cache,
            root,
            0,
            &mut 0,
            Instant::now() + std::time::Duration::from_secs(30),
        )?;
        Ok(cache)
    }
    async fn load(root: &Path, pool: &PgPool) -> Result<Self> {
        let selected = root.to_owned();
        let mut cache = tokio::task::spawn_blocking(move || Self::scan(&selected))
            .await
            .map_err(|_| unavailable())??;
        let paths: Vec<_> = cache.paths.keys().cloned().collect();
        for batch in paths.chunks(1000) {
            let relative = batch
                .iter()
                .map(|path| {
                    path.strip_prefix(root)
                        .ok()
                        .and_then(Path::to_str)
                        .map(str::to_owned)
                        .ok_or_else(integrity)
                })
                .collect::<Result<Vec<_>>>()?;
            let completed: Vec<String> = sqlx_core::query_scalar::query_scalar(
                "SELECT path FROM devres_archive_file WHERE complete AND path=ANY($1)",
            )
            .bind(&relative)
            .fetch_all(pool)
            .await
            .map_err(|_| unavailable())?;
            for path in completed {
                cache.clock = cache.clock.saturating_add(1);
                cache.files.insert(
                    root.join(path),
                    CacheEntry {
                        pins: 0,
                        touched: cache.clock,
                    },
                );
            }
        }
        Ok(cache)
    }
    fn detach(&mut self, path: &Path) -> Result<()> {
        if self.files.get(path).is_some_and(|entry| entry.pins > 0) {
            return Ok(());
        }
        if let Some(identity) = self.paths.remove(path) {
            let empty = if let Some(object) = self.objects.get_mut(&identity) {
                object.paths.remove(path);
                object.paths.is_empty()
            } else {
                return Err(integrity());
            };
            if empty {
                let object = self.objects.remove(&identity).ok_or_else(integrity)?;
                self.used_bytes = self
                    .used_bytes
                    .checked_sub(object.bytes)
                    .ok_or_else(integrity)?;
            }
        }
        self.files.remove(path);
        self.identities.remove(path);
        Ok(())
    }
    fn observe(&mut self, path: &Path) -> Result<()> {
        if self
            .root
            .as_ref()
            .is_some_and(|root| mutable_git(root, path))
        {
            return Ok(());
        }
        let metadata = std::fs::symlink_metadata(path).map_err(|_| unavailable())?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(integrity());
        }
        let physical = (metadata.dev(), metadata.ino());
        if self.paths.get(path).is_some_and(|old| *old != physical) {
            if self.files.get(path).is_some_and(|entry| entry.pins > 0) {
                return Err(integrity());
            }
            self.detach(path)?;
        }
        if !self.paths.contains_key(path) && self.paths.len() >= MAX_LOCAL_FILES {
            return Err(capacity());
        }
        let previous = self.objects.get(&physical).map_or(0, |object| object.bytes);
        self.used_bytes = self
            .used_bytes
            .checked_sub(previous)
            .and_then(|bytes| bytes.checked_add(metadata.len()))
            .ok_or_else(capacity)?;
        let object = self.objects.entry(physical).or_insert_with(|| LocalObject {
            bytes: 0,
            paths: Default::default(),
        });
        object.bytes = metadata.len();
        object.paths.insert(path.to_owned());
        let aliases: Vec<_> = object
            .paths
            .iter()
            .filter(|candidate| candidate.as_path() != path)
            .cloned()
            .collect();
        self.paths.insert(path.to_owned(), physical);
        // A rename changes path reachability without allocating the byte object.
        for alias in aliases {
            let same = std::fs::symlink_metadata(&alias).ok().is_some_and(|meta| {
                meta.is_file()
                    && !meta.file_type().is_symlink()
                    && (meta.dev(), meta.ino()) == physical
            });
            if !same {
                self.detach(&alias)?;
            }
        }
        Ok(())
    }
    fn reconcile(&mut self, deadline: Instant) -> Result<()> {
        // Only run on capacity pressure. The tracked set is explicitly bounded;
        // no directory traversal occurs on the streaming/write hot path.
        let paths: Vec<_> = self.paths.keys().cloned().collect();
        for path in paths {
            if Instant::now() >= deadline {
                return Err(capacity());
            }
            match std::fs::symlink_metadata(&path) {
                Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() => {
                    self.observe(&path)?
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => self.detach(&path)?,
                Ok(_) => return Err(integrity()),
                Err(_) => return Err(unavailable()),
            }
        }
        Ok(())
    }
}
fn admit_local(
    root: &Path,
    cache: &mut Cache,
    extra: u64,
    limit: u64,
    protected: &[PathBuf],
) -> Result<()> {
    admit_local_until(
        root,
        cache,
        extra,
        limit,
        protected,
        Instant::now() + std::time::Duration::from_secs(15),
    )
}
fn admit_local_until(
    root: &Path,
    cache: &mut Cache,
    extra: u64,
    limit: u64,
    protected: &[PathBuf],
    deadline: Instant,
) -> Result<()> {
    let fits = |cache: &Cache| {
        cache
            .used_bytes
            .checked_add(cache.reserved_bytes)
            .and_then(|bytes| bytes.checked_add(extra))
            .is_some_and(|bytes| bytes <= limit)
    };
    let has_space = |cache: &Cache| {
        fs2::available_space(root)
            .map(|free| {
                free >= extra
                    .saturating_add(cache.reserved_bytes)
                    .saturating_add(64 * 1024 * 1024)
            })
            .map_err(|_| unavailable())
    };
    if fits(cache) && has_space(cache)? {
        return Ok(());
    }
    cache.reconcile(deadline)?;
    let mut candidates: Vec<_> = cache
        .files
        .iter()
        .filter(|(path, entry)| entry.pins == 0 && !protected.contains(path))
        .map(|(path, entry)| (entry.touched, path.clone()))
        .collect();
    candidates.sort_unstable();
    for (_, path) in candidates {
        if Instant::now() >= deadline {
            return Err(capacity());
        }
        if fits(cache) && has_space(cache)? {
            return Ok(());
        }
        match std::fs::remove_file(&path) {
            Ok(()) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err(unavailable()),
        }
        cache.detach(&path)?;
    }
    if fits(cache) && has_space(cache)? {
        Ok(())
    } else if !fits(cache) {
        Err(limited(
            capacity(),
            Phase::Materialization,
            LimitKind::CacheWorkingSet,
            cache
                .used_bytes
                .checked_add(cache.reserved_bytes)
                .and_then(|bytes| bytes.checked_add(extra)),
            Some(limit),
        ))
    } else {
        let free = fs2::available_space(root).map_err(|_| unavailable())?;
        Err(limited(
            capacity(),
            Phase::Materialization,
            LimitKind::FreeReserve,
            Some(free),
            Some(
                extra
                    .saturating_add(cache.reserved_bytes)
                    .saturating_add(64 * 1024 * 1024),
            ),
        ))
    }
}

#[cfg(test)]
mod cache_budget_tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn pinned_cache_pressure_reports_the_exact_bound_without_removing_evidence() {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let retained = root.path().join("retained");
        std::fs::write(&retained, [7; 64]).unwrap();
        let mut cache = Cache::scan(root.path()).unwrap();
        let error = admit_local(
            root.path(),
            &mut cache,
            1,
            64,
            std::slice::from_ref(&retained),
        )
        .unwrap_err();
        let context = devres_application::collection::context(&error).unwrap();
        assert_eq!(context.phase, Phase::Materialization);
        let limit = context.limit.unwrap();
        assert_eq!(limit.kind, LimitKind::CacheWorkingSet);
        assert_eq!((limit.observed, limit.maximum), (Some(65), Some(64)));
        assert_eq!(std::fs::read(retained).unwrap(), [7; 64]);
    }

    #[test]
    fn aliases_and_renamed_generations_keep_one_physical_charge() {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let stage = root.path().join(".stage");
        std::fs::create_dir(&stage).unwrap();
        std::fs::write(stage.join("first"), vec![1; 64]).unwrap();
        std::fs::write(stage.join("second"), vec![2; 32]).unwrap();
        let mut cache = Cache::scan(root.path()).unwrap();
        assert_eq!(cache.used_bytes, 96);
        let alias = root.path().join("alias");
        std::fs::hard_link(stage.join("first"), &alias).unwrap();
        cache.observe(&alias).unwrap();
        assert_eq!(cache.used_bytes, 96);
        let published = root.path().join("published");
        std::fs::rename(&stage, &published).unwrap();
        for name in ["first", "second"] {
            cache.observe(&published.join(name)).unwrap();
        }
        assert_eq!(cache.used_bytes, 96);
        assert!(cache.paths.keys().all(|path| !path.starts_with(&stage)));
        std::fs::remove_file(&alias).unwrap();
        cache.detach(&alias).unwrap();
        assert_eq!(cache.used_bytes, 96);
        std::fs::remove_file(published.join("first")).unwrap();
        cache
            .reconcile(Instant::now() + std::time::Duration::from_secs(15))
            .unwrap();
        assert_eq!(cache.used_bytes, 32);
    }

    #[test]
    fn concurrent_stream_writers_cannot_overbook_local_bytes() {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let cache = Arc::new(Mutex::new(Cache::scan(root.path()).unwrap()));
        let completed = std::thread::scope(|scope| {
            let tasks: Vec<_> = (0..8)
                .map(|number| {
                    let cache = cache.clone();
                    let root = root.path();
                    scope.spawn(move || {
                        let path = root.join(format!(".stage-{number}"));
                        let mut file = std::fs::File::create(&path).unwrap();
                        let mut cache = cache.lock().unwrap();
                        if admit_local(root, &mut cache, 16, 64, std::slice::from_ref(&path))
                            .is_err()
                        {
                            return false;
                        }
                        file.write_all(&[7; 16]).unwrap();
                        cache.observe(&path).unwrap();
                        assert!(cache.used_bytes <= 64);
                        true
                    })
                })
                .collect();
            tasks
                .into_iter()
                .map(|task| task.join().unwrap())
                .filter(|completed| *completed)
                .count()
        });
        assert_eq!(completed, 4);
        assert_eq!(cache.lock().unwrap().used_bytes, 64);
        let actual: u64 = std::fs::read_dir(root.path())
            .unwrap()
            .map(|entry| entry.unwrap().metadata().unwrap().len())
            .sum();
        assert_eq!(actual, 64);
    }

    #[test]
    fn capacity_pressure_evicts_only_unpinned_remote_materializations() {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let pinned = root.path().join("pinned");
        let evictable = root.path().join("evictable");
        std::fs::write(&pinned, vec![1; 128]).unwrap();
        std::fs::write(&evictable, vec![2; 128]).unwrap();
        let mut cache = Cache::scan(root.path()).unwrap();
        cache.files.insert(
            pinned.clone(),
            CacheEntry {
                pins: 1,
                touched: 0,
            },
        );
        cache.files.insert(
            evictable.clone(),
            CacheEntry {
                pins: 0,
                touched: 1,
            },
        );
        admit_local(root.path(), &mut cache, 128, 256, &[]).unwrap();
        assert!(pinned.is_file());
        assert!(!evictable.exists());
        assert_eq!(cache.used_bytes, 128);
        assert!(admit_local(root.path(), &mut cache, 129, 256, &[]).is_err());
        assert!(pinned.is_file());
    }
}

#[cfg(test)]
mod namespace_acceptance {
    use super::*;
    use std::io::Write;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires disposable PostgreSQL and RustFS; run scripts/test-s3.sh"]
    async fn s3_all_provider_raw_and_retained_git_namespaces_rehydrate_with_evidence() {
        let base =
            std::env::var("DEVRES_TEST_DATABASE_URL").expect("disposable PostgreSQL required");
        let path =
            std::env::var("DEVRES_TEST_S3_CONFIG").expect("disposable S3 configuration required");
        let mut config: S3Config = toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        config.prefix.push_str("/provider-namespace-acceptance");
        config.cache_max_bytes = 64 * 1024 * 1024;
        let admin = sqlx_postgres::PgPool::connect(&base).await.unwrap();
        sqlx_core::query::query("CREATE DATABASE devres_s3_namespace_fixture")
            .execute(&admin)
            .await
            .unwrap();
        let mut database = url::Url::parse(&base).unwrap();
        database.set_path("/devres_s3_namespace_fixture");
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let store = crate::PgBlobStore::connect_archive(
            database.as_str(),
            root.path(),
            Some(config.clone()),
        )
        .await
        .unwrap();
        // Commit-order buffers charge physical writes rather than enqueueing bytes.
        // A sparse, unretained stage fills the cache without creating remote evidence.
        let filler = root.path().join("quota-fixture.stage");
        let filler_file = std::fs::File::create(&filler).unwrap();
        with_write_budget(&filler, config.cache_max_bytes - 3, || {
            filler_file.set_len(config.cache_max_bytes - 3)
        })
        .unwrap();
        let stage = root.path().join("commit-order.stage");
        let mut writer =
            BudgetedStageWriter::new(stage.clone(), std::fs::File::create(&stage).unwrap());
        writer.write_all(b"a\n").unwrap();
        assert_eq!(std::fs::metadata(&stage).unwrap().len(), 0);
        writer.finish().unwrap();
        assert_eq!(std::fs::read(&stage).unwrap(), b"a\n");
        writer.write_all(b"four").unwrap();
        assert!(
            writer.finish().is_err(),
            "buffer flush bypassed cache capacity"
        );
        drop(writer);
        assert_eq!(std::fs::read(&stage).unwrap(), b"a\n");
        let archive = select(&stage).unwrap().unwrap();
        assert_eq!(
            lock_cache(&archive).unwrap().used_bytes,
            config.cache_max_bytes - 1
        );
        std::fs::remove_file(&stage).unwrap();
        forget_local(&stage).unwrap();
        drop(filler_file);
        std::fs::remove_file(&filler).unwrap();
        forget_local(&filler).unwrap();
        assert_eq!(lock_cache(&archive).unwrap().used_bytes, 0);
        drop(archive);
        // These inert bytes exercise permanent file classes through the shared
        // publication boundary; they do not establish provider/Git acquisition.
        let namespaces = [
            ("rfc", ""),
            ("crates", ""),
            ("rustsec", "rustsec-history/artifacts"),
            ("mdn", "mdn/raw-artifacts"),
            ("whatwg", "whatwg/raw-artifacts"),
            ("w3c", "w3c/raw-artifacts"),
            ("chromium", "chromium/raw-artifacts"),
            ("npm", "npm/raw-artifacts"),
            ("wikipedia", "wikipedia/raw-artifacts"),
        ];
        let git_namespaces = [
            ("crate-index", ""),
            ("rustsec-history", "rustsec-history/artifacts"),
            ("mdn-content", "mdn/content/artifacts"),
            ("whatwg-history", "whatwg/git/html/artifacts"),
            ("w3c-history", "w3c/git/spec/artifacts"),
        ];
        let mut retained = Vec::new();
        for (provider, directory) in namespaces {
            retained.push((
                directory,
                format!("public raw fixture for {provider}").into_bytes(),
            ));
        }
        for (provider, directory) in git_namespaces {
            let pack =
                format!("PACK\0\0\0\u{2}inert retained pack fixture for {provider}").into_bytes();
            let manifest = serde_json::to_vec(&serde_json::json!({"version":1,"provider":provider,"pack":crate::integrity::hash(&pack)})).unwrap();
            retained.push((directory, pack));
            retained.push((directory, manifest));
        }
        let mut files = Vec::new();
        for (namespace, bytes) in retained {
            let digest = crate::integrity::hash(&bytes);
            let relative =
                Path::new(namespace).join(crate::integrity::relative_path(&digest).unwrap());
            let path = root.path().join(&relative);
            crate::integrity::ensure_directory_durable(path.parent().unwrap()).unwrap();
            let mut output = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&path)
                .unwrap();
            with_write_budget(&path, bytes.len() as u64, || output.write_all(&bytes)).unwrap();
            output.sync_all().unwrap();
            crate::integrity::record_file(root.path(), &path, &digest, bytes.len() as u64).unwrap();
            files.push((relative, digest, bytes));
        }
        drop(store);
        std::fs::remove_dir_all(root.path()).unwrap();
        let store =
            crate::PgBlobStore::connect_archive(database.as_str(), root.path(), Some(config))
                .await
                .unwrap();
        for (relative, digest, bytes) in files {
            let path = root.path().join(&relative);
            assert!(!path.exists());
            let _lease = materialize_file(
                &path,
                bytes.len() as u64,
                Instant::now() + std::time::Duration::from_secs(15),
                &CancellationToken::new(),
            )
            .unwrap();
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
            let evidence = crate::integrity::evidence_path(root.path(), &path).unwrap();
            let _evidence_lease = materialize_file(
                &evidence,
                16 * 1024,
                Instant::now() + std::time::Duration::from_secs(15),
                &CancellationToken::new(),
            )
            .unwrap();
            let evidence: crate::integrity::FileEvidence =
                serde_json::from_slice(&std::fs::read(evidence).unwrap()).unwrap();
            assert_eq!(evidence.path, relative.to_str().unwrap());
            assert_eq!(evidence.digest, digest);
            assert_eq!(evidence.bytes, bytes.len() as u64);
        }
        drop(store);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArchiveAdmission {
    Fresh,
    Existing,
    Transfer,
}

pub struct Archive {
    root: PathBuf,
    remote: S3Archive,
    pool: PgPool,
    owner: Weak<tokio::sync::Mutex<PgConnection>>,
    epoch: i64,
    reader: bool,
    owner_pid: i32,
    owner_started: String,
    binding: String,
    cache: Mutex<Cache>,
    materializations: MaterializationControl,
}
impl std::fmt::Debug for Archive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Archive").finish_non_exhaustive()
    }
}
/// Independent paths share exactly two remote materialization slots. Weak path
/// entries bound lifetime without retaining an ever-growing lock per request.
struct MaterializationControl {
    flights: Mutex<BTreeMap<String, Weak<tokio::sync::Mutex<()>>>>,
    io: Arc<tokio::sync::Semaphore>,
}
impl Default for MaterializationControl {
    fn default() -> Self {
        Self {
            flights: Mutex::new(BTreeMap::new()),
            io: Arc::new(tokio::sync::Semaphore::new(2)),
        }
    }
}
impl MaterializationControl {
    fn claim(
        &self,
        path: &str,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<tokio::sync::OwnedMutexGuard<()>> {
        let flight = {
            let mut flights = self.flights.lock().map_err(|_| unavailable())?;
            if let Some(flight) = flights.get(path).and_then(Weak::upgrade) {
                flight
            } else {
                if flights.len() >= MAX_LOCAL_FILES {
                    flights.retain(|_, value| value.strong_count() > 0);
                    if flights.len() >= MAX_LOCAL_FILES {
                        return Err(capacity());
                    }
                }
                let flight = Arc::new(tokio::sync::Mutex::new(()));
                flights.insert(path.to_owned(), Arc::downgrade(&flight));
                flight
            }
        };
        stage("single_flight", || {
            run_bounded(deadline, cancel, async { Ok(flight.lock_owned().await) })
        })
    }
}
fn stage<T>(name: &'static str, operation: impl FnOnce() -> Result<T>) -> Result<T> {
    let started = Instant::now();
    let result = operation();
    tracing::trace!(
        target: "devres_private_timings",
        archive_stage = name,
        elapsed_micros = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        success = result.is_ok(),
        "archive materialization stage"
    );
    result
}
async fn stage_async<T>(name: &'static str, future: impl Future<Output = Result<T>>) -> Result<T> {
    let started = Instant::now();
    let result = future.await;
    tracing::trace!(
        target: "devres_private_timings",
        archive_stage = name,
        elapsed_micros = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        success = result.is_ok(),
        "archive materialization stage"
    );
    result
}
struct DownloadReservation {
    archive: Arc<Archive>,
    bytes: u64,
}
impl DownloadReservation {
    fn new(
        archive: &Arc<Archive>,
        bytes: u64,
        path: &Path,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<Self> {
        let mut cache = lock_materialization(archive, deadline, cancel)?;
        admit_local_until(
            &archive.root,
            &mut cache,
            bytes,
            archive.remote.config().cache_max_bytes,
            &[path.to_owned()],
            deadline,
        )?;
        cache.reserved_bytes = cache
            .reserved_bytes
            .checked_add(bytes)
            .ok_or_else(capacity)?;
        Ok(Self {
            archive: archive.clone(),
            bytes,
        })
    }
    fn commit(&mut self, cache: &mut Cache) -> Result<()> {
        cache.reserved_bytes = cache
            .reserved_bytes
            .checked_sub(self.bytes)
            .ok_or_else(integrity)?;
        self.bytes = 0;
        Ok(())
    }
}
impl Drop for DownloadReservation {
    fn drop(&mut self) {
        if self.bytes > 0
            && let Ok(mut cache) = lock_cache(&self.archive)
        {
            cache.reserved_bytes = cache.reserved_bytes.saturating_sub(self.bytes);
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ArchiveLease(Option<Arc<Lease>>);
#[derive(Debug)]
struct Lease {
    archive: Arc<Archive>,
    paths: Vec<PathBuf>,
}
impl Drop for Lease {
    fn drop(&mut self) {
        if let Ok(mut cache) = lock_cache(&self.archive) {
            for path in &self.paths {
                if let Some(entry) = cache.files.get_mut(path) {
                    entry.pins = entry.pins.saturating_sub(1);
                }
            }
        }
    }
}
impl ArchiveLease {
    fn pin(archive: &Arc<Archive>, cache: &mut Cache, paths: Vec<PathBuf>) -> Self {
        for path in &paths {
            cache.clock = cache.clock.saturating_add(1);
            let clock = cache.clock;
            let entry = cache.files.entry(path.clone()).or_insert(CacheEntry {
                pins: 0,
                touched: clock,
            });
            entry.pins += 1;
            entry.touched = clock;
        }
        Self(Some(Arc::new(Lease {
            archive: archive.clone(),
            paths,
        })))
    }
    /// Number of retained materializations, also useful for private diagnostics.
    pub fn pinned_files(&self) -> usize {
        self.0.as_ref().map_or(0, |v| v.paths.len())
    }
}

impl Archive {
    pub(crate) async fn attach_reader(
        root: PathBuf,
        config: S3Config,
        pool: PgPool,
        owner: Arc<tokio::sync::Mutex<PgConnection>>,
        owner_pid: i32,
        owner_started: String,
    ) -> Result<Arc<Self>> {
        let remote = S3Archive::new_reader(config).await?;
        let binding = config_binding(remote.config())?;
        let row = sqlx_core::query::query("SELECT epoch,store_id FROM devres_archive_control WHERE singleton AND backend='s3' AND binding=$1 AND pending_binding IS NULL AND NOT initializing_s3")
            .bind(&binding).fetch_optional(&pool).await.map_err(|_| unavailable())?.ok_or_else(integrity)?;
        let epoch: i64 = row.try_get("epoch").map_err(|_| integrity())?;
        let store_id: String = row.try_get("store_id").map_err(|_| integrity())?;
        let descriptor = remote.get_bytes("store.json", 16 * 1024).await?;
        if serde_json::from_slice::<serde_json::Value>(&descriptor).map_err(|_| integrity())?
            != serde_json::json!({"version":1,"store_id":store_id})
        {
            return Err(integrity());
        }
        let original: Option<String> = sqlx_core::query_scalar::query_scalar(
            "SELECT source_root FROM devres_archive_transfer WHERE singleton AND source_protected",
        )
        .fetch_optional(&pool)
        .await
        .map_err(|_| unavailable())?;
        if original.as_ref().is_some_and(|original| {
            root.starts_with(original) || Path::new(original).starts_with(&root)
        }) {
            return Err(Error::invalid(
                "Reader requires a separate disposable cache.",
            ));
        }
        let mut cache = Cache::load(&root, &pool).await?;
        admit_local(&root, &mut cache, 0, remote.config().cache_max_bytes, &[])?;
        let archive = Arc::new(Self {
            root,
            remote,
            pool,
            owner: Arc::downgrade(&owner),
            epoch,
            reader: true,
            owner_pid,
            owner_started,
            binding,
            cache: Mutex::new(cache),
            materializations: MaterializationControl::default(),
        });
        archive.health().await?;
        registry()
            .lock()
            .map_err(|_| unavailable())?
            .insert(archive.root.clone(), Arc::downgrade(&archive));
        Ok(archive)
    }
    pub(crate) async fn attach(
        root: PathBuf,
        config: S3Config,
        pool: PgPool,
        owner: Arc<tokio::sync::Mutex<PgConnection>>,
        owner_pid: i32,
        owner_started: String,
        admission: ArchiveAdmission,
    ) -> Result<Arc<Self>> {
        let transfer = admission == ArchiveAdmission::Transfer;
        if tokio::runtime::Handle::try_current()
            .map_err(|_| unavailable())?
            .runtime_flavor()
            != tokio::runtime::RuntimeFlavor::MultiThread
        {
            return Err(Error::invalid(
                "Object storage requires a multithreaded runtime.",
            ));
        }
        let remote = S3Archive::new(config).await?;
        let binding = config_binding(remote.config())?;
        let mut connection = owner.lock().await;
        let mut tx = connection.begin().await.map_err(|_| unavailable())?;
        let row=sqlx_core::query::query("SELECT epoch,backend,binding,pending_binding,store_id,initializing_s3 FROM devres_archive_control WHERE singleton FOR UPDATE").fetch_one(&mut *tx).await.map_err(|_|unavailable())?;
        let previous_epoch: i64 = row.try_get("epoch").map_err(|_| integrity())?;
        let backend: String = row.try_get("backend").map_err(|_| integrity())?;
        let bound: Option<String> = row.try_get("binding").map_err(|_| integrity())?;
        let pending: Option<String> = row.try_get("pending_binding").map_err(|_| integrity())?;
        let initializing: bool = row.try_get("initializing_s3").map_err(|_| integrity())?;
        let store_id: String = row.try_get("store_id").map_err(|_| integrity())?;
        let epoch = if backend == "filesystem" && pending.is_none() {
            previous_epoch.checked_add(1).ok_or_else(integrity)?
        } else {
            previous_epoch
        };
        if (backend == "s3" && bound.as_deref() != Some(&binding))
            || pending.as_deref().is_some_and(|v| v != binding)
        {
            return Err(integrity());
        }
        if backend == "s3" {
            let original:Option<String>=sqlx_core::query_scalar::query_scalar("SELECT source_root FROM devres_archive_transfer WHERE singleton AND source_protected").fetch_optional(&mut *tx).await.map_err(|_|unavailable())?;
            if let Some(original) = original {
                let original = Path::new(&original);
                if !original.is_absolute() {
                    return Err(integrity());
                }
                if root.starts_with(original) || original.starts_with(&root) {
                    return Err(Error::invalid(
                        "Use a separate disposable cache; the original filesystem archive is preserved.",
                    ));
                }
            }
        }
        if backend == "filesystem" && !transfer {
            let count: i64 =
                sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM devres_captures")
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(|_| unavailable())?;
            // A populated filesystem store must use explicit verified migration.
            let populated = has_evidence(&root)?;
            let admitted_fresh = admission == ArchiveAdmission::Fresh
                || (initializing && pending.as_deref() == Some(&binding));
            if !admitted_fresh || count > 0 || populated {
                return Err(Error::unavailable(
                    "Offline object archive migration required.",
                ));
            }
        }
        // Reopening an already committed S3 archive changes neither its binding
        // nor epoch, including offline verification and restored-target checks.
        // Genuine pending/initializing transitions retain their original fence.
        let committed = backend == "s3" && pending.is_none() && !initializing;
        if !committed {
            // Fix the target before remote I/O; a different database cannot claim
            // the prefix, and readers remain stopped while a transfer is pending.
            sqlx_core::query::query("UPDATE devres_archive_control SET pending_binding=$1,epoch=$2,initializing_s3=initializing_s3 OR $3 WHERE singleton AND (binding IS NULL OR binding=$1)").bind(&binding).bind(epoch).bind(admission==ArchiveAdmission::Fresh).execute(&mut *tx).await.map_err(|_|unavailable())?;
        }
        tx.commit().await.map_err(|_| unavailable())?;
        drop(connection);
        remote
            .put_bytes_immutable(
                "store.json",
                serde_json::to_string(&serde_json::json!({"version":1,"store_id":store_id}))
                    .map_err(|_| integrity())?
                    .as_bytes(),
            )
            .await?;
        remote.health().await?;
        let mut cache = if transfer && backend == "filesystem" {
            Cache {
                root: Some(root.clone()),
                ..Cache::default()
            }
        } else {
            Cache::load(&root, &pool).await?
        };
        if !transfer || backend == "s3" {
            admit_local(&root, &mut cache, 0, remote.config().cache_max_bytes, &[])?;
        }
        let archive = Arc::new(Self {
            root,
            remote,
            pool,
            owner: Arc::downgrade(&owner),
            epoch,
            reader: false,
            owner_pid,
            owner_started,
            binding,
            cache: Mutex::new(cache),
            materializations: MaterializationControl::default(),
        });
        archive.recover_pending().await?;
        if !transfer && backend == "filesystem" {
            archive.activate().await?;
        }
        if !transfer || backend == "s3" {
            registry()
                .lock()
                .map_err(|_| unavailable())?
                .insert(archive.root.clone(), Arc::downgrade(&archive));
        }
        Ok(archive)
    }
    async fn fence(&self) -> Result<()> {
        let _owner = self.owner.upgrade().ok_or_else(unavailable)?;
        let owned:bool=sqlx_core::query_scalar::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE l.locktype='advisory' AND l.classid=1835365490 AND l.objid::bigint=$3 AND l.objsubid=2 AND l.granted AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND a.pid=$1 AND EXTRACT(EPOCH FROM a.backend_start)::text=$2)").bind(self.owner_pid).bind(&self.owner_started).bind(if self.reader { 2_i64 } else { 1_i64 }).fetch_one(&self.pool).await.map_err(|_|unavailable())?;
        let matches:bool=sqlx_core::query_scalar::query_scalar("SELECT epoch=$1 AND COALESCE(binding,pending_binding)=$2 AND (NOT $3 OR (backend='s3' AND pending_binding IS NULL AND NOT initializing_s3)) FROM devres_archive_control WHERE singleton").bind(self.epoch).bind(&self.binding).bind(self.reader).fetch_one(&self.pool).await.map_err(|_|unavailable())?;
        if !owned || !matches {
            return Err(Error::unavailable(
                "Storage ownership lost; restart required",
            ));
        }
        Ok(())
    }
    pub(crate) async fn health(&self) -> Result<()> {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            stage_async("owner_fence", self.fence()).await?;
            stage_async("remote_health", self.remote.health()).await
        })
        .await
        .map_err(|_| unavailable())?
    }
    async fn recover_pending(&self) -> Result<()> {
        let mut after = String::new();
        loop {
            self.fence().await?;
            let row:Option<(String,String)>=sqlx_core::query_as::query_as("SELECT path,evidence FROM devres_archive_file WHERE NOT complete AND path>$1 ORDER BY path LIMIT 1").bind(&after).fetch_optional(&self.pool).await.map_err(|_|unavailable())?;
            let Some((path, encoded)) = row else {
                break;
            };
            let binding: Binding = serde_json::from_str(&encoded).map_err(|_| integrity())?;
            binding.validate()?;
            let key = binding.object_key()?;
            if self.remote.head(&key).await?.is_some() {
                self.remote
                    .verify_object(
                        &key,
                        &binding.digest,
                        binding.bytes,
                        &CancellationToken::new(),
                    )
                    .await?;
                self.remote
                    .put_bytes_immutable(
                        &format!("bindings/{}.json", blake3::hash(path.as_bytes()).to_hex()),
                        encoded.as_bytes(),
                    )
                    .await?;
                let owner = self.owner.upgrade().ok_or_else(unavailable)?;
                let mut owner = owner.lock().await;
                sqlx_core::query::query("UPDATE devres_archive_file SET complete=true WHERE path=$1 AND evidence=$2 AND epoch=$3").bind(&path).bind(&encoded).bind(self.epoch).execute(&mut *owner).await.map_err(|_|unavailable())?;
            } else {
                self.remote.abort_incomplete(&key).await?;
                // Retain the reservation: no corpus reference may be published
                // until an explicit retry establishes the complete immutable file.
            }
            after = path;
        }
        Ok(())
    }
    async fn activate(&self) -> Result<()> {
        self.fence().await?;
        let pending: i64 = sqlx_core::query_scalar::query_scalar(
            "SELECT count(*) FROM devres_archive_file WHERE NOT complete",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|_| unavailable())?;
        if pending != 0 {
            return Err(Error::integrity(
                "Incomplete archive uploads block activation.",
            ));
        }
        let owner_handle = self.owner.upgrade().ok_or_else(unavailable)?;
        let mut owner = owner_handle.lock().await;
        let mut tx = owner.begin().await.map_err(|_| unavailable())?;
        let changed=sqlx_core::query::query("UPDATE devres_archive_control SET backend='s3',binding=$1,pending_binding=NULL,initializing_s3=false WHERE singleton AND epoch=$2 AND pending_binding=$1").bind(&self.binding).bind(self.epoch).execute(&mut *tx).await.map_err(|_|unavailable())?.rows_affected();
        if changed != 1 {
            return Err(integrity());
        }
        sqlx_core::query::query(
            "UPDATE devres_archive_transfer SET completed=true WHERE singleton",
        )
        .execute(&mut *tx)
        .await
        .map_err(|_| unavailable())?;
        tx.commit().await.map_err(|_| unavailable())?;
        Ok(())
    }
    fn relative(&self, path: &Path) -> Result<String> {
        let p = path
            .strip_prefix(&self.root)
            .map_err(|_| integrity())?
            .to_str()
            .ok_or_else(integrity)?
            .to_owned();
        if !logical_path(&p) {
            return Err(integrity());
        }
        Ok(p)
    }
    async fn binding_for(&self, path: &str, complete: bool) -> Result<Option<Binding>> {
        let value: Option<String> = sqlx_core::query_scalar::query_scalar(
            "SELECT evidence FROM devres_archive_file WHERE path=$1 AND (NOT $2 OR complete)",
        )
        .bind(path)
        .bind(complete)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| unavailable())?;
        value
            .map(|v| {
                let binding: Binding = serde_json::from_str(&v).map_err(|_| integrity())?;
                binding.validate()?;
                if binding.path != path {
                    return Err(integrity());
                }
                Ok(binding)
            })
            .transpose()
    }
    async fn publish_one(&self, path: &Path, digest: &str, bytes: u64) -> Result<()> {
        self.publish_one_accounted(path, digest, bytes, None).await
    }
    async fn publish_one_accounted(
        &self,
        path: &Path,
        digest: &str,
        bytes: u64,
        accounting: Option<(u64, u64)>,
    ) -> Result<()> {
        if self.reader {
            return Err(Error::unavailable("Reader archive cannot publish."));
        }
        self.health().await?;
        let relative = self.relative(path)?;
        let metadata = std::fs::symlink_metadata(path).map_err(|_| unavailable())?;
        if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() != bytes {
            return Err(integrity());
        }
        let mut binding = Binding {
            version: 1,
            path: relative.clone(),
            digest: digest.into(),
            bytes,
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        if let Some(existing) = self.binding_for(&relative, false).await? {
            if existing.digest != digest || existing.bytes != bytes {
                return Err(integrity());
            }
            binding = existing;
        }
        if self.binding_for(&relative, false).await?.is_none() {
            let (device, inode) = match accounting {
                Some(identity) => identity,
                None => self.local_identity(path)?,
            };
            binding.device = device;
            binding.inode = inode;
        }
        binding.validate()?;
        let encoded = binding.encoded()?;
        {
            let owner_handle = self.owner.upgrade().ok_or_else(unavailable)?;
            let mut owner = owner_handle.lock().await;
            sqlx_core::query::query("INSERT INTO devres_archive_file(path,digest,bytes,device,inode,epoch,evidence) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(path) DO NOTHING").bind(&relative).bind(digest).bind(i64::try_from(bytes).map_err(|_|capacity())?).bind(binding.device.to_string()).bind(binding.inode.to_string()).bind(self.epoch).bind(&encoded).execute(&mut *owner).await.map_err(|_|unavailable())?;
        }
        // Intent remains durable on cancellation or an ambiguous network failure.
        self.remote
            .put_file_immutable(
                &binding.object_key()?,
                path,
                digest,
                bytes,
                &CancellationToken::new(),
            )
            .await?;
        self.remote
            .put_bytes_immutable(
                &format!(
                    "bindings/{}.json",
                    blake3::hash(relative.as_bytes()).to_hex()
                ),
                encoded.as_bytes(),
            )
            .await?;
        self.fence().await?;
        let owner_handle = self.owner.upgrade().ok_or_else(unavailable)?;
        let mut owner = owner_handle.lock().await;
        let changed=sqlx_core::query::query("UPDATE devres_archive_file SET complete=true WHERE path=$1 AND evidence=$2 AND epoch=$3").bind(&relative).bind(&encoded).bind(self.epoch).execute(&mut *owner).await.map_err(|_|unavailable())?.rows_affected();
        if changed != 1 {
            return Err(integrity());
        }
        Ok(())
    }
    fn admit(&self, cache: &mut Cache, extra: u64, protected: &[PathBuf]) -> Result<()> {
        admit_local(
            &self.root,
            cache,
            extra,
            self.remote.config().cache_max_bytes,
            protected,
        )
    }
    fn materialize(
        self: &Arc<Self>,
        path: &Path,
        max_bytes: u64,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<ArchiveLease> {
        self.materialize_selected(path, max_bytes, deadline, cancel, false)?
            .ok_or_else(integrity)
    }
    fn materialize_selected(
        self: &Arc<Self>,
        path: &Path,
        max_bytes: u64,
        deadline: Instant,
        cancel: &CancellationToken,
        optional: bool,
    ) -> Result<Option<ArchiveLease>> {
        let relative = self.relative(path)?;
        // Acquire path ownership before I/O admission. A waiter for this path
        // cannot consume the other independent file's I/O slot.
        let _flight = self.materializations.claim(&relative, deadline, cancel)?;
        let _io = stage("io_admission", || {
            run_bounded(deadline, cancel, async {
                self.materializations
                    .io
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|_| unavailable())
            })
        })?;
        // Warm local bytes and optional misses never replace current authority.
        stage("authority", || run_bounded(deadline, cancel, self.health()))?;
        let binding = stage("binding", || {
            run_bounded(deadline, cancel, self.binding_for(&relative, true))
        })?;
        let Some(binding) = binding else {
            return if optional { Ok(None) } else { Err(integrity()) };
        };
        if binding.bytes > max_bytes {
            return Err(capacity());
        }
        let remote = stage("head", || {
            run_bounded(deadline, cancel, self.remote.head(&binding.object_key()?))
        })?
        .ok_or_else(integrity)?;
        if remote.bytes != binding.bytes {
            return Err(integrity());
        }
        let warm = {
            let mut cache = lock_materialization(self, deadline, cancel)?;
            match std::fs::symlink_metadata(path) {
                Ok(meta) => {
                    if !meta.is_file()
                        || meta.file_type().is_symlink()
                        || meta.len() != binding.bytes
                    {
                        return Err(integrity());
                    }
                    cache.observe(path)?;
                    // Pin before releasing the mutex for hashing: unrelated
                    // downloads and ordinary writers may concurrently evict.
                    Some(ArchiveLease::pin(self, &mut cache, vec![path.to_owned()]))
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(_) => return Err(unavailable()),
            }
        };
        if let Some(lease) = warm {
            let (digest, bytes) = stage("hash", || {
                crate::integrity::file_digest_local(path, binding.bytes, deadline, cancel)
            })?;
            if digest != binding.digest || bytes != binding.bytes {
                return Err(integrity());
            }
            self.recheck_binding(&relative, &binding, deadline, cancel)?;
            let mut cache = lock_materialization(self, deadline, cancel)?;
            cache.observe(path)?;
            self.record_identity(&mut cache, path, &binding)?;
            return Ok(Some(lease));
        }
        let mut reservation = stage("cache_admission", || {
            DownloadReservation::new(self, binding.bytes, path, deadline, cancel)
        })?;
        if let Some(parent) = path.parent() {
            crate::integrity::ensure_directory_durable(parent)?;
        }
        let directory = tempfile::Builder::new()
            .prefix(".archive-download-")
            .tempdir_in(path.parent().ok_or_else(integrity)?)
            .map_err(|_| unavailable())?;
        let payload = directory.path().join("payload");
        let (digest, bytes) = stage("download", || {
            run_bounded(deadline, cancel, async {
                self.remote
                    .get_to_file(&binding.object_key()?, &payload, binding.bytes, cancel)
                    .await
            })
        })?;
        if digest != binding.digest || bytes != binding.bytes {
            return Err(integrity());
        }
        self.recheck_binding(&relative, &binding, deadline, cancel)?;
        let lease = {
            let mut cache = lock_materialization(self, deadline, cancel)?;
            // Publish only our verified stage. A surprising local file must
            // never be overwritten, even if another writer created it.
            std::fs::hard_link(&payload, path).map_err(|_| unavailable())?;
            if let Err(error) = cache.observe(path) {
                let _ = std::fs::remove_file(path);
                return Err(error);
            }
            reservation.commit(&mut cache)?;
            admit_local_until(
                &self.root,
                &mut cache,
                0,
                self.remote.config().cache_max_bytes,
                &[path.to_owned()],
                deadline,
            )?;
            self.record_identity(&mut cache, path, &binding)?;
            ArchiveLease::pin(self, &mut cache, vec![path.to_owned()])
        };
        // The temporary alias and reservation are gone before the caller can
        // use its pin. The permanent remote object is never modified.
        drop(directory);
        Ok(Some(lease))
    }
    fn recheck_binding(
        &self,
        relative: &str,
        expected: &Binding,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<()> {
        stage("recheck", || {
            run_bounded(deadline, cancel, async {
                self.health().await?;
                if self.binding_for(relative, true).await?.as_ref() != Some(expected) {
                    return Err(integrity());
                }
                Ok(())
            })
        })
    }
    fn record_identity(&self, cache: &mut Cache, path: &Path, binding: &Binding) -> Result<()> {
        let metadata = std::fs::symlink_metadata(path).map_err(|_| unavailable())?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() != binding.bytes
        {
            return Err(integrity());
        }
        cache.identities.insert(
            path.to_owned(),
            (
                (metadata.dev(), metadata.ino()),
                (binding.device, binding.inode),
            ),
        );
        Ok(())
    }
    async fn children(&self, path: &str, max_files: usize) -> Result<Vec<Binding>> {
        let prefix = format!("{path}/");
        let rows:Vec<String>=sqlx_core::query_scalar::query_scalar("SELECT evidence FROM devres_archive_file WHERE complete AND starts_with(path,$1) ORDER BY path LIMIT $2").bind(prefix).bind(i64::try_from(max_files.saturating_add(1)).map_err(|_|capacity())?).fetch_all(&self.pool).await.map_err(|_|unavailable())?;
        if rows.len() > max_files {
            return Err(capacity());
        }
        rows.into_iter()
            .map(|value| {
                let binding: Binding = serde_json::from_str(&value).map_err(|_| integrity())?;
                binding.validate()?;
                Ok(binding)
            })
            .collect()
    }
}

impl Archive {
    fn local_identity(&self, path: &Path) -> Result<(u64, u64)> {
        let meta = std::fs::symlink_metadata(path).map_err(|_| unavailable())?;
        if !meta.is_file() || meta.file_type().is_symlink() {
            return Err(integrity());
        }
        let physical = (meta.dev(), meta.ino());
        // Only a currently present alias can establish physical equivalence;
        // stale inode numbers from evicted files must never identify a new file.
        let known = |cache: &Cache| {
            cache
                .identities
                .iter()
                .find_map(|(candidate, (local, identity))| {
                    if *local != physical {
                        return None;
                    }
                    std::fs::symlink_metadata(candidate)
                        .ok()
                        .filter(|meta| {
                            meta.is_file()
                                && !meta.file_type().is_symlink()
                                && (meta.dev(), meta.ino()) == physical
                        })
                        .map(|_| *identity)
                })
        };
        let existing = {
            let cache = lock_cache(self)?;
            known(&cache)
        };
        let allocated = match existing {
            Some(value) => value,
            None => {
                // Sequence allocation can wait on PostgreSQL; it must not hold
                // cache bookkeeping or block unrelated materialization pins.
                let id: i64 = run(async {
                    sqlx_core::query_scalar::query_scalar(
                        "SELECT nextval('devres_archive_accounting_seq')",
                    )
                    .fetch_one(&self.pool)
                    .await
                    .map_err(|_| unavailable())
                })?;
                (u64::MAX, u64::try_from(id).map_err(|_| integrity())?)
            }
        };
        let mut cache = lock_cache(self)?;
        let metadata = std::fs::symlink_metadata(path).map_err(|_| unavailable())?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || (metadata.dev(), metadata.ino()) != physical
        {
            return Err(integrity());
        }
        // Another alias may have won while the sequence was allocated. Adopt
        // its established identity rather than changing physical accounting.
        let identity = known(&cache).unwrap_or(allocated);
        cache
            .identities
            .insert(path.to_owned(), (physical, identity));
        Ok(identity)
    }
}

pub fn check_available(path: &Path) -> Result<()> {
    if let Some(archive) = select(path)? {
        run_bounded(
            Instant::now() + std::time::Duration::from_secs(5),
            &CancellationToken::new(),
            archive.health(),
        )?;
    }
    Ok(())
}
pub fn check_available_with_deadline(
    path: &Path,
    deadline: Instant,
    cancel: &CancellationToken,
) -> Result<()> {
    if let Some(archive) = select(path)? {
        run_bounded(deadline, cancel, archive.health())?;
    }
    Ok(())
}

pub fn retained(path: &Path) -> Result<bool> {
    if let Some(archive) = select(path)? {
        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        let cancel = CancellationToken::new();
        run_bounded(deadline, &cancel, archive.health())?;
        let relative = archive.relative(path)?;
        run_bounded(deadline, &cancel, async {
            sqlx_core::query_scalar::query_scalar("SELECT EXISTS(SELECT 1 FROM devres_archive_file WHERE complete AND (path=$1 OR starts_with(path,$2)))").bind(&relative).bind(format!("{relative}/")).fetch_one(&archive.pool).await.map_err(|_|unavailable())
        })
    } else {
        Ok(path.exists())
    }
}
pub fn materialize_if_retained(
    path: &Path,
    max_bytes: u64,
    deadline: Instant,
    cancel: &CancellationToken,
) -> Result<Option<ArchiveLease>> {
    if let Some(archive) = select(path)? {
        archive.materialize_selected(path, max_bytes, deadline, cancel, true)
    } else if path.exists() {
        Ok(Some(ArchiveLease::default()))
    } else {
        Ok(None)
    }
}
pub fn materialize_file(
    path: &Path,
    max_bytes: u64,
    deadline: Instant,
    cancel: &CancellationToken,
) -> Result<ArchiveLease> {
    let Some(archive) = select(path)? else {
        return Ok(ArchiveLease::default());
    };
    archive.materialize(path, max_bytes, deadline, cancel)
}
pub fn materialize_directory(
    path: &Path,
    max_bytes: u64,
    max_files: usize,
    deadline: Instant,
    cancel: &CancellationToken,
) -> Result<ArchiveLease> {
    let Some(archive) = select(path)? else {
        return Ok(ArchiveLease::default());
    };
    let relative = archive.relative(path)?;
    let files = run_bounded(deadline, cancel, archive.children(&relative, max_files))?;
    if files.is_empty() {
        return Err(integrity());
    }
    files.iter().try_fold(0u64, |total, binding| {
        total
            .checked_add(binding.bytes)
            .filter(|bytes| *bytes <= max_bytes)
            .ok_or_else(capacity)
    })?;
    // Scoped workers are always joined. An error cancels the sibling's I/O,
    // then drains its result before releasing any successful file leases.
    let stopping = cancel.child_token();
    let next = std::sync::atomic::AtomicUsize::new(0);
    let first_error = Mutex::new(None);
    let execute = || {
        std::thread::scope(|scope| {
            let workers: Vec<_> = (0..files.len().min(2))
                .filter_map(|_| {
                    let worker = std::thread::Builder::new().spawn_scoped(scope, || {
                        let mut leases = Vec::new();
                        loop {
                            if stopping.is_cancelled() {
                                break;
                            }
                            let index = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            let Some(binding) = files.get(index) else {
                                break;
                            };
                            match archive.materialize(
                                &archive.root.join(&binding.path),
                                binding.bytes,
                                deadline,
                                &stopping,
                            ) {
                                Ok(lease) => leases.push(lease),
                                Err(error) => {
                                    if let Ok(mut first) = first_error.lock()
                                        && first.is_none()
                                    {
                                        *first = Some(error);
                                    }
                                    stopping.cancel();
                                    break;
                                }
                            }
                        }
                        leases
                    });
                    match worker {
                        Ok(worker) => Some(worker),
                        Err(_) => {
                            stopping.cancel();
                            if let Ok(mut first) = first_error.lock()
                                && first.is_none()
                            {
                                *first = Some(unavailable());
                            }
                            None
                        }
                    }
                })
                .collect();
            let mut leases = Vec::new();
            for worker in workers {
                match worker.join() {
                    Ok(result) => leases.extend(result),
                    Err(_) => {
                        stopping.cancel();
                        if let Ok(mut first) = first_error.lock() {
                            *first = Some(unavailable());
                        }
                    }
                }
            }
            leases
        })
    };
    let leases = if tokio::runtime::Handle::try_current()
        .is_ok_and(|handle| handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
    {
        tokio::task::block_in_place(execute)
    } else {
        execute()
    };
    if let Some(error) = first_error.into_inner().map_err(|_| unavailable())? {
        return Err(error);
    }
    if stopping.is_cancelled() {
        return Err(Error::new("cancelled", "Archive materialization canceled."));
    }
    let paths = leases
        .iter()
        .filter_map(|lease| lease.0.as_ref())
        .flat_map(|lease| lease.paths.iter().cloned())
        .collect();
    let result = {
        let mut cache = lock_materialization(&archive, deadline, cancel)?;
        ArchiveLease::pin(&archive, &mut cache, paths)
    };
    // Lease drops reacquire cache bookkeeping; never drop them under its mutex.
    drop(leases);
    Ok(result)
}

pub(crate) fn publish_file(path: &Path, digest: &str, bytes: u64) -> Result<()> {
    let Some(archive) = select(path)? else {
        return Ok(());
    };
    {
        let mut cache = lock_cache(&archive)?;
        cache.observe(path)?;
        archive.admit(&mut cache, 0, &[path.to_owned()])?;
    }
    run(archive.publish_one(path, digest, bytes))?;
    let mut cache = lock_cache(&archive)?;
    cache.clock = cache.clock.saturating_add(1);
    let touched = cache.clock;
    cache
        .files
        .entry(path.to_owned())
        .or_insert(CacheEntry { pins: 0, touched });
    cache.observe(path)?;
    archive.admit(&mut cache, 0, &[path.to_owned()])
}
pub fn admit_write(path: &Path, bytes: u64) -> Result<()> {
    if let Some(archive) = select(path)? {
        run(archive.health())?;
        let mut cache = lock_cache(&archive)?;
        archive.admit(&mut cache, bytes, &[path.to_owned()])?;
    }
    Ok(())
}
/// Register a just-created local immutable alias before its source stage disappears.
pub fn observe_local(path: &Path) -> Result<()> {
    if let Some(archive) = select(path)? {
        let mut cache = lock_cache(&archive)?;
        cache.observe(path)?;
        archive.admit(&mut cache, 0, &[path.to_owned()])?;
    }
    Ok(())
}
/// Retarget tracked members after an owned staging directory is atomically renamed.
pub fn relocate_local_tree(from: &Path, to: &Path) -> Result<()> {
    if let Some(archive) = select(from)? {
        if !to.starts_with(&archive.root) {
            return Err(integrity());
        }
        let mut cache = lock_cache(&archive)?;
        let members: Vec<_> = cache
            .paths
            .keys()
            .filter(|path| path.starts_with(from))
            .cloned()
            .collect();
        for old in members {
            let target = to.join(old.strip_prefix(from).map_err(|_| integrity())?);
            cache.observe(&target)?;
            cache.detach(&old)?;
        }
    }
    Ok(())
}
/// Release bookkeeping only after an owned local stage has actually disappeared.
pub fn forget_local(path: &Path) -> Result<()> {
    if let Some(archive) = select(path)? {
        let mut cache = lock_cache(&archive)?;
        match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => cache.detach(path)?,
            Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() => cache.observe(path)?,
            Ok(_) => return Err(integrity()),
            Err(_) => return Err(unavailable()),
        }
    }
    Ok(())
}
pub fn with_write_budget<T>(
    path: &Path,
    bytes: u64,
    write: impl FnOnce() -> std::io::Result<T>,
) -> std::io::Result<T> {
    let mapped = |_: Error| std::io::Error::other("Local archive write capacity unavailable.");
    if let Some(archive) = select(path).map_err(mapped)? {
        if mutable_git(&archive.root, path) {
            return write();
        }
        let mut cache = lock_cache(&archive).map_err(mapped)?;
        if !cache.paths.contains_key(path) && cache.paths.len() >= MAX_LOCAL_FILES {
            return Err(mapped(capacity()));
        }
        archive
            .admit(&mut cache, bytes, &[path.to_owned()])
            .map_err(mapped)?;
        let result = write();
        // Failed writes may have persisted a prefix. Charge actual bytes even
        // when the I/O error is propagated; the owner later removes its stage.
        cache.observe(path).map_err(mapped)?;
        result
    } else {
        write()
    }
}

/// Buffer small commit-order records while charging each actual filesystem write.
pub(crate) struct BudgetedStageWriter(std::io::BufWriter<BudgetedStageFile>);
struct BudgetedStageFile {
    path: PathBuf,
    file: std::fs::File,
}
fn blocking_stage_io<T>(operation: impl FnOnce() -> std::io::Result<T>) -> std::io::Result<T> {
    if tokio::runtime::Handle::try_current()
        .is_ok_and(|handle| handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
    {
        tokio::task::block_in_place(operation)
    } else {
        operation()
    }
}
impl std::io::Write for BudgetedStageFile {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        blocking_stage_io(|| {
            with_write_budget(&self.path, bytes.len() as u64, || {
                std::io::Write::write(&mut self.file, bytes)
            })
        })
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl BudgetedStageWriter {
    pub(crate) fn new(path: PathBuf, file: std::fs::File) -> Self {
        Self(std::io::BufWriter::with_capacity(
            64 * 1024,
            BudgetedStageFile { path, file },
        ))
    }
    pub(crate) fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        std::io::Write::write_all(&mut self.0, bytes)
    }
    pub(crate) fn finish(&mut self) -> std::io::Result<()> {
        std::io::Write::flush(&mut self.0)?;
        blocking_stage_io(|| self.0.get_ref().file.sync_all())
    }
}

pub fn is_object_archive(path: &Path) -> Result<bool> {
    select(path).map(|archive| archive.is_some())
}

pub fn accounting_identity(path: &Path) -> Result<Option<(u64, u64)>> {
    let Some(archive) = select(path)? else {
        return Ok(None);
    };
    let relative = archive.relative(path)?;
    if let Some(binding) = run(archive.binding_for(&relative, false))? {
        return Ok(Some((binding.device, binding.inode)));
    }
    archive.local_identity(path).map(Some)
}

/// Bounds optional quota reconstruction independently of permanent retention.
pub const MAX_ACCOUNTING_OBJECTS: usize = 1_000_000;
pub fn retained_accounting(root: &Path) -> Result<Option<Vec<(u64, u64, u64)>>> {
    let Some(archive) = select(root)? else {
        return Ok(None);
    };
    let prefix = if root == archive.root {
        String::new()
    } else {
        format!("{}/", archive.relative(root)?)
    };
    run(async {
        use futures::TryStreamExt;
        let mut rows = sqlx_core::query::query(
            "SELECT path,device,inode,bytes FROM devres_archive_file WHERE starts_with(path,$1) AND substring(path from char_length($1)+1) ~ '^(blake3/)?[0-9a-f]{64}$' LIMIT 1000001",
        )
        .bind(&prefix)
        .fetch(&archive.pool);
        let mut result = Vec::new();
        while let Some(row) = rows.try_next().await.map_err(|_| unavailable())? {
            let path: String = row.try_get("path").map_err(|_| integrity())?;
            let suffix = path.strip_prefix(&prefix).ok_or_else(integrity)?;
            let hash = suffix.strip_prefix("blake3/").unwrap_or(suffix);
            if hash.len() != 64
                || !hash
                    .bytes()
                    .all(|v| v.is_ascii_hexdigit() && !v.is_ascii_uppercase())
            {
                continue;
            }
            let device: String = row.try_get("device").map_err(|_| integrity())?;
            let inode: String = row.try_get("inode").map_err(|_| integrity())?;
            let bytes: i64 = row.try_get("bytes").map_err(|_| integrity())?;
            if result.len() >= MAX_ACCOUNTING_OBJECTS {
                return Err(Error::capacity(
                    "Archive quota object accounting exceeds its bound.",
                ));
            }
            result.push((
                device.parse().map_err(|_| integrity())?,
                inode.parse().map_err(|_| integrity())?,
                u64::try_from(bytes).map_err(|_| integrity())?,
            ));
        }
        Ok(Some(result))
    })
}
fn has_evidence(root: &Path) -> Result<bool> {
    match std::fs::read_dir(root.join(".devres-integrity/files")) {
        Ok(mut entries) => Ok(entries
            .next()
            .transpose()
            .map_err(|_| unavailable())?
            .is_some()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(unavailable()),
    }
}

impl Archive {
    /// Offline transfer never starts listeners or source acquisition.
    pub(crate) async fn transfer(
        self: &Arc<Self>,
        action: &str,
        cancel: CancellationToken,
    ) -> Result<serde_json::Value> {
        if !matches!(
            action,
            "migrate-object-storage" | "verify-object-storage" | "activate-object-storage"
        ) {
            return Err(Error::invalid("Unknown object archive transfer action."));
        }
        self.health().await?;
        let backend: String = sqlx_core::query_scalar::query_scalar(
            "SELECT backend FROM devres_archive_control WHERE singleton",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|_| unavailable())?;
        if backend == "s3" && action != "verify-object-storage" {
            return Err(Error::invalid("Object archive already activated."));
        }
        let inventory = if backend == "filesystem" {
            Some(self.scan_source(&cancel).await?)
        } else {
            None
        };
        if action == "migrate-object-storage" {
            let mut after = String::new();
            loop {
                if cancel.is_cancelled() {
                    return Err(Error::capacity("Object archive transfer canceled."));
                }
                let row:Option<(String,String)>=sqlx_core::query_as::query_as("SELECT path,evidence FROM devres_archive_scan WHERE path>$1 ORDER BY path LIMIT 1").bind(&after).fetch_optional(&self.pool).await.map_err(|_|unavailable())?;
                let Some((path, evidence)) = row else {
                    break;
                };
                let expected: Binding = serde_json::from_str(&evidence).map_err(|_| integrity())?;
                let source = self.root.join(&path);
                let source_hash = expected.digest.clone();
                let bytes = expected.bytes;
                let selected = source.clone();
                let stopping = cancel.clone();
                tokio::task::spawn_blocking(move || {
                    let (digest, length) = crate::integrity::file_digest_local(
                        &selected,
                        bytes,
                        Instant::now() + std::time::Duration::from_secs(24 * 60 * 60),
                        &stopping,
                    )?;
                    if digest != source_hash || length != bytes {
                        return Err(integrity());
                    }
                    Ok(())
                })
                .await
                .map_err(|_| unavailable())??;
                self.publish_one_accounted(
                    &source,
                    &expected.digest,
                    expected.bytes,
                    Some((expected.device, expected.inode)),
                )
                .await?;
                after = path;
            }
        }
        self.verify_remote(&cancel).await?;
        if backend == "filesystem" {
            let missing:i64=sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM devres_archive_scan s LEFT JOIN devres_archive_file f ON f.path=s.path AND f.evidence=s.evidence AND f.complete WHERE f.path IS NULL").fetch_one(&self.pool).await.map_err(|_|unavailable())?;
            if missing != 0 {
                return Err(Error::integrity("Object archive transfer is incomplete."));
            }
        }
        if action == "activate-object-storage" {
            self.activate().await?;
        }
        let files: i64 = sqlx_core::query_scalar::query_scalar(
            "SELECT count(*) FROM devres_archive_file WHERE complete",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|_| unavailable())?;
        Ok(
            serde_json::json!({"version":1,"backend":"s3","action":action,"files":files,"inventory":inventory,"verified":true,"activated":action=="activate-object-storage"||backend=="s3"}),
        )
    }
    async fn scan_source(&self, cancel: &CancellationToken) -> Result<String> {
        {
            let owner_handle = self.owner.upgrade().ok_or_else(unavailable)?;
            let mut owner = owner_handle.lock().await;
            sqlx_core::raw_sql::raw_sql("CREATE TABLE IF NOT EXISTS devres_archive_scan(path text PRIMARY KEY,evidence text NOT NULL); DELETE FROM devres_archive_scan;").execute(&mut *owner).await.map_err(|_|unavailable())?;
        }
        let descriptors = self.root.join(".devres-integrity/files");
        let mut entries = tokio::fs::read_dir(&descriptors)
            .await
            .map_err(|_| unavailable())?;
        while let Some(entry) = entries.next_entry().await.map_err(|_| unavailable())? {
            if cancel.is_cancelled() {
                return Err(Error::capacity("Object archive transfer canceled."));
            }
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                return Err(integrity());
            };
            if name.starts_with(".stage-") {
                continue;
            }
            if name.len() != 69
                || !name.ends_with(".json")
                || !name.as_bytes()[..64]
                    .iter()
                    .copied()
                    .all(|v| v.is_ascii_hexdigit() && !v.is_ascii_uppercase())
            {
                return Err(integrity());
            }
            let metadata = entry.metadata().await.map_err(|_| unavailable())?;
            if !entry
                .file_type()
                .await
                .map_err(|_| unavailable())?
                .is_file()
                || metadata.len() > 16 * 1024
            {
                return Err(integrity());
            }
            let encoded = tokio::fs::read(entry.path())
                .await
                .map_err(|_| unavailable())?;
            let file: crate::integrity::FileEvidence =
                serde_json::from_slice(&encoded).map_err(|_| integrity())?;
            if file.version != 1
                || !logical_path(&file.path)
                || file.path.starts_with(".devres-integrity/")
            {
                return Err(integrity());
            }
            if crate::integrity::evidence_path(&self.root, &self.root.join(&file.path))?
                != entry.path()
            {
                return Err(integrity());
            }
            let source = self.root.join(&file.path);
            let metadata = tokio::fs::symlink_metadata(&source)
                .await
                .map_err(|_| integrity())?;
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.len() != file.bytes
            {
                return Err(integrity());
            }
            let binding = Binding {
                version: 1,
                path: file.path,
                digest: file.digest,
                bytes: file.bytes,
                device: metadata.dev(),
                inode: metadata.ino(),
            };
            binding.validate()?;
            self.scan_row(&binding).await?;
            let meta = entry.metadata().await.map_err(|_| unavailable())?;
            let evidence = Binding {
                version: 1,
                path: self.relative(&entry.path())?,
                digest: crate::integrity::hash(&encoded),
                bytes: encoded.len() as u64,
                device: meta.dev(),
                inode: meta.ino(),
            };
            self.scan_row(&evidence).await?;
        }
        use futures::TryStreamExt;
        let mut hasher = blake3::Hasher::new();
        let mut rows = sqlx_core::query_scalar::query_scalar::<_, String>(
            "SELECT evidence FROM devres_archive_scan ORDER BY path",
        )
        .fetch(&self.pool);
        while let Some(encoded) = rows.try_next().await.map_err(|_| unavailable())? {
            hasher.update(&(encoded.len() as u64).to_le_bytes());
            hasher.update(encoded.as_bytes());
        }
        drop(rows);
        let inventory = format!("blake3:{}", hasher.finalize().to_hex());
        let source_root = self.root.to_str().ok_or_else(integrity)?;
        let owner_handle = self.owner.upgrade().ok_or_else(unavailable)?;
        let mut owner = owner_handle.lock().await;
        sqlx_core::query::query("INSERT INTO devres_archive_transfer(singleton,source_root,inventory) VALUES(true,$1,$2) ON CONFLICT DO NOTHING").bind(source_root).bind(&inventory).execute(&mut *owner).await.map_err(|_|unavailable())?;
        let matches:bool=sqlx_core::query_scalar::query_scalar("SELECT source_root=$1 AND inventory=$2 AND NOT completed FROM devres_archive_transfer WHERE singleton").bind(source_root).bind(&inventory).fetch_one(&mut *owner).await.map_err(|_|unavailable())?;
        if !matches {
            return Err(Error::integrity(
                "Transfer source changed; coordinated recovery required.",
            ));
        }
        Ok(inventory)
    }
    async fn scan_row(&self, binding: &Binding) -> Result<()> {
        let owner_handle = self.owner.upgrade().ok_or_else(unavailable)?;
        let mut owner = owner_handle.lock().await;
        let rows=sqlx_core::query::query("INSERT INTO devres_archive_scan(path,evidence) VALUES($1,$2) ON CONFLICT(path) DO UPDATE SET evidence=EXCLUDED.evidence WHERE devres_archive_scan.evidence=EXCLUDED.evidence").bind(&binding.path).bind(binding.encoded()?).execute(&mut *owner).await.map_err(|_|unavailable())?.rows_affected();
        if rows != 1 {
            return Err(integrity());
        }
        Ok(())
    }
    async fn verify_remote(&self, cancel: &CancellationToken) -> Result<()> {
        let mut after = String::new();
        loop {
            self.fence().await?;
            if cancel.is_cancelled() {
                return Err(Error::capacity("Object archive verification canceled."));
            }
            let row: Option<(String, String)> = sqlx_core::query_as::query_as(
                "SELECT path,evidence FROM devres_archive_file WHERE path>$1 ORDER BY path LIMIT 1",
            )
            .bind(&after)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| unavailable())?;
            let Some((path, evidence)) = row else {
                break;
            };
            let binding: Binding = serde_json::from_str(&evidence).map_err(|_| integrity())?;
            binding.validate()?;
            let key = format!("bindings/{}.json", blake3::hash(path.as_bytes()).to_hex());
            if self
                .remote
                .get_bytes_with_cancel(&key, 16 * 1024, cancel)
                .await?
                != evidence.as_bytes()
            {
                return Err(integrity());
            }
            self.remote
                .verify_object(
                    &binding.object_key()?,
                    &binding.digest,
                    binding.bytes,
                    cancel,
                )
                .await?;
            let owner_handle = self.owner.upgrade().ok_or_else(unavailable)?;
            let mut owner = owner_handle.lock().await;
            sqlx_core::query::query("UPDATE devres_archive_file SET complete=true WHERE path=$1 AND evidence=$2 AND epoch=$3").bind(&path).bind(&evidence).bind(self.epoch).execute(&mut *owner).await.map_err(|_|unavailable())?;
            after = path;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "durable_archive/materialization_tests.rs"]
mod materialization_tests;
