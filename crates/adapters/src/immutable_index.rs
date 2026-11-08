//! Tantivy access to verified, permanently immutable published index directories.
//!
//! Readers need no filesystem lock: published shards are never rewritten.
//! Callers verify their retained file descriptors and retain the archive cache
//! lease for the complete reader lifetime, preventing local eviction. Writable
//! staging indexes use a separate directory with physical-write admission.
use std::{
    io::{self, BufWriter, Write},
    path::{Component, Path, PathBuf},
    sync::Arc,
};
use tantivy::{
    Index, IndexSettings,
    directory::{
        AntiCallToken, Directory, DirectoryLock, FileHandle, Lock, META_LOCK, MmapDirectory,
        TerminatingWrite, WatchCallback, WatchHandle, WritePtr,
        error::{DeleteError, LockError, OpenReadError, OpenWriteError},
    },
};

#[derive(Clone, Debug)]
struct ImmutableDirectory {
    inner: MmapDirectory,
}
fn read_only() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "Published index directory is immutable.",
    )
}
fn checked_path(path: &Path) -> Result<(), OpenReadError> {
    let mut components = path.components();
    if matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none() {
        Ok(())
    } else {
        Err(OpenReadError::wrap_io_error(read_only(), path.to_owned()))
    }
}
impl Directory for ImmutableDirectory {
    fn get_file_handle(&self, path: &Path) -> Result<Arc<dyn FileHandle>, OpenReadError> {
        checked_path(path)?;
        self.inner.get_file_handle(path)
    }
    fn exists(&self, path: &Path) -> Result<bool, OpenReadError> {
        checked_path(path)?;
        self.inner.exists(path)
    }
    fn atomic_read(&self, path: &Path) -> Result<Vec<u8>, OpenReadError> {
        checked_path(path)?;
        self.inner.atomic_read(path)
    }
    fn delete(&self, path: &Path) -> Result<(), DeleteError> {
        Err(DeleteError::IoError {
            io_error: Arc::new(read_only()),
            filepath: path.to_owned(),
        })
    }
    fn open_write(&self, path: &Path) -> Result<WritePtr, OpenWriteError> {
        Err(OpenWriteError::wrap_io_error(read_only(), path.to_owned()))
    }
    fn atomic_write(&self, _path: &Path, _data: &[u8]) -> io::Result<()> {
        Err(read_only())
    }
    fn sync_directory(&self) -> io::Result<()> {
        Err(read_only())
    }
    fn acquire_lock(&self, lock: &Lock) -> Result<DirectoryLock, LockError> {
        if lock.filepath == META_LOCK.filepath {
            // META_LOCK protects readers from concurrent segment collection.
            // Permanent immutable shards cannot have a writer or a collector.
            Ok(DirectoryLock::from(Box::new(())))
        } else {
            Err(LockError::wrap_io_error(read_only()))
        }
    }
    fn watch(&self, _callback: WatchCallback) -> tantivy::Result<WatchHandle> {
        Ok(WatchHandle::empty())
    }
}
pub(crate) fn open(path: &Path) -> tantivy::Result<Index> {
    Index::open(ImmutableDirectory {
        inner: MmapDirectory::open(path)?,
    })
}

/// Writable staging directories use the same archive-wide disk admission as
/// uploads/downloads. Every physical write is checked while holding that budget,
/// including Tantivy's background writer threads and atomic metadata updates.
#[derive(Clone, Debug)]
struct BudgetedDirectory {
    inner: MmapDirectory,
    path: PathBuf,
}
struct BudgetedWriter {
    inner: Box<dyn TerminatingWrite + Send + Sync>,
    path: PathBuf,
}
impl Write for BudgetedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        crate::durable_archive::with_write_budget(&self.path, bytes.len() as u64, || {
            self.inner.write(bytes)
        })
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
impl TerminatingWrite for BudgetedWriter {
    fn terminate_ref(&mut self, token: AntiCallToken) -> io::Result<()> {
        self.inner.terminate_ref(token)
    }
}
impl Directory for BudgetedDirectory {
    fn get_file_handle(&self, path: &Path) -> Result<Arc<dyn FileHandle>, OpenReadError> {
        checked_path(path)?;
        self.inner.get_file_handle(path)
    }
    fn exists(&self, path: &Path) -> Result<bool, OpenReadError> {
        checked_path(path)?;
        self.inner.exists(path)
    }
    fn atomic_read(&self, path: &Path) -> Result<Vec<u8>, OpenReadError> {
        checked_path(path)?;
        self.inner.atomic_read(path)
    }
    fn delete(&self, path: &Path) -> Result<(), DeleteError> {
        self.inner.delete(path)
    }
    fn open_write(&self, path: &Path) -> Result<WritePtr, OpenWriteError> {
        let inner = self.inner.open_write(path)?.into_inner().map_err(|_| {
            OpenWriteError::wrap_io_error(
                io::Error::other("Index writer initialization failed."),
                path.to_owned(),
            )
        })?;
        Ok(BufWriter::new(Box::new(BudgetedWriter {
            inner,
            path: self.path.join(path),
        })))
    }
    fn atomic_write(&self, path: &Path, data: &[u8]) -> io::Result<()> {
        crate::durable_archive::with_write_budget(&self.path.join(path), data.len() as u64, || {
            self.inner.atomic_write(path, data)
        })
    }
    fn sync_directory(&self) -> io::Result<()> {
        self.inner.sync_directory()
    }
    fn acquire_lock(&self, lock: &Lock) -> Result<DirectoryLock, LockError> {
        self.inner.acquire_lock(lock)
    }
    fn watch(&self, callback: WatchCallback) -> tantivy::Result<WatchHandle> {
        self.inner.watch(callback)
    }
}
fn writable(path: &Path) -> tantivy::Result<BudgetedDirectory> {
    Ok(BudgetedDirectory {
        inner: MmapDirectory::open(path)?,
        path: path.to_owned(),
    })
}
pub(crate) fn create_staging(
    path: &Path,
    schema: tantivy::schema::Schema,
) -> tantivy::Result<Index> {
    Index::create(writable(path)?, schema, IndexSettings::default())
}
pub(crate) fn open_staging(path: &Path) -> tantivy::Result<Index> {
    Index::open(writable(path)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use tantivy::{
        TantivyDocument,
        collector::Count,
        directory::INDEX_WRITER_LOCK,
        query::AllQuery,
        schema::{Schema, TEXT},
    };

    fn files(path: &Path) -> BTreeMap<std::ffi::OsString, Vec<u8>> {
        std::fs::read_dir(path)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (entry.file_name(), std::fs::read(entry.path()).unwrap())
            })
            .collect()
    }
    #[test]
    fn published_index_reads_without_locks_and_rejects_every_write() {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let mut schema = Schema::builder();
        let text = schema.add_text_field("text", TEXT);
        {
            let index = Index::create_in_dir(root.path(), schema.build()).unwrap();
            let mut writer = index.writer::<TantivyDocument>(15_000_000).unwrap();
            writer
                .add_document(tantivy::doc!(text=>"immutable published fixture"))
                .unwrap();
            writer.commit().unwrap();
            writer.wait_merging_threads().unwrap();
        }
        for lock in [&META_LOCK.filepath, &INDEX_WRITER_LOCK.filepath] {
            match std::fs::remove_file(root.path().join(lock)) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => panic!("remove completed fixture lock: {error}"),
            }
        }
        let before = files(root.path());
        let index = open(root.path()).unwrap();
        let reader = index.reader().unwrap();
        assert_eq!(reader.searcher().search(&AllQuery, &Count).unwrap(), 1);
        assert!(index.writer::<TantivyDocument>(15_000_000).is_err());
        let directory = ImmutableDirectory {
            inner: MmapDirectory::open(root.path()).unwrap(),
        };
        assert!(directory.acquire_lock(&META_LOCK).is_ok());
        assert!(directory.acquire_lock(&INDEX_WRITER_LOCK).is_err());
        assert!(
            directory
                .acquire_lock(&Lock {
                    filepath: "other.lock".into(),
                    is_blocking: false
                })
                .is_err()
        );
        assert!(directory.open_write(Path::new("new-file")).is_err());
        assert!(
            directory
                .atomic_write(Path::new("meta.json"), b"corrupt")
                .is_err()
        );
        assert!(directory.delete(Path::new("meta.json")).is_err());
        assert!(directory.sync_directory().is_err());
        assert!(directory.atomic_read(Path::new("../outside")).is_err());
        let _watch = directory
            .watch(WatchCallback::new(|| panic!("immutable watch invoked")))
            .unwrap();
        drop(reader);
        drop(index);
        assert_eq!(before, files(root.path()));
        assert!(!root.path().join(&META_LOCK.filepath).exists());
        assert!(!root.path().join(&INDEX_WRITER_LOCK.filepath).exists());
    }
}
