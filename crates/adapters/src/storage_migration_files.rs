//! Bounded offline filesystem qualification; public publication helpers are unchanged.
use super::{PgBlobStore, canceled, mapping_digest, storage_error};
use crate::integrity::{self, FileEvidence};
use devres_domain::{Error, Result};
use sha2::{Digest, Sha256};
use sqlx::{Connection, Row};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;

const FILES: usize = 128;
const METADATA_BYTES: usize = 8 * 1024 * 1024;
const DESCRIPTOR_BYTES: usize = 16 * 1024;
// A source/target path accepted by the filesystem is bounded by PATH_MAX; this
// reserve also includes its descriptor and every retained path copy.
const ENTRY_METADATA_BYTES: usize = 64 * 1024;
static STAGE: AtomicU64 = AtomicU64::new(0);

/// Linux 5.8 added syncfs writeback-error reporting. Other platforms use the
/// existing per-file durable path instead of weakening its error contract.
pub(super) fn supported() -> bool {
    #[cfg(target_os = "linux")]
    {
        let Ok(file) = File::open("/proc/sys/kernel/osrelease") else {
            return false;
        };
        let mut release = String::new();
        if file.take(129).read_to_string(&mut release).is_err() || release.len() > 128 {
            return false;
        }
        kernel_supported(&release)
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

fn kernel_supported(release: &str) -> bool {
    let mut parts = release.trim().split('.');
    let major = parts.next().and_then(|part| part.parse::<u32>().ok());
    let minor = parts.next().and_then(|part| part.parse::<u32>().ok());
    matches!((major, minor), (Some(major), Some(minor)) if major > 5 || (major == 5 && minor >= 8))
}

struct Qualified {
    source: PathBuf,
    relative: String,
    digest: String,
    bytes: u64,
    descriptor: PathBuf,
    encoded: Vec<u8>,
    stage: Option<PathBuf>,
    alias: Option<String>,
    canonical: Option<PathBuf>,
    dev: u64,
    inode: u64,
}

impl Qualified {
    fn metadata_bytes(&self) -> usize {
        self.source.as_os_str().len()
            + self.relative.len()
            + self.digest.len()
            + self.descriptor.as_os_str().len()
            + self.encoded.len()
            + self.stage.as_ref().map_or(0, |path| path.as_os_str().len())
            + self.alias.as_ref().map_or(0, String::len)
            + self
                .canonical
                .as_ref()
                .map_or(0, |path| path.as_os_str().len())
    }
}

impl Drop for Qualified {
    fn drop(&mut self) {
        if let Some(stage) = &self.stage {
            let _ = std::fs::remove_file(stage);
        }
    }
}

#[derive(Default)]
struct Batch {
    entries: Vec<Qualified>,
    bytes: usize,
}

impl Batch {
    fn fits(&self, entry: &Qualified) -> bool {
        self.entries.len() < FILES
            && self
                .bytes
                .checked_add(entry.metadata_bytes())
                .is_some_and(|n| n <= METADATA_BYTES)
    }

    fn push(&mut self, entry: Qualified) -> Result<()> {
        if !self.fits(&entry) {
            return Err(Error::capacity(
                "Migration file batch metadata exceeded its bound.",
            ));
        }
        self.bytes += entry.metadata_bytes();
        self.entries.push(entry);
        Ok(())
    }
}

/// Only a successful second barrier can construct this SQL-publication permit.
struct DurableBatch(Vec<Qualified>);

fn open_nofollow(path: &Path) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| storage_error())
}

fn root_file(root: &Path) -> Result<File> {
    if !root.is_absolute()
        || root
            .components()
            .any(|p| matches!(p, Component::CurDir | Component::ParentDir))
    {
        return Err(Error::integrity("Invalid retained storage root."));
    }
    for ancestor in root.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor).map_err(|_| storage_error())?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(Error::integrity("Invalid retained storage directory."));
        }
    }
    let file = open_nofollow(root)?;
    if !file.metadata().map_err(|_| storage_error())?.is_dir() {
        return Err(Error::integrity("Invalid retained storage root."));
    }
    Ok(file)
}

/// Validate each existing component, creating only directories under this root.
/// Cross-device directories request the unchanged serial path, never omission.
fn directories(root: &Path, path: &Path, dev: u64, create: bool) -> Result<bool> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| Error::integrity("Invalid retained directory."))?;
    let mut current = root.to_path_buf();
    let mut same_device = true;
    for component in relative.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err(Error::integrity("Invalid retained directory."));
        }
        current.push(component);
        let metadata = match std::fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if create && error.kind() == std::io::ErrorKind::NotFound => {
                match std::fs::create_dir(&current) {
                    Ok(()) => (),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
                    Err(_) => return Err(storage_error()),
                }
                std::fs::symlink_metadata(&current).map_err(|_| storage_error())?
            }
            Err(_) => return Err(storage_error()),
        };
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(Error::integrity("Unexpected retained storage link."));
        }
        if metadata.dev() != dev {
            same_device = false;
        }
    }
    Ok(same_device)
}

fn same_file(path: &Path, entry: &Qualified) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| storage_error())?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.dev() != entry.dev
        || metadata.ino() != entry.inode
        || metadata.len() != entry.bytes
    {
        return Err(Error::integrity("Retained migration source changed."));
    }
    Ok(())
}

fn compare_descriptor(path: &Path, expected: &[u8], dev: u64) -> Result<()> {
    let mut file = open_nofollow(path)?;
    let metadata = file.metadata().map_err(|_| storage_error())?;
    if !metadata.is_file() || metadata.dev() != dev || metadata.len() != expected.len() as u64 {
        return Err(Error::integrity("Conflicting retained integrity evidence."));
    }
    let mut bytes = Vec::with_capacity(expected.len());
    (&mut file)
        .take(expected.len() as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| storage_error())?;
    if bytes != expected {
        return Err(Error::integrity("Conflicting retained integrity evidence."));
    }
    Ok(())
}

fn hash_source(
    path: &Path,
    expected_sha: Option<&str>,
    cancel: &CancellationToken,
) -> Result<(String, u64, u64, u64)> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| storage_error())?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > crate::bulk::MAX_ARTIFACT_BYTES
    {
        return Err(Error::integrity("Invalid retained file."));
    }
    let mut file = open_nofollow(path)?;
    let opened = file.metadata().map_err(|_| storage_error())?;
    if !opened.is_file() || opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
        return Err(Error::integrity("Retained migration source changed."));
    }
    let mut b3 = blake3::Hasher::new();
    let mut sha = expected_sha.map(|_| Sha256::new());
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 65536];
    let deadline = Instant::now() + Duration::from_secs(3600);
    loop {
        canceled(cancel)?;
        if Instant::now() >= deadline {
            return Err(Error::capacity(
                "Retained file verification deadline exceeded.",
            ));
        }
        let count = file.read(&mut buffer).map_err(|_| storage_error())?;
        if count == 0 {
            break;
        }
        bytes = bytes
            .checked_add(count as u64)
            .filter(|n| *n <= crate::bulk::MAX_ARTIFACT_BYTES)
            .ok_or_else(|| Error::capacity("Retained file verification bound exceeded."))?;
        b3.update(&buffer[..count]);
        if let Some(sha) = &mut sha {
            sha.update(&buffer[..count]);
        }
    }
    if bytes != metadata.len() {
        return Err(Error::integrity("Retained file length changed."));
    }
    if let (Some(expected), Some(sha)) = (expected_sha, sha)
        && hex::encode(sha.finalize()) != expected
    {
        return Err(Error::integrity("Corrupt legacy source object."));
    }
    Ok((
        format!("blake3:{}", b3.finalize().to_hex()),
        bytes,
        metadata.dev(),
        metadata.ino(),
    ))
}

fn prepare(
    root: &Path,
    path: &Path,
    dev: u64,
    cancel: &CancellationToken,
) -> Result<Option<Qualified>> {
    canceled(cancel)?;
    let parent = path.parent().ok_or_else(storage_error)?;
    if !directories(root, parent, dev, false)? {
        return Ok(None);
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|_| storage_error())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Error::integrity("Unexpected retained storage link."));
    }
    if metadata.dev() != dev {
        return Ok(None);
    }
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| Error::integrity("Invalid retained path."))?;
    let parent_name = parent.file_name().and_then(|n| n.to_str());
    let alias = integrity::valid_hash(name)
        && !name.starts_with("blake3:")
        && parent_name != Some("blake3");
    let manifest = name
        .strip_suffix(".json")
        .filter(|hex| integrity::valid_hash(hex))
        .filter(|_| {
            parent_name == Some("manifests")
                && parent
                    .parent()
                    .and_then(Path::file_name)
                    .and_then(|n| n.to_str())
                    != Some("blake3")
        });
    let (digest, bytes, dev, inode) =
        hash_source(path, if alias { Some(name) } else { manifest }, cancel)?;
    let relative = path
        .strip_prefix(root)
        .ok()
        .and_then(Path::to_str)
        .ok_or_else(|| Error::integrity("Invalid retained path."))?
        .to_owned();
    let evidence = FileEvidence {
        version: 1,
        path: relative.clone(),
        bytes,
        digest: digest.clone(),
    };
    let encoded = serde_json::to_vec(&evidence).map_err(|_| storage_error())?;
    if encoded.len() > DESCRIPTOR_BYTES {
        return Err(Error::capacity("File evidence exceeds its bound."));
    }
    let descriptor = integrity::evidence_path(root, path)?;
    let descriptor_parent = descriptor.parent().ok_or_else(storage_error)?.to_owned();
    if !directories(root, &descriptor_parent, dev, true)? {
        return Ok(None);
    }
    let canonical = if alias {
        let canonical = parent.join(integrity::relative_path(&digest)?);
        if !directories(
            root,
            canonical.parent().ok_or_else(storage_error)?,
            dev,
            true,
        )? {
            return Ok(None);
        }
        match std::fs::symlink_metadata(&canonical) {
            Ok(metadata) if metadata.dev() != dev => return Ok(None),
            Ok(_) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err(storage_error()),
        }
        Some(canonical)
    } else {
        None
    };
    let mut entry = Qualified {
        source: path.to_owned(),
        relative,
        digest,
        bytes,
        descriptor,
        encoded,
        stage: None,
        alias: alias.then(|| name.to_owned()),
        canonical,
        dev,
        inode,
    };
    match std::fs::symlink_metadata(&entry.descriptor) {
        Ok(metadata) if metadata.dev() != dev => return Ok(None),
        Ok(_) => {
            compare_descriptor(&entry.descriptor, &entry.encoded, dev)?;
            return Ok(Some(entry));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(_) => return Err(storage_error()),
    }
    let mut selected = None;
    for _ in 0..1024 {
        let stage = descriptor_parent.join(format!(
            ".stage-{}-{}",
            std::process::id(),
            STAGE.fetch_add(1, Ordering::Relaxed)
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&stage)
        {
            Ok(file) => {
                entry.stage = Some(stage);
                selected = Some(file);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(_) => return Err(storage_error()),
        }
    }
    let mut file = selected.ok_or_else(|| Error::capacity("Migration staging slots exhausted."))?;
    file.write_all(&entry.encoded)
        .map_err(|_| storage_error())?;
    Ok(Some(entry))
}

fn publish(
    batch: Batch,
    root: &Path,
    dev: u64,
    cancel: &CancellationToken,
    mut barrier: impl FnMut() -> Result<()>,
) -> Result<DurableBatch> {
    // First persist every stage byte before introducing any final descriptor name.
    barrier()?;
    for entry in &batch.entries {
        canceled(cancel)?;
        if !directories(
            root,
            entry.source.parent().ok_or_else(storage_error)?,
            dev,
            false,
        )? || !directories(
            root,
            entry.descriptor.parent().ok_or_else(storage_error)?,
            dev,
            false,
        )? {
            return Err(Error::integrity(
                "Migration filesystem changed during publication.",
            ));
        }
        same_file(&entry.source, entry)?;
        if let Some(stage) = &entry.stage {
            match std::fs::hard_link(stage, &entry.descriptor) {
                Ok(()) => (),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
                Err(_) => return Err(storage_error()),
            }
        }
        compare_descriptor(&entry.descriptor, &entry.encoded, dev)?;
        if let Some(canonical) = &entry.canonical {
            if !directories(
                root,
                canonical.parent().ok_or_else(storage_error)?,
                dev,
                false,
            )? {
                return Err(Error::integrity(
                    "Migration filesystem changed during publication.",
                ));
            }
            match std::fs::hard_link(&entry.source, canonical) {
                Ok(()) => (),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let (digest, bytes, target_dev, _) = hash_source(canonical, None, cancel)?;
                    if digest != entry.digest || bytes != entry.bytes || target_dev != dev {
                        return Err(Error::integrity("Conflicting BLAKE3 object."));
                    }
                }
                Err(_) => return Err(storage_error()),
            }
        }
    }
    // SQL is forbidden until all final namespace entries survive power loss.
    canceled(cancel)?;
    barrier()?;
    Ok(DurableBatch(batch.entries))
}

async fn persist_sql(
    store: &PgBlobStore,
    batch: DurableBatch,
    cancel: &CancellationToken,
) -> Result<()> {
    canceled(cancel)?;
    store.fence().await?;
    let mut owner = store.owner.lock().await;
    let mut tx = owner.begin().await.map_err(|_| storage_error())?;
    let paths: Vec<_> = batch.0.iter().map(|e| e.relative.as_str()).collect();
    let digests: Vec<_> = batch.0.iter().map(|e| e.digest.as_str()).collect();
    let sizes: Vec<_> = batch.0.iter().map(|e| e.bytes as i64).collect();
    let aliases: Vec<_> = batch
        .0
        .iter()
        .filter_map(|e| {
            e.alias
                .as_ref()
                .map(|old| (old.as_str(), e.digest.as_str()))
        })
        .collect();
    let old: Vec<_> = aliases.iter().map(|(old, _)| *old).collect();
    let canonical: Vec<_> = aliases.iter().map(|(_, new)| *new).collect();
    let proofs: Vec<_> = aliases
        .iter()
        .map(|(old, new)| mapping_digest("body", old, new))
        .collect::<Result<_>>()?;
    let result: Result<()> = async {
        sqlx::query("INSERT INTO devres_integrity_files(path,digest,bytes) SELECT * FROM UNNEST($1::text[],$2::text[],$3::bigint[]) ON CONFLICT(path) DO NOTHING")
            .bind(&paths).bind(&digests).bind(&sizes).execute(&mut *tx).await.map_err(|_| storage_error())?;
        sqlx::query("INSERT INTO devres_content_aliases(namespace,legacy,canonical,mapping_integrity) SELECT 'body',* FROM UNNEST($1::text[],$2::text[],$3::text[]) ON CONFLICT DO NOTHING")
            .bind(&old).bind(&canonical).bind(&proofs).execute(&mut *tx).await.map_err(|_| storage_error())?;
        verify_sql(&mut tx, &batch, &paths, &old).await?;
        canceled(cancel)?;
        Ok(())
    }.await;
    if let Err(error) = result {
        tx.rollback().await.map_err(|_| storage_error())?;
        return Err(error);
    }
    tx.commit().await.map_err(|_| storage_error())?;
    verify_sql(&mut owner, &batch, &paths, &old).await?;
    Ok(())
}

async fn verify_sql(
    connection: &mut sqlx::PgConnection,
    batch: &DurableBatch,
    paths: &[&str],
    aliases: &[&str],
) -> Result<()> {
    let files =
        sqlx::query("SELECT path,digest,bytes FROM devres_integrity_files WHERE path=ANY($1)")
            .bind(paths)
            .fetch_all(&mut *connection)
            .await
            .map_err(|_| storage_error())?;
    for entry in &batch.0 {
        let prior = files
            .iter()
            .find(|row| {
                row.try_get::<String, _>("path")
                    .is_ok_and(|p| p == entry.relative)
            })
            .ok_or_else(storage_error)?;
        if prior
            .try_get::<String, _>("digest")
            .map_err(|_| storage_error())?
            != entry.digest
            || prior
                .try_get::<i64, _>("bytes")
                .map_err(|_| storage_error())?
                != entry.bytes as i64
        {
            return Err(Error::integrity("Retained migration checkpoint changed."));
        }
    }
    let rows = sqlx::query("SELECT legacy,canonical,mapping_integrity FROM devres_content_aliases WHERE namespace='body' AND legacy=ANY($1)")
        .bind(aliases).fetch_all(&mut *connection).await.map_err(|_| storage_error())?;
    for entry in &batch.0 {
        if let Some(old) = &entry.alias {
            let prior = rows
                .iter()
                .find(|row| row.try_get::<String, _>("legacy").is_ok_and(|v| v == *old))
                .ok_or_else(storage_error)?;
            let canonical: String = prior.try_get("canonical").map_err(|_| storage_error())?;
            let proof: Option<String> = prior
                .try_get("mapping_integrity")
                .map_err(|_| storage_error())?;
            if canonical != entry.digest
                || proof.as_deref() != Some(mapping_digest("body", old, &entry.digest)?.as_str())
            {
                return Err(Error::integrity("Conflicting retained content mapping."));
            }
        }
    }
    Ok(())
}

async fn flush(
    store: &PgBlobStore,
    batch: &mut Batch,
    root_fd: &Arc<File>,
    dev: u64,
    cancel: &CancellationToken,
) -> Result<()> {
    if batch.entries.is_empty() {
        return Ok(());
    }
    canceled(cancel)?;
    let pending = std::mem::take(batch);
    let root = store.root.clone();
    let fd = Arc::clone(root_fd);
    let token = cancel.clone();
    let durable = tokio::task::spawn_blocking(move || {
        publish(pending, &root, dev, &token, || {
            #[cfg(target_os = "linux")]
            {
                nix::unistd::syncfs(fd.as_ref()).map_err(|_| storage_error())
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = &fd;
                Err(storage_error())
            }
        })
    })
    .await
    .map_err(|_| storage_error())??;
    persist_sql(store, durable, cancel).await
}

pub(super) async fn qualify(store: &PgBlobStore, cancel: &CancellationToken) -> Result<()> {
    let root = store.root.clone();
    let opened = root.clone();
    let fd = Arc::new(
        tokio::task::spawn_blocking(move || root_file(&opened))
            .await
            .map_err(|_| storage_error())??,
    );
    let dev = fd.metadata().map_err(|_| storage_error())?.dev();
    let mut batch = Batch::default();
    let mut tree = super::walk::Tree::new(&root).await?;
    while let Some(item) = tree.next(cancel).await? {
        let super::walk::Item::File(path) = item else {
            continue;
        };
        // Reserve room before staging the next entry, so neither the
        // temporary 129th file nor its metadata exceeds the batch bound.
        if batch.entries.len() == FILES || batch.bytes > METADATA_BYTES - ENTRY_METADATA_BYTES {
            flush(store, &mut batch, &fd, dev, cancel).await?;
        }
        let (source, base, token) = (path.clone(), root.clone(), cancel.clone());
        let entry = tokio::task::spawn_blocking(move || prepare(&base, &source, dev, &token))
            .await
            .map_err(|_| storage_error())??;
        if let Some(entry) = entry {
            if entry.metadata_bytes() > ENTRY_METADATA_BYTES {
                return Err(Error::capacity(
                    "Migration file metadata exceeded its bound.",
                ));
            }
            if !batch.fits(&entry) {
                flush(store, &mut batch, &fd, dev, cancel).await?;
            }
            batch.push(entry)?;
        } else {
            flush(store, &mut batch, &fd, dev, cancel).await?;
            store.qualify_file(&path, cancel).await?;
        }
    }
    flush(store, &mut batch, &fd, dev, cancel).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, PathBuf, u64) {
        let directory = tempfile::Builder::new()
            .prefix("devres-file-batch-")
            .tempdir_in("/tmp")
            .unwrap();
        let root = directory.path().to_owned();
        let dev = root_file(&root).unwrap().metadata().unwrap().dev();
        (directory, root, dev)
    }

    fn staged(root: &Path, dev: u64, name: &str) -> Qualified {
        let path = root.join(name);
        std::fs::write(&path, b"retained public source").unwrap();
        prepare(root, &path, dev, &CancellationToken::new())
            .unwrap()
            .unwrap()
    }

    #[test]
    fn kernel_error_reporting_floor_is_explicit() {
        assert!(!kernel_supported("5.7.99"));
        assert!(kernel_supported("5.8.0-custom"));
        assert!(kernel_supported("7.0.1"));
        assert!(!kernel_supported("garbage"));
    }

    #[test]
    fn first_barrier_failure_never_exposes_a_final_descriptor() {
        let (_temporary, root, dev) = fixture();
        let entry = staged(&root, dev, "source.txt");
        let target = entry.descriptor.clone();
        let stage = entry.stage.clone().unwrap();
        let mut batch = Batch::default();
        batch.push(entry).unwrap();
        assert!(
            publish(batch, &root, dev, &CancellationToken::new(), || Err(
                storage_error()
            ))
            .is_err()
        );
        assert!(!target.exists());
        assert!(!stage.exists());
    }

    #[test]
    fn second_barrier_failure_forbids_commit_and_resume_rechecks_final_bytes() {
        let (_temporary, root, dev) = fixture();
        let entry = staged(&root, dev, "source.txt");
        let target = entry.descriptor.clone();
        let mut batch = Batch::default();
        batch.push(entry).unwrap();
        let mut calls = 0;
        let result = publish(batch, &root, dev, &CancellationToken::new(), || {
            calls += 1;
            if calls == 2 {
                Err(storage_error())
            } else {
                Ok(())
            }
        });
        assert!(result.is_err());
        assert!(target.is_file());
        let entry = prepare(
            &root,
            &root.join("source.txt"),
            dev,
            &CancellationToken::new(),
        )
        .unwrap()
        .unwrap();
        assert!(entry.stage.is_none());
        let mut retry = Batch::default();
        retry.push(entry).unwrap();
        let mut calls = 0;
        let durable = publish(retry, &root, dev, &CancellationToken::new(), || {
            calls += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(calls, 2);
        assert_eq!(durable.0.len(), 1);
        std::fs::write(target, b"conflict").unwrap();
        assert!(
            prepare(
                &root,
                &root.join("source.txt"),
                dev,
                &CancellationToken::new()
            )
            .is_err()
        );
    }

    #[test]
    fn canonical_links_appear_between_barriers_and_legacy_checks_remain_authoritative() {
        let (_temporary, root, dev) = fixture();
        let body = b"retained public source";
        let legacy = hex::encode(Sha256::digest(body));
        let entry = staged(&root, dev, &legacy);
        let target = entry.canonical.clone().unwrap();
        let descriptor = entry.descriptor.clone();
        let mut batch = Batch::default();
        batch.push(entry).unwrap();
        let mut calls = 0;
        let durable = publish(batch, &root, dev, &CancellationToken::new(), || {
            calls += 1;
            assert_eq!(target.exists(), calls == 2);
            assert_eq!(descriptor.exists(), calls == 2);
            Ok(())
        })
        .unwrap();
        assert_eq!(durable.0[0].alias.as_deref(), Some(legacy.as_str()));
        assert_eq!(std::fs::read(target).unwrap(), body);
        std::fs::write(root.join(&legacy), b"corrupted").unwrap();
        assert!(prepare(&root, &root.join(legacy), dev, &CancellationToken::new()).is_err());
    }

    #[test]
    fn symlink_sources_parents_and_descriptors_are_never_followed() {
        let (_temporary, root, dev) = fixture();
        let source = root.join("source");
        std::fs::write(&source, b"data").unwrap();
        std::os::unix::fs::symlink(&source, root.join("link")).unwrap();
        assert!(prepare(&root, &root.join("link"), dev, &CancellationToken::new()).is_err());
        let entry = staged(&root, dev, "retained");
        let target = entry.descriptor.clone();
        drop(entry);
        std::os::unix::fs::symlink(&source, &target).unwrap();
        assert!(
            prepare(
                &root,
                &root.join("retained"),
                dev,
                &CancellationToken::new()
            )
            .is_err()
        );
        std::fs::create_dir(root.join("directory")).unwrap();
        std::os::unix::fs::symlink(root.join("directory"), root.join("parent-link")).unwrap();
        assert!(directories(&root, &root.join("parent-link"), dev, false).is_err());
    }

    #[test]
    fn batch_count_and_metadata_limits_are_independent() {
        let (_temporary, root, dev) = fixture();
        let mut batch = Batch::default();
        for i in 0..FILES {
            batch
                .push(staged(&root, dev, &format!("source-{i}")))
                .unwrap();
        }
        assert!(!batch.fits(&staged(&root, dev, "overflow")));
        let mut oversized = staged(&root, dev, "metadata-overflow");
        oversized.encoded.resize(METADATA_BYTES, 0);
        assert!(Batch::default().push(oversized).is_err());
    }

    #[test]
    fn unsupported_filesystem_requests_serial_fallback_without_final_publication() {
        let (_temporary, root, dev) = fixture();
        let path = root.join("source");
        std::fs::write(&path, b"data").unwrap();
        assert!(
            prepare(&root, &path, dev.wrapping_add(1), &CancellationToken::new())
                .unwrap()
                .is_none()
        );
        assert!(!integrity::evidence_path(&root, &path).unwrap().exists());
    }
}
