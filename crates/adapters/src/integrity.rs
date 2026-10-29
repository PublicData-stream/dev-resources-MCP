//! Algorithm-explicit content integrity. Legacy SHA-256 is compatibility evidence only.
use devres_domain::{Error, Result};
use sha2::{Digest, Sha256};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::{io::Read, path::Path, time::Instant};

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileEvidence {
    pub version: u32,
    pub path: String,
    pub bytes: u64,
    pub digest: String,
}

/// Streaming verification under the caller's existing admission/deadline.
pub fn file_digest(path: &Path, max_bytes: u64, deadline: Instant) -> Result<(String, u64)> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| Error::integrity("Retained file unavailable."))?;
    if !metadata.is_file() || metadata.len() > max_bytes {
        return Err(Error::integrity("Invalid retained file."));
    }
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| Error::integrity("Retained file unavailable."))?;
    let mut hasher = blake3::Hasher::new();
    let mut count = 0_u64;
    let mut buffer = [0_u8; 65536];
    loop {
        if Instant::now() >= deadline {
            return Err(Error::capacity(
                "Retained file verification deadline exceeded.",
            ));
        }
        let n = file
            .read(&mut buffer)
            .map_err(|_| Error::integrity("Retained file read failed."))?;
        if n == 0 {
            break;
        }
        count = count
            .checked_add(n as u64)
            .filter(|v| *v <= max_bytes)
            .ok_or_else(|| Error::capacity("Retained file verification bound exceeded."))?;
        hasher.update(&buffer[..n]);
    }
    if count != metadata.len() {
        return Err(Error::integrity("Retained file length changed."));
    }
    Ok((format!("blake3:{}", hasher.finalize().to_hex()), count))
}

pub fn evidence_path(root: &Path, path: &Path) -> Result<PathBuf> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| Error::integrity("Retained file is outside its storage root."))?;
    let relative = relative
        .to_str()
        .ok_or_else(|| Error::integrity("Invalid retained file path."))?;
    Ok(root.join(".devres-integrity/files").join(format!(
        "{}.json",
        blake3::hash(relative.as_bytes()).to_hex()
    )))
}

fn legacy_evidence(path: &Path) -> Result<FileEvidence> {
    const MAX_EVIDENCE_BYTES: u64 = 16 * 1024;
    if !path.is_absolute()
        || path.components().any(|part| {
            matches!(
                part,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(Error::integrity("Invalid retained file path."));
    }
    let source = std::fs::symlink_metadata(path)
        .map_err(|_| Error::integrity("Retained file unavailable."))?;
    if !source.is_file() || source.file_type().is_symlink() {
        return Err(Error::integrity("Invalid retained file."));
    }
    for ancestor in path.ancestors().skip(1).take(32) {
        let metadata = std::fs::symlink_metadata(ancestor)
            .map_err(|_| Error::integrity("Retained directory unavailable."))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(Error::integrity("Invalid retained directory."));
        }
        let marker = ancestor.join(".devres-integrity");
        let metadata = match std::fs::symlink_metadata(&marker) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(Error::integrity("Integrity directory unavailable.")),
        };
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(Error::integrity("Invalid integrity directory."));
        }
        let directory = marker.join("files");
        let metadata = std::fs::symlink_metadata(&directory)
            .map_err(|_| Error::integrity("Retained BLAKE3 evidence missing."))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(Error::integrity("Invalid integrity directory."));
        }
        let descriptor = evidence_path(ancestor, path)?;
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(descriptor)
            .map_err(|_| Error::integrity("Retained BLAKE3 evidence unavailable."))?;
        let metadata = file
            .metadata()
            .map_err(|_| Error::integrity("Invalid integrity evidence."))?;
        if !metadata.is_file() || metadata.len() > MAX_EVIDENCE_BYTES {
            return Err(Error::integrity("Invalid integrity evidence."));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        (&mut file)
            .take(MAX_EVIDENCE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::integrity("Retained BLAKE3 evidence unavailable."))?;
        if bytes.len() as u64 != metadata.len() {
            return Err(Error::integrity(
                "Retained integrity evidence length changed.",
            ));
        }
        let evidence: FileEvidence = serde_json::from_slice(&bytes)
            .map_err(|_| Error::integrity("Invalid integrity evidence."))?;
        if evidence.version != 1
            || !evidence.digest.starts_with(BLAKE3_PREFIX)
            || !valid_hash(&evidence.digest)
            || path.strip_prefix(ancestor).ok().and_then(Path::to_str)
                != Some(evidence.path.as_str())
        {
            return Err(Error::integrity("Retained integrity identity mismatch."));
        }
        return Ok(evidence);
    }
    Err(Error::integrity("Retained BLAKE3 evidence missing."))
}

static EVIDENCE_STAGE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
struct EvidenceStage(PathBuf);
impl Drop for EvidenceStage {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Record already-computed BLAKE3 evidence before a writer publishes its database
/// pointer. Descriptors stay outside immutable payload/index directories.
pub fn record_file(root: &Path, path: &Path, digest: &str, bytes: u64) -> Result<()> {
    if !root.is_absolute()
        || !path.is_absolute()
        || !path.starts_with(root)
        || path.components().any(|part| {
            matches!(
                part,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
        || !digest.starts_with(BLAKE3_PREFIX)
        || !valid_hash(digest)
    {
        return Err(Error::integrity("Invalid durable file evidence identity."));
    }
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| Error::integrity("Published file unavailable."))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() != bytes {
        return Err(Error::integrity(
            "Published file evidence length/type mismatch.",
        ));
    }
    let mut selected = None;
    for ancestor in path.ancestors().skip(1).take(32) {
        let metadata = std::fs::symlink_metadata(ancestor)
            .map_err(|_| Error::integrity("Published directory unavailable."))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(Error::integrity("Invalid published directory."));
        }
        match std::fs::symlink_metadata(ancestor.join(".devres-integrity")) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                selected = Some(ancestor.to_owned());
                break;
            }
            Ok(_) => return Err(Error::integrity("Invalid integrity directory.")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err(Error::integrity("Integrity directory unavailable.")),
        }
    }
    let root = selected.as_deref().unwrap_or(root);
    let relative = path
        .strip_prefix(root)
        .ok()
        .and_then(Path::to_str)
        .ok_or_else(|| Error::integrity("Invalid published file path."))?;
    let evidence = FileEvidence {
        version: 1,
        path: relative.into(),
        bytes,
        digest: digest.into(),
    };
    let encoded =
        serde_json::to_vec(&evidence).map_err(|_| Error::integrity("Invalid file evidence."))?;
    if encoded.len() > 16 * 1024 {
        return Err(Error::capacity("File evidence exceeds its bound."));
    }
    let target = evidence_path(root, path)?;
    let parent = target
        .parent()
        .ok_or_else(|| Error::integrity("Invalid evidence path."))?;
    ensure_directory_durable(parent)?;
    let (mut file, guard) = {
        let mut owned = None;
        for _ in 0..1024 {
            let stage = parent.join(format!(
                ".stage-{}-{}",
                std::process::id(),
                EVIDENCE_STAGE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .custom_flags(nix::libc::O_NOFOLLOW)
                .open(&stage)
            {
                Ok(file) => {
                    owned = Some((file, EvidenceStage(stage)));
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
                Err(_) => return Err(Error::unavailable("File evidence staging failed.")),
            }
        }
        owned.ok_or_else(|| Error::capacity("File evidence staging slots exhausted."))?
    };
    use std::io::Write;
    file.write_all(&encoded)
        .and_then(|()| file.sync_all())
        .map_err(|_| Error::unavailable("File evidence write failed."))?;
    drop(file);
    match std::fs::hard_link(&guard.0, &target) {
        Ok(()) => (),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let mut file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
                .open(&target)
                .map_err(|_| Error::integrity("Retained file evidence unavailable."))?;
            let metadata = file
                .metadata()
                .map_err(|_| Error::integrity("Invalid retained file evidence."))?;
            if !metadata.is_file() || metadata.len() != encoded.len() as u64 {
                return Err(Error::integrity("Conflicting retained file evidence."));
            }
            let mut retained = Vec::with_capacity(encoded.len());
            (&mut file)
                .take(encoded.len() as u64 + 1)
                .read_to_end(&mut retained)
                .map_err(|_| Error::integrity("Retained file evidence read failed."))?;
            if retained != encoded {
                return Err(Error::integrity("Conflicting retained file evidence."));
            }
        }
        Err(_) => return Err(Error::unavailable("File evidence publication failed.")),
    }
    std::fs::File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(|_| Error::unavailable("File evidence directory sync failed."))?;
    Ok(())
}

/// Compare BLAKE3 already computed by the caller's bounded/cancelable read.
/// Only the small descriptor is read here; source bytes are never read a second time.
pub fn verify_legacy_digest(path: &Path, computed_b3: &str, bytes: u64) -> Result<()> {
    if !computed_b3.starts_with(BLAKE3_PREFIX) || !valid_hash(computed_b3) {
        return Err(Error::integrity("Invalid retained BLAKE3 digest."));
    }
    let evidence = legacy_evidence(path)?;
    if evidence.digest != computed_b3 || evidence.bytes != bytes {
        return Err(Error::integrity("Retained BLAKE3 verification failed."));
    }
    Ok(())
}

/// Legacy SHA-only files need independently backfilled BLAKE3 evidence.
/// Blocking callers retain their existing admission and verification deadline.
pub fn verify_legacy_file(path: &Path, deadline: Instant) -> Result<()> {
    let evidence = legacy_evidence(path)?;
    let (digest, bytes) = file_digest(path, evidence.bytes, deadline)?;
    if digest != evidence.digest || bytes != evidence.bytes {
        return Err(Error::integrity("Retained BLAKE3 verification failed."));
    }
    Ok(())
}

/// Migration mappings retain their reference-role namespace even when two roles
/// legitimately share the same old SHA-256 text.
pub fn migration_lookup<'a>(
    mappings: &'a std::collections::BTreeMap<String, String>,
    role: &str,
    old: &str,
) -> Option<&'a String> {
    mappings.get(&format!("{role}:{old}"))
}

/// Create owned directories without following links and durably publish every
/// newly created parent entry. Filesystem mutations run on a blocking worker.
pub async fn ensure_directory(path: &Path) -> Result<()> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || ensure_directory_durable(&path))
        .await
        .map_err(|_| Error::unavailable("Directory publication failed."))?
}

pub fn ensure_directory_durable(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path.components().any(|part| {
            matches!(
                part,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(Error::integrity("Invalid storage directory."));
    }
    let ancestors: Vec<_> = path.ancestors().collect();
    if ancestors.len() > 128 {
        return Err(Error::capacity("Storage directory depth exceeded."));
    }
    for directory in ancestors.iter().rev().copied() {
        match std::fs::symlink_metadata(directory) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => (),
            Ok(_) => return Err(Error::integrity("Invalid storage directory.")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match std::fs::create_dir(directory) {
                    Ok(()) => (),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        let metadata = std::fs::symlink_metadata(directory)
                            .map_err(|_| Error::unavailable("Storage directory unavailable."))?;
                        if !metadata.is_dir() || metadata.file_type().is_symlink() {
                            return Err(Error::integrity("Invalid storage directory."));
                        }
                    }
                    Err(_) => return Err(Error::unavailable("Storage directory creation failed.")),
                }
                std::fs::File::open(directory)
                    .and_then(|file| file.sync_all())
                    .map_err(|_| Error::unavailable("Storage directory sync failed."))?;
                if let Some(parent) = directory.parent() {
                    std::fs::File::open(parent)
                        .and_then(|file| file.sync_all())
                        .map_err(|_| Error::unavailable("Storage parent sync failed."))?;
                }
            }
            Err(_) => return Err(Error::unavailable("Storage directory unavailable.")),
        }
    }
    // Also close a previous process's mkdir→fsync interruption window when
    // resuming an already-created path before publishing new durable contents.
    for directory in ancestors {
        std::fs::File::open(directory)
            .and_then(|file| file.sync_all())
            .map_err(|_| Error::unavailable("Storage directory sync failed."))?;
    }
    Ok(())
}

pub const BLAKE3_PREFIX: &str = "blake3:";

pub fn hash(bytes: &[u8]) -> String {
    format!("{BLAKE3_PREFIX}{}", blake3::hash(bytes).to_hex())
}

pub fn legacy_hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn valid_hash(value: &str) -> bool {
    let digest = value.strip_prefix(BLAKE3_PREFIX).unwrap_or(value);
    digest.len() == 64
        && digest
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
}

pub fn digest_hex(value: &str) -> Result<&str> {
    if !valid_hash(value) {
        return Err(Error::integrity("Invalid content digest."));
    }
    Ok(value.strip_prefix(BLAKE3_PREFIX).unwrap_or(value))
}

pub fn relative_path(value: &str) -> Result<PathBuf> {
    let hex = digest_hex(value)?;
    Ok(if value.starts_with(BLAKE3_PREFIX) {
        PathBuf::from("blake3").join(hex)
    } else {
        PathBuf::from(hex)
    })
}

/// Verifies a digest with its declared algorithm. Legacy callers additionally
/// require the migrated BLAKE3 descriptor at their durable storage boundary.
pub fn verify(expected: &str, bytes: &[u8]) -> Result<()> {
    digest_hex(expected)?;
    let actual = if expected.starts_with(BLAKE3_PREFIX) {
        hash(bytes)
    } else {
        legacy_hash(bytes)
    };
    if actual != expected {
        return Err(Error::integrity("Stored content digest mismatch."));
    }
    Ok(())
}

/// Canonical JSON envelope: serde_json's default ordered maps sort object keys;
/// arrays and number tokens retain their serialized value. Used identically by
/// reads, writes and backfill, never for source-body rewriting.
pub fn payload_hash(namespace: &str, key: &str, value: &serde_json::Value) -> Result<String> {
    canonical_hash(&serde_json::json!([
        "devres-integrity-v1",
        namespace,
        key,
        value
    ]))
}

/// Canonical checksum encoding is separate from stored JSON. Numeric values use
/// exact decimal coefficient/exponent pairs so PostgreSQL numeric formatting does
/// not change the checksum (e.g. 1.00 and 1e0), without conversion through f64.
pub fn canonical_hash(value: &serde_json::Value) -> Result<String> {
    fn encode(value: &serde_json::Value, out: &mut blake3::Hasher, depth: usize) -> Result<()> {
        if depth > 128 {
            return Err(Error::capacity("Integrity value nesting exceeded."));
        }
        match value {
            serde_json::Value::Null => {
                out.update(b"n");
            }
            serde_json::Value::Bool(v) => {
                out.update(if *v { b"t" } else { b"f" });
            }
            serde_json::Value::String(v) => {
                out.update(b"s");
                out.update(&(v.len() as u64).to_be_bytes());
                out.update(v.as_bytes());
            }
            serde_json::Value::Number(v) => {
                out.update(b"d");
                let token = v.to_string();
                if token.len() > 65536 {
                    return Err(Error::capacity("Integrity number bound exceeded."));
                }
                let (mantissa, exponent) = token.split_once(['e', 'E']).unwrap_or((&token, "0"));
                let exponent = exponent
                    .parse::<i64>()
                    .map_err(|_| Error::capacity("Integrity exponent bound exceeded."))?;
                let negative = mantissa.starts_with('-');
                let unsigned = mantissa.strip_prefix('-').unwrap_or(mantissa);
                let fractional = unsigned
                    .split_once('.')
                    .map_or(0, |(_, fraction)| fraction.len());
                let digits = unsigned.replace('.', "");
                let leading = digits.trim_start_matches('0');
                let trailing = leading.len() - leading.trim_end_matches('0').len();
                let coefficient = leading.trim_end_matches('0');
                let (coefficient, exponent) = if coefficient.is_empty() {
                    ("0", 0_i64)
                } else {
                    (
                        coefficient,
                        exponent
                            .checked_sub(fractional as i64)
                            .and_then(|v| v.checked_add(trailing as i64))
                            .ok_or_else(|| Error::capacity("Integrity exponent overflow."))?,
                    )
                };
                out.update(if negative && coefficient != "0" {
                    b"-"
                } else {
                    b"+"
                });
                out.update(&(coefficient.len() as u64).to_be_bytes());
                out.update(coefficient.as_bytes());
                out.update(&exponent.to_be_bytes());
            }
            serde_json::Value::Array(values) => {
                out.update(b"a");
                out.update(&(values.len() as u64).to_be_bytes());
                for value in values {
                    encode(value, out, depth + 1)?;
                }
            }
            serde_json::Value::Object(values) => {
                out.update(b"o");
                out.update(&(values.len() as u64).to_be_bytes());
                for (key, value) in values {
                    encode(&serde_json::Value::String(key.clone()), out, depth + 1)?;
                    encode(value, out, depth + 1)?;
                }
            }
        }
        Ok(())
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"devres-canonical-json-v1\0");
    encode(value, &mut hasher, 0)?;
    Ok(format!("blake3:{}", hasher.finalize().to_hex()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vectors_and_namespace_validation() {
        assert_eq!(
            hash(b""),
            "blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
        assert_eq!(
            hash(b"abc"),
            "blake3:6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
        );
        assert!(verify(&hash(b"abc"), b"abd").is_err());
        assert!(verify(&legacy_hash(b"abc"), b"abc").is_ok());
        for bad in ["blake3:../", "sha256:abc", "BLAKE3:abc", "blake3:"] {
            assert!(!valid_hash(bad));
            assert!(relative_path(bad).is_err());
        }
        assert_eq!(
            relative_path(&hash(b"abc")).unwrap(),
            PathBuf::from("blake3").join(digest_hex(&hash(b"abc")).unwrap())
        );
    }

    #[test]
    fn new_file_evidence_is_atomic_and_uses_existing_outer_marker() {
        let root = tempfile::tempdir().unwrap();
        ensure_directory_durable(&root.path().join(".devres-integrity/files")).unwrap();
        let nested = root.path().join("provider/artifacts");
        ensure_directory_durable(&nested.join("blake3")).unwrap();
        let bytes = b"new public evidence after migration";
        let digest = hash(bytes);
        let path = nested.join(relative_path(&digest).unwrap());
        std::fs::write(&path, bytes).unwrap();
        record_file(&nested, &path, &digest, bytes.len() as u64).unwrap();
        record_file(&nested, &path, &digest, bytes.len() as u64).unwrap();
        assert!(!nested.join(".devres-integrity").exists());
        let descriptor = evidence_path(root.path(), &path).unwrap();
        assert!(descriptor.is_file());
        verify_legacy_digest(&path, &digest, bytes.len() as u64).unwrap();
        verify_legacy_file(&path, Instant::now() + std::time::Duration::from_secs(1)).unwrap();
        let names: Vec<_> = std::fs::read_dir(descriptor.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(
            names.len(),
            1,
            "owned evidence stages are removed after publication"
        );
        assert!(
            record_file(
                &nested,
                &path,
                &hash(b"conflicting evidence"),
                bytes.len() as u64
            )
            .is_err()
        );
        std::fs::write(&path, b"corrupt").unwrap();
        assert!(
            verify_legacy_file(&path, Instant::now() + std::time::Duration::from_secs(1)).is_err()
        );
    }

    #[test]
    fn legacy_digest_verification_is_bounded_role_bound_and_rejects_links() {
        let root = tempfile::tempdir().unwrap();
        let bytes = b"retained public bytes";
        let source = root.path().join(legacy_hash(bytes));
        std::fs::write(&source, bytes).unwrap();
        let digest = hash(bytes);
        assert!(verify_legacy_digest(&source, &digest, bytes.len() as u64).is_err());
        let evidence = FileEvidence {
            version: 1,
            path: source.file_name().unwrap().to_str().unwrap().into(),
            bytes: bytes.len() as u64,
            digest: digest.clone(),
        };
        let descriptor = evidence_path(root.path(), &source).unwrap();
        ensure_directory_durable(descriptor.parent().unwrap()).unwrap();
        let encoded = serde_json::to_vec(&evidence).unwrap();
        std::fs::write(&descriptor, &encoded).unwrap();
        verify_legacy_digest(&source, &digest, bytes.len() as u64).unwrap();
        assert!(verify_legacy_digest(&source, &hash(b"wrong"), bytes.len() as u64).is_err());
        assert!(verify_legacy_digest(&source, &digest, 0).is_err());
        // Already-computed bytes are checked; this helper does not reread source data.
        std::fs::write(&source, vec![b'x'; bytes.len()]).unwrap();
        verify_legacy_digest(&source, &digest, bytes.len() as u64).unwrap();
        assert!(
            verify_legacy_file(&source, Instant::now() + std::time::Duration::from_secs(1))
                .is_err()
        );
        std::fs::write(&descriptor, vec![b' '; 16 * 1024 + 1]).unwrap();
        assert!(verify_legacy_digest(&source, &digest, bytes.len() as u64).is_err());
        let alternate = root.path().join("descriptor-original.json");
        std::fs::write(&alternate, encoded).unwrap();
        std::fs::remove_file(&descriptor).unwrap();
        std::os::unix::fs::symlink(&alternate, &descriptor).unwrap();
        assert!(verify_legacy_digest(&source, &digest, bytes.len() as u64).is_err());
    }

    #[test]
    fn directory_publication_rejects_links_and_role_mappings_do_not_alias() {
        let root = tempfile::tempdir().unwrap();
        let child = root.path().join("new/blake3");
        ensure_directory_durable(&child).unwrap();
        ensure_directory_durable(&child).unwrap();
        assert!(child.is_dir());
        let outside = tempfile::tempdir().unwrap();
        let link = root.path().join("redirect");
        std::os::unix::fs::symlink(outside.path(), &link).unwrap();
        assert!(ensure_directory_durable(&link.join("new")).is_err());
        assert!(!outside.path().join("new").exists());
        let old = "a".repeat(64);
        let mappings = std::collections::BTreeMap::from([
            (format!("body:{old}"), hash(b"body")),
            (format!("capture:{old}"), hash(b"capture")),
        ]);
        assert_ne!(
            migration_lookup(&mappings, "body", &old),
            migration_lookup(&mappings, "capture", &old)
        );
        assert!(migration_lookup(&mappings, "mdn:projections", &old).is_none());
    }

    #[test]
    fn payload_digest_binds_identity_and_order() {
        let a = serde_json::json!({"b": 2, "a": [1, 2]});
        let b = serde_json::json!({"a": [1, 2], "b": 2});
        assert_eq!(
            payload_hash("test", "one", &a).unwrap(),
            payload_hash("test", "one", &b).unwrap()
        );
        assert_ne!(
            payload_hash("test", "one", &a).unwrap(),
            payload_hash("test", "two", &a).unwrap()
        );
        assert_ne!(
            payload_hash("test", "one", &a).unwrap(),
            payload_hash("test", "one", &serde_json::json!({"a":[2,1],"b":2})).unwrap()
        );
    }
}
