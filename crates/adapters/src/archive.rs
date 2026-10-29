//! Bounded, non-extracting inspection of published tar/gzip archives.

use devres_domain::{Error, Result};
use flate2::read::MultiGzDecoder;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    io::{self, Read},
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub const MAX_COMPRESSED: usize = 32 * 1024 * 1024;
const MAX_EXPANDED: u64 = 256 * 1024 * 1024;
const MAX_MEMBERS: usize = 20_000;
const MAX_SELECTED: u64 = 4 * 1024 * 1024;

#[derive(Debug, Serialize)]
pub struct Member {
    pub path: String,
    pub size: u64,
}

pub struct Inspection {
    pub members: Vec<Member>,
    pub selected: Option<Vec<u8>>,
}

/// Admission precedes archive retrieval so waiting callers cannot each retain a
/// maximum-size compressed body. The worker owns this permit through cancellation.
pub fn admit() -> Result<OwnedSemaphorePermit> {
    static SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();
    SLOTS
        .get_or_init(|| Arc::new(Semaphore::new(2)))
        .clone()
        .try_acquire_owned()
        .map_err(|_| Error::capacity("Archive parser capacity exhausted."))
}

/// One request can reuse admission across validation-before-publication and its
/// selected projection. Every blocking worker retains its own shared lease.
pub(crate) async fn inspect_shared_async(
    bytes: devres_domain::Body,
    checksum: String,
    root: String,
    selected: Option<String>,
    permit: Arc<OwnedSemaphorePermit>,
) -> Result<Inspection> {
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        inspect(&bytes, &checksum, &root, selected.as_deref())
    })
    .await
    .map_err(|_| Error::unavailable("Archive parser worker failed."))?
}

struct BudgetReader<R> {
    inner: R,
    remaining: u64,
    deadline: Instant,
}

impl<R: Read> Read for BudgetReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if Instant::now() >= self.deadline {
            return Err(io::Error::other("archive time budget exceeded"));
        }
        let allowed = buf.len().min(self.remaining.saturating_add(1) as usize);
        let count = self.inner.read(&mut buf[..allowed])?;
        if count as u64 > self.remaining {
            return Err(io::Error::other("archive expansion budget exceeded"));
        }
        self.remaining -= count as u64;
        Ok(count)
    }
}

pub fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn valid_relative_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 4096
        && !path.contains(['\\', ':', '\0'])
        && !path.chars().any(char::is_control)
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

/// Verify every member, including unselected files. Nothing is extracted to disk.
pub fn inspect(
    bytes: &[u8],
    checksum: &str,
    root: &str,
    selected: Option<&str>,
) -> Result<Inspection> {
    inspect_until(
        bytes,
        checksum,
        root,
        selected,
        Instant::now() + Duration::from_secs(15),
        None,
    )
}

fn inspect_until(
    bytes: &[u8],
    checksum: &str,
    root: &str,
    selected: Option<&str>,
    deadline: Instant,
    git_revision: Option<&str>,
) -> Result<Inspection> {
    if bytes.len() > MAX_COMPRESSED {
        return Err(Error::capacity("Compressed archive exceeds 32 MiB."));
    }
    let matches = if checksum.starts_with("blake3:") {
        crate::integrity::verify(checksum, bytes).is_ok()
    } else {
        checksum.len() == 64
            && checksum.bytes().all(|v| v.is_ascii_hexdigit())
            && sha256(bytes) == checksum.to_ascii_lowercase()
    };
    if !matches {
        return Err(Error::integrity(
            "Archive checksum does not match its source capture.",
        ));
    }
    if !valid_relative_path(root)
        || root.contains('/')
        || selected.is_some_and(|v| !valid_relative_path(v))
    {
        return Err(Error::invalid("Invalid archive root or member path."));
    }
    let decoder = MultiGzDecoder::new(bytes);
    let mut budget = BudgetReader {
        inner: decoder,
        remaining: MAX_EXPANDED,
        deadline,
    };
    let mut members = Vec::new();
    let mut found = None;
    let mut seen = HashSet::new();
    {
        let mut archive = tar::Archive::new(&mut budget);
        let entries = archive
            .entries()
            .map_err(|_| Error::integrity("Invalid archive."))?;
        for (index, entry) in entries.enumerate() {
            if index >= MAX_MEMBERS {
                return Err(Error::capacity("Archive contains too many members."));
            }
            let mut entry =
                entry.map_err(|_| Error::integrity("Invalid or oversized archive member."))?;
            let kind = entry.header().entry_type();
            if kind.is_pax_global_extensions() {
                // GitHub's immutable Git snapshots begin with a PAX commit
                // comment. Admit only that exact non-path-setting metadata;
                // published crate archives retain the stricter default policy.
                let revision = git_revision.ok_or_else(|| {
                    Error::integrity("Global archive metadata is unsupported for published crates.")
                })?;
                if index != 0
                    || entry.path_bytes().as_ref() != b"pax_global_header"
                    || entry.size() != 52
                {
                    return Err(Error::integrity(
                        "Unsupported Git snapshot global metadata.",
                    ));
                }
                let mut comment = [0u8; 52];
                entry
                    .read_exact(&mut comment)
                    .map_err(|_| Error::integrity("Invalid Git snapshot commit metadata."))?;
                if comment.as_slice() != format!("52 comment={revision}\n").as_bytes() {
                    return Err(Error::integrity(
                        "Git snapshot comment does not match its captured revision.",
                    ));
                }
                continue;
            }
            if !kind.is_file() && !kind.is_dir() {
                return Err(Error::integrity(
                    "Archive links, devices, and special members are unsupported.",
                ));
            }
            let raw = entry.path_bytes();
            let path = std::str::from_utf8(&raw)
                .map_err(|_| Error::integrity("Archive paths must be UTF-8."))?;
            let path = path.trim_end_matches('/');
            if !valid_relative_path(path) || !seen.insert(path.to_owned()) {
                return Err(Error::integrity("Unsafe or duplicate archive member path."));
            }
            let relative = if path == root && kind.is_dir() {
                None
            } else {
                Some(
                    path.strip_prefix(root)
                        .and_then(|v| v.strip_prefix('/'))
                        .ok_or_else(|| {
                            Error::integrity("Archive member is outside its expected root.")
                        })?
                        .to_owned(),
                )
            };
            if kind.is_file() {
                let relative =
                    relative.ok_or_else(|| Error::integrity("Missing archive member path."))?;
                let size = entry.size();
                if selected == Some(relative.as_str()) {
                    if size > MAX_SELECTED {
                        return Err(Error::capacity("Selected source file exceeds 4 MiB."));
                    }
                    let mut content = Vec::new();
                    entry
                        .by_ref()
                        .take(MAX_SELECTED + 1)
                        .read_to_end(&mut content)
                        .map_err(|_| Error::integrity("Could not read bounded archive content."))?;
                    if content.len() as u64 != size || content.len() as u64 > MAX_SELECTED {
                        return Err(Error::integrity("Archive member length mismatch."));
                    }
                    found = Some(content);
                } else {
                    io::copy(&mut entry, &mut io::sink()).map_err(|_| {
                        Error::integrity("Could not validate bounded archive content.")
                    })?;
                }
                members.push(Member {
                    path: relative,
                    size,
                });
            }
        }
    }
    // Validate the gzip trailer and charge bytes beyond tar's end-of-archive marker.
    io::copy(&mut budget, &mut io::sink())
        .map_err(|_| Error::integrity("Archive expansion, trailer, or time budget failed."))?;
    members.sort_by(|a, b| a.path.cmp(&b.path));
    if selected.is_some() && found.is_none() {
        return Err(Error::not_found("Source file is absent from this archive."));
    }
    Ok(Inspection {
        members,
        selected: found,
    })
}

/// Read only advisory Markdown after the complete archive has passed inspection.
/// The second pass is intentional: no record is accepted before all member paths
/// and types, the checksum, expansion limit and gzip trailer have been checked.
pub fn advisory_files(
    bytes: &[u8],
    checksum: &str,
    root: &str,
    deadline: Instant,
) -> Result<Vec<(String, Vec<u8>)>> {
    let revision = root
        .strip_prefix("advisory-db-")
        .filter(|value| {
            value.len() == 40
                && value
                    .bytes()
                    .all(|v| v.is_ascii_hexdigit() && !v.is_ascii_uppercase())
        })
        .ok_or_else(|| Error::integrity("Invalid immutable RustSec archive root."))?;
    inspect_until(bytes, checksum, root, None, deadline, Some(revision))?;
    let decoder = MultiGzDecoder::new(bytes);
    let budget = BudgetReader {
        inner: decoder,
        remaining: MAX_EXPANDED,
        deadline,
    };
    let mut archive = tar::Archive::new(budget);
    let mut files = Vec::new();
    let mut retained = 0usize;
    for entry in archive
        .entries()
        .map_err(|_| Error::integrity("Invalid advisory archive."))?
    {
        let mut entry = entry.map_err(|_| Error::integrity("Invalid advisory archive member."))?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let path = entry.path_bytes();
        let path = std::str::from_utf8(&path)
            .map_err(|_| Error::integrity("Invalid advisory archive path."))?;
        let path = path
            .strip_prefix(root)
            .and_then(|v| v.strip_prefix('/'))
            .ok_or_else(|| Error::integrity("Invalid advisory archive root."))?
            .to_owned();
        let parts = path.split('/').collect::<Vec<_>>();
        if parts.len() != 3
            || parts[0] != "crates"
            || !parts[2].starts_with("RUSTSEC-")
            || !parts[2].ends_with(".md")
            || parts[2].starts_with("RUSTSEC-0000-0000.")
        {
            continue;
        }
        if entry.size() > 1024 * 1024 {
            return Err(Error::capacity("Advisory Markdown member exceeds 1 MiB."));
        }
        let mut body = Vec::new();
        entry
            .by_ref()
            .take(1024 * 1024 + 1)
            .read_to_end(&mut body)
            .map_err(|_| Error::integrity("Could not read advisory Markdown."))?;
        retained = retained.saturating_add(body.len());
        if body.len() > 1024 * 1024 || retained > 64 * 1024 * 1024 {
            return Err(Error::capacity(
                "Advisory metadata exceeds retained byte limit.",
            ));
        }
        files.push((path, body));
    }
    if files.is_empty() {
        return Err(Error::integrity(
            "Advisory archive contains no published crate advisories.",
        ));
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};
    use std::io::Write;

    fn fixture(link: bool) -> Vec<u8> {
        let mut tar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        if link {
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_link_name("../../secret").unwrap();
            header.set_cksum();
            tar.append_data(&mut header, "example-1.0.0/src/lib.rs", &[][..])
                .unwrap();
        } else {
            header.set_size(5);
            header.set_cksum();
            tar.append_data(&mut header, "example-1.0.0/src/lib.rs", &b"hello"[..])
                .unwrap();
        }
        let mut gzip = GzEncoder::new(Vec::new(), Compression::fast());
        gzip.write_all(&tar.into_inner().unwrap()).unwrap();
        gzip.finish().unwrap()
    }

    #[test]
    fn verifies_checksum_and_reads_exact_member() {
        let bytes = fixture(false);
        let view = inspect(&bytes, &sha256(&bytes), "example-1.0.0", Some("src/lib.rs")).unwrap();
        assert_eq!(view.selected.unwrap(), b"hello");
        assert_eq!(view.members[0].path, "src/lib.rs");
        assert!(inspect(&bytes, &"0".repeat(64), "example-1.0.0", None).is_err());
    }

    #[test]
    fn selected_file_limit_does_not_hide_a_valid_archive_listing() {
        let content = vec![b'x'; MAX_SELECTED as usize + 1];
        let mut tar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_size(content.len() as u64);
        header.set_cksum();
        tar.append_data(&mut header, "example-1.0.0/large.txt", &content[..])
            .unwrap();
        let mut gzip = GzEncoder::new(Vec::new(), Compression::fast());
        gzip.write_all(&tar.into_inner().unwrap()).unwrap();
        let bytes = gzip.finish().unwrap();
        assert_eq!(
            inspect(&bytes, &sha256(&bytes), "example-1.0.0", None)
                .unwrap()
                .members[0]
                .size,
            MAX_SELECTED + 1
        );
        assert_eq!(
            inspect(&bytes, &sha256(&bytes), "example-1.0.0", Some("large.txt"))
                .err()
                .unwrap()
                .code,
            "capacity"
        );
    }

    #[test]
    fn rejects_links_roots_and_path_traversal() {
        let bytes = fixture(true);
        assert!(inspect(&bytes, &sha256(&bytes), "example-1.0.0", None).is_err());
        let bytes = fixture(false);
        assert!(inspect(&bytes, &sha256(&bytes), "different-1.0.0", None).is_err());
        for path in [
            "../secret",
            "/secret",
            "src/../secret",
            "a\\b",
            "C:secret",
            "a//b",
        ] {
            assert!(!valid_relative_path(path));
        }
    }

    #[test]
    fn rejects_duplicate_members_and_truncated_gzip() {
        let mut tar = tar::Builder::new(Vec::new());
        for _ in 0..2 {
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o644);
            header.set_size(1);
            header.set_cksum();
            tar.append_data(&mut header, "example-1.0.0/same", &b"x"[..])
                .unwrap();
        }
        let mut gzip = GzEncoder::new(Vec::new(), Compression::fast());
        gzip.write_all(&tar.into_inner().unwrap()).unwrap();
        let duplicate = gzip.finish().unwrap();
        assert!(inspect(&duplicate, &sha256(&duplicate), "example-1.0.0", None).is_err());
        let mut truncated = fixture(false);
        truncated.truncate(truncated.len() - 4);
        assert!(inspect(&truncated, &sha256(&truncated), "example-1.0.0", None).is_err());
    }

    #[test]
    fn rejects_traversal_encoded_directly_in_header() {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_size(1);
        let name = b"example-1.0.0/../outside";
        header.as_mut_bytes()[..name.len()].copy_from_slice(name);
        header.set_cksum();
        let mut tar = tar::Builder::new(Vec::new());
        tar.append(&header, &b"x"[..]).unwrap();
        let mut gzip = GzEncoder::new(Vec::new(), Compression::fast());
        gzip.write_all(&tar.into_inner().unwrap()).unwrap();
        let bytes = gzip.finish().unwrap();
        assert!(inspect(&bytes, &sha256(&bytes), "example-1.0.0", None).is_err());
    }

    #[test]
    fn git_commit_metadata_exception_is_narrow_and_never_applies_to_crates() {
        const ROOT: &str = "advisory-db-84d943a6deeb8cc6c6f632531aaf4f1c62275239";
        let fixture = include_bytes!("../tests/fixtures/rustsec/git-snapshot-minimal.tar.gz");
        // Generic published-crate inspection must still reject global metadata.
        assert!(inspect(fixture, &sha256(fixture), ROOT, None).is_err());
        let mut raw = Vec::new();
        MultiGzDecoder::new(&fixture[..])
            .read_to_end(&mut raw)
            .unwrap();
        let validate = |bytes: Vec<u8>| {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
            encoder.write_all(&bytes).unwrap();
            let compressed = encoder.finish().unwrap();
            advisory_files(
                &compressed,
                &sha256(&compressed),
                ROOT,
                Instant::now() + Duration::from_secs(15),
            )
        };
        assert_eq!(validate(raw.clone()).unwrap().len(), 1);

        let mut wrong_comment = raw.clone();
        wrong_comment[512 + 11] = b'f';
        assert!(validate(wrong_comment).is_err());

        let mut path_override = raw.clone();
        path_override[512..564].fill(b'x');
        path_override[512..520].copy_from_slice(b"52 path=");
        path_override[520..526].copy_from_slice(b"../../");
        path_override[563] = b'\n';
        assert!(validate(path_override).is_err());

        let mut duplicate = raw[..1024].to_vec();
        duplicate.extend_from_slice(&raw);
        assert!(validate(duplicate).is_err());

        let mut late = raw[1024..1536].to_vec();
        late.extend_from_slice(&raw[..1024]);
        late.extend_from_slice(&raw[1536..]);
        assert!(validate(late).is_err());

        // A valid Git comment never permits a subsequent link or unsafe path.
        for link in [true, false] {
            let mut hostile = raw.clone();
            let header = &mut hostile[1536..2048];
            if link {
                header[156] = b'2';
            } else {
                header[..100].fill(0);
                let name = format!("{ROOT}/../outside");
                header[..name.len()].copy_from_slice(name.as_bytes());
            }
            header[148..156].fill(b' ');
            let checksum: usize = header.iter().map(|v| *v as usize).sum();
            header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
            assert!(validate(hostile).is_err());
        }
    }
}
