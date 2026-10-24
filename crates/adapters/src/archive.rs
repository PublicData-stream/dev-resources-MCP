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

pub async fn inspect_async(
    bytes: devres_domain::Body,
    checksum: String,
    root: String,
    selected: Option<String>,
    permit: OwnedSemaphorePermit,
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
    )
}

fn inspect_until(
    bytes: &[u8],
    checksum: &str,
    root: &str,
    selected: Option<&str>,
    deadline: Instant,
) -> Result<Inspection> {
    if bytes.len() > MAX_COMPRESSED {
        return Err(Error::capacity("Compressed archive exceeds 32 MiB."));
    }
    if checksum.len() != 64
        || !checksum.bytes().all(|v| v.is_ascii_hexdigit())
        || sha256(bytes) != checksum.to_ascii_lowercase()
    {
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
    inspect_until(bytes, checksum, root, None, deadline)?;
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
}
