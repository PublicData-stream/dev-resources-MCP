//! Offline Git object materialization. Only verified retained packs enter private scratch.
use crate::{
    bulk::{self, BulkArtifact, BulkArtifactStore, MaterializedArtifact},
    crates_io::git::{base_command, real_directory, run_command, valid_pack_name},
};
use devres_domain::{Error, Result};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

pub(crate) struct PackWorkspace {
    directory: tempfile::TempDir,
    _leases: Vec<MaterializedArtifact>,
}
impl PackWorkspace {
    pub fn root(&self) -> &Path {
        self.directory.path()
    }
}
fn unavailable() -> Error {
    Error::unavailable("Retained Git scratch materialization unavailable.")
}
pub(crate) fn scratch_root(scratch: &Path, archive: &Path) -> Result<PathBuf> {
    let scratch = std::fs::canonicalize(scratch).map_err(|_| unavailable())?;
    let archive = std::fs::canonicalize(archive).map_err(|_| unavailable())?;
    real_directory(&scratch)?;
    if scratch.starts_with(&archive) || archive.starts_with(&scratch) {
        return Err(Error::invalid(
            "Reader Git scratch must be separate from the archive/cache.",
        ));
    }
    Ok(scratch)
}
pub(crate) async fn prepare(
    scratch: &Path,
    artifacts: &BulkArtifactStore,
    packs: Vec<(String, BulkArtifact)>,
    max_bytes: u64,
    min_free: u64,
    cancel: &CancellationToken,
    deadline: Instant,
) -> Result<PackWorkspace> {
    if packs.is_empty() || packs.len() > 10000 {
        return Err(Error::integrity("Invalid retained Git pack inventory."));
    }
    let mut names = BTreeSet::new();
    let mut bytes = 0_u64;
    for (name, artifact) in &packs {
        if !valid_pack_name(name) || !names.insert(name) {
            return Err(Error::integrity("Invalid retained Git pack identity."));
        }
        bytes = bytes
            .checked_add(artifact.bytes)
            .filter(|bytes| *bytes <= max_bytes)
            .ok_or_else(|| Error::capacity("Retained Git scratch exceeds its byte budget."))?;
    }
    real_directory(scratch)?;
    if fs2::available_space(scratch).map_err(|_| unavailable())? < min_free {
        return Err(Error::capacity(
            "Retained Git scratch headroom unavailable.",
        ));
    }
    let directory = tempfile::Builder::new()
        .prefix("devres-retained-git-")
        .tempdir_in(scratch)
        .map_err(|_| unavailable())?;
    let repository = directory.path().join("history.git");
    let mut command = base_command();
    command
        .args(["init", "--bare", "--template="])
        .arg(&repository);
    run_command(command, 4096, cancel, deadline).await?;
    let destination = repository.join("objects/pack");
    real_directory(&destination)?;
    let mut leases = Vec::with_capacity(packs.len());
    for (name, expected) in packs {
        let materialized = bulk::bounded(
            cancel,
            deadline,
            artifacts.materialize(
                &expected.body_hash,
                bulk::MAX_ARTIFACT_BYTES,
                cancel.clone(),
            ),
        )
        .await?;
        if materialized.artifact != expected {
            return Err(Error::integrity("Retained Git pack metadata mismatch."));
        }
        let target = destination.join(name);
        let linked = bulk::bounded(cancel, deadline, async {
            match tokio::fs::hard_link(&materialized.path, &target).await {
                Ok(()) => Ok(true),
                Err(error) if error.kind() == std::io::ErrorKind::CrossesDevices => Ok(false),
                Err(_) => Err(unavailable()),
            }
        })
        .await?;
        if !linked {
            // Different private volumes can prevent hardlinks. Copy only into
            // this operation's owned scratch, with bounded space and lifetime.
            if fs2::available_space(scratch).map_err(|_| unavailable())?
                < expected.bytes.saturating_add(min_free)
            {
                return Err(Error::capacity(
                    "Retained Git scratch copy exceeds free space.",
                ));
            }
            let copied = bulk::bounded(cancel, deadline, async {
                tokio::fs::copy(&materialized.path, &target)
                    .await
                    .map_err(|_| unavailable())
            })
            .await?;
            if copied != expected.bytes {
                return Err(Error::integrity(
                    "Retained Git scratch copy length mismatch.",
                ));
            }
        }
        leases.push(materialized);
    }
    Ok(PackWorkspace {
        directory,
        _leases: leases,
    })
}
