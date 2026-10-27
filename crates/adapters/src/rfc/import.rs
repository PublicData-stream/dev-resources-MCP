//! Private, opt-in fixed-source bulk import. Never registered as an MCP tool.
use crate::{
    rfc::corpus::{BODY_LIMIT, RfcCorpus, advertised_formats, media_type, representation_key},
    rfc::source as rfc,
};
use devres_application::corpus::JobSpec;
use devres_domain::{Error, FetchRequest, FetchResponse, Result, Validators, unix_now};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    process::Stdio,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};
use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;

static IMPORT: AtomicU64 = AtomicU64::new(0);
const RESERVE: u64 = 64 * 1024 * 1024;
const MAX_RUNTIME: Duration = Duration::from_secs(86400);
async fn bounded<T>(
    shutdown: &CancellationToken,
    started: Instant,
    future: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    let remaining = MAX_RUNTIME.saturating_sub(started.elapsed());
    tokio::select! {biased;_=shutdown.cancelled()=>Err(Error::unavailable("RFC mirror import canceled.")),result=tokio::time::timeout(remaining,future)=>result.map_err(|_|Error::capacity("RFC import runtime exceeded."))?}
}
struct Stage(PathBuf);
impl Drop for Stage {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn manifest_file(number: u32, format: &str) -> Result<String> {
    if !(1..=999999).contains(&number) {
        return Err(Error::invalid("Invalid RFC mirror identity."));
    }
    media_type(format)?;
    Ok(format!("rfc{number}.{format}"))
}
fn stage_size(root: &Path) -> Result<u64> {
    let mut total = 0u64;
    for entry in std::fs::read_dir(root)
        .map_err(|_| Error::unavailable("RFC import staging unavailable."))?
    {
        let entry = entry.map_err(|_| Error::unavailable("RFC import staging unavailable."))?;
        let metadata = entry
            .file_type()
            .map_err(|_| Error::unavailable("RFC import staging unavailable."))?;
        if !metadata.is_file() {
            return Err(Error::integrity(
                "RFC mirror returned a non-regular member.",
            ));
        }
        let size = entry
            .metadata()
            .map_err(|_| Error::unavailable("RFC import staging unavailable."))?
            .len();
        if size > BODY_LIMIT as u64 {
            return Err(Error::capacity("RFC mirror member exceeds limit."));
        }
        total = total
            .checked_add(size)
            .ok_or_else(|| Error::capacity("RFC mirror size exceeds limit."))?;
    }
    Ok(total)
}

impl RfcCorpus {
    /// Caller has already acquired the exclusive database owner fence by constructing storage.
    pub async fn import_rsync(&self, max_bytes: u64, shutdown: CancellationToken) -> Result<Value> {
        let started = Instant::now();
        if max_bytes == 0 || max_bytes > 128 * 1024 * 1024 * 1024 {
            return Err(Error::invalid(
                "RFC import byte budget must be 1..137438953472.",
            ));
        }
        let free = fs2::available_space(&self.root)
            .map_err(|_| Error::unavailable("RFC import disk capacity unavailable."))?;
        if free
            < max_bytes
                .saturating_mul(2)
                .saturating_add(RESERVE)
                .saturating_add(BODY_LIMIT as u64)
        {
            return Err(Error::capacity(
                "RFC import requires staging, archive and reserved free space.",
            ));
        }
        let catalogue = bounded(&shutdown, started, self.catalogue()).await?;
        bounded(&shutdown, started, self.refresh_errata()).await?;
        let mut expected = BTreeMap::new();
        for record in &catalogue.records {
            let number = record["number"]
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(|| Error::integrity("RFC catalogue identity is invalid."))?;
            for format in advertised_formats(record) {
                expected.insert(manifest_file(number, &format)?, (number, format));
            }
        }
        if expected.len() > 200000 {
            return Err(Error::capacity("RFC mirror manifest exceeds limit."));
        }
        let stage_path = self.root.join(format!(
            ".rfc-import-{}-{}",
            std::process::id(),
            IMPORT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut options = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            options.mode(0o700);
        }
        options
            .create(&stage_path)
            .map_err(|_| Error::unavailable("RFC import staging could not be created."))?;
        let stage = Stage(stage_path);
        let files = stage.0.join("files");
        std::fs::create_dir(&files)
            .map_err(|_| Error::unavailable("RFC import staging could not be created."))?;
        let manifest = stage.0.join("manifest");
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&manifest)
            .map_err(|_| Error::unavailable("RFC mirror manifest could not be created."))?;
        for name in expected.keys() {
            output
                .write_all(name.as_bytes())
                .and_then(|()| output.write_all(&[0]))
                .map_err(|_| Error::unavailable("RFC mirror manifest could not be written."))?;
        }
        output
            .sync_all()
            .map_err(|_| Error::unavailable("RFC mirror manifest could not be written."))?;
        drop(output);
        let mut command = tokio::process::Command::new("/usr/bin/rsync");
        command
            .env_clear()
            .env("LANG", "C")
            .args([
                "--inplace",
                "--no-recursive",
                "--no-links",
                "--no-devices",
                "--no-specials",
                "--from0",
                "--timeout=30",
                "--contimeout=10",
                "--bwlimit=1024",
                "--max-alloc=64M",
                "--max-size=16777216",
            ])
            .arg(format!("--files-from={}", manifest.display()))
            .arg("rsync://rsync.rfc-editor.org/rfcs/")
            .arg(&files)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let mut child = command
            .spawn()
            .map_err(|_| Error::unavailable("The trusted rsync executable is unavailable."))?;
        loop {
            tokio::select! {
                biased;
                _=shutdown.cancelled()=>{let _=child.kill().await;let _=child.wait().await;return Err(Error::unavailable("RFC mirror import canceled."));}
                result=child.wait()=>{if !result.map_err(|_|Error::unavailable("RFC mirror transfer failed."))?.success(){return Err(Error::unavailable("RFC mirror transfer failed."));}break;}
                _=tokio::time::sleep(Duration::from_millis(250))=>{
                    // Scan is bounded by the fixed manifest's maximum membership.
                    let size=stage_size(&files);
                    if !size.as_ref().is_ok_and(|size|*size<=max_bytes)||started.elapsed()>MAX_RUNTIME {let _=child.kill().await;let _=child.wait().await;return Err(size.err().unwrap_or_else(||Error::capacity("RFC mirror transfer exceeded its budget.")));}
                }
            }
        }
        if stage_size(&files)? > max_bytes {
            return Err(Error::capacity(
                "RFC mirror transfer exceeded its byte budget.",
            ));
        }
        let mut imported = 0usize;
        let mut missing = 0usize;
        for (name, (number, format)) in expected {
            if shutdown.is_cancelled() {
                return Err(Error::unavailable("RFC mirror import canceled."));
            }
            if started.elapsed() > MAX_RUNTIME {
                return Err(Error::capacity("RFC import runtime exceeded."));
            }
            let path = files.join(name);
            let metadata = match tokio::fs::symlink_metadata(&path).await {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    missing += 1;
                    continue;
                }
                Err(_) => return Err(Error::unavailable("RFC mirror member unavailable.")),
            };
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.len() > BODY_LIMIT as u64
            {
                return Err(Error::integrity(
                    "RFC mirror member is not a bounded regular file.",
                ));
            }
            let mut bytes = Vec::new();
            tokio::fs::File::open(&path)
                .await
                .map_err(|_| Error::unavailable("RFC mirror member unavailable."))?
                .take(BODY_LIMIT as u64 + 1)
                .read_to_end(&mut bytes)
                .await
                .map_err(|_| Error::unavailable("RFC mirror member unavailable."))?;
            let key = representation_key(number, &format, "rsync");
            let source_url = format!("rsync://rsync.rfc-editor.org/rfcs/rfc{number}.{format}");
            self.store
                .schedule(&[JobSpec {
                    key: key.clone(),
                    number,
                    format: format.clone(),
                    source_url: source_url.clone(),
                    assurance: "rsync".into(),
                    due_at: i64::MAX,
                }])
                .await?;
            let request = FetchRequest {
                key: key.clone(),
                url: source_url,
                ttl_secs: 86400,
                max_bytes: BODY_LIMIT,
                media_type: media_type(&format)?.into(),
            };
            match bounded(
                &shutdown,
                started,
                self.retrieval.publish_validated(
                    request,
                    FetchResponse {
                        status: 200,
                        body: bytes,
                        validators: Validators::default(),
                    },
                    &rfc::Validator,
                ),
            )
            .await
            {
                Ok(stored) => {
                    self.store
                        .finish(&key, Some(&stored.capture), None, i64::MAX)
                        .await?;
                    imported += 1;
                }
                Err(error) => {
                    self.store
                        .finish(&key, None, Some(&error.code), i64::MAX)
                        .await?;
                }
            }
        }
        let snapshot = bounded(&shutdown, started, self.publish_snapshot()).await?;
        Ok(
            json!({"imported":imported,"missing_from_mirror":missing,"assurance":"rsync","transport_authenticated":false,"observed_at":unix_now(),"snapshot":snapshot.id,"coverage":snapshot.coverage}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_manifest_never_contains_paths_or_links() {
        assert_eq!(manifest_file(9000, "pdf").unwrap(), "rfc9000.pdf");
        assert!(manifest_file(0, "txt").is_err());
        assert!(manifest_file(1, "../txt").is_err());
    }
    #[test]
    fn staging_rejects_symlinks_and_oversize() {
        let temp = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/etc/passwd", temp.path().join("rfc1.txt")).unwrap();
            assert_eq!(stage_size(temp.path()).unwrap_err().code, "integrity");
        }
    }
}
