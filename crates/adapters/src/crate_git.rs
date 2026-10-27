//! Private incremental registry Git acquisition through a fixed-source HTTP relay.
//! Git only parses objects in an owned bare repository; no tree is checked out.
use crate::bulk::{
    self, BulkArtifact, BulkArtifactStore, BulkBroker, BulkRequest, BulkSource, GitOperation,
};
use axum::{
    Router,
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, RawQuery, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use devres_domain::{Error, Result, Validators};
use futures::StreamExt;
use nix::{
    sys::signal::{Signal, killpg},
    unistd::Pid,
};
use serde::{Deserialize, Serialize};
use std::{
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    process::Stdio,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{
        AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt,
        BufReader, ReadBuf,
    },
    process::{Child, Command},
    sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc},
    time::Instant,
};
use tokio_util::sync::CancellationToken;

pub(crate) const AUTH_HEADER: &str = "x-devres-git-token";
#[cfg(test)]
static COMPRESSED_UPLOADS: AtomicU64 = AtomicU64::new(0);
#[cfg(test)]
pub(crate) fn compressed_upload_count() -> u64 {
    COMPRESSED_UPLOADS.load(Ordering::Acquire)
}
const MAX_REQUEST: usize = 1024 * 1024;
const MAX_RECORD: usize = 16 * 1024 * 1024;
const MAX_MANIFEST: usize = 2 * 1024 * 1024;
const MAX_FILES: usize = 10_000;
const MAX_RECORDS: usize = 10_000_000;
const SYNC_RUNTIME: Duration = Duration::from_secs(3600);
const REPO_NAME: &str = "registry.git";
static OWNER_STAGE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GitSnapshot {
    pub revision: String,
    pub manifest: BulkArtifact,
    /// Last successful live Git observation. Offline restoration preserves it;
    /// zero identifies an older manifest without recorded observation time.
    #[serde(default)]
    pub observed_at: i64,
}
#[derive(Clone, Debug)]
pub struct GitIndexRecord {
    pub name: String,
    pub path: String,
    pub blob_oid: String,
    pub revision: String,
    pub bytes: Vec<u8>,
    pub removed: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct EvidenceFile {
    name: String,
    artifact: BulkArtifact,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct EvidenceManifest {
    version: u32,
    source_url: String,
    revision: String,
    previous_revision: Option<String>,
    #[serde(default)]
    observed_at: i64,
    shallow: Vec<String>,
    files: Vec<EvidenceFile>,
}

pub struct GitRegistry {
    root: PathBuf,
    max_repository_bytes: u64,
    sync_gate: Mutex<()>,
}
impl GitRegistry {
    pub fn new(root: impl AsRef<Path>, max_repository_bytes: u64) -> Result<Self> {
        if max_repository_bytes == 0 || max_repository_bytes > 128 * 1024 * 1024 * 1024 {
            return Err(Error::invalid("Invalid registry Git storage budget."));
        }
        std::fs::create_dir_all(root.as_ref()).map_err(|_| git_error())?;
        real_directory(root.as_ref())?;
        let root = std::fs::canonicalize(root).map_err(|_| git_error())?;
        Ok(Self {
            root,
            max_repository_bytes,
            sync_gate: Mutex::new(()),
        })
    }

    pub async fn sync(
        &self,
        broker: Arc<BulkBroker>,
        artifacts: Arc<BulkArtifactStore>,
        shutdown: CancellationToken,
    ) -> Result<GitSnapshot> {
        let deadline = Instant::now() + SYNC_RUNTIME;
        let _gate = bulk::bounded(&shutdown, deadline, async {
            Ok(self.sync_gate.lock().await)
        })
        .await?;
        self.initialize(&shutdown, deadline).await?;
        let previous = self.optional_revision(&shutdown, deadline).await?;
        let relay_stop = shutdown.child_token();
        let failure = CancellationToken::new();
        let mut relay = start_relay(broker, relay_stop.clone(), failure.clone(), deadline).await?;
        let mut command = self.command();
        let relay_header = format!("{AUTH_HEADER}: {}", relay.secret);
        command
            .env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", "http.extraHeader")
            .env("GIT_CONFIG_VALUE_0", relay_header);
        command
            .args([
                "fetch",
                "--depth=1",
                "--no-tags",
                "--no-write-fetch-head",
                "--no-auto-maintenance",
                "--update-shallow",
            ])
            .arg(&relay.url)
            .arg("+refs/heads/master:refs/devres/incoming");
        let mut child = ManagedChild::spawn(command)?;
        let transfer = self
            .wait_fetch(&mut child, &shutdown, &failure, deadline)
            .await;
        child.terminate().await?;
        relay_stop.cancel();
        let mut relay_task = relay.task.take().ok_or_else(git_error)?;
        let relay_result = tokio::time::timeout(Duration::from_secs(5), &mut relay_task).await;
        if relay_result.is_err() {
            relay_task.abort();
            let _ = relay_task.await;
        }
        if !matches!(relay_result, Ok(Ok(Ok(())))) {
            return Err(Error::unavailable(
                "Registry Git relay did not stop cleanly.",
            ));
        }
        transfer?;
        let observed_at = devres_domain::unix_now();
        let revision = self
            .run(
                &["rev-parse", "--verify", "refs/devres/incoming^{commit}"],
                128,
                &shutdown,
                deadline,
            )
            .await?;
        let revision = parse_oid_line(&revision)?;
        // This fixed ref protects every observed commit from future Git maintenance.
        let reference = format!("refs/devres/snapshots/{revision}");
        self.run(
            &["update-ref", &reference, &revision],
            128,
            &shutdown,
            deadline,
        )
        .await?;
        let manifest = self
            .capture_evidence(
                &revision,
                previous,
                observed_at,
                artifacts,
                &shutdown,
                deadline,
            )
            .await?;
        self.run(
            &["update-ref", "refs/devres/current", &revision],
            128,
            &shutdown,
            deadline,
        )
        .await?;
        Ok(GitSnapshot {
            revision,
            manifest,
            observed_at,
        })
    }

    async fn initialize(&self, shutdown: &CancellationToken, deadline: Instant) -> Result<()> {
        let repository = self.root.join(REPO_NAME);
        let repository_exists = tokio::fs::try_exists(&repository)
            .await
            .map_err(|_| git_error())?;
        if repository_exists {
            real_directory(&repository)?;
        }
        ownership_marker(&self.root, repository_exists)?;
        if repository_exists {
            recover_working_stages(&repository)?;
        }
        let mut command = base_command();
        // Reinitialization repairs an interrupted first init in this owned bare
        // directory without checking out or executing repository content.
        command
            .arg("init")
            .arg("--bare")
            .arg("--template=")
            .arg(&repository);
        run_command(command, 4096, shutdown, deadline).await?;
        sync_directory(&self.root).await
    }
    fn command(&self) -> Command {
        let mut command = base_command();
        command.arg("--git-dir").arg(self.root.join(REPO_NAME));
        command
    }
    async fn run(
        &self,
        args: &[&str],
        max_output: usize,
        shutdown: &CancellationToken,
        deadline: Instant,
    ) -> Result<Vec<u8>> {
        let mut command = self.command();
        command.args(args);
        run_command(command, max_output, shutdown, deadline).await
    }
    async fn optional_revision(
        &self,
        shutdown: &CancellationToken,
        deadline: Instant,
    ) -> Result<Option<String>> {
        let reference = self.root.join(REPO_NAME).join("refs/devres/current");
        match tokio::fs::symlink_metadata(&reference).await {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(git_error()),
            Ok(metadata) => {
                if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 128
                {
                    return Err(Error::integrity("Invalid registry Git reference."));
                }
                let bytes = self
                    .run(
                        &["rev-parse", "--verify", "refs/devres/current^{commit}"],
                        128,
                        shutdown,
                        deadline,
                    )
                    .await?;
                Ok(Some(parse_oid_line(&bytes)?))
            }
        }
    }
    async fn wait_fetch(
        &self,
        child: &mut ManagedChild,
        shutdown: &CancellationToken,
        failure: &CancellationToken,
        deadline: Instant,
    ) -> Result<()> {
        loop {
            tokio::select! { biased;
                _ = shutdown.cancelled() => return Err(Error::unavailable("Registry Git synchronization canceled.")),
                _ = failure.cancelled() => return Err(Error::unavailable("Registry Git transport failed.")),
                _ = tokio::time::sleep_until(deadline) => return Err(Error::capacity("Registry Git synchronization deadline exceeded.")),
                status = child.child.wait() => {
                    let status = status.map_err(|_| git_error())?;
                    child.finished = true;
                    return if status.success() { Ok(()) } else { Err(git_error()) };
                }
                _ = tokio::time::sleep(Duration::from_millis(250)) => {
                    directory_size(&self.root.join(REPO_NAME), self.max_repository_bytes)?;
                    if fs2::available_space(&self.root).map_err(|_| git_error())? < 1024 * 1024 * 1024 {
                        return Err(Error::capacity("Insufficient registry Git storage headroom; history is preserved."));
                    }
                }
            }
        }
    }
    async fn capture_evidence(
        &self,
        revision: &str,
        previous_revision: Option<String>,
        observed_at: i64,
        artifacts: Arc<BulkArtifactStore>,
        shutdown: &CancellationToken,
        deadline: Instant,
    ) -> Result<BulkArtifact> {
        directory_size(&self.root.join(REPO_NAME), self.max_repository_bytes)?;
        let packs = self.root.join(REPO_NAME).join("objects/pack");
        real_directory(&packs)?;
        let mut entries = tokio::fs::read_dir(&packs).await.map_err(|_| git_error())?;
        let mut files = Vec::new();
        while let Some(entry) = entries.next_entry().await.map_err(|_| git_error())? {
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| Error::integrity("Invalid registry Git evidence filename."))?;
            if !valid_pack_name(&name)
                || !entry.file_type().await.map_err(|_| git_error())?.is_file()
            {
                return Err(Error::integrity("Unexpected registry Git object file."));
            }
            if files.len() >= MAX_FILES {
                return Err(Error::capacity(
                    "Registry Git evidence file limit exceeded.",
                ));
            }
            let artifact = bulk::bounded(
                shutdown,
                deadline,
                artifacts.ingest_file(&entry.path(), bulk::MAX_ARTIFACT_BYTES, shutdown.clone()),
            )
            .await?;
            files.push(EvidenceFile { name, artifact });
        }
        files.sort_by(|a, b| a.name.cmp(&b.name));
        let shallow_path = self.root.join(REPO_NAME).join("shallow");
        let shallow = match tokio::fs::symlink_metadata(&shallow_path).await {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(_) => return Err(git_error()),
            Ok(metadata) => {
                if !metadata.is_file()
                    || metadata.file_type().is_symlink()
                    || metadata.len() > MAX_REQUEST as u64
                {
                    return Err(Error::integrity("Invalid registry Git shallow boundary."));
                }
                let bytes = tokio::fs::read(shallow_path)
                    .await
                    .map_err(|_| git_error())?;
                let text = std::str::from_utf8(&bytes)
                    .map_err(|_| Error::integrity("Invalid registry Git shallow boundary."))?;
                let mut values = Vec::new();
                for line in text.lines() {
                    if !valid_oid(line) {
                        return Err(Error::integrity("Invalid registry Git shallow commit."));
                    }
                    values.push(line.to_owned());
                }
                values.sort();
                values.dedup();
                values
            }
        };
        let manifest = EvidenceManifest {
            version: 1,
            source_url: "https://github.com/rust-lang/crates.io-index.git".into(),
            revision: revision.into(),
            previous_revision,
            observed_at,
            shallow,
            files,
        };
        let bytes = serde_json::to_vec(&manifest)
            .map_err(|_| Error::integrity("Registry Git evidence encoding failed."))?;
        if bytes.len() > MAX_MANIFEST {
            return Err(Error::capacity(
                "Registry Git manifest exceeds its byte budget.",
            ));
        }
        bulk::bounded(
            shutdown,
            deadline,
            artifacts.capture_bytes(bytes, shutdown.clone()),
        )
        .await
    }

    /// Reconstructs a bare repository from retained immutable packs, without network.
    pub async fn restore(
        &self,
        artifacts: Arc<BulkArtifactStore>,
        manifest: BulkArtifact,
        shutdown: CancellationToken,
    ) -> Result<GitSnapshot> {
        let deadline = Instant::now() + SYNC_RUNTIME;
        let _gate = bulk::bounded(&shutdown, deadline, async {
            Ok(self.sync_gate.lock().await)
        })
        .await?;
        self.initialize(&shutdown, deadline).await?;
        let file = artifacts
            .open(&manifest.body_hash, MAX_MANIFEST as u64, shutdown.clone())
            .await?;
        let mut bytes = Vec::new();
        file.take(MAX_MANIFEST as u64 + 1)
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| git_error())?;
        if bytes.len() > MAX_MANIFEST {
            return Err(Error::capacity(
                "Registry Git manifest exceeds its byte budget.",
            ));
        }
        let evidence: EvidenceManifest = serde_json::from_slice(&bytes)
            .map_err(|_| Error::integrity("Invalid registry Git evidence manifest."))?;
        if evidence.version != 1
            || evidence.observed_at < 0
            || evidence.observed_at > devres_domain::unix_now()
            || !valid_oid(&evidence.revision)
            || evidence.source_url != "https://github.com/rust-lang/crates.io-index.git"
            || evidence
                .previous_revision
                .as_ref()
                .is_some_and(|value| !valid_oid(value))
            || evidence.files.len() > MAX_FILES
            || evidence.shallow.iter().any(|value| !valid_oid(value))
        {
            return Err(Error::integrity("Invalid registry Git evidence identity."));
        }
        let pack_root = self.root.join(REPO_NAME).join("objects/pack");
        let mut seen = std::collections::HashSet::new();
        for entry in &evidence.files {
            if !valid_pack_name(&entry.name) || !seen.insert(entry.name.clone()) {
                return Err(Error::integrity("Invalid registry Git pack membership."));
            }
            let verified = artifacts
                .verify(
                    &entry.artifact.body_hash,
                    bulk::MAX_ARTIFACT_BYTES,
                    shutdown.clone(),
                )
                .await?;
            if verified != entry.artifact {
                return Err(Error::integrity("Registry Git artifact metadata mismatch."));
            }
            let source = artifacts.root().join(&entry.artifact.body_hash);
            let destination = pack_root.join(&entry.name);
            match tokio::fs::hard_link(source, &destination).await {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    // Existing Git files are not trusted merely because their names match.
                    let observed = artifacts
                        .ingest_file(&destination, bulk::MAX_ARTIFACT_BYTES, shutdown.clone())
                        .await?;
                    if observed != entry.artifact {
                        return Err(Error::integrity(
                            "Existing registry Git pack differs from retained evidence.",
                        ));
                    }
                }
                Err(_) => return Err(git_error()),
            }
            directory_size(&self.root.join(REPO_NAME), self.max_repository_bytes)?;
        }
        sync_directory(&pack_root).await?;
        if !evidence.shallow.is_empty() {
            let bytes = evidence
                .shallow
                .iter()
                .map(|revision| format!("{revision}\n"))
                .collect::<String>();
            let path = self.root.join(REPO_NAME).join("shallow");
            match tokio::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&path)
                .await
            {
                Ok(mut file) => {
                    file.write_all(bytes.as_bytes())
                        .await
                        .map_err(|_| git_error())?;
                    file.sync_all().await.map_err(|_| git_error())?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let metadata = tokio::fs::symlink_metadata(&path)
                        .await
                        .map_err(|_| git_error())?;
                    if !metadata.is_file()
                        || metadata.file_type().is_symlink()
                        || metadata.len() != bytes.len() as u64
                        || tokio::fs::read(&path).await.map_err(|_| git_error())?
                            != bytes.as_bytes()
                    {
                        return Err(Error::integrity(
                            "Existing registry Git shallow boundaries differ from retained evidence.",
                        ));
                    }
                }
                Err(_) => return Err(git_error()),
            }
        }
        let reference = format!("refs/devres/snapshots/{}", evidence.revision);
        self.run(
            &["update-ref", &reference, &evidence.revision],
            128,
            &shutdown,
            deadline,
        )
        .await?;
        self.run(
            &["fsck", "--strict", "--no-reflogs", &evidence.revision],
            MAX_REQUEST,
            &shutdown,
            deadline,
        )
        .await?;
        self.run(
            &["update-ref", "refs/devres/current", &evidence.revision],
            128,
            &shutdown,
            deadline,
        )
        .await?;
        Ok(GitSnapshot {
            revision: evidence.revision,
            manifest,
            observed_at: evidence.observed_at,
        })
    }

    /// A two-record channel bounds memory independently of registry cardinality.
    /// Dropping the receiver cancels and reaps both Git readers.
    pub async fn records(
        &self,
        snapshot: &GitSnapshot,
        previous_revision: Option<String>,
        shutdown: CancellationToken,
    ) -> Result<mpsc::Receiver<Result<GitIndexRecord>>> {
        if !valid_oid(&snapshot.revision)
            || previous_revision
                .as_ref()
                .is_some_and(|value| !valid_oid(value))
        {
            return Err(Error::invalid("Invalid registry Git revision."));
        }
        let (sender, receiver) = mpsc::channel(2);
        let root = self.root.clone();
        let revision = snapshot.revision.clone();
        tokio::spawn(async move {
            let cancellation = shutdown.child_token();
            let watcher = cancellation.clone();
            let closed = sender.clone();
            let work = read_records(
                root,
                revision,
                previous_revision,
                sender.clone(),
                cancellation,
            );
            tokio::pin!(work);
            let result = tokio::select! {
                result = &mut work => result,
                _ = closed.closed() => { watcher.cancel(); work.await }
            };
            if let Err(error) = result {
                let _ = sender.send(Err(error)).await;
            }
        });
        Ok(receiver)
    }
}

fn ownership_marker(root: &Path, repository_exists: bool) -> Result<()> {
    const CONTENT: &[u8] = b"devres registry git v1\n";
    let marker = root.join(".devres-git-owned");
    match std::fs::symlink_metadata(&marker) {
        Ok(metadata) => {
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.len() != CONTENT.len() as u64
                || std::fs::read(&marker).map_err(|_| git_error())? != CONTENT
            {
                return Err(Error::integrity(
                    "Registry Git ownership marker is invalid.",
                ));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !repository_exists => {
            use std::io::Write;
            let stage = OwnedStage(root.join(format!(
                ".git-owner-stage-{}-{}",
                std::process::id(),
                OWNER_STAGE.fetch_add(1, Ordering::Relaxed)
            )));
            let mut file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&stage.0)
                .map_err(|_| git_error())?;
            file.write_all(CONTENT).map_err(|_| git_error())?;
            file.sync_all().map_err(|_| git_error())?;
            std::fs::hard_link(&stage.0, &marker).map_err(|_| git_error())?;
            std::fs::File::open(root)
                .and_then(|file| file.sync_all())
                .map_err(|_| git_error())?;
        }
        Err(_) => return Err(Error::integrity("Registry Git ownership marker is absent.")),
    }
    for entry in std::fs::read_dir(root).map_err(|_| git_error())? {
        let entry = entry.map_err(|_| git_error())?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let recognized = name
            .strip_prefix(".git-owner-stage-")
            .and_then(|value| value.split_once('-'))
            .is_some_and(|(pid, counter)| {
                !pid.is_empty()
                    && !counter.is_empty()
                    && pid.bytes().all(|byte| byte.is_ascii_digit())
                    && counter.bytes().all(|byte| byte.is_ascii_digit())
            });
        if recognized && entry.file_type().map_err(|_| git_error())?.is_file() {
            std::fs::remove_file(entry.path()).map_err(|_| git_error())?;
        }
    }
    Ok(())
}
struct OwnedStage(PathBuf);
impl Drop for OwnedStage {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

pub(crate) fn base_command() -> Command {
    let mut command = Command::new("/usr/bin/git");
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ASKPASS", "/bin/false")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("LC_ALL", "C")
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.attributesFile=/dev/null",
            "-c",
            "credential.helper=",
            "-c",
            "protocol.allow=never",
            "-c",
            "protocol.http.allow=always",
            "-c",
            "http.followRedirects=false",
            "-c",
            "http.maxRequests=1",
            "-c",
            "protocol.version=2",
            "-c",
            "fetch.parallel=1",
            "-c",
            "fetch.fsckObjects=true",
            "-c",
            "transfer.fsckObjects=true",
            "-c",
            "fetch.unpackLimit=0",
            "-c",
            "transfer.unpackLimit=0",
            "-c",
            "transfer.bundleURI=false",
            "-c",
            "gc.auto=0",
            "-c",
            "maintenance.auto=false",
            "-c",
            "fetch.writeCommitGraph=false",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    command.process_group(0);
    command
}
pub(crate) struct ManagedChild {
    pub(crate) child: Child,
    group: Pid,
    pub(crate) finished: bool,
    group_live: bool,
}
impl ManagedChild {
    pub(crate) fn spawn(mut command: Command) -> Result<Self> {
        let mut child = command
            .spawn()
            .map_err(|_| Error::unavailable("Trusted registry Git executable unavailable."))?;
        let group = child
            .id()
            .and_then(|pid| i32::try_from(pid).ok())
            .map(Pid::from_raw);
        match group {
            Some(group) => Ok(Self {
                child,
                group,
                finished: false,
                group_live: true,
            }),
            None => {
                let _ = child.start_kill();
                Err(git_error())
            }
        }
    }
    pub(crate) async fn terminate(&mut self) -> Result<()> {
        if self.group_live {
            match killpg(self.group, Signal::SIGKILL) {
                Ok(()) | Err(nix::errno::Errno::ESRCH) => {}
                Err(_) => {
                    return Err(Error::unavailable(
                        "Registry Git process group could not be stopped.",
                    ));
                }
            }
            self.group_live = false;
        }
        if !self.finished {
            let _ = self.child.start_kill();
            tokio::time::timeout(Duration::from_secs(5), self.child.wait())
                .await
                .map_err(|_| Error::unavailable("Registry Git process did not terminate."))?
                .map_err(|_| git_error())?;
            self.finished = true;
        }
        Ok(())
    }
}
impl Drop for ManagedChild {
    fn drop(&mut self) {
        if self.group_live {
            let _ = killpg(self.group, Signal::SIGKILL);
        }
        if !self.finished {
            let _ = self.child.start_kill();
        }
    }
}
pub(crate) async fn run_command(
    mut command: Command,
    max_output: usize,
    shutdown: &CancellationToken,
    deadline: Instant,
) -> Result<Vec<u8>> {
    command.stdout(Stdio::piped());
    let mut child = ManagedChild::spawn(command)?;
    let result = async {
        let stdout = child.child.stdout.take().ok_or_else(git_error)?;
        let mut output = Vec::new();
        bulk::bounded(shutdown, deadline, async {
            stdout
                .take(max_output as u64 + 1)
                .read_to_end(&mut output)
                .await
                .map_err(|_| git_error())?;
            Ok(())
        })
        .await?;
        if output.len() > max_output {
            return Err(Error::capacity("Registry Git output exceeds its budget."));
        }
        let status = bulk::bounded(shutdown, deadline, async {
            child.child.wait().await.map_err(|_| git_error())
        })
        .await?;
        child.finished = true;
        if !status.success() {
            return Err(git_error());
        }
        Ok(output)
    }
    .await;
    child.terminate().await?;
    result
}

/// Closed set of repositories admitted by the private Git relay.
#[derive(Clone, Debug)]
pub(crate) enum GitSource {
    Registry,
    RustSec,
    MdnContent,
    MdnCompat,
    Whatwg(crate::whatwg_git::Repo),
    W3c(crate::w3c_git::Repo),
}
impl GitSource {
    fn request(&self, operation: GitOperation) -> BulkSource {
        match self {
            Self::Registry => BulkSource::RegistryGit(operation),
            Self::RustSec => BulkSource::RustSecGit(operation),
            Self::MdnContent => BulkSource::MdnContentGit(operation),
            Self::MdnCompat => BulkSource::MdnCompatGit(operation),
            Self::Whatwg(repo) => BulkSource::WhatwgGit {
                repository: repo.clone(),
                operation,
            },
            Self::W3c(repo) => BulkSource::W3cGit {
                repository: repo.clone(),
                operation,
            },
        }
    }
}
#[derive(Clone)]
struct RelayState {
    source: GitSource,
    broker: Arc<BulkBroker>,
    secret: String,
    shutdown: CancellationToken,
    failure: CancellationToken,
    failure_reason: Arc<StdMutex<Option<Error>>>,
    deadline: Instant,
}
pub(crate) struct Relay {
    pub(crate) url: String,
    pub(crate) secret: String,
    pub(crate) task: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
    pub(crate) failure_reason: Arc<StdMutex<Option<Error>>>,
    shutdown: CancellationToken,
}
struct RelayListener {
    listener: tokio::net::TcpListener,
    slots: Arc<Semaphore>,
    shutdown: CancellationToken,
}
struct RelayIo {
    stream: tokio::net::TcpStream,
    _permit: OwnedSemaphorePermit,
    closed: Pin<Box<dyn Future<Output = ()> + Send>>,
}
impl axum::serve::Listener for RelayListener {
    type Io = RelayIo;
    type Addr = std::net::SocketAddr;
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let permit = match self.slots.clone().acquire_owned().await {
                Ok(permit) => permit,
                Err(_) => {
                    tokio::task::yield_now().await;
                    continue;
                }
            };
            match self.listener.accept().await {
                Ok((stream, address)) => {
                    return (
                        RelayIo {
                            stream,
                            _permit: permit,
                            closed: Box::pin(self.shutdown.clone().cancelled_owned()),
                        },
                        address,
                    );
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
            }
        }
    }
    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}
fn relay_closed() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::ConnectionAborted,
        "Private Git relay stopped.",
    )
}
impl AsyncRead for RelayIo {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.closed.as_mut().poll(context).is_ready() {
            return Poll::Ready(Err(relay_closed()));
        }
        Pin::new(&mut this.stream).poll_read(context, buffer)
    }
}
impl AsyncWrite for RelayIo {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.closed.as_mut().poll(context).is_ready() {
            return Poll::Ready(Err(relay_closed()));
        }
        Pin::new(&mut this.stream).poll_write(context, buffer)
    }
    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.closed.as_mut().poll(context).is_ready() {
            return Poll::Ready(Err(relay_closed()));
        }
        Pin::new(&mut this.stream).poll_flush(context)
    }
    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(context)
    }
}
impl Drop for Relay {
    fn drop(&mut self) {
        self.shutdown.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
async fn start_relay(
    broker: Arc<BulkBroker>,
    shutdown: CancellationToken,
    failure: CancellationToken,
    deadline: Instant,
) -> Result<Relay> {
    start_source_relay(broker, shutdown, failure, deadline, GitSource::Registry).await
}

pub(crate) async fn start_source_relay(
    broker: Arc<BulkBroker>,
    shutdown: CancellationToken,
    failure: CancellationToken,
    deadline: Instant,
    source: GitSource,
) -> Result<Relay> {
    let mut random = [0_u8; 32];
    tokio::fs::File::open("/dev/urandom")
        .await
        .map_err(|_| git_error())?
        .read_exact(&mut random)
        .await
        .map_err(|_| git_error())?;
    let secret = hex::encode(random);
    let failure_reason = Arc::new(StdMutex::new(None));
    let state = RelayState {
        source,
        broker,
        secret: secret.clone(),
        shutdown: shutdown.clone(),
        failure,
        failure_reason: failure_reason.clone(),
        deadline,
    };
    let router = relay_router(state);
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|_| git_error())?;
    let address = listener.local_addr().map_err(|_| git_error())?;
    let listener = RelayListener {
        listener,
        slots: Arc::new(Semaphore::new(4)),
        shutdown: shutdown.clone(),
    };
    let serve_shutdown = shutdown.clone();
    let task = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(serve_shutdown.cancelled_owned())
            .await
    });
    Ok(Relay {
        url: format!("http://127.0.0.1:{}/registry.git", address.port()),
        secret,
        task: Some(task),
        failure_reason,
        shutdown,
    })
}
fn relay_router(state: RelayState) -> Router {
    Router::new()
        .route("/registry.git/info/refs", get(advertisement))
        .route("/registry.git/git-upload-pack", post(upload_pack))
        .layer(DefaultBodyLimit::max(MAX_REQUEST))
        .with_state(state)
}
fn authorized(headers: &HeaderMap, secret: &str) -> bool {
    let Some(value) = headers.get(AUTH_HEADER) else {
        return false;
    };
    let actual = value.as_bytes();
    actual.len() == secret.len()
        && actual
            .iter()
            .zip(secret.bytes())
            .fold(0_u8, |difference, (left, right)| {
                difference | (*left ^ right)
            })
            == 0
}
async fn advertisement(
    State(state): State<RelayState>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    if !authorized(&headers, &state.secret) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if query.as_deref() != Some("service=git-upload-pack") {
        return StatusCode::BAD_REQUEST.into_response();
    }
    forward_git(state, GitOperation::Advertisement, Vec::new()).await
}
async fn upload_pack(
    State(state): State<RelayState>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !authorized(&headers, &state.secret) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if query.is_some()
        || body.len() > MAX_REQUEST
        || headers
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            != Some("application/x-git-upload-pack-request")
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let body = match decode_upload_body(&body, headers.get(axum::http::header::CONTENT_ENCODING)) {
        Ok(body) => body,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    forward_git(state, GitOperation::UploadPack, body).await
}
/// Git compresses larger POST requests; the relay forwards canonical decoded bytes.
/// Both compressed and expanded input retain the same private request-size bound.
fn decode_upload_body(body: &[u8], encoding: Option<&axum::http::HeaderValue>) -> Result<Vec<u8>> {
    use std::io::Read;
    if body.len() > MAX_REQUEST {
        return Err(Error::capacity("Git request exceeds its byte budget."));
    }
    match encoding {
        None => Ok(body.to_vec()),
        Some(value) if value == "gzip" => {
            let decoder = flate2::read::MultiGzDecoder::new(body);
            let mut bytes = Vec::new();
            decoder
                .take(MAX_REQUEST as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| Error::invalid("Invalid compressed Git request."))?;
            if bytes.len() > MAX_REQUEST {
                return Err(Error::capacity(
                    "Expanded Git request exceeds its byte budget.",
                ));
            }
            #[cfg(test)]
            COMPRESSED_UPLOADS.fetch_add(1, Ordering::AcqRel);
            Ok(bytes)
        }
        Some(_) => Err(Error::invalid("Unsupported Git request content encoding.")),
    }
}
async fn forward_git(state: RelayState, operation: GitOperation, body: Vec<u8>) -> Response {
    let request = BulkRequest {
        source: state.source.request(operation),
        validators: Validators::default(),
        max_bytes: bulk::MAX_ARTIFACT_BYTES,
        deadline: state.deadline,
        body,
    };
    let operation_name = match operation {
        GitOperation::Advertisement => "advertisement",
        GitOperation::UploadPack => "upload-pack",
    };
    let result = state.broker.open(request, state.shutdown.clone()).await;
    let response = match result {
        Ok(response) if response.status == 200 => response,
        other => {
            let error = match other {
                Ok(response) => Error::unavailable(format!(
                    "Git {operation_name} upstream returned HTTP {}.",
                    response.status
                )),
                Err(error) => Error::new(
                    &error.code,
                    format!("Git {operation_name}: {}", error.message),
                ),
            };
            if let Ok(mut reason) = state.failure_reason.lock() {
                *reason = Some(error);
            }
            state.failure.cancel();
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };
    let failure = state.failure;
    let reason = state.failure_reason;
    let stream = response.stream.map(move |item| {
        item.map_err(|error| {
            if let Ok(mut reason) = reason.lock() {
                *reason = Some(Error::new(
                    &error.code,
                    format!("Git {operation_name} stream: {}", error.message),
                ));
            }
            failure.cancel();
            std::io::Error::other(error.message)
        })
    });
    let content_type = match operation {
        GitOperation::Advertisement => "application/x-git-upload-pack-advertisement",
        GitOperation::UploadPack => "application/x-git-upload-pack-result",
    };
    match Response::builder()
        .status(StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, content_type)
        .body(Body::from_stream(stream))
    {
        Ok(response) => response,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn read_records(
    root: PathBuf,
    revision: String,
    previous: Option<String>,
    sender: mpsc::Sender<Result<GitIndexRecord>>,
    shutdown: CancellationToken,
) -> Result<()> {
    let deadline = Instant::now() + SYNC_RUNTIME;
    let mut tree_command = base_command();
    tree_command.arg("--git-dir").arg(root.join(REPO_NAME));
    if let Some(previous) = &previous {
        tree_command.args([
            "diff-tree",
            "--raw",
            "-r",
            "-z",
            "--no-commit-id",
            "--no-renames",
            previous,
            &revision,
        ]);
    } else {
        tree_command.args(["ls-tree", "-r", "-z", &revision]);
    }
    tree_command.stdout(Stdio::piped());
    let mut tree = ManagedChild::spawn(tree_command)?;
    let mut cat_command = base_command();
    cat_command
        .arg("--git-dir")
        .arg(root.join(REPO_NAME))
        .args(["cat-file", "--batch"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    let mut cat = match ManagedChild::spawn(cat_command) {
        Ok(child) => child,
        Err(error) => {
            tree.terminate().await?;
            return Err(error);
        }
    };
    let result = async {
        let mut tree_output = BufReader::with_capacity(
            bulk::CHUNK_BYTES,
            tree.child.stdout.take().ok_or_else(git_error)?,
        );
        let mut cat_input = cat.child.stdin.take().ok_or_else(git_error)?;
        let mut cat_output = BufReader::with_capacity(
            bulk::CHUNK_BYTES,
            cat.child.stdout.take().ok_or_else(git_error)?,
        );
        let mut count = 0usize;
        loop {
            let Some(token) = delimited(&mut tree_output, 0, 8192, &shutdown, deadline).await?
            else {
                break;
            };
            count += 1;
            if count > MAX_RECORDS {
                return Err(Error::capacity(
                    "Registry Git record count exceeds its budget.",
                ));
            }
            let (path, oid, removed) = if previous.is_some() {
                let header = std::str::from_utf8(&token)
                    .map_err(|_| Error::integrity("Invalid registry Git change header."))?;
                let columns: Vec<_> = header.split(' ').collect();
                if columns.len() != 5
                    || !columns[0].starts_with(':')
                    || !valid_oid(columns[2])
                    || !valid_oid(columns[3])
                    || !matches!(columns[4], "A" | "M" | "D" | "T")
                {
                    return Err(Error::integrity("Unsupported registry Git change record."));
                }
                let removed = columns[4] == "D";
                if !removed && columns[1] != "100644" {
                    return Err(Error::integrity(
                        "Registry Git change is not a regular index member.",
                    ));
                }
                let path = delimited(&mut tree_output, 0, 4096, &shutdown, deadline)
                    .await?
                    .ok_or_else(|| Error::integrity("Truncated registry Git change record."))?;
                (
                    String::from_utf8(path)
                        .map_err(|_| Error::integrity("Invalid registry Git path."))?,
                    Some(columns[3].to_owned()),
                    removed,
                )
            } else {
                let token = std::str::from_utf8(&token)
                    .map_err(|_| Error::integrity("Invalid registry Git tree record."))?;
                let (header, path) = token
                    .split_once('\t')
                    .ok_or_else(|| Error::integrity("Invalid registry Git tree record."))?;
                let columns: Vec<_> = header.split(' ').collect();
                if columns.len() != 3
                    || columns[0] != "100644"
                    || columns[1] != "blob"
                    || !valid_oid(columns[2])
                {
                    return Err(Error::integrity(
                        "Registry Git tree contains a non-regular index member.",
                    ));
                }
                (path.to_owned(), Some(columns[2].to_owned()), false)
            };
            let Some(name) = index_name(&path)? else {
                continue;
            };
            if removed {
                bulk::bounded(&shutdown, deadline, async {
                    sender
                        .send(Ok(GitIndexRecord {
                            name,
                            path,
                            blob_oid: String::new(),
                            revision: revision.clone(),
                            bytes: Vec::new(),
                            removed: true,
                        }))
                        .await
                        .map_err(|_| Error::unavailable("Registry Git record consumer stopped."))
                })
                .await?;
                continue;
            }
            let object = oid.unwrap_or_else(|| format!("{revision}:{path}"));
            bulk::bounded(&shutdown, deadline, async {
                cat_input
                    .write_all(format!("{object}\n").as_bytes())
                    .await
                    .map_err(|_| git_error())
            })
            .await?;
            let header = delimited(&mut cat_output, b'\n', 256, &shutdown, deadline)
                .await?
                .ok_or_else(|| Error::integrity("Truncated registry Git object header."))?;
            let header = std::str::from_utf8(&header)
                .map_err(|_| Error::integrity("Invalid registry Git object header."))?;
            let fields: Vec<_> = header.split(' ').collect();
            if fields.len() != 3 || !valid_oid(fields[0]) || fields[1] != "blob" {
                return Err(Error::integrity("Registry Git object is not a blob."));
            }
            let length = fields[2]
                .parse::<usize>()
                .ok()
                .filter(|length| *length <= MAX_RECORD)
                .ok_or_else(|| {
                    Error::capacity("Registry Git index blob exceeds its byte budget.")
                })?;
            let mut bytes = vec![0; length];
            bulk::bounded(&shutdown, deadline, async {
                cat_output
                    .read_exact(&mut bytes)
                    .await
                    .map_err(|_| git_error())?;
                Ok(())
            })
            .await?;
            let mut newline = [0_u8; 1];
            bulk::bounded(&shutdown, deadline, async {
                cat_output
                    .read_exact(&mut newline)
                    .await
                    .map_err(|_| git_error())?;
                Ok(())
            })
            .await?;
            if newline != *b"\n" {
                return Err(Error::integrity("Invalid registry Git object framing."));
            }
            let record = GitIndexRecord {
                name,
                path,
                blob_oid: fields[0].into(),
                revision: revision.clone(),
                bytes,
                removed: false,
            };
            bulk::bounded(&shutdown, deadline, async {
                sender
                    .send(Ok(record))
                    .await
                    .map_err(|_| Error::unavailable("Registry Git record consumer stopped."))
            })
            .await?;
        }
        drop(cat_input);
        let tree_status = bulk::bounded(&shutdown, deadline, async {
            tree.child.wait().await.map_err(|_| git_error())
        })
        .await?;
        tree.finished = true;
        let cat_status = bulk::bounded(&shutdown, deadline, async {
            cat.child.wait().await.map_err(|_| git_error())
        })
        .await?;
        cat.finished = true;
        if !tree_status.success() || !cat_status.success() {
            return Err(git_error());
        }
        Ok(())
    }
    .await;
    let tree_stopped = tree.terminate().await;
    let cat_stopped = cat.terminate().await;
    result?;
    tree_stopped?;
    cat_stopped
}
fn index_name(path: &str) -> Result<Option<String>> {
    if matches!(
        path,
        "config.json" | "README.md" | "README" | ".gitignore" | ".gitattributes"
    ) || path.starts_with(".github/")
    {
        return Ok(None);
    }
    if path.len() > 256 || path.contains('\n') || path.contains('\r') || path.contains('\\') {
        return Err(Error::integrity("Invalid registry Git index path."));
    }
    let name = path
        .rsplit('/')
        .next()
        .ok_or_else(|| Error::integrity("Invalid registry Git index path."))?;
    let expected = crate::cargo::sparse_path(name)
        .map_err(|_| Error::integrity("Invalid registry Git crate name."))?;
    if path != expected || name != name.to_ascii_lowercase() {
        return Err(Error::integrity("Noncanonical registry Git index path."));
    }
    Ok(Some(name.into()))
}
pub(crate) async fn delimited<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    delimiter: u8,
    limit: usize,
    shutdown: &CancellationToken,
    deadline: Instant,
) -> Result<Option<Vec<u8>>> {
    let mut result = Vec::new();
    loop {
        let available = bulk::bounded(shutdown, deadline, async {
            reader.fill_buf().await.map_err(|_| git_error())
        })
        .await?;
        if available.is_empty() {
            return if result.is_empty() {
                Ok(None)
            } else {
                Err(Error::integrity("Truncated registry Git record."))
            };
        }
        let found = available.iter().position(|byte| *byte == delimiter);
        let take = found.map_or(available.len(), |index| index + 1);
        if take > limit.saturating_add(1).saturating_sub(result.len()) {
            return Err(Error::capacity(
                "Registry Git record exceeds its byte budget.",
            ));
        }
        result.extend_from_slice(&available[..take]);
        reader.consume(take);
        if found.is_some() {
            result.pop();
            return Ok(Some(result));
        }
    }
}
pub(crate) fn valid_oid(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
pub(crate) fn parse_oid_line(bytes: &[u8]) -> Result<String> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error::integrity("Invalid registry Git revision."))?
        .trim_end_matches('\n');
    if !valid_oid(text) {
        return Err(Error::integrity("Invalid registry Git revision."));
    }
    Ok(text.into())
}
pub(crate) fn valid_pack_name(name: &str) -> bool {
    name.strip_prefix("pack-")
        .and_then(|value| value.split_once('.'))
        .is_some_and(|(hash, suffix)| {
            valid_oid(hash) && matches!(suffix, "pack" | "idx" | "rev" | "bitmap" | "keep")
        })
}
pub(crate) fn recover_working_stages(repository: &Path) -> Result<()> {
    // A single fenced mutator owns these private temporary files. No immutable
    // archive object or observed snapshot ref is considered disposable.
    directory_size(repository, u64::MAX)?;
    for relative in [
        "shallow.lock",
        "config.lock",
        "packed-refs.lock",
        "FETCH_HEAD.lock",
        "HEAD.lock",
        "refs/devres/incoming.lock",
        "refs/devres/current.lock",
    ] {
        remove_regular_stage(&repository.join(relative))?;
    }
    let snapshots = repository.join("refs/devres/snapshots");
    if snapshots.exists() {
        for entry in std::fs::read_dir(&snapshots).map_err(|_| git_error())? {
            let entry = entry.map_err(|_| git_error())?;
            if entry
                .file_name()
                .to_string_lossy()
                .strip_suffix(".lock")
                .is_some_and(valid_oid)
            {
                remove_regular_stage(&entry.path())?;
            }
        }
    }
    let packs = repository.join("objects/pack");
    if packs.exists() {
        for entry in std::fs::read_dir(&packs).map_err(|_| git_error())? {
            let entry = entry.map_err(|_| git_error())?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let suffix = name
                .strip_prefix("tmp_pack_")
                .or_else(|| name.strip_prefix("tmp_idx_"));
            if suffix.is_some_and(|value| {
                value.len() == 6 && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
            }) {
                remove_regular_stage(&entry.path())?;
            }
        }
    }
    Ok(())
}
fn remove_regular_stage(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            std::fs::remove_file(path).map_err(|_| git_error())?;
            if let Some(parent) = path.parent() {
                std::fs::File::open(parent)
                    .and_then(|file| file.sync_all())
                    .map_err(|_| git_error())?;
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(Error::integrity("Invalid registry Git staging member.")),
    }
}
pub(crate) fn real_directory(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| git_error())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(Error::integrity("Invalid registry Git directory."));
    }
    Ok(())
}
pub(crate) fn directory_size(root: &Path, max_bytes: u64) -> Result<u64> {
    let mut pending = vec![root.to_owned()];
    let mut files = 0usize;
    let mut bytes = 0_u64;
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(directory).map_err(|_| git_error())? {
            let entry = entry.map_err(|_| git_error())?;
            let metadata = entry.metadata().map_err(|_| git_error())?;
            let kind = entry.file_type().map_err(|_| git_error())?;
            if kind.is_symlink() || (!kind.is_file() && !kind.is_dir()) {
                return Err(Error::integrity("Invalid registry Git filesystem member."));
            }
            files += 1;
            if files > 100_000 {
                return Err(Error::capacity(
                    "Registry Git filesystem member limit exceeded.",
                ));
            }
            if kind.is_dir() {
                pending.push(entry.path());
            } else {
                bytes = bytes
                    .checked_add(metadata.len())
                    .filter(|bytes| *bytes <= max_bytes)
                    .ok_or_else(|| {
                        Error::capacity("Registry Git directory exceeds its storage budget.")
                    })?;
            }
        }
    }
    Ok(bytes)
}
pub(crate) async fn sync_directory(path: &Path) -> Result<()> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || std::fs::File::open(path)?.sync_all())
        .await
        .map_err(|_| git_error())?
        .map_err(|_| git_error())
}
fn git_error() -> Error {
    Error::unavailable("Registry Git acquisition unavailable.")
}

#[cfg(test)]
mod tests {
    use super::*;
    async fn fixture_transport(router: Router) -> (Arc<BulkBroker>, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let broker = Arc::new(
            BulkBroker::fixture(url::Url::parse(&format!("http://{address}")).unwrap()).unwrap(),
        );
        (broker, server)
    }
    async fn fixture_input(registry: &GitRegistry, args: &[&str], input: &[u8]) -> Vec<u8> {
        let mut command = registry.command();
        command
            .args(args)
            .env("GIT_AUTHOR_NAME", "Public fixture")
            .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
            .env("GIT_COMMITTER_NAME", "Public fixture")
            .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
            .env("GIT_AUTHOR_DATE", "2026-01-01T00:00:00Z")
            .env("GIT_COMMITTER_DATE", "2026-01-01T00:00:00Z")
            .env("GIT_PROTOCOL", "version=2")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        let mut child = ManagedChild::spawn(command).unwrap();
        let mut stdin = child.child.stdin.take().unwrap();
        stdin.write_all(input).await.unwrap();
        drop(stdin);
        let mut bytes = Vec::new();
        child
            .child
            .stdout
            .take()
            .unwrap()
            .take(MAX_REQUEST as u64)
            .read_to_end(&mut bytes)
            .await
            .unwrap();
        let status = child.child.wait().await.unwrap();
        child.finished = true;
        child.terminate().await.unwrap();
        assert!(status.success());
        bytes
    }
    async fn fixture_commit(
        registry: &GitRegistry,
        content: Option<&[u8]>,
        parent: Option<&str>,
    ) -> String {
        let tree = if let Some(content) = content {
            let blob = parse_oid_line(
                &fixture_input(registry, &["hash-object", "-w", "--stdin"], content).await,
            )
            .unwrap();
            let rd = parse_oid_line(
                &fixture_input(
                    registry,
                    &["mktree"],
                    format!("100644 blob {blob}\tserde\n").as_bytes(),
                )
                .await,
            )
            .unwrap();
            let se = parse_oid_line(
                &fixture_input(
                    registry,
                    &["mktree"],
                    format!("040000 tree {rd}\trd\n").as_bytes(),
                )
                .await,
            )
            .unwrap();
            parse_oid_line(
                &fixture_input(
                    registry,
                    &["mktree"],
                    format!("040000 tree {se}\tse\n").as_bytes(),
                )
                .await,
            )
            .unwrap()
        } else {
            parse_oid_line(&fixture_input(registry, &["mktree"], b"").await).unwrap()
        };
        let mut args = vec!["commit-tree", &tree];
        if let Some(parent) = parent {
            args.extend(["-p", parent]);
        }
        let revision = parse_oid_line(
            &fixture_input(registry, &args, b"Synthetic public index fixture\n").await,
        )
        .unwrap();
        registry
            .run(
                &["update-ref", "refs/heads/master", &revision],
                128,
                &CancellationToken::new(),
                Instant::now() + Duration::from_secs(10),
            )
            .await
            .unwrap();
        revision
    }
    #[test]
    fn tree_paths_and_pack_names_are_not_arbitrary_paths() {
        assert_eq!(index_name("se/rd/serde").unwrap(), Some("serde".into()));
        assert!(index_name("../serde").is_err());
        assert!(index_name("se/rd/Serde").is_err());
        assert_eq!(index_name("config.json").unwrap(), None);
        assert!(valid_pack_name(&format!("pack-{}.pack", "a".repeat(40))));
        assert!(!valid_pack_name("../../pack-evil.idx"));
        assert!(!valid_pack_name(&format!(
            "pack-{}.promisor",
            "a".repeat(40)
        )));
    }
    #[tokio::test]
    async fn record_framing_is_bounded_before_allocation() {
        let token = CancellationToken::new();
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut input = BufReader::new(&b"abc\0def\0"[..]);
        assert_eq!(
            delimited(&mut input, 0, 3, &token, deadline).await.unwrap(),
            Some(b"abc".to_vec())
        );
        assert!(delimited(&mut input, 0, 2, &token, deadline).await.is_err());
    }
    #[tokio::test]
    async fn interrupted_owned_initialization_recovers_but_unowned_repositories_are_rejected() {
        let root = tempfile::tempdir().unwrap();
        let registry = GitRegistry::new(root.path(), 64 * 1024 * 1024).unwrap();
        ownership_marker(root.path(), false).unwrap();
        tokio::fs::create_dir(root.path().join(REPO_NAME))
            .await
            .unwrap();
        registry
            .initialize(
                &CancellationToken::new(),
                Instant::now() + Duration::from_secs(10),
            )
            .await
            .unwrap();
        assert!(root.path().join(REPO_NAME).join("HEAD").exists());
        let repository = root.path().join(REPO_NAME);
        tokio::fs::write(repository.join("shallow.lock"), b"abandoned")
            .await
            .unwrap();
        tokio::fs::write(
            repository.join("objects/pack/tmp_pack_ABC123"),
            b"abandoned",
        )
        .await
        .unwrap();
        tokio::fs::write(repository.join("objects/pack/operator-evidence"), b"retain")
            .await
            .unwrap();
        registry
            .initialize(
                &CancellationToken::new(),
                Instant::now() + Duration::from_secs(10),
            )
            .await
            .unwrap();
        assert!(!repository.join("shallow.lock").exists());
        assert!(!repository.join("objects/pack/tmp_pack_ABC123").exists());
        assert!(repository.join("objects/pack/operator-evidence").exists());
        let unowned_root = tempfile::tempdir().unwrap();
        tokio::fs::create_dir(unowned_root.path().join(REPO_NAME))
            .await
            .unwrap();
        let unowned = GitRegistry::new(unowned_root.path(), 64 * 1024 * 1024).unwrap();
        assert!(
            unowned
                .initialize(
                    &CancellationToken::new(),
                    Instant::now() + Duration::from_secs(10)
                )
                .await
                .is_err()
        );
        assert!(!unowned_root.path().join(".devres-git-owned").exists());
    }
    #[tokio::test]
    async fn relay_rejects_unauthorized_and_non_git_requests_without_upstream_io() {
        use axum::http::Request;
        use tower::ServiceExt;
        let state = RelayState {
            source: GitSource::Registry,
            broker: Arc::new(BulkBroker::new(Default::default()).unwrap()),
            secret: "fixture-secret".into(),
            shutdown: CancellationToken::new(),
            failure: CancellationToken::new(),
            failure_reason: Arc::new(StdMutex::new(None)),
            deadline: Instant::now() + Duration::from_secs(1),
        };
        let router = relay_router(state);
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/registry.git/info/refs?service=git-upload-pack")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/registry.git/info/refs?service=git-receive-pack")
                    .header(AUTH_HEADER, "fixture-secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/arbitrary/path")
                    .header(AUTH_HEADER, "fixture-secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
    #[tokio::test]
    async fn git_inventory_is_incremental_and_reconstructible_from_retained_packs() {
        let root = tempfile::tempdir().unwrap();
        let archive = tempfile::tempdir().unwrap();
        let registry = GitRegistry::new(root.path(), 64 * 1024 * 1024).unwrap();
        let shutdown = CancellationToken::new();
        let deadline = Instant::now() + Duration::from_secs(30);
        registry.initialize(&shutdown, deadline).await.unwrap();
        let content = b"{\"name\":\"serde\",\"vers\":\"1.0.0\"}\n";
        let first = fixture_commit(&registry, Some(content), None).await;
        registry
            .run(
                &["repack", "-a", "-d", "--no-write-bitmap-index"],
                4096,
                &shutdown,
                deadline,
            )
            .await
            .unwrap();
        let artifacts = Arc::new(BulkArtifactStore::new(archive.path(), 64 * 1024 * 1024).unwrap());
        let observed_at = devres_domain::unix_now() - 86400;
        let manifest = registry
            .capture_evidence(
                &first,
                None,
                observed_at,
                artifacts.clone(),
                &shutdown,
                deadline,
            )
            .await
            .unwrap();
        let snapshot = GitSnapshot {
            revision: first.clone(),
            manifest: manifest.clone(),
            observed_at,
        };
        let mut records = registry
            .records(&snapshot, None, shutdown.clone())
            .await
            .unwrap();
        let record = records.recv().await.unwrap().unwrap();
        assert_eq!(record.name, "serde");
        assert_eq!(record.bytes, content);
        assert!(records.recv().await.is_none());
        let second = fixture_commit(&registry, None, Some(&first)).await;
        registry
            .run(
                &["repack", "-a", "-d", "--no-write-bitmap-index"],
                4096,
                &shutdown,
                deadline,
            )
            .await
            .unwrap();
        let changed_observed_at = devres_domain::unix_now();
        let changed_manifest = registry
            .capture_evidence(
                &second,
                Some(first.clone()),
                changed_observed_at,
                artifacts.clone(),
                &shutdown,
                deadline,
            )
            .await
            .unwrap();
        let changed = GitSnapshot {
            revision: second,
            manifest: changed_manifest,
            observed_at: changed_observed_at,
        };
        let mut records = registry
            .records(&changed, Some(first.clone()), shutdown.clone())
            .await
            .unwrap();
        let record = records.recv().await.unwrap().unwrap();
        assert!(record.removed);
        assert_eq!(record.path, "se/rd/serde");
        assert!(records.recv().await.is_none());
        let restored_root = tempfile::tempdir().unwrap();
        let restored = GitRegistry::new(restored_root.path(), 64 * 1024 * 1024).unwrap();
        let restored_snapshot = restored
            .restore(artifacts, manifest, shutdown.clone())
            .await
            .unwrap();
        assert_eq!(restored_snapshot.revision, first);
        assert_eq!(
            restored_snapshot.observed_at, observed_at,
            "Offline replay must preserve the original source observation time."
        );
        let mut records = restored
            .records(&restored_snapshot, None, shutdown)
            .await
            .unwrap();
        assert_eq!(records.recv().await.unwrap().unwrap().bytes, content);
        assert!(records.recv().await.is_none());
    }
    #[tokio::test]
    async fn actual_git_fetch_uses_only_the_mediated_fixture_transport() {
        let source_root = tempfile::tempdir().unwrap();
        let source = Arc::new(GitRegistry::new(source_root.path(), 64 * 1024 * 1024).unwrap());
        let shutdown = CancellationToken::new();
        let deadline = Instant::now() + Duration::from_secs(30);
        source.initialize(&shutdown, deadline).await.unwrap();
        let first = fixture_commit(&source, Some(b"{\"name\":\"serde\"}\n"), None).await;
        let advertisement_source = source.clone();
        let upload_source = source.clone();
        let router = Router::new()
            .route(
                "/rust-lang/crates.io-index.git/info/refs",
                get(move || {
                    let source = advertisement_source.clone();
                    async move {
                        let path = source.root.join(REPO_NAME);
                        let path = path.to_str().unwrap();
                        let bytes = fixture_input(
                            &source,
                            &["upload-pack", "--stateless-rpc", "--advertise-refs", path],
                            b"",
                        )
                        .await;
                        (
                            [(
                                axum::http::header::CONTENT_TYPE,
                                "application/x-git-upload-pack-advertisement",
                            )],
                            bytes,
                        )
                    }
                }),
            )
            .route(
                "/rust-lang/crates.io-index.git/git-upload-pack",
                post(move |body: Bytes| {
                    let source = upload_source.clone();
                    async move {
                        let path = source.root.join(REPO_NAME);
                        let path = path.to_str().unwrap();
                        let bytes = fixture_input(
                            &source,
                            &["upload-pack", "--stateless-rpc", path],
                            &body,
                        )
                        .await;
                        (
                            [(
                                axum::http::header::CONTENT_TYPE,
                                "application/x-git-upload-pack-result",
                            )],
                            bytes,
                        )
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let broker = Arc::new(
            BulkBroker::fixture(url::Url::parse(&format!("http://{address}")).unwrap()).unwrap(),
        );
        let target_root = tempfile::tempdir().unwrap();
        let archive_root = tempfile::tempdir().unwrap();
        let target = GitRegistry::new(target_root.path(), 64 * 1024 * 1024).unwrap();
        let archive =
            Arc::new(BulkArtifactStore::new(archive_root.path(), 64 * 1024 * 1024).unwrap());
        let snapshot = target
            .sync(broker.clone(), archive.clone(), shutdown.clone())
            .await
            .unwrap();
        assert_eq!(snapshot.revision, first);
        let second = fixture_commit(&source, None, Some(&first)).await;
        let snapshot = target.sync(broker, archive, shutdown).await.unwrap();
        assert_eq!(snapshot.revision, second);
        server.abort();
    }
    #[test]
    fn legacy_manifest_does_not_invent_a_current_observation() {
        let manifest: EvidenceManifest = serde_json::from_value(serde_json::json!({
            "version":1,"source_url":"https://github.com/rust-lang/crates.io-index.git", "revision":"a".repeat(40),
            "previous_revision":null,"shallow":[],"files":[]
        })).unwrap();
        assert_eq!(manifest.observed_at, 0);
    }
    #[tokio::test]
    async fn future_dated_retained_evidence_cannot_claim_current_observation() {
        let root = tempfile::tempdir().unwrap();
        let archive = tempfile::tempdir().unwrap();
        let registry = GitRegistry::new(root.path(), 64 * 1024 * 1024).unwrap();
        let artifacts = Arc::new(BulkArtifactStore::new(archive.path(), 64 * 1024 * 1024).unwrap());
        let evidence = serde_json::json!({"version":1,"source_url":"https://github.com/rust-lang/crates.io-index.git","revision":"a".repeat(40),"previous_revision":null,"observed_at":devres_domain::unix_now()+3600,"shallow":[],"files":[]});
        let manifest = artifacts
            .capture_bytes(
                serde_json::to_vec(&evidence).unwrap(),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(
            registry
                .restore(artifacts, manifest, CancellationToken::new())
                .await
                .unwrap_err()
                .code,
            "integrity"
        );
        assert!(
            !root
                .path()
                .join(REPO_NAME)
                .join("refs/devres/current")
                .exists()
        );
    }
    #[tokio::test]
    async fn terminal_transport_failure_has_no_nested_git_retry_or_publication() {
        let calls = Arc::new(AtomicU64::new(0));
        let counted = calls.clone();
        let router = Router::new().route(
            "/rust-lang/crates.io-index.git/info/refs",
            get(move || {
                let counted = counted.clone();
                async move {
                    counted.fetch_add(1, Ordering::SeqCst);
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        [(axum::http::header::RETRY_AFTER, "0")],
                    )
                }
            }),
        );
        let (broker, server) = fixture_transport(router).await;
        let root = tempfile::tempdir().unwrap();
        let archive = tempfile::tempdir().unwrap();
        let target = GitRegistry::new(root.path(), 64 * 1024 * 1024).unwrap();
        let artifacts = Arc::new(BulkArtifactStore::new(archive.path(), 64 * 1024 * 1024).unwrap());
        assert!(
            tokio::time::timeout(
                Duration::from_secs(10),
                target.sync(broker, artifacts, CancellationToken::new())
            )
            .await
            .unwrap()
            .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(
            !root
                .path()
                .join(REPO_NAME)
                .join("refs/devres/current")
                .exists()
        );
        assert_eq!(std::fs::read_dir(archive.path()).unwrap().count(), 0);
        server.abort();
    }
    #[tokio::test]
    async fn canceled_git_fetch_reaps_transport_and_preserves_previous_publication() {
        let entered = Arc::new(tokio::sync::Notify::new());
        let observed = entered.clone();
        let shutdown = CancellationToken::new();
        let backend_shutdown = shutdown.clone();
        let router = Router::new().route(
            "/rust-lang/crates.io-index.git/info/refs",
            get(move || {
                let observed = observed.clone();
                let shutdown = backend_shutdown.clone();
                async move {
                    observed.notify_one();
                    shutdown.cancelled().await;
                    StatusCode::SERVICE_UNAVAILABLE
                }
            }),
        );
        let (broker, server) = fixture_transport(router).await;
        let root = tempfile::tempdir().unwrap();
        let archive = tempfile::tempdir().unwrap();
        let target = Arc::new(GitRegistry::new(root.path(), 64 * 1024 * 1024).unwrap());
        let artifacts = Arc::new(BulkArtifactStore::new(archive.path(), 64 * 1024 * 1024).unwrap());
        let worker = target.clone();
        let token = shutdown.clone();
        let task = tokio::spawn(async move { worker.sync(broker, artifacts, token).await });
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .unwrap();
        shutdown.cancel();
        assert!(
            tokio::time::timeout(Duration::from_secs(5), task)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        assert!(
            !root
                .path()
                .join(REPO_NAME)
                .join("refs/devres/current")
                .exists()
        );
        assert_eq!(std::fs::read_dir(archive.path()).unwrap().count(), 0);
        server.abort();
    }
    #[test]
    fn compressed_upload_requests_preserve_pkt_lines_and_expansion_limits() {
        use std::io::Write;
        let body = b"0014command=ls-refs\n00010009peel\n0000";
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(body).unwrap();
        let bytes = gzip.finish().unwrap();
        assert_eq!(
            decode_upload_body(&bytes, Some(&axum::http::HeaderValue::from_static("gzip")))
                .unwrap(),
            body
        );
        assert!(
            decode_upload_body(
                &bytes,
                Some(&axum::http::HeaderValue::from_static("deflate"))
            )
            .is_err()
        );
        let encoding = axum::http::HeaderValue::from_static("gzip");
        let mut bad_crc = bytes.clone();
        let crc = bad_crc.len() - 8;
        bad_crc[crc] ^= 1;
        assert!(
            decode_upload_body(&bad_crc, Some(&encoding)).is_err(),
            "CRC mismatch must fail closed"
        );
        assert!(
            decode_upload_body(&bytes[..bytes.len() - 1], Some(&encoding)).is_err(),
            "truncated trailer must fail closed"
        );
        let mut trailing = bytes.clone();
        trailing.extend_from_slice(b"trailing garbage");
        assert!(
            decode_upload_body(&trailing, Some(&encoding)).is_err(),
            "trailing non-gzip bytes must fail closed"
        );
        let exact = vec![b'x'; MAX_REQUEST];
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(&exact).unwrap();
        assert_eq!(
            decode_upload_body(&gzip.finish().unwrap(), Some(&encoding)).unwrap(),
            exact,
            "exact expanded boundary must remain usable"
        );
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(&vec![b'x'; MAX_REQUEST + 1]).unwrap();
        let oversized = gzip.finish().unwrap();
        assert_eq!(
            decode_upload_body(
                &oversized,
                Some(&axum::http::HeaderValue::from_static("gzip"))
            )
            .unwrap_err()
            .code,
            "capacity"
        );
    }
}
