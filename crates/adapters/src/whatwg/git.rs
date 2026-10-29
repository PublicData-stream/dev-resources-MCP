//! Fixed-source WHATWG Git acquisition and immutable, offline-restorable evidence.
//! No worktree, repository program, hook, submodule or remote-selected URL is used.
use crate::{
    bulk::{self, BulkArtifact, BulkArtifactStore, BulkBroker},
    crates_io::git::{
        self as crate_git, AUTH_HEADER, GitSource, ManagedChild, base_command, delimited,
        directory_size, real_directory, run_command, valid_oid, valid_pack_name,
    },
};
use devres_domain::{Error, Result};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader},
    sync::{Mutex, mpsc},
    time::Instant,
};
use tokio_util::sync::CancellationToken;

const MAX_REFS: usize = 10_000;
const MAX_COMMITS: usize = 1_000_000;
const MAX_MANIFEST: usize = 4 * 1024 * 1024;
const MAX_ORDER: u64 = 128 * 1024 * 1024;
const FETCH_RUNTIME: Duration = Duration::from_secs(3600);
const READ_RUNTIME: Duration = Duration::from_secs(15);

/// Repository identity admitted from the official catalogue, never caller input.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Repo {
    pub owner: String,
    pub name: String,
}
impl Repo {
    pub fn new(identity: &str) -> Result<Self> {
        let (owner, name) = identity
            .split_once('/')
            .ok_or_else(|| Error::invalid("Invalid WHATWG repository identity."))?;
        let valid = |v: &str| {
            !v.is_empty()
                && v.len() <= 100
                && v != "."
                && v != ".."
                && !v.starts_with('-')
                && v.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        };
        if !valid(owner) || !valid(name) || name.ends_with(".git") {
            return Err(Error::invalid("Invalid WHATWG repository identity."));
        }
        Ok(Self {
            owner: owner.into(),
            name: name.into(),
        })
    }
    pub fn as_str(&self) -> String {
        format!("{}/{}", self.owner, self.name)
    }
    pub fn source_url(&self) -> String {
        format!("https://github.com/{}/{}.git", self.owner, self.name)
    }
    fn relay(&self) -> GitSource {
        GitSource::Whatwg(self.clone())
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct RefEvidence {
    pub name: String,
    pub oid: String,
    pub object_type: String,
    pub peeled_commit: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
struct PackEvidence {
    name: String,
    artifact: BulkArtifact,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
struct Manifest {
    version: u32,
    source_url: String,
    repo: Repo,
    observed_at: i64,
    refs: Vec<RefEvidence>,
    roots: Vec<String>,
    packs: Vec<PackEvidence>,
    commits: BulkArtifact,
    total_commits: usize,
    current_ref: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Observation {
    pub repo: Repo,
    pub observed_at: i64,
    pub refs: Vec<RefEvidence>,
    pub roots: Vec<String>,
    pub manifest: BulkArtifact,
    pub commits: BulkArtifact,
    pub total_commits: usize,
    pub main_revision: Option<String>,
    pub current_ref: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Commit {
    pub revision: String,
    pub tree: String,
    pub parents: Vec<String>,
    pub committed_at: i64,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CommitOrder {
    pub revision: String,
    pub parents: Vec<String>,
    pub committed_at: i64,
}
#[derive(Clone, Debug)]
pub struct CommitPage {
    pub commits: Vec<CommitOrder>,
    pub offsets: Vec<u64>,
    pub next_offset: u64,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TreeEntry {
    pub path: String,
    pub oid: String,
    pub mode: String,
    pub kind: String,
    pub removed: bool,
    /// Reversible original path for entries outside the supported projection namespace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_path_hex: Option<String>,
}
#[derive(Clone, Debug)]
pub struct BlobPage {
    pub bytes: Vec<u8>,
    pub total_bytes: u64,
    pub body_hash: String,
}
#[derive(Clone)]
pub struct WhatwgGit {
    root: PathBuf,
    repo: Repo,
    artifacts: Arc<BulkArtifactStore>,
    max_git_bytes: u64,
    min_free_bytes: u64,
    gate: Arc<Mutex<()>>,
}
fn failure() -> Error {
    Error::unavailable("WHATWG Git operation failed.")
}
/// Only a fixed diagnostic category escapes; upstream stderr is never persisted.
fn fetch_failure_class(stderr: &[u8]) -> &'static str {
    let text = String::from_utf8_lossy(stderr).to_ascii_lowercase();
    if text.contains("fsck error") || text.contains("invalid object") || text.contains("bad object")
    {
        "object_integrity"
    } else if text.contains("curl")
        || text.contains("rpc failed")
        || text.contains("early eof")
        || text.contains("remote end hung up")
    {
        "transfer"
    } else if text.contains("repository not found")
        || text.contains("not a git repository")
        || text.contains("could not read username")
    {
        "repository_access"
    } else {
        "subprocess"
    }
}
struct Stage(PathBuf);
impl Drop for Stage {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
impl WhatwgGit {
    /// Publication inventory paths observed anywhere in retained branch/tag ancestry.
    /// Only the trusted review-drafts namespace is inspected; paths remain inert data.
    pub async fn publication_paths(
        &self,
        observation: &Observation,
        cancel: CancellationToken,
    ) -> Result<Vec<String>> {
        if observation.repo != self.repo {
            return Err(Error::invalid(
                "WHATWG publication inventory belongs to another repository.",
            ));
        }
        let deadline = Instant::now() + FETCH_RUNTIME;
        let mut args: Vec<String> = [
            "log",
            "--format=",
            "--name-only",
            "-z",
            "--no-renames",
            "--diff-filter=AM",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let mut argument_bytes = 0usize;
        for root in &observation.roots {
            check_oid(root)?;
            if let Some(commit) = self.peel_commit(root, &cancel, deadline).await? {
                argument_bytes += commit.len() + 1;
                if argument_bytes > 512 * 1024 {
                    return Err(Error::capacity(
                        "WHATWG publication inventory root arguments exceed their bound.",
                    ));
                }
                args.push(commit);
            }
        }
        if argument_bytes == 0 {
            return Ok(Vec::new());
        }
        args.extend(["--".into(), "review-drafts/".into()]);
        let arguments: Vec<&str> = args.iter().map(String::as_str).collect();
        let bytes = self
            .run(&arguments, 16 * 1024 * 1024, &cancel, deadline)
            .await?;
        let mut paths = BTreeSet::new();
        for token in bytes.split(|b| *b == 0) {
            let token = token.strip_prefix(b"\n").unwrap_or(token);
            let Ok(path) = std::str::from_utf8(token) else {
                continue;
            };
            if path.starts_with("review-drafts/") && valid_path(path) {
                paths.insert(path.into());
                if paths.len() > 100_000 {
                    return Err(Error::capacity(
                        "WHATWG publication path inventory exceeds its bound.",
                    ));
                }
            }
        }
        Ok(paths.into_iter().collect())
    }
    /// Bind retained evidence paths without creating a Git repository or artifacts.
    pub(crate) fn for_verification(
        root: &Path,
        repo: Repo,
        max_git_bytes: u64,
        min_free_bytes: u64,
    ) -> Result<Self> {
        if !(1024 * 1024..=128 * 1024 * 1024 * 1024).contains(&max_git_bytes) {
            return Err(Error::invalid("Invalid WHATWG Git storage budget."));
        }
        Repo::new(&repo.as_str())?;
        let root = root
            .join("whatwg")
            .join("git")
            .join(&repo.owner)
            .join(&repo.name);
        let artifacts = Arc::new(BulkArtifactStore::for_verification(
            root.join("artifacts"),
            min_free_bytes,
        )?);
        Ok(Self {
            root,
            repo,
            artifacts,
            max_git_bytes,
            min_free_bytes,
            gate: Arc::new(Mutex::new(())),
        })
    }
    pub fn new(
        root: &Path,
        repo: Repo,
        max_git_bytes: u64,
        min_free_bytes: u64,
        quota: Option<u64>,
    ) -> Result<Self> {
        if !(1024 * 1024..=128 * 1024 * 1024 * 1024).contains(&max_git_bytes) {
            return Err(Error::invalid("Invalid WHATWG Git storage budget."));
        }
        Repo::new(&repo.as_str())?;
        let root = root
            .join("whatwg")
            .join("git")
            .join(&repo.owner)
            .join(&repo.name);
        std::fs::create_dir_all(&root).map_err(|_| failure())?;
        real_directory(&root)?;
        let root = std::fs::canonicalize(root).map_err(|_| failure())?;
        std::fs::create_dir_all(root.join("artifacts")).map_err(|_| failure())?;
        let artifacts = Arc::new(
            BulkArtifactStore::new(root.join("artifacts"), min_free_bytes)?.with_quota(quota)?,
        );
        Ok(Self {
            root,
            repo,
            artifacts,
            max_git_bytes,
            min_free_bytes,
            gate: Arc::new(Mutex::new(())),
        })
    }
    /// Attach the WHATWG raw-object store's combined quota during fenced startup,
    /// before this Git adapter or its artifact store has been cloned or used.
    pub fn with_shared_budget(mut self, budget: &BulkArtifactStore) -> Result<Self> {
        self.artifacts.require_writable()?;
        if Arc::strong_count(&self.artifacts) != 1 {
            return Err(Error::integrity(
                "WHATWG shared budget must attach before cloning the artifact store.",
            ));
        }
        let artifacts = BulkArtifactStore::new(self.artifacts.root(), self.min_free_bytes)?
            .with_shared_budget(budget)?;
        self.artifacts = Arc::new(artifacts);
        Ok(self)
    }
    pub fn artifacts(&self) -> Arc<BulkArtifactStore> {
        self.artifacts.clone()
    }
    pub fn repository(&self) -> PathBuf {
        self.root.join("history.git")
    }
    fn command(&self) -> tokio::process::Command {
        let mut command = base_command();
        command.arg("--git-dir").arg(self.repository());
        command
    }
    async fn run(
        &self,
        args: &[&str],
        max: usize,
        cancel: &CancellationToken,
        deadline: Instant,
    ) -> Result<Vec<u8>> {
        let mut command = self.command();
        command.args(args);
        run_command(command, max, cancel, deadline).await
    }
    async fn initialize(&self, cancel: &CancellationToken, deadline: Instant) -> Result<()> {
        self.artifacts.require_writable()?;
        let marker = self.root.join("owner-v1");
        let expected = format!("devres-whatwg-{}-v1\n", self.repo.as_str());
        let exists = tokio::fs::try_exists(self.repository())
            .await
            .map_err(|_| failure())?;
        if exists {
            real_directory(&self.repository())?;
            if tokio::fs::read(&marker).await.map_err(|_| failure())? != expected.as_bytes() {
                return Err(Error::integrity("WHATWG Git ownership mismatch."));
            }
        } else {
            match tokio::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&marker)
                .await
            {
                Ok(mut file) => {
                    file.write_all(expected.as_bytes())
                        .await
                        .map_err(|_| failure())?;
                    file.sync_all().await.map_err(|_| failure())?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    if tokio::fs::read(&marker).await.map_err(|_| failure())? != expected.as_bytes()
                    {
                        return Err(Error::integrity("WHATWG Git ownership mismatch."));
                    }
                }
                Err(_) => return Err(failure()),
            }
        }
        let mut command = base_command();
        command
            .args(["init", "--bare", "--template="])
            .arg(self.repository());
        run_command(command, 4096, cancel, deadline).await?;
        recover_locks(&self.repository())?;
        crate_git::recover_working_stages(&self.repository())?;
        self.artifacts.recover_stages().await?;
        self.check_space()
    }
    fn check_space(&self) -> Result<()> {
        directory_size(&self.repository(), self.max_git_bytes)?;
        if fs2::available_space(&self.root).map_err(|_| failure())? < self.min_free_bytes {
            return Err(Error::capacity(
                "WHATWG Git storage headroom exhausted; retained evidence is preserved.",
            ));
        }
        Ok(())
    }
    pub async fn synchronize(
        &self,
        broker: Arc<BulkBroker>,
        previous: Option<&BulkArtifact>,
        cancel: CancellationToken,
    ) -> Result<Observation> {
        let deadline = Instant::now() + FETCH_RUNTIME;
        let _gate = bulk::bounded(&cancel, deadline, async { Ok(self.gate.lock().await) }).await?;
        self.initialize(&cancel, deadline).await?;
        let old = match previous {
            Some(artifact) => {
                let value = bulk::bounded(
                    &cancel,
                    deadline,
                    self.read_manifest(artifact, cancel.clone()),
                )
                .await?;
                bulk::bounded(
                    &cancel,
                    deadline,
                    self.restore_manifest(&value, &cancel, deadline),
                )
                .await?;
                Some(value)
            }
            None => None,
        };
        let stop = cancel.child_token();
        let failed = CancellationToken::new();
        let mut relay = crate_git::start_source_relay(
            broker,
            stop.clone(),
            failed.clone(),
            deadline,
            self.repo.relay(),
        )
        .await?;
        let mut command = self.command();
        command
            .env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", "http.extraHeader")
            .env(
                "GIT_CONFIG_VALUE_0",
                format!("{AUTH_HEADER}: {}", relay.secret),
            );
        command
            .args([
                "fetch",
                "--force",
                "--prune",
                "--no-tags",
                "--no-write-fetch-head",
                "--no-auto-maintenance",
            ])
            .arg(&relay.url)
            .args([
                "+refs/heads/*:refs/devres/live/heads/*",
                "+refs/tags/*:refs/devres/live/tags/*",
            ])
            .stderr(Stdio::piped());
        let mut child = ManagedChild::spawn(command)?;
        let mut stderr = child
            .child
            .stderr
            .take()
            .ok_or_else(failure)?
            .take(64 * 1024);
        let mut diagnostics = tokio::spawn(async move {
            let mut bytes = Vec::new();
            stderr
                .read_to_end(&mut bytes)
                .await
                .map_err(|_| failure())?;
            Ok::<_, Error>(bytes)
        });
        let transfer = loop {
            tokio::select! { biased;
                _ = cancel.cancelled() => break Err(Error::unavailable("WHATWG Git synchronization canceled.")),
                _ = failed.cancelled() => break Err(relay.failure_reason.lock().ok().and_then(|reason| reason.clone()).unwrap_or_else(failure)),
                _ = tokio::time::sleep_until(deadline) => break Err(Error::capacity("WHATWG Git synchronization deadline exceeded.")),
                status = child.child.wait() => { child.finished = true; break match status { Ok(status) if status.success() => Ok(()), _ => Err(failure()) }; }
                _ = tokio::time::sleep(Duration::from_millis(250)) => { if let Err(error) = self.check_space() { break Err(error); } }
            }
        };
        let stopped = child.terminate().await;
        let diagnostic_bytes =
            match tokio::time::timeout(Duration::from_secs(5), &mut diagnostics).await {
                Ok(Ok(Ok(bytes))) => bytes,
                _ => {
                    diagnostics.abort();
                    let _ = diagnostics.await;
                    Vec::new()
                }
            };
        let head = if transfer.is_ok() && stopped.is_ok() {
            let mut command = self.command();
            command
                .env("GIT_CONFIG_COUNT", "1")
                .env("GIT_CONFIG_KEY_0", "http.extraHeader")
                .env(
                    "GIT_CONFIG_VALUE_0",
                    format!("{AUTH_HEADER}: {}", relay.secret),
                );
            command.args(["ls-remote", "--symref", &relay.url, "HEAD"]);
            run_command(command, 4096, &cancel, deadline).await
        } else {
            Err(failure())
        };
        stop.cancel();
        let relay_result = if let Some(mut task) = relay.task.take() {
            match tokio::time::timeout(Duration::from_secs(5), &mut task).await {
                Ok(Ok(Ok(()))) => Ok(()),
                Ok(_) => Err(Error::unavailable("WHATWG Git relay did not stop cleanly.")),
                Err(_) => {
                    task.abort();
                    let _ = task.await;
                    Err(Error::unavailable("WHATWG Git relay did not stop cleanly."))
                }
            }
        } else {
            Err(failure())
        };
        if let Err(error) = transfer {
            if cancel.is_cancelled() {
                return Err(error);
            }
            let reason = relay
                .failure_reason
                .lock()
                .ok()
                .and_then(|reason| reason.clone());
            return Err(match reason {
                Some(reason) => Error::new(
                    &reason.code,
                    format!("WHATWG Git fetch: {}", reason.message),
                ),
                None => Error::new(
                    &error.code,
                    format!(
                        "WHATWG Git fetch failed ({}).",
                        fetch_failure_class(&diagnostic_bytes)
                    ),
                ),
            });
        }
        stopped?;
        relay_result?;
        self.check_space()?;
        let observed_at = devres_domain::unix_now();
        let refs = self.read_refs(&cancel, deadline).await?;
        let head = head.map_err(|error| {
            let reason = relay
                .failure_reason
                .lock()
                .ok()
                .and_then(|reason| reason.clone());
            match reason {
                Some(reason) => Error::new(
                    &reason.code,
                    format!("WHATWG Git HEAD advertisement: {}", reason.message),
                ),
                None => Error::new(&error.code, "WHATWG Git HEAD advertisement read failed."),
            }
        })?;
        let head = std::str::from_utf8(&head)
            .map_err(|_| Error::integrity("Invalid WHATWG default branch advertisement."))?;
        let current_ref = head
            .lines()
            .find_map(|line| {
                line.strip_prefix("ref: ")
                    .and_then(|line| line.strip_suffix("\tHEAD"))
            })
            .filter(|name| name.starts_with("refs/heads/") && valid_ref(name))
            .ok_or_else(|| {
                Error::integrity("WHATWG upstream HEAD does not name an advertised branch.")
            })?
            .to_owned();
        let current_oid = head
            .lines()
            .find_map(|line| line.strip_suffix("\tHEAD").filter(|oid| valid_oid(oid)))
            .ok_or_else(|| Error::integrity("WHATWG upstream HEAD has no commit identity."))?;
        let main_revision = refs
            .iter()
            .find(|reference| {
                reference.name == current_ref
                    && reference.peeled_commit.as_deref() == Some(current_oid)
            })
            .and_then(|reference| reference.peeled_commit.clone())
            .ok_or_else(|| {
                Error::integrity("WHATWG upstream HEAD moved outside the fixed branch observation.")
            })?;
        let mut roots: BTreeSet<String> =
            refs.iter().map(|reference| reference.oid.clone()).collect();
        if let Some(old) = old {
            roots.extend(old.roots);
        }
        if roots.len() > MAX_REFS * 10 {
            return Err(Error::capacity("WHATWG retained ref-root limit exceeded."));
        }
        for oid in &roots {
            self.run(
                &["update-ref", &format!("refs/devres/retained/{oid}"), oid],
                128,
                &cancel,
                deadline,
            )
            .await?;
        }
        self.run(
            &["fsck", "--full", "--no-reflogs", "--no-dangling"],
            1024 * 1024,
            &cancel,
            deadline,
        )
        .await?;
        let (commits, total_commits) = self.capture_commit_order(&roots, &cancel, deadline).await?;
        let packs = bulk::bounded(&cancel, deadline, self.capture_packs(cancel.clone())).await?;
        let roots: Vec<_> = roots.into_iter().collect();
        let manifest = Manifest {
            version: 1,
            source_url: self.repo.source_url(),
            repo: self.repo.clone(),
            observed_at,
            refs: refs.clone(),
            roots: roots.clone(),
            packs,
            commits: commits.clone(),
            total_commits,
            current_ref: current_ref.clone(),
        };
        let bytes = serde_json::to_vec(&manifest).map_err(|_| failure())?;
        if bytes.len() > MAX_MANIFEST {
            return Err(Error::capacity("WHATWG Git manifest exceeds 4 MiB."));
        }
        let artifact = bulk::bounded(
            &cancel,
            deadline,
            self.artifacts.capture_bytes(bytes, cancel.clone()),
        )
        .await?;
        Ok(Observation {
            repo: self.repo.clone(),
            observed_at,
            refs,
            roots,
            manifest: artifact,
            commits,
            total_commits,
            main_revision: Some(main_revision),
            current_ref,
        })
    }
    async fn read_refs(
        &self,
        cancel: &CancellationToken,
        deadline: Instant,
    ) -> Result<Vec<RefEvidence>> {
        let bytes = self
            .run(
                &[
                    "for-each-ref",
                    "--format=%(refname)%09%(objectname)%09%(objecttype)",
                    "refs/devres/live/",
                ],
                MAX_MANIFEST,
                cancel,
                deadline,
            )
            .await?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| Error::integrity("Invalid WHATWG ref encoding."))?;
        let mut refs = Vec::new();
        for line in text.lines() {
            if refs.len() >= MAX_REFS {
                return Err(Error::capacity(
                    "WHATWG advertised ref count exceeds its budget.",
                ));
            }
            let fields: Vec<_> = line.split('\t').collect();
            if fields.len() != 3
                || !valid_oid(fields[1])
                || !matches!(fields[2], "commit" | "tag" | "tree" | "blob")
            {
                return Err(Error::integrity("Invalid WHATWG ref record."));
            }
            let name = format!(
                "refs/{}",
                fields[0]
                    .strip_prefix("refs/devres/live/")
                    .ok_or_else(failure)?
            );
            if !valid_ref(&name) {
                return Err(Error::integrity("Invalid WHATWG advertised ref name."));
            }
            let peeled_commit = self.peel_commit(fields[1], cancel, deadline).await?;
            refs.push(RefEvidence {
                name,
                oid: fields[1].into(),
                object_type: fields[2].into(),
                peeled_commit,
            });
        }
        Ok(refs)
    }
    async fn peel_commit(
        &self,
        oid: &str,
        cancel: &CancellationToken,
        deadline: Instant,
    ) -> Result<Option<String>> {
        let mut oid = oid.to_owned();
        for _ in 0..64 {
            match self
                .run(&["cat-file", "-t", &oid], 64, cancel, deadline)
                .await?
                .as_slice()
            {
                b"commit\n" => return Ok(Some(oid)),
                b"blob\n" | b"tree\n" => return Ok(None),
                b"tag\n" => {
                    let bytes = self
                        .run(&["cat-file", "tag", &oid], 1024 * 1024, cancel, deadline)
                        .await?;
                    oid = std::str::from_utf8(
                        bytes
                            .split(|byte| *byte == b'\n')
                            .next()
                            .ok_or_else(failure)?,
                    )
                    .ok()
                    .and_then(|line| line.strip_prefix("object "))
                    .filter(|value| valid_oid(value))
                    .ok_or_else(|| Error::integrity("Invalid WHATWG annotated tag target."))?
                    .into();
                }
                _ => return Err(Error::integrity("Unsupported WHATWG Git object type.")),
            }
        }
        Err(Error::capacity("WHATWG tag nesting exceeds 64."))
    }
    async fn capture_commit_order(
        &self,
        roots: &BTreeSet<String>,
        cancel: &CancellationToken,
        deadline: Instant,
    ) -> Result<(BulkArtifact, usize)> {
        let stage = self.root.join("commit-order.stage");
        match tokio::fs::symlink_metadata(&stage).await {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                tokio::fs::remove_file(&stage)
                    .await
                    .map_err(|_| failure())?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err(Error::integrity("Invalid WHATWG commit-order stage.")),
        }
        let _guard = Stage(stage.clone());
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&stage)
            .await
            .map_err(|_| failure())?;
        let mut command = self.command();
        command
            .args([
                "rev-list",
                "--topo-order",
                "--reverse",
                "--parents",
                "--timestamp",
                "--stdin",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        let mut commits = BTreeSet::new();
        for root in roots {
            if let Some(commit) = self.peel_commit(root, cancel, deadline).await? {
                commits.insert(commit);
            }
        }
        let mut child = ManagedChild::spawn(command)?;
        let result = async {
            let mut input = child.child.stdin.take().ok_or_else(failure)?;
            for commit in &commits {
                bulk::bounded(cancel, deadline, async {
                    input
                        .write_all(format!("{commit}\n").as_bytes())
                        .await
                        .map_err(|_| failure())
                })
                .await?;
            }
            drop(input);
            let mut reader = BufReader::new(child.child.stdout.take().ok_or_else(failure)?);
            let mut count = 0usize;
            let mut written = 0u64;
            while let Some(line) =
                delimited(&mut reader, b'\n', 64 * 1024, cancel, deadline).await?
            {
                parse_commit_order(&line)?;
                count += 1;
                written += line.len() as u64 + 1;
                if count > MAX_COMMITS || written > MAX_ORDER {
                    return Err(Error::capacity(
                        "WHATWG commit enumeration exceeds its budget.",
                    ));
                }
                file.write_all(&line).await.map_err(|_| failure())?;
                file.write_all(b"\n").await.map_err(|_| failure())?;
            }
            let status = bulk::bounded(cancel, deadline, async {
                child.child.wait().await.map_err(|_| failure())
            })
            .await?;
            child.finished = true;
            if !status.success() {
                return Err(failure());
            }
            file.sync_all().await.map_err(|_| failure())?;
            Ok(count)
        }
        .await;
        child.terminate().await?;
        let count = result?;
        drop(file);
        let artifact = bulk::bounded(
            cancel,
            deadline,
            self.artifacts
                .ingest_file(&stage, MAX_ORDER, cancel.clone()),
        )
        .await?;
        Ok((artifact, count))
    }
    async fn capture_packs(&self, cancel: CancellationToken) -> Result<Vec<PackEvidence>> {
        let root = self.repository().join("objects/pack");
        real_directory(&root)?;
        let mut entries = tokio::fs::read_dir(root).await.map_err(|_| failure())?;
        let mut packs = Vec::new();
        while let Some(entry) = entries.next_entry().await.map_err(|_| failure())? {
            let name = entry.file_name().into_string().map_err(|_| failure())?;
            if !valid_pack_name(&name) || !entry.file_type().await.map_err(|_| failure())?.is_file()
            {
                return Err(Error::integrity("Invalid WHATWG Git pack member."));
            }
            if packs.len() >= 10_000 {
                return Err(Error::capacity("WHATWG Git pack count exceeds its budget."));
            }
            let artifact = self
                .artifacts
                .ingest_file(&entry.path(), bulk::MAX_ARTIFACT_BYTES, cancel.clone())
                .await?;
            packs.push(PackEvidence { name, artifact });
        }
        packs.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(packs)
    }
    async fn read_manifest(
        &self,
        artifact: &BulkArtifact,
        cancel: CancellationToken,
    ) -> Result<Manifest> {
        let mut file = self
            .artifacts
            .open(&artifact.body_hash, MAX_MANIFEST as u64, cancel)
            .await?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).await.map_err(|_| failure())?;
        if bytes.len() as u64 != artifact.bytes {
            return Err(Error::integrity("WHATWG manifest metadata mismatch."));
        }
        let value: Manifest = serde_json::from_slice(&bytes)
            .map_err(|_| Error::integrity("Invalid WHATWG Git manifest."))?;
        if value.version != 1
            || value.repo != self.repo
            || value.source_url != self.repo.source_url()
            || value.observed_at < 0
            || value.observed_at > devres_domain::unix_now()
            || value.refs.len() > MAX_REFS
            || value.roots.len() > MAX_REFS * 10
            || value.packs.len() > 10_000
            || value.total_commits > MAX_COMMITS
            || !value.current_ref.starts_with("refs/heads/")
            || !value.refs.iter().any(|reference| {
                reference.name == value.current_ref && reference.peeled_commit.is_some()
            })
            || value.roots.iter().any(|oid| !valid_oid(oid))
            || value.refs.iter().any(|reference| {
                !valid_ref(&reference.name)
                    || !valid_oid(&reference.oid)
                    || !matches!(
                        reference.object_type.as_str(),
                        "commit" | "tag" | "tree" | "blob"
                    )
                    || reference
                        .peeled_commit
                        .as_ref()
                        .is_some_and(|oid| !valid_oid(oid))
            })
        {
            return Err(Error::integrity("Invalid WHATWG Git manifest identity."));
        }
        Ok(value)
    }
    pub async fn restore(&self, artifact: &BulkArtifact, cancel: CancellationToken) -> Result<()> {
        let deadline = Instant::now() + FETCH_RUNTIME;
        let _gate = bulk::bounded(&cancel, deadline, async { Ok(self.gate.lock().await) }).await?;
        self.initialize(&cancel, deadline).await?;
        let value = bulk::bounded(
            &cancel,
            deadline,
            self.read_manifest(artifact, cancel.clone()),
        )
        .await?;
        bulk::bounded(
            &cancel,
            deadline,
            self.restore_manifest(&value, &cancel, deadline),
        )
        .await
    }
    async fn restore_manifest(
        &self,
        manifest: &Manifest,
        cancel: &CancellationToken,
        deadline: Instant,
    ) -> Result<()> {
        if self
            .artifacts
            .verify(&manifest.commits.body_hash, MAX_ORDER, cancel.clone())
            .await?
            != manifest.commits
        {
            return Err(Error::integrity("WHATWG commit-order metadata mismatch."));
        }
        let root = self.repository().join("objects/pack");
        let mut names = BTreeSet::new();
        for pack in &manifest.packs {
            if !valid_pack_name(&pack.name) || !names.insert(&pack.name) {
                return Err(Error::integrity("Invalid WHATWG retained pack name."));
            }
            if self
                .artifacts
                .verify(
                    &pack.artifact.body_hash,
                    bulk::MAX_ARTIFACT_BYTES,
                    cancel.clone(),
                )
                .await?
                != pack.artifact
            {
                return Err(Error::integrity("WHATWG retained pack metadata mismatch."));
            }
            let target = root.join(&pack.name);
            match tokio::fs::hard_link(
                self.artifacts.root().join(&pack.artifact.relative_path),
                &target,
            )
            .await
            {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let actual = self
                        .artifacts
                        .ingest_file(&target, bulk::MAX_ARTIFACT_BYTES, cancel.clone())
                        .await?;
                    let matches = if pack.artifact.body_hash.starts_with("blake3:") {
                        actual == pack.artifact
                    } else {
                        actual.bytes == pack.artifact.bytes
                            && crate::integrity::verify_legacy_digest(
                                &self.artifacts.root().join(&pack.artifact.relative_path),
                                &actual.body_hash,
                                actual.bytes,
                            )
                            .is_ok()
                    };
                    if !matches {
                        return Err(Error::integrity(
                            "WHATWG working pack differs from retained evidence.",
                        ));
                    }
                }
                Err(_) => return Err(failure()),
            }
        }
        crate_git::sync_directory(&root).await?;
        for oid in &manifest.roots {
            self.run(
                &["update-ref", &format!("refs/devres/retained/{oid}"), oid],
                128,
                cancel,
                deadline,
            )
            .await?;
        }
        self.run(
            &["fsck", "--full", "--no-reflogs", "--no-dangling"],
            1024 * 1024,
            cancel,
            deadline,
        )
        .await?;
        self.check_space()
    }
    pub async fn commit_page(
        &self,
        observation: &Observation,
        offset: u64,
        limit: usize,
        cancel: CancellationToken,
    ) -> Result<CommitPage> {
        if observation.repo != self.repo
            || offset > observation.commits.bytes
            || !(1..=1000).contains(&limit)
        {
            return Err(Error::invalid("Invalid WHATWG commit page."));
        }
        let deadline = Instant::now() + READ_RUNTIME;
        let mut file = bulk::bounded(
            &cancel,
            deadline,
            self.artifacts
                .open(&observation.commits.body_hash, MAX_ORDER, cancel.clone()),
        )
        .await?;
        if offset > 0 {
            file.seek(std::io::SeekFrom::Start(offset - 1))
                .await
                .map_err(|_| failure())?;
            let mut byte = [0];
            file.read_exact(&mut byte).await.map_err(|_| failure())?;
            if byte != *b"\n" {
                return Err(Error::invalid(
                    "WHATWG commit offset must be a line boundary.",
                ));
            }
        } else {
            file.seek(std::io::SeekFrom::Start(0))
                .await
                .map_err(|_| failure())?;
        }
        let mut reader = BufReader::new(file);
        let mut commits = Vec::new();
        let mut offsets = Vec::new();
        let mut next_offset = offset;
        while commits.len() < limit {
            let Some(line) = delimited(&mut reader, b'\n', 64 * 1024, &cancel, deadline).await?
            else {
                break;
            };
            next_offset += line.len() as u64 + 1;
            commits.push(parse_commit_order(&line)?);
            offsets.push(next_offset);
        }
        if next_offset > observation.commits.bytes {
            return Err(Error::integrity(
                "WHATWG commit order exceeds its descriptor.",
            ));
        }
        Ok(CommitPage {
            commits,
            offsets,
            next_offset,
        })
    }
    pub async fn commit(&self, oid: &str, cancel: CancellationToken) -> Result<Commit> {
        check_oid(oid)?;
        let bytes = self
            .run(
                &[
                    "show",
                    "-s",
                    "--no-show-signature",
                    "--format=%H%x00%T%x00%ct%x00%P",
                    oid,
                    "--",
                ],
                128 * 1024,
                &cancel,
                Instant::now() + READ_RUNTIME,
            )
            .await?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| Error::integrity("Invalid WHATWG commit descriptor."))?;
        let fields: Vec<_> = text.trim_end_matches('\n').split('\0').collect();
        if fields.len() != 4 || fields[0] != oid || !valid_oid(fields[1]) {
            return Err(Error::integrity("Invalid WHATWG commit identity."));
        }
        let committed_at = fields[2]
            .parse()
            .map_err(|_| Error::integrity("Invalid WHATWG commit time."))?;
        let parents: Vec<_> = fields[3].split_whitespace().map(str::to_owned).collect();
        if parents.len() > 1024 || parents.iter().any(|parent| !valid_oid(parent)) {
            return Err(Error::integrity("Invalid WHATWG commit parents."));
        }
        Ok(Commit {
            revision: oid.into(),
            tree: fields[1].into(),
            parents,
            committed_at,
        })
    }
    /// Stream all leaves, or a first-parent delta. Bounded queue ownership ends when the reader drops.
    pub fn records(
        &self,
        revision: &str,
        previous: Option<&str>,
        cancel: CancellationToken,
    ) -> Result<mpsc::Receiver<Result<TreeEntry>>> {
        check_oid(revision)?;
        if let Some(previous) = previous {
            check_oid(previous)?;
        }
        let repository = self.clone();
        let revision = revision.to_owned();
        let previous = previous.map(str::to_owned);
        let (sender, receiver) = mpsc::channel(32);
        tokio::spawn(async move {
            let result = repository
                .stream_records(&revision, previous.as_deref(), &sender, &cancel)
                .await;
            if let Err(error) = result {
                let _ = sender.send(Err(error)).await;
            }
        });
        Ok(receiver)
    }
    async fn stream_records(
        &self,
        revision: &str,
        previous: Option<&str>,
        sender: &mpsc::Sender<Result<TreeEntry>>,
        cancel: &CancellationToken,
    ) -> Result<()> {
        let deadline = Instant::now() + FETCH_RUNTIME;
        let mut command = self.command();
        if let Some(previous) = previous {
            command.args([
                "diff-tree",
                "--raw",
                "-r",
                "-z",
                "--no-commit-id",
                "--no-renames",
                "--no-ext-diff",
                previous,
                revision,
                "--",
            ]);
        } else {
            command.args(["ls-tree", "-r", "-z", revision]);
        }
        command.stdout(Stdio::piped());
        let mut child = ManagedChild::spawn(command)?;
        let result = async {
            let mut reader = BufReader::new(child.child.stdout.take().ok_or_else(failure)?); let mut count=0;
            loop {
                let token = tokio::select! { biased; _=sender.closed()=>return Ok(()), value=delimited(&mut reader, 0, 8192, cancel, deadline)=>value? };
                let Some(token)=token else { break; }; count+=1;
                if count > 1_000_000 { return Err(Error::capacity("WHATWG tree entries exceed their budget.")); }
                let entry = if previous.is_some() {
                    let path = delimited(&mut reader, 0, 4096, cancel, deadline).await?.ok_or_else(||Error::integrity("Truncated WHATWG diff path."))?;
                    parse_diff(&token, &path)?
                } else { parse_tree(&token)? };
                tokio::select! { biased; _=sender.closed()=>return Ok(()), _=cancel.cancelled()=>return Err(failure()), result=sender.send(Ok(entry))=> { if result.is_err() { return Ok(()); } } }
            }
            let status = bulk::bounded(cancel, deadline, async { child.child.wait().await.map_err(|_|failure()) }).await?;
            child.finished=true; if !status.success(){return Err(failure());} Ok(())
        }.await;
        child.terminate().await?;
        result
    }
    /// Lookup one literal Git path without allowing pathspec magic or following links.
    pub async fn entry(
        &self,
        revision: &str,
        path: &str,
        cancel: CancellationToken,
    ) -> Result<Option<TreeEntry>> {
        check_oid(revision)?;
        if !valid_path(path) {
            return Err(Error::invalid("Invalid WHATWG source path."));
        }
        let bytes = self
            .run(
                &["--literal-pathspecs", "ls-tree", "-z", revision, "--", path],
                8192,
                &cancel,
                Instant::now() + READ_RUNTIME,
            )
            .await?;
        if bytes.is_empty() {
            return Ok(None);
        }
        if bytes.last() != Some(&0) || bytes[..bytes.len() - 1].contains(&0) {
            return Err(Error::integrity("Invalid WHATWG exact path result."));
        }
        let entry = parse_tree(&bytes[..bytes.len() - 1])?;
        if entry.path != path {
            return Err(Error::integrity(
                "WHATWG source lookup returned another path.",
            ));
        }
        Ok(Some(entry))
    }
    pub async fn blob_size(&self, oid: &str, cancel: CancellationToken) -> Result<u64> {
        check_oid(oid)?;
        self.blob_length(oid, &cancel, Instant::now() + READ_RUNTIME)
            .await
    }
    pub async fn read_blob(
        &self,
        oid: &str,
        max_bytes: usize,
        cancel: CancellationToken,
    ) -> Result<Vec<u8>> {
        check_oid(oid)?;
        if max_bytes == 0 || max_bytes > 64 * 1024 * 1024 {
            return Err(Error::invalid("Invalid WHATWG blob read budget."));
        }
        let deadline = Instant::now() + READ_RUNTIME;
        let length = self.blob_length(oid, &cancel, deadline).await?;
        self.read_blob_at_length(oid, length, max_bytes, &cancel, deadline)
            .await
    }
    /// Use a size already observed from this owned repository, without a second
    /// metadata subprocess. The actual body length and Git object hash are still
    /// verified before any bytes are returned.
    pub async fn read_blob_known_length(
        &self,
        oid: &str,
        length: u64,
        max_bytes: usize,
        cancel: CancellationToken,
    ) -> Result<Vec<u8>> {
        check_oid(oid)?;
        if max_bytes == 0 || max_bytes > 64 * 1024 * 1024 {
            return Err(Error::invalid("Invalid WHATWG blob read budget."));
        }
        self.read_blob_at_length(
            oid,
            length,
            max_bytes,
            &cancel,
            Instant::now() + READ_RUNTIME,
        )
        .await
    }
    async fn read_blob_at_length(
        &self,
        oid: &str,
        length: u64,
        max_bytes: usize,
        cancel: &CancellationToken,
        deadline: Instant,
    ) -> Result<Vec<u8>> {
        if length > max_bytes as u64 {
            return Err(Error::capacity(
                "WHATWG blob exceeds the projection input budget.",
            ));
        }
        let bytes = self
            .run(&["cat-file", "blob", oid], max_bytes, cancel, deadline)
            .await?;
        if bytes.len() as u64 != length {
            return Err(Error::integrity("WHATWG blob length mismatch."));
        }
        let mut git_hash = Sha1::new();
        git_hash.update(format!("blob {length}\0").as_bytes());
        git_hash.update(&bytes);
        if hex::encode(git_hash.finalize()) != oid {
            return Err(Error::integrity("WHATWG Git blob object hash mismatch."));
        }
        Ok(bytes)
    }
    async fn blob_length(
        &self,
        oid: &str,
        cancel: &CancellationToken,
        deadline: Instant,
    ) -> Result<u64> {
        let bytes = self
            .run(&["cat-file", "-s", oid], 64, cancel, deadline)
            .await?;
        std::str::from_utf8(&bytes)
            .ok()
            .and_then(|value| value.trim().parse().ok())
            .filter(|size| *size <= bulk::MAX_ARTIFACT_BYTES)
            .ok_or_else(|| Error::capacity("WHATWG raw blob size exceeds its read bound."))
    }
    /// Hash the entire original object while retaining only the requested binary page.
    pub async fn blob_page(
        &self,
        oid: &str,
        offset: u64,
        limit: usize,
        cancel: CancellationToken,
    ) -> Result<BlobPage> {
        check_oid(oid)?;
        if !(1..=32768).contains(&limit) {
            return Err(Error::invalid("WHATWG raw page limit must be 1..32768."));
        }
        let deadline = Instant::now() + READ_RUNTIME;
        let total = self.blob_length(oid, &cancel, deadline).await?;
        if offset > total {
            return Err(Error::invalid("WHATWG raw offset exceeds source length."));
        }
        let mut command = self.command();
        command
            .args(["cat-file", "blob", oid])
            .stdout(Stdio::piped());
        let mut child = ManagedChild::spawn(command)?;
        let result = async {
            let mut reader = child.child.stdout.take().ok_or_else(failure)?;
            let mut digest = blake3::Hasher::new();
            let mut git_hash = Sha1::new();
            git_hash.update(format!("blob {total}\0").as_bytes());
            let mut position = 0u64;
            let mut bytes = Vec::with_capacity(limit);
            let mut chunk = vec![0; bulk::CHUNK_BYTES];
            loop {
                let read = bulk::bounded(&cancel, deadline, async {
                    reader.read(&mut chunk).await.map_err(|_| failure())
                })
                .await?;
                if read == 0 {
                    break;
                }
                let end = position + read as u64;
                if end > total {
                    return Err(Error::integrity("WHATWG raw blob grew during read."));
                }
                digest.update(&chunk[..read]);
                git_hash.update(&chunk[..read]);
                let start = position.max(offset);
                let stop = end.min(offset.saturating_add(limit as u64));
                if start < stop {
                    bytes.extend_from_slice(
                        &chunk[(start - position) as usize..(stop - position) as usize],
                    );
                }
                position = end;
            }
            let status = bulk::bounded(&cancel, deadline, async {
                child.child.wait().await.map_err(|_| failure())
            })
            .await?;
            child.finished = true;
            if !status.success() || position != total {
                return Err(Error::integrity("WHATWG raw blob read failed."));
            }
            if hex::encode(git_hash.finalize()) != oid {
                return Err(Error::integrity("WHATWG Git blob object hash mismatch."));
            }
            Ok(BlobPage {
                bytes,
                total_bytes: total,
                body_hash: format!("blake3:{}", digest.finalize().to_hex()),
            })
        }
        .await;
        child.terminate().await?;
        result
    }
}
fn check_oid(oid: &str) -> Result<()> {
    if valid_oid(oid) {
        Ok(())
    } else {
        Err(Error::invalid("Invalid WHATWG Git object identity."))
    }
}
fn valid_ref(name: &str) -> bool {
    (name.starts_with("refs/heads/") || name.starts_with("refs/tags/"))
        && name.len() <= 1024
        && !name.contains("..")
        && !name.contains("@{")
        && !name.ends_with('.')
        && !name.contains(['\\', ' ', '~', '^', ':', '?', '*', '['])
        && !name.chars().any(char::is_control)
        && name
            .split('/')
            .all(|part| !part.is_empty() && !part.starts_with('.') && !part.ends_with(".lock"))
}
fn valid_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 4096
        && !path.chars().any(char::is_control)
        && !path.contains('\\')
        && path.split('/').all(|part| !matches!(part, "" | "." | ".."))
}
fn parse_commit_order(bytes: &[u8]) -> Result<CommitOrder> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error::integrity("Invalid WHATWG commit-order encoding."))?;
    let mut fields = text.split(' ');
    let committed_at = fields
        .next()
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| Error::integrity("Invalid WHATWG commit-order time."))?;
    let revision = fields
        .next()
        .filter(|value| valid_oid(value))
        .ok_or_else(|| Error::integrity("Invalid WHATWG commit-order identity."))?
        .into();
    let parents: Vec<_> = fields.map(str::to_owned).collect();
    if parents.len() > 1024 || parents.iter().any(|parent| !valid_oid(parent)) {
        return Err(Error::integrity("Invalid WHATWG commit-order parents."));
    }
    Ok(CommitOrder {
        revision,
        parents,
        committed_at,
    })
}
fn encoded_path(bytes: &[u8]) -> (String, Option<String>) {
    if let Ok(path) = std::str::from_utf8(bytes)
        && valid_path(path)
        && path.split('/').count() <= 64
        && !matches!(
            path.split('/').next(),
            Some("@unsupported-path" | "@unsupported" | "@features" | "@browsers" | "@ambiguities")
        )
    {
        return (path.into(), None);
    }
    (
        format!("@unsupported-path/{}", crate::integrity::hash(bytes)),
        Some(hex::encode(bytes)),
    )
}
fn parse_tree(token: &[u8]) -> Result<TreeEntry> {
    let split = token
        .iter()
        .position(|byte| *byte == b'\t')
        .ok_or_else(|| Error::integrity("Invalid WHATWG Git tree entry."))?;
    let header = std::str::from_utf8(&token[..split])
        .map_err(|_| Error::integrity("Invalid WHATWG Git tree header."))?;
    let raw_path = &token[split + 1..];
    let fields: Vec<_> = header.split(' ').collect();
    if fields.len() != 3
        || !valid_oid(fields[2])
        || raw_path.is_empty()
        || !matches!(
            (fields[0], fields[1]),
            ("100644" | "100755" | "120000", "blob") | ("160000", "commit")
        )
    {
        return Err(Error::integrity("Invalid WHATWG Git tree entry."));
    }
    let (path, raw_path_hex) = encoded_path(raw_path);
    Ok(TreeEntry {
        path,
        oid: fields[2].into(),
        mode: fields[0].into(),
        kind: fields[1].into(),
        removed: false,
        raw_path_hex,
    })
}
fn parse_diff(token: &[u8], raw_path: &[u8]) -> Result<TreeEntry> {
    let header = std::str::from_utf8(token)
        .map_err(|_| Error::integrity("Invalid WHATWG Git diff entry."))?;
    let fields: Vec<_> = header.split(' ').collect();
    if fields.len() != 5
        || !fields[0].starts_with(':')
        || !valid_oid(fields[2])
        || !valid_oid(fields[3])
        || raw_path.is_empty()
        || !matches!(fields[4], "A" | "M" | "D" | "T")
    {
        return Err(Error::integrity("Invalid WHATWG Git diff entry."));
    }
    let removed = fields[4] == "D";
    let mode = if removed { &fields[0][1..] } else { fields[1] };
    let oid = if removed { fields[2] } else { fields[3] };
    let kind = match mode {
        "100644" | "100755" | "120000" => "blob",
        "160000" => "commit",
        _ => return Err(Error::integrity("Unsupported WHATWG Git member mode.")),
    };
    let (path, raw_path_hex) = encoded_path(raw_path);
    Ok(TreeEntry {
        path,
        oid: oid.into(),
        mode: mode.into(),
        kind: kind.into(),
        removed,
        raw_path_hex,
    })
}
fn recover_locks(repository: &Path) -> Result<()> {
    directory_size(repository, u64::MAX)?;
    fn walk(path: &Path) -> Result<()> {
        if !path.exists() {
            return Ok(());
        }
        for entry in std::fs::read_dir(path).map_err(|_| failure())? {
            let entry = entry.map_err(|_| failure())?;
            let kind = entry.file_type().map_err(|_| failure())?;
            if kind.is_symlink() {
                return Err(Error::integrity("Unexpected WHATWG working symlink."));
            }
            if kind.is_dir() {
                walk(&entry.path())?;
            } else if entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.ends_with(".lock"))
            {
                std::fs::remove_file(entry.path()).map_err(|_| failure())?;
            }
        }
        Ok(())
    }
    walk(&repository.join("refs"))?;
    for name in [
        "config.lock",
        "packed-refs.lock",
        "HEAD.lock",
        "FETCH_HEAD.lock",
    ] {
        let path = repository.join(name);
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                std::fs::remove_file(path).map_err(|_| failure())?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err(Error::integrity("Invalid WHATWG working lock.")),
        }
    }
    Ok(())
}

impl WhatwgGit {
    /// Derive a new service-owned manifest without changing retained upstream
    /// Git objects, refs, observation time or the exact original manifest bytes.
    pub async fn migrate_blake3_manifest(
        &self,
        original: &BulkArtifact,
        mappings: &mut std::collections::BTreeMap<String, String>,
        cancel: CancellationToken,
    ) -> Result<BulkArtifact> {
        let mut manifest = self.read_manifest(original, cancel.clone()).await?;
        let rewrite = |artifact: &mut BulkArtifact| -> Result<()> {
            if artifact.body_hash.starts_with("blake3:") {
                return Ok(());
            }
            artifact.body_hash =
                crate::integrity::migration_lookup(mappings, "body", &artifact.body_hash)
                    .cloned()
                    .ok_or_else(|| {
                        Error::integrity("Retained Git manifest body is not qualified.")
                    })?;
            artifact.relative_path = crate::integrity::relative_path(&artifact.body_hash)?
                .to_string_lossy()
                .into_owned();
            Ok(())
        };
        rewrite(&mut manifest.commits)?;
        for pack in &mut manifest.packs {
            rewrite(&mut pack.artifact)?;
        }

        let bytes = serde_json::to_vec(&manifest)
            .map_err(|_| Error::integrity("Invalid canonical Git manifest."))?;
        if bytes.len() > MAX_MANIFEST {
            return Err(Error::capacity(
                "Canonical Git manifest exceeds its byte bound.",
            ));
        }
        let canonical = self.artifacts.capture_bytes(bytes, cancel.clone()).await?;
        self.verify_retained_manifest(&canonical, cancel).await?;
        let role = "whatwg:manifest";
        if crate::integrity::migration_lookup(mappings, role, &original.body_hash)
            .is_some_and(|existing| existing != &canonical.body_hash)
        {
            return Err(Error::integrity(
                "Conflicting canonical Git manifest mapping.",
            ));
        }
        crate::migration_map::insert(
            mappings,
            format!("{role}:{}", original.body_hash),
            canonical.body_hash.clone(),
        )?;
        crate::migration_map::insert(
            mappings,
            format!("whatwg:manifest-descriptor:{}", original.body_hash),
            serde_json::to_string(&canonical)
                .map_err(|_| Error::integrity("Invalid canonical manifest descriptor."))?,
        )?;
        Ok(canonical)
    }
}

impl WhatwgGit {
    pub async fn verify_retained_manifest(
        &self,
        artifact: &BulkArtifact,
        cancel: CancellationToken,
    ) -> Result<()> {
        let manifest = self.read_manifest(artifact, cancel.clone()).await?;
        let actual = self
            .artifacts
            .verify(&manifest.commits.body_hash, MAX_ORDER, cancel.clone())
            .await?;
        if actual != manifest.commits {
            return Err(Error::integrity(
                "Retained Git commit-order metadata mismatch.",
            ));
        }
        let mut names = BTreeSet::new();
        for pack in manifest.packs {
            if !valid_pack_name(&pack.name) || !names.insert(pack.name) {
                return Err(Error::integrity("Invalid retained Git pack name."));
            }
            let actual = self
                .artifacts
                .verify(
                    &pack.artifact.body_hash,
                    bulk::MAX_ARTIFACT_BYTES,
                    cancel.clone(),
                )
                .await?;
            if actual != pack.artifact {
                return Err(Error::integrity("Retained Git pack metadata mismatch."));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use axum::{
        Router,
        body::Bytes,
        routing::{get, post},
    };
    pub(crate) async fn input(git: &WhatwgGit, args: &[&str], bytes: &[u8]) -> Vec<u8> {
        let mut command = git.command();
        command
            .args(args)
            .env("GIT_AUTHOR_NAME", "Synthetic fixture")
            .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
            .env("GIT_COMMITTER_NAME", "Synthetic fixture")
            .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
            .env("GIT_AUTHOR_DATE", "1700000000 +0000")
            .env("GIT_COMMITTER_DATE", "1700000000 +0000")
            .env("GIT_PROTOCOL", "version=2")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        let mut child = ManagedChild::spawn(command).unwrap();
        child
            .child
            .stdin
            .take()
            .unwrap()
            .write_all(bytes)
            .await
            .unwrap();
        let mut output = Vec::new();
        child
            .child
            .stdout
            .take()
            .unwrap()
            .take(1024 * 1024)
            .read_to_end(&mut output)
            .await
            .unwrap();
        let status = child.child.wait().await.unwrap();
        child.finished = true;
        child.terminate().await.unwrap();
        assert!(status.success(), "fixture Git command failed");
        output
    }
    async fn commit_fixture(git: &WhatwgGit, body: &[u8], parents: &[&str]) -> String {
        commit_files(git, &[("index.md", body)], parents).await
    }
    fn oid(bytes: Vec<u8>) -> String {
        crate_git::parse_oid_line(&bytes).unwrap()
    }
    pub(crate) async fn update(git: &WhatwgGit, name: &str, oid: &str) {
        git.run(
            &["update-ref", name, oid],
            128,
            &CancellationToken::new(),
            Instant::now() + READ_RUNTIME,
        )
        .await
        .unwrap();
    }
    pub(crate) fn fixture_router(source: Arc<WhatwgGit>) -> Router {
        let prefix = format!("/{}/{}.git", source.repo.owner, source.repo.name);
        let advertise = source.clone();
        let upload = source;
        Router::new()
            .route(
                &format!("{prefix}/info/refs"),
                get(move || {
                    let source = advertise.clone();
                    async move {
                        let repository = source.repository();
                        let bytes = input(
                            &source,
                            &[
                                "upload-pack",
                                "--stateless-rpc",
                                "--advertise-refs",
                                repository.to_str().unwrap(),
                            ],
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
                &format!("{prefix}/git-upload-pack"),
                post(move |body: Bytes| {
                    let source = upload.clone();
                    async move {
                        let repository = source.repository();
                        let bytes = input(
                            &source,
                            &[
                                "upload-pack",
                                "--stateless-rpc",
                                repository.to_str().unwrap(),
                            ],
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
            )
    }
    pub(crate) async fn fixture_init(git: &WhatwgGit) {
        git.initialize(&CancellationToken::new(), Instant::now() + READ_RUNTIME)
            .await
            .unwrap();
        input(git, &["symbolic-ref", "HEAD", "refs/heads/main"], b"").await;
    }
    pub(crate) async fn commit_files(
        git: &WhatwgGit,
        files: &[(&str, &[u8])],
        parents: &[&str],
    ) -> String {
        let mut directories =
            std::collections::BTreeMap::<String, Vec<(String, String, String, String)>>::new();
        directories.entry(String::new()).or_default();
        for (path, body) in files {
            assert!(valid_path(path));
            let blob = oid(input(git, &["hash-object", "-w", "--stdin"], body).await);
            let (parent, name) = path.rsplit_once('/').unwrap_or(("", path));
            directories.entry(parent.into()).or_default().push((
                "100644".into(),
                "blob".into(),
                blob,
                name.to_string(),
            ));
            let mut ancestor = parent;
            while !ancestor.is_empty() {
                ancestor = ancestor.rsplit_once('/').map_or("", |(p, _)| p);
                directories.entry(ancestor.to_string()).or_default();
            }
        }
        let mut names: Vec<_> = directories.keys().cloned().collect();
        names.sort_by_key(|path| {
            std::cmp::Reverse(path.split('/').count() + usize::from(!path.is_empty()))
        });
        let mut root = None;
        for name in names {
            let mut entries = directories.remove(&name).unwrap();
            entries.sort_by(|a, b| a.3.cmp(&b.3));
            let body = entries
                .iter()
                .map(|(mode, kind, oid, name)| format!("{mode} {kind} {oid}\t{name}\n"))
                .collect::<String>();
            let tree = oid(input(git, &["mktree"], body.as_bytes()).await);
            if name.is_empty() {
                root = Some(tree)
            } else {
                let (parent, leaf) = name.rsplit_once('/').unwrap_or(("", &name));
                directories.get_mut(parent).unwrap().push((
                    "040000".into(),
                    "tree".into(),
                    tree,
                    leaf.to_owned(),
                ));
            }
        }
        let tree = root.unwrap();
        let mut args = vec!["commit-tree", &tree];
        for parent in parents {
            args.extend(["-p", parent]);
        }
        oid(input(git, &args, b"Synthetic nested WHATWG source fixture\n").await)
    }
    pub(crate) async fn serve_fixture(
        router: Router,
    ) -> (Arc<BulkBroker>, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let broker = Arc::new(
            BulkBroker::fixture(url::Url::parse(&format!("http://{address}")).unwrap()).unwrap(),
        );
        (broker, task)
    }
    #[tokio::test]
    async fn full_graph_dropped_refs_pages_and_offline_restore() {
        let _test = crate::mdn::index::TEST_GATE.lock().await;
        let source_root = tempfile::tempdir().unwrap();
        let source = Arc::new(
            WhatwgGit::new(
                source_root.path(),
                Repo::new("whatwg/fixture").unwrap(),
                64 * 1024 * 1024,
                64 * 1024 * 1024,
                None,
            )
            .unwrap(),
        );
        source
            .initialize(&CancellationToken::new(), Instant::now() + READ_RUNTIME)
            .await
            .unwrap();
        input(&source, &["symbolic-ref", "HEAD", "refs/heads/main"], b"").await;
        let first = commit_fixture(&source, b"first\n", &[]).await;
        let second = commit_fixture(&source, b"second\n", &[&first]).await;
        let side = commit_fixture(&source, b"side\n", &[&first]).await;
        update(&source, "refs/heads/main", &second).await;
        update(&source, "refs/heads/side", &side).await;
        let annotated=oid(input(&source,&["mktag"],format!("object {first}\ntype commit\ntag initial\ntagger Synthetic fixture <fixture@example.invalid> 1700000000 +0000\n\nSynthetic annotated tag\n").as_bytes()).await);
        update(&source, "refs/tags/initial", &annotated).await;
        let blob = oid(input(
            &source,
            &["hash-object", "-w", "--stdin"],
            b"standalone tag payload",
        )
        .await);
        update(&source, "refs/tags/raw", &blob).await;
        let (broker, server) = serve_fixture(fixture_router(source.clone())).await;
        let target_root = tempfile::tempdir().unwrap();
        let target = WhatwgGit::new(
            target_root.path(),
            Repo::new("whatwg/fixture").unwrap(),
            64 * 1024 * 1024,
            64 * 1024 * 1024,
            None,
        )
        .unwrap();
        let observation = target
            .synchronize(broker.clone(), None, CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(observation.total_commits, 3);
        assert_eq!(observation.main_revision.as_deref(), Some(second.as_str()));
        assert!(
            observation
                .refs
                .iter()
                .any(|reference| reference.name == "refs/tags/initial"
                    && reference.peeled_commit.as_deref() == Some(first.as_str()))
        );
        let page = target
            .commit_page(&observation, 0, 1, CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(page.commits[0].revision, first);
        assert!(
            target
                .commit_page(&observation, 1, 1, CancellationToken::new())
                .await
                .is_err()
        );
        let rest = target
            .commit_page(
                &observation,
                page.next_offset,
                1000,
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(rest.commits.len(), 2);
        assert_eq!(rest.next_offset, observation.commits.bytes);
        let commit = target
            .commit(&second, CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(commit.parents, vec![first.clone()]);
        let mut records = target
            .records(&second, None, CancellationToken::new())
            .unwrap();
        let member = records.recv().await.unwrap().unwrap();
        assert_eq!(member.path, "index.md");
        assert!(records.recv().await.is_none());
        assert_eq!(
            target
                .entry(&second, "index.md", CancellationToken::new())
                .await
                .unwrap()
                .unwrap()
                .oid,
            member.oid
        );
        assert!(
            target
                .entry(&second, "missing", CancellationToken::new())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            target
                .entry(&second, ":(glob)*", CancellationToken::new())
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            target
                .blob_size(&member.oid, CancellationToken::new())
                .await
                .unwrap(),
            7
        );
        assert_eq!(
            target
                .read_blob(&member.oid, 1024, CancellationToken::new())
                .await
                .unwrap(),
            b"second\n"
        );
        let page = target
            .blob_page(&member.oid, 1, 3, CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(page.bytes, b"eco");
        assert_eq!(page.total_bytes, 7);
        assert_eq!(page.body_hash, crate::integrity::hash(b"second\n"));
        source
            .run(
                &["update-ref", "-d", "refs/heads/side"],
                128,
                &CancellationToken::new(),
                Instant::now() + READ_RUNTIME,
            )
            .await
            .unwrap();
        let newer = target
            .synchronize(
                broker,
                Some(&observation.manifest),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(newer.total_commits, 3);
        assert!(
            !newer
                .refs
                .iter()
                .any(|reference| reference.name == "refs/heads/side")
        );
        server.abort();
        let _ = server.await;
        tokio::fs::remove_dir_all(target.repository())
            .await
            .unwrap();
        target
            .restore(&newer.manifest, CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(
            target
                .commit(&side, CancellationToken::new())
                .await
                .unwrap()
                .parents,
            vec![first]
        );
        let mut changes = target
            .records(&second, Some(&side), CancellationToken::new())
            .unwrap();
        let change = changes.recv().await.unwrap().unwrap();
        assert!(!change.removed);
        assert_eq!(change.path, "index.md");
        assert!(
            target
                .read_blob(&change.oid, 1, CancellationToken::new())
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn verified_upstream_head_and_publication_inventory_bind_the_observation() {
        let source_root = tempfile::tempdir().expect("source");
        let source = Arc::new(
            WhatwgGit::new(
                source_root.path(),
                Repo::new("w3c-cg/web-nfc").expect("repo"),
                64 * 1024 * 1024,
                64 * 1024 * 1024,
                None,
            )
            .expect("source Git"),
        );
        fixture_init(&source).await;
        let first = commit_files(
            &source,
            &[("review-drafts/2026-01.bs", b"first draft")],
            &[],
        )
        .await;
        update(&source, "refs/heads/gh-pages", &first).await;
        input(
            &source,
            &["symbolic-ref", "HEAD", "refs/heads/gh-pages"],
            b"",
        )
        .await;
        let (broker, server) = serve_fixture(fixture_router(source.clone())).await;
        let root = tempfile::tempdir().expect("target");
        let target = WhatwgGit::new(
            root.path(),
            Repo::new("w3c-cg/web-nfc").expect("repo"),
            64 * 1024 * 1024,
            64 * 1024 * 1024,
            None,
        )
        .expect("target Git");
        let observed = target
            .synchronize(broker.clone(), None, CancellationToken::new())
            .await
            .expect("gh-pages HEAD");
        assert_eq!(observed.current_ref, "refs/heads/gh-pages");
        assert_eq!(observed.main_revision.as_deref(), Some(first.as_str()));
        let unrelated = commit_files(
            &source,
            &[
                ("review-drafts/2026-01.bs", b"first draft"),
                ("review-drafts/2026-02.bs", b"later draft"),
            ],
            &[&first],
        )
        .await;
        update(&source, "refs/heads/unrelated", &unrelated).await;
        target
            .synchronize(broker, Some(&observed.manifest), CancellationToken::new())
            .await
            .expect("working mirror gets later unrelated ref");
        assert_eq!(
            target
                .publication_paths(&observed, CancellationToken::new())
                .await
                .expect("frozen publication paths"),
            vec!["review-drafts/2026-01.bs"]
        );
        server.abort();
        let _ = server.await;
    }
    #[test]
    fn fetch_diagnostics_emit_only_fixed_categories() {
        assert_eq!(
            fetch_failure_class(b"fatal: fsck error in packed object private-marker"),
            "object_integrity"
        );
        assert_eq!(
            fetch_failure_class(b"error: RPC failed; curl 92 private-marker"),
            "transfer"
        );
        assert_eq!(
            fetch_failure_class(b"remote: Repository not found private-marker"),
            "repository_access"
        );
        assert_eq!(fetch_failure_class(b"private-marker"), "subprocess");
    }
    #[tokio::test]
    async fn failed_fetch_preserves_sanitized_relay_phase_without_source_bodies() {
        let router = Router::new().route(
            "/whatwg/fixture.git/info/refs",
            get(|| async {
                (
                    axum::http::StatusCode::BAD_GATEWAY,
                    "private-source-body-marker",
                )
            }),
        );
        let (broker, server) = serve_fixture(router).await;
        let root = tempfile::tempdir().expect("owned Git");
        let git = WhatwgGit::new(
            root.path(),
            Repo::new("whatwg/fixture").expect("repo"),
            64 * 1024 * 1024,
            64 * 1024 * 1024,
            None,
        )
        .expect("Git");
        let error = git
            .synchronize(broker, None, CancellationToken::new())
            .await
            .expect_err("failed source");
        assert!(error.message.contains("Git fetch"));
        assert!(error.message.contains("HTTP 502"));
        assert!(!error.message.contains("private-source-body-marker"));
        server.abort();
        let _ = server.await;
    }
}
