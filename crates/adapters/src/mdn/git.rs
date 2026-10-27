//! Fixed-source MDN Git acquisition and immutable, offline-restorable evidence.
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
use sha1::Sha1;
use sha2::{Digest, Sha256};
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

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Repo {
    Content,
    Compat,
}
impl Repo {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Content => "content",
            Self::Compat => "compat",
        }
    }
    pub fn source_url(self) -> &'static str {
        match self {
            Self::Content => "https://github.com/mdn/content.git",
            Self::Compat => "https://github.com/mdn/browser-compat-data.git",
        }
    }
    fn relay(self) -> GitSource {
        match self {
            Self::Content => GitSource::MdnContent,
            Self::Compat => GitSource::MdnCompat,
        }
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
pub struct MdnGit {
    root: PathBuf,
    repo: Repo,
    artifacts: Arc<BulkArtifactStore>,
    max_git_bytes: u64,
    min_free_bytes: u64,
    gate: Arc<Mutex<()>>,
}
fn failure() -> Error {
    Error::unavailable("MDN Git operation failed.")
}
struct Stage(PathBuf);
impl Drop for Stage {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
impl MdnGit {
    pub fn new(
        root: &Path,
        repo: Repo,
        max_git_bytes: u64,
        min_free_bytes: u64,
        quota: Option<u64>,
    ) -> Result<Self> {
        if !(1024 * 1024..=128 * 1024 * 1024 * 1024).contains(&max_git_bytes) {
            return Err(Error::invalid("Invalid MDN Git storage budget."));
        }
        let root = root.join("mdn").join(repo.as_str());
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
    /// Attach the MDN raw-object store's combined quota during fenced startup,
    /// before this Git adapter or its artifact store has been cloned or used.
    pub fn with_shared_budget(mut self, budget: &BulkArtifactStore) -> Result<Self> {
        if Arc::strong_count(&self.artifacts) != 1 {
            return Err(Error::integrity(
                "MDN shared budget must attach before cloning the artifact store.",
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
        let marker = self.root.join("owner-v1");
        let expected = format!("devres-mdn-{}-v1\n", self.repo.as_str());
        let exists = tokio::fs::try_exists(self.repository())
            .await
            .map_err(|_| failure())?;
        if exists {
            real_directory(&self.repository())?;
            if tokio::fs::read(&marker).await.map_err(|_| failure())? != expected.as_bytes() {
                return Err(Error::integrity("MDN Git ownership mismatch."));
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
                        return Err(Error::integrity("MDN Git ownership mismatch."));
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
                "MDN Git storage headroom exhausted; retained evidence is preserved.",
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
            ]);
        let mut child = ManagedChild::spawn(command)?;
        let transfer = loop {
            tokio::select! { biased;
                _ = cancel.cancelled() => break Err(Error::unavailable("MDN Git synchronization canceled.")),
                _ = failed.cancelled() => break Err(relay.failure_reason.lock().ok().and_then(|reason| reason.clone()).unwrap_or_else(failure)),
                _ = tokio::time::sleep_until(deadline) => break Err(Error::capacity("MDN Git synchronization deadline exceeded.")),
                status = child.child.wait() => { child.finished = true; break match status { Ok(status) if status.success() => Ok(()), _ => Err(failure()) }; }
                _ = tokio::time::sleep(Duration::from_millis(250)) => { if let Err(error) = self.check_space() { break Err(error); } }
            }
        };
        let stopped = child.terminate().await;
        stop.cancel();
        let relay_result = if let Some(mut task) = relay.task.take() {
            match tokio::time::timeout(Duration::from_secs(5), &mut task).await {
                Ok(Ok(Ok(()))) => Ok(()),
                Ok(_) => Err(Error::unavailable("MDN Git relay did not stop cleanly.")),
                Err(_) => {
                    task.abort();
                    let _ = task.await;
                    Err(Error::unavailable("MDN Git relay did not stop cleanly."))
                }
            }
        } else {
            Err(failure())
        };
        transfer?;
        stopped?;
        relay_result?;
        self.check_space()?;
        let observed_at = devres_domain::unix_now();
        let refs = self.read_refs(&cancel, deadline).await?;
        let mut roots: BTreeSet<String> =
            refs.iter().map(|reference| reference.oid.clone()).collect();
        if let Some(old) = old {
            roots.extend(old.roots);
        }
        if roots.len() > MAX_REFS * 10 {
            return Err(Error::capacity("MDN retained ref-root limit exceeded."));
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
            source_url: self.repo.source_url().into(),
            repo: self.repo,
            observed_at,
            refs: refs.clone(),
            roots: roots.clone(),
            packs,
            commits: commits.clone(),
            total_commits,
        };
        let bytes = serde_json::to_vec(&manifest).map_err(|_| failure())?;
        if bytes.len() > MAX_MANIFEST {
            return Err(Error::capacity("MDN Git manifest exceeds 4 MiB."));
        }
        let artifact = bulk::bounded(
            &cancel,
            deadline,
            self.artifacts.capture_bytes(bytes, cancel.clone()),
        )
        .await?;
        let main_revision = refs
            .iter()
            .find(|reference| reference.name == "refs/heads/main")
            .and_then(|reference| reference.peeled_commit.clone());
        Ok(Observation {
            repo: self.repo,
            observed_at,
            refs,
            roots,
            manifest: artifact,
            commits,
            total_commits,
            main_revision,
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
            .map_err(|_| Error::integrity("Invalid MDN ref encoding."))?;
        let mut refs = Vec::new();
        for line in text.lines() {
            if refs.len() >= MAX_REFS {
                return Err(Error::capacity(
                    "MDN advertised ref count exceeds its budget.",
                ));
            }
            let fields: Vec<_> = line.split('\t').collect();
            if fields.len() != 3
                || !valid_oid(fields[1])
                || !matches!(fields[2], "commit" | "tag" | "tree" | "blob")
            {
                return Err(Error::integrity("Invalid MDN ref record."));
            }
            let name = format!(
                "refs/{}",
                fields[0]
                    .strip_prefix("refs/devres/live/")
                    .ok_or_else(failure)?
            );
            if !valid_ref(&name) {
                return Err(Error::integrity("Invalid MDN advertised ref name."));
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
                    .ok_or_else(|| Error::integrity("Invalid MDN annotated tag target."))?
                    .into();
                }
                _ => return Err(Error::integrity("Unsupported MDN Git object type.")),
            }
        }
        Err(Error::capacity("MDN tag nesting exceeds 64."))
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
            _ => return Err(Error::integrity("Invalid MDN commit-order stage.")),
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
                        "MDN commit enumeration exceeds its budget.",
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
                return Err(Error::integrity("Invalid MDN Git pack member."));
            }
            if packs.len() >= 10_000 {
                return Err(Error::capacity("MDN Git pack count exceeds its budget."));
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
            return Err(Error::integrity("MDN manifest metadata mismatch."));
        }
        let value: Manifest = serde_json::from_slice(&bytes)
            .map_err(|_| Error::integrity("Invalid MDN Git manifest."))?;
        if value.version != 1
            || value.repo != self.repo
            || value.source_url != self.repo.source_url()
            || value.observed_at < 0
            || value.observed_at > devres_domain::unix_now()
            || value.refs.len() > MAX_REFS
            || value.roots.len() > MAX_REFS * 10
            || value.packs.len() > 10_000
            || value.total_commits > MAX_COMMITS
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
            return Err(Error::integrity("Invalid MDN Git manifest identity."));
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
            return Err(Error::integrity("MDN commit-order metadata mismatch."));
        }
        let root = self.repository().join("objects/pack");
        let mut names = BTreeSet::new();
        for pack in &manifest.packs {
            if !valid_pack_name(&pack.name) || !names.insert(&pack.name) {
                return Err(Error::integrity("Invalid MDN retained pack name."));
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
                return Err(Error::integrity("MDN retained pack metadata mismatch."));
            }
            let target = root.join(&pack.name);
            match tokio::fs::hard_link(
                self.artifacts.root().join(&pack.artifact.body_hash),
                &target,
            )
            .await
            {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    if self
                        .artifacts
                        .ingest_file(&target, bulk::MAX_ARTIFACT_BYTES, cancel.clone())
                        .await?
                        != pack.artifact
                    {
                        return Err(Error::integrity(
                            "MDN working pack differs from retained evidence.",
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
            return Err(Error::invalid("Invalid MDN commit page."));
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
                return Err(Error::invalid("MDN commit offset must be a line boundary."));
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
            return Err(Error::integrity("MDN commit order exceeds its descriptor."));
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
            .map_err(|_| Error::integrity("Invalid MDN commit descriptor."))?;
        let fields: Vec<_> = text.trim_end_matches('\n').split('\0').collect();
        if fields.len() != 4 || fields[0] != oid || !valid_oid(fields[1]) {
            return Err(Error::integrity("Invalid MDN commit identity."));
        }
        let committed_at = fields[2]
            .parse()
            .map_err(|_| Error::integrity("Invalid MDN commit time."))?;
        let parents: Vec<_> = fields[3].split_whitespace().map(str::to_owned).collect();
        if parents.len() > 1024 || parents.iter().any(|parent| !valid_oid(parent)) {
            return Err(Error::integrity("Invalid MDN commit parents."));
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
                if count > 1_000_000 { return Err(Error::capacity("MDN tree entries exceed their budget.")); }
                let entry = if previous.is_some() {
                    let path = delimited(&mut reader, 0, 4096, cancel, deadline).await?.ok_or_else(||Error::integrity("Truncated MDN diff path."))?;
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
            return Err(Error::invalid("Invalid MDN source path."));
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
            return Err(Error::integrity("Invalid MDN exact path result."));
        }
        let entry = parse_tree(&bytes[..bytes.len() - 1])?;
        if entry.path != path {
            return Err(Error::integrity("MDN source lookup returned another path."));
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
        if max_bytes == 0 || max_bytes > 16 * 1024 * 1024 {
            return Err(Error::invalid("Invalid MDN blob read budget."));
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
        if max_bytes == 0 || max_bytes > 16 * 1024 * 1024 {
            return Err(Error::invalid("Invalid MDN blob read budget."));
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
                "MDN blob exceeds the projection input budget.",
            ));
        }
        let bytes = self
            .run(&["cat-file", "blob", oid], max_bytes, cancel, deadline)
            .await?;
        if bytes.len() as u64 != length {
            return Err(Error::integrity("MDN blob length mismatch."));
        }
        let mut git_hash = Sha1::new();
        git_hash.update(format!("blob {length}\0").as_bytes());
        git_hash.update(&bytes);
        if hex::encode(git_hash.finalize()) != oid {
            return Err(Error::integrity("MDN Git blob object hash mismatch."));
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
            .ok_or_else(|| Error::capacity("MDN raw blob size exceeds its read bound."))
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
            return Err(Error::invalid("MDN raw page limit must be 1..32768."));
        }
        let deadline = Instant::now() + READ_RUNTIME;
        let total = self.blob_length(oid, &cancel, deadline).await?;
        if offset > total {
            return Err(Error::invalid("MDN raw offset exceeds source length."));
        }
        let mut command = self.command();
        command
            .args(["cat-file", "blob", oid])
            .stdout(Stdio::piped());
        let mut child = ManagedChild::spawn(command)?;
        let result = async {
            let mut reader = child.child.stdout.take().ok_or_else(failure)?;
            let mut digest = Sha256::new();
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
                    return Err(Error::integrity("MDN raw blob grew during read."));
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
                return Err(Error::integrity("MDN raw blob read failed."));
            }
            if hex::encode(git_hash.finalize()) != oid {
                return Err(Error::integrity("MDN Git blob object hash mismatch."));
            }
            Ok(BlobPage {
                bytes,
                total_bytes: total,
                body_hash: hex::encode(digest.finalize()),
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
        Err(Error::invalid("Invalid MDN Git object identity."))
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
        .map_err(|_| Error::integrity("Invalid MDN commit-order encoding."))?;
    let mut fields = text.split(' ');
    let committed_at = fields
        .next()
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| Error::integrity("Invalid MDN commit-order time."))?;
    let revision = fields
        .next()
        .filter(|value| valid_oid(value))
        .ok_or_else(|| Error::integrity("Invalid MDN commit-order identity."))?
        .into();
    let parents: Vec<_> = fields.map(str::to_owned).collect();
    if parents.len() > 1024 || parents.iter().any(|parent| !valid_oid(parent)) {
        return Err(Error::integrity("Invalid MDN commit-order parents."));
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
        format!("@unsupported-path/{}", hex::encode(Sha256::digest(bytes))),
        Some(hex::encode(bytes)),
    )
}
fn parse_tree(token: &[u8]) -> Result<TreeEntry> {
    let split = token
        .iter()
        .position(|byte| *byte == b'\t')
        .ok_or_else(|| Error::integrity("Invalid MDN Git tree entry."))?;
    let header = std::str::from_utf8(&token[..split])
        .map_err(|_| Error::integrity("Invalid MDN Git tree header."))?;
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
        return Err(Error::integrity("Invalid MDN Git tree entry."));
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
    let header =
        std::str::from_utf8(token).map_err(|_| Error::integrity("Invalid MDN Git diff entry."))?;
    let fields: Vec<_> = header.split(' ').collect();
    if fields.len() != 5
        || !fields[0].starts_with(':')
        || !valid_oid(fields[2])
        || !valid_oid(fields[3])
        || raw_path.is_empty()
        || !matches!(fields[4], "A" | "M" | "D" | "T")
    {
        return Err(Error::integrity("Invalid MDN Git diff entry."));
    }
    let removed = fields[4] == "D";
    let mode = if removed { &fields[0][1..] } else { fields[1] };
    let oid = if removed { fields[2] } else { fields[3] };
    let kind = match mode {
        "100644" | "100755" | "120000" => "blob",
        "160000" => "commit",
        _ => return Err(Error::integrity("Unsupported MDN Git member mode.")),
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
                return Err(Error::integrity("Unexpected MDN working symlink."));
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
            _ => return Err(Error::integrity("Invalid MDN working lock.")),
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use axum::{
        Router,
        body::Bytes,
        routing::{get, post},
    };
    pub(crate) async fn input(git: &MdnGit, args: &[&str], bytes: &[u8]) -> Vec<u8> {
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
    fn oid(bytes: Vec<u8>) -> String {
        crate_git::parse_oid_line(&bytes).unwrap()
    }
    async fn commit_fixture(git: &MdnGit, body: &[u8], parents: &[&str]) -> String {
        let blob = oid(input(git, &["hash-object", "-w", "--stdin"], body).await);
        let tree = oid(input(
            git,
            &["mktree"],
            format!("100644 blob {blob}\tindex.md\n").as_bytes(),
        )
        .await);
        let mut args = vec!["commit-tree", &tree];
        for parent in parents {
            args.extend(["-p", parent]);
        }
        oid(input(git, &args, b"Synthetic MDN fixture\n").await)
    }
    pub(crate) async fn update(git: &MdnGit, name: &str, oid: &str) {
        git.run(
            &["update-ref", name, oid],
            128,
            &CancellationToken::new(),
            Instant::now() + READ_RUNTIME,
        )
        .await
        .unwrap();
    }
    fn fixture_router(source: Arc<MdnGit>) -> Router {
        let prefix = match source.repo {
            Repo::Content => "/mdn/content.git",
            Repo::Compat => "/mdn/browser-compat-data.git",
        };
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
    async fn fixture_server(source: Arc<MdnGit>) -> (Arc<BulkBroker>, tokio::task::JoinHandle<()>) {
        serve_fixture(fixture_router(source)).await
    }
    pub(crate) async fn fixture_server_pair(
        content: Arc<MdnGit>,
        compat: Arc<MdnGit>,
    ) -> (Arc<BulkBroker>, tokio::task::JoinHandle<()>) {
        serve_fixture(fixture_router(content).merge(fixture_router(compat))).await
    }
    pub(crate) async fn fixture_init(git: &MdnGit) {
        git.initialize(&CancellationToken::new(), Instant::now() + READ_RUNTIME)
            .await
            .unwrap();
    }
    pub(crate) async fn commit_files(
        git: &MdnGit,
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
        oid(input(git, &args, b"Synthetic nested MDN source fixture\n").await)
    }
    async fn serve_fixture(router: Router) -> (Arc<BulkBroker>, tokio::task::JoinHandle<()>) {
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
    #[test]
    fn record_identity_and_special_members_are_explicit() {
        let a = "a".repeat(40);
        let b = "b".repeat(40);
        assert!(valid_ref("refs/heads/main"));
        assert!(!valid_ref("refs/pull/1/head"));
        assert!(!valid_ref("refs/tags/../escape"));
        let link = parse_tree(format!("120000 blob {a}\tlink").as_bytes()).unwrap();
        assert_eq!(link.mode, "120000");
        let submodule = parse_tree(format!("160000 commit {a}\tmodule").as_bytes()).unwrap();
        assert_eq!(submodule.kind, "commit");
        let deleted = parse_diff(
            format!(":100644 000000 {a} {} D", "0".repeat(40)).as_bytes(),
            b"index.md",
        )
        .unwrap();
        assert!(deleted.removed);
        assert_eq!(deleted.oid, a);
        assert!(
            parse_diff(
                format!(":100644 100644 {a} {b} R100").as_bytes(),
                b"index.md"
            )
            .is_err()
        );
        let unsupported = parse_tree(format!("100644 blob {a}\t../escape").as_bytes()).unwrap();
        assert_eq!(
            unsupported.raw_path_hex.as_deref(),
            Some(hex::encode(b"../escape").as_str())
        );
        let mut non_utf8 = format!("100644 blob {a}\t").into_bytes();
        non_utf8.extend_from_slice(b"bad\xffpath");
        let unusual = parse_tree(&non_utf8).unwrap();
        assert!(unusual.path.starts_with("@unsupported-path/"));
        assert_eq!(
            hex::decode(unusual.raw_path_hex.unwrap()).unwrap(),
            b"bad\xffpath"
        );
        assert!(parse_commit_order(format!("1 {a} {b}").as_bytes()).is_ok());
        assert!(parse_commit_order(b"1 bad").is_err());
    }
    #[tokio::test]
    async fn full_graph_dropped_refs_pages_and_offline_restore() {
        let _test = crate::mdn::index::TEST_GATE.lock().await;
        let source_root = tempfile::tempdir().unwrap();
        let source = Arc::new(
            MdnGit::new(
                source_root.path(),
                Repo::Content,
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
        let (broker, server) = fixture_server(source.clone()).await;
        let target_root = tempfile::tempdir().unwrap();
        let target = MdnGit::new(
            target_root.path(),
            Repo::Content,
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
        assert_eq!(page.body_hash, hex::encode(Sha256::digest(b"second\n")));
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
    async fn raw_reads_reject_a_git_object_with_changed_bytes_under_the_same_oid() {
        let _test = crate::mdn::index::TEST_GATE.lock().await;
        use std::io::Write;
        let root = tempfile::tempdir().unwrap();
        let git = MdnGit::new(
            root.path(),
            Repo::Content,
            64 * 1024 * 1024,
            64 * 1024 * 1024,
            None,
        )
        .unwrap();
        git.initialize(&CancellationToken::new(), Instant::now() + READ_RUNTIME)
            .await
            .unwrap();
        let blob = oid(input(&git, &["hash-object", "-w", "--stdin"], b"second\n").await);
        assert_eq!(
            git.read_blob(&blob, 1024, CancellationToken::new())
                .await
                .unwrap(),
            b"second\n"
        );
        assert_eq!(
            git.read_blob_known_length(&blob, 7, 1024, CancellationToken::new())
                .await
                .unwrap(),
            b"second\n"
        );
        for length in [6, 8] {
            assert_eq!(
                git.read_blob_known_length(&blob, length, 1024, CancellationToken::new())
                    .await
                    .unwrap_err()
                    .code,
                "integrity"
            );
        }
        assert_eq!(
            git.read_blob_known_length(&blob, 7, 6, CancellationToken::new())
                .await
                .unwrap_err()
                .code,
            "capacity"
        );
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert!(
            git.read_blob_known_length(&blob, 7, 1024, cancelled)
                .await
                .is_err()
        );
        let mut compressed =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        compressed.write_all(b"blob 7\0tamper\n").unwrap();
        let path = git
            .repository()
            .join("objects")
            .join(&blob[..2])
            .join(&blob[2..]);
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .await
            .unwrap();
        tokio::fs::write(path, compressed.finish().unwrap())
            .await
            .unwrap();
        assert_eq!(
            git.read_blob(&blob, 1024, CancellationToken::new())
                .await
                .unwrap_err()
                .code,
            "integrity"
        );
        assert_eq!(
            git.read_blob_known_length(&blob, 7, 1024, CancellationToken::new())
                .await
                .unwrap_err()
                .code,
            "integrity"
        );
        assert_eq!(
            git.blob_page(&blob, 0, 7, CancellationToken::new())
                .await
                .unwrap_err()
                .code,
            "integrity"
        );
    }
    #[tokio::test]
    #[ignore = "requires disposable PostgreSQL; run scripts/test-postgres.sh"]
    async fn mdn_corpus_git_postgres_history_research_restart_and_restore() {
        pg_corpus_acceptance().await;
    }
    async fn pg_corpus_acceptance() {
        use crate::{PgBlobStore, mdn::MdnCorpus};
        use devres_application::mdn::{MdnConfig, MdnStore};
        use serde_json::json;
        let base =
            std::env::var("DEVRES_TEST_DATABASE_URL").expect("disposable PostgreSQL URL required");
        let admin = sqlx::PgPool::connect(&base).await.unwrap();
        let database = "devres_mdn_git_fixture";
        sqlx::query("CREATE DATABASE devres_mdn_git_fixture")
            .execute(&admin)
            .await
            .unwrap();
        let mut url = url::Url::parse(&base).unwrap();
        url.set_path(&format!("/{database}"));
        let source_root = tempfile::tempdir().unwrap();
        let source = Arc::new(
            MdnGit::new(
                source_root.path(),
                Repo::Content,
                64 * 1024 * 1024,
                64 * 1024 * 1024,
                None,
            )
            .unwrap(),
        );
        let compat = Arc::new(
            MdnGit::new(
                source_root.path(),
                Repo::Compat,
                64 * 1024 * 1024,
                64 * 1024 * 1024,
                None,
            )
            .unwrap(),
        );
        fixture_init(&source).await;
        fixture_init(&compat).await;
        let article = "files/en-us/web/api/window/fetch/index.md";
        let side_path = "files/en-us/web/side/index.md";
        let original=b"---\ntitle: Fetch fixture\nslug: Web/API/Window/fetch\npage-type: web-api-instance-method\nbrowser-compat: api.fetch\n---\n\n# Fetch\noriginalliteral public documentation\n";
        let updated=b"---\ntitle: Fetch fixture\nslug: Web/API/Window/fetch\npage-type: web-api-instance-method\nbrowser-compat: api.fetch\n---\n\n# Fetch\nupdatedliteral public documentation\n";
        let side_doc=b"---\ntitle: Side fixture\nslug: Web/Side\npage-type: guide\n---\n\nsidebranch documentation\n";
        let binary_path = "files/en-us/pixel.bin";
        let binary: &[u8] = &[1, 2, 3, 0xff];
        let first = commit_files(&source, &[(article, original), (binary_path, binary)], &[]).await;
        let second = commit_files(
            &source,
            &[(article, updated), (binary_path, binary)],
            &[&first],
        )
        .await;
        let side = commit_files(
            &source,
            &[(side_path, side_doc), (binary_path, binary)],
            &[&first],
        )
        .await;
        let merged = commit_files(
            &source,
            &[
                (article, updated),
                (side_path, side_doc),
                (binary_path, binary),
            ],
            &[&second, &side],
        )
        .await;
        update(&source, "refs/heads/main", &merged).await;
        update(&source, "refs/heads/side", &side).await;
        update(&source, "refs/tags/initial", &first).await;
        let browsers=br#"{"browsers":{"chrome":{"name":"Chrome","type":"desktop","releases":{"1":{"engine":"Blink","engine_version":"1","status":"retired"},"2":{"engine":"Blink","engine_version":"2","status":"current"}}}}}"#;
        let feature1=br#"{"api":{"fetch":{"__compat":{"mdn_url":"https://developer.mozilla.org/docs/Web/API/Window/fetch","support":{"chrome":{"version_added":"1"}},"status":{"experimental":false,"deprecated":false,"standard_track":true}}}}}"#;
        let feature2=br#"{"api":{"fetch":{"__compat":{"mdn_url":"https://developer.mozilla.org/docs/Web/API/Window/fetch","support":{"chrome":{"version_added":"2"}},"status":{"experimental":false,"deprecated":false,"standard_track":true}}}}}"#;
        let bcd_first = commit_files(
            &compat,
            &[
                ("api/fetch.json", feature1),
                ("browsers/chrome.json", browsers),
            ],
            &[],
        )
        .await;
        let bcd_second = commit_files(
            &compat,
            &[
                ("api/fetch.json", feature2),
                ("browsers/chrome.json", browsers),
            ],
            &[&bcd_first],
        )
        .await;
        update(&compat, "refs/heads/main", &bcd_second).await;
        update(&compat, "refs/tags/v1", &bcd_first).await;
        let (broker, server) = fixture_server_pair(source.clone(), compat).await;
        let root = tempfile::tempdir().unwrap();
        let config = MdnConfig {
            enabled: false,
            min_free_bytes: 64 * 1024 * 1024,
            max_git_bytes: 64 * 1024 * 1024,
            publication_interval_secs: 1,
            ..Default::default()
        };
        let store = Arc::new(
            PgBlobStore::connect(url.as_str(), root.path())
                .await
                .unwrap(),
        );
        let corpus =
            MdnCorpus::new(store.clone(), broker.clone(), root.path(), config.clone()).unwrap();
        let observed = corpus
            .synchronize(Repo::Content, CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(observed.total_commits, 4);
        assert_eq!(
            corpus
                .synchronize(Repo::Compat, CancellationToken::new())
                .await
                .unwrap()
                .total_commits,
            2
        );
        for tick in 0..100 {
            if corpus
                .process_current(CancellationToken::new())
                .await
                .unwrap()
            {
                break;
            }
            assert!(tick < 99, "fixture current processing did not finish");
        }
        for tick in 0..100 {
            if corpus
                .process_history(CancellationToken::new())
                .await
                .unwrap()
            {
                break;
            }
            assert!(tick < 99, "fixture history processing did not finish");
        }
        let research = corpus.research();
        let current = research
            .call("mdn.get", json!({"slug":"Web/API/Window/fetch"}))
            .await
            .unwrap();
        assert!(
            current["page"]["text"]
                .as_str()
                .unwrap()
                .contains("updatedliteral")
        );
        let snapshots = research
            .call("mdn.snapshots", json!({"repository":"content","limit":100}))
            .await
            .unwrap();
        let old = snapshots["results"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["revision"] == first)
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let oldest = research
            .call(
                "mdn.get",
                json!({"slug":"Web/API/Window/fetch","snapshot":old,"representation":"source"}),
            )
            .await
            .unwrap();
        assert!(
            oldest["page"]["text"]
                .as_str()
                .unwrap()
                .contains("originalliteral")
        );
        let resource = oldest["resource_uri"].as_str().unwrap().to_owned();
        let replay = research.read_resource(&resource).await.unwrap();
        assert!(
            replay["contents"][0]["text"]
                .as_str()
                .unwrap()
                .contains("originalliteral")
        );
        let search = research
            .call(
                "mdn.search",
                json!({"query":"originalliteral","snapshot":old}),
            )
            .await
            .unwrap();
        assert_eq!(search["results"].as_array().unwrap().len(), 1);
        let present = research
            .call("mdn.search", json!({"query":"originalliteral"}))
            .await
            .unwrap();
        assert!(present["results"].as_array().unwrap().is_empty());
        let feature = research
            .call("mdn.compat_get", json!({"feature":"api.fetch"}))
            .await
            .unwrap();
        assert_eq!(feature["original"]["chrome"]["version_added"], "2");
        let history = research
            .call("mdn.history", json!({"path":article,"limit":100}))
            .await
            .unwrap();
        assert!(
            history["results"]
                .as_array()
                .unwrap()
                .iter()
                .any(|change| change["revision"] == merged && change["parent_index"] == 1)
        );
        let cutoff = history["history_snapshot"].as_i64().unwrap();
        let deleted = commit_files(
            &source,
            &[(side_path, side_doc), (binary_path, binary)],
            &[&merged],
        )
        .await;
        update(&source, "refs/heads/main", &deleted).await;
        source
            .run(
                &["update-ref", "-d", "refs/heads/side"],
                128,
                &CancellationToken::new(),
                Instant::now() + READ_RUNTIME,
            )
            .await
            .unwrap();
        corpus
            .synchronize(Repo::Content, CancellationToken::new())
            .await
            .unwrap();
        for tick in 0..100 {
            if corpus
                .process_current(CancellationToken::new())
                .await
                .unwrap()
            {
                break;
            }
            assert!(tick < 99);
        }
        for tick in 0..100 {
            if corpus
                .process_history(CancellationToken::new())
                .await
                .unwrap()
            {
                break;
            }
            assert!(tick < 99);
        }
        assert_eq!(
            research
                .call("mdn.get", json!({"slug":"Web/API/Window/fetch"}))
                .await
                .unwrap_err()
                .code,
            "not_found"
        );
        let frozen = research
            .call(
                "mdn.history",
                json!({"path":article,"history_snapshot":cutoff,"limit":100}),
            )
            .await
            .unwrap();
        assert!(
            !frozen["results"]
                .as_array()
                .unwrap()
                .iter()
                .any(|change| change["revision"] == deleted)
        );
        let latest = research
            .call("mdn.history", json!({"path":article,"limit":100}))
            .await
            .unwrap();
        assert!(
            latest["results"]
                .as_array()
                .unwrap()
                .iter()
                .any(|change| change["revision"] == deleted && change["kind"] == "deleted")
        );
        let old_body = research
            .call(
                "mdn.get",
                json!({"path":article,"snapshot":old,"representation":"source"}),
            )
            .await
            .unwrap();
        assert_eq!(old_body["page"]["text"], oldest["page"]["text"]);
        server.abort();
        let _ = server.await;
        let mirror = root.path().join("mdn/content/history.git");
        tokio::fs::remove_dir_all(&mirror).await.unwrap();
        drop(research);
        drop(corpus);
        drop(store);
        let reopened = Arc::new(
            PgBlobStore::connect(url.as_str(), root.path())
                .await
                .unwrap(),
        );
        let restored = MdnCorpus::new(reopened.clone(), broker, root.path(), config).unwrap();
        restored.recover(CancellationToken::new()).await.unwrap();
        let raw = restored
            .research()
            .call(
                "mdn.get",
                json!({"path":binary_path,"representation":"bytes"}),
            )
            .await
            .unwrap();
        assert_eq!(raw["page"]["data"], "AQID/w==");
        let retained = restored.research().read_resource(&resource).await.unwrap();
        assert!(
            retained["contents"][0]["text"]
                .as_str()
                .unwrap()
                .contains("originalliteral")
        );
        assert!(
            reopened
                .mdn_get("commits", &format!("content:{side}"))
                .await
                .unwrap()
                .is_some()
        );
        drop(restored);
        drop(reopened);
        sqlx::query("DROP DATABASE devres_mdn_git_fixture WITH (FORCE)")
            .execute(&admin)
            .await
            .unwrap();
        admin.close().await;
    }
    #[tokio::test]
    async fn unowned_mirror_and_corrupt_retained_manifest_fail_closed() {
        let _test = crate::mdn::index::TEST_GATE.lock().await;
        let root = tempfile::tempdir().unwrap();
        let git = MdnGit::new(
            root.path(),
            Repo::Compat,
            64 * 1024 * 1024,
            64 * 1024 * 1024,
            None,
        )
        .unwrap();
        tokio::fs::create_dir_all(git.repository()).await.unwrap();
        assert!(
            git.initialize(&CancellationToken::new(), Instant::now() + READ_RUNTIME)
                .await
                .is_err()
        );
        let artifact = git
            .artifacts
            .capture_bytes(b"malformed".to_vec(), CancellationToken::new())
            .await
            .unwrap();
        assert!(
            git.read_manifest(&artifact, CancellationToken::new())
                .await
                .is_err()
        );
    }
}
