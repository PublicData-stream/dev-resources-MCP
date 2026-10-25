//! Full official RustSec Git evidence, local graph projection, and resumable backfill.
//! Git never checks out a tree, executes repository content, or reaches a remote directly.
use crate::{
    bulk::{self, BulkArtifact, BulkArtifactStore, BulkBroker},
    crate_git::{
        self, AUTH_HEADER, ManagedChild, base_command, delimited, directory_size, real_directory,
        run_command, valid_oid, valid_pack_name,
    },
};
use devres_application::advisory::{
    ADVISORY_PROCESSOR_VERSION, AdvisorySnapshot, AdvisoryStore, RustSecConfig,
};
use devres_domain::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader},
    sync::Mutex,
    time::Instant,
};
use tokio_util::sync::CancellationToken;

const SOURCE: &str = "https://github.com/rustsec/advisory-db.git";
const MAX_REFS: usize = 10_000;
const MAX_COMMITS: usize = 1_000_000;
const MAX_TREE: usize = 100_000;
const MAX_MEMBER: usize = 1024 * 1024;
const MAX_SELECTED: usize = 64 * 1024 * 1024;
const MAX_PROJECTED_RECORDS: usize = 20_000;
const MAX_GAPS: usize = 256;
const MAX_MANIFEST: usize = 4 * 1024 * 1024;
const FETCH_RUNTIME: Duration = Duration::from_secs(3600);
const BATCH_RUNTIME: Duration = Duration::from_secs(15);

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RefEvidence {
    name: String,
    oid: String,
    object_type: String,
    peeled_commit: Option<String>,
    #[serde(default)]
    snapshots: BTreeMap<String, String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct PackEvidence {
    name: String,
    artifact: BulkArtifact,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Manifest {
    version: u32,
    source_url: String,
    observed_at: i64,
    refs: Vec<RefEvidence>,
    roots: Vec<String>,
    packs: Vec<PackEvidence>,
    commits: BulkArtifact,
    total_commits: usize,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct HistoryState {
    manifest: BulkArtifact,
    observation_id: String,
    observed_at: i64,
    offset: u64,
    processed: usize,
    total: usize,
    complete: bool,
    #[serde(default = "default_true")]
    projection_complete: bool,
    #[serde(default = "legacy_processor_version")]
    processor_version: u32,
}
fn legacy_processor_version() -> u32 {
    1
}
fn reset_processor(state: &mut HistoryState) -> bool {
    if state.processor_version == ADVISORY_PROCESSOR_VERSION {
        return false;
    }
    state.offset = 0;
    state.processed = 0;
    state.complete = false;
    state.projection_complete = true;
    state.processor_version = ADVISORY_PROCESSOR_VERSION;
    true
}
fn default_true() -> bool {
    true
}

pub struct AdvisoryHistory {
    store: Arc<dyn AdvisoryStore>,
    broker: Arc<BulkBroker>,
    root: PathBuf,
    artifacts: Arc<BulkArtifactStore>,
    config: RustSecConfig,
    gate: Mutex<()>,
    restored: Mutex<Option<String>>,
}
fn failure() -> Error {
    Error::unavailable("RustSec Git operation failed.")
}
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn encoded<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| Error::integrity("RustSec evidence encoding failed."))
}
// Only the shared bounded-operation deadline marker is a scheduling yield.
// Quotas, output limits and integrity failures remain failures even at this instant.
fn batch_deadline_exhausted(error: &Error, deadline: Instant) -> bool {
    error.code == "capacity"
        && error.message == "Bulk operation deadline exceeded."
        && Instant::now() >= deadline
}
struct CommitOrderStage(PathBuf);
impl Drop for CommitOrderStage {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
impl AdvisoryHistory {
    pub fn new(
        store: Arc<dyn AdvisoryStore>,
        broker: Arc<BulkBroker>,
        root: &Path,
        config: RustSecConfig,
    ) -> Result<Self> {
        config.validate()?;
        let root = root.join("rustsec-history");
        std::fs::create_dir_all(&root).map_err(|_| failure())?;
        real_directory(&root)?;
        let root = std::fs::canonicalize(root).map_err(|_| failure())?;
        std::fs::create_dir_all(root.join("artifacts")).map_err(|_| failure())?;
        let artifacts = Arc::new(
            BulkArtifactStore::new(root.join("artifacts"), config.min_free_bytes)?
                .with_quota(config.max_archive_storage_bytes)?,
        );
        Ok(Self {
            store,
            broker,
            root,
            artifacts,
            config,
            gate: Mutex::new(()),
            restored: Mutex::new(None),
        })
    }
    fn repository(&self) -> PathBuf {
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
        shutdown: &CancellationToken,
        deadline: Instant,
    ) -> Result<Vec<u8>> {
        let mut command = self.command();
        command.args(args);
        run_command(command, max, shutdown, deadline).await
    }
    async fn initialize(&self, shutdown: &CancellationToken, deadline: Instant) -> Result<()> {
        let repository = self.repository();
        let marker = self.root.join("owner-v1");
        if tokio::fs::try_exists(&repository)
            .await
            .map_err(|_| failure())?
        {
            real_directory(&repository)?;
            let value = tokio::fs::read(&marker)
                .await
                .map_err(|_| Error::integrity("RustSec Git ownership marker missing."))?;
            if value != b"devres-rustsec-history-v1\n" {
                return Err(Error::integrity("RustSec Git ownership mismatch."));
            }
            directory_size(&repository, u64::MAX)?;
        } else {
            match tokio::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&marker)
                .await
            {
                Ok(mut file) => {
                    file.write_all(b"devres-rustsec-history-v1\n")
                        .await
                        .map_err(|_| failure())?;
                    file.sync_all().await.map_err(|_| failure())?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    if tokio::fs::read(&marker).await.map_err(|_| failure())?
                        != b"devres-rustsec-history-v1\n"
                    {
                        return Err(Error::integrity("RustSec Git ownership mismatch."));
                    }
                }
                Err(_) => return Err(failure()),
            }
        }
        let mut command = base_command();
        command
            .args(["init", "--bare", "--template="])
            .arg(&repository);
        run_command(command, 4096, shutdown, deadline).await?;
        // These paths are working artifacts only. Never remove packs or retained refs.
        recover_locks(&repository)?;
        crate_git::recover_working_stages(&repository)?;
        directory_size(&repository, self.config.max_git_bytes)?;
        Ok(())
    }
    pub async fn tick(&self, shutdown: CancellationToken) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }
        let _gate = tokio::select! {biased; _=shutdown.cancelled()=>return Ok(()),gate=self.gate.lock()=>gate};
        if self
            .store
            .advisory_state("history-retry")
            .await?
            .as_ref()
            .and_then(|value| value["next_attempt"].as_i64())
            .is_some_and(|time| time > devres_domain::unix_now())
        {
            let active = self.state("history").await?;
            let latest = self.state("history-latest").await?;
            if active
                .or(latest)
                .is_none_or(|state| state.processor_version == ADVISORY_PROCESSOR_VERSION)
            {
                return Ok(());
            }
        }
        let result = self.tick_inner(shutdown.clone()).await;
        if !shutdown.is_cancelled() {
            let retry = match &result {
                Ok(()) => json!({}),
                Err(error) => {
                    json!({"next_attempt":devres_domain::unix_now()+300,"code":error.code})
                }
            };
            self.store
                .set_advisory_state("history-retry", &retry)
                .await?;
        }
        result
    }
    async fn state(&self, key: &str) -> Result<Option<HistoryState>> {
        self.store
            .advisory_state(key)
            .await?
            .map(serde_json::from_value::<HistoryState>)
            .transpose()
            .map_err(|_| Error::integrity("Invalid retained RustSec history checkpoint."))
    }
    async fn tick_inner(&self, shutdown: CancellationToken) -> Result<()> {
        self.artifacts.recover_stages().await?;
        let mut active = self.state("history").await?;
        let active_reset = active.as_mut().is_some_and(reset_processor);
        if active_reset {
            self.store
                .set_advisory_state(
                    "history",
                    &serde_json::to_value(&active).map_err(|_| failure())?,
                )
                .await?;
        }
        let mut latest = self
            .state("history-latest")
            .await?
            .or_else(|| active.clone());
        let latest_reset = latest.as_mut().is_some_and(reset_processor);
        if latest_reset {
            self.store
                .set_advisory_state(
                    "history-latest",
                    &serde_json::to_value(&latest).map_err(|_| failure())?,
                )
                .await?;
        }
        if active_reset || (active.is_none() && latest_reset) {
            self.store
                .set_advisory_state("history-commit", &json!({}))
                .await?;
        }
        if latest.as_ref().is_none_or(|state| {
            devres_domain::unix_now().saturating_sub(state.observed_at)
                >= self.config.history_refresh_secs as i64
        }) {
            latest = Some(self.synchronize(latest.as_ref(), shutdown.clone()).await?);
        }
        let mut state = match active {
            Some(state) if !state.complete => state,
            Some(state)
                if latest
                    .as_ref()
                    .is_some_and(|latest| latest.observation_id == state.observation_id) =>
            {
                return Ok(());
            }
            _ => latest.ok_or_else(failure)?,
        };
        let needs_restore = self.restored.lock().await.as_deref()
            != Some(&state.manifest.body_hash)
            || !tokio::fs::try_exists(self.repository())
                .await
                .map_err(|_| failure())?;
        if needs_restore {
            self.restore(&state.manifest, shutdown.clone()).await?;
        }
        self.process_batch(&mut state, shutdown).await
    }
    async fn synchronize(
        &self,
        previous: Option<&HistoryState>,
        shutdown: CancellationToken,
    ) -> Result<HistoryState> {
        let deadline = Instant::now() + FETCH_RUNTIME;
        self.initialize(&shutdown, deadline).await?;
        if let Some(previous) = previous {
            self.restore(&previous.manifest, shutdown.clone()).await?;
        }
        let stop = shutdown.child_token();
        let transport_failure = CancellationToken::new();
        let mut relay = crate_git::start_source_relay(
            self.broker.clone(),
            stop.clone(),
            transport_failure.clone(),
            deadline,
            true,
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
                _ = shutdown.cancelled() => break Err(Error::unavailable("RustSec Git synchronization canceled.")),
                _ = transport_failure.cancelled() => break Err(relay.failure_reason.lock().ok().and_then(|reason|reason.clone()).unwrap_or_else(||Error::unavailable("RustSec Git relay failed."))),
                _ = tokio::time::sleep_until(deadline) => break Err(Error::capacity("RustSec Git synchronization deadline exceeded.")),
                status = child.child.wait() => { child.finished = true; break match status { Ok(status) if status.success() => Ok(()), _ => Err(failure()) }; }
                _ = tokio::time::sleep(Duration::from_millis(250)) => {
                    if let Err(error) = self.check_space() { break Err(error); }
                }
            }
        };
        let stopped = child.terminate().await;
        stop.cancel();
        if let Some(mut task) = relay.task.take()
            && tokio::time::timeout(Duration::from_secs(5), &mut task)
                .await
                .is_err()
        {
            task.abort();
            let _ = task.await;
        }
        transfer?;
        stopped?;
        self.check_space()?;
        let observed_at = devres_domain::unix_now();
        let refs = self.read_refs(&shutdown, deadline).await?;
        let mut roots: BTreeSet<String> =
            refs.iter().map(|reference| reference.oid.clone()).collect();
        if let Some(previous) = previous {
            roots.extend(
                self.read_manifest(&previous.manifest, shutdown.clone())
                    .await?
                    .roots,
            );
        }
        if roots.len() > MAX_REFS * 10 {
            return Err(Error::capacity("RustSec retained ref-root limit exceeded."));
        }
        // Protect every observed root, including tag/blob/tree targets, from maintenance.
        for oid in &roots {
            self.run(
                &["update-ref", &format!("refs/devres/retained/{oid}"), oid],
                128,
                &shutdown,
                deadline,
            )
            .await?;
        }
        self.run(
            &[
                "fsck",
                "--connectivity-only",
                "--no-reflogs",
                "--no-dangling",
            ],
            1024 * 1024,
            &shutdown,
            deadline,
        )
        .await?;
        let (commits, total_commits) = self.capture_commit_order(&shutdown, deadline).await?;
        let packs = self.capture_packs(shutdown.clone()).await?;
        let manifest = Manifest {
            version: 1,
            source_url: SOURCE.into(),
            observed_at,
            refs,
            roots: roots.into_iter().collect(),
            packs,
            commits,
            total_commits,
        };
        let bytes = encoded(&manifest)?;
        if bytes.len() > MAX_MANIFEST {
            return Err(Error::capacity("RustSec ref manifest exceeds 4 MiB."));
        }
        let artifact = self
            .artifacts
            .capture_bytes(bytes, shutdown.clone())
            .await?;
        let id = artifact.body_hash.clone();
        self.store.put_advisory_row("refs",&id,&json!({"id":id,"observed_at":observed_at,"refs":manifest.refs,"manifest":artifact,"complete":true,"projection_complete":false,"history_scope":"advertised_heads_and_tags_reachable_ancestry","total_commits":total_commits})).await?;
        let state = HistoryState {
            manifest: artifact,
            observation_id: id,
            observed_at,
            offset: 0,
            processed: 0,
            total: total_commits,
            complete: false,
            projection_complete: true,
            processor_version: ADVISORY_PROCESSOR_VERSION,
        };
        self.store
            .set_advisory_state(
                "history-latest",
                &serde_json::to_value(&state).map_err(|_| failure())?,
            )
            .await?;
        *self.restored.lock().await = Some(state.manifest.body_hash.clone());
        Ok(state)
    }
    fn check_space(&self) -> Result<()> {
        directory_size(&self.repository(), self.config.max_git_bytes)?;
        if fs2::available_space(&self.root).map_err(|_| failure())? < self.config.min_free_bytes {
            return Err(Error::capacity(
                "Insufficient RustSec Git storage headroom; retained history is preserved.",
            ));
        }
        Ok(())
    }
    async fn read_refs(
        &self,
        shutdown: &CancellationToken,
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
                shutdown,
                deadline,
            )
            .await?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| Error::integrity("Invalid RustSec ref listing."))?;
        let mut refs = Vec::new();
        for line in text.lines() {
            if refs.len() >= MAX_REFS {
                return Err(Error::capacity("RustSec ref count exceeds its budget."));
            }
            let fields: Vec<_> = line.split('\t').collect();
            if fields.len() != 3
                || !valid_oid(fields[1])
                || !matches!(fields[2], "commit" | "tag" | "tree" | "blob")
            {
                return Err(Error::integrity("Invalid RustSec ref record."));
            }
            let suffix = fields[0]
                .strip_prefix("refs/devres/live/")
                .ok_or_else(failure)?;
            let name = format!("refs/{suffix}");
            if !valid_ref(&name) {
                return Err(Error::integrity("Invalid RustSec upstream ref name."));
            }
            let peeled_commit = if fields[2] == "commit" {
                Some(fields[1].to_owned())
            } else if fields[2] == "tag" {
                self.peel_commit(fields[1], shutdown, deadline).await?
            } else {
                None
            };
            refs.push(RefEvidence {
                name,
                oid: fields[1].into(),
                object_type: fields[2].into(),
                peeled_commit,
                snapshots: BTreeMap::new(),
            });
        }
        Ok(refs)
    }
    async fn peel_commit(
        &self,
        oid: &str,
        shutdown: &CancellationToken,
        deadline: Instant,
    ) -> Result<Option<String>> {
        let mut oid = oid.to_owned();
        for _ in 0..64 {
            let kind = self
                .run(&["cat-file", "-t", &oid], 64, shutdown, deadline)
                .await?;
            match kind.as_slice() {
                b"commit\n" => return Ok(Some(oid)),
                b"blob\n" | b"tree\n" => return Ok(None),
                b"tag\n" => {
                    let bytes = self
                        .run(&["cat-file", "tag", &oid], MAX_MEMBER, shutdown, deadline)
                        .await?;
                    let line = bytes
                        .split(|byte| *byte == b'\n')
                        .next()
                        .ok_or_else(failure)?;
                    oid = std::str::from_utf8(line)
                        .ok()
                        .and_then(|line| line.strip_prefix("object "))
                        .filter(|v| valid_oid(v))
                        .ok_or_else(|| Error::integrity("Invalid RustSec tag target."))?
                        .into();
                }
                _ => return Err(Error::integrity("Invalid RustSec Git object type.")),
            }
        }
        Err(Error::capacity("RustSec tag nesting exceeds 64."))
    }
    async fn capture_commit_order(
        &self,
        shutdown: &CancellationToken,
        deadline: Instant,
    ) -> Result<(BulkArtifact, usize)> {
        let stage = self.root.join("commit-order.stage");
        if tokio::fs::try_exists(&stage).await.map_err(|_| failure())? {
            let metadata = tokio::fs::symlink_metadata(&stage)
                .await
                .map_err(|_| failure())?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(Error::integrity("Invalid RustSec commit-order stage."));
            }
            tokio::fs::remove_file(&stage)
                .await
                .map_err(|_| failure())?;
        }
        let _stage_guard = CommitOrderStage(stage.clone());
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
                "--all",
            ])
            .stdout(Stdio::piped());
        let mut child = ManagedChild::spawn(command)?;
        let result = async {
            let mut output = BufReader::new(child.child.stdout.take().ok_or_else(failure)?);
            let mut count = 0usize;
            let mut written = 0usize;
            while let Some(line) =
                delimited(&mut output, b'\n', 64 * 1024, shutdown, deadline).await?
            {
                parse_commit_line(&line)?;
                written = written.saturating_add(line.len() + 1);
                if written > 128 * 1024 * 1024 {
                    return Err(Error::capacity(
                        "RustSec commit-order bytes exceed 128 MiB.",
                    ));
                }
                count += 1;
                if count > MAX_COMMITS {
                    return Err(Error::capacity("RustSec commit count exceeds its budget."));
                }
                file.write_all(&line).await.map_err(|_| failure())?;
                file.write_all(b"\n").await.map_err(|_| failure())?;
            }
            let status = bulk::bounded(shutdown, deadline, async {
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
        let artifact = self
            .artifacts
            .ingest_file(&stage, 128 * 1024 * 1024, shutdown.clone())
            .await?;
        tokio::fs::remove_file(stage).await.map_err(|_| failure())?;
        Ok((artifact, count))
    }
    async fn capture_packs(&self, shutdown: CancellationToken) -> Result<Vec<PackEvidence>> {
        let root = self.repository().join("objects/pack");
        real_directory(&root)?;
        let mut entries = tokio::fs::read_dir(root).await.map_err(|_| failure())?;
        let mut files = Vec::new();
        while let Some(entry) = entries.next_entry().await.map_err(|_| failure())? {
            let name = entry.file_name().into_string().map_err(|_| failure())?;
            if !valid_pack_name(&name) || !entry.file_type().await.map_err(|_| failure())?.is_file()
            {
                return Err(Error::integrity("Invalid RustSec Git evidence member."));
            }
            if files.len() >= 10_000 {
                return Err(Error::capacity(
                    "RustSec Git pack count exceeds its budget.",
                ));
            }
            let artifact = self
                .artifacts
                .ingest_file(&entry.path(), bulk::MAX_ARTIFACT_BYTES, shutdown.clone())
                .await?;
            files.push(PackEvidence { name, artifact });
        }
        files.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(files)
    }
    async fn read_manifest(
        &self,
        artifact: &BulkArtifact,
        shutdown: CancellationToken,
    ) -> Result<Manifest> {
        let mut file = self
            .artifacts
            .open(&artifact.body_hash, MAX_MANIFEST as u64, shutdown)
            .await?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).await.map_err(|_| failure())?;
        let value: Manifest = serde_json::from_slice(&bytes)
            .map_err(|_| Error::integrity("Invalid RustSec Git manifest."))?;
        if value.version != 1
            || value.source_url != SOURCE
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
                    || reference
                        .peeled_commit
                        .as_ref()
                        .is_some_and(|oid| !valid_oid(oid))
            })
        {
            return Err(Error::integrity("Invalid RustSec Git manifest identity."));
        }
        Ok(value)
    }
    pub async fn restore(
        &self,
        artifact: &BulkArtifact,
        shutdown: CancellationToken,
    ) -> Result<()> {
        let deadline = Instant::now() + FETCH_RUNTIME;
        self.initialize(&shutdown, deadline).await?;
        let manifest = self.read_manifest(artifact, shutdown.clone()).await?;
        if self
            .artifacts
            .verify(
                &manifest.commits.body_hash,
                128 * 1024 * 1024,
                shutdown.clone(),
            )
            .await?
            != manifest.commits
        {
            return Err(Error::integrity(
                "RustSec commit-order artifact metadata mismatch.",
            ));
        }
        let root = self.repository().join("objects/pack");
        for pack in &manifest.packs {
            if !valid_pack_name(&pack.name) {
                return Err(Error::integrity("Invalid RustSec retained pack name."));
            }
            let actual = self
                .artifacts
                .verify(
                    &pack.artifact.body_hash,
                    bulk::MAX_ARTIFACT_BYTES,
                    shutdown.clone(),
                )
                .await?;
            if actual != pack.artifact {
                return Err(Error::integrity(
                    "RustSec pack metadata differs from evidence.",
                ));
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
                        .ingest_file(&target, bulk::MAX_ARTIFACT_BYTES, shutdown.clone())
                        .await?
                        != pack.artifact
                    {
                        return Err(Error::integrity(
                            "RustSec working pack differs from evidence.",
                        ));
                    }
                }
                Err(_) => return Err(failure()),
            }
        }
        for oid in &manifest.roots {
            self.run(
                &["update-ref", &format!("refs/devres/retained/{oid}"), oid],
                128,
                &shutdown,
                deadline,
            )
            .await?;
        }
        self.run(
            &[
                "fsck",
                "--connectivity-only",
                "--no-reflogs",
                "--no-dangling",
            ],
            1024 * 1024,
            &shutdown,
            deadline,
        )
        .await?;
        directory_size(&self.repository(), self.config.max_git_bytes)?;
        *self.restored.lock().await = Some(artifact.body_hash.clone());
        Ok(())
    }
    async fn process_batch(
        &self,
        state: &mut HistoryState,
        shutdown: CancellationToken,
    ) -> Result<()> {
        self.process_batch_until(state, shutdown, Instant::now() + BATCH_RUNTIME)
            .await
    }
    async fn process_batch_until(
        &self,
        state: &mut HistoryState,
        shutdown: CancellationToken,
        deadline: Instant,
    ) -> Result<()> {
        let manifest = self
            .read_manifest(&state.manifest, shutdown.clone())
            .await?;
        let mut file = self
            .artifacts
            .open(
                &manifest.commits.body_hash,
                128 * 1024 * 1024,
                shutdown.clone(),
            )
            .await?;
        file.seek(std::io::SeekFrom::Start(state.offset))
            .await
            .map_err(|_| failure())?;
        if state.offset > manifest.commits.bytes
            || state.processed > state.total
            || state.total != manifest.total_commits
        {
            return Err(Error::integrity("Invalid RustSec history progress bounds."));
        }
        let mut reader = BufReader::new(file);
        for _ in 0..1000 {
            if Instant::now() >= deadline || shutdown.is_cancelled() {
                break;
            }
            let line = match delimited(&mut reader, b'\n', 64 * 1024, &shutdown, deadline).await {
                Ok(line) => line,
                Err(error) if batch_deadline_exhausted(&error, deadline) => break,
                Err(error) => return Err(error),
            };
            let Some(line) = line else {
                if state.processed != state.total {
                    return Err(Error::integrity(
                        "RustSec commit-order evidence is truncated.",
                    ));
                }
                state.complete = true;
                break;
            };
            let commit = parse_commit_line(&line)?;
            match self
                .process_commit(
                    &commit,
                    &state.observation_id,
                    &shutdown,
                    deadline,
                    MAX_PROJECTED_RECORDS,
                )
                .await
            {
                Ok(true) => {}
                Ok(false) => break,
                Err(error) if batch_deadline_exhausted(&error, deadline) => break,
                Err(error) => return Err(error),
            }
            state.offset += line.len() as u64 + 1;
            state.processed += 1;
            let row = self
                .store
                .advisory_commit(&commit.oid, None)
                .await?
                .ok_or_else(failure)?;
            state.projection_complete &= row.data["projection_complete"] == true;
            if state.processed > state.total {
                return Err(Error::integrity(
                    "RustSec commit-order evidence exceeds declared coverage.",
                ));
            }
            self.store
                .set_advisory_state(
                    "history",
                    &serde_json::to_value(&*state).map_err(|_| failure())?,
                )
                .await?;
        }
        state.complete = state.processed == state.total;
        if state.complete {
            self.publish_processed_refs(
                &manifest,
                &state.observation_id,
                state.projection_complete,
            )
            .await?;
        }
        self.store
            .set_advisory_state(
                "history",
                &serde_json::to_value(&*state).map_err(|_| failure())?,
            )
            .await?;
        Ok(())
    }
    async fn process_commit(
        &self,
        commit: &Commit,
        observation: &str,
        shutdown: &CancellationToken,
        deadline: Instant,
        max_members: usize,
    ) -> Result<bool> {
        if self
            .store
            .advisory_row(
                "processing",
                &format!("{}:{}", commit.oid, ADVISORY_PROCESSOR_VERSION),
            )
            .await?
            .is_some()
        {
            return Ok(true);
        }
        // Graph reads also validate storage before starting a retained-object operation.
        let raw = self.store.advisory_row("commits", &commit.oid).await?;
        let mut progress = self
            .store
            .advisory_state("history-commit")
            .await?
            .unwrap_or_else(|| json!({}));
        if progress["revision"] != commit.oid
            || progress["processor_version"] != ADVISORY_PROCESSOR_VERSION
        {
            progress = json!({"revision":commit.oid,"processor_version":ADVISORY_PROCESSOR_VERSION,"snapshots":{},"format":"rustsec","index":0});
        }
        let mut snapshots: BTreeMap<String, String> =
            serde_json::from_value(progress["snapshots"].clone())
                .map_err(|_| Error::integrity("Invalid RustSec commit processing checkpoint."))?;
        // The v2 correction changes only previously incomplete OSV semantics.
        // Reuse unchanged immutable projections, retaining their original provenance.
        if ADVISORY_PROCESSOR_VERSION == 2 {
            for format in ["rustsec", "osv"] {
                if snapshots.contains_key(format) {
                    continue;
                }
                let Some(id) = raw
                    .as_ref()
                    .and_then(|row| row.data["snapshots"][format].as_str())
                else {
                    continue;
                };
                if self
                    .store
                    .advisory_projection_state(id, format)
                    .await?
                    .is_some_and(|state| {
                        state.processor_version == 1 && (format == "rustsec" || state.complete)
                    })
                {
                    snapshots.insert(format.into(), id.to_owned());
                }
            }
        }
        if Instant::now() >= deadline || shutdown.is_cancelled() {
            progress["snapshots"] = serde_json::to_value(&snapshots).map_err(|_| failure())?;
            self.store
                .set_advisory_state("history-commit", &progress)
                .await?;
            return Ok(false);
        }
        if snapshots.len() == 2 {
            let complete = self.projection_completeness(&snapshots).await?;
            self.publish_processing(commit, observation, snapshots, complete)
                .await?;
            return Ok(true);
        }
        let bytes = match self
            .run(
                &["ls-tree", "-r", "-z", &commit.oid],
                16 * 1024 * 1024,
                shutdown,
                deadline,
            )
            .await
        {
            Ok(bytes) => bytes,
            Err(error) if error.code == "capacity" && Instant::now() < deadline => {
                self.publish_commit_gap(commit, observation, &error.code)
                    .await?;
                return Ok(true);
            }
            Err(error) => return Err(error),
        };
        let members = match parse_tree(&bytes) {
            Ok(members) => members,
            Err(error) => {
                self.publish_commit_gap(commit, observation, &error.code)
                    .await?;
                return Ok(true);
            }
        };
        for format in ["rustsec", "osv"] {
            if snapshots.contains_key(format) {
                continue;
            }
            let selected: Vec<_> = members
                .iter()
                .filter(|member| relevant_path(&member.path, format))
                .collect();
            let resume = progress["format"] == format;
            let mut index = if resume {
                progress["index"].as_u64().unwrap_or(0) as usize
            } else {
                0
            };
            if index > selected.len() {
                return Err(Error::integrity(
                    "Invalid RustSec commit member checkpoint.",
                ));
            }
            let partial = if resume {
                match progress["partial"].as_str() {
                    Some(id) => self.store.advisory_snapshot(Some(id), format).await?,
                    None => None,
                }
            } else {
                None
            };
            let mut records = partial
                .as_ref()
                .map_or_else(Vec::new, |value| value.records.clone());
            let mut gaps = partial
                .as_ref()
                .and_then(|value| value.coverage["gaps"].as_array())
                .cloned()
                .unwrap_or_default();
            let mut retained = records
                .iter()
                .map(|record| record.body.len())
                .sum::<usize>();
            let mut seen_ids: BTreeSet<String> =
                records.iter().map(|record| record.id.clone()).collect();
            let mut gap_count = partial
                .as_ref()
                .and_then(|value| value.coverage["gap_count"].as_u64())
                .unwrap_or(gaps.len() as u64);
            let mut omitted = 0;
            let begin = index;
            let mut prefetched = VecDeque::new();
            while index < selected.len() {
                if Instant::now() >= deadline
                    || shutdown.is_cancelled()
                    || index - begin >= max_members
                {
                    break;
                }
                if prefetched.is_empty() {
                    let end = index.saturating_add(16).min(selected.len());
                    let keys: Vec<String> = selected[index..end]
                        .iter()
                        .map(|member| projection_key(member, format))
                        .collect::<Result<_>>()?;
                    let rows = self
                        .store
                        .advisory_rows_by_keys("git-projections", &keys)
                        .await?;
                    let mut cached: HashMap<_, _> =
                        rows.into_iter().map(|row| (row.key, row.data)).collect();
                    let missing: Vec<_> = selected[index..end]
                        .iter()
                        .zip(&keys)
                        .filter(|(_, key)| !cached.contains_key(*key))
                        .map(|(member, key)| {
                            Ok((key.clone(), projection_key_version(member, format, 1)?))
                        })
                        .collect::<Result<_>>()?;
                    if !missing.is_empty() {
                        let legacy_keys: Vec<_> =
                            missing.iter().map(|(_, key)| key.clone()).collect();
                        let mut legacy: HashMap<_, _> = self
                            .store
                            .advisory_rows_by_keys("git-projections", &legacy_keys)
                            .await?
                            .into_iter()
                            .map(|row| (row.key, row.data))
                            .collect();
                        for (key, old_key) in missing {
                            if let Some(mut data) =
                                legacy.remove(&old_key).filter(reusable_v1_projection)
                            {
                                data["coverage"]["processor_version"] =
                                    json!(ADVISORY_PROCESSOR_VERSION);
                                data["coverage"]["reused_processor_version"] = json!(1);
                                self.store
                                    .put_advisory_row("git-projections", &key, &data)
                                    .await?;
                                cached.insert(key, data);
                            }
                        }
                    }
                    prefetched = keys
                        .into_iter()
                        .map(|key| {
                            let value = cached.remove(&key);
                            (key, value)
                        })
                        .collect();
                    if Instant::now() >= deadline || shutdown.is_cancelled() {
                        break;
                    }
                }
                let member = selected[index];
                let (key, value) = prefetched.pop_front().ok_or_else(|| {
                    Error::integrity("RustSec projection prefetch framing failed.")
                })?;
                let cached = match value {
                    Some(data) => data,
                    None => {
                        let bytes = if matches!(member.mode.as_str(), "100644" | "100755") {
                            match self
                                .run(
                                    &["cat-file", "blob", &member.oid],
                                    MAX_MEMBER,
                                    shutdown,
                                    deadline,
                                )
                                .await
                            {
                                Ok(bytes) => bytes,
                                Err(error) if batch_deadline_exhausted(&error, deadline) => break,
                                Err(error) if error.code == "capacity" => Vec::new(),
                                Err(error) => return Err(error),
                            }
                        } else {
                            Vec::new()
                        };
                        let value = match crate::advisory_corpus::normalize_records(
                            vec![(member.path.clone(), bytes)],
                            format,
                        ) {
                            Ok((records, coverage)) => {
                                json!({"records":records,"coverage":coverage})
                            }
                            Err(error) => {
                                json!({"records":[],"coverage":{"complete":false,"gaps":[{"path":member.path,"code":error.code}]}})
                            }
                        };
                        let mut value = if encoded(&value)?.len() > 4 * 1024 * 1024 {
                            json!({"records":[],"coverage":{"complete":false,"gaps":[{"path":member.path,"code":"capacity"}]}})
                        } else {
                            value
                        };
                        value["coverage"]["processor_version"] = json!(ADVISORY_PROCESSOR_VERSION);
                        self.store
                            .put_advisory_row("git-projections", &key, &value)
                            .await?;
                        value
                    }
                };
                let normalized: Vec<devres_application::advisory::AdvisoryRecord> =
                    serde_json::from_value(cached["records"].clone())
                        .map_err(|_| Error::integrity("Invalid RustSec cached projection."))?;
                let mut exhausted = false;
                for record in normalized {
                    if !seen_ids.insert(record.id.clone()) {
                        add_gap(
                            &mut gaps,
                            &mut gap_count,
                            &member.path,
                            "duplicate_identity",
                        );
                        continue;
                    }
                    if retained.saturating_add(record.body.len()) > MAX_SELECTED
                        || records.len() >= MAX_PROJECTED_RECORDS
                    {
                        add_gap(&mut gaps, &mut gap_count, &member.path, "capacity");
                        exhausted = true;
                        break;
                    }
                    retained += record.body.len();
                    records.push(record);
                }
                if let Some(failures) = cached["coverage"]["gaps"].as_array() {
                    for failure in failures {
                        add_gap(
                            &mut gaps,
                            &mut gap_count,
                            failure["path"].as_str().unwrap_or(&member.path),
                            failure["code"].as_str().unwrap_or("unsupported_projection"),
                        );
                    }
                }
                if cached["coverage"]["complete"] != true
                    && cached["coverage"]["gaps"]
                        .as_array()
                        .is_none_or(Vec::is_empty)
                {
                    add_gap(
                        &mut gaps,
                        &mut gap_count,
                        &member.path,
                        "unsupported_projection",
                    );
                }
                index += 1;
                if exhausted {
                    omitted = selected.len() - index;
                    index = selected.len();
                    break;
                }
            }
            let finished = index == selected.len();
            let complete = finished && gap_count == 0;
            let coverage = json!({"complete":complete,"enumerated":selected.len(),"processed":index-omitted,"omitted":omitted,"parsed":records.iter().filter(|record|record.metadata["processing"]!="unsupported").count(),"retained_records":records.len(),"gaps":gaps,"gap_count":gap_count,"git_observation":observation,"source_url":SOURCE,"graph_complete":true,"processor_version":ADVISORY_PROCESSOR_VERSION});
            let identity = json!({"revision":commit.oid,"format":format,"processor":ADVISORY_PROCESSOR_VERSION,"records":records.iter().map(|record|(&record.path,&record.body_hash)).collect::<Vec<_>>(),"processed":index,"complete":complete});
            let id = digest(&encoded(&identity)?);
            let snapshot = AdvisorySnapshot {
                id: id.clone(),
                revision: commit.oid.clone(),
                format: format.into(),
                created_at: devres_domain::unix_now(),
                validated_at: None,
                historical: true,
                complete,
                records,
                captures: Vec::new(),
                coverage,
                parents: commit.parents.clone(),
                committed_at: commit.timestamp,
            };
            if self
                .store
                .advisory_snapshot(Some(&id), format)
                .await?
                .is_none()
            {
                self.store
                    .publish_advisory_snapshot(&snapshot, false)
                    .await?;
            }
            if !finished {
                progress = json!({"revision":commit.oid,"processor_version":ADVISORY_PROCESSOR_VERSION,"format":format,"index":index,"partial":id,"snapshots":snapshots});
                self.store
                    .set_advisory_state("history-commit", &progress)
                    .await?;
                return Ok(false);
            }
            snapshots.insert(format.into(), id);
            progress = json!({"revision":commit.oid,"processor_version":ADVISORY_PROCESSOR_VERSION,"format":"osv","index":0,"snapshots":snapshots});
            self.store
                .set_advisory_state("history-commit", &progress)
                .await?;
        }
        let projection_complete = self.projection_completeness(&snapshots).await?;
        self.publish_processing(commit, observation, snapshots, projection_complete)
            .await?;
        Ok(true)
    }
    async fn projection_completeness(&self, snapshots: &BTreeMap<String, String>) -> Result<bool> {
        let mut complete = true;
        for (format, id) in snapshots {
            complete &= self
                .store
                .advisory_projection_state(id, format)
                .await?
                .ok_or_else(|| Error::integrity("Published advisory projection is missing."))?
                .complete;
        }
        Ok(complete)
    }
    async fn publish_processing(
        &self,
        commit: &Commit,
        observation: &str,
        snapshots: BTreeMap<String, String>,
        projection_complete: bool,
    ) -> Result<()> {
        if self
            .store
            .advisory_row("commits", &commit.oid)
            .await?
            .is_none()
        {
            self.store.put_advisory_row("commits",&commit.oid,&json!({"revision":commit.oid,"parents":commit.parents,"committed_at":commit.timestamp,"first_observation":observation})).await?;
        }
        let mut parent_snapshots = BTreeMap::new();
        for parent in &commit.parents {
            if let Some(row) = self.store.advisory_commit(parent, None).await? {
                parent_snapshots.insert(parent.clone(), row.data["snapshots"].clone());
            }
        }
        self.store.put_advisory_row("processing",&format!("{}:{}",commit.oid,ADVISORY_PROCESSOR_VERSION),&json!({"revision":commit.oid,"processor_version":ADVISORY_PROCESSOR_VERSION,"snapshots":snapshots,"parent_snapshots":parent_snapshots,"projection_complete":projection_complete})).await?;
        self.store
            .set_advisory_state("history-commit", &json!({}))
            .await
    }

    async fn publish_commit_gap(
        &self,
        commit: &Commit,
        observation: &str,
        code: &str,
    ) -> Result<()> {
        let mut snapshots = BTreeMap::new();
        for format in ["rustsec", "osv"] {
            let id = digest(&encoded(
                &json!({"revision":commit.oid,"format":format,"processor":ADVISORY_PROCESSOR_VERSION,"inventory_gap":code}),
            )?);
            if self
                .store
                .advisory_snapshot(Some(&id), format)
                .await?
                .is_none()
            {
                let snapshot = AdvisorySnapshot {
                    id: id.clone(),
                    revision: commit.oid.clone(),
                    format: format.into(),
                    created_at: devres_domain::unix_now(),
                    validated_at: None,
                    historical: true,
                    complete: false,
                    records: Vec::new(),
                    captures: Vec::new(),
                    coverage: json!({"complete":false,"inventory_complete":false,"graph_complete":true,"gaps":[{"code":code}],"gap_count":1,"git_observation":observation,"source_url":SOURCE,"processor_version":ADVISORY_PROCESSOR_VERSION}),
                    parents: commit.parents.clone(),
                    committed_at: commit.timestamp,
                };
                self.store
                    .publish_advisory_snapshot(&snapshot, false)
                    .await?;
            }
            snapshots.insert(format.to_owned(), id);
        }
        self.publish_processing(commit, observation, snapshots, false)
            .await
    }

    async fn publish_processed_refs(
        &self,
        manifest: &Manifest,
        observation: &str,
        projection_complete: bool,
    ) -> Result<()> {
        let mut refs = manifest.refs.clone();
        for reference in &mut refs {
            let Some(commit) = reference.peeled_commit.as_deref() else {
                continue;
            };
            let Some(row) = self.store.advisory_commit(commit, None).await? else {
                continue;
            };
            reference.snapshots =
                serde_json::from_value(row.data["snapshots"].clone()).map_err(|_| failure())?;
            if reference.name == "refs/heads/osv"
                && let Some(id) = reference.snapshots.get("osv").cloned()
                && let Some(mut snapshot) = self.store.advisory_snapshot(Some(&id), "osv").await?
            {
                snapshot.validated_at = Some(manifest.observed_at);
                snapshot.historical = false;
                snapshot.id = digest(&encoded(
                    &json!({"historical_snapshot":id,"observation":observation,"processor_version":ADVISORY_PROCESSOR_VERSION}),
                )?);
                if snapshot.records.is_empty() {
                    snapshot.complete = false;
                    snapshot.coverage["complete"] = serde_json::Value::Bool(false);
                    snapshot.coverage["empty_export"] = serde_json::Value::Bool(true);
                }
                let snapshot = self
                    .store
                    .advisory_snapshot(Some(&snapshot.id), "osv")
                    .await?
                    .unwrap_or(snapshot);
                // A malformed export never replaces a previously usable default.
                self.store
                    .publish_advisory_snapshot(&snapshot, snapshot.complete)
                    .await?;
                reference.snapshots.insert("osv".into(), snapshot.id);
            }
        }
        let observation_sequence = self
            .store
            .advisory_row("refs", observation)
            .await?
            .ok_or_else(|| Error::integrity("RustSec raw ref observation missing."))?
            .sequence;
        self.store.put_advisory_row("refs",&format!("{observation}:processed:{ADVISORY_PROCESSOR_VERSION}"),&json!({"id":observation,"processor_version":ADVISORY_PROCESSOR_VERSION,"observation_sequence":observation_sequence,"observed_at":manifest.observed_at,"refs":refs,"complete":true,"processing_finished":true,"projection_complete":projection_complete,"history_scope":"advertised_heads_and_tags_reachable_ancestry","total_commits":manifest.total_commits})).await
    }
}
fn add_gap(gaps: &mut Vec<serde_json::Value>, count: &mut u64, path: &str, code: &str) {
    *count = count.saturating_add(1);
    if gaps.len() < MAX_GAPS {
        gaps.push(json!({"path":path.chars().take(256).collect::<String>(),"path_hash":digest(path.as_bytes()),"code":code.chars().take(64).collect::<String>()}));
    }
}

#[derive(Clone, Debug)]
struct Commit {
    oid: String,
    parents: Vec<String>,
    timestamp: i64,
}
fn parse_commit_line(bytes: &[u8]) -> Result<Commit> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error::integrity("Invalid RustSec Git commit line."))?;
    let mut fields = text.split(' ');
    let timestamp = fields
        .next()
        .and_then(|value| value.parse::<i64>().ok())
        .ok_or_else(|| Error::integrity("Invalid RustSec commit date."))?;
    let oid = fields
        .next()
        .filter(|value| valid_oid(value))
        .ok_or_else(|| Error::integrity("Invalid RustSec commit identity."))?
        .to_owned();
    let parents: Vec<_> = fields.map(str::to_owned).collect();
    if parents.len() > 1024 || parents.iter().any(|value| !valid_oid(value)) {
        return Err(Error::integrity("Invalid RustSec commit parents."));
    }
    Ok(Commit {
        oid,
        parents,
        timestamp,
    })
}
#[derive(Clone, Debug)]
struct TreeMember {
    mode: String,
    oid: String,
    path: String,
}
fn parse_tree(bytes: &[u8]) -> Result<Vec<TreeMember>> {
    if !bytes.is_empty() && bytes.last() != Some(&0) {
        return Err(Error::integrity("Truncated RustSec tree listing."));
    }
    let mut members = Vec::new();
    for record in bytes
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        if members.len() >= MAX_TREE {
            return Err(Error::capacity(
                "RustSec tree member count exceeds its budget.",
            ));
        }
        let record = std::str::from_utf8(record)
            .map_err(|_| Error::integrity("Invalid RustSec tree path encoding."))?;
        let (header, path) = record
            .split_once('\t')
            .ok_or_else(|| Error::integrity("Invalid RustSec tree record."))?;
        let fields: Vec<_> = header.split(' ').collect();
        if fields.len() != 3
            || !valid_oid(fields[2])
            || path.len() > 4096
            || path.contains(['\n', '\r', '\\'])
            || path.split('/').any(|part| matches!(part, "" | "." | ".."))
        {
            return Err(Error::integrity("Invalid RustSec tree member."));
        }
        members.push(TreeMember {
            mode: fields[0].into(),
            oid: fields[2].into(),
            path: path.into(),
        });
    }
    Ok(members)
}
fn projection_key(member: &TreeMember, format: &str) -> Result<String> {
    projection_key_version(member, format, ADVISORY_PROCESSOR_VERSION)
}
fn projection_key_version(member: &TreeMember, format: &str, version: u32) -> Result<String> {
    Ok(digest(&encoded(
        &json!({"oid":member.oid,"path":member.path,"mode":member.mode,"format":format,"processor":version}),
    )?))
}
// Version two only repairs previously incomplete OSV intervals. Future processors
// must explicitly decide which earlier semantic projections are safe to migrate.
fn reusable_v1_projection(data: &serde_json::Value) -> bool {
    ADVISORY_PROCESSOR_VERSION == 2
        && data["coverage"]["complete"] == true
        && data["coverage"]["gaps"]
            .as_array()
            .is_none_or(Vec::is_empty)
        && data["records"].as_array().is_some_and(|records| {
            !records.is_empty()
                && records.iter().all(|record| {
                    record["metadata"]["matching_complete"] != false
                        && record["metadata"]["processing"] != "unsupported"
                })
        })
}
fn relevant_path(path: &str, format: &str) -> bool {
    path.starts_with("crates/")
        && match format {
            "rustsec" => !path.ends_with(".json") && path.contains("RUSTSEC-"),
            "osv" => path.ends_with(".json") && path.contains("RUSTSEC-"),
            _ => false,
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
fn recover_locks(repository: &Path) -> Result<()> {
    directory_size(repository, u64::MAX)?;
    fn walk(path: &Path) -> Result<()> {
        if !path.exists() {
            return Ok(());
        }
        for entry in std::fs::read_dir(path).map_err(|_| failure())? {
            let entry = entry.map_err(|_| failure())?;
            let metadata = entry.file_type().map_err(|_| failure())?;
            if metadata.is_symlink() {
                return Err(Error::integrity("Unexpected RustSec working symlink."));
            }
            if metadata.is_dir() {
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
            _ => return Err(Error::integrity("Invalid RustSec working lock.")),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use axum::{
        Router,
        body::Bytes,
        routing::{get, post},
    };
    use devres_application::advisory::AdvisoryRow;
    use serde_json::Value;

    #[derive(Default)]
    struct Memory {
        rows: Mutex<BTreeMap<(String, String), AdvisoryRow>>,
        states: Mutex<BTreeMap<String, Value>>,
        snapshots: Mutex<BTreeMap<String, AdvisorySnapshot>>,
        defaults: Mutex<BTreeMap<String, String>>,
        projection_prefetches: Mutex<Vec<usize>>,
        single_projection_reads: Mutex<usize>,
        commit_lookup_delay: Mutex<Option<Duration>>,
        commit_lookup_failure: Mutex<Option<Error>>,
    }
    #[async_trait]
    impl AdvisoryStore for Memory {
        async fn publish_advisory_snapshot(
            &self,
            snapshot: &AdvisorySnapshot,
            make_default: bool,
        ) -> Result<()> {
            let mut snapshots = self.snapshots.lock().await;
            if let Some(existing) = snapshots.get(&snapshot.id) {
                if serde_json::to_value(existing).unwrap()
                    != serde_json::to_value(snapshot).unwrap()
                {
                    return Err(Error::integrity("Fixture immutable descriptor collision."));
                }
            } else {
                snapshots.insert(snapshot.id.clone(), snapshot.clone());
            }
            drop(snapshots);
            if make_default {
                self.defaults
                    .lock()
                    .await
                    .insert(snapshot.format.clone(), snapshot.id.clone());
            }
            Ok(())
        }
        async fn advisory_snapshot(
            &self,
            id: Option<&str>,
            format: &str,
        ) -> Result<Option<AdvisorySnapshot>> {
            let id = match id {
                Some(id) => Some(id.to_owned()),
                None => self.defaults.lock().await.get(format).cloned(),
            };
            Ok(id
                .and_then(|id| {
                    self.snapshots
                        .try_lock()
                        .ok()
                        .and_then(|values| values.get(&id).cloned())
                })
                .filter(|snapshot| snapshot.format == format))
        }
        async fn advisory_rows(
            &self,
            kind: &str,
            cutoff: Option<i64>,
            after: i64,
            limit: usize,
        ) -> Result<Vec<AdvisoryRow>> {
            let mut rows: Vec<_> = self
                .rows
                .lock()
                .await
                .iter()
                .filter(|((k, _), row)| {
                    k == kind
                        && row.sequence > after
                        && cutoff.is_none_or(|cutoff| row.sequence <= cutoff)
                })
                .map(|(_, row)| row.clone())
                .collect();
            rows.sort_by_key(|row| row.sequence);
            rows.truncate(limit);
            Ok(rows)
        }
        async fn advisory_rows_by_keys(
            &self,
            kind: &str,
            keys: &[String],
        ) -> Result<Vec<AdvisoryRow>> {
            assert!(keys.len() <= 16);
            if kind == "git-projections" {
                self.projection_prefetches.lock().await.push(keys.len());
            }
            let rows = self.rows.lock().await;
            Ok(keys
                .iter()
                .filter_map(|key| rows.get(&(kind.into(), key.clone())).cloned())
                .collect())
        }
        async fn advisory_row(&self, kind: &str, key: &str) -> Result<Option<AdvisoryRow>> {
            if kind == "commits" {
                let delay = self.commit_lookup_delay.lock().await.take();
                if let Some(delay) = delay {
                    tokio::time::sleep(delay).await;
                }
                if let Some(error) = self.commit_lookup_failure.lock().await.take() {
                    return Err(error);
                }
            }
            if kind == "git-projections" {
                *self.single_projection_reads.lock().await += 1;
            }
            Ok(self
                .rows
                .lock()
                .await
                .get(&(kind.into(), key.into()))
                .cloned())
        }
        async fn advisory_cutoff(&self) -> Result<i64> {
            Ok(self.rows.lock().await.len() as i64)
        }
        async fn advisory_ref_rows(
            &self,
            _name: &str,
            _cutoff: i64,
            _after: i64,
            _limit: usize,
        ) -> Result<Vec<AdvisoryRow>> {
            Ok(Vec::new())
        }
        async fn put_advisory_row(&self, kind: &str, key: &str, data: &Value) -> Result<()> {
            let mut rows = self.rows.lock().await;
            let sequence = rows.len() as i64 + 1;
            rows.entry((kind.into(), key.into()))
                .or_insert_with(|| AdvisoryRow {
                    sequence,
                    key: key.into(),
                    data: data.clone(),
                });
            Ok(())
        }
        async fn advisory_state(&self, key: &str) -> Result<Option<Value>> {
            Ok(self.states.lock().await.get(key).cloned())
        }
        async fn set_advisory_state(&self, key: &str, data: &Value) -> Result<()> {
            self.states.lock().await.insert(key.into(), data.clone());
            Ok(())
        }
        async fn advisory_status(&self) -> Result<Value> {
            Ok(json!({}))
        }
    }
    fn config() -> RustSecConfig {
        RustSecConfig {
            min_free_bytes: 64 * 1024 * 1024,
            max_git_bytes: 64 * 1024 * 1024,
            ..Default::default()
        }
    }
    async fn input(history: &AdvisoryHistory, args: &[&str], bytes: &[u8]) -> Vec<u8> {
        let mut command = history.command();
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
        stdin.write_all(bytes).await.unwrap();
        drop(stdin);
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
    async fn commit(
        history: &AdvisoryHistory,
        path: Option<&str>,
        body: &[u8],
        parents: &[&str],
    ) -> String {
        let mut tree = if let Some(path) = path {
            let blob = oid(input(history, &["hash-object", "-w", "--stdin"], body).await);
            let mut components: Vec<_> = path.split('/').collect();
            let leaf = components.pop().unwrap();
            let mut tree = oid(input(
                history,
                &["mktree"],
                format!("100644 blob {blob}\t{leaf}\n").as_bytes(),
            )
            .await);
            while let Some(component) = components.pop() {
                tree = oid(input(
                    history,
                    &["mktree"],
                    format!("040000 tree {tree}\t{component}\n").as_bytes(),
                )
                .await);
            }
            tree
        } else {
            oid(input(history, &["mktree"], b"").await)
        };
        let mut args = vec!["commit-tree", &tree];
        for parent in parents {
            args.extend(["-p", parent]);
        }
        tree = oid(input(history, &args, b"Synthetic advisory graph fixture\n").await);
        tree
    }
    async fn update(history: &AdvisoryHistory, name: &str, oid: &str) {
        history
            .run(
                &["update-ref", name, oid],
                128,
                &CancellationToken::new(),
                Instant::now() + Duration::from_secs(10),
            )
            .await
            .unwrap();
    }
    async fn server(
        source: Arc<AdvisoryHistory>,
    ) -> (Arc<BulkBroker>, tokio::task::JoinHandle<()>) {
        let advertisement = source.clone();
        let upload = source.clone();
        let router = Router::new()
            .route(
                "/rustsec/advisory-db.git/info/refs",
                get(move || {
                    let source = advertisement.clone();
                    async move {
                        let path = source.repository();
                        let bytes = input(
                            &source,
                            &[
                                "upload-pack",
                                "--stateless-rpc",
                                "--advertise-refs",
                                path.to_str().unwrap(),
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
                "/rustsec/advisory-db.git/git-upload-pack",
                post(move |body: Bytes| {
                    let source = upload.clone();
                    async move {
                        let path = source.repository();
                        let bytes = input(
                            &source,
                            &["upload-pack", "--stateless-rpc", path.to_str().unwrap()],
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
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (
            Arc::new(
                BulkBroker::fixture(url::Url::parse(&format!("http://{address}")).unwrap())
                    .unwrap(),
            ),
            task,
        )
    }
    fn advisory() -> &'static [u8] {
        b"```toml\n[advisory]\nid = \"RUSTSEC-2024-0001\"\npackage = \"example\"\ndate = \"2024-01-01\"\n[versions]\npatched = [\">= 1.0.1\"]\n```\n\n# Synthetic Git history fixture\n\nPublic fixture only.\n"
    }
    async fn complete(history: &AdvisoryHistory, state: &mut HistoryState) {
        for _ in 0..100 {
            if state.complete {
                return;
            }
            history
                .process_batch(state, CancellationToken::new())
                .await
                .unwrap();
        }
        panic!("fixture history processing did not finish");
    }

    #[test]
    fn refs_and_graph_framing_reject_untrusted_names_and_truncation() {
        assert!(valid_ref("refs/heads/main"));
        assert!(valid_ref("refs/tags/release/v1"));
        for name in [
            "refs/pull/1/head",
            "refs/heads/../escape",
            "refs/heads/a.lock",
            "refs/heads/a\nsecret",
            "refs/heads/a@{b",
        ] {
            assert!(!valid_ref(name), "{name}");
        }
        assert!(
            parse_commit_line(format!("1 {} {}", "a".repeat(40), "b".repeat(40)).as_bytes())
                .is_ok()
        );
        assert!(parse_commit_line(b"1 bad").is_err());
        assert!(parse_tree(b"100644 blob bad\tfile\0").is_err());
        assert!(
            parse_tree(format!("100644 blob {}\t../file\0", "a".repeat(40)).as_bytes()).is_err()
        );
    }
    #[tokio::test]
    async fn full_transport_graph_projection_and_dropped_ref_restore() {
        let source_root = tempfile::tempdir().unwrap();
        let source = Arc::new(
            AdvisoryHistory::new(
                Arc::new(Memory::default()),
                Arc::new(BulkBroker::new(Default::default()).unwrap()),
                source_root.path(),
                config(),
            )
            .unwrap(),
        );
        source
            .initialize(
                &CancellationToken::new(),
                Instant::now() + Duration::from_secs(30),
            )
            .await
            .unwrap();
        let first = commit(
            &source,
            Some("crates/example/RUSTSEC-2024-0001.md"),
            advisory(),
            &[],
        )
        .await;
        let removed = commit(&source, None, b"", &[&first]).await;
        let side = commit(
            &source,
            Some("crates/example/RUSTSEC-2024-0001.md"),
            advisory(),
            &[&first],
        )
        .await;
        let merge = commit(
            &source,
            Some("crates/example/RUSTSEC-2024-0001.md"),
            advisory(),
            &[&removed, &side],
        )
        .await;
        let osv=commit(&source,Some("crates/RUSTSEC-2024-0001.json"),br#"{"id":"RUSTSEC-2024-0001","modified":"2024-01-01T00:00:00Z","published":"2024-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"crates.io","name":"example"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.1"}]}]}]}"#,&[]).await;
        let orphan = commit(
            &source,
            Some("crates/example/RUSTSEC-2024-0001.md"),
            b"invalid legacy format",
            &[],
        )
        .await;
        update(&source, "refs/heads/main", &merge).await;
        update(&source, "refs/heads/side", &orphan).await;
        update(&source, "refs/heads/osv", &osv).await;
        update(&source, "refs/tags/v1", &first).await;
        let blob = oid(input(
            &source,
            &["hash-object", "-w", "--stdin"],
            b"inert public blob tag",
        )
        .await);
        update(&source, "refs/tags/blob", &blob).await;
        let tag=oid(input(&source,&["mktag"],format!("object {first}\ntype commit\ntag annotated\ntagger Public Fixture <fixture@example.invalid> 1767225600 +0000\n\nSynthetic tag\n").as_bytes()).await);
        update(&source, "refs/tags/annotated", &tag).await;
        let (broker, task) = server(source.clone()).await;
        let target_root = tempfile::tempdir().unwrap();
        let memory = Arc::new(Memory::default());
        let target =
            AdvisoryHistory::new(memory.clone(), broker, target_root.path(), config()).unwrap();
        let mut state = target
            .synchronize(None, CancellationToken::new())
            .await
            .unwrap();
        let manifest = target
            .read_manifest(&state.manifest, CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(manifest.refs.len(), 6);
        assert_eq!(manifest.total_commits, 6);
        assert!(manifest.refs.iter().any(
            |reference| reference.name == "refs/tags/blob" && reference.peeled_commit.is_none()
        ));
        assert!(
            manifest
                .refs
                .iter()
                .any(|reference| reference.name == "refs/tags/annotated"
                    && reference.peeled_commit.as_deref() == Some(first.as_str()))
        );
        complete(&target, &mut state).await;
        let first_row = memory.advisory_commit(&first, None).await.unwrap().unwrap();
        let first_snapshot = memory
            .advisory_snapshot(first_row.data["snapshots"]["rustsec"].as_str(), "rustsec")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first_snapshot.records.len(), 1);
        assert!(first_snapshot.historical);
        assert!(!first_snapshot.assessment_complete(devres_domain::unix_now()));
        let removed_row = memory
            .advisory_commit(&removed, None)
            .await
            .unwrap()
            .unwrap();
        let removed_snapshot = memory
            .advisory_snapshot(removed_row.data["snapshots"]["rustsec"].as_str(), "rustsec")
            .await
            .unwrap()
            .unwrap();
        assert!(removed_snapshot.records.is_empty());
        let merge_row = memory.advisory_commit(&merge, None).await.unwrap().unwrap();
        assert_eq!(merge_row.data["parents"].as_array().unwrap().len(), 2);
        assert!(merge_row.data["parent_snapshots"][&first].is_null());
        assert!(merge_row.data["parent_snapshots"][&removed].is_object());
        let orphan_row = memory
            .advisory_commit(&orphan, None)
            .await
            .unwrap()
            .unwrap();
        let legacy = memory
            .advisory_snapshot(orphan_row.data["snapshots"]["rustsec"].as_str(), "rustsec")
            .await
            .unwrap()
            .unwrap();
        assert!(!legacy.complete);
        assert!(!legacy.coverage["gaps"].as_array().unwrap().is_empty());
        let osv_default = memory
            .advisory_snapshot(None, "osv")
            .await
            .unwrap()
            .unwrap();
        assert!(!osv_default.historical);
        assert!(osv_default.assessment_complete(devres_domain::unix_now()));
        assert!(
            memory
                .advisory_snapshot(None, "rustsec")
                .await
                .unwrap()
                .is_none()
        );
        source
            .run(
                &["update-ref", "-d", "refs/heads/side"],
                128,
                &CancellationToken::new(),
                Instant::now() + Duration::from_secs(10),
            )
            .await
            .unwrap();
        update(&source, "refs/heads/main", &removed).await;
        let mut second = target
            .synchronize(Some(&state), CancellationToken::new())
            .await
            .unwrap();
        complete(&target, &mut second).await;
        let newest = target
            .read_manifest(&second.manifest, CancellationToken::new())
            .await
            .unwrap();
        assert!(
            !newest
                .refs
                .iter()
                .any(|reference| reference.name == "refs/heads/side")
        );
        assert!(newest.roots.contains(&orphan));
        tokio::fs::remove_dir_all(target.repository())
            .await
            .unwrap();
        target
            .restore(&second.manifest, CancellationToken::new())
            .await
            .unwrap();
        target
            .run(
                &["cat-file", "-e", &orphan],
                128,
                &CancellationToken::new(),
                Instant::now() + Duration::from_secs(10),
            )
            .await
            .unwrap();
        assert!(
            memory
                .advisory_row("refs", &state.observation_id)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            memory
                .advisory_row("refs", &second.observation_id)
                .await
                .unwrap()
                .is_some()
        );
        task.abort();
    }
    #[tokio::test]
    async fn member_checkpoint_survives_restart_and_reuses_immutable_partial() {
        let root = tempfile::tempdir().unwrap();
        let memory = Arc::new(Memory::default());
        let broker = Arc::new(BulkBroker::new(Default::default()).unwrap());
        let history =
            AdvisoryHistory::new(memory.clone(), broker.clone(), root.path(), config()).unwrap();
        history
            .initialize(
                &CancellationToken::new(),
                Instant::now() + Duration::from_secs(10),
            )
            .await
            .unwrap();
        let mut listing = String::new();
        for number in 1..=4 {
            let id = format!("RUSTSEC-2024-{number:04}");
            let body = std::str::from_utf8(advisory())
                .unwrap()
                .replace("RUSTSEC-2024-0001", &id);
            let blob =
                oid(input(&history, &["hash-object", "-w", "--stdin"], body.as_bytes()).await);
            listing.push_str(&format!("100644 blob {blob}\t{id}.md\n"));
        }
        let package = oid(input(&history, &["mktree"], listing.as_bytes()).await);
        let crates = oid(input(
            &history,
            &["mktree"],
            format!("040000 tree {package}\texample\n").as_bytes(),
        )
        .await);
        let tree = oid(input(
            &history,
            &["mktree"],
            format!("040000 tree {crates}\tcrates\n").as_bytes(),
        )
        .await);
        let revision = oid(input(
            &history,
            &["commit-tree", &tree],
            b"Synthetic multi-member checkpoint\n",
        )
        .await);
        let commit = Commit {
            oid: revision.clone(),
            parents: Vec::new(),
            timestamp: 1767225600,
        };
        let shutdown = CancellationToken::new();
        let observation = "a".repeat(64);
        assert!(
            !history
                .process_commit(
                    &commit,
                    &observation,
                    &shutdown,
                    Instant::now() + Duration::from_secs(15),
                    2
                )
                .await
                .unwrap()
        );
        let checkpoint = memory
            .advisory_state("history-commit")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(checkpoint["index"], 2);
        let partial = checkpoint["partial"].as_str().unwrap().to_owned();
        memory
            .snapshots
            .lock()
            .await
            .get_mut(&partial)
            .unwrap()
            .created_at = 0;
        // Simulate a crash after immutable publication but before saving its checkpoint.
        memory
            .set_advisory_state("history-commit", &json!({}))
            .await
            .unwrap();
        let restored = AdvisoryHistory::new(memory.clone(), broker, root.path(), config()).unwrap();
        assert!(
            !restored
                .process_commit(
                    &commit,
                    &observation,
                    &shutdown,
                    Instant::now() + Duration::from_secs(15),
                    2
                )
                .await
                .unwrap()
        );
        let second = memory
            .advisory_state("history-commit")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(second["partial"], partial);
        assert_eq!(
            memory
                .advisory_snapshot(Some(&partial), "rustsec")
                .await
                .unwrap()
                .unwrap()
                .created_at,
            0
        );
        assert!(
            restored
                .process_commit(
                    &commit,
                    &observation,
                    &shutdown,
                    Instant::now() + Duration::from_secs(15),
                    2
                )
                .await
                .unwrap()
        );
        let row = memory
            .advisory_commit(&revision, None)
            .await
            .unwrap()
            .unwrap();
        let snapshot = memory
            .advisory_snapshot(row.data["snapshots"]["rustsec"].as_str(), "rustsec")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(snapshot.records.len(), 4);
        assert!(snapshot.complete);
        assert!(snapshot.historical);
        assert_eq!(
            memory
                .advisory_rows("git-projections", None, 0, 100)
                .await
                .unwrap()
                .len(),
            4
        );
        let batches = memory.projection_prefetches.lock().await;
        assert!(!batches.is_empty());
        assert!(batches.iter().all(|size| *size <= 16));
        assert_eq!(
            *memory.single_projection_reads.lock().await,
            0,
            "prefetched misses must not trigger a redundant individual SELECT"
        );
    }
    #[tokio::test]
    async fn terminal_transport_failure_has_persisted_backoff() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let attempts = Arc::new(AtomicUsize::new(0));
        let counted = attempts.clone();
        let router = Router::new().route(
            "/rustsec/advisory-db.git/info/refs",
            get(move || {
                let counted = counted.clone();
                async move {
                    counted.fetch_add(1, Ordering::SeqCst);
                    (
                        axum::http::StatusCode::SERVICE_UNAVAILABLE,
                        [(axum::http::header::RETRY_AFTER, "0")],
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
        let root = tempfile::tempdir().unwrap();
        let memory = Arc::new(Memory::default());
        let history = AdvisoryHistory::new(memory.clone(), broker, root.path(), config()).unwrap();
        assert!(
            tokio::time::timeout(
                Duration::from_secs(10),
                history.tick(CancellationToken::new())
            )
            .await
            .unwrap()
            .is_err()
        );
        let observed = attempts.load(Ordering::SeqCst);
        assert!((1..=2).contains(&observed));
        let retry = memory
            .advisory_state("history-retry")
            .await
            .unwrap()
            .unwrap();
        assert!(retry["next_attempt"].as_i64().unwrap() > devres_domain::unix_now());
        history.tick(CancellationToken::new()).await.unwrap();
        assert_eq!(attempts.load(Ordering::SeqCst), observed);
        assert!(
            memory
                .advisory_rows("refs", None, 0, 100)
                .await
                .unwrap()
                .is_empty()
        );
        server.abort();
    }
    #[tokio::test]
    async fn canceled_pack_stages_are_recovered_without_removing_retained_files() {
        let root = tempfile::tempdir().unwrap();
        let history = AdvisoryHistory::new(
            Arc::new(Memory::default()),
            Arc::new(BulkBroker::new(Default::default()).unwrap()),
            root.path(),
            config(),
        )
        .unwrap();
        let shutdown = CancellationToken::new();
        history
            .initialize(&shutdown, Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        let packs = history.repository().join("objects/pack");
        for name in ["tmp_pack_Ab1234", "tmp_idx_Zz9988"] {
            tokio::fs::write(packs.join(name), b"disposable canceled transfer")
                .await
                .unwrap();
        }
        let retained = packs.join(format!("pack-{}.pack", "a".repeat(40)));
        tokio::fs::write(&retained, b"retained evidence fixture")
            .await
            .unwrap();
        history
            .initialize(&shutdown, Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        assert!(!packs.join("tmp_pack_Ab1234").exists());
        assert!(!packs.join("tmp_idx_Zz9988").exists());
        assert_eq!(
            tokio::fs::read(&retained).await.unwrap(),
            b"retained evidence fixture"
        );
    }
    #[tokio::test]
    async fn canceled_live_transport_reaps_git_without_publishing_an_observation() {
        let entered = Arc::new(tokio::sync::Notify::new());
        let observed = entered.clone();
        let release = CancellationToken::new();
        let held = release.clone();
        let router = Router::new().route(
            "/rustsec/advisory-db.git/info/refs",
            get(move || {
                let observed = observed.clone();
                let held = held.clone();
                async move {
                    observed.notify_one();
                    held.cancelled().await;
                    axum::http::StatusCode::SERVICE_UNAVAILABLE
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
        let root = tempfile::tempdir().unwrap();
        let memory = Arc::new(Memory::default());
        let history =
            Arc::new(AdvisoryHistory::new(memory.clone(), broker, root.path(), config()).unwrap());
        let shutdown = CancellationToken::new();
        let worker_shutdown = shutdown.clone();
        let worker = history.clone();
        let mut task = tokio::spawn(async move { worker.tick(worker_shutdown).await });
        // Process startup is fixture synchronization, outside the cancellation deadline.
        if tokio::time::timeout(Duration::from_secs(30), entered.notified())
            .await
            .is_err()
        {
            shutdown.cancel();
            release.cancel();
            task.abort();
            let _ = task.await;
            server.abort();
            panic!("fixture Git process did not reach the held source request");
        }
        shutdown.cancel();
        let canceled = tokio::time::timeout(Duration::from_secs(5), &mut task).await;
        release.cancel();
        if canceled.is_err() {
            task.abort();
            let _ = task.await;
            server.abort();
            panic!("Git cancellation exceeded its unchanged five-second deadline");
        }
        assert!(canceled.unwrap().unwrap().is_err());
        assert!(
            memory
                .advisory_rows("refs", None, 0, 100)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            memory
                .advisory_state("history-latest")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            memory
                .advisory_state("history-retry")
                .await
                .unwrap()
                .is_none()
        );
        history
            .initialize(
                &CancellationToken::new(),
                Instant::now() + Duration::from_secs(5),
            )
            .await
            .unwrap();
        server.abort();
    }
    #[tokio::test]
    async fn duplicate_historical_id_is_a_gap_instead_of_a_permanent_import_failure() {
        let root = tempfile::tempdir().unwrap();
        let memory = Arc::new(Memory::default());
        let history = AdvisoryHistory::new(
            memory.clone(),
            Arc::new(BulkBroker::new(Default::default()).unwrap()),
            root.path(),
            config(),
        )
        .unwrap();
        let shutdown = CancellationToken::new();
        history
            .initialize(&shutdown, Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        let valid = oid(input(&history, &["hash-object", "-w", "--stdin"], advisory()).await);
        let invalid = oid(input(
            &history,
            &["hash-object", "-w", "--stdin"],
            b"Unsupported historical TOML",
        )
        .await);
        let package=oid(input(&history,&["mktree"],format!("100644 blob {valid}\tRUSTSEC-2024-0001.md\n100644 blob {invalid}\tRUSTSEC-2024-0001.toml\n").as_bytes()).await);
        let crates = oid(input(
            &history,
            &["mktree"],
            format!("040000 tree {package}\texample\n").as_bytes(),
        )
        .await);
        let tree = oid(input(
            &history,
            &["mktree"],
            format!("040000 tree {crates}\tcrates\n").as_bytes(),
        )
        .await);
        let revision = oid(input(
            &history,
            &["commit-tree", &tree],
            b"Synthetic duplicate historical identity\n",
        )
        .await);
        let commit = Commit {
            oid: revision.clone(),
            parents: Vec::new(),
            timestamp: 1767225600,
        };
        assert!(
            history
                .process_commit(
                    &commit,
                    &"a".repeat(64),
                    &shutdown,
                    Instant::now() + Duration::from_secs(15),
                    1000
                )
                .await
                .unwrap()
        );
        let row = memory
            .advisory_commit(&revision, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.data["projection_complete"], false);
        let snapshot = memory
            .advisory_snapshot(row.data["snapshots"]["rustsec"].as_str(), "rustsec")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(snapshot.records.len(), 1);
        assert!(!snapshot.complete);
        assert!(
            snapshot.coverage["gaps"]
                .as_array()
                .unwrap()
                .iter()
                .any(|gap| gap["code"] == "duplicate_identity")
        );
    }
    #[tokio::test]
    #[ignore = "requires explicit DEVRES_RUSTSEC_GIT_LIVE=1; at most five official source attempts"]
    async fn official_git_transport_acceptance() {
        assert_eq!(
            std::env::var("DEVRES_RUSTSEC_GIT_LIVE").as_deref(),
            Ok("1"),
            "Explicit live opt-in required"
        );
        let broker = Arc::new(
            BulkBroker::new(Default::default())
                .unwrap()
                .with_attempt_budget(5)
                .unwrap(),
        );
        let root = tempfile::tempdir().unwrap();
        let history = AdvisoryHistory::new(
            Arc::new(Memory::default()),
            broker.clone(),
            root.path(),
            config(),
        )
        .unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(120),
            history.synchronize(None, CancellationToken::new()),
        )
        .await;
        match result {
            Ok(Ok(state)) => eprintln!(
                "RustSec Git transport accepted: {} commits, {} admitted source attempts",
                state.total,
                broker.attempt_count()
            ),
            Ok(Err(error)) => panic!(
                "RustSec Git transport failed after {} admitted source attempts: {}",
                broker.attempt_count(),
                error
            ),
            Err(_) => panic!(
                "RustSec Git transport deadline after {} admitted source attempts",
                broker.attempt_count()
            ),
        }
    }
    #[tokio::test]
    async fn many_ref_fetch_preserves_gzipped_private_git_request_framing() {
        let before = crate_git::compressed_upload_count();
        let source_root = tempfile::tempdir().unwrap();
        let source = Arc::new(
            AdvisoryHistory::new(
                Arc::new(Memory::default()),
                Arc::new(BulkBroker::new(Default::default()).unwrap()),
                source_root.path(),
                config(),
            )
            .unwrap(),
        );
        source
            .initialize(
                &CancellationToken::new(),
                Instant::now() + Duration::from_secs(10),
            )
            .await
            .unwrap();
        let mut parent = None;
        for number in 0..32 {
            let parents = parent
                .as_deref()
                .map(|parent| vec![parent])
                .unwrap_or_default();
            let revision = commit(&source, None, b"", &parents).await;
            update(&source, &format!("refs/heads/branch-{number}"), &revision).await;
            parent = Some(revision);
        }
        let (broker, task) = server(source).await;
        let target_root = tempfile::tempdir().unwrap();
        let target = AdvisoryHistory::new(
            Arc::new(Memory::default()),
            broker,
            target_root.path(),
            config(),
        )
        .unwrap();
        let state = target
            .synchronize(None, CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(state.total, 32);
        assert!(
            crate_git::compressed_upload_count() > before,
            "real Git fixture did not exercise gzip POST framing"
        );
        task.abort();
    }
    #[tokio::test]
    async fn cache_identity_preserves_regular_and_symlink_mode_transitions() {
        for modes in [["100644", "120000"], ["120000", "100644"]] {
            let root = tempfile::tempdir().unwrap();
            let memory = Arc::new(Memory::default());
            let history = AdvisoryHistory::new(
                memory.clone(),
                Arc::new(BulkBroker::new(Default::default()).unwrap()),
                root.path(),
                config(),
            )
            .unwrap();
            let shutdown = CancellationToken::new();
            history
                .initialize(&shutdown, Instant::now() + Duration::from_secs(10))
                .await
                .unwrap();
            let blob = oid(input(&history, &["hash-object", "-w", "--stdin"], advisory()).await);
            for mode in modes {
                let package = oid(input(
                    &history,
                    &["mktree"],
                    format!("{mode} blob {blob}\tRUSTSEC-2024-0001.md\n").as_bytes(),
                )
                .await);
                let crates = oid(input(
                    &history,
                    &["mktree"],
                    format!("040000 tree {package}\texample\n").as_bytes(),
                )
                .await);
                let tree = oid(input(
                    &history,
                    &["mktree"],
                    format!("040000 tree {crates}\tcrates\n").as_bytes(),
                )
                .await);
                let revision = oid(input(
                    &history,
                    &["commit-tree", &tree],
                    b"Synthetic regular/symlink transition\n",
                )
                .await);
                let commit = Commit {
                    oid: revision.clone(),
                    parents: Vec::new(),
                    timestamp: 1767225600,
                };
                assert!(
                    history
                        .process_commit(
                            &commit,
                            &"a".repeat(64),
                            &shutdown,
                            Instant::now() + Duration::from_secs(15),
                            1000
                        )
                        .await
                        .unwrap()
                );
                let row = memory
                    .advisory_commit(&revision, None)
                    .await
                    .unwrap()
                    .unwrap();
                let snapshot = memory
                    .advisory_snapshot(row.data["snapshots"]["rustsec"].as_str(), "rustsec")
                    .await
                    .unwrap()
                    .unwrap();
                if mode == "100644" {
                    assert!(snapshot.complete);
                    assert_eq!(snapshot.records.len(), 1);
                    assert_eq!(
                        snapshot.records[0].body,
                        std::str::from_utf8(advisory()).unwrap()
                    );
                } else {
                    assert!(!snapshot.complete);
                    assert!(
                        snapshot
                            .records
                            .iter()
                            .all(|record| record.metadata["processing"] == "unsupported")
                    );
                }
            }
            assert_eq!(
                memory
                    .advisory_rows("git-projections", None, 0, 100)
                    .await
                    .unwrap()
                    .len(),
                2
            );
        }
    }
    #[tokio::test]
    async fn batch_deadline_yields_last_checkpoint_and_resumes_without_hiding_capacity() {
        let root = tempfile::tempdir().unwrap();
        let memory = Arc::new(Memory::default());
        let history = AdvisoryHistory::new(
            memory.clone(),
            Arc::new(BulkBroker::new(Default::default()).unwrap()),
            root.path(),
            config(),
        )
        .unwrap();
        let shutdown = CancellationToken::new();
        history
            .initialize(&shutdown, Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        let first = commit(
            &history,
            Some("crates/example/RUSTSEC-2024-0001.md"),
            advisory(),
            &[],
        )
        .await;
        let second = commit(&history, None, b"", &[&first]).await;
        update(&history, "refs/heads/main", &second).await;
        history
            .run(
                &["repack", "-a", "-d", "--no-write-bitmap-index"],
                4096,
                &shutdown,
                Instant::now() + Duration::from_secs(10),
            )
            .await
            .unwrap();
        let (commits, total_commits) = history
            .capture_commit_order(&shutdown, Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        let packs = history.capture_packs(shutdown.clone()).await.unwrap();
        let manifest = Manifest {
            version: 1,
            source_url: SOURCE.into(),
            observed_at: devres_domain::unix_now(),
            refs: vec![RefEvidence {
                name: "refs/heads/main".into(),
                oid: second.clone(),
                object_type: "commit".into(),
                peeled_commit: Some(second.clone()),
                snapshots: BTreeMap::new(),
            }],
            roots: vec![second],
            packs,
            commits,
            total_commits,
        };
        let artifact = history
            .artifacts
            .capture_bytes(encoded(&manifest).unwrap(), shutdown.clone())
            .await
            .unwrap();
        let observation = artifact.body_hash.clone();
        memory
            .put_advisory_row(
                "refs",
                &observation,
                &json!({"id":observation,"refs":manifest.refs,"manifest":artifact}),
            )
            .await
            .unwrap();
        let mut state = HistoryState {
            manifest: artifact,
            observation_id: observation.clone(),
            observed_at: manifest.observed_at,
            offset: 0,
            processed: 0,
            total: total_commits,
            complete: false,
            projection_complete: true,
            processor_version: ADVISORY_PROCESSOR_VERSION,
        };
        let file = history
            .artifacts
            .open(
                &manifest.commits.body_hash,
                128 * 1024 * 1024,
                shutdown.clone(),
            )
            .await
            .unwrap();
        let mut reader = BufReader::new(file);
        let line = delimited(
            &mut reader,
            b'\n',
            64 * 1024,
            &shutdown,
            Instant::now() + Duration::from_secs(10),
        )
        .await
        .unwrap()
        .unwrap();
        let first_commit = parse_commit_line(&line).unwrap();
        assert!(
            history
                .process_commit(
                    &first_commit,
                    &observation,
                    &shutdown,
                    Instant::now() + Duration::from_secs(10),
                    MAX_PROJECTED_RECORDS
                )
                .await
                .unwrap()
        );
        state.offset = line.len() as u64 + 1;
        state.processed = 1;
        let previous_offset = state.offset;
        *memory.commit_lookup_failure.lock().await = Some(Error::capacity(
            "Fixture quota exhausted before batch deadline.",
        ));
        let failure = history
            .process_batch_until(
                &mut state,
                shutdown.clone(),
                Instant::now() + Duration::from_secs(10),
            )
            .await
            .unwrap_err();
        assert_eq!(failure.code, "capacity");
        assert!(failure.message.contains("quota"));
        assert_eq!(state.processed, 1);
        assert_eq!(state.offset, previous_offset);
        *memory.commit_lookup_delay.lock().await = Some(Duration::from_millis(300));
        history
            .process_batch_until(
                &mut state,
                shutdown.clone(),
                Instant::now() + Duration::from_millis(200),
            )
            .await
            .unwrap();
        assert!(
            memory.commit_lookup_delay.lock().await.is_none(),
            "forced deadline must race inside commit processing"
        );
        assert_eq!(state.processed, 1);
        assert_eq!(state.offset, previous_offset);
        assert!(!state.complete);
        let retained = memory.advisory_state("history").await.unwrap().unwrap();
        assert_eq!(retained["processed"], 1);
        assert_eq!(retained["offset"], previous_offset);
        history.process_batch(&mut state, shutdown).await.unwrap();
        assert!(state.complete);
        assert_eq!(state.processed, 2);
        assert!(state.offset > previous_offset);
        assert!(
            memory
                .advisory_state("history-retry")
                .await
                .unwrap()
                .is_none(),
            "normal batch yield must not schedule provider failure backoff"
        );
    }
    #[tokio::test]
    async fn generation_replay_preserves_raw_cutoffs_and_original_validation_without_fetch() {
        let root = tempfile::tempdir().unwrap();
        let memory = Arc::new(Memory::default());
        let broker = Arc::new(
            BulkBroker::fixture(url::Url::parse("http://127.0.0.1:9").unwrap())
                .unwrap()
                .with_attempt_budget(1)
                .unwrap(),
        );
        let history =
            AdvisoryHistory::new(memory.clone(), broker.clone(), root.path(), config()).unwrap();
        let shutdown = CancellationToken::new();
        history
            .initialize(&shutdown, Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        let path = "crates/RUSTSEC-2024-0001.json";
        let body=br#"{"id":"RUSTSEC-2024-0001","modified":"2024-01-01T00:00:00Z","published":"2024-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"crates.io","name":"example"},"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"1.0.0"}]}]}]}"#;
        let revision = commit(&history, Some(path), body, &[]).await;
        update(&history, "refs/heads/osv", &revision).await;
        history
            .run(
                &["repack", "-a", "-d", "--no-write-bitmap-index"],
                4096,
                &shutdown,
                Instant::now() + Duration::from_secs(10),
            )
            .await
            .unwrap();
        let (commits, total_commits) = history
            .capture_commit_order(&shutdown, Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        let packs = history.capture_packs(shutdown.clone()).await.unwrap();
        let observed_at = devres_domain::unix_now() - 3600;
        let manifest = Manifest {
            version: 1,
            source_url: SOURCE.into(),
            observed_at,
            refs: vec![RefEvidence {
                name: "refs/heads/osv".into(),
                oid: revision.clone(),
                object_type: "commit".into(),
                peeled_commit: Some(revision.clone()),
                snapshots: BTreeMap::new(),
            }],
            roots: vec![revision.clone()],
            packs,
            commits,
            total_commits,
        };
        let artifact = history
            .artifacts
            .capture_bytes(encoded(&manifest).unwrap(), shutdown.clone())
            .await
            .unwrap();
        let observation = artifact.body_hash.clone();
        memory.put_advisory_row("refs",&observation,&json!({"id":observation,"observed_at":observed_at,"refs":manifest.refs,"manifest":artifact})).await.unwrap();
        let tree = history
            .run(
                &["ls-tree", "-r", "-z", &revision],
                4096,
                &shutdown,
                Instant::now() + Duration::from_secs(10),
            )
            .await
            .unwrap();
        let members = parse_tree(&tree).unwrap();
        let member = &members[0];
        let (mut old_records, mut old_coverage) =
            crate::advisory_corpus::normalize_records(vec![(path.into(), body.to_vec())], "osv")
                .unwrap();
        assert_eq!(
            old_coverage["complete"], true,
            "empty OSV interval is supported by generation two"
        );
        old_records[0].metadata["matching_complete"] = json!(false);
        old_coverage["complete"] = json!(false);
        old_coverage["matching_complete"] = json!(false);
        old_coverage["processor_version"] = json!(1);
        let old_cache = json!({"records":old_records,"coverage":old_coverage});
        let old_key = projection_key_version(member, "osv", 1).unwrap();
        memory
            .put_advisory_row("git-projections", &old_key, &old_cache)
            .await
            .unwrap();
        let old_id = "a".repeat(64);
        let old_snapshot = AdvisorySnapshot {
            id: old_id.clone(),
            revision: revision.clone(),
            format: "osv".into(),
            created_at: observed_at,
            validated_at: None,
            historical: true,
            complete: false,
            records: serde_json::from_value(old_cache["records"].clone()).unwrap(),
            captures: Vec::new(),
            coverage: old_cache["coverage"].clone(),
            parents: Vec::new(),
            committed_at: 1767225600,
        };
        memory
            .publish_advisory_snapshot(&old_snapshot, false)
            .await
            .unwrap();
        let raw = json!({"revision":revision,"parents":[],"committed_at":1767225600,"snapshots":{"osv":old_id},"parent_snapshots":{},"projection_complete":false,"first_observation":observation});
        memory
            .put_advisory_row("commits", &revision, &raw)
            .await
            .unwrap();
        memory.put_advisory_row("processing",&format!("{revision}:1"),&json!({"revision":revision,"processor_version":1,"snapshots":{"osv":old_id},"parent_snapshots":{},"projection_complete":false})).await.unwrap();
        let cutoff = memory.advisory_cutoff().await.unwrap();
        let raw_sequence = memory
            .advisory_row("commits", &revision)
            .await
            .unwrap()
            .unwrap()
            .sequence;
        let legacy_state = HistoryState {
            manifest: artifact,
            observation_id: observation.clone(),
            observed_at,
            offset: manifest.commits.bytes,
            processed: 1,
            total: 1,
            complete: true,
            projection_complete: false,
            processor_version: 1,
        };
        let mut legacy_value = serde_json::to_value(&legacy_state).unwrap();
        legacy_value
            .as_object_mut()
            .unwrap()
            .remove("processor_version");
        assert_eq!(
            serde_json::from_value::<HistoryState>(legacy_value.clone())
                .unwrap()
                .processor_version,
            1
        );
        memory
            .set_advisory_state("history", &legacy_value)
            .await
            .unwrap();
        memory
            .set_advisory_state("history-latest", &legacy_value)
            .await
            .unwrap();
        memory.set_advisory_state("history-commit",&json!({"revision":revision,"format":"osv","index":1,"partial":old_id,"snapshots":{},"processor_version":1})).await.unwrap();
        memory
            .set_advisory_state(
                "history-retry",
                &json!({"next_attempt":devres_domain::unix_now()+300,"code":"capacity"}),
            )
            .await
            .unwrap();
        history.tick(shutdown.clone()).await.unwrap();
        let current = memory.advisory_state("history").await.unwrap().unwrap();
        assert_eq!(current["processor_version"], ADVISORY_PROCESSOR_VERSION);
        assert_eq!(current["processed"], 1);
        assert_eq!(current["complete"], true);
        assert_eq!(current["observed_at"], observed_at);
        assert_eq!(broker.attempt_count(), 0);
        let frozen = memory
            .advisory_commit(&revision, Some(cutoff))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(frozen.sequence, raw_sequence);
        assert_eq!(frozen.data["snapshots"]["osv"], old_id);
        assert_eq!(frozen.data["processor_version"], 1);
        let latest = memory
            .advisory_commit(&revision, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(latest.sequence, raw_sequence);
        assert_eq!(latest.data["processor_version"], ADVISORY_PROCESSOR_VERSION);
        assert_ne!(latest.data["snapshots"]["osv"], old_id);
        let projected = memory
            .advisory_snapshot(latest.data["snapshots"]["osv"].as_str(), "osv")
            .await
            .unwrap()
            .unwrap();
        assert!(projected.complete);
        assert_eq!(projected.records[0].metadata["matching_complete"], true);
        assert_eq!(
            projected.coverage["processor_version"],
            ADVISORY_PROCESSOR_VERSION
        );
        let raw_after = memory
            .advisory_row("commits", &revision)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(raw_after.sequence, raw_sequence);
        assert_eq!(raw_after.data, raw);
        assert_eq!(
            serde_json::to_value(
                memory
                    .advisory_snapshot(Some(&old_id), "osv")
                    .await
                    .unwrap()
                    .unwrap()
            )
            .unwrap(),
            serde_json::to_value(old_snapshot).unwrap()
        );
        assert_eq!(
            memory
                .advisory_row("git-projections", &old_key)
                .await
                .unwrap()
                .unwrap()
                .data,
            old_cache
        );
        let promoted = memory
            .advisory_snapshot(None, "osv")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(promoted.validated_at, Some(observed_at));
        assert!(!promoted.historical);
        assert!(
            memory
                .advisory_row(
                    "refs",
                    &format!("{observation}:processed:{ADVISORY_PROCESSOR_VERSION}")
                )
                .await
                .unwrap()
                .is_some()
        );
        let restarted =
            AdvisoryHistory::new(memory.clone(), broker.clone(), root.path(), config()).unwrap();
        restarted.tick(shutdown).await.unwrap();
        assert_eq!(broker.attempt_count(), 0);
        assert_eq!(
            memory.advisory_state("history").await.unwrap().unwrap(),
            current
        );
    }
    #[tokio::test]
    async fn complete_mode_sensitive_v1_cache_is_reused_with_v2_coverage() {
        let root = tempfile::tempdir().unwrap();
        let memory = Arc::new(Memory::default());
        let history = AdvisoryHistory::new(
            memory.clone(),
            Arc::new(BulkBroker::new(Default::default()).unwrap()),
            root.path(),
            config(),
        )
        .unwrap();
        let shutdown = CancellationToken::new();
        history
            .initialize(&shutdown, Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        let path = "crates/example/RUSTSEC-2024-0001.md";
        let revision = commit(&history, Some(path), advisory(), &[]).await;
        let tree = history
            .run(
                &["ls-tree", "-r", "-z", &revision],
                4096,
                &shutdown,
                Instant::now() + Duration::from_secs(10),
            )
            .await
            .unwrap();
        let members = parse_tree(&tree).unwrap();
        let member = &members[0];
        let (mut records, mut coverage) = crate::advisory_corpus::normalize_records(
            vec![(path.into(), advisory().to_vec())],
            "rustsec",
        )
        .unwrap();
        assert_eq!(coverage["complete"], true);
        records[0].metadata["fixture_legacy_projection"] = json!(true);
        coverage["processor_version"] = json!(1);
        let legacy = json!({"records":records,"coverage":coverage});
        let old_key = projection_key_version(member, "rustsec", 1).unwrap();
        memory
            .put_advisory_row("git-projections", &old_key, &legacy)
            .await
            .unwrap();
        let commit = Commit {
            oid: revision.clone(),
            parents: Vec::new(),
            timestamp: 1767225600,
        };
        assert!(
            history
                .process_commit(
                    &commit,
                    &"b".repeat(64),
                    &shutdown,
                    Instant::now() + Duration::from_secs(10),
                    MAX_PROJECTED_RECORDS
                )
                .await
                .unwrap()
        );
        let current_key = projection_key(member, "rustsec").unwrap();
        assert_ne!(old_key, current_key);
        let reused = memory
            .advisory_row("git-projections", &current_key)
            .await
            .unwrap()
            .unwrap()
            .data;
        assert_eq!(
            reused["coverage"]["processor_version"],
            ADVISORY_PROCESSOR_VERSION
        );
        assert_eq!(reused["coverage"]["reused_processor_version"], 1);
        assert_eq!(reused["records"], legacy["records"]);
        assert_eq!(
            memory
                .advisory_row("git-projections", &old_key)
                .await
                .unwrap()
                .unwrap()
                .data,
            legacy
        );
        let row = memory
            .advisory_commit(&revision, None)
            .await
            .unwrap()
            .unwrap();
        let snapshot = memory
            .advisory_snapshot(row.data["snapshots"]["rustsec"].as_str(), "rustsec")
            .await
            .unwrap()
            .unwrap();
        assert!(snapshot.complete);
        assert_eq!(
            snapshot.coverage["processor_version"],
            ADVISORY_PROCESSOR_VERSION
        );
        assert_eq!(
            snapshot.records[0].metadata["fixture_legacy_projection"],
            true
        );
        assert!(
            memory
                .advisory_row("commits", &revision)
                .await
                .unwrap()
                .unwrap()
                .data["snapshots"]
                .is_null(),
            "new graph evidence must not embed mutable projections"
        );
    }
    #[tokio::test]
    async fn unchanged_v1_snapshots_reuse_without_git_tree_or_new_snapshot_identity() {
        let root = tempfile::tempdir().unwrap();
        let memory = Arc::new(Memory::default());
        let broker = Arc::new(
            BulkBroker::fixture(url::Url::parse("http://127.0.0.1:9").unwrap())
                .unwrap()
                .with_attempt_budget(1)
                .unwrap(),
        );
        let history =
            AdvisoryHistory::new(memory.clone(), broker.clone(), root.path(), config()).unwrap();
        let revision = "c".repeat(40);
        let canonical = "a".repeat(64);
        let osv = "b".repeat(64);
        for (format, id, complete) in [("rustsec", &canonical, false), ("osv", &osv, true)] {
            memory.publish_advisory_snapshot(&AdvisorySnapshot{id:id.clone(),revision:revision.clone(),format:format.into(),created_at:1,validated_at:None,historical:true,complete,records:Vec::new(),captures:Vec::new(),coverage:json!({"complete":complete,"processor_version":1,"fixture":"synthetic unchanged generation-one projection"}),parents:Vec::new(),committed_at:1},false).await.unwrap();
        }
        let raw = json!({"revision":revision,"parents":[],"committed_at":1,"snapshots":{"rustsec":canonical,"osv":osv},"parent_snapshots":{},"projection_complete":false});
        memory
            .put_advisory_row("commits", &revision, &raw)
            .await
            .unwrap();
        let cutoff = memory.advisory_cutoff().await.unwrap();
        assert!(
            !history.repository().exists(),
            "reuse fixture must not have a Git repository to read"
        );
        assert!(
            history
                .process_commit(
                    &Commit {
                        oid: revision.clone(),
                        parents: Vec::new(),
                        timestamp: 1
                    },
                    &"d".repeat(64),
                    &CancellationToken::new(),
                    Instant::now() + Duration::from_secs(10),
                    MAX_PROJECTED_RECORDS
                )
                .await
                .unwrap()
        );
        let latest = memory
            .advisory_commit(&revision, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(latest.data["processor_version"], ADVISORY_PROCESSOR_VERSION);
        assert_eq!(latest.data["snapshots"], raw["snapshots"]);
        assert_eq!(latest.data["projection_complete"], false);
        assert_eq!(
            memory.snapshots.lock().await.len(),
            2,
            "reuse must not mint duplicate snapshots"
        );
        assert_eq!(
            memory
                .advisory_commit(&revision, Some(cutoff))
                .await
                .unwrap()
                .unwrap()
                .data,
            raw
        );
        assert_eq!(
            memory
                .advisory_row("commits", &revision)
                .await
                .unwrap()
                .unwrap()
                .data,
            raw
        );
        assert_eq!(broker.attempt_count(), 0);
    }
}
