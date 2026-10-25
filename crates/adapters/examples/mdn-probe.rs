//! Explicit retained MDN acceptance. Credentials enter only through the environment.
use devres_adapters::{
    MdnCorpus, PgBlobStore,
    bulk::{BulkBroker, BulkConfig},
    mdn_git::{CommitOrder, MdnGit, Observation, Repo},
    mdn_index::MdnIndex,
    mdn_inventory,
};
use devres_application::mdn::{MdnConfig, MdnStore, PROCESSOR_VERSION, Snapshot};
use devres_domain::{Error, Result};
use serde_json::{Value, json};
use std::io::Write;
type AttemptObserver = Arc<dyn Fn(usize) -> Result<()> + Send + Sync>;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;

async fn processing_permit<'a>(
    gate: &'a tokio::sync::RwLock<()>,
    cancel: &CancellationToken,
) -> Result<tokio::sync::RwLockReadGuard<'a, ()>> {
    let guard = tokio::select! {
        _ = cancel.cancelled() => return Err(Error::unavailable("MDN acceptance paused; evidence retained.")),
        guard = gate.read() => guard,
    };
    if cancel.is_cancelled() {
        return Err(Error::unavailable(
            "MDN acceptance paused; evidence retained.",
        ));
    }
    Ok(guard)
}

fn attempt_accounting(root: &Path, live: bool) -> Result<(usize, AttemptObserver)> {
    let path = root.join("attempts");
    if !path.exists() {
        let fresh = std::fs::read_dir(root.join("blobs"))
            .map_err(|_| Error::unavailable("MDN acceptance storage unavailable."))?
            .next()
            .is_none();
        let initial = if live && fresh { 0 } else { 20 };
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|_| Error::unavailable("MDN attempt ledger unavailable."))?;
        file.write_all(initial.to_string().as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|_| Error::unavailable("MDN attempt ledger unavailable."))?;
        if initial == 20 {
            std::fs::write(
                root.join("attempts-conservative"),
                b"legacy live invocation reserved at most 20 attempts\n",
            )
            .map_err(|_| Error::unavailable("MDN attempt ledger unavailable."))?;
        }
    }
    std::fs::File::open(root)
        .and_then(|f| f.sync_all())
        .map_err(|_| Error::unavailable("MDN attempt ledger unavailable."))?;
    let metadata = std::fs::symlink_metadata(&path)
        .map_err(|_| Error::unavailable("MDN attempt ledger unavailable."))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 32 {
        return Err(Error::integrity("Invalid MDN attempt ledger."));
    }
    let initial = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|n| *n <= 20)
        .ok_or_else(|| Error::integrity("Invalid MDN attempt ledger."))?;
    let saved = std::sync::Mutex::new(initial);
    let root = root.to_path_buf();
    let observer = Arc::new(move |count: usize| -> Result<()> {
        let mut current = saved
            .lock()
            .map_err(|_| Error::unavailable("MDN attempt ledger unavailable."))?;
        let count = count.max(*current);
        if count > 20 {
            return Err(Error::capacity(
                "MDN retained source attempt budget exhausted.",
            ));
        }
        let stage = root.join(format!(".attempt-stage-{}-{count}", std::process::id()));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&stage)
            .map_err(|_| Error::unavailable("MDN attempt ledger unavailable."))?;
        file.write_all(count.to_string().as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|_| Error::unavailable("MDN attempt ledger unavailable."))?;
        drop(file);
        std::fs::rename(&stage, &path)
            .map_err(|_| Error::unavailable("MDN attempt ledger unavailable."))?;
        std::fs::File::open(&root)
            .and_then(|f| f.sync_all())
            .map_err(|_| Error::unavailable("MDN attempt ledger unavailable."))?;
        *current = count;
        Ok(())
    });
    Ok((initial, observer))
}

async fn budget(root: &Path) -> Result<()> {
    for path in [
        root.to_path_buf(),
        root.join("blobs"),
        root.join("postgres"),
    ] {
        let path = std::fs::canonicalize(path)
            .map_err(|_| Error::unavailable("Acceptance headroom unavailable."))?;
        if fs2::available_space(path)
            .map_err(|_| Error::unavailable("Acceptance headroom unavailable."))?
            < 10 * 1024 * 1024 * 1024
        {
            return Err(Error::capacity(
                "MDN acceptance headroom exhausted; evidence retained.",
            ));
        }
    }
    // PostgreSQL files are owned by its container UID. This fixed read-only command
    // counts that directory too; the explicitly owned root is never shell-expanded.
    let mut measured = None;
    for _ in 0..5 {
        let output = tokio::time::timeout(
            Duration::from_secs(30),
            tokio::process::Command::new("sudo")
                .args(["-n", "du", "-sb", "--"])
                .stderr(std::process::Stdio::null())
                .kill_on_drop(true)
                .arg(root)
                .output(),
        )
        .await
        .map_err(|_| Error::capacity("Acceptance storage accounting timed out."))?
        .map_err(|_| Error::unavailable("Acceptance storage accounting unavailable."))?;
        if !output.status.success() {
            continue;
        }
        if output.stdout.len() > 8192 {
            return Err(Error::capacity(
                "Acceptance storage accounting exceeds its bound.",
            ));
        }
        let bytes = std::str::from_utf8(&output.stdout)
            .ok()
            .and_then(|s| s.split_whitespace().next())
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or_else(|| Error::integrity("Invalid acceptance storage accounting."))?;
        measured = Some(bytes);
        break;
    }
    let bytes = measured.ok_or_else(|| {
        Error::unavailable("Acceptance storage accounting failed after bounded retries.")
    })?;
    if bytes > 256 * 1024 * 1024 * 1024 {
        return Err(Error::capacity(
            "MDN acceptance working budget exhausted; evidence retained.",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use devres_application::mdn::{MdnRow, View};
    use std::sync::Mutex;

    #[derive(Default)]
    struct HistoryStore {
        rows: Mutex<BTreeMap<(String, String), MdnRow>>,
        states: Mutex<BTreeMap<String, Value>>,
    }
    impl HistoryStore {
        fn insert(&self, kind: &str, key: &str, data: Value) {
            let mut rows = self.rows.lock().unwrap();
            let sequence = rows.len() as i64 + 1;
            rows.insert(
                (kind.into(), key.into()),
                MdnRow {
                    sequence,
                    key: key.into(),
                    data,
                },
            );
        }
        fn snapshot(&self, commit: &CommitOrder, version: u32, suffix: &str) -> Snapshot {
            let snapshot = Snapshot {
                id: mdn_inventory::digest(
                    format!("{}:{version}:{suffix}", commit.revision).as_bytes(),
                ),
                repository: "content".into(),
                revision: commit.revision.clone(),
                tree: "a".repeat(40),
                parents: commit.parents.clone(),
                committed_at: commit.committed_at,
                inventory: mdn_inventory::digest(commit.revision.as_bytes()),
                processor_version: version,
                index: json!({"fixture":suffix}),
                coverage: json!({"accounted":true}),
            };
            self.insert(
                "snapshots",
                &snapshot.id,
                serde_json::to_value(&snapshot).unwrap(),
            );
            snapshot
        }
        fn original(&self, snapshot: &Snapshot) {
            self.insert(
                "snapshot-keys",
                &format!(
                    "content:{}:{}",
                    snapshot.revision, snapshot.processor_version
                ),
                json!(snapshot.id),
            );
        }
    }
    #[async_trait]
    impl MdnStore for HistoryStore {
        async fn mdn_cutoff(&self) -> Result<i64> {
            panic!("sampler must not discover unrelated history")
        }
        async fn mdn_get(&self, kind: &str, key: &str) -> Result<Option<MdnRow>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .get(&(kind.into(), key.into()))
                .cloned())
        }
        async fn mdn_put(&self, kind: &str, key: &str, data: &Value) -> Result<i64> {
            self.insert(kind, key, data.clone());
            Ok(self.mdn_get(kind, key).await?.unwrap().sequence)
        }
        async fn mdn_rows(&self, _: &str, _: i64, _: usize, _: Option<i64>) -> Result<Vec<MdnRow>> {
            panic!("sampler must not scan generations or unrelated revisions")
        }
        async fn mdn_state(&self, key: &str) -> Result<Option<Value>> {
            Ok(self.states.lock().unwrap().get(key).cloned())
        }
        async fn mdn_set_state(&self, _: &str, _: &Value) -> Result<()> {
            panic!("read-only sampler")
        }
        async fn mdn_publish_view(&self, _: &View) -> Result<()> {
            panic!("read-only sampler")
        }
    }
    fn commit(n: u32) -> CommitOrder {
        CommitOrder {
            revision: format!("{n:040x}"),
            parents: if n == 2 {
                vec!["a".repeat(40), "b".repeat(40)]
            } else {
                Vec::new()
            },
            committed_at: i64::from(n),
        }
    }
    #[tokio::test]
    async fn frozen_samples_ignore_legacy_duplicates_and_extra_revisions_use_current_alias() {
        let store = HistoryStore::default();
        let commits: Vec<_> = (1..=5).map(commit).collect();
        let mut current = Vec::new();
        for commit in &commits {
            let legacy = store.snapshot(commit, 2, "corrupt-old-index");
            store.original(&legacy);
            store.snapshot(commit, 2, "retained-repaired-index");
            let snapshot = store.snapshot(commit, PROCESSOR_VERSION, "original");
            store.original(&snapshot);
            current.push(snapshot);
        }
        let repaired = store.snapshot(&commits[2], PROCESSOR_VERSION, "repaired");
        store.states.lock().unwrap().insert(
            format!(
                "rebuild-alias:content:{}:{PROCESSOR_VERSION}",
                commits[2].revision
            ),
            json!(repaired.id),
        );
        let unrelated =
            store.snapshot(&commit(99), PROCESSOR_VERSION, "outside-frozen-observation");
        store.original(&unrelated);
        let mut samples = HistorySamples::new(5, Some(commits[3].revision.clone())).unwrap();
        for commit in &commits {
            samples.push(&store, "content", commit).await.unwrap();
        }
        let selected = samples.finish().unwrap();
        assert_eq!(selected["oldest"].id, current[0].id);
        assert_eq!(selected["recent"].id, current[4].id);
        assert_eq!(selected["middle"].id, repaired.id);
        assert_eq!(selected["merge"].id, current[1].id);
        assert_eq!(selected["advertised_tip"].id, current[3].id);
        assert!(
            selected
                .values()
                .all(|s| s.processor_version == PROCESSOR_VERSION
                    && s.revision != unrelated.revision)
        );
        let mut incomplete = HistorySamples::new(5, None).unwrap();
        incomplete
            .push(&store, "content", &commits[0])
            .await
            .unwrap();
        assert!(
            incomplete
                .push(&store, "content", &commits[0])
                .await
                .is_err()
        );
        assert!(incomplete.finish().is_err());
    }
    #[tokio::test]
    async fn missing_or_invalid_current_generation_never_falls_back_to_legacy() {
        let store = HistoryStore::default();
        let commit = commit(1);
        let legacy = store.snapshot(&commit, 2, "readable-legacy");
        store.original(&legacy);
        assert!(
            canonical_history_snapshot(&store, "content", &commit)
                .await
                .is_err()
        );
        let current = store.snapshot(&commit, PROCESSOR_VERSION, "current");
        store.original(&current);
        let key = format!(
            "rebuild-alias:content:{}:{PROCESSOR_VERSION}",
            commit.revision
        );
        store
            .states
            .lock()
            .unwrap()
            .insert(key.clone(), json!(legacy.id));
        assert!(
            canonical_history_snapshot(&store, "content", &commit)
                .await
                .is_err()
        );
        store
            .states
            .lock()
            .unwrap()
            .insert(key.clone(), json!("f".repeat(64)));
        assert!(
            canonical_history_snapshot(&store, "content", &commit)
                .await
                .is_err()
        );
        store.states.lock().unwrap().remove(&key);
        let mut misbound = store.snapshot(&commit, PROCESSOR_VERSION, "wrong-inventory");
        misbound.inventory = "e".repeat(64);
        store.insert(
            "snapshots",
            &misbound.id,
            serde_json::to_value(&misbound).unwrap(),
        );
        store
            .states
            .lock()
            .unwrap()
            .insert(key.clone(), json!(misbound.id));
        assert!(
            canonical_history_snapshot(&store, "content", &commit)
                .await
                .is_err()
        );
        store.states.lock().unwrap().remove(&key);
        let mut invalid = current.clone();
        invalid.index = Value::Null;
        store.insert(
            "snapshots",
            &current.id,
            serde_json::to_value(invalid).unwrap(),
        );
        assert!(
            canonical_history_snapshot(&store, "content", &commit)
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn wrong_generation_history_and_selected_corrupt_index_fail() {
        let store = Arc::new(HistoryStore::default());
        let artifact = json!({"body_hash":"a".repeat(64),"bytes":1,"relative_path":"fixture"});
        let observation = json!({"repo":"content","observed_at":1,"refs":[],"roots":[],"manifest":artifact,"commits":artifact,"total_commits":1,"main_revision":commit(1).revision});
        store.states.lock().unwrap().insert(
            "content-history".into(),
            json!({"processor_version":2,"complete":true,"processed":1,"observation":observation}),
        );
        assert!(frozen_history(store.as_ref(), Repo::Content).await.is_err());
        store
            .states
            .lock()
            .unwrap()
            .get_mut("content-history")
            .unwrap()["processor_version"] = json!(PROCESSOR_VERSION);
        assert_eq!(
            frozen_history(store.as_ref(), Repo::Content)
                .await
                .unwrap()
                .total_commits,
            1
        );
        let root = tempfile::tempdir().unwrap();
        let mut current = store.snapshot(&commit(1), PROCESSOR_VERSION, "corrupt-current-index");
        current.inventory = mdn_inventory::empty(store.as_ref()).await.unwrap();
        store.insert(
            "snapshots",
            &current.id,
            serde_json::to_value(&current).unwrap(),
        );
        store.original(&current);
        let selected = canonical_history_snapshot(store.as_ref(), "content", &commit(1))
            .await
            .unwrap();
        let research = devres_adapters::mdn_research::MdnResearch::new(store, root.path()).unwrap();
        let error = research
            .call(
                "mdn_search",
                json!({"snapshot":selected.id,"query":"fixture"}),
            )
            .await
            .expect_err("a selected current index failure stays fatal; no legacy fallback");
        assert_eq!(error.code, "integrity");
    }

    #[tokio::test]
    async fn failed_accounting_cannot_resume_a_waiting_processing_slice() {
        let gate = tokio::sync::RwLock::new(());
        let measuring = gate.write().await;
        let cancel = CancellationToken::new();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), processing_permit(&gate, &cancel))
                .await
                .is_err()
        );
        cancel.cancel();
        assert!(processing_permit(&gate, &cancel).await.is_err());
        drop(measuring);
        assert!(processing_permit(&gate, &cancel).await.is_err());
    }

    #[test]
    fn durable_attempts_survive_resume_and_reject_over_budget() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("blobs")).unwrap();
        let (initial, record) = attempt_accounting(root.path(), true).unwrap();
        assert_eq!(initial, 0);
        record(3).unwrap();
        record(2).unwrap();
        let (resumed, record) = attempt_accounting(root.path(), false).unwrap();
        assert_eq!(resumed, 3);
        record(20).unwrap();
        assert!(record(21).is_err());
        assert_eq!(attempt_accounting(root.path(), false).unwrap().0, 20);
    }

    #[test]
    fn legacy_evidence_cannot_reset_live_attempts() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("blobs")).unwrap();
        std::fs::write(root.path().join("blobs/retained"), b"evidence").unwrap();
        assert_eq!(attempt_accounting(root.path(), true).unwrap().0, 20);
        assert!(root.path().join("attempts-conservative").is_file());
    }
}
async fn verify(store: &dyn MdnStore, root: &Path, cancel: CancellationToken) -> Result<Value> {
    let reference = store
        .mdn_state("index")
        .await?
        .ok_or_else(|| Error::unavailable("MDN index unpublished."))?;
    MdnIndex::new(root)?
        .prewarm(&reference, cancel.clone())
        .await?;
    let mut after = 0;
    let mut snapshots = 0u64;
    let mut gaps = 0u64;
    loop {
        if cancel.is_cancelled() {
            return Err(Error::unavailable("MDN verification canceled."));
        }
        let rows = store.mdn_rows("snapshots", after, 250, None).await?;
        if rows.is_empty() {
            break;
        }
        for row in rows {
            after = row.sequence;
            let snapshot: Snapshot = mdn_inventory::decode(row.data)?;
            let node = mdn_inventory::node(store, &snapshot.inventory).await?;
            if snapshot.id != row.key
                || snapshot.coverage["accounted"] != true
                || snapshot.coverage["members"].as_u64() != Some(node.members)
                || snapshot.coverage["projection_gaps"].as_u64() != Some(node.gaps)
            {
                return Err(Error::integrity("MDN frozen snapshot accounting failed."));
            }
            snapshots += 1;
            gaps = gaps.saturating_add(node.gaps);
        }
    }
    for repository in ["content", "compat"] {
        let state = store
            .mdn_state(&format!("{repository}-history"))
            .await?
            .ok_or_else(|| Error::unavailable("MDN history has not started."))?;
        if state["complete"] != true || state["processed"] != state["observation"]["total_commits"]
        {
            return Err(Error::unavailable("MDN ancestry processing incomplete."));
        }
    }
    Ok(
        json!({"snapshots_verified":snapshots,"historical_projection_gap_memberships":gaps,"latest_index_verified":true}),
    )
}
async fn frozen_history(store: &dyn MdnStore, repository: Repo) -> Result<Observation> {
    let state = store
        .mdn_state(&format!("{}-history", repository.as_str()))
        .await?
        .ok_or_else(|| Error::unavailable("MDN frozen history missing."))?;
    let observation: Observation = mdn_inventory::decode(state["observation"].clone())?;
    if state["processor_version"].as_u64() != Some(u64::from(PROCESSOR_VERSION))
        || state["complete"] != true
        || state["processed"].as_u64() != Some(observation.total_commits as u64)
        || observation.repo != repository
        || !(1..=1_000_000).contains(&observation.total_commits)
    {
        return Err(Error::integrity(
            "Current-generation frozen MDN history is incomplete.",
        ));
    }
    Ok(observation)
}

async fn canonical_history_snapshot(
    store: &dyn MdnStore,
    repository: &str,
    commit: &CommitOrder,
) -> Result<Snapshot> {
    fn valid_id(id: &str) -> bool {
        id.len() == 64
            && id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }
    let key = format!("{repository}:{}:{PROCESSOR_VERSION}", commit.revision);
    let original = store
        .mdn_get("snapshot-keys", &key)
        .await?
        .ok_or_else(|| Error::integrity("Current-generation historical snapshot missing."))?;
    let original_id = original
        .data
        .as_str()
        .filter(|id| valid_id(id))
        .ok_or_else(|| Error::integrity("Invalid historical snapshot alias."))?;
    let original: Snapshot = mdn_inventory::decode(
        store
            .mdn_get("snapshots", original_id)
            .await?
            .ok_or_else(|| Error::integrity("Current-generation historical snapshot missing."))?
            .data,
    )?;
    if original.id != original_id
        || original.repository != repository
        || original.revision != commit.revision
        || original.processor_version != PROCESSOR_VERSION
        || original.parents != commit.parents
        || original.committed_at != commit.committed_at
        || original.index.is_null()
        || original.coverage["accounted"] != true
        || original.coverage["synthetic"] == true
    {
        return Err(Error::integrity(
            "Invalid current-generation historical evidence.",
        ));
    }
    let Some(alias) = store.mdn_state(&format!("rebuild-alias:{key}")).await? else {
        return Ok(original);
    };
    let id = alias
        .as_str()
        .filter(|id| valid_id(id))
        .ok_or_else(|| Error::integrity("Invalid historical rebuild alias."))?;
    let repaired: Snapshot = mdn_inventory::decode(
        store
            .mdn_get("snapshots", id)
            .await?
            .ok_or_else(|| Error::integrity("Historical rebuilt snapshot missing."))?
            .data,
    )?;
    if repaired.id != id
        || repaired.repository != original.repository
        || repaired.revision != original.revision
        || repaired.processor_version != original.processor_version
        || repaired.tree != original.tree
        || repaired.parents != original.parents
        || repaired.committed_at != original.committed_at
        || repaired.inventory != original.inventory
        || repaired.index.is_null()
        || repaired.coverage["accounted"] != true
        || repaired.coverage["synthetic"] == true
    {
        return Err(Error::integrity("Invalid historical rebuilt evidence."));
    }
    Ok(repaired)
}

struct HistorySamples {
    total: usize,
    tip: Option<String>,
    // Fixed-width identities keep the maximum one-million-commit set bounded.
    seen: BTreeSet<[u8; 20]>,
    samples: BTreeMap<String, Snapshot>,
}
impl HistorySamples {
    fn new(total: usize, tip: Option<String>) -> Result<Self> {
        if !(1..=1_000_000).contains(&total) {
            return Err(Error::integrity("Invalid frozen MDN history size."));
        }
        Ok(Self {
            total,
            tip,
            seen: BTreeSet::new(),
            samples: BTreeMap::new(),
        })
    }
    async fn push(
        &mut self,
        store: &dyn MdnStore,
        repository: &str,
        commit: &CommitOrder,
    ) -> Result<()> {
        let mut oid = [0u8; 20];
        if commit.revision.len() != 40
            || hex::decode_to_slice(&commit.revision, &mut oid).is_err()
            || !self.seen.insert(oid)
            || self.seen.len() > self.total
        {
            return Err(Error::integrity("Invalid or duplicate frozen MDN commit."));
        }
        let snapshot = canonical_history_snapshot(store, repository, commit).await?;
        for (case, oldest) in [("oldest", true), ("recent", false)] {
            if self.samples.get(case).is_none_or(|previous| {
                let key = (snapshot.committed_at, &snapshot.revision);
                let before = (previous.committed_at, &previous.revision);
                if oldest { key < before } else { key > before }
            }) {
                self.samples.insert(case.into(), snapshot.clone());
            }
        }
        if self.seen.len() - 1 == self.total / 2 {
            self.samples.insert("middle".into(), snapshot.clone());
        }
        if snapshot.parents.len() > 1 {
            self.samples
                .entry("merge".into())
                .or_insert_with(|| snapshot.clone());
        }
        if self.tip.as_ref() == Some(&snapshot.revision) {
            self.samples.insert("advertised_tip".into(), snapshot);
        }
        Ok(())
    }
    fn finish(self) -> Result<BTreeMap<String, Snapshot>> {
        if self.seen.len() != self.total
            || (self.tip.is_some() && !self.samples.contains_key("advertised_tip"))
        {
            return Err(Error::integrity(
                "Frozen MDN history snapshot count mismatch.",
            ));
        }
        Ok(self.samples)
    }
}

async fn historical_samples(
    store: &dyn MdnStore,
    research: &devres_adapters::mdn_research::MdnResearch,
    root: &Path,
    cancel: CancellationToken,
) -> Result<Value> {
    let mut samples = BTreeMap::<(String, String), Snapshot>::new();
    for repository in [Repo::Content, Repo::Compat] {
        let observation = frozen_history(store, repository).await?;
        let tip = observation
            .refs
            .iter()
            .find(|reference| {
                reference.name != "refs/heads/main" && reference.peeled_commit.is_some()
            })
            .and_then(|reference| reference.peeled_commit.clone());
        let mut selected = HistorySamples::new(observation.total_commits, tip)?;
        let git = MdnGit::new(
            root,
            repository,
            8 * 1024 * 1024 * 1024,
            64 * 1024 * 1024,
            None,
        )?;
        let mut offset = 0;
        while offset < observation.commits.bytes {
            if cancel.is_cancelled() {
                return Err(Error::unavailable("Historical verification canceled."));
            }
            let page = git
                .commit_page(&observation, offset, 1000, cancel.clone())
                .await?;
            if page.next_offset <= offset || page.next_offset > observation.commits.bytes {
                return Err(Error::integrity("Invalid frozen MDN commit page."));
            }
            for commit in page.commits {
                if cancel.is_cancelled() {
                    return Err(Error::unavailable("Historical verification canceled."));
                }
                selected.push(store, repository.as_str(), &commit).await?;
            }
            offset = page.next_offset;
        }
        for (case, snapshot) in selected.finish()? {
            samples.insert((repository.as_str().into(), case), snapshot);
        }
    }
    let mut historical = Vec::new();
    let mut seen = BTreeSet::new();
    for ((repository, case), snapshot) in samples {
        if cancel.is_cancelled() {
            return Err(Error::unavailable("Historical verification canceled."));
        }
        if !seen.insert(snapshot.id.clone()) {
            continue;
        }
        let members = mdn_inventory::members(store, &snapshot.inventory, 1_000_000).await?;
        let selected = members
            .iter()
            .find(|m| {
                m.kind
                    == if repository == "content" {
                        "article"
                    } else {
                        "feature"
                    }
            })
            .or_else(|| {
                members.iter().find(|m| {
                    m.raw.is_some() && m.raw.as_ref().is_some_and(|r| r["raw_path_hex"].is_null())
                })
            });
        let Some(member) = selected else { continue };
        let source_path = member
            .raw
            .as_ref()
            .and_then(|r| r["source_path"].as_str())
            .unwrap_or(&member.path);
        let source=research.call("mdn_get",json!({"repository":repository,"snapshot":snapshot.id,"path":source_path,"representation":"source","limit":128})).await?;
        if source["provenance"]["revision"] != snapshot.revision {
            return Err(Error::integrity(
                "Historical MDN source rebound its revision.",
            ));
        }
        let uri = source["resource_uri"]
            .as_str()
            .ok_or_else(|| Error::integrity("Historical source resource missing."))?;
        research.read_resource(&format!("{uri}?limit=128")).await?;
        let mut searched = false;
        if member.kind == "article" && member.projection.is_some() {
            research.call("mdn_get",json!({"repository":repository,"snapshot":snapshot.id,"path":member.path,"limit":128})).await?;
            if !member.gaps.iter().any(|g| g == "search_index_gap") {
                let result = research
                    .call(
                        "mdn_search",
                        json!({"snapshot":snapshot.id,"path":member.path,"limit":1}),
                    )
                    .await?;
                if result["total"].as_u64().unwrap_or(0) == 0 {
                    return Err(Error::integrity(
                        "Historical MDN document absent from selected index.",
                    ));
                }
                searched = true;
            }
        } else if member.kind == "feature" {
            let key = member
                .path
                .strip_prefix("@features/")
                .ok_or_else(|| Error::integrity("Historical BCD feature identity invalid."))?;
            research
                .call(
                    "mdn_compat_get",
                    json!({"snapshot":snapshot.id,"feature":key}),
                )
                .await?;
            if !member.gaps.iter().any(|g| g == "search_index_gap") {
                let result = research
                    .call(
                        "mdn_compat_search",
                        json!({"snapshot":snapshot.id,"feature":key,"limit":1}),
                    )
                    .await?;
                if result["total"].as_u64().unwrap_or(0) == 0 {
                    return Err(Error::integrity(
                        "Historical BCD feature absent from selected index.",
                    ));
                }
                searched = true;
            }
        }
        historical.push(json!({"case":case,"repository":repository,"snapshot":snapshot.id,"revision":snapshot.revision,"processor_version":snapshot.processor_version,"path":source_path,"search_verified":searched,"raw_resource_verified":true}));
    }
    Ok(json!(historical))
}
#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let (live,full)=match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice(){["--live","full"] =>(true,true),["--live","current"] =>(true,false),["--resume","full"] =>(false,true),_=>return Err("usage: mdn-probe --live current|full | --resume full; dedicated DATABASE_URL, BLOB_DIR, DEVRES_MDN_ACCEPTANCE_ROOT required".into())};
    let root = PathBuf::from(std::env::var("DEVRES_MDN_ACCEPTANCE_ROOT")?);
    if std::fs::read(root.join("owner-v1"))? != b"devres-mdn-retained-acceptance-v1\n" {
        return Err("Dedicated retained acceptance ownership marker required".into());
    }
    let blob = PathBuf::from(std::env::var("BLOB_DIR")?);
    if std::fs::canonicalize(&blob)? != std::fs::canonicalize(root.join("blobs"))? {
        return Err("Acceptance blobs must use the owned directory".into());
    }
    budget(&root).await?;
    let cancel = CancellationToken::new();
    let stop = cancel.clone();
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            if let Ok(mut term) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            {
                tokio::select! {_=tokio::signal::ctrl_c()=>{},_=term.recv()=>{}}
            } else {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
        stop.cancel();
    });
    let store = Arc::new(PgBlobStore::connect(&std::env::var("DATABASE_URL")?, &blob).await?);
    let (initial_attempts, observer) = attempt_accounting(&root, live)?;
    let broker = Arc::new(
        BulkBroker::new(BulkConfig::default())?
            .with_attempt_budget(20)?
            .with_attempt_observer(initial_attempts, observer)?,
    );
    let corpus = Arc::new(MdnCorpus::new(
        store.clone(),
        broker.clone(),
        &blob,
        MdnConfig {
            enabled: false,
            min_free_bytes: 10 * 1024 * 1024 * 1024,
            ..Default::default()
        },
    )?);
    corpus.recover(cancel.clone()).await?;
    let monitor_root = root.clone();
    let monitor_cancel = cancel.clone();
    // Measure between resumable slices. No collector writes continue while an
    // accounting command runs; a timeout still cancels the entire invocation.
    let storage_gate = Arc::new(tokio::sync::RwLock::new(()));
    let monitor_gate = storage_gate.clone();
    let monitor = tokio::spawn(async move {
        loop {
            tokio::select! {_=monitor_cancel.cancelled()=>return Ok(()),_=tokio::time::sleep(Duration::from_secs(2))=>{
                let _guard = tokio::select! {
                    _ = monitor_cancel.cancelled() => return Ok(()),
                    guard = monitor_gate.write() => guard,
                };
                if let Err(error)=budget(&monitor_root).await{monitor_cancel.cancel();return Err(error)}
            }}
        }
    });
    let result:Result<Value>=async{
        for repo in [Repo::Content, Repo::Compat] {
            if store.mdn_state(&format!("{}-observation", repo.as_str())).await?.is_none() {
                if !live { return Err(Error::unavailable("Offline resume requires both frozen observations.")); }
                let _guard = processing_permit(&storage_gate, &cancel).await?;
                corpus.synchronize(repo, cancel.clone()).await?;
            }
        }
        let mut last=Instant::now();
        loop {
            if cancel.is_cancelled(){return Err(Error::unavailable("MDN acceptance paused; evidence retained."));}
            let current={
                let _guard=processing_permit(&storage_gate, &cancel).await?;
                corpus.process_current(cancel.clone()).await?
            };
            let history=if full{
                let _guard=processing_permit(&storage_gate, &cancel).await?;
                corpus.process_history(cancel.clone()).await?
            }else{true};
            if last.elapsed()>=Duration::from_secs(30){println!("{}",json!({"stage":"processing","attempts_upper_bound":broker.attempt_count(),"attempts_this_invocation":broker.attempt_count().saturating_sub(initial_attempts),"status":store.mdn_state("status").await?}));last=Instant::now();}
            if current&&history{break}tokio::task::yield_now().await;
        }
        let research=corpus.research();
        let frozen=store.mdn_state("default-view").await?.ok_or_else(||Error::unavailable("Frozen MDN view missing."))?;
        let found=research.call("mdn_search",json!({"query":"fetch","limit":3,"snapshot":frozen})).await?;
        if found["total"].as_u64().unwrap_or(0)==0{return Err(Error::integrity("Fixed MDN search found no evidence."));}
        let document=research.call("mdn_get",json!({"slug":"Web/API/Window/fetch","snapshot":frozen})).await?;
        let feature=research.call("mdn_compat_get",json!({"feature":"api.fetch","snapshot":frozen})).await?;
        research.read_resource(document["resource_uri"].as_str().ok_or_else(||Error::integrity("MDN resource missing."))?).await?;
        let mut verification=if full{verify(store.as_ref(),&blob,cancel.clone()).await?}else{Value::Null};
        if full{verification["historical_samples"]=historical_samples(store.as_ref(),research.as_ref(),&blob,cancel.clone()).await?;}
        Ok(json!({"stage":"complete","full_history":full,"attempts_upper_bound":broker.attempt_count(),"attempts_this_invocation":broker.attempt_count().saturating_sub(initial_attempts),"document":document["provenance"],"compatibility":feature["provenance"],"verification":verification,"status":store.mdn_state("status").await?}))
    }.await;
    cancel.cancel();
    let monitored = monitor.await?;
    if let Err(error) = monitored {
        return Err(error.into());
    }
    let result = result?;
    budget(&root).await?;
    std::fs::write(
        root.join("acceptance.json"),
        serde_json::to_vec_pretty(&result)?,
    )?;
    println!("{result}");
    Ok(())
}
