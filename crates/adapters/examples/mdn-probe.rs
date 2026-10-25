//! Explicit retained MDN acceptance. Credentials enter only through the environment.
use devres_adapters::{
    MdnCorpus, PgBlobStore,
    bulk::{BulkBroker, BulkConfig},
    mdn_git::Repo,
    mdn_index::MdnIndex,
    mdn_inventory,
};
use devres_application::mdn::{MdnConfig, MdnStore, Snapshot};
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
async fn historical_samples(
    store: &dyn MdnStore,
    research: &devres_adapters::mdn_research::MdnResearch,
    cancel: CancellationToken,
) -> Result<Value> {
    let mut totals = BTreeMap::new();
    let mut tips = BTreeMap::new();
    for repository in ["content", "compat"] {
        let state = store
            .mdn_state(&format!("{repository}-history"))
            .await?
            .ok_or_else(|| Error::unavailable("MDN frozen history missing."))?;
        totals.insert(
            repository.to_owned(),
            state["observation"]["total_commits"].as_u64().unwrap_or(0),
        );
        if let Some(reference) = state["observation"]["refs"].as_array().and_then(|refs| {
            refs.iter()
                .find(|r| r["name"] != "refs/heads/main" && r["peeled_commit"].is_string())
        }) {
            tips.insert(
                repository.to_owned(),
                reference["peeled_commit"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
            );
        }
    }
    let mut counts = BTreeMap::<String, u64>::new();
    let mut samples = BTreeMap::<(String, String), Snapshot>::new();
    let mut after = 0;
    loop {
        if cancel.is_cancelled() {
            return Err(Error::unavailable("Historical verification canceled."));
        }
        let rows = store.mdn_rows("snapshots", after, 250, None).await?;
        if rows.is_empty() {
            break;
        }
        for row in rows {
            after = row.sequence;
            let snapshot: Snapshot = mdn_inventory::decode(row.data)?;
            let count = counts.entry(snapshot.repository.clone()).or_default();
            let oldest = (snapshot.repository.clone(), "oldest".into());
            if samples
                .get(&oldest)
                .is_none_or(|s| snapshot.committed_at < s.committed_at)
            {
                samples.insert(oldest, snapshot.clone());
            }
            let recent = (snapshot.repository.clone(), "recent".into());
            if samples
                .get(&recent)
                .is_none_or(|s| snapshot.committed_at > s.committed_at)
            {
                samples.insert(recent, snapshot.clone());
            }
            if *count == totals.get(&snapshot.repository).copied().unwrap_or(0) / 2 {
                samples.insert(
                    (snapshot.repository.clone(), "middle".into()),
                    snapshot.clone(),
                );
            }
            if snapshot.parents.len() > 1 {
                samples
                    .entry((snapshot.repository.clone(), "merge".into()))
                    .or_insert_with(|| snapshot.clone());
            }
            if tips.get(&snapshot.repository) == Some(&snapshot.revision) {
                samples.insert(
                    (snapshot.repository.clone(), "advertised_tip".into()),
                    snapshot.clone(),
                );
            }
            *count += 1;
        }
    }
    let mut historical = Vec::new();
    let mut seen = BTreeSet::new();
    for ((repository, case), snapshot) in samples {
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
        historical.push(json!({"case":case,"repository":repository,"snapshot":snapshot.id,"revision":snapshot.revision,"path":source_path,"search_verified":searched,"raw_resource_verified":true}));
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
        if full{verification["historical_samples"]=historical_samples(store.as_ref(),research.as_ref(),cancel.clone()).await?;}
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
