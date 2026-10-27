//! Explicit retained WHATWG acceptance; source observations are frozen before backfill.
use devres_adapters::{
    PgBlobStore,
    bulk::{BulkBroker, BulkConfig},
    whatwg::WhatwgCorpus,
    whatwg::research::WhatwgResearch,
};
use devres_application::whatwg::{PROCESSOR_VERSION, WhatwgConfig};
use devres_domain::{Error, Result};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio_util::sync::CancellationToken;

const MAX_MANIFEST_BYTES: u64 = 32 * 1024 * 1024;
const MIN_FREE_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    Live,
    Resume,
    Recover,
    ResumeRecovery,
}
impl Action {
    fn recovery(self) -> bool {
        matches!(self, Self::Recover | Self::ResumeRecovery)
    }
    fn allows_source(self) -> bool {
        matches!(self, Self::Live | Self::Recover)
    }
    fn starts_offline(self) -> bool {
        !self.allows_source() || self == Self::Recover
    }
}

fn selection(args: &[String]) -> Option<(Action, bool)> {
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["--live", "full"] => Some((Action::Live, true)),
        ["--live", "current"] => Some((Action::Live, false)),
        ["--resume", "full"] => Some((Action::Resume, true)),
        ["--recover", "full"] => Some((Action::Recover, true)),
        ["--resume-recovery", "full"] => Some((Action::ResumeRecovery, true)),
        _ => None,
    }
}

fn storage_error() -> Error {
    Error::unavailable("Retained WHATWG acceptance storage unavailable.")
}

fn save(root: &Path, name: &str, value: &Value) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|_| storage_error())?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(Error::capacity(
            "WHATWG acceptance manifest exceeds its bound.",
        ));
    }
    let stage = root.join(format!(".{name}.stage-{}", std::process::id()));
    // Create only a fixed process-owned stage; preserve all retained public evidence.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&stage)
        .map_err(|_| storage_error())?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| storage_error())?;
    drop(file);
    std::fs::rename(stage, root.join(name)).map_err(|_| storage_error())?;
    std::fs::File::open(root)
        .and_then(|file| file.sync_all())
        .map_err(|_| storage_error())
}

fn read_manifest(root: &Path, name: &str) -> Result<Value> {
    let path = root.join(name);
    let metadata = std::fs::symlink_metadata(&path).map_err(|_| storage_error())?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_MANIFEST_BYTES
    {
        return Err(Error::integrity(
            "Invalid WHATWG acceptance frozen observation.",
        ));
    }
    let file = std::fs::File::open(path).map_err(|_| storage_error())?;
    serde_json::from_reader(file)
        .map_err(|_| Error::integrity("Invalid WHATWG acceptance frozen observation."))
}

fn read_frozen(root: &Path) -> Result<Value> {
    read_manifest(root, "frozen.json")
}

// Link a fully synced stage without replacing an existing immutable destination.
fn save_immutable(root: &Path, name: &str, value: &Value) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|_| storage_error())?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(Error::capacity(
            "WHATWG acceptance manifest exceeds its bound.",
        ));
    }
    let stage = root.join(format!(".{name}.immutable-stage-{}", std::process::id()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&stage)
        .map_err(|_| storage_error())?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| storage_error())?;
    drop(file);
    let published = std::fs::hard_link(&stage, root.join(name));
    std::fs::remove_file(&stage).map_err(|_| storage_error())?;
    match published {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if read_manifest(root, name)? != *value {
                return Err(Error::integrity(
                    "Immutable WHATWG acceptance evidence differs.",
                ));
            }
        }
        Err(_) => return Err(storage_error()),
    }
    std::fs::File::open(root)
        .and_then(|file| file.sync_all())
        .map_err(|_| storage_error())
}

fn checked_id(value: &Value) -> Result<&str> {
    value
        .as_str()
        .filter(|id| {
            id.len() == 64
                && id
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        })
        .ok_or_else(|| Error::integrity("Invalid WHATWG acceptance observation identity."))
}

fn require_full(envelope: &Value) -> Result<()> {
    if envelope["version"] != 1 || envelope["mode"] != "full" || !envelope["frozen"].is_object() {
        return Err(Error::integrity(
            "Full resume requires a frozen full observation.",
        ));
    }
    Ok(())
}

fn save_recovery(root: &Path, parent: &Value, frozen: Value) -> Result<Value> {
    require_full(parent)?;
    let parent_id = checked_id(&parent["frozen"]["id"])?;
    let id = checked_id(&frozen["id"])?;
    if id == parent_id {
        return Err(Error::integrity(
            "WHATWG recovery requires a distinct successor.",
        ));
    }
    let envelope = json!({"version":1,"mode":"full","parent_frozen":parent_id,"frozen":frozen});
    let id = checked_id(&envelope["frozen"]["id"])?;
    save_immutable(root, &format!("frozen-recovery-{id}.json"), &envelope)?;
    save(
        root,
        "recovery-current.json",
        &json!({"version":1,"frozen_id":id}),
    )?;
    Ok(envelope)
}

fn read_recovery(root: &Path) -> Result<Value> {
    let pointer = read_manifest(root, "recovery-current.json")?;
    if pointer["version"] != 1 {
        return Err(Error::integrity("Invalid WHATWG recovery pointer."));
    }
    let id = checked_id(&pointer["frozen_id"])?;
    let envelope = read_manifest(root, &format!("frozen-recovery-{id}.json"))?;
    require_full(&envelope)?;
    let parent = read_frozen(root)?;
    require_full(&parent)?;
    if envelope["frozen"]["id"] != id || envelope["parent_frozen"] != parent["frozen"]["id"] {
        return Err(Error::integrity("WHATWG recovery lineage mismatch."));
    }
    Ok(envelope)
}

fn save_recovery_receipt(root: &Path, envelope: &Value, evidence: &Value) -> Result<String> {
    let id = checked_id(&envelope["frozen"]["id"])?;
    let bytes = serde_json::to_vec_pretty(evidence).map_err(|_| storage_error())?;
    let hash = hex::encode(Sha256::digest(&bytes));
    let name = format!("acceptance-recovery-{id}-p{PROCESSOR_VERSION}-{hash}.json");
    save_immutable(root, &name, evidence)?;
    save(
        root,
        "recovery-acceptance.json",
        &json!({"version":1,"frozen_id":id,"receipt":name,"receipt_sha256":hash}),
    )?;
    Ok(name)
}

fn retain_recovery_failure(root: &Path, evidence: &Value) -> Result<String> {
    let mut evidence = evidence.clone();
    evidence["observed_at"] = json!(devres_domain::unix_now());
    evidence["process_id"] = json!(std::process::id());
    if let Ok(parent) = read_frozen(root)
        && let Ok(id) = checked_id(&parent["frozen"]["id"])
    {
        evidence["parent_frozen"] = json!(id);
    }
    if let Ok(successor) = read_recovery(root)
        && let Ok(id) = checked_id(&successor["frozen"]["id"])
    {
        evidence["last_known_successor"] = json!(id);
    }
    let bytes = serde_json::to_vec_pretty(&evidence).map_err(|_| storage_error())?;
    let hash = hex::encode(Sha256::digest(&bytes));
    let name = format!("recovery-failure-{hash}.json");
    save_immutable(root, &name, &evidence)?;
    evidence["retained_record"] = json!(name);
    save(root, "last-recovery-failure.json", &evidence)?;
    Ok(name)
}

fn headroom(root: &Path) -> Result<()> {
    if fs2::available_space(root).map_err(|_| storage_error())? < MIN_FREE_BYTES {
        return Err(Error::capacity(
            "WHATWG acceptance headroom exhausted; evidence retained.",
        ));
    }
    Ok(())
}

fn required_env(name: &str) -> Result<String> {
    std::env::var(name).map_err(|_| Error::invalid("Required acceptance environment is missing."))
}

fn report(value: &Value) {
    let _ = writeln!(std::io::stdout().lock(), "{value}");
}

async fn supervise<F>(
    future: F,
    root: &Path,
    broker: &BulkBroker,
    cancel: &CancellationToken,
    stage: &'static str,
    mode: &'static str,
) -> Result<Value>
where
    F: std::future::Future<Output = Result<Value>>,
{
    tokio::pin!(future);
    let mut progress = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_secs(30),
        Duration::from_secs(30),
    );
    loop {
        tokio::select! {
            result = &mut future => return result,
            _ = progress.tick() => {
                if let Err(error) = headroom(root) {
                    cancel.cancel();
                    // Await cooperative shutdown so no writer outlives this invocation.
                    let _ = future.await;
                    return Err(error);
                }
                report(&json!({"stage":stage,"mode":mode,"complete":false,"attempts_this_invocation":broker.attempt_count()}));
            }
        }
    }
}

async fn accept(root: &Path, action: Action, full: bool, cancel: CancellationToken) -> Result<()> {
    let mode = if full { "full" } else { "current" };
    let blobs = std::fs::canonicalize(required_env("BLOB_DIR")?).map_err(|_| storage_error())?;
    if blobs != root.join("blobs") {
        return Err(Error::invalid(
            "Acceptance blobs must use the owned retained directory.",
        ));
    }
    headroom(root)?;
    let store = Arc::new(PgBlobStore::connect(&required_env("DATABASE_URL")?, &blobs).await?);
    let offline = Arc::new(AtomicBool::new(action.starts_offline()));
    let admission = offline.clone();
    let broker = Arc::new(
        BulkBroker::new(BulkConfig::default())?
            .with_attempt_budget(1_000_000)?
            .with_attempt_observer(
                0,
                Arc::new(move |_| {
                    if admission.load(Ordering::Acquire) {
                        Err(Error::integrity(
                            "Frozen WHATWG processing attempted source I/O.",
                        ))
                    } else {
                        Ok(())
                    }
                }),
            )?,
    );
    let corpus = Arc::new(WhatwgCorpus::new(
        store,
        broker.clone(),
        &blobs,
        WhatwgConfig {
            enabled: false,
            ..Default::default()
        },
    )?);
    corpus.initialize_status().await?;
    corpus.recover(cancel.clone()).await?;
    let envelope = if action == Action::Live {
        if root.join("frozen.json").exists() {
            return Err(Error::invalid(
                "Frozen observation already exists; resume it or use a new root.",
            ));
        }
        report(&json!({"stage":"freezing","mode":mode,"complete":false}));
        let frozen = supervise(
            async {
                if full {
                    corpus.freeze(cancel.clone()).await
                } else {
                    corpus.freeze_current(cancel.clone()).await
                }
            },
            root,
            &broker,
            &cancel,
            "freezing",
            mode,
        )
        .await?;
        let envelope = json!({"version":1,"mode":mode,"frozen":frozen});
        save_immutable(root, "frozen.json", &envelope)?;
        envelope
    } else if action == Action::Recover {
        let parent = read_frozen(root)?;
        require_full(&parent)?;
        report(&json!({"stage":"recovering_discovery","mode":mode,"complete":false}));
        offline.store(false, Ordering::Release);
        let result = supervise(
            corpus.recover_frozen(&parent["frozen"], cancel.clone()),
            root,
            &broker,
            &cancel,
            "recovering_discovery",
            mode,
        )
        .await;
        offline.store(true, Ordering::Release);
        let frozen = result?;
        save_recovery(root, &parent, frozen)?
    } else if action == Action::ResumeRecovery {
        read_recovery(root)?
    } else {
        let envelope = read_frozen(root)?;
        require_full(&envelope)?;
        envelope
    };
    offline.store(true, Ordering::Release);
    let frozen_attempts = broker.attempt_count();
    let mut outcome = supervise(
        async {
            if full {
                corpus
                    .accept_frozen(&envelope["frozen"], cancel.clone())
                    .await
            } else {
                corpus
                    .accept_frozen_current(&envelope["frozen"], cancel.clone())
                    .await
            }
        },
        root,
        &broker,
        &cancel,
        "processing",
        mode,
    )
    .await?;
    if outcome["complete"] == true {
        outcome["research"] = tokio::select! {
            result = verify_research(corpus.clone()) => result?,
            _ = cancel.cancelled() => return Err(Error::new("cancelled", "WHATWG acceptance canceled.")),
        };
    }
    if broker.attempt_count() != frozen_attempts {
        return Err(Error::integrity(
            "Frozen WHATWG processing attempted source I/O.",
        ));
    }
    let complete = outcome["complete"] == true;
    let mut evidence = json!({
        "version":1,"stage":if complete {"complete"} else {"incomplete"},
        "complete":complete,"mode":mode,"attempts_this_invocation":broker.attempt_count(),
        "verification":outcome,"attempts_before_processing":frozen_attempts,"attempts_during_processing":0,
    });
    if action.recovery() {
        evidence["parent_frozen"] = envelope["parent_frozen"].clone();
    }
    let receipt = if action.recovery() {
        save_recovery_receipt(root, &envelope, &evidence)?
    } else {
        save(root, "acceptance.json", &evidence)?;
        "acceptance.json".into()
    };
    let mut aggregate = json!({"stage":evidence["stage"],"mode":mode,"complete":complete,"attempts_this_invocation":broker.attempt_count()});
    aggregate["receipt"] = json!(receipt);
    for key in [
        "standards",
        "git_commits_expected",
        "git_commits_processed",
        "publications_expected",
        "publications_processed",
        "projection_gaps",
        "index_gaps",
    ] {
        if evidence["verification"][key].is_number() {
            aggregate[key] = evidence["verification"][key].clone();
        }
    }
    report(&aggregate);
    if !complete {
        return Err(Error::unavailable(
            "WHATWG acceptance is incomplete; retained evidence records remaining work.",
        ));
    }
    Ok(())
}

// Exercise the actual frozen corpus through the public local research adapter.
// HTTP/WebTransport framing is a separate fixture/edge acceptance gate.
async fn verify_research(corpus: Arc<WhatwgCorpus>) -> Result<Value> {
    let view = corpus.view(None).await?;
    let research = WhatwgResearch::new(corpus);
    let catalog = research
        .call("whatwg.catalog_search", json!({"view":view.id,"limit":100}))
        .await?;
    let catalog_total = catalog["total"].as_u64().ok_or_else(storage_error)?;
    if catalog_total != view.snapshots.len() as u64 || view.snapshots.is_empty() {
        return Err(Error::integrity("WHATWG acceptance view is incomplete."));
    }
    let selected = json!({"standard":"dom","view":view.id,"limit":1024});
    let text = research.call("whatwg.get", selected.clone()).await?;
    if text["page"]["text"].as_str().is_none_or(str::is_empty) {
        return Err(Error::integrity("WHATWG acceptance text is empty."));
    }
    let uri = text["resource_uri"].as_str().ok_or_else(storage_error)?;
    research.read_resource(uri).await?;
    let mut bytes_input = selected;
    bytes_input["representation"] = json!("bytes");
    let bytes = research.call("whatwg.get", bytes_input).await?;
    if bytes["page"]["total_bytes"].as_u64().unwrap_or(0) == 0 {
        return Err(Error::integrity("WHATWG acceptance raw evidence is empty."));
    }
    let search = research
        .call(
            "whatwg.search",
            json!({"standard":"dom","view":view.id,"query":"EventTarget","limit":2}),
        )
        .await?;
    let hits = search["results"].as_array().ok_or_else(storage_error)?;
    if hits.is_empty() {
        return Err(Error::integrity(
            "WHATWG acceptance search has no expected DOM match.",
        ));
    }
    let symbols = research
        .call(
            "whatwg.symbol_search",
            json!({"standard":"dom","view":view.id,"kind":"idl","name":"EventTarget","limit":2}),
        )
        .await?;
    let symbol = symbols["items"]
        .as_array()
        .and_then(|items| items.first())
        .ok_or_else(|| Error::integrity("WHATWG acceptance IDL declaration is absent."))?;
    let symbol_uri = symbol["resource_uri"].as_str().ok_or_else(storage_error)?;
    research.read_resource(symbol_uri).await?;
    history_with_items(|input| research.call("whatwg.history", input)).await?;
    Ok(
        json!({"view":view.id,"catalog_standards":catalog_total,"default_standards":view.snapshots.len(),"text":true,"raw_bytes":true,"text_resource":true,"search":true,"idl_symbol_resource":true,"history":true,"transport":"local_adapter"}),
    )
}

// Filtered discovery can scan its bounded global page without finding a match.
// Keep the same query and observation cutoff while following its continuation.
async fn history_with_items<F, Fut>(mut call: F) -> Result<Value>
where
    F: FnMut(Value) -> Fut,
    Fut: std::future::Future<Output = Result<Value>>,
{
    let mut input = json!({"standard":"dom","limit":2});
    let mut cutoff = None;
    for _ in 0..1024 {
        let page = call(input.clone()).await?;
        let observed = page["history_snapshot"]
            .as_i64()
            .filter(|value| *value >= 0)
            .ok_or_else(|| Error::integrity("Invalid WHATWG acceptance history cutoff."))?;
        if cutoff.is_some_and(|value| value != observed) {
            return Err(Error::integrity(
                "WHATWG acceptance history cutoff changed.",
            ));
        }
        cutoff = Some(observed);
        let items = page["items"]
            .as_array()
            .ok_or_else(|| Error::integrity("Invalid WHATWG acceptance history page."))?;
        if !items.is_empty() {
            return Ok(page);
        }
        let cursor = page["next_cursor"]
            .as_str()
            .filter(|value| !value.is_empty() && value.len() <= 16384)
            .ok_or_else(|| Error::integrity("WHATWG acceptance history is empty."))?;
        if input["cursor"].as_str() == Some(cursor) {
            return Err(Error::integrity(
                "WHATWG acceptance history did not advance.",
            ));
        }
        input["cursor"] = json!(cursor);
        input["history_snapshot"] = json!(observed);
    }
    Err(Error::capacity(
        "WHATWG acceptance history page bound exceeded.",
    ))
}

#[tokio::main]
async fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let Some((action, full)) = selection(&args) else {
        report(&json!({"stage":"failed","complete":false,"error_code":"invalid_input"}));
        std::process::exit(2);
    };
    let root = required_env("DEVRES_WHATWG_ACCEPTANCE_ROOT")
        .and_then(|value| std::fs::canonicalize(PathBuf::from(value)).map_err(|_| storage_error()));
    let root = match root {
        Ok(root)
            if root.starts_with("/tmp/")
                && root != Path::new("/tmp")
                && std::fs::read(root.join("owner-v1")).ok().as_deref()
                    == Some(b"devres-whatwg-retained-acceptance-v1\n") =>
        {
            root
        }
        _ => {
            report(&json!({"stage":"failed","complete":false,"error_code":"invalid_input"}));
            std::process::exit(2);
        }
    };
    let cancel = CancellationToken::new();
    let stop = cancel.clone();
    tokio::spawn(async move {
        #[cfg(unix)]
        if let Ok(mut term) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
        } else {
            let _ = tokio::signal::ctrl_c().await;
        }
        #[cfg(not(unix))]
        let _ = tokio::signal::ctrl_c().await;
        stop.cancel();
    });
    if let Err(error) = accept(&root, action, full, cancel.clone()).await {
        let evidence = json!({"version":1,"stage":if cancel.is_cancelled(){"paused"}else{"failed"},"complete":false,"mode":if full{"full"}else{"current"},"error_code":error.code});
        // Keep any detailed incomplete verification already emitted by accept().
        if action.recovery() {
            let _ = retain_recovery_failure(&root, &evidence);
        } else {
            let _ = save(&root, "last-failure.json", &evidence);
        }
        report(&evidence);
        std::process::exit(if cancel.is_cancelled() { 130 } else { 1 });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn filtered_history_follows_empty_pages_with_fixed_query_and_cutoff() {
        let mut requests = Vec::new();
        let pages = [
            json!({"items":[],"history_snapshot":731,"next_cursor":"first"}),
            json!({"items":[],"history_snapshot":731,"next_cursor":"second"}),
            json!({"items":[{"standard":"dom"}],"history_snapshot":731,"next_cursor":null}),
        ];
        let found = history_with_items(|input| {
            let page = pages[requests.len()].clone();
            requests.push(input);
            std::future::ready(Ok(page))
        })
        .await
        .expect("matching history after empty filtered pages");
        assert_eq!(found["items"][0]["standard"], "dom");
        assert_eq!(
            requests,
            vec![
                json!({"standard":"dom","limit":2}),
                json!({"standard":"dom","limit":2,"cursor":"first","history_snapshot":731}),
                json!({"standard":"dom","limit":2,"cursor":"second","history_snapshot":731}),
            ]
        );
    }

    #[tokio::test]
    async fn filtered_history_rejects_empty_terminal_and_malformed_pages() {
        for page in [
            json!({"items":[],"history_snapshot":731,"next_cursor":null}),
            json!({"items":null,"history_snapshot":731,"next_cursor":"first"}),
            json!({"items":[{}],"next_cursor":null}),
        ] {
            assert_eq!(
                history_with_items(|_| std::future::ready(Ok(page.clone())))
                    .await
                    .expect_err("no valid history evidence")
                    .code,
                "integrity"
            );
        }
    }

    #[tokio::test]
    async fn filtered_history_rejects_changed_cutoff_and_nonadvancing_or_unbounded_cursors() {
        for changed_cutoff in [false, true] {
            let mut calls = 0;
            let error = history_with_items(|_| {
                calls += 1;
                std::future::ready(Ok(json!({"items":[],"history_snapshot":if changed_cutoff && calls > 1 {732} else {731},"next_cursor":"first"})))
            }).await.expect_err("unstable continuation");
            assert_eq!(error.code, "integrity");
            assert_eq!(calls, 2);
        }
        let mut calls = 0;
        let error = history_with_items(|_| {
            calls += 1;
            std::future::ready(Ok(
                json!({"items":[],"history_snapshot":731,"next_cursor":format!("cursor-{calls}")}),
            ))
        })
        .await
        .expect_err("bounded continuation");
        assert_eq!(error.code, "capacity");
        assert_eq!(calls, 1024);
    }

    #[test]
    fn recovery_manifests_and_receipts_preserve_original_and_each_attempt() {
        let root = tempfile::tempdir().expect("fixture directory");
        let parent = json!({"version":1,"mode":"full","frozen":{"id":"a".repeat(64),"observations":{"kept":"fixed"}}});
        save_immutable(root.path(), "frozen.json", &parent).expect("original frozen");
        let original = std::fs::read(root.path().join("frozen.json")).expect("original bytes");
        let failed = json!({"complete":false,"unavailable_publications":8});
        save(root.path(), "acceptance.json", &failed).expect("original failure");
        let child = json!({"id":"b".repeat(64),"observations":{"kept":"fixed"}});
        let envelope = save_recovery(root.path(), &parent, child.clone()).expect("successor");
        assert_eq!(
            read_recovery(root.path()).expect("recovery resume"),
            envelope
        );
        assert_eq!(
            save_recovery(root.path(), &parent, child).expect("idempotent successor"),
            envelope
        );
        let first = save_recovery_receipt(
            root.path(),
            &envelope,
            &json!({"complete":false,"index_gaps":1}),
        )
        .expect("first receipt");
        let second = save_recovery_receipt(
            root.path(),
            &envelope,
            &json!({"complete":true,"index_gaps":0}),
        )
        .expect("later receipt");
        assert_ne!(first, second);
        assert_eq!(
            read_manifest(root.path(), &first).expect("first retained")["complete"],
            false
        );
        assert_eq!(
            read_manifest(root.path(), &second).expect("second retained")["complete"],
            true
        );
        assert_eq!(
            read_manifest(root.path(), "recovery-acceptance.json").expect("latest pointer")["receipt"],
            second
        );
        assert_eq!(
            std::fs::read(root.path().join("frozen.json")).expect("original retained"),
            original
        );
        assert_eq!(
            read_manifest(root.path(), "acceptance.json").expect("original outcome retained"),
            failed
        );
        assert_eq!(
            save_immutable(root.path(), "frozen.json", &json!({"changed":true}))
                .expect_err("no replacement")
                .code,
            "integrity"
        );
    }

    #[test]
    fn recovery_resume_rejects_escaping_pointer_and_foreign_lineage() {
        let root = tempfile::tempdir().expect("fixture directory");
        let parent = json!({"version":1,"mode":"full","frozen":{"id":"a".repeat(64)}});
        save_immutable(root.path(), "frozen.json", &parent).expect("original");
        save(
            root.path(),
            "recovery-current.json",
            &json!({"version":1,"frozen_id":"../outside"}),
        )
        .expect("invalid pointer fixture");
        assert_eq!(
            read_recovery(root.path()).expect_err("escaping ID").code,
            "integrity"
        );
        let id = "b".repeat(64);
        save(
            root.path(),
            "recovery-current.json",
            &json!({"version":1,"frozen_id":id}),
        )
        .expect("pointer");
        save_immutable(
            root.path(),
            &format!("frozen-recovery-{id}.json"),
            &json!({"version":1,"mode":"full","parent_frozen":"c".repeat(64),"frozen":{"id":id}}),
        )
        .expect("foreign lineage fixture");
        assert_eq!(
            read_recovery(root.path()).expect_err("foreign parent").code,
            "integrity"
        );
    }

    #[test]
    fn failed_recovery_attempts_remain_archived_without_replacing_parent_failure() {
        let root = tempfile::tempdir().expect("fixture directory");
        let parent = json!({"version":1,"mode":"full","frozen":{"id":"a".repeat(64)}});
        save_immutable(root.path(), "frozen.json", &parent).expect("parent");
        let old = json!({"stage":"failed","error_code":"original"});
        save(root.path(), "last-failure.json", &old).expect("original failure");
        let first = retain_recovery_failure(
            root.path(),
            &json!({"complete":false,"error_code":"unavailable"}),
        )
        .expect("unavailable attempt");
        let second = retain_recovery_failure(
            root.path(),
            &json!({"complete":false,"error_code":"cancelled"}),
        )
        .expect("cancelled attempt");
        assert_ne!(first, second);
        assert_eq!(
            read_manifest(root.path(), &first).expect("first retained")["error_code"],
            "unavailable"
        );
        assert_eq!(
            read_manifest(root.path(), &second).expect("second retained")["parent_frozen"],
            "a".repeat(64)
        );
        assert_eq!(
            read_manifest(root.path(), "last-recovery-failure.json").expect("latest failure")["retained_record"],
            second
        );
        assert_eq!(
            read_manifest(root.path(), "last-failure.json").expect("original untouched"),
            old
        );
    }

    #[cfg(unix)]
    #[test]
    fn immutable_recovery_evidence_rejects_symlinks_without_changing_targets() {
        let root = tempfile::tempdir().expect("fixture directory");
        let target = root.path().join("target.json");
        std::fs::write(&target, b"{\"fixed\":true}").expect("target");
        std::os::unix::fs::symlink(&target, root.path().join("frozen.json")).expect("symlink");
        assert_eq!(
            save_immutable(root.path(), "frozen.json", &json!({"fixed":true}))
                .expect_err("symlink not admitted")
                .code,
            "integrity"
        );
        assert_eq!(
            std::fs::read(target).expect("target untouched"),
            b"{\"fixed\":true}"
        );
    }

    #[test]
    fn recovery_is_explicit_and_its_resume_never_allows_provider_io() {
        let parse = |flag: &str, mode: &str| selection(&[flag.into(), mode.into()]);
        assert_eq!(parse("--recover", "full"), Some((Action::Recover, true)));
        assert_eq!(
            parse("--resume-recovery", "full"),
            Some((Action::ResumeRecovery, true))
        );
        assert!(Action::Recover.allows_source());
        assert!(Action::Recover.starts_offline());
        assert!(!Action::Live.starts_offline());
        assert!(!Action::ResumeRecovery.allows_source());
        assert!(!Action::Resume.allows_source());
        assert_eq!(parse("--recover", "current"), None);
        assert_eq!(parse("--resume-recovery", "current"), None);
    }

    #[test]
    fn frozen_observation_roundtrips_and_persists_across_later_outcomes() {
        let root = tempfile::tempdir().expect("fixture directory");
        let frozen = json!({"version":1,"mode":"full","frozen":{"catalog":"fixed","observations":["first","second"]}});
        save_immutable(root.path(), "frozen.json", &frozen).expect("save frozen evidence");
        save(root.path(), "acceptance.json", &json!({"complete":false}))
            .expect("save incomplete outcome");
        assert_eq!(
            read_frozen(root.path()).expect("read frozen evidence"),
            frozen
        );
        save(root.path(), "acceptance.json", &json!({"complete":true}))
            .expect("save completed outcome");
        assert_eq!(
            read_frozen(root.path()).expect("read frozen evidence"),
            frozen
        );
    }

    #[test]
    fn corrupt_and_oversized_frozen_observations_fail_explicitly() {
        let root = tempfile::tempdir().expect("fixture directory");
        std::fs::write(root.path().join("frozen.json"), b"not JSON").expect("corrupt fixture");
        assert_eq!(
            read_frozen(root.path()).expect_err("corrupt rejected").code,
            "integrity"
        );
        let file =
            std::fs::File::create(root.path().join("frozen.json")).expect("oversized fixture");
        file.set_len(MAX_MANIFEST_BYTES + 1)
            .expect("sparse fixture size");
        assert_eq!(
            read_frozen(root.path())
                .expect_err("oversized rejected")
                .code,
            "integrity"
        );
    }

    #[cfg(unix)]
    #[test]
    fn frozen_observation_symlinks_are_not_followed() {
        let root = tempfile::tempdir().expect("fixture directory");
        let original = root.path().join("original.json");
        std::fs::write(&original, b"{}").expect("source fixture");
        std::os::unix::fs::symlink(original, root.path().join("frozen.json"))
            .expect("symlink fixture");
        assert_eq!(
            read_frozen(root.path()).expect_err("symlink rejected").code,
            "integrity"
        );
    }
}
