//! Explicit retained WHATWG acceptance; source observations are frozen before backfill.
use devres_adapters::{
    PgBlobStore, WhatwgCorpus,
    bulk::{BulkBroker, BulkConfig},
    whatwg_research::WhatwgResearch,
};
use devres_application::whatwg::WhatwgConfig;
use devres_domain::{Error, Result};
use serde_json::{Value, json};
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

fn read_frozen(root: &Path) -> Result<Value> {
    let path = root.join("frozen.json");
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

async fn accept(root: &Path, live: bool, full: bool, cancel: CancellationToken) -> Result<()> {
    let mode = if full { "full" } else { "current" };
    let blobs = std::fs::canonicalize(required_env("BLOB_DIR")?).map_err(|_| storage_error())?;
    if blobs != root.join("blobs") {
        return Err(Error::invalid(
            "Acceptance blobs must use the owned retained directory.",
        ));
    }
    headroom(root)?;
    let store = Arc::new(PgBlobStore::connect(&required_env("DATABASE_URL")?, &blobs).await?);
    let offline = Arc::new(AtomicBool::new(!live));
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
    let envelope = if live {
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
        save(root, "frozen.json", &envelope)?;
        envelope
    } else {
        let envelope = read_frozen(root)?;
        if envelope["version"] != 1 || envelope["mode"] != "full" || !envelope["frozen"].is_object()
        {
            return Err(Error::integrity(
                "Full resume requires a frozen full observation.",
            ));
        }
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
    let evidence = json!({
        "version":1,"stage":if complete {"complete"} else {"incomplete"},
        "complete":complete,"mode":mode,"attempts_this_invocation":broker.attempt_count(),
        "verification":outcome,
    });
    save(root, "acceptance.json", &evidence)?;
    let mut aggregate = json!({"stage":evidence["stage"],"mode":mode,"complete":complete,"attempts_this_invocation":broker.attempt_count()});
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
        .call("whatwg_catalog_search", json!({"view":view.id,"limit":100}))
        .await?;
    let catalog_total = catalog["total"].as_u64().ok_or_else(storage_error)?;
    if catalog_total != view.snapshots.len() as u64 || view.snapshots.is_empty() {
        return Err(Error::integrity("WHATWG acceptance view is incomplete."));
    }
    let selected = json!({"standard":"dom","view":view.id,"limit":1024});
    let text = research.call("whatwg_get", selected.clone()).await?;
    if text["page"]["text"].as_str().is_none_or(str::is_empty) {
        return Err(Error::integrity("WHATWG acceptance text is empty."));
    }
    let uri = text["resource_uri"].as_str().ok_or_else(storage_error)?;
    research.read_resource(uri).await?;
    let mut bytes_input = selected;
    bytes_input["representation"] = json!("bytes");
    let bytes = research.call("whatwg_get", bytes_input).await?;
    if bytes["page"]["total_bytes"].as_u64().unwrap_or(0) == 0 {
        return Err(Error::integrity("WHATWG acceptance raw evidence is empty."));
    }
    let search = research
        .call(
            "whatwg_search",
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
            "whatwg_symbol_search",
            json!({"standard":"dom","view":view.id,"kind":"idl","name":"EventTarget","limit":2}),
        )
        .await?;
    let symbol = symbols["items"]
        .as_array()
        .and_then(|items| items.first())
        .ok_or_else(|| Error::integrity("WHATWG acceptance IDL declaration is absent."))?;
    let symbol_uri = symbol["resource_uri"].as_str().ok_or_else(storage_error)?;
    research.read_resource(symbol_uri).await?;
    let history = research
        .call("whatwg_history", json!({"standard":"dom","limit":2}))
        .await?;
    if history["items"].as_array().is_none_or(Vec::is_empty) {
        return Err(Error::integrity("WHATWG acceptance history is empty."));
    }
    Ok(
        json!({"view":view.id,"catalog_standards":catalog_total,"default_standards":view.snapshots.len(),"text":true,"raw_bytes":true,"text_resource":true,"search":true,"idl_symbol_resource":true,"history":true,"transport":"local_adapter"}),
    )
}

#[tokio::main]
async fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let selection = match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["--live", "full"] => Some((true, true)),
        ["--live", "current"] => Some((true, false)),
        ["--resume", "full"] => Some((false, true)),
        _ => None,
    };
    let Some((live, full)) = selection else {
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
    if let Err(error) = accept(&root, live, full, cancel.clone()).await {
        let evidence = json!({"version":1,"stage":if cancel.is_cancelled(){"paused"}else{"failed"},"complete":false,"mode":if full{"full"}else{"current"},"error_code":error.code});
        // Keep any detailed incomplete verification already emitted by accept().
        let _ = save(&root, "last-failure.json", &evidence);
        report(&evidence);
        std::process::exit(if cancel.is_cancelled() { 130 } else { 1 });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_observation_roundtrips_and_persists_across_later_outcomes() {
        let root = tempfile::tempdir().expect("fixture directory");
        let frozen = json!({"version":1,"mode":"full","frozen":{"catalog":"fixed","observations":["first","second"]}});
        save(root.path(), "frozen.json", &frozen).expect("save frozen evidence");
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
