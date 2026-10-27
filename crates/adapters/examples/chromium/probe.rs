//! Retained Chromium acceptance; frozen source selection never changes on resume.
#[path = "../support/root.rs"]
mod root;
use devres_adapters::{
    PgBlobStore,
    bulk::{BulkBroker, BulkConfig},
    chromium::ChromiumCorpus,
};
use devres_application::chromium::{ChromiumConfig, PROCESSOR_VERSION};
use devres_domain::{Error, Result};
use serde_json::{Value, json};
use std::{io::Write, path::Path, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
const MAX_MANIFEST_BYTES: u64 = 32 * 1024 * 1024;
fn storage_error() -> Error {
    Error::unavailable("Retained Chromium acceptance storage unavailable.")
}

fn save(root: &Path, name: &str, value: &Value) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|_| storage_error())?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(Error::capacity(
            "Chromium acceptance manifest exceeds its bound.",
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
            "Invalid Chromium acceptance frozen observation.",
        ));
    }
    let file = std::fs::File::open(path).map_err(|_| storage_error())?;
    serde_json::from_reader(file)
        .map_err(|_| Error::integrity("Invalid Chromium acceptance frozen observation."))
}

fn read_frozen(root: &Path) -> Result<Value> {
    read_manifest(root, "frozen.json")
}

// Link a fully synced stage without replacing an existing immutable destination.
fn save_immutable(root: &Path, name: &str, value: &Value) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|_| storage_error())?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(Error::capacity(
            "Chromium acceptance manifest exceeds its bound.",
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
                    "Immutable Chromium acceptance evidence differs.",
                ));
            }
        }
        Err(_) => return Err(storage_error()),
    }
    std::fs::File::open(root)
        .and_then(|file| file.sync_all())
        .map_err(|_| storage_error())
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    use fs2::FileExt as _;
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let (resume, full) = match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["--live", "current"] => (false, false),
        ["--live", "full"] => (false, true),
        ["--resume", "full"] => (true, true),
        _ => return Err("usage: chromium-probe --live current|full | --resume full".into()),
    };
    let root = root::owned_root(
        Path::new(&std::env::var("DEVRES_CHROMIUM_ACCEPTANCE_ROOT")?),
        b"devres-chromium-retained-acceptance-v1\n",
    )?;
    for child in [
        "blobs",
        "postgres",
        "runner.lock",
        "frozen.json",
        "acceptance.json",
    ] {
        if std::fs::symlink_metadata(root.join(child)).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err("Retained Chromium state must not be symlinked".into());
        }
    }
    let lock_path = root.join("runner.lock");
    if std::fs::symlink_metadata(&lock_path)
        .is_ok_and(|m| !m.is_file() || m.file_type().is_symlink())
    {
        return Err("Invalid Chromium runner lock".into());
    }
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(lock_path)?;
    lock.try_lock_exclusive()
        .map_err(|_| Error::unavailable("Retained Chromium runner already owns this root."))?;
    let store =
        Arc::new(PgBlobStore::connect(&std::env::var("DATABASE_URL")?, &root.join("blobs")).await?);
    let corpus = ChromiumCorpus::new(
        store,
        Arc::new(BulkBroker::new(BulkConfig::default())?),
        &root.join("blobs"),
        ChromiumConfig {
            enabled: false,
            ..Default::default()
        },
    )?;
    corpus.initialize_status().await?;
    let cancel = CancellationToken::new();
    let interrupted = cancel.clone();
    let signal = tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        interrupted.cancel();
    });
    let frozen = if resume {
        let manifest = read_frozen(&root)?;
        if manifest["version"] != 1
            || manifest["mode"] != "full"
            || manifest["processor_version"] != PROCESSOR_VERSION
        {
            return Err("Unsupported frozen Chromium observation".into());
        }
        manifest["frozen"].clone()
    } else {
        if root.join("frozen.json").exists() {
            return Err(
                "Frozen Chromium observation already exists; resume or use a new root".into(),
            );
        }
        let frozen = if full {
            corpus.freeze_observation(cancel.clone()).await?
        } else {
            corpus.freeze_current_observation(cancel.clone()).await?
        };
        save_immutable(
            &root,
            "frozen.json",
            &json!({"version":1,"mode":if full{"full"}else{"current"},"processor_version":PROCESSOR_VERSION,"frozen":frozen}),
        )?;
        frozen
    };
    if full {
        loop {
            if cancel.is_cancelled() {
                save(
                    &root,
                    "acceptance.json",
                    &json!({"complete":false,"interrupted":true,"processor_version":PROCESSOR_VERSION,"status":corpus.frozen_status(&frozen).await?}),
                )?;
                return Err(
                    "Chromium acceptance interrupted; retained evidence can be resumed".into(),
                );
            }
            match corpus.resume_frozen(&frozen, cancel.clone()).await {
                Ok(true) => break,
                Ok(false) => {}
                Err(error) => {
                    save(
                        &root,
                        "acceptance.json",
                        &json!({"complete":false,"failure_code":error.code,"processor_version":PROCESSOR_VERSION,"status":corpus.frozen_status(&frozen).await?}),
                    )?;
                    return Err(error.into());
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
    let status = corpus.frozen_status(&frozen).await?;
    let complete = status[if full {
        "frozen_observation_complete"
    } else {
        "current_observation_accounted"
    }]
    .as_bool()
    .unwrap_or(false);
    let receipt = json!({"version":1,"mode":if full{"full"}else{"current"},"processor_version":PROCESSOR_VERSION,"complete":complete,"status":status,"proof_boundary":"Retained frozen observation only; no production, hosted architecture or native client UI claim."});
    save(&root, "acceptance.json", &receipt)?;
    signal.abort();
    println!("{}", serde_json::to_string_pretty(&receipt)?);
    if !complete {
        return Err(
            "Chromium frozen observation remains incomplete; inspect retained acceptance.json"
                .into(),
        );
    }
    Ok(())
}
