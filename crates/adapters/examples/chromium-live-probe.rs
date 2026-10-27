//! Fixed-record evidence only; never a claim of full corpus/history completion.
use devres_adapters::{
    ChromiumCorpus,
    bulk::{BulkArtifact, BulkArtifactStore, BulkBroker, BulkConfig},
    chromium_processing,
    chromium_source::{self, ChromiumSource, Operation, SourceResponse},
};
use devres_domain::{Error, Result};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio_util::sync::CancellationToken;
#[path = "w3c_support/root.rs"]
mod root;
const MARKER: &[u8] = b"devres-chromium-live-v1\n";
fn unavailable() -> Error {
    Error::unavailable("Chromium live evidence unavailable.")
}
fn integrity() -> Error {
    Error::integrity("Invalid retained Chromium live evidence.")
}
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn safe_file(root: &Path, name: &str) -> Result<PathBuf> {
    let path = root.join(name);
    if let Ok(metadata) = std::fs::symlink_metadata(&path)
        && (!metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > 1024 * 1024)
    {
        return Err(integrity());
    }
    Ok(path)
}
fn persist(root: &Path, name: &str, value: &Value) -> Result<()> {
    let destination = safe_file(root, name)?;
    let stage = root.join(format!("{name}.stage-{}", std::process::id()));
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&stage)
        .map_err(|_| unavailable())?;
    serde_json::to_writer_pretty(&mut output, value).map_err(|_| unavailable())?;
    output
        .write_all(b"\n")
        .and_then(|()| output.sync_all())
        .map_err(|_| unavailable())?;
    std::fs::rename(stage, destination).map_err(|_| unavailable())?;
    std::fs::File::open(root)
        .and_then(|f| f.sync_all())
        .map_err(|_| unavailable())
}
fn counted_broker(root: &Path) -> Result<(Arc<BulkBroker>, usize)> {
    let path = safe_file(root, "attempt-count")?;
    let initial = match std::fs::read_to_string(path) {
        Ok(s) => s.trim().parse::<usize>().map_err(|_| integrity())?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        Err(_) => return Err(unavailable()),
    };
    let owned = root.to_owned();
    let broker = BulkBroker::new(BulkConfig::default())?
        .with_attempt_budget(20)?
        .with_attempt_observer(
            initial,
            Arc::new(move |count| {
                let destination = safe_file(&owned, "attempt-count")?;
                let stage = owned.join(format!("attempt-count.stage-{}", std::process::id()));
                let mut output = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&stage)
                    .map_err(|_| unavailable())?;
                writeln!(output, "{count}")
                    .and_then(|()| output.sync_all())
                    .map_err(|_| unavailable())?;
                std::fs::rename(stage, destination).map_err(|_| unavailable())?;
                std::fs::File::open(&owned)
                    .and_then(|f| f.sync_all())
                    .map_err(|_| unavailable())
            }),
        )?;
    Ok((Arc::new(broker), initial))
}
fn metadata(response: &SourceResponse) -> Value {
    json!({"source_url":response.source_url,"status":response.status,"bytes":response.bytes.len(),"body_hash":digest(&response.bytes),"observed_at":response.observed_at,"retry_at":response.retry_at})
}
async fn checked(
    source: &ChromiumSource,
    operation: &Operation,
    cancel: &CancellationToken,
    observations: &mut Vec<Value>,
) -> Result<SourceResponse> {
    let response = source.fetch(operation, cancel.clone()).await?;
    observations.push(metadata(&response));
    if response.status != 200 {
        return Err(Error::unavailable(
            "Fixed Chromium record did not return 200.",
        ));
    }
    Ok(response)
}
async fn selected_revision(
    source: &ChromiumSource,
    component: &str,
    cancel: &CancellationToken,
    observations: &mut Vec<Value>,
) -> Result<String> {
    let response = checked(
        source,
        &Operation::CurrentRef {
            component: component.into(),
        },
        cancel,
        observations,
    )
    .await?;
    let refs = chromium_source::parse_refs(component, &response.bytes)?;
    refs.get("HEAD")
        .or_else(|| refs.get("refs/heads/main"))
        .or_else(|| refs.get("refs/heads/master"))
        .cloned()
        .ok_or_else(|| Error::integrity("Fixed Chromium main revision unavailable."))
}
async fn directory(
    source: &ChromiumSource,
    component: &str,
    revision: &str,
    path: &str,
    cancel: &CancellationToken,
    observations: &mut Vec<Value>,
) -> Result<chromium_source::Directory> {
    let response = checked(
        source,
        &Operation::Tree {
            component: component.into(),
            revision: revision.into(),
            path: path.into(),
        },
        cancel,
        observations,
    )
    .await?;
    chromium_source::parse_tree(component, &response.bytes)
}
async fn blob(
    source: &ChromiumSource,
    component: &str,
    revision: &str,
    path: &str,
    oid: &str,
    cancel: &CancellationToken,
    observations: &mut Vec<Value>,
) -> Result<(Vec<u8>, Value)> {
    let response = checked(
        source,
        &Operation::Blob {
            component: component.into(),
            revision: revision.into(),
            path: path.into(),
        },
        cancel,
        observations,
    )
    .await?;
    let body = chromium_source::decode_blob(component, &response.bytes, oid)?;
    let evidence = json!({"path":path,"oid":oid,"source_url":response.source_url,"observed_at":response.observed_at,"decoded_sha256":digest(&body),"git_blob_verified":true});
    Ok((body, evidence))
}
fn license(component: &str, body: &[u8], source_url: &str) -> Result<Value> {
    let decision = ChromiumCorpus::qualify_license(component, body, source_url)?;
    if decision["decision"] != "approved" {
        return Err(Error::unavailable(
            "Fixed Chromium license remains unresolved; no body retained.",
        ));
    }
    Ok(decision)
}

async fn retained(
    artifacts: &BulkArtifactStore,
    path: &str,
    body: Vec<u8>,
    license: Value,
    evidence: Value,
    cancel: &CancellationToken,
) -> Result<Value> {
    let projection = chromium_processing::process_document(path, &body, cancel.clone())?;
    if projection.text.trim().is_empty() {
        return Err(Error::integrity(
            "Chromium fixed projection contains no text.",
        ));
    }
    let artifact = artifacts.capture_bytes(body, cancel.clone()).await?;
    Ok(
        json!({"path":path,"artifact":artifact,"license":license,"evidence":evidence,"processing":{"sections":projection.sections.len(),"symbols":projection.symbols.len(),"references":projection.references.len(),"gaps":projection.gaps}}),
    )
}
async fn src_record(
    source: &ChromiumSource,
    artifacts: &BulkArtifactStore,
    cancel: &CancellationToken,
    observations: &mut Vec<Value>,
) -> Result<Value> {
    let revision = selected_revision(source, "src", cancel, observations).await?;
    let root = directory(source, "src", &revision, "", cancel, observations).await?;
    let notice = root
        .entries
        .iter()
        .find(|e| e.name == "LICENSE" && e.mode == 0o100644)
        .ok_or_else(integrity)?;
    let (license_body, license_evidence) = blob(
        source,
        "src",
        &revision,
        "LICENSE",
        &notice.oid,
        cancel,
        observations,
    )
    .await?;
    let decision = license(
        "src",
        &license_body,
        license_evidence["source_url"]
            .as_str()
            .ok_or_else(integrity)?,
    )?;
    let docs = directory(source, "src", &revision, "docs", cancel, observations).await?;
    let readme = docs
        .entries
        .iter()
        .find(|e| e.name == "README.md" && e.mode == 0o100644)
        .ok_or_else(integrity)?;
    let (body, evidence) = blob(
        source,
        "src",
        &revision,
        "docs/README.md",
        &readme.oid,
        cancel,
        observations,
    )
    .await?;
    let notice_artifact = artifacts
        .capture_bytes(license_body, cancel.clone())
        .await?;
    let mut record = retained(
        artifacts,
        "docs/README.md",
        body,
        decision,
        evidence,
        cancel,
    )
    .await?;
    record["revision"] = json!(revision);
    record["license_artifact"] = json!(notice_artifact);
    record["license_evidence"] = license_evidence;
    Ok(record)
}
async fn chrome_record(
    source: &ChromiumSource,
    artifacts: &BulkArtifactStore,
    cancel: &CancellationToken,
    observations: &mut Vec<Value>,
) -> Result<Value> {
    let response = checked(
        source,
        &Operation::Page {
            path: "docs/devtools/overview".into(),
        },
        cancel,
        observations,
    )
    .await?;
    let decision = license("chrome", &response.bytes, &response.source_url)?;
    let evidence = metadata(&response);
    retained(
        artifacts,
        "docs/devtools/overview.html",
        response.bytes,
        decision,
        evidence,
        cancel,
    )
    .await
}
async fn site_record(
    source: &ChromiumSource,
    artifacts: &BulkArtifactStore,
    cancel: &CancellationToken,
    observations: &mut Vec<Value>,
) -> Result<Value> {
    let terms = checked(
        source,
        &Operation::SitePage {
            path: "Home".into(),
        },
        cancel,
        observations,
    )
    .await?;
    let decision = license("site", &terms.bytes, &terms.source_url)?;
    let revision = selected_revision(source, "site", cancel, observations).await?;
    let directory = directory(source, "site", &revision, "site/Home", cancel, observations).await?;
    let member = directory
        .entries
        .iter()
        .find(|e| e.name == "index.md" && e.mode == 0o100644)
        .ok_or_else(integrity)?;
    let (body, evidence) = blob(
        source,
        "site",
        &revision,
        "site/Home/index.md",
        &member.oid,
        cancel,
        observations,
    )
    .await?;
    let terms_evidence = metadata(&terms);
    let terms_artifact = artifacts.capture_bytes(terms.bytes, cancel.clone()).await?;
    let mut record = retained(
        artifacts,
        "site/Home/index.md",
        body,
        decision,
        evidence,
        cancel,
    )
    .await?;
    record["revision"] = json!(revision);
    record["license_artifact"] = json!(terms_artifact);
    record["license_evidence"] = terms_evidence;
    record["scope_gap"] = json!(
        "The live footer qualifies this current page; it does not establish every historical page's terms."
    );
    Ok(record)
}
async fn archive_record(
    source: &ChromiumSource,
    artifacts: &BulkArtifactStore,
    cancel: &CancellationToken,
    observations: &mut Vec<Value>,
) -> Result<Value> {
    let revision = selected_revision(source, "chrome-archive", cancel, observations).await?;
    let response = checked(
        source,
        &Operation::Commit {
            component: "chrome-archive".into(),
            revision: revision.clone(),
        },
        cancel,
        observations,
    )
    .await?;
    let commit = chromium_source::parse_commit("chrome-archive", &response.bytes)?;
    let directory = directory(
        source,
        "chrome-archive",
        &commit.tree,
        "",
        cancel,
        observations,
    )
    .await?;
    let notice = directory
        .entries
        .iter()
        .find(|e| e.name == "LICENSE" && e.mode == 0o100644)
        .ok_or_else(integrity)?;
    let readme = directory
        .entries
        .iter()
        .find(|e| e.name == "README.md" && e.mode == 0o100644)
        .ok_or_else(integrity)?;
    let (license_body, license_evidence) = blob(
        source,
        "chrome-archive",
        &commit.revision,
        "LICENSE",
        &notice.oid,
        cancel,
        observations,
    )
    .await?;
    let decision = license(
        "chrome-archive",
        &license_body,
        license_evidence["source_url"]
            .as_str()
            .ok_or_else(integrity)?,
    )?;
    let (body, evidence) = blob(
        source,
        "chrome-archive",
        &commit.revision,
        "README.md",
        &readme.oid,
        cancel,
        observations,
    )
    .await?;
    let notice_artifact = artifacts
        .capture_bytes(license_body, cancel.clone())
        .await?;
    let mut record = retained(artifacts, "README.md", body, decision, evidence, cancel).await?;
    record["revision"] = json!(commit.revision);
    record["license_artifact"] = json!(notice_artifact);
    record["license_evidence"] = license_evidence;
    record["history_gap"] = json!(
        "This archived source cannot reconstruct unexposed post-migration website revisions."
    );
    Ok(record)
}
async fn run(root: &Path) -> Result<Value> {
    let (broker, initial) = counted_broker(root)?;
    let source = ChromiumSource::new(broker.clone())?;
    let raw = root.join("raw");
    if let Ok(metadata) = std::fs::symlink_metadata(&raw)
        && (!metadata.is_dir() || metadata.file_type().is_symlink())
    {
        return Err(integrity());
    }
    std::fs::create_dir_all(&raw).map_err(|_| unavailable())?;
    let artifacts = BulkArtifactStore::new(raw, 64 * 1024 * 1024)?;
    let cancel = CancellationToken::new();
    let stop = cancel.clone();
    let signal = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            stop.cancel();
        }
    });
    let mut records = Vec::new();
    let mut observations = Vec::new();
    for component in ["src", "chrome", "site", "chrome-archive"] {
        let result = match component {
            "src" => src_record(&source, &artifacts, &cancel, &mut observations).await,
            "chrome" => chrome_record(&source, &artifacts, &cancel, &mut observations).await,
            "site" => site_record(&source, &artifacts, &cancel, &mut observations).await,
            _ => archive_record(&source, &artifacts, &cancel, &mut observations).await,
        };
        records.push(match result{Ok(record)=>json!({"component":component,"success":true,"record":record}),Err(error)=>json!({"component":component,"success":false,"code":error.code,"message":error.message})});
        persist(
            root,
            "live-progress.json",
            &json!({"records":records,"observations":observations,"attempts":broker.attempt_count(),"complete":false}),
        )?;
        if cancel.is_cancelled() {
            break;
        }
    }
    signal.abort();
    let core_pass = ["src", "chrome"].iter().all(|component| {
        records
            .iter()
            .any(|r| r["component"] == *component && r["success"] == true)
    });
    let all_pass = records.len() == 4 && records.iter().all(|r| r["success"] == true);
    Ok(
        json!({"version":1,"complete":all_pass,"primary_components_passed":core_pass,"all_named_components_passed":all_pass,"evidence":"bounded_provider_and_parser","whole_corpus":false,"full_history":false,"transport_acceptance":false,"attempt_limit_total":20,"attempts":broker.attempt_count()-initial,"attempts_before_invocation":initial,"budget_used":broker.attempt_count(),"records":records,"observations":observations,"coverage_gap":"Unexposed post-migration Chrome website revisions remain unavailable; bounded observations are not corpus acceptance."}),
    )
}
async fn accept(path: &Path) -> Result<Value> {
    let root = root::owned_root(path, MARKER)?;
    let lock_path = safe_file(&root, "live.lock")?;
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(lock_path)
        .map_err(|_| unavailable())?;
    fs2::FileExt::try_lock_exclusive(&lock)
        .map_err(|_| Error::capacity("Chromium live acceptance already owns this root."))?;
    let receipt_path = safe_file(&root, "live-receipt.json")?;
    if receipt_path.try_exists().map_err(|_| unavailable())? {
        return Err(Error::invalid(
            "Chromium live receipt already exists; use a new owned root.",
        ));
    }
    let receipt = run(&root).await?;
    persist(&root, "live-receipt.json", &receipt)?;
    Ok(receipt)
}
fn read_record(root: &Path, name: &str) -> Result<(Vec<u8>, Value)> {
    let path = safe_file(root, name)?;
    let bytes = std::fs::read(path).map_err(|_| unavailable())?;
    if bytes.len() > 1024 * 1024 {
        return Err(integrity());
    }
    let value = serde_json::from_slice(&bytes).map_err(|_| integrity())?;
    Ok((bytes, value))
}
async fn replay_body(
    artifacts: &BulkArtifactStore,
    descriptor: &Value,
    evidence: &Value,
    cancel: &CancellationToken,
) -> Result<Vec<u8>> {
    use tokio::io::AsyncReadExt as _;
    let artifact: BulkArtifact =
        serde_json::from_value(descriptor.clone()).map_err(|_| integrity())?;
    let verified = artifacts
        .verify(
            &artifact.body_hash,
            chromium_source::MAX_METADATA_BYTES as u64,
            cancel.clone(),
        )
        .await?;
    if artifact.body_hash != verified.body_hash || artifact.bytes != verified.bytes {
        return Err(integrity());
    }
    let mut body = Vec::new();
    artifacts
        .open(
            &artifact.body_hash,
            chromium_source::MAX_METADATA_BYTES as u64,
            cancel.clone(),
        )
        .await?
        .take(chromium_source::MAX_METADATA_BYTES as u64 + 1)
        .read_to_end(&mut body)
        .await
        .map_err(|_| unavailable())?;
    if body.len() as u64 != artifact.bytes {
        return Err(integrity());
    }
    let expected = evidence["decoded_sha256"]
        .as_str()
        .or_else(|| evidence["body_hash"].as_str())
        .ok_or_else(integrity)?;
    if digest(&body) != expected {
        return Err(integrity());
    }
    if evidence["git_blob_verified"] == true {
        let oid = evidence["oid"]
            .as_str()
            .filter(|oid| chromium_source::valid_oid(oid))
            .ok_or_else(integrity)?;
        if chromium_source::object_oid("blob", &body) != oid {
            return Err(integrity());
        }
    }
    Ok(body)
}
fn persist_immutable(root: &Path, name: &str, value: &Value) -> Result<()> {
    let destination = safe_file(root, name)?;
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|_| integrity())?;
    bytes.push(b'\n');
    if bytes.len() > 1024 * 1024 {
        return Err(integrity());
    }
    if destination.try_exists().map_err(|_| unavailable())? {
        return if std::fs::read(destination).map_err(|_| unavailable())? == bytes {
            Ok(())
        } else {
            Err(integrity())
        };
    }
    let stage = root.join(format!("{name}.stage-{}", std::process::id()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&stage)
        .map_err(|_| unavailable())?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| unavailable())?;
    drop(file);
    let linked = std::fs::hard_link(&stage, &destination);
    std::fs::remove_file(stage).map_err(|_| unavailable())?;
    match linked {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if std::fs::read(destination).map_err(|_| unavailable())? != bytes {
                return Err(integrity());
            }
        }
        Err(_) => return Err(unavailable()),
    }
    std::fs::File::open(root)
        .and_then(|f| f.sync_all())
        .map_err(|_| unavailable())
}
/// Re-evaluate retained fixed records through production policy without creating a
/// broker, renewing observations, or changing the original receipt/attempt count.
async fn replay(path: &Path) -> Result<Value> {
    let root = root::owned_root(path, MARKER)?;
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(safe_file(&root, "live.lock")?)
        .map_err(|_| unavailable())?;
    fs2::FileExt::try_lock_exclusive(&lock)
        .map_err(|_| Error::capacity("Chromium live acceptance already owns this root."))?;
    let (original_bytes, original) = read_record(&root, "live-receipt.json")?;
    if original["version"] != 1
        || original["complete"] != true
        || original["all_named_components_passed"] != true
    {
        return Err(integrity());
    }
    let attempts_path = safe_file(&root, "attempt-count")?;
    let attempts_before = std::fs::read(&attempts_path).map_err(|_| unavailable())?;
    let attempts = std::str::from_utf8(&attempts_before)
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .ok_or_else(integrity)?;
    if attempts > 20 || original["budget_used"].as_u64() != Some(attempts as u64) {
        return Err(integrity());
    }
    let raw = root.join("raw");
    let metadata = std::fs::symlink_metadata(&raw).map_err(|_| unavailable())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(integrity());
    }
    let artifacts = BulkArtifactStore::new(raw, 64 * 1024 * 1024)?;
    let cancel = CancellationToken::new();
    let originals = original["records"]
        .as_array()
        .filter(|records| records.len() == 4)
        .ok_or_else(integrity)?;
    let mut records = Vec::new();
    for component in ["src", "chrome", "site", "chrome-archive"] {
        let selected = originals
            .iter()
            .filter(|r| r["component"] == component && r["success"] == true)
            .collect::<Vec<_>>();
        if selected.len() != 1 {
            return Err(integrity());
        }
        let record = &selected[0]["record"];
        let body = replay_body(
            &artifacts,
            &record["artifact"],
            &record["evidence"],
            &cancel,
        )
        .await?;
        let (notice, notice_evidence) = if component == "chrome" {
            (body.clone(), record["evidence"].clone())
        } else {
            (
                replay_body(
                    &artifacts,
                    &record["license_artifact"],
                    &record["license_evidence"],
                    &cancel,
                )
                .await?,
                record["license_evidence"].clone(),
            )
        };
        let decision = license(
            component,
            &notice,
            notice_evidence["source_url"]
                .as_str()
                .ok_or_else(integrity)?,
        )?;
        let path = record["path"].as_str().ok_or_else(integrity)?;
        let projection = chromium_processing::process_document(path, &body, cancel.clone())?;
        if projection.text.trim().is_empty() {
            return Err(integrity());
        }
        records.push(json!({"component":component,"success":true,"path":path,"artifact":record["artifact"],"license":decision,"notice_evidence":notice_evidence,"source_evidence":record["evidence"],"processing":{"sections":projection.sections.len(),"symbols":projection.symbols.len(),"references":projection.references.len(),"gaps":projection.gaps}}));
    }
    if std::fs::read(&attempts_path).map_err(|_| unavailable())? != attempts_before
        || std::fs::read(root.join("live-receipt.json")).map_err(|_| unavailable())?
            != original_bytes
    {
        return Err(integrity());
    }
    let receipt = json!({"version":1,"complete":true,"all_named_components_passed":true,"evidence":"offline_retained_requalification","parent_receipt_sha256":digest(&original_bytes),"processor_version":chromium_processing::PROCESSOR_VERSION,"production_license_qualification":true,"fresh_network_evidence":false,"attempts":0,"budget_used":attempts,"original_observations_preserved":true,"whole_corpus":false,"full_history":false,"records":records});
    persist_immutable(
        &root,
        &format!(
            "live-replay-v{}.json",
            chromium_processing::PROCESSOR_VERSION
        ),
        &receipt,
    )?;
    Ok(receipt)
}

#[tokio::main]
async fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 3 || (args[1] != "--live" && args[1] != "--replay") {
        eprintln!("usage: chromium-live-probe --live|--replay OWNED_ROOT");
        std::process::exit(2);
    }
    let result = if args[1] == "--replay" {
        replay(Path::new(&args[2])).await
    } else {
        accept(Path::new(&args[2])).await
    };
    match result {
        Ok(receipt) => {
            println!("{}", receipt);
            if receipt["complete"] != true {
                std::process::exit(1);
            }
        }
        Err(error) => {
            eprintln!("{}: {}", error.code, error.message);
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn current_and_archived_license_terms_are_distinct() {
        let current = b"<footer>Except as otherwise noted, the content of this page is licensed under the <a href='https://creativecommons.org/licenses/by/4.0/'>Creative Commons Attribution 4.0 License</a>, and code samples are licensed under the <a href='https://www.apache.org/licenses/LICENSE-2.0'>Apache 2.0 License</a>.</footer>";
        assert_eq!(
            license(
                "chrome",
                current,
                "https://developer.chrome.com/docs/devtools/overview?hl=en"
            )
            .unwrap()["licenses"],
            json!(["CC-BY-4.0", "Apache-2.0"])
        );
        assert_eq!(license("chrome-archive", b"Except as otherwise noted, the content of this site is licensed under the Creative Commons Attribution-ShareAlike 4.0 International License, and code samples are licensed under the Apache 2.0 License.", "https://api.github.com/repos/GoogleChrome/developer.chrome.com/contents/LICENSE").unwrap()["licenses"],json!(["CC-BY-SA-4.0","Apache-2.0"]));
        assert!(
            license(
                "chrome",
                b"public page without notice",
                "https://developer.chrome.com/docs/a"
            )
            .is_err()
        );
        let spoof=b"<pre><code>Except as otherwise noted, the content of this page is licensed under the Creative Commons Attribution 4.0 License, and code samples are licensed under the Apache 2.0 License.</code></pre>";
        assert!(license("chrome", spoof, "https://developer.chrome.com/docs/a").is_err());
    }
    #[test]
    fn counters_refuse_symlinks_and_persist_before_attempts() {
        let temp = tempfile::tempdir_in("/tmp").unwrap();
        let root = temp.path();
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(root.join("owner-v1"), MARKER).unwrap();
        std::fs::set_permissions(
            root.join("owner-v1"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert_eq!(root::owned_root(root, MARKER).unwrap(), root);
        persist(root, "sample.json", &json!({"complete":false})).unwrap();
        let data: Value =
            serde_json::from_slice(&std::fs::read(root.join("sample.json")).unwrap()).unwrap();
        assert_eq!(data["complete"], false);
        std::os::unix::fs::symlink("other", root.join("attempt-count")).unwrap();
        assert!(counted_broker(root).is_err());
    }
    #[tokio::test]
    async fn replay_rejects_hash_oid_and_size_changes() {
        let temporary = tempfile::tempdir_in("/tmp").unwrap();
        let artifacts = BulkArtifactStore::new(temporary.path(), 64 * 1024 * 1024).unwrap();
        let body = b"# Synthetic retained public source\n";
        let artifact = artifacts
            .capture_bytes(body.to_vec(), CancellationToken::new())
            .await
            .unwrap();
        let descriptor = json!(artifact);
        let evidence = json!({"decoded_sha256":digest(body),"git_blob_verified":true,"oid":chromium_source::object_oid("blob",body)});
        assert_eq!(
            replay_body(
                &artifacts,
                &descriptor,
                &evidence,
                &CancellationToken::new()
            )
            .await
            .unwrap(),
            body
        );
        let mut wrong_oid = evidence.clone();
        wrong_oid["oid"] = json!("1".repeat(40));
        assert!(
            replay_body(
                &artifacts,
                &descriptor,
                &wrong_oid,
                &CancellationToken::new()
            )
            .await
            .is_err()
        );
        let mut wrong_size = descriptor.clone();
        wrong_size["bytes"] = json!(body.len() + 1);
        assert!(
            replay_body(
                &artifacts,
                &wrong_size,
                &evidence,
                &CancellationToken::new()
            )
            .await
            .is_err()
        );
        std::fs::write(temporary.path().join(&artifact.body_hash), b"corrupt").unwrap();
        assert!(
            replay_body(
                &artifacts,
                &descriptor,
                &evidence,
                &CancellationToken::new()
            )
            .await
            .is_err()
        );
    }
    #[test]
    fn immutable_replay_successor_never_replaces_previous_evidence() {
        let temporary = tempfile::tempdir_in("/tmp").unwrap();
        let record = json!({"complete":true,"attempts":0,"budget_used":15});
        persist_immutable(temporary.path(), "live-replay-v1.json", &record).unwrap();
        let retained = std::fs::read(temporary.path().join("live-replay-v1.json")).unwrap();
        persist_immutable(temporary.path(), "live-replay-v1.json", &record).unwrap();
        assert!(
            persist_immutable(
                temporary.path(),
                "live-replay-v1.json",
                &json!({"complete":false})
            )
            .is_err()
        );
        assert_eq!(
            std::fs::read(temporary.path().join("live-replay-v1.json")).unwrap(),
            retained
        );
    }
}
