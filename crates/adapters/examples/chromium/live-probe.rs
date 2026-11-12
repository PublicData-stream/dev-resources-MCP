//! Fixed-record evidence only; never a claim of full corpus/history completion.
use devres_adapters::{
    bulk::{BulkArtifact, BulkArtifactStore, BulkBroker, BulkConfig},
    chromium::ChromiumCorpus,
    chromium::processing as chromium_processing,
    chromium::source::{self as chromium_source, ChromiumSource, Operation, SourceResponse},
};
use devres_domain::{Error, Result};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio_util::sync::CancellationToken;
#[path = "../support/root.rs"]
mod root;
const MARKER: &[u8] = b"devres-chromium-live-v1\n";
const TOTAL_ATTEMPTS: usize = 20;

#[derive(Clone, Copy, PartialEq, Eq)]
enum DiagnosticKind {
    Validation,
    CommitDate,
}
impl DiagnosticKind {
    fn attempts(self) -> usize {
        if self == Self::Validation { 6 } else { 4 }
    }
    fn name(self) -> &'static str {
        if self == Self::Validation {
            "validation"
        } else {
            "commit-date"
        }
    }
}
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
        .mode(0o600)
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
    counted_broker_with_invocation_limit(root, None)
}
fn attempt_ceiling(initial: usize, invocation: Option<usize>) -> Result<usize> {
    if initial > TOTAL_ATTEMPTS || invocation.is_some_and(|limit| limit == 0 || limit > 6) {
        return Err(integrity());
    }
    Ok(invocation.map_or(TOTAL_ATTEMPTS, |limit| {
        initial.saturating_add(limit).min(TOTAL_ATTEMPTS)
    }))
}
fn counted_broker_with_invocation_limit(
    root: &Path,
    invocation: Option<usize>,
) -> Result<(Arc<BulkBroker>, usize)> {
    let path = safe_file(root, "attempt-count")?;
    let initial = match std::fs::read_to_string(path) {
        Ok(s) => s.trim().parse::<usize>().map_err(|_| integrity())?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        Err(_) => return Err(unavailable()),
    };
    let limit = attempt_ceiling(initial, invocation)?;
    let owned = root.to_owned();
    let broker = BulkBroker::new(BulkConfig::default())?
        .with_attempt_budget(limit)?
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
async fn selected_commit(
    source: &ChromiumSource,
    component: &str,
    revision: &str,
    cancel: &CancellationToken,
    observations: &mut Vec<Value>,
) -> Result<chromium_source::Commit> {
    let response = checked(
        source,
        &Operation::Commit {
            component: component.into(),
            revision: revision.into(),
        },
        cancel,
        observations,
    )
    .await?;
    let resolved = chromium_source::resolve_commit(
        component,
        revision,
        &response.bytes,
        cancel,
        |operation| async move { checked(source, &operation, cancel, observations).await },
    )
    .await?;
    Ok(resolved.commit)
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
    let commit = selected_commit(source, "src", &revision, cancel, observations).await?;
    let root = directory(source, "src", &revision, "", cancel, observations).await?;
    if root.id != commit.tree {
        return Err(integrity());
    }
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
    let _commit = selected_commit(source, "site", &revision, cancel, observations).await?;
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

fn validation_observation<T>(
    records: &mut Vec<Value>,
    component: &str,
    operation: &str,
    response: &SourceResponse,
    selected_oid: Option<&str>,
    result: Result<T>,
) -> Result<T> {
    if selected_oid.is_some_and(|oid| !chromium_source::valid_oid(oid)) {
        return Err(integrity());
    }
    let mut record = json!({
        "component":component,"operation":operation,"observed_at":response.observed_at,
        "http_status":response.status,"body_bytes":response.bytes.len(),
        "body_digest":format!("blake3:{}", blake3::hash(&response.bytes).to_hex()),
        "success":result.is_ok(),
        "selected_oid":selected_oid,
    });
    if let Err(error) = &result {
        record["failure"] = if response.status == 200 {
            chromium_source::validation_diagnostic(error)
        } else {
            json!({"reason":"http_status"})
        };
    }
    records.push(record);
    result
}

async fn diagnose_component(
    source: &ChromiumSource,
    component: &str,
    cancel: &CancellationToken,
    records: &mut Vec<Value>,
    kind: DiagnosticKind,
    broker: &BulkBroker,
    initial: usize,
) -> Result<()> {
    diagnose_component_with(component, records, kind, cancel, |operation| async move {
        if broker.attempt_count() >= TOTAL_ATTEMPTS
            || broker.attempt_count().saturating_sub(initial) >= kind.attempts()
        {
            return Err(Error::capacity(
                "Diagnostic invocation attempt budget exhausted.",
            ));
        }
        source.fetch(&operation, cancel.clone()).await
    })
    .await
}

async fn diagnose_component_with<F, Fut>(
    component: &str,
    records: &mut Vec<Value>,
    kind: DiagnosticKind,
    cancel: &CancellationToken,
    mut fetch: F,
) -> Result<()>
where
    F: FnMut(Operation) -> Fut,
    Fut: std::future::Future<Output = Result<SourceResponse>>,
{
    let response = fetch(Operation::CurrentRef {
        component: component.into(),
    })
    .await?;
    let parsed = if response.status == 200 {
        chromium_source::parse_refs(component, &response.bytes)
    } else {
        Err(Error::unavailable("Fixed Chromium refs unavailable."))
    };
    let selected = parsed
        .as_ref()
        .ok()
        .and_then(|refs| refs.get("refs/heads/main").or_else(|| refs.get("HEAD")))
        .cloned();
    let refs = validation_observation(
        records,
        component,
        "refs",
        &response,
        selected.as_deref(),
        parsed,
    )?;
    let revision = refs
        .get("refs/heads/main")
        .or_else(|| refs.get("HEAD"))
        .ok_or_else(integrity)?;
    let response = fetch(Operation::Commit {
        component: component.into(),
        revision: revision.clone(),
    })
    .await?;
    if kind == DiagnosticKind::CommitDate && response.status == 200 {
        let detail = commit_date_detail(&response.bytes, revision)?;
        let result = chromium_source::parse_commit(component, &response.bytes);
        let _ = validation_observation(
            records,
            component,
            "commit",
            &response,
            Some(revision),
            result,
        );
        records.last_mut().ok_or_else(integrity)?["commit_date"] = detail;
        return Ok(());
    }
    let resolved = if response.status == 200 {
        chromium_source::resolve_commit(component, revision, &response.bytes, cancel, &mut fetch)
            .await
    } else {
        Err(Error::unavailable("Fixed Chromium commit unavailable."))
    };
    let resolved = validation_observation(
        records,
        component,
        "commit",
        &response,
        Some(revision),
        resolved,
    )?;
    if let Some(proof) = resolved.timestamp_proof {
        records.last_mut().ok_or_else(integrity)?["timestamp_proof"] =
            serde_json::to_value(proof).map_err(|_| integrity())?;
    }
    let commit = resolved.commit;
    let response = fetch(Operation::Tree {
        component: component.into(),
        revision: revision.clone(),
        path: String::new(),
    })
    .await?;
    let parsed = if response.status == 200 {
        chromium_source::parse_tree(component, &response.bytes).and_then(|tree| {
            if tree.id == commit.tree {
                Ok(tree)
            } else {
                Err(integrity())
            }
        })
    } else {
        Err(Error::unavailable("Fixed Chromium root tree unavailable."))
    };
    validation_observation(
        records,
        component,
        "root_tree",
        &response,
        Some(&commit.tree),
        parsed,
    )?;
    Ok(())
}

/// Private operator-only scalar. Never copy commit messages, identities or response bodies.
fn commit_date_detail(bytes: &[u8], selected: &str) -> Result<Value> {
    if !chromium_source::valid_oid(selected) {
        return Err(integrity());
    }
    let data = chromium_source::json(bytes)?;
    if data["commit"].as_str() != Some(selected) {
        return Err(integrity());
    }
    let date = data["committer"]["time"].as_str().ok_or_else(integrity)?;
    if date.is_empty()
        || date.len() > 128
        || !date
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b" +-:.,/()".contains(&byte))
    {
        return Err(Error::integrity(
            "Commit date scalar exceeds its private diagnostic shape.",
        ));
    }
    let fields = date
        .split_ascii_whitespace()
        .map(str::len)
        .collect::<Vec<_>>();
    if fields.len() > 16 {
        return Err(integrity());
    }
    Ok(
        json!({"scalar":date,"bytes":date.len(),"token_lengths":fields,
        "shape":if date.as_bytes().get(4)==Some(&b'-') { "iso_candidate" } else { "gitiles_calendar_candidate" }}),
    )
}

async fn diagnose(root: &Path, kind: DiagnosticKind, component: Option<&str>) -> Result<Value> {
    let (broker, initial) = counted_broker_with_invocation_limit(root, Some(kind.attempts()))?;
    let source = ChromiumSource::new(broker.clone())?;
    let cancel = CancellationToken::new();
    let mut records = Vec::new();
    let mut components = Vec::new();
    let selected: &[&str] = match component {
        None => &["src", "site"],
        Some("src") => &["src"],
        Some("site") => &["site"],
        _ => return Err(integrity()),
    };
    for component in selected {
        let result = diagnose_component(
            &source,
            component,
            &cancel,
            &mut records,
            kind,
            &broker,
            initial,
        )
        .await;
        components.push(json!({"component":component,"success":result.is_ok(),"code":result.as_ref().err().map(|error| devres_application::collection::safe_code(&error.code))}));
        persist(
            root,
            &format!("{}-progress.json", kind.name()),
            &json!({"records":records,"components":components,"budget_used":broker.attempt_count()}),
        )?;
    }
    let used = broker.attempt_count();
    if used < initial || used > TOTAL_ATTEMPTS || used - initial > kind.attempts() {
        return Err(integrity());
    }
    Ok(
        json!({"version":1,"complete":components.iter().all(|component| component["success"]==true),
        "evidence":if kind == DiagnosticKind::Validation { "bounded_metadata_validation_diagnostic" } else { "bounded_private_commit_date_diagnostic" },"attempt_limit_total":TOTAL_ATTEMPTS,
        "attempt_limit_per_invocation":kind.attempts(),"attempts_before_invocation":initial,"selected_component":component,
        "attempts":broker.attempt_count()-initial,"budget_used":broker.attempt_count(),
        "records":records,"components":components,"retained_bodies":false,
        "whole_corpus":false,"full_history":false,"production_recovery":false}),
    )
}

async fn accept(
    path: &Path,
    diagnostic: Option<DiagnosticKind>,
    component: Option<&str>,
) -> Result<Value> {
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
    if diagnostic.is_none() && receipt_path.try_exists().map_err(|_| unavailable())? {
        return Err(Error::invalid(
            "Chromium live receipt already exists; use a new owned root.",
        ));
    }
    let receipt = if let Some(kind) = diagnostic {
        diagnose(&root, kind, component).await?
    } else {
        run(&root).await?
    };
    if let Some(kind) = diagnostic {
        persist_immutable(
            &root,
            &format!(
                "{}-receipt-{}.json",
                kind.name(),
                receipt["budget_used"].as_u64().ok_or_else(integrity)?
            ),
            &receipt,
        )?;
    } else {
        persist(&root, "live-receipt.json", &receipt)?;
    }
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
        .mode(0o600)
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
    if !matches!(args.len(), 3 | 5)
        || (args[1] != "--live"
            && args[1] != "--replay"
            && args[1] != "--diagnose-validation"
            && args[1] != "--diagnose-commit-date")
    {
        eprintln!(
            "usage: chromium-live-probe --live|--replay|--diagnose-validation|--diagnose-commit-date OWNED_ROOT [--component src|site]"
        );
        std::process::exit(2);
    }
    let component = if args.len() == 5 {
        if args[3] != "--component"
            || !matches!(
                args[1].to_str(),
                Some("--diagnose-validation" | "--diagnose-commit-date")
            )
            || !matches!(args[4].to_str(), Some("src" | "site"))
        {
            eprintln!("diagnostic component must be src or site");
            std::process::exit(2);
        }
        args[4].to_str()
    } else {
        None
    };
    let result = if args[1] == "--replay" {
        replay(Path::new(&args[2])).await
    } else {
        let diagnostic = if args[1] == "--diagnose-validation" {
            Some(DiagnosticKind::Validation)
        } else if args[1] == "--diagnose-commit-date" {
            Some(DiagnosticKind::CommitDate)
        } else {
            None
        };
        accept(Path::new(&args[2]), diagnostic, component).await
    };
    match result {
        Ok(receipt) => {
            if args[1] == "--diagnose-commit-date" {
                println!(
                    "{}",
                    json!({"complete":receipt["complete"],"evidence":receipt["evidence"],"attempts":receipt["attempts"],"budget_used":receipt["budget_used"],"private_date_details_retained":true})
                );
            } else {
                println!("{}", receipt);
            }
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
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn diagnostic_attempt_caps_preserve_total_and_invocation_budgets() {
        assert_eq!(attempt_ceiling(4, Some(6)).unwrap(), 10);
        assert_eq!(attempt_ceiling(4, Some(4)).unwrap(), 8);
        assert_eq!(attempt_ceiling(18, Some(6)).unwrap(), 20);
        assert_eq!(attempt_ceiling(20, Some(4)).unwrap(), 20);
        assert!(attempt_ceiling(21, Some(4)).is_err());
        assert!(attempt_ceiling(4, Some(0)).is_err());
        assert!(attempt_ceiling(4, Some(7)).is_err());
    }

    #[tokio::test]
    async fn scoped_validation_shares_raw_proof_and_finishes_with_four_fixed_operations() {
        let tree = chromium_source::object_oid("tree", b"");
        let raw = format!(
            "tree {tree}\nauthor Inert <inert.invalid> 0 +0000\ncommitter Private Synthetic <private-email.invalid> 1794502830 -0700\n\nprivate inert message\n"
        );
        let revision = chromium_source::object_oid("commit", raw.as_bytes());
        let refs = serde_json::to_vec(&json!({"value":revision})).unwrap();
        let commit=serde_json::to_vec(&json!({"commit":revision,"tree":tree,"parents":[],"committer":{"time":"Thu Nov 12 17:00:30 2026"}})).unwrap();
        let directory = serde_json::to_vec(&json!({"id":tree,"entries":[]})).unwrap();
        let proof = STANDARD.encode(raw).into_bytes();
        let operations = std::sync::Mutex::new(Vec::new());
        let mut records = Vec::new();
        diagnose_component_with(
            "src",
            &mut records,
            DiagnosticKind::Validation,
            &CancellationToken::new(),
            |operation| {
                operations.lock().unwrap().push(operation.clone());
                let bytes = match operation {
                    Operation::CurrentRef { component } => {
                        assert_eq!(component, "src");
                        refs.clone()
                    }
                    Operation::Commit {
                        revision: selected, ..
                    } => {
                        assert_eq!(selected, revision);
                        commit.clone()
                    }
                    Operation::RawCommit {
                        revision: selected, ..
                    } => {
                        assert_eq!(selected, revision);
                        proof.clone()
                    }
                    Operation::Tree {
                        revision: selected,
                        path,
                        ..
                    } => {
                        assert_eq!(selected, revision);
                        assert!(path.is_empty());
                        directory.clone()
                    }
                    _ => panic!("unexpected diagnostic operation"),
                };
                std::future::ready(Ok(SourceResponse {
                    status: 200,
                    bytes,
                    observed_at: 42,
                    source_url: "https://untrusted.invalid/private-source".into(),
                    next: None,
                    retry_at: None,
                }))
            },
        )
        .await
        .unwrap();
        assert_eq!(operations.lock().unwrap().len(), 4);
        assert_eq!(records.len(), 3);
        assert_eq!(records[1]["timestamp_proof"]["selected_oid"], revision);
        assert_eq!(records[1]["timestamp_proof"]["epoch"], 1_794_502_830i64);
        assert_eq!(records[2]["operation"], "root_tree");
        assert!(records.iter().all(|record| record["success"] == true));
        assert!(!serde_json::to_string(&records).unwrap().contains("private"));
    }

    #[tokio::test]
    async fn private_commit_date_probe_stops_before_tree_and_keeps_only_bounded_scalar() {
        let revision = "ab".repeat(20);
        let date = "Thu Nov 12 17:11:22 2026 +0000";
        let refs = serde_json::to_vec(&json!({"value":revision})).unwrap();
        let commit = serde_json::to_vec(&json!({"commit":revision,"tree":"cd".repeat(20),"parents":[],
            "committer":{"time":date,"name":"private-name","email":"private-email"},"message":"private-message"})).unwrap();
        let operations = std::sync::Mutex::new(Vec::new());
        let mut records = Vec::new();
        diagnose_component_with(
            "site",
            &mut records,
            DiagnosticKind::CommitDate,
            &CancellationToken::new(),
            |operation| {
                operations.lock().unwrap().push(operation.clone());
                let bytes = match operation {
                    Operation::CurrentRef { .. } => refs.clone(),
                    Operation::Commit {
                        revision: selected, ..
                    } => {
                        assert_eq!(selected, revision);
                        commit.clone()
                    }
                    _ => panic!("date diagnosis must not fetch tree or blob"),
                };
                std::future::ready(Ok(SourceResponse {
                    status: 200,
                    bytes,
                    observed_at: 42,
                    source_url: "https://untrusted.invalid/private-source".into(),
                    next: None,
                    retry_at: None,
                }))
            },
        )
        .await
        .unwrap();
        assert_eq!(operations.lock().unwrap().len(), 2);
        assert_eq!(records[1]["commit_date"]["scalar"], date);
        assert_eq!(records[1]["selected_oid"], revision);
        assert!(!serde_json::to_string(&records).unwrap().contains("private"));
        let malicious = serde_json::to_vec(&json!({"commit":revision,"committer":{"time":"<script>arbitrary source text</script>"}})).unwrap();
        assert!(commit_date_detail(&malicious, &revision).is_err());
        assert!(commit_date_detail(&commit, &"ff".repeat(20)).is_err());
    }
    #[tokio::test]
    async fn validation_diagnostic_stops_at_exact_failed_operation_without_retaining_text() {
        let revision = "56".repeat(20);
        let commit = serde_json::to_vec(
            &json!({"commit":revision,"tree":"78".repeat(20),"parents":[],
            "committer":{"time":"private-invalid-date"},"message":"unqualified-private-body"}),
        )
        .unwrap();
        let refs = serde_json::to_vec(&json!({"value":revision})).unwrap();
        let operations = std::sync::Mutex::new(Vec::new());
        let mut records = Vec::new();
        let error = diagnose_component_with(
            "src",
            &mut records,
            DiagnosticKind::Validation,
            &CancellationToken::new(),
            |operation| {
                operations.lock().unwrap().push(operation.clone());
                let bytes = match operation {
                    Operation::CurrentRef { component } => {
                        assert_eq!(component, "src");
                        refs.clone()
                    }
                    Operation::Commit {
                        component,
                        revision: selected,
                    } => {
                        assert_eq!(component, "src");
                        assert_eq!(selected, revision);
                        commit.clone()
                    }
                    _ => panic!("diagnosis fetched beyond the rejected commit"),
                };
                std::future::ready(Ok(SourceResponse {
                    status: 200,
                    bytes,
                    observed_at: 42,
                    source_url: "https://untrusted.invalid/private-path".into(),
                    next: None,
                    retry_at: None,
                }))
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, "integrity");
        assert_eq!(operations.lock().unwrap().len(), 2);
        assert_eq!(records.len(), 2);
        assert_eq!(records[1]["operation"], "commit");
        assert_eq!(records[1]["selected_oid"], revision);
        assert_eq!(records[1]["failure"]["reason"], "commit_date");
        assert!(
            records[1]["body_digest"]
                .as_str()
                .unwrap()
                .starts_with("blake3:")
        );
        assert!(!serde_json::to_string(&records).unwrap().contains("private"));
        assert!(
            records
                .iter()
                .all(|record| record.get("source_url").is_none())
        );
    }
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
        std::fs::write(temporary.path().join(&artifact.relative_path), b"corrupt").unwrap();
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
