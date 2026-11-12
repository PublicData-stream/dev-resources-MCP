//! Fixed-record provider evidence, distinct from full corpus and transport acceptance.
use devres_adapters::{
    bulk::{BulkArtifactStore, BulkBroker, BulkConfig, BulkRequest, BulkSource, GitOperation},
    integrity,
    w3c::catalog::{self as w3c_catalog, ApiOperation},
    w3c::git::Repo,
    w3c::processing as w3c_processing,
};
use devres_application::w3c::Standard;
use devres_domain::{Error, Result, Validators};
use futures::StreamExt;
use serde_json::{Value, json};
use std::{path::Path, sync::Arc, time::Duration};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
#[path = "../support/root.rs"]
mod root;

async fn fetch(
    broker: &BulkBroker,
    source: BulkSource,
    cancel: &CancellationToken,
) -> Result<Vec<u8>> {
    let response = broker
        .open(
            BulkRequest {
                source,
                validators: Validators::default(),
                max_bytes: 16 * 1024 * 1024,
                deadline: Instant::now() + Duration::from_secs(90),
                body: Vec::new(),
            },
            cancel.clone(),
        )
        .await?;
    if response.status != 200 {
        return Err(Error::unavailable("Fixed W3C record did not return 200."));
    }
    let mut bytes = Vec::new();
    let mut stream = response.stream;
    while let Some(chunk) = stream.next().await {
        bytes.extend(chunk?);
    }
    Ok(bytes)
}

fn counted_broker(root: &Path, counter_name: &str) -> Result<(BulkBroker, usize)> {
    let initial_attempts = match std::fs::read_to_string(root.join(counter_name)) {
        Ok(value) => value
            .trim()
            .parse::<usize>()
            .map_err(|_| Error::integrity("Invalid retained live attempt count."))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(_) => return Err(Error::unavailable("Live attempt accounting unavailable.")),
    };
    let accounting_root = root.to_path_buf();
    let counter_name = counter_name.to_owned();
    let broker = BulkBroker::new(BulkConfig::default())?
        .with_attempt_budget(20)?
        .with_attempt_observer(
            initial_attempts,
            Arc::new(move |count| {
                use std::io::Write;
                let stage =
                    accounting_root.join(format!("{counter_name}.stage-{}", std::process::id()));
                let mut output = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&stage)
                    .map_err(|_| Error::unavailable("Live attempt accounting unavailable."))?;
                writeln!(output, "{count}")
                    .and_then(|()| output.sync_all())
                    .map_err(|_| Error::unavailable("Live attempt accounting unavailable."))?;
                std::fs::rename(stage, accounting_root.join(&counter_name))
                    .map_err(|_| Error::unavailable("Live attempt accounting unavailable."))?;
                std::fs::File::open(&accounting_root)
                    .and_then(|file| file.sync_all())
                    .map_err(|_| Error::unavailable("Live attempt accounting unavailable."))
            }),
        )?;
    Ok((broker, initial_attempts))
}

fn css_processing(body: &[u8], cancel: &CancellationToken) -> Result<Value> {
    let processed = w3c_processing::process_document("index.html", body, cancel.clone())?;
    if processed.sections.is_empty() || !processed.text.to_ascii_lowercase().contains("color") {
        return Err(Error::integrity(
            "W3C live text projection has no expected content.",
        ));
    }
    let mapping = w3c_catalog::publication_metadata(body, cancel)?;
    let expected = Repo::new("w3c/csswg-drafts")?;
    if !mapping.repositories.iter().any(|value| {
        w3c_catalog::repository_mapping(value).is_ok_and(|(repository, _)| repository == expected)
    }) {
        return Err(Error::integrity("W3C live source mapping is absent."));
    }
    Ok(
        json!({"sections":processed.sections.len(),"symbols":processed.symbols.len(),"references":processed.references.len(),"gaps":processed.gaps,"source_mapping":mapping.repositories}),
    )
}

fn catalog_page_evidence(bytes: &[u8], observed_at: i64) -> Result<Value> {
    let catalog = w3c_catalog::parse_page(bytes, observed_at)?;
    let dotted: Vec<_> = catalog
        .standards
        .iter()
        .filter(|standard| standard.id.contains('.'))
        .map(|standard| standard.id.as_str())
        .collect();
    if dotted.is_empty() {
        return Err(Error::integrity(
            "Fixed W3C catalog page has no dotted specification identity.",
        ));
    }
    Ok(
        json!({"source_url":ApiOperation::Catalog{page:1}.url()?,"page":1,
        "observed_at":observed_at,"catalog":catalog.id,"standards":catalog.standards.len(),
        "dotted_shortnames":dotted,"has_next":w3c_catalog::page_has_next(bytes)?,"whole_catalog":false}),
    )
}

async fn retained_css(
    root: &Path,
    artifacts: &BulkArtifactStore,
    cancel: &CancellationToken,
) -> Result<Option<Value>> {
    use tokio::io::AsyncReadExt;
    // An earlier preflight can identify a body subsequently admitted into this
    // same owned archive. Replay that exact licensed body without claiming freshness.
    let mut candidates = Vec::new();
    for entry in std::fs::read_dir(root)
        .map_err(|_| Error::unavailable("Retained live evidence unavailable."))?
    {
        let entry = entry.map_err(|_| Error::unavailable("Retained live evidence unavailable."))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("license-preflight-") && name.ends_with(".json") {
            let metadata = entry
                .file_type()
                .map_err(|_| Error::unavailable("Retained live evidence unavailable."))?;
            if !metadata.is_file() || metadata.is_symlink() {
                return Err(Error::integrity("Invalid retained live metadata."));
            }
            candidates.push(entry.path());
            if candidates.len() > 20 {
                return Err(Error::capacity("Retained live metadata exceeds bounds."));
            }
        }
    }
    candidates.sort();
    for path in candidates.into_iter().rev() {
        if std::fs::metadata(&path)
            .map_err(|_| Error::unavailable("Retained live metadata unavailable."))?
            .len()
            > 64 * 1024
        {
            return Err(Error::capacity("Retained live metadata exceeds bounds."));
        }
        let bytes = std::fs::read(&path)
            .map_err(|_| Error::unavailable("Retained live metadata unavailable."))?;
        if bytes.len() > 64 * 1024 {
            return Err(Error::capacity("Retained live metadata exceeds bounds."));
        }
        let observation: Value = serde_json::from_slice(&bytes)
            .map_err(|_| Error::integrity("Invalid retained live metadata."))?;
        let hash = observation["body_hash"]
            .as_str()
            .filter(|hash| integrity::valid_hash(hash))
            .ok_or_else(|| Error::integrity("Invalid retained live body identity."))?;
        let relative_path = integrity::relative_path(hash)?;
        let raw = root.join(&relative_path);
        if !raw
            .try_exists()
            .map_err(|_| Error::unavailable("Retained live body unavailable."))?
        {
            continue;
        }
        let source = observation["source_url"]
            .as_str()
            .ok_or_else(|| Error::integrity("Retained live source identity missing."))?;
        let uri = url::Url::parse(source)
            .map_err(|_| Error::integrity("Invalid retained live source identity."))?;
        if uri.host_str() != Some("www.w3.org")
            || !uri.path().starts_with("/TR/")
            || !uri.path().contains("-css-color-4-")
        {
            return Err(Error::integrity(
                "Retained live source is not the fixed CSS record.",
            ));
        }
        let standard = Standard {
            id: "css-color-4".into(),
            title: "CSS Color Module Level 4".into(),
            url: source.into(),
            repository: String::new(),
            metadata: json!({"publication_url":source}),
        };
        let publication = w3c_catalog::current_publication(&standard)?;
        let mut body = Vec::new();
        artifacts
            .open(hash, 16 * 1024 * 1024, cancel.clone())
            .await?
            .take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut body)
            .await
            .map_err(|_| Error::unavailable("Retained live body unavailable."))?;
        if observation["bytes"].as_u64() != Some(body.len() as u64) {
            return Err(Error::integrity(
                "Retained live body differs from its preflight.",
            ));
        }
        integrity::verify(hash, &body)?;
        if !hash.starts_with("blake3:") {
            // Legacy replay requires the same independent BLAKE3 evidence as
            // ordinary retained reads, including the exact bytes just read.
            integrity::verify_legacy_digest(&raw, &integrity::hash(&body), body.len() as u64)?;
        }
        let license = w3c_catalog::publication_license(&publication, &body);
        if license["decision"] != "approved" {
            return Err(Error::unavailable(
                "Retained live body license remains unresolved.",
            ));
        }
        let observed_at = std::fs::metadata(&raw)
            .and_then(|metadata| metadata.modified())
            .map_err(|_| Error::unavailable("Retained live observation time unavailable."))?
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error::integrity("Invalid retained observation time."))?
            .as_secs();
        return Ok(Some(
            json!({"specification":"css-color-4","source_url":source,"capture_file_mtime":observed_at,"upstream_validated_at":null,"license":license,
            "artifact":{"body_hash":hash,"bytes":body.len(),"relative_path":relative_path},"processing":css_processing(&body,cancel)?,
            "replay":{"kind":"licensed_capture_reprocessed","preflight_metadata":path.file_name().and_then(|name|name.to_str()),"preflight_hash":devres_adapters::w3c::inventory::digest(&bytes),"original_capture_reused":true,"upstream_validation_time_available":false,"api_response_bytes_retained":false,"latest_metadata_revalidated":false}}),
        ));
    }
    Ok(None)
}

async fn run(root: &Path) -> Result<Value> {
    let root = root::owned_root(root, b"devres-w3c-live-v1\n")?;
    let (broker, initial_attempts) = counted_broker(&root, "attempt-count")?;
    let artifacts = BulkArtifactStore::new(&root, 64 * 1024 * 1024)?;
    let cancel = CancellationToken::new();
    let signal = cancel.clone();
    let task = tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        signal.cancel();
    });
    let catalog_bytes = fetch(
        &broker,
        BulkSource::W3cApi(ApiOperation::Catalog { page: 1 }),
        &cancel,
    )
    .await?;
    let catalog_artifact = artifacts
        .capture_bytes(catalog_bytes.clone(), cancel.clone())
        .await?;
    let catalog_observation = devres_domain::unix_now();
    let mut catalog_page = catalog_page_evidence(&catalog_bytes, catalog_observation)?;
    catalog_page["artifact"] = json!(catalog_artifact);
    let mut records = Vec::new();
    for shortname in ["css-color-4", "2dcontext"] {
        if shortname == "css-color-4"
            && let Some(record) = retained_css(&root, &artifacts, &cancel).await?
        {
            records.push(record);
            continue;
        }
        let metadata = fetch(
            &broker,
            BulkSource::W3cApi(ApiOperation::Specification {
                shortname: shortname.into(),
            }),
            &cancel,
        )
        .await?;
        let data: Value = serde_json::from_slice(&metadata)
            .map_err(|_| Error::integrity("Invalid fixed W3C metadata."))?;
        let version = data["_links"]["latest-version"]["href"]
            .as_str()
            .and_then(|v| v.rsplit('/').next())
            .ok_or_else(|| Error::integrity("Fixed W3C record has no edition."))?;
        let edition_bytes = fetch(
            &broker,
            BulkSource::W3cApi(ApiOperation::Version {
                shortname: shortname.into(),
                version: version.into(),
            }),
            &cancel,
        )
        .await?;
        let edition: Value = serde_json::from_slice(&edition_bytes)
            .map_err(|_| Error::integrity("Invalid W3C edition metadata."))?;
        if shortname == "2dcontext" && edition["status"] != "Retired" {
            return Err(Error::integrity("Retired W3C fixture changed status."));
        }
        let mut record = json!({"specification":shortname,"metadata":data,"edition":edition,"observed_at":devres_domain::unix_now()});
        if shortname == "css-color-4" {
            let uri = edition["uri"]
                .as_str()
                .ok_or_else(|| Error::integrity("W3C dated publication missing."))?;
            let standard = Standard {
                id: shortname.into(),
                title: data["title"].as_str().unwrap_or(shortname).into(),
                url: uri.into(),
                repository: String::new(),
                metadata: json!({"publication_url":uri}),
            };
            let publication = w3c_catalog::current_publication(&standard)?;
            let body = fetch(
                &broker,
                BulkSource::W3cPublication(publication.clone()),
                &cancel,
            )
            .await?;
            let license = w3c_catalog::publication_license(&publication, &body);
            record["license"] = license.clone();
            if license["decision"] != "approved" {
                use std::io::Write;
                let metadata = w3c_catalog::publication_metadata(&body, &cancel).ok();
                let projection =
                    w3c_processing::process_document("index.html", &body, cancel.clone()).ok();
                let diagnostic = json!({"source_url":publication.as_str(),"body_hash":devres_adapters::w3c::inventory::digest(&body),"bytes":body.len(),"license":license,
                    "title":projection.as_ref().map(|document|&document.title),"processing_gaps":projection.as_ref().map(|document|&document.gaps),
                    "license_links":metadata.as_ref().map(|metadata|metadata.links.iter().filter(|link|link.contains("copyright")||link.contains("license")).take(20).collect::<Vec<_>>())});
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(root.join(format!("license-preflight-{}.json", broker.attempt_count())))
                    .map_err(|_| {
                        Error::unavailable("Live preflight metadata persistence failed.")
                    })?;
                serde_json::to_writer_pretty(&mut file, &diagnostic).map_err(|_| {
                    Error::unavailable("Live preflight metadata persistence failed.")
                })?;
                file.write_all(b"\n")
                    .and_then(|()| file.sync_all())
                    .map_err(|_| {
                        Error::unavailable("Live preflight metadata persistence failed.")
                    })?;
                return Err(Error::unavailable(
                    "W3C live publication license remains unresolved; no body retained.",
                ));
            }
            let artifact = artifacts
                .capture_bytes(body.clone(), cancel.clone())
                .await?;
            record["artifact"] = json!(artifact);
            record["processing"] = css_processing(&body, &cancel)?;
        }
        records.push(record);
    }
    // Advertisement is metadata only; this does not claim licensed Git pack intake.
    // W3C and GitHub have separate provider attempt receipts. The sequential
    // pause also preserves the W3C family pacing across the two brokers.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let (github_broker, initial_github_attempts) = counted_broker(&root, "github-attempt-count")?;
    let advertisement = fetch(
        &github_broker,
        BulkSource::W3cGit {
            repository: Repo::new("w3c/csswg-drafts")?,
            operation: GitOperation::Advertisement,
        },
        &cancel,
    )
    .await?;
    if !advertisement.windows(15).any(|w| w == b"git-upload-pack") {
        return Err(Error::integrity("W3C Git advertisement is invalid."));
    }
    task.abort();
    Ok(
        json!({"version":1,"stage":"complete","complete":true,"evidence":"bounded_provider_and_parser","whole_corpus":false,"transport_acceptance":false,"attempts":broker.attempt_count()-initial_attempts+github_broker.attempt_count()-initial_github_attempts,"attempts_before_invocation":{"w3c":initial_attempts,"github":initial_github_attempts},"budget_used":{"w3c":broker.attempt_count(),"github":github_broker.attempt_count()},"attempt_limit_per_provider":20,"git_advertisement_bytes":advertisement.len(),"catalog_page":catalog_page,"records":records}),
    )
}

fn live_lock(root: &Path) -> Result<std::fs::File> {
    let path = root.join("live.lock");
    if let Ok(metadata) = std::fs::symlink_metadata(&path)
        && (!metadata.is_file() || metadata.file_type().is_symlink())
    {
        return Err(Error::integrity("Invalid retained live lock."));
    }
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .map_err(|_| Error::unavailable("Live acceptance lock unavailable."))?;
    fs2::FileExt::try_lock_exclusive(&lock)
        .map_err(|_| Error::capacity("Live acceptance is already running for this directory."))?;
    Ok(lock)
}

fn catalog_page_number(value: &str) -> Result<u32> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::invalid(
            "Catalog diagnosis page must be an integer from 1 through 1000.",
        ));
    }
    value
        .parse::<u32>()
        .ok()
        .filter(|page| (1..=1000).contains(page))
        .ok_or_else(|| {
            Error::invalid("Catalog diagnosis page must be an integer from 1 through 1000.")
        })
}

async fn fetch_catalog_page(
    broker: &BulkBroker,
    page: u32,
    cancel: &CancellationToken,
) -> Result<Vec<u8>> {
    const MAX_BYTES: usize = 8 * 1024 * 1024;
    let deadline = Instant::now() + Duration::from_secs(90);
    let work = async {
        let response = broker
            .open(
                BulkRequest {
                    source: BulkSource::W3cApi(ApiOperation::Catalog { page }),
                    validators: Validators::default(),
                    max_bytes: MAX_BYTES as u64,
                    deadline,
                    body: Vec::new(),
                },
                cancel.clone(),
            )
            .await?;
        if response.status != 200 {
            return Err(devres_application::collection::http_failure(
                Error::unavailable("Catalog diagnosis request did not return 200."),
                devres_application::collection::Phase::CatalogAcquisition,
                response.status,
            ));
        }
        let mut bytes = Vec::new();
        let mut stream = response.stream;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            if bytes.len().saturating_add(chunk.len()) > MAX_BYTES {
                return Err(Error::capacity("Catalog diagnosis body exceeds its bound."));
            }
            bytes.extend(chunk);
        }
        Ok(bytes)
    };
    tokio::select! { biased;
        _ = cancel.cancelled() => Err(Error::new("cancelled", "Catalog diagnosis canceled.")),
        result = tokio::time::timeout_at(deadline, work) => result
            .map_err(|_| Error::capacity("Catalog diagnosis deadline exceeded."))?,
    }
}

fn write_catalog_receipt(root: &Path, name: &str, receipt: &Value) -> Result<()> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(root.join(name))
        .map_err(|_| Error::unavailable("Catalog diagnosis receipt unavailable."))?;
    let bytes = serde_json::to_vec_pretty(receipt)
        .map_err(|_| Error::integrity("Catalog diagnosis receipt encoding failed."))?;
    if bytes.len() > 64 * 1024 {
        return Err(Error::capacity(
            "Catalog diagnosis receipt exceeds its bound.",
        ));
    }
    file.write_all(&bytes)
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .map_err(|_| Error::unavailable("Catalog diagnosis receipt unavailable."))?;
    std::fs::File::open(root)
        .and_then(|file| file.sync_all())
        .map_err(|_| Error::unavailable("Catalog diagnosis receipt unavailable."))
}

async fn retain_catalog_diagnosis(
    root: &Path,
    page: u32,
    bytes: Vec<u8>,
    observed_at: i64,
    attempts_before: usize,
    attempts_after: usize,
    cancel: &CancellationToken,
) -> Result<Value> {
    if !(1..=1000).contains(&page) || bytes.len() > 8 * 1024 * 1024 {
        return Err(Error::invalid("Invalid bounded catalog diagnosis input."));
    }
    let artifacts = BulkArtifactStore::new(root, 64 * 1024 * 1024)?;
    let validation = w3c_catalog::page_validation_diagnosis(&bytes, observed_at);
    let artifact = artifacts.capture_bytes(bytes, cancel.clone()).await?;
    if !artifact.body_hash.starts_with("blake3:")
        || artifacts
            .verify(&artifact.body_hash, 8 * 1024 * 1024, cancel.clone())
            .await?
            != artifact
    {
        return Err(Error::integrity("Retained catalog diagnosis body differs."));
    }
    let receipt = json!({"version":1,"evidence":"fresh_catalog_page_diagnosis",
        "page":page,"observed_at":observed_at,"body_hash":artifact.body_hash,"bytes":artifact.bytes,
        "validation":validation,"attempts":attempts_after.saturating_sub(attempts_before),
        "attempts_before_invocation":attempts_before,"budget_used":attempts_after,"attempt_limit_per_provider":20,
        "whole_catalog":false,"publication":false,"production_failure_reproduced":false});
    write_catalog_receipt(
        root,
        &format!("catalog-diagnosis-{page}-{attempts_after}.json"),
        &receipt,
    )?;
    Ok(receipt)
}

async fn diagnose_catalog_page(input: &Path, page: u32) -> Result<(std::path::PathBuf, Value)> {
    if !(1..=1000).contains(&page) {
        return Err(Error::invalid("Invalid catalog diagnosis page."));
    }
    let root = root::owned_root(input, b"devres-w3c-live-v1\n")?;
    let _lock = live_lock(&root)?;
    let (broker, attempts_before) = counted_broker(&root, "attempt-count")?;
    let cancel = CancellationToken::new();
    let signal = cancel.clone();
    let task = tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        signal.cancel();
    });
    let result = async {
        let bytes = fetch_catalog_page(&broker, page, &cancel).await?;
        retain_catalog_diagnosis(
            &root,
            page,
            bytes,
            devres_domain::unix_now(),
            attempts_before,
            broker.attempt_count(),
            &cancel,
        )
        .await
    }
    .await;
    task.abort();
    let _ = task.await;
    Ok((root, result?))
}

fn original_catalog_diagnosis(root: &Path, page: u32, digest: &str, bytes: usize) -> Result<Value> {
    use std::{io::Read, os::unix::fs::OpenOptionsExt};
    let invalid =
        || Error::integrity("Retained catalog diagnosis has no matching original receipt.");
    for (examined, entry) in std::fs::read_dir(root)
        .map_err(|_| invalid())?
        .take(129)
        .enumerate()
    {
        if examined >= 128 {
            return Err(Error::capacity(
                "Retained catalog diagnosis metadata exceeds its bound.",
            ));
        }
        let entry = entry.map_err(|_| invalid())?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with("catalog-diagnosis-") || !name.ends_with(".json") {
            continue;
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(entry.path())
            .map_err(|_| invalid())?;
        let metadata = file.metadata().map_err(|_| invalid())?;
        if !metadata.is_file() || metadata.len() > 64 * 1024 {
            return Err(invalid());
        }
        let mut body = Vec::new();
        file.take(64 * 1024 + 1)
            .read_to_end(&mut body)
            .map_err(|_| invalid())?;
        if body.len() > 64 * 1024 {
            return Err(invalid());
        }
        let original: Value = serde_json::from_slice(&body).map_err(|_| invalid())?;
        if original["page"].as_u64() != Some(page as u64)
            || original["body_hash"].as_str() != Some(digest)
        {
            continue;
        }
        let before = original["attempts_before_invocation"]
            .as_u64()
            .ok_or_else(invalid)?;
        let after = original["budget_used"].as_u64().ok_or_else(invalid)?;
        let observed = original["observed_at"].as_i64().ok_or_else(invalid)?;
        if original["version"] != 1
            || original["evidence"] != "fresh_catalog_page_diagnosis"
            || original["bytes"].as_u64() != Some(bytes as u64)
            || after > 20
            || before >= after
            || original["attempts"].as_u64() != Some(after - before)
            || original["attempt_limit_per_provider"] != 20
            || name != format!("catalog-diagnosis-{page}-{after}.json")
            || original["whole_catalog"] != false
            || original["publication"] != false
        {
            return Err(invalid());
        }
        return Ok(
            json!({"observed_at":observed,"attempts_before_invocation":before,
            "budget_used":after,"attempts":after-before,"receipt_digest":integrity::hash(&body)}),
        );
    }
    Err(invalid())
}

async fn replay_catalog_page(
    input: &Path,
    page: u32,
    digest: &str,
) -> Result<(std::path::PathBuf, Value)> {
    use tokio::io::AsyncReadExt;
    if !(1..=1000).contains(&page)
        || !digest.starts_with("blake3:")
        || !integrity::valid_hash(digest)
    {
        return Err(Error::invalid(
            "Invalid retained catalog diagnosis selection.",
        ));
    }
    let root = root::owned_root(input, b"devres-w3c-live-v1\n")?;
    let _lock = live_lock(&root)?;
    let artifacts = BulkArtifactStore::new(&root, 64 * 1024 * 1024)?;
    let cancel = CancellationToken::new();
    let mut bytes = Vec::new();
    artifacts
        .open(digest, 8 * 1024 * 1024, cancel)
        .await?
        .take(8 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| Error::unavailable("Retained catalog diagnosis body unavailable."))?;
    if bytes.len() > 8 * 1024 * 1024 {
        return Err(Error::capacity(
            "Retained catalog diagnosis body exceeds its bound.",
        ));
    }
    integrity::verify(digest, &bytes)?;
    let original = original_catalog_diagnosis(&root, page, digest, bytes.len())?;
    let observed_at = original["observed_at"]
        .as_i64()
        .ok_or_else(|| Error::integrity("Original catalog diagnosis time is invalid."))?;
    let receipt = json!({"version":1,"evidence":"retained_catalog_page_diagnosis","page":page,
        "body_hash":digest,"bytes":bytes.len(),"validation":w3c_catalog::page_validation_diagnosis(&bytes, observed_at),
        "observed_at":observed_at,"original":original,"upstream_revalidated":false,"attempts":0,"whole_catalog":false,
        "publication":false,"production_failure_reproduced":false});
    write_catalog_receipt(
        &root,
        &format!(
            "catalog-replay-{page}-{}.json",
            digest.trim_start_matches("blake3:")
        ),
        &receipt,
    )?;
    Ok((root, receipt))
}

async fn accept(input: &Path) -> Result<(std::path::PathBuf, Value)> {
    use std::io::Write;
    let root = root::owned_root(input, b"devres-w3c-live-v1\n")?;
    let _lock = live_lock(&root)?;
    if root
        .join("live-receipt.json")
        .try_exists()
        .map_err(|_| Error::unavailable("Live receipt unavailable."))?
    {
        return Err(Error::invalid(
            "Live receipt already exists; use a new owned root.",
        ));
    }
    let receipt = run(&root).await?;
    let stage = root.join(format!("live-receipt.stage-{}", std::process::id()));
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&stage)
        .map_err(|_| Error::unavailable("Live receipt persistence failed."))?;
    serde_json::to_writer_pretty(&mut output, &receipt)
        .map_err(|_| Error::unavailable("Live receipt persistence failed."))?;
    output
        .write_all(b"\n")
        .and_then(|()| output.sync_all())
        .map_err(|_| Error::unavailable("Live receipt persistence failed."))?;
    std::fs::rename(stage, root.join("live-receipt.json"))
        .map_err(|_| Error::unavailable("Live receipt persistence failed."))?;
    std::fs::File::open(&root)
        .and_then(|file| file.sync_all())
        .map_err(|_| Error::unavailable("Live receipt persistence failed."))?;
    Ok((root, receipt))
}

#[tokio::main]
async fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let result = match args.as_slice() {
        [flag, root] if flag == "--live" => accept(Path::new(root)).await,
        [flag, page, root] if flag == "--diagnose-catalog-page" => {
            match catalog_page_number(page) {
                Ok(page) => diagnose_catalog_page(Path::new(root), page).await,
                Err(error) => Err(error),
            }
        }
        [flag, page, digest, root] if flag == "--replay-catalog-page" => {
            match catalog_page_number(page) {
                Ok(page) => replay_catalog_page(Path::new(root), page, digest).await,
                Err(error) => Err(error),
            }
        }
        _ => Err(Error::invalid(
            "usage: w3c-live-probe --live OWNED_TMP_ROOT | --diagnose-catalog-page PAGE OWNED_TMP_ROOT | --replay-catalog-page PAGE BLAKE3_HASH OWNED_TMP_ROOT",
        )),
    };
    match result {
        Ok((root, receipt)) => println!(
            "{}",
            json!({"complete":true,"attempts":receipt["attempts"],"evidence":receipt["evidence"],"root":root})
        ),
        Err(error) => {
            eprintln!("W3C live acceptance failed: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_catalog_diagnosis_page_options_are_bounded() {
        for value in ["1", "12", "1000"] {
            assert!((1..=1000).contains(&catalog_page_number(value).unwrap()));
        }
        for value in [
            "",
            "0",
            "1001",
            "-1",
            "+1",
            "1.0",
            " 12",
            "12/../1",
            "999999999999999999999",
        ] {
            assert!(catalog_page_number(value).is_err());
        }
    }

    #[tokio::test]
    async fn rejected_catalog_probe_retains_exact_bytes_and_replays_offline_without_attempts() {
        use std::os::unix::fs::PermissionsExt;
        let temporary = tempfile::tempdir_in("/tmp").unwrap();
        let root = temporary.path();
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(root.join("owner-v1"), b"devres-w3c-live-v1\n").unwrap();
        std::fs::set_permissions(
            root.join("owner-v1"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        std::fs::write(root.join("attempt-count"), b"5\n").unwrap();
        assert_eq!(
            root::owned_root(root, b"devres-w3c-live-v1\n").unwrap(),
            root
        );
        let bytes = br#"{"_links":{"specifications":[{"shortname":"fixture","title":""}]},"unselected":"PRIVATE SOURCE MARKER"}"#.to_vec();
        let digest = integrity::hash(&bytes);
        let receipt =
            retain_catalog_diagnosis(root, 12, bytes.clone(), 42, 4, 5, &CancellationToken::new())
                .await
                .unwrap();
        assert_eq!(receipt["body_hash"], digest);
        assert_eq!(receipt["bytes"], bytes.len());
        assert_eq!(receipt["validation"]["accepted"], false);
        assert_eq!(receipt["validation"]["reason"], "title");
        assert_eq!(receipt["validation"]["row"], 1);
        assert_eq!(receipt["attempts"], 1);
        assert_eq!(receipt["budget_used"], 5);
        assert_eq!(receipt["production_failure_reproduced"], false);
        assert!(
            !serde_json::to_string(&receipt)
                .unwrap()
                .contains("PRIVATE SOURCE MARKER")
        );
        let path = root.join(integrity::relative_path(&digest).unwrap());
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert_eq!(
            root::owned_root(root, b"devres-w3c-live-v1\n").unwrap(),
            root
        );
        assert_eq!(
            replay_catalog_page(root, 999, &digest)
                .await
                .unwrap_err()
                .code,
            "integrity"
        );
        let (_, replay) = replay_catalog_page(root, 12, &digest).await.unwrap();
        assert_eq!(replay["attempts"], 0);
        assert_eq!(replay["validation"], receipt["validation"]);
        assert_eq!(replay["upstream_revalidated"], false);
        assert_eq!(replay["observed_at"], 42);
        assert_eq!(replay["original"]["budget_used"], 5);
        assert_eq!(std::fs::read(root.join("attempt-count")).unwrap(), b"5\n");
        assert_eq!(
            std::fs::read_dir(root)
                .unwrap()
                .filter_map(|entry| entry.ok())
                .filter(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("catalog-diagnosis-"))
                .count(),
            1
        );
        std::fs::write(&path, b"changed bytes").unwrap();
        assert!(replay_catalog_page(root, 12, &digest).await.is_err());
    }

    #[tokio::test]
    async fn canceled_catalog_probe_makes_no_provider_attempt_and_oversized_fixture_is_rejected() {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        std::fs::write(root.path().join("attempt-count"), b"20\n").unwrap();
        let (broker, before) = counted_broker(root.path(), "attempt-count").unwrap();
        assert_eq!(before, 20);
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert_eq!(
            fetch_catalog_page(&broker, 12, &cancel)
                .await
                .unwrap_err()
                .code,
            "cancelled"
        );
        assert_eq!(broker.attempt_count(), 20);
        assert_eq!(
            std::fs::read(root.path().join("attempt-count")).unwrap(),
            b"20\n"
        );
        assert!(
            retain_catalog_diagnosis(
                root.path(),
                12,
                vec![b'x'; 8 * 1024 * 1024 + 1],
                42,
                20,
                20,
                &CancellationToken::new()
            )
            .await
            .is_err()
        );
    }

    #[test]
    fn fixed_catalog_receipt_requires_parsed_dotted_identities_and_keeps_page_scope() {
        let bytes = br#"{"_links":{"specifications":[{"href":"https://api.w3.org/specifications/core-aam-1.1","title":"Core AAM"}],"next":{"href":"https://api.w3.org/specifications?page=2&items=100"}}}"#;
        let evidence = catalog_page_evidence(bytes, 42).unwrap();
        assert_eq!(evidence["dotted_shortnames"], json!(["core-aam-1.1"]));
        assert_eq!(evidence["standards"], 1);
        assert_eq!(evidence["page"], 1);
        assert_eq!(evidence["has_next"], true);
        assert_eq!(evidence["whole_catalog"], false);
        assert_eq!(evidence["observed_at"], 42);
        assert_eq!(
            evidence["source_url"],
            "https://api.w3.org/specifications?page=1&items=100"
        );
        assert!(catalog_page_evidence(br#"{"_embedded":{"specifications":[{"shortname":"css-color-4","title":"CSS Color"}]}}"#,42).is_err());
        assert!(
            catalog_page_evidence(
                br#"{"_embedded":{"specifications":[{"shortname":"a..b","title":"Invalid"}]}}"#,
                42
            )
            .is_err()
        );
    }
    #[test]
    fn live_attempt_lock_excludes_concurrent_invocations() {
        let temporary = tempfile::tempdir_in(std::env::temp_dir()).unwrap();
        let first = live_lock(temporary.path()).unwrap();
        assert!(live_lock(temporary.path()).is_err());
        drop(first);
        assert!(live_lock(temporary.path()).is_ok());
    }

    #[tokio::test]
    async fn retained_css_replay_preserves_capture_age_and_requires_exact_body() {
        let temporary = tempfile::tempdir_in(std::env::temp_dir()).unwrap();
        let root = temporary.path();
        let artifacts = BulkArtifactStore::new(root, 64 * 1024 * 1024).unwrap();
        let source = "https://www.w3.org/TR/2026/CRD-css-color-4-20261026/";
        let body=br#"<h1>CSS Color Module Level 4</h1><p class=copyright>Copyright 2026 Synthetic fixture. <a href='/copyright/software-license/'>License</a></p><div class=head><dl><dt>Suggest an Edit for this Spec:<dd><a href='https://github.com/w3c/csswg-drafts/blob/main/css-color-4/Overview.bs'>GitHub Editor</a></dl></div><h2 id=color>Color</h2><p>Synthetic color content.</p>"#.to_vec();
        let artifact = artifacts
            .capture_bytes(body.clone(), CancellationToken::new())
            .await
            .unwrap();
        let observed = devres_domain::unix_now() - 120;
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(root.join(&artifact.relative_path))
            .unwrap();
        file.set_times(
            std::fs::FileTimes::new()
                .set_modified(std::time::UNIX_EPOCH + Duration::from_secs(observed as u64)),
        )
        .unwrap();
        std::fs::write(root.join("license-preflight-1.json"),serde_json::to_vec(&json!({"source_url":source,"body_hash":artifact.body_hash,"bytes":body.len(),"synthetic":true})).unwrap()).unwrap();
        let replay = retained_css(root, &artifacts, &CancellationToken::new())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(replay["capture_file_mtime"], observed);
        assert!(replay["upstream_validated_at"].is_null());
        assert_eq!(replay["replay"]["original_capture_reused"], true);
        assert_eq!(
            replay["replay"]["upstream_validation_time_available"],
            false
        );
        assert_eq!(replay["replay"]["latest_metadata_revalidated"], false);
        assert!(replay["processing"]["sections"].as_u64().unwrap() > 0);
        assert_eq!(replay["artifact"]["relative_path"], artifact.relative_path);
        let legacy_hash = integrity::legacy_hash(&body);
        let legacy_path = root.join(integrity::relative_path(&legacy_hash).unwrap());
        std::fs::hard_link(root.join(&artifact.relative_path), &legacy_path).unwrap();
        std::fs::write(root.join("license-preflight-1.json"),serde_json::to_vec(&json!({"source_url":source,"body_hash":legacy_hash,"bytes":body.len(),"synthetic":true})).unwrap()).unwrap();
        assert!(
            retained_css(root, &artifacts, &CancellationToken::new())
                .await
                .is_err(),
            "legacy SHA replay requires independent BLAKE3 file evidence"
        );
        integrity::record_file(
            root,
            &legacy_path,
            &integrity::hash(&body),
            body.len() as u64,
        )
        .unwrap();
        let legacy = retained_css(root, &artifacts, &CancellationToken::new())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(legacy["artifact"]["body_hash"], legacy_hash);
        assert_eq!(legacy["artifact"]["relative_path"], legacy_hash);
        assert_eq!(legacy["capture_file_mtime"], observed);
        std::fs::write(root.join(&artifact.relative_path), b"changed body").unwrap();
        assert!(
            retained_css(root, &artifacts, &CancellationToken::new())
                .await
                .is_err()
        );
    }
}
