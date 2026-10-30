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
        json!({"version":1,"stage":"complete","complete":true,"evidence":"bounded_provider_and_parser","whole_corpus":false,"transport_acceptance":false,"attempts":broker.attempt_count()-initial_attempts+github_broker.attempt_count()-initial_github_attempts,"attempts_before_invocation":{"w3c":initial_attempts,"github":initial_github_attempts},"budget_used":{"w3c":broker.attempt_count(),"github":github_broker.attempt_count()},"attempt_limit_per_provider":20,"git_advertisement_bytes":advertisement.len(),"records":records}),
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
        _ => Err(Error::invalid(
            "usage: w3c-live-probe --live OWNED_TMP_ROOT",
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
    fn live_attempt_lock_excludes_concurrent_invocations() {
        let temporary = tempfile::tempdir_in("/tmp").unwrap();
        let first = live_lock(temporary.path()).unwrap();
        assert!(live_lock(temporary.path()).is_err());
        drop(first);
        assert!(live_lock(temporary.path()).is_ok());
    }

    #[tokio::test]
    async fn retained_css_replay_preserves_capture_age_and_requires_exact_body() {
        let temporary = tempfile::tempdir_in("/tmp").unwrap();
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
