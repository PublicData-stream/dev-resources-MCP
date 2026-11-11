//! Fixed-record transport comparison. No source body is persisted or published.
use devres_adapters::{
    attribution_providers::AttributionSource,
    bulk::{BulkBroker, BulkConfig, BulkRequest, BulkSource},
    chromium::{processing as chromium_processing, source::Operation},
    w3c::{catalog, discovery::DiscoveryOperation, processing as w3c_processing},
};
use devres_application::w3c::Standard;
use devres_domain::{Error, Result, Validators};
use futures::StreamExt;
use serde_json::{Value, json};
use std::{
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
#[path = "../support/root.rs"]
mod root;
const MARKER: &[u8] = b"devres-html-transport-probe-v1\n";
const MAX_BODY: u64 = 16 * 1024 * 1024;
const CAP: usize = 20;

fn failed() -> Error {
    Error::unavailable("HTML comparison evidence unavailable.")
}
fn code(error: &Error) -> &str {
    match error.code.as_str() {
        "invalid_input" | "unavailable" | "not_found" | "capacity" | "integrity" | "cancelled" => {
            error.code.as_str()
        }
        _ => "other",
    }
}
fn safe_path(root: &Path, name: &str) -> Result<PathBuf> {
    let path = root.join(name);
    match std::fs::symlink_metadata(&path) {
        Ok(metadata)
            if metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.len() <= 1024 * 1024 => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err(failed()),
    }
    Ok(path)
}
fn persist(root: &Path, name: &str, value: &[u8]) -> Result<()> {
    let destination = safe_path(root, name)?;
    let stage = root.join(format!("{name}.stage-{}", std::process::id()));
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&stage)
        .map_err(|_| failed())?;
    output
        .write_all(value)
        .and_then(|()| output.sync_all())
        .map_err(|_| failed())?;
    std::fs::rename(stage, destination).map_err(|_| failed())?;
    std::fs::File::open(root)
        .and_then(|file| file.sync_all())
        .map_err(|_| failed())
}
fn save_receipts(root: &Path, broker: &BulkBroker, receipts: &[Value]) -> Result<()> {
    let value = json!({"schema":1,"attempts":broker.attempt_count(),"combined_attempt_cap":CAP,"observations":receipts,
        "boundary":"Raw transport and selected processing comparison only; no durable publication, full corpus, production activation or native architecture qualification."});
    persist(
        root,
        "comparison.json",
        &serde_json::to_vec_pretty(&value).map_err(|_| failed())?,
    )
}
async fn fetch(
    broker: &BulkBroker,
    source: BulkSource,
    legacy: bool,
    cancel: &CancellationToken,
) -> Result<(u16, Vec<u8>)> {
    let request = BulkRequest {
        source,
        validators: Validators::default(),
        max_bytes: MAX_BODY,
        deadline: Instant::now() + Duration::from_secs(90),
        body: Vec::new(),
    };
    let mut response = if legacy {
        broker
            .open_legacy_html_probe(request, cancel.clone())
            .await?
    } else {
        broker.open(request, cancel.clone()).await?
    };
    let status = response.status;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.stream.next().await {
        let chunk = chunk?;
        if chunk.len() > (MAX_BODY as usize).saturating_sub(bytes.len()) {
            return Err(Error::capacity("HTML comparison body exceeds limit."));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok((status, bytes))
}
async fn metadata(
    broker: &BulkBroker,
    operation: catalog::ApiOperation,
    label: &str,
    cancel: &CancellationToken,
    receipts: &mut Vec<Value>,
    root: &Path,
) -> Result<Value> {
    let source_url = operation.url()?;
    let observed_at = devres_domain::unix_now();
    let result = fetch(broker, BulkSource::W3cApi(operation), false, cancel).await;
    let parsed = match result {
        Ok((status, bytes)) => {
            let parsed = if status == 200 {
                serde_json::from_slice(&bytes)
                    .map_err(|_| Error::integrity("Fixed W3C metadata invalid."))
            } else {
                Err(Error::unavailable("Fixed W3C metadata unavailable."))
            };
            receipts.push(json!({"record":label,"source_url":source_url,"observed_at":observed_at,"transport":"existing_metadata","status":status,"bytes":bytes.len(),"body_hash":devres_adapters::integrity::hash(&bytes),"parsed":parsed.is_ok()}));
            parsed
        }
        Err(error) => {
            receipts
                .push(json!({"record":label,"source_url":source_url,"observed_at":observed_at,"transport":"existing_metadata","error":code(&error)}));
            Err(error)
        }
    };
    save_receipts(root, broker, receipts)?;
    parsed
}
fn processing(label: &str, source: &BulkSource, body: &[u8], cancel: &CancellationToken) -> Value {
    match source {
        BulkSource::W3cPublication(publication) => {
            let license = catalog::publication_license(publication, body);
            let projected = w3c_processing::process_document("index.html", body, cancel.clone());
            match projected {
                Ok(document) => {
                    json!({"projection":"passed","sections":document.sections.len(),"license_decision":license["decision"]})
                }
                Err(error) => {
                    json!({"projection":"failed","error":code(&error),"license_decision":license["decision"]})
                }
            }
        }
        BulkSource::Chromium(_) => {
            match chromium_processing::process_document("index.html", body, cancel.clone()) {
                Ok(document) => {
                    json!({"projection":"passed","sections":document.sections.len(),"license_qualification":"not_exercised"})
                }
                Err(error) => {
                    json!({"projection":"failed","error":code(&error),"license_qualification":"not_exercised"})
                }
            }
        }
        _ => json!({"record":label,"validation":"not_exercised","publication":"not_exercised"}),
    }
}
async fn compare(
    broker: &BulkBroker,
    source: BulkSource,
    label: &str,
    cancel: &CancellationToken,
    receipts: &mut Vec<Value>,
    root: &Path,
) -> Result<()> {
    for legacy in [true, false] {
        let transport = if legacy { "reqwest" } else { "wreq" };
        let started = std::time::Instant::now();
        let source_url = source.url()?;
        let observed_at = devres_domain::unix_now();
        let result = fetch(broker, source.clone(), legacy, cancel).await;
        let receipt = match result {
            Ok((status, bytes)) => {
                json!({"record":label,"source_url":source_url,"observed_at":observed_at,"transport":transport,"status":status,"bytes":bytes.len(),
                "body_hash":devres_adapters::integrity::hash(&bytes),"elapsed_ms":started.elapsed().as_millis(),
                "processing":if status == 200 {processing(label,&source,&bytes,cancel)} else {json!({"skipped":"http_status"})}})
            }
            Err(error) => {
                json!({"record":label,"source_url":source_url,"observed_at":observed_at,"transport":transport,"error":code(&error),"elapsed_ms":started.elapsed().as_millis()})
            }
        };
        receipts.push(receipt);
        save_receipts(root, broker, receipts)?;
        if cancel.is_cancelled() {
            return Err(Error::new("cancelled", "HTML comparison canceled."));
        }
    }
    Ok(())
}
fn qualified_css(uri: &str) -> Result<catalog::PublicationUrl> {
    let parsed = url::Url::parse(uri).map_err(|_| failed())?;
    if !parsed.path().contains("-css-color-4-") {
        return Err(Error::integrity(
            "Fixed CSS record requires a dated publication.",
        ));
    }
    catalog::current_publication(&Standard {
        id: "css-color-4".into(),
        title: "CSS Color Module Level 4".into(),
        url: uri.into(),
        repository: String::new(),
        metadata: json!({"publication_url":uri}),
    })
}

fn counted_broker(root: &Path) -> Result<BulkBroker> {
    let count_path = safe_path(root, "attempt-count")?;
    let initial = match std::fs::read_to_string(count_path) {
        Ok(value) => value.trim().parse::<usize>().map_err(|_| failed())?,
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                && !root.join("comparison.json").exists() =>
        {
            0
        }
        Err(_) => return Err(failed()),
    };
    if initial > CAP {
        return Err(Error::capacity("HTML comparison attempt cap exceeded."));
    }
    let accounting_root = root.to_path_buf();
    BulkBroker::new(BulkConfig::default())?
        .with_attempt_budget(CAP)?
        .with_attempt_observer(
            initial,
            Arc::new(move |count| {
                persist(
                    &accounting_root,
                    "attempt-count",
                    format!("{count}\n").as_bytes(),
                )
            }),
        )
}

async fn run(root: &Path) -> Result<()> {
    let root = root::owned_root(root, MARKER)?;
    let lock_path = safe_path(&root, "probe.lock")?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)
        .map_err(|_| failed())?;
    fs2::FileExt::try_lock_exclusive(&lock)
        .map_err(|_| Error::capacity("HTML comparison root is already in use."))?;
    let broker = counted_broker(&root)?;
    let previous = safe_path(&root, "comparison.json")?;
    let mut receipts = match std::fs::read(previous) {
        Ok(bytes) => serde_json::from_slice::<Value>(&bytes).map_err(|_| failed())?["observations"]
            .as_array()
            .cloned()
            .ok_or_else(failed)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(_) => return Err(failed()),
    };
    let cancel = CancellationToken::new();
    let signal = cancel.clone();
    let signal_task = tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        signal.cancel();
    });
    compare(
        &broker,
        BulkSource::W3cDiscovery(DiscoveryOperation::TrIndex),
        "w3c_tr_index",
        &cancel,
        &mut receipts,
        &root,
    )
    .await?;
    let qualification: Result<_> = async {
        let fixed = safe_path(&root, "fixed-css-publication.json")?;
        match std::fs::read(fixed) {
            Ok(bytes) => {
                let uri: String = serde_json::from_slice(&bytes).map_err(|_| failed())?;
                return qualified_css(&uri);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(failed()),
        }
        let data = metadata(
            &broker,
            catalog::ApiOperation::Specification {
                shortname: "css-color-4".into(),
            },
            "w3c_css_metadata",
            &cancel,
            &mut receipts,
            &root,
        )
        .await?;
        let version = data["_links"]["latest-version"]["href"]
            .as_str()
            .and_then(|href| {
                href.strip_prefix("https://api.w3.org/specifications/css-color-4/versions/")
            })
            .filter(|version| !version.is_empty() && !version.contains('/'))
            .ok_or_else(failed)?;
        let edition = metadata(
            &broker,
            catalog::ApiOperation::Version {
                shortname: "css-color-4".into(),
                version: version.into(),
            },
            "w3c_css_edition",
            &cancel,
            &mut receipts,
            &root,
        )
        .await?;
        let uri = edition["uri"].as_str().ok_or_else(failed)?;
        let publication = qualified_css(uri)?;
        persist(
            &root,
            "fixed-css-publication.json",
            &serde_json::to_vec(uri).map_err(|_| failed())?,
        )?;
        Ok(publication)
    }
    .await;
    match qualification {
        Ok(publication) => {
            compare(
                &broker,
                BulkSource::W3cPublication(publication),
                "w3c_css_publication",
                &cancel,
                &mut receipts,
                &root,
            )
            .await?
        }
        Err(error) => {
            receipts.push(json!({"record":"w3c_css_qualification","error":code(&error)}));
            save_receipts(&root, &broker, &receipts)?;
        }
    }
    for (source, label) in [
        (
            BulkSource::Chromium(Operation::Page {
                path: "docs/devtools/overview".into(),
            }),
            "chrome_devtools_overview",
        ),
        (
            BulkSource::Chromium(Operation::SitePage {
                path: "Home".into(),
            }),
            "chromium_site_home",
        ),
        (
            BulkSource::Attribution(AttributionSource::Rfc {
                number: 9000,
                format: "html".into(),
            }),
            "rfc_9000_html_attribution",
        ),
    ] {
        compare(&broker, source, label, &cancel, &mut receipts, &root).await?;
    }
    signal_task.abort();
    save_receipts(&root, &broker, &receipts)?;
    println!(
        "Compared fixed HTML records; {} total charged attempts. See comparison.json; this is not publication acceptance.",
        broker.attempt_count()
    );
    Ok(())
}
#[tokio::main]
async fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let result = if args.len() == 2 && args[0] == "--live" {
        run(Path::new(&args[1])).await
    } else {
        Err(Error::invalid(
            "Usage: html-transport-probe --live OWNED_ROOT",
        ))
    };
    if let Err(error) = result {
        eprintln!("HTML comparison stopped: {}", code(&error));
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn charged_attempts_survive_restart_and_a_missing_counter_fails_closed() {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let broker = counted_broker(root.path()).unwrap();
        let permit = broker.admit_foreground("www.rfc-editor.org").await.unwrap();
        assert_eq!(
            std::fs::read_to_string(root.path().join("attempt-count")).unwrap(),
            "1\n"
        );
        drop(permit);
        save_receipts(root.path(), &broker, &[]).unwrap();
        drop(broker);
        assert_eq!(counted_broker(root.path()).unwrap().attempt_count(), 1);
        std::fs::remove_file(root.path().join("attempt-count")).unwrap();
        assert!(counted_broker(root.path()).is_err());
    }

    #[test]
    fn receipt_writes_refuse_symlink_destinations() {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let target = root.path().join("untouched");
        std::fs::write(&target, b"untouched").unwrap();
        std::os::unix::fs::symlink(&target, root.path().join("comparison.json")).unwrap();
        assert!(persist(root.path(), "comparison.json", b"changed").is_err());
        assert_eq!(std::fs::read(target).unwrap(), b"untouched");
    }
}
