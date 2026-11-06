//! Fixed-source, opt-in repair acceptance; no collectors or corpus sweep are composed.
use devres_adapters::{
    attribution_providers::{self, AttributionSource},
    bulk::*,
};
use devres_domain::{Error, Result, Validators};
use futures::StreamExt;
use serde_json::json;
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

async fn probe(provider: &str, operation: BulkSource, root: &std::path::Path) -> Result<()> {
    let broker = Arc::new(BulkBroker::new(BulkConfig::default())?.with_attempt_budget(20)?);
    let source_url = operation.url()?;
    let response = broker
        .open(
            BulkRequest {
                source: operation,
                validators: Validators::default(),
                max_bytes: 16 * 1024 * 1024,
                deadline: Instant::now() + Duration::from_secs(120),
                body: vec![],
            },
            CancellationToken::new(),
        )
        .await?;
    if response.status != 200 {
        return Err(Error::unavailable(
            "Fixed live source did not return a body.",
        ));
    }
    let mut bytes = Vec::new();
    let mut stream = response.stream;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if bytes.len().saturating_add(chunk.len()) > 16 * 1024 * 1024 {
            return Err(Error::capacity("Live source exceeds fixed probe bound."));
        }
        bytes.extend_from_slice(&chunk);
    }
    // Preserve separately from disposable synthetic database/blob pairs.
    tokio::fs::write(root.join(format!("{provider}-source.bin")), &bytes)
        .await
        .map_err(|_| Error::unavailable("Cannot retain live evidence."))?;
    let output =
        json!({"source_url":source_url,"body_hash":devres_adapters::integrity::hash(&bytes)});
    let targets = attribution_providers::targets(provider, &output)?;
    if targets.len() != 1 {
        return Err(Error::integrity("Fixed live source mapping differs."));
    }
    let generation =
        attribution_providers::repair(&targets[0], &broker, CancellationToken::new()).await?;
    let receipt = json!({"provider":provider,"source":output,"subject":targets[0].subject,
        "request_attempts":broker.attempt_count(),"maximum_requests":20,
        "policy_epoch":generation.policy_epoch,"notices":generation.notices,
        "receipts":generation.receipts,"scope":"fixed representative; not all variants or corpus acceptance"});
    let encoded = serde_json::to_vec_pretty(&receipt)
        .map_err(|_| Error::integrity("Invalid live receipt."))?;
    tokio::fs::write(root.join(format!("{provider}-receipt.json")), encoded)
        .await
        .map_err(|_| Error::unavailable("Cannot retain live receipt."))?;
    Ok(())
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 2 || args[0] != "--live" {
        return Err("usage: attribution-live-probe --live NEW_DIRECTORY".into());
    }
    let requested = PathBuf::from(&args[1]);
    if !requested.is_absolute() {
        return Err("Live evidence needs a new absolute directory below /tmp".into());
    }
    let parent =
        tokio::fs::canonicalize(requested.parent().ok_or("Missing evidence parent")?).await?;
    if !parent.starts_with("/tmp") {
        return Err("Evidence parent must resolve below /tmp".into());
    }
    let root = parent.join(
        requested
            .file_name()
            .ok_or("Missing evidence directory name")?,
    );
    if root.exists() {
        return Err("Live evidence directory already exists".into());
    }
    tokio::fs::create_dir(&root).await?;
    tokio::fs::write(root.join("owner-v1"), b"devres-attribution-live-v1\n").await?;
    for (provider, source) in [
        (
            "rfc",
            BulkSource::Attribution(AttributionSource::Rfc {
                number: 9000,
                format: "txt".into(),
            }),
        ),
        (
            "crates",
            BulkSource::CrateArchive {
                name: "itoa".into(),
                version: "1.0.15".into(),
            },
        ),
        (
            "npm",
            BulkSource::Npm(devres_adapters::npm::source::Operation::Archive {
                name: "is-number".into(),
                version: "7.0.0".into(),
                url: "https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz".into(),
            }),
        ),
    ] {
        let result = probe(provider, source, &root).await;
        match result {
            Ok(()) => println!("{provider}: exact source and notice reacquisition passed"),
            Err(error) => {
                println!("{provider}: {}", error.code);
                return Err(error.into());
            }
        }
    }
    println!("Retained bounded live evidence: {}", root.display());
    Ok(())
}
