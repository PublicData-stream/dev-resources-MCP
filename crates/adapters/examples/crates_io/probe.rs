//! Opt-in bounded live acquisition; never starts collectors or builds a package.
use devres_adapters::{
    bulk::{
        BulkArtifact, BulkArtifactStore, BulkBroker, BulkConfig, BulkRequest, BulkSource,
        DocsOperation, GitOperation,
    },
    crates_io::docs::{self as crate_docs, ProcessingBudget},
};
use devres_domain::{Error, Result, Validators};
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

const NAME: &str = "itoa";
const VERSION: &str = "1.0.15";
struct Stage(PathBuf);
impl Drop for Stage {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

async fn capture(
    broker: &BulkBroker,
    store: &BulkArtifactStore,
    source: BulkSource,
    max_bytes: u64,
    stop: CancellationToken,
) -> Result<Option<BulkArtifact>> {
    let response = broker
        .open(
            BulkRequest {
                source,
                validators: Validators::default(),
                max_bytes,
                deadline: tokio::time::Instant::now() + Duration::from_secs(120),
                body: Vec::new(),
            },
            stop.child_token(),
        )
        .await?;
    if response.status == 404 {
        return Ok(None);
    }
    store.capture(response, None, stop).await.map(Some)
}
async fn expand_json(
    root: &Path,
    store: &BulkArtifactStore,
    artifact: &BulkArtifact,
    target: &str,
    stop: &CancellationToken,
) -> Result<Value> {
    let stage = Stage(root.join(format!(".probe-json-{target}")));
    let mut output = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&stage.0)
        .map_err(|_| Error::unavailable("Probe stage unavailable."))?;
    let file = store
        .open(&artifact.body_hash, 32 * 1024 * 1024, stop.child_token())
        .await?
        .into_std()
        .await;
    let mut decoder = flate2::read::MultiGzDecoder::new(file);
    let mut bytes = 0;
    let mut chunk = [0; 65536];
    let started = std::time::Instant::now();
    loop {
        if stop.is_cancelled() || started.elapsed() > Duration::from_secs(15) {
            return Err(Error::capacity("Probe processing deadline exceeded."));
        }
        let n = decoder
            .read(&mut chunk)
            .map_err(|_| Error::integrity("Malformed documentation gzip."))?;
        if n == 0 {
            break;
        }
        bytes += n as u64;
        if bytes > crate_docs::MAX_EXPANDED {
            return Err(Error::capacity("Probe expansion limit exceeded."));
        }
        output
            .write_all(&chunk[..n])
            .map_err(|_| Error::unavailable("Probe stage write failed."))?;
    }
    drop(output);
    let file = std::fs::File::open(&stage.0)
        .map_err(|_| Error::unavailable("Probe stage unavailable."))?;
    let mut items = 0;
    match crate_docs::parse_rustdoc_json(
        file,
        VERSION,
        Some(target),
        &ProcessingBudget::new(stop.child_token()),
        |_| {
            items += 1;
            Ok(())
        },
    ) {
        Ok(summary) => Ok(json!({"status":"normalized","summary":summary,"items":items})),
        Err(error) if error.code == "unsupported_format" => {
            Ok(json!({"status":"unsupported_format","raw_retained":true}))
        }
        Err(error) => Err(error),
    }
}
async fn probe(root: &Path, stop: CancellationToken) -> Result<Value> {
    let broker = BulkBroker::new(BulkConfig {
        static_requests_per_second: 1,
        max_transfers: 1,
        min_free_bytes: 64 * 1024 * 1024,
        ..Default::default()
    })?;
    let store = BulkArtifactStore::new(root, 64 * 1024 * 1024)?;
    let platform_source = BulkSource::Documentation {
        name: NAME.into(),
        version: VERSION.into(),
        operation: DocsOperation::Platforms,
    };
    let platforms = capture(
        &broker,
        &store,
        platform_source,
        1024 * 1024,
        stop.child_token(),
    )
    .await?
    .ok_or_else(|| Error::not_found("Fixed documentation platform record is absent."))?;
    let file = store
        .open(&platforms.body_hash, 1024 * 1024, stop.child_token())
        .await?
        .into_std()
        .await;
    let targets = crate_docs::parse_platforms(file, &ProcessingBudget::new(stop.child_token()))?;
    if targets.is_empty() {
        return Err(Error::integrity("Fixed documentation has no targets."));
    }
    let html = capture(
        &broker,
        &store,
        BulkSource::Documentation {
            name: NAME.into(),
            version: VERSION.into(),
            operation: DocsOperation::Html,
        },
        32 * 1024 * 1024,
        stop.child_token(),
    )
    .await?
    .ok_or_else(|| Error::not_found("Fixed documentation bundle is absent."))?;
    let file = store
        .open(&html.body_hash, 32 * 1024 * 1024, stop.child_token())
        .await?
        .into_std()
        .await;
    let html_summary =
        crate_docs::inspect_html_zip(file, &ProcessingBudget::new(stop.child_token()), |_| Ok(()))?;
    if html_summary.documents == 0 {
        return Err(Error::integrity("Documentation ZIP contains no HTML."));
    }
    let mut json_results = Vec::new();
    // Two named targets at most. At most four docs.rs operations, eight attempts with retries.
    for target in targets.iter().take(2) {
        let captured = capture(
            &broker,
            &store,
            BulkSource::Documentation {
                name: NAME.into(),
                version: VERSION.into(),
                operation: DocsOperation::Json {
                    target: target.triple.clone(),
                    format: None,
                },
            },
            32 * 1024 * 1024,
            stop.child_token(),
        )
        .await?;
        json_results.push(match captured {Some(artifact)=>json!({"target":target.triple,"capture":artifact,"processing":expand_json(root,&store,&artifact,&target.triple,&stop).await?}),None=>json!({"target":target.triple,"status":"not_found"})});
    }
    // Read-only smart-HTTP advertisement only; never requests a registry pack.
    let git = capture(
        &broker,
        &store,
        BulkSource::RegistryGit(GitOperation::Advertisement),
        65536,
        stop.child_token(),
    )
    .await?
    .ok_or_else(|| Error::not_found("Official registry advertisement is absent."))?;
    Ok(
        json!({"package":format!("{NAME}@{VERSION}"),"platforms":platforms,"published_target_count":targets.len(),"html":html,"html_processing":html_summary,"json":json_results,"git_advertisement":git,"maximum_attempts":{"docs.rs":8,"github.com":2},"scope":"fixed-record acquisition and parser checks; no registry mirror or full-provider acceptance"}),
    )
}
#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if let [mode, path] = args.as_slice()
        && mode == "--replay"
    {
        let root = Path::new(path);
        let file = std::fs::File::open(root.join("evidence.json"))?;
        let mut bytes = Vec::new();
        file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > 1024 * 1024 {
            return Err("probe evidence exceeds 1 MiB".into());
        }
        let captured: Value = serde_json::from_slice(&bytes)?;
        if captured["package"] != format!("{NAME}@{VERSION}") {
            return Err("unexpected replay package".into());
        }
        let store = BulkArtifactStore::new(root, 64 * 1024 * 1024)?;
        let stop = CancellationToken::new();
        let mut results = Vec::new();
        let representations = captured["json"]
            .as_array()
            .filter(|j| j.len() <= 2)
            .ok_or("invalid replay representation list")?;
        for item in representations {
            let target = item["target"]
                .as_str()
                .filter(|t| devres_adapters::bulk::valid_target(t))
                .ok_or("invalid replay target")?;
            if item.get("capture").is_none() {
                continue;
            }
            let artifact: BulkArtifact = serde_json::from_value(item["capture"].clone())?;
            let verified = store
                .verify(&artifact.body_hash, 32 * 1024 * 1024, stop.child_token())
                .await?;
            if verified != artifact {
                return Err("replay artifact identity differs".into());
            }
            results.push(json!({"target":target,"capture":artifact,"processing":expand_json(root,&store,&artifact,target,&stop).await?}));
        }
        let evidence = json!({"package":format!("{NAME}@{VERSION}"),"json":results,"network_attempts":0,"scope":"offline processing of retained fixed live captures"});
        let output = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(root.join("processing-evidence.json"))?;
        serde_json::to_writer_pretty(output, &evidence)?;
        println!("{}", serde_json::to_string(&evidence)?);
        return Ok(());
    }
    let [live, flag, path] = args.as_slice() else {
        return Err(
            "usage: crate-provider-probe --live --output NEW_DIRECTORY | --replay DIRECTORY".into(),
        );
    };
    if live != "--live" || flag != "--output" {
        return Err("explicit --live and new output directory are required".into());
    }
    std::fs::create_dir(path)?;
    let stop = CancellationToken::new();
    let result = tokio::time::timeout(
        Duration::from_secs(300),
        probe(Path::new(path), stop.child_token()),
    )
    .await;
    stop.cancel();
    let evidence = result??;
    std::fs::write(
        Path::new(path).join("evidence.json"),
        serde_json::to_vec_pretty(&evidence)?,
    )?;
    println!("{}", serde_json::to_string(&evidence)?);
    Ok(())
}
