//! Fixed-record npm evidence. Replay never constructs a network client.
use async_trait::async_trait;
use devres_adapters::{
    bulk::{BulkArtifact, BulkArtifactStore, BulkBroker, BulkConfig, BulkRequest, BulkSource},
    integrity as content_integrity,
    npm::NpmPackages,
    npm::audit as npm_audit,
    npm::processing as npm_processing,
    npm::source::Operation,
};
use devres_application::{Cached, Fetcher, Retrieval, Store};
use devres_domain::{
    Capture, Error, FetchRequest, FetchResponse, Result, StoredCapture, Validators,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;
#[path = "../support/root.rs"]
mod root;

const MARKER: &[u8] = b"devres-npm-live-v1\n";
const RECORDS: [(&str, &str); 2] = [("is-number", "7.0.0"), ("@types/is-number", "7.0.5")];
const METADATA_RECORDS: [(&str, &str); 2] = [("react", "18.3.1"), ("left-pad", "1.3.0")];
const SEARCH_QUERY: &str = "TLS";
const SEARCH_MAX: u64 = 2 * 1024 * 1024;
const ADVISORY: &str = "GHSA-p6mc-m468-83gw";
const MAX_EXPORT: u64 = 512 * 1024 * 1024;
const MAX_RECEIPT: u64 = 1024 * 1024;
fn unavailable() -> Error {
    Error::unavailable("npm fixed-record evidence unavailable.")
}
fn integrity() -> Error {
    Error::integrity("Invalid retained npm fixed-record evidence.")
}
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn safe_file(root: &Path, name: &str) -> Result<PathBuf> {
    let path = root.join(name);
    if let Ok(metadata) = std::fs::symlink_metadata(&path)
        && (!metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > MAX_RECEIPT)
    {
        return Err(integrity());
    }
    Ok(path)
}
fn persist(root: &Path, name: &str, value: &Value) -> Result<()> {
    let destination = safe_file(root, name)?;
    let stage = root.join(format!("{name}.stage-{}", std::process::id()));
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&stage)
        .map_err(|_| unavailable())?;
    serde_json::to_writer_pretty(&mut file, value).map_err(|_| unavailable())?;
    file.write_all(b"\n")
        .and_then(|()| file.sync_all())
        .map_err(|_| unavailable())?;
    std::fs::rename(stage, destination).map_err(|_| unavailable())?;
    std::fs::File::open(root)
        .and_then(|file| file.sync_all())
        .map_err(|_| unavailable())
}
fn read_json(root: &Path, name: &str) -> Result<Value> {
    let bytes = std::fs::read(safe_file(root, name)?).map_err(|_| unavailable())?;
    if bytes.len() as u64 > MAX_RECEIPT {
        return Err(integrity());
    }
    serde_json::from_slice(&bytes).map_err(|_| integrity())
}
fn raw_store(root: &Path, create: bool) -> Result<BulkArtifactStore> {
    let raw = root.join("raw");
    if let Ok(metadata) = std::fs::symlink_metadata(&raw)
        && (!metadata.is_dir() || metadata.file_type().is_symlink())
    {
        return Err(integrity());
    }
    if create {
        std::fs::create_dir_all(&raw).map_err(|_| unavailable())?;
    }
    BulkArtifactStore::new(raw, 64 * 1024 * 1024)
}
fn counted_broker(root: &Path, provider: &str) -> Result<Arc<BulkBroker>> {
    let filename = format!("{provider}-attempt-count");
    let initial = match std::fs::read_to_string(safe_file(root, &filename)?) {
        Ok(text) => text.trim().parse::<usize>().map_err(|_| integrity())?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(_) => return Err(unavailable()),
    };
    let owned = root.to_owned();
    let broker = BulkBroker::new(BulkConfig::default())?
        .with_npm_rates(1, 1)?
        .with_attempt_budget(20)?
        .with_attempt_observer(
            initial,
            Arc::new(move |count| persist(&owned, &filename, &json!(count))),
        )?;
    Ok(Arc::new(broker))
}
fn receipt<'a>(observations: &'a Value, key: &str) -> Result<&'a Value> {
    observations
        .get(key)
        .filter(|value| value.is_object())
        .ok_or_else(integrity)
}
struct FixedRequest<'a> {
    key: &'a str,
    operation: Operation,
    max: u64,
}
async fn fetch(
    root: &Path,
    raw: &BulkArtifactStore,
    broker: &BulkBroker,
    request: FixedRequest<'_>,
    observations: &mut Value,
    cancel: &CancellationToken,
    progress_name: &str,
) -> Result<()> {
    let FixedRequest {
        key,
        operation,
        max,
    } = request;
    let expected = operation.url()?;
    if let Some(saved) = observations.get(key) {
        if saved["source_url"] != expected {
            return Err(integrity());
        }
        verified(raw, saved, max, cancel).await?;
        return Ok(());
    }
    let observed_at = devres_domain::unix_now();
    let response = broker
        .open(
            BulkRequest {
                source: BulkSource::Npm(operation),
                validators: Validators::default(),
                max_bytes: max,
                deadline: tokio::time::Instant::now() + Duration::from_secs(900),
                body: Vec::new(),
            },
            cancel.clone(),
        )
        .await?;
    if response.status != 200 {
        return Err(Error::unavailable("Fixed npm source did not return 200."));
    }
    let artifact = raw.capture(response, None, cancel.clone()).await?;
    observations[key] = json!({"source_url":expected,"artifact":artifact,"validated_at":observed_at,"whole_source":false,"provider_endorsement":false});
    persist(
        root,
        progress_name,
        &json!({"version":1,"observations":observations,"whole_source":false,"provider_endorsement":false}),
    )
}
async fn verified(
    raw: &BulkArtifactStore,
    receipt: &Value,
    max: u64,
    cancel: &CancellationToken,
) -> Result<BulkArtifact> {
    let artifact: BulkArtifact =
        serde_json::from_value(receipt["artifact"].clone()).map_err(|_| integrity())?;
    if receipt["whole_source"] != false
        || receipt["provider_endorsement"] != false
        || receipt["validated_at"]
            .as_i64()
            .is_none_or(|value| value <= 0)
        || std::path::Path::new(&artifact.relative_path)
            != content_integrity::relative_path(&artifact.body_hash)?
    {
        return Err(integrity());
    }
    let checked = raw.verify(&artifact.body_hash, max, cancel.clone()).await?;
    if checked != artifact {
        return Err(integrity());
    }
    Ok(artifact)
}
async fn body(
    raw: &BulkArtifactStore,
    receipt: &Value,
    max: u64,
    cancel: &CancellationToken,
) -> Result<Vec<u8>> {
    let artifact = verified(raw, receipt, max, cancel).await?;
    let mut bytes = Vec::new();
    raw.open(&artifact.body_hash, max, cancel.clone())
        .await?
        .take(max + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| unavailable())?;
    if bytes.len() as u64 != artifact.bytes {
        return Err(integrity());
    }
    Ok(bytes)
}
fn advisory_member(file: std::fs::File) -> Result<Vec<u8>> {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut archive = npm_processing::open_advisory_zip(file)?;
    // The shared constructor bounds the export's metadata. This probe proves
    // only one named advisory, so unrelated member bodies are never inspected.
    let expected = format!("{ADVISORY}.json");
    let mut member = archive.by_name(&expected).map_err(|error| match error {
        zip::result::ZipError::FileNotFound => {
            Error::not_found("Fixed GHSA record is absent from the retained npm export.")
        }
        _ => integrity(),
    })?;
    if member.name().map_err(|_| integrity())?.as_ref() != expected
        || member.is_dir()
        || member.encrypted()
        || member
            .unix_mode()
            .is_some_and(|mode| !matches!(mode & 0o170000, 0 | 0o100000))
    {
        return Err(integrity());
    }
    let declared_size = member.size();
    if declared_size > 1024 * 1024 {
        return Err(Error::capacity("Fixed OSV record exceeds 1 MiB."));
    }
    let mut bytes = Vec::new();
    let mut buffer = [0; 8192];
    loop {
        if Instant::now() > deadline {
            return Err(Error::capacity("Fixed OSV inspection deadline exceeded."));
        }
        let count = Read::read(&mut member, &mut buffer).map_err(|_| integrity())?;
        if count == 0 {
            break;
        }
        if bytes.len() + count > 1024 * 1024 {
            return Err(Error::capacity("Fixed OSV record exceeds 1 MiB."));
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    if bytes.len() as u64 != declared_size || npm_audit::parse_advisory(&bytes)?["id"] != ADVISORY {
        return Err(integrity());
    }
    Ok(bytes)
}

async fn inspect_observations(
    raw: &BulkArtifactStore,
    observations: &Value,
    cancel: &CancellationToken,
) -> Result<Value> {
    let mut records = Vec::new();
    for (name, version) in RECORDS {
        let metadata = receipt(observations, &format!("metadata:{name}"))?;
        if metadata["source_url"] != (Operation::Metadata { name: name.into() }).url()? {
            return Err(integrity());
        }
        let bytes = body(raw, metadata, npm_processing::MAX_METADATA as u64, cancel).await?;
        let packument = npm_processing::parse_packument(&bytes, name)?;
        let manifest = packument["versions"].get(version).ok_or_else(integrity)?;
        let tarball = manifest["dist"]["tarball"].as_str().ok_or_else(integrity)?;
        let source = Operation::Archive {
            name: name.into(),
            version: version.into(),
            url: tarball.into(),
        }
        .url()?;
        let archive = receipt(observations, &format!("archive:{name}@{version}"))?;
        if archive["source_url"] != source {
            return Err(integrity());
        }
        let bytes = body(raw, archive, npm_processing::MAX_ARCHIVE as u64, cancel).await?;
        let projection = npm_processing::inspect_package(&bytes, manifest)?;
        let checksum = npm_processing::verify_integrity(&bytes, manifest)?;
        records.push(json!({"name":name,"version":version,"metadata_capture":metadata,"archive_capture":archive,"checksum":checksum,"members":projection["members"].as_array().map_or(0,Vec::len),"documents":projection["documents"].as_array().map_or(0,Vec::len),"projection_sha256":digest(&serde_json::to_vec(&projection).map_err(|_|integrity())?),"gaps":projection["gaps"],"whole_source":false,"provider_endorsement":false}));
    }
    let export = receipt(observations, "osv:npm")?;
    if export["source_url"] != Operation::AdvisoryExport.url()? {
        return Err(integrity());
    }
    let artifact = verified(raw, export, MAX_EXPORT, cancel).await?;
    let (file, materialized) = raw
        .open(&artifact.body_hash, MAX_EXPORT, cancel.clone())
        .await?
        .into_std()
        .await;
    let bytes = tokio::task::spawn_blocking(move || {
        let _materialized = materialized;
        advisory_member(file)
    })
    .await
    .map_err(|_| unavailable())??;
    let advisory = npm_audit::parse_advisory(&bytes)?;
    if advisory["id"] != ADVISORY {
        return Err(integrity());
    }
    let assessment = npm_audit::match_record(&advisory, "lodash", "4.17.15")?;
    if assessment["matched"] != true || assessment["complete"] != true {
        return Err(Error::integrity(
            "Fixed GHSA assessment did not match the expected supported version.",
        ));
    }
    Ok(
        json!({"packages":records,"advisory":{"id":ADVISORY,"record_sha256":digest(&bytes),"export":export,"assessment":assessment,"whole_source":false,"provider_endorsement":false}}),
    )
}
async fn run(root: &Path, resume: bool) -> Result<Value> {
    if safe_file(root, "live-receipt.json")?.exists() {
        return Err(Error::invalid(
            "npm live receipt already exists; use --replay.",
        ));
    }
    let progress = safe_file(root, "live-progress.json")?;
    if resume && !progress.exists() {
        return Err(Error::invalid("npm resume requires retained progress."));
    }
    let mut observations = if progress.exists() {
        read_json(root, "live-progress.json")?["observations"].clone()
    } else {
        json!({})
    };
    if !observations.is_object() {
        return Err(integrity());
    }
    if !progress.exists() {
        persist(
            root,
            "live-progress.json",
            &json!({"version":1,"observations":observations,"whole_source":false,"provider_endorsement":false}),
        )?;
    }
    let registry = counted_broker(root, "registry")?;
    let osv = counted_broker(root, "osv")?;
    let raw = raw_store(root, true)?;
    let cancel = CancellationToken::new();
    let stop = cancel.clone();
    let signal = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            stop.cancel();
        }
    });
    let result=async {
        for (name,version) in RECORDS {
            fetch(root,&raw,&registry,FixedRequest{key:&format!("metadata:{name}"),operation:Operation::Metadata{name:name.into()},max:npm_processing::MAX_METADATA as u64},&mut observations,&cancel,"live-progress.json").await?;
            let metadata=receipt(&observations,&format!("metadata:{name}"))?;
            let bytes=body(&raw,metadata,npm_processing::MAX_METADATA as u64,&cancel).await?;
            let packument=npm_processing::parse_packument(&bytes,name)?;
            let url=packument["versions"][version]["dist"]["tarball"].as_str().ok_or_else(integrity)?.to_owned();
            fetch(root,&raw,&registry,FixedRequest{key:&format!("archive:{name}@{version}"),operation:Operation::Archive{name:name.into(),version:version.into(),url},max:npm_processing::MAX_ARCHIVE as u64},&mut observations,&cancel,"live-progress.json").await?;
        }
        fetch(root,&raw,&osv,FixedRequest{key:"osv:npm",operation:Operation::AdvisoryExport,max:MAX_EXPORT},&mut observations,&cancel,"live-progress.json").await?;
        let evidence=inspect_observations(&raw,&observations,&cancel).await?;
        let receipt=json!({"version":1,"complete":true,"evidence":"bounded_provider_and_parser","whole_source":false,"provider_endorsement":false,"full_history":false,"transport_acceptance":false,"attempt_limit_per_provider":20,"registry_attempts":registry.attempt_count(),"osv_attempts":osv.attempt_count(),"observations":observations,"evidence_records":evidence});
        persist(root,"live-receipt.json",&receipt)?;Ok(receipt)
    }.await;
    signal.abort();
    result
}
async fn replay(root: &Path) -> Result<Value> {
    // No BulkBroker or other HTTP client is constructed on this branch.
    let receipt = read_json(root, "live-receipt.json")?;
    if receipt["version"] != 1
        || receipt["whole_source"] != false
        || receipt["provider_endorsement"] != false
    {
        return Err(integrity());
    }
    let raw = raw_store(root, false)?;
    let evidence =
        inspect_observations(&raw, &receipt["observations"], &CancellationToken::new()).await?;
    if evidence != receipt["evidence_records"] {
        return Err(integrity());
    }
    Ok(
        json!({"version":1,"complete":true,"evidence":"offline_replay","network_attempts":0,"whole_source":false,"provider_endorsement":false,"original_receipt_sha256":digest(&std::fs::read(safe_file(root,"live-receipt.json")?).map_err(|_|unavailable())?),"original_observations":receipt["observations"],"evidence_records":evidence}),
    )
}

struct RetainedMetadata(HashMap<String, StoredCapture>);
#[async_trait]
impl Store for RetainedMetadata {
    async fn latest(&self, _: &str) -> Result<Option<Cached>> {
        Err(integrity())
    }
    async fn capture(&self, id: &str) -> Result<StoredCapture> {
        self.0.get(id).cloned().ok_or_else(integrity)
    }
    async fn publish(&self, _: &FetchRequest, _: FetchResponse, _: i64) -> Result<StoredCapture> {
        Err(integrity())
    }
    async fn revalidate(&self, _: &str, _: &str, _: Validators, _: i64) -> Result<StoredCapture> {
        Err(integrity())
    }
}
struct NoNetwork(AtomicUsize);
#[async_trait]
impl Fetcher for NoNetwork {
    async fn fetch(&self, _: &FetchRequest, _: Option<&Validators>) -> Result<FetchResponse> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(Error::integrity(
            "Retained npm inspection cannot fetch providers.",
        ))
    }
}

fn metadata_requests() -> Vec<(String, Operation, u64)> {
    let mut requests = METADATA_RECORDS
        .into_iter()
        .map(|(name, _)| {
            (
                format!("metadata:{name}"),
                Operation::Metadata { name: name.into() },
                npm_processing::MAX_METADATA as u64,
            )
        })
        .collect::<Vec<_>>();
    requests.push((
        "search:TLS".into(),
        Operation::Search {
            query: SEARCH_QUERY.into(),
            offset: 0,
            limit: 100,
        },
        SEARCH_MAX,
    ));
    requests
}

async fn inspect_metadata_observations(
    raw: &BulkArtifactStore,
    observations: &Value,
    cancel: &CancellationToken,
) -> Result<Value> {
    let requests = metadata_requests();
    if observations
        .as_object()
        .is_none_or(|items| items.len() != requests.len())
    {
        return Err(integrity());
    }
    let mut captures = HashMap::new();
    let mut pins = HashMap::new();
    for (key, operation, max) in requests {
        let saved = receipt(observations, &key)?;
        let source_url = operation.url()?;
        if saved["source_url"] != source_url {
            return Err(integrity());
        }
        let bytes = body(raw, saved, max, cancel).await?;
        let artifact: BulkArtifact =
            serde_json::from_value(saved["artifact"].clone()).map_err(|_| integrity())?;
        let validated_at = saved["validated_at"].as_i64().ok_or_else(integrity)?;
        let request_key = match operation {
            Operation::Metadata { name } => format!("npm:metadata:{name}"),
            Operation::Search { .. } => format!("npm:search:{SEARCH_QUERY}:0"),
            _ => return Err(integrity()),
        };
        pins.insert(key, artifact.body_hash.clone());
        captures.insert(
            artifact.body_hash.clone(),
            StoredCapture {
                capture: Capture {
                    id: artifact.body_hash.clone(),
                    key: request_key,
                    source_url,
                    body_hash: artifact.body_hash,
                    media_type: "application/json".into(),
                    retrieved_at: validated_at,
                    validated_at,
                },
                body: bytes.into(),
            },
        );
    }
    let offline = Arc::new(NoNetwork(AtomicUsize::new(0)));
    let packages = NpmPackages::new(Arc::new(Retrieval::new(
        Arc::new(RetainedMetadata(captures)),
        offline.clone(),
    )));
    let mut records = Vec::new();
    for (name, version) in METADATA_RECORDS {
        let key = format!("metadata:{name}");
        let pin = pins.get(&key).ok_or_else(integrity)?;
        let selected = packages
            .call(
                "npm.metadata",
                json!({"name":name,"version":version,"capture":pin}),
            )
            .await?;
        // Keep source times from observations. Derived stale flags change with
        // wall time and are deliberately outside deterministic replay evidence.
        records.push(json!({"name":name,"version":version,"metadata":selected["metadata"],"dist_tags":selected["dist_tags"],"time":selected["time"],"capture":observations[key]}));
    }
    let search = packages.call("npm.search",json!({"query":SEARCH_QUERY,"limit":3,"capture":pins.get("search:TLS").ok_or_else(integrity)?})).await?;
    if offline.0.load(Ordering::SeqCst) != 0 {
        return Err(integrity());
    }
    Ok(
        json!({"packages":records,"search":{"query":SEARCH_QUERY,"items":search["items"],"total":search["total"],"capture":observations["search:TLS"]},"foreground_tools":["npm.metadata","npm.search"],"inspection_network_attempts":0}),
    )
}

async fn run_metadata(root: &Path) -> Result<Value> {
    if safe_file(root, "metadata-receipt.json")?.exists() {
        return Err(Error::invalid(
            "npm metadata receipt exists; use --replay-metadata.",
        ));
    }
    let progress = safe_file(root, "metadata-progress.json")?;
    let mut observations = if progress.exists() {
        let saved = read_json(root, "metadata-progress.json")?;
        if saved["version"] != 1
            || saved["whole_source"] != false
            || saved["provider_endorsement"] != false
        {
            return Err(integrity());
        }
        saved["observations"].clone()
    } else {
        json!({})
    };
    if !observations.is_object() {
        return Err(integrity());
    }
    let registry = counted_broker(root, "registry")?;
    let raw = raw_store(root, true)?;
    let cancel = CancellationToken::new();
    let stop = cancel.clone();
    let signal = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            stop.cancel();
        }
    });
    let result = async {
        for (key,operation,max) in metadata_requests() {
            fetch(root,&raw,&registry,FixedRequest{key:&key,operation,max},&mut observations,&cancel,"metadata-progress.json").await?;
        }
        let evidence = inspect_metadata_observations(&raw,&observations,&cancel).await?;
        let receipt = json!({"version":1,"mode":"fixed_metadata_and_search","complete":true,"evidence":"bounded_provider_and_foreground_parser","whole_source":false,"provider_endorsement":false,"full_history":false,"transport_acceptance":false,"attempt_limit_per_provider":20,"registry_attempts":registry.attempt_count(),"osv_attempts":0,"observations":observations,"evidence_records":evidence});
        persist(root,"metadata-receipt.json",&receipt)?;
        Ok(receipt)
    }.await;
    signal.abort();
    result
}

async fn replay_metadata(root: &Path) -> Result<Value> {
    // This branch constructs neither BulkBroker nor an HTTP client.
    let saved = read_json(root, "metadata-receipt.json")?;
    if saved["version"] != 1
        || saved["mode"] != "fixed_metadata_and_search"
        || saved["complete"] != true
        || saved["whole_source"] != false
        || saved["provider_endorsement"] != false
        || saved["registry_attempts"].as_u64().is_none_or(|n| n > 20)
        || saved["osv_attempts"] != 0
    {
        return Err(integrity());
    }
    let raw = raw_store(root, false)?;
    let evidence =
        inspect_metadata_observations(&raw, &saved["observations"], &CancellationToken::new())
            .await?;
    if evidence != saved["evidence_records"] {
        return Err(integrity());
    }
    Ok(
        json!({"version":1,"complete":true,"mode":"fixed_metadata_and_search","evidence":"offline_replay","network_attempts":0,"whole_source":false,"provider_endorsement":false,"original_receipt_sha256":digest(&std::fs::read(safe_file(root,"metadata-receipt.json")?).map_err(|_|unavailable())?),"original_observations":saved["observations"],"evidence_records":evidence}),
    )
}

#[tokio::main]
async fn main() {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3
        || !matches!(
            args[1].as_str(),
            "--live" | "--resume" | "--replay" | "--live-metadata" | "--replay-metadata"
        )
    {
        eprintln!(
            "usage: npm-live-probe --live|--resume|--replay|--live-metadata|--replay-metadata OWNED_ROOT"
        );
        std::process::exit(2);
    }
    let result = async {
        let root = root::owned_root(Path::new(&args[2]), MARKER)?;
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(safe_file(&root, "live.lock")?)
            .map_err(|_| unavailable())?;
        fs2::FileExt::try_lock_exclusive(&lock)
            .map_err(|_| Error::capacity("npm acceptance already owns this root."))?;
        match args[1].as_str() {
            "--replay" => replay(&root).await,
            "--live-metadata" => run_metadata(&root).await,
            "--replay-metadata" => replay_metadata(&root).await,
            _ => run(&root, args[1] == "--resume").await,
        }
    }
    .await;
    match result {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("{}: {}", error.code, error.message);
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::STANDARD};
    use flate2::{Compression, write::GzEncoder};
    use sha2::Sha512;
    use std::os::unix::fs::{PermissionsExt, symlink};
    fn owned() -> tempfile::TempDir {
        let temporary = tempfile::tempdir_in(std::env::temp_dir()).expect("temporary root");
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))
            .expect("root permissions");
        std::fs::write(temporary.path().join("owner-v1"), MARKER).expect("marker");
        temporary
    }
    async fn evidence() -> (tempfile::TempDir, Value) {
        let temporary = owned();
        let root = temporary.path();
        let raw = raw_store(root, true).expect("raw");
        let cancel = CancellationToken::new();
        let mut observations = json!({});
        for (name, version) in RECORDS {
            let manifest = json!({"name":name,"version":version});
            let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::fast()));
            let manifest_bytes = serde_json::to_vec(&manifest).expect("manifest");
            let mut header = tar::Header::new_gnu();
            header.set_size(manifest_bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(
                    &mut header,
                    "package/package.json",
                    manifest_bytes.as_slice(),
                )
                .expect("package");
            let bytes = builder.into_inner().expect("tar").finish().expect("gzip");
            let url = format!(
                "https://registry.npmjs.org/{name}/-/{base}-{version}.tgz",
                base = name.rsplit('/').next().expect("basename")
            );
            let mut manifest = manifest;
            manifest["dist"] = json!({"tarball":url,"integrity":format!("sha512-{}",STANDARD.encode(Sha512::digest(&bytes)))});
            let archive = raw
                .capture_bytes(bytes, cancel.clone())
                .await
                .expect("archive");
            let metadata = raw
                .capture_bytes(
                    serde_json::to_vec(&json!({"name":name,"versions":{version:manifest}}))
                        .expect("packument"),
                    cancel.clone(),
                )
                .await
                .expect("metadata");
            observations[format!("metadata:{name}")] = json!({"source_url":Operation::Metadata{name:name.into()}.url().expect("metadata URL"),"artifact":metadata,"validated_at":1,"whole_source":false,"provider_endorsement":false});
            observations[format!("archive:{name}@{version}")] = json!({"source_url":url,"artifact":archive,"validated_at":1,"whole_source":false,"provider_endorsement":false});
        }
        let advisory = json!({"schema_version":"1.6.0","id":ADVISORY,"modified":"2026-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"lodash"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"4.17.19"}]}]}]});
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        writer
            .start_file(
                format!("{ADVISORY}.json"),
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored),
            )
            .expect("ZIP member");
        writer
            .write_all(&serde_json::to_vec(&advisory).expect("advisory"))
            .expect("ZIP bytes");
        let artifact = raw
            .capture_bytes(writer.finish().expect("ZIP").into_inner(), cancel.clone())
            .await
            .expect("export");
        observations["osv:npm"] = json!({"source_url":Operation::AdvisoryExport.url().expect("OSV URL"),"artifact":artifact,"validated_at":1,"whole_source":false,"provider_endorsement":false});
        let evidence = inspect_observations(&raw, &observations, &cancel)
            .await
            .expect("fixed observations");
        persist(root,"live-receipt.json",&json!({"version":1,"complete":true,"whole_source":false,"provider_endorsement":false,"observations":observations,"evidence_records":evidence})).expect("receipt");
        (temporary, observations)
    }
    #[tokio::test]
    async fn replay_revalidates_all_fixed_evidence_without_changing_source_times() {
        let (root, observations) = evidence().await;
        let before = std::fs::read(root.path().join("live-receipt.json")).expect("receipt");
        let result = replay(root.path()).await.expect("replay");
        assert_eq!(result["network_attempts"], 0);
        assert_eq!(result["original_observations"], observations);
        assert_eq!(
            std::fs::read(root.path().join("live-receipt.json")).expect("receipt"),
            before
        );
        assert_eq!(result["whole_source"], false);
    }
    #[tokio::test]
    async fn replay_rejects_tampered_artifacts_and_source_provenance() {
        let (root, observations) = evidence().await;
        let artifact = &observations["metadata:is-number"]["artifact"];
        std::fs::write(
            root.path()
                .join("raw")
                .join(artifact["relative_path"].as_str().expect("artifact path")),
            b"tampered",
        )
        .expect("tamper");
        assert!(replay(root.path()).await.is_err());
        let (root, _) = evidence().await;
        let mut receipt = read_json(root.path(), "live-receipt.json").expect("receipt");
        receipt["observations"]["metadata:is-number"]["source_url"] =
            json!("https://example.invalid/is-number");
        persist(root.path(), "live-receipt.json", &receipt).expect("tamper receipt");
        assert!(replay(root.path()).await.is_err());
    }

    async fn metadata_evidence() -> (tempfile::TempDir, Value) {
        let temporary = owned();
        let raw = raw_store(temporary.path(), true).expect("raw");
        let cancel = CancellationToken::new();
        let mut observations = json!({});
        for (key, operation, _) in metadata_requests() {
            let value = match &operation {
                Operation::Metadata { name } => {
                    let version = METADATA_RECORDS
                        .iter()
                        .find(|(fixed, _)| *fixed == name.as_str())
                        .expect("fixed package")
                        .1;
                    json!({"name":name,"versions":{version:{"name":name,"version":version,"dependencies":{"fixture":"^1.0.0"}}},"dist-tags":{"latest":version},"time":{"created":"2020-01-01",version:"2021-01-01","modified":"2026-01-01"}})
                }
                Operation::Search { .. } => {
                    json!({"objects":[{"package":{"name":"tls-fixture","version":"1.0.0","description":"Synthetic TLS search fixture"},"score":{"final":478.37408,"detail":{"quality":0.875}},"searchScore":478.37408}],"total":1})
                }
                _ => panic!("metadata mode attempted archive or OSV acquisition"),
            };
            let artifact = raw
                .capture_bytes(
                    serde_json::to_vec(&value).expect("fixture JSON"),
                    cancel.clone(),
                )
                .await
                .expect("capture");
            observations[key] = json!({"source_url":operation.url().expect("fixed source"),"artifact":artifact,"validated_at":1,"whole_source":false,"provider_endorsement":false});
        }
        let evidence = inspect_metadata_observations(&raw, &observations, &cancel)
            .await
            .expect("foreground inspection");
        persist(temporary.path(),"metadata-receipt.json",&json!({"version":1,"mode":"fixed_metadata_and_search","complete":true,"whole_source":false,"provider_endorsement":false,"registry_attempts":0,"osv_attempts":0,"observations":observations,"evidence_records":evidence})).expect("metadata receipt");
        (temporary, observations)
    }

    #[tokio::test]
    async fn metadata_replay_exercises_foreground_tools_without_network_or_counter_changes() {
        let (root, observations) = metadata_evidence().await;
        persist(root.path(), "registry-attempt-count", &json!(19))
            .expect("existing attempt ledger");
        let original = std::fs::read(root.path().join("metadata-receipt.json")).expect("receipt");
        let result = replay_metadata(root.path())
            .await
            .expect("offline metadata replay");
        assert_eq!(result["network_attempts"], 0);
        assert_eq!(result["original_observations"], observations);
        assert_eq!(result["evidence_records"]["packages"][0]["name"], "react");
        assert_eq!(
            result["evidence_records"]["packages"][0]["version"],
            "18.3.1"
        );
        assert_eq!(
            result["evidence_records"]["packages"][1]["name"],
            "left-pad"
        );
        assert_eq!(result["evidence_records"]["search"]["query"], "TLS");
        assert!(result["evidence_records"]["search"]["items"][0]["score"]["final"].is_number());
        assert_eq!(
            result["evidence_records"]["search"]["items"][0]["score"]["final"].to_string(),
            "478.37408"
        );
        assert_eq!(result["evidence_records"]["inspection_network_attempts"], 0);
        assert_eq!(
            std::fs::read(root.path().join("metadata-receipt.json")).expect("receipt"),
            original
        );
        assert_eq!(
            read_json(root.path(), "registry-attempt-count").expect("ledger"),
            19
        );
        assert!(!root.path().join("osv-attempt-count").exists());
        assert!(!root.path().join("live-receipt.json").exists());
    }

    #[tokio::test]
    async fn metadata_replay_rejects_raw_source_and_attempt_provenance_tampering() {
        let (root, observations) = metadata_evidence().await;
        let path = observations["metadata:react"]["artifact"]["relative_path"]
            .as_str()
            .expect("capture path");
        std::fs::write(root.path().join("raw").join(path), b"tampered").expect("tamper raw");
        assert!(replay_metadata(root.path()).await.is_err());
        let (root, _) = metadata_evidence().await;
        let mut saved = read_json(root.path(), "metadata-receipt.json").expect("receipt");
        saved["observations"]["metadata:react"]["source_url"] =
            json!("https://example.invalid/react");
        persist(root.path(), "metadata-receipt.json", &saved).expect("tamper source");
        assert!(replay_metadata(root.path()).await.is_err());
        saved["observations"]["metadata:react"]["source_url"] = json!(
            Operation::Metadata {
                name: "react".into()
            }
            .url()
            .expect("fixed URL")
        );
        saved["registry_attempts"] = json!(21);
        persist(root.path(), "metadata-receipt.json", &saved).expect("tamper counter");
        assert!(replay_metadata(root.path()).await.is_err());
    }
    #[test]
    fn provider_budgets_survive_restarts_and_reject_symlinked_state() {
        let root = owned();
        persist(root.path(), "registry-attempt-count", &json!(19)).expect("counter");
        assert_eq!(
            counted_broker(root.path(), "registry")
                .expect("broker")
                .attempt_count(),
            19
        );
        assert_eq!(
            std::fs::read_to_string(root.path().join("registry-attempt-count"))
                .expect("counter")
                .trim(),
            "19"
        );
        persist(root.path(), "registry-attempt-count", &json!(21)).expect("counter");
        assert!(counted_broker(root.path(), "registry").is_err());
        symlink(
            "registry-attempt-count",
            root.path().join("osv-attempt-count"),
        )
        .expect("symlink");
        assert!(counted_broker(root.path(), "osv").is_err());
    }

    #[test]
    fn fixed_advisory_selection_ignores_unrelated_member_bodies_and_checks_crc() {
        use std::io::{Seek as _, Write as _};
        let selected=serde_json::to_vec(&json!({"schema_version":"1.6.0","id":ADVISORY,"modified":"2026-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"lodash"},"versions":["4.17.15"]}]})).expect("selected record");
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for index in 0..200 {
            writer
                .add_directory(format!("directory-{index}/"), options)
                .expect("unrelated directory");
        }
        writer
            .start_file("unrelated.json", options)
            .expect("unrelated member");
        writer
            .write_all(b"not parsed as an advisory")
            .expect("unrelated body");
        writer
            .start_file(format!("{ADVISORY}.json"), options)
            .expect("named member");
        writer.write_all(&selected).expect("named body");
        let bytes = writer.finish().expect("ZIP").into_inner();
        let file = |bytes: &[u8]| {
            let mut file = tempfile::tempfile_in("/tmp").expect("ZIP fixture");
            file.write_all(bytes).expect("ZIP bytes");
            file.rewind().expect("rewind");
            file
        };
        assert_eq!(
            advisory_member(file(&bytes)).expect("named record"),
            selected
        );
        let mut corrupt = bytes;
        let position = corrupt
            .windows(selected.len())
            .position(|window| window == selected)
            .expect("stored body offset");
        corrupt[position] ^= 1;
        assert!(advisory_member(file(&corrupt)).is_err());
    }
}
