//! Private fixed-record deployment evidence. No collectors, package execution or publication.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use devres_adapters::{
    HttpFetcher,
    attribution_providers::{self, AttributionSource},
    bulk::{BulkBroker, BulkConfig, BulkRequest, BulkSource, GitOperation},
    chromium::{ChromiumCorpus, source as chromium},
    integrity,
};
use devres_application::Fetcher;
use devres_domain::{Error, FetchRequest, Result, Validators};
use fs2::FileExt;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

#[path = "../support/root.rs"]
mod root;

const REVISION: &str = "a938112b5af87996661ddd91ae68755dc0d579b9";
const MARKER: &[u8] = b"devres-deployment-live-v1\n";
const FAMILIES: [&str; 8] = [
    "rfc", "crates", "rustsec", "mdn", "whatwg", "w3c", "chromium", "npm",
];
const MAX_BODY: usize = 16 * 1024 * 1024;

fn bad() -> Error {
    Error::integrity("Deployment evidence or accounting is invalid.")
}
fn io_error() -> Error {
    Error::unavailable("Deployment evidence storage is unavailable.")
}

fn save(path: &Path, bytes: &[u8]) -> Result<()> {
    let stage = path.with_extension("stage");
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&stage)
        .map_err(|_| io_error())?;
    output
        .write_all(bytes)
        .and_then(|()| output.sync_all())
        .map_err(|_| io_error())?;
    std::fs::rename(stage, path).map_err(|_| io_error())?;
    File::open(path.parent().ok_or_else(bad)?)
        .and_then(|file| file.sync_all())
        .map_err(|_| io_error())
}
fn save_json(path: &Path, value: &impl Serialize) -> Result<()> {
    save(path, &serde_json::to_vec_pretty(value).map_err(|_| bad())?)
}
fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let meta = std::fs::symlink_metadata(path).map_err(|_| io_error())?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 1024 * 1024 {
        return Err(bad());
    }
    serde_json::from_slice(&std::fs::read(path).map_err(|_| io_error())?).map_err(|_| bad())
}

fn verify_artifacts(root: &Path, value: &Value) -> Result<()> {
    match value {
        Value::Object(map) => {
            if let Some(name) = map.get("file").and_then(Value::as_str) {
                if !name.ends_with(".bin") || name.contains(['/', '\\']) {
                    return Err(bad());
                }
                let path = root.join(name);
                let meta = std::fs::symlink_metadata(&path).map_err(|_| bad())?;
                if !meta.is_file()
                    || meta.file_type().is_symlink()
                    || meta.len() > MAX_BODY as u64
                    || map.get("bytes").and_then(Value::as_u64) != Some(meta.len())
                {
                    return Err(bad());
                }
                let bytes = std::fs::read(path).map_err(|_| bad())?;
                if map.get("body_hash").and_then(Value::as_str)
                    != Some(integrity::hash(&bytes).as_str())
                {
                    return Err(bad());
                }
            }
            for child in map.values() {
                verify_artifacts(root, child)?;
            }
        }
        Value::Array(items) => {
            for child in items {
                verify_artifacts(root, child)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    version: u32,
    revision: String,
    families: BTreeMap<String, usize>,
    hosts: BTreeMap<String, usize>,
    github: usize,
}
impl Ledger {
    fn new() -> Self {
        Self {
            version: 1,
            revision: REVISION.into(),
            ..Self::default()
        }
    }
    fn validate(&self) -> Result<()> {
        if self.version != 1
            || self.revision != REVISION
            || self.github > 20
            || self
                .families
                .iter()
                .any(|(f, n)| !FAMILIES.contains(&f.as_str()) || *n > 20)
            || self
                .hosts
                .iter()
                .any(|(host, count)| !known_host(host) || *count > 160)
            || self.hosts.values().sum::<usize>() != self.families.values().sum::<usize>()
            || self
                .hosts
                .iter()
                .filter(|(h, _)| github(h))
                .map(|(_, n)| n)
                .sum::<usize>()
                != self.github
        {
            return Err(bad());
        }
        Ok(())
    }
    fn reserve(&mut self, family: &str, host: &str) -> Result<()> {
        self.validate()?;
        if !FAMILIES.contains(&family) || !known_host(host) {
            return Err(bad());
        }
        let count = self.families.get(family).copied().unwrap_or(0);
        if count >= 20 || (github(host) && self.github >= 20) {
            return Err(Error::capacity(
                "Deployment retained source attempt budget exhausted.",
            ));
        }
        *self.families.entry(family.into()).or_default() += 1;
        *self.hosts.entry(host.into()).or_default() += 1;
        if github(host) {
            self.github += 1;
        }
        Ok(())
    }
}
fn github(host: &str) -> bool {
    matches!(
        host,
        "github.com" | "api.github.com" | "codeload.github.com" | "raw.githubusercontent.com"
    )
}
fn known_host(host: &str) -> bool {
    github(host)
        || matches!(
            host,
            "www.rfc-editor.org"
                | "index.crates.io"
                | "static.crates.io"
                | "registry.npmjs.org"
                | "www.w3.org"
                | "chromium.googlesource.com"
        )
}

struct Probe {
    root: PathBuf,
    ledger: Arc<Mutex<Ledger>>,
    brokers: BTreeMap<(String, String), Arc<BulkBroker>>,
    cancel: CancellationToken,
}
impl Probe {
    fn broker(&mut self, family: &str, host: &str) -> Result<Arc<BulkBroker>> {
        if !FAMILIES.contains(&family) || !known_host(host) {
            return Err(bad());
        }
        let key = (family.to_owned(), host.to_owned());
        if let Some(broker) = self.brokers.get(&key) {
            return Ok(broker.clone());
        }
        let ledger = self.ledger.clone();
        let path = self.root.join("attempts.json");
        let (family, host) = key.clone();
        let broker = BulkBroker::new(BulkConfig {
            max_transfers: 1,
            ..Default::default()
        })?
        .with_attempt_budget(20)?
        .with_attempt_observer(
            0,
            Arc::new(move |_| {
                let mut current = ledger.lock().map_err(|_| bad())?;
                // A failed fsync never permits I/O. Interrupted reservations remain spent.
                current.reserve(&family, &host)?;
                save_json(&path, &*current)?;
                // Serial acceptance conservatively stays below every source's 1/s clock,
                // including requests crossing broker/family boundaries and process restarts.
                std::thread::sleep(Duration::from_secs(1));
                Ok(())
            }),
        )?;
        let broker = Arc::new(broker);
        self.brokers.insert(key, broker.clone());
        Ok(broker)
    }
    async fn fetch(&mut self, family: &str, source: BulkSource) -> Result<(Vec<u8>, Value)> {
        let url = source.url()?;
        let host = source.host().to_owned();
        let response = self
            .broker(family, &host)?
            .open(
                BulkRequest {
                    source,
                    validators: Validators::default(),
                    max_bytes: MAX_BODY as u64,
                    deadline: tokio::time::Instant::now() + Duration::from_secs(90),
                    body: vec![],
                },
                self.cancel.clone(),
            )
            .await?;
        if response.status != 200
            || url::Url::parse(&response.effective_url)
                .map_err(|_| bad())?
                .host_str()
                != Some(host.as_str())
        {
            return Err(Error::unavailable(
                "Fixed source did not return the admitted body.",
            ));
        }
        let mut bytes = Vec::new();
        let mut stream = response.stream;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            if bytes.len().saturating_add(chunk.len()) > MAX_BODY {
                return Err(Error::capacity(
                    "Fixed source body exceeds the probe bound.",
                ));
            }
            bytes.extend_from_slice(&chunk);
        }
        let evidence = json!({"source_url":url,"body_hash":integrity::hash(&bytes),"observed_at":devres_domain::unix_now()});
        Ok((bytes, evidence))
    }
    fn retain(&self, family: &str, label: &str, bytes: &[u8]) -> Result<Value> {
        let path = self.root.join(format!("{family}-{label}.bin"));
        if path.exists() {
            return Err(bad());
        }
        save(&path, bytes)?;
        Ok(
            json!({"file":path.file_name().and_then(|x|x.to_str()).ok_or_else(bad)?,"body_hash":integrity::hash(bytes),"bytes":bytes.len()}),
        )
    }
    async fn rights(&mut self, family: &str, host: &str, evidence: &Value) -> Result<Value> {
        let targets = attribution_providers::targets(family, evidence)?;
        if targets.len() != 1 {
            return Err(bad());
        }
        let generation = attribution_providers::repair(
            &targets[0],
            &self.broker(family, host)?,
            self.cancel.clone(),
        )
        .await?;
        if generation.notices.is_empty() {
            return Err(bad());
        }
        Ok(json!(generation))
    }
    async fn git_record(
        &mut self,
        family: &str,
        repository: &str,
        path: &str,
        advertisement: BulkSource,
    ) -> Result<(Vec<u8>, Value)> {
        let (advert, observed) = self.fetch(family, advertisement).await?;
        let revision = head(&advert)?;
        self.retain(family, "refs", &advert)?;
        let operation = match family {
            "mdn" => AttributionSource::Mdn {
                compatibility: false,
                revision: revision.clone(),
                path: path.into(),
            },
            "rustsec" => AttributionSource::RustSec {
                revision: revision.clone(),
                path: path.into(),
            },
            "whatwg" => AttributionSource::Whatwg {
                repository: devres_adapters::whatwg::git::Repo::new(repository)?,
                revision: revision.clone(),
                path: path.into(),
            },
            _ => return Err(bad()),
        };
        let (bytes, mut evidence) = self
            .fetch(family, BulkSource::Attribution(operation))
            .await?;
        let bytes = decode_git(bytes)?;
        evidence["body_hash"] = json!(integrity::hash(&bytes));
        evidence["revision"] = json!(revision);
        evidence["repository"] = json!(repository);
        evidence["path"] = json!(path);
        evidence["ref_observation"] = observed;
        Ok((bytes, evidence))
    }
    async fn run(&mut self, family: &str) -> Result<Value> {
        match family {
            "rfc" => {
                let (bytes, evidence) = self
                    .fetch(
                        family,
                        BulkSource::Attribution(AttributionSource::Rfc {
                            number: 9000,
                            format: "txt".into(),
                        }),
                    )
                    .await?;
                let rights = self.rights(family, "www.rfc-editor.org", &evidence).await?;
                let text = std::str::from_utf8(&bytes).map_err(|_| bad())?;
                if !text.contains("RFC 9000") || !text.contains("QUIC") {
                    return Err(bad());
                }
                Ok(
                    json!({"source":evidence,"artifact":self.retain(family,"source",&bytes)?,"parser":"released_rfc_notice_and_fixed_text_identity","rights":rights}),
                )
            }
            "crates" => {
                let fetcher = HttpFetcher::with_broker(self.broker(family, "index.crates.io")?)?;
                let url = "https://index.crates.io/it/oa/itoa";
                let response = fetcher
                    .fetch(
                        &FetchRequest {
                            key: "crate:itoa".into(),
                            url: url.into(),
                            ttl_secs: 3600,
                            max_bytes: MAX_BODY,
                            media_type: "application/json".into(),
                        },
                        None,
                    )
                    .await?;
                if response.status != 200 {
                    return Err(bad());
                }
                // The sparse selector is private in the released adapter. Select
                // only this fixed identity; rights repair uses its archive parser.
                let mut selected = None;
                for line in response
                    .body
                    .split(|byte| *byte == b'\n')
                    .filter(|line| !line.is_empty())
                {
                    let value: Value = serde_json::from_slice(line).map_err(|_| bad())?;
                    if value["name"] == "itoa" && value["vers"] == "1.0.15" {
                        if selected.is_some() {
                            return Err(bad());
                        }
                        selected = Some(value);
                    }
                }
                let record = selected.ok_or_else(bad)?;
                let (bytes, evidence) = self
                    .fetch(
                        family,
                        BulkSource::CrateArchive {
                            name: "itoa".into(),
                            version: "1.0.15".into(),
                        },
                    )
                    .await?;
                let digest = hex::encode(Sha256::digest(&bytes));
                if record["cksum"].as_str() != Some(digest.as_str()) {
                    return Err(Error::integrity("Fixed crate published checksum mismatch."));
                }
                let rights = self.rights(family, "static.crates.io", &evidence).await?;
                Ok(
                    json!({"source":evidence,"metadata_source":url,"record":record,"artifact":self.retain(family,"source",&bytes)?,"metadata_artifact":self.retain(family,"metadata",&response.body)?,"parser":"fixed_sparse_identity_and_released_bounded_archive_notice_inspection","published_sha256_verified":true,"rights":rights}),
                )
            }
            "rustsec" | "mdn" | "whatwg" => {
                let (repository, path, advertisement) = match family {
                    "rustsec" => (
                        "rustsec/advisory-db",
                        "crates/odbc/RUSTSEC-2022-0039.md",
                        BulkSource::RustSecGit(GitOperation::Advertisement),
                    ),
                    "mdn" => (
                        "mdn/content",
                        "files/en-us/web/javascript/reference/global_objects/array/index.md",
                        BulkSource::MdnContentGit(GitOperation::Advertisement),
                    ),
                    _ => (
                        "whatwg/dom",
                        "dom.bs",
                        BulkSource::WhatwgGit {
                            repository: devres_adapters::whatwg::git::Repo::new("whatwg/dom")?,
                            operation: GitOperation::Advertisement,
                        },
                    ),
                };
                let (bytes, evidence) = self
                    .git_record(family, repository, path, advertisement)
                    .await?;
                let parser = match family {
                    "rustsec" => {
                        let advisory = ::rustsec::Advisory::from_str(
                            std::str::from_utf8(&bytes).map_err(|_| bad())?,
                        )
                        .map_err(|_| bad())?;
                        if advisory.metadata.id.to_string() != "RUSTSEC-2022-0039"
                            || advisory.metadata.package.as_str() != "odbc"
                        {
                            return Err(bad());
                        }
                        json!({"parser":"rustsec::Advisory::from_str","id":advisory.metadata.id.to_string(),"package":advisory.metadata.package.as_str(),"whole_snapshot_normalization":false})
                    }
                    "mdn" => {
                        let document = devres_adapters::mdn::processing::process_document(
                            path,
                            &bytes,
                            &mut |_| Ok(None),
                            &devres_adapters::mdn::processing::ProcessingBudget::new(
                                self.cancel.clone(),
                            ),
                        )?;
                        if document.text.trim().is_empty() || !document.title.contains("Array") {
                            return Err(bad());
                        }
                        json!({"parser":"released_mdn_document","title":document.title,"gaps":document.gaps,"unresolved_dependencies":document.dependencies})
                    }
                    _ => {
                        let document = devres_adapters::whatwg::processing::process_document(
                            path,
                            &bytes,
                            self.cancel.clone(),
                        )?;
                        if document.text.trim().is_empty() || document.sections.is_empty() {
                            return Err(bad());
                        }
                        json!({"parser":"released_whatwg_document","sections":document.sections.len(),"gaps":document.gaps})
                    }
                };
                let rights = self.rights(family, "api.github.com", &evidence).await?;
                Ok(
                    json!({"source":evidence,"artifact":self.retain(family,"source",&bytes)?,"parser":parser,"rights":rights}),
                )
            }
            "w3c" => {
                let standard = devres_application::w3c::Standard {
                    id: "css-color-4".into(),
                    title: "CSS Color 4".into(),
                    url: "https://www.w3.org/TR/css-color-4/".into(),
                    repository: "w3c/csswg-drafts".into(),
                    metadata: Value::Null,
                };
                let publication = devres_adapters::w3c::catalog::current_publication(&standard)?;
                let (bytes, evidence) = self
                    .fetch(family, BulkSource::W3cPublication(publication))
                    .await?;
                let rights = self.rights(family, "www.w3.org", &evidence).await?;
                let document = devres_adapters::w3c::processing::process_document(
                    "index.html",
                    &bytes,
                    self.cancel.clone(),
                )?;
                if document.sections.is_empty()
                    || !document.text.to_ascii_lowercase().contains("color")
                {
                    return Err(bad());
                }
                Ok(
                    json!({"source":evidence,"artifact":self.retain(family,"source",&bytes)?,"parser":{"name":"released_w3c_document","sections":document.sections.len(),"gaps":document.gaps},"rights":rights}),
                )
            }
            "npm" => {
                let (metadata, meta_evidence) = self
                    .fetch(
                        family,
                        BulkSource::Npm(devres_adapters::npm::source::Operation::Metadata {
                            name: "is-number".into(),
                        }),
                    )
                    .await?;
                let packument =
                    devres_adapters::npm::processing::parse_packument(&metadata, "is-number")?;
                let manifest = packument
                    .get("versions")
                    .and_then(|v| v.get("7.0.0"))
                    .ok_or_else(bad)?;
                let (bytes, evidence) = self
                    .fetch(
                        family,
                        BulkSource::Npm(devres_adapters::npm::source::Operation::Archive {
                            name: "is-number".into(),
                            version: "7.0.0".into(),
                            url: "https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz"
                                .into(),
                        }),
                    )
                    .await?;
                let package = devres_adapters::npm::processing::inspect_package(&bytes, manifest)?;
                let rights = self.rights(family, "registry.npmjs.org", &evidence).await?;
                Ok(
                    json!({"source":evidence,"metadata_source":meta_evidence,"artifact":self.retain(family,"source",&bytes)?,"metadata_artifact":self.retain(family,"metadata",&metadata)?,"parser":"released_npm_packument_and_package_inspection","package":package,"rights":rights,"advisory_export_acceptance":false}),
                )
            }
            "chromium" => self.chromium().await,
            _ => Err(bad()),
        }
    }
    async fn chromium(&mut self) -> Result<Value> {
        let family = "chromium";
        let (refs, ref_evidence) = self
            .fetch(
                family,
                BulkSource::Chromium(chromium::Operation::CurrentRef {
                    component: "src".into(),
                }),
            )
            .await?;
        let parsed = chromium::parse_refs("src", &refs)?;
        let revision = parsed
            .get("HEAD")
            .or_else(|| parsed.get("refs/heads/main"))
            .ok_or_else(bad)?
            .clone();
        let (tree, _) = self
            .fetch(
                family,
                BulkSource::Chromium(chromium::Operation::Tree {
                    component: "src".into(),
                    revision: revision.clone(),
                    path: String::new(),
                }),
            )
            .await?;
        let root = chromium::parse_tree("src", &tree)?;
        let license = root
            .entries
            .iter()
            .find(|e| e.name == "LICENSE" && e.mode == 0o100644)
            .ok_or_else(bad)?;
        let (license_bytes, license_evidence) = self
            .fetch(
                family,
                BulkSource::Chromium(chromium::Operation::Blob {
                    component: "src".into(),
                    revision: revision.clone(),
                    path: "LICENSE".into(),
                }),
            )
            .await?;
        let license_body = chromium::decode_blob("src", &license_bytes, &license.oid)?;
        let decision = ChromiumCorpus::qualify_license(
            "src",
            &license_body,
            license_evidence["source_url"].as_str().ok_or_else(bad)?,
        )?;
        if decision["decision"] != "approved" {
            return Err(Error::unavailable(
                "Fixed Chromium rights remain unresolved.",
            ));
        }
        let (tree, _) = self
            .fetch(
                family,
                BulkSource::Chromium(chromium::Operation::Tree {
                    component: "src".into(),
                    revision: revision.clone(),
                    path: "docs".into(),
                }),
            )
            .await?;
        let docs = chromium::parse_tree("src", &tree)?;
        let readme = docs
            .entries
            .iter()
            .find(|e| e.name == "README.md" && e.mode == 0o100644)
            .ok_or_else(bad)?;
        let (bytes, evidence) = self
            .fetch(
                family,
                BulkSource::Chromium(chromium::Operation::Blob {
                    component: "src".into(),
                    revision: revision.clone(),
                    path: "docs/README.md".into(),
                }),
            )
            .await?;
        let body = chromium::decode_blob("src", &bytes, &readme.oid)?;
        let document = devres_adapters::chromium::processing::process_document(
            "docs/README.md",
            &body,
            self.cancel.clone(),
        )?;
        if document.text.trim().is_empty() {
            return Err(bad());
        }
        Ok(
            json!({"revision":revision,"ref_observation":ref_evidence,"source":evidence,"artifact":self.retain(family,"source",&body)?,"license_artifact":self.retain(family,"license",&license_body)?,"rights":decision,"license_source":license_evidence,"git_blob_verified":true,"parser":{"name":"released_chromium_document","sections":document.sections.len(),"gaps":document.gaps},"other_chromium_components_accepted":false}),
        )
    }
}

fn decode_git(bytes: Vec<u8>) -> Result<Vec<u8>> {
    if let Ok(value) = serde_json::from_slice::<Value>(&bytes)
        && value["encoding"] == "base64"
    {
        let content = value["content"]
            .as_str()
            .ok_or_else(bad)?
            .bytes()
            .filter(|c| !c.is_ascii_whitespace())
            .collect::<Vec<_>>();
        return STANDARD.decode(content).map_err(|_| bad());
    }
    Ok(bytes)
}
fn head(bytes: &[u8]) -> Result<String> {
    let mut rest = bytes;
    while !rest.is_empty() {
        let prefix = rest.get(..4).ok_or_else(bad)?;
        let length = usize::from_str_radix(std::str::from_utf8(prefix).map_err(|_| bad())?, 16)
            .map_err(|_| bad())?;
        if length == 0 {
            rest = &rest[4..];
            continue;
        }
        if length < 4 || length > rest.len() {
            return Err(bad());
        }
        let line = &rest[4..length];
        let line = std::str::from_utf8(line).map_err(|_| bad())?;
        let value = line.split('\0').next().ok_or_else(bad)?.trim();
        if let Some((oid, name)) = value.split_once(' ')
            && name == "HEAD"
            && chromium::valid_oid(oid)
        {
            return Ok(oid.into());
        }
        rest = &rest[length..];
    }
    Err(Error::integrity(
        "Fixed Git repository did not advertise a valid HEAD.",
    ))
}

fn evidence_path(requested: &Path) -> Result<PathBuf> {
    if !requested.is_absolute() {
        return Err(bad());
    }
    let parent = std::fs::canonicalize(requested.parent().ok_or_else(bad)?).map_err(|_| bad())?;
    if !parent.starts_with("/tmp") {
        return Err(bad());
    }
    let status = std::fs::read_to_string("/proc/self/status").map_err(|_| bad())?;
    let uid = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or_else(bad)?;
    // /tmp itself is the shared sticky boundary. Every nested parent must be
    // private and owned by this process's user; resolve aliases before creation.
    for ancestor in parent
        .ancestors()
        .take_while(|path| *path != Path::new("/tmp"))
    {
        let metadata = std::fs::symlink_metadata(ancestor).map_err(|_| bad())?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != uid
            || metadata.mode() & 0o077 != 0
        {
            return Err(bad());
        }
    }
    let temporary = std::fs::symlink_metadata("/tmp").map_err(|_| bad())?;
    if !temporary.is_dir() || temporary.file_type().is_symlink() || temporary.mode() & 0o1000 == 0 {
        return Err(bad());
    }
    let name = requested.file_name().ok_or_else(bad)?;
    Ok(parent.join(name))
}

fn initialize(root: &Path) -> Result<()> {
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(root)
        .map_err(|_| io_error())?;
    save(&root.join("owner-v1"), MARKER)?;
    save_json(&root.join("attempts.json"), &Ledger::new())
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 2 || !matches!(args[0].as_str(), "--live" | "--resume" | "--initialize") {
        return Err("usage: deployment-live-probe --live NEW_ROOT | --resume OWNED_ROOT | --initialize NEW_ROOT (no network)".into());
    }
    let requested = evidence_path(Path::new(&args[1]))?;
    if args[0] != "--resume" {
        initialize(&requested)?;
    }
    let root = root::owned_root(&requested, MARKER)?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(root.join("run.lock"))?;
    FileExt::try_lock_exclusive(&lock)
        .map_err(|_| "Deployment evidence root already has an owner")?;
    let ledger: Ledger = read_json(&root.join("attempts.json"))?;
    ledger.validate()?;
    if args[0] == "--initialize" {
        println!(
            "Initialized private evidence root; no provider requests: {}",
            root.display()
        );
        return Ok(());
    }
    let mut probe = Probe {
        root: root.clone(),
        ledger: Arc::new(Mutex::new(ledger)),
        brokers: BTreeMap::new(),
        cancel: CancellationToken::new(),
    };
    let mut records = BTreeMap::new();
    for family in FAMILIES {
        let receipt_path = root.join(format!("{family}-receipt.json"));
        if receipt_path.exists() {
            let receipt: Value = read_json(&receipt_path)?;
            let attempts = probe
                .ledger
                .lock()
                .map_err(|_| bad())?
                .families
                .get(family)
                .copied()
                .unwrap_or(0);
            if receipt["complete"] != true
                || receipt["revision"] != REVISION
                || receipt["family"] != family
                || receipt["fixture"] != false
                || receipt["passed"] != true
                || receipt["attempts"].as_u64() != Some(attempts as u64)
                || attempts == 0
            {
                return Err(bad().into());
            }
            verify_artifacts(&root, &receipt)?;
            records.insert(family, receipt);
            continue;
        }
        // Partial source work is never automatically repeated with fresh credits.
        if probe
            .ledger
            .lock()
            .map_err(|_| bad())?
            .families
            .get(family)
            .copied()
            .unwrap_or(0)
            > 0
        {
            return Err(Error::unavailable("Incomplete family evidence needs operator review; automatic network retry is disabled.").into());
        }
        let result = tokio::time::timeout(Duration::from_secs(300), probe.run(family)).await;
        let record = match result {
            Ok(Ok(record)) => record,
            failure => {
                let code = match failure {
                    Ok(Err(error)) => error.code,
                    _ => "deadline_exceeded".into(),
                };
                probe.cancel.cancel();
                save_json(
                    &root.join("failure.json"),
                    &json!({"family":family,"code":code,"complete":false}),
                )?;
                return Err(Error::unavailable("Fixed-source acceptance incomplete; retained evidence and spent budgets preserved.").into());
            }
        };
        let attempts = probe
            .ledger
            .lock()
            .map_err(|_| bad())?
            .families
            .get(family)
            .copied()
            .ok_or_else(bad)?;
        let receipt = json!({"version":1,"revision":REVISION,"family":family,"complete":true,"passed":true,"fixture":false,"attempts":attempts,"scope":"fixed_source_parser_and_rights","whole_corpus":false,"transport_acceptance":false,"record":record});
        save_json(&receipt_path, &receipt)?;
        records.insert(family, receipt);
        println!("{family}: fixed source, parser and rights passed");
    }
    let counts = probe.ledger.lock().map_err(|_| bad())?.clone();
    save_json(
        &root.join("receipt.json"),
        &json!({"version":1,"release_revision":REVISION,"fixture":false,"complete":true,"whole_corpus":false,"production_publication":false,"transport_acceptance":false,"attempt_limit_per_family":20,"shared_github_attempt_limit":20,"github_attempts":counts.github,"attempt_ledger":counts,"providers":records}),
    )?;
    println!("Retained fixed-source evidence: {}", root.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_github_and_family_caps_are_independent_and_survive_reload() {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let path = root.path().join("ledger.json");
        let mut ledger = Ledger::new();
        for _ in 0..10 {
            ledger.reserve("mdn", "api.github.com").unwrap();
        }
        for _ in 0..10 {
            ledger.reserve("whatwg", "github.com").unwrap();
        }
        save_json(&path, &ledger).unwrap();
        let mut resumed: Ledger = read_json(&path).unwrap();
        assert!(resumed.reserve("rustsec", "api.github.com").is_err());
        for _ in 0..20 {
            resumed.reserve("npm", "registry.npmjs.org").unwrap();
        }
        assert!(resumed.reserve("npm", "registry.npmjs.org").is_err());
        resumed.reserve("rfc", "www.rfc-editor.org").unwrap();
        resumed.validate().unwrap();
    }
    #[test]
    fn corrupted_or_unsupported_accounting_fails_closed() {
        let mut ledger = Ledger::new();
        assert!(ledger.reserve("unknown", "api.github.com").is_err());
        assert!(ledger.reserve("npm", "evil.invalid").is_err());
        ledger.github = 1;
        assert!(ledger.validate().is_err());
        let mut wrong_revision = Ledger::new();
        wrong_revision.revision = "172d528d88d16c9ec4fd83a16674280815178930".into();
        assert!(wrong_revision.validate().is_err());
        let mut oversized_host_count = Ledger::new();
        oversized_host_count
            .hosts
            .insert("api.github.com".into(), usize::MAX);
        assert!(oversized_host_count.validate().is_err());
    }
    #[test]
    fn fixed_git_head_requires_bounded_valid_packets() {
        let oid = "a".repeat(40);
        let data = format!("{oid} HEAD\0symref=HEAD:refs/heads/main\n");
        let packet = format!("{:04x}{data}0000", data.len() + 4);
        assert_eq!(head(packet.as_bytes()).unwrap(), oid);
        assert!(head(b"ffffbad").is_err());
        assert!(head(b"0003").is_err());
    }
    #[test]
    fn interrupted_save_does_not_overwrite_or_replenish_a_ledger() {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let path = root.path().join("attempts.json");
        let mut ledger = Ledger::new();
        ledger.reserve("rfc", "www.rfc-editor.org").unwrap();
        save_json(&path, &ledger).unwrap();
        std::fs::write(path.with_extension("stage"), b"interrupted").unwrap();
        ledger.reserve("rfc", "www.rfc-editor.org").unwrap();
        assert!(save_json(&path, &ledger).is_err());
        let retained: Ledger = read_json(&path).unwrap();
        assert_eq!(retained.families["rfc"], 1);
    }
    #[tokio::test]
    async fn real_broker_requires_durable_reservation_before_admission() {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let mut probe = Probe {
            root: root.path().to_owned(),
            ledger: Arc::new(Mutex::new(Ledger::new())),
            brokers: BTreeMap::new(),
            cancel: CancellationToken::new(),
        };
        let broker = probe.broker("rfc", "www.rfc-editor.org").unwrap();
        let permit = broker.admit_foreground("www.rfc-editor.org").await.unwrap();
        let retained: Ledger = read_json(&root.path().join("attempts.json")).unwrap();
        assert_eq!(retained.families["rfc"], 1);
        drop(permit);
        std::fs::write(root.path().join("attempts.stage"), b"interrupted").unwrap();
        assert!(broker.admit_foreground("www.rfc-editor.org").await.is_err());
        let retained: Ledger = read_json(&root.path().join("attempts.json")).unwrap();
        assert_eq!(retained.families["rfc"], 1);
    }
    #[test]
    fn resume_rejects_changed_or_escaped_retained_artifacts() {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let path = root.path().join("source.bin");
        std::fs::write(&path, b"public evidence").unwrap();
        let record = json!({"artifact":{"file":"source.bin","body_hash":integrity::hash(b"public evidence"),"bytes":15}});
        verify_artifacts(root.path(), &record).unwrap();
        std::fs::write(&path, b"changed bytes!!").unwrap();
        assert!(verify_artifacts(root.path(), &record).is_err());
        assert!(verify_artifacts(root.path(), &json!({"file":"../source.bin"})).is_err());
    }
}
