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
const PRIOR_REVISION: &str = "172d528d88d16c9ec4fd83a16674280815178930";
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
        self.validate_revision(REVISION)
    }
    fn validate_revision(&self, revision: &str) -> Result<()> {
        if self.version != 1
            || self.revision != revision
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
            || self.families.get("rfc").copied().unwrap_or(0)
                != self.hosts.get("www.rfc-editor.org").copied().unwrap_or(0)
            || self.families.get("npm").copied().unwrap_or(0)
                != self.hosts.get("registry.npmjs.org").copied().unwrap_or(0)
            || self.families.get("chromium").copied().unwrap_or(0)
                != self
                    .hosts
                    .get("chromium.googlesource.com")
                    .copied()
                    .unwrap_or(0)
            || self.families.get("crates").copied().unwrap_or(0)
                != ["index.crates.io", "static.crates.io"]
                    .iter()
                    .map(|host| self.hosts.get(*host).copied().unwrap_or(0))
                    .sum::<usize>()
            || self.families.get("w3c").copied().unwrap_or(0)
                != self.hosts.get("www.w3.org").copied().unwrap_or(0)
            || ["mdn", "rustsec", "whatwg"]
                .iter()
                .map(|family| self.families.get(*family).copied().unwrap_or(0))
                .sum::<usize>()
                != self.github
        {
            return Err(bad());
        }
        Ok(())
    }
    fn reserve(&mut self, family: &str, host: &str) -> Result<()> {
        self.validate()?;
        if !family_host(family, host) {
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
fn family_host(family: &str, host: &str) -> bool {
    match family {
        "rfc" => host == "www.rfc-editor.org",
        "crates" => matches!(host, "index.crates.io" | "static.crates.io"),
        "npm" => host == "registry.npmjs.org",
        "chromium" => host == "chromium.googlesource.com",
        "w3c" => host == "www.w3.org",
        "mdn" | "rustsec" | "whatwg" => github(host),
        _ => false,
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
    retained_git_advertisement: Option<(Vec<u8>, Value)>,
    retained_git_head: Option<RetainedGitHead>,
    retained_git_content: Option<RetainedGitContent>,
}
struct RetainedGitHead {
    refs: Vec<u8>,
    ref_observation: Value,
    head_observation: Value,
}
struct RetainedGitContent {
    bytes: Vec<u8>,
    evidence: Value,
    artifact: Value,
}
impl Probe {
    fn stage(&self, family: &str, stage: &str) -> Result<()> {
        save_json(
            &self.root.join("progress.json"),
            &json!({"family":family,"stage":stage,"complete":false}),
        )
    }
    fn retain_rfc_initial(&self, bytes: &[u8], evidence: &Value) -> Result<Value> {
        let artifact = self.retain("rfc", "source", bytes)?;
        save_json(
            &self.root.join("rfc-initial-response.json"),
            &json!({"source":evidence,"artifact":artifact,"complete":false,"rights_qualified":false}),
        )?;
        self.stage("rfc", "validating_fixed_text")?;
        validate_rfc_text(bytes)?;
        Ok(artifact)
    }
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
        self.fetch_body(family, source, Vec::new()).await
    }
    async fn fetch_body(
        &mut self,
        family: &str,
        source: BulkSource,
        body: Vec<u8>,
    ) -> Result<(Vec<u8>, Value)> {
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
                    body,
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
        let evidence = json!({"source_url":url,"body_hash":integrity::hash(&bytes),"observed_at":devres_domain::unix_now(),"status":response.status,"content_length":response.content_length});
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
        let target = single_rights_target(family, evidence)?;
        let generation = attribution_providers::repair(
            &target,
            &self.broker(family, host)?,
            self.cancel.clone(),
        )
        .await?;
        if generation.notices.is_empty() {
            return Err(bad());
        }
        Ok(json!(generation))
    }
    fn retain_git_content(
        &self,
        family: &str,
        bytes: Vec<u8>,
        evidence: &Value,
    ) -> Result<(Vec<u8>, Value, Value)> {
        let raw_artifact = self.retain(family, "content-raw", &bytes)?;
        save_json(
            &self.root.join(format!("{family}-content-response.json")),
            &json!({"source":evidence,"artifact":raw_artifact,"complete":false,"rights_qualified":false}),
        )?;
        self.stage(family, "decoding_git_content")?;
        let bytes = decode_git(bytes)?;
        let artifact = self.retain(family, "source", &bytes)?;
        self.stage(family, "validating_fixed_git_content")?;
        Ok((bytes, raw_artifact, artifact))
    }
    async fn git_record(
        &mut self,
        family: &str,
        repository: &str,
        path: &str,
        advertisement: BulkSource,
    ) -> Result<(Vec<u8>, Value, Value)> {
        let retained = if family == "rustsec" {
            self.retained_git_head.take()
        } else {
            None
        };
        let (revision, observed, head_observation) = if let Some(retained) = retained {
            self.stage(family, "validating_retained_git_head")?;
            (
                head(&retained.refs)?,
                retained.ref_observation,
                retained.head_observation,
            )
        } else {
            self.stage(family, "fetching_git_advertisement")?;
            let upload = match &advertisement {
                BulkSource::RustSecGit(_) => BulkSource::RustSecGit(GitOperation::UploadPack),
                BulkSource::MdnContentGit(_) => BulkSource::MdnContentGit(GitOperation::UploadPack),
                BulkSource::WhatwgGit { repository, .. } => BulkSource::WhatwgGit {
                    repository: repository.clone(),
                    operation: GitOperation::UploadPack,
                },
                _ => return Err(bad()),
            };
            let (advert, observed) = if family == "rustsec" {
                if let Some(retained) = self.retained_git_advertisement.take() {
                    retained
                } else {
                    let result = self.fetch(family, advertisement).await?;
                    self.retain(family, "refs", &result.0)?;
                    result
                }
            } else {
                let result = self.fetch(family, advertisement).await?;
                self.retain(family, "refs", &result.0)?;
                result
            };
            self.stage(family, "validating_git_v2_capabilities")?;
            validate_git_v2(&advert)?;
            self.stage(family, "fetching_git_head")?;
            let (refs, head_observation) =
                self.fetch_body(family, upload, ls_refs_request()).await?;
            self.retain(family, "head", &refs)?;
            self.stage(family, "validating_git_head")?;
            let revision = head(&refs)?;
            (revision, observed, head_observation)
        };
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
        self.stage(family, "fetching_git_content")?;
        let (bytes, mut evidence) = self
            .fetch(family, BulkSource::Attribution(operation))
            .await?;
        let (bytes, raw_artifact, artifact) = self.retain_git_content(family, bytes, &evidence)?;
        evidence["body_hash"] = json!(integrity::hash(&bytes));
        evidence["revision"] = json!(revision);
        evidence["repository"] = json!(repository);
        evidence["path"] = json!(path);
        evidence["ref_observation"] = observed;
        evidence["head_observation"] = head_observation;
        evidence["raw_content_artifact"] = raw_artifact;
        Ok((bytes, evidence, artifact))
    }
    async fn qualify_rfc(&mut self, evidence: Value, artifact: Value) -> Result<Value> {
        self.stage("rfc", "repairing_exact_rights")?;
        let rights = self.rights("rfc", "www.rfc-editor.org", &evidence).await?;
        self.stage("rfc", "rights_qualified")?;
        Ok(json!({"source":evidence,"artifact":artifact,
            "parser":"released_rfc_notice_and_fixed_text_identity","rights":rights}))
    }
    async fn run(&mut self, family: &str) -> Result<Value> {
        match family {
            "rfc" => {
                self.stage(family, "fetching_initial_body")?;
                let (bytes, evidence) = self
                    .fetch(
                        family,
                        BulkSource::Attribution(AttributionSource::Rfc {
                            number: 9000,
                            format: "txt".into(),
                        }),
                    )
                    .await?;
                // Preserve the exact first public response before any second
                // acquisition or qualification. It is not accepted rights evidence.
                let artifact = self.retain_rfc_initial(&bytes, &evidence)?;
                self.qualify_rfc(evidence, artifact).await
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
                let retained = if family == "rustsec" {
                    self.retained_git_content.take()
                } else {
                    None
                };
                let (bytes, evidence, artifact) = if let Some(retained) = retained {
                    self.stage(family, "validating_retained_git_content")?;
                    (retained.bytes, retained.evidence, retained.artifact)
                } else {
                    self.git_record(family, repository, path, advertisement)
                        .await?
                };
                let parser = match family {
                    "rustsec" => fixed_rustsec(&bytes)?,
                    "mdn" => {
                        let document = devres_adapters::mdn::processing::process_document(
                            path,
                            &bytes,
                            &mut |_| Ok(None),
                            &devres_adapters::mdn::processing::ProcessingBudget::new(
                                self.cancel.clone(),
                            ),
                        )
                        .map_err(|_| Error::integrity("Fixed MDN document parsing failed."))?;
                        if document.text.trim().is_empty() || !document.title.contains("Array") {
                            return Err(Error::integrity("Fixed MDN document identity mismatch."));
                        }
                        json!({"parser":"released_mdn_document","title":document.title,"gaps":document.gaps,"unresolved_dependencies":document.dependencies})
                    }
                    _ => {
                        let document = devres_adapters::whatwg::processing::process_document(
                            path,
                            &bytes,
                            self.cancel.clone(),
                        )
                        .map_err(|_| Error::integrity("Fixed WHATWG document parsing failed."))?;
                        if document.text.trim().is_empty() || document.sections.is_empty() {
                            return Err(Error::integrity(
                                "Fixed WHATWG document identity mismatch.",
                            ));
                        }
                        json!({"parser":"released_whatwg_document","sections":document.sections.len(),"gaps":document.gaps})
                    }
                };
                self.stage(family, "repairing_exact_git_rights")?;
                let rights = self
                    .rights(
                        family,
                        "api.github.com",
                        &git_content_provenance(&evidence)?,
                    )
                    .await?;
                self.stage(family, "git_rights_qualified")?;
                Ok(json!({"source":evidence,"artifact":artifact,"parser":parser,"rights":rights}))
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

fn validate_rfc_text(bytes: &[u8]) -> Result<()> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| Error::integrity("Fixed RFC text is not UTF-8."))?;
    let mut header_bytes = 0usize;
    let mut numbers = Vec::new();
    let mut title = false;
    for line in text.trim_start_matches('\u{feff}').lines().take(32) {
        header_bytes = header_bytes.saturating_add(line.len());
        if header_bytes > 8192 || line.len() > 512 {
            return Err(Error::integrity("Fixed RFC text identity mismatch."));
        }
        let words = line.split_whitespace().collect::<Vec<_>>();
        if words.starts_with(&["Request", "for", "Comments:"]) {
            numbers.push(words.get(3).copied());
        }
        title |= words.join(" ") == "QUIC: A UDP-Based Multiplexed and Secure Transport";
    }
    if numbers != [Some("9000")] || !title {
        return Err(Error::integrity("Fixed RFC text identity mismatch."));
    }
    Ok(())
}

fn diagnostic(error: &Error) -> &'static str {
    match error.message.as_str() {
        "Bulk source length mismatch." => "source_length_mismatch",
        "Re-requested source differs from the retained representation." => {
            "exact_source_hash_mismatch"
        }
        "Fixed RFC text is not UTF-8." => "fixed_rfc_invalid_utf8",
        "Fixed RFC text identity mismatch." => "fixed_rfc_text_identity_mismatch",
        "Fixed source rights target count mismatch." => "rights_target_count_mismatch",
        "Fixed Git content base64 is invalid." => "fixed_git_content_invalid_base64",
        "Fixed Git content envelope is invalid." => "fixed_git_content_invalid_envelope",
        "Fixed RustSec advisory is not UTF-8." => "fixed_rustsec_invalid_utf8",
        "Fixed RustSec advisory schema mismatch." => "fixed_rustsec_schema_mismatch",
        "Fixed RustSec advisory identity mismatch." => "fixed_rustsec_identity_mismatch",
        "Fixed MDN document parsing failed." => "fixed_mdn_parse_failed",
        "Fixed MDN document identity mismatch." => "fixed_mdn_identity_mismatch",
        "Fixed WHATWG document parsing failed." => "fixed_whatwg_parse_failed",
        "Fixed WHATWG document identity mismatch." => "fixed_whatwg_identity_mismatch",
        _ => "unclassified_failure",
    }
}

fn decode_git(bytes: Vec<u8>) -> Result<Vec<u8>> {
    if let Ok(value) = serde_json::from_slice::<Value>(&bytes)
        && value["encoding"] == "base64"
    {
        let content = value["content"]
            .as_str()
            .ok_or_else(|| Error::integrity("Fixed Git content envelope is invalid."))?
            .bytes()
            .filter(|c| !c.is_ascii_whitespace())
            .collect::<Vec<_>>();
        return STANDARD
            .decode(content)
            .map_err(|_| Error::integrity("Fixed Git content base64 is invalid."));
    }
    Ok(bytes)
}
fn fixed_rustsec(bytes: &[u8]) -> Result<Value> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error::integrity("Fixed RustSec advisory is not UTF-8."))?;
    let advisory = ::rustsec::Advisory::from_str(text)
        .map_err(|_| Error::integrity("Fixed RustSec advisory schema mismatch."))?;
    if advisory.metadata.id.to_string() != "RUSTSEC-2022-0039"
        || advisory.metadata.package.as_str() != "odbc"
    {
        return Err(Error::integrity(
            "Fixed RustSec advisory identity mismatch.",
        ));
    }
    Ok(
        json!({"parser":"rustsec::Advisory::from_str","id":advisory.metadata.id.to_string(),"package":advisory.metadata.package.as_str(),"whole_snapshot_normalization":false}),
    )
}
// Rights qualification selects the immutable content occurrence. Discovery
// exchanges remain in the receipt, but are not themselves licensed content.
fn git_content_provenance(evidence: &Value) -> Result<Value> {
    let mut source = serde_json::Map::new();
    for field in ["source_url", "body_hash", "revision", "repository", "path"] {
        let value = evidence
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(bad)?;
        source.insert(field.into(), json!(value));
    }
    Ok(Value::Object(source))
}
fn single_rights_target(
    family: &str,
    evidence: &Value,
) -> Result<devres_domain::attribution::AttributionTarget> {
    let targets = attribution_providers::targets(family, evidence)?;
    if targets.len() != 1 {
        return Err(Error::integrity(
            "Fixed source rights target count mismatch.",
        ));
    }
    targets.into_iter().next().ok_or_else(bad)
}
fn git_packets(bytes: &[u8]) -> Result<Vec<&str>> {
    let mut rest = bytes;
    let mut lines = Vec::new();
    if bytes.len() > 65536 {
        return Err(bad());
    }
    while !rest.is_empty() {
        let prefix = rest.get(..4).ok_or_else(bad)?;
        let length = usize::from_str_radix(std::str::from_utf8(prefix).map_err(|_| bad())?, 16)
            .map_err(|_| bad())?;
        if length == 0 {
            if rest.len() != 4 {
                return Err(bad());
            }
            return Ok(lines);
        }
        if length < 4 || length > rest.len() {
            return Err(bad());
        }
        lines.push(std::str::from_utf8(&rest[4..length]).map_err(|_| bad())?);
        rest = &rest[length..];
    }
    Err(bad())
}
fn validate_git_v2(bytes: &[u8]) -> Result<()> {
    // Smart HTTP can prepend its service announcement and flush before the
    // protocol-v2 capability section. Only this exact advertised service is valid.
    let bytes = bytes
        .strip_prefix(b"001e# service=git-upload-pack\n0000")
        .unwrap_or(bytes);
    let lines = git_packets(bytes)?;
    if lines.first() != Some(&"version 2\n")
        || !lines.iter().any(|line| {
            line.trim_end()
                .split_once('=')
                .is_some_and(|(key, _)| key == "ls-refs")
        })
    {
        return Err(Error::integrity(
            "Fixed Git repository did not advertise protocol v2 ls-refs.",
        ));
    }
    Ok(())
}
fn ls_refs_request() -> Vec<u8> {
    let mut body = Vec::new();
    for (index, line) in ["command=ls-refs\n", "symrefs\n", "ref-prefix HEAD\n"]
        .iter()
        .enumerate()
    {
        if index == 1 {
            body.extend_from_slice(b"0001");
        }
        body.extend_from_slice(format!("{:04x}{}", line.len() + 4, line).as_bytes());
    }
    body.extend_from_slice(b"0000");
    body
}
fn head(bytes: &[u8]) -> Result<String> {
    let mut selected = None;
    for line in git_packets(bytes)? {
        let fields = line.trim_end_matches('\n').split(' ').collect::<Vec<_>>();
        if fields.len() < 2
            || fields[1] != "HEAD"
            || !chromium::valid_oid(fields[0])
            || fields[2..]
                .iter()
                .any(|field| !field.starts_with("symref-target:refs/heads/"))
            || selected.is_some()
        {
            return Err(Error::integrity(
                "Fixed Git repository did not advertise a unique valid HEAD.",
            ));
        }
        selected = Some(fields[0].to_owned());
    }
    selected.ok_or_else(|| {
        Error::integrity("Fixed Git repository did not advertise a unique valid HEAD.")
    })
}

fn evidence_path(requested: &Path) -> Result<PathBuf> {
    if !requested.is_absolute()
        || requested
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(bad());
    }
    if requested
        .ancestors()
        .any(|path| std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()))
    {
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
    initialize_ledger(root, &Ledger::new())
}
fn initialize_ledger(root: &Path, ledger: &Ledger) -> Result<()> {
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(root)
        .map_err(|_| io_error())?;
    save(&root.join("owner-v1"), MARKER)?;
    save_json(&root.join("attempts.json"), ledger)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RetryProvenance {
    version: u32,
    prior_root: PathBuf,
    prior_revision: String,
    attempts_sha256: String,
    failure_sha256: String,
    carried_ledger: Ledger,
    claim_file: PathBuf,
    new_root: PathBuf,
}
fn private_bytes(path: &Path, uid: u32) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| bad())?;
    let metadata = file.metadata().map_err(|_| bad())?;
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
        || metadata.len() > 1024 * 1024
    {
        return Err(bad());
    }
    use std::io::Read;
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| bad())?;
    if bytes.len() > 1024 * 1024 {
        return Err(bad());
    }
    Ok(bytes)
}
fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn present(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(bad()),
    }
}
fn failed_source(root: &Path) -> Result<(Ledger, Vec<u8>, Vec<u8>, File)> {
    let root = root::owned_root(root, MARKER)?;
    let metadata = std::fs::symlink_metadata(&root).map_err(|_| bad())?;
    if metadata.mode() & 0o077 != 0
        || present(&root.join("receipt.json"))?
        || present(&root.join("retry-provenance.json"))?
        || present(&root.join("retry-pending"))?
    {
        return Err(bad());
    }
    private_bytes(&root.join("owner-v1"), metadata.uid())?;
    private_bytes(&root.join("run.lock"), metadata.uid())?;
    let lock = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(root.join("run.lock"))
        .map_err(|_| bad())?;
    FileExt::try_lock_exclusive(&lock).map_err(|_| bad())?;
    let attempts = private_bytes(&root.join("attempts.json"), metadata.uid())?;
    let failure = private_bytes(&root.join("failure.json"), metadata.uid())?;
    let ledger: Ledger = serde_json::from_slice(&attempts).map_err(|_| bad())?;
    if !matches!(ledger.revision.as_str(), PRIOR_REVISION | REVISION) {
        return Err(bad());
    }
    ledger.validate_revision(&ledger.revision)?;
    let value: Value = serde_json::from_slice(&failure).map_err(|_| bad())?;
    let family = value["family"].as_str().ok_or_else(bad)?;
    let code = value["code"].as_str().ok_or_else(bad)?;
    if value["complete"] != false
        || !FAMILIES.contains(&family)
        || ledger.families.get(family).copied().unwrap_or(0) == 0
        || present(&root.join(format!("{family}-receipt.json")))?
        || code.is_empty()
        || code.len() > 64
        || !code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
    {
        return Err(bad());
    }
    Ok((ledger, attempts, failure, lock))
}
fn retry_claim(source: &Path) -> Result<PathBuf> {
    let canonical = std::fs::canonicalize(source).map_err(|_| bad())?;
    let metadata = std::fs::symlink_metadata(&canonical).map_err(|_| bad())?;
    // Counter/failure hashes belong inside the claim, never in its namespace:
    // changing otherwise valid source bytes cannot authorize another child.
    let identity = json!({"uid":metadata.uid(),"root":canonical,
                         "device":metadata.dev(),"inode":metadata.ino()});
    Ok(Path::new("/tmp").join(format!(
        ".devres-source-retry-{}-{}.json",
        metadata.uid(),
        sha256(&serde_json::to_vec(&identity).map_err(|_| bad())?)
    )))
}
fn initialize_retry(source: &Path, destination: &Path) -> Result<File> {
    if source.starts_with(destination) || destination.starts_with(source) || present(destination)? {
        return Err(bad());
    }
    let (previous, attempts, failure, lock) = failed_source(source)?;
    let claim_file = retry_claim(source)?;
    if present(&claim_file)? {
        return Err(bad());
    }
    let mut carried = previous.clone();
    carried.revision = REVISION.into();
    carried.validate()?;
    let provenance = RetryProvenance {
        version: 1,
        prior_root: source.to_owned(),
        prior_revision: previous.revision.clone(),
        attempts_sha256: sha256(&attempts),
        failure_sha256: sha256(&failure),
        carried_ledger: previous,
        claim_file: claim_file.clone(),
        new_root: destination.to_owned(),
    };
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(destination)
        .map_err(|_| io_error())?;
    save(&destination.join("owner-v1"), MARKER)?;
    // Until the external claim is durable, even a child with only later-family
    // carried work must refuse --resume before its first provider request.
    save(&destination.join("retry-pending"), MARKER)?;
    save_json(&destination.join("attempts.json"), &carried)?;
    save(&destination.join("retry-prior-attempts.json"), &attempts)?;
    save(&destination.join("retry-prior-failure.json"), &failure)?;
    save_json(&destination.join("retry-provenance.json"), &provenance)?;
    // One global child for this exact unchanged source. A failed claim/fsync
    // never permits live work; the original root is never written.
    let mut claim = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&claim_file)
        .map_err(|_| bad())?;
    claim
        .write_all(&serde_json::to_vec(&provenance).map_err(|_| bad())?)
        .and_then(|()| claim.sync_all())
        .map_err(|_| io_error())?;
    File::open("/tmp")
        .and_then(|file| file.sync_all())
        .map_err(|_| io_error())?;
    std::fs::remove_file(destination.join("retry-pending")).map_err(|_| io_error())?;
    File::open(destination)
        .and_then(|file| file.sync_all())
        .map_err(|_| io_error())?;
    Ok(lock)
}
fn retry_baseline(root: &Path, current: &Ledger) -> Result<Option<(Ledger, File)>> {
    if present(&root.join("retry-pending"))? {
        return Err(bad());
    }
    if !present(&root.join("retry-provenance.json"))? {
        return Ok(None);
    }
    let uid = std::fs::metadata(root).map_err(|_| bad())?.uid();
    let encoded = private_bytes(&root.join("retry-provenance.json"), uid)?;
    let provenance: RetryProvenance = serde_json::from_slice(&encoded).map_err(|_| bad())?;
    if provenance.version != 1
        || provenance.new_root != root
        || evidence_path(&provenance.prior_root)? != provenance.prior_root
    {
        return Err(bad());
    }
    let (previous, attempts, failure, lock) = failed_source(&provenance.prior_root)?;
    if provenance.prior_revision != previous.revision
        || provenance.attempts_sha256 != sha256(&attempts)
        || provenance.failure_sha256 != sha256(&failure)
        || provenance.claim_file != retry_claim(&provenance.prior_root)?
        || private_bytes(&root.join("retry-prior-attempts.json"), uid)? != attempts
        || private_bytes(&root.join("retry-prior-failure.json"), uid)? != failure
    {
        return Err(bad());
    }
    let claimed: RetryProvenance =
        serde_json::from_slice(&private_bytes(&provenance.claim_file, uid)?).map_err(|_| bad())?;
    if serde_json::to_value(&claimed).map_err(|_| bad())?
        != serde_json::to_value(&provenance).map_err(|_| bad())?
        || serde_json::to_value(&provenance.carried_ledger).map_err(|_| bad())?
            != serde_json::to_value(&previous).map_err(|_| bad())?
        || current.github < previous.github
        || previous
            .families
            .iter()
            .any(|(family, spent)| current.families.get(family).copied().unwrap_or(0) < *spent)
        || previous
            .hosts
            .iter()
            .any(|(host, spent)| current.hosts.get(host).copied().unwrap_or(0) < *spent)
    {
        return Err(bad());
    }
    Ok(Some((previous, lock)))
}
fn family_can_begin(family: &str, spent: usize, baseline: Option<&Ledger>) -> bool {
    spent == 0
        || baseline.is_some_and(|ledger| ledger.families.get(family).copied().unwrap_or(0) == spent)
}

fn prepare_rfc_identity_recovery(
    root: &Path,
    ledger: &Ledger,
    baseline: Option<&Ledger>,
) -> Result<(Value, Value)> {
    let previous = baseline.ok_or_else(bad)?;
    let mut expected = previous.clone();
    expected.revision = REVISION.into();
    expected.reserve("rfc", "www.rfc-editor.org")?;
    if serde_json::to_value(&expected).map_err(|_| bad())?
        != serde_json::to_value(ledger).map_err(|_| bad())?
        || present(&root.join("receipt.json"))?
        || present(&root.join("rfc-identity-recovery.json"))?
        || present(&root.join("rfc-identity-prior-failure.json"))?
        || FAMILIES
            .iter()
            .any(|family| root.join(format!("{family}-receipt.json")).exists())
    {
        return Err(bad());
    }
    let uid = std::fs::metadata(root).map_err(|_| bad())?.uid();
    let raw_failure = private_bytes(&root.join("failure.json"), uid)?;
    let failure: Value = serde_json::from_slice(&raw_failure).map_err(|_| bad())?;
    if failure["complete"] != false
        || failure["family"] != "rfc"
        || failure["code"] != "integrity"
        || failure["diagnostic"] != "fixed_rfc_text_identity_mismatch"
        || failure["stage"] != "validating_fixed_text"
    {
        return Err(bad());
    }
    let progress: Value = serde_json::from_slice(&private_bytes(&root.join("progress.json"), uid)?)
        .map_err(|_| bad())?;
    if progress["family"] != "rfc" || progress["stage"] != "validating_fixed_text" {
        return Err(bad());
    }
    let raw_initial = private_bytes(&root.join("rfc-initial-response.json"), uid)?;
    let initial: Value = serde_json::from_slice(&raw_initial).map_err(|_| bad())?;
    let bytes = private_bytes(&root.join("rfc-source.bin"), uid)?;
    validate_rfc_text(&bytes)?;
    let body_hash = integrity::hash(&bytes);
    let source = &initial["source"];
    let artifact = &initial["artifact"];
    if initial["complete"] != false
        || initial["rights_qualified"] != false
        || source["status"] != 200
        || source["source_url"] != "https://www.rfc-editor.org/rfc/rfc9000.txt"
        || source["body_hash"] != body_hash
        || artifact["body_hash"] != body_hash
        || artifact["file"] != "rfc-source.bin"
        || artifact["bytes"].as_u64() != Some(bytes.len() as u64)
        || source["observed_at"].as_i64().is_none_or(|n| n <= 0)
        || (!source["content_length"].is_null()
            && source["content_length"].as_u64() != Some(bytes.len() as u64))
    {
        return Err(bad());
    }
    // Creating this durable one-shot marker consumes recovery authority. A crash,
    // failed rights refetch or partial marker cannot authorize another attempt.
    let provenance = json!({"version":1,"release_revision":REVISION,
        "kind":"retained_rfc_header_identity_recovery","prior_attempt_ledger":ledger,
        "prior_rfc_attempts":ledger.families.get("rfc"),"failure_sha256":sha256(&raw_failure),
        "initial_response_sha256":sha256(&raw_initial),"body_hash":body_hash,
        "initial_fetch_reused":true,"qualified_rights_reused":false});
    let mut marker = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(root.join("rfc-identity-recovery.json"))
        .map_err(|_| bad())?;
    marker
        .write_all(&serde_json::to_vec_pretty(&provenance).map_err(|_| bad())?)
        .and_then(|()| marker.sync_all())
        .map_err(|_| io_error())?;
    File::open(root)
        .and_then(|file| file.sync_all())
        .map_err(|_| io_error())?;
    save(&root.join("rfc-identity-prior-failure.json"), &raw_failure)?;
    Ok((source.clone(), artifact.clone()))
}

fn prepare_git_v2_recovery(root: &Path, ledger: &Ledger, baseline: Option<&Ledger>) -> Result<()> {
    let baseline = baseline.ok_or_else(bad)?;
    let mut known_baseline = Ledger::new();
    for _ in 0..2 {
        known_baseline.reserve("rfc", "www.rfc-editor.org")?;
    }
    known_baseline.revision = PRIOR_REVISION.into();
    // The approved retry carried exactly the two prior RFC attempts. This mode
    // is deliberately specific to the one observed pre-v2 helper failure.
    if serde_json::to_value(baseline).map_err(|_| bad())?
        != serde_json::to_value(&known_baseline).map_err(|_| bad())?
    {
        return Err(bad());
    }
    let mut expected = known_baseline;
    expected.revision = REVISION.into();
    for (family, host) in [
        ("rfc", "www.rfc-editor.org"),
        ("rfc", "www.rfc-editor.org"),
        ("crates", "index.crates.io"),
        ("crates", "static.crates.io"),
        ("crates", "static.crates.io"),
        ("rustsec", "github.com"),
    ] {
        expected.reserve(family, host)?;
    }
    if serde_json::to_value(ledger).map_err(|_| bad())?
        != serde_json::to_value(&expected).map_err(|_| bad())?
        || [
            "receipt.json",
            "git-v2-recovery.json",
            "git-v2-prior-failure.json",
            "rustsec-refs.bin",
            "rustsec-head.bin",
        ]
        .iter()
        .any(|name| root.join(name).exists())
        || FAMILIES[2..]
            .iter()
            .any(|family| root.join(format!("{family}-receipt.json")).exists())
    {
        return Err(bad());
    }
    let uid = std::fs::metadata(root).map_err(|_| bad())?.uid();
    let raw_failure = private_bytes(&root.join("failure.json"), uid)?;
    let failure: Value = serde_json::from_slice(&raw_failure).map_err(|_| bad())?;
    let progress: Value = serde_json::from_slice(&private_bytes(&root.join("progress.json"), uid)?)
        .map_err(|_| bad())?;
    if failure
        != json!({"code":"integrity","complete":false,"diagnostic":"unclassified_failure","family":"rustsec","stage":"starting_family"})
        || progress != json!({"complete":false,"family":"rustsec","stage":"starting_family"})
    {
        return Err(bad());
    }
    // These already completed receipts are validated again in the main loop
    // before the next network operation; no successful evidence is overwritten.
    for family in ["rfc", "crates"] {
        if !root.join(format!("{family}-receipt.json")).is_file() {
            return Err(bad());
        }
    }
    let provenance = json!({"version":1,"release_revision":REVISION,"kind":"git_v2_head_negotiation_recovery","prior_attempt_ledger":ledger,"failure_sha256":sha256(&raw_failure),"lost_initial_advertisement_attempts":1,"initial_advertisement_reused":false,"qualified_receipts_preserved":["rfc","crates"]});
    let mut marker = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(root.join("git-v2-recovery.json"))
        .map_err(|_| bad())?;
    marker
        .write_all(&serde_json::to_vec_pretty(&provenance).map_err(|_| bad())?)
        .and_then(|()| marker.sync_all())
        .map_err(|_| io_error())?;
    File::open(root)
        .and_then(|file| file.sync_all())
        .map_err(|_| io_error())?;
    save(&root.join("git-v2-prior-failure.json"), &raw_failure)?;
    Ok(())
}

fn prepare_git_head_recovery(
    root: &Path,
    ledger: &Ledger,
    baseline: Option<&Ledger>,
) -> Result<(Vec<u8>, Value)> {
    let mut expected_baseline = Ledger::new();
    for _ in 0..2 {
        expected_baseline.reserve("rfc", "www.rfc-editor.org")?;
    }
    expected_baseline.revision = PRIOR_REVISION.into();
    if baseline
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| bad())?
        != Some(serde_json::to_value(&expected_baseline).map_err(|_| bad())?)
    {
        return Err(bad());
    }
    let mut previous = Ledger::new();
    for (family, host, count) in [
        ("rfc", "www.rfc-editor.org", 4),
        ("crates", "index.crates.io", 1),
        ("crates", "static.crates.io", 2),
        ("rustsec", "github.com", 1),
    ] {
        for _ in 0..count {
            previous.reserve(family, host)?;
        }
    }
    let mut expected = previous.clone();
    expected.reserve("rustsec", "github.com")?;
    if serde_json::to_value(ledger).map_err(|_| bad())?
        != serde_json::to_value(&expected).map_err(|_| bad())?
        || [
            "receipt.json",
            "git-head-recovery.json",
            "git-head-prior-failure.json",
            "rustsec-head.bin",
            "rustsec-source.bin",
        ]
        .iter()
        .any(|name| root.join(name).exists())
        || FAMILIES[2..]
            .iter()
            .any(|family| root.join(format!("{family}-receipt.json")).exists())
    {
        return Err(bad());
    }
    let uid = std::fs::metadata(root).map_err(|_| bad())?.uid();
    let prior: Value =
        serde_json::from_slice(&private_bytes(&root.join("git-v2-recovery.json"), uid)?)
            .map_err(|_| bad())?;
    if prior["release_revision"] != REVISION
        || prior["kind"] != "git_v2_head_negotiation_recovery"
        || prior["prior_attempt_ledger"] != serde_json::to_value(&previous).map_err(|_| bad())?
    {
        return Err(bad());
    }
    let failure_raw = private_bytes(&root.join("failure.json"), uid)?;
    let failure: Value = serde_json::from_slice(&failure_raw).map_err(|_| bad())?;
    let progress: Value = serde_json::from_slice(&private_bytes(&root.join("progress.json"), uid)?)
        .map_err(|_| bad())?;
    if failure
        != json!({"code":"integrity","complete":false,"diagnostic":"unclassified_failure","family":"rustsec","stage":"validating_git_v2_capabilities"})
        || progress
            != json!({"complete":false,"family":"rustsec","stage":"validating_git_v2_capabilities"})
    {
        return Err(bad());
    }
    for family in ["rfc", "crates"] {
        if !root.join(format!("{family}-receipt.json")).is_file() {
            return Err(bad());
        }
    }
    let bytes = private_bytes(&root.join("rustsec-refs.bin"), uid)?;
    if !bytes.starts_with(b"001e# service=git-upload-pack\n0000") {
        return Err(bad());
    }
    validate_git_v2(&bytes)?;
    // The old fetch guard returns bytes only after status200. It retained this
    // artifact immediately before failing capability parsing. Reconstruct only
    // those facts; do not invent response headers or the original HTTP clock.
    let observation = json!({"source_url":BulkSource::RustSecGit(GitOperation::Advertisement).url()?,
        "body_hash":integrity::hash(&bytes),"retained_artifact_modified_at":std::fs::metadata(root.join("rustsec-refs.bin")).map_err(|_|bad())?.mtime(),
        "retained_from_prior_fetch":true,"http_status_inferred_from_executed_fetch_guard":200,
        "original_http_headers_and_observation_time_unavailable":true});
    let provenance = json!({"release_revision":REVISION,"kind":"retained_http_git_advertisement_recovery","prior_attempt_ledger":ledger,"failure_sha256":sha256(&failure_raw),"retained_advertisement_sha256":sha256(&bytes),"advertisement_fetch_reused":true,"head_request_reused":false});
    let mut marker = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(root.join("git-head-recovery.json"))
        .map_err(|_| bad())?;
    marker
        .write_all(&serde_json::to_vec_pretty(&provenance).map_err(|_| bad())?)
        .and_then(|()| marker.sync_all())
        .map_err(|_| io_error())?;
    File::open(root)
        .and_then(|file| file.sync_all())
        .map_err(|_| io_error())?;
    save(&root.join("git-head-prior-failure.json"), &failure_raw)?;
    Ok((bytes, observation))
}

fn retained_git_observation(
    root: &Path,
    name: &str,
    bytes: &[u8],
    source: BulkSource,
) -> Result<Value> {
    Ok(
        json!({"source_url":source.url()?,"body_hash":integrity::hash(bytes),
        "retained_artifact_modified_at":std::fs::metadata(root.join(name)).map_err(|_|bad())?.mtime(),
        "retained_from_prior_fetch":true,"http_status_inferred_from_executed_fetch_guard":200,
        "original_http_headers_and_observation_time_unavailable":true}),
    )
}

fn prepare_git_content_recovery(
    root: &Path,
    ledger: &Ledger,
    baseline: Option<&Ledger>,
) -> Result<RetainedGitHead> {
    let mut expected_baseline = Ledger::new();
    for _ in 0..2 {
        expected_baseline.reserve("rfc", "www.rfc-editor.org")?;
    }
    expected_baseline.revision = PRIOR_REVISION.into();
    if baseline
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| bad())?
        != Some(serde_json::to_value(&expected_baseline).map_err(|_| bad())?)
    {
        return Err(bad());
    }
    let mut first = Ledger::new();
    for (family, host, count) in [
        ("rfc", "www.rfc-editor.org", 4),
        ("crates", "index.crates.io", 1),
        ("crates", "static.crates.io", 2),
        ("rustsec", "github.com", 1),
    ] {
        for _ in 0..count {
            first.reserve(family, host)?;
        }
    }
    let mut second = first.clone();
    second.reserve("rustsec", "github.com")?;
    let mut expected = second.clone();
    expected.reserve("rustsec", "github.com")?;
    expected.reserve("rustsec", "api.github.com")?;
    if serde_json::to_value(ledger).map_err(|_| bad())?
        != serde_json::to_value(&expected).map_err(|_| bad())?
        || [
            "receipt.json",
            "git-content-recovery.json",
            "git-content-prior-failure.json",
            "rustsec-source.bin",
            "rustsec-content-raw.bin",
            "rustsec-content-response.json",
        ]
        .iter()
        .any(|name| root.join(name).exists())
        || FAMILIES[2..]
            .iter()
            .any(|family| root.join(format!("{family}-receipt.json")).exists())
    {
        return Err(bad());
    }
    let uid = std::fs::metadata(root).map_err(|_| bad())?.uid();
    let v2: Value =
        serde_json::from_slice(&private_bytes(&root.join("git-v2-recovery.json"), uid)?)
            .map_err(|_| bad())?;
    let retained: Value =
        serde_json::from_slice(&private_bytes(&root.join("git-head-recovery.json"), uid)?)
            .map_err(|_| bad())?;
    if v2["release_revision"] != REVISION
        || v2["kind"] != "git_v2_head_negotiation_recovery"
        || v2["prior_attempt_ledger"] != serde_json::to_value(&first).map_err(|_| bad())?
        || retained["release_revision"] != REVISION
        || retained["kind"] != "retained_http_git_advertisement_recovery"
        || retained["prior_attempt_ledger"] != serde_json::to_value(&second).map_err(|_| bad())?
        || retained["failure_sha256"]
            != sha256(&private_bytes(
                &root.join("git-head-prior-failure.json"),
                uid,
            )?)
    {
        return Err(bad());
    }
    let failure_raw = private_bytes(&root.join("failure.json"), uid)?;
    let failure: Value = serde_json::from_slice(&failure_raw).map_err(|_| bad())?;
    let progress: Value = serde_json::from_slice(&private_bytes(&root.join("progress.json"), uid)?)
        .map_err(|_| bad())?;
    if failure
        != json!({"code":"integrity","complete":false,"diagnostic":"unclassified_failure","family":"rustsec","stage":"validating_git_head"})
        || progress != json!({"complete":false,"family":"rustsec","stage":"validating_git_head"})
    {
        return Err(bad());
    }
    for family in ["rfc", "crates"] {
        if !root.join(format!("{family}-receipt.json")).is_file() {
            return Err(bad());
        }
    }
    let advert = private_bytes(&root.join("rustsec-refs.bin"), uid)?;
    validate_git_v2(&advert)?;
    if retained["retained_advertisement_sha256"] != sha256(&advert) {
        return Err(bad());
    }
    let refs = private_bytes(&root.join("rustsec-head.bin"), uid)?;
    // This mode is restricted to the exact HEAD from the observed failed trial.
    // There is no fresh Git discovery, automatic retry, or generic family replay.
    if head(&refs)? != "28d73fc95e5972af3403225a217def57dcaba3c4" {
        return Err(bad());
    }
    let ref_observation = retained_git_observation(
        root,
        "rustsec-refs.bin",
        &advert,
        BulkSource::RustSecGit(GitOperation::Advertisement),
    )?;
    let head_observation = retained_git_observation(
        root,
        "rustsec-head.bin",
        &refs,
        BulkSource::RustSecGit(GitOperation::UploadPack),
    )?;
    let provenance = json!({"release_revision":REVISION,"kind":"retained_git_head_content_refetch",
        "prior_attempt_ledger":ledger,"failure_sha256":sha256(&failure_raw),
        "retained_advertisement_sha256":sha256(&advert),"retained_head_sha256":sha256(&refs),
        "advertisement_fetch_reused":true,"head_request_reused":true,"content_fetch_reused":false});
    let mut marker = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(root.join("git-content-recovery.json"))
        .map_err(|_| bad())?;
    marker
        .write_all(&serde_json::to_vec_pretty(&provenance).map_err(|_| bad())?)
        .and_then(|()| marker.sync_all())
        .map_err(|_| io_error())?;
    File::open(root)
        .and_then(|file| file.sync_all())
        .map_err(|_| io_error())?;
    save(&root.join("git-content-prior-failure.json"), &failure_raw)?;
    Ok(RetainedGitHead {
        refs,
        ref_observation,
        head_observation,
    })
}

fn prepare_git_rights_recovery(
    root: &Path,
    ledger: &Ledger,
    baseline: Option<&Ledger>,
) -> Result<RetainedGitContent> {
    let mut expected_baseline = Ledger::new();
    for _ in 0..2 {
        expected_baseline.reserve("rfc", "www.rfc-editor.org")?;
    }
    expected_baseline.revision = PRIOR_REVISION.into();
    if baseline
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| bad())?
        != Some(serde_json::to_value(&expected_baseline).map_err(|_| bad())?)
    {
        return Err(bad());
    }
    let mut first = Ledger::new();
    for (family, host, count) in [
        ("rfc", "www.rfc-editor.org", 4),
        ("crates", "index.crates.io", 1),
        ("crates", "static.crates.io", 2),
        ("rustsec", "github.com", 1),
    ] {
        for _ in 0..count {
            first.reserve(family, host)?;
        }
    }
    let mut second = first.clone();
    second.reserve("rustsec", "github.com")?;
    let mut content = second.clone();
    content.reserve("rustsec", "github.com")?;
    content.reserve("rustsec", "api.github.com")?;
    let mut expected = content.clone();
    expected.reserve("rustsec", "api.github.com")?;
    if serde_json::to_value(ledger).map_err(|_| bad())?
        != serde_json::to_value(&expected).map_err(|_| bad())?
        || [
            "receipt.json",
            "git-rights-recovery.json",
            "git-rights-prior-failure.json",
        ]
        .iter()
        .any(|name| root.join(name).exists())
        || FAMILIES[2..]
            .iter()
            .any(|family| root.join(format!("{family}-receipt.json")).exists())
    {
        return Err(bad());
    }
    let uid = std::fs::metadata(root).map_err(|_| bad())?.uid();
    let v2: Value =
        serde_json::from_slice(&private_bytes(&root.join("git-v2-recovery.json"), uid)?)
            .map_err(|_| bad())?;
    let retained: Value =
        serde_json::from_slice(&private_bytes(&root.join("git-head-recovery.json"), uid)?)
            .map_err(|_| bad())?;
    let prior: Value = serde_json::from_slice(&private_bytes(
        &root.join("git-content-recovery.json"),
        uid,
    )?)
    .map_err(|_| bad())?;
    if v2["release_revision"] != REVISION
        || v2["kind"] != "git_v2_head_negotiation_recovery"
        || v2["prior_attempt_ledger"] != serde_json::to_value(&first).map_err(|_| bad())?
        || retained["release_revision"] != REVISION
        || retained["kind"] != "retained_http_git_advertisement_recovery"
        || retained["prior_attempt_ledger"] != serde_json::to_value(&second).map_err(|_| bad())?
        || retained["failure_sha256"]
            != sha256(&private_bytes(
                &root.join("git-head-prior-failure.json"),
                uid,
            )?)
        || prior["release_revision"] != REVISION
        || prior["kind"] != "retained_git_head_content_refetch"
        || prior["prior_attempt_ledger"] != serde_json::to_value(&content).map_err(|_| bad())?
        || prior["failure_sha256"]
            != sha256(&private_bytes(
                &root.join("git-content-prior-failure.json"),
                uid,
            )?)
    {
        return Err(bad());
    }
    let failure_raw = private_bytes(&root.join("failure.json"), uid)?;
    let failure: Value = serde_json::from_slice(&failure_raw).map_err(|_| bad())?;
    let progress: Value = serde_json::from_slice(&private_bytes(&root.join("progress.json"), uid)?)
        .map_err(|_| bad())?;
    if failure
        != json!({"code":"integrity","complete":false,"diagnostic":"unclassified_failure","family":"rustsec","stage":"repairing_exact_git_rights"})
        || progress
            != json!({"complete":false,"family":"rustsec","stage":"repairing_exact_git_rights"})
    {
        return Err(bad());
    }
    for family in ["rfc", "crates"] {
        if !root.join(format!("{family}-receipt.json")).is_file() {
            return Err(bad());
        }
    }
    let advert = private_bytes(&root.join("rustsec-refs.bin"), uid)?;
    validate_git_v2(&advert)?;
    let refs = private_bytes(&root.join("rustsec-head.bin"), uid)?;
    let revision = head(&refs)?;
    if revision != "28d73fc95e5972af3403225a217def57dcaba3c4"
        || retained["retained_advertisement_sha256"] != sha256(&advert)
        || prior["retained_advertisement_sha256"] != sha256(&advert)
        || prior["retained_head_sha256"] != sha256(&refs)
    {
        return Err(bad());
    }
    let raw = private_bytes(&root.join("rustsec-content-raw.bin"), uid)?;
    let bytes = private_bytes(&root.join("rustsec-source.bin"), uid)?;
    if raw.len() != 306 || bytes.len() != 306 || decode_git(raw.clone())? != bytes {
        return Err(bad());
    }
    fixed_rustsec(&bytes)?;
    let response_raw = private_bytes(&root.join("rustsec-content-response.json"), uid)?;
    let response: Value = serde_json::from_slice(&response_raw).map_err(|_| bad())?;
    let mut evidence = response["source"].clone();
    let raw_artifact = json!({"file":"rustsec-content-raw.bin","body_hash":integrity::hash(&raw),"bytes":raw.len()});
    let expected_url = BulkSource::Attribution(AttributionSource::RustSec {
        revision: revision.clone(),
        path: "crates/odbc/RUSTSEC-2022-0039.md".into(),
    })
    .url()?;
    if response
        != json!({"source":evidence,"artifact":raw_artifact,"complete":false,"rights_qualified":false})
        || evidence["source_url"] != expected_url
        || evidence["status"] != 200
        || evidence["body_hash"] != integrity::hash(&raw)
        || evidence["observed_at"].as_i64().is_none_or(|n| n <= 0)
        || (!evidence["content_length"].is_null()
            && evidence["content_length"].as_u64() != Some(raw.len() as u64))
        || evidence
            != json!({"source_url":expected_url,"body_hash":integrity::hash(&raw),"status":200,
            "observed_at":evidence["observed_at"],"content_length":evidence["content_length"]})
    {
        return Err(bad());
    }
    evidence["body_hash"] = json!(integrity::hash(&bytes));
    evidence["revision"] = json!(revision);
    evidence["repository"] = json!("rustsec/advisory-db");
    evidence["path"] = json!("crates/odbc/RUSTSEC-2022-0039.md");
    evidence["ref_observation"] = retained_git_observation(
        root,
        "rustsec-refs.bin",
        &advert,
        BulkSource::RustSecGit(GitOperation::Advertisement),
    )?;
    evidence["head_observation"] = retained_git_observation(
        root,
        "rustsec-head.bin",
        &refs,
        BulkSource::RustSecGit(GitOperation::UploadPack),
    )?;
    evidence["raw_content_artifact"] = raw_artifact;
    single_rights_target("rustsec", &git_content_provenance(&evidence)?)?;
    let artifact = json!({"file":"rustsec-source.bin","body_hash":integrity::hash(&bytes),"bytes":bytes.len()});
    let provenance = json!({"release_revision":REVISION,"kind":"retained_git_content_rights_projection_recovery","prior_attempt_ledger":ledger,
        "failure_sha256":sha256(&failure_raw),"content_response_sha256":sha256(&response_raw),"raw_body_hash":integrity::hash(&raw),"decoded_body_hash":integrity::hash(&bytes),
        "advertisement_fetch_reused":true,"head_request_reused":true,"content_fetch_reused":true,"qualified_rights_reused":false});
    let mut marker = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(root.join("git-rights-recovery.json"))
        .map_err(|_| bad())?;
    marker
        .write_all(&serde_json::to_vec_pretty(&provenance).map_err(|_| bad())?)
        .and_then(|()| marker.sync_all())
        .map_err(|_| io_error())?;
    File::open(root)
        .and_then(|file| file.sync_all())
        .map_err(|_| io_error())?;
    save(&root.join("git-rights-prior-failure.json"), &failure_raw)?;
    Ok(RetainedGitContent {
        bytes,
        evidence,
        artifact,
    })
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let (mode, destination, previous) = match args.as_slice() {
        [mode, destination] if matches!(mode.as_str(), "--live" | "--resume" | "--initialize" | "--resume-rfc-identity" | "--resume-git-v2" | "--resume-git-head" | "--resume-git-content" | "--resume-git-rights") => (mode.as_str(), destination, None),
        [retry, previous, mode, destination] if retry == "--retry-from" && mode == "--live" => (mode.as_str(), destination, Some(previous)),
        _ => return Err("usage: deployment-live-probe --live NEW_ROOT | --resume OWNED_ROOT | --resume-rfc-identity OWNED_ROOT | --resume-git-v2 OWNED_ROOT | --resume-git-head OWNED_ROOT | --resume-git-content OWNED_ROOT | --resume-git-rights OWNED_ROOT | --initialize NEW_ROOT (no network) | --retry-from FAILED_ROOT --live NEW_ROOT".into()),
    };
    let requested = evidence_path(Path::new(destination))?;
    if let Some(previous) = previous {
        let previous = evidence_path(Path::new(previous))?;
        // Validate again under the retained source lock below. No live I/O can
        // occur in this short interval between the two exclusive acquisitions.
        drop(initialize_retry(&previous, &requested)?);
    } else if matches!(mode, "--live" | "--initialize") {
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
    let carried = retry_baseline(&root, &ledger)?;
    let (baseline, _prior_lock) = match carried {
        Some((ledger, lock)) => (Some(ledger), Some(lock)),
        None => (None, None),
    };
    if mode == "--initialize" {
        println!(
            "Initialized private evidence root; no provider requests: {}",
            root.display()
        );
        return Ok(());
    }
    let mut rfc_recovery = if mode == "--resume-rfc-identity" {
        Some(prepare_rfc_identity_recovery(
            &root,
            &ledger,
            baseline.as_ref(),
        )?)
    } else {
        None
    };
    let git_recovery = matches!(
        mode,
        "--resume-git-v2" | "--resume-git-head" | "--resume-git-content" | "--resume-git-rights"
    );
    if mode == "--resume-git-v2" {
        prepare_git_v2_recovery(&root, &ledger, baseline.as_ref())?;
    }
    let retained_git_advertisement = if mode == "--resume-git-head" {
        Some(prepare_git_head_recovery(
            &root,
            &ledger,
            baseline.as_ref(),
        )?)
    } else {
        None
    };
    let retained_git_head = if mode == "--resume-git-content" {
        Some(prepare_git_content_recovery(
            &root,
            &ledger,
            baseline.as_ref(),
        )?)
    } else {
        None
    };
    let retained_git_content = if mode == "--resume-git-rights" {
        Some(prepare_git_rights_recovery(
            &root,
            &ledger,
            baseline.as_ref(),
        )?)
    } else {
        None
    };
    let mut probe = Probe {
        root: root.clone(),
        ledger: Arc::new(Mutex::new(ledger)),
        brokers: BTreeMap::new(),
        cancel: CancellationToken::new(),
        retained_git_advertisement,
        retained_git_head,
        retained_git_content,
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
        let spent = probe
            .ledger
            .lock()
            .map_err(|_| bad())?
            .families
            .get(family)
            .copied()
            .unwrap_or(0);
        if !(family == "rfc" && rfc_recovery.is_some() || family == "rustsec" && git_recovery)
            && !family_can_begin(family, spent, baseline.as_ref())
        {
            return Err(Error::unavailable("Incomplete family evidence needs operator review; automatic network retry is disabled.").into());
        }
        probe.stage(family, "starting_family")?;
        let result = if family == "rfc" {
            if let Some((evidence, artifact)) = rfc_recovery.take() {
                tokio::time::timeout(
                    Duration::from_secs(300),
                    probe.qualify_rfc(evidence, artifact),
                )
                .await
            } else {
                tokio::time::timeout(Duration::from_secs(300), probe.run(family)).await
            }
        } else {
            tokio::time::timeout(Duration::from_secs(300), probe.run(family)).await
        };
        let record = match result {
            Ok(Ok(record)) => record,
            failure => {
                let (code, detail) = match failure {
                    Ok(Err(error)) => (error.code.clone(), diagnostic(&error)),
                    _ => ("deadline_exceeded".into(), "family_deadline_exceeded"),
                };
                probe.cancel.cancel();
                let progress: Value = read_json(&root.join("progress.json"))?;
                save_json(
                    &root.join("failure.json"),
                    &json!({"family":family,"code":code,"diagnostic":detail,"stage":progress["stage"],"complete":false}),
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
        let receipt = json!({"version":1,"revision":REVISION,"family":family,"complete":true,"passed":true,"fixture":false,"attempts":attempts,"carried_attempts":baseline.as_ref().and_then(|ledger| ledger.families.get(family)).copied().unwrap_or(0),"scope":"fixed_source_parser_and_rights","whole_corpus":false,"transport_acceptance":false,"record":record});
        save_json(&receipt_path, &receipt)?;
        records.insert(family, receipt);
        println!("{family}: fixed source, parser and rights passed");
    }
    let counts = probe.ledger.lock().map_err(|_| bad())?.clone();
    let provenance: Option<RetryProvenance> = if baseline.is_some() {
        Some(read_json(&root.join("retry-provenance.json"))?)
    } else {
        None
    };
    let rfc_identity_recovery: Option<Value> = if present(&root.join("rfc-identity-recovery.json"))?
    {
        Some(read_json(&root.join("rfc-identity-recovery.json"))?)
    } else {
        None
    };
    save_json(
        &root.join("receipt.json"),
        &json!({"version":1,"release_revision":REVISION,"fixture":false,"complete":true,"whole_corpus":false,"production_publication":false,"transport_acceptance":false,"attempt_limit_per_family":20,"shared_github_attempt_limit":20,"github_attempts":counts.github,"attempt_ledger":counts,"carried_budget_provenance":provenance,"rfc_identity_recovery":rfc_identity_recovery,"git_rights_recovery":if root.join("git-rights-recovery.json").exists(){Some(read_json::<Value>(&root.join("git-rights-recovery.json"))?)}else{None},"git_content_recovery":if root.join("git-content-recovery.json").exists(){Some(read_json::<Value>(&root.join("git-content-recovery.json"))?)}else{None},"git_head_recovery":if root.join("git-head-recovery.json").exists(){Some(read_json::<Value>(&root.join("git-head-recovery.json"))?)}else{None},"git_v2_recovery":if root.join("git-v2-recovery.json").exists(){Some(read_json::<Value>(&root.join("git-v2-recovery.json"))?)}else{None},"providers":records}),
    )?;
    println!("Retained fixed-source evidence: {}", root.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn failed_fixture(parent: &Path, revision: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = parent.join("failed");
        initialize(&root).unwrap();
        let mut ledger = Ledger::new();
        ledger.reserve("rfc", "www.rfc-editor.org").unwrap();
        ledger.reserve("rfc", "www.rfc-editor.org").unwrap();
        ledger.reserve("mdn", "api.github.com").unwrap();
        ledger.revision = revision.into();
        save_json(&root.join("attempts.json"), &ledger).unwrap();
        save_json(
            &root.join("failure.json"),
            &json!({"family":"rfc","code":"integrity","complete":false}),
        )
        .unwrap();
        save(&root.join("run.lock"), b"").unwrap();
        root
    }
    #[test]
    fn retry_carries_every_spent_counter_without_copying_acceptance_or_changing_source() {
        let temporary = tempfile::tempdir_in("/tmp").unwrap();
        let source = failed_fixture(temporary.path(), PRIOR_REVISION);
        save(
            &source.join("rfc-source.bin"),
            b"old unqualified public body",
        )
        .unwrap();
        let before = std::fs::read_dir(&source)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (entry.file_name(), std::fs::read(entry.path()).unwrap())
            })
            .collect::<BTreeMap<_, _>>();
        let destination = temporary.path().join("retry");
        let source_lock = initialize_retry(&source, &destination).unwrap();
        let mut current: Ledger = read_json(&destination.join("attempts.json")).unwrap();
        assert_eq!(current.revision, REVISION);
        assert_eq!(current.families["rfc"], 2);
        assert_eq!(current.families["mdn"], 1);
        assert_eq!(current.hosts["www.rfc-editor.org"], 2);
        assert_eq!(current.hosts["api.github.com"], 1);
        assert_eq!(current.github, 1);
        assert!(!destination.join("rfc-source.bin").exists());
        assert!(!destination.join("rfc-receipt.json").exists());
        current.reserve("rfc", "www.rfc-editor.org").unwrap();
        assert_eq!(current.families["rfc"], 3);
        save_json(&destination.join("attempts.json"), &current).unwrap();
        drop(source_lock);
        let (baseline, lock) = retry_baseline(&destination, &current).unwrap().unwrap();
        assert!(family_can_begin("rfc", 2, Some(&baseline)));
        assert!(!family_can_begin("rfc", 3, Some(&baseline)));
        assert!(!family_can_begin("rfc", 2, None));
        assert!(family_can_begin("npm", 0, None));
        assert!(initialize_retry(&source, &temporary.path().join("second-child")).is_err());
        assert!(initialize_retry(&destination, &temporary.path().join("chained")).is_err());
        drop(lock);
        let after = std::fs::read_dir(&source)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (entry.file_name(), std::fs::read(entry.path()).unwrap())
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(before, after);
        let provenance: RetryProvenance =
            read_json(&destination.join("retry-provenance.json")).unwrap();
        assert_eq!(
            provenance.attempts_sha256,
            sha256(&before[std::ffi::OsStr::new("attempts.json")])
        );
        std::fs::remove_file(provenance.claim_file).unwrap();
    }
    #[test]
    fn existing_claim_rejects_forks_after_valid_source_failure_or_counter_changes() {
        let temporary = tempfile::tempdir_in("/tmp").unwrap();
        let source = failed_fixture(temporary.path(), PRIOR_REVISION);
        let destination = temporary.path().join("retry");
        drop(initialize_retry(&source, &destination).unwrap());
        let provenance: RetryProvenance =
            read_json(&destination.join("retry-provenance.json")).unwrap();
        let attempts_path = source.join("attempts.json");
        let failure_path = source.join("failure.json");
        let attempts_before = std::fs::read(&attempts_path).unwrap();
        let mut changed_failure = std::fs::read(&failure_path).unwrap();
        changed_failure.push(b'\n');
        save(&failure_path, &changed_failure).unwrap();
        let second = temporary.path().join("second-after-failure-change");
        assert!(initialize_retry(&source, &second).is_err());
        assert!(!second.exists());
        assert_eq!(retry_claim(&source).unwrap(), provenance.claim_file);
        assert_eq!(std::fs::read(&attempts_path).unwrap(), attempts_before);
        assert_eq!(std::fs::read(&failure_path).unwrap(), changed_failure);

        let mut changed: Ledger = read_json(&attempts_path).unwrap();
        changed.families.insert("rfc".into(), 1);
        changed.hosts.insert("www.rfc-editor.org".into(), 1);
        changed.validate_revision(PRIOR_REVISION).unwrap();
        save_json(&attempts_path, &changed).unwrap();
        let changed_attempts = std::fs::read(&attempts_path).unwrap();
        let third = temporary.path().join("third-after-counter-change");
        assert!(initialize_retry(&source, &third).is_err());
        assert!(!third.exists());
        assert_eq!(retry_claim(&source).unwrap(), provenance.claim_file);
        assert_eq!(std::fs::read(&attempts_path).unwrap(), changed_attempts);
        assert_eq!(std::fs::read(&failure_path).unwrap(), changed_failure);
        // Original child also refuses the now mismatching immutable provenance.
        let current: Ledger = read_json(&destination.join("attempts.json")).unwrap();
        assert!(retry_baseline(&destination, &current).is_err());
        std::fs::remove_file(provenance.claim_file).unwrap();
    }
    #[test]
    fn retry_refuses_unknown_completed_active_and_inconsistent_sources_without_new_root() {
        let temporary = tempfile::tempdir_in("/tmp").unwrap();
        let source = failed_fixture(temporary.path(), "unknown");
        let destination = temporary.path().join("retry");
        assert!(initialize_retry(&source, &destination).is_err());
        assert!(!destination.exists());
        let mut ledger: Ledger = read_json(&source.join("attempts.json")).unwrap();
        ledger.revision = REVISION.into();
        save_json(&source.join("attempts.json"), &ledger).unwrap();
        save_json(&source.join("receipt.json"), &json!({"complete":true})).unwrap();
        assert!(initialize_retry(&source, &destination).is_err());
        std::fs::remove_file(source.join("receipt.json")).unwrap();
        let active = File::open(source.join("run.lock")).unwrap();
        FileExt::try_lock_exclusive(&active).unwrap();
        assert!(initialize_retry(&source, &destination).is_err());
        drop(active);
        ledger.hosts.insert("www.rfc-editor.org".into(), 1);
        save_json(&source.join("attempts.json"), &ledger).unwrap();
        assert!(initialize_retry(&source, &destination).is_err());
        assert!(!destination.exists());
    }
    #[test]
    fn retry_rejects_symlinks_and_tampered_or_replenished_child_accounting() {
        let temporary = tempfile::tempdir_in("/tmp").unwrap();
        let source = failed_fixture(temporary.path(), REVISION);
        let alias = temporary.path().join("alias");
        std::os::unix::fs::symlink(&source, &alias).unwrap();
        assert!(evidence_path(&alias).is_err());
        assert!(initialize_retry(&alias, &temporary.path().join("invalid")).is_err());
        let destination = temporary.path().join("retry");
        drop(initialize_retry(&source, &destination).unwrap());
        let mut current: Ledger = read_json(&destination.join("attempts.json")).unwrap();
        assert!(retry_baseline(&destination, &current).is_ok());
        save(&destination.join("retry-pending"), MARKER).unwrap();
        assert!(retry_baseline(&destination, &current).is_err());
        std::fs::remove_file(destination.join("retry-pending")).unwrap();
        current.families.insert("rfc".into(), 1);
        current.hosts.insert("www.rfc-editor.org".into(), 1);
        assert!(retry_baseline(&destination, &current).is_err());
        let provenance: RetryProvenance =
            read_json(&destination.join("retry-provenance.json")).unwrap();
        std::fs::write(destination.join("retry-prior-failure.json"), b"tampered").unwrap();
        let original: Ledger = read_json(&destination.join("attempts.json")).unwrap();
        assert!(retry_baseline(&destination, &original).is_err());
        std::fs::remove_file(provenance.claim_file).unwrap();
    }
    fn packets(lines: &[&str]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for line in lines {
            bytes.extend_from_slice(format!("{:04x}{}", line.len() + 4, line).as_bytes());
        }
        bytes.extend_from_slice(b"0000");
        bytes
    }
    const FIXED_ADVISORY: &[u8] = br#"```toml
[advisory]
id = "RUSTSEC-2022-0039"
package = "odbc"
date = "2022-01-17"
informational = "unmaintained"
url = "https://github.com/Koka/odbc-rs/commit/f9e5f77fac0a6328f9759e6e0f9e10c16509aebb"

[versions]
patched = []
unaffected = []
```

# project abandoned

Alternatives:
- `odbc-api`
- `rs-odbc`
"#;
    #[test]
    fn git_rights_projection_qualifies_only_content_and_preserves_discovery_evidence() {
        let evidence = json!({"source_url":"https://api.github.com/repos/rustsec/advisory-db/contents/crates/odbc/RUSTSEC-2022-0039.md?ref=28d73fc95e5972af3403225a217def57dcaba3c4",
            "body_hash":integrity::hash(FIXED_ADVISORY),"revision":"28d73fc95e5972af3403225a217def57dcaba3c4","repository":"rustsec/advisory-db","path":"crates/odbc/RUSTSEC-2022-0039.md",
            "ref_observation":{"source_url":"https://github.com/rustsec/advisory-db.git/info/refs?service=git-upload-pack","body_hash":integrity::hash(b"advertisement")},
            "head_observation":{"source_url":"https://github.com/rustsec/advisory-db.git/git-upload-pack","body_hash":integrity::hash(b"head")}});
        let original = evidence.clone();
        let targets = attribution_providers::targets("rustsec", &evidence).unwrap();
        assert_eq!(targets.len(), 3);
        let error = single_rights_target("rustsec", &evidence).unwrap_err();
        assert_eq!(diagnostic(&error), "rights_target_count_mismatch");
        let projection = git_content_provenance(&evidence).unwrap();
        assert_eq!(
            attribution_providers::targets("rustsec", &projection)
                .unwrap()
                .len(),
            1
        );
        let target = single_rights_target("rustsec", &projection).unwrap();
        assert_eq!(
            target.evidence["source"]["source_url"],
            evidence["source_url"]
        );
        assert_eq!(
            target.evidence["source"]["body_hash"],
            integrity::hash(FIXED_ADVISORY)
        );
        assert_eq!(target.evidence["source"]["revision"], evidence["revision"]);
        assert_eq!(evidence, original);
        assert!(projection.get("ref_observation").is_none());
        assert!(projection.get("head_observation").is_none());
    }
    #[test]
    fn fixed_advisory_uses_released_parser_for_raw_or_encoded_contents_without_private_errors() {
        assert_eq!(
            fixed_rustsec(FIXED_ADVISORY).unwrap()["id"],
            "RUSTSEC-2022-0039"
        );
        let envelope = json!({"encoding":"base64","content":STANDARD.encode(FIXED_ADVISORY)});
        let decoded = decode_git(serde_json::to_vec(&envelope).unwrap()).unwrap();
        assert_eq!(decoded, FIXED_ADVISORY);
        assert_eq!(fixed_rustsec(&decoded).unwrap()["package"], "odbc");
        let invalid = fixed_rustsec(b"arbitrary private failure text").unwrap_err();
        assert_eq!(diagnostic(&invalid), "fixed_rustsec_schema_mismatch");
        assert!(!invalid.message.contains("private"));
        let wrong = String::from_utf8(FIXED_ADVISORY.to_vec())
            .unwrap()
            .replace("RUSTSEC-2022-0039", "RUSTSEC-2022-0040");
        assert_eq!(
            diagnostic(&fixed_rustsec(wrong.as_bytes()).unwrap_err()),
            "fixed_rustsec_identity_mismatch"
        );
        assert_eq!(
            diagnostic(&fixed_rustsec(&[0xff]).unwrap_err()),
            "fixed_rustsec_invalid_utf8"
        );
    }
    #[test]
    fn git_content_raw_and_decoded_evidence_precede_decoder_parser_and_rights() {
        let temporary = tempfile::tempdir_in("/tmp").unwrap();
        let make_probe = |root: PathBuf| Probe {
            root,
            ledger: Arc::new(Mutex::new(Ledger::new())),
            brokers: BTreeMap::new(),
            cancel: CancellationToken::new(),
            retained_git_advertisement: None,
            retained_git_head: None,
            retained_git_content: None,
        };
        let invalid_root = temporary.path().join("invalid-base64");
        std::fs::create_dir(&invalid_root).unwrap();
        let probe = make_probe(invalid_root.clone());
        let bytes = br#"{"encoding":"base64","content":"!invalid!"}"#.to_vec();
        let evidence = json!({"status":200,"body_hash":integrity::hash(&bytes),"source_url":"https://api.github.com/repos/rustsec/advisory-db/contents/crates/odbc/RUSTSEC-2022-0039.md?ref=28d73fc95e5972af3403225a217def57dcaba3c4"});
        let error = probe
            .retain_git_content("rustsec", bytes.clone(), &evidence)
            .unwrap_err();
        assert_eq!(diagnostic(&error), "fixed_git_content_invalid_base64");
        assert_eq!(
            std::fs::read(invalid_root.join("rustsec-content-raw.bin")).unwrap(),
            bytes
        );
        let response: Value =
            read_json(&invalid_root.join("rustsec-content-response.json")).unwrap();
        assert_eq!(response["source"], evidence);
        assert_eq!(response["rights_qualified"], false);
        verify_artifacts(&invalid_root, &response).unwrap();
        assert_eq!(
            read_json::<Value>(&invalid_root.join("progress.json")).unwrap()["stage"],
            "decoding_git_content"
        );
        assert!(!invalid_root.join("rustsec-source.bin").exists());

        let decoded_root = temporary.path().join("invalid-schema");
        std::fs::create_dir(&decoded_root).unwrap();
        let probe = make_probe(decoded_root.clone());
        let bytes = b"invalid advisory schema".to_vec();
        let (decoded, _, artifact) = probe
            .retain_git_content("rustsec", bytes.clone(), &json!({"status":200}))
            .unwrap();
        assert!(fixed_rustsec(&decoded).is_err());
        assert_eq!(
            std::fs::read(decoded_root.join("rustsec-source.bin")).unwrap(),
            bytes
        );
        verify_artifacts(&decoded_root, &artifact).unwrap();
        assert_eq!(
            read_json::<Value>(&decoded_root.join("progress.json")).unwrap()["stage"],
            "validating_fixed_git_content"
        );
        assert!(!decoded_root.join("rustsec-receipt.json").exists());
    }
    #[test]
    fn git_v2_capabilities_and_explicit_head_are_distinct_strict_exchanges() {
        let advert = packets(&[
            "version 2\n",
            "agent=fixture\n",
            "ls-refs=unborn\n",
            "fetch=shallow\n",
        ]);
        validate_git_v2(&advert).unwrap();
        let mut http_advert = b"001e# service=git-upload-pack\n0000".to_vec();
        http_advert.extend_from_slice(&advert);
        validate_git_v2(&http_advert).unwrap();
        assert!(
            validate_git_v2(
                &[
                    b"001e# service=git-receive-pack\n0000".as_slice(),
                    advert.as_slice()
                ]
                .concat()
            )
            .is_err()
        );
        assert!(head(&http_advert).is_err());
        assert!(head(&advert).is_err());
        let oid = "0123456789012345678901234567890123456789";
        let line = format!("{oid} HEAD symref-target:refs/heads/main\n");
        let refs = packets(&[&line]);
        assert_eq!(head(&refs).unwrap(), oid);
        assert!(head(&packets(&[&line, &line])).is_err());
        assert!(head(&packets(&["unborn HEAD symref-target:refs/heads/main\n"])).is_err());
        assert!(validate_git_v2(&packets(&["version 1\n", "ls-refs=unborn\n"])).is_err());
        assert!(validate_git_v2(&packets(&["version 2\n", "fetch=shallow\n"])).is_err());
        assert!(head(&refs[..refs.len() - 1]).is_err());
        let mut trailing = refs.clone();
        trailing.push(b'x');
        assert!(head(&trailing).is_err());
        assert_eq!(
            ls_refs_request(),
            b"0014command=ls-refs\n0001000csymrefs\n0014ref-prefix HEAD\n0000"
        );
    }
    #[test]
    fn git_recovery_is_single_use_and_retains_all_observed_spent_budgets() {
        use std::os::unix::fs::PermissionsExt;
        let temporary = tempfile::tempdir_in("/tmp").unwrap();
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let source = temporary.path().join("prior");
        initialize(&source).unwrap();
        save(&source.join("run.lock"), b"").unwrap();
        let destination = temporary.path().join("retry");
        let root = destination.as_path();
        let mut baseline = Ledger::new();
        for _ in 0..2 {
            baseline.reserve("rfc", "www.rfc-editor.org").unwrap();
        }
        baseline.revision = PRIOR_REVISION.into();
        let mut ledger = baseline.clone();
        ledger.revision = REVISION.into();
        for (family, host) in [
            ("rfc", "www.rfc-editor.org"),
            ("rfc", "www.rfc-editor.org"),
            ("crates", "index.crates.io"),
            ("crates", "static.crates.io"),
            ("crates", "static.crates.io"),
            ("rustsec", "github.com"),
        ] {
            ledger.reserve(family, host).unwrap();
        }
        save_json(&source.join("attempts.json"), &baseline).unwrap();
        save_json(
            &source.join("failure.json"),
            &json!({"family":"rfc","code":"integrity","complete":false}),
        )
        .unwrap();
        drop(initialize_retry(&source, root).unwrap());
        save_json(&root.join("attempts.json"), &ledger).unwrap();
        let (baseline, prior_lock) = retry_baseline(root, &ledger).unwrap().unwrap();
        assert_eq!(baseline.revision, PRIOR_REVISION);
        let failure = json!({"code":"integrity","complete":false,"diagnostic":"unclassified_failure","family":"rustsec","stage":"starting_family"});
        save_json(&root.join("failure.json"), &failure).unwrap();
        save_json(
            &root.join("progress.json"),
            &json!({"complete":false,"family":"rustsec","stage":"starting_family"}),
        )
        .unwrap();
        for family in ["rfc", "crates"] {
            save_json(
                &root.join(format!("{family}-receipt.json")),
                &json!({"fixture_receipt_for_preflight_only":true}),
            )
            .unwrap();
        }
        let mut extra = ledger.clone();
        extra.reserve("rustsec", "github.com").unwrap();
        assert!(prepare_git_v2_recovery(root, &extra, Some(&baseline)).is_err());
        assert!(!root.join("git-v2-recovery.json").exists());
        let mut wrong_revision = baseline.clone();
        wrong_revision.revision = REVISION.into();
        assert!(prepare_git_v2_recovery(root, &ledger, Some(&wrong_revision)).is_err());
        wrong_revision.revision = "unknown".into();
        assert!(prepare_git_v2_recovery(root, &ledger, Some(&wrong_revision)).is_err());
        prepare_git_v2_recovery(root, &ledger, Some(&baseline)).unwrap();
        assert_eq!(
            read_json::<Value>(&root.join("git-v2-prior-failure.json")).unwrap(),
            failure
        );
        assert_eq!(
            read_json::<Value>(&root.join("git-v2-recovery.json")).unwrap()["prior_attempt_ledger"],
            serde_json::to_value(&ledger).unwrap()
        );
        assert!(prepare_git_v2_recovery(root, &ledger, Some(&baseline)).is_err());
        assert!(!family_can_begin("rustsec", 1, Some(&baseline)));
        ledger.reserve("rustsec", "github.com").unwrap();
        assert_eq!(ledger.families["rustsec"], 2);
        assert_eq!(ledger.github, 2);
        save_json(&root.join("attempts.json"), &ledger).unwrap();
        let mut advert = b"001e# service=git-upload-pack\n0000".to_vec();
        advert.extend_from_slice(&packets(&["version 2\n", "ls-refs=unborn\n"]));
        save(&root.join("rustsec-refs.bin"), &advert).unwrap();
        let cap_failure = json!({"code":"integrity","complete":false,"diagnostic":"unclassified_failure","family":"rustsec","stage":"validating_git_v2_capabilities"});
        save_json(&root.join("failure.json"), &cap_failure).unwrap();
        save_json(
            &root.join("progress.json"),
            &json!({"complete":false,"family":"rustsec","stage":"validating_git_v2_capabilities"}),
        )
        .unwrap();
        let mut extra = ledger.clone();
        extra.reserve("rustsec", "github.com").unwrap();
        assert!(prepare_git_head_recovery(root, &extra, Some(&baseline)).is_err());
        assert!(!root.join("git-head-recovery.json").exists());
        let (retained, observation) =
            prepare_git_head_recovery(root, &ledger, Some(&baseline)).unwrap();
        assert_eq!(retained, advert);
        assert_eq!(observation["retained_from_prior_fetch"], true);
        assert_eq!(
            observation["original_http_headers_and_observation_time_unavailable"],
            true
        );
        assert_eq!(
            read_json::<Value>(&root.join("git-head-prior-failure.json")).unwrap(),
            cap_failure
        );
        assert!(prepare_git_head_recovery(root, &ledger, Some(&baseline)).is_err());
        let unchanged: Ledger = read_json(&root.join("attempts.json")).unwrap();
        assert_eq!(unchanged.families["rustsec"], 2);

        // The next observed helper failure spent HEAD and contents but retained
        // only HEAD. The explicit content recovery must reuse both Git exchanges
        // and preserve every attempt before its single charged contents refetch.
        ledger.reserve("rustsec", "github.com").unwrap();
        ledger.reserve("rustsec", "api.github.com").unwrap();
        save_json(&root.join("attempts.json"), &ledger).unwrap();
        let head_bytes = packets(&[
            "28d73fc95e5972af3403225a217def57dcaba3c4 HEAD symref-target:refs/heads/main\n",
        ]);
        save(&root.join("rustsec-head.bin"), &head_bytes).unwrap();
        let content_failure = json!({"code":"integrity","complete":false,"diagnostic":"unclassified_failure","family":"rustsec","stage":"validating_git_head"});
        save_json(&root.join("failure.json"), &content_failure).unwrap();
        save_json(
            &root.join("progress.json"),
            &json!({"complete":false,"family":"rustsec","stage":"validating_git_head"}),
        )
        .unwrap();
        let mut extra = ledger.clone();
        extra.reserve("rustsec", "api.github.com").unwrap();
        assert!(prepare_git_content_recovery(root, &extra, Some(&baseline)).is_err());
        let mut wrong_revision = baseline.clone();
        wrong_revision.revision = REVISION.into();
        assert!(prepare_git_content_recovery(root, &ledger, Some(&wrong_revision)).is_err());
        save(
            &root.join("rustsec-head.bin"),
            &packets(&["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa HEAD\n"]),
        )
        .unwrap();
        assert!(prepare_git_content_recovery(root, &ledger, Some(&baseline)).is_err());
        save(&root.join("rustsec-head.bin"), &head_bytes).unwrap();
        let mut changed_advert = advert.clone();
        changed_advert.extend_from_slice(b"x");
        save(&root.join("rustsec-refs.bin"), &changed_advert).unwrap();
        assert!(prepare_git_content_recovery(root, &ledger, Some(&baseline)).is_err());
        save(&root.join("rustsec-refs.bin"), &advert).unwrap();
        assert!(!root.join("git-content-recovery.json").exists());
        let retained = prepare_git_content_recovery(root, &ledger, Some(&baseline)).unwrap();
        assert_eq!(retained.refs, head_bytes);
        assert_eq!(retained.head_observation["retained_from_prior_fetch"], true);
        assert_eq!(
            retained.head_observation["original_http_headers_and_observation_time_unavailable"],
            true
        );
        assert!(prepare_git_content_recovery(root, &ledger, Some(&baseline)).is_err());
        assert_eq!(
            read_json::<Value>(&root.join("git-content-prior-failure.json")).unwrap(),
            content_failure
        );
        let unchanged: Ledger = read_json(&root.join("attempts.json")).unwrap();
        assert_eq!(unchanged.families["rustsec"], 4);
        assert_eq!(unchanged.github, 4);
        assert_eq!(unchanged.hosts["api.github.com"], 1);
        assert!(!family_can_begin("rustsec", 4, Some(&baseline)));
        let mut charged = unchanged;
        charged.reserve("rustsec", "api.github.com").unwrap();
        assert_eq!(charged.families["rustsec"], 5);
        assert_eq!(charged.github, 5);
        assert_eq!(charged.hosts["api.github.com"], 2);

        // That single refetch succeeded, but discovery provenance accidentally
        // created three rights targets before any rights I/O. Reuse the exact
        // retained representation and preserve API2; only rights may fetch next.
        let ledger = charged;
        save_json(&root.join("attempts.json"), &ledger).unwrap();
        save(&root.join("rustsec-content-raw.bin"), FIXED_ADVISORY).unwrap();
        save(&root.join("rustsec-source.bin"), FIXED_ADVISORY).unwrap();
        let url = BulkSource::Attribution(AttributionSource::RustSec {
            revision: "28d73fc95e5972af3403225a217def57dcaba3c4".into(),
            path: "crates/odbc/RUSTSEC-2022-0039.md".into(),
        })
        .url()
        .unwrap();
        let response = json!({"source":{"source_url":url,"body_hash":integrity::hash(FIXED_ADVISORY),"status":200,"observed_at":1,"content_length":306},
            "artifact":{"file":"rustsec-content-raw.bin","body_hash":integrity::hash(FIXED_ADVISORY),"bytes":306},"complete":false,"rights_qualified":false});
        save_json(&root.join("rustsec-content-response.json"), &response).unwrap();
        let rights_failure = json!({"code":"integrity","complete":false,"diagnostic":"unclassified_failure","family":"rustsec","stage":"repairing_exact_git_rights"});
        save_json(&root.join("failure.json"), &rights_failure).unwrap();
        save_json(
            &root.join("progress.json"),
            &json!({"complete":false,"family":"rustsec","stage":"repairing_exact_git_rights"}),
        )
        .unwrap();
        let mut extra = ledger.clone();
        extra.reserve("rustsec", "api.github.com").unwrap();
        assert!(prepare_git_rights_recovery(root, &extra, Some(&baseline)).is_err());
        let mut wrong_revision = baseline.clone();
        wrong_revision.revision = REVISION.into();
        assert!(prepare_git_rights_recovery(root, &ledger, Some(&wrong_revision)).is_err());
        let mut wrong_response = response.clone();
        wrong_response["source"]["source_url"] = json!(
            "https://api.github.com/repos/rustsec/advisory-db/contents/wrong.md?ref=28d73fc95e5972af3403225a217def57dcaba3c4"
        );
        save_json(&root.join("rustsec-content-response.json"), &wrong_response).unwrap();
        assert!(prepare_git_rights_recovery(root, &ledger, Some(&baseline)).is_err());
        save_json(&root.join("rustsec-content-response.json"), &response).unwrap();
        save(&root.join("rustsec-source.bin"), b"tampered public fixture").unwrap();
        assert!(prepare_git_rights_recovery(root, &ledger, Some(&baseline)).is_err());
        save(&root.join("rustsec-source.bin"), FIXED_ADVISORY).unwrap();
        assert!(!root.join("git-rights-recovery.json").exists());
        let restored = prepare_git_rights_recovery(root, &ledger, Some(&baseline)).unwrap();
        assert_eq!(restored.bytes, FIXED_ADVISORY);
        assert_eq!(restored.evidence["observed_at"], 1);
        assert_eq!(restored.evidence["status"], 200);
        assert_eq!(
            attribution_providers::targets(
                "rustsec",
                &git_content_provenance(&restored.evidence).unwrap()
            )
            .unwrap()
            .len(),
            1
        );
        assert!(restored.evidence.get("ref_observation").is_some());
        assert!(restored.evidence.get("head_observation").is_some());
        verify_artifacts(root, &restored.artifact).unwrap();
        assert!(prepare_git_rights_recovery(root, &ledger, Some(&baseline)).is_err());
        assert_eq!(
            read_json::<Value>(&root.join("git-rights-prior-failure.json")).unwrap(),
            rights_failure
        );
        let unchanged: Ledger = read_json(&root.join("attempts.json")).unwrap();
        assert_eq!(unchanged.families["rustsec"], 5);
        assert_eq!(unchanged.github, 5);
        assert_eq!(unchanged.hosts["api.github.com"], 2);
        assert!(!family_can_begin("rustsec", 5, Some(&baseline)));
        let mut next = unchanged;
        next.reserve("rustsec", "api.github.com").unwrap();
        assert_eq!(next.families["rustsec"], 6);
        assert_eq!(next.github, 6);
        assert_eq!(next.hosts["api.github.com"], 3);

        drop(prior_lock);
        let provenance: RetryProvenance = read_json(&root.join("retry-provenance.json")).unwrap();
        std::fs::remove_file(provenance.claim_file).unwrap();
    }
    const RFC_HEADER: &[u8] = b"\xef\xbb\xbf\n\nInternet Engineering Task Force (IETF)\nRequest for Comments: 9000      Synthetic Author\nCategory: Standards Track\n\n QUIC: A UDP-Based Multiplexed and Secure Transport\n\nAbstract\nSynthetic bounded RFC header fixture only.\n";
    #[test]
    fn rfc_header_requires_exact_number_and_full_title_within_bounded_header() {
        validate_rfc_text(RFC_HEADER).unwrap();
        let text = std::str::from_utf8(RFC_HEADER).unwrap();
        validate_rfc_text(
            text.replace(
                "Request for Comments: 9000",
                "  Request \t for   Comments: 9000",
            )
            .as_bytes(),
        )
        .unwrap();
        assert!(validate_rfc_text(text.replace("9000", "9001").as_bytes()).is_err());
        assert!(validate_rfc_text(text.replace("9000", "90000").as_bytes()).is_err());
        assert!(validate_rfc_text(text.replace("UDP-Based", "TCP-Based").as_bytes()).is_err());
        assert!(validate_rfc_text(b"RFC 9000 QUIC").is_err());
        assert!(validate_rfc_text(format!("{}{}", "\n".repeat(32), text).as_bytes()).is_err());
    }
    #[test]
    fn identity_recovery_reuses_only_unqualified_body_once_and_preserves_spent_three() {
        let temporary = tempfile::tempdir_in("/tmp").unwrap();
        let source = failed_fixture(temporary.path(), PRIOR_REVISION);
        let destination = temporary.path().join("retry");
        drop(initialize_retry(&source, &destination).unwrap());
        let mut ledger: Ledger = read_json(&destination.join("attempts.json")).unwrap();
        ledger.reserve("rfc", "www.rfc-editor.org").unwrap();
        save_json(&destination.join("attempts.json"), &ledger).unwrap();
        let probe = Probe {
            root: destination.clone(),
            ledger: Arc::new(Mutex::new(ledger.clone())),
            brokers: BTreeMap::new(),
            cancel: CancellationToken::new(),
            retained_git_advertisement: None,
            retained_git_head: None,
            retained_git_content: None,
        };
        let evidence = json!({"source_url":"https://www.rfc-editor.org/rfc/rfc9000.txt",
            "body_hash":integrity::hash(RFC_HEADER),"status":200,"content_length":null,"observed_at":1});
        probe.retain_rfc_initial(RFC_HEADER, &evidence).unwrap();
        let failure = json!({"code":"integrity","complete":false,"diagnostic":"fixed_rfc_text_identity_mismatch",
            "family":"rfc","stage":"validating_fixed_text"});
        save_json(&destination.join("failure.json"), &failure).unwrap();
        let failure_before = std::fs::read(destination.join("failure.json")).unwrap();
        let (baseline, _lock) = retry_baseline(&destination, &ledger).unwrap().unwrap();
        // Wrong stage, changed body and unrecorded extra attempts all fail before
        // the durable single-use marker is allocated.
        let initial_path = destination.join("rfc-initial-response.json");
        let original = std::fs::read(&initial_path).unwrap();
        let mut invalid: Value = read_json(&initial_path).unwrap();
        invalid["source"]["source_url"] = json!("https://www.rfc-editor.org/rfc/rfc9001.txt");
        save_json(&initial_path, &invalid).unwrap();
        assert!(prepare_rfc_identity_recovery(&destination, &ledger, Some(&baseline)).is_err());
        assert!(!destination.join("rfc-identity-recovery.json").exists());
        save(&initial_path, &original).unwrap();
        let mut extra = ledger.clone();
        extra.reserve("rfc", "www.rfc-editor.org").unwrap();
        assert!(prepare_rfc_identity_recovery(&destination, &extra, Some(&baseline)).is_err());
        let (retained, artifact) =
            prepare_rfc_identity_recovery(&destination, &ledger, Some(&baseline)).unwrap();
        assert_eq!(retained, evidence);
        assert_eq!(artifact["file"], "rfc-source.bin");
        let unchanged: Ledger = read_json(&destination.join("attempts.json")).unwrap();
        assert_eq!(unchanged.families["rfc"], 3);
        assert_eq!(
            std::fs::read(destination.join("rfc-identity-prior-failure.json")).unwrap(),
            failure_before
        );
        assert!(prepare_rfc_identity_recovery(&destination, &ledger, Some(&baseline)).is_err());
        assert!(!family_can_begin("rfc", 3, Some(&baseline)));
        assert!(!destination.join("rfc-receipt.json").exists());
        let provenance: Value = read_json(&destination.join("rfc-identity-recovery.json")).unwrap();
        assert_eq!(provenance["prior_rfc_attempts"], 3);
        assert_eq!(provenance["initial_response_sha256"], sha256(&original));
        assert_eq!(provenance["qualified_rights_reused"], false);
        // The unchanged released broker path must still reserve the next rights
        // fetch as attempt four; no initial fetch or credit reset is performed.
        let mut charged = ledger;
        charged.reserve("rfc", "www.rfc-editor.org").unwrap();
        assert_eq!(charged.families["rfc"], 4);
        let retry: RetryProvenance = read_json(&destination.join("retry-provenance.json")).unwrap();
        std::fs::remove_file(retry.claim_file).unwrap();
    }
    #[test]
    fn rfc_initial_diagnostics_survive_identity_failure_without_claiming_rights() {
        let temporary = tempfile::tempdir_in("/tmp").unwrap();
        let probe = Probe {
            root: temporary.path().to_owned(),
            ledger: Arc::new(Mutex::new(Ledger::new())),
            brokers: BTreeMap::new(),
            cancel: CancellationToken::new(),
            retained_git_advertisement: None,
            retained_git_head: None,
            retained_git_content: None,
        };
        let body = b"unrelated HTML challenge without the fixed document identity";
        let evidence = json!({"source_url":"https://www.rfc-editor.org/rfc/rfc9000.txt","body_hash":integrity::hash(body),"status":200,"content_length":body.len()});
        let error = probe.retain_rfc_initial(body, &evidence).unwrap_err();
        assert_eq!(diagnostic(&error), "fixed_rfc_text_identity_mismatch");
        assert_eq!(
            std::fs::read(temporary.path().join("rfc-source.bin")).unwrap(),
            body
        );
        assert_eq!(
            std::fs::metadata(temporary.path().join("rfc-source.bin"))
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );
        let meta: Value = read_json(&temporary.path().join("rfc-initial-response.json")).unwrap();
        assert_eq!(meta["rights_qualified"], false);
        assert_eq!(meta["complete"], false);
        assert!(!temporary.path().join("rfc-receipt.json").exists());
        let targets = attribution_providers::targets("rfc", &evidence).unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(
            targets[0].evidence["source"]["body_hash"],
            evidence["body_hash"]
        );
        assert_eq!(
            diagnostic(&Error::integrity("private or arbitrary text")),
            "unclassified_failure"
        );
    }
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
    fn fixed_git_head_rejects_v0_capabilities_and_invalid_packets() {
        let oid = "a".repeat(40);
        let data = format!("{oid} HEAD\0symref=HEAD:refs/heads/main\n");
        let packet = format!("{:04x}{data}0000", data.len() + 4);
        assert!(head(packet.as_bytes()).is_err());
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
            retained_git_advertisement: None,
            retained_git_head: None,
            retained_git_content: None,
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
