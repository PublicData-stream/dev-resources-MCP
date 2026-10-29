//! Resumable public npm catalog and OSV collection. Research never enrolls packages.
use crate::{
    bulk::{BulkArtifact, BulkArtifactStore, BulkBroker, BulkRequest, BulkSource},
    npm::index::{IndexDocument, NpmIndex},
    npm::processing as npm_processing,
    npm::source::Operation,
};
use devres_application::npm::{NpmConfig, NpmStore, PROCESSOR_VERSION};
use devres_domain::{Error, Result, Validators};
use serde_json::{Value, json};
use sha2::Digest;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::Arc,
    time::Duration,
};
use tokio::{io::AsyncReadExt, sync::Mutex, time::Instant};
use tokio_util::sync::CancellationToken;

const MAX_METADATA: u64 = 16 * 1024 * 1024;
const MAX_INSPECTION: u64 = 32 * 1024 * 1024;
const MAX_RELEVANT: usize = 120 * 1024 * 1024;
struct ScannedAdvisory {
    record: Value,
    bytes: Vec<u8>,
    path: String,
}
pub struct NpmCorpus {
    pub(crate) store: Arc<dyn NpmStore>,
    broker: Arc<BulkBroker>,
    pub(crate) raw: Arc<BulkArtifactStore>,
    pub(crate) index: NpmIndex,
    config: NpmConfig,
    processing: Mutex<()>,
}
pub(crate) fn digest(bytes: &[u8]) -> String {
    crate::integrity::hash(bytes)
}
pub(crate) fn identity(value: &Value) -> Result<String> {
    Ok(digest(&serde_json::to_vec(value).map_err(|_| failure())?))
}
fn failure() -> Error {
    Error::unavailable("npm corpus evidence unavailable.")
}
fn canceled(cancel: &CancellationToken) -> Result<()> {
    if cancel.is_cancelled() {
        Err(Error::new("cancelled", "npm collection canceled."))
    } else {
        Ok(())
    }
}
fn state_key(prefix: &str, name: &str) -> String {
    // Operational source/job lookup names stay stable across the content-ID migration.
    format!(
        "{prefix}:{}",
        crate::integrity::legacy_hash(name.as_bytes())
    )
}
impl NpmCorpus {
    pub fn new(
        store: Arc<dyn NpmStore>,
        broker: Arc<BulkBroker>,
        root: &Path,
        config: NpmConfig,
    ) -> Result<Self> {
        config.validate()?;
        for name in &config.packages {
            npm_processing::validate_name(name)?;
        }
        std::fs::create_dir_all(root.join("npm/raw-artifacts")).map_err(|_| failure())?;
        let raw = Arc::new(
            BulkArtifactStore::new(root.join("npm/raw-artifacts"), config.min_free_bytes)?
                .with_quota(config.max_archive_storage_bytes)?,
        );
        Ok(Self {
            store,
            broker,
            raw,
            index: NpmIndex::new(root)?,
            config,
            processing: Mutex::new(()),
        })
    }
    pub fn store(&self) -> Arc<dyn NpmStore> {
        self.store.clone()
    }
    pub fn config(&self) -> &NpmConfig {
        &self.config
    }
    pub async fn initialize_status(&self) -> Result<()> {
        self.raw.recover_stages().await?;
        self.index.recover_stages()?;
        self.update_status().await
    }
    pub async fn status(&self) -> Result<Value> {
        let mut output = self
            .store
            .npm_state("status")
            .await?
            .unwrap_or_else(|| json!({}));
        output["counts"] = self.store.npm_statistics().await?;
        output["enabled"] = json!(self.config.enabled);
        output["collection_enabled"] = json!(self.config.enabled);
        output["advisories_enabled"] = json!(self.config.advisories_enabled);
        output["catalog_packages"] = json!(self.config.packages.len());
        output["catalog_scope"] = json!("explicit_operator_catalog");
        output["full_registry_coverage"] = json!(false);
        output["raw_bytes"] = json!(self.raw.accounted_bytes());
        output["raw_quota_bytes"] = json!(self.raw.quota_bytes());
        for lane in ["research", "advisories"] {
            output[format!("{lane}_default")] = self
                .store
                .npm_state(&format!("default-{lane}"))
                .await?
                .map(|v| snapshot_summary(&v))
                .unwrap_or(Value::Null);
        }
        Ok(output)
    }
    async fn update_status(&self) -> Result<()> {
        let previous = self
            .store
            .npm_state("status")
            .await?
            .unwrap_or_else(|| json!({}));
        self.store.npm_set_state("status", &previous).await
    }
    pub async fn run(&self, cancel: CancellationToken) -> Result<()> {
        loop {
            if cancel.is_cancelled() {
                return Ok(());
            }
            if self.config.enabled {
                // Alternate independent lanes. A package failure never suppresses advisory refresh.
                if !self.config.packages.is_empty() {
                    let rotation = self
                        .store
                        .npm_state("package-rotation")
                        .await?
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as usize;
                    let position = rotation % self.config.packages.len();
                    let name = &self.config.packages[position];
                    if let Err(error) = self.collect_package(name, cancel.clone()).await {
                        self.record_failure("package", Some(name), &error).await?;
                    }
                    self.store
                        .npm_set_state(
                            "package-rotation",
                            &json!((position + 1) % self.config.packages.len()),
                        )
                        .await?;
                }
                if self.config.advisories_enabled
                    && !cancel.is_cancelled()
                    && let Err(error) = self.collect_advisories(cancel.clone()).await
                {
                    self.record_failure("advisories", None, &error).await?;
                }
                if !cancel.is_cancelled() {
                    self.publish_research().await?;
                }
            }
            tokio::select! {_=cancel.cancelled()=>return Ok(()),_=tokio::time::sleep(Duration::from_secs(self.config.collection_interval_secs))=>{}}
        }
    }
    async fn record_failure(&self, lane: &str, name: Option<&str>, error: &Error) -> Result<()> {
        let data =
            json!({"lane":lane,"name":name,"code":error.code,"at":devres_domain::unix_now()});
        let key = identity(&data)?;
        self.store.npm_put("failures", &key, &data).await?;
        let terminal = matches!(
            error.code.as_str(),
            "invalid_input" | "integrity" | "processing_gap"
        ) || lane == "advisories" && error.code == "capacity";
        let job_key = if let Some(name) = name {
            state_key("package-job", name)
        } else {
            "advisory-job".into()
        };
        if terminal && let Some(mut job) = self.store.npm_state(&job_key).await? {
            job["done"] = json!(true);
            job["failed"] = json!(error.code);
            self.store.npm_set_state(&job_key, &job).await?;
        }
        let refresh = if lane == "advisories" {
            self.config.advisory_refresh_secs
        } else {
            self.config.metadata_refresh_secs
        };
        let delay = if terminal { refresh } else { refresh.min(60) };
        let retry_key = if let Some(name) = name {
            state_key("package-retry", name)
        } else {
            "advisory-retry".into()
        };
        self.store
            .npm_set_state(
                &retry_key,
                &json!(devres_domain::unix_now().saturating_add(delay as i64)),
            )
            .await?;
        self.store
            .npm_set_state("status", &json!({"last_failure":data}))
            .await
    }
    async fn fetch(
        &self,
        operation: Operation,
        max: u64,
        cancel: CancellationToken,
    ) -> Result<BulkArtifact> {
        canceled(&cancel)?;
        let moving = matches!(
            operation,
            Operation::Metadata { .. } | Operation::AdvisoryExport
        );
        let url = operation.url()?;
        let cache_key = state_key("source-cache", &url);
        let cached = if moving {
            self.store.npm_state(&cache_key).await?
        } else {
            None
        };
        let validators = cached
            .as_ref()
            .map_or_else(Validators::default, |v| Validators {
                etag: v["validators"]["etag"].as_str().map(str::to_owned),
                last_modified: v["validators"]["last_modified"].as_str().map(str::to_owned),
            });
        let response = self
            .broker
            .open(
                BulkRequest {
                    source: BulkSource::Npm(operation),
                    validators,
                    max_bytes: max,
                    deadline: Instant::now() + Duration::from_secs(3600),
                    body: Vec::new(),
                },
                cancel.clone(),
            )
            .await?;
        let status = response.status;
        let validators = json!({"etag":response.validators.etag.clone(),"last_modified":response.validators.last_modified.clone()});
        let artifact = if status == 304 {
            let data = cached.as_ref().ok_or_else(|| {
                Error::integrity("npm conditional response has no qualified retained body.")
            })?;
            let artifact: BulkArtifact =
                serde_json::from_value(data["artifact"].clone()).map_err(|_| failure())?;
            self.raw
                .verify(&artifact.body_hash, max, cancel.clone())
                .await?;
            artifact
        } else {
            self.raw.capture(response, None, cancel).await?
        };
        let mut observation = json!({"source_url":url,"artifact":artifact,"status":status,"validated_at":devres_domain::unix_now(),"validators":validators});
        if status == 304
            && let Some(previous) = &cached
        {
            for field in ["etag", "last_modified"] {
                if observation["validators"][field].is_null() {
                    observation["validators"][field] = previous["validators"][field].clone();
                }
            }
        }
        self.store
            .npm_put(
                "source-observations",
                &identity(&observation)?,
                &observation,
            )
            .await?;
        if moving {
            self.store
                .npm_set_state(&state_key("source-response", &url), &observation)
                .await?;
        }
        Ok(artifact)
    }
    /// Only a successfully interpreted moving representation can supply future HTTP validators.
    async fn accept_fetch(&self, operation: Operation, artifact: &BulkArtifact) -> Result<()> {
        let url = operation.url()?;
        if let Some(response) = self
            .store
            .npm_state(&state_key("source-response", &url))
            .await?
            && response["artifact"]["body_hash"] == artifact.body_hash
        {
            self.store
                .npm_set_state(&state_key("source-cache", &url), &response)
                .await?;
        }
        Ok(())
    }
    pub(crate) async fn bytes(
        &self,
        artifact: &BulkArtifact,
        max: u64,
        cancel: CancellationToken,
    ) -> Result<Vec<u8>> {
        if artifact.bytes > max {
            return Err(Error::capacity(
                "npm retained artifact exceeds inspection limit.",
            ));
        }
        let file = self
            .raw
            .open(&artifact.body_hash, max, cancel.clone())
            .await?;
        let mut bytes = Vec::new();
        file.take(max + 1)
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| failure())?;
        canceled(&cancel)?;
        if bytes.len() as u64 != artifact.bytes {
            return Err(Error::integrity("npm retained artifact length mismatch."));
        }
        Ok(bytes)
    }
    async fn collect_package(&self, name: &str, cancel: CancellationToken) -> Result<()> {
        let _guard = self.processing.lock().await;
        if self
            .store
            .npm_state(&state_key("package-retry", name))
            .await?
            .and_then(|v| v.as_i64())
            .is_some_and(|t| t > devres_domain::unix_now())
        {
            return Ok(());
        }
        let key = state_key("package-job", name);
        let mut job = match self.store.npm_state(&key).await? {
            Some(job) if job["done"] != true => job,
            _ => {
                let last = self
                    .store
                    .npm_state(&state_key("package-head", name))
                    .await?;
                if last
                    .as_ref()
                    .and_then(|v| v["validated_at"].as_i64())
                    .is_some_and(|t| {
                        devres_domain::unix_now().saturating_sub(t)
                            < self.config.metadata_refresh_secs as i64
                    })
                {
                    return Ok(());
                }
                let artifact = self
                    .fetch(
                        Operation::Metadata { name: name.into() },
                        MAX_METADATA,
                        cancel.clone(),
                    )
                    .await?;
                let time = devres_domain::unix_now();
                let id = identity(&json!([name, artifact.body_hash, time, PROCESSOR_VERSION]))?;
                self.store
                    .npm_put(
                        "metadata-captures",
                        &id,
                        &json!({"id":id,"name":name,"artifact":artifact,"validated_at":time}),
                    )
                    .await?;
                let job = json!({"snapshot":id,"name":name,"metadata":artifact,"validated_at":time,"next":0,"versions":0,"gaps":0,"documents":0,"done":false});
                self.store.npm_set_state(&key, &job).await?;
                job
            }
        };
        let snapshot_id = job["snapshot"].as_str().ok_or_else(failure)?.to_owned();
        if let Some(published) = self
            .store
            .npm_get("package-snapshots", &snapshot_id)
            .await?
        {
            self.finish_package(&key, &mut job, &published.data).await?;
            return Ok(());
        }
        let artifact: BulkArtifact =
            serde_json::from_value(job["metadata"].clone()).map_err(|_| failure())?;
        let bytes = self.bytes(&artifact, MAX_METADATA, cancel.clone()).await?;
        let owned = name.to_string();
        let packument =
            tokio::task::spawn_blocking(move || npm_processing::parse_packument(&bytes, &owned))
                .await
                .map_err(|_| failure())??;
        let versions = packument["versions"]
            .as_object()
            .ok_or_else(|| Error::integrity("npm metadata has no release inventory."))?;
        self.accept_fetch(Operation::Metadata { name: name.into() }, &artifact)
            .await?;
        let snapshot = job["snapshot"].as_str().ok_or_else(failure)?.to_owned();
        let next = job["next"].as_u64().unwrap_or(0) as usize;
        let start = Instant::now();
        for (position, (version, manifest)) in versions.iter().enumerate().skip(next) {
            canceled(&cancel)?;
            let result = self
                .process_version(
                    &snapshot,
                    name,
                    version,
                    manifest,
                    &artifact,
                    cancel.clone(),
                )
                .await;
            let gap = match result {
                Ok((documents, gaps)) => {
                    job["documents"] = json!(job["documents"].as_u64().unwrap_or(0) + documents);
                    gaps
                }
                Err(error) => {
                    if matches!(
                        error.code.as_str(),
                        "unavailable" | "capacity" | "cancelled"
                    ) {
                        return Err(error);
                    }
                    let data = json!({"snapshot":snapshot,"name":name,"version":version,"code":error.code,"metadata":artifact.body_hash});
                    self.store.npm_put("gaps", &identity(&data)?, &data).await?;
                    1
                }
            };
            job["gaps"] = json!(job["gaps"].as_u64().unwrap_or(0) + gap);
            job["versions"] = json!(position + 1);
            job["next"] = json!(position + 1);
            self.store.npm_set_state(&key, &job).await?;
            // A bounded iteration lets the advisory lane and cancellation make progress.
            if start.elapsed() > Duration::from_secs(15) {
                return Ok(());
            }
        }
        if let Err(error) = self.index_pending(&snapshot, cancel.clone()).await {
            if error.code == "cancelled" {
                return Err(error);
            }
            job["gaps"] = json!(job["gaps"].as_u64().unwrap_or(0) + 1);
            let gap = json!({"snapshot":snapshot,"name":name,"code":error.code,"stage":"index"});
            self.store.npm_put("gaps", &identity(&gap)?, &gap).await?;
        }
        let missing = self.capture_index_members(&snapshot).await?;
        job["gaps"] = json!(job["gaps"].as_u64().unwrap_or(0) + missing);
        let previous = self
            .store
            .npm_state(&state_key("package-head", name))
            .await?;
        let package = json!({"previous":previous.as_ref().map(|v|v["id"].clone()),"id":snapshot,"name":name,"metadata":artifact,"validated_at":job["validated_at"],
            "versions":job["versions"],"documents":job["documents"],"gaps":job["gaps"],"accounted":true,
            "processor_version":PROCESSOR_VERSION,"dist_tags":packument["dist-tags"],"time":{ "created":packument["time"]["created"],"modified":packument["time"]["modified"],"unpublished":packument["time"]["unpublished"]},
            "index":self.store.npm_state("index").await?.unwrap_or(Value::Null)});
        self.store
            .npm_put("package-snapshots", &snapshot, &package)
            .await?;
        self.finish_package(&key, &mut job, &package).await?;
        Ok(())
    }
    async fn finish_package(&self, key: &str, job: &mut Value, package: &Value) -> Result<()> {
        if package["id"] != job["snapshot"]
            || package["name"] != job["name"]
            || package["accounted"] != true
        {
            return Err(Error::integrity(
                "npm package completion does not match its acquisition.",
            ));
        }
        let name = package["name"].as_str().ok_or_else(failure)?;
        self.store
            .npm_set_state(&state_key("package-head", name), package)
            .await?;
        job["done"] = json!(true);
        self.store.npm_set_state(key, job).await
    }
    async fn process_version(
        &self,
        snapshot: &str,
        name: &str,
        version: &str,
        manifest: &Value,
        metadata: &BulkArtifact,
        cancel: CancellationToken,
    ) -> Result<(u64, u64)> {
        let release = json!({"name":name,"version":version,"manifest":manifest,"metadata":metadata.body_hash});
        let release_id = identity(&release)?;
        self.store
            .npm_put("versions", &release_id, &release)
            .await?;
        let member = json!({"snapshot":snapshot,"kind":"version","name":name,"version":version,"record":release_id});
        self.store
            .npm_put("members", &identity(&member)?, &member)
            .await?;
        npm_processing::parse_version(version).map_err(|_| {
            Error::new(
                "processing_gap",
                "Historical npm version has unsupported syntax.",
            )
        })?;
        let archive_key = identity(&json!([name, version, manifest["dist"], PROCESSOR_VERSION]))?;
        let previous = self.store.npm_get("artifacts", &archive_key).await?;
        let artifact = if let Some(previous) = previous {
            serde_json::from_value(previous.data["artifact"].clone()).map_err(|_| failure())?
        } else {
            let url = manifest
                .pointer("/dist/tarball")
                .and_then(Value::as_str)
                .ok_or_else(|| Error::integrity("npm archive destination missing."))?;
            let artifact = self
                .fetch(
                    Operation::Archive {
                        name: name.into(),
                        version: version.into(),
                        url: url.into(),
                    },
                    crate::bulk::MAX_ARTIFACT_BYTES,
                    cancel.clone(),
                )
                .await?;
            // Raw observations are permanent even when they fail the published digest.
            let observation = json!({"name":name,"version":version,"artifact":artifact,"metadata":metadata.body_hash});
            self.store
                .npm_put(
                    "archive-observations",
                    &identity(&observation)?,
                    &observation,
                )
                .await?;
            let assurance = self
                .verify_artifact(&artifact, manifest, cancel.clone())
                .await?;
            // Only digest-verified bytes become reusable distribution evidence.
            self.store.npm_put("artifacts",&archive_key,&json!({"name":name,"version":version,"artifact":artifact,"assurance":assurance})).await?;
            artifact
        };
        let data = json!({"snapshot":snapshot,"kind":"archive","name":name,"version":version,"record":archive_key});
        self.store
            .npm_put("members", &identity(&data)?, &data)
            .await?;
        let projection_key = identity(&json!([release_id, artifact.body_hash, PROCESSOR_VERSION]))?;
        let projection = if let Some(projection) =
            self.store.npm_get("projections", &projection_key).await?
        {
            projection.data
        } else {
            let bytes = self
                .bytes(&artifact, MAX_INSPECTION, cancel.clone())
                .await
                .map_err(|_| {
                    Error::new(
                        "processing_gap",
                        "npm archive checksum verified and retained; source inspection exceeds its bound.",
                    )
                })?;
            let manifest = manifest.clone();
            let projection = tokio::task::spawn_blocking(move || {
                npm_processing::inspect_package(&bytes, &manifest)
            })
            .await
            .map_err(|_| failure())?
            .map_err(|_| {
                Error::new(
                    "processing_gap",
                    "npm retained archive failed bounded integrity or source processing.",
                )
            })?;
            // Documents are stored independently, never as one version-sized JSON row.
            let data = json!({"name":name,"version":version,"members":projection["members"],"contracts":projection["contracts"],"gaps":projection["gaps"],"artifact":artifact,"release":release_id});
            let mut ids = Vec::new();
            for document in projection["documents"].as_array().into_iter().flatten() {
                let value = json!({"name":name,"version":version,"path":document["path"],"kind":document["kind"],"text":document["text"],"artifact":artifact.body_hash,"release":release_id});
                let id = identity(&value)?;
                self.store.npm_put("documents", &id, &value).await?;
                ids.push(id);
            }
            let mut data = data;
            data["documents"] = json!(ids);
            self.store
                .npm_put("projections", &projection_key, &data)
                .await?;
            data
        };
        let member = json!({"snapshot":snapshot,"kind":"projection","name":name,"version":version,"record":projection_key});
        self.store
            .npm_put("members", &identity(&member)?, &member)
            .await?;
        let mut count = 0;
        for id in projection["documents"].as_array().into_iter().flatten() {
            let id = id.as_str().ok_or_else(failure)?;
            let member = json!({"snapshot":snapshot,"kind":"document","name":name,"version":version,"record":id});
            self.store
                .npm_put("members", &identity(&member)?, &member)
                .await?;
            count += 1;
        }
        Ok((
            count,
            projection["gaps"].as_array().map_or(1, |v| v.len() as u64),
        ))
    }
    async fn verify_artifact(
        &self,
        artifact: &BulkArtifact,
        manifest: &Value,
        cancel: CancellationToken,
    ) -> Result<Value> {
        let mut file = self
            .raw
            .open(
                &artifact.body_hash,
                crate::bulk::MAX_ARTIFACT_BYTES,
                cancel.clone(),
            )
            .await?;
        let mut sha512 = sha2::Sha512::new();
        let mut sha384 = sha2::Sha384::new();
        let mut sha256 = sha2::Sha256::new();
        let mut sha1 = sha1::Sha1::new();
        let mut buffer = vec![0; 64 * 1024];
        let start = Instant::now();
        loop {
            canceled(&cancel)?;
            if start.elapsed() > Duration::from_secs(3600) {
                return Err(Error::capacity(
                    "npm archive verification deadline exceeded.",
                ));
            }
            let count = tokio::select! {_=cancel.cancelled()=>return Err(Error::new("cancelled","npm archive verification canceled.")),result=file.read(&mut buffer)=>result.map_err(|_|failure())?};
            if count == 0 {
                break;
            }
            let bytes = &buffer[..count];
            sha512.update(bytes);
            sha384.update(bytes);
            sha256.update(bytes);
            sha1.update(bytes);
        }
        npm_processing::integrity_matches(
            manifest,
            &sha512.finalize(),
            &sha384.finalize(),
            &sha256.finalize(),
            &sha1.finalize(),
        )
    }
    async fn index_pending(&self, snapshot: &str, cancel: CancellationToken) -> Result<()> {
        let mut after = 0;
        let mut documents = Vec::new();
        let mut bytes = 0;
        let filter = json!({"snapshot":snapshot,"kind":"document"});
        loop {
            canceled(&cancel)?;
            let rows = self
                .store
                .npm_rows("members", after, 100, None, Some(&filter))
                .await?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                after = row.sequence;
                let id = row.data["record"].as_str().ok_or_else(failure)?;
                if self.store.npm_get("indexed", id).await?.is_some() {
                    continue;
                }
                let data = self
                    .store
                    .npm_get("documents", id)
                    .await?
                    .ok_or_else(failure)?
                    .data;
                let doc = IndexDocument {
                    id: id.into(),
                    name: data["name"].as_str().unwrap_or_default().into(),
                    version: data["version"].as_str().unwrap_or_default().into(),
                    path: data["path"].as_str().unwrap_or_default().into(),
                    title: data["path"].as_str().unwrap_or_default().into(),
                    text: data["text"].as_str().unwrap_or_default().into(),
                    kind: data["kind"].as_str().unwrap_or("source").into(),
                    metadata: json!({"document":id}),
                };
                if !documents.is_empty()
                    && (bytes + doc.text.len() > 16 * 1024 * 1024 || documents.len() >= 512)
                {
                    self.publish_documents(std::mem::take(&mut documents), cancel.clone())
                        .await?;
                    bytes = 0;
                }
                if let Err(error) = NpmIndex::validate_document(&doc, &cancel) {
                    if cancel.is_cancelled() {
                        return Err(error);
                    }
                    let gap = json!({"snapshot":snapshot,"document":id,"code":error.code,"stage":"index"});
                    self.store.npm_put("gaps", &identity(&gap)?, &gap).await?;
                    continue;
                }
                bytes += doc.text.len();
                documents.push(doc);
            }
        }
        if !documents.is_empty() {
            self.publish_documents(documents, cancel).await?;
        }
        Ok(())
    }
    async fn capture_index_members(&self, snapshot: &str) -> Result<u64> {
        let mut missing = 0;
        let mut after = 0;
        let filter = json!({"snapshot":snapshot,"kind":"document"});
        loop {
            let rows = self
                .store
                .npm_rows("members", after, 1000, None, Some(&filter))
                .await?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                after = row.sequence;
                if self
                    .store
                    .npm_get("indexed", row.data["record"].as_str().ok_or_else(failure)?)
                    .await?
                    .is_some()
                {
                    let mut member = row.data;
                    member["kind"] = json!("indexed-document");
                    self.store
                        .npm_put("members", &identity(&member)?, &member)
                        .await?;
                } else {
                    missing += 1;
                }
            }
        }
        Ok(missing)
    }
    async fn publish_documents(
        &self,
        documents: Vec<IndexDocument>,
        cancel: CancellationToken,
    ) -> Result<()> {
        let ids: Vec<_> = documents.iter().map(|v| v.id.clone()).collect();
        let old = self.store.npm_state("index").await?;
        let index = self.index.publish(old.as_ref(), documents, cancel).await?;
        self.store.npm_commit_index(&index, &ids).await?;
        Ok(())
    }
    async fn publish_research(&self) -> Result<()> {
        if let Some(last) = self.store.npm_state("last-research-publication").await?
            && last.as_i64().is_some_and(|t| {
                devres_domain::unix_now().saturating_sub(t)
                    < self.config.publication_interval_secs as i64
            })
        {
            return Ok(());
        }
        let mut packages = BTreeMap::new();
        let mut validated = devres_domain::unix_now();
        let mut gaps = 0;
        let mut synthetic = false;
        for name in &self.config.packages {
            if let Some(head) = self
                .store
                .npm_state(&state_key("package-head", name))
                .await?
            {
                packages.insert(name.clone(), head["id"].clone());
                synthetic |= head["synthetic"] == true;
                validated = validated.min(head["validated_at"].as_i64().unwrap_or(0));
                gaps += head["gaps"].as_u64().unwrap_or(0);
            }
        }
        if packages.is_empty() {
            return Ok(());
        }
        let mut data = json!({"lane":"research","packages":packages,"catalog":self.config.packages,
            "validated_at":validated,"accounted":true,"complete":packages.len()==self.config.packages.len()&&gaps==0,
            "gaps":gaps,"synthetic":synthetic,"index":self.store.npm_state("index").await?.unwrap_or(Value::Null),"processor_version":PROCESSOR_VERSION});
        data["id"] = json!(identity(&data)?);
        self.store.npm_publish("research", &data).await?;
        self.store
            .npm_set_state(
                "last-research-publication",
                &json!(devres_domain::unix_now()),
            )
            .await
    }
    async fn collect_advisories(&self, cancel: CancellationToken) -> Result<()> {
        let _guard = self.processing.lock().await;
        if self
            .store
            .npm_state("advisory-retry")
            .await?
            .and_then(|v| v.as_i64())
            .is_some_and(|t| t > devres_domain::unix_now())
        {
            return Ok(());
        }
        let mut job = match self.store.npm_state("advisory-job").await? {
            Some(job) if job["done"] != true => job,
            _ => {
                let last = self.store.npm_state("default-advisories").await?;
                if last
                    .as_ref()
                    .and_then(|v| v["validated_at"].as_i64())
                    .is_some_and(|t| {
                        devres_domain::unix_now().saturating_sub(t)
                            < self.config.advisory_refresh_secs as i64
                    })
                {
                    return Ok(());
                }
                let artifact = self
                    .fetch(
                        Operation::AdvisoryExport,
                        crate::bulk::MAX_ARTIFACT_BYTES,
                        cancel.clone(),
                    )
                    .await?;
                let time = devres_domain::unix_now();
                if let Some(previous) = last
                    && previous["artifact"]["body_hash"] == artifact.body_hash
                    && previous["processor_version"] == PROCESSOR_VERSION
                {
                    let mut data = previous;
                    data.as_object_mut().ok_or_else(failure)?.remove("id");
                    data["validated_at"] = json!(time);
                    data["id"] = json!(identity(&data)?);
                    let id = data["id"].as_str().ok_or_else(failure)?;
                    self.store
                        .npm_set_state(
                            &format!("ready:{id}"),
                            &json!({"id":id,"records":data["records"],"accounted":true}),
                        )
                        .await?;
                    self.store.npm_publish("advisories", &data).await?;
                    self.accept_fetch(Operation::AdvisoryExport, &artifact)
                        .await?;
                    return Ok(());
                }
                let snapshot = identity(&json!([artifact.body_hash, time, PROCESSOR_VERSION]))?;
                let job = json!({"snapshot":snapshot,"artifact":artifact,"validated_at":time,"next":0,"records":0,"gaps":0,"done":false});
                self.store.npm_set_state("advisory-job", &job).await?;
                job
            }
        };
        let artifact: BulkArtifact =
            serde_json::from_value(job["artifact"].clone()).map_err(|_| failure())?;
        let file = self
            .raw
            .open(
                &artifact.body_hash,
                crate::bulk::MAX_ARTIFACT_BYTES,
                cancel.clone(),
            )
            .await?
            .into_std()
            .await;
        let next = job["next"].as_u64().unwrap_or(0) as usize;
        let (sender, mut receiver) = tokio::sync::mpsc::channel(2);
        let stop = cancel.clone();
        let expanded = job["expanded"].as_u64().unwrap_or(0);
        let worker =
            tokio::task::spawn_blocking(move || scan_export(file, next, expanded, sender, &stop));
        let snapshot = job["snapshot"].as_str().ok_or_else(failure)?.to_owned();
        while let Some((position, expanded, result)) = receiver.recv().await {
            job["expanded"] = json!(expanded);
            canceled(&cancel)?;
            match result {
                Ok(Some(item)) => {
                    let record = item.record;
                    if record["matching_complete"] != true || record["rights_gap"] == true {
                        let gap = json!({"snapshot":snapshot,"member":position,"code":"unsupported_advisory_coverage","artifact":artifact.body_hash});
                        self.store.npm_put("gaps", &identity(&gap)?, &gap).await?;
                        job["gaps"] = json!(job["gaps"].as_u64().unwrap_or(0) + 1);
                    }
                    let id = identity(&record)?;
                    self.store.npm_put("advisories", &id, &record).await?;
                    let raw_id = if record["rights_gap"] == true {
                        None
                    } else {
                        let raw = self.raw.capture_bytes(item.bytes, cancel.clone()).await?;
                        let data = json!({"record":id,"artifact":raw,"member_path":item.path,"export_hash":artifact.body_hash,"source_url":crate::npm::source::OSV_EXPORT});
                        let raw_id = identity(&data)?;
                        self.store.npm_put("advisory-raw", &raw_id, &data).await?;
                        Some(raw_id)
                    };
                    let member =
                        json!({"snapshot":snapshot,"id":record["id"],"record":id,"raw":raw_id});
                    self.store
                        .npm_put("advisory-members", &identity(&member)?, &member)
                        .await?;
                    let names: Vec<_> = record["packages"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|v| {
                            v.as_str().or_else(|| v.get("name").and_then(Value::as_str))
                        })
                        .collect();
                    for name in if names.is_empty() { vec!["*"] } else { names } {
                        let link =
                            json!({"snapshot":snapshot,"name":name,"record":id,"id":record["id"]});
                        self.store
                            .npm_put("advisory-packages", &identity(&link)?, &link)
                            .await?;
                    }
                    job["records"] = json!(job["records"].as_u64().unwrap_or(0) + 1);
                }
                Ok(None) => {}
                Err(error) => {
                    let gap = json!({"snapshot":snapshot,"member":position,"code":error.code,"artifact":artifact.body_hash});
                    self.store.npm_put("gaps", &identity(&gap)?, &gap).await?;
                    job["gaps"] = json!(job["gaps"].as_u64().unwrap_or(0) + 1);
                }
            }
            job["next"] = json!(position + 1);
            self.store.npm_set_state("advisory-job", &job).await?;
        }
        if !worker.await.map_err(|_| failure())?? {
            return Ok(());
        }
        let mut data = json!({"lane":"advisories","artifact":artifact,"validated_at":job["validated_at"],"records":job["records"],
            "gaps":job["gaps"],"accounted":true,"complete":job["gaps"]==0,"source":"osv_npm_export","processor_version":PROCESSOR_VERSION});
        // Snapshot membership is staged under its acquisition identity; public ID binds the manifest.
        data["membership"] = json!(snapshot);
        data["id"] = json!(identity(&data)?);
        let id = data["id"].as_str().ok_or_else(failure)?;
        self.store
            .npm_set_state(
                &format!("ready:{id}"),
                &json!({"id":id,"records":data["records"],"accounted":true}),
            )
            .await?;
        self.store.npm_publish("advisories", &data).await?;
        self.accept_fetch(Operation::AdvisoryExport, &artifact)
            .await?;
        job["done"] = json!(true);
        self.store.npm_set_state("advisory-job", &job).await?;
        Ok(())
    }
    pub async fn selection(&self, lane: &str, selected: Option<&str>) -> Result<Value> {
        let mut snapshot = if let Some(id) = selected {
            self.store
                .npm_get("snapshots", id)
                .await?
                .ok_or_else(|| Error::not_found("npm snapshot not found."))?
                .data
        } else {
            self.store
                .npm_state(&format!("default-{lane}"))
                .await?
                .ok_or_else(|| Error::unavailable("No npm snapshot has been published."))?
        };
        if snapshot["lane"] != lane {
            return Err(Error::invalid(
                "npm snapshot belongs to another evidence family.",
            ));
        }
        let validated_at = snapshot["validated_at"]
            .as_i64()
            .filter(|v| *v > 0 && *v <= devres_domain::unix_now())
            .ok_or_else(|| Error::integrity("npm snapshot validation time is invalid."))?;
        let age = devres_domain::unix_now().saturating_sub(validated_at);
        if selected.is_none() && age > 7 * 86400 {
            return Err(Error::unavailable(
                "npm default snapshot exceeds seven days.",
            ));
        }
        let current = self.store.npm_state(&format!("default-{lane}")).await?;
        let historical = current
            .as_ref()
            .is_none_or(|current| current["id"] != snapshot["id"]);
        snapshot["stale"] = json!(age > 86400);
        snapshot["historical"] = json!(historical);
        Ok(snapshot)
    }
    pub async fn advisory_selection(&self, selected: Option<&str>) -> Result<Value> {
        self.selection("advisories", selected).await
    }
    pub async fn advisory_snapshot_for_names(
        &self,
        selected: Option<&str>,
        names: &[String],
    ) -> Result<Value> {
        if names.len() > 10_000 {
            return Err(Error::capacity("npm assessment exceeds package bound."));
        }
        let start = Instant::now();
        let snapshot = self.advisory_selection(selected).await?;
        let mut names: BTreeSet<&str> = names.iter().map(String::as_str).collect();
        names.insert("*");
        let mut seen = BTreeSet::new();
        let mut records = Vec::new();
        let mut bytes = 0;
        for name in names {
            if start.elapsed() > Duration::from_secs(15) {
                return Err(Error::capacity("npm advisory selection deadline exceeded."));
            }
            let filter = json!({"snapshot":snapshot["membership"],"name":name});
            let mut after = 0;
            loop {
                if start.elapsed() > Duration::from_secs(15) {
                    return Err(Error::capacity("npm advisory selection deadline exceeded."));
                }
                let rows = self
                    .store
                    .npm_rows("advisory-packages", after, 100, None, Some(&filter))
                    .await?;
                if rows.is_empty() {
                    break;
                }
                for row in rows {
                    after = row.sequence;
                    let id = row.data["record"].as_str().ok_or_else(failure)?;
                    if seen.insert(id.to_owned()) {
                        let record = self
                            .store
                            .npm_get("advisories", id)
                            .await?
                            .ok_or_else(failure)?
                            .data;
                        bytes += serde_json::to_vec(&record).map_err(|_| failure())?.len();
                        if bytes > MAX_RELEVANT {
                            return Err(Error::capacity(
                                "Relevant npm advisory evidence exceeds worker budget.",
                            ));
                        }
                        records.push(record);
                    }
                }
            }
        }
        Ok(
            json!({"complete":snapshot["complete"],"snapshot":snapshot_summary(&snapshot),"records":records}),
        )
    }
    /// Private harness import of explicitly synthetic public evidence. Never registered as a tool.
    /// Every exact release must have an archive supplied; this path cannot initiate network I/O.
    pub async fn import_fixture_package(
        &self,
        packument: Value,
        archives: BTreeMap<String, Vec<u8>>,
        validated_at: i64,
        cancel: CancellationToken,
    ) -> Result<Value> {
        let _guard = self.processing.lock().await;
        if validated_at <= 0 {
            return Err(Error::invalid("Invalid fixture validation time."));
        }
        let bytes = serde_json::to_vec(&packument).map_err(|_| failure())?;
        if bytes.len() > MAX_METADATA as usize {
            return Err(Error::capacity("npm fixture metadata exceeds bound."));
        }
        let name = packument["name"]
            .as_str()
            .ok_or_else(|| Error::invalid("Fixture package name missing."))?
            .to_owned();
        if !self.config.packages.contains(&name) {
            return Err(Error::invalid(
                "Fixture package must be explicitly cataloged.",
            ));
        }
        let packument = npm_processing::parse_packument(&bytes, &name)?;
        let versions = packument["versions"].as_object().ok_or_else(failure)?;
        if versions.len() != archives.len() || versions.keys().any(|v| !archives.contains_key(v)) {
            return Err(Error::invalid(
                "Every fixture version requires a supplied archive.",
            ));
        }
        let metadata = self.raw.capture_bytes(bytes, cancel.clone()).await?;
        let snapshot = identity(&json!([
            "synthetic-npm-package",
            name,
            metadata.body_hash,
            validated_at,
            PROCESSOR_VERSION
        ]))?;
        self.store.npm_put("metadata-captures",&snapshot,&json!({"id":snapshot,"name":name,"artifact":metadata,"validated_at":validated_at,"synthetic":true})).await?;
        for (version, bytes) in archives {
            let manifest = &versions[&version];
            let assurance = npm_processing::verify_integrity(&bytes, manifest)?;
            let artifact = self
                .raw
                .capture_bytes_bounded(bytes, MAX_INSPECTION, cancel.clone())
                .await?;
            let key = identity(&json!([name, version, manifest["dist"], PROCESSOR_VERSION]))?;
            self.store
                .npm_put(
                    "artifacts",
                    &key,
                    &json!({"name":name,"version":version,"artifact":artifact,"assurance":assurance}),
                )
                .await?;
        }
        let mut documents = 0;
        let mut gaps = 0;
        for (version, manifest) in versions {
            let (count, version_gaps) = self
                .process_version(
                    &snapshot,
                    &name,
                    version,
                    manifest,
                    &metadata,
                    cancel.clone(),
                )
                .await?;
            documents += count;
            gaps += version_gaps;
        }
        self.index_pending(&snapshot, cancel).await?;
        gaps += self.capture_index_members(&snapshot).await?;
        let previous = self
            .store
            .npm_state(&state_key("package-head", &name))
            .await?;
        let package = json!({"id":snapshot,"name":name,"metadata":metadata,"validated_at":validated_at,
            "versions":versions.len(),"documents":documents,"gaps":gaps,"accounted":true,"synthetic":true,
            "previous":previous.as_ref().map(|v|v["id"].clone()),"processor_version":PROCESSOR_VERSION,
            "dist_tags":packument["dist-tags"],"index":self.store.npm_state("index").await?.unwrap_or(Value::Null)});
        self.store
            .npm_put("package-snapshots", &snapshot, &package)
            .await?;
        self.store
            .npm_set_state(&state_key("package-head", &name), &package)
            .await?;
        self.store
            .npm_set_state("last-research-publication", &json!(0))
            .await?;
        self.publish_research().await?;
        self.selection("research", None).await
    }
    /// Bounded synthetic public OSV import for isolated persistence and transport acceptance.
    pub async fn import_fixture_advisories(
        &self,
        records: Vec<Value>,
        validated_at: i64,
    ) -> Result<Value> {
        let _guard = self.processing.lock().await;
        if records.len() > 100 || validated_at <= 0 {
            return Err(Error::invalid("Invalid bounded npm advisory fixture."));
        }
        let membership = identity(&json!([
            "synthetic-npm-advisories",
            records,
            validated_at,
            PROCESSOR_VERSION
        ]))?;
        let mut count = 0;
        for original in records {
            let bytes = serde_json::to_vec(&original).map_err(|_| failure())?;
            if bytes.len() > 1024 * 1024 {
                return Err(Error::capacity(
                    "npm advisory fixture record exceeds bound.",
                ));
            }
            let artifact = self
                .raw
                .capture_bytes(bytes.clone(), CancellationToken::new())
                .await?;
            let record = crate::npm::audit::parse_advisory(&bytes)?;
            let id = identity(&record)?;
            self.store.npm_put("advisories", &id, &record).await?;
            let raw_data = json!({"record":id,"artifact":artifact,"synthetic":true,"member_path":format!("{}.json",record["id"].as_str().unwrap_or("fixture")),"source_url":"https://fixtures.invalid/npm/advisories"});
            let raw_id = identity(&raw_data)?;
            self.store
                .npm_put("advisory-raw", &raw_id, &raw_data)
                .await?;
            let member = json!({"snapshot":membership,"id":record["id"],"record":id,"raw":raw_id});
            self.store
                .npm_put("advisory-members", &identity(&member)?, &member)
                .await?;
            for name in record["packages"].as_array().into_iter().flatten() {
                let name = name
                    .as_str()
                    .or_else(|| name.get("name").and_then(Value::as_str))
                    .unwrap_or("*");
                let link = json!({"snapshot":membership,"name":name,"record":id,"id":record["id"]});
                self.store
                    .npm_put("advisory-packages", &identity(&link)?, &link)
                    .await?;
            }
            count += 1;
        }
        let mut data = json!({"lane":"advisories","membership":membership,"validated_at":validated_at,"records":count,
            "gaps":0,"accounted":true,"complete":true,"synthetic":true,"source":"synthetic_fixture","processor_version":PROCESSOR_VERSION});
        data["id"] = json!(identity(&data)?);
        let id = data["id"].as_str().ok_or_else(failure)?;
        self.store
            .npm_set_state(
                &format!("ready:{id}"),
                &json!({"id":id,"records":count,"accounted":true}),
            )
            .await?;
        self.store.npm_publish("advisories", &data).await?;
        self.advisory_selection(None).await
    }
    pub async fn rebuild_index(&self, cancel: CancellationToken) -> Result<Value> {
        let _guard = self.processing.lock().await;
        let cutoff = self.store.npm_cutoff().await?;
        let build = identity(&json!(["npm-index-rebuild", cutoff, PROCESSOR_VERSION]))?;
        let mut after = 0;
        let mut index = None;
        let mut count = 0;
        let mut documents = Vec::new();
        let mut bytes = 0;
        loop {
            canceled(&cancel)?;
            let rows = self
                .store
                .npm_rows("documents", after, 1, Some(cutoff), None)
                .await?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                after = row.sequence;
                let data = row.data;
                let doc = IndexDocument {
                    id: row.key,
                    name: data["name"].as_str().unwrap_or_default().into(),
                    version: data["version"].as_str().unwrap_or_default().into(),
                    path: data["path"].as_str().unwrap_or_default().into(),
                    title: data["path"].as_str().unwrap_or_default().into(),
                    text: data["text"].as_str().unwrap_or_default().into(),
                    kind: data["kind"].as_str().unwrap_or("source").into(),
                    metadata: json!({}),
                };
                NpmIndex::validate_document(&doc, &cancel)?;
                if !documents.is_empty()
                    && (bytes + doc.text.len() > 16 * 1024 * 1024 || documents.len() >= 512)
                {
                    index = Some(
                        self.index
                            .publish_generation(
                                index.as_ref(),
                                std::mem::take(&mut documents),
                                cancel.clone(),
                                "rebuild",
                            )
                            .await?,
                    );
                    bytes = 0;
                }
                let member = json!({"build":build,"record":doc.id});
                self.store
                    .npm_put("rebuild-index-members", &identity(&member)?, &member)
                    .await?;
                bytes += doc.text.len();
                documents.push(doc);
                count += 1;
                if count > 1_000_000 {
                    return Err(Error::capacity(
                        "npm rebuilt index exceeds one million documents.",
                    ));
                }
            }
        }
        if !documents.is_empty() {
            index = Some(
                self.index
                    .publish_generation(index.as_ref(), documents, cancel, "rebuild")
                    .await?,
            );
        }
        if let Some(index) = index {
            self.store.npm_commit_rebuilt_index(&index, &build).await?;
            if let Some(mut view) = self.store.npm_state("default-research").await? {
                let previous = view["id"].clone();
                view.as_object_mut().ok_or_else(failure)?.remove("id");
                view["index"] = index;
                view["reprocessed_from"] = previous;
                view["id"] = json!(identity(&view)?);
                self.store.npm_publish("research", &view).await?;
            }
        }
        Ok(json!({"documents":count,"source_validation_refreshed":false}))
    }
}

/// ZIP metadata and one member are bounded before parsing; a two-record channel applies backpressure.
fn scan_export(
    file: std::fs::File,
    next: usize,
    mut expanded: u64,
    sender: tokio::sync::mpsc::Sender<(usize, u64, Result<Option<ScannedAdvisory>>)>,
    cancel: &CancellationToken,
) -> Result<bool> {
    use std::io::Read as _;
    let mut archive = npm_processing::open_advisory_zip(file)?;
    if archive.len() > 1_000_000 {
        return Err(Error::capacity("npm advisory ZIP member bound exceeded."));
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    for position in next..archive.len() {
        canceled(cancel)?;
        if position > next && (position - next >= 1000 || std::time::Instant::now() > deadline) {
            return Ok(false);
        }
        let mut member = archive
            .by_index(position)
            .map_err(|_| Error::integrity("Invalid npm advisory ZIP member."))?;
        if member.is_dir() {
            sender
                .blocking_send((position, expanded, Ok(None)))
                .map_err(|_| Error::new("cancelled", "npm advisory receiver closed."))?;
            continue;
        }
        expanded = expanded.saturating_add(member.size());
        if expanded > 64 * 1024 * 1024 * 1024 {
            return Err(Error::capacity(
                "npm advisory expanded byte bound exceeded.",
            ));
        }
        let name = member
            .name()
            .map_err(|_| Error::integrity("Invalid npm advisory ZIP member name."))?
            .into_owned();
        let safe = name.len() <= 4096
            && !name.chars().any(char::is_control)
            && !name.starts_with('/')
            && !name.contains('\\')
            && name.split('/').all(|p| !matches!(p, "" | "." | ".."))
            && name.ends_with(".json")
            && member
                .unix_mode()
                .is_none_or(|m| m & 0o170000 == 0 || m & 0o170000 == 0o100000);
        let result = if !safe || member.size() > 1024 * 1024 || member.encrypted() {
            Err(Error::capacity(
                "Unsupported or oversized npm advisory ZIP member.",
            ))
        } else {
            let mut bytes = Vec::new();
            member
                .by_ref()
                .take(1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| failure())?;
            if bytes.len() > 1024 * 1024 {
                Err(Error::capacity("npm advisory record exceeds 1 MiB."))
            } else {
                crate::npm::audit::parse_advisory(&bytes).map(|record| {
                    Some(ScannedAdvisory {
                        record,
                        bytes,
                        path: name,
                    })
                })
            }
        };
        if sender.blocking_send((position, expanded, result)).is_err() {
            return Err(Error::new("cancelled", "npm advisory receiver closed."));
        }
    }
    Ok(true)
}

pub(crate) fn snapshot_summary(value: &Value) -> Value {
    let mut output = serde_json::Map::new();
    for key in [
        "id",
        "lane",
        "validated_at",
        "complete",
        "stale",
        "historical",
        "synthetic",
        "processor_version",
        "records",
        "gaps",
        "accounted",
    ] {
        if let Some(value) = value.get(key) {
            output.insert(key.into(), value.clone());
        }
    }
    if let Some(hash) = value.pointer("/artifact/body_hash") {
        output.insert("artifact_capture".into(), hash.clone());
    }
    if let Some(source) = value.get("source") {
        output.insert("source".into(), source.clone());
    }
    if let Some(packages) = value["packages"].as_object() {
        output.insert("package_count".into(), json!(packages.len()));
    }
    Value::Object(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use devres_application::npm::Row;
    use std::{
        io::Write,
        sync::atomic::{AtomicUsize, Ordering},
    };

    type State = (
        i64,
        BTreeMap<(String, String), Row>,
        BTreeMap<String, Value>,
    );
    #[derive(Default)]
    struct Memory(Mutex<State>);
    #[async_trait]
    impl NpmStore for Memory {
        async fn npm_get(&self, kind: &str, key: &str) -> Result<Option<Row>> {
            Ok(self
                .0
                .lock()
                .await
                .1
                .get(&(kind.into(), key.into()))
                .cloned())
        }
        async fn npm_put(&self, kind: &str, key: &str, value: &Value) -> Result<i64> {
            let mut state = self.0.lock().await;
            let key = (kind.into(), key.into());
            if let Some(old) = state.1.get(&key) {
                return if old.data == *value {
                    Ok(old.sequence)
                } else {
                    Err(Error::integrity("Fixture collision."))
                };
            }
            state.0 += 1;
            let sequence = state.0;
            state.1.insert(
                key.clone(),
                Row {
                    sequence,
                    key: key.1,
                    data: value.clone(),
                },
            );
            Ok(sequence)
        }
        async fn npm_cutoff(&self) -> Result<i64> {
            Ok(self.0.lock().await.0)
        }
        async fn npm_rows(
            &self,
            kind: &str,
            after: i64,
            limit: usize,
            cutoff: Option<i64>,
            filter: Option<&Value>,
        ) -> Result<Vec<Row>> {
            let state = self.0.lock().await;
            let mut rows: Vec<_> = state
                .1
                .iter()
                .filter(|((k, _), v)| {
                    k == kind
                        && v.sequence > after
                        && cutoff.is_none_or(|c| v.sequence <= c)
                        && filter.is_none_or(|f| {
                            f.as_object()
                                .is_some_and(|f| f.iter().all(|(k, x)| v.data.get(k) == Some(x)))
                        })
                })
                .map(|(_, v)| v.clone())
                .collect();
            rows.sort_by_key(|r| r.sequence);
            rows.truncate(limit);
            Ok(rows)
        }
        async fn npm_state(&self, key: &str) -> Result<Option<Value>> {
            Ok(self.0.lock().await.2.get(key).cloned())
        }
        async fn npm_set_state(&self, key: &str, value: &Value) -> Result<()> {
            self.0.lock().await.2.insert(key.into(), value.clone());
            Ok(())
        }
        async fn npm_commit_index(&self, index: &Value, ids: &[String]) -> Result<()> {
            let mut state = self.0.lock().await;
            for id in ids {
                let key = ("indexed".into(), id.clone());
                if let Some(old) = state.1.get(&key)
                    && old.data != json!({"id":id})
                {
                    return Err(Error::integrity("Fixture marker collision."));
                }
            }
            let (sequence, rows, heads) = &mut *state;
            for id in ids {
                if let std::collections::btree_map::Entry::Vacant(entry) =
                    rows.entry(("indexed".into(), id.clone()))
                {
                    *sequence += 1;
                    entry.insert(Row {
                        sequence: *sequence,
                        key: id.clone(),
                        data: json!({"id":id}),
                    });
                }
            }
            heads.insert("index".into(), index.clone());
            Ok(())
        }
        async fn npm_commit_rebuilt_index(&self, index: &Value, build: &str) -> Result<()> {
            let rows = self
                .npm_rows(
                    "rebuild-index-members",
                    0,
                    1000,
                    None,
                    Some(&json!({"build":build})),
                )
                .await?;
            let ids = rows
                .iter()
                .map(|r| r.data["record"].as_str().unwrap().to_string())
                .collect::<Vec<_>>();
            self.npm_commit_index(index, &ids).await
        }
        async fn npm_publish(&self, lane: &str, value: &Value) -> Result<()> {
            self.npm_put("snapshots", value["id"].as_str().unwrap(), value)
                .await?;
            self.npm_set_state(&format!("default-{lane}"), value).await
        }
        async fn npm_statistics(&self) -> Result<Value> {
            Ok(json!({}))
        }
    }
    fn corpus(store: Arc<Memory>, broker: Arc<BulkBroker>, root: &Path) -> NpmCorpus {
        NpmCorpus::new(
            store,
            broker,
            root,
            NpmConfig {
                enabled: false,
                packages: vec!["fixture".into()],
                ..NpmConfig::default()
            },
        )
        .unwrap()
    }
    fn package() -> (Value, Vec<u8>) {
        use base64::Engine as _;
        let mut tar = tar::Builder::new(Vec::new());
        let body = br#"{"name":"fixture","version":"1.0.0","license":"MIT"}"#;
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_size(body.len() as u64);
        header.set_cksum();
        tar.append_data(&mut header, "package/package.json", body.as_slice())
            .unwrap();
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(&tar.into_inner().unwrap()).unwrap();
        let archive = gzip.finish().unwrap();
        let manifest = json!({"name":"fixture","version":"1.0.0","dist":{"tarball":"https://registry.npmjs.org/fixture/-/fixture-1.0.0.tgz",
            "integrity":format!("sha512-{}",base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(&archive)))}});
        (manifest, archive)
    }
    #[tokio::test]
    async fn bad_archive_is_retained_but_corrected_distribution_can_recover() {
        let (manifest, archive) = package();
        let attempts = Arc::new(AtomicUsize::new(0));
        let seen = attempts.clone();
        let router = axum::Router::new().route(
            "/fixture/-/fixture-1.0.0.tgz",
            axum::routing::get(move || {
                let seen = seen.clone();
                let archive = archive.clone();
                async move {
                    if seen.fetch_add(1, Ordering::SeqCst) == 0 {
                        b"bad original body".to_vec()
                    } else {
                        archive
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let broker = Arc::new(
            BulkBroker::fixture(url::Url::parse(&format!("http://{address}")).unwrap()).unwrap(),
        );
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let store = Arc::new(Memory::default());
        let corpus = corpus(store.clone(), broker, root.path());
        let metadata = corpus
            .raw
            .capture_bytes(
                b"Synthetic metadata observation".to_vec(),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert!(
            corpus
                .process_version(
                    "first",
                    "fixture",
                    "1.0.0",
                    &manifest,
                    &metadata,
                    CancellationToken::new()
                )
                .await
                .is_err()
        );
        let key = identity(&json!([
            "fixture",
            "1.0.0",
            manifest["dist"],
            PROCESSOR_VERSION
        ]))
        .unwrap();
        assert!(store.npm_get("artifacts", &key).await.unwrap().is_none());
        corpus
            .raw
            .verify(
                &digest(b"bad original body"),
                1024,
                CancellationToken::new(),
            )
            .await
            .unwrap();
        corpus
            .process_version(
                "second",
                "fixture",
                "1.0.0",
                &manifest,
                &metadata,
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .npm_get("artifacts", &key)
                .await
                .unwrap()
                .unwrap()
                .data["assurance"]["verified"],
            true
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert_eq!(
            store
                .npm_rows("archive-observations", 0, 10, None, None)
                .await
                .unwrap()
                .len(),
            2
        );
        server.abort();
    }
    #[tokio::test]
    async fn terminal_metadata_failure_reacquires_while_transient_failures_keep_checkpoint() {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let store = Arc::new(Memory::default());
        let broker = Arc::new(BulkBroker::new(crate::bulk::BulkConfig::default()).unwrap());
        let corpus = corpus(store.clone(), broker, root.path());
        let key = state_key("package-job", "fixture");
        let raw = digest(b"retained malformed metadata");
        let job = json!({"metadata":raw,"done":false,"next":3});
        store.npm_set_state(&key, &job).await.unwrap();
        corpus
            .record_failure(
                "package",
                Some("fixture"),
                &Error::integrity("Malformed metadata."),
            )
            .await
            .unwrap();
        let failed = store.npm_state(&key).await.unwrap().unwrap();
        assert_eq!(failed["done"], true);
        assert_eq!(failed["metadata"], raw);
        assert!(
            store
                .npm_state(&state_key("package-retry", "fixture"))
                .await
                .unwrap()
                .unwrap()
                .as_i64()
                .unwrap()
                > devres_domain::unix_now()
        );
        store.npm_set_state(&key, &job).await.unwrap();
        corpus
            .record_failure(
                "package",
                Some("fixture"),
                &Error::unavailable("Temporary source failure."),
            )
            .await
            .unwrap();
        assert_eq!(store.npm_state(&key).await.unwrap().unwrap(), job);
    }
    #[tokio::test]
    async fn completed_package_snapshot_resumes_both_checkpoint_cuts_without_rewriting_evidence() {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let store = Arc::new(Memory::default());
        let broker =
            Arc::new(BulkBroker::fixture(url::Url::parse("http://127.0.0.1:9").unwrap()).unwrap());
        let corpus = corpus(store.clone(), broker.clone(), root.path());
        let id = digest(b"published acquisition");
        let published = json!({"id":id,"name":"fixture","previous":digest(b"previous acquisition"),"accounted":true,
            "metadata":{"body_hash":digest(b"original source")},"index":{"retained":"original-index"},"validated_at":devres_domain::unix_now()});
        store
            .npm_put("package-snapshots", &id, &published)
            .await
            .unwrap();
        let key = state_key("package-job", "fixture");
        for head_already_written in [false, true] {
            let job = json!({"snapshot":id,"name":"fixture","metadata":"must not be reparsed after publication","done":false,"next":4});
            store.npm_set_state(&key, &job).await.unwrap();
            let previous_head = json!({"id":"previous"});
            store
                .npm_set_state(
                    &state_key("package-head", "fixture"),
                    if head_already_written {
                        &published
                    } else {
                        &previous_head
                    },
                )
                .await
                .unwrap();
            store
                .npm_set_state("index", &json!({"unrelated":"later-global-index"}))
                .await
                .unwrap();
            corpus
                .collect_package("fixture", CancellationToken::new())
                .await
                .unwrap();
            assert_eq!(
                store
                    .npm_get("package-snapshots", &id)
                    .await
                    .unwrap()
                    .unwrap()
                    .data,
                published
            );
            assert_eq!(
                store
                    .npm_state(&state_key("package-head", "fixture"))
                    .await
                    .unwrap()
                    .unwrap(),
                published
            );
            assert_eq!(store.npm_state(&key).await.unwrap().unwrap()["done"], true);
            assert_eq!(
                store.npm_state("index").await.unwrap().unwrap(),
                json!({"unrelated":"later-global-index"})
            );
        }
        assert_eq!(broker.attempt_count(), 0);
    }
    #[tokio::test]
    async fn zip_directory_slices_advance_and_preserve_exact_source_bytes() {
        let raw=br#"{ "id":"GHSA-2345-6789-cfgh", "modified":"2026-10-27T00:00:00Z", "affected":[{"package":{"ecosystem":"npm","name":"fixture"},"versions":["1.0.0"]}] }"#;
        let file = tempfile::NamedTempFile::new_in("/tmp").unwrap();
        let mut writer = zip::ZipWriter::new(file.reopen().unwrap());
        for n in 0..1001 {
            writer
                .add_directory(format!("dir{n}/"), zip::write::SimpleFileOptions::default())
                .unwrap();
        }
        writer
            .start_file(
                "GHSA-2345-6789-cfgh.json",
                zip::write::SimpleFileOptions::default(),
            )
            .unwrap();
        writer.write_all(raw).unwrap();
        writer.finish().unwrap();
        let (sender, mut receiver) = tokio::sync::mpsc::channel(2);
        let source = file.reopen().unwrap();
        let task = tokio::task::spawn_blocking(move || {
            scan_export(source, 0, 0, sender, &CancellationToken::new())
        });
        let mut next = 0;
        let mut records = 0;
        while let Some((position, _, record)) = receiver.recv().await {
            next = position + 1;
            if record.unwrap().is_some() {
                records += 1;
            }
        }
        assert!(!task.await.unwrap().unwrap());
        assert_eq!(next, 1000);
        assert_eq!(records, 0);
        let (sender, mut receiver) = tokio::sync::mpsc::channel(2);
        let source = file.reopen().unwrap();
        let task = tokio::task::spawn_blocking(move || {
            scan_export(source, next, 0, sender, &CancellationToken::new())
        });
        while let Some((_, expanded, record)) = receiver.recv().await {
            if let Some(record) = record.unwrap() {
                assert_eq!(record.bytes, raw);
                assert_eq!(expanded, raw.len() as u64);
                records += 1;
            }
        }
        assert!(task.await.unwrap().unwrap());
        assert_eq!(records, 1);
    }
}
