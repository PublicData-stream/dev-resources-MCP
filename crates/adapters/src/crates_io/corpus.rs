//! Supervised registry collection. Inventories, acquisition and projections commit independently.
#[cfg(test)]
#[path = "corpus/tests.rs"]
mod pipeline_tests;
use crate::{
    archive,
    bulk::{
        BulkArtifact, BulkArtifactStore, BulkBroker, BulkConfig, BulkRequest, BulkSource,
        DocsOperation, MAX_ARTIFACT_BYTES,
    },
    crates_io::docs::{self as crate_docs, ProcessingBudget},
    crates_io::git::{GitRegistry, GitSnapshot},
    crates_io::packages as cargo,
};
use devres_application::{
    Retrieval,
    crate_corpus::{
        Artifact, CollectionJob, ContentRecord, CrateCorpusStore, Snapshot, VersionRecord,
    },
};
use devres_domain::{Capture, Error, Result, Validators, unix_now};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicI64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Mutex, Semaphore, mpsc};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CrateConfig {
    pub enabled: bool,
    pub index_refresh_secs: u64,
    pub metadata_refresh_secs: u64,
    pub documentation_refresh_secs: u64,
    pub collection_interval_secs: u64,
    pub publication_interval_secs: u64,
    pub static_requests_per_second: u32,
    pub index_requests_per_second: u32,
    pub max_bulk_transfers: usize,
    pub max_processing_workers: usize,
    pub max_artifact_bytes: u64,
    pub min_free_bytes: u64,
    pub max_archive_storage_bytes: Option<u64>,
    pub max_git_bytes: u64,
}
impl Default for CrateConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            index_refresh_secs: 3600,
            metadata_refresh_secs: 86400,
            documentation_refresh_secs: 86400,
            collection_interval_secs: 1,
            publication_interval_secs: 300,
            static_requests_per_second: 5,
            index_requests_per_second: 1,
            max_bulk_transfers: 4,
            max_processing_workers: 1,
            max_artifact_bytes: MAX_ARTIFACT_BYTES,
            min_free_bytes: 1024 * 1024 * 1024,
            max_archive_storage_bytes: None,
            max_git_bytes: 64 * 1024 * 1024 * 1024,
        }
    }
}
impl CrateConfig {
    pub fn validate(&self) -> Result<()> {
        if [
            self.index_refresh_secs,
            self.metadata_refresh_secs,
            self.documentation_refresh_secs,
            self.collection_interval_secs,
            self.publication_interval_secs,
        ]
        .iter()
        .any(|v| !(1..=31622400).contains(v))
            || !(1..=1000).contains(&self.static_requests_per_second)
            || !(1..=1000).contains(&self.index_requests_per_second)
            || !(1..=32).contains(&self.max_bulk_transfers)
            || !(1..=2).contains(&self.max_processing_workers)
            || !(1024 * 1024..=MAX_ARTIFACT_BYTES).contains(&self.max_artifact_bytes)
            || self.min_free_bytes < 64 * 1024 * 1024
            || self
                .max_archive_storage_bytes
                .is_some_and(|v| v < self.min_free_bytes)
            || !(1024 * 1024..=128 * 1024 * 1024 * 1024_u64).contains(&self.max_git_bytes)
        {
            return Err(Error::invalid("Invalid crate corpus configuration."));
        }
        Ok(())
    }
    pub fn bulk_config(&self) -> BulkConfig {
        BulkConfig {
            static_requests_per_second: self.static_requests_per_second,
            index_requests_per_second: self.index_requests_per_second,
            other_requests_per_second: 1,
            max_transfers: self.max_bulk_transfers,
            min_free_bytes: self.min_free_bytes,
        }
    }
}

pub struct CrateCorpus {
    store: Arc<dyn CrateCorpusStore>,
    retrieval: Arc<Retrieval>,
    broker: Arc<BulkBroker>,
    artifacts: Arc<BulkArtifactStore>,
    git: Arc<GitRegistry>,
    root: PathBuf,
    config: CrateConfig,
    state: Mutex<Value>,
    publication: Mutex<()>,
    last_publication: AtomicI64,
    parsers: Arc<Semaphore>,
    cursor: AtomicUsize,
}
impl CrateCorpus {
    pub fn new(
        store: Arc<dyn CrateCorpusStore>,
        retrieval: Arc<Retrieval>,
        broker: Arc<BulkBroker>,
        root: impl AsRef<Path>,
        config: CrateConfig,
    ) -> Result<Self> {
        config.validate()?;
        let root = root.as_ref().to_path_buf();
        let artifacts = Arc::new(
            BulkArtifactStore::new(&root, config.min_free_bytes)?
                .with_quota(config.max_archive_storage_bytes)?,
        );
        let git = Arc::new(GitRegistry::new(
            root.join("crate-git"),
            config.max_git_bytes,
        )?);
        let processing_workers = config.max_processing_workers;
        Ok(Self {
            store,
            retrieval,
            broker,
            artifacts,
            git,
            root,
            config,
            state: Mutex::new(json!({})),
            publication: Mutex::new(()),
            last_publication: AtomicI64::new(0),
            parsers: Arc::new(Semaphore::new(processing_workers)),
            cursor: AtomicUsize::new(0),
        })
    }
    pub fn research(&self) -> crate::crates_io::research::CrateResearch {
        crate::crates_io::research::CrateResearch::new(
            self.store.clone(),
            self.retrieval.clone(),
            self.root.clone(),
        )
    }
    pub fn artifact_budget(&self) -> Arc<BulkArtifactStore> {
        self.artifacts.clone()
    }
    pub async fn status(&self) -> Result<Value> {
        let mut status = self.store.status().await?;
        status["collection_enabled"] = json!(self.config.enabled);
        status["collector"] = self.state.lock().await.clone();
        Ok(status)
    }
    pub async fn recover_stages(&self) -> Result<()> {
        self.artifacts.recover_stages().await?;
        let mut entries = tokio::fs::read_dir(&self.root)
            .await
            .map_err(|_| Error::unavailable("Corpus archive unavailable."))?;
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|_| Error::unavailable("Corpus archive unavailable."))?
        {
            if entry.file_name().to_str().is_some_and(|s| {
                s.strip_prefix(".crate-json-stage-").is_some_and(|rest| {
                    rest.split('-')
                        .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
                })
            }) && entry
                .file_type()
                .await
                .map_err(|_| Error::unavailable("Corpus staging unavailable."))?
                .is_file()
            {
                tokio::fs::remove_file(entry.path())
                    .await
                    .map_err(|_| Error::unavailable("Corpus staging unavailable."))?;
            }
        }
        Ok(())
    }
    pub async fn run(self: Arc<Self>, shutdown: CancellationToken) -> Result<()> {
        if let Some(snapshot) = self.store.snapshot(None).await?
            && !snapshot.index_manifest.is_null()
        {
            self.state.lock().await["index_warmup"] = json!({"state":"warming"});
            let reference = snapshot.index_manifest;
            let result = crate::crates_io::index::prewarm(
                self.root.clone(),
                reference.clone(),
                shutdown.child_token(),
            )
            .await;
            if result.is_ok() {
                crate::crates_io::index::activate(&self.root, &reference)?;
            }
            self.record_state("index_warmup", &result).await;
            if shutdown.is_cancelled() {
                return Ok(());
            }
        }
        if !self.config.enabled {
            shutdown.cancelled().await;
            return Ok(());
        }
        // Independent loops prevent long inventory transfers from starving archive/doc work.
        let mut workers = tokio::task::JoinSet::new();
        let this = self.clone();
        let stop = shutdown.child_token();
        workers.spawn(async move { this.inventory_loop(stop).await });
        let this = self.clone();
        let stop = shutdown.child_token();
        workers.spawn(async move { this.dump_loop(stop).await });
        for _ in 0..self.config.max_bulk_transfers {
            let this = self.clone();
            let stop = shutdown.child_token();
            workers.spawn(async move { this.jobs_loop(stop).await });
        }
        tokio::select! {biased;_=shutdown.cancelled()=>{},result=workers.join_next()=>{if let Some(result)=result{result.map_err(|_|Error::unavailable("Crate collector worker failed."))??;}return Err(Error::unavailable("Crate collector stopped unexpectedly."));}}
        // Cancellation is propagated to every owned network/parser/process operation.
        while let Some(result) = workers.join_next().await {
            result.map_err(|_| Error::unavailable("Crate collector shutdown failed."))??;
        }
        Ok(())
    }
    async fn inventory_loop(&self, stop: CancellationToken) -> Result<()> {
        loop {
            if stop.is_cancelled() {
                return Ok(());
            }
            let result = self.sync_inventory(stop.child_token()).await;
            self.record_state("inventory", &result).await;
            let wait = if result.is_ok() {
                self.config.index_refresh_secs
            } else {
                60
            };
            tokio::select! {_=stop.cancelled()=>return Ok(()),_=tokio::time::sleep(Duration::from_secs(wait))=>{}}
        }
    }
    async fn dump_loop(&self, stop: CancellationToken) -> Result<()> {
        loop {
            if stop.is_cancelled() {
                return Ok(());
            }
            let result = async {
                let captured = self
                    .fetch_artifact(
                        "cargo:database-dump",
                        BulkSource::DatabaseDump,
                        None,
                        self.config.metadata_refresh_secs,
                        stop.child_token(),
                    )
                    .await?;
                crate::crates_io::dump::import_dump(
                    self.root.join(crate::integrity::relative_path(
                        &captured.capture.body_hash,
                    )?),
                    captured.capture.id.clone(),
                    self.store.clone(),
                    stop.child_token(),
                )
                .await?;
                Ok(())
            }
            .await;
            self.record_state("metadata", &result).await;
            tokio::select! {_=stop.cancelled()=>return Ok(()),_=tokio::time::sleep(Duration::from_secs(if result.is_ok(){self.config.metadata_refresh_secs}else{60}))=>{}}
        }
    }
    async fn record_state(&self, kind: &str, result: &Result<()>) {
        self.state.lock().await[kind] = match result {
            Ok(()) => json!({"state":"ready","observed_at":unix_now()}),
            Err(e) => {
                json!({"state":if e.code=="capacity"{"paused"}else{"degraded"},"reason":e.code,"observed_at":unix_now()})
            }
        };
    }
    pub async fn sync_inventory(&self, stop: CancellationToken) -> Result<()> {
        let pending = self.store.pending_inventory().await?;
        let snapshot = if let Some(pending) = &pending {
            let saved = self
                .store
                .latest_artifact(&format!("cargo:git-manifest:{}", pending.revision))
                .await?
                .ok_or_else(|| Error::integrity("Pending registry evidence is absent."))?;
            let manifest = BulkArtifact {
                relative_path: crate::integrity::relative_path(&saved.capture.body_hash)?
                    .to_string_lossy()
                    .into_owned(),
                body_hash: saved.capture.body_hash,
                bytes: saved.bytes,
            };
            self.git
                .restore(self.artifacts.clone(), manifest, stop.child_token())
                .await?
        } else {
            self.git
                .sync(
                    self.broker.clone(),
                    self.artifacts.clone(),
                    stop.child_token(),
                )
                .await?
        };
        self.ingest_snapshot(snapshot, stop).await
    }
    async fn ingest_snapshot(&self, snapshot: GitSnapshot, stop: CancellationToken) -> Result<()> {
        let previous = self.store.latest_inventory().await?;
        let manifest = self
            .persist_artifact(
                &format!("cargo:git-manifest:{}", snapshot.revision),
                "https://github.com/rust-lang/crates.io-index.git",
                "application/json",
                snapshot.manifest.clone(),
                json!({"transport":"git","revision":snapshot.revision,"observed_at":snapshot.observed_at}),
                false,
            )
            .await?;
        let epoch = self
            .store
            .begin_inventory(&snapshot.revision, snapshot.observed_at)
            .await?;
        if previous.as_ref().is_some_and(|p| p.id == epoch.id) {
            self.publish(stop).await?;
            return Ok(());
        }
        let mut records = self
            .git
            .records(
                &snapshot,
                previous.as_ref().map(|p| p.revision.clone()),
                stop.child_token(),
            )
            .await?;
        while let Some(record) = records.recv().await {
            let record = record?;
            if epoch.cursor.as_ref().is_some_and(|c| record.path <= *c) {
                continue;
            }
            if stop.is_cancelled() {
                return Err(Error::unavailable("Inventory import canceled."));
            }
            let mut versions = Vec::new();
            if !record.removed {
                // Validate the entire blob before publishing its derived metadata capture.
                let validation = cargo::visit_index(&record.bytes, &record.name, |value| {
                    versions.push(value);
                    Ok(())
                });
                if let Err(error) = validation {
                    self.store
                        .stage_gap(&epoch.id, &record.name, safe_code(&error), &record.path)
                        .await?;
                    continue;
                }
                let capture = self
                    .store
                    .import_metadata(
                        &record.name,
                        &record.revision,
                        &record.path,
                        &record.blob_oid,
                        &record.bytes,
                        snapshot.observed_at,
                    )
                    .await?;
                let versions: Vec<_> = versions
                    .into_iter()
                    .map(|value| VersionRecord {
                        name: record.name.to_ascii_lowercase(),
                        version: value["vers"].as_str().unwrap_or_default().to_owned(),
                        metadata_capture: capture.id.clone(),
                        record: value,
                        metadata_status: None,
                    })
                    .collect();
                self.store
                    .stage_crate(&epoch.id, &record.name, &versions, &record.path)
                    .await?;
            } else {
                self.store
                    .stage_crate(&epoch.id, &record.name, &[], &record.path)
                    .await?;
            }
        }
        self.store
            .commit_inventory(&epoch.id, &manifest.capture.id)
            .await?;
        self.publish(stop).await?;
        Ok(())
    }
    pub async fn publish(&self, stop: CancellationToken) -> Result<Snapshot> {
        let _gate = self.publication.lock().await;
        let inv = self
            .store
            .latest_inventory()
            .await?
            .ok_or_else(|| Error::unavailable("No crate inventory is published."))?;
        let provisional = self.store.prepare_snapshot(&inv.id, unix_now()).await?;
        let reusable = self.store.snapshot(None).await?.filter(|s| {
            s.inventory.id == provisional.inventory.id
                && s.content_sequence == provisional.content_sequence
                && s.enrichment == provisional.enrichment
                && !s.index_manifest.is_null()
        });
        let index = if let Some(existing) = reusable {
            existing.index_manifest
        } else {
            crate::crates_io::index::build(
                self.store.clone(),
                self.retrieval.clone(),
                self.root.clone(),
                provisional.clone(),
                stop.child_token(),
            )
            .await?
        };
        crate::crates_io::index::prewarm(self.root.clone(), index.clone(), stop).await?;
        let mut prepared = provisional;
        prepared.index_manifest = index;
        let snapshot = self.store.commit_snapshot(prepared).await?;
        crate::crates_io::index::activate(&self.root, &snapshot.index_manifest)?;
        self.last_publication.store(unix_now(), Ordering::Relaxed);
        Ok(snapshot)
    }
    async fn jobs_loop(&self, stop: CancellationToken) -> Result<()> {
        let kinds = ["archive", "platforms", "html", "json"];
        loop {
            if stop.is_cancelled() {
                return Ok(());
            }
            let kind = kinds[self.cursor.fetch_add(1, Ordering::Relaxed) % kinds.len()];
            if let Some(job) = self.store.claim(unix_now(), kind).await? {
                let result = self.process_job(&job, stop.child_token()).await;
                if stop.is_cancelled() {
                    return Ok(());
                }
                let retained = if result.is_err() {
                    self.store
                        .latest_artifact(&artifact_key(&job))
                        .await?
                        .map(|a| a.capture.id)
                } else {
                    None
                };
                let (artifact, error, next) = match &result {
                    Ok(capture) => (
                        Some(capture.as_str()),
                        None,
                        if job.kind == "archive" {
                            i64::MAX
                        } else {
                            unix_now().saturating_add(self.config.documentation_refresh_secs as i64)
                        },
                    ),
                    Err(e) => (
                        retained.as_deref(),
                        Some(safe_code(e)),
                        unix_now().saturating_add(if e.code == "not_found" {
                            21600
                        } else {
                            60_i64
                                .saturating_mul(1_i64 << job.attempts.saturating_sub(1).min(9))
                                .min(21600)
                        }),
                    ),
                };
                self.store.finish(&job.key, artifact, error, next).await?;
                self.record_state("acquisition", &result.map(|_| ())).await;
            }
            if unix_now().saturating_sub(self.last_publication.load(Ordering::Relaxed))
                >= self.config.publication_interval_secs as i64
                && self.store.latest_inventory().await?.is_some()
            {
                let result = self.publish(stop.child_token()).await.map(|_| ());
                self.record_state("publication", &result).await;
            }
            tokio::select! {_=stop.cancelled()=>return Ok(()),_=tokio::time::sleep(Duration::from_secs(self.config.collection_interval_secs))=>{}}
        }
    }
    async fn process_job(&self, job: &CollectionJob, stop: CancellationToken) -> Result<String> {
        let metadata = self.retrieval.read_capture(&job.metadata_capture).await?;
        let record = cargo::version_record(&metadata.body, &job.name, &job.version)?;
        let canonical = record["name"]
            .as_str()
            .ok_or_else(|| Error::integrity("Crate name is absent."))?
            .to_owned();
        let (key, source, expected, ttl) = match job.kind.as_str() {
            "archive" => (
                format!(
                    "cargo:archive:{}:{}:{}",
                    job.name, job.version, job.checksum
                ),
                BulkSource::CrateArchive {
                    name: canonical.clone(),
                    version: job.version.clone(),
                },
                Some(job.checksum.as_str()),
                u64::MAX,
            ),
            "platforms" => (
                format!("cargo:docs-platforms:{}:{}", job.name, job.version),
                BulkSource::Documentation {
                    name: canonical.clone(),
                    version: job.version.clone(),
                    operation: DocsOperation::Platforms,
                },
                None,
                self.config.documentation_refresh_secs,
            ),
            "html" => (
                format!("cargo:docs-html:{}:{}", job.name, job.version),
                BulkSource::Documentation {
                    name: canonical.clone(),
                    version: job.version.clone(),
                    operation: DocsOperation::Html,
                },
                None,
                self.config.documentation_refresh_secs,
            ),
            "json" => (
                format!(
                    "cargo:docs-json:{}:{}:{}",
                    job.name, job.version, job.target
                ),
                BulkSource::Documentation {
                    name: canonical.clone(),
                    version: job.version.clone(),
                    operation: DocsOperation::Json {
                        target: job.target.clone(),
                        format: None,
                    },
                },
                None,
                self.config.documentation_refresh_secs,
            ),
            _ => return Err(Error::invalid("Unknown crate job kind.")),
        };
        let captured = self
            .fetch_artifact(&key, source, expected, ttl, stop.child_token())
            .await?;
        match job.kind.as_str() {
            "platforms" => {
                if captured.bytes > 1024 * 1024 {
                    return Err(Error::capacity(
                        "Documentation platform metadata exceeds 1 MiB.",
                    ));
                }
                let file = std::fs::File::open(self.root.join(crate::integrity::relative_path(
                    &captured.capture.body_hash,
                )?))
                .map_err(|_| Error::unavailable("Platform capture unavailable."))?;
                let targets =
                    crate_docs::parse_platforms(file, &ProcessingBudget::new(stop.child_token()))?;
                let mut jobs = Vec::new();
                jobs.push(CollectionJob {
                    key: format!("html:{}:{}", job.name, job.version),
                    kind: "html".into(),
                    target: String::new(),
                    ..job.clone()
                });
                for target in targets {
                    jobs.push(CollectionJob {
                        key: format!("json:{}:{}:{}", job.name, job.version, target.triple),
                        kind: "json".into(),
                        target: target.triple,
                        ..job.clone()
                    });
                }
                self.store.schedule(&jobs, unix_now()).await?;
            }
            "archive" | "html" | "json" => {
                self.project(job, &captured, &canonical, stop.child_token())
                    .await?
            }
            _ => {}
        }
        Ok(captured.capture.id)
    }
    async fn fetch_artifact(
        &self,
        key: &str,
        source: BulkSource,
        expected: Option<&str>,
        ttl: u64,
        stop: CancellationToken,
    ) -> Result<Artifact> {
        let previous = self.store.latest_artifact(key).await?;
        if let Some(old) = &previous
            && unix_now().saturating_sub(old.capture.validated_at) as u64 <= ttl
        {
            self.artifacts
                .verify(
                    &old.capture.body_hash,
                    MAX_ARTIFACT_BYTES,
                    stop.child_token(),
                )
                .await?;
            return Ok(old.clone());
        }
        let url = source.url()?;
        let validators = previous
            .as_ref()
            .map_or_else(Validators::default, |a| Validators {
                etag: a.provenance["etag"].as_str().map(str::to_owned),
                last_modified: a.provenance["last_modified"].as_str().map(str::to_owned),
            });
        let response = self
            .broker
            .open(
                BulkRequest {
                    source,
                    validators,
                    max_bytes: self.config.max_artifact_bytes,
                    deadline: tokio::time::Instant::now() + Duration::from_secs(86400),
                    body: Vec::new(),
                },
                stop.child_token(),
            )
            .await?;
        if response.status == 304 {
            let mut old =
                previous.ok_or_else(|| Error::integrity("Bulk 304 lacks prior capture."))?;
            self.artifacts
                .verify(
                    &old.capture.body_hash,
                    MAX_ARTIFACT_BYTES,
                    stop.child_token(),
                )
                .await?;
            old.capture.validated_at = unix_now();
            self.store.save_artifact(&old, true).await?;
            return Ok(old);
        }
        if response.status == 404 {
            return Err(Error::not_found(
                "Public package representation is not available.",
            ));
        }
        let provenance = json!({"transport":"https","etag":response.validators.etag,"last_modified":response.validators.last_modified});
        let media_type = if key.starts_with("cargo:docs-platforms:") {
            "text/html"
        } else if key.starts_with("cargo:docs-html:") {
            "application/zip"
        } else {
            "application/gzip"
        };
        let artifact = self.artifacts.capture(response, expected, stop).await?;
        self.persist_artifact(key, &url, media_type, artifact, provenance, true)
            .await
    }
    async fn persist_artifact(
        &self,
        key: &str,
        url: &str,
        media: &str,
        artifact: BulkArtifact,
        provenance: Value,
        http: bool,
    ) -> Result<Artifact> {
        let now = if !http && provenance["transport"] == "git" {
            provenance["observed_at"].as_i64().unwrap_or(0)
        } else {
            unix_now()
        };
        let id = digest(format!("{key}\0{url}\0{media}\0{}", artifact.body_hash).as_bytes());
        let captured = Artifact {
            capture: Capture {
                id,
                key: key.into(),
                source_url: url.into(),
                body_hash: artifact.body_hash,
                media_type: media.into(),
                retrieved_at: now,
                validated_at: now,
            },
            bytes: artifact.bytes,
            provenance,
        };
        self.store.save_artifact(&captured, http).await?;
        Ok(captured)
    }
    async fn project(
        &self,
        job: &CollectionJob,
        artifact: &Artifact,
        canonical_name: &str,
        stop: CancellationToken,
    ) -> Result<()> {
        self.artifacts
            .verify(
                &artifact.capture.body_hash,
                MAX_ARTIFACT_BYTES,
                stop.child_token(),
            )
            .await?;
        let permit = self
            .parsers
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| Error::capacity("Crate processing stopped."))?;
        let (send, mut receive) = mpsc::channel::<ProjectionText>(2);
        let path = self.root.join(crate::integrity::relative_path(
            &artifact.capture.body_hash,
        )?);
        let processing_job = job.clone();
        let captured = artifact.clone();
        let token = stop.child_token();
        let root = self.root.clone();
        let canonical_name = canonical_name.to_owned();
        let cancel = CancelOnDrop(token.clone());
        let mut platform_capture = None;
        let default_target = if job.kind == "html" {
            let platforms = self
                .store
                .latest_artifact(&format!(
                    "cargo:docs-platforms:{}:{}",
                    job.name, job.version
                ))
                .await?
                .ok_or_else(|| Error::unavailable("Documentation targets are not captured."))?;
            self.artifacts
                .verify(
                    &platforms.capture.body_hash,
                    MAX_ARTIFACT_BYTES,
                    token.child_token(),
                )
                .await?;
            platform_capture = Some(platforms.capture.id.clone());
            let targets = crate_docs::parse_platforms(
                std::fs::File::open(self.root.join(crate::integrity::relative_path(
                    &platforms.capture.body_hash,
                )?))
                .map_err(|_| Error::unavailable("Platform capture unavailable."))?,
                &ProcessingBudget::new(token.child_token()),
            )?;
            targets
                .into_iter()
                .find(|t| t.is_default)
                .map(|t| t.triple)
                .ok_or_else(|| Error::integrity("Documentation default target is absent."))?
        } else {
            job.target.clone()
        };
        let generation = digest(
            format!(
                "crate-projection:1:{}:{}:{}:{}:{}",
                artifact.capture.id,
                job.kind,
                job.target,
                job.metadata_capture,
                platform_capture.as_deref().unwrap_or_default()
            )
            .as_bytes(),
        );
        let work = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            process_capture(
                ProjectionContext {
                    job: &processing_job,
                    artifact: &captured,
                    path: &path,
                    root: &root,
                    default_target: &default_target,
                    canonical_name: &canonical_name,
                    stop: token,
                },
                |row| {
                    send.blocking_send(row)
                        .map_err(|_| Error::unavailable("Crate projection canceled."))
                },
            )
        });
        let mut batch = Vec::with_capacity(100);
        while let Some(row) = receive.recv().await {
            if stop.is_cancelled() {
                return Err(Error::unavailable("Crate projection canceled."));
            }
            let key = format!(
                "cargo:derived:{}:{}:{}:{}:{}",
                job.name, job.version, artifact.capture.id, row.target, row.path
            );
            let capture=self.store.save_text(&key,&artifact.capture.source_url,&row.text,json!({"source_capture":artifact.capture.id,"metadata_capture":job.metadata_capture,"kind":row.kind,"target":row.target,"path":row.path,"processor_version":1}),unix_now()).await?;
            let id = digest(
                format!("{}\0{}\0{}\0{}", capture.id, row.kind, row.target, row.path).as_bytes(),
            );
            batch.push(ContentRecord {
                id,
                name: job.name.clone(),
                version: job.version.clone(),
                target: row.target,
                path: row.path,
                kind: row.kind,
                capture: capture.id,
                metadata_capture: job.metadata_capture.clone(),
                archive_capture: artifact.capture.id.clone(),
                attributes: row.attributes,
            });
            if batch.len() == 100 {
                self.store.stage_content(&generation, &batch).await?;
                batch.clear();
            }
        }
        let mut summary = work
            .await
            .map_err(|_| Error::unavailable("Crate projection worker failed."))??;
        summary["job_key"] = json!(job.key);
        summary["name"] = json!(job.name);
        summary["version"] = json!(job.version);
        summary["target"] = json!(job.target);
        summary["kind"] = json!(job.kind);
        summary["source_capture"] = json!(artifact.capture.id);
        if !batch.is_empty() {
            self.store.stage_content(&generation, &batch).await?;
        }
        self.store.commit_content(&generation, summary).await?;
        drop(cancel);
        Ok(())
    }
    pub async fn rebuild_index(&self, stop: CancellationToken) -> Result<Value> {
        let snapshot = self.publish(stop).await?;
        Ok(json!({"snapshot":snapshot.id,"coverage":snapshot.coverage}))
    }
    /// Replay a retained, hashed inventory manifest with serving stopped.
    pub async fn import_inventory(
        &self,
        manifest_hash: &str,
        stop: CancellationToken,
    ) -> Result<Value> {
        let artifact = self
            .artifacts
            .verify(manifest_hash, MAX_ARTIFACT_BYTES, stop.child_token())
            .await?;
        let snapshot = self
            .git
            .restore(self.artifacts.clone(), artifact.clone(), stop.child_token())
            .await?;
        let revision = snapshot.revision.clone();
        self.ingest_snapshot(snapshot, stop).await?;
        Ok(json!({"inventory":revision}))
    }
}
struct ProjectionText {
    target: String,
    path: String,
    kind: String,
    text: String,
    attributes: Value,
}
struct CancelOnDrop(CancellationToken);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
struct Stage(PathBuf);
impl Drop for Stage {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
fn digest(bytes: &[u8]) -> String {
    crate::integrity::hash(bytes)
}
fn artifact_key(job: &CollectionJob) -> String {
    match job.kind.as_str() {
        "archive" => format!(
            "cargo:archive:{}:{}:{}",
            job.name, job.version, job.checksum
        ),
        "platforms" => format!("cargo:docs-platforms:{}:{}", job.name, job.version),
        "html" => format!("cargo:docs-html:{}:{}", job.name, job.version),
        _ => format!(
            "cargo:docs-json:{}:{}:{}",
            job.name, job.version, job.target
        ),
    }
}
fn safe_code(error: &Error) -> &str {
    match error.code.as_str() {
        "invalid_input" | "not_found" | "unavailable" | "capacity" | "integrity"
        | "unsupported_format" => &error.code,
        _ => "unavailable",
    }
}
struct ProjectionContext<'a> {
    job: &'a CollectionJob,
    artifact: &'a Artifact,
    path: &'a Path,
    root: &'a Path,
    default_target: &'a str,
    canonical_name: &'a str,
    stop: CancellationToken,
}
fn process_capture(
    context: ProjectionContext<'_>,
    mut emit: impl FnMut(ProjectionText) -> Result<()>,
) -> Result<Value> {
    let ProjectionContext {
        job,
        artifact,
        path,
        root,
        default_target,
        canonical_name,
        stop,
    } = context;
    let budget = ProcessingBudget::new(stop.clone());
    match job.kind.as_str() {
        "archive" => {
            if artifact.bytes > archive::MAX_COMPRESSED as u64 {
                return Err(Error::capacity(
                    "Raw archive retained; source processing exceeds 32 MiB.",
                ));
            }
            let bytes = std::fs::read(path)
                .map_err(|_| Error::unavailable("Captured archive unavailable."))?;
            let metadata_root = format!("{canonical_name}-{}", job.version);
            // Root must still identify this exact package/version; mixed-case historical names are valid.
            if !metadata_root.eq_ignore_ascii_case(&format!("{}-{}", job.name, job.version)) {
                return Err(Error::integrity("Crate archive root identity mismatch."));
            }
            let inspected =
                archive::inspect(&bytes, &job.checksum, &metadata_root, Some("Cargo.toml"))?;
            let manifest = inspected
                .selected
                .as_deref()
                .and_then(|s| std::str::from_utf8(s).ok())
                .and_then(|s| toml::from_str::<toml::Value>(s).ok());
            let readme = manifest
                .as_ref()
                .and_then(|m| m.get("package"))
                .and_then(|p| p.get("readme"));
            let license_file = manifest
                .as_ref()
                .and_then(|m| m.get("package"))
                .and_then(|p| p.get("license-file"))
                .and_then(toml::Value::as_str);
            let mut skipped_binary = 0;
            let mut skipped_oversized = 0;
            let mut count = 0;
            let decoder = flate2::read::MultiGzDecoder::new(bytes.as_slice());
            let mut tar = tar::Archive::new(decoder);
            for entry in tar
                .entries()
                .map_err(|_| Error::integrity("Malformed crate archive."))?
            {
                if stop.is_cancelled() {
                    return Err(Error::unavailable("Crate projection canceled."));
                }
                if std::time::Instant::now() >= budget.deadline {
                    return Err(Error::capacity("Crate projection deadline exceeded."));
                }
                let mut entry = entry.map_err(|_| Error::integrity("Malformed crate member."))?;
                if !entry.header().entry_type().is_file() {
                    continue;
                }
                let member = entry
                    .path()
                    .map_err(|_| Error::integrity("Invalid crate member path."))?
                    .to_string_lossy()
                    .into_owned();
                let relative = member
                    .strip_prefix(&format!("{metadata_root}/"))
                    .ok_or_else(|| Error::integrity("Crate member root mismatch."))?
                    .to_owned();
                if entry.size() > 4 * 1024 * 1024 {
                    skipped_oversized += 1;
                    continue;
                }
                let mut body = Vec::new();
                entry
                    .read_to_end(&mut body)
                    .map_err(|_| Error::integrity("Invalid crate member."))?;
                let Ok(text) = String::from_utf8(body) else {
                    skipped_binary += 1;
                    continue;
                };
                if text.contains('\0') {
                    skipped_binary += 1;
                    continue;
                }
                let filename = relative.to_ascii_lowercase();
                let kind = if relative == "Cargo.toml" || relative == "Cargo.toml.orig" {
                    "manifest"
                } else if license_file == Some(relative.as_str())
                    || (!relative.contains('/')
                        && ["license", "notice", "copying"]
                            .iter()
                            .any(|s| filename.starts_with(s)))
                {
                    "license"
                } else if readme.and_then(toml::Value::as_str) == Some(relative.as_str())
                    || (readme.and_then(toml::Value::as_bool) != Some(false)
                        && !relative.contains('/')
                        && ["readme", "readme.md", "readme.txt", "readme.rst"]
                            .contains(&filename.as_str()))
                {
                    "readme"
                } else {
                    "source"
                };
                emit(ProjectionText {
                    target: String::new(),
                    path: relative,
                    kind: kind.into(),
                    text,
                    attributes: json!({"bytes":entry.size(),"checksum_verified":true}),
                })?;
                count += 1;
            }
            Ok(
                json!({"kind":"archive","files":count,"skipped_binary":skipped_binary,"skipped_oversized":skipped_oversized,"complete_for_eligible_text":true}),
            )
        }
        "html" => {
            let summary = crate_docs::inspect_html_zip(
                std::fs::File::open(path)
                    .map_err(|_| Error::unavailable("Documentation capture unavailable."))?,
                &budget,
                |doc| {
                    emit(ProjectionText {
                        target: doc.target.unwrap_or_else(|| default_target.into()),
                        path: doc.path,
                        kind: "rustdoc".into(),
                        text: doc.text,
                        attributes: json!({"headings":doc.headings,"links":doc.links}),
                    })
                },
            )?;
            serde_json::to_value(summary)
                .map_err(|_| Error::integrity("Documentation summary failed."))
        }
        "json" => {
            static STAGE_ID: AtomicUsize = AtomicUsize::new(0);
            let stage = Stage(root.join(format!(
                ".crate-json-stage-{}-{}",
                std::process::id(),
                STAGE_ID.fetch_add(1, Ordering::Relaxed)
            )));
            let mut output = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&stage.0)
                .map_err(|_| Error::unavailable("JSON processing stage unavailable."))?;
            let mut decoder = flate2::read::MultiGzDecoder::new(
                std::fs::File::open(path)
                    .map_err(|_| Error::unavailable("JSON capture unavailable."))?,
            );
            let mut chunk = [0; 65536];
            let mut bytes = 0_u64;
            loop {
                if stop.is_cancelled() {
                    return Err(Error::unavailable("JSON projection canceled."));
                }
                let count = decoder
                    .read(&mut chunk)
                    .map_err(|_| Error::integrity("Malformed rustdoc gzip."))?;
                if count == 0 {
                    break;
                }
                bytes += count as u64;
                if bytes > crate_docs::MAX_EXPANDED {
                    return Err(Error::capacity("Rustdoc JSON expansion exceeds 256 MiB."));
                }
                if fs2::available_space(root)
                    .map_err(|_| Error::unavailable("JSON stage capacity unavailable."))?
                    < 64 * 1024 * 1024 + count as u64
                {
                    return Err(Error::capacity("Insufficient JSON processing space."));
                }
                output
                    .write_all(&chunk[..count])
                    .map_err(|_| Error::unavailable("JSON processing stage failed."))?;
            }
            drop(output);
            let summary = crate_docs::parse_rustdoc_json(
                std::fs::File::open(&stage.0)
                    .map_err(|_| Error::unavailable("JSON processing stage unavailable."))?,
                &job.version,
                Some(&job.target),
                &budget,
                |item| {
                    let mut attributes = serde_json::to_value(&item)
                        .map_err(|_| Error::integrity("API projection failed."))?;
                    attributes["item_kind"] = json!(item.kind);
                    attributes["format_version"] = json!(item.format_version);
                    let text = format!(
                        "{}\n{}\n{}",
                        item.public_paths.join("\n"),
                        serde_json::to_string(&item.signature)
                            .map_err(|_| Error::integrity("API signature failed."))?,
                        item.docs.as_deref().unwrap_or_default()
                    );
                    for public_path in &item.public_paths {
                        emit(ProjectionText {
                            target: job.target.clone(),
                            path: public_path.clone(),
                            kind: "api".into(),
                            text: text.clone(),
                            attributes: attributes.clone(),
                        })?;
                    }
                    Ok(())
                },
            )?;
            serde_json::to_value(summary).map_err(|_| Error::integrity("API summary failed."))
        }
        _ => Err(Error::invalid("Unsupported projection kind.")),
    }
}
