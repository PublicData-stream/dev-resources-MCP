//! Supervised, resumable collection of public RFC representations.
use crate::{rfc, rfc_index};
use devres_application::{
    Retrieval,
    corpus::{Dataset, Document, JobSpec, RfcCorpusStore, Snapshot},
};
use devres_domain::{Error, FetchRequest, Result, unix_now};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicI64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

pub(crate) const INDEX_URL: &str = "https://www.rfc-editor.org/rfc-index.xml";
pub(crate) const ERRATA_URL: &str = "https://www.rfc-editor.org/api/v1/errata.json";
pub(crate) const BODY_LIMIT: usize = 16 * 1024 * 1024;
pub(crate) const PROCESSOR_VERSION: u32 = 1;

/// Omitted configuration enables collection. Pausing never deletes durable work.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RfcConfig {
    pub enabled: bool,
    pub index_refresh_secs: u64,
    pub errata_refresh_secs: u64,
    pub body_refresh_secs: u64,
    pub collection_interval_secs: u64,
}
impl Default for RfcConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            index_refresh_secs: 86400,
            errata_refresh_secs: 86400,
            body_refresh_secs: 86400,
            collection_interval_secs: 1,
        }
    }
}
impl RfcConfig {
    pub fn validate(&self) -> Result<()> {
        for value in [
            self.index_refresh_secs,
            self.errata_refresh_secs,
            self.body_refresh_secs,
            self.collection_interval_secs,
        ] {
            if value == 0 || value > 366 * 86400 {
                return Err(Error::invalid(
                    "RFC collection intervals must be 1..31622400 seconds.",
                ));
            }
        }
        Ok(())
    }
}

pub struct RfcCorpus {
    pub(crate) retrieval: Arc<Retrieval>,
    pub(crate) store: Arc<dyn RfcCorpusStore>,
    pub(crate) root: PathBuf,
    pub(crate) config: RfcConfig,
    catalogue_lock: Mutex<()>,
    snapshot_lock: Mutex<()>,
    next_catalogue: AtomicI64,
    next_errata: AtomicI64,
    dirty: AtomicUsize,
    last_snapshot: AtomicI64,
    last_failure: Mutex<Option<Value>>,
}

// A detached blocking writer must retain the database ownership fence through
// filesystem writes AND stage cleanup, even after its awaiting task is canceled.
// Fields drop in declaration order: the builder cleans up before ownership drops.
struct OwnedIndexBuilder {
    index: rfc_index::IndexBuilder,
    _owner: Arc<dyn RfcCorpusStore>,
}
impl OwnedIndexBuilder {
    fn begin(
        root: &Path,
        id: &str,
        base: Option<&str>,
        owner: Arc<dyn RfcCorpusStore>,
    ) -> Result<Self> {
        let index = rfc_index::IndexBuilder::begin_from(root, id, base)?;
        Ok(Self {
            index,
            _owner: owner,
        })
    }
    fn add_document(&mut self, document: rfc_index::IndexDocument) -> Result<()> {
        self.index.add_document(document)
    }
    fn remove_document(&mut self, number: u32) -> Result<()> {
        self.index.remove_document(number)
    }
    fn finish(self) -> Result<String> {
        self.index.finish()
    }
}
impl RfcCorpus {
    pub fn new(
        retrieval: Arc<Retrieval>,
        store: Arc<dyn RfcCorpusStore>,
        root: impl AsRef<Path>,
        config: RfcConfig,
    ) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            retrieval,
            store,
            root: root.as_ref().to_path_buf(),
            config,
            catalogue_lock: Mutex::new(()),
            snapshot_lock: Mutex::new(()),
            next_catalogue: AtomicI64::new(0),
            next_errata: AtomicI64::new(0),
            dirty: AtomicUsize::new(0),
            last_snapshot: AtomicI64::new(0),
            last_failure: Mutex::new(None),
        })
    }

    pub(crate) async fn catalogue(&self) -> Result<Dataset> {
        if let Some(dataset) = self.store.dataset("catalogue", None).await? {
            return Ok(dataset);
        }
        self.refresh_catalogue().await
    }

    async fn refresh_catalogue(&self) -> Result<Dataset> {
        let _lock = self.catalogue_lock.lock().await;
        let stored = self
            .retrieval
            .get_validated(
                FetchRequest {
                    key: "rfc:index".into(),
                    url: INDEX_URL.into(),
                    ttl_secs: self.config.index_refresh_secs,
                    max_bytes: 64 * 1024 * 1024,
                    media_type: "application/xml".into(),
                },
                &rfc::Validator,
            )
            .await?;
        let body = stored.body;
        let records = tokio::task::spawn_blocking(move || rfc::parse_index(&body))
            .await
            .map_err(|_| Error::unavailable("RFC catalogue processor failed."))??;
        let values = records
            .iter()
            .map(serde_json::to_value)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| Error::integrity("RFC metadata projection failed."))?;
        let dataset = Dataset {
            capture: stored.capture,
            records: values,
        };
        self.store.save_dataset("catalogue", &dataset).await?;
        let mut jobs = Vec::new();
        for record in &dataset.records {
            let Some(number) = record["number"]
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
            else {
                return Err(Error::integrity("Invalid stored RFC identity."));
            };
            for format in advertised_formats(record) {
                jobs.push(JobSpec {
                    key: representation_key(number, &format, "https"),
                    number,
                    format: format.clone(),
                    source_url: representation_url(number, &format),
                    assurance: "https".into(),
                    due_at: unix_now(),
                });
            }
        }
        for batch in jobs.chunks(100) {
            self.store.schedule(batch).await?;
        }
        self.dirty.fetch_add(1, Ordering::Relaxed);
        Ok(dataset)
    }

    pub(crate) async fn refresh_errata(&self) -> Result<Dataset> {
        let stored = self
            .retrieval
            .get_validated(
                FetchRequest {
                    key: "rfc:errata".into(),
                    url: ERRATA_URL.into(),
                    ttl_secs: self.config.errata_refresh_secs,
                    max_bytes: 64 * 1024 * 1024,
                    media_type: "application/json".into(),
                },
                &rfc::Validator,
            )
            .await?;
        let body = stored.body;
        let records = tokio::task::spawn_blocking(move || rfc::parse_errata(&body))
            .await
            .map_err(|_| Error::unavailable("RFC errata processor failed."))??;
        let dataset = Dataset {
            capture: stored.capture,
            records,
        };
        self.store.save_dataset("errata", &dataset).await?;
        self.dirty.fetch_add(1, Ordering::Relaxed);
        Ok(dataset)
    }

    /// A managed worker owns collection, independently of any public request.
    pub async fn run(&self, shutdown: CancellationToken) -> Result<()> {
        loop {
            if self.config.enabled {
                tokio::select! {
                    biased;
                    _ = shutdown.cancelled() => return Ok(()),
                    result = self.tick() => {
                        // Public provider/capacity failures remain durable, sanitized state.
                        // The serving ownership supervisor independently fails closed on loss.
                        if let Err(error) = result {
                            *self.last_failure.lock().await = Some(json!({"code":error.code,"observed_at":unix_now()}));
                        }
                    }
                }
            }
            tokio::select! {
                _ = shutdown.cancelled() => return Ok(()),
                _ = tokio::time::sleep(Duration::from_secs(self.config.collection_interval_secs)) => {}
            }
        }
    }

    async fn tick(&self) -> Result<()> {
        let now = unix_now();
        if now >= self.next_catalogue.load(Ordering::Relaxed) {
            self.next_catalogue.store(
                now.saturating_add(self.config.index_refresh_secs.min(3600) as i64),
                Ordering::Relaxed,
            );
            match self.refresh_catalogue().await {
                Ok(_) => self.next_catalogue.store(
                    now.saturating_add(self.config.index_refresh_secs as i64),
                    Ordering::Relaxed,
                ),
                Err(error) => {
                    *self.last_failure.lock().await =
                        Some(json!({"source":"catalogue","code":error.code,"observed_at":now}))
                }
            }
        }
        if now >= self.next_errata.load(Ordering::Relaxed) {
            self.next_errata.store(
                now.saturating_add(self.config.errata_refresh_secs.min(3600) as i64),
                Ordering::Relaxed,
            );
            match self.refresh_errata().await {
                Ok(_) => self.next_errata.store(
                    now.saturating_add(self.config.errata_refresh_secs as i64),
                    Ordering::Relaxed,
                ),
                Err(error) => {
                    *self.last_failure.lock().await =
                        Some(json!({"source":"errata","code":error.code,"observed_at":now}))
                }
            }
        }
        if !self.retrieval.foreground_active()
            && let Some(job) = self.store.claim(now).await?
        {
            let request = FetchRequest {
                key: job.spec.key.clone(),
                url: job.spec.source_url.clone(),
                ttl_secs: self.config.body_refresh_secs,
                max_bytes: BODY_LIMIT,
                media_type: media_type(&job.spec.format)?.into(),
            };
            let result = self
                .retrieval
                .get_background_validated(request, &rfc::Validator)
                .await;
            match result {
                Ok(stored) => {
                    self.store
                        .finish(
                            &job.spec.key,
                            Some(&stored.capture),
                            None,
                            now.saturating_add(self.config.body_refresh_secs as i64),
                        )
                        .await?
                }
                Err(error) => {
                    let delay = if error.code == "not_found" {
                        self.config.body_refresh_secs.max(300)
                    } else {
                        30_u64
                            .saturating_mul(1_u64 << job.attempts.min(7))
                            .min(3600)
                    };
                    self.store
                        .finish(
                            &job.spec.key,
                            None,
                            Some(&error.code),
                            now.saturating_add(delay as i64),
                        )
                        .await?;
                }
            }
            self.dirty.fetch_add(1, Ordering::Relaxed);
        }
        if self.dirty.load(Ordering::Relaxed) > 0
            && now.saturating_sub(self.last_snapshot.load(Ordering::Relaxed)) >= 60
        {
            self.publish_snapshot().await?;
        }
        Ok(())
    }

    pub(crate) async fn selected_snapshot(&self, id: Option<&str>) -> Result<Snapshot> {
        if let Some(id) = id {
            valid_snapshot_id(id)?;
        }
        if let Some(snapshot) = self.store.snapshot(id).await? {
            let oldest = snapshot
                .documents
                .iter()
                .map(|d| d.capture.validated_at)
                .chain(snapshot.coverage["catalogue_validated_at"].as_i64())
                .chain(snapshot.coverage["errata_validated_at"].as_i64())
                .min()
                .unwrap_or(snapshot.created_at);
            if id.is_none() && unix_now().saturating_sub(oldest) > 7 * 86400 {
                return Err(Error::unavailable(
                    "Default RFC research snapshot is older than seven days; select an explicit historical snapshot.",
                ));
            }
            return Ok(snapshot);
        }
        if id.is_some() {
            return Err(Error::not_found("RFC research snapshot not found."));
        }
        self.catalogue().await?;
        let snapshot = self.publish_snapshot().await?;
        let oldest = snapshot
            .documents
            .iter()
            .map(|d| d.capture.validated_at)
            .chain(snapshot.coverage["catalogue_validated_at"].as_i64())
            .chain(snapshot.coverage["errata_validated_at"].as_i64())
            .min()
            .unwrap_or(snapshot.created_at);
        if unix_now().saturating_sub(oldest) > 7 * 86400 {
            return Err(Error::unavailable(
                "Default RFC research snapshot is older than seven days.",
            ));
        }
        Ok(snapshot)
    }

    pub(crate) async fn publish_snapshot(&self) -> Result<Snapshot> {
        self.publish_snapshot_inner(false).await
    }
    pub async fn rebuild_index(&self) -> Result<Value> {
        let snapshot = self.publish_snapshot_inner(true).await?;
        Ok(json!({"snapshot":snapshot.id,"coverage":snapshot.coverage}))
    }
    async fn publish_snapshot_inner(&self, force: bool) -> Result<Snapshot> {
        let _lock = self.snapshot_lock.lock().await;
        let generation = self.dirty.load(Ordering::Relaxed);
        let catalogue = self.catalogue().await?;
        let errata = self.store.dataset("errata", None).await?;
        let all_documents = self.store.documents().await?;
        let mut available = BTreeMap::new();
        for document in all_documents {
            let key = (document.number, document.format.clone());
            if available.get(&key).is_none_or(|old: &Document| {
                old.assurance != "https" && document.assurance == "https"
            }) {
                available.insert(key, document);
            }
        }
        let mut documents = Vec::new();
        let mut expected = 0usize;
        let mut captured = 0usize;
        let mut candidates = BTreeMap::new();
        for record in &catalogue.records {
            let number = record["number"].as_u64().unwrap_or(0) as u32;
            let formats = advertised_formats(record);
            expected += formats.len();
            for format in ["txt", "html", "xml", "pdf"] {
                let document = available.get(&(number, format.into()));
                if let Some(document) = document {
                    if formats.iter().any(|f| f == format) {
                        captured += 1;
                    }
                    documents.push(document.clone());
                }
            }
            let choices = ["txt", "xml", "html"]
                .into_iter()
                .filter_map(|format| available.get(&(number, format.into())).cloned())
                .collect::<Vec<_>>();
            candidates.insert(number, choices);
        }
        let stale = documents
            .iter()
            .filter(|d| unix_now().saturating_sub(d.capture.validated_at) > 86400)
            .count();
        let expired = documents
            .iter()
            .filter(|d| unix_now().saturating_sub(d.capture.validated_at) > 7 * 86400)
            .count();
        let unsupported: usize = catalogue
            .records
            .iter()
            .map(|r| r["unsupported_formats"].as_array().map_or(0, Vec::len))
            .sum();
        let complete = captured == expected
            && unsupported == 0
            && expired == 0
            && unix_now().saturating_sub(catalogue.capture.validated_at) <= 7 * 86400
            && errata
                .as_ref()
                .is_some_and(|e| unix_now().saturating_sub(e.capture.validated_at) <= 7 * 86400);
        let previous = if force {
            None
        } else {
            self.store.snapshot(None).await?
        };
        let previous_selected = previous
            .as_ref()
            .filter(|s| s.processor_version == PROCESSOR_VERSION)
            .map(|s| select_search_documents(&s.search_documents))
            .unwrap_or_default();
        let previous_path = previous.as_ref().and_then(|s| s.index_path.clone());
        let preidentity = serde_json::to_vec(&(
            PROCESSOR_VERSION,
            &catalogue.capture,
            errata.as_ref().map(|e| &e.capture),
            &documents,
        ))
        .map_err(|_| Error::integrity("RFC index identity failed."))?;
        // A prior completed index may be orphaned after a crash before DB commit.
        // A unique derived-artifact name allows safe replay without replacing it.
        static BUILDS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let mut build_hash = Sha256::new();
        build_hash.update(&preidentity);
        build_hash.update(std::process::id().to_le_bytes());
        build_hash.update(BUILDS.fetch_add(1, Ordering::Relaxed).to_le_bytes());
        build_hash.update(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
                .to_le_bytes(),
        );
        let build_id = hex::encode(build_hash.finalize());
        let mut builder = None;
        let mut selected = BTreeMap::new();
        let mut extraction_errors = BTreeMap::new();
        for (number, choices) in candidates {
            for document in choices {
                if previous_selected
                    .get(&number)
                    .is_some_and(|old| old.capture.id == document.capture.id)
                    && previous_path.is_some()
                {
                    selected.insert(number, document);
                    break;
                }
                let stored = self.retrieval.read_capture(&document.capture.id).await?;
                let format = document.format.clone();
                let extraction =
                    tokio::task::spawn_blocking(move || rfc::extract_text(&format, &stored.body))
                        .await
                        .map_err(|_| Error::unavailable("RFC extraction worker failed."))?;
                let text = match extraction {
                    Ok(text) => text,
                    Err(error) => {
                        extraction_errors.insert(number, error.code);
                        continue;
                    }
                };
                if builder.is_none() {
                    let root = self.root.clone();
                    let id = build_id.clone();
                    let base = previous_path.clone();
                    let owner = self.store.clone();
                    builder = Some(
                        tokio::task::spawn_blocking(move || {
                            OwnedIndexBuilder::begin(&root, &id, base.as_deref(), owner)
                        })
                        .await
                        .map_err(|_| Error::unavailable("RFC index worker failed."))??,
                    );
                }
                let Some(mut current) = builder.take() else {
                    return Err(Error::integrity("RFC indexing state missing."));
                };
                let (next, outcome) = tokio::task::spawn_blocking(move || {
                    let outcome = current.add_document(rfc_index::IndexDocument { number, text });
                    (current, outcome)
                })
                .await
                .map_err(|_| Error::unavailable("RFC index worker failed."))?;
                builder = Some(next);
                match outcome {
                    Ok(()) => {
                        selected.insert(number, document);
                        extraction_errors.remove(&number);
                        break;
                    }
                    Err(error) => {
                        extraction_errors.insert(number, error.code);
                    }
                }
            }
        }
        let removed = previous_selected
            .keys()
            .filter(|n| !selected.contains_key(n))
            .copied()
            .collect::<Vec<_>>();
        if builder.is_none() && (!removed.is_empty() || previous_path.is_none()) {
            let root = self.root.clone();
            let base = previous_path.clone();
            let owner = self.store.clone();
            builder = Some(
                tokio::task::spawn_blocking(move || {
                    OwnedIndexBuilder::begin(&root, &build_id, base.as_deref(), owner)
                })
                .await
                .map_err(|_| Error::unavailable("RFC index worker failed."))??,
            );
        }
        let index_path = if let Some(mut builder) = builder {
            Some(
                tokio::task::spawn_blocking(move || {
                    for number in removed {
                        builder.remove_document(number)?;
                    }
                    builder.finish()
                })
                .await
                .map_err(|_| Error::unavailable("RFC index worker failed."))??,
            )
        } else {
            previous_path
        };
        let missing_text = catalogue.records.len().saturating_sub(selected.len());
        let error_count = extraction_errors.len();
        let error_sample = extraction_errors
            .into_iter()
            .take(20)
            .collect::<BTreeMap<_, _>>();
        let coverage = json!({"expected_representations":expected,"unsupported_formats":unsupported,"captured_representations":captured,"missing_representations":expected.saturating_sub(captured),"stale_representations":stale,"expired_representations":expired,"documents":catalogue.records.len(),"searchable_documents":selected.len(),"no_extractable_text":missing_text,"acquisition_complete":complete,"search_complete":missing_text==0&&expired==0,"processing_error_count":error_count,"processing_errors":error_sample,"catalogue_validated_at":catalogue.capture.validated_at,"errata_validated_at":errata.as_ref().map(|e|e.capture.validated_at)});
        let search_documents = selected.into_values().collect::<Vec<_>>();
        let identity = serde_json::to_vec(&(
            PROCESSOR_VERSION,
            &catalogue.capture,
            errata.as_ref().map(|e| &e.capture),
            &documents,
            &search_documents,
            &coverage,
            &index_path,
        ))
        .map_err(|_| Error::integrity("RFC snapshot identity failed."))?;
        let id = hex::encode(Sha256::digest(&identity));
        if let Some(existing) = self.store.snapshot(Some(&id)).await? {
            self.dirty.fetch_sub(generation, Ordering::Relaxed);
            self.last_snapshot.store(unix_now(), Ordering::Relaxed);
            return Ok(existing);
        }
        let snapshot = Snapshot {
            id,
            catalogue_capture: catalogue.capture.id,
            errata_capture: errata.map(|e| e.capture.id),
            documents,
            search_documents,
            coverage,
            created_at: unix_now(),
            complete,
            index_path,
            processor_version: PROCESSOR_VERSION,
        };
        self.store.save_snapshot(&snapshot).await?;
        self.dirty.fetch_sub(generation, Ordering::Relaxed);
        self.last_snapshot.store(unix_now(), Ordering::Relaxed);
        Ok(snapshot)
    }

    pub(crate) async fn status(&self) -> Result<Value> {
        let mut value = self.store.status().await?;
        value["collection_enabled"] = json!(self.config.enabled);
        value["body_refresh_secs"] = json!(self.config.body_refresh_secs);
        value["last_worker_failure"] = json!(*self.last_failure.lock().await);
        Ok(value)
    }

    pub(crate) async fn record_foreground(
        &self,
        number: u32,
        format: &str,
        capture: &devres_domain::Capture,
    ) -> Result<()> {
        self.store
            .schedule(&[JobSpec {
                key: capture.key.clone(),
                number,
                format: format.into(),
                source_url: capture.source_url.clone(),
                assurance: "https".into(),
                due_at: unix_now().saturating_add(self.config.body_refresh_secs as i64),
            }])
            .await?;
        self.store
            .finish(
                &capture.key,
                Some(capture),
                None,
                unix_now().saturating_add(self.config.body_refresh_secs as i64),
            )
            .await?;
        self.dirty.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    pub(crate) async fn refresh_partial(&self) -> Result<()> {
        if self.dirty.load(Ordering::Relaxed) > 0 {
            self.publish_snapshot().await?;
        }
        Ok(())
    }

    /// Call only before workers start, while the storage owner fence is held.
    pub async fn recover_stages(&self) -> Result<()> {
        let root = self.root.clone();
        tokio::task::spawn_blocking(move || {
            let path = root.join("rfc-indexes");
            let meta = match std::fs::symlink_metadata(&path) {
                Ok(meta) => meta,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(_) => return Err(Error::unavailable("RFC stage recovery failed.")),
            };
            if !meta.is_dir() || meta.file_type().is_symlink() {
                return Err(Error::integrity(
                    "RFC index root is not a regular directory.",
                ));
            }
            for entry in std::fs::read_dir(&path)
                .map_err(|_| Error::unavailable("RFC stage recovery failed."))?
            {
                let entry = entry.map_err(|_| Error::unavailable("RFC stage recovery failed."))?;
                let name = entry.file_name();
                let name = name.to_string_lossy();
                let recognized = name
                    .strip_prefix(".stage-")
                    .and_then(|s| s.split_once('-'))
                    .is_some_and(|(pid, n)| {
                        !pid.is_empty()
                            && !n.is_empty()
                            && pid.bytes().all(|b| b.is_ascii_digit())
                            && n.bytes().all(|b| b.is_ascii_digit())
                    });
                if recognized {
                    let meta = entry
                        .file_type()
                        .map_err(|_| Error::unavailable("RFC stage recovery failed."))?;
                    if meta.is_symlink() {
                        return Err(Error::integrity(
                            "RFC stage recovery encountered a symbolic link.",
                        ));
                    }
                    if meta.is_dir() {
                        std::fs::remove_dir_all(entry.path())
                            .map_err(|_| Error::unavailable("RFC stage recovery failed."))?;
                    }
                }
            }
            Ok(())
        })
        .await
        .map_err(|_| Error::unavailable("RFC stage recovery worker failed."))?
    }
}

pub(crate) fn select_search_documents(documents: &[Document]) -> BTreeMap<u32, Document> {
    let mut selected = BTreeMap::new();
    for document in documents {
        let priority = |d: &Document| match d.format.as_str() {
            "txt" => 0,
            "xml" => 1,
            "html" => 2,
            _ => 3,
        };
        if priority(document) == 3 {
            continue;
        }
        if selected
            .get(&document.number)
            .is_none_or(|old| priority(document) < priority(old))
        {
            selected.insert(document.number, document.clone());
        }
    }
    selected
}
pub(crate) fn advertised_formats(record: &Value) -> Vec<String> {
    record["formats"]
        .as_array()
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .filter(|f| matches!(*f, "txt" | "html" | "xml" | "pdf"))
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}
pub(crate) fn representation_key(number: u32, format: &str, assurance: &str) -> String {
    if assurance == "rsync" {
        format!("rfc:rsync:{number}:{format}")
    } else if format == "txt" {
        format!("rfc:text:{number}")
    } else {
        format!("rfc:format:{number}:{format}")
    }
}
pub(crate) fn representation_url(number: u32, format: &str) -> String {
    format!("https://www.rfc-editor.org/rfc/rfc{number}.{format}")
}
pub(crate) fn media_type(format: &str) -> Result<&'static str> {
    match format {
        "txt" => Ok("text/plain"),
        "html" => Ok("text/html"),
        "xml" => Ok("application/xml"),
        "pdf" => Ok("application/pdf"),
        _ => Err(Error::invalid("RFC format must be txt, html, xml, or pdf.")),
    }
}
pub(crate) fn valid_snapshot_id(id: &str) -> Result<()> {
    if id.len() != 64
        || !id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::invalid("Invalid RFC snapshot identifier."));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    struct TestOwner {
        dropped: Arc<AtomicUsize>,
        root: PathBuf,
    }
    impl Drop for TestOwner {
        fn drop(&mut self) {
            let staged =
                std::fs::read_dir(self.root.join("rfc-indexes")).is_ok_and(|mut entries| {
                    entries.any(|e| {
                        e.is_ok_and(|e| e.file_name().to_string_lossy().starts_with(".stage-"))
                    })
                });
            self.dropped
                .store(if staged { 2 } else { 1 }, Ordering::SeqCst);
        }
    }
    #[async_trait::async_trait]
    impl RfcCorpusStore for TestOwner {
        async fn save_dataset(&self, _: &str, _: &Dataset) -> Result<()> {
            Err(Error::unavailable("Unused test port"))
        }
        async fn dataset(&self, _: &str, _: Option<&str>) -> Result<Option<Dataset>> {
            Err(Error::unavailable("Unused test port"))
        }
        async fn schedule(&self, _: &[JobSpec]) -> Result<()> {
            Err(Error::unavailable("Unused test port"))
        }
        async fn claim(&self, _: i64) -> Result<Option<devres_application::corpus::Job>> {
            Err(Error::unavailable("Unused test port"))
        }
        async fn finish(
            &self,
            _: &str,
            _: Option<&devres_domain::Capture>,
            _: Option<&str>,
            _: i64,
        ) -> Result<()> {
            Err(Error::unavailable("Unused test port"))
        }
        async fn documents(&self) -> Result<Vec<Document>> {
            Err(Error::unavailable("Unused test port"))
        }
        async fn save_snapshot(&self, _: &Snapshot) -> Result<()> {
            Err(Error::unavailable("Unused test port"))
        }
        async fn snapshot(&self, _: Option<&str>) -> Result<Option<Snapshot>> {
            Err(Error::unavailable("Unused test port"))
        }
        async fn status(&self) -> Result<Value> {
            Err(Error::unavailable("Unused test port"))
        }
    }
    #[tokio::test]
    async fn canceled_blocking_index_writer_retains_owner_through_cleanup() {
        let _test = crate::rfc_index::TEST_SERIAL.lock().await;
        let root = tempfile::tempdir().unwrap();
        let dropped = Arc::new(AtomicUsize::new(0));
        let owner: Arc<dyn RfcCorpusStore> = Arc::new(TestOwner {
            dropped: dropped.clone(),
            root: root.path().to_path_buf(),
        });
        let weak = Arc::downgrade(&owner);
        // Other index unit tests share the single-writer admission; retry only admission.
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        let mut builder = loop {
            match OwnedIndexBuilder::begin(root.path(), &"a".repeat(64), None, owner.clone()) {
                Ok(builder) => break builder,
                Err(error) if error.code == "capacity" && std::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(5)).await
                }
                Err(error) => panic!("{error}"),
            }
        };
        drop(owner);
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            tokio::task::spawn_blocking(move || {
                let _ = entered_tx.send(());
                let _ = release_rx.blocking_recv();
                builder
                    .add_document(rfc_index::IndexDocument {
                        number: 1,
                        text: "public synthetic text".into(),
                    })
                    .unwrap();
                drop(builder);
            })
            .await
        });
        entered_rx.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(weak.upgrade().is_some());
        assert_eq!(dropped.load(Ordering::SeqCst), 0);
        release_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            while dropped.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            dropped.load(Ordering::SeqCst),
            1,
            "stage cleanup must finish before the storage owner is dropped"
        );
        assert!(weak.upgrade().is_none());
    }
    #[test]
    fn defaults_and_pause_are_explicit() {
        assert!(RfcConfig::default().enabled);
        let c: RfcConfig = serde_json::from_value(json!({"enabled":false})).unwrap();
        assert!(!c.enabled);
        assert_eq!(c.body_refresh_secs, 86400);
        assert!(serde_json::from_value::<RfcConfig>(json!({"unknown":true})).is_err());
        let c = RfcConfig {
            collection_interval_secs: 0,
            ..Default::default()
        };
        assert!(c.validate().is_err());
    }
    #[test]
    fn legacy_identity_and_format_availability_are_preserved() {
        assert_eq!(representation_key(1, "txt", "https"), "rfc:text:1");
        assert_ne!(
            representation_key(1, "txt", "rsync"),
            representation_key(1, "txt", "https")
        );
        assert_eq!(
            advertised_formats(&json!({"formats":["txt","html","unknown"]})),
            vec!["txt", "html"]
        );
        assert!(valid_snapshot_id("../outside").is_err());
    }
}
