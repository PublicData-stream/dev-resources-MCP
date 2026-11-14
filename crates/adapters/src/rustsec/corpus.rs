//! Supervised RustSec publication. Public requests never acquire upstream data.
use crate::{archive, bulk::BulkBroker, rustsec::advisory, rustsec::git::AdvisoryHistory};
use devres_application::{
    ResponseValidator, Retrieval,
    advisory::{
        ADVISORY_PROCESSOR_VERSION, AdvisoryAttemptOutcome, AdvisoryCurrentDiagnostic,
        AdvisoryCurrentOperation, AdvisoryCurrentStage, AdvisoryPublicationError, AdvisoryRecord,
        AdvisorySnapshot, AdvisoryStore, CURRENT_DIAGNOSTICS_KEY, RustSecConfig,
    },
    collection::{Failure, Phase},
};
use devres_domain::{Error, FetchRequest, FetchResponse, Result, StoredCapture};
use serde_json::{Value, json};
use std::{
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

pub(crate) const HEAD_URL: &str = "https://api.github.com/repos/RustSec/advisory-db/commits/main";
pub struct AdvisoryCorpus {
    retrieval: Arc<Retrieval>,
    pub(crate) store: Arc<dyn AdvisoryStore>,
    config: RustSecConfig,
    gate: Mutex<()>,
    history: AdvisoryHistory,
}
pub(crate) fn digest(bytes: &[u8]) -> String {
    crate::integrity::hash(bytes)
}
pub(crate) fn revision(bytes: &[u8]) -> Result<String> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|_| Error::integrity("Malformed RustSec revision metadata."))?;
    value["sha"]
        .as_str()
        .filter(|v| {
            v.len() == 40
                && v.bytes()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        })
        .map(str::to_owned)
        .ok_or_else(|| Error::integrity("Invalid immutable RustSec revision."))
}
struct HeadValidator;
#[async_trait::async_trait]
impl ResponseValidator for HeadValidator {
    fn collection_diagnostics(&self) -> bool {
        true
    }
    async fn validate(&self, _: &FetchRequest, response: FetchResponse) -> Result<FetchResponse> {
        revision(&response.body)?;
        Ok(response)
    }
}

struct BundleValidator;
#[async_trait::async_trait]
impl ResponseValidator for BundleValidator {
    fn collection_diagnostics(&self) -> bool {
        true
    }
    async fn validate(&self, _: &FetchRequest, response: FetchResponse) -> Result<FetchResponse> {
        Ok(response)
    }
}

pub(super) fn attempt_id(operation: &str) -> Result<String> {
    static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::unavailable("Advisory attempt clock unavailable."))?
        .as_nanos();
    Ok(digest(
        format!(
            "{operation}:{}:{nanos}:{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        )
        .as_bytes(),
    ))
}

/// Normalize every relevant file; unsupported historical inputs remain explicit gaps.
pub(crate) fn normalize_records(
    files: Vec<(String, Vec<u8>)>,
    format: &str,
) -> Result<(Vec<AdvisoryRecord>, Value)> {
    if !matches!(format, "rustsec" | "osv") {
        return Err(Error::invalid("Unsupported advisory representation."));
    }
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut records = Vec::new();
    let mut gaps = Vec::new();
    let mut ids = std::collections::HashSet::new();
    let enumerated = files.len();
    let mut total = 0usize;
    if enumerated > 20_000 {
        return Err(Error::capacity("Advisory record count exceeds 20000."));
    }
    for (path, bytes) in files {
        total = total.saturating_add(bytes.len());
        if total > 64 * 1024 * 1024 || Instant::now() >= deadline {
            return Err(Error::capacity("Advisory normalization budget exceeded."));
        }
        let result = (|| {
            if bytes.len() > 1024 * 1024 {
                return Err(Error::capacity("Advisory record exceeds 1 MiB."));
            }
            let body = std::str::from_utf8(&bytes)
                .map_err(|_| Error::integrity("Advisory source is not UTF-8."))?;
            if format == "osv" {
                let record = crate::rustsec::osv::normalize(&path, body)?;
                if path != format!("crates/{}.json", record.id) {
                    return Err(Error::integrity("OSV advisory path and identity disagree."));
                }
                return Ok(record);
            }
            let parsed = advisory::parse_files(vec![(path.clone(), bytes.clone())], deadline)?;
            let parsed = parsed
                .first()
                .ok_or_else(|| Error::integrity("Missing parsed advisory."))?;
            let mut metadata = advisory::summary(parsed);
            metadata["title"] = json!(parsed.title());
            metadata["categories"] = json!(parsed.metadata.categories);
            metadata["keywords"] = json!(parsed.metadata.keywords);
            metadata["affected"] = json!(parsed.affected);
            metadata["original"] = serde_json::to_value(parsed)
                .map_err(|_| Error::integrity("Advisory metadata serialization failed."))?;
            metadata["applicability_known"] = json!(true);
            Ok(AdvisoryRecord {
                id: parsed.metadata.id.to_string(),
                package: parsed.metadata.package.to_string(),
                format: format.into(),
                path: path.clone(),
                body: body.into(),
                body_hash: digest(&bytes),
                metadata,
            })
        })();
        match result {
            Ok(record) if ids.insert(record.id.clone()) => records.push(record),
            Ok(_) => gaps.push(json!({"path":path,"code":"duplicate_identity"})),
            Err(error) => {
                gaps.push(json!({"path":path,"code":error.code}));
                // Keep attributable raw history readable even when its schema is unsupported.
                let name = path.rsplit('/').next().unwrap_or("");
                let id = name.rsplit_once('.').map(|(name, _)| name).unwrap_or(name);
                if id.parse::<::rustsec::advisory::Id>().is_ok()
                    && ids.insert(id.to_owned())
                    && bytes.len() <= 1024 * 1024
                    && let Ok(body) = String::from_utf8(bytes.clone())
                {
                    let package = if format == "rustsec" {
                        path.split('/').nth(1).unwrap_or("")
                    } else {
                        ""
                    };
                    records.push(AdvisoryRecord{id:id.into(),package:package.into(),format:format.into(),path:path.clone(),body,body_hash:digest(&bytes),metadata:json!({"id":id,"package":package,"processing":"unsupported","classification":"unassessed","matching_complete":false,"applicability_known":false})});
                }
            }
        }
    }
    records.sort_by(|a, b| a.id.cmp(&b.id));
    let matching_complete = records
        .iter()
        .all(|r| r.metadata["matching_complete"] != false);
    let parsed = records
        .iter()
        .filter(|r| r.metadata["processing"] != "unsupported")
        .count();
    let coverage = json!({"complete":gaps.is_empty()&&matching_complete,"enumerated":enumerated,"parsed":parsed,"retained_records":records.len(),"gaps":gaps,"matching_complete":matching_complete,"processor_version":ADVISORY_PROCESSOR_VERSION});
    Ok((records, coverage))
}

impl AdvisoryCorpus {
    pub fn new_reader(
        retrieval: Arc<Retrieval>,
        store: Arc<dyn AdvisoryStore>,
        broker: Arc<BulkBroker>,
        root: &Path,
        config: RustSecConfig,
    ) -> Result<Self> {
        config.validate()?;
        let history = AdvisoryHistory::for_reader(store.clone(), broker, root, config.clone())?;
        Ok(Self {
            retrieval,
            store,
            config,
            gate: Mutex::new(()),
            history,
        })
    }

    pub fn new(
        retrieval: Arc<Retrieval>,
        store: Arc<dyn AdvisoryStore>,
        broker: Arc<BulkBroker>,
        root: &Path,
        config: RustSecConfig,
    ) -> Result<Self> {
        config.validate()?;
        let history = AdvisoryHistory::new(store.clone(), broker, root, config.clone())?;
        Ok(Self {
            retrieval,
            store,
            config,
            gate: Mutex::new(()),
            history,
        })
    }
    pub async fn refresh_current(&self) -> Result<Value> {
        // Keep failure recording under this gate too: a late error must not erase success.
        let _gate = self.gate.lock().await;
        self.reconcile_interrupted_current().await?;
        let mut attempt = AdvisoryCurrentDiagnostic {
            version: 1,
            attempt: attempt_id("current_refresh")?,
            operation: AdvisoryCurrentOperation::CurrentRefresh,
            outcome: AdvisoryAttemptOutcome::Running,
            stage: AdvisoryCurrentStage::Head,
            started_at: devres_domain::unix_now(),
            finished_at: None,
            head_capture: None,
            bundle_capture: None,
            revision: None,
            snapshot: None,
            failure: None,
        };
        self.save_attempt(&attempt).await?;
        let result = self.prepare_current(&mut attempt).await;
        let snapshot = match result {
            Ok(snapshot) => snapshot,
            Err(error) => {
                self.fail_attempt(&mut attempt, &error, false).await?;
                return Err(error);
            }
        };
        attempt.stage = AdvisoryCurrentStage::Publication;
        attempt.snapshot = Some(snapshot.id.clone());
        self.save_attempt(&attempt).await?;
        match self
            .store
            .publish_current_advisory(&snapshot, &attempt)
            .await
        {
            Ok(()) => {}
            Err(failure) => {
                let unknown = matches!(failure, AdvisoryPublicationError::CommitUnknown(_));
                let error = failure.into_error();
                // A COMMIT response can be lost after the server committed. Read only exact
                // attempt success, public success, and its default before reporting success.
                if unknown && self.committed_attempt(&attempt).await.unwrap_or(false) {
                    return Ok(Self::refresh_result(&snapshot));
                }
                self.fail_attempt(&mut attempt, &error, unknown).await?;
                return Err(error);
            }
        }
        Ok(Self::refresh_result(&snapshot))
    }
    async fn reconcile_interrupted_current(&self) -> Result<()> {
        let Some(previous) = self.store.advisory_state(CURRENT_DIAGNOSTICS_KEY).await? else {
            return Ok(());
        };
        let previous: AdvisoryCurrentDiagnostic = serde_json::from_value(previous)
            .map_err(|_| Error::integrity("Invalid current advisory diagnostic."))?;
        previous.validate()?;
        if matches!(
            previous.outcome,
            AdvisoryAttemptOutcome::Running | AdvisoryAttemptOutcome::Unknown
        ) {
            self.store.reconcile_current_advisory_attempt().await?;
        }
        Ok(())
    }
    fn refresh_result(snapshot: &AdvisorySnapshot) -> Value {
        json!({"snapshot":crate::rustsec::research::snapshot_metadata(snapshot),"advisories":snapshot.records.len()})
    }
    async fn save_attempt(&self, attempt: &AdvisoryCurrentDiagnostic) -> Result<()> {
        attempt.validate()?;
        self.store
            .set_advisory_state(
                CURRENT_DIAGNOSTICS_KEY,
                &serde_json::to_value(attempt)
                    .map_err(|_| Error::integrity("Invalid advisory attempt encoding."))?,
            )
            .await
    }
    async fn fail_attempt(
        &self,
        attempt: &mut AdvisoryCurrentDiagnostic,
        error: &Error,
        unknown: bool,
    ) -> Result<()> {
        let now = devres_domain::unix_now().max(attempt.started_at);
        attempt.finished_at = Some(now);
        attempt.outcome = if unknown {
            AdvisoryAttemptOutcome::Unknown
        } else {
            AdvisoryAttemptOutcome::Failed
        };
        let phase = match attempt.stage {
            AdvisoryCurrentStage::Head | AdvisoryCurrentStage::Bundle => Phase::HttpAcquisition,
            AdvisoryCurrentStage::Normalization => Phase::Projection,
            AdvisoryCurrentStage::SnapshotLookup => Phase::RetainedLookup,
            AdvisoryCurrentStage::Publication => Phase::ViewPublication,
        };
        attempt.failure = Some(Failure::from_error(error, phase, now));
        self.store.finish_current_advisory_attempt(attempt).await?;
        Ok(())
    }
    async fn committed_attempt(&self, attempt: &AdvisoryCurrentDiagnostic) -> Result<bool> {
        let Some(retained) = self.store.advisory_state(CURRENT_DIAGNOSTICS_KEY).await? else {
            return Ok(false);
        };
        let retained: AdvisoryCurrentDiagnostic = serde_json::from_value(retained)
            .map_err(|_| Error::integrity("Invalid current advisory diagnostic."))?;
        retained.validate()?;
        if retained.attempt != attempt.attempt
            || retained.outcome != AdvisoryAttemptOutcome::Succeeded
            || retained.snapshot != attempt.snapshot
        {
            return Ok(false);
        }
        let public = self
            .store
            .advisory_state("current")
            .await?
            .unwrap_or(Value::Null);
        let default = self.store.advisory_snapshot(None, "rustsec").await?;
        Ok(public["snapshot"].as_str() == attempt.snapshot.as_deref()
            && default.as_ref().map(|snapshot| snapshot.id.as_str()) == attempt.snapshot.as_deref())
    }
    async fn prepare_current(
        &self,
        attempt: &mut AdvisoryCurrentDiagnostic,
    ) -> Result<AdvisorySnapshot> {
        let head = self
            .retrieval
            .get_fresh_validated(
                FetchRequest {
                    key: "rustsec:head".into(),
                    url: HEAD_URL.into(),
                    ttl_secs: 0,
                    max_bytes: 4 * 1024 * 1024,
                    media_type: "application/json".into(),
                },
                &HeadValidator,
            )
            .await?;
        let revision = revision(&head.body)?;
        attempt.head_capture = Some(head.capture.id.clone());
        attempt.revision = Some(revision.clone());
        attempt.stage = AdvisoryCurrentStage::Bundle;
        self.save_attempt(attempt).await?;
        // Immutable bundle reuse does not replace fresh head validation.
        let bundle = self
            .retrieval
            .get_validated(
                FetchRequest {
                    key: format!("rustsec:bundle:{revision}"),
                    url: format!(
                        "https://codeload.github.com/RustSec/advisory-db/tar.gz/{revision}"
                    ),
                    ttl_secs: 365 * 86400,
                    max_bytes: archive::MAX_COMPRESSED,
                    media_type: "application/gzip".into(),
                },
                &BundleValidator,
            )
            .await?;
        attempt.bundle_capture = Some(bundle.capture.id.clone());
        attempt.stage = AdvisoryCurrentStage::Normalization;
        self.save_attempt(attempt).await?;
        self.prepare_pair(head, bundle, false, Some(attempt)).await
    }
    async fn publish_pair(
        &self,
        head: StoredCapture,
        bundle: StoredCapture,
        historical: bool,
        make_default: bool,
    ) -> Result<AdvisorySnapshot> {
        let snapshot = self.prepare_pair(head, bundle, historical, None).await?;
        self.store
            .publish_advisory_snapshot(&snapshot, make_default)
            .await?;
        Ok(snapshot)
    }
    async fn prepare_pair(
        &self,
        head: StoredCapture,
        bundle: StoredCapture,
        historical: bool,
        mut attempt: Option<&mut AdvisoryCurrentDiagnostic>,
    ) -> Result<AdvisorySnapshot> {
        let _permit = archive::admit()?;
        let bytes = bundle.body;
        let checksum = bundle.capture.body_hash.clone();
        let revision = revision(&head.body)?;
        let root = format!("advisory-db-{revision}");
        let (records, coverage) = tokio::task::spawn_blocking(move || {
            let _permit = _permit;
            let files = archive::advisory_files(
                &bytes,
                &checksum,
                &root,
                Instant::now() + Duration::from_secs(15),
            )?;
            normalize_records(files, "rustsec")
        })
        .await
        .map_err(|_| Error::unavailable("RustSec normalization worker failed."))??;
        if coverage["complete"] != true || records.is_empty() {
            return Err(Error::integrity(
                "Current RustSec snapshot has processing gaps.",
            ));
        }
        let now = devres_domain::unix_now();
        let mut snapshot = AdvisorySnapshot {
            id: String::new(),
            revision,
            format: "rustsec".into(),
            created_at: now,
            validated_at: Some(head.capture.validated_at),
            historical,
            complete: true,
            records,
            captures: vec![head.capture, bundle.capture],
            coverage,
            parents: vec![],
            committed_at: 0,
        };
        // Processing time does not change an observation's immutable identity.
        snapshot.id=digest(&serde_json::to_vec(&json!({"revision":snapshot.revision,"format":"rustsec","validated_at":snapshot.validated_at,"captures":snapshot.captures.iter().map(|c|&c.id).collect::<Vec<_>>(),"historical":historical,"processor_version":ADVISORY_PROCESSOR_VERSION})).map_err(|_|Error::integrity("RustSec snapshot identity failed."))?);
        if let Some(attempt) = attempt.as_mut() {
            attempt.stage = AdvisoryCurrentStage::SnapshotLookup;
            attempt.snapshot = Some(snapshot.id.clone());
            self.save_attempt(attempt).await?;
        }
        // Same observation after restart must retain exactly the same descriptor.
        if let Some(existing) = self
            .store
            .advisory_snapshot(Some(&snapshot.id), "rustsec")
            .await?
        {
            snapshot = existing;
        }
        Ok(snapshot)
    }
    async fn recover_legacy(&self) -> Result<()> {
        let after = self
            .store
            .advisory_state("legacy-after")
            .await?
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let rows = self
            .store
            .advisory_rows("legacy-heads", None, after, 1)
            .await?;
        for row in rows {
            let result = async {
                let head = self.retrieval.read_capture(&row.key).await?;
                let revision = revision(&head.body)?;
                let bundle = self
                    .retrieval
                    .latest_capture(&format!("rustsec:bundle:{revision}"))
                    .await?
                    .ok_or_else(|| Error::not_found("Retained advisory bundle unavailable."))?;
                let latest = self.retrieval.latest_capture("rustsec:head").await?;
                let historical = latest
                    .as_ref()
                    .is_none_or(|latest| latest.capture.id != head.capture.id);
                let make_default = !historical
                    && devres_domain::unix_now().saturating_sub(head.capture.validated_at)
                        <= 7 * 86400;
                self.publish_pair(head, bundle, historical, make_default)
                    .await?;
                Ok::<_, Error>(())
            }
            .await;
            if let Err(error) = result {
                self.store
                    .put_advisory_row("legacy-gaps", &row.key, &json!({"code":error.code}))
                    .await?;
            }
            self.store
                .set_advisory_state("legacy-after", &json!(row.sequence))
                .await?;
        }
        Ok(())
    }
    pub async fn run_current(&self, shutdown: CancellationToken) -> Result<()> {
        self.store
            .set_advisory_state(
                "config",
                &serde_json::to_value(&self.config)
                    .map_err(|_| Error::integrity("RustSec config serialization failed."))?,
            )
            .await?;
        loop {
            if shutdown.is_cancelled() {
                return Ok(());
            }
            tokio::select! {_=shutdown.cancelled()=>return Ok(()), result=self.recover_legacy()=>result?};
            {
                let _gate = self.gate.lock().await;
                self.reconcile_interrupted_current().await?;
            }
            let state = self.store.advisory_state("current").await?;
            let last = state
                .as_ref()
                .and_then(|v| v["last_attempt"].as_i64())
                .unwrap_or(0);
            let now = devres_domain::unix_now();
            if self.config.enabled
                && now.saturating_sub(last) >= self.config.current_refresh_secs as i64
            {
                let previous_attempt = self
                    .store
                    .advisory_state(CURRENT_DIAGNOSTICS_KEY)
                    .await?
                    .and_then(|value| value["attempt"].as_str().map(str::to_owned));
                let result = tokio::select! {biased;_=shutdown.cancelled()=>return Ok(()), result=self.refresh_current()=>result};
                if let Err(error) = result {
                    let recorded = self.store.advisory_state(CURRENT_DIAGNOSTICS_KEY).await?;
                    // A failed diagnostic write must not create an acquisition loop at the
                    // collection interval. Supervision stops unless this attempt has a
                    // durable terminal result (including a commit outcome still unknown).
                    let recorded = recorded.as_ref().is_some_and(|value| {
                        value["attempt"].as_str() != previous_attempt.as_deref()
                            && matches!(
                                value["outcome"].as_str(),
                                Some("failed" | "unknown" | "succeeded")
                            )
                    });
                    if !recorded {
                        return Err(error);
                    }
                }
            }
            tokio::select! {_=shutdown.cancelled()=>return Ok(()),_=tokio::time::sleep(Duration::from_secs(self.config.collection_interval_secs))=>{}}
        }
    }
    pub async fn run_history(&self, shutdown: CancellationToken) -> Result<()> {
        loop {
            if shutdown.is_cancelled() {
                return Ok(());
            }
            if self.config.enabled {
                let result = tokio::select! {biased;_=shutdown.cancelled()=>return Ok(()),result=self.history.tick(shutdown.child_token())=>result};
                if let Err(error) = result {
                    self.store
                        .set_advisory_state(
                            "history-error",
                            &json!({"at":devres_domain::unix_now(),"code":error.code}),
                        )
                        .await?;
                }
            }
            tokio::select! {_=shutdown.cancelled()=>return Ok(()),_=tokio::time::sleep(Duration::from_secs(self.config.collection_interval_secs))=>{}}
        }
    }
}

pub(crate) async fn writer_head(retrieval: &Retrieval, force: bool) -> Result<StoredCapture> {
    retrieval
        .get_validated(
            FetchRequest {
                key: "rustsec:head".into(),
                url: HEAD_URL.into(),
                ttl_secs: if force { 0 } else { 86400 },
                max_bytes: 4 * 1024 * 1024,
                media_type: "application/json".into(),
            },
            &HeadValidator,
        )
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_history_is_a_gap_without_losing_valid_records() {
        let bytes = include_bytes!("../../tests/fixtures/rustsec/git-snapshot-minimal.tar.gz");
        let root = "advisory-db-84d943a6deeb8cc6c6f632531aaf4f1c62275239";
        let mut files = archive::advisory_files(
            bytes,
            &archive::sha256(bytes),
            root,
            Instant::now() + Duration::from_secs(15),
        )
        .unwrap();
        files.push((
            "crates/bad/RUSTSEC-2024-0001.md".into(),
            b"invalid".to_vec(),
        ));
        let (records, coverage) = normalize_records(files, "rustsec").unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(coverage["complete"], false);
        assert_eq!(coverage["gaps"][0]["code"], "integrity");
    }
}

#[cfg(test)]
#[path = "current_tests.rs"]
mod current_tests;
