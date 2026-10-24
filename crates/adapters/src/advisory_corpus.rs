//! Supervised RustSec publication. Public requests never acquire upstream data.
use crate::{advisory, advisory_git::AdvisoryHistory, archive, bulk::BulkBroker};
use devres_application::{
    ResponseValidator, Retrieval,
    advisory::{AdvisoryRecord, AdvisorySnapshot, AdvisoryStore, RustSecConfig},
};
use devres_domain::{Error, FetchRequest, FetchResponse, Result, StoredCapture};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
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
    hex::encode(Sha256::digest(bytes))
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
    async fn validate(&self, _: &FetchRequest, response: FetchResponse) -> Result<FetchResponse> {
        revision(&response.body)?;
        Ok(response)
    }
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
                let record = crate::advisory_osv::normalize(&path, body)?;
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
                if id.parse::<rustsec::advisory::Id>().is_ok()
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
    let coverage = json!({"complete":gaps.is_empty()&&matching_complete,"enumerated":enumerated,"parsed":parsed,"retained_records":records.len(),"gaps":gaps,"matching_complete":matching_complete,"processor_version":1});
    Ok((records, coverage))
}

impl AdvisoryCorpus {
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
        let _gate = self.gate.lock().await;
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
        // Stale fallback is usable evidence, but never a successful fresh observation.
        let bundle = self
            .retrieval
            .get(FetchRequest {
                key: format!("rustsec:bundle:{revision}"),
                url: format!("https://codeload.github.com/RustSec/advisory-db/tar.gz/{revision}"),
                ttl_secs: 365 * 86400,
                max_bytes: archive::MAX_COMPRESSED,
                media_type: "application/gzip".into(),
            })
            .await?;
        let snapshot = self.publish_pair(head, bundle, false, true).await?;
        let result = json!({"snapshot":crate::advisory_research::snapshot_metadata(&snapshot),"advisories":snapshot.records.len()});
        self.store.set_advisory_state("current",&json!({"last_attempt":devres_domain::unix_now(),"last_success":snapshot.validated_at,"snapshot":snapshot.id,"error":null})).await?;
        Ok(result)
    }
    async fn publish_pair(
        &self,
        head: StoredCapture,
        bundle: StoredCapture,
        historical: bool,
        make_default: bool,
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
        snapshot.id=digest(&serde_json::to_vec(&json!({"revision":snapshot.revision,"format":"rustsec","validated_at":snapshot.validated_at,"captures":snapshot.captures.iter().map(|c|&c.id).collect::<Vec<_>>(),"historical":historical,"processor_version":1})).map_err(|_|Error::integrity("RustSec snapshot identity failed."))?);
        // Same observation after restart must retain exactly the same descriptor.
        if let Some(existing) = self
            .store
            .advisory_snapshot(Some(&snapshot.id), "rustsec")
            .await?
        {
            snapshot = existing;
        }
        self.store
            .publish_advisory_snapshot(&snapshot, make_default)
            .await?;
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
            let state = self.store.advisory_state("current").await?;
            let last = state
                .as_ref()
                .and_then(|v| v["last_attempt"].as_i64())
                .unwrap_or(0);
            let now = devres_domain::unix_now();
            if self.config.enabled
                && now.saturating_sub(last) >= self.config.current_refresh_secs as i64
            {
                let result = tokio::select! {biased;_=shutdown.cancelled()=>return Ok(()), result=self.refresh_current()=>result};
                if let Err(error) = result {
                    self.store.set_advisory_state("current",&json!({"last_attempt":now,"error":error.code,"previous_snapshot_preserved":true})).await?;
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_history_is_a_gap_without_losing_valid_records() {
        let bytes = include_bytes!("../tests/fixtures/rustsec/git-snapshot-minimal.tar.gz");
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
