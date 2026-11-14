//! Synthetic public-source fixtures; caller lockfiles never enter these stores.
use super::*;
use async_trait::async_trait;
use devres_application::{Cached, Fetcher, Store, advisory::AdvisoryRow};
use devres_domain::{Body, Capture, Validators};
use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicUsize, Ordering},
};

const REVISION: &str = "84d943a6deeb8cc6c6f632531aaf4f1c62275239";
#[derive(Default)]
struct Data {
    captures: BTreeMap<String, Cached>,
    snapshots: BTreeMap<String, AdvisorySnapshot>,
    defaults: BTreeMap<String, String>,
    states: BTreeMap<String, Value>,
}
#[derive(Default)]
struct Memory {
    data: Mutex<Data>,
    publication: AtomicUsize,
    readback_failures: AtomicUsize,
}
#[async_trait]
impl Store for Memory {
    async fn latest(&self, key: &str) -> Result<Option<Cached>> {
        Ok(self.data.lock().await.captures.get(key).cloned())
    }
    async fn capture(&self, id: &str) -> Result<StoredCapture> {
        self.data
            .lock()
            .await
            .captures
            .values()
            .find(|cached| cached.stored.capture.id == id)
            .map(|cached| cached.stored.clone())
            .ok_or_else(|| Error::not_found("Fixture capture unavailable."))
    }
    async fn publish(
        &self,
        request: &FetchRequest,
        response: FetchResponse,
        now: i64,
    ) -> Result<StoredCapture> {
        let stored = StoredCapture {
            capture: Capture {
                id: digest(format!("{}:{}:{now}", request.key, digest(&response.body)).as_bytes()),
                key: request.key.clone(),
                source_url: request.url.clone(),
                body_hash: digest(&response.body),
                media_type: request.media_type.clone(),
                retrieved_at: now,
                validated_at: now,
            },
            body: Body::from(response.body),
        };
        self.data.lock().await.captures.insert(
            request.key.clone(),
            Cached {
                stored: stored.clone(),
                validators: response.validators,
            },
        );
        Ok(stored)
    }
    async fn revalidate(
        &self,
        key: &str,
        _: &str,
        validators: Validators,
        now: i64,
    ) -> Result<StoredCapture> {
        let mut data = self.data.lock().await;
        let cached = data
            .captures
            .get_mut(key)
            .ok_or_else(|| Error::not_found("Fixture capture unavailable."))?;
        cached.stored.capture.validated_at = now;
        cached.validators = validators;
        Ok(cached.stored.clone())
    }
}
#[async_trait]
impl AdvisoryStore for Memory {
    async fn publish_advisory_snapshot(
        &self,
        snapshot: &AdvisorySnapshot,
        make_default: bool,
    ) -> Result<()> {
        let mut data = self.data.lock().await;
        data.snapshots.insert(snapshot.id.clone(), snapshot.clone());
        if make_default {
            data.defaults
                .insert(snapshot.format.clone(), snapshot.id.clone());
        }
        Ok(())
    }
    async fn publish_current_advisory(
        &self,
        snapshot: &AdvisorySnapshot,
        attempt: &AdvisoryCurrentDiagnostic,
    ) -> std::result::Result<(), AdvisoryPublicationError> {
        match self.publication.load(Ordering::SeqCst) {
            1 => return Err(Error::unavailable("Fixture publication rejected.").into()),
            2 => {
                return Err(AdvisoryPublicationError::CommitUnknown(Error::unavailable(
                    "Fixture commit response lost.",
                )));
            }
            _ => {}
        }
        {
            let mut data = self.data.lock().await;
            let mut succeeded = attempt.clone();
            succeeded.outcome = AdvisoryAttemptOutcome::Succeeded;
            succeeded.finished_at = Some(devres_domain::unix_now().max(attempt.started_at));
            data.snapshots.insert(snapshot.id.clone(), snapshot.clone());
            data.defaults.insert("rustsec".into(), snapshot.id.clone());
            data.states.insert("current".into(), json!({"last_attempt":attempt.started_at,"last_success":snapshot.validated_at,"snapshot":snapshot.id,"error":null}));
            data.states
                .insert(CURRENT_DIAGNOSTICS_KEY.into(), json!(succeeded));
        }
        if self.publication.load(Ordering::SeqCst) >= 3 {
            if self.publication.load(Ordering::SeqCst) == 4 {
                self.readback_failures.store(1, Ordering::SeqCst);
            }
            return Err(AdvisoryPublicationError::CommitUnknown(Error::unavailable(
                "Fixture committed response lost.",
            )));
        }
        Ok(())
    }
    async fn finish_current_advisory_attempt(
        &self,
        attempt: &AdvisoryCurrentDiagnostic,
    ) -> Result<bool> {
        let mut data = self.data.lock().await;
        let previous = data.states.get(CURRENT_DIAGNOSTICS_KEY).unwrap();
        if previous["attempt"] != attempt.attempt || previous["outcome"] == "succeeded" {
            return Ok(false);
        }
        data.states
            .insert(CURRENT_DIAGNOSTICS_KEY.into(), json!(attempt));
        if attempt.outcome == AdvisoryAttemptOutcome::Failed {
            let public = data
                .states
                .entry("current".into())
                .or_insert_with(|| json!({}));
            public["last_attempt"] = json!(attempt.started_at);
            public["error"] = json!(attempt.failure.as_ref().unwrap().code);
            public["previous_snapshot_preserved"] = json!(true);
        }
        Ok(true)
    }
    async fn reconcile_current_advisory_attempt(&self) -> Result<AdvisoryAttemptOutcome> {
        let mut data = self.data.lock().await;
        let attempt = data.states.get_mut(CURRENT_DIAGNOSTICS_KEY).unwrap();
        if attempt["outcome"] == "succeeded" {
            return Ok(AdvisoryAttemptOutcome::Succeeded);
        }
        // The fixture transaction is fully synchronous under Data's single mutex.
        attempt["outcome"] = json!("failed");
        Ok(AdvisoryAttemptOutcome::Failed)
    }
    async fn advisory_snapshot(
        &self,
        id: Option<&str>,
        format: &str,
    ) -> Result<Option<AdvisorySnapshot>> {
        let data = self.data.lock().await;
        let id = id.or_else(|| data.defaults.get(format).map(String::as_str));
        Ok(id
            .and_then(|id| data.snapshots.get(id))
            .filter(|snapshot| snapshot.format == format)
            .cloned())
    }
    async fn advisory_rows(
        &self,
        _: &str,
        _: Option<i64>,
        _: i64,
        _: usize,
    ) -> Result<Vec<AdvisoryRow>> {
        Ok(vec![])
    }
    async fn advisory_row(&self, _: &str, _: &str) -> Result<Option<AdvisoryRow>> {
        Ok(None)
    }
    async fn advisory_cutoff(&self) -> Result<i64> {
        Ok(0)
    }
    async fn advisory_ref_rows(
        &self,
        _: &str,
        _: i64,
        _: i64,
        _: usize,
    ) -> Result<Vec<AdvisoryRow>> {
        Ok(vec![])
    }
    async fn put_advisory_row(&self, _: &str, _: &str, _: &Value) -> Result<()> {
        Ok(())
    }
    async fn advisory_state(&self, key: &str) -> Result<Option<Value>> {
        if key == CURRENT_DIAGNOSTICS_KEY
            && self
                .readback_failures
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                    value.checked_sub(1)
                })
                .is_ok()
        {
            return Err(Error::unavailable("Fixture readback unavailable."));
        }
        Ok(self.data.lock().await.states.get(key).cloned())
    }
    async fn set_advisory_state(&self, key: &str, value: &Value) -> Result<()> {
        self.data
            .lock()
            .await
            .states
            .insert(key.into(), value.clone());
        Ok(())
    }
    async fn advisory_status(&self) -> Result<Value> {
        Ok(json!({}))
    }
}
#[derive(Default)]
struct Source {
    mode: AtomicUsize,
    calls: AtomicUsize,
}
#[async_trait]
impl Fetcher for Source {
    async fn fetch(&self, request: &FetchRequest, _: Option<&Validators>) -> Result<FetchResponse> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mode = self.mode.load(Ordering::SeqCst);
        let (status, body) = if request.key == "rustsec:head" {
            match mode {
                1 => (503, b"secret upstream response".to_vec()),
                2 => (429, b"secret rate limit body".to_vec()),
                3 => (200, b"invalid head private diagnostic".to_vec()),
                _ => (200, serde_json::to_vec(&json!({"sha":REVISION})).unwrap()),
            }
        } else {
            match mode {
                4 => (503, b"secret bundle upstream response".to_vec()),
                5 => (200, b"malformed fixture archive".to_vec()),
                _ => (
                    200,
                    include_bytes!("../../tests/fixtures/rustsec/git-snapshot-minimal.tar.gz")
                        .to_vec(),
                ),
            }
        };
        Ok(FetchResponse {
            status,
            body,
            validators: Validators::default(),
        })
    }
}
async fn fixture() -> (tempfile::TempDir, Arc<Memory>, Arc<Source>, AdvisoryCorpus) {
    let root = tempfile::tempdir().unwrap();
    let memory = Arc::new(Memory::default());
    for format in ["rustsec", "osv"] {
        let snapshot = AdvisorySnapshot {
            id: digest(format.as_bytes()),
            revision: "0".repeat(40),
            format: format.into(),
            created_at: 10,
            validated_at: Some(10),
            historical: false,
            complete: true,
            records: vec![],
            captures: vec![],
            coverage: json!({}),
            parents: vec![],
            committed_at: 0,
        };
        memory
            .publish_advisory_snapshot(&snapshot, true)
            .await
            .unwrap();
    }
    memory.set_advisory_state("current", &json!({"last_attempt":10,"last_success":10,"snapshot":digest(b"rustsec"),"error":null})).await.unwrap();
    let source = Arc::new(Source::default());
    let retrieval = Arc::new(Retrieval::new(memory.clone(), source.clone()));
    let corpus = AdvisoryCorpus::new(
        retrieval,
        memory.clone(),
        Arc::new(BulkBroker::new(Default::default()).unwrap()),
        root.path(),
        RustSecConfig {
            min_free_bytes: 64 * 1024 * 1024,
            ..Default::default()
        },
    )
    .unwrap();
    (root, memory, source, corpus)
}
// Shared archive admission is tested separately. Deterministic source/transaction
// fixtures retry only this pre-parser admission race, never a provider failure.
async fn refresh_fixture(corpus: &AdvisoryCorpus) -> Result<Value> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match corpus.refresh_current().await {
            Err(error)
                if error.code == "capacity"
                    && error.message == "Archive parser capacity exhausted."
                    && tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(1)).await
            }
            result => return result,
        }
    }
}
#[tokio::test]
async fn current_stages_preserve_both_defaults_and_sanitize_failures() {
    for (mode, stage, status) in [
        (1, "head", Some(503)),
        (2, "head", Some(429)),
        (3, "head", None),
        (4, "bundle", Some(503)),
        (5, "normalization", None),
    ] {
        let (_root, memory, source, corpus) = fixture().await;
        source.mode.store(mode, Ordering::SeqCst);
        assert!(refresh_fixture(&corpus).await.is_err());
        let diagnostic = memory
            .advisory_state(CURRENT_DIAGNOSTICS_KEY)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(diagnostic["stage"], stage);
        assert_eq!(diagnostic["failure"]["http_status"].as_u64(), status);
        assert_eq!(diagnostic["outcome"], "failed");
        assert!(!diagnostic.to_string().contains("secret"));
        assert!(!diagnostic.to_string().contains("private diagnostic"));
        let public = memory.advisory_state("current").await.unwrap().unwrap();
        assert_eq!(public["last_success"], 10);
        assert_eq!(public["snapshot"], digest(b"rustsec"));
        assert_eq!(public["previous_snapshot_preserved"], true);
        for format in ["rustsec", "osv"] {
            assert_eq!(
                memory
                    .advisory_snapshot(None, format)
                    .await
                    .unwrap()
                    .unwrap()
                    .id,
                digest(format.as_bytes())
            );
        }
    }
}
#[tokio::test]
async fn stale_head_cannot_become_fresh_and_late_failure_cannot_erase_success() {
    let (_root, memory, source, corpus) = fixture().await;
    let first = refresh_fixture(&corpus).await.unwrap();
    let mut success: AdvisoryCurrentDiagnostic = serde_json::from_value(
        memory
            .advisory_state(CURRENT_DIAGNOSTICS_KEY)
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    success.outcome = AdvisoryAttemptOutcome::Failed;
    success.failure = Some(Failure::from_error(
        &Error::unavailable("late fixture failure"),
        Phase::ViewPublication,
        devres_domain::unix_now(),
    ));
    assert!(
        !memory
            .finish_current_advisory_attempt(&success)
            .await
            .unwrap()
    );
    let calls = source.calls.load(Ordering::SeqCst);
    source.mode.store(1, Ordering::SeqCst);
    assert!(refresh_fixture(&corpus).await.is_err());
    assert_eq!(
        memory
            .advisory_snapshot(None, "rustsec")
            .await
            .unwrap()
            .unwrap()
            .id,
        first["snapshot"]["id"]
    );
    assert_eq!(
        memory
            .advisory_state(CURRENT_DIAGNOSTICS_KEY)
            .await
            .unwrap()
            .unwrap()["outcome"],
        "failed"
    );
    assert_eq!(source.calls.load(Ordering::SeqCst), calls + 1);
}
#[tokio::test]
async fn current_publication_rejection_and_commit_response_loss_are_distinct() {
    for mode in [1, 2, 3, 4] {
        let (_root, memory, source, corpus) = fixture().await;
        memory.publication.store(mode, Ordering::SeqCst);
        let result = refresh_fixture(&corpus).await;
        if mode == 3 {
            assert!(result.is_ok());
        } else {
            assert!(result.is_err());
        }
        let diagnostic = memory
            .advisory_state(CURRENT_DIAGNOSTICS_KEY)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            diagnostic["outcome"],
            match mode {
                1 => "failed",
                2 => "unknown",
                _ => "succeeded",
            }
        );
        if mode == 2 {
            let calls = source.calls.load(Ordering::SeqCst);
            assert_eq!(
                memory.advisory_state("current").await.unwrap().unwrap()["last_success"],
                10
            );
            corpus.reconcile_interrupted_current().await.unwrap();
            assert_eq!(source.calls.load(Ordering::SeqCst), calls);
            assert_eq!(
                memory
                    .advisory_state(CURRENT_DIAGNOSTICS_KEY)
                    .await
                    .unwrap()
                    .unwrap()["outcome"],
                "failed"
            );
            memory.publication.store(0, Ordering::SeqCst);
            assert!(refresh_fixture(&corpus).await.is_ok());
        }
        assert_eq!(
            memory
                .advisory_snapshot(None, "osv")
                .await
                .unwrap()
                .unwrap()
                .id,
            digest(b"osv")
        );
    }
}
