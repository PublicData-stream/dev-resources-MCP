use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Mutex;

struct VisibilityAcquirer {
    checks: AtomicUsize,
    block_at: usize,
}
fn wikipedia_subject() -> AttributionSubject {
    let mut subject = target().subject;
    subject.provider = "wikipedia".into();
    subject
}
#[async_trait]
impl AttributionAcquirer for VisibilityAcquirer {
    fn targets(&self, _: &str, _: &Value) -> Result<Vec<AttributionTarget>> {
        Ok(vec![AttributionTarget {
            subject: wikipedia_subject(),
            evidence: json!({}),
        }])
    }
    async fn repair(
        &self,
        _: &AttributionTarget,
        _: CancellationToken,
    ) -> Result<AttributionGeneration> {
        Err(Error::integrity(
            "Visibility test must use already qualified evidence.",
        ))
    }
    async fn ensure_public(&self, subject: &AttributionSubject) -> Result<()> {
        assert_eq!(*subject, wikipedia_subject());
        if self.checks.fetch_add(1, Ordering::SeqCst) + 1 >= self.block_at {
            return Err(Error::new("wikipedia_withheld", "Source withdrawn."));
        }
        Ok(())
    }
}
#[tokio::test]
async fn current_visibility_overrides_ready_attribution_and_known_bundle_urls() {
    for block_at in [1, 2, 3] {
        let store = Arc::new(Memory::default());
        let mut generation = generation();
        generation.subject = wikipedia_subject();
        *store.ready.lock().await = Some(QualifiedAttribution {
            id: format!("blake3:{}", "a".repeat(64)),
            generation,
        });
        let runtime = AttributionRuntime::new(
            store,
            Arc::new(VisibilityAcquirer {
                checks: AtomicUsize::new(0),
                block_at,
            }),
            vec!["wikipedia".into()],
        )
        .unwrap();
        assert_eq!(
            runtime
                .qualify("wikipedia", &json!({}))
                .await
                .unwrap_err()
                .code,
            "wikipedia_withheld"
        );
    }
    for block_at in [1, 2] {
        let store = Arc::new(Memory::default());
        let mut generation = generation();
        generation.subject = wikipedia_subject();
        *store.ready.lock().await = Some(QualifiedAttribution {
            id: format!("blake3:{}", "a".repeat(64)),
            generation,
        });
        let runtime = AttributionRuntime::new(
            store,
            Arc::new(VisibilityAcquirer {
                checks: AtomicUsize::new(0),
                block_at,
            }),
            vec!["wikipedia".into()],
        )
        .unwrap();
        assert_eq!(
            runtime
                .bundle(&format!("blake3:{}", "a".repeat(64)), 0, 8)
                .await
                .unwrap_err()
                .code,
            "wikipedia_withheld"
        );
    }
}

#[derive(Default)]
struct Memory {
    queued: Mutex<Vec<AttributionTarget>>,
    ready: Mutex<Option<QualifiedAttribution>>,
    failures: AtomicUsize,
    attempts: AtomicUsize,
    last_retry: Mutex<Option<i64>>,
    classifications: Mutex<Vec<AttributionFailure>>,
    claim_capacity: AtomicUsize,
    admissions: Mutex<Vec<u64>>,
    completion_capacity: AtomicUsize,
}
#[async_trait]
impl AttributionStore for Memory {
    async fn attribution_enqueue(&self, t: &AttributionTarget, _: u8) -> Result<()> {
        let mut q = self.queued.lock().await;
        if !q.contains(t) {
            q.push(t.clone());
        }
        Ok(())
    }
    async fn attribution_ready(
        &self,
        _: &AttributionSubject,
    ) -> Result<Option<QualifiedAttribution>> {
        Ok(self.ready.lock().await.clone())
    }
    async fn attribution_claim(
        &self,
        enabled: &[String],
        _: i64,
        admission: u64,
    ) -> Result<Option<AttributionJob>> {
        self.admissions.lock().await.push(admission);
        if self
            .claim_capacity
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            return Err(Error::capacity("Bounded claim deadline."));
        }
        let mut q = self.queued.lock().await;
        if let Some(i) = q.iter().position(|t| enabled.contains(&t.subject.provider)) {
            Ok(Some(AttributionJob {
                target: q.remove(i),
                claim: "owner".into(),
                attempts: u32::try_from(self.attempts.load(Ordering::SeqCst))
                    .unwrap_or(u32::MAX)
                    .saturating_add(1),
            }))
        } else {
            Ok(None)
        }
    }
    async fn attribution_complete(
        &self,
        _: &AttributionJob,
        g: &AttributionGeneration,
    ) -> Result<()> {
        if self
            .completion_capacity
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            return Err(Error::capacity("Proof bound exceeded."));
        }
        *self.ready.lock().await = Some(QualifiedAttribution {
            id: format!("blake3:{}", "a".repeat(64)),
            generation: g.clone(),
        });
        Ok(())
    }
    async fn attribution_fail(
        &self,
        _: &AttributionJob,
        retry: Option<i64>,
        _: &str,
    ) -> Result<()> {
        *self.last_retry.lock().await = retry;
        self.failures.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn attribution_fail_classified(
        &self,
        job: &AttributionJob,
        retry_at: Option<i64>,
        code: &str,
        classification: &AttributionFailure,
    ) -> Result<()> {
        self.classifications.lock().await.push(*classification);
        self.attribution_fail(job, retry_at, code).await
    }
    async fn attribution_sweep_page(&self, _: &str) -> Result<Vec<AttributionTarget>> {
        Ok(vec![])
    }
    async fn attribution_bundle(&self, _: &str) -> Result<QualifiedAttribution> {
        self.ready
            .lock()
            .await
            .clone()
            .ok_or_else(|| Error::not_found("absent"))
    }
    async fn attribution_status(&self) -> Result<Value> {
        Ok(json!({}))
    }
}

struct FailedSource(&'static str);
#[async_trait]
impl AttributionAcquirer for FailedSource {
    fn targets(&self, _: &str, _: &Value) -> Result<Vec<AttributionTarget>> {
        Ok(vec![target()])
    }
    async fn repair(
        &self,
        _: &AttributionTarget,
        _: CancellationToken,
    ) -> Result<AttributionGeneration> {
        Err(Error::new(self.0, "Fixed source failure"))
    }
}
#[tokio::test]
async fn long_outages_remain_recoverable_but_confirmed_absence_is_blocked() {
    for (code, retryable) in [("unavailable", true), ("not_found", false)] {
        let store = Arc::new(Memory::default());
        store.attempts.store(100, Ordering::SeqCst);
        store.attribution_enqueue(&target(), 1).await.unwrap();
        let runtime = AttributionRuntime::new(
            store.clone(),
            Arc::new(FailedSource(code)),
            vec!["mdn".into()],
        )
        .unwrap();
        let cancel = CancellationToken::new();
        let stop = cancel.clone();
        let task = tokio::spawn(async move { runtime.run(stop).await });
        tokio::time::timeout(Duration::from_secs(2), async {
            while store.failures.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let retry = *store.last_retry.lock().await;
        assert_eq!(retry.is_some(), retryable);
        if let Some(retry) = retry {
            assert!(retry <= devres_domain::unix_now() + 60 * 1024);
        }
        assert!(store.ready.lock().await.is_none());
        cancel.cancel();
        task.await.unwrap().unwrap();
    }
}
struct Acquirer {
    calls: AtomicUsize,
    stalled: bool,
}
fn target() -> AttributionTarget {
    AttributionTarget {
        subject: AttributionSubject {
            provider: "mdn".into(),
            namespace: "source".into(),
            key: "revision/path".into(),
            fingerprint: format!("blake3:{}", "b".repeat(64)),
        },
        evidence: json!({"source_url":"https://example.invalid/original"}),
    }
}
fn generation() -> AttributionGeneration {
    AttributionGeneration {
        subject: target().subject,
        policy_epoch: ATTRIBUTION_POLICY_EPOCH,
        policy_fingerprint: ATTRIBUTION_POLICY_FINGERPRINT.into(),
        notices: vec![AttributionNotice {
            source_url: "https://example.invalid/original".into(),
            license: Some("MIT".into()),
            copyright: None,
            text: "가나다 original notice".into(),
            evidence: json!({}),
        }],
        receipts: vec![json!({"status":200,"body_hash":"exact"})],
    }
}
#[async_trait]
impl AttributionAcquirer for Acquirer {
    fn targets(&self, _: &str, _: &Value) -> Result<Vec<AttributionTarget>> {
        Ok(vec![target()])
    }
    async fn repair(
        &self,
        _: &AttributionTarget,
        cancel: CancellationToken,
    ) -> Result<AttributionGeneration> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.stalled {
            cancel.cancelled().await;
            return Err(Error::unavailable("cancelled"));
        }
        Ok(generation())
    }
}
fn runtime(store: Arc<Memory>, acquirer: Arc<Acquirer>, enabled: bool) -> AttributionRuntime {
    AttributionRuntime::new(
        store,
        acquirer,
        if enabled { vec!["mdn".into()] } else { vec![] },
    )
    .unwrap()
}
#[tokio::test]
async fn pending_reads_coalesce_and_only_worker_can_qualify() {
    let store = Arc::new(Memory::default());
    let acquirer = Arc::new(Acquirer {
        calls: AtomicUsize::new(0),
        stalled: false,
    });
    let runtime = Arc::new(runtime(store.clone(), acquirer.clone(), true));
    for _ in 0..2 {
        assert_eq!(
            runtime.qualify("mdn", &json!({})).await.unwrap_err().code,
            "unavailable"
        );
    }
    assert_eq!(store.queued.lock().await.len(), 1);
    assert_eq!(acquirer.calls.load(Ordering::SeqCst), 0);
    let cancel = CancellationToken::new();
    let worker = runtime.clone();
    let stop = cancel.clone();
    let task = tokio::spawn(async move { worker.run(stop).await });
    tokio::time::timeout(Duration::from_secs(2), async {
        while store.ready.lock().await.is_none() {
            tokio::task::yield_now().await
        }
    })
    .await
    .unwrap();
    let value = runtime.qualify("mdn", &json!({})).await.unwrap();
    assert_eq!(value["status"], "ready");
    assert!(
        value["readable_notice"]
            .as_str()
            .unwrap()
            .contains("original notice")
    );
    assert!(value["generations"][0].get("receipts").is_none());
    cancel.cancel();
    task.await.unwrap().unwrap();
    assert_eq!(acquirer.calls.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn audit_does_not_queue_and_old_policy_is_not_ready() {
    let store = Arc::new(Memory::default());
    let acquirer = Arc::new(Acquirer {
        calls: AtomicUsize::new(0),
        stalled: false,
    });
    let runtime = runtime(store.clone(), acquirer, false);
    assert!(
        runtime
            .qualify("audit:mdn", &json!({"snapshot":"public"}))
            .await
            .is_err()
    );
    assert!(store.queued.lock().await.is_empty());
    let mut g = generation();
    g.policy_epoch = 0;
    *store.ready.lock().await = Some(QualifiedAttribution {
        id: format!("blake3:{}", "a".repeat(64)),
        generation: g,
    });
    assert!(runtime.qualify("mdn", &json!({})).await.is_err());
    assert_eq!(store.queued.lock().await.len(), 1);
}
#[tokio::test]
async fn disabled_provider_never_acquires_and_cancellation_releases_claim() {
    let store = Arc::new(Memory::default());
    let acquirer = Arc::new(Acquirer {
        calls: AtomicUsize::new(0),
        stalled: true,
    });
    store.attribution_enqueue(&target(), 1).await.unwrap();
    let disabled = runtime(store.clone(), acquirer.clone(), false);
    let cancel = CancellationToken::new();
    cancel.cancel();
    disabled.run(cancel).await.unwrap();
    assert_eq!(acquirer.calls.load(Ordering::SeqCst), 0);
    let runtime = runtime(store.clone(), acquirer.clone(), true);
    let cancel = CancellationToken::new();
    let stop = cancel.clone();
    let task = tokio::spawn(async move { runtime.run(stop).await });
    while acquirer.calls.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }
    cancel.cancel();
    task.await.unwrap().unwrap();
    assert_eq!(store.failures.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn immutable_notice_pages_do_not_repeat_unbounded_generation_payloads() {
    let store = Arc::new(Memory::default());
    *store.ready.lock().await = Some(QualifiedAttribution {
        id: format!("blake3:{}", "a".repeat(64)),
        generation: generation(),
    });
    let runtime = runtime(
        store,
        Arc::new(Acquirer {
            calls: AtomicUsize::new(0),
            stalled: false,
        }),
        false,
    );
    let value = runtime
        .bundle(&format!("blake3:{}", "a".repeat(64)), 0, 8)
        .await
        .unwrap();
    assert!(value["contents"][0]["text"].as_str().unwrap().len() <= 8);
    assert!(
        value["contents"][0]["_meta"]["attribution"]
            .get("generation")
            .is_none()
    );
    assert!(
        runtime
            .bundle(&format!("blake3:{}", "a".repeat(64)), 1, 8)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn historical_notice_uri_preserves_utf8_pages_without_qualifying_current_content() {
    let store = Arc::new(Memory::default());
    let mut historical = generation();
    historical.policy_epoch = 1;
    historical.policy_fingerprint =
        "devres-attribution-v1:exact-reacquisition:member-scopes:readable-notices".into();
    let expected = format!(
        "{}\n{}",
        historical.notices[0].source_url, historical.notices[0].text
    );
    let id = format!("blake3:{}", "a".repeat(64));
    *store.ready.lock().await = Some(QualifiedAttribution {
        id: id.clone(),
        generation: historical,
    });
    let runtime = runtime(
        store.clone(),
        Arc::new(Acquirer {
            calls: AtomicUsize::new(0),
            stalled: false,
        }),
        false,
    );
    let mut text = String::new();
    let mut offset = 0;
    loop {
        let page = runtime.bundle(&id, offset, 13).await.unwrap();
        assert_eq!(
            page["contents"][0]["_meta"]["attribution"]["policy_epoch"],
            1
        );
        text.push_str(page["contents"][0]["text"].as_str().unwrap());
        let Some(next) = page["contents"][0]["_meta"]["next_offset"].as_u64() else {
            break;
        };
        offset = usize::try_from(next).unwrap();
    }
    assert_eq!(text, expected);
    assert_eq!(
        runtime
            .qualify("audit:rfc", &json!({}))
            .await
            .unwrap_err()
            .code,
        "unavailable"
    );
    assert!(store.queued.lock().await.is_empty());
    store
        .ready
        .lock()
        .await
        .as_mut()
        .unwrap()
        .generation
        .policy_fingerprint = "unknown-policy".into();
    assert_eq!(
        runtime.bundle(&id, 0, 13).await.unwrap_err().code,
        "unavailable"
    );
}

struct PublicSchedulingDelegate(AtomicUsize);
#[async_trait]
impl crate::acquisition::AcquisitionDelegate for PublicSchedulingDelegate {
    async fn attribution_status(&self) -> Result<Value> {
        Ok(
            json!({"scan_gaps":{"mdn":"capacity"},"complete":false,"repair_complete_for_enqueued_targets":false}),
        )
    }

    async fn acquire(&self, _: crate::acquisition::Acquisition) -> Result<devres_domain::Capture> {
        Err(Error::integrity("Unexpected acquisition."))
    }
    async fn effect(&self, effect: crate::acquisition::WriterEffect) -> Result<()> {
        match effect {
            crate::acquisition::WriterEffect::AttributionEnqueue { target: queued } => {
                assert_eq!(queued, target())
            }
            _ => panic!("Unexpected source effect"),
        }
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
#[tokio::test]
async fn reader_schedules_public_notices_through_writer_but_audit_never_crosses_processes() {
    let store = Arc::new(Memory::default());
    let acquirer = Arc::new(Acquirer {
        calls: AtomicUsize::new(0),
        stalled: false,
    });
    let delegate = Arc::new(PublicSchedulingDelegate(AtomicUsize::new(0)));
    let reader = runtime(store.clone(), acquirer.clone(), true).with_delegate(delegate.clone());
    assert_eq!(
        reader
            .qualify("audit:mdn", &json!({"snapshot":"public-snapshot"}))
            .await
            .unwrap_err()
            .code,
        "unavailable"
    );
    assert_eq!(delegate.0.load(Ordering::SeqCst), 0);
    assert!(store.queued.lock().await.is_empty());
    assert_eq!(
        reader
            .qualify("mdn", &json!({"snapshot":"public-snapshot"}))
            .await
            .unwrap_err()
            .code,
        "unavailable"
    );
    assert_eq!(delegate.0.load(Ordering::SeqCst), 1);
    assert!(store.queued.lock().await.is_empty());
    assert_eq!(acquirer.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn reader_status_reports_writer_scan_gaps_instead_of_empty_local_state() {
    let store = Arc::new(Memory::default());
    let acquirer = Arc::new(Acquirer {
        calls: AtomicUsize::new(0),
        stalled: false,
    });
    let delegate = Arc::new(PublicSchedulingDelegate(AtomicUsize::new(0)));
    let reader = runtime(store, acquirer, true).with_delegate(delegate);
    let status = reader.status().await.unwrap();
    assert_eq!(status["scan_gaps"]["mdn"], "capacity");
    assert_eq!(status["complete"], false);
    assert_eq!(status["repair_complete_for_enqueued_targets"], false);
}

#[tokio::test(start_paused = true)]
async fn claim_capacity_recovers_without_advancing_admission_and_reports_gap() {
    let store = Arc::new(Memory::default());
    store.claim_capacity.store(1, Ordering::SeqCst);
    store.attribution_enqueue(&target(), 1).await.unwrap();
    let runtime = Arc::new(runtime(
        store.clone(),
        Arc::new(Acquirer {
            calls: AtomicUsize::new(0),
            stalled: false,
        }),
        true,
    ));
    let cancel = CancellationToken::new();
    let worker = runtime.clone();
    let stop = cancel.clone();
    let task = tokio::spawn(async move { worker.run(stop).await });
    while store.admissions.lock().await.is_empty() {
        tokio::task::yield_now().await;
    }
    let status = runtime.status().await.unwrap();
    assert_eq!(status["admission_gap"]["reason"], "admission_deferred");
    tokio::time::advance(Duration::from_secs(1)).await;
    while store.ready.lock().await.is_none() {
        tokio::task::yield_now().await;
    }
    assert_eq!(&store.admissions.lock().await[..2], &[0, 0]);
    assert!(runtime.status().await.unwrap()["admission_gap"].is_null());
    cancel.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn shutdown_interrupts_claim_backoff_without_another_claim() {
    let store = Arc::new(Memory::default());
    store.claim_capacity.store(100, Ordering::SeqCst);
    let runtime = Arc::new(runtime(
        store.clone(),
        Arc::new(Acquirer {
            calls: AtomicUsize::new(0),
            stalled: false,
        }),
        true,
    ));
    let cancel = CancellationToken::new();
    let worker = runtime.clone();
    let stop = cancel.clone();
    let task = tokio::spawn(async move { worker.run(stop).await });
    while store.admissions.lock().await.is_empty() {
        tokio::task::yield_now().await;
    }
    cancel.cancel();
    task.await.unwrap().unwrap();
    assert_eq!(store.admissions.lock().await.len(), 1);
}

struct ClassifiedSource(AttributionFailure);
#[async_trait]
impl AttributionAcquirer for ClassifiedSource {
    fn targets(&self, _: &str, _: &Value) -> Result<Vec<AttributionTarget>> {
        Ok(vec![target()])
    }
    async fn repair(
        &self,
        _: &AttributionTarget,
        _: CancellationToken,
    ) -> Result<AttributionGeneration> {
        Err(self.0.attach(Error::capacity("Sanitized source limit.")))
    }
}

#[tokio::test]
async fn typed_permanent_bounds_block_while_temporary_parser_admission_retries() {
    for (reason, disposition) in [
        (
            AttributionFailureReason::PayloadBound,
            AttributionDisposition::Blocked,
        ),
        (
            AttributionFailureReason::ParserBusy,
            AttributionDisposition::Retry,
        ),
        (
            AttributionFailureReason::MissingNotice,
            AttributionDisposition::Blocked,
        ),
    ] {
        let classification =
            AttributionFailure::new(AttributionPhase::Qualification, reason, disposition);
        let store = Arc::new(Memory::default());
        store.attribution_enqueue(&target(), 1).await.unwrap();
        let runtime = AttributionRuntime::new(
            store.clone(),
            Arc::new(ClassifiedSource(classification)),
            vec!["mdn".into()],
        )
        .unwrap();
        let cancel = CancellationToken::new();
        let stop = cancel.clone();
        let task = tokio::spawn(async move { runtime.run(stop).await });
        tokio::time::timeout(Duration::from_secs(2), async {
            while store.failures.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            store.last_retry.lock().await.is_some(),
            disposition == AttributionDisposition::Retry
        );
        assert_eq!(*store.classifications.lock().await, vec![classification]);
        assert!(store.ready.lock().await.is_none());
        cancel.cancel();
        task.await.unwrap().unwrap();
    }
}

#[tokio::test(start_paused = true)]
async fn acquisition_deadline_releases_claim_as_retry_after_cooperative_cancellation() {
    let store = Arc::new(Memory::default());
    store.attribution_enqueue(&target(), 1).await.unwrap();
    let acquirer = Arc::new(Acquirer {
        calls: AtomicUsize::new(0),
        stalled: true,
    });
    let runtime = runtime(store.clone(), acquirer.clone(), true);
    let cancel = CancellationToken::new();
    let stop = cancel.clone();
    let task = tokio::spawn(async move { runtime.run(stop).await });
    while acquirer.calls.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }
    tokio::time::advance(Duration::from_secs(240)).await;
    while store.failures.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }
    assert!(store.last_retry.lock().await.is_some());
    assert!(store.ready.lock().await.is_none());
    cancel.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn deterministic_publication_capacity_retains_blocked_classification() {
    let store = Arc::new(Memory::default());
    store.completion_capacity.store(1, Ordering::SeqCst);
    store.attribution_enqueue(&target(), 1).await.unwrap();
    let runtime = runtime(
        store.clone(),
        Arc::new(Acquirer {
            calls: AtomicUsize::new(0),
            stalled: false,
        }),
        true,
    );
    let cancel = CancellationToken::new();
    let stop = cancel.clone();
    let task = tokio::spawn(async move { runtime.run(stop).await });
    tokio::time::timeout(Duration::from_secs(2), async {
        while store.failures.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(store.last_retry.lock().await.is_none());
    assert_eq!(
        store.classifications.lock().await[0],
        AttributionFailure::new(
            AttributionPhase::Publication,
            AttributionFailureReason::PayloadBound,
            AttributionDisposition::Blocked
        )
    );
    cancel.cancel();
    task.await.unwrap().unwrap();
}
