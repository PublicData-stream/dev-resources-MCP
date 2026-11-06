use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Mutex;

#[derive(Default)]
struct Memory {
    queued: Mutex<Vec<AttributionTarget>>,
    ready: Mutex<Option<QualifiedAttribution>>,
    failures: AtomicUsize,
    attempts: AtomicUsize,
    last_retry: Mutex<Option<i64>>,
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
    ) -> Result<Option<AttributionJob>> {
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
