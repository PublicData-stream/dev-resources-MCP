//! Opt-in, fixed-size private status timing. No caller/source values are retained.
use devres_domain::Result;
use std::{
    future::Future,
    sync::{Arc, Mutex},
    time::Instant,
};

#[derive(Clone, Copy)]
pub enum Stage {
    SavedState,
    Statistics,
    KindInventory,
    EvidencePage,
    Defaults,
    Attribution,
    WriterToken,
    WriterTransport,
}
impl Stage {
    fn name(self) -> &'static str {
        match self {
            Self::SavedState => "saved_state",
            Self::Statistics => "statistics",
            Self::KindInventory => "kind_inventory",
            Self::EvidencePage => "evidence_page",
            Self::Defaults => "defaults",
            Self::Attribution => "attribution",
            Self::WriterToken => "writer_token",
            Self::WriterTransport => "writer_transport",
        }
    }
}
#[derive(Clone, Copy, Default)]
struct Summary {
    calls: u64,
    micros: u64,
    failed: u64,
    cancelled: u64,
    reason: &'static str,
}
tokio::task_local! { static RECORD: Arc<Mutex<[Summary;8]>>; }
struct Emit(Arc<Mutex<[Summary; 8]>>);
impl Drop for Emit {
    fn drop(&mut self) {
        let Ok(record) = self.0.lock() else { return };
        for stage in [
            Stage::SavedState,
            Stage::Statistics,
            Stage::KindInventory,
            Stage::EvidencePage,
            Stage::Defaults,
            Stage::Attribution,
            Stage::WriterToken,
            Stage::WriterTransport,
        ] {
            let entry = record[stage as usize];
            if entry.calls > 0 {
                tracing::debug!(target:"devres_private_timings",status_stage=stage.name(),calls=entry.calls,elapsed_micros=entry.micros,failed=entry.failed,cancelled=entry.cancelled,reason=entry.reason,"status operation");
            }
        }
    }
}
struct Span {
    record: Option<Arc<Mutex<[Summary; 8]>>>,
    stage: Stage,
    start: Instant,
    reason: Option<&'static str>,
}
impl Drop for Span {
    fn drop(&mut self) {
        if let Some(record) = &self.record
            && let Ok(mut record) = record.lock()
        {
            let entry = &mut record[self.stage as usize];
            entry.calls = entry.calls.saturating_add(1);
            entry.micros = entry.micros.saturating_add(
                u64::try_from(self.start.elapsed().as_micros()).unwrap_or(u64::MAX),
            );
            match self.reason {
                Some("ok") => {}
                Some(reason) => {
                    entry.failed = entry.failed.saturating_add(1);
                    if entry.reason.is_empty() {
                        entry.reason = reason;
                    }
                }
                None => {
                    entry.cancelled = entry.cancelled.saturating_add(1);
                    if entry.reason.is_empty() {
                        entry.reason = "cancelled";
                    }
                }
            }
        }
    }
}
pub async fn scope<T>(future: impl Future<Output = T>) -> T {
    if !tracing::enabled!(target:"devres_private_timings",tracing::Level::DEBUG)
        || RECORD.try_with(|_| ()).is_ok()
    {
        return future.await;
    }
    let record = Arc::new(Mutex::new([Summary::default(); 8]));
    let _emit = Emit(record.clone());
    RECORD.scope(record, future).await
}
pub async fn stage<T>(stage: Stage, future: impl Future<Output = Result<T>>) -> Result<T> {
    let mut span = Span {
        record: RECORD.try_with(Clone::clone).ok(),
        stage,
        start: Instant::now(),
        reason: None,
    };
    let result = future.await;
    span.reason = Some(match &result {
        Ok(_) => "ok",
        Err(error) => match error.code.as_str() {
            "unavailable" => "unavailable",
            "integrity" => "integrity",
            "capacity" => "capacity",
            "invalid" | "invalid_input" => "invalid",
            _ => "unknown",
        },
    });
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn fixed_record_preserves_first_failure_and_cancellation_without_messages() {
        let record = Arc::new(Mutex::new([Summary::default(); 8]));
        RECORD
            .scope(record.clone(), async {
                stage(Stage::SavedState, async {
                    Err::<(), _>(devres_domain::Error::unavailable("secret://sentinel"))
                })
                .await
                .unwrap_err();
                stage(Stage::SavedState, async { Ok(()) }).await.unwrap();
                let future = stage(Stage::Attribution, std::future::pending::<Result<()>>());
                assert!(
                    tokio::time::timeout(std::time::Duration::from_millis(1), future)
                        .await
                        .is_err()
                );
            })
            .await;
        let record = record.lock().unwrap();
        assert_eq!(record[0].calls, 2);
        assert_eq!(record[0].failed, 1);
        assert_eq!(record[0].reason, "unavailable");
        assert_eq!(record[Stage::Attribution as usize].cancelled, 1);
    }
}
