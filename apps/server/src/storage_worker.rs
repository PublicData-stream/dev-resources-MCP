//! Recover durable corpus workers after temporary object-storage unavailability.
//! Database ownership remains supervised independently by the required owner task.
use devres_domain::Result;
use std::{future::Future, time::Duration};
use tokio_util::sync::CancellationToken;

pub(crate) async fn run<F, T>(
    recover_archive: bool,
    shutdown: CancellationToken,
    mut worker: F,
) -> Result<()>
where
    F: FnMut(CancellationToken) -> T,
    T: Future<Output = Result<()>>,
{
    loop {
        if shutdown.is_cancelled() {
            return Ok(());
        }
        let attempt = shutdown.child_token();
        let attempt_guard = attempt.clone().drop_guard();
        let result = worker(attempt).await;
        drop(attempt_guard);
        if !recover_archive || !matches!(&result, Err(error) if error.code == "unavailable") {
            return result;
        }
        // Interrupted work retains its durable leases/checkpoints and evidence.
        // Source HTTP retries remain owned by the existing acquisition paths.
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => return Ok(()),
            _ = tokio::time::sleep(Duration::from_secs(1)) => {},
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use devres_domain::Error;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[tokio::test]
    async fn archive_lane_retries_unavailability_and_recovers() {
        let mut attempts = 0;
        let mut previous: Option<CancellationToken> = None;
        let shutdown = CancellationToken::new();
        run(true, shutdown.clone(), |attempt| {
            if let Some(previous) = &previous {
                assert!(
                    previous.is_cancelled(),
                    "previous attempt still owns live work"
                );
            }
            assert!(!attempt.is_cancelled());
            previous = Some(attempt);
            attempts += 1;
            let result = if attempts == 1 {
                Err(Error::unavailable("Object storage unavailable."))
            } else {
                Ok(())
            };
            std::future::ready(result)
        })
        .await
        .expect("recovery");
        assert_eq!(attempts, 2);
        assert!(previous.expect("last attempt").is_cancelled());
        assert!(!shutdown.is_cancelled());
    }

    #[tokio::test]
    async fn already_cancelled_shutdown_does_not_start_work() {
        let shutdown = CancellationToken::new();
        shutdown.cancel();
        let mut attempts = 0;
        run(true, shutdown, |_| {
            attempts += 1;
            std::future::ready(Ok(()))
        })
        .await
        .expect("cancelled lane");
        assert_eq!(attempts, 0);
    }

    #[tokio::test]
    async fn filesystem_and_integrity_failures_still_stop_the_lane() {
        for (archive, error) in [
            (false, Error::unavailable("Storage unavailable.")),
            (true, Error::integrity("Invalid retained evidence.")),
        ] {
            let mut attempts = 0;
            let result = run(archive, CancellationToken::new(), |_| {
                attempts += 1;
                std::future::ready(Err(error.clone()))
            })
            .await;
            assert!(result.is_err());
            assert_eq!(attempts, 1);
        }
    }

    #[tokio::test]
    async fn shutdown_interrupts_outage_backoff_without_restarting_work() {
        let cancel = CancellationToken::new();
        let attempts = Arc::new(AtomicUsize::new(0));
        let observed = attempts.clone();
        let stopping = cancel.clone();
        let lane = tokio::spawn(async move {
            run(true, stopping, |_| {
                observed.fetch_add(1, Ordering::SeqCst);
                std::future::ready(Err(Error::unavailable("Object storage unavailable.")))
            })
            .await
        });
        while attempts.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(1), lane)
            .await
            .expect("bounded shutdown")
            .expect("task")
            .expect("cancelled lane");
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }
}
