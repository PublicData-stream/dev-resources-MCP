//! Bounded blocking work for private offline storage commands.
//!
//! A command passes one context through every nested migration/verification
//! phase. Cancellation is cooperative: callers must cancel the token and await
//! the operation, rather than aborting its async task and detaching workers.
use devres_domain::{Error, Result};
use futures::{StreamExt, stream::FuturesUnordered};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

pub const MIGRATION_WINDOW_RECORDS: usize = 128;

/// Offline execution limits, independent of mapping and seal-metadata limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MigrationExecutionOptions {
    pub workers: usize,
    pub payload_budget_bytes: usize,
}

impl MigrationExecutionOptions {
    pub fn new(workers: usize, payload_budget_bytes: usize) -> Result<Self> {
        if !(1..=64).contains(&workers) {
            return Err(Error::invalid("Offline workers must be between 1 and 64."));
        }
        if payload_budget_bytes == 0 {
            return Err(Error::invalid("Offline payload budget must be positive."));
        }
        Ok(Self {
            workers,
            payload_budget_bytes,
        })
    }
}

impl Default for MigrationExecutionOptions {
    fn default() -> Self {
        Self {
            workers: std::thread::available_parallelism()
                .map(|workers| workers.get().min(8))
                .unwrap_or(1),
            payload_budget_bytes: 64 * 1024 * 1024,
        }
    }
}

#[derive(Default)]
struct Counters {
    admitted: AtomicUsize,
    completed: AtomicUsize,
    active: AtomicUsize,
    high_water: AtomicUsize,
    window_high_water: AtomicUsize,
    worker_wait_micros: AtomicU64,
    publication_micros: AtomicU64,
}

/// Aggregate job counts. Jobs may contain multiple SQL records. These are not
/// unique retained-record counts, memory measurements, or completion percentages.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MigrationExecutionSnapshot {
    pub admitted: usize,
    pub completed: usize,
    pub active: usize,
    pub high_water: usize,
    pub window_high_water: usize,
    pub worker_wait_micros: u64,
    pub publication_micros: u64,
}

struct Progress {
    phases: std::collections::HashMap<String, (Instant, u64, u64, u64)>,
    phase: String,
    phase_started: Instant,
    last_report: Option<Instant>,
}

struct ProgressState {
    enabled: AtomicBool,
    started: Instant,
    current: Mutex<Progress>,
}

#[derive(Clone)]
pub struct MigrationExecution {
    options: MigrationExecutionOptions,
    permits: Arc<Semaphore>,
    counters: Arc<Counters>,
    progress: Arc<ProgressState>,
}

impl Default for MigrationExecution {
    fn default() -> Self {
        Self::from_validated(MigrationExecutionOptions::default())
    }
}

fn cancelled() -> Error {
    Error::new("cancelled", "Offline storage work canceled.")
}

impl MigrationExecution {
    pub fn new(options: MigrationExecutionOptions) -> Result<Self> {
        let options =
            MigrationExecutionOptions::new(options.workers, options.payload_budget_bytes)?;
        Ok(Self::from_validated(options))
    }

    fn from_validated(options: MigrationExecutionOptions) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(options.workers)),
            counters: Arc::new(Counters::default()),
            progress: Arc::new(ProgressState {
                enabled: AtomicBool::new(false),
                started: Instant::now(),
                current: Mutex::new(Progress {
                    phases: std::collections::HashMap::new(),
                    phase: String::new(),
                    phase_started: Instant::now(),
                    last_report: None,
                }),
            }),
            options,
        }
    }

    pub fn options(&self) -> MigrationExecutionOptions {
        self.options
    }

    pub fn snapshot(&self) -> MigrationExecutionSnapshot {
        MigrationExecutionSnapshot {
            admitted: self.counters.admitted.load(Ordering::Relaxed),
            completed: self.counters.completed.load(Ordering::Relaxed),
            active: self.counters.active.load(Ordering::Relaxed),
            high_water: self.counters.high_water.load(Ordering::Relaxed),
            window_high_water: self.counters.window_high_water.load(Ordering::Relaxed),
            worker_wait_micros: self.counters.worker_wait_micros.load(Ordering::Relaxed),
            publication_micros: self.counters.publication_micros.load(Ordering::Relaxed),
        }
    }

    /// Enable aggregate diagnostics for an offline CLI invocation. Adapter
    /// wrappers remain quiet unless the caller explicitly opts in.
    pub fn enable_progress(&self) {
        self.progress.enabled.store(true, Ordering::Relaxed);
    }

    /// Account coordinator publication/SQL wall time separately from worker
    /// waits. Durations are aggregate wall times, not CPU utilization.
    pub fn record_publication(&self, elapsed: Duration) {
        self.counters
            .publication_micros
            .fetch_add(micros(elapsed), Ordering::Relaxed);
    }

    /// Emit at most once per second, and always on a phase change. Callers use
    /// fixed internal phase names and counts from the current pass only.
    pub fn report(
        &self,
        phase: &str,
        admitted: u64,
        completed: u64,
        committed: u64,
        payload_bytes: usize,
    ) {
        if !self.progress.enabled.load(Ordering::Relaxed)
            || phase.is_empty()
            || phase.len() > 64
            || !phase
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return;
        }
        let Ok(mut current) = self.progress.current.lock() else {
            return;
        };
        let now = Instant::now();
        let changed = current.phase != phase;
        if !changed
            && current
                .last_report
                .is_some_and(|last| now.duration_since(last) < Duration::from_secs(1))
        {
            return;
        }
        // Each pass keeps its own clock across interleaved hash/commit reports.
        // Decreasing counters identify a new pass rather than continued work.
        if !current.phases.contains_key(phase) && current.phases.len() >= 256 {
            return;
        }
        let clock = current
            .phases
            .entry(phase.to_owned())
            .or_insert((now, 0, 0, 0));
        if admitted < clock.1 || completed < clock.2 || committed < clock.3 {
            clock.0 = now;
        }
        clock.1 = admitted;
        clock.2 = completed;
        clock.3 = committed;
        let phase_started = clock.0;
        current.phase = phase.to_owned();
        current.phase_started = phase_started;
        current.last_report = Some(now);
        let snapshot = self.snapshot();
        let phase_elapsed = now.duration_since(current.phase_started).as_secs_f64();
        let throughput = if phase_elapsed > 0.0 {
            completed as f64 / phase_elapsed
        } else {
            0.0
        };
        eprintln!(
            "{}",
            serde_json::json!({
                "event":"offline_storage_progress", "phase":phase,
                "workers":self.options.workers,
                "payload_budget_bytes":self.options.payload_budget_bytes,
                "admitted":admitted,"completed":completed,"committed":committed,
                "elapsed_secs":now.duration_since(self.progress.started).as_secs_f64(),
                "phase_elapsed_secs":phase_elapsed,"records_per_second":throughput,
                "active_jobs":snapshot.active,"jobs_high_water":snapshot.high_water,
                "window_high_water":snapshot.window_high_water,
                "payload_bytes":payload_bytes,
                "worker_wait_micros":snapshot.worker_wait_micros,
                "publication_micros":snapshot.publication_micros,
            })
        );
    }

    /// Acquire admission before submitting to Tokio's blocking pool. Every
    /// submitted handle is awaited even when its token becomes canceled.
    pub async fn run<T, F>(&self, cancel: &CancellationToken, work: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(CancellationToken) -> Result<T> + Send + 'static,
    {
        let waiting = Instant::now();
        let permit = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(cancelled()),
            permit = self.permits.clone().acquire_owned() => {
                permit.map_err(|_| Error::unavailable("Offline worker admission unavailable."))?
            }
        };
        if cancel.is_cancelled() {
            return Err(cancelled());
        }
        let counters = self.counters.clone();
        counters.admitted.fetch_add(1, Ordering::Relaxed);
        let active = counters.active.fetch_add(1, Ordering::Relaxed) + 1;
        counters.high_water.fetch_max(active, Ordering::Relaxed);
        let guard = CompletionGuard { counters };
        let cancel = cancel.clone();
        let result = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _guard = guard;
            if cancel.is_cancelled() {
                return Err(cancelled());
            }
            work(cancel)
        })
        .await
        .map_err(|_| Error::unavailable("Offline blocking worker failed."));
        self.counters
            .worker_wait_micros
            .fetch_add(micros(waiting.elapsed()), Ordering::Relaxed);
        result?
    }

    /// Process one bounded window, retaining results in admission order.
    /// Errors stop new admission; every already admitted operation is drained.
    /// A higher ordinal's error never cancels lower ordinal workers.
    pub async fn map_ordered<T, R, F>(
        &self,
        items: Vec<T>,
        cancel: &CancellationToken,
        work: F,
    ) -> Result<Vec<R>>
    where
        T: Send + 'static,
        R: Send + 'static,
        F: Fn(T, CancellationToken) -> Result<R> + Send + Sync + 'static,
    {
        if items.len() > MIGRATION_WINDOW_RECORDS {
            return Err(Error::capacity("Offline worker window exceeds its bound."));
        }
        if cancel.is_cancelled() {
            return Err(cancelled());
        }
        self.counters
            .window_high_water
            .fetch_max(items.len(), Ordering::Relaxed);
        let mut items = items.into_iter().enumerate();
        let work = Arc::new(work);
        let mut running = FuturesUnordered::new();
        let mut results = Vec::new();
        let mut failed = false;
        loop {
            while !failed && !cancel.is_cancelled() && running.len() < self.options.workers {
                let Some((ordinal, item)) = items.next() else {
                    break;
                };
                let work = work.clone();
                running.push(async move {
                    let result = self.run(cancel, move |token| work(item, token)).await;
                    (ordinal, result)
                });
            }
            let Some((ordinal, result)) = running.next().await else {
                break;
            };
            failed |= result.is_err();
            results.push((ordinal, result));
        }
        results.sort_unstable_by_key(|(ordinal, _)| *ordinal);
        // Completion order is intentionally irrelevant. Retain any established
        // underlying error before reporting cooperative cancellation.
        if let Some(index) = results
            .iter()
            .position(|(_, result)| matches!(result, Err(error) if error.code != "cancelled"))
        {
            results.remove(index).1?;
        }
        if cancel.is_cancelled() {
            return Err(cancelled());
        }
        results.into_iter().map(|(_, result)| result).collect()
    }
}

fn micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

struct CompletionGuard {
    counters: Arc<Counters>,
}

impl Drop for CompletionGuard {
    fn drop(&mut self) {
        self.counters.active.fetch_sub(1, Ordering::Relaxed);
        self.counters.completed.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::{Barrier, atomic::AtomicBool},
        time::Duration,
    };

    fn execution(workers: usize) -> MigrationExecution {
        MigrationExecution::new(MigrationExecutionOptions::new(workers, 1024).unwrap()).unwrap()
    }

    #[test]
    fn validates_options_and_defaults() {
        for workers in [0, 65, usize::MAX] {
            assert!(MigrationExecutionOptions::new(workers, 1).is_err());
        }
        assert!(MigrationExecutionOptions::new(1, 0).is_err());
        assert!(
            MigrationExecution::new(MigrationExecutionOptions {
                workers: 0,
                payload_budget_bytes: 1,
            })
            .is_err()
        );
        let options = MigrationExecutionOptions::default();
        assert!((1..=8).contains(&options.workers));
        assert_eq!(options.payload_budget_bytes, 64 * 1024 * 1024);
    }

    #[test]
    fn interleaved_progress_keeps_each_pass_clock_and_resets_new_passes() {
        let execution = execution(1);
        execution.enable_progress();
        execution.report("seal_fixture", 10, 10, 0, 1024);
        let first = Instant::now() - Duration::from_secs(5);
        execution
            .progress
            .current
            .lock()
            .unwrap()
            .phases
            .get_mut("seal_fixture")
            .unwrap()
            .0 = first;
        execution.report("commit_fixture", 5, 5, 5, 0);
        execution.report("seal_fixture", 20, 20, 0, 1024);
        assert_eq!(
            execution.progress.current.lock().unwrap().phase_started,
            first
        );
        execution.report("commit_fixture", 10, 10, 10, 0);
        execution.report("seal_fixture", 1, 0, 0, 1024);
        assert!(execution.progress.current.lock().unwrap().phase_started > first);
    }

    #[tokio::test]
    async fn preserves_order_and_drains_lowest_ordinal_error() {
        let execution = execution(3);
        let gate = Arc::new(Barrier::new(3));
        let finished = Arc::new(AtomicUsize::new(0));
        let completed = finished.clone();
        let result: Result<Vec<usize>> = execution
            .map_ordered(vec![0, 1, 2, 3], &CancellationToken::new(), move |n, _| {
                gate.wait();
                if n == 0 {
                    std::thread::sleep(Duration::from_millis(30));
                }
                completed.fetch_add(1, Ordering::Relaxed);
                Err(Error::new(&format!("failure-{n}"), "Fixture failure."))
            })
            .await;
        assert_eq!(result.unwrap_err().code, "failure-0");
        assert_eq!(finished.load(Ordering::Relaxed), 3);
        let snapshot = execution.snapshot();
        assert_eq!(snapshot.admitted, 3);
        assert_eq!(snapshot.completed, 3);
        assert_eq!(snapshot.active, 0);
        let gate = Arc::new(Barrier::new(3));
        let values = execution
            .map_ordered(vec![0, 1, 2], &CancellationToken::new(), move |n, _| {
                gate.wait();
                std::thread::sleep(Duration::from_millis((2 - n) * 5));
                Ok(n)
            })
            .await
            .unwrap();
        assert_eq!(values, [0, 1, 2]);
    }

    #[tokio::test]
    async fn bounds_windows_and_shares_worker_limit_between_calls() {
        let execution = execution(2);
        let cancel = CancellationToken::new();
        assert!(
            execution
                .map_ordered(vec![0; 129], &cancel, |n, _| Ok(n))
                .await
                .is_err()
        );
        let work = |n, _| {
            std::thread::sleep(Duration::from_millis(2));
            Ok(n)
        };
        let (first, second) = tokio::join!(
            execution.map_ordered((0..16).collect(), &cancel, work),
            execution.map_ordered((16..32).collect(), &cancel, work),
        );
        assert_eq!(first.unwrap(), (0..16).collect::<Vec<_>>());
        assert_eq!(second.unwrap(), (16..32).collect::<Vec<_>>());
        let snapshot = execution.snapshot();
        assert_eq!(snapshot.admitted, 32);
        assert_eq!(snapshot.completed, 32);
        assert_eq!(snapshot.high_water, 2);
        assert_eq!(snapshot.active, 0);
        assert_eq!(snapshot.window_high_water, 16);
    }

    #[tokio::test]
    async fn cancellation_drains_started_workers_and_preserves_underlying_failure() {
        let execution = execution(2);
        let cancel = CancellationToken::new();
        let started = Arc::new(AtomicBool::new(false));
        let signal = started.clone();
        let trigger = cancel.clone();
        let result = execution
            .map_ordered(vec![0, 1, 2], &cancel, move |n, token| {
                if n == 0 {
                    while !signal.load(Ordering::Acquire) {
                        std::thread::yield_now();
                    }
                    trigger.cancel();
                    Err(Error::integrity("Underlying fixture failure."))
                } else {
                    signal.store(true, Ordering::Release);
                    while !token.is_cancelled() {
                        std::thread::yield_now();
                    }
                    std::thread::sleep(Duration::from_millis(10));
                    Err::<(), _>(cancelled())
                }
            })
            .await;
        assert_eq!(result.unwrap_err().code, "integrity");
        assert_eq!(execution.snapshot().active, 0);
        assert_eq!(execution.snapshot().completed, 2);
        assert!(started.load(Ordering::Acquire));
        let called = Arc::new(AtomicBool::new(false));
        let call = called.clone();
        assert_eq!(
            execution
                .run(&cancel, move |_| {
                    call.store(true, Ordering::Relaxed);
                    Ok(())
                })
                .await
                .unwrap_err()
                .code,
            "cancelled"
        );
        assert!(!called.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn panic_is_sanitized_and_permit_released_after_drain() {
        let execution = execution(1);
        let cancel = CancellationToken::new();
        let error = execution
            .map_ordered(vec![0, 1], &cancel, |_, _| -> Result<()> {
                panic!("fixture worker panic")
            })
            .await
            .unwrap_err();
        assert_eq!(error.code, "unavailable");
        assert!(!error.message.contains("fixture"));
        assert_eq!(execution.snapshot().active, 0);
        assert_eq!(execution.snapshot().completed, 1);
        assert_eq!(execution.run(&cancel, |_| Ok(7)).await.unwrap(), 7);
    }
}
