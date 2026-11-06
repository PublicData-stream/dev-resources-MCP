//! Bounded blocking work for private offline storage commands.
//!
//! A command passes one context through every nested migration/verification
//! phase. Cancellation is cooperative: callers must cancel the token and await
//! the operation, rather than aborting its async task and detaching workers.
use devres_domain::{Error, Result};
use futures::{FutureExt, StreamExt, stream::FuturesUnordered};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};
use std::{collections::VecDeque, future::Future, ops::Deref, panic::AssertUnwindSafe};
use tokio::sync::{Notify, Semaphore};
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

/// Accounted graph working memory, separate from SQL payload windows and RSS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MigrationGraphOptions {
    pub memory_budget_bytes: usize,
}

impl MigrationGraphOptions {
    pub fn new(memory_budget_bytes: usize) -> Result<Self> {
        if memory_budget_bytes == 0 {
            return Err(Error::invalid(
                "Offline graph memory budget must be positive.",
            ));
        }
        Ok(Self {
            memory_budget_bytes,
        })
    }
}

impl Default for MigrationGraphOptions {
    fn default() -> Self {
        Self {
            memory_budget_bytes: 1024 * 1024 * 1024,
        }
    }
}

struct GraphBudget {
    limit: usize,
    state: Mutex<GraphBudgetState>,
    changed: Notify,
    high_water: AtomicUsize,
}

#[derive(Default)]
struct GraphBudgetState {
    used: usize,
    next_ticket: u64,
    waiting: VecDeque<u64>,
}

/// An unadmitted request removes its ticket even if its future is dropped.
struct GraphWaiter {
    budget: Arc<GraphBudget>,
    ticket: Option<u64>,
}

impl Drop for GraphWaiter {
    fn drop(&mut self) {
        if let Some(ticket) = self.ticket.take() {
            if let Ok(mut state) = self.budget.state.lock()
                && let Some(position) = state.waiting.iter().position(|queued| *queued == ticket)
            {
                state.waiting.remove(position);
            }
            self.budget.changed.notify_waiters();
        }
    }
}

impl GraphBudget {
    async fn reserve(
        self: &Arc<Self>,
        bytes: usize,
        cancel: &CancellationToken,
    ) -> Result<GraphReservation> {
        if cancel.is_cancelled() {
            return Err(cancelled());
        }
        let ticket = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| Error::unavailable("Offline graph memory admission unavailable."))?;
            let ticket = state.next_ticket;
            state.next_ticket = ticket
                .checked_add(1)
                .ok_or_else(|| Error::capacity("Offline graph admission ticket overflow."))?;
            state.waiting.push_back(ticket);
            ticket
        };
        let mut waiter = GraphWaiter {
            budget: self.clone(),
            ticket: Some(ticket),
        };
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if cancel.is_cancelled() {
                return Err(cancelled());
            }
            {
                let mut state = self.state.lock().map_err(|_| {
                    Error::unavailable("Offline graph memory admission unavailable.")
                })?;
                if state.waiting.front() == Some(&ticket)
                    && (state.used == 0
                        || state
                            .used
                            .checked_add(bytes)
                            .is_some_and(|next| next <= self.limit))
                {
                    state.used = state.used.checked_add(bytes).ok_or_else(|| {
                        Error::capacity("Offline graph memory accounting overflow.")
                    })?;
                    state.waiting.pop_front();
                    waiter.ticket = None;
                    self.high_water.fetch_max(state.used, Ordering::Relaxed);
                    // The next queued window may fit alongside this one.
                    self.changed.notify_waiters();
                    return Ok(GraphReservation(Arc::new(GraphMemoryGuard {
                        budget: self.clone(),
                        bytes,
                    })));
                }
            }
            tokio::select! {
                biased;
                _ = cancel.cancelled() => return Err(cancelled()),
                _ = &mut changed => (),
            }
        }
    }
}

struct GraphMemoryGuard {
    budget: Arc<GraphBudget>,
    bytes: usize,
}

impl Drop for GraphMemoryGuard {
    fn drop(&mut self) {
        if let Ok(mut state) = self.budget.state.lock() {
            state.used -= self.bytes;
        }
        self.budget.changed.notify_waiters();
    }
}

/// A shared window reservation. Keep this alive while extracted results remain resident.
#[derive(Clone)]
pub struct GraphReservation(Arc<GraphMemoryGuard>);

impl GraphReservation {
    pub fn accounted_bytes(&self) -> usize {
        self.0.bytes
    }
}

/// Prepared output stays charged until publication or explicit reservation transfer.
pub struct GraphPrepared<T> {
    value: T,
    reservation: GraphReservation,
}

impl<T: std::fmt::Debug> std::fmt::Debug for GraphPrepared<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GraphPrepared")
            .field("value", &self.value)
            .field("accounted_bytes", &self.reservation.accounted_bytes())
            .finish()
    }
}

impl<T> GraphPrepared<T> {
    pub fn value(&self) -> &T {
        &self.value
    }
    pub fn value_mut(&mut self) -> &mut T {
        &mut self.value
    }
    pub fn into_parts(self) -> (T, GraphReservation) {
        (self.value, self.reservation)
    }
    /// Call only after publication, or when the returned value no longer owns graph working memory.
    pub fn into_inner_after_commit(self) -> T {
        self.value
    }
}

impl<T> Deref for GraphPrepared<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.value
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
    pub graph_admitted: usize,
    pub graph_completed: usize,
    pub graph_active: usize,
    pub graph_high_water: usize,
    pub graph_memory_bytes: usize,
    pub graph_memory_high_water: usize,
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
    graph_options: MigrationGraphOptions,
    graph_permits: Arc<Semaphore>,
    graph_counters: Arc<Counters>,
    graph_budget: Arc<GraphBudget>,
}

impl Default for MigrationExecution {
    fn default() -> Self {
        Self::from_validated(
            MigrationExecutionOptions::default(),
            MigrationGraphOptions::default(),
        )
    }
}

fn cancelled() -> Error {
    Error::new("cancelled", "Offline storage work canceled.")
}

impl MigrationExecution {
    pub fn new(options: MigrationExecutionOptions) -> Result<Self> {
        Self::new_with_graph_options(options, MigrationGraphOptions::default())
    }

    pub fn new_with_graph_options(
        options: MigrationExecutionOptions,
        graph_options: MigrationGraphOptions,
    ) -> Result<Self> {
        let options =
            MigrationExecutionOptions::new(options.workers, options.payload_budget_bytes)?;
        let graph_options = MigrationGraphOptions::new(graph_options.memory_budget_bytes)?;
        Ok(Self::from_validated(options, graph_options))
    }

    fn from_validated(
        options: MigrationExecutionOptions,
        graph_options: MigrationGraphOptions,
    ) -> Self {
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
            graph_permits: Arc::new(Semaphore::new(options.workers)),
            graph_counters: Arc::new(Counters::default()),
            graph_budget: Arc::new(GraphBudget {
                limit: graph_options.memory_budget_bytes,
                state: Mutex::new(GraphBudgetState::default()),
                changed: Notify::new(),
                high_water: AtomicUsize::new(0),
            }),
            graph_options,
            options,
        }
    }

    pub fn options(&self) -> MigrationExecutionOptions {
        self.options
    }

    pub fn graph_options(&self) -> MigrationGraphOptions {
        self.graph_options
    }

    /// Conservative decoded JSON allocation charge shared with SQL admission.
    /// PostgreSQL returns scalar JSON size/shape before decoded graph payloads are admitted.
    /// Per-node slack covers the SQL JSON envelope charge and several live clones;
    /// serialized bytes cover strings, number formatting and driver/transient buffers.
    pub fn graph_input_charge(encoded_bytes: usize, nodes: usize) -> Result<usize> {
        encoded_bytes
            .checked_mul(24)
            .and_then(|bytes| nodes.checked_mul(8192).and_then(|n| bytes.checked_add(n)))
            .and_then(|bytes| bytes.checked_add(64 * 1024))
            .ok_or_else(|| Error::capacity("Offline graph input charge overflow."))
    }

    /// Keep a retained-order prefix. A large individually valid unit is always admitted alone.
    pub fn graph_input_window<T>(&self, items: Vec<(T, usize)>) -> Result<Vec<(T, usize)>> {
        let mut output = Vec::new();
        let mut total = 0_usize;
        for (item, bytes) in items {
            if bytes == 0 {
                return Err(Error::invalid("Offline graph work must reserve memory."));
            }
            let proposed = total
                .checked_add(bytes)
                .ok_or_else(|| Error::capacity("Offline graph window charge overflow."))?;
            if !output.is_empty()
                && (proposed > self.graph_options.memory_budget_bytes
                    || output.len() >= self.options.workers.min(MIGRATION_WINDOW_RECORDS))
            {
                break;
            }
            output.push((item, bytes));
            total = proposed;
            if total > self.graph_options.memory_budget_bytes {
                break;
            }
        }
        Ok(output)
    }

    pub fn graph_value_charge(value: &serde_json::Value) -> Result<usize> {
        crate::storage::migration_value_charge(value)
    }

    /// Size a whole window before admission; one individually oversized unit runs alone.
    pub fn graph_window_limit(&self, per_unit_bytes: usize) -> usize {
        (self.graph_options.memory_budget_bytes / per_unit_bytes.max(1))
            .clamp(1, self.options.workers.min(MIGRATION_WINDOW_RECORDS))
    }

    /// Reserve a complete input/result window before loading its payloads.
    /// This does not consume a job slot. Transfer the same reservation into
    /// `graph_map_ordered_reserved`; do not reacquire graph memory inside it.
    pub async fn graph_reserve(
        &self,
        bytes: usize,
        cancel: &CancellationToken,
    ) -> Result<GraphReservation> {
        if bytes == 0 {
            return Err(Error::invalid("Offline graph work must reserve memory."));
        }
        self.graph_budget.reserve(bytes, cancel).await
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
            graph_admitted: self.graph_counters.admitted.load(Ordering::Relaxed),
            graph_completed: self.graph_counters.completed.load(Ordering::Relaxed),
            graph_active: self.graph_counters.active.load(Ordering::Relaxed),
            graph_high_water: self.graph_counters.high_water.load(Ordering::Relaxed),
            graph_memory_bytes: self
                .graph_budget
                .state
                .lock()
                .map(|state| state.used)
                .unwrap_or(usize::MAX),
            graph_memory_high_water: self.graph_budget.high_water.load(Ordering::Relaxed),
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
                "graph_memory_budget_bytes":self.graph_options.memory_budget_bytes,
                "graph_admitted":snapshot.graph_admitted,"graph_completed":snapshot.graph_completed,
                "graph_active_jobs":snapshot.graph_active,"graph_jobs_high_water":snapshot.graph_high_water,
                "graph_memory_bytes":snapshot.graph_memory_bytes,"graph_memory_high_water":snapshot.graph_memory_high_water,
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

    /// Admit one async graph unit. Its blocking work may call `run`, whose
    /// admission is separate. Do not nest graph admission inside graph units.
    pub async fn graph_run<R, F, Fut>(
        &self,
        estimated_bytes: usize,
        cancel: &CancellationToken,
        work: F,
    ) -> Result<GraphPrepared<R>>
    where
        F: FnOnce(CancellationToken) -> Fut,
        Fut: Future<Output = Result<R>>,
    {
        if estimated_bytes == 0 {
            return Err(Error::invalid("Offline graph work must reserve memory."));
        }
        let reservation = self.graph_budget.reserve(estimated_bytes, cancel).await?;
        self.graph_run_reserved(reservation, cancel, work).await
    }

    async fn graph_run_reserved<R, F, Fut>(
        &self,
        reservation: GraphReservation,
        cancel: &CancellationToken,
        work: F,
    ) -> Result<GraphPrepared<R>>
    where
        F: FnOnce(CancellationToken) -> Fut,
        Fut: Future<Output = Result<R>>,
    {
        let _permit = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(cancelled()),
            permit = self.graph_permits.acquire() => {
                permit.map_err(|_| Error::unavailable("Offline graph worker admission unavailable."))?
            }
        };
        if cancel.is_cancelled() {
            return Err(cancelled());
        }
        self.graph_counters.admitted.fetch_add(1, Ordering::Relaxed);
        let active = self.graph_counters.active.fetch_add(1, Ordering::Relaxed) + 1;
        self.graph_counters
            .high_water
            .fetch_max(active, Ordering::Relaxed);
        let _guard = CompletionGuard {
            counters: self.graph_counters.clone(),
        };
        // Catch both construction and polling panics without spawning or
        // detaching a task; borrowed provider contexts remain usable.
        let token = cancel.clone();
        let value = AssertUnwindSafe(async move { work(token).await })
            .catch_unwind()
            .await
            .map_err(|_| Error::unavailable("Offline graph worker failed."))??;
        if cancel.is_cancelled() {
            return Err(cancelled());
        }
        Ok(GraphPrepared { value, reservation })
    }

    /// Prepare one bounded, ordered window. Reserve its complete memory charge
    /// atomically, including completed outputs, before admitting any worker.
    /// This avoids competing provider windows each holding partial admission.
    /// Callers must bound inputs before materializing them; estimates cover
    /// inputs, clones, index buffers and results, rather than only serialized bytes.
    /// An oversized window is permitted only for one individually valid unit.
    pub async fn graph_map_ordered<T, R, F, Fut>(
        &self,
        items: Vec<(T, usize)>,
        cancel: &CancellationToken,
        work: F,
    ) -> Result<Vec<GraphPrepared<R>>>
    where
        F: Fn(T, CancellationToken) -> Fut,
        Fut: Future<Output = Result<R>>,
    {
        if items.len() > MIGRATION_WINDOW_RECORDS {
            return Err(Error::capacity("Offline graph window exceeds its bound."));
        }
        if cancel.is_cancelled() {
            return Err(cancelled());
        }
        if items.is_empty() {
            return Ok(Vec::new());
        }
        let bytes = items.iter().try_fold(0_usize, |sum, (_, bytes)| {
            if *bytes == 0 {
                return Err(Error::invalid("Offline graph work must reserve memory."));
            }
            sum.checked_add(*bytes)
                .ok_or_else(|| Error::capacity("Offline graph memory accounting overflow."))
        })?;
        if items.len() > 1 && bytes > self.graph_options.memory_budget_bytes {
            return Err(Error::capacity(
                "Offline graph window exceeds its memory budget.",
            ));
        }
        let reservation = self.graph_budget.reserve(bytes, cancel).await?;
        self.graph_map_ordered_reserved(
            items.into_iter().map(|(item, _)| item).collect(),
            reservation,
            cancel,
            work,
        )
        .await
    }

    /// Prepare already-accounted input. The caller reserves enough for the
    /// whole window before reading it, including all worker buffers and outputs.
    /// Reservations belong to this execution and remain alive through results.
    pub async fn graph_map_ordered_reserved<T, R, F, Fut>(
        &self,
        items: Vec<T>,
        reservation: GraphReservation,
        cancel: &CancellationToken,
        work: F,
    ) -> Result<Vec<GraphPrepared<R>>>
    where
        F: Fn(T, CancellationToken) -> Fut,
        Fut: Future<Output = Result<R>>,
    {
        if items.len() > MIGRATION_WINDOW_RECORDS
            || (items.len() > 1
                && reservation.accounted_bytes() > self.graph_options.memory_budget_bytes)
        {
            return Err(Error::capacity("Offline graph window exceeds its bound."));
        }
        if !Arc::ptr_eq(&reservation.0.budget, &self.graph_budget) {
            return Err(Error::invalid(
                "Offline graph reservation belongs to another execution.",
            ));
        }
        if cancel.is_cancelled() {
            return Err(cancelled());
        }
        let mut items = items.into_iter().enumerate();
        let mut running = FuturesUnordered::new();
        let mut results = Vec::new();
        let mut failed = false;
        loop {
            while !failed && !cancel.is_cancelled() && running.len() < self.options.workers {
                let Some((ordinal, item)) = items.next() else {
                    break;
                };
                let reservation = reservation.clone();
                let work = &work;
                running.push(async move {
                    let result = self
                        .graph_run_reserved(reservation, cancel, |token| work(item, token))
                        .await;
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

#[cfg(test)]
#[path = "migration_execution_graph_tests.rs"]
mod graph_accounting_tests;

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

    fn graph_execution(workers: usize, memory: usize) -> MigrationExecution {
        MigrationExecution::new_with_graph_options(
            MigrationExecutionOptions::new(workers, 1024).unwrap(),
            MigrationGraphOptions::new(memory).unwrap(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn graph_memory_fifo_prevents_small_windows_from_starving_a_large_waiter() {
        let execution = graph_execution(8, 8);
        let cancel = CancellationToken::new();
        let active = execution.graph_reserve(1, &cancel).await.unwrap();
        let mut large = Box::pin(execution.graph_reserve(8, &cancel));
        assert!(futures::poll!(&mut large).is_pending());
        let mut small = Box::pin(execution.graph_reserve(1, &cancel));
        let mut later = Box::pin(execution.graph_reserve(1, &cancel));
        // Both would fit beside active, but the older whole-budget waiter owns
        // the next admission. Polling newcomers first cannot bypass that turn.
        assert!(futures::poll!(&mut small).is_pending());
        assert!(futures::poll!(&mut later).is_pending());
        drop(active);
        assert!(futures::poll!(&mut small).is_pending());
        let large = tokio::time::timeout(Duration::from_secs(1), large)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(execution.snapshot().graph_memory_bytes, 8);
        assert!(futures::poll!(&mut small).is_pending());
        assert!(futures::poll!(&mut later).is_pending());
        drop(large);
        let small = tokio::time::timeout(Duration::from_secs(1), small)
            .await
            .unwrap()
            .unwrap();
        let later = tokio::time::timeout(Duration::from_secs(1), later)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(execution.snapshot().graph_memory_bytes, 2);
        drop((small, later));
        assert_eq!(execution.snapshot().graph_memory_bytes, 0);
        assert!(
            execution
                .graph_budget
                .state
                .lock()
                .unwrap()
                .waiting
                .is_empty()
        );
    }

    #[tokio::test]
    async fn graph_memory_fifo_removes_canceled_and_dropped_admission_tickets() {
        for drop_waiter in [false, true] {
            let execution = graph_execution(2, 8);
            let cancel = CancellationToken::new();
            let active = execution.graph_reserve(7, &cancel).await.unwrap();
            let queued_cancel = cancel.child_token();
            let mut first = Box::pin(execution.graph_reserve(9, &queued_cancel));
            assert!(futures::poll!(&mut first).is_pending());
            let mut following = Box::pin(execution.graph_reserve(1, &cancel));
            assert!(futures::poll!(&mut following).is_pending());
            if drop_waiter {
                drop(first);
            } else {
                queued_cancel.cancel();
                assert_eq!(
                    first.await.err().expect("canceled waiter").code,
                    "cancelled"
                );
            }
            // Removing the oversized head wakes the small waiter immediately;
            // the existing seven-byte reservation remains live throughout.
            let following = tokio::time::timeout(Duration::from_secs(1), following)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(execution.snapshot().graph_memory_bytes, 8);
            assert!(
                execution
                    .graph_budget
                    .state
                    .lock()
                    .unwrap()
                    .waiting
                    .is_empty()
            );
            drop((following, active));
            assert_eq!(execution.snapshot().graph_memory_bytes, 0);
        }
    }

    #[tokio::test]
    async fn graph_input_reservation_transfers_without_reacquiring_and_rejects_other_contexts() {
        let execution = graph_execution(1, 8);
        let cancel = CancellationToken::new();
        let reservation = execution.graph_reserve(8, &cancel).await.unwrap();
        assert_eq!(execution.snapshot().graph_memory_bytes, 8);
        let results = tokio::time::timeout(
            Duration::from_secs(1),
            execution.graph_map_ordered_reserved(
                vec![7],
                reservation,
                &cancel,
                |n, _| async move { Ok(n) },
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(*results[0], 7);
        drop(results);
        assert_eq!(execution.snapshot().graph_memory_bytes, 0);
        let other = graph_execution(1, 8);
        let reservation = other.graph_reserve(1, &cancel).await.unwrap();
        assert_eq!(
            execution
                .graph_map_ordered_reserved(
                    vec![7],
                    reservation,
                    &cancel,
                    |n, _| async move { Ok(n) }
                )
                .await
                .unwrap_err()
                .code,
            "invalid_input"
        );
        assert_eq!(other.snapshot().graph_memory_bytes, 0);
        assert!(MigrationGraphOptions::new(0).is_err());
        assert!(
            MigrationExecution::new_with_graph_options(
                execution.options(),
                MigrationGraphOptions {
                    memory_budget_bytes: 0
                }
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn graph_windows_overlap_across_providers_and_share_job_limit() {
        let execution = graph_execution(2, 8);
        let cancel = CancellationToken::new();
        let barrier = tokio::sync::Barrier::new(2);
        let barrier = &barrier;
        let work = |n, _| async move {
            barrier.wait().await;
            Ok(n)
        };
        let (first, second) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(
                execution.graph_map_ordered(vec![(1, 1), (2, 1)], &cancel, work),
                execution.graph_map_ordered(vec![(3, 1), (4, 1)], &cancel, work)
            )
        })
        .await
        .unwrap();
        assert_eq!(
            first.unwrap().iter().map(|n| **n).collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(
            second.unwrap().iter().map(|n| **n).collect::<Vec<_>>(),
            vec![3, 4]
        );
        let snapshot = execution.snapshot();
        assert_eq!(snapshot.graph_high_water, 2);
        assert_eq!(snapshot.graph_active, 0);
        assert_eq!(snapshot.graph_admitted, 4);
        assert_eq!(snapshot.graph_completed, 4);
        assert_eq!(snapshot.graph_memory_bytes, 0);
    }

    #[tokio::test]
    async fn graph_outputs_keep_memory_and_oversized_units_are_exclusive() {
        let execution = graph_execution(2, 8);
        let cancel = CancellationToken::new();
        let oversized = execution
            .graph_run(9, &cancel, |_| async { Ok(7) })
            .await
            .unwrap();
        let next = execution.graph_run(1, &cancel, |_| async { Ok(8) });
        tokio::pin!(next);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut next)
                .await
                .is_err()
        );
        let (value, reservation) = oversized.into_parts();
        assert_eq!(value, 7);
        assert_eq!(reservation.accounted_bytes(), 9);
        assert_eq!(execution.snapshot().graph_memory_bytes, 9);
        drop(reservation);
        assert_eq!(
            *tokio::time::timeout(Duration::from_secs(1), next)
                .await
                .unwrap()
                .unwrap(),
            8
        );
        assert_eq!(execution.snapshot().graph_memory_bytes, 0);
        assert_eq!(execution.snapshot().graph_memory_high_water, 9);
    }

    #[tokio::test]
    async fn graph_windows_reserve_atomically_and_enforce_input_bounds() {
        let execution = graph_execution(4, 8);
        let cancel = CancellationToken::new();
        assert_eq!(execution.graph_window_limit(3), 2);
        assert_eq!(execution.graph_window_limit(9), 1);
        let prepared = execution
            .graph_map_ordered(vec![(0, 4), (1, 4)], &cancel, |n, _| async move { Ok(n) })
            .await
            .unwrap();
        let mut prepared = prepared.into_iter();
        drop(prepared.next());
        assert_eq!(execution.snapshot().graph_memory_bytes, 8);
        drop(prepared);
        for items in [
            vec![(0, 4), (1, 5)],
            vec![(0, 1); 129],
            vec![(0, usize::MAX), (1, 1)],
        ] {
            assert_eq!(
                execution
                    .graph_map_ordered(items, &cancel, |n, _| async move { Ok(n) })
                    .await
                    .unwrap_err()
                    .code,
                "capacity"
            );
        }
        assert_eq!(
            execution
                .graph_map_ordered(vec![(0, 0)], &cancel, |n, _| async move { Ok(n) })
                .await
                .unwrap_err()
                .code,
            "invalid_input"
        );
        assert_eq!(execution.snapshot().graph_memory_bytes, 0);
    }

    #[tokio::test]
    async fn graph_worker_one_can_invoke_blocking_worker_and_borrow_context() {
        let execution = graph_execution(1, 8);
        let cancel = CancellationToken::new();
        let borrowed = String::from("fixture");
        let results = tokio::time::timeout(
            Duration::from_secs(1),
            execution.graph_map_ordered(vec![(borrowed.as_str(), 1)], &cancel, |text, token| {
                let execution = &execution;
                async move {
                    let length = text.len();
                    execution.run(&token, move |_| Ok(length)).await
                }
            }),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(*results[0], 7);
        assert_eq!(execution.snapshot().graph_high_water, 1);
        assert_eq!(execution.snapshot().high_water, 1);
    }

    #[tokio::test]
    async fn graph_error_order_and_cancellation_drain_every_started_job() {
        let execution = graph_execution(2, 8);
        let cancel = CancellationToken::new();
        let error = execution
            .graph_map_ordered(vec![(0, 1), (1, 1), (2, 1)], &cancel, |n, _| async move {
                if n == 0 {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err::<(), _>(Error::new(
                    if n == 0 { "first" } else { "later" },
                    "fixture failure",
                ))
            })
            .await
            .unwrap_err();
        assert_eq!(error.code, "first");
        assert_eq!(execution.snapshot().graph_admitted, 2);
        assert_eq!(execution.snapshot().graph_completed, 2);
        assert_eq!(execution.snapshot().graph_memory_bytes, 0);
        let trigger = cancel.clone();
        let work = execution.graph_map_ordered(vec![(0, 1), (1, 1)], &cancel, |n, token| {
            let trigger = &trigger;
            async move {
                if n == 1 {
                    trigger.cancel();
                }
                token.cancelled().await;
                Err::<(), _>(cancelled())
            }
        });
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), work)
                .await
                .unwrap()
                .unwrap_err()
                .code,
            "cancelled"
        );
        assert_eq!(execution.snapshot().graph_active, 0);
        assert_eq!(execution.snapshot().graph_memory_bytes, 0);
    }

    #[tokio::test]
    async fn graph_panics_are_sanitized_and_admission_is_released() {
        let execution = graph_execution(1, 8);
        let cancel = CancellationToken::new();
        let error = execution
            .graph_run(1, &cancel, |_| async {
                panic!("fixture graph worker panic");
                #[allow(unreachable_code)]
                Ok(())
            })
            .await
            .unwrap_err();
        assert_eq!(error.code, "unavailable");
        assert!(!error.message.contains("fixture"));
        assert_eq!(execution.snapshot().graph_active, 0);
        assert_eq!(execution.snapshot().graph_memory_bytes, 0);
        assert_eq!(
            *execution
                .graph_run(1, &cancel, |_| async { Ok(7) })
                .await
                .unwrap(),
            7
        );
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
