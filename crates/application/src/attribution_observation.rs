//! Process-local, read-only attribution enumeration. No queue or publication port.
use async_trait::async_trait;
use devres_domain::{Error, Result, attribution::*};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

pub const OBSERVATION_TIMEOUT: Duration = Duration::from_secs(900);
pub const OBSERVATION_PAGE_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Default, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObservationCounts {
    pub examined: u64,
    pub ready: u64,
    pub unqualified: u64,
    pub origin_gaps: u64,
}
impl ObservationCounts {
    fn add(&mut self, other: &Self) {
        self.examined = self.examined.saturating_add(other.examined);
        self.ready = self.ready.saturating_add(other.ready);
        self.unqualified = self.unqualified.saturating_add(other.unqualified);
        self.origin_gaps = self.origin_gaps.saturating_add(other.origin_gaps);
    }
}

/// Only bounded aggregate deltas cross the adapter boundary.
pub struct ObservationPage {
    pub counts: BTreeMap<String, ObservationCounts>,
    pub complete: bool,
}

#[async_trait]
pub trait AttributionObservationSession: Send {
    /// A page belongs to one fixed read-only database snapshot.
    async fn next_page(&mut self) -> Result<ObservationPage>;
}

#[async_trait]
pub trait AttributionObservationStore: Send + Sync {
    async fn begin_observation(&self) -> Result<(String, Box<dyn AttributionObservationSession>)>;
    /// Validate live lifecycle/policy/archive/visibility outside the scan snapshot.
    async fn validate_observation(&self, binding: &str) -> Result<()>;
}

#[derive(Clone, Debug, Serialize)]
pub struct ObservationStatus {
    pub version: u32,
    pub state: &'static str,
    pub scope: &'static str,
    pub counting: &'static str,
    pub policy_epoch: u32,
    pub policy_fingerprint: &'static str,
    pub started_at: Option<i64>,
    pub completed_at: Option<i64>,
    pub gap: Option<&'static str>,
    pub providers: BTreeMap<String, ObservationCounts>,
    #[serde(skip)]
    binding: Option<String>,
}
impl Default for ObservationStatus {
    fn default() -> Self {
        Self {
            version: 1,
            state: "pending",
            scope: "retained_source_cutoffs",
            counting: "source_occurrences",
            policy_epoch: ATTRIBUTION_POLICY_EPOCH,
            policy_fingerprint: ATTRIBUTION_POLICY_FINGERPRINT,
            started_at: None,
            completed_at: None,
            gap: None,
            providers: crate::attribution_runtime::ATTRIBUTION_PROVIDERS
                .into_iter()
                .map(|name| (name.to_owned(), ObservationCounts::default()))
                .collect(),
            binding: None,
        }
    }
}

pub struct AttributionObservation {
    store: Arc<dyn AttributionObservationStore>,
    status: Mutex<ObservationStatus>,
    timeout: Duration,
    invalidated: CancellationToken,
}
impl AttributionObservation {
    pub fn new(store: Arc<dyn AttributionObservationStore>, timeout: Duration) -> Self {
        Self {
            store,
            status: Mutex::new(ObservationStatus::default()),
            timeout,
            invalidated: CancellationToken::new(),
        }
    }
    pub async fn status(&self) -> Result<ObservationStatus> {
        let binding = self.status.lock().await.binding.clone();
        if let Some(binding) = binding
            && let Err(error) = self.store.validate_observation(&binding).await
        {
            let mut status = self.status.lock().await;
            status.state = "invalidated";
            status.gap = Some(reason(&error));
            status.completed_at = None;
            self.invalidated.cancel();
            return Err(error);
        }
        Ok(self.status.lock().await.clone())
    }
    /// Exactly one pass; completion never grants repair or publication authority.
    pub async fn run(&self, cancel: CancellationToken) -> Result<()> {
        {
            let mut status = self.status.lock().await;
            if status.state != "pending" {
                return Err(Error::unavailable(
                    "Attribution observation already started.",
                ));
            }
            status.state = "running";
            status.started_at = Some(devres_domain::unix_now());
        }
        let result = tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(Error::new("cancelled", "Attribution observation cancelled.")),
            _ = self.invalidated.cancelled() => Err(Error::unavailable("Attribution observation invalidated.")),
            result = tokio::time::timeout(self.timeout, self.scan()) => {
                result.unwrap_or_else(|_| Err(Error::capacity("Attribution observation deadline exceeded.")))
            }
        };
        if let Err(error) = result {
            let mut status = self.status.lock().await;
            status.state = if self.invalidated.is_cancelled() {
                "invalidated"
            } else if error.code == "cancelled" {
                "cancelled"
            } else {
                "gap"
            };
            status.gap = Some(reason(&error));
            status.completed_at = None;
        }
        // Failed scans are represented explicitly; they never restart or mutate.
        Ok(())
    }
    async fn scan(&self) -> Result<()> {
        let (binding, mut session) = self.store.begin_observation().await?;
        self.store.validate_observation(&binding).await?;
        self.status.lock().await.binding = Some(binding.clone());
        loop {
            self.store.validate_observation(&binding).await?;
            let page = tokio::time::timeout(OBSERVATION_PAGE_TIMEOUT, session.next_page())
                .await
                .map_err(|_| {
                    Error::capacity("Attribution observation page deadline exceeded.")
                })??;
            self.store.validate_observation(&binding).await?;
            let mut status = self.status.lock().await;
            for (provider, counts) in page.counts {
                let saved = status
                    .providers
                    .get_mut(&provider)
                    .ok_or_else(|| Error::integrity("Invalid attribution observation provider."))?;
                saved.add(&counts);
            }
            if page.complete {
                status.state = "complete";
                status.completed_at = Some(devres_domain::unix_now());
                return Ok(());
            }
            drop(status);
            tokio::task::yield_now().await;
        }
    }
}

fn reason(error: &Error) -> &'static str {
    match error.code.as_str() {
        "capacity" => "capacity",
        "integrity" | "invalid_input" => "integrity",
        "cancelled" => "cancelled",
        _ => "unavailable",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    struct Store {
        invalid: AtomicBool,
        hold: bool,
        dropped: Arc<AtomicUsize>,
    }
    struct Session {
        hold: bool,
        dropped: Arc<AtomicUsize>,
    }
    impl Drop for Session {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::SeqCst);
        }
    }
    #[async_trait]
    impl AttributionObservationSession for Session {
        async fn next_page(&mut self) -> Result<ObservationPage> {
            if self.hold {
                std::future::pending::<()>().await;
            }
            Ok(ObservationPage {
                counts: BTreeMap::from([(
                    "npm".into(),
                    ObservationCounts {
                        examined: 2,
                        ready: 1,
                        unqualified: 1,
                        origin_gaps: 1,
                    },
                )]),
                complete: true,
            })
        }
    }
    #[async_trait]
    impl AttributionObservationStore for Store {
        async fn begin_observation(
            &self,
        ) -> Result<(String, Box<dyn AttributionObservationSession>)> {
            Ok((
                "private-fixture-binding".into(),
                Box::new(Session {
                    hold: self.hold,
                    dropped: self.dropped.clone(),
                }),
            ))
        }
        async fn validate_observation(&self, _: &str) -> Result<()> {
            if self.invalid.load(Ordering::SeqCst) {
                Err(Error::unavailable("secret-sentinel-raw-error"))
            } else {
                Ok(())
            }
        }
    }
    fn store(hold: bool) -> Arc<Store> {
        Arc::new(Store {
            invalid: AtomicBool::new(false),
            hold,
            dropped: Arc::new(AtomicUsize::new(0)),
        })
    }
    #[tokio::test]
    async fn bounded_counts_are_snapshot_scoped_and_binding_is_never_serialized() {
        let store = store(false);
        let observer = AttributionObservation::new(store.clone(), OBSERVATION_TIMEOUT);
        observer.run(CancellationToken::new()).await.unwrap();
        let status = observer.status().await.unwrap();
        assert_eq!(status.state, "complete");
        assert_eq!(status.providers["npm"].unqualified, 1);
        assert_eq!(status.providers["npm"].origin_gaps, 1);
        assert_eq!(status.scope, "retained_source_cutoffs");
        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("private-fixture-binding"));
        assert_eq!(store.dropped.load(Ordering::SeqCst), 1);
        assert!(observer.run(CancellationToken::new()).await.is_err());
    }
    #[tokio::test]
    async fn live_binding_failure_invalidates_completed_scan_without_raw_diagnostics() {
        let store = store(false);
        let observer = AttributionObservation::new(store.clone(), OBSERVATION_TIMEOUT);
        observer.run(CancellationToken::new()).await.unwrap();
        store.invalid.store(true, Ordering::SeqCst);
        assert!(observer.status().await.is_err());
        let status = observer.status.lock().await;
        assert_eq!(status.state, "invalidated");
        assert_eq!(status.gap, Some("unavailable"));
        assert!(
            !serde_json::to_string(&*status)
                .unwrap()
                .contains("secret-sentinel")
        );
    }
    #[tokio::test(start_paused = true)]
    async fn pass_deadline_releases_owned_session_and_retains_incomplete_gap() {
        let store = store(true);
        let observer = AttributionObservation::new(store.clone(), Duration::from_secs(1));
        observer.run(CancellationToken::new()).await.unwrap();
        let status = observer.status().await.unwrap();
        assert_eq!(status.state, "gap");
        assert_eq!(status.gap, Some("capacity"));
        assert_eq!(status.completed_at, None);
        assert_eq!(store.dropped.load(Ordering::SeqCst), 1);
    }
    #[tokio::test]
    async fn cancellation_does_not_begin_a_new_observation_or_report_completion() {
        let store = store(true);
        let observer = AttributionObservation::new(store.clone(), OBSERVATION_TIMEOUT);
        let cancel = CancellationToken::new();
        cancel.cancel();
        observer.run(cancel).await.unwrap();
        assert_eq!(observer.status().await.unwrap().state, "cancelled");
        assert_eq!(store.dropped.load(Ordering::SeqCst), 0);
    }
}
