//! Request-owned reuse of verified immutable search membership.
use devres_domain::{Error, Result};
use std::{
    collections::{BTreeSet, VecDeque},
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::sync::{Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore};

const MAX_KEYS: usize = 4;
const MAX_IDS: usize = 1_000_000;
const MAX_BYTES: usize = 64 * 1024 * 1024;

fn capacity() -> Error {
    Error::capacity("MDN selected search membership capacity exhausted.")
}
fn failure() -> Error {
    Error::unavailable("MDN selected search membership unavailable.")
}

struct Retained {
    ids: BTreeSet<String>,
    // These permits follow the last reader, including a canceled blocking search.
    _bytes: Option<OwnedSemaphorePermit>,
    _ids: Option<OwnedSemaphorePermit>,
}

#[derive(Clone)]
pub(super) struct Membership(Arc<Retained>);
impl AsRef<BTreeSet<String>> for Membership {
    fn as_ref(&self) -> &BTreeSet<String> {
        &self.0.ids
    }
}

type Slot = Arc<AsyncMutex<Option<Membership>>>;
type Slots = VecDeque<((String, String), Slot)>;

fn evict_unused(slots: &mut Slots) -> bool {
    if let Some(position) = slots
        .iter()
        .position(|(_, slot)| Arc::strong_count(slot) == 1)
    {
        slots.remove(position);
        true
    } else {
        false
    }
}

pub(super) struct MembershipCache {
    enabled: bool,
    slots: Mutex<Slots>,
    bytes: Arc<Semaphore>,
    ids: Arc<Semaphore>,
    stats: CacheStats,
}

#[derive(Default)]
struct CacheStats {
    hits: AtomicU64,
    misses: AtomicU64,
    completed: AtomicU64,
    failed: AtomicU64,
    cancelled: AtomicU64,
}
struct BuildGuard<'a> {
    stats: &'a CacheStats,
    finished: bool,
}
impl BuildGuard<'_> {
    fn finish(mut self, succeeded: bool) {
        if succeeded {
            &self.stats.completed
        } else {
            &self.stats.failed
        }
        .fetch_add(1, Ordering::Relaxed);
        self.finished = true;
    }
}
impl Drop for BuildGuard<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.stats.cancelled.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl MembershipCache {
    pub(super) fn new(enabled: bool) -> Self {
        Self {
            enabled,
            slots: Mutex::new(VecDeque::new()),
            bytes: Arc::new(Semaphore::new(MAX_BYTES)),
            ids: Arc::new(Semaphore::new(MAX_IDS)),
            stats: CacheStats::default(),
        }
    }

    pub(super) fn metrics(&self) -> String {
        format!(
            "devres_mdn_search_membership_cache_hits_total {}\ndevres_mdn_search_membership_cache_misses_total {}\ndevres_mdn_search_membership_builds_completed_total {}\ndevres_mdn_search_membership_builds_failed_total {}\ndevres_mdn_search_membership_builds_cancelled_total {}\n",
            self.stats.hits.load(Ordering::Relaxed),
            self.stats.misses.load(Ordering::Relaxed),
            self.stats.completed.load(Ordering::Relaxed),
            self.stats.failed.load(Ordering::Relaxed),
            self.stats.cancelled.load(Ordering::Relaxed),
        )
    }

    fn reserve(
        &self,
        bytes: usize,
        ids: usize,
    ) -> Result<(OwnedSemaphorePermit, OwnedSemaphorePermit)> {
        if bytes > MAX_BYTES || ids > MAX_IDS {
            return Err(capacity());
        }
        let mut slots = self.slots.lock().map_err(|_| failure())?;
        loop {
            if let Ok(byte_permit) = self.bytes.clone().try_acquire_many_owned(bytes as u32)
                && let Ok(id_permit) = self.ids.clone().try_acquire_many_owned(ids as u32)
            {
                return Ok((byte_permit, id_permit));
            }
            if !evict_unused(&mut slots) {
                return Err(capacity());
            }
        }
    }

    pub(super) async fn get_or_build<F, Fut, I>(
        &self,
        inventory: &str,
        kind: &str,
        build: F,
    ) -> Result<Membership>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<I>>,
        I: IntoIterator<Item = String>,
    {
        if !self.enabled {
            return Ok(Membership(Arc::new(Retained {
                ids: build().await?.into_iter().collect(),
                _bytes: None,
                _ids: None,
            })));
        }
        let key = (inventory.to_owned(), kind.to_owned());
        let slot = {
            let mut slots = self.slots.lock().map_err(|_| failure())?;
            if let Some((_, slot)) = slots.iter().find(|(found, _)| found == &key) {
                slot.clone()
            } else {
                while slots.len() >= MAX_KEYS {
                    if !evict_unused(&mut slots) {
                        return Err(capacity());
                    }
                }
                let slot = Arc::new(AsyncMutex::new(None));
                slots.push_back((key, slot.clone()));
                slot
            }
        };
        // The caller owns the fill future. Dropping it releases this lock; a
        // waiter can retry, and neither partial data nor errors become entries.
        let mut selected = slot.lock().await;
        if let Some(found) = selected.as_ref() {
            self.stats.hits.fetch_add(1, Ordering::Relaxed);
            return Ok(found.clone());
        }
        self.stats.misses.fetch_add(1, Ordering::Relaxed);
        let guard = BuildGuard {
            stats: &self.stats,
            finished: false,
        };
        let result = self.build(inventory, kind, build).await;
        guard.finish(result.is_ok());
        let membership = result?;
        *selected = Some(membership.clone());
        Ok(membership)
    }

    async fn build<F, Fut, I>(&self, inventory: &str, kind: &str, build: F) -> Result<Membership>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<I>>,
        I: IntoIterator<Item = String>,
    {
        let members = build().await?;
        let (mut byte_permit, mut id_permit) = self.reserve(
            inventory.len().saturating_add(kind.len()).saturating_add(2),
            0,
        )?;
        let mut ids = BTreeSet::new();
        for (position, id) in members.into_iter().enumerate() {
            if position % 1000 == 0 {
                tokio::task::yield_now().await;
            }
            if !crate::integrity::valid_hash(&id) {
                return Err(Error::integrity("Invalid MDN search projection identity."));
            }
            if !ids.contains(&id) {
                // Charge each retained string before insertion, including fill
                // work. Source inventory bytes keep their separate read bound.
                let (bytes, count) = self.reserve(id.len() + 3, 1)?;
                byte_permit.merge(bytes);
                id_permit.merge(count);
                ids.insert(id);
            }
        }
        Ok(Membership(Arc::new(Retained {
            ids,
            _bytes: Some(byte_permit),
            _ids: Some(id_permit),
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Notify;

    fn ids(value: &str) -> BTreeSet<String> {
        BTreeSet::from([crate::integrity::hash(value.as_bytes())])
    }

    #[tokio::test]
    async fn verified_sets_are_reused_by_root_and_kind_and_fifo_eviction_is_bounded() {
        let cache = MembershipCache::new(true);
        let calls = AtomicUsize::new(0);
        for _ in 0..2 {
            let set = cache
                .get_or_build("root", "article", || async {
                    calls.fetch_add(1, Ordering::Relaxed);
                    Ok(ids("article"))
                })
                .await
                .expect("membership");
            assert_eq!(set.as_ref(), &ids("article"));
        }
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        cache
            .get_or_build("root", "feature", || async { Ok(ids("feature")) })
            .await
            .expect("separate kind");
        for root in ["next", "third", "fourth"] {
            cache
                .get_or_build(root, "article", || async { Ok(ids(root)) })
                .await
                .expect("new root");
        }
        assert_eq!(cache.slots.lock().expect("slots").len(), MAX_KEYS);
        cache
            .get_or_build("root", "article", || async {
                calls.fetch_add(1, Ordering::Relaxed);
                Ok(ids("article"))
            })
            .await
            .expect("evicted root rebuilt");
        assert_eq!(calls.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn byte_and_identifier_reservations_follow_active_leases_after_eviction() {
        for (bytes, count) in [(MAX_BYTES, 1), (100, MAX_IDS)] {
            let cache = MembershipCache {
                bytes: Arc::new(Semaphore::new(bytes)),
                ids: Arc::new(Semaphore::new(count)),
                ..MembershipCache::new(true)
            };
            let held = cache
                .get_or_build("first", "article", || async { Ok(ids("first")) })
                .await
                .expect("first lease");
            let retained_bytes = cache.bytes.available_permits();
            assert!(retained_bytes < bytes);
            assert_eq!(cache.ids.available_permits(), count - 1);
            assert_eq!(
                cache
                    .get_or_build("second", "article", || async { Ok(ids("second")) })
                    .await
                    .err()
                    .expect("active lease cannot be evicted out of accounting")
                    .code,
                "capacity"
            );
            assert_eq!(cache.bytes.available_permits(), retained_bytes);
            assert_eq!(held.as_ref(), &ids("first"));
            drop(held);
            cache
                .get_or_build("second", "article", || async { Ok(ids("second")) })
                .await
                .expect("capacity released with last lease");
        }
    }

    #[tokio::test]
    async fn coalesced_fills_are_request_owned_and_cancelled_leaders_can_be_retried() {
        let cache = Arc::new(MembershipCache::new(true));
        let started = Arc::new(Notify::new());
        let leader_cache = cache.clone();
        let leader_started = started.clone();
        let leader = tokio::spawn(async move {
            leader_cache
                .get_or_build("root", "article", || async {
                    leader_started.notify_one();
                    std::future::pending::<Result<BTreeSet<String>>>().await
                })
                .await
        });
        started.notified().await;
        let waiter_cache = cache.clone();
        let waiter = tokio::spawn(async move {
            waiter_cache
                .get_or_build("root", "article", || async { Ok(ids("complete")) })
                .await
        });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        leader.abort();
        assert!(matches!(leader.await, Err(error) if error.is_cancelled()));
        let complete = tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
            .await
            .expect("waiter released")
            .expect("waiter joined")
            .expect("retry complete");
        let reused = cache
            .get_or_build("root", "article", || async {
                Err::<BTreeSet<String>, _>(Error::integrity("successful fill was not retained"))
            })
            .await
            .expect("reuse");
        assert!(Arc::ptr_eq(&complete.0, &reused.0));
    }

    #[tokio::test]
    async fn cancelling_a_waiter_does_not_cancel_the_fill_owner() {
        let cache = Arc::new(MembershipCache::new(true));
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let leader_cache = cache.clone();
        let leader_started = started.clone();
        let leader_release = release.clone();
        let leader = tokio::spawn(async move {
            leader_cache
                .get_or_build("root", "article", || async {
                    leader_started.notify_one();
                    leader_release.notified().await;
                    Ok(ids("complete"))
                })
                .await
        });
        started.notified().await;
        let waiter_cache = cache.clone();
        let waiter = tokio::spawn(async move {
            waiter_cache
                .get_or_build("root", "article", || async { Ok(ids("wrong fill")) })
                .await
        });
        tokio::task::yield_now().await;
        waiter.abort();
        assert!(matches!(waiter.await, Err(error) if error.is_cancelled()));
        assert!(!leader.is_finished());
        release.notify_one();
        let complete = leader.await.expect("join").expect("complete");
        assert_eq!(complete.as_ref(), &ids("complete"));
        let reused = cache
            .get_or_build("root", "article", || async { Ok(ids("wrong fill")) })
            .await
            .expect("reuse owner's fill");
        assert!(Arc::ptr_eq(&complete.0, &reused.0));
    }

    #[tokio::test]
    async fn growing_fills_charge_unique_ids_and_refund_incomplete_work() {
        let cache = MembershipCache {
            ids: Arc::new(Semaphore::new(2)),
            ..MembershipCache::new(true)
        };
        let initial_bytes = cache.bytes.available_permits();
        let input =
            ["first", "first", "second", "third"].map(|s| crate::integrity::hash(s.as_bytes()));
        let observed = AtomicUsize::new(0);
        let observed_ref = &observed;
        let cache_ref = &cache;
        let error = cache
            .get_or_build("root", "article", || async move {
                Ok(input.into_iter().inspect(move |_| {
                    // The previous unique ID is charged before the next input
                    // is read; a duplicate does not consume another ID permit.
                    let expected = [2, 1, 1, 0][observed_ref.fetch_add(1, Ordering::Relaxed)];
                    assert_eq!(cache_ref.ids.available_permits(), expected);
                }))
            })
            .await
            .err()
            .expect("third unique ID exceeds aggregate bound");
        assert_eq!(error.code, "capacity");
        assert_eq!(observed.load(Ordering::Relaxed), 4);
        assert_eq!(cache.ids.available_permits(), 2);
        assert_eq!(cache.bytes.available_permits(), initial_bytes);
        cache
            .get_or_build("root", "article", || async { Ok(ids("recovered")) })
            .await
            .expect("no partial entry or reservation retained");
    }

    #[tokio::test]
    async fn failures_invalid_identities_and_verification_handles_are_never_cached() {
        let cache = MembershipCache::new(true);
        assert_eq!(
            cache
                .get_or_build("root", "article", || async {
                    Err::<BTreeSet<String>, _>(Error::integrity("injected incomplete inventory"))
                })
                .await
                .err()
                .expect("failure")
                .code,
            "integrity"
        );
        assert_eq!(
            cache
                .get_or_build("root", "article", || async {
                    Ok(BTreeSet::from(["invalid projection".into()]))
                })
                .await
                .err()
                .expect("invalid projection")
                .code,
            "integrity"
        );
        let complete = cache
            .get_or_build("root", "article", || async { Ok(ids("complete")) })
            .await
            .expect("complete after failures");
        assert_eq!(complete.as_ref(), &ids("complete"));
        let verifier = MembershipCache::new(false);
        let calls = AtomicUsize::new(0);
        for _ in 0..2 {
            verifier
                .get_or_build("root", "article", || async {
                    calls.fetch_add(1, Ordering::Relaxed);
                    Ok(ids("complete"))
                })
                .await
                .expect("verified again");
        }
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        assert!(verifier.slots.lock().expect("slots").is_empty());
    }
}
