//! Retrieval policy shared by every transport and research operation.
use async_trait::async_trait;
use devres_domain::{Error, FetchRequest, FetchResponse, Result, StoredCapture, Validators};
use std::{
    collections::HashMap,
    sync::{Arc, Weak},
};
use tokio::sync::{Mutex, Semaphore};

#[derive(Clone)]
pub struct Cached {
    pub stored: StoredCapture,
    pub validators: Validators,
}

#[async_trait]
pub trait Store: Send + Sync {
    async fn latest(&self, key: &str) -> Result<Option<Cached>>;
    async fn capture(&self, id: &str) -> Result<StoredCapture>;
    async fn publish(
        &self,
        request: &FetchRequest,
        response: FetchResponse,
        now: i64,
    ) -> Result<StoredCapture>;
    async fn revalidate(
        &self,
        key: &str,
        id: &str,
        validators: Validators,
        now: i64,
    ) -> Result<StoredCapture>;
}

#[async_trait]
pub trait Fetcher: Send + Sync {
    async fn fetch(
        &self,
        request: &FetchRequest,
        validators: Option<&Validators>,
    ) -> Result<FetchResponse>;
}

pub trait Clock: Send + Sync {
    fn now(&self) -> i64;
}
pub struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> i64 {
        devres_domain::unix_now()
    }
}

/// No detached refresh tasks: cancellation drops owned work and releases admission.
pub struct Retrieval {
    store: Arc<dyn Store>,
    fetcher: Arc<dyn Fetcher>,
    clock: Arc<dyn Clock>,
    admission: Semaphore,
    keys: Mutex<HashMap<String, Weak<Mutex<()>>>>,
    negatives: Mutex<HashMap<String, i64>>,
}
impl Retrieval {
    pub fn new(store: Arc<dyn Store>, fetcher: Arc<dyn Fetcher>) -> Self {
        Self::with_clock(store, fetcher, Arc::new(SystemClock))
    }
    pub fn with_clock(
        store: Arc<dyn Store>,
        fetcher: Arc<dyn Fetcher>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            store,
            fetcher,
            clock,
            admission: Semaphore::new(32),
            keys: Mutex::new(HashMap::new()),
            negatives: Mutex::new(HashMap::new()),
        }
    }
    pub async fn read_capture(&self, id: &str) -> Result<StoredCapture> {
        if id.len() != 64
            || !id
                .bytes()
                .all(|v| v.is_ascii_hexdigit() && !v.is_ascii_uppercase())
        {
            return Err(Error::invalid("Invalid capture identifier"));
        }
        let _permit = self
            .admission
            .try_acquire()
            .map_err(|_| Error::capacity("Retrieval capacity exhausted"))?;
        self.store.capture(id).await
    }
    pub async fn get(&self, request: FetchRequest) -> Result<StoredCapture> {
        if request.key.is_empty()
            || request.key.len() > 2048
            || request.max_bytes == 0
            || request.max_bytes > 128 * 1024 * 1024
        {
            return Err(Error::invalid("Invalid retrieval bounds"));
        }
        let _permit = self
            .admission
            .try_acquire()
            .map_err(|_| Error::capacity("Retrieval capacity exhausted"))?;
        let key_lock = {
            let mut keys = self.keys.lock().await;
            keys.retain(|_, lock| lock.strong_count() > 0);
            if let Some(lock) = keys.get(&request.key).and_then(Weak::upgrade) {
                lock
            } else {
                if keys.len() >= 1024 {
                    return Err(Error::capacity("Retrieval key capacity exhausted"));
                }
                let lock = Arc::new(Mutex::new(()));
                keys.insert(request.key.clone(), Arc::downgrade(&lock));
                lock
            }
        };
        let _key_guard = key_lock.lock().await;
        let now = self.clock.now();
        let existing = self.store.latest(&request.key).await?;
        if let Some(cached) = &existing {
            if cached.stored.capture.source_url != request.url
                || cached.stored.body.len() > request.max_bytes
            {
                return Err(Error::integrity(
                    "Capture identity or size does not match request",
                ));
            }
            if now
                .saturating_sub(cached.stored.capture.validated_at)
                .max(0)
                < request.ttl_secs.min(i64::MAX as u64) as i64
            {
                return Ok(cached.stored.clone());
            }
        }
        {
            let mut negatives = self.negatives.lock().await;
            negatives.retain(|_, until| *until > now);
            if negatives.contains_key(&request.key) {
                return Err(Error::not_found("Source record not found"));
            }
        }
        let response = match self
            .fetcher
            .fetch(&request, existing.as_ref().map(|v| &v.validators))
            .await
        {
            Ok(response) => response,
            Err(error) => return self.stale_or_error(existing, now, error),
        };
        match response.status {
            200 => {
                if response.body.len() > request.max_bytes {
                    return Err(Error::capacity("Source body exceeds limit"));
                }
                drop(existing); // Old bytes are no longer needed after a successful replacement.
                self.store.publish(&request, response, now).await
            }
            304 => {
                let old =
                    existing.ok_or_else(|| Error::integrity("Unexpected source revalidation"))?;
                let id = old.stored.capture.id.clone();
                drop(old); // Revalidation reloads the body under the same weighted budget.
                self.store
                    .revalidate(&request.key, &id, response.validators, now)
                    .await
            }
            404 => {
                let mut negatives = self.negatives.lock().await;
                if negatives.len() < 1024 {
                    negatives.insert(request.key, now.saturating_add(300));
                }
                Err(Error::not_found("Source record not found"))
            }
            _ => self.stale_or_error(existing, now, Error::unavailable("Source request failed")),
        }
    }
    fn stale_or_error(
        &self,
        existing: Option<Cached>,
        now: i64,
        error: Error,
    ) -> Result<StoredCapture> {
        // Integrity and admission failures must not be disguised as valid cached results.
        if error.code != "unavailable" {
            return Err(error);
        }
        match existing {
            Some(cached) if now.saturating_sub(cached.stored.capture.validated_at) <= 7 * 86400 => {
                Ok(cached.stored)
            }
            _ => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use devres_domain::Capture;
    use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
    struct TestClock(AtomicI64);
    impl Clock for TestClock {
        fn now(&self) -> i64 {
            self.0.load(Ordering::SeqCst)
        }
    }
    #[derive(Default)]
    struct MemoryStore(Mutex<Option<Cached>>);
    #[async_trait]
    impl Store for MemoryStore {
        async fn latest(&self, _: &str) -> Result<Option<Cached>> {
            Ok(self.0.lock().await.clone())
        }
        async fn capture(&self, _: &str) -> Result<StoredCapture> {
            self.0
                .lock()
                .await
                .as_ref()
                .map(|x| x.stored.clone())
                .ok_or_else(|| Error::not_found("missing"))
        }
        async fn publish(
            &self,
            request: &FetchRequest,
            response: FetchResponse,
            now: i64,
        ) -> Result<StoredCapture> {
            let stored = StoredCapture {
                capture: Capture {
                    id: "a".repeat(64),
                    key: request.key.clone(),
                    source_url: request.url.clone(),
                    body_hash: "b".repeat(64),
                    media_type: request.media_type.clone(),
                    retrieved_at: now,
                    validated_at: now,
                },
                body: response.body.into(),
            };
            *self.0.lock().await = Some(Cached {
                stored: stored.clone(),
                validators: response.validators,
            });
            Ok(stored)
        }
        async fn revalidate(
            &self,
            _: &str,
            _: &str,
            _: Validators,
            now: i64,
        ) -> Result<StoredCapture> {
            let mut state = self.0.lock().await;
            let Some(cached) = state.as_mut() else {
                return Err(Error::not_found("missing"));
            };
            cached.stored.capture.validated_at = now;
            Ok(cached.stored.clone())
        }
    }
    struct MockFetcher {
        calls: AtomicUsize,
        status: AtomicUsize,
    }
    #[async_trait]
    impl Fetcher for MockFetcher {
        async fn fetch(&self, _: &FetchRequest, _: Option<&Validators>) -> Result<FetchResponse> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::task::yield_now().await;
            Ok(FetchResponse {
                status: self.status.load(Ordering::SeqCst) as u16,
                body: b"source".to_vec(),
                validators: Validators::default(),
            })
        }
    }
    fn request() -> FetchRequest {
        FetchRequest {
            key: "rfc:1".into(),
            url: "https://www.rfc-editor.org/rfc/rfc1.txt".into(),
            ttl_secs: 10,
            max_bytes: 100,
            media_type: "text/plain".into(),
        }
    }
    #[tokio::test]
    async fn coalesces_and_revalidates_without_replacing_body() {
        let store = Arc::new(MemoryStore::default());
        let fetch = Arc::new(MockFetcher {
            calls: AtomicUsize::new(0),
            status: AtomicUsize::new(200),
        });
        let clock = Arc::new(TestClock(AtomicI64::new(100)));
        let retrieval = Arc::new(Retrieval::with_clock(store, fetch.clone(), clock.clone()));
        let (a, b) = tokio::join!(retrieval.get(request()), retrieval.get(request()));
        assert_eq!(a.unwrap().body, b.unwrap().body);
        assert_eq!(fetch.calls.load(Ordering::SeqCst), 1);
        fetch.status.store(304, Ordering::SeqCst);
        clock.0.store(111, Ordering::SeqCst);
        let capture = retrieval.get(request()).await.unwrap();
        assert_eq!(capture.body, b"source");
        assert_eq!(capture.capture.retrieved_at, 100);
        assert_eq!(capture.capture.validated_at, 111);
    }
    #[tokio::test]
    async fn negative_cache_expires_and_stale_data_has_a_hard_limit() {
        let fetch = Arc::new(MockFetcher {
            calls: AtomicUsize::new(0),
            status: AtomicUsize::new(404),
        });
        let clock = Arc::new(TestClock(AtomicI64::new(100)));
        let retrieval = Retrieval::with_clock(
            Arc::new(MemoryStore::default()),
            fetch.clone(),
            clock.clone(),
        );
        assert_eq!(
            retrieval.get(request()).await.unwrap_err().code,
            "not_found"
        );
        assert!(retrieval.get(request()).await.is_err());
        assert_eq!(fetch.calls.load(Ordering::SeqCst), 1);
        clock.0.store(401, Ordering::SeqCst);
        fetch.status.store(200, Ordering::SeqCst);
        retrieval.get(request()).await.unwrap();
        fetch.status.store(503, Ordering::SeqCst);
        clock.0.store(420, Ordering::SeqCst);
        assert_eq!(
            retrieval.get(request()).await.unwrap().capture.validated_at,
            401
        );
        clock.0.store(401 + 7 * 86400 + 1, Ordering::SeqCst);
        assert_eq!(
            retrieval.get(request()).await.unwrap_err().code,
            "unavailable"
        );
    }
}
