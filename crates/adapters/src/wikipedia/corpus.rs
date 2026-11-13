//! Sole-writer Wikipedia scheduling and immutable representation publication.
use super::{
    cache::CacheMetadata,
    events::{Change, ChangeKind, SseParser},
    processing,
    source::{Operation, Response, WikipediaSource},
};
use crate::bulk::{BulkArtifact, BulkArtifactStore, BulkBroker};
use devres_application::{
    acquisition::AcquisitionDelegate,
    wikipedia::{State, WikipediaConfig, WikipediaStore, Write},
};
use devres_domain::{Error, Result, Validators};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::AsyncReadExt,
    sync::{Mutex, Semaphore, mpsc, oneshot},
};
use tokio_util::sync::CancellationToken;

const MAX_BODY: u64 = 16 * 1024 * 1024;
fn now() -> i64 {
    devres_domain::unix_now()
}
fn bad() -> Error {
    Error::integrity("Invalid retained Wikipedia evidence.")
}
pub(super) fn network_readiness_error(error: &Error) -> bool {
    matches!(
        error.code.as_str(),
        "wikipedia_configuration_required" | "wikipedia_authentication_failed"
    )
}
fn value<T: Serialize>(v: &T) -> Result<Value> {
    serde_json::to_value(v).map_err(|_| bad())
}
fn decode<T: serde::de::DeserializeOwned>(v: Value) -> Result<T> {
    serde_json::from_value(v).map_err(|_| bad())
}
fn key(prefix: &str, title: &str) -> String {
    format!("{prefix}:{}", crate::integrity::hash(title.as_bytes()))
}
fn state(key: String, data: Value, due_at: Option<i64>) -> State {
    State { key, data, due_at }
}
fn number(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64().filter(|n| *n > 0).ok_or_else(bad)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArticleCapture {
    pub id: String,
    pub page_id: u64,
    pub revision_id: u64,
    pub title: String,
    pub representation: String,
    pub source_url: String,
    pub artifact: BulkArtifact,
    pub projection: Option<BulkArtifact>,
    #[serde(default)]
    pub processing_gaps: Vec<String>,
    pub observed_at: i64,
    pub validated_at: i64,
    pub expires_at: i64,
    pub current: Option<bool>,
    pub cache: CacheMetadata,
    pub license: Value,
    #[serde(default)]
    pub categories: Vec<String>,
    pub acquisition_policy_epoch: u32,
    pub acquisition_policy_fingerprint: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Endpoint {
    cache: CacheMetadata,
    capture: Option<String>,
}

enum PolicyMessage {
    Observe {
        until: i64,
        ack: oneshot::Sender<Result<()>>,
    },
    Barrier(oneshot::Sender<Result<()>>),
}
struct PolicyWorker {
    sender: mpsc::Sender<PolicyMessage>,
    task: tokio::task::JoinHandle<()>,
}
/// One lazy storage-only worker, at most four queued receipts. It owns neither
/// an HTTP transfer nor a Corpus reference. Closing the last sender drains it.
struct PolicyReceipts {
    store: Arc<dyn WikipediaStore>,
    admission: Arc<Mutex<()>>,
    floor: Arc<AtomicI64>,
    worker: std::sync::Mutex<Option<PolicyWorker>>,
}
impl PolicyReceipts {
    fn new(
        store: Arc<dyn WikipediaStore>,
        admission: Arc<Mutex<()>>,
        floor: Arc<AtomicI64>,
    ) -> Self {
        Self {
            store,
            admission,
            floor,
            worker: std::sync::Mutex::new(None),
        }
    }
    fn sender(&self) -> Result<mpsc::Sender<PolicyMessage>> {
        let mut worker = self
            .worker
            .lock()
            .map_err(|_| Error::unavailable("Wikipedia policy receipt worker is unavailable."))?;
        if let Some(worker) = worker.as_ref()
            && !worker.task.is_finished()
        {
            return Ok(worker.sender.clone());
        }
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| {
            Error::unavailable("Wikipedia policy receipts require an async runtime.")
        })?;
        let (sender, mut receiver) = mpsc::channel::<PolicyMessage>(4);
        let store = self.store.clone();
        let admission = self.admission.clone();
        let floor = self.floor.clone();
        let task = runtime.spawn(async move {
            let mut failure: Option<Error> = None;
            while let Some(message) = receiver.recv().await {
                match message {
                    PolicyMessage::Observe { until, ack } => {
                        let result = tokio::time::timeout(Duration::from_secs(30), async {
                            let _guard = admission.lock().await;
                            let target = until.max(floor.load(Ordering::Acquire));
                            let mut data = store
                                .wiki_state("provider:admission")
                                .await?
                                .unwrap_or(json!({}));
                            data["cooldown"] =
                                json!(target.max(data["cooldown"].as_i64().unwrap_or(0)));
                            store
                                .wiki_commit(&[], &[state("provider:admission".into(), data, None)])
                                .await
                        })
                        .await
                        .unwrap_or_else(|_| {
                            Err(Error::unavailable(
                                "Wikipedia policy receipt persistence timed out.",
                            ))
                        });
                        failure = result.as_ref().err().cloned();
                        let _ = ack.send(result);
                    }
                    PolicyMessage::Barrier(ack) => {
                        let _ = ack.send(failure.clone().map_or(Ok(()), Err));
                    }
                }
            }
        });
        *worker = Some(PolicyWorker {
            sender: sender.clone(),
            task,
        });
        Ok(sender)
    }
    fn observe(&self, until: i64) -> Result<super::source::PolicyReceipt> {
        // Synchronous handoff occurs while the response future is being polled;
        // its owner may subsequently disappear without canceling persistence.
        self.floor.fetch_max(until, Ordering::AcqRel);
        let (ack, receipt) = oneshot::channel();
        self.sender()?
            .try_send(PolicyMessage::Observe { until, ack })
            .map_err(|_| Error::capacity("Wikipedia policy receipt queue is full or stopped."))?;
        Ok(Box::pin(async move {
            receipt.await.map_err(|_| {
                Error::unavailable("Wikipedia policy receipt acknowledgement is unavailable.")
            })?
        }))
    }
    async fn drain(&self) -> Result<()> {
        let sender = self
            .worker
            .lock()
            .map_err(|_| Error::unavailable("Wikipedia policy receipt worker is unavailable."))?
            .as_ref()
            .map(|worker| worker.sender.clone());
        let Some(sender) = sender else {
            return Ok(());
        };
        tokio::time::timeout(Duration::from_secs(35), async {
            let (ack, receipt) = oneshot::channel();
            sender
                .send(PolicyMessage::Barrier(ack))
                .await
                .map_err(|_| Error::unavailable("Wikipedia policy receipt worker stopped."))?;
            receipt.await.map_err(|_| {
                Error::unavailable("Wikipedia policy receipt drain acknowledgement is unavailable.")
            })?
        })
        .await
        .map_err(|_| Error::unavailable("Wikipedia policy receipt drain timed out."))?
    }
}

pub struct WikipediaCorpus {
    store: Arc<dyn WikipediaStore>,
    source: WikipediaSource,
    raw: BulkArtifactStore,
    config: WikipediaConfig,
    writer: bool,
    delegate: Option<Arc<dyn AcquisitionDelegate>>,
    network: Mutex<()>,
    admission_updates: Arc<Mutex<()>>,
    policy_receipts: Arc<PolicyReceipts>,
    processing: Mutex<()>,
    // Never held while waiting for upstream I/O or projecting source bytes.
    state_updates: Mutex<()>,
    projection_slots: Arc<Semaphore>,
}
impl WikipediaCorpus {
    pub fn new(
        store: Arc<dyn WikipediaStore>,
        broker: Arc<BulkBroker>,
        root: &Path,
        config: WikipediaConfig,
    ) -> Result<Self> {
        config.validate()?;
        let path = root.join("wikipedia/raw-artifacts");
        crate::integrity::ensure_directory_durable(&path)?;
        let source = WikipediaSource::new(broker);
        let admission_updates = Arc::new(Mutex::new(()));
        let policy_receipts = Arc::new(PolicyReceipts::new(
            store.clone(),
            admission_updates.clone(),
            source.policy_floor(),
        ));
        Ok(Self {
            store,
            source,
            raw: BulkArtifactStore::new(path, config.min_free_bytes)?
                .with_quota(config.max_archive_storage_bytes)?,
            config,
            writer: true,
            delegate: None,
            network: Mutex::new(()),
            admission_updates,
            policy_receipts,
            processing: Mutex::new(()),
            state_updates: Mutex::new(()),
            projection_slots: Arc::new(Semaphore::new(1)),
        })
    }
    pub fn new_reader(
        store: Arc<dyn WikipediaStore>,
        broker: Arc<BulkBroker>,
        root: &Path,
        config: WikipediaConfig,
    ) -> Result<Self> {
        config.validate()?;
        let source = WikipediaSource::new(broker);
        let admission_updates = Arc::new(Mutex::new(()));
        let policy_receipts = Arc::new(PolicyReceipts::new(
            store.clone(),
            admission_updates.clone(),
            source.policy_floor(),
        ));
        Ok(Self {
            store,
            source,
            raw: BulkArtifactStore::for_verification(
                root.join("wikipedia/raw-artifacts"),
                config.min_free_bytes,
            )?,
            config,
            writer: false,
            delegate: None,
            network: Mutex::new(()),
            admission_updates,
            policy_receipts,
            processing: Mutex::new(()),
            state_updates: Mutex::new(()),
            projection_slots: Arc::new(Semaphore::new(1)),
        })
    }
    pub fn with_delegate(mut self, delegate: Option<Arc<dyn AcquisitionDelegate>>) -> Self {
        self.delegate = delegate;
        self
    }
    pub fn store(&self) -> Arc<dyn WikipediaStore> {
        self.store.clone()
    }
    fn policy_observer(&self) -> super::source::PolicyObserver {
        let receipts = self.policy_receipts.clone();
        Arc::new(move |until| receipts.observe(until))
    }
    /// Call after acquisition tasks stop and before shutting down the runtime.
    /// This bounded barrier reports any undrained/failed policy persistence.
    pub async fn drain_policy_receipts(&self) -> Result<()> {
        self.policy_receipts.drain().await
    }
    async fn save(&self, key: &str, data: Value, due: Option<i64>) -> Result<()> {
        self.store
            .wiki_commit(&[], &[state(key.into(), data, due)])
            .await
    }
    pub async fn initialize_status(&self) -> Result<()> {
        if !self.writer {
            return Ok(());
        }
        for title in self
            .config
            .category_roots
            .iter()
            .filter(|_| self.source.network_ready())
        {
            let k = key("category", title);
            match self.store.wiki_state(&k).await? {
                None=>self.save(&k,json!({"title":title,"roots":[title],"continuation":null,"generation":now()}),Some(now())).await?,
                Some(mut data) if data["out_of_scope"]==true && !self.config.excluded_categories.contains(title)=> {
                    data["out_of_scope"]=json!(false);
                    self.save(&k,data,Some(now())).await?;
                },
                Some(_)=>{},
            }
        }
        if self.store.wiki_state("visibility:epoch").await?.is_none() {
            self.save("visibility:epoch", json!(0), None).await?;
        }
        if self.store.wiki_state("aliases").await?.is_none() {
            self.save(
                "aliases",
                json!({"titles":["Template:Current"],"complete":false}),
                None,
            )
            .await?;
        }
        self.save("status",json!({"enabled":self.config.enabled,"coverage":"partial","category_roots":self.config.category_roots}),None).await
    }
    async fn reserve_attempt(&self, cancel: &CancellationToken) -> Result<()> {
        fn millis() -> i64 {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis().min(i64::MAX as u128) as i64)
                .unwrap_or(0)
        }
        self.source.ensure_network_ready()?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(31);
        loop {
            self.source.ensure_network_ready()?;
            let delay = {
                let _guard = self.admission_updates.lock().await;
                self.source.ensure_network_ready()?;
                let mut old = self
                    .store
                    .wiki_state("provider:admission")
                    .await?
                    .unwrap_or(json!({}));
                let observed = self.source.policy_floor().load(Ordering::Acquire);
                if observed > old["cooldown"].as_i64().unwrap_or(0) {
                    old["cooldown"] = json!(observed);
                    self.save("provider:admission", old.clone(), None).await?;
                }
                let due = old["not_before_millis"]
                    .as_i64()
                    .unwrap_or_else(|| old["not_before"].as_i64().unwrap_or(0).saturating_mul(1000))
                    .max(old["cooldown"].as_i64().unwrap_or(0).saturating_mul(1000));
                let delay = due.saturating_sub(millis());
                if delay <= 0 {
                    let next = millis()
                        .saturating_add(1000u32.div_ceil(self.config.requests_per_second) as i64);
                    return self.save("provider:admission",json!({"not_before":next.saturating_add(999)/1000,"not_before_millis":next,"cooldown":old["cooldown"],"attempts":old["attempts"].as_u64().unwrap_or(0).saturating_add(1)}),None).await;
                }
                delay as u64
            };
            if tokio::time::Instant::now() >= deadline {
                return Err(Error::unavailable("Wikipedia provider cooldown is active."));
            }
            tokio::select! {biased;_=cancel.cancelled()=>return Err(Error::new("cancelled","Wikipedia acquisition canceled.")),_=tokio::time::sleep(Duration::from_millis(delay.min(1000)))=>{}}
        }
    }
    async fn cooldown(&self, until: i64) -> Result<()> {
        let _guard = self.admission_updates.lock().await;
        let mut v = self
            .store
            .wiki_state("provider:admission")
            .await?
            .unwrap_or(json!({}));
        v["cooldown"] = json!(until.max(v["cooldown"].as_i64().unwrap_or(0)));
        self.save("provider:admission", v, None).await
    }
    async fn failed_attempt(&self, lane: &str, retry_at: Option<i64>) -> Result<()> {
        let _guard = self.admission_updates.lock().await;
        let k = format!("provider:backoff:{lane}");
        let previous = self.store.wiki_state(&k).await?.unwrap_or(json!({}));
        let count = previous["failures"]
            .as_u64()
            .unwrap_or(0)
            .saturating_add(1)
            .min(9);
        let delay = (5_i64 << (count.saturating_sub(1) as u32)).min(900);
        let until = now().saturating_add(delay).max(retry_at.unwrap_or(0));
        let mut admission = self
            .store
            .wiki_state("provider:admission")
            .await?
            .unwrap_or(json!({}));
        admission["cooldown"] = json!(until.max(admission["cooldown"].as_i64().unwrap_or(0)));
        self.store
            .wiki_commit(
                &[],
                &[
                    state(k, json!({"failures":count,"not_before":until}), None),
                    state("provider:admission".into(), admission, None),
                ],
            )
            .await
    }
    async fn recovered_attempt(&self, lane: &str) -> Result<()> {
        self.save(
            &format!("provider:backoff:{lane}"),
            json!({"failures":0}),
            None,
        )
        .await
    }
    async fn fetch(
        &self,
        op: Operation,
        validators: Validators,
        cancel: CancellationToken,
    ) -> Result<Response> {
        self.source.ensure_network_ready()?;
        let _guard = self.network.lock().await;
        self.source.ensure_network_ready()?;
        let cacheable_metadata = !matches!(
            op,
            Operation::ArticleHtml { .. } | Operation::ArticleSource { .. }
        );
        let cache_key = key("metadata-cache", &op.url()?);
        if cacheable_metadata && let Some(v) = self.store.wiki_state(&cache_key).await? {
            let cache: CacheMetadata = decode(v["cache"].clone())?;
            if cache.freshness_deadline()? > now() && cache.retention_allowed()? {
                let artifact: BulkArtifact = decode(v["artifact"].clone())?;
                return Ok(Response {
                    effective_url: op.url()?,
                    status: 200,
                    body: self.read_artifact(&artifact).await?,
                    validators: cache.validators(),
                    cache,
                    retry_at: None,
                    action_slow_until: None,
                    api_error: None,
                });
            }
        }
        let result = self
            .source
            .fetch_with_policy(
                op,
                validators,
                cancel.clone(),
                || self.reserve_attempt(&cancel),
                self.policy_observer(),
            )
            .await;
        match &result {
            Ok(r) => {
                if let Some(t) = r.retry_at.into_iter().chain(r.action_slow_until).max() {
                    self.cooldown(t).await?;
                }
                if r.status >= 500 || r.status == 429 || r.api_error.is_some() {
                    self.failed_attempt("http", r.retry_at).await?;
                } else {
                    self.recovered_attempt("http").await?;
                }
                if cacheable_metadata
                    && r.status == 200
                    && r.api_error.is_none()
                    && r.cache
                        .public_retention_allowed(self.source.authenticated())?
                {
                    let artifact = self.raw.capture_bytes(r.body.clone(), cancel).await?;
                    self.save(
                        &cache_key,
                        json!({"cache":r.cache,"artifact":artifact}),
                        None,
                    )
                    .await?;
                }
            }
            Err(error) if network_readiness_error(error) => {}
            Err(error) => {
                self.failed_attempt(
                    "http",
                    error.details.as_ref().and_then(|v| v["retry_at"].as_i64()),
                )
                .await?
            }
        }
        result
    }
    pub async fn request_article(&self, title: &str) -> Result<()> {
        self.request_selector(Some(title.to_owned()), None, CancellationToken::new())
            .await
    }
    pub async fn request_selector(
        &self,
        title: Option<String>,
        page_id: Option<u64>,
        cancel: CancellationToken,
    ) -> Result<()> {
        let token = cancel.child_token();
        let _cancel_on_drop = token.clone().drop_guard();
        let cancel = token;
        if title.is_some() == page_id.is_some() {
            return Err(Error::invalid("Select one Wikipedia title or page ID."));
        }
        if !self.writer {
            return self
                .delegate
                .as_ref()
                .ok_or_else(|| Error::unavailable("Wikipedia writer is unavailable."))?
                .wikipedia_request(title, page_id)
                .await;
        }
        self.source.ensure_network_ready()?;
        let _guard = self.processing.lock().await;
        self.source.ensure_network_ready()?;
        let title = if let Some(t) = title {
            super::source::validate_title(&t)?;
            t
        } else {
            let r = self
                .fetch(
                    Operation::Metadata {
                        titles: vec![],
                        page_ids: vec![page_id.ok_or_else(bad)?],
                    },
                    Validators::default(),
                    cancel.clone(),
                )
                .await?;
            let v: Value = serde_json::from_slice(&r.body).map_err(|_| bad())?;
            metadata_pages(&v)
                .into_iter()
                .find_map(|p| p["title"].as_str().map(str::to_owned))
                .ok_or_else(|| Error::not_found("Wikipedia article not found."))?
        };
        let negative_key = key("negative-title", &title);
        if self
            .store
            .wiki_state(&negative_key)
            .await?
            .and_then(|v| v["not_before"].as_i64())
            .is_some_and(|t| t > now())
        {
            return Err(Error::not_found(
                "Wikipedia article not found or outside article scope.",
            ));
        }
        let k = key("demand", &title);
        let work = self
            .store
            .wiki_state(&k)
            .await?
            .filter(|v| v["title"].is_string())
            .unwrap_or_else(|| json!({"title":title,"demand":true}));
        self.save(&k, work.clone(), Some(now())).await?;
        if let Err(error) = self.collect_article(&k, work, cancel).await {
            if error.code == "not_found" || error.code == "invalid_input" {
                let _guard = self.state_updates.lock().await;
                self.store
                    .wiki_commit(
                        &[],
                        &[
                            state(k, Value::Null, None),
                            state(
                                negative_key,
                                json!({"not_before":now().saturating_add(300)}),
                                None,
                            ),
                        ],
                    )
                    .await?;
            }
            return Err(error);
        }
        self.publish_snapshot().await?;
        Ok(())
    }
    pub async fn upstream_search(
        &self,
        query: &str,
        limit: usize,
        cancel: CancellationToken,
    ) -> Result<Value> {
        if !self.writer {
            return self
                .delegate
                .as_ref()
                .ok_or_else(|| Error::unavailable("Wikipedia writer is unavailable."))?
                .wikipedia_search(query.to_owned(), limit)
                .await;
        }
        self.source.ensure_network_ready()?;
        let r = self
            .fetch(
                Operation::Search {
                    query: query.to_owned(),
                    limit,
                },
                Validators::default(),
                cancel,
            )
            .await?;
        if r.status != 200 {
            return Err(Error::unavailable("Wikipedia discovery is unavailable."));
        }
        let v: Value = serde_json::from_slice(&r.body).map_err(|_| bad())?;
        let items=v["pages"].as_array().ok_or_else(bad)?.iter().take(limit).map(|p| {
            let title=p["title"].as_str().unwrap_or("");
            json!({"page_id":p["id"],"fetch_id":format!("wikipedia:{title}"),"url":article_url(title)})
        }).collect::<Vec<_>>();
        Ok(
            json!({"metadata_only_discovery":true,"source":"wikipedia","items":items,"coverage":"upstream_discovery"}),
        )
    }
    async fn collect_article(
        &self,
        work_key: &str,
        work: Value,
        cancel: CancellationToken,
    ) -> Result<()> {
        let requested_title = work["title"].as_str().ok_or_else(bad)?.to_owned();
        let metadata_response = self
            .fetch(
                Operation::Metadata {
                    titles: vec![requested_title.clone()],
                    page_ids: vec![],
                },
                Validators::default(),
                cancel.clone(),
            )
            .await?;
        if metadata_response.status != 200
            || metadata_response.api_error.is_some()
            || metadata_response.body.is_empty()
        {
            return Err(Error::unavailable("Wikipedia metadata is unavailable."));
        }
        let metadata: Value = serde_json::from_slice(&metadata_response.body).map_err(|_| bad())?;
        let metadata_page = metadata_pages(&metadata)
            .into_iter()
            .find(|p| p["ns"] == 0 && p["missing"].is_null())
            .cloned()
            .ok_or_else(|| {
                Error::not_found("Only existing English Wikipedia articles are supported.")
            })?;
        let title = metadata_page["title"].as_str().ok_or_else(bad)?.to_owned();
        super::source::validate_title(&title)?;
        let metadata_pid = number(&metadata_page, "pageid")?;
        let metadata_revision = number(&metadata_page, "lastrevid")?;
        let aliases = self.store.wiki_state("aliases").await?.unwrap_or(json!({}));
        let titles: Vec<String> = aliases["titles"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        let current = super::source::parse_current(
            &metadata,
            metadata_pid,
            metadata_revision,
            &titles,
            aliases["complete"].as_bool() == Some(true),
        );
        let profile = self.config.profile(current);
        let (minimum, fallback) = (profile.minimum_secs, profile.fallback_secs);
        {
            let _guard = self.state_updates.lock().await;
            let mut head = self
                .store
                .wiki_state(&format!("page:{metadata_pid}"))
                .await?
                .unwrap_or_else(|| json!({"page_id":metadata_pid,"title":title}));
            // Fresh metadata can update moving classification even when article
            // TTLs defer body I/O; it never rewrites frozen capture metadata.
            if metadata_revision >= head["current_revision"].as_u64().unwrap_or(0) {
                head["current_revision"] = json!(metadata_revision);
                head["current"] = json!(current);
                head["metadata"] = metadata_page.clone();
            }
            let mut states = vec![
                state(format!("page:{metadata_pid}"), head, None),
                state(key("title", &requested_title), json!(metadata_pid), None),
                state(key("title", &title), json!(metadata_pid), None),
            ];
            if work["demand"] == true {
                states.push(state(
                    format!("tracked-demand:{metadata_pid}"),
                    json!(true),
                    None,
                ));
            }
            self.store.wiki_commit(&[], &states).await?;
        }
        let mut next = now().saturating_add(fallback as i64);
        for (representation, op) in [
            (
                "html",
                Operation::ArticleHtml {
                    title: title.clone(),
                },
            ),
            (
                "wikitext",
                Operation::ArticleSource {
                    title: title.clone(),
                },
            ),
        ] {
            let endpoint_key = key("endpoint", &format!("{representation}:{title}"));
            let previous = self
                .store
                .wiki_state(&endpoint_key)
                .await?
                .map(decode::<Endpoint>)
                .transpose()?;
            if let Some(p) = &previous {
                let floor =
                    profile.endpoint_not_before(p.cache.received_at, p.cache.freshness_deadline()?);
                if floor > now() {
                    next = next.min(floor);
                    continue;
                }
            }
            let restore_identity = {
                let _guard = self.state_updates.lock().await;
                self.store
                    .wiki_state(&format!("events:{metadata_pid}"))
                    .await?
                    .filter(|v| v["last_moderation_kind"] == "restore")
                    .and_then(|v| v["last_moderation_identity"].as_str().map(str::to_owned))
            };
            let r = self
                .fetch(
                    op,
                    if representation == "html"
                        && self
                            .store
                            .wiki_state(&format!("events:{metadata_pid}"))
                            .await?
                            .is_some_and(|v| v["restoration_pending"] == true)
                    {
                        Validators::default()
                    } else {
                        previous
                            .as_ref()
                            .map(|p| p.cache.validators())
                            .unwrap_or_default()
                    },
                    cancel.clone(),
                )
                .await?;
            if r.api_error.is_some() {
                return Err(Error::unavailable(
                    "Wikipedia response policy or metadata is unavailable.",
                ));
            }
            if r.status == 304 {
                let mut previous = previous.ok_or_else(bad)?;
                previous.cache = r.cache.merged_after_304(&previous.cache)?;
                if self.source.authenticated() && !previous.cache.public_retention_allowed(true)? {
                    return Err(Error::unavailable(
                        "Wikipedia authenticated response is not eligible for public retention.",
                    ));
                }
                let _guard = self.state_updates.lock().await;
                if let Some(id) = &previous.capture {
                    self.save(&format!("validation:{id}"),json!({"validated_at":now(),"expires_at":previous.cache.freshness_deadline()?,"cache":previous.cache}),None).await?;
                }
                next = next.min(
                    previous
                        .cache
                        .freshness_deadline()?
                        .max(now().saturating_add(minimum as i64)),
                );
                if !previous.cache.retention_allowed()? {
                    previous.capture = None;
                }
                self.save(&endpoint_key, value(&previous)?, None).await?;
                continue;
            }
            if r.status != 200 {
                return Err(Error::unavailable(
                    "Wikipedia article acquisition is unavailable.",
                ));
            }
            if !r
                .cache
                .public_retention_allowed(self.source.authenticated())?
            {
                if self.source.authenticated() {
                    return Err(Error::unavailable(
                        "Wikipedia authenticated response is not eligible for public retention.",
                    ));
                }
                let _guard = self.state_updates.lock().await;
                if let Some(id) = previous.as_ref().and_then(|v| v.capture.as_ref()) {
                    self.save(&format!("validation:{id}"),json!({"validated_at":now(),"expires_at":r.cache.freshness_deadline()?,"cache":r.cache}),None).await?;
                }
                self.save(
                    &endpoint_key,
                    value(&Endpoint {
                        cache: r.cache,
                        capture: None,
                    })?,
                    None,
                )
                .await?;
                continue;
            }
            let body: Value = serde_json::from_slice(&r.body)
                .map_err(|_| Error::integrity("Malformed Wikipedia article response."))?;
            let pid = number(&body, "id")?;
            let rev = number(&body["latest"], "id")?;
            if pid != metadata_pid {
                return Err(Error::unavailable(
                    "Wikipedia article identity changed during acquisition.",
                ));
            }
            let capture_current = if rev == metadata_revision {
                current
            } else {
                None
            };
            let canonical = body["title"].as_str().ok_or_else(bad)?.to_owned();
            super::source::validate_title(&canonical)?;
            if body["content_model"].as_str() != Some("wikitext")
                || canonical.replace('_', " ") != title.replace('_', " ")
                || body["namespace"].as_i64().is_some_and(|n| n != 0)
            {
                return Err(Error::unavailable(
                    "Only English Wikipedia articles are supported.",
                ));
            }
            let original = body[if representation == "html" {
                "html"
            } else {
                "source"
            }]
            .as_str()
            .ok_or_else(bad)?;
            // Archive admitted source before attempting an optional projection.
            let raw = self
                .raw
                .capture_bytes(original.as_bytes().to_vec(), cancel.clone())
                .await?;
            let mut processing_gaps = Vec::new();
            let projection = if representation == "html" {
                let bytes = original.as_bytes().to_vec();
                let token = cancel.clone();
                let projected = match self.projection_slots.clone().try_acquire_owned() {
                    Ok(permit) => tokio::task::spawn_blocking(move || {
                        let _permit = permit;
                        processing::process_html(&bytes, token)
                    })
                    .await
                    .map_err(|_| bad())
                    .and_then(|v| v),
                    Err(_) => Err(Error::capacity("Wikipedia projection capacity exhausted.")),
                };
                match projected {
                    Ok(projected) => match serde_json::to_vec(&projected).map_err(|_| bad()) {
                        Ok(bytes) => match self.raw.capture_bytes(bytes, cancel.clone()).await {
                            Ok(artifact) => Some(artifact),
                            Err(error) if error.code == "cancelled" => return Err(error),
                            Err(error) => {
                                processing_gaps.push(error.code);
                                None
                            }
                        },
                        Err(error) => {
                            processing_gaps.push(error.code);
                            None
                        }
                    },
                    Err(error) if error.code == "cancelled" => return Err(error),
                    Err(error) => {
                        processing_gaps.push(error.code);
                        None
                    }
                }
            } else {
                None
            };
            if cancel.is_cancelled() {
                return Err(Error::new("cancelled", "Wikipedia acquisition canceled."));
            }
            let identity = crate::integrity::hash(
                &serde_json::to_vec(&(pid, rev, representation, &raw.body_hash, 1u32))
                    .map_err(|_| bad())?,
            );
            let expires = r.cache.freshness_deadline()?;
            let capture = ArticleCapture {
                id: identity.clone(),
                page_id: pid,
                revision_id: rev,
                title: canonical.clone(),
                representation: representation.into(),
                source_url: r.effective_url.clone(),
                artifact: raw,
                projection,
                processing_gaps,
                observed_at: now(),
                validated_at: now(),
                expires_at: expires,
                current: capture_current,
                cache: r.cache.clone(),
                license: body["license"].clone(),
                categories: if rev == metadata_revision {
                    metadata_page["categories"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|c| c["title"].as_str().map(str::to_owned))
                        .collect()
                } else {
                    vec![]
                },
                acquisition_policy_epoch: devres_domain::attribution::ATTRIBUTION_POLICY_EPOCH,
                acquisition_policy_fingerprint:
                    devres_domain::attribution::ATTRIBUTION_POLICY_FINGERPRINT.into(),
            };
            {
                let _guard = self.state_updates.lock().await;
                let mut head = self
                    .store
                    .wiki_state(&format!("page:{pid}"))
                    .await?
                    .unwrap_or(json!({"page_id":pid}));
                head[representation] = json!(identity);
                head["title"] = json!(canonical);
                head["last_observed_at"] = json!(now());
                if rev >= head["current_revision"].as_u64().unwrap_or(0) {
                    head["current"] = json!(capture_current);
                    head["current_revision"] = json!(rev);
                }
                let mut rows = Vec::new();
                if self.store.wiki_get("captures", &identity).await?.is_none() {
                    rows.push(Write {
                        kind: "captures".into(),
                        key: identity.clone(),
                        data: value(&capture)?,
                    });
                }
                let endpoint = Endpoint {
                    cache: r.cache,
                    capture: Some(identity.clone()),
                };
                let mut states = vec![
                    state(format!("page:{pid}"), head, None),
                    state(key("title", &requested_title), json!(pid), None),
                    state(key("title", &canonical), json!(pid), None),
                    state(endpoint_key, value(&endpoint)?, None),
                    state(
                        format!("validation:{identity}"),
                        json!({"validated_at":now(),"expires_at":expires,"cache":endpoint.cache}),
                        None,
                    ),
                ];
                if representation == "html"
                    && rev == metadata_revision
                    && let Some(restore_identity) = restore_identity
                {
                    let event_key = format!("events:{pid}");
                    if let Some(mut observed) = self.store.wiki_state(&event_key).await?
                        && observed["last_moderation_kind"] == "restore"
                        && observed["last_moderation_identity"].as_str()
                            == Some(restore_identity.as_str())
                    {
                        observed["restoration_pending"] = json!(false);
                        states.push(state(event_key, observed, None));
                        states.push(state(format!("visibility:page:{pid}"),json!({"blocked":true,"restore_identity":restore_identity,"verified_revisions":[rev],"verified_at":now()}),None));
                        states.push(state(
                            format!("visibility:restored:{pid}:{rev}"),
                            json!({"restore_identity":restore_identity,"verified_at":now()}),
                            None,
                        ));
                        let epoch = self
                            .store
                            .wiki_state("visibility:epoch")
                            .await?
                            .and_then(|v| v.as_u64())
                            .ok_or_else(bad)?;
                        states.push(state(
                            "visibility:epoch".into(),
                            json!(epoch.saturating_add(1)),
                            None,
                        ));
                    }
                }
                self.store.wiki_commit(&rows, &states).await?;
            }
            next = next.min(expires.max(now().saturating_add(fallback as i64)));
        }
        {
            let _guard = self.state_updates.lock().await;
            let selected = self
                .store
                .wiki_states(work_key, "", 1)
                .await?
                .into_iter()
                .find(|v| v.key == work_key);
            let mut latest = selected.as_ref().map(|v| v.data.clone()).unwrap_or(work);
            let event_key = format!("events:{metadata_pid}");
            let mut observed = self
                .store
                .wiki_state(&event_key)
                .await?
                .unwrap_or(json!({}));
            let head = self
                .store
                .wiki_state(&format!("page:{metadata_pid}"))
                .await?
                .unwrap_or(json!({}));
            let html_revision = if let Some(id) = head["html"].as_str() {
                self.store
                    .wiki_get("captures", id)
                    .await?
                    .and_then(|v| v.data["revision_id"].as_u64())
                    .unwrap_or(0)
            } else {
                0
            };
            let dirty = observed["dirty_revision"]
                .as_u64()
                .unwrap_or(0)
                .max(latest["dirty_revision"].as_u64().unwrap_or(0));
            let pending_restore = observed["restoration_pending"] == true;
            latest["failure"] = Value::Null;
            latest["last_completed_at"] = json!(now());
            let due = if dirty > html_revision || pending_restore {
                let first = latest["pending_since"].as_i64().unwrap_or_else(now);
                latest["pending_since"] = json!(first);
                latest["dirty_revision"] = json!(dirty);
                if let Some(t) = observed["title"].as_str() {
                    latest["title"] = json!(t);
                }
                let floor = self
                    .store
                    .wiki_state(&key("endpoint", &format!("html:{title}")))
                    .await?
                    .map(decode::<Endpoint>)
                    .transpose()?
                    .map(|v| {
                        v.cache
                            .freshness_deadline()
                            .map(|t| t.max(v.cache.received_at.saturating_add(minimum as i64)))
                    })
                    .transpose()?
                    .unwrap_or_else(|| now().saturating_add(minimum as i64));
                let debounce = if current == Some(false) {
                    self.config.normal_debounce_secs
                } else {
                    self.config.current_debounce_secs
                };
                floor
                    .max(first.saturating_add(debounce as i64))
                    .max(now().saturating_add(minimum as i64))
            } else {
                latest["pending_since"] = Value::Null;
                latest["dirty_revision"] = Value::Null;
                if observed["dirty_revision"]
                    .as_u64()
                    .is_some_and(|v| v <= html_revision)
                {
                    observed["dirty_revision"] = Value::Null;
                }
                next.max(now().saturating_add(minimum as i64))
            };
            self.store
                .wiki_commit(
                    &[],
                    &[
                        state(work_key.into(), latest, Some(due)),
                        state(event_key, observed, None),
                    ],
                )
                .await?;
        }
        Ok(())
    }
    async fn collect_category(&self, row: State, cancel: CancellationToken) -> Result<()> {
        let title = row.data["title"].as_str().ok_or_else(bad)?.to_owned();
        if self.config.excluded_categories.contains(&title) {
            return self.save(&row.key, row.data, None).await;
        }
        let category_id = key("membership", &title);
        let membership_prefix = format!("{category_id}:");
        if row.data["phase"] == "reconcile" {
            let _guard = self.state_updates.lock().await;
            let cursor = row.data["reconcile_after"].as_str().unwrap_or("");
            let members = self
                .store
                .wiki_states(&membership_prefix, cursor, 20)
                .await?;
            let mut parent = row.data;
            let mut states = Vec::new();
            let empty = members.is_empty();
            for member in members {
                parent["reconcile_after"] = json!(member.key);
                if member.data["generation"] != parent["generation"]
                    && member.data["active"] == true
                {
                    let pid = number(&member.data, "page_id")?;
                    let mut removed = member.data;
                    removed["active"] = json!(false);
                    states.push(state(member.key, removed.clone(), None));
                    let namespace = removed["namespace"].as_i64().unwrap_or(0);
                    let reverse = if namespace == 14 {
                        format!(
                            "membership-category:{}:{}",
                            crate::integrity::hash(
                                removed["title"].as_str().ok_or_else(bad)?.as_bytes()
                            ),
                            crate::integrity::hash(title.as_bytes())
                        )
                    } else {
                        format!("membership-page:{pid}:{}", key("category", &title))
                    };
                    states.push(state(reverse.clone(), removed, None));
                    if namespace == 14 {
                        continue;
                    }
                    let others = self
                        .store
                        .wiki_states(&format!("membership-page:{pid}:"), "", 100)
                        .await?;
                    // A full page is incomplete evidence of absence. Keep work
                    // active rather than dropping membership beyond this window.
                    let active = others.len() == 100
                        || others
                            .iter()
                            .any(|m| m.key != reverse && m.data["active"] == true);
                    if !active {
                        let work_key = format!("article:{pid}");
                        if let Some(mut work) = self.store.wiki_state(&work_key).await? {
                            work["category_active"] = json!(false);
                            let demand =
                                work["demand"] == true || work["pending_since"].as_i64().is_some();
                            states.push(state(work_key, work, demand.then_some(now())));
                        }
                    }
                }
            }
            if empty {
                parent["phase"] = Value::Null;
                parent["last_complete_at"] = json!(now());
                parent["reconcile_after"] = Value::Null;
            }
            states.push(state(
                row.key,
                parent,
                Some(if empty {
                    now().saturating_add(self.config.category_reconcile_secs as i64)
                } else {
                    now()
                }),
            ));
            return self.store.wiki_commit(&[], &states).await;
        }
        let continuation = row.data["continuation"].as_str().map(str::to_owned);
        let mut parent = row.data;
        if continuation.is_none() {
            parent["generation"] = json!(now());
        }
        let response = self
            .fetch(
                Operation::Category {
                    title: title.clone(),
                    continuation,
                },
                Validators::default(),
                cancel,
            )
            .await?;
        if response.status != 200 || response.api_error.is_some() || response.body.is_empty() {
            return self
                .save(
                    &row.key,
                    parent,
                    Some(response.retry_at.unwrap_or(now() + 60)),
                )
                .await;
        }
        let v: Value = serde_json::from_slice(&response.body).map_err(|_| bad())?;
        let members = v
            .pointer("/query/categorymembers")
            .and_then(Value::as_array)
            .ok_or_else(bad)?;
        if members.len() > 500 {
            return Err(Error::capacity(
                "Wikipedia category response exceeds its member bound.",
            ));
        }
        for chunk in members.chunks(25) {
            let _guard = self.state_updates.lock().await;
            let mut states = Vec::new();
            for member in chunk {
                let Some(name) = member["title"].as_str() else {
                    continue;
                };
                let ns = member["ns"].as_i64().unwrap_or(-1);
                let pid = number(member, "pageid")?;
                let child = if ns == 14 {
                    key("category", name)
                } else if ns == 0 {
                    format!("article:{pid}")
                } else {
                    continue;
                };
                if ns == 14 && self.config.excluded_categories.iter().any(|v| v == name) {
                    continue;
                }
                let old = self
                    .store
                    .wiki_states(&child, "", 1)
                    .await?
                    .into_iter()
                    .find(|v| v.key == child);
                let mut work = old.as_ref().map(|v| v.data.clone()).unwrap_or_else(
                    || json!({"title":name,"roots":[],"continuation":null,"discovered_at":now()}),
                );
                let mut roots = work["roots"].as_array().cloned().unwrap_or_default();
                let before = roots.len();
                for root in parent["roots"].as_array().into_iter().flatten() {
                    if !roots.contains(root) {
                        roots.push(root.clone());
                    }
                }
                work["roots"] = json!(roots);
                work["category_active"] = json!(true);
                let due = if old.is_none() || ns == 14 && roots.len() > before {
                    Some(now())
                } else {
                    old.and_then(|v| v.due_at).or(Some(now()))
                };
                states.push(state(child, work, due));
                let membership = json!({"page_id":pid,"namespace":ns,"title":name,"category":title,"roots":parent["roots"],"generation":parent["generation"],"active":true});
                states.push(state(
                    format!("{membership_prefix}{pid}"),
                    membership.clone(),
                    None,
                ));
                let reverse = if ns == 14 {
                    format!(
                        "membership-category:{}:{}",
                        crate::integrity::hash(name.as_bytes()),
                        crate::integrity::hash(title.as_bytes())
                    )
                } else {
                    format!("membership-page:{pid}:{}", key("category", &title))
                };
                states.push(state(reverse, membership, None));
            }
            self.store.wiki_commit(&[], &states).await?;
        }
        let continuation = v.pointer("/continue/cmcontinue").and_then(Value::as_str);
        parent["continuation"] = json!(continuation);
        parent["last_observed_at"] = json!(now());
        if continuation.is_none() {
            parent["phase"] = json!("reconcile");
            parent["reconcile_after"] = json!("");
        }
        let _guard = self.state_updates.lock().await;
        self.store
            .wiki_commit(&[], &[state(row.key, parent, Some(now()))])
            .await
    }
    async fn update_aliases(&self, cancel: CancellationToken) -> Result<()> {
        let old = self.store.wiki_state("aliases").await?.unwrap_or(json!({}));
        if old["observed_at"]
            .as_i64()
            .is_some_and(|t| now() - t < 86400)
        {
            return Ok(());
        }
        let response = self
            .fetch(
                Operation::CurrentAliases { continuation: None },
                Validators::default(),
                cancel,
            )
            .await?;
        if response.status != 200 {
            return Ok(());
        }
        let v: Value = serde_json::from_slice(&response.body).map_err(|_| bad())?;
        let mut titles = vec!["Template:Current".to_owned()];
        for p in metadata_pages(&v) {
            if let Some(rs) = p["redirects"].as_array() {
                for r in rs {
                    if let Some(t) = r["title"].as_str() {
                        titles.push(t.into());
                    }
                }
            }
        }
        self.save(
            "aliases",
            json!({"titles":titles,"complete":v.get("continue").is_none(),"observed_at":now()}),
            None,
        )
        .await
    }
    pub async fn publish_snapshot(&self) -> Result<Value> {
        let cutoff = self.store.wiki_cutoff().await?;
        let content = json!({"cutoff":cutoff,"published_at":now(),"coverage":"partial","language":"en","category_roots":self.config.category_roots});
        let id = crate::integrity::hash(&serde_json::to_vec(&content).map_err(|_| bad())?);
        let mut snapshot = content;
        snapshot["id"] = json!(id);
        self.store
            .wiki_commit(
                &[Write {
                    kind: "snapshots".into(),
                    key: id.clone(),
                    data: snapshot.clone(),
                }],
                &[state("snapshot:default".into(), snapshot.clone(), None)],
            )
            .await?;
        Ok(snapshot)
    }
    async fn reconcile_pages(&self, row: State) -> Result<()> {
        let _guard = self.state_updates.lock().await;
        let pages = self
            .store
            .wiki_states("page:", row.data["after"].as_str().unwrap_or(""), 30)
            .await?;
        let empty = pages.is_empty();
        let mut cursor = row.data;
        let mut states = Vec::new();
        for p in pages {
            cursor["after"] = json!(p.key);
            let Some(pid) = p.data["page_id"].as_u64() else {
                continue;
            };
            let work_key = format!("article:{pid}");
            let existing = self
                .store
                .wiki_states(&work_key, "", 1)
                .await?
                .into_iter()
                .find(|v| v.key == work_key);
            let mut work = existing
                .as_ref()
                .map(|v| v.data.clone())
                .unwrap_or_else(|| json!({"title":p.data["title"]}));
            work["visibility_reconciliation"] = json!(true);
            states.push(state(
                work_key,
                work,
                Some(existing.and_then(|v| v.due_at).unwrap_or_else(now)),
            ));
        }
        states.push(state(
            row.key,
            cursor,
            if empty { None } else { Some(now()) },
        ));
        self.store.wiki_commit(&[], &states).await
    }
    pub async fn run(&self, cancel: CancellationToken) -> Result<()> {
        if !self.config.enabled || !self.source.network_ready() {
            cancel.cancelled().await;
            return Ok(());
        }
        self.initialize_status().await?;
        let mut turn = 0u64;
        let mut next_publication = now();
        loop {
            if cancel.is_cancelled() {
                return Ok(());
            }
            if !self.source.network_ready() {
                cancel.cancelled().await;
                return Ok(());
            }
            let result = {
                let _guard = self.processing.lock().await;
                let prefix = match turn % 4 {
                    0 => "demand:",
                    1 => "article:",
                    2 => "category:",
                    _ => "reconcile:",
                };
                let rows = self.store.wiki_due(prefix, now(), 1).await?;
                if let Some(row) = rows.into_iter().next() {
                    let saved = row.clone();
                    let scoped = async {
                        if prefix == "category:" {
                            super::scope::category_reachable(
                                self.store.as_ref(),
                                &self.config,
                                row.data["title"].as_str().ok_or_else(bad)?,
                                &cancel,
                            )
                            .await
                        } else if prefix == "article:" {
                            let page_id = row
                                .key
                                .strip_prefix("article:")
                                .and_then(|v| v.parse::<u64>().ok())
                                .ok_or_else(bad)?;
                            super::scope::article_reachable(
                                self.store.as_ref(),
                                &self.config,
                                page_id,
                                &cancel,
                            )
                            .await
                        } else {
                            Ok(true)
                        }
                    }
                    .await;
                    let r = if matches!(&scoped, Ok(false)) {
                        let _guard = self.state_updates.lock().await;
                        let mut data = self
                            .store
                            .wiki_state(&row.key)
                            .await?
                            .unwrap_or(row.data.clone());
                        data["out_of_scope"] = json!(true);
                        self.save(&row.key, data, None).await
                    } else if let Err(error) = scoped {
                        Err(error)
                    } else if prefix == "category:" {
                        self.collect_category(row, cancel.clone()).await
                    } else if prefix == "reconcile:" {
                        self.reconcile_pages(row).await
                    } else {
                        self.collect_article(&row.key, row.data, cancel.clone())
                            .await
                    };
                    if let Err(e) = &r
                        && !network_readiness_error(e)
                    {
                        let _guard = self.state_updates.lock().await;
                        let current = self
                            .store
                            .wiki_states(&saved.key, "", 1)
                            .await?
                            .into_iter()
                            .find(|v| v.key == saved.key)
                            .unwrap_or(saved);
                        let mut failed = current.data;
                        failed["failure"] = json!(e.code);
                        self.save(
                            &current.key,
                            failed,
                            Some(current.due_at.unwrap_or(0).max(now() + 60)),
                        )
                        .await?;
                    }
                    r
                } else {
                    Ok(())
                }
            };
            if let Err(error) = result {
                tracing::warn!(code=%error.code,"Wikipedia collection slice deferred");
            }
            if !self.source.network_ready() {
                cancel.cancelled().await;
                return Ok(());
            }
            if now() >= next_publication {
                self.publish_snapshot().await?;
                self.update_aliases(cancel.clone()).await?;
                next_publication = now() + self.config.publication_interval_secs as i64;
            }
            turn = turn.wrapping_add(1);
            tokio::select! {biased;_=cancel.cancelled()=>return Ok(()),_=tokio::time::sleep(Duration::from_secs(self.config.collection_interval_secs))=>{}}
        }
    }
    pub async fn run_events(&self, cancel: CancellationToken) -> Result<()> {
        if !self.config.enabled || !self.source.network_ready() {
            cancel.cancelled().await;
            return Ok(());
        }
        loop {
            if cancel.is_cancelled() {
                return Ok(());
            }
            if !self.source.network_ready() {
                cancel.cancelled().await;
                return Ok(());
            }
            let checkpoint = self
                .store
                .wiki_state("stream:checkpoint")
                .await?
                .unwrap_or(json!({}));
            let delay = self
                .store
                .wiki_state("stream:retry")
                .await?
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            if delay > now() {
                tokio::select! {biased;_=cancel.cancelled()=>return Ok(()),_=tokio::time::sleep(Duration::from_secs((delay-now()).min(30) as u64))=>{}}
                if delay > now() {
                    continue;
                }
            }
            let connection = {
                let _guard = self.network.lock().await;
                let result = match self.reserve_attempt(&cancel).await {
                    Ok(()) => {
                        self.source
                            .stream_with_policy(
                                checkpoint["id"].as_str().map(str::to_owned),
                                cancel.clone(),
                                self.policy_observer(),
                            )
                            .await
                    }
                    Err(error) => Err(error),
                };
                let response_policy = match &result {
                    Ok(response) => (Some(response.status), response.retry_at),
                    Err(error) => (
                        None,
                        error.details.as_ref().and_then(|v| v["retry_at"].as_i64()),
                    ),
                };
                match response_policy {
                    (Some(200), retry_at) => {
                        if let Some(until) = retry_at {
                            self.cooldown(until).await?;
                        }
                    }
                    (_, _) if result.as_ref().is_err_and(network_readiness_error) => {}
                    (_, retry_at) => self.failed_attempt("stream", retry_at).await?,
                }

                result
            };
            match connection {
                Ok(mut connection) if connection.status == 200 => {
                    let mut parser = SseParser::default();
                    let mut recovered = false;
                    self.save(
                        "stream:status",
                        json!({"connected":true,"connected_at":now(),"coverage":"observed_events"}),
                        None,
                    )
                    .await?;
                    loop {
                        let chunk = tokio::select! {biased;_=cancel.cancelled()=>return Ok(()),v=tokio::time::timeout(Duration::from_secs(90),connection.stream.next())=>v};
                        let chunk = match chunk {
                            Ok(Some(Ok(chunk))) => chunk,
                            Ok(Some(Err(error))) => {
                                self.failed_attempt(
                                    "stream",
                                    error.details.as_ref().and_then(|v| v["retry_at"].as_i64()),
                                )
                                .await?;
                                break;
                            }
                            Err(_) => {
                                self.failed_attempt("stream", None).await?;
                                break;
                            }
                            Ok(None) => {
                                if !recovered {
                                    self.failed_attempt("stream", None).await?;
                                }
                                break;
                            }
                        };
                        let events = match parser.push(&chunk) {
                            Ok(v) => v,
                            Err(_) => {
                                self.failed_attempt("stream", None).await?;
                                self.stream_gap("invalid_frame", true).await?;
                                break;
                            }
                        };
                        for event in events {
                            if !recovered && event.id.is_some() {
                                self.recovered_attempt("stream").await?;
                                recovered = true;
                            }
                            self.accept_stream_event(event).await?;
                        }
                    }
                }
                Ok(c) => {
                    self.stream_gap(
                        "resume_or_connection_failed",
                        matches!(c.status, 400 | 409 | 410 | 422),
                    )
                    .await?
                }
                Err(_) => {}
            }
            if !self.source.network_ready() {
                cancel.cancelled().await;
                return Ok(());
            }
            self.save(
                "stream:status",
                json!({"connected":false,"observed_at":now(),"coverage":"reconciliation_pending"}),
                None,
            )
            .await?;
            let retry = self
                .store
                .wiki_state("stream:retry-seconds")
                .await?
                .and_then(|v| v.as_i64())
                .unwrap_or(5);
            self.save(
                "stream:retry",
                json!(now().saturating_add(retry.max(5))),
                None,
            )
            .await?;
            tokio::select! {biased;_=cancel.cancelled()=>return Ok(()),_=tokio::time::sleep(Duration::from_secs(5))=>{}}
        }
    }
    async fn accept_stream_event(&self, event: super::events::SseEvent) -> Result<()> {
        let _guard = self.state_updates.lock().await;
        let mut states = Vec::new();
        if let Some(ms) = event.retry_millis {
            states.push(state(
                "stream:retry-seconds".into(),
                json!(ms.div_ceil(1000).max(5)),
                None,
            ));
        }
        if let Some(change) = event.change {
            states.extend(self.event_states(&change).await?);
        }
        if let Some(id) = event.id {
            states.push(state(
                "stream:checkpoint".into(),
                json!({"id":id,"observed_at":now()}),
                None,
            ));
        }
        self.store.wiki_commit(&[], &states).await
    }
    async fn event_states(&self, c: &Change) -> Result<Vec<State>> {
        // The caller holds state_updates through the resulting atomic commit.
        let pid = if let Some(id) = c.page_id {
            Some(id)
        } else {
            self.store
                .wiki_state(&key("title", &c.title))
                .await?
                .and_then(|v| v.as_u64())
        };
        let Some(pid) = pid else { return Ok(vec![]) };
        let Some(page) = self.store.wiki_state(&format!("page:{pid}")).await? else {
            return Ok(vec![]);
        };
        let event_key = format!("events:{pid}");
        let mut observed = self
            .store
            .wiki_state(&event_key)
            .await?
            .unwrap_or_else(|| json!({"title":page["title"]}));
        let identity = crate::integrity::hash(&serde_json::to_vec(c).map_err(|_| bad())?);
        let mut recent = observed["recent_event_ids"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        if recent.iter().any(|v| v.as_str() == Some(&identity)) {
            return Ok(vec![]);
        }
        if matches!(c.kind, ChangeKind::Edit | ChangeKind::New)
            && c.revision_id
                .is_some_and(|r| r <= observed["last_event_revision"].as_u64().unwrap_or(0))
        {
            return Ok(vec![]);
        }
        let moderation = matches!(
            c.kind,
            ChangeKind::Delete | ChangeKind::Restore | ChangeKind::RevisionVisibility { .. }
        );
        let old_moderation_time = observed["last_moderation_timestamp"].as_i64().unwrap_or(-1);
        if moderation
            && (c.timestamp < old_moderation_time
                || c.timestamp == old_moderation_time
                    && matches!(c.kind, ChangeKind::Restore)
                    && observed["last_moderation_kind"] == "delete")
        {
            return Ok(vec![]);
        }
        recent.push(json!(identity));
        if recent.len() > 64 {
            recent.remove(0);
        }
        observed["recent_event_ids"] = json!(recent);
        if let Some(r) = c.revision_id {
            observed["last_event_revision"] =
                json!(r.max(observed["last_event_revision"].as_u64().unwrap_or(0)));
        }
        let mut states = Vec::new();
        match &c.kind {
            ChangeKind::Delete => {
                observed["restoration_pending"] = json!(false);
                observed["last_moderation_kind"] = json!("delete");
                states.push(state(
                    format!("visibility:page:{pid}"),
                    json!({"blocked":true,"observed_at":now()}),
                    None,
                ));
            }
            ChangeKind::RevisionVisibility { revision_ids } => {
                observed["restoration_pending"] = json!(false);
                observed["last_moderation_kind"] = json!("revision_visibility");
                if revision_ids.is_empty() || revision_ids.len() > 80 {
                    states.push(state(format!("visibility:page:{pid}"),json!({"blocked":true,"observed_at":now(),"reason":"unspecified_revision_visibility"}),None));
                } else {
                    for rev in revision_ids {
                        states.push(state(
                            format!("visibility:revision:{pid}:{rev}"),
                            json!({"blocked":true,"observed_at":now()}),
                            None,
                        ));
                    }
                }
            }
            ChangeKind::Move { new_title } => {
                observed["title"] = json!(new_title);
                states.push(state(key("title", new_title), json!(pid), None));
            }
            ChangeKind::Restore => {
                states.push(state(format!("visibility:page:{pid}"),json!({"blocked":true,"observed_at":now(),"reason":"restoration_requires_public_verification"}),None));
                observed["restoration_pending"] = json!(true);
                observed["last_moderation_kind"] = json!("restore");
            }
            ChangeKind::Edit | ChangeKind::New => {}
        }
        if moderation {
            observed["last_moderation_timestamp"] = json!(c.timestamp);
            observed["last_moderation_identity"] = json!(identity);
        }
        if !states.is_empty() || moderation {
            let epoch = self
                .store
                .wiki_state("visibility:epoch")
                .await?
                .and_then(|v| v.as_u64())
                .ok_or_else(bad)?;
            states.push(state(
                "visibility:epoch".into(),
                json!(epoch.saturating_add(1)),
                None,
            ));
        }
        let rev = c.revision_id.unwrap_or(0);
        if rev > observed["dirty_revision"].as_u64().unwrap_or(0) {
            observed["dirty_revision"] = json!(rev);
        }
        let work_key = format!("article:{pid}");
        let mut work = self
            .store
            .wiki_state(&work_key)
            .await?
            .unwrap_or_else(|| json!({"title":observed["title"]}));
        let first = work["pending_since"].as_i64().unwrap_or_else(now);
        let debounce = if page["current"] == false {
            self.config.normal_debounce_secs
        } else {
            self.config.current_debounce_secs
        };
        work["title"] = observed["title"].clone();
        work["pending_since"] = json!(first);
        work["dirty_revision"] = json!(rev.max(work["dirty_revision"].as_u64().unwrap_or(0)));
        states.push(state(
            work_key,
            work,
            Some(first.saturating_add(debounce as i64)),
        ));
        states.push(state(event_key, observed, None));
        Ok(states)
    }
    async fn stream_gap(&self, reason: &str, reset_checkpoint: bool) -> Result<()> {
        let _guard = self.state_updates.lock().await;
        let mut states = vec![
            state(
                "stream:gap".into(),
                json!({"observed_at":now(),"reason":reason}),
                None,
            ),
            state("reconcile:stream".into(), json!({"after":""}), Some(now())),
        ];
        if reset_checkpoint {
            states.push(state(
                "stream:checkpoint".into(),
                json!({"id":null,"gap_at":now()}),
                None,
            ));
        }
        self.store.wiki_commit(&[], &states).await
    }
    pub async fn ensure_visible(&self, page_id: u64, revision_id: u64) -> Result<()> {
        self.store
            .wiki_state("visibility:epoch")
            .await?
            .filter(|v| v.as_u64().is_some())
            .ok_or_else(|| Error::unavailable("Wikipedia visibility state is unavailable."))?;
        if let Some(v) = self
            .store
            .wiki_state(&format!("visibility:revision:{page_id}:{revision_id}"))
            .await?
            && v["blocked"].as_bool().ok_or_else(bad)?
        {
            return Err(Error::new(
                "wikipedia_withheld",
                "Wikipedia source content is withheld.",
            ));
        }
        if let Some(v) = self
            .store
            .wiki_state(&format!("visibility:page:{page_id}"))
            .await?
            && v["blocked"].as_bool().ok_or_else(bad)?
        {
            let allowed = v["verified_revisions"]
                .as_array()
                .is_some_and(|items| items.iter().any(|id| id.as_u64() == Some(revision_id)));
            let certificate = self
                .store
                .wiki_state(&format!("visibility:restored:{page_id}:{revision_id}"))
                .await?;
            let certified = v["restore_identity"].as_str().is_some_and(|id| {
                certificate
                    .as_ref()
                    .and_then(|v| v["restore_identity"].as_str())
                    == Some(id)
            });
            if !allowed && !certified {
                return Err(Error::new(
                    "wikipedia_withheld",
                    "Wikipedia source content is withheld.",
                ));
            }
        }
        Ok(())
    }
    pub async fn visibility_epoch(&self) -> Result<Value> {
        self.store
            .wiki_state("visibility:epoch")
            .await?
            .ok_or_else(|| Error::unavailable("Wikipedia visibility state is unavailable."))
    }
    pub async fn research_view(&self, input: &Value) -> Result<Value> {
        if let Some(id) = input["snapshot"].as_str() {
            return self
                .store
                .wiki_get("snapshots", id)
                .await?
                .map(|r| r.data)
                .ok_or_else(|| Error::not_found("Wikipedia snapshot not found."));
        }
        self.store
            .wiki_state("snapshot:default")
            .await?
            .ok_or_else(|| Error::unavailable("Wikipedia corpus is not published yet."))
    }
    pub async fn research_catalog(&self, input: &Value) -> Result<Vec<Value>> {
        let view = self.research_view(input).await?;
        let limit = input["limit"].as_u64().unwrap_or(100).min(100) as usize;
        self.store
            .wiki_catalog(
                input["after_page_id"].as_u64().unwrap_or(0),
                limit,
                view["cutoff"].as_i64().ok_or_else(bad)?,
            )
            .await?
            .into_iter()
            .map(|r| Ok(r.data))
            .collect()
    }
    async fn select_research_capture(
        &self,
        input: &Value,
        representation: &str,
    ) -> Result<(ArticleCapture, Option<Value>, bool)> {
        let frozen = (input["capture"].is_string() || input["snapshot"].is_string())
            && input["require_current"] != true;
        let title = input["title"].as_str();
        let mut pid = input["page_id"].as_u64();
        if pid.is_none()
            && let Some(title) = title
        {
            pid = self
                .store
                .wiki_state(&key("title", title))
                .await?
                .and_then(|value| value.as_u64());
        }
        if !frozen && !input["capture"].is_string() {
            // Demand must finish before freezing the newly published default view.
            let initial = self.store.wiki_state("snapshot:default").await?;
            let initial_cutoff = initial
                .as_ref()
                .and_then(|view| view["cutoff"].as_i64())
                .unwrap_or(0);
            let has_head = if let Some(page) = pid {
                self.store
                    .wiki_catalog(page.saturating_sub(1), 1, initial_cutoff)
                    .await?
                    .iter()
                    .any(|row| row.data["page_id"].as_u64() == Some(page))
            } else {
                false
            };
            if !has_head {
                self.request_selector(
                    title.map(str::to_owned),
                    input["page_id"].as_u64(),
                    CancellationToken::new(),
                )
                .await?;
                if pid.is_none()
                    && let Some(title) = title
                {
                    pid = self
                        .store
                        .wiki_state(&key("title", title))
                        .await?
                        .and_then(|value| value.as_u64());
                }
            }
        }
        let view = if input["snapshot"].is_string() {
            Some(self.research_view(input).await?)
        } else if input["capture"].is_string() {
            None
        } else {
            Some(self.research_view(input).await?)
        };
        let cutoff = view
            .as_ref()
            .and_then(|v| v["cutoff"].as_i64())
            .unwrap_or(i64::MAX);
        let selected = if let Some(id) = input["capture"].as_str() {
            self.store
                .wiki_get("captures", id)
                .await?
                .ok_or_else(|| Error::not_found("Wikipedia capture not found."))?
        } else {
            let pid = pid.ok_or_else(|| Error::not_found("Wikipedia article is not captured."))?;
            let target = if representation == "wikitext" {
                "wikitext"
            } else {
                "html"
            };
            let head = self
                .store
                .wiki_catalog(pid.saturating_sub(1), 1, cutoff)
                .await?
                .into_iter()
                .find(|r| r.data["page_id"].as_u64() == Some(pid));
            let revision = head.as_ref().and_then(|r| r.data["revision_id"].as_u64());
            if target == "html" {
                head.ok_or_else(|| {
                    Error::not_found("Wikipedia HTML representation is not captured.")
                })?
            } else {
                let mut after = 0;
                let mut selected = None;
                loop {
                    let rows = self
                        .store
                        .wiki_page_captures(pid, after, 100, cutoff)
                        .await?;
                    if rows.is_empty() {
                        break;
                    }
                    for row in rows {
                        after = row.sequence;
                        if row.data["representation"] == target
                            && (revision.is_none() || row.data["revision_id"].as_u64() == revision)
                        {
                            selected = Some(row);
                        }
                    }
                    if after > cutoff {
                        break;
                    }
                }
                selected.ok_or_else(|| {
                    Error::unavailable(
                        "Wikipedia format is unavailable for the selected article revision.",
                    )
                })?
            }
        };
        if selected.sequence > cutoff {
            return Err(Error::not_found(
                "Wikipedia capture is outside the selected snapshot.",
            ));
        }
        Ok((decode(selected.data)?, view, frozen))
    }
    /// Metadata remains readable even when present moderation policy withholds bodies.
    pub async fn research_metadata(&self, input: &Value) -> Result<Value> {
        if !input.is_object() {
            return Err(Error::invalid("Wikipedia selectors must be objects."));
        }
        let mut selected_input = input.clone();
        if !input["capture"].is_string() || input["snapshot"].is_string() {
            // Metadata selects published evidence; a missing HTML format does
            // not authorize acquisition or an implicit change of snapshot.
            let view = self.research_view(input).await?;
            selected_input["snapshot"] = json!(view["id"].as_str().ok_or_else(bad)?);
        }
        let (capture, view, _) = match self.select_research_capture(&selected_input, "text").await {
            Ok(selected) => selected,
            Err(error) if error.code == "not_found" && !selected_input["capture"].is_string() => {
                self.select_research_capture(&selected_input, "wikitext")
                    .await?
            }
            Err(error) => return Err(error),
        };
        let body_public = self
            .ensure_visible(capture.page_id, capture.revision_id)
            .await
            .is_ok();
        Ok(
            json!({"capture":capture,"snapshot":view,"body_public":body_public,"source":"wikipedia"}),
        )
    }
    pub async fn research_document(&self, input: &Value, representation: &str) -> Result<Value> {
        if !matches!(representation, "text" | "markdown" | "html" | "wikitext") {
            return Err(Error::invalid("Unknown Wikipedia representation."));
        }
        let (mut capture, view, frozen) =
            self.select_research_capture(input, representation).await?;
        if representation == "wikitext" && capture.representation != "wikitext"
            || representation != "wikitext" && capture.representation != "html"
        {
            return Err(Error::unavailable(
                "The selected capture does not contain that representation.",
            ));
        }
        self.ensure_visible(capture.page_id, capture.revision_id)
            .await?;
        let page = self
            .store
            .wiki_state(&format!("page:{}", capture.page_id))
            .await?
            .unwrap_or(json!({}));
        let event_info = self
            .store
            .wiki_state(&format!("events:{}", capture.page_id))
            .await?
            .unwrap_or(json!({}));
        let known_latest = [
            event_info["dirty_revision"].as_u64(),
            event_info["last_event_revision"].as_u64(),
            page["dirty_revision"].as_u64(),
            page["last_event_revision"].as_u64(),
            page["current_revision"].as_u64(),
            page.pointer("/metadata/lastrevid").and_then(Value::as_u64),
        ]
        .into_iter()
        .flatten()
        .max();
        let observed_newer_revision =
            known_latest.is_some_and(|revision| revision > capture.revision_id);
        if !frozen {
            if let Some(v) = self
                .store
                .wiki_state(&format!("validation:{}", capture.id))
                .await?
            {
                capture.validated_at = v["validated_at"].as_i64().ok_or_else(bad)?;
                capture.expires_at = v["expires_at"].as_i64().ok_or_else(bad)?;
                capture.cache = decode(v["cache"].clone())?;
            }
            capture.current = if page["current_revision"].as_u64() == Some(capture.revision_id) {
                page["current"].as_bool()
            } else {
                None
            };
            let profile = self.config.profile(capture.current);
            if !capture.cache.retention_allowed()? {
                return Err(Error::unavailable(
                    "Wikipedia current representation is unavailable under upstream cache policy.",
                ));
            }
            if !profile.permits_current_read(
                now(),
                capture.expires_at,
                capture.cache.stale_allowed()?,
            ) {
                return Err(Error::unavailable("Wikipedia current content is expired."));
            }
        }
        let (text, projection) = if representation == "text" || representation == "markdown" {
            let projection = capture
                .projection
                .as_ref()
                .ok_or_else(|| Error::unavailable("Wikipedia projection is unavailable."))?;
            let bytes = self.read_artifact(projection).await?;
            let v: Value = serde_json::from_slice(&bytes).map_err(|_| bad())?;
            (v[representation].as_str().ok_or_else(bad)?.to_owned(), v)
        } else {
            (
                String::from_utf8(self.read_artifact(&capture.artifact).await?)
                    .map_err(|_| bad())?,
                json!({}),
            )
        };
        self.ensure_visible(capture.page_id, capture.revision_id)
            .await?;
        let uri = format!("devres://wikipedia/{}/{representation}", capture.id);
        let stale = now() > capture.expires_at || observed_newer_revision;
        let mut metadata = value(&capture)?;
        metadata["observed_newer_revision"] = json!(observed_newer_revision);
        metadata["update_pending"] = json!(observed_newer_revision);
        metadata["stale"] = json!(stale);
        Ok(
            json!({"capture":metadata,"text":text,"projection":projection,"resource_uri":uri,"snapshot":view,"stale":stale,"observed_newer_revision":observed_newer_revision,"update_pending":observed_newer_revision,"source_evidence":{"wikipedia_evidence":capture},"source":"wikipedia"}),
        )
    }
    async fn read_artifact(&self, artifact: &BulkArtifact) -> Result<Vec<u8>> {
        let file = self
            .raw
            .open(&artifact.body_hash, MAX_BODY, CancellationToken::new())
            .await?;
        let mut bytes = Vec::new();
        file.take(MAX_BODY + 1)
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| bad())?;
        if bytes.len() as u64 > MAX_BODY {
            return Err(Error::capacity("Wikipedia artifact exceeds its bound."));
        }
        Ok(bytes)
    }
    pub async fn status(&self) -> Result<Value> {
        let mut v = self
            .store
            .wiki_state("status")
            .await?
            .unwrap_or(json!({"coverage":"uninitialized"}));
        v["stream"] = self
            .store
            .wiki_state("stream:status")
            .await?
            .unwrap_or(Value::Null);
        v["stream_gap"] = self
            .store
            .wiki_state("stream:gap")
            .await?
            .unwrap_or(Value::Null);
        v["snapshot"] = self
            .store
            .wiki_state("snapshot:default")
            .await?
            .unwrap_or(Value::Null);
        v["provider"] = self
            .store
            .wiki_state("provider:admission")
            .await?
            .unwrap_or(Value::Null);
        let mut queues = serde_json::Map::new();
        for prefix in ["article:", "category:", "demand:", "reconcile:"] {
            let rows = self.store.wiki_due(prefix, now(), 100).await?;
            queues.insert(prefix.trim_end_matches(':').into(),json!({"due_count_at_least":rows.len(),"count_is_lower_bound":rows.len()==100,"oldest_due_at":rows.iter().filter_map(|r|r.due_at).min(),"oldest_due_age_secs":rows.iter().filter_map(|r|r.due_at).min().map(|t|now().saturating_sub(t))}));
        }
        v["queues"] = Value::Object(queues);
        v["coverage"] = json!("partial");
        v["history"] = json!("observed_representations_only");
        Ok(v)
    }
}
fn metadata_pages(v: &Value) -> Vec<&Value> {
    match &v["query"]["pages"] {
        Value::Array(a) => a.iter().collect(),
        Value::Object(o) => o.values().collect(),
        _ => vec![],
    }
}
fn article_url(title: &str) -> String {
    format!(
        "https://en.wikipedia.org/wiki/{}",
        url::form_urlencoded::byte_serialize(title.replace(' ', "_").as_bytes())
            .collect::<String>()
    )
}

#[cfg(test)]
mod tests;
