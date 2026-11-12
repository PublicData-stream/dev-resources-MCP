//! Private fixed-source streaming I/O. Public capture reads retain their smaller limits.
use crate::html_transport::{HtmlClient, ProxyPolicy, Response};
use devres_application::collection::{LimitKind, Phase, limited};
use devres_domain::{Error, Result, Validators};
use futures::{Stream, StreamExt, TryStreamExt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::AsyncReadExt,
    sync::{Mutex, OwnedSemaphorePermit, Semaphore},
    time::Instant,
};
use tokio_util::{io::StreamReader, sync::CancellationToken};

pub const CHUNK_BYTES: usize = 64 * 1024;
pub const MAX_ARTIFACT_BYTES: u64 = 32 * 1024 * 1024 * 1024;
const MAX_RETRY_AFTER: u64 = 5;
static STAGE: AtomicU64 = AtomicU64::new(0);

pub type BulkStream = Pin<Box<dyn Stream<Item = Result<Vec<u8>>> + Send>>;

#[derive(Clone, Debug)]
pub struct BulkConfig {
    pub static_requests_per_second: u32,
    pub index_requests_per_second: u32,
    pub other_requests_per_second: u32,
    pub max_transfers: usize,
    pub min_free_bytes: u64,
}
impl Default for BulkConfig {
    fn default() -> Self {
        Self {
            static_requests_per_second: 5,
            index_requests_per_second: 1,
            other_requests_per_second: 1,
            max_transfers: 4,
            min_free_bytes: 1024 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug)]
pub enum DocsOperation {
    Status,
    Platforms,
    Html,
    Builds,
    Json { target: String, format: Option<u32> },
}
#[derive(Clone, Copy, Debug)]
pub enum GitOperation {
    Advertisement,
    UploadPack,
}
#[derive(Clone, Debug)]
pub enum BulkSource {
    /// Immutable, source-qualified attribution evidence through existing admission.
    Attribution(crate::attribution_providers::AttributionSource),
    Npm(crate::npm::source::Operation),
    DatabaseDump,
    /// Compatibility revalidation of retained captures from the former endpoint.
    LegacyDatabaseDump,
    CrateArchive {
        name: String,
        version: String,
    },
    Documentation {
        name: String,
        version: String,
        operation: DocsOperation,
    },
    RegistryGit(GitOperation),
    RustSecGit(GitOperation),
    MdnContentGit(GitOperation),
    MdnCompatGit(GitOperation),
    WhatwgGit {
        repository: crate::whatwg::git::Repo,
        operation: GitOperation,
    },
    WhatwgPublication(crate::whatwg::catalog::PublicationUrl),
    W3cGit {
        repository: crate::w3c::git::Repo,
        operation: GitOperation,
    },
    W3cPublication(crate::w3c::catalog::PublicationUrl),
    W3cApi(crate::w3c::catalog::ApiOperation),
    W3cDiscovery(crate::w3c::discovery::DiscoveryOperation),
    Chromium(crate::chromium::source::Operation),
}
impl BulkSource {
    pub fn url(&self) -> Result<String> {
        match self {
            Self::Attribution(source) => source.url(),
            Self::Npm(operation) => operation.url(),
            Self::Chromium(operation) => operation.url(),
            Self::W3cGit { repository, operation } => {
                repository.validate()?;
                let suffix = match operation {
                    GitOperation::Advertisement => "info/refs?service=git-upload-pack",
                    GitOperation::UploadPack => "git-upload-pack",
                };
                Ok(format!("{}/{suffix}", repository.source_url()))
            }
            Self::W3cPublication(source) => { source.validate()?; Ok(source.as_str().to_owned()) },
            Self::W3cApi(operation) => operation.url(),
            Self::W3cDiscovery(operation) => operation.url(),
            Self::WhatwgGit { repository, operation } => {
                crate::whatwg::git::Repo::new(&repository.as_str())?;
                let suffix=match operation { GitOperation::Advertisement=>"info/refs?service=git-upload-pack",GitOperation::UploadPack=>"git-upload-pack" };
                Ok(format!("{}/{suffix}",repository.source_url()))
            }
            Self::WhatwgPublication(source) => {source.validate()?; Ok(source.as_str().to_owned())},
            Self::DatabaseDump => Ok("https://cloudfront-static.crates.io/db-dump.tar.gz".into()),
            Self::LegacyDatabaseDump => Ok("https://static.crates.io/db-dump.tar.gz".into()),
            Self::CrateArchive { name, version } => {
                package_identity(name, version)?;
                Ok(format!("https://static.crates.io/crates/{name}/{name}-{version}.crate"))
            }
            Self::Documentation { name, version, operation } => {
                package_identity(name, version)?;
                let suffix = match operation {
                    DocsOperation::Status => "status.json".into(),
                    DocsOperation::Platforms => "menus/platforms/".into(),
                    DocsOperation::Html => "download".into(),
                    DocsOperation::Builds => "builds".into(),
                    DocsOperation::Json { target, format } => {
                        if !valid_target(target) { return Err(Error::invalid("Invalid documentation target.")); }
                        match format {
                            Some(format) if *format > 0 => format!("{target}/json/{format}.gz"),
                            Some(_) => return Err(Error::invalid("Invalid documentation format.")),
                            None => format!("{target}/json.gz"),
                        }
                    }
                };
                Ok(format!("https://docs.rs/crate/{name}/{version}/{suffix}"))
            }
            Self::MdnContentGit(GitOperation::Advertisement) => Ok("https://github.com/mdn/content.git/info/refs?service=git-upload-pack".into()),
            Self::MdnContentGit(GitOperation::UploadPack) => Ok("https://github.com/mdn/content.git/git-upload-pack".into()),
            Self::MdnCompatGit(GitOperation::Advertisement) => Ok("https://github.com/mdn/browser-compat-data.git/info/refs?service=git-upload-pack".into()),
            Self::MdnCompatGit(GitOperation::UploadPack) => Ok("https://github.com/mdn/browser-compat-data.git/git-upload-pack".into()),
            Self::RustSecGit(GitOperation::Advertisement) => Ok("https://github.com/rustsec/advisory-db.git/info/refs?service=git-upload-pack".into()),
            Self::RustSecGit(GitOperation::UploadPack) => Ok("https://github.com/rustsec/advisory-db.git/git-upload-pack".into()),
            Self::RegistryGit(GitOperation::Advertisement) => Ok("https://github.com/rust-lang/crates.io-index.git/info/refs?service=git-upload-pack".into()),
            Self::RegistryGit(GitOperation::UploadPack) => Ok("https://github.com/rust-lang/crates.io-index.git/git-upload-pack".into()),
        }
    }
    pub fn host(&self) -> &str {
        match self {
            Self::Attribution(source) => source.host(),
            Self::Npm(operation) => operation.host(),
            Self::Chromium(operation) => operation.host(),
            Self::W3cGit { repository, .. } => repository.host(),
            Self::W3cPublication(source) => source.host(),
            Self::W3cApi(_) => "api.w3.org",
            Self::W3cDiscovery(operation) => operation.host(),
            Self::WhatwgPublication(source) => source.host(),
            Self::WhatwgGit { .. } => "github.com",
            Self::DatabaseDump | Self::LegacyDatabaseDump | Self::CrateArchive { .. } => {
                "static.crates.io"
            }
            Self::Documentation { .. } => "docs.rs",
            Self::RegistryGit(_)
            | Self::RustSecGit(_)
            | Self::MdnContentGit(_)
            | Self::MdnCompatGit(_) => "github.com",
        }
    }
    fn html_transport(&self) -> Option<ProxyPolicy> {
        use crate::{
            attribution_providers::AttributionSource,
            chromium::source::Operation,
            w3c::{catalog::PublicationKind, discovery::DiscoveryOperation},
        };
        match self {
            Self::W3cPublication(source) if source.kind() == PublicationKind::Html => {
                Some(ProxyPolicy::Public)
            }
            Self::W3cDiscovery(DiscoveryOperation::TrIndex)
            | Self::Chromium(Operation::Page { .. } | Operation::SitePage { .. }) => {
                Some(ProxyPolicy::Public)
            }
            Self::Attribution(AttributionSource::Rfc { format, .. }) if format == "html" => {
                Some(ProxyPolicy::Direct)
            }
            _ => None,
        }
    }
    fn media_type(&self) -> &'static str {
        match self {
            Self::Attribution(source) => source.media_type(),
            Self::Npm(operation) => operation.media_type(),
            Self::Chromium(operation) => operation.media_type(),
            Self::W3cApi(_) => "application/hal+json",
            Self::W3cDiscovery(operation) => operation.media_type(),
            Self::W3cPublication(source) => source.media_type(),
            Self::W3cGit {
                operation: GitOperation::Advertisement,
                ..
            } => "application/x-git-upload-pack-advertisement",
            Self::W3cGit {
                operation: GitOperation::UploadPack,
                ..
            } => "application/x-git-upload-pack-result",
            Self::WhatwgGit {
                operation: GitOperation::Advertisement,
                ..
            }
            | Self::RegistryGit(GitOperation::Advertisement)
            | Self::RustSecGit(GitOperation::Advertisement)
            | Self::MdnContentGit(GitOperation::Advertisement)
            | Self::MdnCompatGit(GitOperation::Advertisement) => {
                "application/x-git-upload-pack-advertisement"
            }
            Self::WhatwgGit {
                operation: GitOperation::UploadPack,
                ..
            }
            | Self::RegistryGit(GitOperation::UploadPack)
            | Self::RustSecGit(GitOperation::UploadPack)
            | Self::MdnContentGit(GitOperation::UploadPack)
            | Self::MdnCompatGit(GitOperation::UploadPack) => {
                "application/x-git-upload-pack-result"
            }
            Self::WhatwgPublication(source) => source.media_type(),
            Self::Documentation {
                operation: DocsOperation::Status,
                ..
            } => "application/json",
            Self::Documentation {
                operation: DocsOperation::Platforms | DocsOperation::Builds,
                ..
            } => "text/html",
            Self::Documentation {
                operation: DocsOperation::Html,
                ..
            } => "application/zip",
            _ => "application/gzip",
        }
    }
}
fn package_identity(name: &str, version: &str) -> Result<()> {
    crate::crates_io::packages::validate_name(name)?;
    crate::crates_io::packages::validate_version(version)?;
    Ok(())
}
pub fn valid_target(target: &str) -> bool {
    !target.is_empty()
        && target.len() <= 128
        && !target.contains("..")
        && target
            .bytes()
            .all(|v| v.is_ascii_alphanumeric() || b"-_.".contains(&v))
}
fn admitted_host(host: &str) -> Result<&str> {
    match host {
        "rfc-editor.org" => Ok("www.rfc-editor.org"),
        "www.rfc-editor.org"
        | "crates.io"
        | "index.crates.io"
        | "static.crates.io"
        | "api.github.com"
        | "codeload.github.com"
        | "github.com"
        | "docs.rs" => Ok(host),
        "registry.npmjs.org" | "osv-vulnerabilities.storage.googleapis.com" => Ok(host),
        host if crate::whatwg::catalog::publication_host(host) => Ok(host),
        _ => Err(Error::invalid("Source host is not permitted.")),
    }
}

pub struct BulkRequest {
    pub source: BulkSource,
    pub validators: Validators,
    pub max_bytes: u64,
    pub deadline: Instant,
    /// Only the read-only Git upload-pack operation accepts a request body.
    pub body: Vec<u8>,
}
pub struct BulkResponse {
    /// Trusted constructed URL that supplied this response.
    pub effective_url: String,
    pub status: u16,
    pub validators: Validators,
    pub content_length: Option<u64>,
    pub next_page: Option<u32>,
    pub retry_at: Option<i64>,
    pub stream: BulkStream,
}
pub struct AttemptPermit {
    _transfer: OwnedSemaphorePermit,
    _documentation: Option<OwnedSemaphorePermit>,
}

/// An aborted Action transfer still incurs Wikimedia's five-second pause.
/// The guard owns timing/policy only, never response bytes or a transfer task.
struct WikipediaActionAttempt<'a> {
    started: Instant,
    active: bool,
    floor: Arc<AtomicI64>,
    observed: &'a AtomicI64,
    observer: Option<crate::wikipedia::source::PolicyObserver>,
}
impl Drop for WikipediaActionAttempt<'_> {
    fn drop(&mut self) {
        if self.active && self.started.elapsed() > Duration::from_secs(1) {
            let until = devres_domain::unix_now().saturating_add(5);
            self.floor.fetch_max(until, Ordering::AcqRel);
            self.observed.fetch_max(until, Ordering::AcqRel);
            if let Some(observe) = &self.observer {
                // Enqueue is synchronous. Dropping only the acknowledgement
                // leaves the bounded storage worker responsible for the write.
                let _ = observe(until);
            }
        }
    }
}

pub struct BulkBroker {
    client: reqwest::Client,
    w3c_client: reqwest::Client,
    html_public: HtmlClient,
    html_direct: HtmlClient,
    config: BulkConfig,
    rates: Mutex<HashMap<String, Instant>>,
    bulk_slots: Arc<Semaphore>,
    foreground_slots: Arc<Semaphore>,
    documentation_slots: Arc<Semaphore>,
    chromium_slots: Arc<Semaphore>,
    npm_slots: Arc<Semaphore>,
    osv_slots: Arc<Semaphore>,
    wikipedia_slots: Arc<Semaphore>,
    wikipedia_action_slots: Arc<Semaphore>,
    wikipedia_stream_slots: Arc<Semaphore>,
    wikipedia_requests_per_second: u32,
    wikipedia_policy_floor: Arc<AtomicI64>,
    npm_registry_rate: u32,
    npm_advisory_rate: u32,
    attempt_budget: Option<usize>,
    attempts: AtomicUsize,
    // Public immutable attribution evidence only. Per-broker ownership prevents
    // fixture/live or policy-generation proof from crossing admission contexts.
    attribution_cache: Mutex<std::collections::VecDeque<(String, Vec<u8>, serde_json::Value)>>,
    attempt_observer: Option<Arc<dyn Fn(usize) -> Result<()> + Send + Sync>>,
    #[cfg(test)]
    test_origin: Option<url::Url>,
}
impl BulkBroker {
    #[cfg(test)]
    pub(crate) fn fixture(origin: url::Url) -> Result<Self> {
        if origin.scheme() != "http" || origin.host_str() != Some("127.0.0.1") {
            return Err(Error::invalid("Fixture broker requires loopback HTTP."));
        }
        let mut broker = Self::new(BulkConfig::default())?;
        broker.client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .build()
            .map_err(|_| Error::unavailable("Fixture HTTP initialization failed."))?;
        broker.test_origin = Some(origin);
        broker.w3c_client = broker.client.clone();
        broker.html_public = HtmlClient::fixture()?;
        broker.html_direct = HtmlClient::fixture()?;
        Ok(broker)
    }
    pub fn new(config: BulkConfig) -> Result<Self> {
        if !(1..=1000).contains(&config.static_requests_per_second)
            || !(1..=1000).contains(&config.index_requests_per_second)
            || config.other_requests_per_second != 1
            || !(1..=32).contains(&config.max_transfers)
            || config.min_free_bytes < 64 * 1024 * 1024
        {
            return Err(Error::invalid("Invalid bulk transfer limits."));
        }
        let client = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(Duration::from_secs(10))
            .user_agent(
                "dev-resources-MCP/0.0.0 (+https://github.com/PublicData-stream/dev-resources-MCP)",
            )
            .build()
            .map_err(|_| Error::unavailable("Bulk HTTP initialization failed."))?;
        Ok(Self {
            client,
            w3c_client: crate::w3c::network::client()?,
            html_public: HtmlClient::new(ProxyPolicy::Public)?,
            html_direct: HtmlClient::new(ProxyPolicy::Direct)?,
            bulk_slots: Arc::new(Semaphore::new(config.max_transfers)),
            foreground_slots: Arc::new(Semaphore::new(2)),
            documentation_slots: Arc::new(Semaphore::new(1)),
            chromium_slots: Arc::new(Semaphore::new(1)),
            npm_slots: Arc::new(Semaphore::new(1)),
            osv_slots: Arc::new(Semaphore::new(1)),
            wikipedia_slots: Arc::new(Semaphore::new(2)),
            wikipedia_action_slots: Arc::new(Semaphore::new(1)),
            wikipedia_stream_slots: Arc::new(Semaphore::new(1)),
            wikipedia_requests_per_second: 1,
            wikipedia_policy_floor: Arc::new(AtomicI64::new(0)),
            npm_registry_rate: 1,
            npm_advisory_rate: 1,
            rates: Mutex::new(HashMap::new()),
            config,
            attempt_budget: None,
            attempts: AtomicUsize::new(0),
            attribution_cache: Mutex::new(std::collections::VecDeque::new()),
            attempt_observer: None,
            #[cfg(test)]
            test_origin: None,
        })
    }

    /// Reuse only successful current-policy public evidence in this broker context.
    pub(crate) async fn attribution_cached(
        &self,
        url: &str,
    ) -> Option<(Vec<u8>, serde_json::Value)> {
        let key = format!(
            "{}:{url}",
            devres_domain::attribution::ATTRIBUTION_POLICY_FINGERPRINT
        );
        let mut cache = self.attribution_cache.lock().await;
        let position = cache.iter().position(|(id, _, _)| id == &key)?;
        let entry = cache.remove(position)?;
        let output = (entry.1.clone(), entry.2.clone());
        cache.push_back(entry);
        Some(output)
    }
    pub(crate) async fn attribution_cache(
        &self,
        url: &str,
        body: &[u8],
        receipt: &serde_json::Value,
    ) {
        const BYTES: usize = 64 * 1024 * 1024;
        if body.len() > BYTES
            || url.len() > 16384
            || receipt["status"] != 200
            || receipt["policy_fingerprint"]
                != devres_domain::attribution::ATTRIBUTION_POLICY_FINGERPRINT
            || receipt["body_hash"] != crate::integrity::hash(body)
        {
            return;
        }
        let key = format!(
            "{}:{url}",
            devres_domain::attribution::ATTRIBUTION_POLICY_FINGERPRINT
        );
        let mut cache = self.attribution_cache.lock().await;
        if cache.iter().any(|(id, _, _)| id == &key) {
            return;
        }
        let mut bytes: usize = cache.iter().map(|(_, body, _)| body.len()).sum();
        while cache.len() >= 32 || bytes.saturating_add(body.len()) > BYTES {
            let Some((_, body, _)) = cache.pop_front() else {
                break;
            };
            bytes = bytes.saturating_sub(body.len());
        }
        cache.push_back((key, body.to_vec(), receipt.clone()));
    }

    /// Configure only npm provider clocks, preserving all existing provider policy.
    pub fn with_npm_rates(mut self, registry: u32, advisory: u32) -> Result<Self> {
        if !(1..=1000).contains(&registry) || !(1..=1000).contains(&advisory) {
            return Err(Error::invalid("Invalid npm attempt rate."));
        }
        self.npm_registry_rate = registry;
        self.npm_advisory_rate = advisory;
        Ok(self)
    }

    /// Private acceptance harness bound; normal serving has no global attempt cap.
    pub fn with_attempt_budget(mut self, limit: usize) -> Result<Self> {
        if limit == 0 || limit > 1_000_000 {
            return Err(Error::invalid("Invalid source attempt budget."));
        }
        self.attempt_budget = Some(limit);
        Ok(self)
    }
    pub fn attempt_count(&self) -> usize {
        self.attempts.load(Ordering::Acquire)
    }
    /// Trusted private acceptance accounting; persistence must succeed before I/O.
    pub fn with_attempt_observer(
        mut self,
        initial: usize,
        observer: Arc<dyn Fn(usize) -> Result<()> + Send + Sync>,
    ) -> Result<Self> {
        if self.attempt_budget.is_none_or(|limit| initial > limit) {
            return Err(Error::invalid("Invalid resumed source attempt budget."));
        }
        self.attempts.store(initial, Ordering::Release);
        self.attempt_observer = Some(observer);
        Ok(self)
    }

    /// Existing bounded fetches use this same host clock, with their own two slots.
    pub async fn admit_foreground(&self, host: &str) -> Result<AttemptPermit> {
        self.admit(host, false).await
    }
    async fn admit(&self, host: &str, bulk: bool) -> Result<AttemptPermit> {
        self.admit_rate(host, bulk, None).await
    }
    async fn admit_rate(
        &self,
        host: &str,
        bulk: bool,
        forced_rate: Option<u32>,
    ) -> Result<AttemptPermit> {
        self.admit_rate_inner(host, bulk, forced_rate, false, false)
            .await
    }

    async fn admit_rate_inner(
        &self,
        host: &str,
        bulk: bool,
        forced_rate: Option<u32>,
        w3c: bool,
        chromium: bool,
    ) -> Result<AttemptPermit> {
        // W3C hosts reach this branch only after typed destination validation in open().
        let host = if w3c || chromium {
            host
        } else {
            admitted_host(host)?
        };
        let source_slots = match host {
            "docs.rs" => Some(&self.documentation_slots),
            "registry.npmjs.org" => Some(&self.npm_slots),
            "osv-vulnerabilities.storage.googleapis.com" => Some(&self.osv_slots),
            _ => None,
        };
        let documentation = if let Some(source_slots) = source_slots {
            Some(
                source_slots
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|_| Error::unavailable("Documentation admission stopped."))?,
            )
        } else {
            None
        };
        let slots = if bulk {
            &self.bulk_slots
        } else {
            &self.foreground_slots
        };
        let transfer = slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| Error::unavailable("HTTP admission stopped."))?;
        let scheduled = {
            let mut rates = self.rates.lock().await;
            let now = Instant::now();
            let whatwg = crate::whatwg::catalog::publication_host(host);
            let clock = if whatwg { "whatwg-publications" } else { host };
            let mut scheduled = rates.get(clock).copied().unwrap_or(now).max(now);
            if w3c {
                scheduled = scheduled.max(rates.get("w3c-acquisition").copied().unwrap_or(now));
                rates.insert("w3c-acquisition".into(), scheduled + Duration::from_secs(1));
            }
            if chromium {
                scheduled =
                    scheduled.max(rates.get("chromium-acquisition").copied().unwrap_or(now));
                rates.insert(
                    "chromium-acquisition".into(),
                    scheduled + Duration::from_secs(1),
                );
            }
            let per_second = if whatwg {
                1
            } else {
                forced_rate.unwrap_or(match host {
                    "static.crates.io" => self.config.static_requests_per_second,
                    "registry.npmjs.org" => self.npm_registry_rate,
                    "osv-vulnerabilities.storage.googleapis.com" => self.npm_advisory_rate,
                    "index.crates.io" | "github.com" => self.config.index_requests_per_second,
                    _ => self.config.other_requests_per_second,
                })
            };
            rates.insert(
                clock.to_owned(),
                scheduled + Duration::from_secs_f64(1.0 / f64::from(per_second)),
            );
            scheduled
        };
        tokio::time::sleep_until(scheduled).await;
        let previous = self
            .attempts
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                if self.attempt_budget.is_some_and(|limit| count >= limit) {
                    None
                } else {
                    count.checked_add(1)
                }
            })
            .map_err(|_| {
                limited(
                    Error::capacity("Source attempt budget exhausted."),
                    Phase::HttpAcquisition,
                    LimitKind::ProviderAttempts,
                    None,
                    self.attempt_budget.map(|limit| limit as u64),
                )
            })?;
        if let Some(observer) = &self.attempt_observer {
            observer(previous + 1)?;
        }
        Ok(AttemptPermit {
            _transfer: transfer,
            _documentation: documentation,
        })
    }

    pub async fn open(
        &self,
        request: BulkRequest,
        shutdown: CancellationToken,
    ) -> Result<BulkResponse> {
        self.open_inner(request, shutdown, false).await
    }

    /// Fixed-source comparison tooling only; shares normal admission and retry policy.
    #[doc(hidden)]
    pub async fn open_legacy_html_probe(
        &self,
        request: BulkRequest,
        shutdown: CancellationToken,
    ) -> Result<BulkResponse> {
        if request.source.html_transport().is_none() {
            return Err(Error::invalid(
                "Legacy HTML comparison requires a qualified HTML source.",
            ));
        }
        self.open_inner(request, shutdown, true).await
    }

    async fn open_inner(
        &self,
        request: BulkRequest,
        shutdown: CancellationToken,
        legacy_html: bool,
    ) -> Result<BulkResponse> {
        if request.max_bytes == 0
            || request.max_bytes > MAX_ARTIFACT_BYTES
            || request.deadline <= Instant::now()
        {
            return Err(Error::invalid("Invalid bulk response budget."));
        }
        let upload = matches!(
            request.source,
            BulkSource::RegistryGit(GitOperation::UploadPack)
                | BulkSource::RustSecGit(GitOperation::UploadPack)
                | BulkSource::MdnContentGit(GitOperation::UploadPack)
                | BulkSource::MdnCompatGit(GitOperation::UploadPack)
                | BulkSource::WhatwgGit {
                    operation: GitOperation::UploadPack,
                    ..
                }
                | BulkSource::W3cGit {
                    operation: GitOperation::UploadPack,
                    ..
                }
        );
        if request.body.len() > 1024 * 1024 || (!upload && !request.body.is_empty()) {
            return Err(Error::invalid("Invalid bulk request body."));
        }
        let mut effective_url = request.source.url()?;
        let mut redirected = false;
        let mut retried = false;
        let chromium = matches!(request.source, BulkSource::Chromium(_));
        let w3c = matches!(
            request.source,
            BulkSource::W3cGit { .. }
                | BulkSource::W3cPublication(_)
                | BulkSource::W3cApi(_)
                | BulkSource::W3cDiscovery(_)
                | BulkSource::Attribution(
                    crate::attribution_providers::AttributionSource::W3c { .. }
                )
        );
        // At most one transient retry and one narrowly authorized legacy hop.
        for _ in 0..3 {
            #[cfg(test)]
            let url = if let Some(origin) = &self.test_origin {
                let original = url::Url::parse(&effective_url)
                    .map_err(|_| Error::invalid("Invalid test source."))?;
                let mut destination = origin.clone();
                destination.set_path(original.path());
                destination.set_query(original.query());
                destination.to_string()
            } else {
                effective_url.clone()
            };
            #[cfg(not(test))]
            let url = effective_url.clone();
            let chromium_permit = if chromium {
                Some(
                    bounded(&shutdown, request.deadline, async {
                        self.chromium_slots
                            .clone()
                            .acquire_owned()
                            .await
                            .map_err(|_| Error::unavailable("Chromium admission stopped."))
                    })
                    .await?,
                )
            } else {
                None
            };
            let permit = bounded(
                &shutdown,
                request.deadline,
                self.admit_rate_inner(
                    request.source.host(),
                    true,
                    matches!(
                        request.source,
                        BulkSource::RustSecGit(_)
                            | BulkSource::MdnContentGit(_)
                            | BulkSource::MdnCompatGit(_)
                            | BulkSource::WhatwgGit { .. }
                            | BulkSource::W3cGit { .. }
                    )
                    .then_some(1),
                    w3c,
                    chromium,
                ),
            )
            .await?;
            let client = if w3c || chromium {
                &self.w3c_client
            } else {
                &self.client
            };
            let mut builder = if upload {
                client.post(&url).body(request.body.clone())
            } else {
                client.get(&url)
            };
            builder = builder.header(reqwest::header::ACCEPT, request.source.media_type());
            if matches!(
                request.source,
                BulkSource::RegistryGit(_)
                    | BulkSource::RustSecGit(_)
                    | BulkSource::MdnContentGit(_)
                    | BulkSource::MdnCompatGit(_)
                    | BulkSource::WhatwgGit { .. }
                    | BulkSource::W3cGit { .. }
            ) {
                builder = builder.header("Git-Protocol", "version=2");
                if upload {
                    builder = builder.header(
                        reqwest::header::CONTENT_TYPE,
                        "application/x-git-upload-pack-request",
                    );
                }
            }
            if let Some(etag) = &request.validators.etag {
                builder = builder.header(reqwest::header::IF_NONE_MATCH, etag);
            }
            if let Some(modified) = &request.validators.last_modified {
                builder = builder.header(reqwest::header::IF_MODIFIED_SINCE, modified);
            }
            let response = bounded(&shutdown, request.deadline, async {
                if let Some(policy) = request.source.html_transport().filter(|_| !legacy_html) {
                    let prepared = builder
                        .build()
                        .map_err(|_| Error::unavailable("Bulk source connection failed."))?;
                    let html = match policy {
                        ProxyPolicy::Public => &self.html_public,
                        ProxyPolicy::Direct => &self.html_direct,
                        ProxyPolicy::Ambient => {
                            return Err(Error::invalid("Invalid bulk HTML proxy policy."));
                        }
                    };
                    html.send(&url, prepared.headers().clone())
                        .await
                        .map_err(|_| Error::unavailable("Bulk source connection failed."))
                } else {
                    builder
                        .send()
                        .await
                        .map(Response::from)
                        .map_err(|_| Error::unavailable("Bulk source connection failed."))
                }
            })
            .await
            .inspect_err(|_| {
                if request.source.html_transport().is_some() {
                    let provider = if chromium { "chromium" } else if w3c { "w3c" } else { "rfc" };
                    tracing::warn!(target: "devres_server::collection", provider, stage = "source_connection", "Public collection stage failed");
                }
            })?;
            let status = response.status();
            if status == 307
                && matches!(request.source, BulkSource::LegacyDatabaseDump)
                && !redirected
                && effective_url == "https://static.crates.io/db-dump.tar.gz"
                && response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    == Some("https://cloudfront-static.crates.io/db-dump.tar.gz")
            {
                drop(response);
                drop(permit);
                redirected = true;
                effective_url = "https://cloudfront-static.crates.io/db-dump.tar.gz".into();
                continue;
            }
            let retry_at = match &request.source {
                BulkSource::Chromium(operation) => {
                    operation.retry_at(response.headers(), status)?
                }
                _ => None,
            };
            if let Some(retry_at) = retry_at {
                let seconds = retry_at.saturating_sub(devres_domain::unix_now()).max(0) as u64;
                let until = Instant::now() + Duration::from_secs(seconds);
                let mut rates = self.rates.lock().await;
                // An exhausted archive API must not suspend independent current
                // Chromium/Chrome origins. The family retains its normal pace.
                let clock = request.source.host();
                let previous = rates.get(clock).copied().unwrap_or(until);
                rates.insert(clock.into(), previous.max(until));
            }
            if !retried && retry_at.is_none() && matches!(status, 429 | 500 | 502 | 503 | 504) {
                retried = true;
                let delay = retry_after(response.headers());
                drop(response);
                drop(permit);
                if let Some(delay) = delay {
                    bounded(&shutdown, request.deadline, async {
                        tokio::time::sleep(delay).await;
                        Ok(())
                    })
                    .await?;
                    continue;
                }
                return Err(Error::unavailable(
                    "Bulk source requested a deferred retry.",
                ));
            }
            let validators = response_validators(response.headers());
            let content_length = response.content_length();
            let next_page = match &request.source {
                BulkSource::Chromium(operation) => operation.next_page(response.headers())?,
                _ => None,
            };
            if status != 200 {
                drop(response);
                drop(permit);
                return Ok(BulkResponse {
                    effective_url,
                    status,
                    validators,
                    content_length,
                    next_page,
                    retry_at,
                    stream: Box::pin(futures::stream::empty()),
                });
            }
            if content_length.is_some_and(|length| length > request.max_bytes) {
                return Err(limited(
                    Error::capacity("Bulk source exceeds its byte budget."),
                    Phase::HttpBody,
                    LimitKind::CompressedBytes,
                    content_length,
                    Some(request.max_bytes),
                ));
            }
            let input = response
                .bytes_stream()
                .map_err(|_| std::io::Error::other("Bulk source transfer failed."));
            let reader = StreamReader::new(input);
            let state = StreamState {
                reader: Box::pin(reader),
                _permit: permit,
                _chromium_permit: chromium_permit,
                received: 0,
                max_bytes: request.max_bytes,
                expected_bytes: content_length,
                deadline: request.deadline,
                shutdown,
            };
            let stream = futures::stream::try_unfold(state, |mut state| async move {
                let mut chunk = vec![0; CHUNK_BYTES];
                let read = bounded(&state.shutdown, state.deadline, async {
                    state
                        .reader
                        .read(&mut chunk)
                        .await
                        .map_err(|_| Error::unavailable("Bulk source transfer failed."))
                })
                .await?;
                if read == 0 {
                    if state
                        .expected_bytes
                        .is_some_and(|length| length != state.received)
                    {
                        return Err(Error::integrity("Bulk source length mismatch."));
                    }
                    return Ok(None);
                }
                state.received = state
                    .received
                    .checked_add(read as u64)
                    .filter(|length| *length <= state.max_bytes)
                    .ok_or_else(|| {
                        limited(
                            Error::capacity("Bulk source exceeds its byte budget."),
                            Phase::HttpBody,
                            LimitKind::CompressedBytes,
                            state.received.checked_add(read as u64),
                            Some(state.max_bytes),
                        )
                    })?;
                chunk.truncate(read);
                Ok(Some((chunk, state)))
            });
            return Ok(BulkResponse {
                effective_url,
                status,
                validators,
                content_length,
                next_page,
                retry_at,
                stream: Box::pin(stream),
            });
        }
        Err(Error::unavailable("Bulk source unavailable."))
    }
}
impl BulkBroker {
    pub(crate) fn wikipedia_policy_floor(&self) -> Arc<AtomicI64> {
        self.wikipedia_policy_floor.clone()
    }
    fn wikipedia_policy_receipt(
        &self,
        until: i64,
        observer: &Option<crate::wikipedia::source::PolicyObserver>,
    ) -> Result<Option<crate::wikipedia::source::PolicyReceipt>> {
        self.wikipedia_policy_floor
            .fetch_max(until, Ordering::AcqRel);
        observer.as_ref().map(|observe| observe(until)).transpose()
    }
    /// Wikimedia's current anonymous 200/minute ceiling also applies across APIs.
    /// The default is one; three remains below that ceiling with burst size one.
    pub fn with_wikipedia_rate(mut self, rate: u32) -> Result<Self> {
        if !(1..=3).contains(&rate) {
            return Err(Error::invalid("Invalid Wikipedia request rate."));
        }
        self.wikipedia_requests_per_second = rate;
        Ok(self)
    }

    fn record_wikipedia_attempt(&self) -> Result<()> {
        let previous = self
            .attempts
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                if self.attempt_budget.is_some_and(|limit| count >= limit) {
                    None
                } else {
                    count.checked_add(1)
                }
            })
            .map_err(|_| Error::capacity("Source attempt budget exhausted."))?;
        if let Some(observer) = &self.attempt_observer {
            observer(previous + 1)?;
        }
        Ok(())
    }

    async fn pace_wikipedia(&self) -> Result<()> {
        loop {
            let wait = {
                let mut clocks = self.rates.lock().await;
                let now = Instant::now();
                let floor = self
                    .wikipedia_policy_floor
                    .load(Ordering::Acquire)
                    .saturating_sub(devres_domain::unix_now())
                    .max(0) as u64;
                let policy_until = now + Duration::from_secs(floor.min(365 * 24 * 60 * 60));
                let scheduled = clocks
                    .get("wikipedia-api")
                    .copied()
                    .unwrap_or(now)
                    .max(policy_until);
                if scheduled > now {
                    Some(scheduled)
                } else {
                    clocks.insert(
                        "wikipedia-api".into(),
                        now + Duration::from_secs_f64(
                            1.0 / f64::from(self.wikipedia_requests_per_second),
                        ),
                    );
                    None
                }
            };
            let Some(wait) = wait else {
                return self.record_wikipedia_attempt();
            };
            // Recheck after sleeping: a different in-flight request can extend a cooldown.
            tokio::time::sleep_until(wait).await;
        }
    }

    async fn wikipedia_not_before(&self, unix_time: i64) {
        let seconds = unix_time.saturating_sub(devres_domain::unix_now()).max(0) as u64;
        // Tokio Instant cannot represent arbitrary remote timestamps. A very
        // distant Retry-After is still returned exactly for durable admission.
        let until = Instant::now() + Duration::from_secs(seconds.min(365 * 24 * 60 * 60));
        let mut clocks = self.rates.lock().await;
        let old = clocks.get("wikipedia-api").copied().unwrap_or(until);
        clocks.insert("wikipedia-api".into(), old.max(until));
    }

    #[cfg(test)]
    fn wikipedia_fixture_url(&self, value: &str) -> Result<String> {
        if let Some(origin) = &self.test_origin {
            let original = url::Url::parse(value)
                .map_err(|_| Error::invalid("Invalid Wikipedia fixture URL."))?;
            let mut destination = origin.clone();
            destination.set_path(original.path());
            destination.set_query(original.query());
            return Ok(destination.into());
        }
        Ok(value.into())
    }

    pub(crate) async fn fetch_wikipedia(
        &self,
        operation: crate::wikipedia::source::Operation,
        validators: Validators,
        shutdown: CancellationToken,
    ) -> Result<crate::wikipedia::source::Response> {
        self.fetch_wikipedia_with_admission(operation, validators, shutdown, || async { Ok(()) })
            .await
    }

    pub(crate) async fn fetch_wikipedia_with_admission<F, Fut>(
        &self,
        operation: crate::wikipedia::source::Operation,
        validators: Validators,
        shutdown: CancellationToken,
        before_attempt: F,
    ) -> Result<crate::wikipedia::source::Response>
    where
        F: Fn() -> Fut + Send + Sync,
        Fut: std::future::Future<Output = Result<()>> + Send,
    {
        self.fetch_wikipedia_with_observer(operation, validators, shutdown, before_attempt, None)
            .await
    }
    pub(crate) async fn fetch_wikipedia_with_observer<F, Fut>(
        &self,
        operation: crate::wikipedia::source::Operation,
        validators: Validators,
        shutdown: CancellationToken,
        before_attempt: F,
        observer: Option<crate::wikipedia::source::PolicyObserver>,
    ) -> Result<crate::wikipedia::source::Response>
    where
        F: Fn() -> Fut + Send + Sync,
        Fut: std::future::Future<Output = Result<()>> + Send,
    {
        let observed_retry_at = AtomicI64::new(0);
        let result = async {
            use crate::wikipedia::{cache::CacheMetadata, source::Response};
            let deadline = Instant::now() + Duration::from_secs(30);
            let mut operation = operation;
            let mut validators = validators;
            let maximum = operation.max_bytes();
            for hop in 0..=5 {
                let effective_url = operation.url()?;
                let action = operation.is_action();
                let _action = if action {
                    Some(
                        bounded(&shutdown, deadline, async {
                            self.wikipedia_action_slots
                                .clone()
                                .acquire_owned()
                                .await
                                .map_err(|_| {
                                    Error::unavailable("Wikipedia Action admission stopped.")
                                })
                        })
                        .await?,
                    )
                } else {
                    None
                };
                let _api = bounded(&shutdown, deadline, async {
                    self.wikipedia_slots
                        .clone()
                        .acquire_owned()
                        .await
                        .map_err(|_| Error::unavailable("Wikipedia admission stopped."))
                })
                .await?;
                let _transfer = bounded(&shutdown, deadline, async {
                    self.bulk_slots
                        .clone()
                        .acquire_owned()
                        .await
                        .map_err(|_| Error::unavailable("HTTP admission stopped."))
                })
                .await?;
                bounded(&shutdown, deadline, self.pace_wikipedia()).await?;
                bounded(&shutdown, deadline, before_attempt()).await?;
                #[cfg(test)]
                let destination = self.wikipedia_fixture_url(&effective_url)?;
                #[cfg(not(test))]
                let destination = effective_url.clone();
                let mut builder = self
                    .client
                    .get(destination)
                    .header(reqwest::header::ACCEPT, "application/json")
                    .header(
                        reqwest::header::USER_AGENT,
                        crate::wikipedia::source::USER_AGENT,
                    )
                    .header(reqwest::header::ACCEPT_ENCODING, "gzip");
                if let Some(etag) = &validators.etag {
                    if etag.len() > 8192 {
                        return Err(Error::invalid("Invalid Wikipedia validator."));
                    }
                    builder = builder.header(reqwest::header::IF_NONE_MATCH, etag);
                }
                if let Some(modified) = &validators.last_modified {
                    if modified.len() > 8192 {
                        return Err(Error::invalid("Invalid Wikipedia validator."));
                    }
                    builder = builder.header(reqwest::header::IF_MODIFIED_SINCE, modified);
                }
                let sent_at = devres_domain::unix_now();
                let started = Instant::now();
                let mut action_attempt = WikipediaActionAttempt {
                    started,
                    active: action,
                    floor: self.wikipedia_policy_floor.clone(),
                    observed: &observed_retry_at,
                    observer: observer.clone(),
                };
                let response = bounded(&shutdown, deadline, async {
                    builder
                        .send()
                        .await
                        .map_err(|_| Error::unavailable("Wikipedia source connection failed."))
                })
                .await;
                let received_at = devres_domain::unix_now();
                let initial_action_slow_until = (action
                    && started.elapsed() > Duration::from_secs(1))
                .then(|| received_at.saturating_add(5));
                let mut retry_at = response.as_ref().ok().and_then(|response| {
                    wikipedia_retry_at(response.headers(), response.status().as_u16(), received_at)
                });
                // Observe every policy already available from these headers before
                // the first await: dropping during a short Action receipt must not
                // discard a longer Retry-After on the same response.
                if let Some(until) = retry_at.into_iter().chain(initial_action_slow_until).max() {
                    observed_retry_at.fetch_max(until, Ordering::AcqRel);
                    let receipt = self.wikipedia_policy_receipt(until, &observer)?;
                    self.wikipedia_not_before(until).await;
                    if let Some(receipt) = receipt {
                        receipt.await?;
                    }
                }
                let response = response?;
                let status = response.status().as_u16();
                let cache =
                    match CacheMetadata::from_headers(response.headers(), sent_at, received_at) {
                        Ok(cache) => cache,
                        Err(_) => {
                            // Cache corruption must not erase a valid throttling delay.
                            // Return only status/policy failure evidence, never body bytes.
                            let until = retry_at.unwrap_or_else(|| received_at.saturating_add(5));
                            observed_retry_at.fetch_max(until, Ordering::AcqRel);
                            let receipt = self.wikipedia_policy_receipt(until, &observer)?;
                            action_attempt.active = false;
                            self.wikipedia_not_before(until).await;
                            if let Some(receipt) = receipt {
                                receipt.await?;
                            }
                            return Ok(Response {
                                effective_url,
                                status,
                                body: Vec::new(),
                                validators: Validators::default(),
                                cache: CacheMetadata {
                                    request_sent_at: sent_at,
                                    received_at,
                                    ..CacheMetadata::default()
                                },
                                retry_at: Some(until),
                                action_slow_until: initial_action_slow_until,
                                api_error: Some("malformed_cache_metadata".into()),
                            });
                        }
                    };
                if matches!(status, 301 | 302 | 303 | 307 | 308) {
                    if hop == 5 {
                        return Err(Error::unavailable("Wikipedia redirect limit exceeded."));
                    }
                    let location = response
                        .headers()
                        .get(reqwest::header::LOCATION)
                        .and_then(|value| value.to_str().ok())
                        .ok_or_else(|| Error::integrity("Invalid Wikipedia redirect."))?;
                    operation = wikipedia_redirect(&operation, &effective_url, location)?;
                    // Validators identify a representation URL and never cross a redirect.
                    validators = Validators::default();
                    action_attempt.active = false;
                    continue;
                }
                if status == 200 && !cache.retention_allowed()? {
                    // Preserve policy evidence, but never expose forbidden body bytes
                    // to any durable-capture caller.
                    action_attempt.active = false;
                    return Ok(Response {
                        effective_url,
                        status,
                        body: Vec::new(),
                        validators: cache.validators(),
                        cache,
                        retry_at,
                        action_slow_until: initial_action_slow_until,
                        api_error: None,
                    });
                }
                let mut body = Vec::new();
                if status == 200 {
                    if response
                        .content_length()
                        .is_some_and(|length| length > maximum as u64)
                    {
                        return Err(Error::capacity(
                            "Wikipedia response exceeds its byte budget.",
                        ));
                    }
                    let mut decoder = WikipediaDecoder::new(response.headers())?;
                    let mut input = response.bytes_stream();
                    let mut received = 0usize;
                    while let Some(chunk) =
                        bounded(&shutdown, deadline, async {
                            input.next().await.transpose().map_err(|_| {
                                Error::unavailable("Wikipedia source transfer failed.")
                            })
                        })
                        .await?
                    {
                        received = received
                            .checked_add(chunk.len())
                            .filter(|bytes| *bytes <= maximum)
                            .ok_or_else(|| {
                                Error::capacity("Wikipedia transfer exceeds its byte budget.")
                            })?;
                        for part in chunk.chunks(16 * 1024) {
                            let decoded =
                                decoder.decode(part, maximum.saturating_sub(body.len()))?;
                            body.extend_from_slice(&decoded);
                        }
                    }
                    body.extend(decoder.finish(maximum.saturating_sub(body.len()))?);
                }
                let api_error = if action && status == 200 {
                    serde_json::from_slice::<serde_json::Value>(&body)
                        .map_err(|_| Error::integrity("Invalid Wikipedia Action response."))
                        .map(|parsed| {
                            parsed.get("error").map(|error| {
                                match error.get("code").and_then(serde_json::Value::as_str) {
                                    Some("maxlag") => "maxlag",
                                    Some("ratelimited") => "ratelimited",
                                    Some("readonly") => "readonly",
                                    _ => "upstream_error",
                                }
                                .to_owned()
                            })
                        })
                } else {
                    Ok(None)
                };
                if let Some(code) = api_error.as_ref().ok().and_then(|code| code.as_deref()) {
                    let fallback = if code == "ratelimited" { 60 } else { 5 };
                    let until = retry_at
                        .unwrap_or_else(|| devres_domain::unix_now().saturating_add(fallback));
                    retry_at = Some(until);
                    // Do not retain upstream diagnostic messages in resources or state.
                    body.clear();
                }
                let action_slow_until = (action && started.elapsed() > Duration::from_secs(1))
                    .then(|| devres_domain::unix_now().saturating_add(5));
                if let Some(until) = retry_at.into_iter().chain(action_slow_until).max() {
                    observed_retry_at.fetch_max(until, Ordering::AcqRel);
                    let receipt = self.wikipedia_policy_receipt(until, &observer)?;
                    action_attempt.active = false;
                    self.wikipedia_not_before(until).await;
                    if let Some(receipt) = receipt {
                        receipt.await?;
                    }
                }
                action_attempt.active = false;
                let api_error = api_error?;
                return Ok(Response {
                    effective_url,
                    status,
                    body,
                    validators: cache.validators(),
                    cache,
                    retry_at,
                    action_slow_until,
                    api_error,
                });
            }
            Err(Error::unavailable("Wikipedia source unavailable."))
        }
        .await;
        result.map_err(|error| {
            wikipedia_error_with_retry(error, observed_retry_at.load(Ordering::Acquire))
        })
    }

    /// The long-lived stream has its own permit and never occupies a transfer
    /// slot while idle. A caller-owned durable lease coordinates replicas.
    pub(crate) async fn open_wikipedia_stream(
        &self,
        last_event_id: Option<String>,
        shutdown: CancellationToken,
    ) -> Result<crate::wikipedia::events::Connection> {
        self.open_wikipedia_stream_with_observer(last_event_id, shutdown, None)
            .await
    }
    pub(crate) async fn open_wikipedia_stream_with_observer(
        &self,
        last_event_id: Option<String>,
        shutdown: CancellationToken,
        observer: Option<crate::wikipedia::source::PolicyObserver>,
    ) -> Result<crate::wikipedia::events::Connection> {
        let observed_retry_at = AtomicI64::new(0);
        let result = async {
            use crate::wikipedia::{
                events::{Connection, validate_resume_id},
                source::STREAM_URL,
            };
            if let Some(id) = &last_event_id {
                validate_resume_id(id)?;
            }
            let deadline = Instant::now() + Duration::from_secs(30);
            let permit = bounded(&shutdown, deadline, async {
                self.wikipedia_stream_slots
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|_| Error::unavailable("Wikipedia stream admission stopped."))
            })
            .await?;
            self.record_wikipedia_attempt()?;
            #[cfg(test)]
            let destination = self.wikipedia_fixture_url(STREAM_URL)?;
            #[cfg(not(test))]
            let destination = STREAM_URL;
            let mut builder = self
                .client
                .get(destination)
                .header(reqwest::header::ACCEPT, "text/event-stream")
                .header(
                    reqwest::header::USER_AGENT,
                    crate::wikipedia::source::USER_AGENT,
                )
                .header(reqwest::header::ACCEPT_ENCODING, "gzip");
            if let Some(id) = last_event_id.filter(|id| !id.is_empty()) {
                builder = builder.header("Last-Event-ID", id);
            }
            let response = bounded(&shutdown, deadline, async {
                builder
                    .send()
                    .await
                    .map_err(|_| Error::unavailable("Wikipedia stream connection failed."))
            })
            .await?;
            let status = response.status().as_u16();
            let retry_at =
                wikipedia_retry_at(response.headers(), status, devres_domain::unix_now());
            if let Some(until) = retry_at {
                observed_retry_at.fetch_max(until, Ordering::AcqRel);
                let receipt = self.wikipedia_policy_receipt(until, &observer)?;
                if let Some(receipt) = receipt {
                    receipt.await?;
                }
            }
            if status != 200 {
                return Ok(Connection {
                    status,
                    retry_at,
                    stream: Box::pin(futures::stream::empty()),
                });
            }
            if !response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| {
                    value
                        .split(';')
                        .next()
                        .is_some_and(|kind| kind.trim().eq_ignore_ascii_case("text/event-stream"))
                })
            {
                return Err(Error::integrity("Invalid Wikipedia stream content type."));
            }
            let decoder = WikipediaDecoder::new(response.headers())?;
            let input: BulkStream = Box::pin(response.bytes_stream().map(|result| {
                result
                    .map(|bytes| bytes.to_vec())
                    .map_err(|_| Error::unavailable("Wikipedia stream transfer failed."))
            }));
            let state = WikipediaStreamState {
                input,
                decoder,
                _permit: permit,
                shutdown,
                deadline: Instant::now() + Duration::from_secs(16 * 60),
                pending: std::collections::VecDeque::new(),
                ended: false,
                retry_at,
            };
            let stream = futures::stream::try_unfold(state, |mut state| async move {
                let retry_at = state.retry_at.unwrap_or(0);
                let result = async {
                    loop {
                        if let Some(chunk) = state.pending.pop_front() {
                            return Ok(Some((chunk, state)));
                        }
                        if state.ended {
                            return Ok(None);
                        }
                        let idle_deadline =
                            state.deadline.min(Instant::now() + Duration::from_secs(90));
                        let next = bounded(&state.shutdown, idle_deadline, async {
                            state.input.next().await.transpose()
                        })
                        .await?;
                        let decoded = if let Some(input) = next {
                            if input.len() > 1024 * 1024 {
                                return Err(Error::capacity(
                                    "Wikipedia stream chunk exceeds its bound.",
                                ));
                            }
                            let mut decoded = Vec::new();
                            for part in input.chunks(16 * 1024) {
                                let output = state.decoder.decode(
                                    part,
                                    (8 * 1024 * 1024usize).saturating_sub(decoded.len()),
                                )?;
                                decoded.extend(output);
                            }
                            decoded
                        } else {
                            state.ended = true;
                            state.decoder.finish(8 * 1024 * 1024)?
                        };
                        state
                            .pending
                            .extend(decoded.chunks(CHUNK_BYTES).map(<[u8]>::to_vec));
                    }
                }
                .await;
                result.map_err(|error| wikipedia_error_with_retry(error, retry_at))
            });
            Ok(Connection {
                status,
                retry_at,
                stream: Box::pin(stream),
            })
        }
        .await;
        result.map_err(|error| {
            wikipedia_error_with_retry(error, observed_retry_at.load(Ordering::Acquire))
        })
    }
}

fn wikipedia_error_with_retry(error: Error, retry_at: i64) -> Error {
    if retry_at > 0 {
        error.with_details(serde_json::json!({"retry_at":retry_at}))
    } else {
        error
    }
}

fn wikipedia_retry_at(headers: &reqwest::header::HeaderMap, status: u16, now: i64) -> Option<i64> {
    if let Some(value) = headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
    {
        if let Ok(seconds) = value.parse::<u64>() {
            return Some(now.saturating_add(seconds.min(i64::MAX as u64) as i64));
        }
        if let Ok(date) = httpdate::parse_http_date(value) {
            return Some(
                date.duration_since(std::time::UNIX_EPOCH)
                    .map(|value| value.as_secs().min(i64::MAX as u64) as i64)
                    .unwrap_or(now)
                    .max(now),
            );
        }
    }
    match status {
        429 => Some(now.saturating_add(60)),
        500..=599 => Some(now.saturating_add(5)),
        _ => None,
    }
}

fn wikipedia_redirect(
    operation: &crate::wikipedia::source::Operation,
    base: &str,
    location: &str,
) -> Result<crate::wikipedia::source::Operation> {
    use crate::wikipedia::source::Operation;
    let invalid = || Error::integrity("Wikipedia redirect destination is not permitted.");
    if location.len() > 8192 || location.chars().any(char::is_control) || location.contains('\\') {
        return Err(invalid());
    }
    let destination = url::Url::parse(base)
        .map_err(|_| invalid())?
        .join(location)
        .map_err(|_| invalid())?;
    if destination.scheme() != "https"
        || destination.host_str() != Some("en.wikipedia.org")
        || destination.port().is_some()
        || !destination.username().is_empty()
        || destination.password().is_some()
        || destination.fragment().is_some()
    {
        return Err(invalid());
    }
    let parts: Vec<_> = destination.path_segments().ok_or_else(invalid)?.collect();
    if parts.len() < 5 || parts[..4] != ["w", "rest.php", "v1", "page"] {
        return Err(invalid());
    }
    let title = percent_encoding::percent_decode_str(parts[4])
        .decode_utf8()
        .map_err(|_| invalid())?
        .into_owned();
    crate::wikipedia::source::validate_title(&title).map_err(|_| invalid())?;
    if destination
        .query_pairs()
        .any(|(key, value)| key != "redirect" || value != "no")
    {
        return Err(invalid());
    }
    match operation {
        Operation::ArticleHtml { .. } if parts.len() == 6 && parts[5] == "with_html" => {
            Ok(Operation::ArticleHtml { title })
        }
        Operation::ArticleSource { .. } if parts.len() == 5 => {
            Ok(Operation::ArticleSource { title })
        }
        _ => Err(invalid()),
    }
}

struct WikipediaBuffer {
    bytes: Vec<u8>,
    limit: usize,
}
impl std::io::Write for WikipediaBuffer {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        if input.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other(
                "Wikipedia decoded byte budget exceeded.",
            ));
        }
        self.bytes.extend_from_slice(input);
        Ok(input.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
struct WikipediaDecoder {
    gzip: Option<flate2::write::MultiGzDecoder<WikipediaBuffer>>,
}
impl WikipediaDecoder {
    fn new(headers: &reqwest::header::HeaderMap) -> Result<Self> {
        let encoding = headers
            .get(reqwest::header::CONTENT_ENCODING)
            .map(|value| value.to_str().map(str::trim))
            .transpose()
            .map_err(|_| Error::integrity("Invalid Wikipedia content encoding."))?
            .unwrap_or("identity");
        match encoding {
            "identity" => Ok(Self { gzip: None }),
            "gzip" => Ok(Self {
                gzip: Some(flate2::write::MultiGzDecoder::new(WikipediaBuffer {
                    bytes: Vec::new(),
                    limit: 0,
                })),
            }),
            _ => Err(Error::integrity("Unsupported Wikipedia content encoding.")),
        }
    }
    fn decode(&mut self, input: &[u8], limit: usize) -> Result<Vec<u8>> {
        use std::io::Write;
        if let Some(decoder) = &mut self.gzip {
            decoder.get_mut().limit = limit;
            decoder.write_all(input).map_err(|_| {
                Error::capacity("Wikipedia gzip response is invalid or exceeds its bound.")
            })?;
            decoder.flush().map_err(|_| {
                Error::capacity("Wikipedia gzip response is invalid or exceeds its bound.")
            })?;
            Ok(std::mem::take(&mut decoder.get_mut().bytes))
        } else if input.len() <= limit {
            Ok(input.to_vec())
        } else {
            Err(Error::capacity(
                "Wikipedia response exceeds its byte budget.",
            ))
        }
    }
    fn finish(&mut self, limit: usize) -> Result<Vec<u8>> {
        if let Some(mut decoder) = self.gzip.take() {
            decoder.get_mut().limit = limit;
            decoder.try_finish().map_err(|_| {
                Error::integrity("Wikipedia gzip response is incomplete or invalid.")
            })?;
            Ok(std::mem::take(&mut decoder.get_mut().bytes))
        } else {
            Ok(Vec::new())
        }
    }
}
struct WikipediaStreamState {
    input: BulkStream,
    decoder: WikipediaDecoder,
    _permit: OwnedSemaphorePermit,
    shutdown: CancellationToken,
    deadline: Instant,
    pending: std::collections::VecDeque<Vec<u8>>,
    ended: bool,
    retry_at: Option<i64>,
}

#[cfg(test)]
mod wikipedia_tests {
    use super::*;
    use crate::wikipedia::{
        events::SseParser,
        source::{Operation, WikipediaSource},
    };
    use axum::{
        Router,
        body::Body,
        http::{HeaderMap, Response, StatusCode},
        routing::get,
    };
    use std::io::Write;

    async fn broker(app: Router) -> (Arc<BulkBroker>, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("fixture bind");
        let address = listener.local_addr().expect("fixture address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("fixture server");
        });
        let origin = url::Url::parse(&format!("http://{address}")).expect("fixture URL");
        (
            Arc::new(BulkBroker::fixture(origin).expect("fixture broker")),
            server,
        )
    }
    fn gzip(value: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(value).expect("gzip write");
        encoder.finish().expect("gzip finish")
    }
    #[tokio::test]
    async fn wikipedia_identified_gzip_fetch_retains_cache_evidence() {
        let app = Router::new().route(
            "/w/rest.php/v1/page/Rust/with_html",
            get(|headers: HeaderMap| async move {
                assert_eq!(
                    headers.get("accept-encoding").and_then(|v| v.to_str().ok()),
                    Some("gzip")
                );
                assert!(
                    headers
                        .get("user-agent")
                        .and_then(|v| v.to_str().ok())
                        .is_some_and(|v| v
                            .contains("https://github.com/PublicData-stream/dev-resources-MCP"))
                );
                assert_eq!(
                    headers.get("if-none-match").and_then(|v| v.to_str().ok()),
                    Some("\"old\"")
                );
                Response::builder()
                    .status(200)
                    .header("content-encoding", "gzip")
                    .header("cache-control", "public,max-age=600")
                    .header("etag", "\"new\"")
                    .body(Body::from(gzip(br#"{"id":1,"html":"Rust"}"#)))
                    .expect("response")
            }),
        );
        let (broker, server) = broker(app).await;
        let source = WikipediaSource::new(broker.clone());
        let response = source
            .fetch(
                Operation::ArticleHtml {
                    title: "Rust".into(),
                },
                Validators {
                    etag: Some("\"old\"".into()),
                    last_modified: None,
                },
                CancellationToken::new(),
            )
            .await
            .expect("fetch");
        assert_eq!(response.body, br#"{"id":1,"html":"Rust"}"#);
        assert_eq!(response.validators.etag.as_deref(), Some("\"new\""));
        assert!(response.cache.retention_allowed().expect("retention"));
        assert_eq!(broker.attempt_count(), 1);
        server.abort();
    }
    #[tokio::test]
    async fn wikipedia_retry_after_is_returned_without_internal_retry() {
        let app = Router::new().fallback(|| async {
            Response::builder()
                .status(429)
                .header("retry-after", "3600")
                .body(Body::from("diagnostics must not escape"))
                .expect("response")
        });
        let (broker, server) = broker(app).await;
        let before = devres_domain::unix_now();
        let response = WikipediaSource::new(broker.clone())
            .fetch(
                Operation::ArticleSource {
                    title: "Rust".into(),
                },
                Validators::default(),
                CancellationToken::new(),
            )
            .await
            .expect("429");
        assert_eq!(response.status, 429);
        assert!(
            response
                .retry_at
                .is_some_and(|until| until >= before + 3600)
        );
        assert!(response.body.is_empty());
        assert_eq!(broker.attempt_count(), 1);
        server.abort();
    }
    #[tokio::test]
    async fn wikipedia_private_response_cannot_expose_body_for_retention() {
        let app = Router::new().fallback(|| async {
            Response::builder()
                .status(200)
                .header("cache-control", "private, no-store")
                .body(Body::from("forbidden bytes"))
                .expect("response")
        });
        let (broker, server) = broker(app).await;
        let response = WikipediaSource::new(broker)
            .fetch(
                Operation::ArticleSource {
                    title: "Rust".into(),
                },
                Validators::default(),
                CancellationToken::new(),
            )
            .await
            .expect("policy response");
        assert!(response.body.is_empty());
        assert!(!response.cache.retention_allowed().expect("policy"));
        server.abort();
    }
    #[tokio::test]
    async fn wikipedia_malformed_cache_cannot_erase_retry_after() {
        let app = Router::new().fallback(|| async {
            Response::builder()
                .status(429)
                .header("retry-after", "3600")
                .header("age", "malformed")
                .body(Body::from("diagnostic body"))
                .expect("response")
        });
        let (broker, server) = broker(app).await;
        let before = devres_domain::unix_now();
        let response = WikipediaSource::new(broker.clone())
            .fetch(
                Operation::ArticleSource {
                    title: "Rust".into(),
                },
                Validators::default(),
                CancellationToken::new(),
            )
            .await
            .expect("throttling evidence");
        assert_eq!(response.status, 429);
        assert_eq!(
            response.api_error.as_deref(),
            Some("malformed_cache_metadata")
        );
        assert!(
            response
                .retry_at
                .is_some_and(|until| until >= before + 3600)
        );
        assert!(response.body.is_empty());
        assert_eq!(broker.attempt_count(), 1);
        server.abort();
    }
    #[tokio::test]
    async fn wikipedia_post_header_gzip_and_stream_type_errors_preserve_retry_after() {
        let app = Router::new().fallback(|| async {
            Response::builder()
                .status(200)
                .header("retry-after", "3600")
                .header("content-type", "application/json")
                .header("content-encoding", "gzip")
                .body(Body::from("invalid-gzip"))
                .expect("response")
        });
        let (broker, server) = broker(app).await;
        let before = devres_domain::unix_now();
        let source = WikipediaSource::new(broker);
        let error = source
            .fetch(
                Operation::ArticleSource {
                    title: "Rust".into(),
                },
                Validators::default(),
                CancellationToken::new(),
            )
            .await
            .err()
            .expect("bad gzip");
        assert!(
            error
                .details
                .as_ref()
                .and_then(|details| details["retry_at"].as_i64())
                .is_some_and(|until| until >= before + 3600)
        );
        let error = source
            .stream(None, CancellationToken::new())
            .await
            .err()
            .expect("bad stream content type");
        assert!(
            error
                .details
                .as_ref()
                .and_then(|details| details["retry_at"].as_i64())
                .is_some_and(|until| until >= before + 3600)
        );
        server.abort();
    }
    #[tokio::test]
    async fn wikipedia_redirect_cancellation_preserves_a_long_observed_retry_after() {
        let app = Router::new().fallback(|| async {
            Response::builder()
                .status(301)
                .header("retry-after", "3600")
                .header("location", "/w/rest.php/v1/page/Rust/with_html")
                .body(Body::empty())
                .expect("redirect")
        });
        let (broker, server) = broker(app).await;
        let source = WikipediaSource::new(broker.clone());
        let cancel = CancellationToken::new();
        let token = cancel.clone();
        let before = devres_domain::unix_now();
        let task = tokio::spawn(async move {
            source
                .fetch(
                    Operation::ArticleHtml {
                        title: "Alias".into(),
                    },
                    Validators::default(),
                    token,
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if broker
                    .rates
                    .lock()
                    .await
                    .get("wikipedia-api")
                    .is_some_and(|until| *until > Instant::now() + Duration::from_secs(3000))
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("observed header before cancellation");
        cancel.cancel();
        let error = task
            .await
            .expect("source task")
            .err()
            .expect("canceled redirect wait");
        assert!(
            error
                .details
                .as_ref()
                .and_then(|details| details["retry_at"].as_i64())
                .is_some_and(|until| until >= before + 3600)
        );
        assert_eq!(broker.attempt_count(), 1);
        assert!(
            !serde_json::to_string(&error)
                .expect("sanitized error")
                .contains("/page/")
        );
        server.abort();
    }
    #[tokio::test]
    async fn wikipedia_stream_has_an_independent_permit_and_projects_only_public_fields() {
        let app = Router::new().route("/v2/stream/recentchange", get(|| async {
            let value = serde_json::json!({"meta":{"domain":"en.wikipedia.org"},"wiki":"enwiki","server_name":"en.wikipedia.org","title":"Rust","namespace":0,"timestamp":100,"type":"edit","user":"private-editor"});
            Response::builder().header("content-type", "text/event-stream").header("content-encoding", "gzip").body(Body::from(gzip(format!("data: {value}\n\n").as_bytes()))).expect("response")
        }));
        let (broker, server) = broker(app).await;
        let _occupied = broker
            .bulk_slots
            .clone()
            .acquire_many_owned(4)
            .await
            .expect("occupy transfer slots");
        let mut connection = WikipediaSource::new(broker.clone())
            .stream(None, CancellationToken::new())
            .await
            .expect("stream independent");
        assert_eq!(connection.status, 200);
        let mut parser = SseParser::new();
        let mut events = Vec::new();
        while let Some(chunk) = connection.stream.next().await {
            events.extend(parser.push(&chunk.expect("chunk")).expect("events"));
        }
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].change.as_ref().expect("change").title, "Rust");
        assert_eq!(broker.wikipedia_stream_slots.available_permits(), 1);
        server.abort();
    }
    #[tokio::test]
    async fn wikipedia_off_origin_redirect_is_rejected_without_following() {
        let app = Router::new().fallback(|| async {
            Response::builder()
                .status(StatusCode::TEMPORARY_REDIRECT)
                .header(
                    "location",
                    "https://evil.invalid/w/rest.php/v1/page/Rust/with_html",
                )
                .body(Body::empty())
                .expect("response")
        });
        let (broker, server) = broker(app).await;
        assert!(
            WikipediaSource::new(broker.clone())
                .fetch(
                    Operation::ArticleHtml {
                        title: "Rust".into()
                    },
                    Validators::default(),
                    CancellationToken::new()
                )
                .await
                .is_err()
        );
        assert_eq!(broker.attempt_count(), 1);
        server.abort();
    }
    #[tokio::test]
    async fn wikipedia_each_canonical_redirect_hop_requires_durable_admission() {
        let app = Router::new()
            .route(
                "/w/rest.php/v1/page/Alias/with_html",
                get(|| async {
                    Response::builder()
                        .status(307)
                        .header("location", "/w/rest.php/v1/page/Rust/with_html")
                        .body(Body::empty())
                        .expect("redirect")
                }),
            )
            .route(
                "/w/rest.php/v1/page/Rust/with_html",
                get(|| async { "{\"id\":1,\"html\":\"Rust\"}" }),
            );
        let (broker, server) = broker(app).await;
        let reservations = AtomicUsize::new(0);
        let result = WikipediaSource::new(broker.clone())
            .fetch_with_admission(
                Operation::ArticleHtml {
                    title: "Alias".into(),
                },
                Validators::default(),
                CancellationToken::new(),
                || async {
                    reservations.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
            )
            .await
            .expect("canonical redirect");
        assert_eq!(result.status, 200);
        assert!(result.effective_url.contains("/page/Rust/with_html"));
        assert_eq!(reservations.load(Ordering::SeqCst), 2);
        assert_eq!(broker.attempt_count(), 2);
        server.abort();
    }
    #[test]
    fn wikipedia_gzip_bombs_and_redirect_query_injection_are_bounded() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("content-encoding", "gzip".parse().expect("header"));
        let input = gzip(&vec![b'x'; 1024 * 1024]);
        assert!(
            WikipediaDecoder::new(&headers)
                .expect("decoder")
                .decode(&input, 1024)
                .is_err()
        );
        let op = Operation::ArticleHtml {
            title: "Rust".into(),
        };
        let base = op.url().expect("base");
        assert!(
            wikipedia_redirect(&op, &base, "/w/rest.php/v1/page/Rust/with_html?url=evil").is_err()
        );
        assert!(
            wikipedia_redirect(&op, &base, "/w/rest.php/v1/page/Rust%20language/with_html").is_ok()
        );
    }
    #[test]
    fn wikipedia_gzip_sse_survives_arbitrarily_fragmented_transport_bytes() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("content-encoding", "gzip".parse().expect("header"));
        let wire = b":ok\n\nevent: message\ndata: {\"meta\":{\"domain\":\"canary\"}}\n\n";
        let compressed = gzip(wire);
        let mut decoder = WikipediaDecoder::new(&headers).expect("decoder");
        let mut decoded = Vec::new();
        for byte in compressed {
            decoded.extend(decoder.decode(&[byte], 1024).expect("fragmented gzip"));
        }
        decoded.extend(decoder.finish(1024).expect("gzip trailer"));
        assert_eq!(decoded, wire);
        assert_eq!(SseParser::new().push(&decoded).expect("SSE").len(), 1);
        let mut members = gzip(wire);
        members.extend(gzip(wire));
        let mut decoder = WikipediaDecoder::new(&headers).expect("multi-member decoder");
        let mut decoded = decoder
            .decode(&members, 4096)
            .expect("concatenated gzip members");
        decoded.extend(decoder.finish(4096).expect("concatenated trailers"));
        assert_eq!(
            SseParser::new()
                .push(&decoded)
                .expect("two member SSE")
                .len(),
            2
        );
    }
}

type ByteReader = Pin<Box<dyn tokio::io::AsyncRead + Send>>;
struct StreamState {
    reader: ByteReader,
    _permit: AttemptPermit,
    _chromium_permit: Option<OwnedSemaphorePermit>,
    received: u64,
    max_bytes: u64,
    expected_bytes: Option<u64>,
    deadline: Instant,
    shutdown: CancellationToken,
}
pub(crate) async fn bounded<T>(
    shutdown: &CancellationToken,
    deadline: Instant,
    future: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    tokio::select! { biased;
        _ = shutdown.cancelled() => Err(Error::unavailable("Bulk operation canceled.")),
        result = tokio::time::timeout_at(deadline, future) => result.map_err(|_| limited(Error::capacity("Bulk operation deadline exceeded."), Phase::BulkOperation, LimitKind::Deadline, None, None))?,
    }
}
fn response_validators(headers: &reqwest::header::HeaderMap) -> Validators {
    Validators {
        etag: headers
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned),
        last_modified: headers
            .get(reqwest::header::LAST_MODIFIED)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned),
    }
}
fn retry_after(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    let seconds = match headers.get(reqwest::header::RETRY_AFTER) {
        None => 1,
        Some(value) => {
            let value = value.to_str().ok()?;
            value.parse::<u64>().ok().or_else(|| {
                httpdate::parse_http_date(value).ok().map(|date| {
                    date.duration_since(std::time::SystemTime::now())
                        .map(|d| d.as_secs().saturating_add(1))
                        .unwrap_or(1)
                })
            })?
        }
    };
    (seconds <= MAX_RETRY_AFTER).then(|| Duration::from_secs(seconds.max(1)))
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BulkArtifact {
    pub body_hash: String,
    pub bytes: u64,
    pub relative_path: String,
}

/// A verified local artifact whose cache residency remains reserved until drop.
/// The serialized artifact descriptor deliberately stays independent of this lease.
pub struct MaterializedArtifact {
    pub artifact: BulkArtifact,
    pub path: PathBuf,
    _lease: crate::durable_archive::ArchiveLease,
}

/// An open artifact retains its materialization lease through all asynchronous I/O.
pub struct LeasedArtifactFile {
    file: tokio::fs::File,
    _materialized: MaterializedArtifact,
}

impl tokio::io::AsyncRead for LeasedArtifactFile {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().file).poll_read(context, buffer)
    }
}

impl tokio::io::AsyncSeek for LeasedArtifactFile {
    fn start_seek(self: Pin<&mut Self>, position: std::io::SeekFrom) -> std::io::Result<()> {
        Pin::new(&mut self.get_mut().file).start_seek(position)
    }

    fn poll_complete(
        self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<u64>> {
        Pin::new(&mut self.get_mut().file).poll_complete(context)
    }
}

impl LeasedArtifactFile {
    /// Callers transferring to blocking parsers must keep the returned residency
    /// guard alive until the standard file and parser have both been dropped.
    pub async fn into_std(self) -> (std::fs::File, MaterializedArtifact) {
        (self.file.into_std().await, self._materialized)
    }
}

/// Materialize a retained path without replacing its caller-owned read/proof
/// policy. Byte-page consumers retain their existing per-block verification.
pub(crate) async fn lease_path(
    path: &Path,
    max_bytes: u64,
    deadline: std::time::Instant,
    cancel: CancellationToken,
) -> Result<crate::durable_archive::ArchiveLease> {
    let path = path.to_owned();
    // Dropping an RPC waiter must stop its owned blocking download as well.
    // A child token leaves the caller's shared collection token untouched.
    let cancel = cancel.child_token();
    let _cancel_on_drop = cancel.clone().drop_guard();
    tokio::task::spawn_blocking(move || {
        crate::durable_archive::materialize_file(&path, max_bytes, deadline, &cancel)
    })
    .await
    .map_err(|_| storage_error())?
}

pub struct BulkArtifactStore {
    root: PathBuf,
    verification_only: bool,
    min_free_bytes: u64,
    quota: Option<Quota>,
}
type PhysicalObjects = std::collections::BTreeSet<(u64, u64)>;
type PhysicalRegistry = Arc<std::sync::Mutex<PhysicalObjects>>;
#[derive(Clone)]
struct Quota {
    used: Arc<AtomicU64>,
    limit: u64,
    roots: Arc<std::sync::Mutex<std::collections::BTreeSet<PathBuf>>>,
    objects: PhysicalRegistry,
}
pub struct ArtifactReservation {
    used: Option<Arc<AtomicU64>>,
    objects: Option<PhysicalRegistry>,
    bytes: u64,
    retained: bool,
}
impl ArtifactReservation {
    fn reserve(&mut self, bytes: u64, limit: u64) -> Result<()> {
        if let Some(used) = &self.used {
            used.try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(bytes).filter(|next| *next <= limit)
            })
            .map_err(|_| {
                limited(
                    Error::capacity("Bulk archive quota exhausted; history is preserved."),
                    Phase::ArtifactRetention,
                    LimitKind::ArchiveQuota,
                    used.load(Ordering::Acquire).checked_add(bytes),
                    Some(limit),
                )
            })?;
            self.bytes += bytes;
        }
        Ok(())
    }
    /// Call immediately after creating a new immutable hash-named object, even if
    /// later directory fsync or database publication fails.
    pub fn retain(mut self) {
        self.retained = true;
    }
    /// Register the newly published physical object for cross-root hard-link accounting.
    pub fn retain_at(mut self, path: &Path) -> Result<()> {
        // A failed bookkeeping check must not release bytes already published on disk.
        self.retained = true;
        if let Some(objects) = &self.objects {
            let metadata = std::fs::symlink_metadata(path).map_err(|_| storage_error())?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(Error::integrity("Invalid retained artifact."));
            }
            let selected = crate::durable_archive::accounting_identity(path)?;
            let identity = selected.unwrap_or((metadata.dev(), metadata.ino()));
            let mut objects = objects.lock().map_err(|_| storage_error())?;
            if selected.is_some()
                && objects.len() >= crate::durable_archive::MAX_ACCOUNTING_OBJECTS
                && !objects.contains(&identity)
            {
                return Err(Error::capacity(
                    "Archive quota object accounting exceeds its bound.",
                ));
            }
            objects.insert(identity);
        }
        Ok(())
    }
}
impl Drop for ArtifactReservation {
    fn drop(&mut self) {
        if !self.retained
            && let Some(used) = &self.used
        {
            used.fetch_sub(self.bytes, Ordering::AcqRel);
        }
    }
}
struct Stage(PathBuf);
impl Drop for Stage {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let _ = crate::durable_archive::forget_local(&self.0);
    }
}
pub(crate) fn valid_hash(hash: &str) -> bool {
    crate::integrity::valid_hash(hash)
}

impl BulkArtifactStore {
    /// The caller must already hold the database's exclusive storage fence.
    pub fn new(root: impl AsRef<Path>, min_free_bytes: u64) -> Result<Self> {
        if min_free_bytes < 64 * 1024 * 1024 {
            return Err(Error::invalid("Invalid bulk storage headroom."));
        }
        // A cold object-backed cache need not retain empty archive directories.
        // Recreate only a directory whose permanent children are already bound;
        // an absent ordinary filesystem store remains an explicit error.
        if root.as_ref().is_absolute()
            && !root.as_ref().exists()
            && crate::durable_archive::retained(root.as_ref())?
        {
            crate::integrity::ensure_directory_durable(root.as_ref())?;
        }
        let metadata = std::fs::symlink_metadata(root.as_ref()).map_err(|_| storage_error())?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(Error::integrity("Invalid bulk archive directory."));
        }
        Ok(Self {
            root: std::fs::canonicalize(root).map_err(|_| storage_error())?,
            verification_only: false,
            min_free_bytes,
            quota: None,
        })
    }
    /// Bind an expected archive path without initializing, recovering, or scanning it.
    /// Verification validates referenced objects when they are read.
    pub(crate) fn for_verification(root: impl AsRef<Path>, min_free_bytes: u64) -> Result<Self> {
        if min_free_bytes < 64 * 1024 * 1024 {
            return Err(Error::invalid("Invalid bulk storage headroom."));
        }
        Ok(Self {
            root: root.as_ref().to_owned(),
            verification_only: true,
            min_free_bytes,
            quota: None,
        })
    }
    pub(crate) fn require_writable(&self) -> Result<()> {
        if self.verification_only {
            return Err(Error::integrity(
                "Verification archive handles are read-only.",
            ));
        }
        Ok(())
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
    /// Counts existing hash-named immutable objects; concurrent bulk stages reserve
    /// quota before writes. Ordinary publishers must share this store's accounting.
    pub fn with_quota(mut self, max_bytes: Option<u64>) -> Result<Self> {
        self.require_writable()?;
        let Some(limit) = max_bytes else {
            self.quota = None;
            return Ok(self);
        };
        if limit == 0 {
            return Err(Error::invalid("Artifact quota must be positive."));
        }
        let (used, objects) = retained_bytes(&self.root, &std::collections::BTreeSet::new())?;
        self.quota = Some(Quota {
            used: Arc::new(AtomicU64::new(used)),
            limit,
            objects: Arc::new(std::sync::Mutex::new(objects)),
            roots: Arc::new(std::sync::Mutex::new(std::collections::BTreeSet::from([
                self.root.clone(),
            ]))),
        });
        Ok(self)
    }
    /// Attach another owned archive directory to the same retention quota before
    /// starting publishers. Each canonical directory is counted exactly once,
    /// including when another handle is reconstructed for an already attached root.
    /// All publishers into those directories must use this shared budget.
    pub fn with_shared_budget(mut self, other: &Self) -> Result<Self> {
        self.require_writable()?;
        let Some(quota) = &other.quota else {
            self.quota = None;
            return Ok(self);
        };
        {
            let mut roots = quota.roots.lock().map_err(|_| storage_error())?;
            if !roots.contains(&self.root) {
                let mut objects = quota.objects.lock().map_err(|_| storage_error())?;
                let (bytes, additions) = retained_bytes(&self.root, &objects)?;
                if crate::durable_archive::is_object_archive(&self.root)?
                    && objects.len().saturating_add(additions.len())
                        > crate::durable_archive::MAX_ACCOUNTING_OBJECTS
                {
                    return Err(Error::capacity(
                        "Archive quota object accounting exceeds its bound.",
                    ));
                }
                quota
                    .used
                    .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                        used.checked_add(bytes)
                    })
                    .map_err(|_| Error::capacity("Artifact quota accounting overflow."))?;
                objects.extend(additions);
                roots.insert(self.root.clone());
            }
        }
        self.quota = Some(quota.clone());
        Ok(self)
    }
    pub fn accounted_bytes(&self) -> Option<u64> {
        self.quota
            .as_ref()
            .map(|quota| quota.used.load(Ordering::Acquire))
    }
    pub fn quota_bytes(&self) -> Option<u64> {
        self.quota.as_ref().map(|quota| quota.limit)
    }
    /// The ordinary small-blob publisher can share the same accounting. Dropping
    /// an unretained reservation rolls back staging/duplicate charges.
    pub fn reserve_bytes(&self, bytes: u64) -> Result<ArtifactReservation> {
        self.require_writable()?;
        let mut reservation = ArtifactReservation {
            used: self.quota.as_ref().map(|quota| quota.used.clone()),
            objects: self.quota.as_ref().map(|quota| quota.objects.clone()),
            bytes: 0,
            retained: false,
        };
        reservation.reserve(
            bytes,
            self.quota.as_ref().map_or(u64::MAX, |quota| quota.limit),
        )?;
        Ok(reservation)
    }
    /// Only recognized abandoned regular staging files are disposable.
    pub async fn recover_stages(&self) -> Result<()> {
        self.require_writable()?;
        let mut entries = tokio::fs::read_dir(&self.root)
            .await
            .map_err(|_| storage_error())?;
        while let Some(entry) = entries.next_entry().await.map_err(|_| storage_error())? {
            let name = entry.file_name();
            if stage_name(&name.to_string_lossy())
                && entry
                    .file_type()
                    .await
                    .map_err(|_| storage_error())?
                    .is_file()
            {
                tokio::fs::remove_file(entry.path())
                    .await
                    .map_err(|_| storage_error())?;
            }
        }
        sync_directory(&self.root).await
    }
    pub async fn capture(
        &self,
        response: BulkResponse,
        expected_hash: Option<&str>,
        shutdown: CancellationToken,
    ) -> Result<BulkArtifact> {
        if response.status != 200 {
            return Err(if response.status == 404 {
                Error::not_found("Bulk source not found.")
            } else {
                Error::unavailable("Bulk source did not supply a representation.")
            });
        }
        self.publish_stream(response.stream, expected_hash, MAX_ARTIFACT_BYTES, shutdown)
            .await
    }
    pub async fn ingest_file(
        &self,
        path: &Path,
        max_bytes: u64,
        shutdown: CancellationToken,
    ) -> Result<BulkArtifact> {
        if max_bytes == 0 || max_bytes > MAX_ARTIFACT_BYTES {
            return Err(Error::invalid("Invalid artifact byte budget."));
        }
        let metadata = tokio::fs::symlink_metadata(path)
            .await
            .map_err(|_| storage_error())?;
        if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > max_bytes {
            return Err(Error::capacity("Invalid or oversized artifact file."));
        }
        let file = tokio::fs::File::open(path)
            .await
            .map_err(|_| storage_error())?;
        let stream = futures::stream::try_unfold(file, |mut file| async move {
            let mut chunk = vec![0; CHUNK_BYTES];
            let read = file.read(&mut chunk).await.map_err(|_| storage_error())?;
            if read == 0 {
                return Ok(None);
            }
            chunk.truncate(read);
            Ok(Some((chunk, file)))
        });
        self.publish_stream(Box::pin(stream), None, max_bytes, shutdown)
            .await
    }
    pub async fn capture_bytes(
        &self,
        bytes: Vec<u8>,
        shutdown: CancellationToken,
    ) -> Result<BulkArtifact> {
        self.capture_bytes_bounded(bytes, 16 * 1024 * 1024, shutdown)
            .await
    }
    /// Trusted normalized-document capture with an explicit bounded envelope.
    /// Ordinary callers retain the original 16 MiB admission limit.
    pub(crate) async fn capture_bytes_bounded(
        &self,
        bytes: Vec<u8>,
        max_bytes: u64,
        shutdown: CancellationToken,
    ) -> Result<BulkArtifact> {
        if max_bytes == 0 || max_bytes > 256 * 1024 * 1024 || bytes.len() as u64 > max_bytes {
            return Err(limited(
                Error::capacity("In-memory artifact exceeds its byte budget."),
                Phase::ArtifactRetention,
                LimitKind::ArtifactBytes,
                Some(bytes.len() as u64),
                Some(max_bytes),
            ));
        }
        let stream = futures::stream::unfold((bytes, 0), |(bytes, offset)| async move {
            if offset == bytes.len() {
                return None;
            }
            let end = offset.saturating_add(CHUNK_BYTES).min(bytes.len());
            let chunk = bytes[offset..end].to_vec();
            Some((Ok(chunk), (bytes, end)))
        });
        self.publish_stream(Box::pin(stream), None, max_bytes, shutdown)
            .await
    }
    async fn publish_stream(
        &self,
        mut stream: BulkStream,
        expected_hash: Option<&str>,
        max_bytes: u64,
        shutdown: CancellationToken,
    ) -> Result<BulkArtifact> {
        self.require_writable()?;
        if expected_hash.is_some_and(|hash| !valid_hash(hash) || hash.starts_with("blake3:")) {
            return Err(Error::invalid("Invalid expected artifact checksum."));
        }
        let path = self.root.join(format!(
            ".bulk-stage-{}-{}",
            std::process::id(),
            STAGE.fetch_add(1, Ordering::Relaxed)
        ));
        let mut stage = Stage(path.clone());
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .await
            .map_err(|_| storage_error())?
            .into_std()
            .await;
        let mut upstream_hash = Sha256::new();
        let mut hash = blake3::Hasher::new();
        let mut bytes = 0_u64;
        let mut reservation = self.reserve_bytes(0)?;
        loop {
            let next = tokio::select! { biased; _ = shutdown.cancelled() => return Err(Error::unavailable("Bulk artifact publication canceled.")), next = stream.next() => next };
            let Some(chunk) = next else {
                break;
            };
            let chunk = chunk?;
            if chunk.len() > CHUNK_BYTES {
                return Err(Error::capacity("Artifact chunk exceeds streaming budget."));
            }
            bytes = bytes
                .checked_add(chunk.len() as u64)
                .filter(|length| *length <= max_bytes)
                .ok_or_else(|| {
                    limited(
                        Error::capacity("Artifact exceeds byte budget."),
                        Phase::ArtifactRetention,
                        LimitKind::ArtifactBytes,
                        bytes.checked_add(chunk.len() as u64),
                        Some(max_bytes),
                    )
                })?;
            let free = fs2::available_space(&self.root).map_err(|_| storage_error())?;
            if free < self.min_free_bytes.saturating_add(chunk.len() as u64) {
                return Err(limited(
                    Error::capacity("Insufficient archive space; history is preserved."),
                    Phase::ArtifactRetention,
                    LimitKind::FreeReserve,
                    Some(free),
                    Some(self.min_free_bytes.saturating_add(chunk.len() as u64)),
                ));
            }
            reservation.reserve(
                chunk.len() as u64,
                self.quota.as_ref().map_or(u64::MAX, |quota| quota.limit),
            )?;
            upstream_hash.update(&chunk);
            hash.update(&chunk);
            let selected = path.clone();
            let write = tokio::task::spawn_blocking(move || {
                crate::durable_archive::with_write_budget(&selected, chunk.len() as u64, || {
                    std::io::Write::write_all(&mut file, &chunk)
                })
                .map_err(|_| storage_error())?;
                Ok::<_, Error>((file, stage))
            });
            (file, stage) = tokio::select! {
                biased;
                _ = shutdown.cancelled() => return Err(Error::unavailable("Bulk artifact publication canceled.")),
                result = write => result.map_err(|_| storage_error())??,
            };
        }
        let body_hash = format!("blake3:{}", hash.finalize().to_hex());
        let upstream_hash = hex::encode(upstream_hash.finalize());
        if expected_hash.is_some_and(|expected| expected != upstream_hash) {
            return Err(Error::integrity("Bulk artifact checksum mismatch."));
        }
        stage = tokio::task::spawn_blocking(move || {
            file.sync_all().map_err(|_| storage_error())?;
            drop(file);
            Ok::<_, Error>(stage)
        })
        .await
        .map_err(|_| storage_error())??;
        if shutdown.is_cancelled() {
            return Err(Error::unavailable("Bulk artifact publication canceled."));
        }
        let relative_path = crate::integrity::relative_path(&body_hash)?;
        let destination = self.root.join(&relative_path);
        let retained_path = destination.clone();
        let retained_cancel = shutdown.clone();
        let _retained = tokio::task::spawn_blocking(move || {
            crate::durable_archive::materialize_if_retained(
                &retained_path,
                max_bytes,
                std::time::Instant::now() + Duration::from_secs(24 * 60 * 60),
                &retained_cancel,
            )
        })
        .await
        .map_err(|_| storage_error())??;
        let destination_directory = destination.parent().ok_or_else(storage_error)?.to_owned();
        crate::integrity::ensure_directory(&destination_directory).await?;
        // The filesystem operation and quota ownership transition must have one
        // owner even if its async waiter is canceled after link creation.
        let stage_path = stage.0.clone();
        let created =
            tokio::task::spawn_blocking(move || retain_link(stage_path, destination, reservation))
                .await
                .map_err(|_| storage_error())??;
        if !created {
            // A previous failed upload may have left an unreferenced local
            // object. Verify its bytes before retrying durable publication;
            // ordinary reads still require an established archive binding.
            let existing = self
                .verify_resident(&body_hash, max_bytes, shutdown.clone())
                .await?;
            if existing.bytes != bytes {
                return Err(Error::integrity("Immutable artifact length mismatch."));
            }
        }
        sync_directory(&destination_directory).await?;
        let root = self.root.clone();
        let published_path = self.root.join(&relative_path);
        let published_digest = body_hash.clone();
        tokio::task::spawn_blocking(move || {
            crate::integrity::record_file(&root, &published_path, &published_digest, bytes)
        })
        .await
        .map_err(|_| storage_error())??;
        Ok(BulkArtifact {
            relative_path: relative_path.to_string_lossy().into_owned(),
            body_hash,
            bytes,
        })
    }
    pub async fn verify(
        &self,
        hash: &str,
        max_bytes: u64,
        shutdown: CancellationToken,
    ) -> Result<BulkArtifact> {
        Ok(self.materialize(hash, max_bytes, shutdown).await?.artifact)
    }

    /// Verify and pin an artifact for consumers that need its filesystem path.
    /// Keeping this handle alive closes the verification-to-open eviction race.
    pub async fn materialize(
        &self,
        hash: &str,
        max_bytes: u64,
        shutdown: CancellationToken,
    ) -> Result<MaterializedArtifact> {
        if !valid_hash(hash) {
            return Err(Error::invalid("Invalid artifact hash."));
        }
        let path = self.root.join(crate::integrity::relative_path(hash)?);
        // Bulk callers impose their own shorter operation deadlines. The outer
        // bound also covers private imports, which already admit up to 24 hours.
        let deadline = std::time::Instant::now() + Duration::from_secs(24 * 60 * 60);
        let lease = lease_path(&path, max_bytes, deadline, shutdown.clone()).await?;
        let artifact = self.verify_resident(hash, max_bytes, shutdown).await?;
        Ok(MaterializedArtifact {
            artifact,
            path,
            _lease: lease,
        })
    }

    async fn verify_resident(
        &self,
        hash: &str,
        max_bytes: u64,
        shutdown: CancellationToken,
    ) -> Result<BulkArtifact> {
        if self.verification_only {
            let metadata = tokio::fs::symlink_metadata(&self.root)
                .await
                .map_err(|_| storage_error())?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(Error::integrity("Invalid bulk archive directory."));
            }
        }
        let path = self.root.join(crate::integrity::relative_path(hash)?);
        let metadata = tokio::fs::symlink_metadata(&path)
            .await
            .map_err(|_| storage_error())?;
        if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > max_bytes {
            return Err(Error::integrity("Invalid retained artifact."));
        }
        let mut file = tokio::fs::File::open(&path)
            .await
            .map_err(|_| storage_error())?;
        let mut legacy_digest = Sha256::new();
        let mut digest = blake3::Hasher::new();
        let mut length = 0_u64;
        let mut chunk = vec![0; CHUNK_BYTES];
        loop {
            let count = tokio::select! { biased; _ = shutdown.cancelled() => return Err(Error::unavailable("Artifact verification canceled.")), result = file.read(&mut chunk) => result.map_err(|_| storage_error())? };
            if count == 0 {
                break;
            }
            length = length
                .checked_add(count as u64)
                .filter(|bytes| *bytes <= max_bytes)
                .ok_or_else(|| Error::integrity("Retained artifact grew beyond its budget."))?;
            legacy_digest.update(&chunk[..count]);
            digest.update(&chunk[..count]);
        }
        let computed_b3 = format!("blake3:{}", digest.finalize().to_hex());
        let actual = if hash.starts_with("blake3:") {
            computed_b3.clone()
        } else {
            hex::encode(legacy_digest.finalize())
        };
        if length != metadata.len() || actual != hash {
            return Err(Error::integrity("Retained artifact checksum mismatch."));
        }
        if !hash.starts_with("blake3:") {
            crate::integrity::verify_legacy_digest(&self.root.join(hash), &computed_b3, length)?;
        }
        Ok(BulkArtifact {
            body_hash: hash.into(),
            relative_path: crate::integrity::relative_path(hash)?
                .to_string_lossy()
                .into_owned(),
            bytes: length,
        })
    }
    pub async fn open(
        &self,
        hash: &str,
        max_bytes: u64,
        shutdown: CancellationToken,
    ) -> Result<LeasedArtifactFile> {
        let materialized = self.materialize(hash, max_bytes, shutdown).await?;
        let file = tokio::fs::File::open(&materialized.path)
            .await
            .map_err(|_| storage_error())?;
        Ok(LeasedArtifactFile {
            file,
            _materialized: materialized,
        })
    }
}
fn retained_bytes(root: &Path, known: &PhysicalObjects) -> Result<(u64, PhysicalObjects)> {
    if let Some(retained) = crate::durable_archive::retained_accounting(root)? {
        let mut additions = PhysicalObjects::new();
        let mut bytes = 0_u64;
        for (device, inode, length) in retained {
            let identity = (device, inode);
            if !known.contains(&identity) && additions.insert(identity) {
                bytes = bytes
                    .checked_add(length)
                    .ok_or_else(|| Error::capacity("Artifact quota accounting overflow."))?;
            }
        }
        return Ok((bytes, additions));
    }
    fn scan(
        root: &Path,
        canonical: bool,
        known: &PhysicalObjects,
        additions: &mut PhysicalObjects,
    ) -> Result<u64> {
        let mut used = 0_u64;
        for entry in std::fs::read_dir(root).map_err(|_| storage_error())? {
            let entry = entry.map_err(|_| storage_error())?;
            if entry.file_name() == "blake3" {
                let kind = entry.file_type().map_err(|_| storage_error())?;
                if canonical || !kind.is_dir() || kind.is_symlink() {
                    return Err(Error::integrity("Invalid BLAKE3 artifact directory."));
                }
                used = used
                    .checked_add(scan(&entry.path(), true, known, additions)?)
                    .ok_or_else(|| Error::capacity("Artifact quota accounting overflow."))?;
                continue;
            }
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !valid_hash(&name) || name.starts_with("blake3:") {
                continue;
            }
            let metadata = std::fs::symlink_metadata(entry.path()).map_err(|_| storage_error())?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(Error::integrity(
                    "Invalid immutable artifact filesystem member.",
                ));
            }
            let identity = (metadata.dev(), metadata.ino());
            if !known.contains(&identity) && additions.insert(identity) {
                used = used
                    .checked_add(metadata.len())
                    .ok_or_else(|| Error::capacity("Artifact quota accounting overflow."))?;
            }
        }
        Ok(used)
    }
    let mut additions = PhysicalObjects::new();
    let bytes = scan(root, false, known, &mut additions)?;
    Ok((bytes, additions))
}

fn storage_error() -> Error {
    Error::unavailable("Bulk artifact storage unavailable.")
}
fn retain_link(
    stage: PathBuf,
    destination: PathBuf,
    reservation: ArtifactReservation,
) -> Result<bool> {
    match std::fs::hard_link(stage, &destination) {
        Ok(()) => {
            reservation.retain_at(&destination)?;
            crate::durable_archive::observe_local(&destination)?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(_) => Err(storage_error()),
    }
}
async fn sync_directory(path: &Path) -> Result<()> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || std::fs::File::open(path)?.sync_all())
        .await
        .map_err(|_| storage_error())?
        .map_err(|_| storage_error())
}
fn stage_name(name: &str) -> bool {
    name.strip_prefix(".bulk-stage-")
        .and_then(|rest| rest.split_once('-'))
        .is_some_and(|(pid, counter)| {
            !pid.is_empty()
                && !counter.is_empty()
                && pid.bytes().all(|v| v.is_ascii_digit())
                && counter.bytes().all(|v| v.is_ascii_digit())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires disposable PostgreSQL and RustFS; run scripts/test-s3.sh"]
    async fn s3_bulk_cold_cache_quota_and_active_reader_acceptance() {
        let base =
            std::env::var("DEVRES_TEST_DATABASE_URL").expect("disposable PostgreSQL required");
        let config_path =
            std::env::var("DEVRES_TEST_S3_CONFIG").expect("disposable S3 configuration required");
        let mut config: crate::object_storage::S3Config =
            toml::from_str(&std::fs::read_to_string(config_path).unwrap()).unwrap();
        config.prefix.push_str("/bulk-acceptance");
        let cache_limit = config.cache_max_bytes;
        let admin = sqlx_postgres::PgPool::connect(&base).await.unwrap();
        sqlx_core::query::query("CREATE DATABASE devres_s3_bulk_fixture")
            .execute(&admin)
            .await
            .unwrap();
        let mut database = url::Url::parse(&base).unwrap();
        database.set_path("/devres_s3_bulk_fixture");
        let root = tempfile::tempdir().unwrap();
        let store = crate::PgBlobStore::connect_archive(
            database.as_str(),
            root.path(),
            Some(config.clone()),
        )
        .await
        .unwrap();
        let first_root = root.path().join("first");
        let second_root = root.path().join("second");
        for directory in [&first_root, &second_root] {
            crate::integrity::ensure_directory(directory).await.unwrap();
        }
        let first = BulkArtifactStore::new(&first_root, 64 * 1024 * 1024)
            .unwrap()
            .with_quota(Some(256))
            .unwrap();
        let body = vec![37; 64];
        let artifact = first
            .capture_bytes(body.clone(), CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(first.accounted_bytes(), Some(64));
        // An evicted byte object remains retained and must not be charged again.
        std::fs::remove_file(first_root.join(&artifact.relative_path)).unwrap();
        assert_eq!(
            first
                .capture_bytes(body.clone(), CancellationToken::new())
                .await
                .unwrap(),
            artifact,
        );
        assert_eq!(first.accounted_bytes(), Some(64));
        let second = BulkArtifactStore::new(&second_root, 64 * 1024 * 1024)
            .unwrap()
            .with_shared_budget(&first)
            .unwrap();
        second
            .capture_bytes(body.clone(), CancellationToken::new())
            .await
            .unwrap();
        // Separate published files retain separate accounting identities even
        // when their remote content-addressed bytes are deduplicated.
        assert_eq!(first.accounted_bytes(), Some(128));
        let mut reader = first
            .open(&artifact.body_hash, 128, CancellationToken::new())
            .await
            .unwrap();
        assert!(
            crate::durable_archive::admit_write(
                &root.path().join(".bulk-stage-pin-fixture"),
                cache_limit,
            )
            .is_err()
        );
        assert!(first_root.join(&artifact.relative_path).exists());
        let mut observed = Vec::new();
        reader.read_to_end(&mut observed).await.unwrap();
        assert_eq!(observed, body);
        drop((reader, second, first, store));
        // Neither byte objects, descriptors nor private local state are required
        // to survive a restart in an object-backed deployment.
        std::fs::remove_dir_all(root.path()).unwrap();
        let store =
            crate::PgBlobStore::connect_archive(database.as_str(), root.path(), Some(config))
                .await
                .unwrap();
        let first = BulkArtifactStore::new(&first_root, 64 * 1024 * 1024)
            .unwrap()
            .with_quota(Some(256))
            .unwrap();
        let second = BulkArtifactStore::new(&second_root, 64 * 1024 * 1024)
            .unwrap()
            .with_shared_budget(&first)
            .unwrap();
        assert_eq!(second.accounted_bytes(), Some(128));
        let mut reader = second
            .open(&artifact.body_hash, 128, CancellationToken::new())
            .await
            .unwrap();
        let mut observed = Vec::new();
        reader.read_to_end(&mut observed).await.unwrap();
        assert_eq!(observed, body);
        store.check_health().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn npm_foreground_and_bulk_share_one_transfer_and_attempt_clock() {
        let broker = Arc::new(BulkBroker::new(BulkConfig::default()).unwrap());
        let first = broker.admit_foreground("registry.npmjs.org").await.unwrap();
        let other = broker.clone();
        let second = tokio::spawn(async move { other.admit("registry.npmjs.org", true).await });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(
            !second.is_finished(),
            "bulk bypassed the shared npm transfer permit"
        );
        assert_eq!(broker.attempt_count(), 1);
        drop(first);
        let permit = second.await.unwrap().unwrap();
        assert_eq!(broker.attempt_count(), 2);
        drop(permit);
        assert!(
            BulkBroker::new(BulkConfig::default())
                .unwrap()
                .with_npm_rates(0, 1)
                .is_err()
        );
    }
    use axum::{
        Router,
        body::Body,
        http::{HeaderValue, StatusCode},
        response::IntoResponse,
        routing::get,
    };
    async fn mock_broker(router: Router) -> (BulkBroker, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let broker =
            BulkBroker::fixture(url::Url::parse(&format!("http://{address}")).unwrap()).unwrap();
        (broker, task)
    }
    #[tokio::test]
    async fn legacy_dump_has_one_exact_redirect_and_one_shared_retry() {
        use std::sync::atomic::AtomicUsize;
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = calls.clone();
        let router = Router::new().route(
            "/db-dump.tar.gz",
            get(move || {
                let attempt = counted.fetch_add(1, Ordering::SeqCst);
                async move {
                    match attempt {
                        0 => (
                            StatusCode::TEMPORARY_REDIRECT,
                            [(
                                "location",
                                "https://cloudfront-static.crates.io/db-dump.tar.gz",
                            )],
                            "",
                        )
                            .into_response(),
                        1 => (StatusCode::SERVICE_UNAVAILABLE, [("retry-after", "0")], "")
                            .into_response(),
                        _ => "dump".into_response(),
                    }
                }
            }),
        );
        let (broker, task) = mock_broker(router).await;
        let mut input = request(100);
        input.source = BulkSource::LegacyDatabaseDump;
        let mut response = broker.open(input, CancellationToken::new()).await.unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(
            response.effective_url,
            BulkSource::DatabaseDump.url().unwrap()
        );
        assert_eq!(response.stream.next().await.unwrap().unwrap(), b"dump");
        assert_eq!(broker.attempt_count(), 3);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        task.abort();
    }

    #[tokio::test]
    async fn dump_redirect_policy_rejects_variations_and_second_hops() {
        for (source, location, status, expected_calls) in [
            (
                BulkSource::DatabaseDump,
                "https://cloudfront-static.crates.io/db-dump.tar.gz",
                StatusCode::TEMPORARY_REDIRECT,
                1,
            ),
            (
                BulkSource::LegacyDatabaseDump,
                "https://evil.example/db-dump.tar.gz",
                StatusCode::TEMPORARY_REDIRECT,
                1,
            ),
            (
                BulkSource::LegacyDatabaseDump,
                "https://cloudfront-static.crates.io/db-dump.tar.gz?other",
                StatusCode::TEMPORARY_REDIRECT,
                1,
            ),
            (
                BulkSource::LegacyDatabaseDump,
                "https://cloudfront-static.crates.io/db-dump.tar.gz",
                StatusCode::FOUND,
                1,
            ),
            (
                BulkSource::LegacyDatabaseDump,
                "https://cloudfront-static.crates.io/db-dump.tar.gz",
                StatusCode::TEMPORARY_REDIRECT,
                2,
            ),
        ] {
            let router = Router::new().route(
                "/db-dump.tar.gz",
                get(move || async move { (status, [("location", location)], "") }),
            );
            let (broker, task) = mock_broker(router).await;
            let mut input = request(100);
            input.source = source;
            let response = broker.open(input, CancellationToken::new()).await.unwrap();
            assert_eq!(response.status, status.as_u16());
            assert_eq!(broker.attempt_count(), expected_calls);
            task.abort();
        }
        assert_eq!(
            BulkSource::DatabaseDump.host(),
            BulkSource::LegacyDatabaseDump.host()
        );
        assert_eq!(BulkSource::DatabaseDump.host(), "static.crates.io");
    }
    fn request(max_bytes: u64) -> BulkRequest {
        BulkRequest {
            source: BulkSource::DatabaseDump,
            validators: Validators::default(),
            max_bytes,
            deadline: Instant::now() + Duration::from_secs(10),
            body: Vec::new(),
        }
    }
    #[test]
    fn constructed_destinations_are_exact_and_reject_untrusted_paths() {
        assert_eq!(
            BulkSource::RegistryGit(GitOperation::Advertisement)
                .url()
                .unwrap(),
            "https://github.com/rust-lang/crates.io-index.git/info/refs?service=git-upload-pack"
        );
        assert!(
            BulkSource::Documentation {
                name: "serde".into(),
                version: "1.0.0".into(),
                operation: DocsOperation::Json {
                    target: "../../evil".into(),
                    format: None
                }
            }
            .url()
            .is_err()
        );
        assert!(
            BulkSource::CrateArchive {
                name: "../serde".into(),
                version: "1.0.0".into()
            }
            .url()
            .is_err()
        );
        assert_eq!(
            BulkSource::CrateArchive {
                name: "Inflector".into(),
                version: "0.11.4".into()
            }
            .url()
            .unwrap(),
            "https://static.crates.io/crates/Inflector/Inflector-0.11.4.crate"
        );
        assert!(
            BulkSource::CrateArchive {
                name: "serde".into(),
                version: "latest".into()
            }
            .url()
            .is_err()
        );
        assert_eq!(
            BulkSource::Documentation {
                name: "serde".into(),
                version: "1.0.0".into(),
                operation: DocsOperation::Json {
                    target: "x86_64-unknown-linux-gnu".into(),
                    format: Some(61)
                }
            }
            .url()
            .unwrap(),
            "https://docs.rs/crate/serde/1.0.0/x86_64-unknown-linux-gnu/json/61.gz"
        );
    }
    #[tokio::test]
    async fn artifact_publication_is_immutable_hashed_and_cleans_failed_stages() {
        let root = tempfile::tempdir().unwrap();
        let store = BulkArtifactStore::new(root.path(), 64 * 1024 * 1024).unwrap();
        let artifact = store
            .capture_bytes(b"public evidence".to_vec(), CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(artifact.bytes, 15);
        assert_eq!(
            store
                .verify(&artifact.body_hash, 100, CancellationToken::new())
                .await
                .unwrap(),
            artifact
        );
        let response = BulkResponse {
            effective_url: "https://cloudfront-static.crates.io/db-dump.tar.gz".into(),
            status: 200,
            validators: Validators::default(),
            content_length: Some(3),
            next_page: None,
            retry_at: None,
            stream: Box::pin(futures::stream::iter([Ok(b"bad".to_vec())])),
        };
        assert!(
            store
                .capture(response, Some(&"a".repeat(64)), CancellationToken::new())
                .await
                .is_err()
        );
        let files: Vec<_> = std::fs::read_dir(root.path()).unwrap().collect();
        assert_eq!(files.len(), 2);
        crate::integrity::verify_legacy_file(
            &root.path().join(&artifact.relative_path),
            std::time::Instant::now() + Duration::from_secs(15),
        )
        .unwrap();
        tokio::fs::write(root.path().join(&artifact.relative_path), b"corrupt")
            .await
            .unwrap();
        assert!(
            store
                .verify(&artifact.body_hash, 100, CancellationToken::new())
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn migrated_hard_links_are_charged_once_across_roots_and_restart() {
        let root = tempfile::tempdir().unwrap();
        let first_root = root.path().join("first");
        let second_root = root.path().join("second");
        let third_root = root.path().join("third");
        for directory in [&first_root, &second_root, &third_root] {
            crate::integrity::ensure_directory(directory).await.unwrap();
        }
        let body = vec![17; 64];
        let first = BulkArtifactStore::new(&first_root, 64 * 1024 * 1024)
            .unwrap()
            .with_quota(Some(128))
            .unwrap();
        let artifact = first
            .capture_bytes(body.clone(), CancellationToken::new())
            .await
            .unwrap();
        let canonical = first_root.join(&artifact.relative_path);
        let legacy = first_root.join(crate::integrity::legacy_hash(&body));
        std::fs::hard_link(&canonical, &legacy).unwrap();
        let second_path = second_root.join(&artifact.relative_path);
        crate::integrity::ensure_directory(second_path.parent().unwrap())
            .await
            .unwrap();
        std::fs::hard_link(&canonical, &second_path).unwrap();
        let second = BulkArtifactStore::new(&second_root, 64 * 1024 * 1024)
            .unwrap()
            .with_shared_budget(&first)
            .unwrap();
        assert_eq!(second.accounted_bytes(), Some(64));
        let restarted = BulkArtifactStore::new(&first_root, 64 * 1024 * 1024)
            .unwrap()
            .with_quota(Some(128))
            .unwrap();
        let second = BulkArtifactStore::new(&second_root, 64 * 1024 * 1024)
            .unwrap()
            .with_shared_budget(&restarted)
            .unwrap();
        assert_eq!(second.accounted_bytes(), Some(64));
        // Equal bytes in a separate inode still consume storage and quota.
        std::fs::write(third_root.join(crate::integrity::legacy_hash(&body)), &body).unwrap();
        let third = BulkArtifactStore::new(&third_root, 64 * 1024 * 1024)
            .unwrap()
            .with_shared_budget(&restarted)
            .unwrap();
        assert_eq!(third.accounted_bytes(), Some(128));
        assert!(
            third
                .capture_bytes(vec![18; 1], CancellationToken::new())
                .await
                .is_err()
        );
        assert!(legacy.exists() && canonical.exists() && second_path.exists());
    }

    #[tokio::test]
    async fn streaming_blake3_storage_keeps_registry_sha256_and_legacy_verification_separate() {
        let root = tempfile::tempdir().unwrap();
        let store = BulkArtifactStore::new(root.path(), 64 * 1024 * 1024).unwrap();
        let body = vec![29; 3 * CHUNK_BYTES + 19];
        let sha = crate::integrity::legacy_hash(&body);
        let chunks: Vec<_> = body
            .chunks(CHUNK_BYTES)
            .map(|chunk| Ok(chunk.to_vec()))
            .collect();
        let response = BulkResponse {
            effective_url: "https://cloudfront-static.crates.io/db-dump.tar.gz".into(),
            status: 200,
            validators: Validators::default(),
            content_length: Some(body.len() as u64),
            next_page: None,
            retry_at: None,
            stream: Box::pin(futures::stream::iter(chunks)),
        };
        let artifact = store
            .capture(response, Some(&sha), CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(artifact.body_hash, crate::integrity::hash(&body));
        assert!(artifact.relative_path.starts_with("blake3/"));
        let legacy = root.path().join(&sha);
        std::fs::hard_link(root.path().join(&artifact.relative_path), &legacy).unwrap();
        assert!(
            store
                .verify(&sha, body.len() as u64, CancellationToken::new())
                .await
                .is_err()
        );
        let evidence = crate::integrity::FileEvidence {
            version: 1,
            path: sha.clone(),
            bytes: body.len() as u64,
            digest: artifact.body_hash.clone(),
        };
        let descriptor = crate::integrity::evidence_path(root.path(), &legacy).unwrap();
        crate::integrity::ensure_directory(descriptor.parent().unwrap())
            .await
            .unwrap();
        std::fs::write(&descriptor, serde_json::to_vec(&evidence).unwrap()).unwrap();
        assert_eq!(
            store
                .verify(&sha, body.len() as u64, CancellationToken::new())
                .await
                .unwrap()
                .bytes,
            body.len() as u64
        );
        let wrong = crate::integrity::FileEvidence {
            digest: crate::integrity::hash(b"different"),
            ..evidence
        };
        std::fs::write(&descriptor, serde_json::to_vec(&wrong).unwrap()).unwrap();
        assert!(
            store
                .verify(&sha, body.len() as u64, CancellationToken::new())
                .await
                .is_err()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn foreground_and_background_share_one_provider_clock() {
        let broker = BulkBroker::new(BulkConfig::default()).unwrap();
        let before = Instant::now();
        drop(broker.admit_foreground("crates.io").await.unwrap());
        drop(broker.admit("crates.io", true).await.unwrap());
        assert!(Instant::now().duration_since(before) >= Duration::from_secs(1));
        assert!(broker.admit_foreground("untrusted.invalid").await.is_err());
    }
    #[tokio::test(start_paused = true)]
    async fn configurable_index_rates_do_not_raise_api_or_docs_rates() {
        let config = BulkConfig {
            index_requests_per_second: 5,
            ..Default::default()
        };
        let broker = BulkBroker::new(config).unwrap();
        for host in ["index.crates.io", "github.com"] {
            let before = Instant::now();
            drop(broker.admit_foreground(host).await.unwrap());
            drop(broker.admit(host, true).await.unwrap());
            assert_eq!(
                Instant::now().duration_since(before),
                Duration::from_millis(200)
            );
        }
        for host in ["crates.io", "docs.rs"] {
            let before = Instant::now();
            drop(broker.admit_foreground(host).await.unwrap());
            drop(broker.admit(host, true).await.unwrap());
            assert_eq!(
                Instant::now().duration_since(before),
                Duration::from_secs(1)
            );
        }
    }
    #[tokio::test]
    async fn cancellation_discards_owned_stage_and_never_removes_history() {
        let root = tempfile::tempdir().unwrap();
        let store = BulkArtifactStore::new(root.path(), 64 * 1024 * 1024).unwrap();
        let token = CancellationToken::new();
        token.cancel();
        assert!(store.capture_bytes(vec![1; 10], token).await.is_err());
        tokio::fs::write(root.path().join(".bulk-stage-1-1"), b"stage")
            .await
            .unwrap();
        tokio::fs::write(root.path().join(".bulk-stage-unknown"), b"other")
            .await
            .unwrap();
        tokio::fs::write(root.path().join("a".repeat(64)), b"retained")
            .await
            .unwrap();
        store.recover_stages().await.unwrap();
        assert!(!root.path().join(".bulk-stage-1-1").exists());
        assert!(root.path().join(".bulk-stage-unknown").exists());
        assert!(root.path().join("a".repeat(64)).exists());
    }
    #[tokio::test]
    async fn transfer_streams_fixed_chunks_and_preserves_validators() {
        let length = 3 * CHUNK_BYTES + 19;
        let router = Router::new().route(
            "/db-dump.tar.gz",
            get(move || async move {
                let mut response = vec![7_u8; length].into_response();
                response.headers_mut().insert(
                    reqwest::header::ETAG,
                    HeaderValue::from_static("\"fixture\""),
                );
                response
            }),
        );
        let (broker, task) = mock_broker(router).await;
        let mut response = broker
            .open(request(length as u64), CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(response.validators.etag.as_deref(), Some("\"fixture\""));
        let mut observed = 0;
        while let Some(chunk) = response.stream.next().await {
            let chunk = chunk.unwrap();
            assert!(chunk.len() <= CHUNK_BYTES);
            assert!(chunk.iter().all(|byte| *byte == 7));
            observed += chunk.len();
        }
        assert_eq!(observed, length);
        assert_eq!(broker.bulk_slots.available_permits(), 4);
        task.abort();
    }
    #[tokio::test]
    async fn transient_status_has_one_retry_but_absence_and_redirect_do_not() {
        let calls = Arc::new(AtomicU64::new(0));
        let counted = calls.clone();
        let router = Router::new().route(
            "/db-dump.tar.gz",
            get(move || {
                let counted = counted.clone();
                async move {
                    if counted.fetch_add(1, Ordering::SeqCst) == 0 {
                        (
                            StatusCode::SERVICE_UNAVAILABLE,
                            [(reqwest::header::RETRY_AFTER, "0")],
                            "retry",
                        )
                            .into_response()
                    } else {
                        b"fixture".to_vec().into_response()
                    }
                }
            }),
        );
        let (broker, task) = mock_broker(router).await;
        let mut response = broker
            .open(request(100), CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(response.stream.next().await.unwrap().unwrap(), b"fixture");
        task.abort();
        for status in [
            StatusCode::NOT_FOUND,
            StatusCode::NOT_MODIFIED,
            StatusCode::FOUND,
        ] {
            let calls = Arc::new(AtomicU64::new(0));
            let counted = calls.clone();
            let router = Router::new().route(
                "/db-dump.tar.gz",
                get(move || {
                    let counted = counted.clone();
                    async move {
                        counted.fetch_add(1, Ordering::SeqCst);
                        (
                            status,
                            [(reqwest::header::LOCATION, "https://untrusted.invalid/")],
                        )
                    }
                }),
            );
            let (broker, task) = mock_broker(router).await;
            let mut response = broker
                .open(request(100), CancellationToken::new())
                .await
                .unwrap();
            assert_eq!(response.status, status.as_u16());
            assert!(response.stream.next().await.is_none());
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            task.abort();
        }
    }
    #[tokio::test]
    async fn canceled_stream_releases_transfer_admission() {
        let router = Router::new().route(
            "/db-dump.tar.gz",
            get(|| async {
                let first =
                    futures::stream::once(async { Ok::<_, std::io::Error>(vec![1_u8; 10]) });
                Body::from_stream(first.chain(futures::stream::pending()))
            }),
        );
        let (broker, task) = mock_broker(router).await;
        let shutdown = CancellationToken::new();
        let mut response = broker.open(request(100), shutdown.clone()).await.unwrap();
        assert_eq!(response.stream.next().await.unwrap().unwrap(), vec![1; 10]);
        shutdown.cancel();
        assert!(response.stream.next().await.unwrap().is_err());
        assert_eq!(broker.bulk_slots.available_permits(), 4);
        task.abort();
    }
    #[tokio::test]
    async fn quota_reservations_are_concurrent_rollback_safe_and_deduplicated() {
        let root = tempfile::tempdir().unwrap();
        let store = BulkArtifactStore::new(root.path(), 64 * 1024 * 1024)
            .unwrap()
            .with_quota(Some(100))
            .unwrap();
        let (first, second) = tokio::join!(
            store.capture_bytes(vec![1; 64], CancellationToken::new()),
            store.capture_bytes(vec![2; 64], CancellationToken::new())
        );
        assert_ne!(first.is_ok(), second.is_ok());
        assert_eq!(store.accounted_bytes(), Some(64));
        let value = if first.is_ok() { 1 } else { 2 };
        let store = BulkArtifactStore::new(root.path(), 64 * 1024 * 1024)
            .unwrap()
            .with_quota(Some(200))
            .unwrap();
        store
            .capture_bytes(vec![value; 64], CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(store.accounted_bytes(), Some(64));
        let reservation = store.reserve_bytes(100).unwrap();
        assert_eq!(store.accounted_bytes(), Some(164));
        drop(reservation);
        assert_eq!(store.accounted_bytes(), Some(64));
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 2);
    }
    #[tokio::test]
    async fn shared_quota_counts_three_roots_once_and_recovers_after_restart() {
        let first_root = tempfile::tempdir().unwrap();
        let second_root = tempfile::tempdir().unwrap();
        let third_root = tempfile::tempdir().unwrap();
        let first = BulkArtifactStore::new(first_root.path(), 64 * 1024 * 1024)
            .unwrap()
            .with_quota(Some(128))
            .unwrap();
        let second = BulkArtifactStore::new(second_root.path(), 64 * 1024 * 1024)
            .unwrap()
            .with_shared_budget(&first)
            .unwrap();
        let third = BulkArtifactStore::new(third_root.path(), 64 * 1024 * 1024)
            .unwrap()
            .with_shared_budget(&first)
            .unwrap();
        for (store, byte) in [(&first, 1), (&second, 2), (&third, 3)] {
            store
                .capture_bytes(vec![byte; 32], CancellationToken::new())
                .await
                .unwrap();
        }
        assert_eq!(first.accounted_bytes(), Some(96));
        assert_eq!(second.accounted_bytes(), Some(96));
        assert_eq!(third.accounted_bytes(), Some(96));
        assert!(
            second
                .capture_bytes(vec![4; 64], CancellationToken::new())
                .await
                .is_err()
        );
        third
            .capture_bytes(vec![3; 32], CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(first.accounted_bytes(), Some(96));
        drop((first, second, third));
        let first = BulkArtifactStore::new(first_root.path(), 64 * 1024 * 1024)
            .unwrap()
            .with_quota(Some(128))
            .unwrap();
        let second = BulkArtifactStore::new(second_root.path(), 64 * 1024 * 1024)
            .unwrap()
            .with_shared_budget(&first)
            .unwrap();
        let third = BulkArtifactStore::new(third_root.path(), 64 * 1024 * 1024)
            .unwrap()
            .with_shared_budget(&first)
            .unwrap();
        let duplicate = BulkArtifactStore::new(second_root.path(), 64 * 1024 * 1024)
            .unwrap()
            .with_shared_budget(&third)
            .unwrap();
        assert_eq!(duplicate.accounted_bytes(), Some(96));
        assert_eq!(second.accounted_bytes(), Some(96));
        let held = third.reserve_bytes(32).unwrap();
        assert!(first.reserve_bytes(1).is_err());
        drop(held);
        assert_eq!(first.accounted_bytes(), Some(96));
    }
    #[tokio::test]
    async fn canceled_link_waiter_cannot_uncharge_a_new_permanent_object() {
        let root = tempfile::tempdir().unwrap();
        let store = Arc::new(
            BulkArtifactStore::new(root.path(), 64 * 1024 * 1024)
                .unwrap()
                .with_quota(Some(100))
                .unwrap(),
        );
        let stage = root.path().join(".bulk-stage-fixture");
        let destination = root.path().join("a".repeat(64));
        std::fs::write(&stage, vec![1; 64]).unwrap();
        let reservation = store.reserve_bytes(64).unwrap();
        let (started_send, started_receive) = tokio::sync::oneshot::channel();
        let (release_send, release_receive) = std::sync::mpsc::channel();
        let (done_send, done_receive) = tokio::sync::oneshot::channel();
        let destination_copy = destination.clone();
        let waiter = tokio::spawn(async move {
            tokio::task::spawn_blocking(move || {
                let result = retain_link(stage, destination_copy, reservation);
                let _ = started_send.send(());
                let _ = release_receive.recv();
                let _ = done_send.send(());
                result
            })
            .await
        });
        started_receive.await.unwrap();
        assert!(destination.exists());
        waiter.abort();
        let _ = waiter.await;
        assert_eq!(store.accounted_bytes(), Some(64));
        release_send.send(()).unwrap();
        done_receive.await.unwrap();
        assert_eq!(store.accounted_bytes(), Some(64));
    }
    #[test]
    fn mdn_git_destinations_and_wire_types_are_fixed() {
        for (source, url, media) in [
            (
                BulkSource::MdnContentGit(GitOperation::Advertisement),
                "https://github.com/mdn/content.git/info/refs?service=git-upload-pack",
                "application/x-git-upload-pack-advertisement",
            ),
            (
                BulkSource::MdnContentGit(GitOperation::UploadPack),
                "https://github.com/mdn/content.git/git-upload-pack",
                "application/x-git-upload-pack-result",
            ),
            (
                BulkSource::MdnCompatGit(GitOperation::Advertisement),
                "https://github.com/mdn/browser-compat-data.git/info/refs?service=git-upload-pack",
                "application/x-git-upload-pack-advertisement",
            ),
            (
                BulkSource::MdnCompatGit(GitOperation::UploadPack),
                "https://github.com/mdn/browser-compat-data.git/git-upload-pack",
                "application/x-git-upload-pack-result",
            ),
        ] {
            assert_eq!(source.url().unwrap(), url);
            assert_eq!(source.host(), "github.com");
            assert_eq!(source.media_type(), media);
        }
    }
    #[tokio::test(start_paused = true)]
    async fn rustsec_git_reserves_one_second_even_when_registry_rate_is_raised() {
        let broker = BulkBroker::new(BulkConfig {
            index_requests_per_second: 1000,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            BulkSource::RustSecGit(GitOperation::Advertisement)
                .url()
                .unwrap(),
            "https://github.com/rustsec/advisory-db.git/info/refs?service=git-upload-pack"
        );
        assert_eq!(
            BulkSource::RustSecGit(GitOperation::UploadPack)
                .url()
                .unwrap(),
            "https://github.com/rustsec/advisory-db.git/git-upload-pack"
        );
        let started = Instant::now();
        let _rustsec = broker
            .admit_rate("github.com", true, Some(1))
            .await
            .unwrap();
        let _registry = broker.admit_foreground("github.com").await.unwrap();
        assert!(Instant::now().duration_since(started) >= Duration::from_secs(1));
        let _second = broker
            .admit_rate("github.com", true, Some(1))
            .await
            .unwrap();
        let next = broker.rates.lock().await["github.com"];
        assert!(next.duration_since(Instant::now()) >= Duration::from_secs(1));
    }
    #[tokio::test(start_paused = true)]
    async fn explicit_attempt_budget_is_shared_by_foreground_and_bulk() {
        let broker = BulkBroker::new(BulkConfig::default())
            .unwrap()
            .with_attempt_budget(2)
            .unwrap();
        let _foreground = broker.admit_foreground("api.github.com").await.unwrap();
        let _bulk = broker
            .admit_rate("github.com", true, Some(1))
            .await
            .unwrap();
        assert_eq!(broker.attempt_count(), 2);
        assert_eq!(
            broker
                .admit_foreground("codeload.github.com")
                .await
                .err()
                .unwrap()
                .code,
            "capacity"
        );
        assert_eq!(broker.attempt_count(), 2);
    }
}

#[cfg(test)]
mod whatwg_policy_tests {
    use super::*;
    #[tokio::test(start_paused = true)]
    async fn whatwg_publication_hosts_share_one_attempt_per_second() {
        let broker = BulkBroker::new(BulkConfig::default()).expect("broker");
        let started = Instant::now();
        drop(
            broker
                .admit_rate("dom.spec.whatwg.org", true, Some(100))
                .await
                .expect("DOM"),
        );
        drop(
            broker
                .admit_rate("html.spec.whatwg.org", true, Some(100))
                .await
                .expect("HTML"),
        );
        assert!(Instant::now().duration_since(started) >= Duration::from_secs(1));
        drop(
            broker
                .admit_rate("w3c-cg.github.io", true, Some(100))
                .await
                .expect("predecessor"),
        );
        assert!(Instant::now().duration_since(started) >= Duration::from_secs(2));
    }
    #[tokio::test]
    async fn large_normalized_projection_has_an_explicit_archive_limit() {
        let root = tempfile::tempdir().expect("owned artifacts");
        let artifacts = BulkArtifactStore::new(root.path(), 64 * 1024 * 1024).expect("artifacts");
        let bytes = vec![b'a'; 17 * 1024 * 1024];
        assert_eq!(
            artifacts
                .capture_bytes(bytes.clone(), CancellationToken::new())
                .await
                .expect_err("old admission remains bounded")
                .code,
            "capacity"
        );
        let artifact = artifacts
            .capture_bytes_bounded(bytes, 32 * 1024 * 1024, CancellationToken::new())
            .await
            .expect("explicit normalized admission");
        assert_eq!(artifact.bytes, 17 * 1024 * 1024);
        artifacts
            .verify(
                &artifact.body_hash,
                32 * 1024 * 1024,
                CancellationToken::new(),
            )
            .await
            .expect("verified retained projection");
    }
}

#[cfg(test)]
mod w3c_policy_tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn w3c_family_and_github_host_clock_are_both_reserved() {
        let broker = BulkBroker::new(BulkConfig::default()).expect("broker");
        let start = Instant::now();
        let api = broker
            .admit_rate_inner("api.w3.org", true, Some(1), true, false)
            .await
            .expect("API permit");
        drop(api);
        let publication = broker
            .admit_rate_inner("www.w3.org", true, Some(1), true, false)
            .await
            .expect("publication permit");
        drop(publication);
        let git = broker
            .admit_rate_inner("github.com", true, Some(1), true, false)
            .await
            .expect("Git permit");
        drop(git);
        assert!(Instant::now().duration_since(start) >= Duration::from_secs(2));
        let legacy = broker
            .admit_foreground("github.com")
            .await
            .expect("shared host permit");
        drop(legacy);
        assert!(Instant::now().duration_since(start) >= Duration::from_secs(3));
        // Qualifying a W3C source never expands legacy foreground host admission.
        assert!(broker.admit_foreground("drafts.csswg.org").await.is_err());
    }

    #[tokio::test]
    async fn w3c_uses_validated_typed_paths_and_cannot_supply_post_bodies() {
        use crate::w3c::catalog::ApiOperation;
        let source = BulkSource::W3cApi(ApiOperation::Specification {
            shortname: "css-color-4".into(),
        });
        assert_eq!(
            source.url().expect("typed URL"),
            "https://api.w3.org/specifications/css-color-4"
        );
        assert!(
            BulkSource::W3cApi(ApiOperation::Specification {
                shortname: "../private".into()
            })
            .url()
            .is_err()
        );
        let broker = BulkBroker::new(BulkConfig::default()).expect("broker");
        let result = broker
            .open(
                BulkRequest {
                    source,
                    validators: Validators::default(),
                    max_bytes: 1024,
                    deadline: Instant::now() + Duration::from_secs(1),
                    body: b"not Git".to_vec(),
                },
                CancellationToken::new(),
            )
            .await;
        assert_eq!(
            result.err().expect("body rejected before I/O").code,
            "invalid_input"
        );
        assert_eq!(broker.attempt_count(), 0);
    }
}

#[cfg(test)]
#[path = "bulk_verification_tests.rs"]
mod verification_tests;

#[cfg(test)]
mod html_policy_tests {
    use super::*;
    use crate::{
        attribution_providers::AttributionSource,
        chromium::source::Operation,
        w3c::{catalog::PublicationUrl, discovery::DiscoveryOperation},
    };
    use axum::{Router, response::IntoResponse, routing::get};

    fn request(source: BulkSource, max_bytes: u64) -> BulkRequest {
        BulkRequest {
            source,
            validators: Validators::default(),
            max_bytes,
            deadline: Instant::now() + Duration::from_secs(10),
            body: Vec::new(),
        }
    }
    fn html() -> BulkSource {
        BulkSource::Attribution(AttributionSource::Rfc {
            number: 9000,
            format: "html".into(),
        })
    }
    async fn fixture(router: Router) -> (BulkBroker, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let broker = BulkBroker::fixture(
            format!("http://{}/", listener.local_addr().unwrap())
                .parse()
                .unwrap(),
        )
        .unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (broker, task)
    }
    #[test]
    fn selection_is_typed_and_keeps_unrelated_html_unchanged() {
        for source in [
            BulkSource::W3cPublication(
                PublicationUrl::new("https://www.w3.org/TR/css-color-4/").unwrap(),
            ),
            BulkSource::W3cDiscovery(DiscoveryOperation::TrIndex),
            BulkSource::Chromium(Operation::Page {
                path: "docs/devtools/overview".into(),
            }),
            BulkSource::Chromium(Operation::SitePage {
                path: "Home".into(),
            }),
            html(),
        ] {
            assert!(source.html_transport().is_some());
        }
        for source in [
            BulkSource::W3cPublication(
                PublicationUrl::new("https://www.w3.org/TR/css-color-4/index.xml").unwrap(),
            ),
            BulkSource::W3cDiscovery(DiscoveryOperation::BrowserSpecs),
            BulkSource::Chromium(Operation::Sitemap {
                path: "sitemap.xml".into(),
            }),
            BulkSource::Attribution(AttributionSource::Rfc {
                number: 9000,
                format: "txt".into(),
            }),
            BulkSource::Documentation {
                name: "serde".into(),
                version: "1.0.0".into(),
                operation: DocsOperation::Builds,
            },
        ] {
            assert!(source.html_transport().is_none());
        }
    }
    #[tokio::test]
    async fn selected_html_retry_and_comparison_share_accounting() {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let router = Router::new().route(
            "/rfc/rfc9000.html",
            get(move |headers: http::HeaderMap| {
                let seen = seen.clone();
                async move {
                    assert_eq!(headers["accept"], "text/html");
                    if seen.fetch_add(1, Ordering::SeqCst) == 0 {
                        (
                            http::StatusCode::SERVICE_UNAVAILABLE,
                            [("retry-after", "0")],
                            "retry",
                        )
                            .into_response()
                    } else {
                        ([("etag", "\"html\"")], "<html>original</html>").into_response()
                    }
                }
            }),
        );
        let (broker, task) = fixture(router).await;
        let broker = broker.with_attempt_budget(3).unwrap();
        for legacy in [false, true] {
            let result = if legacy {
                broker
                    .open_legacy_html_probe(request(html(), 1024), CancellationToken::new())
                    .await
            } else {
                broker
                    .open(request(html(), 1024), CancellationToken::new())
                    .await
            };
            let mut response = result.unwrap();
            assert_eq!(response.status, 200);
            assert_eq!(response.validators.etag.as_deref(), Some("\"html\""));
            let mut body = Vec::new();
            while let Some(chunk) = response.stream.next().await {
                body.extend(chunk.unwrap());
            }
            assert_eq!(body, b"<html>original</html>");
        }
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert_eq!(broker.attempt_count(), 3);
        assert!(
            broker
                .open(request(html(), 1024), CancellationToken::new())
                .await
                .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        task.abort();
    }
    #[tokio::test]
    async fn selected_html_stream_holds_and_releases_permits_and_enforces_limits() {
        let router = Router::new().route(
            "/rfc/rfc9000.html",
            get(|| async { vec![b'x'; CHUNK_BYTES + 1] }),
        );
        let (broker, task) = fixture(router).await;
        let response = broker
            .open(request(html(), 1), CancellationToken::new())
            .await;
        assert_eq!(response.err().unwrap().code, "capacity");
        assert_eq!(broker.bulk_slots.available_permits(), 4);
        let cancel = CancellationToken::new();
        let mut response = broker
            .open(request(html(), (CHUNK_BYTES + 1) as u64), cancel.clone())
            .await
            .unwrap();
        assert_eq!(broker.bulk_slots.available_permits(), 3);
        cancel.cancel();
        assert!(response.stream.next().await.unwrap().is_err());
        drop(response);
        assert_eq!(broker.bulk_slots.available_permits(), 4);
        task.abort();
    }
    #[tokio::test]
    async fn legacy_comparison_rejects_other_sources_without_admission() {
        let broker = BulkBroker::new(BulkConfig::default()).unwrap();
        let response = broker
            .open_legacy_html_probe(
                request(BulkSource::DatabaseDump, 1),
                CancellationToken::new(),
            )
            .await;
        assert_eq!(response.err().unwrap().code, "invalid_input");
        assert_eq!(broker.attempt_count(), 0);
    }
}
