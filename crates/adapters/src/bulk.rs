//! Private fixed-source streaming I/O. Public capture reads retain their smaller limits.
use devres_domain::{Error, Result, Validators};
use futures::{Stream, StreamExt, TryStreamExt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
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
    DatabaseDump,
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
        repository: crate::whatwg_git::Repo,
        operation: GitOperation,
    },
    WhatwgPublication(crate::whatwg_catalog::PublicationUrl),
    W3cGit {
        repository: crate::w3c_git::Repo,
        operation: GitOperation,
    },
    W3cPublication(crate::w3c_catalog::PublicationUrl),
    W3cApi(crate::w3c_catalog::ApiOperation),
    W3cDiscovery(crate::w3c_discovery::DiscoveryOperation),
}
impl BulkSource {
    pub fn url(&self) -> Result<String> {
        match self {
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
                crate::whatwg_git::Repo::new(&repository.as_str())?;
                let suffix=match operation { GitOperation::Advertisement=>"info/refs?service=git-upload-pack",GitOperation::UploadPack=>"git-upload-pack" };
                Ok(format!("{}/{suffix}",repository.source_url()))
            }
            Self::WhatwgPublication(source) => {source.validate()?; Ok(source.as_str().to_owned())},
            Self::DatabaseDump => Ok("https://static.crates.io/db-dump.tar.gz".into()),
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
            Self::W3cGit { repository, .. } => repository.host(),
            Self::W3cPublication(source) => source.host(),
            Self::W3cApi(_) => "api.w3.org",
            Self::W3cDiscovery(operation) => operation.host(),
            Self::WhatwgPublication(source) => source.host(),
            Self::WhatwgGit { .. } => "github.com",
            Self::DatabaseDump | Self::CrateArchive { .. } => "static.crates.io",
            Self::Documentation { .. } => "docs.rs",
            Self::RegistryGit(_)
            | Self::RustSecGit(_)
            | Self::MdnContentGit(_)
            | Self::MdnCompatGit(_) => "github.com",
        }
    }
    fn media_type(&self) -> &'static str {
        match self {
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
    crate::cargo::validate_name(name)?;
    crate::cargo::validate_version(version)?;
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
        host if crate::whatwg_catalog::publication_host(host) => Ok(host),
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
    pub status: u16,
    pub validators: Validators,
    pub content_length: Option<u64>,
    pub stream: BulkStream,
}
pub struct AttemptPermit {
    _transfer: OwnedSemaphorePermit,
    _documentation: Option<OwnedSemaphorePermit>,
}

pub struct BulkBroker {
    client: reqwest::Client,
    w3c_client: reqwest::Client,
    config: BulkConfig,
    rates: Mutex<HashMap<String, Instant>>,
    bulk_slots: Arc<Semaphore>,
    foreground_slots: Arc<Semaphore>,
    documentation_slots: Arc<Semaphore>,
    attempt_budget: Option<usize>,
    attempts: AtomicUsize,
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
            .build()
            .map_err(|_| Error::unavailable("Fixture HTTP initialization failed."))?;
        broker.test_origin = Some(origin);
        broker.w3c_client = broker.client.clone();
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
            .connect_timeout(Duration::from_secs(10))
            .user_agent(
                "dev-resources-MCP/0.0.0 (+https://github.com/PublicData-stream/dev-resources-MCP)",
            )
            .build()
            .map_err(|_| Error::unavailable("Bulk HTTP initialization failed."))?;
        Ok(Self {
            client,
            w3c_client: crate::w3c_network::client()?,
            bulk_slots: Arc::new(Semaphore::new(config.max_transfers)),
            foreground_slots: Arc::new(Semaphore::new(2)),
            documentation_slots: Arc::new(Semaphore::new(1)),
            rates: Mutex::new(HashMap::new()),
            config,
            attempt_budget: None,
            attempts: AtomicUsize::new(0),
            attempt_observer: None,
            #[cfg(test)]
            test_origin: None,
        })
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
        self.admit_rate_inner(host, bulk, forced_rate, false).await
    }

    async fn admit_rate_inner(
        &self,
        host: &str,
        bulk: bool,
        forced_rate: Option<u32>,
        w3c: bool,
    ) -> Result<AttemptPermit> {
        // W3C hosts reach this branch only after typed destination validation in open().
        let host = if w3c { host } else { admitted_host(host)? };
        let documentation = if host == "docs.rs" {
            Some(
                self.documentation_slots
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
            let whatwg = crate::whatwg_catalog::publication_host(host);
            let clock = if whatwg { "whatwg-publications" } else { host };
            let mut scheduled = rates.get(clock).copied().unwrap_or(now).max(now);
            if w3c {
                scheduled = scheduled.max(rates.get("w3c-acquisition").copied().unwrap_or(now));
                rates.insert("w3c-acquisition".into(), scheduled + Duration::from_secs(1));
            }
            let per_second = if whatwg {
                1
            } else {
                forced_rate.unwrap_or(match host {
                    "static.crates.io" => self.config.static_requests_per_second,
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
            .map_err(|_| Error::capacity("Source attempt budget exhausted."))?;
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
        let url = request.source.url()?;
        let w3c = matches!(
            request.source,
            BulkSource::W3cGit { .. }
                | BulkSource::W3cPublication(_)
                | BulkSource::W3cApi(_)
                | BulkSource::W3cDiscovery(_)
        );
        #[cfg(test)]
        let url = if let Some(origin) = &self.test_origin {
            let original =
                url::Url::parse(&url).map_err(|_| Error::invalid("Invalid test source."))?;
            let mut destination = origin.clone();
            destination.set_path(original.path());
            destination.set_query(original.query());
            destination.to_string()
        } else {
            url
        };
        for attempt in 0..=1 {
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
                ),
            )
            .await?;
            let client = if w3c { &self.w3c_client } else { &self.client };
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
                builder
                    .send()
                    .await
                    .map_err(|_| Error::unavailable("Bulk source connection failed."))
            })
            .await?;
            let status = response.status().as_u16();
            if attempt == 0 && matches!(status, 429 | 500 | 502 | 503 | 504) {
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
            if status != 200 {
                drop(response);
                drop(permit);
                return Ok(BulkResponse {
                    status,
                    validators,
                    content_length,
                    stream: Box::pin(futures::stream::empty()),
                });
            }
            if content_length.is_some_and(|length| length > request.max_bytes) {
                return Err(Error::capacity("Bulk source exceeds its byte budget."));
            }
            let input = response
                .bytes_stream()
                .map_err(|_| std::io::Error::other("Bulk source transfer failed."));
            let reader = StreamReader::new(input);
            let state = StreamState {
                reader: Box::pin(reader),
                _permit: permit,
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
                    .ok_or_else(|| Error::capacity("Bulk source exceeds its byte budget."))?;
                chunk.truncate(read);
                Ok(Some((chunk, state)))
            });
            return Ok(BulkResponse {
                status,
                validators,
                content_length,
                stream: Box::pin(stream),
            });
        }
        Err(Error::unavailable("Bulk source unavailable."))
    }
}
type ByteReader = Pin<Box<dyn tokio::io::AsyncRead + Send>>;
struct StreamState {
    reader: ByteReader,
    _permit: AttemptPermit,
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
        result = tokio::time::timeout_at(deadline, future) => result.map_err(|_| Error::capacity("Bulk operation deadline exceeded."))?,
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
pub struct BulkArtifactStore {
    root: PathBuf,
    min_free_bytes: u64,
    quota: Option<Quota>,
}
#[derive(Clone)]
struct Quota {
    used: Arc<AtomicU64>,
    limit: u64,
    roots: Arc<std::sync::Mutex<std::collections::BTreeSet<PathBuf>>>,
}
pub struct ArtifactReservation {
    used: Option<Arc<AtomicU64>>,
    bytes: u64,
    retained: bool,
}
impl ArtifactReservation {
    fn reserve(&mut self, bytes: u64, limit: u64) -> Result<()> {
        if let Some(used) = &self.used {
            used.try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(bytes).filter(|next| *next <= limit)
            })
            .map_err(|_| Error::capacity("Bulk archive quota exhausted; history is preserved."))?;
            self.bytes += bytes;
        }
        Ok(())
    }
    /// Call immediately after creating a new immutable hash-named object, even if
    /// later directory fsync or database publication fails.
    pub fn retain(mut self) {
        self.retained = true;
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
    }
}
pub(crate) fn valid_hash(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
}
impl BulkArtifactStore {
    /// The caller must already hold the database's exclusive storage fence.
    pub fn new(root: impl AsRef<Path>, min_free_bytes: u64) -> Result<Self> {
        if min_free_bytes < 64 * 1024 * 1024 {
            return Err(Error::invalid("Invalid bulk storage headroom."));
        }
        let metadata = std::fs::symlink_metadata(root.as_ref()).map_err(|_| storage_error())?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(Error::integrity("Invalid bulk archive directory."));
        }
        Ok(Self {
            root: std::fs::canonicalize(root).map_err(|_| storage_error())?,
            min_free_bytes,
            quota: None,
        })
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
    /// Counts existing hash-named immutable objects; concurrent bulk stages reserve
    /// quota before writes. Ordinary publishers must share this store's accounting.
    pub fn with_quota(mut self, max_bytes: Option<u64>) -> Result<Self> {
        let Some(limit) = max_bytes else {
            self.quota = None;
            return Ok(self);
        };
        if limit == 0 {
            return Err(Error::invalid("Artifact quota must be positive."));
        }
        let used = retained_bytes(&self.root)?;
        self.quota = Some(Quota {
            used: Arc::new(AtomicU64::new(used)),
            limit,
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
        let Some(quota) = &other.quota else {
            self.quota = None;
            return Ok(self);
        };
        {
            let mut roots = quota.roots.lock().map_err(|_| storage_error())?;
            if !roots.contains(&self.root) {
                let bytes = retained_bytes(&self.root)?;
                quota
                    .used
                    .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                        used.checked_add(bytes)
                    })
                    .map_err(|_| Error::capacity("Artifact quota accounting overflow."))?;
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
        let mut reservation = ArtifactReservation {
            used: self.quota.as_ref().map(|quota| quota.used.clone()),
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
            return Err(Error::capacity(
                "In-memory artifact exceeds its byte budget.",
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
        if expected_hash.is_some_and(|hash| !valid_hash(hash)) {
            return Err(Error::invalid("Invalid expected artifact checksum."));
        }
        let path = self.root.join(format!(
            ".bulk-stage-{}-{}",
            std::process::id(),
            STAGE.fetch_add(1, Ordering::Relaxed)
        ));
        let stage = Stage(path.clone());
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .await
            .map_err(|_| storage_error())?;
        let mut hash = Sha256::new();
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
                .ok_or_else(|| Error::capacity("Artifact exceeds byte budget."))?;
            if fs2::available_space(&self.root).map_err(|_| storage_error())?
                < self.min_free_bytes.saturating_add(chunk.len() as u64)
            {
                return Err(Error::capacity(
                    "Insufficient archive space; history is preserved.",
                ));
            }
            reservation.reserve(
                chunk.len() as u64,
                self.quota.as_ref().map_or(u64::MAX, |quota| quota.limit),
            )?;
            tokio::select! { biased; _ = shutdown.cancelled() => return Err(Error::unavailable("Bulk artifact publication canceled.")), result = file.write_all(&chunk) => result.map_err(|_| storage_error())? }
            hash.update(&chunk);
        }
        let body_hash = hex::encode(hash.finalize());
        if expected_hash.is_some_and(|expected| expected != body_hash) {
            return Err(Error::integrity("Bulk artifact checksum mismatch."));
        }
        file.sync_all().await.map_err(|_| storage_error())?;
        drop(file);
        if shutdown.is_cancelled() {
            return Err(Error::unavailable("Bulk artifact publication canceled."));
        }
        let destination = self.root.join(&body_hash);
        // The filesystem operation and quota ownership transition must have one
        // owner even if its async waiter is canceled after link creation.
        let stage_path = stage.0.clone();
        let created =
            tokio::task::spawn_blocking(move || retain_link(stage_path, destination, reservation))
                .await
                .map_err(|_| storage_error())??;
        if !created {
            let existing = self.verify(&body_hash, max_bytes, shutdown.clone()).await?;
            if existing.bytes != bytes {
                return Err(Error::integrity("Immutable artifact length mismatch."));
            }
        }
        sync_directory(&self.root).await?;
        Ok(BulkArtifact {
            relative_path: body_hash.clone(),
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
        if !valid_hash(hash) {
            return Err(Error::invalid("Invalid artifact hash."));
        }
        let path = self.root.join(hash);
        let metadata = tokio::fs::symlink_metadata(&path)
            .await
            .map_err(|_| storage_error())?;
        if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > max_bytes {
            return Err(Error::integrity("Invalid retained artifact."));
        }
        let mut file = tokio::fs::File::open(path)
            .await
            .map_err(|_| storage_error())?;
        let mut digest = Sha256::new();
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
            digest.update(&chunk[..count]);
        }
        if length != metadata.len() || hex::encode(digest.finalize()) != hash {
            return Err(Error::integrity("Retained artifact checksum mismatch."));
        }
        Ok(BulkArtifact {
            body_hash: hash.into(),
            relative_path: hash.into(),
            bytes: length,
        })
    }
    pub async fn open(
        &self,
        hash: &str,
        max_bytes: u64,
        shutdown: CancellationToken,
    ) -> Result<tokio::fs::File> {
        self.verify(hash, max_bytes, shutdown).await?;
        tokio::fs::File::open(self.root.join(hash))
            .await
            .map_err(|_| storage_error())
    }
}
fn retained_bytes(root: &Path) -> Result<u64> {
    let mut used = 0_u64;
    for entry in std::fs::read_dir(root).map_err(|_| storage_error())? {
        let entry = entry.map_err(|_| storage_error())?;
        if !valid_hash(&entry.file_name().to_string_lossy()) {
            continue;
        }
        if !entry.file_type().map_err(|_| storage_error())?.is_file() {
            return Err(Error::integrity(
                "Invalid immutable artifact filesystem member.",
            ));
        }
        used = used
            .checked_add(entry.metadata().map_err(|_| storage_error())?.len())
            .ok_or_else(|| Error::capacity("Artifact quota accounting overflow."))?;
    }
    Ok(used)
}
fn storage_error() -> Error {
    Error::unavailable("Bulk artifact storage unavailable.")
}
fn retain_link(
    stage: PathBuf,
    destination: PathBuf,
    reservation: ArtifactReservation,
) -> Result<bool> {
    match std::fs::hard_link(stage, destination) {
        Ok(()) => {
            reservation.retain();
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
            status: 200,
            validators: Validators::default(),
            content_length: Some(3),
            stream: Box::pin(futures::stream::iter([Ok(b"bad".to_vec())])),
        };
        assert!(
            store
                .capture(response, Some(&"a".repeat(64)), CancellationToken::new())
                .await
                .is_err()
        );
        let files: Vec<_> = std::fs::read_dir(root.path()).unwrap().collect();
        assert_eq!(files.len(), 1);
        tokio::fs::write(root.path().join(&artifact.body_hash), b"corrupt")
            .await
            .unwrap();
        assert!(
            store
                .verify(&artifact.body_hash, 100, CancellationToken::new())
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
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
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
            .admit_rate_inner("api.w3.org", true, Some(1), true)
            .await
            .expect("API permit");
        drop(api);
        let publication = broker
            .admit_rate_inner("www.w3.org", true, Some(1), true)
            .await
            .expect("publication permit");
        drop(publication);
        let git = broker
            .admit_rate_inner("github.com", true, Some(1), true)
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
        use crate::w3c_catalog::ApiOperation;
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
