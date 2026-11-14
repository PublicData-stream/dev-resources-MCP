//! Private, operator-configured S3 transport. Objects are immutable and never deleted.
//!
//! Publication, ownership, quota reservations and logical path bindings belong to
//! the durable archive coordinator; this adapter owns only bounded remote I/O.
use aws_credential_types::{
    Credentials,
    provider::{
        ProvideCredentials, error::CredentialsError,
        future::ProvideCredentials as CredentialsFuture,
    },
};
use aws_smithy_runtime_api::client::{
    http::{
        HttpConnector, HttpConnectorFuture, SharedHttpClient, SharedHttpConnector, http_client_fn,
    },
    orchestrator::{HttpRequest, HttpResponse},
    result::ConnectorError,
};
use aws_smithy_types::{body::SdkBody, byte_stream::ByteStream};
use devres_domain::{Error, Result};
use futures::StreamExt;
use serde::Deserialize;
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct S3Config {
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub prefix: String,
    #[serde(default = "default_true")]
    pub path_style: bool,
    #[serde(default)]
    pub allow_http: bool,
    pub ca_file: Option<PathBuf>,
    pub cache_max_bytes: u64,
    /// Explicit placement for new objects; omitted preserves provider defaults.
    #[serde(default)]
    pub storage_class: Option<String>,
    pub credentials: S3Credentials,
}

const fn default_true() -> bool {
    true
}

/// Exactly one source is selected; no ambient AWS credential chain is evaluated.
#[derive(Clone, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum S3Credentials {
    Files {
        access_key_file: PathBuf,
        secret_key_file: PathBuf,
        session_token_file: Option<PathBuf>,
    },
    Oidc {
        token_file: PathBuf,
        role_arn: String,
        session_name: String,
        sts_endpoint: String,
        #[serde(default)]
        allow_http: bool,
        ca_file: Option<PathBuf>,
    },
    Container {
        endpoint: String,
        authorization_token_file: Option<PathBuf>,
        #[serde(default)]
        allow_http: bool,
        ca_file: Option<PathBuf>,
        #[serde(default = "default_refresh_before_secs")]
        refresh_before_secs: u64,
    },
}

const fn default_refresh_before_secs() -> u64 {
    300
}

fn invalid_config() -> Error {
    Error::invalid("Invalid S3 storage configuration.")
}
fn unavailable() -> Error {
    Error::unavailable("Object storage unavailable.")
}
fn cancelled() -> Error {
    Error::capacity("Object storage operation canceled.")
}

fn endpoint_url(value: &str, allow_http: bool, path_allowed: bool) -> Result<url::Url> {
    let parsed = url::Url::parse(value).map_err(|_| invalid_config())?;
    if !(parsed.scheme() == "https" || (allow_http && parsed.scheme() == "http"))
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || (!path_allowed && parsed.path() != "/" && !parsed.path().is_empty())
        || value.chars().any(char::is_control)
    {
        return Err(invalid_config());
    }
    Ok(parsed)
}

fn valid_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 1024
        && !key.starts_with('/')
        && key
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
        && !key.chars().any(|ch| ch.is_control() || ch == '\\')
}

impl S3Config {
    pub fn validate(&self) -> Result<()> {
        endpoint_url(&self.endpoint, self.allow_http, false)?;
        if self.bucket.len() < 3
            || self.bucket.len() > 63
            || !self.bucket.bytes().all(|ch| {
                ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == b'-' || ch == b'.'
            })
            || !self
                .bucket
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            || !self
                .bucket
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
            || self.bucket.contains("..")
            || self.bucket.contains(".-")
            || self.bucket.contains("-.")
            || self.bucket.parse::<std::net::IpAddr>().is_ok()
            || self.region.is_empty()
            || self.region.len() > 128
            || !self
                .region
                .bytes()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == b'-')
            || !valid_key(&self.prefix)
            || self.cache_max_bytes < 64 * 1024 * 1024
            || self
                .storage_class
                .as_deref()
                .is_some_and(|value| !matches!(value, "STANDARD" | "ONEZONE_IA"))
        {
            return Err(invalid_config());
        }
        match &self.credentials {
            S3Credentials::Files {
                access_key_file,
                secret_key_file,
                session_token_file,
            } => {
                valid_secret_path(access_key_file)?;
                valid_secret_path(secret_key_file)?;
                if let Some(path) = session_token_file {
                    valid_secret_path(path)?;
                }
            }
            S3Credentials::Oidc {
                token_file,
                role_arn,
                session_name,
                sts_endpoint,
                allow_http,
                ..
            } => {
                valid_secret_path(token_file)?;
                endpoint_url(sts_endpoint, *allow_http, false)?;
                if role_arn.is_empty()
                    || role_arn.len() > 2048
                    || role_arn.chars().any(char::is_control)
                    || !(2..=64).contains(&session_name.len())
                    || !session_name
                        .bytes()
                        .all(|ch| ch.is_ascii_alphanumeric() || b"_+=,.@-".contains(&ch))
                {
                    return Err(invalid_config());
                }
            }
            S3Credentials::Container {
                endpoint,
                authorization_token_file,
                allow_http,
                refresh_before_secs,
                ..
            } => {
                endpoint_url(endpoint, *allow_http, true)?;
                if !(1..=3600).contains(refresh_before_secs) {
                    return Err(invalid_config());
                }
                if let Some(path) = authorization_token_file {
                    valid_secret_path(path)?;
                }
            }
        }
        Ok(())
    }
}

fn valid_secret_path(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path.components().any(|part| {
            matches!(
                part,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(invalid_config());
    }
    Ok(())
}

async fn read_secret(path: &Path) -> Result<String> {
    use tokio::io::AsyncReadExt;
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|_| unavailable())?;
    if !file.metadata().await.map_err(|_| unavailable())?.is_file() {
        return Err(unavailable());
    }
    let mut bytes = Vec::new();
    file.take(64 * 1024 + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| unavailable())?;
    if bytes.len() > 64 * 1024 {
        return Err(invalid_config());
    }
    let text = String::from_utf8(bytes).map_err(|_| invalid_config())?;
    let text = text.trim_end_matches(['\n', '\r']);
    if text.is_empty() || text.chars().any(char::is_control) {
        return Err(invalid_config());
    }
    Ok(text.into())
}

fn http_client(ca_file: Option<&Path>) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .connect_timeout(Duration::from_secs(5))
        .read_timeout(Duration::from_secs(30));
    if let Some(path) = ca_file {
        if std::fs::metadata(path).map_err(|_| unavailable())?.len() > 1024 * 1024 {
            return Err(invalid_config());
        }
        let bytes = std::fs::read(path).map_err(|_| unavailable())?;
        if bytes.len() > 1024 * 1024 {
            return Err(invalid_config());
        }
        let certificates =
            reqwest::Certificate::from_pem_bundle(&bytes).map_err(|_| invalid_config())?;
        if certificates.is_empty() {
            return Err(invalid_config());
        }
        for certificate in certificates {
            builder = builder.add_root_certificate(certificate);
        }
    }
    builder.build().map_err(|_| unavailable())
}

#[derive(Clone, Debug)]
pub struct ObjectMetadata {
    pub bytes: u64,
}

#[derive(Clone)]
struct Connector {
    client: reqwest::Client,
    origin: url::Origin,
    read_only: bool,
}
impl std::fmt::Debug for Connector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("S3EndpointConnector")
    }
}

fn connector_error() -> ConnectorError {
    ConnectorError::io(Box::new(std::io::Error::other(
        "Object storage transport failed.",
    )))
}

impl HttpConnector for Connector {
    fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
        let connector = self.clone();
        HttpConnectorFuture::new(async move {
            let url = url::Url::parse(request.uri()).map_err(|_| connector_error())?;
            if url.origin() != connector.origin
                || !url.username().is_empty()
                || url.password().is_some()
            {
                return Err(ConnectorError::user(Box::new(std::io::Error::other(
                    "Object storage destination rejected.",
                ))));
            }
            let request = request.try_into_http1x().map_err(|_| connector_error())?;
            let (parts, body) = request.into_parts();
            if connector.read_only
                && !matches!(parts.method, http::Method::GET | http::Method::HEAD)
            {
                return Err(ConnectorError::user(Box::new(std::io::Error::other(
                    "Reader object storage mutation rejected.",
                ))));
            }
            let unbounded_object_body = parts.method == http::Method::GET
                && !url
                    .query_pairs()
                    .any(|(key, _)| key == "uploads" || key == "list-type");
            let stream = tokio_util::io::ReaderStream::new(ByteStream::new(body).into_async_read());
            let response = connector
                .client
                .request(parts.method, url)
                .headers(parts.headers)
                .body(reqwest::Body::wrap_stream(stream))
                .send()
                .await
                .map_err(|_| connector_error())?;
            let mut builder = http::Response::builder().status(response.status());
            *builder.headers_mut().ok_or_else(connector_error)? = response.headers().clone();
            let response_limit = if unbounded_object_body && response.status().is_success() {
                None
            } else {
                Some(1024 * 1024_u64)
            };
            let mut received = 0_u64;
            let body = http_body_util::StreamBody::new(response.bytes_stream().map(move |chunk| {
                let bytes =
                    chunk.map_err(|_| std::io::Error::other("Object storage response failed."))?;
                received = received.checked_add(bytes.len() as u64).ok_or_else(|| {
                    std::io::Error::other("Object storage response exceeds its bound.")
                })?;
                if response_limit.is_some_and(|limit| received > limit) {
                    return Err(std::io::Error::other(
                        "Object storage response exceeds its bound.",
                    ));
                }
                Ok(http_body::Frame::data(bytes))
            }));
            let response = builder
                .body(SdkBody::from_body_1_x(body))
                .map_err(|_| connector_error())?;
            HttpResponse::try_from(response).map_err(|_| connector_error())
        })
    }
}

fn sdk_http(client: reqwest::Client, endpoint: &url::Url, read_only: bool) -> SharedHttpClient {
    let connector = SharedHttpConnector::new(Connector {
        client,
        origin: endpoint.origin(),
        read_only,
    });
    http_client_fn(move |_, _| connector.clone())
}

#[derive(Clone)]
struct ExplicitCredentials {
    source: S3Credentials,
    region: String,
    identity_client: Option<reqwest::Client>,
    container_cache: std::sync::Arc<ContainerCache>,
}

#[derive(Default)]
struct ContainerCache {
    value: std::sync::Mutex<Option<Credentials>>,
    refresh: std::sync::Arc<tokio::sync::Mutex<()>>,
}
impl std::fmt::Debug for ExplicitCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ExplicitStorageCredentials")
    }
}
impl ProvideCredentials for ExplicitCredentials {
    fn provide_credentials<'a>(&'a self) -> CredentialsFuture<'a>
    where
        Self: 'a,
    {
        CredentialsFuture::new(async move {
            self.cached_load()
                .await
                .map_err(|_| CredentialsError::provider_error("Storage credentials unavailable."))
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ContainerCredentials {
    access_key_id: String,
    secret_access_key: String,
    token: Option<String>,
    expiration: String,
}

impl ExplicitCredentials {
    async fn cached_load(&self) -> Result<Credentials> {
        self.cached_load_until(tokio::time::Instant::now() + Duration::from_secs(15))
            .await
    }

    async fn cached_load_until(&self, deadline: tokio::time::Instant) -> Result<Credentials> {
        let S3Credentials::Container {
            refresh_before_secs,
            ..
        } = self.source
        else {
            return tokio::time::timeout_at(deadline, self.load())
                .await
                .map_err(|_| unavailable())?;
        };
        let cached = self.cached_value()?;
        if let Some(value) = cached.as_ref()
            && value.expiry().is_some_and(|expiry| {
                expiry > std::time::SystemTime::now() + Duration::from_secs(refresh_before_secs)
            })
        {
            return Ok(value.clone());
        }
        // One cache-owned refresh survives a cancelled or impatient waiter.
        // Concurrent signers keep using an old key only while it remains valid.
        let refresh = match self.container_cache.refresh.clone().try_lock_owned() {
            Ok(guard) => guard,
            Err(_) => {
                if let Some(value) = cached.as_ref()
                    && usable(value, 5)
                {
                    return Ok(value.clone());
                }
                let _refresh =
                    tokio::time::timeout_at(deadline, self.container_cache.refresh.lock())
                        .await
                        .map_err(|_| unavailable())?;
                return self
                    .cached_value()?
                    .filter(|value| usable(value, 5))
                    .ok_or_else(unavailable);
            }
        };
        let cached = self.cached_value()?;
        if let Some(value) = cached.as_ref()
            && usable(value, refresh_before_secs)
        {
            return Ok(value.clone());
        }
        // Health still waits at most two seconds before falling back to a valid
        // key. That waiter budget must not cancel an admitted credential issuance.
        let wait_deadline = if cached.as_ref().is_some_and(|value| usable(value, 5)) {
            deadline.min(tokio::time::Instant::now() + Duration::from_secs(2))
        } else {
            deadline
        };
        let owner = self.clone();
        let renewal = tokio::spawn(async move {
            let _refresh = refresh;
            let value = tokio::time::timeout(Duration::from_secs(15), owner.load())
                .await
                .map_err(|_| unavailable())??;
            *owner
                .container_cache
                .value
                .lock()
                .map_err(|_| unavailable())? = Some(value.clone());
            Ok(value)
        });
        // Dropping a JoinHandle detaches the single bounded owner; it does not
        // abort the request and turn a healthy slow response into an unknown create.
        let result = match tokio::time::timeout_at(wait_deadline, renewal).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) | Err(_) => Err(unavailable()),
        };
        match result {
            Ok(value) => Ok(value),
            Err(error) => {
                if let Some(value) = cached.as_ref()
                    && usable(value, 5)
                {
                    return Ok(value.clone());
                }
                Err(error)
            }
        }
    }

    fn cached_value(&self) -> Result<Option<Credentials>> {
        self.container_cache
            .value
            .lock()
            .map(|value| value.clone())
            .map_err(|_| unavailable())
    }

    async fn load(&self) -> Result<Credentials> {
        match &self.source {
            S3Credentials::Files {
                access_key_file,
                secret_key_file,
                session_token_file,
            } => {
                let access = read_secret(access_key_file).await?;
                let secret = read_secret(secret_key_file).await?;
                let token = match session_token_file {
                    Some(path) => Some(read_secret(path).await?),
                    None => None,
                };
                Ok(Credentials::new(
                    access,
                    secret,
                    token,
                    None,
                    "explicit-files",
                ))
            }
            S3Credentials::Oidc {
                token_file,
                role_arn,
                session_name,
                sts_endpoint,
                allow_http,
                ..
            } => {
                let endpoint = endpoint_url(sts_endpoint, *allow_http, false)?;
                let client = self.identity_client.clone().ok_or_else(unavailable)?;
                let config = aws_sdk_sts::config::Builder::new()
                    .behavior_version(aws_sdk_sts::config::BehaviorVersion::latest())
                    .region(aws_sdk_sts::config::Region::new(self.region.clone()))
                    .endpoint_url(sts_endpoint)
                    .http_client(sdk_http(client, &endpoint, false))
                    .retry_config(
                        aws_sdk_sts::config::retry::RetryConfig::standard().with_max_attempts(3),
                    )
                    .build();
                let response = aws_sdk_sts::Client::from_conf(config)
                    .assume_role_with_web_identity()
                    .role_arn(role_arn)
                    .role_session_name(session_name)
                    .web_identity_token(read_secret(token_file).await?)
                    .send()
                    .await
                    .map_err(|_| unavailable())?;
                let credentials = response.credentials().ok_or_else(unavailable)?;
                let expiration = std::time::SystemTime::try_from(*credentials.expiration())
                    .map_err(|_| unavailable())?;
                validate_expiration(expiration)?;
                Ok(Credentials::new(
                    credentials.access_key_id(),
                    credentials.secret_access_key(),
                    Some(credentials.session_token().into()),
                    Some(expiration),
                    "explicit-oidc",
                ))
            }
            S3Credentials::Container {
                endpoint,
                authorization_token_file,
                ..
            } => {
                let client = self.identity_client.as_ref().ok_or_else(unavailable)?;
                let mut request = client.get(endpoint);
                if let Some(path) = authorization_token_file {
                    request =
                        request.header(reqwest::header::AUTHORIZATION, read_secret(path).await?);
                }
                let mut response = request.send().await.map_err(|_| unavailable())?;
                if !response.status().is_success()
                    || response.content_length().is_some_and(|len| len > 64 * 1024)
                {
                    return Err(unavailable());
                }
                let mut bytes = Vec::new();
                while let Some(chunk) = response.chunk().await.map_err(|_| unavailable())? {
                    if bytes
                        .len()
                        .checked_add(chunk.len())
                        .is_none_or(|len| len > 64 * 1024)
                    {
                        return Err(unavailable());
                    }
                    bytes.extend_from_slice(&chunk);
                }
                let value: ContainerCredentials =
                    serde_json::from_slice(&bytes).map_err(|_| unavailable())?;
                if [&value.access_key_id, &value.secret_access_key]
                    .iter()
                    .any(|value| value.is_empty() || value.chars().any(char::is_control))
                    || value.token.as_ref().is_some_and(|value| {
                        value.is_empty() || value.chars().any(char::is_control)
                    })
                {
                    return Err(unavailable());
                }
                let expiration = aws_smithy_types::DateTime::from_str(
                    &value.expiration,
                    aws_smithy_types::date_time::Format::DateTime,
                )
                .map_err(|_| unavailable())?;
                let expiration =
                    std::time::SystemTime::try_from(expiration).map_err(|_| unavailable())?;
                validate_expiration(expiration)?;
                Ok(Credentials::new(
                    value.access_key_id,
                    value.secret_access_key,
                    value.token,
                    Some(expiration),
                    "explicit-container",
                ))
            }
        }
    }
}

fn usable(value: &Credentials, margin_secs: u64) -> bool {
    value.expiry().is_some_and(|expiry| {
        expiry > std::time::SystemTime::now() + Duration::from_secs(margin_secs)
    })
}

fn validate_expiration(expiration: std::time::SystemTime) -> Result<()> {
    if expiration <= std::time::SystemTime::now() + Duration::from_secs(5) {
        return Err(unavailable());
    }
    Ok(())
}

pub struct S3Archive {
    client: aws_sdk_s3::Client,
    config: S3Config,
}

fn storage_destination(config: &S3Config) -> Result<url::Url> {
    let mut destination = endpoint_url(&config.endpoint, config.allow_http, false)?;
    if !config.path_style {
        let host = destination.host_str().ok_or_else(invalid_config)?;
        if host.parse::<std::net::IpAddr>().is_ok() {
            return Err(invalid_config());
        }
        destination
            .set_host(Some(&format!("{}.{}", config.bucket, host)))
            .map_err(|_| invalid_config())?;
    }
    Ok(destination)
}

impl S3Archive {
    pub async fn new(config: S3Config) -> Result<Self> {
        Self::with_read_only(config, false).await
    }

    /// Reader authority comes from the storage open mode, never credential configuration.
    pub(crate) async fn new_reader(config: S3Config) -> Result<Self> {
        Self::with_read_only(config, true).await
    }

    async fn with_read_only(config: S3Config, read_only: bool) -> Result<Self> {
        config.validate()?;
        let destination = storage_destination(&config)?;
        let identity_client = match &config.credentials {
            S3Credentials::Files { .. } => None,
            S3Credentials::Oidc { ca_file, .. } | S3Credentials::Container { ca_file, .. } => {
                Some(http_client(ca_file.as_deref())?)
            }
        };
        let credentials = ExplicitCredentials {
            source: config.credentials.clone(),
            region: config.region.clone(),
            identity_client,
            container_cache: Default::default(),
        };
        let container_identity = matches!(&config.credentials, S3Credentials::Container { .. });
        let builder = aws_sdk_s3::config::Builder::new()
            .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest())
            .region(aws_sdk_s3::config::Region::new(config.region.clone()))
            .endpoint_url(&config.endpoint)
            .force_path_style(config.path_style)
            .credentials_provider(credentials)
            .request_checksum_calculation(
                aws_sdk_s3::config::RequestChecksumCalculation::WhenRequired,
            )
            .response_checksum_validation(
                aws_sdk_s3::config::ResponseChecksumValidation::WhenRequired,
            )
            .http_client(sdk_http(
                http_client(config.ca_file.as_deref())?,
                &destination,
                read_only,
            ))
            .retry_config(aws_sdk_s3::config::retry::RetryConfig::standard().with_max_attempts(3));
        // Container refresh is owned by ExplicitCredentials so the SDK cannot
        // cache past the configured refresh margin (which would hide rotation).
        let builder = if container_identity {
            builder.identity_cache(aws_sdk_s3::config::IdentityCache::no_cache())
        } else {
            builder
        };
        let client = aws_sdk_s3::Client::from_conf(builder.build());
        Ok(Self { client, config })
    }

    pub fn config(&self) -> &S3Config {
        &self.config
    }

    fn key(&self, relative: &str) -> Result<String> {
        if !valid_key(relative) {
            return Err(Error::integrity("Invalid object storage key."));
        }
        let key = format!("{}/{}", self.config.prefix, relative);
        if key.len() > 1024 {
            return Err(Error::capacity("Object storage key exceeds its bound."));
        }
        Ok(key)
    }

    pub async fn health(&self) -> Result<()> {
        tokio::time::timeout(
            Duration::from_secs(5),
            self.client
                .list_objects_v2()
                .bucket(&self.config.bucket)
                .prefix(format!("{}/", self.config.prefix))
                .max_keys(1)
                .send(),
        )
        .await
        .map_err(|_| unavailable())?
        .map_err(|_| unavailable())?;
        Ok(())
    }

    /// Fresh maintenance destinations must contain no objects, including orphans.
    pub async fn prefix_is_empty(&self) -> Result<bool> {
        self.run_for(
            &CancellationToken::new(),
            Duration::from_secs(15),
            Box::pin(async {
                let response = self
                    .client
                    .list_objects_v2()
                    .bucket(&self.config.bucket)
                    .prefix(format!("{}/", self.config.prefix))
                    .max_keys(1)
                    .send()
                    .await
                    .map_err(|_| unavailable())?;
                Ok(response.contents().is_empty())
            }),
        )
        .await
    }

    pub async fn head(&self, key: &str) -> Result<Option<ObjectMetadata>> {
        self.run_for(
            &CancellationToken::new(),
            Duration::from_secs(15),
            Box::pin(async {
                let response = self
                    .client
                    .head_object()
                    .bucket(&self.config.bucket)
                    .key(self.key(key)?)
                    .send()
                    .await;
                match response {
                    Ok(value) => Ok(Some(ObjectMetadata {
                        bytes: positive_length(value.content_length())?,
                    })),
                    Err(error)
                        if error
                            .raw_response()
                            .is_some_and(|response| response.status().as_u16() == 404) =>
                    {
                        Ok(None)
                    }
                    Err(_) => Err(unavailable()),
                }
            }),
        )
        .await
    }

    pub async fn get_to_file(
        &self,
        key: &str,
        target: &Path,
        max_bytes: u64,
        cancel: &CancellationToken,
    ) -> Result<(String, u64)> {
        // A dropped tokio::fs write can leave its blocking job running after
        // the download future and archive byte reservation have been dropped.
        // Keep each local operation in this poll's ownership instead. On a
        // multithreaded runtime block_in_place supplies a replacement worker;
        // cancellation is observed between bounded network/write iterations.
        fn local_io<T>(operation: impl FnOnce() -> std::io::Result<T>) -> std::io::Result<T> {
            if tokio::runtime::Handle::try_current().is_ok_and(|handle| {
                handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread
            }) {
                tokio::task::block_in_place(operation)
            } else {
                operation()
            }
        }
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        self.run(
            cancel,
            Box::pin(async {
                let response = self
                    .client
                    .get_object()
                    .bucket(&self.config.bucket)
                    .key(self.key(key)?)
                    .send()
                    .await
                    .map_err(|_| unavailable())?;
                let expected = positive_length(response.content_length())?;
                if expected > max_bytes {
                    return Err(Error::capacity("Object storage read exceeds its bound."));
                }
                let mut output = local_io(|| {
                    std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .custom_flags(nix::libc::O_NOFOLLOW)
                        .open(target)
                })
                .map_err(|_| unavailable())?;
                let mut guard = DownloadGuard(Some(target.to_owned()));
                let mut reader = response.body.into_async_read();
                let mut hasher = blake3::Hasher::new();
                let mut bytes = 0_u64;
                let mut buffer = vec![0_u8; 65536];
                loop {
                    let count = reader.read(&mut buffer).await.map_err(|_| unavailable())?;
                    if count == 0 {
                        break;
                    }
                    bytes = bytes
                        .checked_add(count as u64)
                        .filter(|count| *count <= max_bytes && *count <= expected)
                        .ok_or_else(|| Error::integrity("Object storage length mismatch."))?;
                    hasher.update(&buffer[..count]);
                    local_io(|| output.write_all(&buffer[..count])).map_err(|_| unavailable())?;
                }
                if bytes != expected {
                    return Err(Error::integrity("Object storage length mismatch."));
                }
                local_io(|| output.sync_all()).map_err(|_| unavailable())?;
                guard.0 = None;
                Ok((format!("blake3:{}", hasher.finalize().to_hex()), bytes))
            }),
        )
        .await
    }

    pub async fn get_bytes(&self, key: &str, max_bytes: u64) -> Result<Vec<u8>> {
        self.get_bytes_with_cancel(key, max_bytes, &CancellationToken::new())
            .await
    }

    pub async fn get_bytes_with_cancel(
        &self,
        key: &str,
        max_bytes: u64,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>> {
        if max_bytes > 128 * 1024 * 1024 {
            return Err(Error::capacity(
                "Object storage memory read exceeds its bound.",
            ));
        }
        self.run_for(
            cancel,
            Duration::from_secs(60),
            Box::pin(async {
                let response = self
                    .client
                    .get_object()
                    .bucket(&self.config.bucket)
                    .key(self.key(key)?)
                    .send()
                    .await
                    .map_err(|_| unavailable())?;
                let expected = positive_length(response.content_length())?;
                if expected > max_bytes {
                    return Err(Error::capacity("Object storage read exceeds its bound."));
                }
                let reader = response.body.into_async_read();
                let mut output =
                    Vec::with_capacity(usize::try_from(expected).map_err(|_| unavailable())?);
                reader
                    .take(max_bytes + 1)
                    .read_to_end(&mut output)
                    .await
                    .map_err(|_| unavailable())?;
                if output.len() as u64 != expected {
                    return Err(Error::integrity("Object storage length mismatch."));
                }
                Ok(output)
            }),
        )
        .await
    }

    pub async fn put_bytes_immutable(&self, key: &str, bytes: &[u8]) -> Result<()> {
        self.put_bytes_immutable_with_cancel(key, bytes, &CancellationToken::new())
            .await
    }

    pub async fn put_bytes_immutable_with_cancel(
        &self,
        key: &str,
        bytes: &[u8],
        cancel: &CancellationToken,
    ) -> Result<()> {
        self.run_for(
            cancel,
            Duration::from_secs(60),
            Box::pin(async {
                if bytes.len() > 16 * 1024 * 1024 {
                    return Err(Error::capacity(
                        "Object storage memory write exceeds its bound.",
                    ));
                }
                let digest = crate::integrity::hash(bytes);
                let result = self
                    .client
                    .put_object()
                    .bucket(&self.config.bucket)
                    .set_storage_class(
                        self.config
                            .storage_class
                            .as_deref()
                            .map(aws_sdk_s3::types::StorageClass::from),
                    )
                    .key(self.key(key)?)
                    .if_none_match("*")
                    .content_length(bytes.len() as i64)
                    .body(ByteStream::from(bytes.to_vec()))
                    .send()
                    .await;
                // A failed response can follow a completed write. Exact readback reconciles
                // that ambiguity without ever replacing the immutable destination.
                if result.is_err() && self.head(key).await?.is_none() {
                    return Err(unavailable());
                }
                self.verify_remote(key, &digest, bytes.len() as u64, cancel)
                    .await
            }),
        )
        .await
    }

    pub async fn put_file_immutable(
        &self,
        key: &str,
        path: &Path,
        digest: &str,
        bytes: u64,
        cancel: &CancellationToken,
    ) -> Result<()> {
        if !digest.starts_with("blake3:") || !crate::integrity::valid_hash(digest) {
            return Err(Error::integrity("Invalid object storage digest."));
        }
        self.run(
            cancel,
            Box::pin(async {
                let metadata = tokio::fs::symlink_metadata(path)
                    .await
                    .map_err(|_| unavailable())?;
                if !metadata.is_file() || metadata.len() != bytes {
                    return Err(Error::integrity("Invalid object storage source file."));
                }
                let actual = hash_file(path, bytes).await?;
                if actual != digest {
                    return Err(Error::integrity("Object storage source digest mismatch."));
                }
                if self.head(key).await?.is_some() {
                    return self.verify_remote(key, digest, bytes, cancel).await;
                }
                const PART_BYTES: usize = 16 * 1024 * 1024;
                let mut file = tokio::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(nix::libc::O_NOFOLLOW)
                    .open(path)
                    .await
                    .map_err(|_| unavailable())?;
                if bytes <= PART_BYTES as u64 {
                    let mut body = Vec::with_capacity(bytes as usize);
                    (&mut file)
                        .take(bytes + 1)
                        .read_to_end(&mut body)
                        .await
                        .map_err(|_| unavailable())?;
                    if body.len() as u64 != bytes {
                        return Err(Error::integrity("Object storage source length changed."));
                    }
                    let result = self
                        .client
                        .put_object()
                        .bucket(&self.config.bucket)
                        .set_storage_class(
                            self.config
                                .storage_class
                                .as_deref()
                                .map(aws_sdk_s3::types::StorageClass::from),
                        )
                        .key(self.key(key)?)
                        .if_none_match("*")
                        .content_length(bytes as i64)
                        .body(ByteStream::from(body))
                        .send()
                        .await;
                    if result.is_err() && self.head(key).await?.is_none() {
                        return Err(unavailable());
                    }
                } else {
                    self.multipart(key, &mut file, bytes, cancel).await?;
                }
                self.verify_remote(key, digest, bytes, cancel).await
            }),
        )
        .await
    }

    async fn multipart(
        &self,
        key: &str,
        file: &mut tokio::fs::File,
        bytes: u64,
        cancel: &CancellationToken,
    ) -> Result<()> {
        if bytes.div_ceil(16 * 1024 * 1024) > 10000 {
            return Err(Error::capacity("Multipart upload exceeds its part bound."));
        }
        let remote_key = self.key(key)?;
        let created = self
            .client
            .create_multipart_upload()
            .bucket(&self.config.bucket)
            .set_storage_class(
                self.config
                    .storage_class
                    .as_deref()
                    .map(aws_sdk_s3::types::StorageClass::from),
            )
            .key(&remote_key)
            .send()
            .await
            .map_err(|_| unavailable())?;
        let id = created.upload_id().ok_or_else(unavailable)?.to_owned();
        let mut guard = MultipartGuard {
            client: self.client.clone(),
            bucket: self.config.bucket.clone(),
            key: remote_key.clone(),
            id: id.clone(),
            armed: true,
        };
        async {
            let mut remaining = bytes;
            let mut number = 1_i32;
            let mut parts = Vec::new();
            while remaining > 0 {
                if cancel.is_cancelled() {
                    return Err(cancelled());
                }
                if number > 10000 {
                    return Err(Error::capacity("Multipart upload exceeds its part bound."));
                }
                let count = remaining.min(16 * 1024 * 1024) as usize;
                let mut buffer = vec![0_u8; count];
                file.read_exact(&mut buffer)
                    .await
                    .map_err(|_| unavailable())?;
                let response = self
                    .client
                    .upload_part()
                    .bucket(&self.config.bucket)
                    .key(&remote_key)
                    .upload_id(&id)
                    .part_number(number)
                    .content_length(count as i64)
                    .body(ByteStream::from(buffer))
                    .send()
                    .await
                    .map_err(|_| unavailable())?;
                parts.push(
                    aws_sdk_s3::types::CompletedPart::builder()
                        .part_number(number)
                        .e_tag(response.e_tag().ok_or_else(unavailable)?)
                        .build(),
                );
                remaining -= count as u64;
                number += 1;
            }
            let completed = self
                .client
                .complete_multipart_upload()
                .bucket(&self.config.bucket)
                .key(&remote_key)
                .upload_id(&id)
                .if_none_match("*")
                .multipart_upload(
                    aws_sdk_s3::types::CompletedMultipartUpload::builder()
                        .set_parts(Some(parts))
                        .build(),
                )
                .send()
                .await;
            if completed.is_ok() {
                guard.armed = false;
            }
            if completed.is_err() && self.head(key).await?.is_none() {
                return Err(unavailable());
            }
            Ok(())
        }
        .await
    }

    /// Recover only unfinished multipart uploads of an exact journaled object key.
    /// The caller must hold the exclusive database storage fence and suspend new
    /// admissions. Listings never establish object integrity or publication.
    pub async fn abort_incomplete(&self, key: &str) -> Result<()> {
        self.run_for(
            &CancellationToken::new(),
            Duration::from_secs(60),
            Box::pin(async {
                let remote_key = self.key(key)?;
                let mut key_marker = None;
                let mut id_marker = None;
                let mut inspected = 0_usize;
                loop {
                    let response = self
                        .client
                        .list_multipart_uploads()
                        .bucket(&self.config.bucket)
                        .prefix(&remote_key)
                        .max_uploads(100)
                        .set_key_marker(key_marker.clone())
                        .set_upload_id_marker(id_marker.clone())
                        .send()
                        .await
                        .map_err(|_| unavailable())?;
                    for upload in response.uploads() {
                        inspected += 1;
                        if inspected > 1024 {
                            return Err(Error::capacity("Multipart recovery exceeds its bound."));
                        }
                        if upload.key() == Some(remote_key.as_str()) {
                            let id = upload.upload_id().ok_or_else(unavailable)?;
                            self.client
                                .abort_multipart_upload()
                                .bucket(&self.config.bucket)
                                .key(&remote_key)
                                .upload_id(id)
                                .send()
                                .await
                                .map_err(|_| unavailable())?;
                        }
                    }
                    if response.is_truncated() != Some(true) {
                        return Ok(());
                    }
                    let next_key = response.next_key_marker().map(str::to_owned);
                    let next_id = response.next_upload_id_marker().map(str::to_owned);
                    if next_key.is_none() || (next_key == key_marker && next_id == id_marker) {
                        return Err(Error::integrity("Invalid multipart recovery pagination."));
                    }
                    key_marker = next_key;
                    id_marker = next_id;
                }
            }),
        )
        .await
    }

    /// Verify retained content without materializing it in the local cache.
    pub async fn verify_object(
        &self,
        key: &str,
        digest: &str,
        bytes: u64,
        cancel: &CancellationToken,
    ) -> Result<()> {
        if !digest.starts_with("blake3:") || !crate::integrity::valid_hash(digest) {
            return Err(Error::integrity("Invalid object storage digest."));
        }
        self.verify_remote(key, digest, bytes, cancel).await
    }

    async fn verify_remote(
        &self,
        key: &str,
        digest: &str,
        expected: u64,
        cancel: &CancellationToken,
    ) -> Result<()> {
        self.run(
            cancel,
            Box::pin(async {
                let response = self
                    .client
                    .get_object()
                    .bucket(&self.config.bucket)
                    .key(self.key(key)?)
                    .send()
                    .await
                    .map_err(|_| unavailable())?;
                if positive_length(response.content_length())? != expected {
                    return Err(Error::integrity("Conflicting immutable object length."));
                }
                let mut reader = response.body.into_async_read();
                let mut hasher = blake3::Hasher::new();
                let mut count = 0_u64;
                let mut buffer = vec![0_u8; 65536];
                loop {
                    let n = reader.read(&mut buffer).await.map_err(|_| unavailable())?;
                    if n == 0 {
                        break;
                    }
                    count = count
                        .checked_add(n as u64)
                        .filter(|v| *v <= expected)
                        .ok_or_else(|| Error::integrity("Conflicting immutable object length."))?;
                    hasher.update(&buffer[..n]);
                }
                if count != expected || format!("blake3:{}", hasher.finalize().to_hex()) != digest {
                    return Err(Error::integrity("Conflicting immutable object digest."));
                }
                Ok(())
            }),
        )
        .await
    }

    async fn run<T>(
        &self,
        cancel: &CancellationToken,
        future: impl std::future::Future<Output = Result<T>>,
    ) -> Result<T> {
        self.run_for(cancel, Duration::from_secs(3600), future)
            .await
    }

    async fn run_for<T>(
        &self,
        cancel: &CancellationToken,
        timeout: Duration,
        future: impl std::future::Future<Output = Result<T>>,
    ) -> Result<T> {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(cancelled()),
            result = tokio::time::timeout(timeout, future) => result.map_err(|_| Error::capacity("Object storage operation deadline exceeded."))?,
        }
    }
}

fn positive_length(value: Option<i64>) -> Result<u64> {
    value
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| Error::integrity("Invalid object storage content length."))
}

struct DownloadGuard(Option<PathBuf>);
impl Drop for DownloadGuard {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            let _ = std::fs::remove_file(path);
        }
    }
}

struct MultipartGuard {
    client: aws_sdk_s3::Client,
    bucket: String,
    key: String,
    id: String,
    armed: bool,
}
impl Drop for MultipartGuard {
    fn drop(&mut self) {
        if self.armed
            && let Ok(runtime) = tokio::runtime::Handle::try_current()
        {
            let client = self.client.clone();
            let bucket = self.bucket.clone();
            let key = self.key.clone();
            let id = self.id.clone();
            runtime.spawn(async move {
                let _ = tokio::time::timeout(
                    Duration::from_secs(5),
                    client
                        .abort_multipart_upload()
                        .bucket(bucket)
                        .key(key)
                        .upload_id(id)
                        .send(),
                )
                .await;
            });
        }
    }
}

async fn hash_file(path: &Path, expected: u64) -> Result<String> {
    let mut file = tokio::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)
        .await
        .map_err(|_| unavailable())?;
    let mut hash = blake3::Hasher::new();
    let mut count = 0_u64;
    let mut buffer = vec![0_u8; 65536];
    loop {
        let n = file.read(&mut buffer).await.map_err(|_| unavailable())?;
        if n == 0 {
            break;
        }
        count = count
            .checked_add(n as u64)
            .filter(|value| *value <= expected)
            .ok_or_else(|| Error::integrity("Object storage source length changed."))?;
        hash.update(&buffer[..n]);
    }
    if count != expected {
        return Err(Error::integrity("Object storage source length changed."));
    }
    Ok(format!("blake3:{}", hash.finalize().to_hex()))
}

#[cfg(test)]
#[path = "object_storage/tests.rs"]
mod tests;
