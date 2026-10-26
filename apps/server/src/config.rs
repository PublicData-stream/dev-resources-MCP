// Generic validation adapted from OpenLegal 7a592e0c7b1ef1518bd9ab47788a4e03697f3e63 (AGPL-3.0-only).
//! Explicit configuration and resource policy for both transports.

use crate::ServerError;
use serde::Deserialize;
use std::{net::SocketAddr, path::PathBuf};

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub max_message_bytes: usize,
    /// Omitted values retain the message-relative tool output budget.
    pub max_tool_result_bytes: Option<usize>,
    pub max_buffer_bytes: usize,
    pub max_in_flight: usize,
    pub max_connections: usize,
    pub max_calls_per_connection: usize,
    pub io_timeout_secs: u64,
    pub call_timeout_secs: u64,
    pub idle_timeout_secs: u64,
    pub shutdown_timeout_secs: u64,
    pub rate_limit: RateLimitConfig,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub calls_per_second: u32,
    pub burst: u32,
    pub verified_tunnel: Option<VerifiedTunnelRateLimitConfig>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedTunnelRateLimitConfig {
    pub calls_per_second: u32,
    pub burst: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            calls_per_second: 100,
            burst: 100,
            verified_tunnel: None,
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_message_bytes: 8 * 1024 * 1024,
            max_tool_result_bytes: Some(256 * 1024),
            max_buffer_bytes: 64 * 1024 * 1024,
            max_in_flight: 32,
            max_connections: 128,
            max_calls_per_connection: 8,
            io_timeout_secs: 10,
            call_timeout_secs: 30,
            idle_timeout_secs: 60,
            shutdown_timeout_secs: 15,
            rate_limit: RateLimitConfig::default(),
        }
    }
}

impl Limits {
    pub fn tool_result_limit(&self) -> usize {
        self.max_tool_result_bytes
            .unwrap_or(self.max_message_bytes / 8)
    }

    pub fn validate(&self) -> Result<(), ServerError> {
        if !(4096..=16 * 1024 * 1024).contains(&self.max_message_bytes)
            || self
                .max_tool_result_bytes
                .is_some_and(|value| value == 0 || value > self.max_message_bytes / 8)
            || self.max_buffer_bytes < self.max_message_bytes * 4
            || self.max_buffer_bytes > u32::MAX as usize
            || self.max_in_flight == 0
            || self.max_in_flight > 128_000
            || self.max_connections == 0
            || self.max_connections > 256_000
            || self.max_calls_per_connection == 0
            || self.max_calls_per_connection > self.max_in_flight
            || !(1..=200_000).contains(&self.rate_limit.calls_per_second)
            || !(1..=200_000).contains(&self.rate_limit.burst)
            || self
                .rate_limit
                .verified_tunnel
                .as_ref()
                .is_some_and(|override_config| {
                    !(1..=200_000).contains(&override_config.calls_per_second)
                        || !(1..=200_000).contains(&override_config.burst)
                })
            || [
                self.io_timeout_secs,
                self.call_timeout_secs,
                self.idle_timeout_secs,
                self.shutdown_timeout_secs,
            ]
            .iter()
            .any(|v| *v == 0 || *v > 86400)
        {
            return Err("invalid resource limits".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessPolicy {
    pub allowed_hosts: Vec<String>,
    pub allowed_origins: Vec<String>,
}

impl AccessPolicy {
    pub fn validate(&self) -> Result<(), ServerError> {
        if self.allowed_hosts.is_empty()
            || self
                .allowed_hosts
                .iter()
                .any(|host| host.parse::<http::uri::Authority>().is_err() || host.contains('@'))
        {
            return Err("configure explicit allowed host authorities".into());
        }
        if self
            .allowed_origins
            .iter()
            .any(|origin| normalized_origin(origin).is_none())
        {
            return Err("allowed origins must be HTTP(S) origins without paths".into());
        }
        Ok(())
    }

    /// Native clients may omit Origin. An empty origin allowlist rejects every present Origin.
    pub fn permits(&self, authority: &str, origin: Option<&str>) -> bool {
        self.allowed_hosts
            .iter()
            .any(|host| host.eq_ignore_ascii_case(authority))
            && origin.is_none_or(|origin| {
                normalized_origin(origin).is_some_and(|normalized| {
                    self.allowed_origins
                        .iter()
                        .any(|allowed| normalized_origin(allowed).as_ref() == Some(&normalized))
                })
            })
    }
}

fn normalized_origin(value: &str) -> Option<String> {
    let parsed = url::Url::parse(value).ok()?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return None;
    }
    Some(parsed.origin().ascii_serialization())
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpConfig {
    pub bind: SocketAddr,
    pub allowed_hosts: Vec<String>,
    pub allowed_origins: Vec<String>,
    #[serde(default)]
    pub tls: Option<HttpTlsConfig>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpTlsConfig {
    pub certificate: PathBuf,
    pub private_key: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeMtlsConfig {
    pub client_ca_file: PathBuf,
    pub required_client_dns_san: String,
}

impl EdgeMtlsConfig {
    pub fn validate(&self) -> Result<(), ServerError> {
        let name = self.required_client_dns_san.as_str();
        if name.is_empty()
            || name.len() > 253
            || name.starts_with('.')
            || name.ends_with('.')
            || name.parse::<std::net::IpAddr>().is_ok()
            || name.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            })
        {
            return Err("edge mTLS requires an exact DNS SAN".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebTransportConfig {
    pub bind: SocketAddr,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub allowed_hosts: Vec<String>,
    pub allowed_origins: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthConfig {
    pub bind: SocketAddr,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct SourceOffer(String);

impl SourceOffer {
    pub const MAX_URL_BYTES: usize = 2048;
    pub const LICENSE: &str = "AGPL-3.0-only";
    pub const LICENSE_URL: &str = "https://www.gnu.org/licenses/agpl-3.0.html";

    /// Require an explicit absolute HTTPS destination without embedded credentials.
    /// Both input and normalized output are bounded, including percent-encoding expansion.
    pub fn new(value: &str) -> Result<Self, ServerError> {
        if value.len() > Self::MAX_URL_BYTES
            || value.chars().any(char::is_control)
            || value.trim() != value
            || value.contains('\\')
        {
            return Err("source URL exceeds its limit or contains control characters".into());
        }
        let (scheme, rest) = value
            .split_once("://")
            .ok_or("source URL must be absolute HTTPS")?;
        let authority = rest.split(['/', '?', '#', '\\']).next().unwrap_or_default();
        let parsed = url::Url::parse(value).map_err(|_| "invalid source URL")?;
        if !scheme.eq_ignore_ascii_case("https")
            || parsed.scheme() != "https"
            || authority.is_empty()
            || authority.contains('@')
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.as_str().len() > Self::MAX_URL_BYTES
        {
            return Err("source URL must be absolute HTTPS with a host and no credentials".into());
        }
        Ok(Self(parsed.into()))
    }

    pub fn url(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for SourceOffer {
    type Error = ServerError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(&value)
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceConfig {
    pub url: SourceOffer,
}

/// Secrets are read from an operator-controlled TOML file, never logged.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    pub database_url: String,
    pub blob_dir: PathBuf,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub source: SourceConfig,
    pub http: HttpConfig,
    pub webtransport: WebTransportConfig,
    pub health: HealthConfig,
    pub storage: StorageConfig,
    pub edge_mtls: Option<EdgeMtlsConfig>,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub rfc: devres_adapters::RfcConfig,
    #[serde(default)]
    pub crates: devres_adapters::CrateConfig,
    #[serde(default)]
    pub rustsec: devres_adapters::RustSecConfig,
    #[serde(default)]
    pub mdn: devres_adapters::MdnConfig,
    #[serde(default)]
    pub whatwg: devres_adapters::WhatwgConfig,
}
impl Config {
    pub fn validate(&self) -> Result<(), ServerError> {
        self.limits.validate()?;
        self.rfc.validate()?;
        self.crates.validate()?;
        self.rustsec.validate()?;
        self.mdn.validate()?;
        self.whatwg.validate()?;
        for access in [
            AccessPolicy {
                allowed_hosts: self.http.allowed_hosts.clone(),
                allowed_origins: self.http.allowed_origins.clone(),
            },
            AccessPolicy {
                allowed_hosts: self.webtransport.allowed_hosts.clone(),
                allowed_origins: self.webtransport.allowed_origins.clone(),
            },
        ] {
            access.validate()?;
        }
        if let Some(mtls) = &self.edge_mtls {
            mtls.validate()?;
            if self.http.tls.is_none() {
                return Err("edge mTLS requires HTTP TLS".into());
            }
        }
        if self.limits.rate_limit.verified_tunnel.is_some() && self.edge_mtls.is_none() {
            return Err("verified tunnel limits require edge mTLS".into());
        }
        if self.storage.database_url.is_empty() || self.storage.blob_dir.as_os_str().is_empty() {
            return Err("storage paths and database URL must be nonempty".into());
        }
        Ok(())
    }
    pub async fn load(path: &std::path::Path) -> Result<Self, ServerError> {
        use tokio::io::AsyncReadExt;
        let mut bytes = Vec::new();
        tokio::fs::File::open(path)
            .await?
            .take(64 * 1024 + 1)
            .read_to_end(&mut bytes)
            .await?;
        if bytes.len() > 64 * 1024 {
            return Err("configuration exceeds limit".into());
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| "configuration must be UTF-8")?;
        let config: Self = toml::from_str(text).map_err(|_| "invalid server configuration")?;
        config.validate()?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strict_source_and_origin_validation() {
        for invalid in [
            "http://source.test",
            "https://user:secret@source.test",
            " https://source.test",
            "https://source.test\\bad",
        ] {
            assert!(SourceOffer::new(invalid).is_err());
        }
        let access = AccessPolicy {
            allowed_hosts: vec!["backend:8080".into()],
            allowed_origins: vec!["https://client.test".into()],
        };
        assert!(access.validate().is_ok());
        assert!(access.permits("BACKEND:8080", None));
        assert!(access.permits("backend:8080", Some("https://client.test")));
        assert!(!access.permits("evil.test", None));
        assert!(!access.permits("backend:8080", Some("https://evil.test")));
    }
    #[test]
    fn reject_zero_or_overcommitted_limits() {
        let mut limits = Limits::default();
        assert!(limits.validate().is_ok());
        limits.max_in_flight = 0;
        assert!(limits.validate().is_err());
        limits = Limits::default();
        limits.max_buffer_bytes = 1;
        assert!(limits.validate().is_err());
    }
    #[test]
    fn crate_collection_defaults_and_pause_configuration_are_explicit() {
        let defaults: devres_adapters::CrateConfig = toml::from_str("").unwrap();
        assert!(defaults.enabled);
        assert_eq!(defaults.index_refresh_secs, 3600);
        assert_eq!(defaults.static_requests_per_second, 5);
        assert_eq!(defaults.index_requests_per_second, 1);
        defaults.validate().unwrap();
        let paused: devres_adapters::CrateConfig = toml::from_str("enabled=false").unwrap();
        assert!(!paused.enabled);
        paused.validate().unwrap();
        assert!(
            toml::from_str::<devres_adapters::CrateConfig>(
                "arbitrary_url='https://private.invalid'"
            )
            .is_err()
        );
        for bad in [
            "index_refresh_secs=0",
            "max_bulk_transfers=0",
            "index_requests_per_second=0",
            "min_free_bytes=1",
        ] {
            assert!(
                toml::from_str::<devres_adapters::CrateConfig>(bad)
                    .unwrap()
                    .validate()
                    .is_err()
            );
        }
    }
    #[tokio::test]
    async fn invalid_config_never_echoes_credential_bearing_input() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        tokio::fs::write(
            temp.path(),
            "[storage]\ndatabase_url = 'postgres://user:PRIVATE_SENTINEL@db/devres'\ninvalid = [",
        )
        .await
        .unwrap();
        let error = match Config::load(temp.path()).await {
            Ok(_) => panic!("invalid config accepted"),
            Err(error) => error,
        };
        assert_eq!(error.to_string(), "invalid server configuration");
        assert!(!error.to_string().contains("PRIVATE_SENTINEL"));
        tokio::fs::write(temp.path(), vec![b'a'; 64 * 1024 + 1])
            .await
            .unwrap();
        let error = match Config::load(temp.path()).await {
            Ok(_) => panic!("oversized config accepted"),
            Err(error) => error,
        };
        assert_eq!(error.to_string(), "configuration exceeds limit");
    }
}
