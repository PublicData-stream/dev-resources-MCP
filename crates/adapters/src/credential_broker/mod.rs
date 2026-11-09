//! Private workload identity and expiring Object Storage credentials.
//! This module never participates in public MCP routing or corpus persistence.
mod config;
mod crypto;
pub mod identity;
mod issuer;
mod journal;
mod service;

pub use config::{BrokerConfig, Profile, Role};
pub use service::{Broker, CredentialResponse};

use std::{fmt, path::Path, time::Duration};
use tokio::io::AsyncReadExt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerError {
    Invalid,
    Unauthorized,
    Forbidden,
    Capacity,
    Unavailable,
    Integrity,
}
impl fmt::Display for BrokerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Invalid => "Invalid credential broker configuration or request.",
            Self::Unauthorized => "Workload identity rejected.",
            Self::Forbidden => "Workload access denied.",
            Self::Capacity => "Credential broker capacity unavailable.",
            Self::Unavailable => "Credential broker unavailable.",
            Self::Integrity => "Credential broker integrity verification failed.",
        })
    }
}
impl std::error::Error for BrokerError {}
pub type Result<T> = std::result::Result<T, BrokerError>;

pub(crate) fn now() -> Result<i64> {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| BrokerError::Unavailable)?
            .as_secs(),
    )
    .map_err(|_| BrokerError::Unavailable)
}
pub(crate) fn timestamp(value: &str) -> Result<i64> {
    aws_smithy_types::DateTime::from_str(value, aws_smithy_types::date_time::Format::DateTime)
        .map(|time| time.secs())
        .map_err(|_| BrokerError::Integrity)
}
pub(crate) fn format_timestamp(value: i64) -> Result<String> {
    aws_smithy_types::DateTime::from_secs(value)
        .fmt(aws_smithy_types::date_time::Format::DateTime)
        .map_err(|_| BrokerError::Integrity)
}
pub(crate) fn random_id() -> Result<String> {
    use ring::rand::SecureRandom;
    let mut bytes = [0_u8; 24];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| BrokerError::Unavailable)?;
    Ok(hex::encode(bytes))
}
pub(crate) fn path_valid(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path.components().any(|part| {
            matches!(
                part,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err(BrokerError::Invalid);
    }
    Ok(())
}
pub(crate) async fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    path_valid(path)?;
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|_| BrokerError::Unavailable)?;
    if !file
        .metadata()
        .await
        .map_err(|_| BrokerError::Unavailable)?
        .is_file()
    {
        return Err(BrokerError::Invalid);
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| BrokerError::Unavailable)?;
    if bytes.len() > limit {
        return Err(BrokerError::Invalid);
    }
    Ok(bytes)
}
pub(crate) async fn secret(path: &Path) -> Result<String> {
    let value =
        String::from_utf8(read_bounded(path, 65536).await?).map_err(|_| BrokerError::Invalid)?;
    let value = value.trim_end_matches(['\r', '\n']);
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(BrokerError::Invalid);
    }
    Ok(value.to_owned())
}
pub(crate) fn endpoint(value: &str, allow_http: bool) -> Result<url::Url> {
    let url = url::Url::parse(value).map_err(|_| BrokerError::Invalid)?;
    if !(url.scheme() == "https" || allow_http && url.scheme() == "http")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(BrokerError::Invalid);
    }
    Ok(url)
}
pub(crate) fn client(ca_file: Option<&Path>) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(8));
    if let Some(path) = ca_file {
        path_valid(path)?;
        if std::fs::metadata(path)
            .map_err(|_| BrokerError::Unavailable)?
            .len()
            > 1024 * 1024
        {
            return Err(BrokerError::Invalid);
        }
        let bytes = std::fs::read(path).map_err(|_| BrokerError::Unavailable)?;
        let certs =
            reqwest::Certificate::from_pem_bundle(&bytes).map_err(|_| BrokerError::Invalid)?;
        if certs.is_empty() {
            return Err(BrokerError::Invalid);
        }
        for cert in certs {
            builder = builder.add_root_certificate(cert);
        }
    }
    builder.build().map_err(|_| BrokerError::Invalid)
}
pub(crate) async fn response_bytes(mut response: reqwest::Response) -> Result<Vec<u8>> {
    if !response.status().is_success() {
        return Err(BrokerError::Unavailable);
    }
    if response.content_length().is_some_and(|n| n > 262144) {
        return Err(BrokerError::Capacity);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| BrokerError::Unavailable)?
    {
        if bytes.len().saturating_add(chunk.len()) > 262144 {
            return Err(BrokerError::Capacity);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
