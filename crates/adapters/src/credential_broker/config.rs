use super::identity::AuthConfig;
use super::{BrokerError, Result, endpoint, path_valid, read_bounded};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Readonly,
    Readwrite,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub namespace: String,
    pub service_account: String,
    pub application_id: String,
    pub default_project_id: String,
    pub bucket: String,
    pub prefix: String,
    pub role: Role,
    /// Digest of the operator's exact admitted IAM and bucket policy documents.
    pub policy_fingerprint: String,
    #[serde(default = "yes")]
    pub enabled: bool,
}
fn yes() -> bool {
    true
}
fn ttl() -> u64 {
    900
}
fn refresh() -> u64 {
    300
}
fn pods() -> usize {
    16
}
fn budget() -> i64 {
    32
}
fn reserve() -> i64 {
    8
}
fn iam() -> String {
    "https://api.scaleway.com".into()
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerConfig {
    pub bind: SocketAddr,
    pub tls_certificate_file: PathBuf,
    pub tls_private_key_file: PathBuf,
    pub database_url_file: PathBuf,
    pub keyring_file: PathBuf,
    pub issuer_key_file: PathBuf,
    pub issuer_access_key: String,
    pub issuer_application_id: String,
    pub acceptance_receipt_file: PathBuf,
    pub authentication: AuthConfig,
    #[serde(default = "iam")]
    pub iam_endpoint: String,
    pub iam_ca_file: Option<PathBuf>,
    #[serde(default)]
    pub fixture_mode: bool,
    #[serde(default = "ttl")]
    pub ttl_secs: u64,
    #[serde(default = "refresh")]
    pub refresh_before_secs: u64,
    #[serde(default = "pods")]
    pub max_pods: usize,
    /// All journaled issued keys and unresolved issuance attempts count.
    #[serde(default = "budget")]
    pub max_issued_keys: i64,
    #[serde(default = "reserve")]
    pub quota_reserve: i64,
    pub profiles: Vec<Profile>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Receipt {
    pub issuer_access_key: String,
    pub issuer_application_id: String,
    pub issuer_secret_fingerprint: String,
    pub profile_fingerprints: BTreeMap<String, String>,
    pub confined_application_ids: BTreeSet<String>,
    pub verified_at: String,
    pub expires_at: String,
    pub broker_key_budget: i64,
    pub ttl_secs: u64,
    pub unrelated_application_denied: bool,
    pub policy_management_denied: bool,
    pub expiry_accepted: bool,
    #[serde(default)]
    pub fixture: bool,
}
pub(crate) fn id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}
pub(crate) fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}
impl Profile {
    pub fn fingerprint(&self) -> Result<String> {
        let value = serde_json::json!({"application_id":self.application_id,"default_project_id":self.default_project_id,
            "bucket":self.bucket,"prefix":self.prefix,"role":self.role,"policy_fingerprint":self.policy_fingerprint});
        Ok(
            blake3::hash(&serde_json::to_vec(&value).map_err(|_| BrokerError::Invalid)?)
                .to_hex()
                .to_string(),
        )
    }
}
impl BrokerConfig {
    pub async fn issuer_secret_fingerprint(&self) -> Result<String> {
        Ok(
            blake3::hash(super::secret(&self.issuer_key_file).await?.as_bytes())
                .to_hex()
                .to_string(),
        )
    }
    /// Parse non-secret configuration for offline policy fingerprint generation.
    pub async fn read(path: &Path) -> Result<Self> {
        let bytes = read_bounded(path, 65536).await?;
        let config: Self =
            toml::from_str(std::str::from_utf8(&bytes).map_err(|_| BrokerError::Invalid)?)
                .map_err(|_| BrokerError::Invalid)?;
        config.validate()?;
        Ok(config)
    }
    pub async fn load(path: &Path) -> Result<Self> {
        let config = Self::read(path).await?;
        config.receipt().await?;
        Ok(config)
    }
    pub fn validate(&self) -> Result<()> {
        if self.bind.port() == 0
            || !(60..=3600).contains(&self.ttl_secs)
            || !(10..=300).contains(&self.refresh_before_secs)
            || self.refresh_before_secs >= self.ttl_secs / 2
            || !(1..=256).contains(&self.max_pods)
            || self.max_issued_keys < 2
            || self.max_issued_keys > 32
            || self.quota_reserve < 1
            || self.quota_reserve > 10000
            || self.max_issued_keys < self.max_pods as i64 * 2
            || self.profiles.is_empty()
            || self.profiles.len() > 128
            || !id(&self.issuer_access_key)
            || !uuid(&self.issuer_application_id)
        {
            return Err(BrokerError::Invalid);
        }
        for path in [
            &self.tls_certificate_file,
            &self.tls_private_key_file,
            &self.database_url_file,
            &self.keyring_file,
            &self.issuer_key_file,
            &self.acceptance_receipt_file,
        ] {
            path_valid(path)?;
        }
        let issuer_url = endpoint(&self.iam_endpoint, self.fixture_mode)?;
        if self.fixture_mode {
            let private = match issuer_url.host() {
                Some(url::Host::Domain(host)) => host == "localhost" || host == "iam-fixture",
                Some(url::Host::Ipv4(ip)) => ip.is_loopback() || ip.is_private(),
                Some(url::Host::Ipv6(ip)) => ip.is_loopback() || ip.is_unique_local(),
                None => false,
            };
            if !private
                || self.profiles.iter().any(|p| {
                    p.namespace != "devres-acceptance" && !p.namespace.starts_with("devres-test-")
                })
            {
                return Err(BrokerError::Invalid);
            }
        }
        if !self.fixture_mode
            && (self.iam_endpoint.trim_end_matches('/') != "https://api.scaleway.com"
                || self.authentication.allow_http)
        {
            return Err(BrokerError::Invalid);
        }
        let mut accounts = BTreeSet::new();
        let mut applications = BTreeMap::new();
        for profile in &self.profiles {
            if !id(&profile.namespace)
                || !id(&profile.service_account)
                || !uuid(&profile.application_id)
                || !uuid(&profile.default_project_id)
                || profile.application_id == self.issuer_application_id
                || profile.bucket.len() < 3
                || profile.bucket.len() > 63
                || !id(&profile.bucket)
                || profile.prefix.is_empty()
                || profile.prefix.len() > 512
                || profile.prefix.starts_with('/')
                || profile
                    .prefix
                    .split('/')
                    .any(|p| !id(p) || p == "." || p == "..")
                || profile.policy_fingerprint.len() != 64
                || !profile
                    .policy_fingerprint
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit())
                || !accounts.insert((&profile.namespace, &profile.service_account))
            {
                return Err(BrokerError::Invalid);
            }
            let fingerprint = profile.fingerprint()?;
            if applications
                .insert(&profile.application_id, fingerprint.clone())
                .is_some_and(|old| old != fingerprint)
            {
                return Err(BrokerError::Invalid);
            }
        }
        Ok(())
    }
    pub(crate) async fn receipt(&self) -> Result<Receipt> {
        let receipt: Receipt =
            serde_json::from_slice(&read_bounded(&self.acceptance_receipt_file, 65536).await?)
                .map_err(|_| BrokerError::Invalid)?;
        let applications: BTreeSet<_> = self
            .profiles
            .iter()
            .map(|p| p.application_id.clone())
            .collect();
        let fingerprints: BTreeMap<_, _> = self
            .profiles
            .iter()
            .map(|p| Ok((p.application_id.clone(), p.fingerprint()?)))
            .collect::<Result<_>>()?;
        let now = super::now()?;
        if receipt.fixture != self.fixture_mode
            || receipt.issuer_access_key != self.issuer_access_key
            || receipt.issuer_application_id != self.issuer_application_id
            || receipt.issuer_secret_fingerprint
                != blake3::hash(super::secret(&self.issuer_key_file).await?.as_bytes())
                    .to_hex()
                    .as_str()
            || receipt.confined_application_ids != applications
            || receipt.profile_fingerprints != fingerprints
            || !receipt.unrelated_application_denied
            || !receipt.policy_management_denied
            || !receipt.expiry_accepted
            || receipt.broker_key_budget < self.max_issued_keys + self.quota_reserve
            || receipt.ttl_secs != self.ttl_secs
            || super::timestamp(&receipt.expires_at)? <= now
            || super::timestamp(&receipt.verified_at)? > now
            || super::timestamp(&receipt.verified_at)? < now - 31 * 86400
        {
            return Err(BrokerError::Forbidden);
        }
        Ok(receipt)
    }
}
