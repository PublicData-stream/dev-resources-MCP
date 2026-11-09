use super::{
    BrokerConfig, BrokerError, Profile, Result,
    crypto::Keyring,
    format_timestamp,
    identity::{PodAuthenticator, PodIdentity},
    issuer::Issuer,
    journal::{Journal, Record},
    now, secret,
};
use futures::{StreamExt, stream};
use serde::{Deserialize, Serialize};
use sqlx_core::connection::Connection;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

/// Container credential response. Scaleway application keys have no session token.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct CredentialResponse {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub expiration: String,
}
#[derive(Clone)]
pub struct Broker {
    inner: Arc<Inner>,
}
struct Inner {
    path: PathBuf,
    baseline: BrokerConfig,
    auth: PodAuthenticator,
    issuer: Issuer,
    journal: tokio::sync::Mutex<Journal>,
    ready: AtomicBool,
}
fn valid_secret(value: &str) -> bool {
    !value.is_empty() && value.len() <= 4096 && value.bytes().all(|b| b.is_ascii_graphic())
}
fn matches(profile: &Profile, identity: &PodIdentity) -> bool {
    profile.enabled
        && profile.namespace == identity.namespace
        && profile.service_account == identity.service_account
}
impl Broker {
    pub async fn open(path: PathBuf) -> Result<Self> {
        let config = BrokerConfig::load(&path).await?;
        let auth = PodAuthenticator::new(config.authentication.clone())?;
        let cluster_uid = auth.cluster_uid().await?;
        let mut journal = Journal::connect(&secret(&config.database_url_file).await?).await?;
        if let Err(error) = journal.bind_cluster(&cluster_uid).await {
            let _ = journal.connection.close().await;
            return Err(error);
        }
        let issuer = Issuer::new(&config)?;
        issuer
            .verify_identity(&config.issuer_access_key, &config.issuer_application_id)
            .await?;
        let broker = Self {
            inner: Arc::new(Inner {
                path,
                baseline: config,
                auth,
                issuer,
                journal: tokio::sync::Mutex::new(journal),
                ready: AtomicBool::new(false),
            }),
        };
        broker.maintain().await?;
        Ok(broker)
    }
    pub fn ready(&self) -> bool {
        self.inner.ready.load(Ordering::Acquire)
    }
    async fn current(&self) -> Result<BrokerConfig> {
        let result = BrokerConfig::load(&self.inner.path).await;
        let config = match result {
            Ok(config) => config,
            Err(error) => {
                self.inner.ready.store(false, Ordering::Release);
                return Err(error);
            }
        };
        let baseline = &self.inner.baseline;
        // Endpoint, identity and secret-location changes require a controlled restart.
        if config.iam_endpoint != baseline.iam_endpoint
            || config.issuer_access_key != baseline.issuer_access_key
            || config.issuer_application_id != baseline.issuer_application_id
            || config.issuer_key_file != baseline.issuer_key_file
            || config.database_url_file != baseline.database_url_file
            || config.keyring_file != baseline.keyring_file
            || config.fixture_mode != baseline.fixture_mode
            || config.iam_ca_file != baseline.iam_ca_file
            || config.authentication.kube_api_url != baseline.authentication.kube_api_url
            || config.authentication.kube_token_file != baseline.authentication.kube_token_file
            || config.authentication.kube_ca_file != baseline.authentication.kube_ca_file
            || config.authentication.audience != baseline.authentication.audience
            || config.authentication.allow_http != baseline.authentication.allow_http
        {
            self.inner.ready.store(false, Ordering::Release);
            return Err(BrokerError::Invalid);
        }
        Ok(config)
    }
    pub async fn credentials(&self, authorization: &str) -> Result<CredentialResponse> {
        let config = self.current().await?;
        let identity = self.inner.auth.authenticate(authorization).await?;
        let profile = config
            .profiles
            .iter()
            .find(|profile| matches(profile, &identity))
            .ok_or(BrokerError::Forbidden)?;
        let fingerprint = profile.fingerprint()?;
        let keyring = Keyring::load(&config.keyring_file).await?;
        // Admission fails promptly rather than building a queue of credential issuances.
        let mut journal = self
            .inner
            .journal
            .try_lock()
            .map_err(|_| BrokerError::Capacity)?;
        let records = journal.records(config.max_issued_keys).await?;
        for row in &records {
            journal.reseal(row, &keyring).await?;
        }
        for mut row in records
            .into_iter()
            .filter(|row| row.identity.pod_uid == identity.pod_uid)
        {
            journal.reseal(&row, &keyring).await?;
            if row.state == "pending" {
                self.reconcile(&mut journal, &mut row).await?;
            } else if row.state == "revoke"
                || row.expires_at <= now()?
                || row.profile != fingerprint
                || row.identity.service_account_uid != identity.service_account_uid
            {
                self.revoke(&mut journal, &row).await?;
            }
        }
        let records = journal.records(config.max_issued_keys).await?;
        let current = now()?;
        if let Some(row) = records
            .iter()
            .filter(|row| {
                row.state == "issued"
                    && row.identity.pod_uid == identity.pod_uid
                    && row.profile == fingerprint
                    && row.expires_at > current + config.refresh_before_secs as i64
            })
            .max_by_key(|row| row.expires_at)
        {
            return decode(&journal, row, &keyring);
        }
        if records
            .iter()
            .any(|row| row.identity.pod_uid == identity.pod_uid && row.state != "issued")
        {
            // A negative list result may lag a successful create. Resolve or outlive
            // the journaled uncertainty before starting another issuance.
            return Err(BrokerError::Unavailable);
        }
        let pod_count = records
            .iter()
            .filter(|row| row.identity.pod_uid == identity.pod_uid)
            .count();
        let distinct: BTreeSet<_> = records.iter().map(|row| &row.identity.pod_uid).collect();
        if records.len() as i64 >= config.max_issued_keys
            || pod_count >= 2
            || pod_count == 0 && distinct.len() >= config.max_pods
        {
            return Err(BrokerError::Capacity);
        }
        let current = now()?;
        let expires = (current + config.ttl_secs as i64).min(identity.token_expires_at - 5);
        if expires <= current + config.refresh_before_secs as i64 + 5 {
            return Err(BrokerError::Unauthorized);
        }
        let mut row = journal
            .intent(&identity, &fingerprint, &profile.application_id, expires)
            .await?;
        let key = self
            .inner
            .issuer
            .create(
                &profile.application_id,
                &profile.default_project_id,
                &row.description,
                expires,
            )
            .await?;
        // Never delete or return an unrelated key if a provider returns malformed identity.
        if key.application_id.as_deref() != Some(profile.application_id.as_str())
            || key.description != row.description
            || !super::config::id(&key.access_key)
        {
            return Err(BrokerError::Integrity);
        }
        row.access_key = Some(key.access_key.clone());
        row.expires_at = match key.expiry() {
            Ok(value) => value,
            Err(_) => {
                self.revoke(&mut journal, &row).await?;
                return Err(BrokerError::Integrity);
            }
        };
        let within_deadline = match key.no_later_than(expires) {
            Ok(value) => value,
            Err(_) => {
                self.revoke(&mut journal, &row).await?;
                return Err(BrokerError::Integrity);
            }
        };
        let Some(secret_key) = key.secret_key else {
            self.revoke(&mut journal, &row).await?;
            return Err(BrokerError::Integrity);
        };
        if !within_deadline
            || row.expires_at <= now()? + config.refresh_before_secs as i64 + 5
            || !valid_secret(&secret_key)
        {
            self.revoke(&mut journal, &row).await?;
            return Err(BrokerError::Integrity);
        }
        let response = CredentialResponse {
            access_key_id: key.access_key,
            secret_access_key: secret_key,
            expiration: format_timestamp(row.expires_at)?,
        };
        let mut plain = serde_json::to_vec(&response).map_err(|_| BrokerError::Integrity)?;
        let result = journal.issued(&row, &keyring, &plain).await;
        plain.fill(0);
        result?;
        self.inner.ready.store(true, Ordering::Release);
        Ok(response)
    }
    async fn reconcile(&self, journal: &mut Journal, row: &mut Record) -> Result<()> {
        if let Some(key) = self
            .inner
            .issuer
            .find(&row.application_id, &row.description)
            .await?
        {
            if !super::config::id(&key.access_key) {
                return Err(BrokerError::Integrity);
            }
            row.expires_at = key
                .expiry()
                .unwrap_or(row.requested_expiry)
                .max(row.requested_expiry);
            row.access_key = Some(key.access_key);
            self.revoke(journal, row).await?;
        } else if now()? > row.requested_expiry + 60 {
            // Unknown outcomes remain reserved until the accepted maximum expiry plus skew.
            journal.revoked(&row.intent).await?;
        }
        Ok(())
    }
    async fn revoke(&self, journal: &mut Journal, row: &Record) -> Result<()> {
        journal.revoke_pending(row).await?;
        if let Some(access) = &row.access_key {
            self.inner.issuer.revoke(access).await?;
            journal.revoked(&row.intent).await?;
        }
        Ok(())
    }
    /// Reloads operator profiles/receipt/keyring and performs bounded revocation/recovery.
    pub async fn maintain(&self) -> Result<()> {
        let result = self.maintain_inner().await;
        self.inner.ready.store(result.is_ok(), Ordering::Release);
        result
    }
    async fn maintain_inner(&self) -> Result<()> {
        let config = self.current().await?;
        let keys = Keyring::load(&config.keyring_file).await?;
        let mut journal = self.inner.journal.lock().await;
        let records = journal.records(config.max_issued_keys).await?;
        // Authenticate every encrypted row before admission; old key removal fails closed.
        for row in &records {
            journal.reseal(row, &keys).await?;
        }
        if records.is_empty() {
            return Ok(());
        }
        drop(journal);
        let identities: BTreeMap<_, _> = records
            .iter()
            .filter(|row| row.state != "pending")
            .map(|row| (row.identity.pod_uid.clone(), row.identity.clone()))
            .collect();
        let checked: Vec<_> =
            stream::iter(identities.into_iter().map(|(uid, identity)| async move {
                let result = tokio::time::timeout(
                    std::time::Duration::from_secs(4),
                    self.inner.auth.validate_live(&identity),
                )
                .await;
                (
                    uid,
                    match result {
                        Ok(value) => value,
                        Err(_) => Err(BrokerError::Unavailable),
                    },
                )
            }))
            .buffer_unordered(8)
            .collect()
            .await;
        let mut failures = false;
        let mut dead = BTreeSet::new();
        for (uid, result) in checked {
            match result {
                Ok(()) => {}
                Err(BrokerError::Unauthorized) => {
                    dead.insert(uid);
                }
                Err(_) => failures = true,
            }
        }
        let mut revoked = Vec::new();
        for row in records.iter().filter(|row| row.state != "pending") {
            let mut configured = false;
            for profile in &config.profiles {
                if matches(profile, &row.identity) && profile.fingerprint()? == row.profile {
                    configured = true;
                }
            }
            if row.state == "revoke"
                || row.expires_at <= now()?
                || !configured
                || dead.contains(&row.identity.pod_uid)
            {
                revoked.push(row.clone());
            }
        }
        // Known revocations precede uncertain issuance lookups.
        if self.revoke_batch(revoked).await.is_err() {
            failures = true;
        }
        let outcomes: Vec<_> = stream::iter(
            records
                .into_iter()
                .filter(|row| row.state == "pending")
                .map(|row| async move {
                    let result = self
                        .inner
                        .issuer
                        .find(&row.application_id, &row.description)
                        .await;
                    (row, result)
                }),
        )
        .buffer_unordered(8)
        .collect()
        .await;
        let mut owned = Vec::new();
        for (mut row, result) in outcomes {
            match result {
                Ok(Some(key)) if super::config::id(&key.access_key) => {
                    row.expires_at = key
                        .expiry()
                        .unwrap_or(row.requested_expiry)
                        .max(row.requested_expiry);
                    row.access_key = Some(key.access_key);
                    owned.push(row);
                }
                Ok(None) if now()? > row.requested_expiry + 60 => {
                    self.inner.journal.lock().await.revoked(&row.intent).await?;
                }
                Ok(None) => {}
                _ => failures = true,
            }
        }
        if self.revoke_batch(owned).await.is_err() {
            failures = true;
        }
        if failures {
            Err(BrokerError::Unavailable)
        } else {
            Ok(())
        }
    }
    async fn revoke_batch(&self, rows: Vec<Record>) -> Result<()> {
        {
            let mut journal = self.inner.journal.lock().await;
            for row in &rows {
                journal.revoke_pending(row).await?;
            }
        }
        let results: Vec<_> = stream::iter(rows.into_iter().map(|row| async move {
            let result = match &row.access_key {
                Some(key) => self.inner.issuer.revoke(key).await,
                None => Err(BrokerError::Integrity),
            };
            (row.intent, result)
        }))
        .buffer_unordered(8)
        .collect()
        .await;
        let mut failures = false;
        let mut journal = self.inner.journal.lock().await;
        for (intent, result) in results {
            if result.is_ok() {
                journal.revoked(&intent).await?;
            } else {
                failures = true;
            }
        }
        if failures {
            Err(BrokerError::Unavailable)
        } else {
            Ok(())
        }
    }
}
fn decode(journal: &Journal, row: &Record, keys: &Keyring) -> Result<CredentialResponse> {
    let mut plain = keys.open(
        row.encryption_key
            .as_deref()
            .ok_or(BrokerError::Integrity)?,
        &journal.aad(row)?,
        row.ciphertext.as_deref().ok_or(BrokerError::Integrity)?,
    )?;
    let result: Result<CredentialResponse> =
        serde_json::from_slice(&plain).map_err(|_| BrokerError::Integrity);
    plain.fill(0);
    let response = result?;
    if Some(&response.access_key_id) != row.access_key.as_ref()
        || super::timestamp(&response.expiration)? != row.expires_at
        || !valid_secret(&response.secret_access_key)
    {
        return Err(BrokerError::Integrity);
    }
    Ok(response)
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
