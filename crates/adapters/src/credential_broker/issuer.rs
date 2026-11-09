//! Scaleway application keys; each create is attempted exactly once.
use super::{
    BrokerError, Result, client, config::BrokerConfig, format_timestamp, response_bytes, secret,
    timestamp,
};
use serde::Deserialize;
use std::{sync::Arc, time::Duration};

#[derive(Deserialize)]
pub(crate) struct RemoteKey {
    pub access_key: String,
    pub secret_key: Option<String>,
    pub application_id: Option<String>,
    pub expires_at: Option<String>,
    pub description: String,
}
impl RemoteKey {
    pub fn expiry(&self) -> Result<i64> {
        timestamp(self.expires_at.as_deref().ok_or(BrokerError::Integrity)?)
    }
    pub fn no_later_than(&self, deadline: i64) -> Result<bool> {
        let expiry = aws_smithy_types::DateTime::from_str(
            self.expires_at.as_deref().ok_or(BrokerError::Integrity)?,
            aws_smithy_types::date_time::Format::DateTime,
        )
        .map_err(|_| BrokerError::Integrity)?;
        Ok(expiry <= aws_smithy_types::DateTime::from_secs(deadline))
    }
}
#[derive(Clone)]
pub(crate) struct Issuer {
    endpoint: String,
    key_file: std::path::PathBuf,
    client: reqwest::Client,
    next: Arc<tokio::sync::Mutex<tokio::time::Instant>>,
    receipt_file: std::path::PathBuf,
    issuer_access_key: String,
    issuer_application_id: String,
    organization_id: String,
    fixture_mode: bool,
}
impl Issuer {
    pub fn new(config: &BrokerConfig) -> Result<Self> {
        Ok(Self {
            endpoint: config.iam_endpoint.trim_end_matches('/').into(),
            key_file: config.issuer_key_file.clone(),
            client: client(config.iam_ca_file.as_deref())?,
            next: Arc::new(tokio::sync::Mutex::new(tokio::time::Instant::now())),
            receipt_file: config.acceptance_receipt_file.clone(),
            issuer_access_key: config.issuer_access_key.clone(),
            issuer_application_id: config.issuer_application_id.clone(),
            organization_id: config.organization_id.clone(),
            fixture_mode: config.fixture_mode,
        })
    }
    async fn request(
        &self,
        method: reqwest::Method,
        path: &str,
    ) -> Result<reqwest::RequestBuilder> {
        // One owner for pacing; the HTTP client never retries a create.
        let mut next = self.next.lock().await;
        tokio::time::sleep_until(*next).await;
        *next = tokio::time::Instant::now() + Duration::from_secs(1);
        let key = secret(&self.key_file).await?;
        let receipt: super::config::Receipt =
            serde_json::from_slice(&super::read_bounded(&self.receipt_file, 65536).await?)
                .map_err(|_| BrokerError::Forbidden)?;
        let current = super::now()?;
        if receipt.issuer_secret_fingerprint != blake3::hash(key.as_bytes()).to_hex().as_str()
            || receipt.issuer_access_key != self.issuer_access_key
            || receipt.issuer_application_id != self.issuer_application_id
            || receipt.fixture != self.fixture_mode
            || !receipt.unrelated_application_denied
            || !receipt.policy_management_denied
            || !receipt.expiry_accepted
            || timestamp(&receipt.expires_at)? <= current
            || timestamp(&receipt.verified_at)? > current
            || timestamp(&receipt.verified_at)? < current - 31 * 86400
        {
            return Err(BrokerError::Forbidden);
        }
        Ok(self
            .client
            .request(method, format!("{}{path}", self.endpoint))
            .header("X-Auth-Token", key))
    }
    pub async fn verify_identity(&self, access_key: &str, application_id: &str) -> Result<()> {
        if !super::config::id(access_key) {
            return Err(BrokerError::Invalid);
        }
        let response = self
            .request(
                reqwest::Method::GET,
                &format!("/iam/v1alpha1/api-keys/{access_key}"),
            )
            .await?
            .send()
            .await
            .map_err(|_| BrokerError::Unavailable)?;
        let key: RemoteKey = serde_json::from_slice(&response_bytes(response).await?)
            .map_err(|_| BrokerError::Integrity)?;
        if key.access_key != access_key || key.application_id.as_deref() != Some(application_id) {
            return Err(BrokerError::Forbidden);
        }
        Ok(())
    }
    pub async fn create(
        &self,
        application_id: &str,
        project_id: &str,
        description: &str,
        expires: i64,
    ) -> Result<RemoteKey> {
        let body=serde_json::to_vec(&serde_json::json!({"application_id":application_id,
            "default_project_id":project_id,"description":description,"expires_at":format_timestamp(expires)?}))
            .map_err(|_|BrokerError::Invalid)?;
        let response = self
            .request(reqwest::Method::POST, "/iam/v1alpha1/api-keys")
            .await?
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|_| BrokerError::Unavailable)?;
        serde_json::from_slice(&response_bytes(response).await?).map_err(|_| BrokerError::Integrity)
    }
    pub async fn find(&self, application_id: &str, description: &str) -> Result<Option<RemoteKey>> {
        let mut url =
            url::Url::parse("https://fixture.invalid/").map_err(|_| BrokerError::Invalid)?;
        url.query_pairs_mut().extend_pairs([
            ("organization_id", self.organization_id.as_str()),
            ("bearer_id", application_id),
            ("description", description),
            ("page_size", "100"),
            ("page", "1"),
        ]);
        let path = format!(
            "/iam/v1alpha1/api-keys?{}",
            url.query().ok_or(BrokerError::Invalid)?
        );
        let response = self
            .request(reqwest::Method::GET, &path)
            .await?
            .send()
            .await
            .map_err(|_| BrokerError::Unavailable)?;
        #[derive(Deserialize)]
        struct List {
            api_keys: Vec<RemoteKey>,
            total_count: u64,
        }
        let result: List = serde_json::from_slice(&response_bytes(response).await?)
            .map_err(|_| BrokerError::Integrity)?;
        if result.total_count > 100 || result.api_keys.len() > 100 {
            return Err(BrokerError::Capacity);
        }
        let mut found = None;
        for key in result.api_keys {
            if key.application_id.as_deref() == Some(application_id)
                && key.description == description
            {
                if found.is_some() {
                    return Err(BrokerError::Integrity);
                }
                found = Some(key);
            }
        }
        Ok(found)
    }
    pub async fn revoke(&self, access_key: &str) -> Result<()> {
        if !super::config::id(access_key) {
            return Err(BrokerError::Integrity);
        }
        let response = self
            .request(
                reqwest::Method::DELETE,
                &format!("/iam/v1alpha1/api-keys/{access_key}"),
            )
            .await?
            .send()
            .await
            .map_err(|_| BrokerError::Unavailable)?;
        if response.status().is_success() || response.status() == reqwest::StatusCode::NOT_FOUND {
            Ok(())
        } else {
            Err(BrokerError::Unavailable)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn organization_scoped_find_preserves_encoding_and_response_bounds() {
        use axum::{
            Json, Router,
            extract::{Query, State},
            routing::get,
        };
        use std::{
            collections::BTreeMap,
            sync::atomic::{AtomicUsize, Ordering},
        };

        const ORGANIZATION: &str = "55555555-5555-4555-8555-555555555555";
        const APPLICATION: &str = "11111111-1111-4111-8111-111111111111";
        const DESCRIPTION: &str = "owned & description=/한글?";
        async fn list(
            State(mode): State<Arc<AtomicUsize>>,
            Query(query): Query<Vec<(String, String)>>,
        ) -> Json<serde_json::Value> {
            assert_eq!(query.len(), 5);
            let query: BTreeMap<_, _> = query.into_iter().collect();
            assert_eq!(
                query,
                BTreeMap::from([
                    ("organization_id".into(), ORGANIZATION.into()),
                    ("bearer_id".into(), APPLICATION.into()),
                    ("description".into(), DESCRIPTION.into()),
                    ("page_size".into(), "100".into()),
                    ("page".into(), "1".into()),
                ])
            );
            let key = serde_json::json!({"access_key":"owned-key", "application_id":APPLICATION,
                "description":DESCRIPTION, "expires_at":"2026-11-09T12:00:00Z"});
            let (keys, count) = match mode.load(Ordering::Relaxed) {
                0 => (vec![key], 1),
                1 => (vec![key.clone(), key], 2),
                2 => (vec![], 101),
                3 => (vec![key; 101], 100),
                _ => (vec![], 0),
            };
            Json(serde_json::json!({"api_keys":keys,"total_count":count}))
        }
        let temp = tempfile::tempdir_in("/tmp").expect("test directory");
        let mode = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route("/iam/v1alpha1/api-keys", get(list))
            .with_state(mode.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let mut config = super::super::config::tests::configuration();
        config.organization_id = ORGANIZATION.into();
        config.iam_endpoint = format!("http://{}", listener.local_addr().expect("address"));
        config.fixture_mode = true;
        config.issuer_key_file = temp.path().join("issuer");
        config.acceptance_receipt_file = temp.path().join("receipt");
        tokio::fs::write(&config.issuer_key_file, "synthetic-issuer-secret")
            .await
            .expect("secret file");
        let now = super::super::now().expect("time");
        let receipt = serde_json::json!({
            "issuer_access_key":config.issuer_access_key,
            "issuer_application_id":config.issuer_application_id,
            "issuer_secret_fingerprint":config.issuer_secret_fingerprint().await.expect("fingerprint"),
            "profile_fingerprints":{}, "confined_application_ids":[],
            "verified_at":format_timestamp(now).expect("timestamp"),
            "expires_at":format_timestamp(now+3600).expect("timestamp"),
            "broker_key_budget":40,"ttl_secs":900,
            "unrelated_application_denied":true,"policy_management_denied":true,
            "expiry_accepted":true,"fixture":true,
        });
        tokio::fs::write(
            &config.acceptance_receipt_file,
            serde_json::to_vec(&receipt).expect("receipt"),
        )
        .await
        .expect("receipt file");
        let server = tokio::spawn(async move { axum::serve(listener, app).await });
        let issuer = Issuer::new(&config).expect("issuer");
        assert_eq!(
            issuer
                .find(APPLICATION, DESCRIPTION)
                .await
                .expect("matching key")
                .expect("key")
                .access_key,
            "owned-key"
        );
        for (value, expected) in [
            (1, BrokerError::Integrity),
            (2, BrokerError::Capacity),
            (3, BrokerError::Capacity),
        ] {
            mode.store(value, Ordering::Relaxed);
            assert!(
                matches!(issuer.find(APPLICATION, DESCRIPTION).await, Err(error) if error == expected)
            );
        }
        mode.store(4, Ordering::Relaxed);
        assert!(
            issuer
                .find(APPLICATION, DESCRIPTION)
                .await
                .expect("empty list")
                .is_none()
        );
        server.abort();
        let _ = server.await;
    }

    #[test]
    fn credential_deadline_comparison_does_not_round_away_excess_lifetime() {
        let key = RemoteKey {
            access_key: "key".into(),
            secret_key: Some("secret".into()),
            application_id: Some("app".into()),
            expires_at: Some("2026-11-09T12:00:00.001Z".into()),
            description: "owned".into(),
        };
        let second = timestamp("2026-11-09T12:00:00Z").expect("timestamp");
        assert!(!key.no_later_than(second).expect("comparison"));
        assert!(key.no_later_than(second + 1).expect("comparison"));
    }
}
