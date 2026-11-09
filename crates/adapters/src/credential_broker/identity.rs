//! Audience-bound Kubernetes TokenReview and live pod/ServiceAccount validation.
use super::{BrokerError, Result, client, endpoint, now, path_valid, response_bytes, secret};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::PathBuf, sync::Arc, time::Duration};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    pub kube_api_url: String,
    pub kube_token_file: PathBuf,
    pub kube_ca_file: Option<PathBuf>,
    pub audience: String,
    #[serde(default)]
    pub allow_http: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PodIdentity {
    pub namespace: String,
    pub service_account: String,
    pub service_account_uid: String,
    pub pod_name: String,
    pub pod_uid: String,
    pub token_expires_at: i64,
}
#[derive(Clone)]
pub struct PodAuthenticator {
    config: AuthConfig,
    client: reqwest::Client,
    permits: Arc<tokio::sync::Semaphore>,
}
#[derive(Deserialize)]
struct Review {
    status: ReviewStatus,
}
#[derive(Deserialize)]
struct ReviewStatus {
    #[serde(default)]
    authenticated: bool,
    #[serde(default)]
    audiences: Vec<String>,
    user: Option<User>,
}
#[derive(Deserialize)]
struct User {
    username: String,
    uid: String,
    #[serde(default)]
    extra: BTreeMap<String, Vec<String>>,
}
#[derive(Deserialize)]
struct Metadata {
    uid: String,
    name: String,
    namespace: String,
    #[serde(rename = "deletionTimestamp")]
    deletion_timestamp: Option<String>,
}
#[derive(Deserialize)]
struct Pod {
    metadata: Metadata,
    spec: PodSpec,
}
#[derive(Deserialize)]
struct PodSpec {
    #[serde(rename = "serviceAccountName")]
    service_account_name: String,
}
#[derive(Deserialize)]
struct Account {
    metadata: Metadata,
}
#[derive(Deserialize)]
struct Namespace {
    metadata: NamespaceMetadata,
}
#[derive(Deserialize)]
struct NamespaceMetadata {
    uid: String,
    name: String,
    #[serde(rename = "deletionTimestamp")]
    deletion_timestamp: Option<String>,
}

fn dns_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}
fn one(extra: &BTreeMap<String, Vec<String>>, key: &str) -> Result<String> {
    let values = extra.get(key).ok_or(BrokerError::Unauthorized)?;
    if values.len() != 1 || values[0].is_empty() || values[0].len() > 253 {
        return Err(BrokerError::Unauthorized);
    }
    Ok(values[0].clone())
}
fn jwt_exp(token: &str) -> Result<i64> {
    let parts: Vec<_> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(BrokerError::Unauthorized);
    }
    let data = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| BrokerError::Unauthorized)?;
    #[derive(Deserialize)]
    struct Claims {
        exp: i64,
    }
    serde_json::from_slice::<Claims>(&data)
        .map(|c| c.exp)
        .map_err(|_| BrokerError::Unauthorized)
}
impl PodAuthenticator {
    pub fn new(config: AuthConfig) -> Result<Self> {
        endpoint(&config.kube_api_url, config.allow_http)?;
        path_valid(&config.kube_token_file)?;
        if config.audience.is_empty()
            || config.audience.len() > 253
            || config.audience.chars().any(char::is_control)
        {
            return Err(BrokerError::Invalid);
        }
        let client = client(config.kube_ca_file.as_deref())?;
        Ok(Self {
            config,
            client,
            permits: Arc::new(tokio::sync::Semaphore::new(8)),
        })
    }
    pub async fn authenticate(&self, authorization: &str) -> Result<PodIdentity> {
        let _permit = self
            .permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| BrokerError::Capacity)?;
        tokio::time::timeout(
            Duration::from_secs(20),
            self.authenticate_inner(authorization),
        )
        .await
        .map_err(|_| BrokerError::Unavailable)?
    }
    /// Stable cluster identity from the already trusted Kubernetes API.
    /// Requires GET only for the kube-system Namespace, never a namespace list.
    pub async fn cluster_uid(&self) -> Result<String> {
        let namespace: Namespace = self.get("/api/v1/namespaces/kube-system").await?;
        if namespace.metadata.name != "kube-system"
            || namespace.metadata.deletion_timestamp.is_some()
            || !super::config::id(&namespace.metadata.uid)
        {
            return Err(BrokerError::Unauthorized);
        }
        Ok(namespace.metadata.uid)
    }
    async fn authenticate_inner(&self, authorization: &str) -> Result<PodIdentity> {
        let token = authorization
            .strip_prefix("Bearer ")
            .unwrap_or(authorization);
        if token.is_empty() || token.len() > 16384 || token.bytes().any(|b| !b.is_ascii_graphic()) {
            return Err(BrokerError::Unauthorized);
        }
        let body = serde_json::to_vec(&serde_json::json!({
            "apiVersion":"authentication.k8s.io/v1", "kind":"TokenReview",
            "spec":{"token":token,"audiences":[self.config.audience]}
        }))
        .map_err(|_| BrokerError::Invalid)?;
        let url = format!(
            "{}/apis/authentication.k8s.io/v1/tokenreviews",
            self.config.kube_api_url.trim_end_matches('/')
        );
        let response = self
            .client
            .post(url)
            .bearer_auth(secret(&self.config.kube_token_file).await?)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|_| BrokerError::Unavailable)?;
        let review: Review = serde_json::from_slice(&response_bytes(response).await?)
            .map_err(|_| BrokerError::Unauthorized)?;
        if !review.status.authenticated || !review.status.audiences.contains(&self.config.audience)
        {
            return Err(BrokerError::Unauthorized);
        }
        let user = review.status.user.ok_or(BrokerError::Unauthorized)?;
        let parts: Vec<_> = user.username.split(':').collect();
        if parts.len() != 4
            || parts[0] != "system"
            || parts[1] != "serviceaccount"
            || !dns_name(parts[2])
            || !dns_name(parts[3])
            || user.uid.is_empty()
        {
            return Err(BrokerError::Unauthorized);
        }
        let pod_name = one(&user.extra, "authentication.kubernetes.io/pod-name")?;
        let pod_uid = one(&user.extra, "authentication.kubernetes.io/pod-uid")?;
        if !dns_name(&pod_name) {
            return Err(BrokerError::Unauthorized);
        }
        // Parsing exp is safe only after the API server verified the same token.
        let expires = jwt_exp(token)?;
        if expires <= now()?.saturating_add(5) {
            return Err(BrokerError::Unauthorized);
        }
        let namespace = parts[2];
        let account_name = parts[3];
        let identity = PodIdentity {
            namespace: namespace.into(),
            service_account: account_name.into(),
            service_account_uid: user.uid,
            pod_name,
            pod_uid,
            token_expires_at: expires,
        };
        self.validate_live(&identity).await?;
        Ok(identity)
    }
    /// Revalidate a previously verified identity for revocation; grants no new identity.
    pub async fn validate_live(&self, identity: &PodIdentity) -> Result<()> {
        if !dns_name(&identity.namespace)
            || !dns_name(&identity.service_account)
            || !dns_name(&identity.pod_name)
        {
            return Err(BrokerError::Unauthorized);
        }
        let pod: Pod = self
            .get(&format!(
                "/api/v1/namespaces/{}/pods/{}",
                identity.namespace, identity.pod_name
            ))
            .await?;
        let account: Account = self
            .get(&format!(
                "/api/v1/namespaces/{}/serviceaccounts/{}",
                identity.namespace, identity.service_account
            ))
            .await?;
        if pod.metadata.uid != identity.pod_uid
            || pod.metadata.name != identity.pod_name
            || pod.metadata.namespace != identity.namespace
            || pod.metadata.deletion_timestamp.is_some()
            || pod.spec.service_account_name != identity.service_account
            || account.metadata.uid != identity.service_account_uid
            || account.metadata.name != identity.service_account
            || account.metadata.namespace != identity.namespace
            || account.metadata.deletion_timestamp.is_some()
        {
            return Err(BrokerError::Unauthorized);
        }
        Ok(())
    }
    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        let response = self
            .client
            .get(format!(
                "{}{path}",
                self.config.kube_api_url.trim_end_matches('/')
            ))
            .bearer_auth(secret(&self.config.kube_token_file).await?)
            .send()
            .await
            .map_err(|_| BrokerError::Unavailable)?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(BrokerError::Unauthorized);
        }
        serde_json::from_slice(&response_bytes(response).await?)
            .map_err(|_| BrokerError::Unauthorized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        extract::State,
        response::{IntoResponse, Response},
        routing::{get, post},
    };
    use std::sync::atomic::{AtomicU8, Ordering};

    async fn review(
        State(mode): State<Arc<AtomicU8>>,
        headers: axum::http::HeaderMap,
        axum::Json(value): axum::Json<serde_json::Value>,
    ) -> Response {
        if headers.get("Authorization").and_then(|v| v.to_str().ok())
            != Some("Bearer fixture-kube-auth")
            || value["spec"]["audiences"] != serde_json::json!(["fixture-broker"])
        {
            return axum::http::StatusCode::UNAUTHORIZED.into_response();
        }
        let mode = mode.load(Ordering::Relaxed);
        axum::Json(serde_json::json!({"status":{"authenticated":mode!=6,
            "audiences":[if mode==1{"other-audience"}else{"fixture-broker"}],
            "user":{"username":"system:serviceaccount:fixture-ns:reader","uid":"account-uid",
                "extra":if mode==4{serde_json::json!({})}else{serde_json::json!({
                    "authentication.kubernetes.io/pod-name":["reader-pod"],
                    "authentication.kubernetes.io/pod-uid":["pod-uid"]})}}}}))
        .into_response()
    }
    async fn pod(State(mode): State<Arc<AtomicU8>>) -> Response {
        let mode = mode.load(Ordering::Relaxed);
        if mode == 7 {
            return axum::http::StatusCode::NOT_FOUND.into_response();
        }
        axum::Json(serde_json::json!({"metadata":{"uid":if mode==5{"replacement-uid"}else{"pod-uid"},
            "name":"reader-pod","namespace":"fixture-ns","deletionTimestamp":if mode==2{Some("2030-01-01T00:00:00Z")}else{None}},
            "spec":{"serviceAccountName":"reader"}})).into_response()
    }
    async fn account(State(mode): State<Arc<AtomicU8>>) -> Response {
        axum::Json(serde_json::json!({"metadata":{"uid":if mode.load(Ordering::Relaxed)==3{"new-account-uid"}else{"account-uid"},
            "name":"reader","namespace":"fixture-ns"}})).into_response()
    }
    async fn namespace(
        State(mode): State<Arc<AtomicU8>>,
        headers: axum::http::HeaderMap,
    ) -> Response {
        if headers.get("Authorization").and_then(|v| v.to_str().ok())
            != Some("Bearer fixture-kube-auth")
        {
            return axum::http::StatusCode::UNAUTHORIZED.into_response();
        }
        axum::Json(serde_json::json!({"metadata":{"name":"kube-system","uid":if mode.load(Ordering::Relaxed)==8{""}else{"fixture-cluster"}}})).into_response()
    }
    #[tokio::test]
    async fn audience_pod_and_account_identity_are_validated_again_on_each_request() {
        let temporary = tempfile::tempdir_in("/tmp").expect("private test directory");
        let token_file = temporary.path().join("kube-token");
        tokio::fs::write(&token_file, "fixture-kube-auth")
            .await
            .expect("token file");
        let mode = Arc::new(AtomicU8::new(0));
        let app = Router::new()
            .route("/api/v1/namespaces/kube-system", get(namespace))
            .route("/apis/authentication.k8s.io/v1/tokenreviews", post(review))
            .route("/api/v1/namespaces/fixture-ns/pods/reader-pod", get(pod))
            .route(
                "/api/v1/namespaces/fixture-ns/serviceaccounts/reader",
                get(account),
            )
            .with_state(mode.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback fixture");
        let addr = listener.local_addr().expect("address");
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let auth = PodAuthenticator::new(AuthConfig {
            kube_api_url: format!("http://{addr}"),
            kube_token_file: token_file.clone(),
            kube_ca_file: None,
            audience: "fixture-broker".into(),
            allow_http: true,
        })
        .expect("authenticator");
        assert_eq!(
            auth.cluster_uid().await.expect("trusted cluster UID"),
            "fixture-cluster"
        );
        mode.store(8, Ordering::Relaxed);
        assert_eq!(auth.cluster_uid().await, Err(BrokerError::Unauthorized));
        mode.store(0, Ordering::Relaxed);
        let claims = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({"exp":now().expect("clock")+3600}))
                .expect("claims"),
        );
        let token = format!("header.{claims}.signature");
        let identity = auth
            .authenticate(&token)
            .await
            .expect("live projected token");
        assert_eq!(identity.pod_uid, "pod-uid");
        assert_eq!(identity.service_account_uid, "account-uid");
        assert!(auth.authenticate(&format!("Bearer {token}")).await.is_ok());
        for invalid in 1..=7 {
            mode.store(invalid, Ordering::Relaxed);
            assert_eq!(
                auth.authenticate(&token).await,
                Err(BrokerError::Unauthorized),
                "invalid fixture mode {invalid}"
            );
        }
        mode.store(0, Ordering::Relaxed);
        tokio::fs::write(&token_file, "rotated-invalid-token")
            .await
            .expect("rotate token");
        assert!(
            auth.authenticate(&token).await.is_err(),
            "API token file must be reread"
        );
        task.abort();
        let _ = task.await;
    }
    #[test]
    fn identity_path_names_cannot_escape_kubernetes_resources() {
        for name in ["../pods", "a/b", "x?fieldSelector=x", "UPPER", "", "-name"] {
            assert!(!dns_name(name));
        }
        assert!(dns_name("devres-serving-56ddcc"));
    }
    #[test]
    fn projected_token_exp_requires_exact_jwt_shape() {
        let claims = URL_SAFE_NO_PAD.encode(br#"{"exp":1234}"#);
        assert_eq!(jwt_exp(&format!("header.{claims}.signature")), Ok(1234));
        assert_eq!(
            jwt_exp(&format!("header.{claims}.signature.extra")),
            Err(BrokerError::Unauthorized)
        );
        assert_eq!(jwt_exp("opaque"), Err(BrokerError::Unauthorized));
    }
}
