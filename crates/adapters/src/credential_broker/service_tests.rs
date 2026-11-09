use super::*;
use crate::credential_broker::{Role, identity::AuthConfig};
use axum::{
    Router,
    extract::{Path, State},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sqlx::Connection;
use std::sync::{Mutex, atomic::AtomicUsize};

const APP: &str = "11111111-1111-4111-8111-111111111111";
const ISSUER: &str = "33333333-3333-4333-8333-333333333333";
const KEYRING:&[u8]=br#"{"active_key_id":"one","keys":{"one":"0101010101010101010101010101010101010101010101010101010101010101"}}"#;
#[derive(Default)]
struct Fixture {
    deleted: Mutex<BTreeSet<String>>,
    mode: AtomicUsize,
    created: AtomicUsize,
    cluster: AtomicUsize,
}
async fn namespace(State(fixture): State<Arc<Fixture>>) -> axum::Json<serde_json::Value> {
    axum::Json(
        serde_json::json!({"metadata":{"name":"kube-system","uid":if fixture.cluster.load(Ordering::Relaxed)==0{"fixture-cluster-devres"}else{"different-cluster"}}}),
    )
}
async fn issuer_key() -> axum::Json<serde_json::Value> {
    axum::Json(
        serde_json::json!({"access_key":"fixture-issuer","application_id":ISSUER,"description":"fixture issuer"}),
    )
}
async fn delete_key(
    State(fixture): State<Arc<Fixture>>,
    Path(key): Path<String>,
) -> axum::http::StatusCode {
    fixture.deleted.lock().expect("test lock").insert(key);
    axum::http::StatusCode::NO_CONTENT
}
async fn create_key(
    State(fixture): State<Arc<Fixture>>,
    axum::Json(request): axum::Json<serde_json::Value>,
) -> axum::Json<serde_json::Value> {
    fixture.created.fetch_add(1, Ordering::Relaxed);
    let mode = fixture.mode.load(Ordering::Relaxed);
    let mut value = serde_json::json!({"access_key":format!("malformed-{mode}"),"secret_key":"fixture-issued-secret",
        "application_id":APP,"description":request["description"]});
    if mode == 1 {
        value["expires_at"] = serde_json::Value::Null;
    }
    if mode == 2 {
        value["expires_at"] = serde_json::json!("not-a-timestamp");
    }
    axum::Json(value)
}
async fn hidden_list() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({"api_keys":[],"total_count":0}))
}
async fn pod(Path(name): Path<String>) -> Response {
    if name == "pod-9" {
        return axum::http::StatusCode::NOT_FOUND.into_response();
    }
    axum::Json(serde_json::json!({"metadata":{"uid":format!("uid-{name}"),"name":name,"namespace":"devres-acceptance"},
        "spec":{"serviceAccountName":"devres-serving"}})).into_response()
}
async fn account() -> axum::Json<serde_json::Value> {
    axum::Json(
        serde_json::json!({"metadata":{"uid":"sa-uid","name":"devres-serving","namespace":"devres-acceptance"}}),
    )
}
async fn review() -> axum::Json<serde_json::Value> {
    axum::Json(
        serde_json::json!({"status":{"authenticated":true,"audiences":["devres-credential-broker"],
        "user":{"username":"system:serviceaccount:devres-acceptance:devres-serving","uid":"sa-uid","extra":{
            "authentication.kubernetes.io/pod-name":["request-pod"],"authentication.kubernetes.io/pod-uid":["uid-request-pod"]}}}}),
    )
}

#[tokio::test]
#[ignore = "requires a dedicated DEVRES_TEST_BROKER_DATABASE_URL fixture database"]
async fn credential_broker_maintenance_checks_last_row_and_revokes_malformed_provider_keys() {
    let database =
        std::env::var("DEVRES_TEST_BROKER_DATABASE_URL").expect("isolated broker database");
    let temp = tempfile::tempdir_in("/tmp").expect("test directory");
    let root = temp.path();
    let fixture = Arc::new(Fixture::default());
    let app = Router::new()
        .route("/api/v1/namespaces/kube-system", get(namespace))
        .route("/iam/v1alpha1/api-keys/fixture-issuer", get(issuer_key))
        .route(
            "/iam/v1alpha1/api-keys/{key}",
            axum::routing::delete(delete_key),
        )
        .route("/iam/v1alpha1/api-keys", post(create_key).get(hidden_list))
        .route("/api/v1/namespaces/devres-acceptance/pods/{name}", get(pod))
        .route(
            "/api/v1/namespaces/devres-acceptance/serviceaccounts/devres-serving",
            get(account),
        )
        .route("/apis/authentication.k8s.io/v1/tokenreviews", post(review))
        .with_state(fixture.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("fixture listener");
    let endpoint = format!("http://{}", listener.local_addr().expect("address"));
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let profile = Profile {
        namespace: "devres-acceptance".into(),
        service_account: "devres-serving".into(),
        application_id: APP.into(),
        default_project_id: "44444444-4444-4444-8444-444444444444".into(),
        bucket: "fixture-bucket".into(),
        prefix: "archive".into(),
        role: Role::Readonly,
        policy_fingerprint: "a".repeat(64),
        enabled: true,
    };
    let config = BrokerConfig {
        bind: "127.0.0.1:8444".parse().expect("bind"),
        tls_certificate_file: root.join("cert"),
        tls_private_key_file: root.join("tls-key"),
        database_url_file: root.join("database"),
        keyring_file: root.join("keyring"),
        issuer_key_file: root.join("issuer"),
        issuer_access_key: "fixture-issuer".into(),
        issuer_application_id: ISSUER.into(),
        acceptance_receipt_file: root.join("receipt"),
        authentication: AuthConfig {
            kube_api_url: endpoint.clone(),
            kube_token_file: root.join("kube-token"),
            kube_ca_file: None,
            audience: "devres-credential-broker".into(),
            allow_http: true,
        },
        iam_endpoint: endpoint,
        iam_ca_file: None,
        fixture_mode: true,
        ttl_secs: 900,
        refresh_before_secs: 300,
        max_pods: 16,
        max_issued_keys: 32,
        quota_reserve: 8,
        profiles: vec![profile.clone()],
    };
    tokio::fs::write(&config.database_url_file, &database)
        .await
        .expect("database selector");
    tokio::fs::write(&config.keyring_file, KEYRING)
        .await
        .expect("encryption keys");
    tokio::fs::write(&config.issuer_key_file, "fixture-issuer-secret")
        .await
        .expect("issuer secret");
    tokio::fs::write(
        &config.authentication.kube_token_file,
        "fixture-kube-secret",
    )
    .await
    .expect("API token");
    let now = now().expect("clock");
    let receipt = serde_json::json!({"issuer_access_key":"fixture-issuer","issuer_application_id":ISSUER,
        "issuer_secret_fingerprint":config.issuer_secret_fingerprint().await.expect("issuer binding"),
        "profile_fingerprints":{(APP):profile.fingerprint().expect("profile fingerprint")},"confined_application_ids":[APP],
        "verified_at":format_timestamp(now).expect("timestamp"),"expires_at":format_timestamp(now+3600).expect("timestamp"),
        "broker_key_budget":40,"ttl_secs":900,"unrelated_application_denied":true,"policy_management_denied":true,"expiry_accepted":true,"fixture":true});
    tokio::fs::write(
        &config.acceptance_receipt_file,
        serde_json::to_vec(&receipt).expect("receipt"),
    )
    .await
    .expect("receipt file");
    let config_path = root.join("broker.toml");
    tokio::fs::write(&config_path, toml::to_string(&config).expect("config"))
        .await
        .expect("configuration file");
    let keys = Keyring::parse(KEYRING).expect("keyring");
    let mut journal = Journal::connect(&database).await.expect("journal");
    journal
        .bind_cluster("fixture-cluster-devres")
        .await
        .expect("fixture cluster binding");
    let mut intents = Vec::new();
    for index in 0..10 {
        let identity = PodIdentity {
            namespace: "devres-acceptance".into(),
            service_account: "devres-serving".into(),
            service_account_uid: "sa-uid".into(),
            pod_name: format!("pod-{index}"),
            pod_uid: format!("uid-pod-{index}"),
            token_expires_at: now + 3600,
        };
        let mut row = journal
            .intent(
                &identity,
                &profile.fingerprint().expect("fingerprint"),
                APP,
                now + 900,
            )
            .await
            .expect("intent");
        row.access_key = Some(format!("key-{index}"));
        let response = CredentialResponse {
            access_key_id: format!("key-{index}"),
            secret_access_key: "encrypted-fixture-secret".into(),
            expiration: format_timestamp(now + 900).expect("expiry"),
        };
        journal
            .issued(
                &row,
                &keys,
                &serde_json::to_vec(&response).expect("response"),
            )
            .await
            .expect("issued key");
        intents.push(row.intent);
    }
    journal.connection.close().await.expect("release owner");
    let broker = Broker::open(config_path.clone())
        .await
        .expect("recover broker");
    assert_eq!(
        *fixture.deleted.lock().expect("test lock"),
        BTreeSet::from(["key-9".into()]),
        "every maintenance cycle must include rows after the eighth"
    );
    tokio::fs::write(&config.issuer_key_file, "swapped-broad-issuer-secret")
        .await
        .expect("replace issuer");
    assert!(
        matches!(
            broker.inner.issuer.revoke("key-0").await,
            Err(BrokerError::Forbidden)
        ),
        "every mutation must bind the actual issuer secret"
    );
    assert_eq!(fixture.deleted.lock().expect("test lock").len(), 1);
    tokio::fs::write(&config.issuer_key_file, "fixture-issuer-secret")
        .await
        .expect("restore issuer");
    let claims = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&serde_json::json!({"exp":now+3600})).expect("claims"));
    let token = format!("header.{claims}.signature");
    let identity = PodIdentity {
        namespace: "devres-acceptance".into(),
        service_account: "devres-serving".into(),
        service_account_uid: "sa-uid".into(),
        pod_name: "request-pod".into(),
        pod_uid: "uid-request-pod".into(),
        token_expires_at: now + 3600,
    };
    let pending = broker
        .inner
        .journal
        .lock()
        .await
        .intent(
            &identity,
            &profile.fingerprint().expect("fingerprint"),
            APP,
            now + 900,
        )
        .await
        .expect("unresolved create intent");
    for _ in 0..3 {
        assert!(
            matches!(
                broker.credentials(&token).await,
                Err(BrokerError::Unavailable)
            ),
            "a temporarily absent list result must not authorize another create"
        );
        assert_eq!(fixture.created.load(Ordering::Relaxed), 0);
    }
    broker
        .inner
        .journal
        .lock()
        .await
        .revoked(&pending.intent)
        .await
        .expect("release synthetic uncertain intent");
    for mode in 0..3 {
        fixture.mode.store(mode, Ordering::Relaxed);
        assert!(
            matches!(
                broker.credentials(&token).await,
                Err(BrokerError::Integrity)
            ),
            "missing/null/malformed expiry must not be issued"
        );
        assert!(
            fixture
                .deleted
                .lock()
                .expect("test lock")
                .contains(&format!("malformed-{mode}")),
            "known owned anomalous key must be deleted"
        );
    }
    let mut journal = broker.inner.journal.lock().await;
    assert!(
        !journal
            .records(32)
            .await
            .expect("active records")
            .iter()
            .any(|row| row.identity.pod_name == "request-pod")
    );
    for intent in intents {
        journal
            .revoked(&intent)
            .await
            .expect("discard synthetic row");
    }
    drop(journal);
    let created = fixture.created.load(Ordering::Relaxed);
    let deleted = fixture.deleted.lock().expect("test lock").len();
    let inner = match Arc::try_unwrap(broker.inner) {
        Ok(inner) => inner,
        Err(_) => panic!("test broker must have one owner"),
    };
    inner
        .journal
        .into_inner()
        .connection
        .close()
        .await
        .expect("stop broker owner");
    fixture.cluster.store(1, Ordering::Relaxed);
    assert!(
        matches!(
            Broker::open(config_path.clone()).await,
            Err(BrokerError::Forbidden)
        ),
        "different Kubernetes cluster cannot reuse this journal"
    );
    assert_eq!(fixture.created.load(Ordering::Relaxed), created);
    assert_eq!(fixture.deleted.lock().expect("test lock").len(), deleted);
    fixture.cluster.store(0, Ordering::Relaxed);
    let repeated = Broker::open(config_path)
        .await
        .expect("same cluster starts again");
    assert!(repeated.ready());
    drop(repeated);
    task.abort();
    let _ = task.await;
}
