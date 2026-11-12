use super::*;
use crate::{
    ServerBuilder,
    config::{Limits, SourceOffer, WriterClientIdentity},
    registry::server_info_registry,
};
use axum::{Json, extract::State, routing::get};
use devres_adapters::credential_broker::identity::AuthConfig;
use serde_json::{Value, json};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio_util::sync::CancellationToken;

const TOKEN: &str = "e30.eyJleHAiOjQxMDI0NDQ4MDB9.signature";
struct FakeWriter {
    calls: AtomicUsize,
    hold: AtomicBool,
    entered: tokio::sync::Notify,
    cancelled: Arc<AtomicUsize>,
    attribution: Option<Value>,
}
struct Cancelled(Arc<AtomicUsize>);
impl Drop for Cancelled {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
fn receipt() -> Capture {
    Capture {
        id: "a".repeat(64),
        key: "rfc:text:1".into(),
        source_url: "https://www.rfc-editor.org/rfc/rfc1.txt".into(),
        body_hash: "b".repeat(64),
        media_type: "text/plain".into(),
        retrieved_at: 100,
        validated_at: 200,
    }
}
#[async_trait]
impl AcquisitionDelegate for FakeWriter {
    async fn acquire(&self, operation: Acquisition) -> Result<Capture> {
        if !matches!(operation, Acquisition::RfcRepresentation { number: 1, .. }) {
            return Err(Error::invalid("Fixture source rejected."));
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.entered.notify_one();
        if self.hold.load(Ordering::SeqCst) {
            let _guard = Cancelled(self.cancelled.clone());
            std::future::pending::<()>().await;
        }
        Ok(receipt())
    }
    async fn effect(&self, _: WriterEffect) -> Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn source_status(&self, _: SourceStatus) -> Result<Value> {
        Ok(json!({"collector":{"index":{"code":"capacity"}}}))
    }
    async fn attribution_status(&self) -> Result<Value> {
        Ok(self
            .attribution
            .clone()
            .unwrap_or_else(|| json!({"scan_gaps":{"mdn":"capacity"},"complete":false})))
    }
    async fn rfc_snapshot(&self) -> Result<String> {
        Ok("c".repeat(64))
    }
}
#[derive(Clone)]
struct KubeState {
    deleting: Arc<AtomicBool>,
    wrong_uid: Arc<AtomicBool>,
    reviews: Arc<AtomicUsize>,
}
async fn review(State(state): State<KubeState>, Json(body): Json<Value>) -> Json<Value> {
    state.reviews.fetch_add(1, Ordering::SeqCst);
    if body["spec"]["token"] != TOKEN || body["spec"]["audiences"] != json!(["devres-writer"]) {
        return Json(json!({"status":{"authenticated":false}}));
    }
    Json(
        json!({"status":{"authenticated":true,"audiences":["devres-writer"],"user":{"username":"system:serviceaccount:fixture:serving","uid":"sa-uid","extra":{"authentication.kubernetes.io/pod-name":["serving-pod"],"authentication.kubernetes.io/pod-uid":["pod-uid"]}}}}),
    )
}
async fn pod(State(state): State<KubeState>) -> Json<Value> {
    Json(
        json!({"metadata":{"name":"serving-pod","namespace":"fixture","uid":if state.wrong_uid.load(Ordering::SeqCst){"recreated-uid"}else{"pod-uid"},"deletionTimestamp":if state.deleting.load(Ordering::SeqCst){json!("2030-01-01T00:00:00Z")}else{Value::Null}},"spec":{"serviceAccountName":"serving"}}),
    )
}
async fn account() -> Json<Value> {
    Json(json!({"metadata":{"name":"serving","namespace":"fixture","uid":"sa-uid"}}))
}
struct Fixture {
    _directory: tempfile::TempDir,
    config: WriterClientConfig,
    client: reqwest::Client,
    writer: Arc<FakeWriter>,
    kube: KubeState,
    shutdown: CancellationToken,
    server: tokio::task::JoinHandle<std::result::Result<(), ServerError>>,
    api: tokio::task::JoinHandle<()>,
}
impl Fixture {
    async fn new(allowed: bool) -> Self {
        Self::with_attribution(allowed, None).await
    }
    async fn with_attribution(allowed: bool, attribution: Option<Value>) -> Self {
        let directory = tempfile::tempdir_in("/tmp").unwrap();
        let certificate = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let cert = directory.path().join("writer.pem");
        let key = directory.path().join("writer-key.pem");
        let reviewer = directory.path().join("reviewer");
        let token = directory.path().join("projected");
        std::fs::write(&cert, certificate.cert.pem()).unwrap();
        std::fs::write(&key, certificate.signing_key.serialize_pem()).unwrap();
        std::fs::write(&reviewer, "fixture-reviewer").unwrap();
        std::fs::write(&token, TOKEN).unwrap();
        let kube = KubeState {
            deleting: Arc::new(AtomicBool::new(false)),
            wrong_uid: Arc::new(AtomicBool::new(false)),
            reviews: Arc::new(AtomicUsize::new(0)),
        };
        let app = Router::new()
            .route("/apis/authentication.k8s.io/v1/tokenreviews", post(review))
            .route("/api/v1/namespaces/fixture/pods/serving-pod", get(pod))
            .route(
                "/api/v1/namespaces/fixture/serviceaccounts/serving",
                get(account),
            )
            .with_state(kube.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api_url = format!("http://{}", listener.local_addr().unwrap());
        let shutdown = CancellationToken::new();
        let stop = shutdown.clone();
        let api = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(stop.cancelled_owned())
                .await
                .unwrap();
        });
        let writer = Arc::new(FakeWriter {
            calls: AtomicUsize::new(0),
            hold: AtomicBool::new(false),
            entered: tokio::sync::Notify::new(),
            cancelled: Arc::new(AtomicUsize::new(0)),
            attribution,
        });
        let source = SourceOffer::new("https://source.test/revision").unwrap();
        let limits = Limits {
            max_message_bytes: 1024 * 1024,
            max_tool_result_bytes: Some(128 * 1024),
            max_buffer_bytes: 4 * 1024 * 1024,
            max_in_flight: 2,
            max_calls_per_connection: 2,
            io_timeout_secs: 2,
            search_timeout_secs: 5,
            shutdown_timeout_secs: 2,
            ..Limits::default()
        };
        let mut builder = ServerBuilder::new(
            server_info_registry(source.clone()).unwrap(),
            limits,
            source,
        );
        builder
            .register_endpoint(WriterEndpoint {
                coordinator: writer.clone(),
                config: WriterListenerConfig {
                    bind: "127.0.0.1:0".parse().unwrap(),
                    certificate: cert.clone(),
                    private_key: key,
                    auth: AuthConfig {
                        kube_api_url: api_url,
                        kube_token_file: reviewer,
                        kube_ca_file: None,
                        audience: "devres-writer".into(),
                        allow_http: true,
                    },
                    allowed_clients: vec![WriterClientIdentity {
                        namespace: if allowed { "fixture" } else { "other" }.into(),
                        service_account: "serving".into(),
                    }],
                },
            })
            .unwrap();
        let running = builder.bind().await.unwrap();
        let endpoint = format!("https://{}/v1/acquire", running.addresses()[0].1[0]);
        let stop = shutdown.clone();
        let server = tokio::spawn(async move { running.run(stop).await });
        let client = reqwest::Client::builder()
            .no_proxy()
            .retry(reqwest::retry::never())
            .http1_only()
            .add_root_certificate(
                reqwest::Certificate::from_pem(certificate.cert.pem().as_bytes()).unwrap(),
            )
            .build()
            .unwrap();
        Self {
            _directory: directory,
            config: WriterClientConfig {
                endpoint,
                token_file: token,
                ca_file: Some(cert),
            },
            client,
            writer,
            kube,
            shutdown,
            server,
            api,
        }
    }
    fn request(&self, value: Value) -> reqwest::RequestBuilder {
        self.client
            .post(&self.config.endpoint)
            .header(header::AUTHORIZATION, TOKEN)
            .json(&value)
    }
    async fn finish(self) {
        self.shutdown.cancel();
        self.server.await.unwrap().unwrap();
        self.api.await.unwrap();
    }
}
fn source_request() -> Value {
    json!({"kind":"acquire","source":{"operation":"rfc_representation","number":1,"format":"txt"}})
}

// Exercise the actual authenticated reply encoder and client decoder with the
// storage sampler's envelope: two rows per bucket and a 24-KiB samples budget.
// Storage tests separately check that real SQL samples obey that source bound.
fn attribution_status_fixture(per_bucket: usize, sample_budget: Option<usize>) -> Value {
    use devres_application::attribution_runtime::ATTRIBUTION_PROVIDERS;
    use devres_domain::attribution::{
        ATTRIBUTION_POLICY_EPOCH, AttributionDisposition, AttributionFailure,
        AttributionFailureReason, AttributionPhase,
    };
    let mut samples = Vec::new();
    let mut counts = Vec::new();
    let mut sweeps = Vec::new();
    let mut progress = serde_json::Map::new();
    let mut scan_gaps = serde_json::Map::new();
    for provider in ATTRIBUTION_PROVIDERS {
        for status in ["pending", "retry", "running", "blocked", "ready"] {
            counts.push(json!({"provider":provider,"status":status,"count":i64::MAX}));
            if status == "ready" {
                continue;
            }
            for priority in [0, 1] {
                for _ in 0..per_bucket {
                    let classification = AttributionFailure::new(
                        AttributionPhase::Qualification,
                        AttributionFailureReason::UpstreamUnavailable,
                        if status == "blocked" {
                            AttributionDisposition::Blocked
                        } else {
                            AttributionDisposition::Retry
                        },
                    );
                    samples.push(
                        json!({"provider":provider,"status":status,"priority":priority,
                        "namespace":"devres_chromium_evidence/projection-references",
                        "attempts":u32::MAX,"retry_at":i64::MAX,"eligible":false,
                        "failure":"publication_deferred","classification":classification}),
                    );
                }
            }
        }
        sweeps.push(json!({"provider":provider,"completed_passes":u64::MAX,
            "scan_complete":false,"source":usize::MAX,"membership":"indexed_range_enumeration"}));
        progress.insert(
            provider.into(),
            json!({"enqueued":u64::MAX,"claimed":u64::MAX,
            "ready":u64::MAX,"retry":u64::MAX,"blocked":u64::MAX}),
        );
        scan_gaps.insert(provider.into(), json!("capacity"));
    }
    let candidates = samples.len();
    if let Some(budget) = sample_budget {
        while serde_json::to_vec(&samples).unwrap().len() > budget {
            samples.pop().unwrap();
        }
        // Fill the budget with real enum/scalar rows, not arbitrary padding.
        assert!(serde_json::to_vec(&samples).unwrap().len() > budget - 512);
    }
    json!({"policy_epoch":ATTRIBUTION_POLICY_EPOCH,"counts":counts,"sweeps":sweeps,
        "enabled_providers":ATTRIBUTION_PROVIDERS,"disabled_providers":[],
        "scan_gaps":scan_gaps,"admission_gap":AttributionFailure::new(
            AttributionPhase::Scheduling,AttributionFailureReason::AdmissionDeferred,AttributionDisposition::Retry),
        "progress":{"scope":"this_store_process","started_at":i64::MAX,"providers":progress},
        "diagnostics":{"sampled":true,"limit_per_bucket":per_bucket,"ordering":"retry_at_then_id",
            "sample_budget_bytes":sample_budget,"truncated":samples.len()<candidates,
            "omitted_sample_rows":candidates-samples.len(),"omission_scope":"bounded_candidates_only",
            "observed_at":i64::MAX,"pending_age_available":false,"samples":samples},
        "repair_complete_for_enqueued_targets":false,"initial_scan_passes_complete":false,
        "completion_scope":"observed_sweep_cutoffs","complete":false,"corpus_complete":false})
}

#[tokio::test]
async fn bounded_attribution_status_survives_authenticated_private_rpc() {
    let status = attribution_status_fixture(2, Some(24 * 1024));
    let encoded = serde_json::to_vec(&Reply::AttributionStatus {
        status: status.clone(),
    })
    .unwrap();
    assert!(encoded.len() <= RESPONSE_LIMIT);
    let fixture = Fixture::with_attribution(true, Some(status.clone())).await;
    let client = WriterClient::new(fixture.config.clone(), Duration::from_secs(5)).unwrap();
    assert_eq!(client.attribution_status().await.unwrap(), status);
    assert_eq!(fixture.kube.reviews.load(Ordering::SeqCst), 1);
    fixture.finish().await;
}

#[tokio::test]
async fn oversized_attribution_status_is_a_typed_private_rpc_failure() {
    let status = attribution_status_fixture(4, None);
    assert!(
        serde_json::to_vec(&Reply::AttributionStatus {
            status: status.clone()
        })
        .unwrap()
        .len()
            > RESPONSE_LIMIT
    );
    let fixture = Fixture::with_attribution(true, Some(status)).await;
    let client = WriterClient::new(fixture.config.clone(), Duration::from_secs(5)).unwrap();
    let error = client.attribution_status().await.unwrap_err();
    assert_eq!(error.code, "capacity");
    assert!(error.details.is_none());
    fixture.finish().await;
}

#[tokio::test]
async fn authenticated_source_rpc_returns_only_committed_receipt_and_reloads_projected_token() {
    let fixture = Fixture::new(true).await;
    let client = WriterClient::new(fixture.config.clone(), Duration::from_secs(5)).unwrap();
    let capture = client
        .acquire(Acquisition::RfcRepresentation {
            number: 1,
            format: "txt".into(),
        })
        .await
        .unwrap();
    assert_eq!(capture.id, receipt().id);
    assert_eq!(capture.validated_at, 200);
    assert_eq!(client.rfc_snapshot().await.unwrap(), "c".repeat(64));
    assert_eq!(
        client.attribution_status().await.unwrap()["scan_gaps"]["mdn"],
        "capacity"
    );
    assert_eq!(fixture.writer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        client.source_status(SourceStatus::Crates).await.unwrap()["collector"]["index"]["code"],
        "capacity"
    );
    assert_eq!(fixture.kube.reviews.load(Ordering::SeqCst), 4);
    std::fs::write(&fixture.config.token_file, "invalid-rotated-token").unwrap();
    assert_eq!(
        client
            .acquire(Acquisition::RfcRepresentation {
                number: 1,
                format: "txt".into()
            })
            .await
            .unwrap_err()
            .code,
        "unavailable"
    );
    assert_eq!(fixture.writer.calls.load(Ordering::SeqCst), 1);
    fixture.finish().await;
}
#[tokio::test]
async fn private_rpc_rejects_anonymous_audit_url_and_generic_tool_inputs() {
    let fixture = Fixture::new(true).await;
    assert_eq!(
        fixture
            .client
            .post(&fixture.config.endpoint)
            .json(&source_request())
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    for value in [
        json!({"tool":"packages.crate.audit_lockfile","lockfile":"request-only-marker"}),
        json!({"kind":"acquire","source":{"operation":"rfc_representation","number":1,"format":"txt","url":"http://private.invalid"}}),
        json!({"kind":"acquire","source":{"operation":"audit_lockfile","lockfile":"request-only-marker"}}),
    ] {
        assert_eq!(
            fixture.request(value).send().await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(fixture.writer.calls.load(Ordering::SeqCst), 0);
    fixture.finish().await;
}
#[tokio::test]
async fn private_rpc_checks_allowlist_and_revalidates_deleted_or_recreated_pods() {
    let denied = Fixture::new(false).await;
    assert_eq!(
        denied
            .request(source_request())
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(denied.writer.calls.load(Ordering::SeqCst), 0);
    denied.finish().await;
    let fixture = Fixture::new(true).await;
    fixture.kube.deleting.store(true, Ordering::SeqCst);
    assert_eq!(
        fixture
            .request(source_request())
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    fixture.kube.deleting.store(false, Ordering::SeqCst);
    fixture.kube.wrong_uid.store(true, Ordering::SeqCst);
    assert_eq!(
        fixture
            .request(source_request())
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(fixture.writer.calls.load(Ordering::SeqCst), 0);
    fixture.finish().await;
}
#[tokio::test]
async fn disconnect_drops_owned_acquisition_without_detached_work() {
    let fixture = Fixture::new(true).await;
    fixture.writer.hold.store(true, Ordering::SeqCst);
    let mut response = fixture.request(source_request()).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.chunk().await.unwrap().unwrap().as_ref(), b" ");
    tokio::time::timeout(Duration::from_secs(2), fixture.writer.entered.notified())
        .await
        .unwrap();
    drop(response);
    tokio::time::timeout(Duration::from_secs(2), async {
        while fixture.writer.cancelled.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(fixture.writer.calls.load(Ordering::SeqCst), 1);
    fixture.finish().await;
}
#[test]
fn runtime_alias_is_serve_only_and_configuration_rejects_identity_redirects() {
    assert_eq!(
        runtime_arguments(vec!["fixture.toml".into()]).unwrap().0,
        RuntimeRole::Serve
    );
    assert_eq!(
        runtime_arguments(vec!["serve".into(), "fixture.toml".into()])
            .unwrap()
            .0,
        RuntimeRole::Serve
    );
    assert_eq!(
        runtime_arguments(vec!["collect".into(), "fixture.toml".into()])
            .unwrap()
            .0,
        RuntimeRole::Collect
    );
    for endpoint in [
        "http://writer/v1/acquire",
        "https://user:secret@writer/v1/acquire",
        "https://writer/v1/acquire?scope=write",
        "https://writer/other",
    ] {
        assert!(
            WriterClientConfig {
                endpoint: endpoint.into(),
                token_file: "/run/token".into(),
                ca_file: None
            }
            .validate()
            .is_err()
        );
    }
}

#[tokio::test]
async fn private_body_admission_charges_actual_bytes_and_releases_capacity() {
    let buffers = Arc::new(tokio::sync::Semaphore::new(4 * 1024 * 1024));
    let request = Request::builder()
        .header(header::CONTENT_LENGTH, "16")
        .body(Body::from(vec![b'x'; 16]))
        .unwrap();
    let (bytes, permit) = admitted_body(request, buffers.clone()).await.unwrap();
    assert_eq!(bytes.len(), 16);
    assert_eq!(buffers.available_permits(), 4 * 1024 * 1024 - 16);
    let held = buffers
        .clone()
        .try_acquire_many_owned((4 * 1024 * 1024 - 16) as u32)
        .unwrap();
    let request = Request::builder()
        .header(header::CONTENT_LENGTH, "1")
        .body(Body::from("x"))
        .unwrap();
    assert_eq!(
        admitted_body(request, buffers.clone()).await.unwrap_err(),
        StatusCode::TOO_MANY_REQUESTS
    );
    drop(held);
    drop(permit);
    assert_eq!(buffers.available_permits(), 4 * 1024 * 1024);
    let request = Request::new(Body::from_stream(futures::stream::iter(vec![
        Ok::<_, std::convert::Infallible>(Bytes::from_static(b"ab")),
        Ok(Bytes::from_static(b"cde")),
    ])));
    let (bytes, permit) = admitted_body(request, buffers.clone()).await.unwrap();
    assert_eq!(bytes.as_ref(), b"abcde");
    assert_eq!(buffers.available_permits(), 4 * 1024 * 1024 - 5);
    drop(permit);
    assert_eq!(buffers.available_permits(), 4 * 1024 * 1024);
}
