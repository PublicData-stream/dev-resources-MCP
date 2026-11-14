//! Offline admission and recovery checks with the configured memory reservation intact.
use devres_server::{
    ServerBuilder,
    config::{AccessPolicy, Limits, SourceOffer},
    endpoint::{Binding, BoundEndpoint, Endpoint, EndpointContext},
    http::HttpEndpoint,
    registry::server_info_registry,
};
use serde_json::{Value, json};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio_util::sync::CancellationToken;

struct Fixture {
    url: String,
    client: reqwest::Client,
    gate: Arc<tokio::sync::Semaphore>,
    entered: Arc<tokio::sync::Notify>,
    calls: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
    context: EndpointContext,
    shutdown: CancellationToken,
    task: tokio::task::JoinHandle<Result<(), devres_server::ServerError>>,
}
struct ObservedHttp {
    endpoint: HttpEndpoint,
    observe: tokio::sync::oneshot::Sender<EndpointContext>,
}
impl Endpoint for ObservedHttp {
    fn id(&self) -> &str {
        self.endpoint.id()
    }
    fn bindings(&self) -> Vec<Binding> {
        self.endpoint.bindings()
    }
    async fn bind(
        self,
        context: EndpointContext,
    ) -> Result<BoundEndpoint, devres_server::ServerError> {
        let _ = self.observe.send(context.clone());
        self.endpoint.bind(context).await
    }
}
struct Active(Arc<AtomicUsize>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Fixture {
    async fn new() -> Self {
        Self::with_limits(Limits {
            io_timeout_secs: 1,
            call_timeout_secs: 3,
            ..Limits::default()
        })
        .await
    }
    async fn with_limits(limits: Limits) -> Self {
        let source = SourceOffer::new("https://source.test/revision").unwrap();
        let mut registry = server_info_registry(source.clone()).unwrap();
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let active = Arc::new(AtomicUsize::new(0));
        let entered = Arc::new(tokio::sync::Notify::new());
        let (g, c, p, a, e) = (
            gate.clone(),
            calls.clone(),
            peak.clone(),
            active,
            entered.clone(),
        );
        registry.register(json!({"name":"held","description":"Fixture admission gate.","inputSchema":{"type":"object","properties":{},"additionalProperties":false},"annotations":{"readOnlyHint":true}}), move |_, _| {
            let (g,c,p,a,e) = (g.clone(),c.clone(),p.clone(),a.clone(),e.clone());
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                p.fetch_max(a.fetch_add(1, Ordering::SeqCst)+1, Ordering::SeqCst);
                let _active = Active(a); e.notify_one();
                let permit = g.acquire().await.unwrap(); permit.forget();
                Ok(json!({"ok":true}))
            }
        }).unwrap();
        registry.register(json!({"name":"unavailable","description":"Fixture application error.","inputSchema":{"type":"object","properties":{},"additionalProperties":false},"annotations":{"readOnlyHint":true}}), |_, _| async { Err(devres_domain::Error::unavailable("Fixture source unavailable.")) }).unwrap();
        let mut builder = ServerBuilder::new(registry, limits, source);
        let (observe, observed) = tokio::sync::oneshot::channel();
        builder
            .register_endpoint(ObservedHttp {
                observe,
                endpoint: HttpEndpoint {
                    bind: "127.0.0.1:0".parse().unwrap(),
                    access: AccessPolicy {
                        allowed_hosts: vec!["backend".into()],
                        allowed_origins: vec![],
                    },
                    tls: None,
                    edge_mtls: None,
                },
            })
            .unwrap();
        let server = builder.bind().await.unwrap();
        let context = observed.await.unwrap();
        let url = format!("http://{}/mcp", server.addresses()[0].1[0]);
        let shutdown = CancellationToken::new();
        let signal = shutdown.clone();
        let task = tokio::spawn(async move { server.run(signal).await });
        Self {
            url,
            client: reqwest::Client::new(),
            gate,
            entered,
            calls,
            peak,
            context,
            shutdown,
            task,
        }
    }
    fn request(&self, revision: &str, name: &str, id: usize) -> reqwest::RequestBuilder {
        let mut params = json!({"name":name,"arguments":{}});
        if revision == "2026-07-28" {
            params["_meta"] = json!({"io.modelcontextprotocol/protocolVersion":revision,"io.modelcontextprotocol/clientInfo":{"name":"fixture","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}});
        }
        self.client
            .post(&self.url)
            .header("host", "backend")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-protocol-version", revision)
            .header("mcp-method", "tools/call")
            .header("mcp-name", name)
            .json(&json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":params}))
    }
    async fn stop(self) {
        self.shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(5), self.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}
async fn json_response(response: reqwest::Response) -> Value {
    let text = response.text().await.unwrap();
    serde_json::from_str(&text).unwrap_or_else(|_| {
        text.lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .find(|v| v.get("id").is_some())
            .unwrap()
    })
}

#[tokio::test]
async fn ten_default_limit_calls_are_admitted_together_in_both_revisions() {
    for revision in ["2026-07-28", "2025-11-25"] {
        let fixture = Fixture::new().await;
        let mut tasks = tokio::task::JoinSet::new();
        for id in 0..10 {
            let request = fixture.request(revision, "held", id);
            tasks.spawn(async move {
                let response = request.send().await.unwrap();
                assert_eq!(response.status(), 200);
                json_response(response).await
            });
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while fixture.calls.load(Ordering::SeqCst) < 10 {
                fixture.entered.notified().await;
            }
        })
        .await
        .unwrap();
        fixture.gate.add_permits(10);
        while let Some(result) = tokio::time::timeout(Duration::from_secs(3), tasks.join_next())
            .await
            .unwrap()
        {
            assert_eq!(result.unwrap()["result"]["structuredContent"]["ok"], true);
        }
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 10);
        assert_eq!(fixture.peak.load(Ordering::SeqCst), 10);
        let response = fixture
            .request(revision, "unavailable", 10)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let value = json_response(response).await;
        assert_eq!(value["result"]["isError"], true);
        assert_eq!(value["result"]["structuredContent"]["code"], "unavailable");
        assert_eq!(
            fixture
                .request(revision, "server.info", 11)
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
        fixture.stop().await;
    }
}

#[tokio::test]
async fn body_bounds_malformed_input_and_request_capacity_recover() {
    let fixture = Fixture::with_limits(Limits {
        max_message_bytes: 4096,
        max_tool_result_bytes: Some(512),
        max_buffer_bytes: 32768,
        max_in_flight: 2,
        max_calls_per_connection: 2,
        io_timeout_secs: 1,
        call_timeout_secs: 3,
        ..Limits::default()
    })
    .await;
    let mut tasks = tokio::task::JoinSet::new();
    for id in 0..2 {
        let request = fixture.request("2026-07-28", "held", id);
        tasks.spawn(async move { json_response(request.send().await.unwrap()).await });
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        while fixture.calls.load(Ordering::SeqCst) < 2 {
            fixture.entered.notified().await;
        }
    })
    .await
    .unwrap();
    let response = fixture
        .request("2026-07-28", "held", 3)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 503);
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 2);
    fixture.gate.add_permits(2);
    while let Some(result) = tasks.join_next().await {
        result.unwrap();
    }
    assert_eq!(
        fixture
            .request("2026-07-28", "server.info", 4)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    for body in [
        reqwest::Body::from(vec![b'x'; 4097]),
        reqwest::Body::wrap_stream(futures::stream::iter([
            Ok::<_, std::io::Error>(vec![b'x'; 2048]),
            Ok(vec![b'x'; 2049]),
        ])),
    ] {
        let response = fixture
            .client
            .post(&fixture.url)
            .header("host", "backend")
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 413);
    }
    let response = fixture
        .client
        .post(&fixture.url)
        .header("host", "backend")
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .body("not-json")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 415);
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        fixture
            .request("2026-07-28", "server.info", 5)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    fixture.stop().await;
}

#[tokio::test]
async fn exhausted_shared_bytes_expire_before_dispatch_and_recover() {
    let fixture = Fixture::new().await;
    let held = fixture
        .context
        .buffers
        .clone()
        .try_acquire_many_owned((64 * 1024 * 1024) as u32)
        .unwrap();
    let started = tokio::time::Instant::now();
    let response = fixture
        .request("2026-07-28", "held", 1)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 503);
    assert!(started.elapsed() >= Duration::from_millis(900));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        fixture
            .context
            .handler
            .counters
            .http_buffer_wait_expired
            .load(Ordering::Relaxed),
        1
    );
    drop(held);
    let response = fixture
        .request("2026-07-28", "server.info", 2)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    json_response(response).await;
    fixture.stop().await;
}

#[tokio::test]
async fn cancelled_clients_and_shutdown_release_default_admission() {
    let fixture = Fixture::new().await;
    let mut pending = Vec::new();
    for id in 0..10 {
        let request = fixture.request("2026-07-28", "held", id);
        pending.push(tokio::spawn(async move { request.send().await }));
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        while fixture.calls.load(Ordering::SeqCst) < 10 {
            fixture.entered.notified().await;
        }
    })
    .await
    .unwrap();
    for call in pending {
        call.abort();
        let _ = call.await;
    }
    fixture.gate.add_permits(10);
    tokio::time::timeout(Duration::from_secs(3), async {
        while fixture.context.requests.available_permits() != 32
            || fixture.context.buffers.available_permits() != 64 * 1024 * 1024
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    fixture.stop().await;
}

#[tokio::test]
async fn sdk_output_capacity_before_first_event_returns_503_and_recovers() {
    let fixture = Fixture::new().await;
    let request = fixture.request("2026-07-28", "held", 1);
    let pending = tokio::spawn(async move { request.send().await.unwrap() });
    tokio::time::timeout(Duration::from_secs(2), async {
        while fixture.calls.load(Ordering::SeqCst) < 1 {
            fixture.entered.notified().await;
        }
    })
    .await
    .unwrap();
    let available = fixture.context.buffers.available_permits();
    let held = fixture
        .context
        .buffers
        .clone()
        .try_acquire_many_owned(available as u32)
        .unwrap();
    fixture.gate.add_permits(1);
    let response = tokio::time::timeout(Duration::from_secs(2), pending)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), 503);
    assert_eq!(
        fixture
            .context
            .handler
            .counters
            .http_request_rejected
            .load(Ordering::Relaxed),
        1
    );
    drop(response);
    drop(held);
    tokio::time::timeout(Duration::from_secs(2), async {
        while fixture.context.buffers.available_permits() != 64 * 1024 * 1024 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        fixture
            .request("2026-07-28", "server.info", 2)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    fixture.stop().await;
}

#[tokio::test]
async fn sdk_output_capacity_after_progress_closes_stream_and_releases_charges() {
    let fixture = Fixture::new().await;
    let value = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"held","arguments":{},"_meta":{
        "progressToken":"capacity-fixture","io.modelcontextprotocol/protocolVersion":"2026-07-28",
        "io.modelcontextprotocol/clientInfo":{"name":"fixture","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}
    }}});
    let mut response = fixture
        .client
        .post(&fixture.url)
        .header("host", "backend")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "held")
        .json(&value)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let progress = response.chunk().await.unwrap().unwrap();
    assert!(
        std::str::from_utf8(&progress)
            .unwrap()
            .contains("notifications/progress")
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        while fixture.calls.load(Ordering::SeqCst) < 1 {
            fixture.entered.notified().await;
        }
    })
    .await
    .unwrap();
    let available = fixture.context.buffers.available_permits();
    let held = fixture
        .context
        .buffers
        .clone()
        .try_acquire_many_owned(available as u32)
        .unwrap();
    fixture.gate.add_permits(1);
    let end = tokio::time::timeout(Duration::from_secs(2), response.chunk())
        .await
        .unwrap();
    assert!(
        matches!(end, Ok(None) | Err(_)),
        "a capacity failure must not emit an uncharged result"
    );
    drop(response);
    drop(progress);
    drop(held);
    tokio::time::timeout(Duration::from_secs(2), async {
        while fixture.context.buffers.available_permits() != 64 * 1024 * 1024
            || fixture.context.requests.available_permits() != 32
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    fixture.stop().await;
}

async fn direct_sdk_response(
    fixture: &Fixture,
    hooked: bool,
    json_response: bool,
    value: &Value,
    keep_alive: Option<Duration>,
) -> axum::response::Response {
    use rmcp::transport::streamable_http_server::{
        BodyBudget, StreamableHttpServerConfig, StreamableHttpService,
        session::local::LocalSessionManager,
    };
    let budget = Arc::new(BodyBudget::new(
        fixture.context.buffers.clone(),
        8 * 1024 * 1024,
        fixture.context.shutdown.clone(),
    ));
    let mut config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_json_response(json_response)
        .with_sse_keep_alive(keep_alive)
        .with_allowed_hosts(["backend"]);
    if hooked {
        config = config.with_body_budget(budget.clone());
    }
    let handler = fixture.context.handler.clone();
    let service = StreamableHttpService::new(
        move || Ok(handler.clone()),
        Arc::new(LocalSessionManager::default()),
        config,
    );
    let bytes = if hooked {
        budget.encode_json(value).unwrap()
    } else {
        axum::body::Bytes::from(serde_json::to_vec(value).unwrap())
    };
    let mut builder = http::Request::builder()
        .method("POST")
        .uri("http://backend/mcp")
        .header("host", "backend")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2025-11-25");
    if let Some(method) = value["method"].as_str() {
        builder = builder.header("mcp-method", method);
    }
    if let Some(name) = value["params"]["name"].as_str() {
        builder = builder.header("mcp-name", name);
    }
    let mut request = builder.body(axum::body::Body::from(bytes.clone())).unwrap();
    if hooked {
        request.extensions_mut().insert(budget.request(bytes));
    }
    service.handle(request).await.map(axum::body::Body::new)
}

#[tokio::test]
async fn hooked_and_unhooked_sdk_preserve_json_sse_errors_notifications_and_keepalive() {
    use futures::StreamExt;
    let fixture = Fixture::new().await;
    let values = [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}}),
        json!({"jsonrpc":"2.0","id":2,"method":"unknown-fixture-method","params":{}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"unavailable","arguments":{}}}),
    ];
    for json_response in [false, true] {
        for value in &values {
            let mut observed = Vec::new();
            for hooked in [false, true] {
                let response =
                    direct_sdk_response(&fixture, hooked, json_response, value, None).await;
                let status = response.status();
                let kind = response.headers().get("content-type").cloned();
                let bytes = axum::body::to_bytes(response.into_body(), 8 * 1024 * 1024)
                    .await
                    .unwrap();
                observed.push((status, kind, bytes.to_vec()));
                drop(bytes);
                tokio::time::timeout(Duration::from_secs(2), async {
                    while fixture.context.buffers.available_permits() != 64 * 1024 * 1024 {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
            }
            assert_eq!(observed[0], observed[1]);
        }
    }
    let held = json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"held","arguments":{}}});
    for hooked in [false, true] {
        let response = direct_sdk_response(
            &fixture,
            hooked,
            false,
            &held,
            Some(Duration::from_millis(10)),
        )
        .await;
        let mut body = response.into_body().into_data_stream();
        let first = tokio::time::timeout(Duration::from_secs(1), body.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(&first[..], b":\n\n");
        drop(first);
        drop(body);
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        while fixture.context.buffers.available_permits() != 64 * 1024 * 1024 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    fixture.stop().await;
}

#[tokio::test]
async fn shutdown_cancels_held_default_requests_and_returns_all_bytes() {
    let fixture = Fixture::new().await;
    let buffers = fixture.context.buffers.clone();
    let requests = fixture.context.requests.clone();
    let mut pending = Vec::new();
    for id in 0..10 {
        let request = fixture.request("2026-07-28", "held", id);
        pending.push(tokio::spawn(async move { request.send().await }));
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        while fixture.calls.load(Ordering::SeqCst) < 10 {
            fixture.entered.notified().await;
        }
    })
    .await
    .unwrap();
    fixture.stop().await;
    for task in pending {
        let _ = task.await.unwrap();
    }
    assert_eq!(requests.available_permits(), 32);
    assert_eq!(buffers.available_permits(), 64 * 1024 * 1024);
}
