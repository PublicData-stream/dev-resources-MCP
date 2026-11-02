//! Offline admission and recovery checks with the configured memory reservation intact.
use devres_server::{
    ServerBuilder,
    config::{AccessPolicy, Limits, SourceOffer},
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
    shutdown: CancellationToken,
    task: tokio::task::JoinHandle<Result<(), devres_server::ServerError>>,
}
struct Active(Arc<AtomicUsize>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Fixture {
    async fn new() -> Self {
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
        let limits = Limits {
            max_message_bytes: 4096,
            max_tool_result_bytes: Some(512),
            max_buffer_bytes: 32768,
            max_in_flight: 8,
            io_timeout_secs: 1,
            call_timeout_secs: 3,
            ..Limits::default()
        };
        let mut builder = ServerBuilder::new(registry, limits, source);
        builder
            .register_endpoint(HttpEndpoint {
                bind: "127.0.0.1:0".parse().unwrap(),
                access: AccessPolicy {
                    allowed_hosts: vec!["backend".into()],
                    allowed_origins: vec![],
                },
                tls: None,
                edge_mtls: None,
            })
            .unwrap();
        let server = builder.bind().await.unwrap();
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
async fn six_parallel_calls_wait_for_two_reservations_in_both_revisions() {
    for revision in ["2026-07-28", "2025-11-25"] {
        let fixture = Fixture::new().await;
        let mut tasks = tokio::task::JoinSet::new();
        for id in 0..6 {
            let request = fixture.request(revision, "held", id);
            tasks.spawn(async move {
                let response = request.send().await.unwrap();
                assert_eq!(response.status(), 200);
                json_response(response).await
            });
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while fixture.calls.load(Ordering::SeqCst) < 2 {
                fixture.entered.notified().await;
            }
        })
        .await
        .unwrap();
        fixture.gate.add_permits(6);
        while let Some(result) = tokio::time::timeout(Duration::from_secs(3), tasks.join_next())
            .await
            .unwrap()
        {
            assert_eq!(result.unwrap()["result"]["structuredContent"]["ok"], true);
        }
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 6);
        assert_eq!(fixture.peak.load(Ordering::SeqCst), 2);
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
async fn buffer_wait_expiry_precedes_dispatch_and_releases_admission() {
    let fixture = Fixture::new().await;
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
    let start = tokio::time::Instant::now();
    let response = fixture
        .request("2026-07-28", "held", 3)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 503);
    assert!(start.elapsed() >= Duration::from_millis(900));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 2);
    fixture.gate.add_permits(2);
    while tasks.join_next().await.is_some() {}
    let response = fixture
        .request("2026-07-28", "server.info", 4)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let _ = json_response(response).await;
    let response = fixture
        .client
        .post(&fixture.url)
        .header("host", "backend")
        .body(vec![b'x'; 4097])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 413);
    let stream = futures::stream::iter([
        Ok::<_, std::io::Error>(vec![b'x'; 2048]),
        Ok(vec![b'x'; 2049]),
    ]);
    let response = fixture
        .client
        .post(&fixture.url)
        .header("host", "backend")
        .body(reqwest::Body::wrap_stream(stream))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 413);
    fixture.stop().await;
}
