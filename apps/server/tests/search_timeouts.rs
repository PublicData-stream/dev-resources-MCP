//! Offline transport checks for the independently bounded generic-search deadline.
use devres_server::{
    ServerBuilder,
    config::{AccessPolicy, Limits, SourceOffer},
    framing::{FrameReader, write_json},
    http::HttpEndpoint,
    registry::server_info_registry,
    webtransport::WebTransportEndpoint,
};
use serde_json::{Value, json};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use wtransport::{
    ClientConfig, Endpoint,
    endpoint::ConnectOptions,
    tls::{Certificate, rustls},
};

const MAX: usize = 4096;

fn metadata() -> Value {
    json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"timeout-fixture","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}})
}

fn request(revision: &str, id: usize, name: &str) -> Value {
    let mut params = json!({"name":name,"arguments":{}});
    if revision == "2026-07-28" {
        params["_meta"] = metadata();
    }
    json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":params})
}

struct Active(Arc<AtomicUsize>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn fixture_registry() -> (devres_server::registry::ToolRegistry, Arc<AtomicUsize>) {
    let source = SourceOffer::new("https://source.test/revision").unwrap();
    let mut registry = server_info_registry(source).unwrap();
    let active = Arc::new(AtomicUsize::new(0));
    for name in ["search", "ordinary"] {
        let active = active.clone();
        registry
            .register(
                json!({"name":name,"description":"Synthetic delayed result.","inputSchema":{"type":"object","properties":{},"additionalProperties":false},"annotations":{"readOnlyHint":true}}),
                move |_, _| {
                    let active = active.clone();
                    async move {
                        active.fetch_add(1, Ordering::SeqCst);
                        let _active = Active(active);
                        tokio::time::sleep(Duration::from_millis(2500)).await;
                        Ok(json!({"completed":true}))
                    }
                },
            )
            .unwrap();
    }
    (registry, active)
}

fn fixture_limits() -> Limits {
    Limits {
        max_message_bytes: MAX,
        max_tool_result_bytes: Some(512),
        max_buffer_bytes: MAX * 8,
        call_timeout_secs: 1,
        search_timeout_secs: 4,
        idle_timeout_secs: 5,
        ..Limits::default()
    }
}

async fn response_json(response: reqwest::Response) -> Value {
    let text = response.text().await.unwrap();
    response_value(&text).expect("missing JSON/SSE fixture response")
}

fn response_value(text: &str) -> Option<Value> {
    serde_json::from_str(text).ok().or_else(|| {
        text.lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .find(|value| value.get("id").is_some())
    })
}

#[tokio::test]
async fn http_search_outlives_ordinary_calls_in_both_revisions() {
    let (registry, active) = fixture_registry();
    let mut builder = ServerBuilder::new(
        registry,
        fixture_limits(),
        SourceOffer::new("https://source.test/revision").unwrap(),
    );
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
    let address = server.addresses()[0].1[0];
    let shutdown = CancellationToken::new();
    let signal = shutdown.clone();
    let task = tokio::spawn(async move { server.run(signal).await });
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .unwrap();
    for revision in ["2026-07-28", "2025-11-25"] {
        for (id, name) in [(1, "ordinary"), (2, "search")] {
            let started = tokio::time::Instant::now();
            let response = client
                .post(format!("http://{address}/mcp"))
                .header("host", "backend")
                .header("accept", "application/json, text/event-stream")
                .header("mcp-protocol-version", revision)
                .header("mcp-method", "tools/call")
                .header("mcp-name", name)
                .json(&request(revision, id, name))
                .send()
                .await
                .unwrap();
            if name == "search" {
                assert!(response.status().is_success());
                let result = response_json(response).await;
                assert_eq!(result["result"]["structuredContent"]["completed"], true);
                assert!(started.elapsed() >= Duration::from_secs(2));
            } else {
                if response.status().is_success() {
                    // The outer body deadline may close SSE before the handler's
                    // simultaneous deadline can publish its JSON-RPC error.
                    match response.text().await {
                        Ok(text) => assert!(
                            response_value(&text).is_some_and(|value| value.get("error").is_some())
                        ),
                        Err(error) => assert!(error.is_body() || error.is_decode()),
                    }
                } else {
                    assert_eq!(response.status(), reqwest::StatusCode::GATEWAY_TIMEOUT);
                }
                assert!(started.elapsed() >= Duration::from_millis(900));
                assert!(started.elapsed() < Duration::from_secs(2));
            }
            tokio::time::timeout(Duration::from_secs(1), async {
                while active.load(Ordering::SeqCst) != 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("completed/timed-out requests must release their handler");
        }
    }
    shutdown.cancel();
    task.await.unwrap().unwrap();
}

async fn exchange(
    send: &mut wtransport::SendStream,
    reader: &mut FrameReader<wtransport::RecvStream>,
    budget: &Arc<Semaphore>,
    value: Value,
) -> Value {
    let id = value["id"].clone();
    write_json(send, &value, MAX, budget, Duration::from_secs(1))
        .await
        .unwrap();
    loop {
        let frame = reader.read().await.unwrap().unwrap();
        let response: Value = serde_json::from_slice(&frame.bytes).unwrap();
        if response.get("id") == Some(&id) {
            return response;
        }
    }
}

#[tokio::test]
async fn webtransport_search_completes_without_more_client_frames_in_both_revisions() {
    let temp = tempfile::tempdir_in("/tmp").unwrap();
    let certificate = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let certificate_path = temp.path().join("certificate.pem");
    let key_path = temp.path().join("key.pem");
    std::fs::write(&certificate_path, certificate.cert.pem()).unwrap();
    std::fs::write(&key_path, certificate.signing_key.serialize_pem()).unwrap();
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let bind = socket.local_addr().unwrap();
    drop(socket);
    let (registry, active) = fixture_registry();
    let mut builder = ServerBuilder::new(
        registry,
        fixture_limits(),
        SourceOffer::new("https://source.test/revision").unwrap(),
    );
    builder
        .register_endpoint(WebTransportEndpoint {
            bind,
            certificate: certificate_path.clone(),
            private_key: key_path,
            access: AccessPolicy {
                allowed_hosts: vec![bind.to_string()],
                allowed_origins: vec![],
            },
            edge_mtls: None,
        })
        .unwrap();
    let server = builder.bind().await.unwrap();
    let address = server.addresses()[0].1[0];
    let shutdown = CancellationToken::new();
    let signal = shutdown.clone();
    let task = tokio::spawn(async move { server.run(signal).await });
    let certificate = Certificate::load_pemfile(certificate_path).await.unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(
            certificate.der().to_vec(),
        ))
        .unwrap();
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![wtransport::tls::WEBTRANSPORT_ALPN.to_vec()];
    let endpoint = Endpoint::client(
        ClientConfig::builder()
            .with_bind_default()
            .with_custom_tls(tls)
            .build(),
    )
    .unwrap();
    for revision in ["2026-07-28", "2025-11-25"] {
        let url = format!("https://{address}/mcp-wt/v1");
        let connection = tokio::time::timeout(
            Duration::from_secs(5),
            endpoint.connect(
                ConnectOptions::builder(&url)
                    .add_header("sec-webtransport-http3-draft02", "1")
                    .build(),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        let (mut send, recv) = connection.open_bi().await.unwrap().await.unwrap();
        let budget = Arc::new(Semaphore::new(MAX * 4));
        let mut reader = FrameReader::new(
            recv,
            MAX,
            budget.clone(),
            Duration::from_secs(8),
            Duration::from_secs(1),
        );
        if revision == "2025-11-25" {
            let initialized = exchange(&mut send, &mut reader, &budget, json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":revision,"capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}})).await;
            assert!(initialized.get("result").is_some());
            write_json(
                &mut send,
                &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
                MAX,
                &budget,
                Duration::from_secs(1),
            )
            .await
            .unwrap();
        }
        let result = exchange(
            &mut send,
            &mut reader,
            &budget,
            request(revision, 1, "search"),
        )
        .await;
        assert_eq!(result["result"]["structuredContent"]["completed"], true);
        let result = exchange(
            &mut send,
            &mut reader,
            &budget,
            request(revision, 2, "ordinary"),
        )
        .await;
        assert!(result.get("error").is_some());
        assert_eq!(active.load(Ordering::SeqCst), 0);
        connection.close(0_u32.into(), b"fixture complete");
    }
    shutdown.cancel();
    task.await.unwrap().unwrap();
}
