//! Offline wire-level tests: no provider or persistent service is contacted.
use devres_server::{
    ServerBuilder,
    config::{AccessPolicy, Limits, SourceOffer},
    http::{HealthEndpoint, HttpEndpoint},
    registry::server_info_registry,
    webtransport::WebTransportEndpoint,
};
use serde_json::{Value, json};
use std::{
    net::{SocketAddr, UdpSocket},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio_util::sync::CancellationToken;

fn meta() -> Value {
    json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"offline-test","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}})
}
async fn response_json(response: reqwest::Response) -> Value {
    let text = response.text().await.unwrap();
    if let Ok(value) = serde_json::from_str(&text) {
        return value;
    }
    text.lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .find_map(|line| {
            serde_json::from_str::<Value>(line)
                .ok()
                .filter(|v| v.get("id").is_some())
        })
        .unwrap_or_else(|| panic!("missing JSON/SSE response"))
}
#[tokio::test]
async fn both_revisions_validation_origin_and_private_health() {
    let mut registry =
        server_info_registry(SourceOffer::new("https://source.test/revision").unwrap()).unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    registry.register(json!({"name":"bounded","description":"Synthetic validation test.","inputSchema":{"type":"object","properties":{"value":{"type":"string","maxLength":5}},"required":["value"],"additionalProperties":false},"annotations":{"readOnlyHint":true}}), move |_,_| { seen.fetch_add(1,Ordering::Relaxed); async { Ok(json!({"ok":true})) } }).unwrap();
    let mut builder = ServerBuilder::new(
        registry,
        Limits::default(),
        SourceOffer::new("https://source.test/revision").unwrap(),
    );
    builder
        .register_endpoint(HttpEndpoint {
            bind: "127.0.0.1:0".parse().unwrap(),
            access: AccessPolicy {
                allowed_hosts: vec!["backend".into()],
                allowed_origins: vec!["https://client.test".into()],
            },
            tls: None,
            edge_mtls: None,
        })
        .unwrap();
    builder
        .register_endpoint(HealthEndpoint {
            bind: "127.0.0.1:0".parse().unwrap(),
        })
        .unwrap();
    let server = builder.bind().await.unwrap();
    let addresses = server.addresses();
    let http = addresses.iter().find(|(id, _)| id == "http").unwrap().1[0];
    let health = addresses.iter().find(|(id, _)| id == "health").unwrap().1[0];
    let shutdown = CancellationToken::new();
    let signal = shutdown.clone();
    let task = tokio::spawn(async move { server.run(signal).await });
    let client = reqwest::Client::new();
    let request = |value: Value| {
        let method = value["method"].as_str().unwrap().to_owned();
        let mut request = client
            .post(format!("http://{http}/mcp"))
            .header("host", "backend")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-protocol-version", "2026-07-28")
            .header("mcp-method", method)
            .json(&value);
        if let Some(name) = value.pointer("/params/name").and_then(Value::as_str) {
            request = request.header("mcp-name", name);
        }
        request
    };
    let discovery = request(
        json!({"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":meta()}}),
    )
    .send()
    .await
    .unwrap();
    let status = discovery.status();
    let value = response_json(discovery).await;
    assert!(status.is_success(), "discovery status {status}: {value}");
    assert_eq!(
        value["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
        "dev-resources-MCP"
    );
    let listed = response_json(
        request(json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":meta()}}))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(listed["result"]["tools"].as_array().unwrap().len(), 2);
    let rejected = request(json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"bounded","arguments":{"value":"too long"},"_meta":meta()}})).send().await.unwrap();
    assert_eq!(rejected.status(), 400);
    assert_eq!(response_json(rejected).await["error"]["code"], -32602);
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    let rejected =
        request(json!({"jsonrpc":"2.0","id":4,"method":"tools/list","params":{"_meta":meta()}}))
            .header("origin", "https://evil.test")
            .send()
            .await
            .unwrap();
    assert_eq!(rejected.status(), 403);
    let rejected =
        request(json!({"jsonrpc":"2.0","id":5,"method":"tools/list","params":{"_meta":meta()}}))
            .header("host", "evil.test")
            .send()
            .await
            .unwrap();
    assert_eq!(rejected.status(), 403);
    let legacy = client.post(format!("http://{http}/mcp")).header("host","backend").header("accept","application/json, text/event-stream").json(&json!({"jsonrpc":"2.0","id":6,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"legacy","version":"1"}}})).send().await.unwrap();
    assert!(legacy.headers().get("mcp-session-id").is_none());
    assert_eq!(
        response_json(legacy).await["result"]["protocolVersion"],
        "2025-11-25"
    );
    assert_eq!(
        client
            .get(format!("http://{http}/ready"))
            .header("host", "backend")
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    assert_eq!(
        client
            .get(format!("http://{health}/ready"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let metrics = client
        .get(format!("http://{health}/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(metrics.contains("devres_tool_calls_total"));
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
#[tokio::test]
async fn native_webtransport_probe_both_revisions_and_origin_rejection() {
    let temp = tempfile::tempdir().unwrap();
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let cert_path = temp.path().join("cert.pem");
    let key_path = temp.path().join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.signing_key.serialize_pem()).unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let bind = socket.local_addr().unwrap();
    drop(socket);
    let authority = format!("127.0.0.1:{}", bind.port());
    let source = SourceOffer::new("https://source.test/revision").unwrap();
    let mut builder = ServerBuilder::new(
        server_info_registry(source.clone()).unwrap(),
        Limits::default(),
        source,
    );
    builder
        .register_endpoint(WebTransportEndpoint {
            bind,
            certificate: cert_path.clone(),
            private_key: key_path,
            access: AccessPolicy {
                allowed_hosts: vec![authority.clone()],
                allowed_origins: vec!["https://client.test".into()],
            },
            edge_mtls: None,
        })
        .unwrap();
    let server = builder.bind().await.unwrap();
    let shutdown = CancellationToken::new();
    let signal = shutdown.clone();
    let task = tokio::spawn(async move { server.run(signal).await });
    for revision in ["2026-07-28", "2025-11-25"] {
        let status = tokio::process::Command::new(env!("CARGO_BIN_EXE_devres-probe"))
            .args([
                format!("https://{authority}/mcp-wt/v1"),
                cert_path.to_str().unwrap().into(),
                revision.into(),
                "https://client.test".into(),
            ])
            .output()
            .await
            .unwrap();
        assert!(
            status.status.success(),
            "probe failed: {}",
            String::from_utf8_lossy(&status.stderr)
        );
    }
    let rejected = tokio::process::Command::new(env!("CARGO_BIN_EXE_devres-probe"))
        .args([
            format!("https://{authority}/mcp-wt/v1"),
            cert_path.to_str().unwrap().into(),
            "2026-07-28".into(),
            "https://evil.test".into(),
        ])
        .output()
        .await
        .unwrap();
    assert!(!rejected.status.success());
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
#[test]
fn unspecified_addresses_conflict_before_any_listener_binds() {
    let source = SourceOffer::new("https://source.test").unwrap();
    let mut builder = ServerBuilder::new(
        server_info_registry(source.clone()).unwrap(),
        Limits::default(),
        source,
    );
    let endpoint = |bind: SocketAddr| HttpEndpoint {
        bind,
        access: AccessPolicy {
            allowed_hosts: vec!["backend".into()],
            allowed_origins: vec![],
        },
        tls: None,
        edge_mtls: None,
    };
    builder
        .register_endpoint(endpoint("0.0.0.0:8080".parse().unwrap()))
        .unwrap();
    assert!(
        builder
            .register_endpoint(HealthEndpoint {
                bind: "127.0.0.1:8080".parse().unwrap()
            })
            .is_err()
    );
}

#[tokio::test]
async fn disconnect_drops_in_flight_tool_inputs() {
    struct Dropped(Arc<tokio::sync::Notify>);
    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.notify_one();
        }
    }
    let source = SourceOffer::new("https://source.test/revision").unwrap();
    let mut registry = server_info_registry(source.clone()).unwrap();
    let started = Arc::new(tokio::sync::Notify::new());
    let dropped = Arc::new(tokio::sync::Notify::new());
    let entered = started.clone();
    let released = dropped.clone();
    registry.register(json!({"name":"slow","description":"Synthetic request ownership test.","inputSchema":{"type":"object","properties":{},"additionalProperties":false},"annotations":{"readOnlyHint":true}}), move |input, _| {
        let entered = entered.clone(); let released = released.clone();
        async move {
            let _owned_input = input; let _drop = Dropped(released);
            entered.notify_one();
            std::future::pending::<devres_domain::Result<Value>>().await
        }
    }).unwrap();
    let mut builder = ServerBuilder::new(registry, Limits::default(), source);
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
    let http = server.addresses()[0].1[0];
    let shutdown = CancellationToken::new();
    let signal = shutdown.clone();
    let task = tokio::spawn(async move { server.run(signal).await });
    let mut metadata = meta();
    metadata["progressToken"] = json!("ownership");
    let response = reqwest::Client::new().post(format!("http://{http}/mcp")).header("host","backend").header("accept","application/json, text/event-stream").header("mcp-protocol-version","2026-07-28").header("mcp-method","tools/call").header("mcp-name","slow").json(&json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"slow","arguments":{},"_meta":metadata}})).send().await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), started.notified())
        .await
        .unwrap();
    drop(response);
    tokio::time::timeout(Duration::from_secs(3), dropped.notified())
        .await
        .expect("disconnect must release request-owned inputs");
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
