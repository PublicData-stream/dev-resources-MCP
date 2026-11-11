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
async fn dotted_tools_are_discovered_and_legacy_names_rejected_in_both_http_revisions() {
    let source = SourceOffer::new("https://source.test/revision").unwrap();
    let mut registry = server_info_registry(source.clone()).unwrap();
    for descriptor in devres_adapters::Research::tool_schemas() {
        registry
            .register(descriptor, |_, _| async { Ok(json!({"called":true})) })
            .unwrap();
    }
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
    let client = reqwest::Client::new();
    let expected: Vec<String> = serde_json::from_str(include_str!("tool-names.json")).unwrap();
    for revision in ["2026-07-28", "2025-11-25"] {
        let request = |method: &str, mut params: Value| {
            let modern = revision == "2026-07-28";
            if modern {
                params["_meta"] = meta();
            }
            let mut request = client
                .post(format!("http://{http}/mcp"))
                .header("host", "backend")
                .header("accept", "application/json, text/event-stream")
                .header("mcp-protocol-version", revision);
            if modern {
                request = request.header("mcp-method", method);
                if let Some(name) = params["name"].as_str() {
                    request = request.header("mcp-name", name);
                }
            }
            request.json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
        };
        if revision == "2025-11-25" {
            let initialized = response_json(
                request(
                    "initialize",
                    json!({
                        "protocolVersion":revision,"capabilities":{},
                        "clientInfo":{"name":"tool-name-test","version":"1"}
                    }),
                )
                .send()
                .await
                .unwrap(),
            )
            .await;
            assert_eq!(initialized["result"]["protocolVersion"], revision);
        }
        let listed = response_json(request("tools/list", json!({})).send().await.unwrap()).await;
        let actual: Vec<_> = listed["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| tool["name"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(actual, expected);
        let obsolete: Vec<String> =
            serde_json::from_str(include_str!("obsolete-package-tool-names.json")).unwrap();
        let rejected_names = obsolete
            .iter()
            .cloned()
            .chain(obsolete.iter().map(|name| name.replacen('.', "_", 1)))
            .chain(
                expected
                    .iter()
                    .filter(|name| name.contains('.'))
                    .map(|name| name.replacen('.', "_", 1)),
            )
            .chain(
                [
                    "packages.crate.api.search",
                    "packages.npm.advisory.get",
                    "packages.crates.search",
                    "rfc.catalog.search",
                ]
                .map(str::to_owned),
            );
        for old in rejected_names {
            let rejected = request("tools/call", json!({"name":old,"arguments":{}}))
                .send()
                .await
                .unwrap();
            assert_eq!(
                rejected.status(),
                if revision == "2026-07-28" { 400 } else { 200 }
            );
            let value = response_json(rejected).await;
            assert_eq!(value["error"]["code"], -32602, "{old}");
            assert_eq!(value["error"]["message"], "unknown tool", "{old}");
        }
        for (name, arguments) in [
            ("server.info", json!({})),
            ("rfc.catalog_search", json!({})),
            (
                "packages.crate.compare",
                json!({"name":"example","from_version":"1.0.0","to_version":"2.0.0","kind":"metadata"}),
            ),
            (
                "packages.npm.metadata",
                json!({"name":"example","version":"1.0.0"}),
            ),
            (
                "packages.crate.advisory_lookup",
                json!({"name":"example","version":"1.0.0"}),
            ),
            (
                "packages.crate.audit_lockfile",
                json!({"lockfile":"version = 4"}),
            ),
            (
                "packages.npm.audit_lockfile",
                json!({"lockfile":"{}","lockfile_format":"npm"}),
            ),
        ] {
            let value = response_json(
                request("tools/call", json!({"name":name,"arguments":arguments}))
                    .send()
                    .await
                    .unwrap(),
            )
            .await;
            assert!(value.get("error").is_none(), "{name}: {value}");
            assert_ne!(value["result"]["isError"], true);
        }
        let invalid = request(
            "tools/call",
            json!({"name":"rfc.catalog_search","arguments":{"url":"https://untrusted.invalid"}}),
        )
        .send()
        .await
        .unwrap();
        assert_eq!(response_json(invalid).await["error"]["code"], -32602);
    }
    let mismatch = client.post(format!("http://{http}/mcp"))
        .header("host", "backend").header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call").header("mcp-name", "server_info")
        .json(&json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"server.info","arguments":{},"_meta":meta()}}))
        .send().await.unwrap();
    assert_eq!(mismatch.status(), 400);
    assert!(response_json(mismatch).await.get("error").is_some());
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn http_media_and_optional_extensions_preserve_both_protocol_contracts() {
    let source = SourceOffer::new("https://source.test/revision").unwrap();
    let mut registry = server_info_registry(source.clone()).unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    registry
        .register(
            json!({
                "name":"fixture.header",
                "description":"Synthetic routing-header validation.",
                "inputSchema":{
                    "type":"object",
                    "properties":{"region":{"type":"string","x-mcp-header":"Region"}},
                    "additionalProperties":false
                },
                "annotations":{"readOnlyHint":true}
            }),
            move |_, _| {
                seen.fetch_add(1, Ordering::Relaxed);
                async { Ok(json!({"ok":true})) }
            },
        )
        .unwrap();
    // Resources alone must not opt the server into the skills extension.
    registry.with_resource_reader(|_, _| async { Ok(json!({"contents":[]})) });
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
    let client = reqwest::Client::new();
    for revision in ["2026-07-28", "2025-11-25"] {
        let request = |method: &str, mut params: Value, accept: &[&str], content_type: &str| {
            let mut request = client
                .post(format!("http://{http}/mcp"))
                .header("host", "backend")
                .header("content-type", content_type)
                .header("mcp-protocol-version", revision);
            for value in accept {
                request = request.header("accept", *value);
            }
            if revision == "2026-07-28" {
                params["_meta"] = meta();
                request = request.header("mcp-method", method);
                if let Some(name) = params["name"].as_str() {
                    request = request.header("mcp-name", name);
                }
            }
            request.body(
                serde_json::to_vec(
                    &json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}),
                )
                .unwrap(),
            )
        };
        let accept = ["application/json, text/event-stream"];
        let (method, params) = if revision == "2026-07-28" {
            ("server/discover", json!({}))
        } else {
            (
                "initialize",
                json!({"protocolVersion":revision,"capabilities":{},"clientInfo":{"name":"upgrade-fixture","version":"1"}}),
            )
        };
        let opened = request(method, params, &accept, "application/json")
            .send()
            .await
            .unwrap();
        assert!(opened.status().is_success());
        assert!(opened.headers().get("mcp-session-id").is_none());
        let opened = response_json(opened).await;
        if revision == "2026-07-28" {
            assert_eq!(
                opened["result"]["supportedVersions"],
                json!(["2026-07-28", "2025-11-25"])
            );
        } else {
            assert_eq!(opened["result"]["protocolVersion"], revision);
        }
        assert_eq!(opened["result"]["capabilities"]["tools"], json!({}));
        assert_eq!(opened["result"]["capabilities"]["resources"], json!({}));
        assert!(opened["result"]["capabilities"].get("extensions").is_none());
        for (method, params) in [
            ("skills/list", json!({})),
            (
                "skills/get",
                json!({"uri":"devres://skills/fixture/SKILL.md"}),
            ),
            (
                "resources/directory/read",
                json!({"uri":"devres://skills/fixture/"}),
            ),
        ] {
            let rejected = request(method, params, &accept, "application/json")
                .send()
                .await
                .unwrap();
            assert_eq!(
                response_json(rejected).await["error"]["code"],
                -32601,
                "{revision} {method}"
            );
        }
        for (accept, content_type, expected) in [
            (
                vec!["application/json, text/event-stream"],
                "application/json",
                200,
            ),
            (
                vec!["APPLICATION/JSON, TEXT/EVENT-STREAM"],
                "APPLICATION/JSON; charset=utf-8",
                200,
            ),
            (
                vec!["application/json", "text/event-stream"],
                "application/json",
                200,
            ),
            (
                vec!["application/json;q=0, text/event-stream"],
                "application/json",
                406,
            ),
            (
                vec!["application/json, text/event-stream;q=0.000"],
                "application/json",
                406,
            ),
            (
                vec!["application/jsonp, text/event-stream"],
                "application/json",
                406,
            ),
            (
                vec!["application/json, text/event-stream"],
                "application/json-seq",
                415,
            ),
        ] {
            let response = request("tools/list", json!({}), &accept, content_type)
                .send()
                .await
                .unwrap();
            assert_eq!(
                response.status().as_u16(),
                expected,
                "{revision} {accept:?} {content_type}"
            );
            if expected == 200 {
                let listed = response_json(response).await;
                assert_eq!(listed["result"]["tools"].as_array().unwrap().len(), 2);
            }
        }
        if revision == "2026-07-28" {
            let valid = request(
                "tools/call",
                json!({"name":"fixture.header","arguments":{"region":"eu"}}),
                &accept,
                "application/json",
            )
            .header("mcp-param-region", "eu")
            .send()
            .await
            .unwrap();
            assert_eq!(
                response_json(valid).await["result"]["structuredContent"]["ok"],
                true
            );
            assert_eq!(calls.load(Ordering::Relaxed), 1);
            let rejected = request(
                "tools/call",
                json!({"name":"fixture.header","arguments":{}}),
                &accept,
                "application/json",
            )
            .header(
                "mcp-param-region",
                reqwest::header::HeaderValue::from_bytes(&[0xff]).unwrap(),
            )
            .send()
            .await
            .unwrap();
            assert_eq!(rejected.status(), 400);
            assert!(response_json(rejected).await.get("error").is_some());
            assert_eq!(calls.load(Ordering::Relaxed), 1);
        }
    }
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
    let mut registry = server_info_registry(source.clone()).unwrap();
    // The native probe verifies complete discovery, including corpus status calls.
    // These schema-backed handlers keep this transport fixture entirely offline.
    for descriptor in devres_adapters::Research::tool_schemas() {
        registry
            .register(descriptor, |_, _| async {
                Ok(json!({"collection_enabled":false,"counts":{},"coverage":"partial"}))
            })
            .unwrap();
    }
    let mut builder = ServerBuilder::new(registry, Limits::default(), source);
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

#[tokio::test]
async fn attribution_notices_reach_both_http_revisions_and_resource_pages() {
    let source = SourceOffer::new("https://source.test/attribution-fixture").unwrap();
    let mut registry = server_info_registry(source.clone()).unwrap();
    let notice_uri = format!("devres://attribution/{}", "a".repeat(64));
    let attribution = json!({"readable_notice":"Copyright fixture authors; original terms apply.","resource_uri":notice_uri,"generations":[]});
    let tool_attribution = attribution.clone();
    registry.register(json!({"name":"fixture.attribution","description":"Public synthetic attribution fixture.","inputSchema":{"type":"object","properties":{},"additionalProperties":false},"annotations":{"readOnlyHint":true}}),move |_,_| {
        let attribution=tool_attribution.clone();
        async move { Ok(json!({"page":{"text":"original page","offset":12},"attribution":attribution})) }
    }).unwrap();
    registry.with_resource_reader(move |uri,_| {
        let attribution=attribution.clone();
        async move { Ok(json!({"contents":[{"uri":uri,"mimeType":"text/plain","text":"original page","_meta":{"attribution":attribution}}, {"uri":attribution["resource_uri"],"mimeType":"text/plain","text":attribution["readable_notice"]}]})) }
    });
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
    let client = reqwest::Client::new();
    for revision in ["2026-07-28", "2025-11-25"] {
        let request = |method: &str, mut params: Value| {
            let mut request = client
                .post(format!("http://{http}/mcp"))
                .header("host", "backend")
                .header("accept", "application/json, text/event-stream")
                .header("mcp-protocol-version", revision);
            if revision == "2026-07-28" {
                params["_meta"] = meta();
                request = request.header("mcp-method", method);
                if let Some(name) = params
                    .get("name")
                    .or_else(|| params.get("uri"))
                    .and_then(Value::as_str)
                {
                    request = request.header("mcp-name", name);
                }
            }
            request.json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
        };
        if revision == "2025-11-25" {
            let response=request("initialize",json!({"protocolVersion":revision,"capabilities":{},"clientInfo":{"name":"attribution-fixture","version":"1"}})).send().await.unwrap();
            assert!(response.status().is_success());
            let _ = response_json(response).await;
        }
        let tool = response_json(
            request(
                "tools/call",
                json!({"name":"fixture.attribution","arguments":{}}),
            )
            .send()
            .await
            .unwrap(),
        )
        .await;
        assert_eq!(
            tool["result"]["structuredContent"]["page"]["text"],
            "original page"
        );
        let content = tool["result"]["content"].as_array().unwrap();
        assert!(content.iter().any(|item| item["type"] == "text"
            && item["text"] == "Copyright fixture authors; original terms apply."));
        assert!(
            content
                .iter()
                .any(|item| item["type"] == "resource_link" && item["uri"] == notice_uri)
        );
        let resource = response_json(
            request("resources/read", json!({"uri":"devres://capture/fixture"}))
                .send()
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(resource["result"]["contents"][0]["text"], "original page");
        assert_eq!(
            resource["result"]["contents"][1]["text"],
            "Copyright fixture authors; original terms apply."
        );
        assert_eq!(
            resource["result"]["contents"][0]["_meta"]["attribution"]["resource_uri"],
            notice_uri
        );
    }
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn oversized_attribution_error_details_are_omitted_in_both_http_revisions() {
    let source = SourceOffer::new("https://source.test/error-fixture").unwrap();
    let mut registry = server_info_registry(source.clone()).unwrap();
    registry.register(json!({"name":"fixture.attribution_error","description":"Synthetic bounded error.","inputSchema":{"type":"object","properties":{},"additionalProperties":false},"annotations":{"readOnlyHint":true}}),|_,_|async {
        Err(devres_domain::Error::unavailable("Attribution repair is pending.").with_details(json!({"attribution_status":"unavailable","subjects":[{"key":"public-fixture-".repeat(8192)}]})))
    }).unwrap();
    registry.with_resource_reader(|uri,_|async move {
        if uri.ends_with("/required-notice-too-large") {
            return Ok(json!({"contents":[{"uri":uri,"mimeType":"text/plain","text":"original-selected-page"},
                {"uri":"devres://attribution/fixture","mimeType":"text/plain","text":"mandatory-notice".repeat(8192)}]}));
        }
        Err(devres_domain::Error::unavailable("Attribution repair is pending.").with_details(json!({"attribution_status":"unavailable","subjects":[{"key":"public-fixture-".repeat(8192)}]})))
    });
    let limits = Limits {
        max_message_bytes: 8192,
        max_tool_result_bytes: None,
        ..Default::default()
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
    let http = server.addresses()[0].1[0];
    let shutdown = CancellationToken::new();
    let signal = shutdown.clone();
    let task = tokio::spawn(async move { server.run(signal).await });
    let client = reqwest::Client::new();
    for revision in ["2026-07-28", "2025-11-25"] {
        let request = |method: &str, mut params: Value| {
            let mut request = client
                .post(format!("http://{http}/mcp"))
                .header("host", "backend")
                .header("accept", "application/json, text/event-stream")
                .header("mcp-protocol-version", revision);
            if revision == "2026-07-28" {
                params["_meta"] = meta();
                request = request.header("mcp-method", method);
                if let Some(name) = params
                    .get("name")
                    .or_else(|| params.get("uri"))
                    .and_then(Value::as_str)
                {
                    request = request.header("mcp-name", name);
                }
            }
            request.json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
        };
        if revision == "2025-11-25" {
            let initialized=request("initialize",json!({"protocolVersion":revision,"capabilities":{},"clientInfo":{"name":"error-fixture","version":"1"}})).send().await.unwrap();
            assert!(initialized.status().is_success());
            let _ = response_json(initialized).await;
        }
        for (method, args) in [
            (
                "tools/call",
                json!({"name":"fixture.attribution_error","arguments":{}}),
            ),
            ("resources/read", json!({"uri":"devres://capture/fixture"})),
        ] {
            let response = request(method, args).send().await.unwrap();
            let raw = response.text().await.unwrap();
            assert!(
                raw.len() < 8192,
                "oversized public error escaped configured message bound"
            );
            assert!(!raw.contains("public-fixture-"));
            let value = serde_json::from_str::<Value>(&raw)
                .ok()
                .or_else(|| {
                    raw.lines()
                        .filter_map(|line| line.strip_prefix("data:"))
                        .find_map(|line| serde_json::from_str::<Value>(line).ok())
                })
                .unwrap();
            if method == "tools/call" {
                assert_eq!(value["result"]["isError"], true);
                assert_eq!(value["result"]["structuredContent"]["code"], "unavailable");
                assert!(
                    value["result"]["structuredContent"]
                        .get("details")
                        .is_none()
                );
            } else {
                assert_eq!(value["error"]["code"], -32602);
                assert!(value["error"].get("data").is_none_or(Value::is_null));
            }
        }
        let oversized = response_json(
            request(
                "resources/read",
                json!({"uri":"devres://capture/required-notice-too-large"}),
            )
            .send()
            .await
            .unwrap(),
        )
        .await;
        assert_eq!(oversized["error"]["code"], -32603);
        assert!(!oversized.to_string().contains("original-selected-page"));
        assert!(!oversized.to_string().contains("mandatory-notice"));
    }
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
