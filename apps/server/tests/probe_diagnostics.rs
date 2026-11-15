//! Native diagnostic fault fixtures: loopback only, no provider or production I/O.
use devres_server::framing::{FrameReader, write_json};
use serde_json::{Value, json};
use std::{os::unix::fs::PermissionsExt, sync::Arc, time::Duration};
use tokio::{sync::Semaphore, time::timeout};
use wtransport::{Endpoint, Identity, ServerConfig};

const MAX: usize = 8 * 1024 * 1024;

#[tokio::test]
async fn native_fault_diagnostics_stream_large_frames_and_sanitize_errors_in_both_revisions() {
    for revision in ["2026-07-28", "2025-11-25"] {
        for malformed in [false, true] {
            let temp = tempfile::tempdir_in("/tmp").unwrap();
            std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
            let cert_path = temp.path().join("cert.pem");
            let key_path = temp.path().join("key.pem");
            std::fs::write(&cert_path, cert.cert.pem()).unwrap();
            std::fs::write(&key_path, cert.signing_key.serialize_pem()).unwrap();
            let identity = Identity::load_pemfiles(&cert_path, key_path).await.unwrap();
            let mut config = ServerConfig::builder()
                .with_bind_address("127.0.0.1:0".parse().unwrap())
                .with_identity(identity)
                .build();
            let mut transport = wtransport::quinn::TransportConfig::default();
            transport.send_window(64 * 1024);
            config
                .quic_config_mut()
                .transport_config(Arc::new(transport));
            let endpoint = Endpoint::server(config).unwrap();
            let address = endpoint.local_addr().unwrap();
            let fixture = tokio::spawn(async move {
                let incoming = endpoint.accept().await;
                let request = incoming.await.unwrap();
                let connection = request
                    .accept_with_headers([("sec-webtransport-http3-draft", "draft02")])
                    .await
                    .unwrap();
                let (mut send, recv) = connection.accept_bi().await.unwrap();
                let budget = Arc::new(Semaphore::new(MAX * 4));
                let mut reader = FrameReader::new(
                    recv,
                    MAX,
                    budget.clone(),
                    Duration::from_secs(10),
                    Duration::from_secs(10),
                );
                let frame = reader.read().await.unwrap().unwrap();
                let value: Value = serde_json::from_slice(&frame.bytes).unwrap();
                assert_eq!(value["id"], 1);
                if malformed {
                    send.write_all(b"private-malformed-response-sentinel\n")
                        .await
                        .unwrap();
                } else {
                    // Exceeds the fixture's 64-KiB send window; peer drain and
                    // acknowledgement are required to complete this frame.
                    let message = "private-upstream-error-sentinel".repeat(20_000);
                    write_json(
                        &mut send,
                        &json!({"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":message}}),
                        MAX,
                        &budget,
                        Duration::from_secs(10),
                    )
                    .await
                    .unwrap();
                }
                let _ = timeout(Duration::from_secs(3), connection.closed()).await;
                endpoint.close(0_u32.into(), b"fixture complete");
            });
            let trace = temp.path().join("trace.jsonl");
            let output = timeout(
                Duration::from_secs(20),
                tokio::process::Command::new(env!("CARGO_BIN_EXE_devres-probe"))
                    .args([
                        "--diagnostic-trace".into(),
                        trace.to_str().unwrap().into(),
                        format!("https://{address}/mcp-wt/v1"),
                        cert_path.to_str().unwrap().into(),
                        revision.into(),
                    ])
                    .output(),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(!output.status.success());
            fixture.await.unwrap();
            let text = std::fs::read_to_string(trace).unwrap();
            assert!(!text.contains("private-"));
            assert!(!String::from_utf8_lossy(&output.stdout).contains("private-"));
            assert!(!String::from_utf8_lossy(&output.stderr).contains("private-"));
            let rows: Vec<Value> = text
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            let last = rows.last().unwrap();
            assert_eq!(last["event"], "failed");
            assert_eq!(last["operation"], 1);
            assert_eq!(
                last["label"],
                if revision == "2026-07-28" {
                    "server/discover"
                } else {
                    "initialize"
                }
            );
            if malformed {
                assert_eq!(last["stage"], "decode");
                assert_eq!(last["result"], "json");
            } else {
                assert_eq!(last["stage"], "assertions");
                assert_eq!(last["result"], "assertion");
                assert!(rows.iter().any(|row| {
                    row["completed_frame_bytes"]
                        .as_u64()
                        .is_some_and(|bytes| bytes > 256 * 1024)
                }));
            }
        }
    }
}
