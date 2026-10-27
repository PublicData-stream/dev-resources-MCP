//! Process-level privacy and canonical sparse-registry matching regression cases.
use serde_json::{Value, json};
use std::io::Write;

fn payload(lockfile: &str) -> Value {
    let text = "```toml\n[advisory]\nid = \"RUSTSEC-2024-0001\"\npackage = \"example\"\ndate = \"2024-01-01\"\n[versions]\npatched = [\">= 1.0.1\"]\n```\n\n# Synthetic advisory\n\nFixture only.\n";
    let mut advisory: rustsec::Advisory = text.parse().unwrap();
    advisory.metadata.collection = Some(rustsec::Collection::Crates);
    let capture = json!({"id":"a".repeat(64),"key":"rustsec:head","source_url":"https://api.github.com/repos/RustSec/advisory-db/commits/main","body_hash":"b".repeat(64),"media_type":"application/json","retrieved_at":devres_domain::unix_now(),"validated_at":devres_domain::unix_now()});
    json!({"lockfile":lockfile,"snapshot":{"head":capture,"bundle":capture,"revision":"c".repeat(40),"advisories":[advisory]},"page":{"offset":0,"limit":20}})
}

fn run(input: &Value) -> std::process::Output {
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_devres-audit-worker"))
        .env_clear()
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(input).unwrap())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn registry_and_sparse_default_sources_match_the_same_advisory() {
    for source in [
        "registry+https://github.com/rust-lang/crates.io-index",
        "sparse+https://index.crates.io/",
    ] {
        let lockfile = format!(
            "version = 4\n[[package]]\nname = \"example\"\nversion = \"1.0.0\"\nsource = \"{source}\"\n"
        );
        let output = run(&payload(&lockfile));
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["Ok"]["vulnerability_count"], 1);
        assert_eq!(report["Ok"]["assessed_count"], 1);
    }
}

#[test]
fn invalid_private_input_is_never_reflected_on_stdio() {
    let secret = "SYNTHETIC_PRIVATE_INPUT_SENTINEL = invalid toml";
    let output = run(&payload(secret));
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let encoded = String::from_utf8(output.stdout).unwrap();
    assert!(!encoded.contains("SYNTHETIC_PRIVATE_INPUT_SENTINEL"));
    let report: Value = serde_json::from_str(&encoded).unwrap();
    assert_eq!(report["Err"]["code"], "invalid_input");
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn kill_on_drop_terminates_worker_holding_incomplete_private_input() {
    use tokio::io::AsyncWriteExt;
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let request = tokio::spawn(async move {
        let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_devres-audit-worker"))
            .env_clear()
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let pid = child.id().unwrap();
        let mut stdin = child.stdin.take().unwrap();
        // Large incomplete input keeps the real helper waiting for EOF. These
        // futures and Child have the same ownership as the production caller.
        stdin.write_all(b"{\"lockfile\":\"").await.unwrap();
        stdin.write_all(&vec![b'x'; 1024 * 1024]).await.unwrap();
        sender.send(pid).unwrap();
        std::future::pending::<()>().await;
        drop((stdin, child));
    });
    let pid = receiver.await.unwrap();
    request.abort();
    let _ = request.await;
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            match tokio::fs::read_to_string(format!("/proc/{pid}/status")).await {
                Err(_) => break,
                Ok(status)
                    if status
                        .lines()
                        .any(|line| line.starts_with("State:") && line.contains('Z')) =>
                {
                    break;
                }
                _ => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
            }
        }
    })
    .await
    .unwrap();
}
