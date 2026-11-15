use super::*;
use crate::{MAX, exchange_response};
use devres_server::framing::{FrameReadPhase, FrameReader};
use serde_json::{Value, json};
use std::{os::unix::fs::PermissionsExt, sync::Arc, time::Duration};
use tokio::{io::AsyncWriteExt, sync::Semaphore};

fn private_temp() -> tempfile::TempDir {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    root
}

fn entries(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn request() -> Value {
    json!({"id":1,"method":"tools/call","params":{"name":"packages.crate.audit_lockfile","arguments":{"lockfile":"private-lockfile-sentinel","credential":"private-credential-sentinel","uri":"private-resource-sentinel"}}})
}

#[tokio::test(start_paused = true)]
async fn timeout_diagnostics_distinguish_no_bytes_and_partial_frame() {
    for partial in [false, true] {
        let temp = private_temp();
        let path = temp.path().join("trace.jsonl");
        let trace = Trace::create(&path).unwrap();
        let (mut tx, rx) = tokio::io::duplex(32);
        if partial {
            tx.write_all(b"{\"private-body-sentinel\":").await.unwrap();
        }
        let budget = Arc::new(Semaphore::new(32 * 1024 * 1024));
        let mut reader = FrameReader::new(
            rx,
            128,
            budget.clone(),
            Duration::from_secs(10),
            Duration::from_secs(10),
        );
        let started = tokio::time::Instant::now();
        let result = TRACE
            .scope(RefCell::new(trace), async {
                exchange_response(&mut Vec::new(), &mut reader, &budget, request()).await
            })
            .await;
        let error = result.unwrap_err();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::TimedOut
        );
        assert_eq!(started.elapsed(), Duration::from_secs(10));
        let rows = entries(&path);
        let last = rows.last().unwrap();
        assert_eq!(last["label"], "tools/call packages.crate.audit_lockfile");
        assert_eq!(last["result"], "timed_out");
        assert_eq!(last["operation"], 1);
        assert_eq!(last["stage"], "read");
        assert_eq!(
            last["frame"]["phase"],
            if partial {
                "completing_frame"
            } else {
                "awaiting_first_byte"
            }
        );
        assert_eq!(
            last["frame"]["buffered_frame_bytes"],
            if partial {
                b"{\"private-body-sentinel\":".len()
            } else {
                0
            }
        );
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("private-"));
    }
}

#[tokio::test]
async fn streaming_response_crosses_flow_control_windows_and_skips_unmatched_frames() {
    let temp = private_temp();
    let path = temp.path().join("trace.jsonl");
    let trace = Trace::create(&path).unwrap();
    // The response exceeds the server's 256-KiB QUIC stream window; this much
    // smaller pipe forces continual drain/write progress rather than prebuffering.
    let (mut tx, rx) = tokio::io::duplex(4096);
    let expected = "private-response-sentinel".repeat(24_000);
    let body = serde_json::to_vec(&json!({"id":1,"result":{"value":expected}})).unwrap();
    let bytes = body.len();
    let writer = tokio::spawn(async move {
        tx.write_all(b"{\"method\":\"notifications/progress\"}\n{\"id\":2,\"result\":{}}\n")
            .await
            .unwrap();
        for chunk in body.chunks(997) {
            tx.write_all(chunk).await.unwrap();
        }
        tx.write_all(b"\n").await.unwrap();
    });
    let budget = Arc::new(Semaphore::new(32 * 1024 * 1024));
    let mut reader = FrameReader::new(
        rx,
        MAX,
        budget.clone(),
        Duration::from_secs(10),
        Duration::from_secs(10),
    );
    let result = TRACE
        .scope(RefCell::new(trace), async {
            exchange_response(&mut Vec::new(), &mut reader, &budget, request()).await
        })
        .await
        .unwrap();
    writer.await.unwrap();
    assert_eq!(result["result"]["value"], expected);
    let rows = entries(&path);
    assert!(rows.iter().any(|row| row["completed_frame_bytes"] == bytes));
    assert_eq!(
        rows.iter()
            .filter(|row| row["stage"] == "read" && row["event"] == "ready")
            .count(),
        3
    );
    assert!(!std::fs::read_to_string(path).unwrap().contains("private-"));
    assert_eq!(reader.progress().phase, FrameReadPhase::AwaitingFirstByte);
    assert_eq!(budget.available_permits(), 32 * 1024 * 1024 - 8192);
}

#[tokio::test(start_paused = true)]
async fn cancelled_receive_retains_progress_deadline_and_budget() {
    let (mut tx, rx) = tokio::io::duplex(32);
    let budget = Arc::new(Semaphore::new(96));
    let mut reader = FrameReader::new(
        rx,
        32,
        budget.clone(),
        Duration::from_secs(10),
        Duration::from_secs(10),
    );
    tx.write_all(b"{").await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(3), reader.read())
            .await
            .is_err()
    );
    let before = reader.progress();
    assert_eq!(before.phase, FrameReadPhase::CompletingFrame);
    assert_eq!(before.buffered_frame_bytes, 1);
    assert_eq!(budget.available_permits(), 32);
    tokio::time::advance(Duration::from_secs(8)).await;
    assert_eq!(reader.progress(), before);
    assert_eq!(
        reader.read().await.err().unwrap().kind(),
        std::io::ErrorKind::TimedOut
    );
    drop(reader);
    assert_eq!(budget.available_permits(), 96);
}

#[tokio::test(start_paused = true)]
async fn write_stall_keeps_its_ten_second_deadline_and_safe_stage() {
    let temp = private_temp();
    let path = temp.path().join("trace.jsonl");
    let trace = Trace::create(&path).unwrap();
    let (mut send, _undrained) = tokio::io::duplex(1);
    let (_tx, rx) = tokio::io::duplex(32);
    let budget = Arc::new(Semaphore::new(32 * 1024 * 1024));
    let mut reader = FrameReader::new(
        rx,
        128,
        budget.clone(),
        Duration::from_secs(10),
        Duration::from_secs(10),
    );
    let started = tokio::time::Instant::now();
    TRACE
        .scope(RefCell::new(trace), async {
            let error = exchange_response(&mut send, &mut reader, &budget, request())
                .await
                .unwrap_err();
            failed(error.as_ref());
        })
        .await;
    assert_eq!(started.elapsed(), Duration::from_secs(10));
    let rows = entries(&path);
    let last = rows.last().unwrap();
    assert_eq!(last["stage"], "write");
    assert_eq!(last["result"], "timed_out");
    assert!(!std::fs::read_to_string(path).unwrap().contains("private-"));
}

#[tokio::test(start_paused = true)]
async fn legacy_notification_stall_is_distinct_from_initialize_response_assertions() {
    let temp = private_temp();
    let path = temp.path().join("trace.jsonl");
    let trace = Trace::create(&path).unwrap();
    let budget = Arc::new(Semaphore::new(32 * 1024 * 1024));
    let (mut send, _undrained) = tokio::io::duplex(1);
    let started = tokio::time::Instant::now();
    TRACE
        .scope(RefCell::new(trace), async {
            operation(|| "initialize".into()).unwrap();
            let error = crate::initialized_notification(&mut send, &budget)
                .await
                .unwrap_err();
            failed(error.as_ref());
        })
        .await;
    assert_eq!(started.elapsed(), Duration::from_secs(10));
    let rows = entries(&path);
    assert_eq!(
        rows.last().unwrap()["stage"],
        "initialized_notification_write"
    );
    assert_eq!(rows.last().unwrap()["result"], "timed_out");

    let path = temp.path().join("success.jsonl");
    let trace = Trace::create(&path).unwrap();
    TRACE
        .scope(RefCell::new(trace), async {
            operation(|| "initialize".into()).unwrap();
            crate::initialized_notification(&mut Vec::new(), &budget)
                .await
                .unwrap();
        })
        .await;
    let rows = entries(&path);
    assert_eq!(rows.last().unwrap()["label"], "initialize");
    assert_eq!(rows.last().unwrap()["stage"], "assertions");
}

#[tokio::test]
async fn malformed_oversized_and_unterminated_frames_have_finite_categories() {
    for (input, max, code, stage) in [
        (b"private-json-sentinel\n".as_slice(), 64, "json", "decode"),
        (b"12345\n".as_slice(), 4, "invalid_data", "read"),
        (b"{\"id\":1}".as_slice(), 64, "invalid_data", "read"),
        (b"".as_slice(), 64, "closed", "read"),
    ] {
        let temp = private_temp();
        let path = temp.path().join("trace.jsonl");
        let trace = Trace::create(&path).unwrap();
        let budget = Arc::new(Semaphore::new(32 * 1024 * 1024));
        let mut reader = FrameReader::new(
            input,
            max,
            budget.clone(),
            Duration::from_secs(10),
            Duration::from_secs(10),
        );
        TRACE
            .scope(RefCell::new(trace), async {
                let error = exchange_response(&mut Vec::new(), &mut reader, &budget, request())
                    .await
                    .unwrap_err();
                failed(error.as_ref());
            })
            .await;
        let rows = entries(&path);
        let last = rows.last().unwrap();
        assert_eq!(last["stage"], stage);
        assert_eq!(last["result"], code);
        assert!(!std::fs::read_to_string(path).unwrap().contains("private-"));
    }
}

#[test]
fn output_requires_a_new_private_tmp_file_and_is_bounded() {
    let temp = private_temp();
    let path = temp.path().join("trace.jsonl");
    let mut trace = Trace::create(&path).unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(Trace::create(&path).is_err());
    let link = temp.path().join("link");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(Trace::create(&link).is_err());
    assert!(Trace::create(Path::new("/var/tmp/devres-diagnostic-refused/file")).is_err());
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(Trace::create(&temp.path().join("other")).is_err());
    for _ in 0..MAX_EVENTS {
        if trace
            .append(Stage::Read, Event::Begin, ResultCode::Ok, None, None)
            .is_err()
        {
            break;
        }
    }
    assert!(
        trace
            .append(Stage::Read, Event::Begin, ResultCode::Ok, None, None)
            .is_err()
    );
    assert!(std::fs::metadata(path).unwrap().len() <= MAX_BYTES as u64);
}

#[tokio::test]
async fn recorder_refuses_unlisted_labels_and_output_failures_are_sanitized() {
    let temp = private_temp();
    let path = temp.path().join("trace.jsonl");
    let mut trace = Trace::create(&path).unwrap();
    // A read-only descriptor deterministically fails writes without special
    // devices, filesystem filling, or platform-specific failure injection.
    trace.file = File::open(&path).unwrap();
    TRACE
        .scope(RefCell::new(trace), async {
            let error = operation(|| "private-tool-label-sentinel".into()).unwrap_err();
            assert_eq!(error.to_string(), "diagnostic label refused");
            let error = mark(Stage::Write, Event::Begin).unwrap_err();
            assert_eq!(error.to_string(), "diagnostic output unavailable");
        })
        .await;
    assert!(std::fs::read(&path).unwrap().is_empty());
}
