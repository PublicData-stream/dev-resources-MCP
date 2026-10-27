//! Process-level npm assessment and request-only privacy regression checks.
use serde_json::{Value, json};
use std::io::Write;

fn request(lockfile: &str, format: &str) -> Value {
    json!({"operation":"npm","phase":"audit","input":{"lockfile":lockfile,"lockfile_format":format,"registry_context":{"default":"npmjs"}},"snapshot":{"snapshot":{"id":"a".repeat(64),"validated_at":devres_domain::unix_now(),"complete":true,"historical":false},"complete":true,"records":[{"id":"GHSA-synthetic-0001","schema_version":"1.9.2","modified":"2026-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"example"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]}]}})
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
fn every_format_reaches_the_same_local_public_match() {
    for (format, lockfile) in [
        (
            "npm",
            r#"{"lockfileVersion":1,"dependencies":{"example":{"version":"1.0.0"}}}"#,
        ),
        (
            "npm",
            r#"{"lockfileVersion":2,"packages":{"node_modules/example":{"version":"1.0.0"}},"dependencies":{"ignored":{"version":"9.0.0"}}}"#,
        ),
        (
            "npm",
            r#"{"lockfileVersion":3,"packages":{"node_modules/example":{"version":"1.0.0"}}}"#,
        ),
        (
            "pnpm",
            "lockfileVersion: '9.0'\npackages:\n  example@1.0.0: {}\n",
        ),
        (
            "yarn_classic",
            "# yarn lockfile v1\n\nexample@^1:\n  version \"1.0.0\"\n  resolved \"https://registry.yarnpkg.com/example/-/example-1.0.0.tgz#hash\"\n",
        ),
        (
            "yarn_berry",
            "__metadata:\n  version: 10\n\n\"example@npm:^1\":\n  version: 1.0.0\n  resolution: \"example@npm:1.0.0\"\n",
        ),
    ] {
        let output = run(&request(lockfile, format));
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["Ok"]["vulnerability_count"], 1, "{format}: {report}");
        assert_eq!(report["Ok"]["complete"], true);
    }
}
#[test]
fn inventory_phase_returns_names_without_private_locations_or_ranges() {
    let mut message = request(
        r#"{"lockfileVersion":3,"packages":{"node_modules/example":{"version":"1.0.0"},"node_modules/PRIVATE_LOCAL_NAME":{"version":"file:PRIVATE_PATH"}}}"#,
        "npm",
    );
    message["phase"] = json!("inventory");
    message["snapshot"] = Value::Null;
    let output = run(&message);
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.contains("PRIVATE_"));
    let report: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(report["Ok"]["names"], json!(["example"]));
}
#[test]
fn malformed_private_lockfiles_never_escape_through_worker_diagnostics() {
    for format in ["npm", "pnpm", "yarn_classic", "yarn_berry"] {
        let output = run(&request("PRIVATE_NPM_INPUT_SENTINEL invalid", format));
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(!text.contains("PRIVATE_NPM_INPUT_SENTINEL"));
        let report: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(report["Err"]["code"], "invalid_input");
    }
}
#[test]
fn explicit_foreign_origin_wins_over_public_default_assertion() {
    let lockfile = r#"{"lockfileVersion":3,"packages":{"node_modules/example":{"version":"1.0.0","resolved":"https://private.example/example.tgz"}}}"#;
    let output = run(&request(lockfile, "npm"));
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["Ok"]["unassessed_count"], 1);
    assert_eq!(report["Ok"]["vulnerability_count"], 0);
    assert_eq!(report["Ok"]["complete"], false);
}
