use super::*;
use std::{collections::BTreeMap, fmt};
use tracing::{Event, Metadata, Subscriber, field::Visit, instrument::WithSubscriber, span};

#[derive(Clone, Default)]
struct Events(Arc<StdMutex<Vec<BTreeMap<String, String>>>>);

impl Subscriber for Events {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.target() == "devres_private_timings"
            && metadata
                .fields()
                .field("crate_inventory_restore_stage")
                .is_some()
    }

    fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }

    fn record(&self, _: &span::Id, _: &span::Record<'_>) {}
    fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}

    fn event(&self, event: &Event<'_>) {
        struct Fields(BTreeMap<String, String>);
        impl Visit for Fields {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
                self.0.insert(field.name().into(), format!("{value:?}"));
            }
        }
        let mut fields = Fields(BTreeMap::new());
        event.record(&mut fields);
        self.0.lock().unwrap().push(fields.0);
    }

    fn enter(&self, _: &span::Id) {}
    fn exit(&self, _: &span::Id) {}
}

async fn capture_manifest(
    artifacts: &BulkArtifactStore,
    revision: &str,
    files: Vec<EvidenceFile>,
) -> BulkArtifact {
    let evidence = EvidenceManifest {
        version: 1,
        source_url: "https://github.com/rust-lang/crates.io-index.git".into(),
        revision: revision.into(),
        previous_revision: None,
        observed_at: 0,
        shallow: Vec::new(),
        files,
    };
    artifacts
        .capture_bytes(
            serde_json::to_vec(&evidence).unwrap(),
            CancellationToken::new(),
        )
        .await
        .unwrap()
}

async fn restore_with_trace(
    registry: &GitRegistry,
    artifacts: Arc<BulkArtifactStore>,
    manifest: BulkArtifact,
    trace: &mut RestoreTrace<'_>,
    events: Events,
) -> Result<GitSnapshot> {
    async {
        let result = registry
            .restore_observed(artifacts, manifest, CancellationToken::new(), trace)
            .await;
        trace.report(&result);
        result
    }
    .with_subscriber(events)
    .await
}

#[tokio::test]
async fn retained_manifest_must_match_pending_revision_and_length_before_git_changes() {
    let workspace = tempfile::tempdir_in("/tmp").unwrap();
    let git_root = workspace.path().join("git");
    let registry = GitRegistry::new(&git_root, 64 * 1024 * 1024).unwrap();
    let artifacts = Arc::new(BulkArtifactStore::new(workspace.path(), 64 * 1024 * 1024).unwrap());
    let actual_revision = "a".repeat(40);
    let different_revision = "b".repeat(40);
    let inventory = crate::integrity::hash(b"inventory");
    let capture = crate::integrity::hash(b"capture");
    let manifest = capture_manifest(&artifacts, &actual_revision, Vec::new()).await;
    let wrong_length = BulkArtifact {
        bytes: manifest.bytes + 1,
        ..manifest.clone()
    };
    for (candidate, revision, stage) in [
        (wrong_length, &actual_revision, "manifest_length"),
        (manifest, &different_revision, "manifest_identity"),
    ] {
        let mut trace = RestoreTrace::pending(&inventory, revision);
        trace.bind_manifest(&capture);
        let events = Events::default();
        let error = restore_with_trace(
            &registry,
            artifacts.clone(),
            candidate,
            &mut trace,
            events.clone(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, "integrity");
        assert!(error.details.is_none());
        assert!(!git_root.join(REPO_NAME).exists());
        assert!(!git_root.join(".devres-git-owned").exists());
        let events = events.0.lock().unwrap();
        let [event] = events.as_slice() else {
            panic!("expected one inventory restore event, got {events:?}");
        };
        assert_eq!(event["crate_inventory_restore_stage"], format!("{stage:?}"));
        assert_eq!(event["inventory"], format!("{inventory:?}"));
        assert_eq!(event["revision"], format!("{revision:?}"));
        assert_eq!(event["manifest_capture"], format!("{capture:?}"));
        assert_eq!(event["success"], "false");
        assert_eq!(event["code"], "\"integrity\"");
        assert!(event.values().all(|value| !value.contains(&error.message)));
    }
}

#[tokio::test]
async fn restore_reports_missing_pack_separately_from_git_ref_failure() {
    let workspace = tempfile::tempdir_in("/tmp").unwrap();
    let git_root = workspace.path().join("git");
    let registry = GitRegistry::new(&git_root, 64 * 1024 * 1024).unwrap();
    let artifacts = Arc::new(BulkArtifactStore::new(workspace.path(), 64 * 1024 * 1024).unwrap());
    let pack_name = format!("pack-{}.pack", "b".repeat(40));
    let pack_digest = crate::integrity::hash(b"nonexistent pack");
    let pack = EvidenceFile {
        name: pack_name.clone(),
        artifact: BulkArtifact {
            relative_path: "untrusted-pack-path".into(),
            body_hash: pack_digest.clone(),
            bytes: 16,
        },
    };
    let revision = "a".repeat(40);
    for (files, stage, ordinal) in [
        (vec![pack], "pack_materialization", Some("1")),
        (Vec::new(), "snapshot_ref_update", None),
    ] {
        let manifest = capture_manifest(&artifacts, &revision, files).await;
        let mut trace = RestoreTrace::pending("untrusted-inventory", &revision);
        trace.bind_manifest("untrusted-capture");
        let events = Events::default();
        let error = restore_with_trace(
            &registry,
            artifacts.clone(),
            manifest,
            &mut trace,
            events.clone(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, "unavailable");
        assert!(error.details.is_none());
        assert!(
            !git_root
                .join(REPO_NAME)
                .join("refs/devres/current")
                .exists()
        );
        let events = events.0.lock().unwrap();
        let [event] = events.as_slice() else {
            panic!("expected one inventory restore event, got {events:?}");
        };
        assert_eq!(event["crate_inventory_restore_stage"], format!("{stage:?}"));
        assert_eq!(event.get("pack_ordinal").map(String::as_str), ordinal);
        assert_eq!(event["revision"], format!("{revision:?}"));
        assert_eq!(event["success"], "false");
        assert_eq!(event["code"], "\"unavailable\"");
        assert!(event.keys().all(|key| matches!(
            key.as_str(),
            "crate_inventory_restore_stage"
                | "pack_ordinal"
                | "revision"
                | "success"
                | "code"
                | "message"
        )));
        assert!(event.values().all(|value| {
            !value.contains("untrusted-")
                && !value.contains(&pack_name)
                && !value.contains(&pack_digest)
                && !value.contains(&error.message)
        }));
    }
}
