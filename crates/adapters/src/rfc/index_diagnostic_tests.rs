//! Closed error phases distinguish selected immutable reader boundaries.
use super::*;
use devres_application::collection::context;

fn phase(error: Error, code: &str, expected: Phase) {
    assert_eq!(error.code, code);
    assert_eq!(context(&error).unwrap().phase, expected);
    let details = error.details.unwrap();
    assert_eq!(details.as_object().unwrap().len(), 1);
    assert!(details["collector"]["phase"].is_string());
    let serialized = details.to_string();
    assert!(!serialized.contains("/tmp"));
    assert!(!serialized.contains("meta.json"));
}

fn fixture(root: &Path, identity: &[u8]) -> String {
    build(
        root,
        &crate::integrity::hash(identity),
        vec![IndexDocument {
            number: 9000,
            text: "retained transport fixture".into(),
        }],
    )
    .unwrap()
}

#[test]
fn selected_path_and_reader_admission_fail_with_closed_phases() {
    let _serial = TEST_SERIAL.blocking_lock();
    let root = tempfile::tempdir_in("/tmp").unwrap();
    phase(
        search(
            root.path(),
            "rfc-indexes/../../outside",
            "transport",
            TECHNICAL,
            0,
            1,
            None,
        )
        .unwrap_err(),
        "invalid_input",
        Phase::IndexSelection,
    );
    let relative = fixture(root.path(), b"admission diagnostics");
    phase(
        search(
            &root.path().join("absent"),
            &relative,
            "transport",
            TECHNICAL,
            0,
            1,
            None,
        )
        .unwrap_err(),
        "unavailable",
        Phase::IndexSelection,
    );
    let _held = READERS.try_acquire_many(2).unwrap();
    phase(
        search(root.path(), &relative, "transport", TECHNICAL, 0, 1, None).unwrap_err(),
        "capacity",
        Phase::IndexAdmission,
    );
}

#[test]
fn missing_and_corrupt_members_fail_manifest_verification() {
    let _serial = TEST_SERIAL.blocking_lock();
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let relative = fixture(root.path(), b"manifest diagnostics");
    let member = root.path().join(&relative).join("meta.json");
    fs::write(&member, b"{}").unwrap();
    phase(
        search(root.path(), &relative, "transport", TECHNICAL, 0, 1, None).unwrap_err(),
        "integrity",
        Phase::IndexManifest,
    );
    fs::remove_file(member).unwrap();
    phase(
        search(root.path(), &relative, "transport", TECHNICAL, 0, 1, None).unwrap_err(),
        "integrity",
        Phase::IndexManifest,
    );
    fs::remove_file(root.path().join(&relative).join(MANIFEST)).unwrap();
    phase(
        search(root.path(), &relative, "transport", TECHNICAL, 0, 1, None).unwrap_err(),
        "integrity",
        Phase::IndexManifest,
    );
}

#[test]
fn verified_members_with_invalid_engine_metadata_fail_engine_open() {
    let _serial = TEST_SERIAL.blocking_lock();
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let relative = fixture(root.path(), b"engine diagnostics");
    let path = root.path().join(&relative);
    fs::write(path.join("meta.json"), b"{}").unwrap();
    let manifest_path = path.join(MANIFEST);
    let mut manifest: Manifest =
        serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    manifest.files.insert(
        "meta.json".into(),
        digest(
            &path.join("meta.json"),
            Instant::now() + Duration::from_secs(15),
        )
        .unwrap(),
    );
    fs::write(manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    phase(
        search(root.path(), &relative, "transport", TECHNICAL, 0, 1, None).unwrap_err(),
        "integrity",
        Phase::IndexEngine,
    );
}
