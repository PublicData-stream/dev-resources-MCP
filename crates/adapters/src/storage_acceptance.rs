//! Disposable database acceptance for the integrated storage integrity boundary.
use super::*;
use serde_json::json;

#[tokio::test]
#[ignore = "requires disposable PostgreSQL; run scripts/test-postgres.sh"]
async fn fresh_content_events_and_unreferenced_files_fail_closed() {
    let base = std::env::var("DEVRES_TEST_DATABASE_URL").expect("disposable PostgreSQL required");
    let admin = PgPool::connect(&base).await.unwrap();
    sqlx::query("CREATE DATABASE devres_integrated_integrity_fixture")
        .execute(&admin)
        .await
        .unwrap();
    let mut url = url::Url::parse(&base).unwrap();
    url.set_path("/devres_integrated_integrity_fixture");
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(
        PgBlobStore::connect(url.as_str(), root.path())
            .await
            .unwrap(),
    );
    let request = FetchRequest {
        key: "fixture:events".into(),
        url: "https://fixtures.invalid/events".into(),
        ttl_secs: 3600,
        max_bytes: 128,
        media_type: "text/plain".into(),
    };
    let captured = store
        .publish(
            &request,
            FetchResponse {
                status: 200,
                body: b"public fixture evidence".to_vec(),
                validators: Validators {
                    etag: Some("fixture-etag".into()),
                    last_modified: None,
                },
            },
            10,
        )
        .await
        .unwrap();
    assert!(captured.capture.id.starts_with("blake3:"));
    assert!(captured.capture.body_hash.starts_with("blake3:"));
    store
        .revalidate(
            &request.key,
            &captured.capture.id,
            Validators::default(),
            20,
        )
        .await
        .unwrap();
    assert_eq!(
        store
            .latest(&request.key)
            .await
            .unwrap()
            .unwrap()
            .validators
            .etag
            .as_deref(),
        Some("fixture-etag")
    );
    sqlx::query("UPDATE devres_observations SET validated_at=21 WHERE status=304")
        .execute(&store.pool)
        .await
        .unwrap();
    assert_eq!(
        store.capture(&captured.capture.id).await.unwrap_err().code,
        "integrity"
    );
    sqlx::query("UPDATE devres_observations SET validated_at=20 WHERE status=304")
        .execute(&store.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE devres_heads SET etag='different-existing-validator'")
        .execute(&store.pool)
        .await
        .unwrap();
    assert_eq!(
        store
            .latest(&request.key)
            .await
            .err()
            .expect("corrupt head must fail")
            .code,
        "integrity"
    );
    sqlx::query("UPDATE devres_heads SET etag='fixture-etag'")
        .execute(&store.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE devres_captures SET retrieved_at=999")
        .execute(&store.pool)
        .await
        .unwrap();
    assert_eq!(
        store.capture(&captured.capture.id).await.unwrap_err().code,
        "integrity"
    );
    sqlx::query("UPDATE devres_captures SET retrieved_at=10")
        .execute(&store.pool)
        .await
        .unwrap();
    assert_eq!(
        store
            .capture(&captured.capture.id)
            .await
            .unwrap()
            .capture
            .validated_at,
        20
    );
    let proof = store
        .verify_storage(tokio_util::sync::CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(proof["verified_files"], json!(1));
    // The operator verifier uses a read-only pool and leaves provider layouts absent.
    drop(store);
    let before: Vec<_> = std::fs::read_dir(root.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    let inspector = Arc::new(
        PgBlobStore::connect_for_verification(url.as_str(), root.path())
            .await
            .unwrap(),
    );
    assert_eq!(
        inspector
            .verify_storage(tokio_util::sync::CancellationToken::new())
            .await
            .unwrap()["verified_files"],
        json!(1)
    );
    assert!(
        sqlx::query("UPDATE devres_integrity_control SET active=false")
            .execute(&inspector.pool)
            .await
            .is_err()
    );
    let after: Vec<_> = std::fs::read_dir(root.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(before, after);
    drop(inspector);
    let store = Arc::new(
        PgBlobStore::connect(url.as_str(), root.path())
            .await
            .unwrap(),
    );
    let orphan = crate::integrity::hash(b"unreferenced permanent public fixture");
    store
        .write_blob(&orphan, b"unreferenced permanent public fixture")
        .await
        .unwrap();
    assert_eq!(
        store
            .verify_storage(tokio_util::sync::CancellationToken::new())
            .await
            .unwrap()["verified_files"],
        json!(2)
    );
    // The record has no database reference; its permanent descriptor still makes
    // removal detectable, including for files published after schema activation.
    tokio::fs::remove_file(
        root.path()
            .join(crate::integrity::relative_path(&orphan).unwrap()),
    )
    .await
    .unwrap();
    assert_eq!(
        store
            .verify_storage(tokio_util::sync::CancellationToken::new())
            .await
            .unwrap_err()
            .code,
        "integrity"
    );
    drop(store);
    sqlx::query("DROP DATABASE devres_integrated_integrity_fixture WITH(FORCE)")
        .execute(&admin)
        .await
        .unwrap();
}
