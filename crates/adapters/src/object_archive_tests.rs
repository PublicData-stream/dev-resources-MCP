//! Opt-in end-to-end capture/transfer acceptance against disposable services.
use super::*;
use tokio_util::sync::CancellationToken;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires disposable PostgreSQL and RustFS; run scripts/test-s3.sh"]
async fn s3_capture_transfer_resume_activation_and_cold_history() {
    let base = std::env::var("DEVRES_TEST_DATABASE_URL").unwrap();
    let configured = std::env::var("DEVRES_TEST_S3_CONFIG").unwrap();
    let mut config: crate::object_storage::S3Config =
        toml::from_str(&std::fs::read_to_string(configured).unwrap()).unwrap();
    config.prefix.push_str("/capture-transfer");
    let admin = PgPool::connect(&base).await.unwrap();
    sqlx::query("CREATE DATABASE devres_s3_capture_transfer")
        .execute(&admin)
        .await
        .unwrap();
    let mut database = url::Url::parse(&base).unwrap();
    database.set_path("/devres_s3_capture_transfer");
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let store = Arc::new(
        PgBlobStore::connect(database.as_str(), root.path())
            .await
            .unwrap(),
    );
    drop(store);
    let wrong_cache = tempfile::tempdir_in("/tmp").unwrap();
    let rejected =
        PgBlobStore::connect_archive(database.as_str(), wrong_cache.path(), Some(config.clone()))
            .await
            .err()
            .expect("existing filesystem store requires transfer");
    assert_eq!(rejected.code, "unavailable");
    assert!(rejected.message.contains("migration required"));
    let store = Arc::new(
        PgBlobStore::connect(database.as_str(), root.path())
            .await
            .unwrap(),
    );
    let request = FetchRequest {
        key: "fixture:s3-history".into(),
        url: "https://fixtures.invalid/history".into(),
        ttl_secs: 3600,
        max_bytes: 4096,
        media_type: "text/plain".into(),
    };
    let a = store
        .publish(
            &request,
            FetchResponse {
                status: 200,
                body: b"retained first body".to_vec(),
                validators: Validators::default(),
            },
            100,
        )
        .await
        .unwrap();
    let b = store
        .publish(
            &request,
            FetchResponse {
                status: 200,
                body: b"retained second body".to_vec(),
                validators: Validators::default(),
            },
            200,
        )
        .await
        .unwrap();
    assert_ne!(a.capture.id, b.capture.id);
    drop(store);
    // Merely selecting S3 never implicitly migrates a populated filesystem.
    assert!(
        PgBlobStore::connect_archive(database.as_str(), root.path(), Some(config.clone()))
            .await
            .is_err()
    );
    let transfer = Arc::new(
        PgBlobStore::connect_for_object_transfer(database.as_str(), root.path(), config.clone())
            .await
            .unwrap(),
    );
    assert!(
        transfer
            .transfer_object_archive("verify-object-storage", CancellationToken::new())
            .await
            .is_err()
    );
    let stopped = CancellationToken::new();
    stopped.cancel();
    assert!(
        transfer
            .transfer_object_archive("migrate-object-storage", stopped)
            .await
            .is_err()
    );
    transfer
        .transfer_object_archive("migrate-object-storage", CancellationToken::new())
        .await
        .unwrap();
    transfer
        .transfer_object_archive("migrate-object-storage", CancellationToken::new())
        .await
        .unwrap();
    transfer
        .transfer_object_archive("verify-object-storage", CancellationToken::new())
        .await
        .unwrap();
    transfer
        .transfer_object_archive("activate-object-storage", CancellationToken::new())
        .await
        .unwrap();
    drop(transfer);
    assert!(
        root.path()
            .join(crate::integrity::relative_path(&a.capture.body_hash).unwrap())
            .is_file()
    );
    assert!(
        PgBlobStore::connect(database.as_str(), root.path())
            .await
            .is_err()
    );
    // A fresh local working directory proves PostgreSQL+S3 are sufficient.
    let cache = tempfile::tempdir_in("/tmp").unwrap();
    let store = Arc::new(
        PgBlobStore::connect_archive(database.as_str(), cache.path(), Some(config.clone()))
            .await
            .unwrap(),
    );
    assert_eq!(
        store.capture(&a.capture.id).await.unwrap().body.as_ref(),
        b"retained first body"
    );
    assert_eq!(
        store
            .latest(&request.key)
            .await
            .unwrap()
            .unwrap()
            .stored
            .capture
            .id,
        b.capture.id
    );
    store
        .transfer_object_archive("verify-object-storage", CancellationToken::new())
        .await
        .unwrap();
    let mut wrong = config.clone();
    wrong.prefix.push_str("/wrong");
    drop(store);
    assert!(
        PgBlobStore::connect_archive(database.as_str(), cache.path(), Some(wrong))
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires disposable PostgreSQL and RustFS; run scripts/test-s3.sh"]
async fn s3_fresh_initialization_resumes_only_its_matching_failed_attempt() {
    let base = std::env::var("DEVRES_TEST_DATABASE_URL").unwrap();
    let path = std::env::var("DEVRES_TEST_S3_CONFIG").unwrap();
    let mut config: crate::object_storage::S3Config =
        toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    config.prefix.push_str("/fresh-initialization-retry");
    let admin = PgPool::connect(&base).await.unwrap();
    sqlx::query("CREATE DATABASE devres_s3_fresh_retry")
        .execute(&admin)
        .await
        .unwrap();
    let mut database = url::Url::parse(&base).unwrap();
    database.set_path("/devres_s3_fresh_retry");
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let mut missing_ca = config.clone();
    missing_ca.ca_file = Some(root.path().join("missing-ca.pem"));
    assert!(
        PgBlobStore::connect_archive(database.as_str(), root.path(), Some(missing_ca))
            .await
            .is_err()
    );
    let mut unavailable = config.clone();
    unavailable.credentials = crate::object_storage::S3Credentials::Files {
        access_key_file: root.path().join("missing-access"),
        secret_key_file: root.path().join("missing-secret"),
        session_token_file: None,
    };
    assert!(
        PgBlobStore::connect_archive(database.as_str(), root.path(), Some(unavailable))
            .await
            .is_err()
    );
    let inspect = PgPool::connect(database.as_str()).await.unwrap();
    let pending:bool=sqlx::query_scalar("SELECT initializing_s3 AND backend='filesystem' AND pending_binding IS NOT NULL FROM devres_archive_control WHERE singleton").fetch_one(&inspect).await.unwrap();
    assert!(pending);
    let mut other = config.clone();
    other.prefix.push_str("/different");
    assert!(
        PgBlobStore::connect_archive(database.as_str(), root.path(), Some(other))
            .await
            .is_err()
    );
    let store = PgBlobStore::connect_archive(database.as_str(), root.path(), Some(config))
        .await
        .unwrap();
    store.check_health().await.unwrap();
    let active: bool = sqlx::query_scalar(
        "SELECT backend='s3' AND NOT initializing_s3 FROM devres_archive_control WHERE singleton",
    )
    .fetch_one(&inspect)
    .await
    .unwrap();
    assert!(active);
}
