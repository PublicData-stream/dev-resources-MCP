use devres_adapters::PgBlobStore;
use devres_application::Store;
use devres_domain::{FetchRequest, FetchResponse, Validators};

#[tokio::test]
#[ignore = "requires disposable PostgreSQL; run scripts/test-postgres.sh"]
async fn permanent_history_revalidation_and_integrity() {
    let url = std::env::var("DEVRES_TEST_DATABASE_URL").expect("disposable database required");
    let root = tempfile::tempdir().unwrap();
    let store = PgBlobStore::connect(&url, root.path()).await.unwrap();
    assert!(
        PgBlobStore::connect(&url, root.path()).await.is_err(),
        "second serving owner must be rejected"
    );
    let key = format!("fixture:{}", devres_domain::unix_now());
    let req = FetchRequest {
        key,
        url: "https://fixtures.invalid/history".into(),
        ttl_secs: 100,
        max_bytes: 1024,
        media_type: "text/plain".into(),
    };
    let a = store
        .publish(
            &req,
            FetchResponse {
                status: 200,
                body: b"first".to_vec(),
                validators: Validators::default(),
            },
            100,
        )
        .await
        .unwrap();
    let b = store
        .publish(
            &req,
            FetchResponse {
                status: 200,
                body: b"second".to_vec(),
                validators: Validators::default(),
            },
            200,
        )
        .await
        .unwrap();
    assert_ne!(a.capture.id, b.capture.id);
    assert_eq!(store.capture(&a.capture.id).await.unwrap().body, b"first");
    assert_eq!(
        store
            .revalidate(&req.key, &b.capture.id, Validators::default(), 300)
            .await
            .unwrap()
            .capture
            .validated_at,
        300
    );
    assert_eq!(
        store
            .capture(&b.capture.id)
            .await
            .unwrap()
            .capture
            .retrieved_at,
        200
    );
    assert_eq!(
        store
            .capture(&b.capture.id)
            .await
            .unwrap()
            .capture
            .validated_at,
        300
    );
    drop(store);
    tokio::fs::write(root.path().join(".stage-123-0"), b"abandoned")
        .await
        .unwrap();
    tokio::fs::write(root.path().join("operator-note"), b"keep")
        .await
        .unwrap();
    let store = PgBlobStore::connect(&url, root.path()).await.unwrap();
    assert!(!root.path().join(".stage-123-0").exists());
    assert!(root.path().join("operator-note").exists());
    assert!(root.path().join(&a.capture.body_hash).exists());
    assert_eq!(
        store.latest(&req.key).await.unwrap().unwrap().stored.body,
        b"second"
    );
    tokio::fs::write(root.path().join(&a.capture.body_hash), b"corrupt")
        .await
        .unwrap();
    assert_eq!(
        store.capture(&a.capture.id).await.unwrap_err().code,
        "integrity"
    );
    assert_eq!(
        store.latest(&req.key).await.unwrap().unwrap().stored.body,
        b"second"
    );
    let maintenance = sqlx::PgPool::connect(&url).await.unwrap();
    let terminated: Vec<bool> = sqlx::query_scalar("SELECT pg_terminate_backend(pid) FROM pg_locks WHERE locktype='advisory' AND classid=1835365490 AND objid=1 AND database=(SELECT oid FROM pg_database WHERE datname=current_database())")
        .fetch_all(&maintenance).await.unwrap();
    assert_eq!(terminated, vec![true]);
    assert!(store.check_health().await.is_err());
    assert!(
        store
            .publish(
                &req,
                FetchResponse {
                    status: 200,
                    body: b"must not publish".to_vec(),
                    validators: Validators::default()
                },
                400
            )
            .await
            .is_err()
    );
    let replacement = PgBlobStore::connect(&url, root.path()).await.unwrap();
    assert_eq!(
        replacement
            .latest(&req.key)
            .await
            .unwrap()
            .unwrap()
            .stored
            .body,
        b"second"
    );
    // One-MiB-rounded reservations make this a small, real budget test without
    // allocating 128 MiB. Shared clones must retain the final reservation.
    let mut held = Vec::new();
    for _ in 0..128 {
        held.push(replacement.capture(&b.capture.id).await.unwrap());
    }
    assert_eq!(
        replacement.capture(&b.capture.id).await.unwrap_err().code,
        "capacity"
    );
    let last = held.pop().unwrap();
    let clone = last.body.clone();
    drop(last);
    assert_eq!(
        replacement.capture(&b.capture.id).await.unwrap_err().code,
        "capacity"
    );
    drop(clone);
    assert_eq!(
        replacement.capture(&b.capture.id).await.unwrap().body,
        b"second"
    );
    drop(held);
    assert_eq!(
        replacement.capture(&b.capture.id).await.unwrap().body,
        b"second"
    );
}
