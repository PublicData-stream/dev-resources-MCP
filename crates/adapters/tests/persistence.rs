use devres_adapters::PgBlobStore;
use devres_application::Store;
use devres_domain::{FetchRequest, FetchResponse, Validators};

#[tokio::test]
#[ignore = "requires disposable PostgreSQL; run scripts/test-postgres.sh"]
async fn corpus_v1_migration_jobs_snapshots_and_import_provenance() {
    use devres_application::corpus::{Dataset, Document, JobSpec, RfcCorpusStore, Snapshot};
    use serde_json::json;
    use sha2::{Digest, Sha256};

    let base_url = std::env::var("DEVRES_TEST_DATABASE_URL").expect("disposable database required");
    let admin = sqlx::PgPool::connect(&base_url).await.unwrap();
    let database_name = "devres_rfc_storage_fixture";
    sqlx::query("CREATE DATABASE devres_rfc_storage_fixture")
        .execute(&admin)
        .await
        .unwrap();
    let mut parsed_url = url::Url::parse(&base_url).unwrap();
    parsed_url.set_path(&format!("/{database_name}"));
    let url = parsed_url.to_string();
    let root = tempfile::tempdir().unwrap();
    let fixture_pool = sqlx::PgPool::connect(&url).await.unwrap();
    // The disposable database begins with the original v1 schema and a retained body.
    sqlx::raw_sql("CREATE TABLE devres_schema(singleton boolean PRIMARY KEY CHECK(singleton),version integer NOT NULL); INSERT INTO devres_schema VALUES(true,1); CREATE TABLE devres_captures(id text PRIMARY KEY,source_key text NOT NULL,source_url text NOT NULL,body_hash text NOT NULL,media_type text NOT NULL,retrieved_at bigint NOT NULL); CREATE TABLE devres_heads(source_key text PRIMARY KEY,capture_id text NOT NULL REFERENCES devres_captures(id),validated_at bigint NOT NULL,etag text,last_modified text); CREATE TABLE devres_observations(id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,capture_id text NOT NULL REFERENCES devres_captures(id),validated_at bigint NOT NULL,status smallint NOT NULL CHECK(status IN (200,304))); ")
        .execute(&fixture_pool).await.unwrap();
    let original_id = "a".repeat(64);
    let original_hash = hex::encode(Sha256::digest(b"v1 retained capture"));
    tokio::fs::write(root.path().join(&original_hash), b"v1 retained capture")
        .await
        .unwrap();
    sqlx::query("INSERT INTO devres_captures VALUES($1,'fixture:v1','https://fixture.invalid/v1',$2,'text/plain',1)")
        .bind(&original_id).bind(&original_hash).execute(&fixture_pool).await.unwrap();
    let store = PgBlobStore::connect(&url, root.path()).await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i32>("SELECT version FROM devres_schema")
            .fetch_one(&fixture_pool)
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        store.capture(&original_id).await.unwrap().body,
        b"v1 retained capture"
    );

    let catalogue_request = FetchRequest {
        key: "rfc:index".into(),
        url: "https://www.rfc-editor.org/rfc-index.xml".into(),
        ttl_secs: 86400,
        max_bytes: 1024,
        media_type: "application/xml".into(),
    };
    let catalogue = store
        .publish(
            &catalogue_request,
            FetchResponse {
                status: 200,
                body: b"<rfc-index/>".to_vec(),
                validators: Validators::default(),
            },
            10,
        )
        .await
        .unwrap();
    let dataset = Dataset {
        capture: catalogue.capture.clone(),
        records: vec![json!({"number":1})],
    };
    store.save_dataset("catalogue", &dataset).await.unwrap();
    let mut changed = dataset.clone();
    changed.records.push(json!({"number":2}));
    assert_eq!(
        store
            .save_dataset("catalogue", &changed)
            .await
            .unwrap_err()
            .code,
        "integrity"
    );
    store
        .revalidate(
            "rfc:index",
            &catalogue.capture.id,
            Validators::default(),
            20,
        )
        .await
        .unwrap();
    assert_eq!(
        store
            .dataset("catalogue", None)
            .await
            .unwrap()
            .unwrap()
            .capture
            .validated_at,
        20
    );
    assert_eq!(
        store
            .dataset("catalogue", Some(&catalogue.capture.id))
            .await
            .unwrap()
            .unwrap()
            .records,
        dataset.records
    );
    let mut absent = dataset.clone();
    absent.capture.id = "c".repeat(64);
    assert!(store.save_dataset("catalogue", &absent).await.is_err());
    let newer_catalogue = store
        .publish(
            &catalogue_request,
            FetchResponse {
                status: 200,
                body: b"<rfc-index><new/></rfc-index>".to_vec(),
                validators: Validators::default(),
            },
            25,
        )
        .await
        .unwrap();
    store
        .save_dataset(
            "catalogue",
            &Dataset {
                capture: newer_catalogue.capture.clone(),
                records: vec![json!({"number":2})],
            },
        )
        .await
        .unwrap();
    store.save_dataset("catalogue", &dataset).await.unwrap();
    assert_eq!(
        store
            .dataset("catalogue", None)
            .await
            .unwrap()
            .unwrap()
            .capture
            .id,
        newer_catalogue.capture.id,
        "a late historical projection must not move the dataset head backwards"
    );

    let job = JobSpec {
        key: "rfc:text:1".into(),
        number: 1,
        format: "txt".into(),
        source_url: "https://www.rfc-editor.org/rfc/rfc1.txt".into(),
        assurance: "https".into(),
        due_at: 10,
    };
    store.schedule(std::slice::from_ref(&job)).await.unwrap();
    let claim = store.claim(10).await.unwrap().unwrap();
    assert_eq!(claim.attempts, 1);
    assert!(store.claim(10).await.unwrap().is_none());
    store.schedule(std::slice::from_ref(&job)).await.unwrap();
    assert!(
        store.claim(10).await.unwrap().is_none(),
        "scheduling must not reset running jobs"
    );
    drop(store);
    let store = PgBlobStore::connect(&url, root.path()).await.unwrap();
    let claim = store.claim(10).await.unwrap().unwrap();
    assert_eq!(claim.attempts, 2, "interrupted work resumes after restart");
    let request = FetchRequest {
        key: job.key.clone(),
        url: job.source_url.clone(),
        ttl_secs: 86400,
        max_bytes: 1024,
        media_type: "text/plain".into(),
    };
    let first = store
        .publish(
            &request,
            FetchResponse {
                status: 200,
                body: b"First RFC text".to_vec(),
                validators: Validators::default(),
            },
            30,
        )
        .await
        .unwrap();
    store
        .finish(&job.key, Some(&first.capture), None, 40)
        .await
        .unwrap();
    assert!(store.claim(39).await.unwrap().is_none());
    store.claim(40).await.unwrap().unwrap();
    store
        .finish(&job.key, None, Some("unavailable"), 50)
        .await
        .unwrap();
    assert_eq!(
        store.documents().await.unwrap()[0].capture.id,
        first.capture.id,
        "refresh failure retains valid content"
    );
    assert_eq!(
        store.status().await.unwrap()["errors"][0]["error"],
        "unavailable"
    );
    assert_eq!(store.status().await.unwrap()["pending_documents"], 0);
    assert_eq!(store.status().await.unwrap()["outstanding_jobs"], 1);
    let mut snapshot = Snapshot {
        id: "d".repeat(64),
        catalogue_capture: catalogue.capture.id.clone(),
        errata_capture: None,
        documents: vec![Document {
            number: 1,
            format: "txt".into(),
            capture: first.capture.clone(),
            assurance: "https".into(),
        }],
        coverage: json!({"captured":1}),
        created_at: 40,
        complete: true,
        index_path: None,
        processor_version: 1,
        search_documents: vec![],
    };
    snapshot.search_documents = snapshot.documents.clone();
    store.save_snapshot(&snapshot).await.unwrap();
    store.save_snapshot(&snapshot).await.unwrap();
    let mut duplicate_source = snapshot.clone();
    duplicate_source.id = "f".repeat(64);
    duplicate_source
        .search_documents
        .push(snapshot.documents[0].clone());
    assert_eq!(
        store
            .save_snapshot(&duplicate_source)
            .await
            .unwrap_err()
            .code,
        "invalid_input"
    );
    let mut absent_source = snapshot.clone();
    absent_source.id = "f".repeat(64);
    absent_source.search_documents[0].capture.id = "0".repeat(64);
    assert_eq!(
        store.save_snapshot(&absent_source).await.unwrap_err().code,
        "invalid_input"
    );
    let mut changed_snapshot = snapshot.clone();
    changed_snapshot.coverage = json!({"captured":2});
    assert!(store.save_snapshot(&changed_snapshot).await.is_err());
    let second = store
        .publish(
            &request,
            FetchResponse {
                status: 200,
                body: b"Second RFC text".to_vec(),
                validators: Validators::default(),
            },
            50,
        )
        .await
        .unwrap();
    store
        .finish(&job.key, Some(&second.capture), None, 100)
        .await
        .unwrap();
    store.schedule(std::slice::from_ref(&job)).await.unwrap();
    assert!(
        store.claim(99).await.unwrap().is_none(),
        "rediscovery must not reset the due time"
    );
    let mut partial = snapshot.clone();
    partial.id = "e".repeat(64);
    partial.created_at = 60;
    partial.complete = false;
    partial.documents[0].capture = second.capture.clone();
    partial.search_documents = partial.documents.clone();
    store.save_snapshot(&partial).await.unwrap();
    assert_eq!(
        store.snapshot(None).await.unwrap().unwrap().id,
        snapshot.id,
        "new partial must not displace complete snapshot"
    );
    let mut newer_partial = partial.clone();
    newer_partial.id = "b".repeat(64);
    store.save_snapshot(&newer_partial).await.unwrap();
    assert_eq!(
        store.status().await.unwrap()["latest_partial"]["id"],
        newer_partial.id,
        "same-second partial selection follows durable publication order"
    );
    let mut newer_complete = snapshot.clone();
    newer_complete.id = "a".repeat(64);
    store.save_snapshot(&newer_complete).await.unwrap();
    assert_eq!(
        store.snapshot(None).await.unwrap().unwrap().id,
        newer_complete.id,
        "same-second complete selection follows publication order, not hash sort"
    );
    store.save_snapshot(&snapshot).await.unwrap();
    assert_eq!(
        store.snapshot(None).await.unwrap().unwrap().id,
        newer_complete.id,
        "idempotent historical publication cannot move the active selection backward"
    );
    assert_eq!(
        store
            .snapshot(Some(&snapshot.id))
            .await
            .unwrap()
            .unwrap()
            .documents[0]
            .capture
            .id,
        first.capture.id
    );
    assert_eq!(
        store.documents().await.unwrap()[0].capture.id,
        second.capture.id
    );

    let imported_job = JobSpec {
        key: "rfc:rsync:1:txt".into(),
        number: 1,
        format: "txt".into(),
        source_url: "rsync://rsync.rfc-editor.org/rfcs/rfc1.txt".into(),
        assurance: "rsync".into(),
        due_at: 60,
    };
    store
        .schedule(std::slice::from_ref(&imported_job))
        .await
        .unwrap();
    assert!(
        store.claim(60).await.unwrap().is_none(),
        "the HTTPS worker must never claim rsync imports"
    );
    let imported_request = FetchRequest {
        key: imported_job.key.clone(),
        url: imported_job.source_url.clone(),
        ..request.clone()
    };
    let imported = store
        .publish(
            &imported_request,
            FetchResponse {
                status: 200,
                body: b"Imported research text".to_vec(),
                validators: Validators::default(),
            },
            60,
        )
        .await
        .unwrap();
    store
        .finish(&imported_job.key, Some(&imported.capture), None, 100)
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM devres_observations WHERE capture_id=$1"
        )
        .bind(&imported.capture.id)
        .fetch_one(&fixture_pool)
        .await
        .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM devres_rfc_import_observations WHERE capture_id=$1"
        )
        .bind(&imported.capture.id)
        .fetch_one(&fixture_pool)
        .await
        .unwrap(),
        1
    );
    assert_eq!(
        store
            .latest(&job.key)
            .await
            .unwrap()
            .unwrap()
            .stored
            .capture
            .id,
        second.capture.id
    );
    assert_eq!(
        store
            .capture(&imported.capture.id)
            .await
            .unwrap()
            .capture
            .validated_at,
        60
    );
    assert!(
        store
            .revalidate(
                &imported_job.key,
                &imported.capture.id,
                Validators::default(),
                70
            )
            .await
            .is_err()
    );
    assert_eq!(store.documents().await.unwrap().len(), 2);
    assert_eq!(
        store.capture(&original_id).await.unwrap().body,
        b"v1 retained capture"
    );
    sqlx::query("SELECT pg_terminate_backend(pid) FROM pg_locks WHERE locktype='advisory' AND classid=1835365490 AND objid=1 AND database=(SELECT oid FROM pg_database WHERE datname=current_database())")
        .execute(&fixture_pool).await.unwrap();
    assert!(store.save_dataset("catalogue", &dataset).await.is_err());
    assert!(store.schedule(std::slice::from_ref(&job)).await.is_err());
    assert!(store.claim(100).await.is_err());
    assert!(
        store
            .finish(&job.key, Some(&second.capture), None, 100)
            .await
            .is_err()
    );
    assert!(store.save_snapshot(&snapshot).await.is_err());
    drop(store);
    fixture_pool.close().await;
    sqlx::query("DROP DATABASE devres_rfc_storage_fixture WITH (FORCE)")
        .execute(&admin)
        .await
        .unwrap();
}

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
