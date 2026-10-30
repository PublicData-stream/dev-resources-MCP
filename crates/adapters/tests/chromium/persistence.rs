//! Real PostgreSQL tests; only task-created databases and /tmp blobs are mutated.
use devres_adapters::PgBlobStore;
use devres_application::{
    Store,
    chromium::{ChromiumStore, Write},
    w3c::W3cStore,
};
use devres_domain::{FetchRequest, FetchResponse, Validators};
use serde_json::json;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[tokio::test]
#[ignore = "requires disposable PostgreSQL; run scripts/test-postgres.sh"]
async fn chromium_schema_upgrade_immutability_fencing_and_restart() {
    let base = std::env::var("DEVRES_TEST_DATABASE_URL").expect("disposable PostgreSQL URL");
    let admin = sqlx::PgPool::connect(&base).await.expect("fixture admin");
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let database = format!("devres_chromium_fixture_{}_{suffix}", std::process::id());
    assert!(
        database
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    );
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {database}")))
        .execute(&admin)
        .await
        .expect("owned fixture database");
    let mut url = url::Url::parse(&base).expect("fixture URL");
    url.set_path(&format!("/{database}"));
    let root = tempfile::tempdir_in("/tmp").expect("owned blobs");
    let inspection = sqlx::PgPool::connect(url.as_str())
        .await
        .expect("inspection");
    let store = PgBlobStore::connect(url.as_str(), root.path())
        .await
        .expect("fresh schema ten");
    // Acceptance is a recognized opaque evidence role; production rejects unknown roles.
    let old = json!({"synthetic":true,"body":"Prior W3C evidence remains immutable"});
    store
        .w3c_put("acceptance", "before-chromium", &old)
        .await
        .unwrap();
    let request = FetchRequest {
        key: "fixture:before-chromium".into(),
        url: "https://fixtures.invalid/before-chromium".into(),
        ttl_secs: 3600,
        max_bytes: 4096,
        media_type: "text/plain".into(),
    };
    let canonical_capture = store
        .publish(
            &request,
            FetchResponse {
                status: 200,
                body: b"Synthetic retained public evidence".to_vec(),
                validators: Validators::default(),
            },
            1234,
        )
        .await
        .unwrap()
        .capture;
    drop(store);
    wait_owner_release(&inspection).await;
    let count:i64=sqlx::query_scalar("SELECT (SELECT count(*) FROM devres_chromium_evidence)+(SELECT count(*) FROM devres_chromium_state)+(SELECT count(*) FROM devres_chromium_statistics)").fetch_one(&inspection).await.unwrap();
    assert_eq!(count, 0, "new tables are empty before isolated downgrade");
    remove_integrity_schema(&inspection).await;
    let capture = seed_legacy_capture(
        &inspection,
        root.path(),
        &canonical_capture,
        b"Synthetic retained public evidence",
    )
    .await;
    sqlx::raw_sql("DROP TABLE devres_npm_state; DROP TABLE devres_npm_evidence; DROP TABLE devres_chromium_statistics; DROP TABLE devres_chromium_state; DROP TABLE devres_chromium_evidence; UPDATE devres_schema SET version=7 WHERE singleton")
        .execute(&inspection).await.expect("prepare owned schema-seven fixture");
    assert!(
        PgBlobStore::connect(url.as_str(), root.path())
            .await
            .is_err(),
        "schema-seven serving requires explicit offline migration"
    );
    wait_owner_release(&inspection).await;
    let migrating = std::sync::Arc::new(
        PgBlobStore::connect_for_migration(url.as_str(), root.path())
            .await
            .expect("upgrade schema seven in maintenance mode"),
    );
    assert!(
        migrating
            .activate_storage(tokio_util::sync::CancellationToken::new())
            .await
            .is_err(),
        "unqualified storage cannot activate"
    );
    devres_adapters::migrate_storage_graphs(
        &devres_adapters::MigrationSettings::default(),
        migrating.clone(),
        tokio_util::sync::CancellationToken::new(),
    )
    .await
    .expect("qualify every retained storage graph offline");
    migrating
        .activate_storage(tokio_util::sync::CancellationToken::new())
        .await
        .expect("activate fully qualified storage");
    drop(migrating);
    wait_owner_release(&inspection).await;
    let store = PgBlobStore::connect(url.as_str(), root.path())
        .await
        .expect("serve fully migrated schema ten");
    assert_eq!(
        sqlx::query_scalar::<_, i32>("SELECT version FROM devres_schema WHERE singleton")
            .fetch_one(&inspection)
            .await
            .unwrap(),
        10
    );
    assert_eq!(
        store
            .w3c_get("acceptance", "before-chromium")
            .await
            .unwrap()
            .unwrap()
            .data,
        old
    );
    let retained = store.capture(&capture.id).await.unwrap();
    assert_eq!(retained.body, b"Synthetic retained public evidence");
    assert_eq!(retained.capture.validated_at, 1234);
    assert!(
        PgBlobStore::connect(url.as_str(), root.path())
            .await
            .is_err(),
        "second writer must not acquire ownership"
    );

    let original = json!({"synthetic":true,"source":"src","revision":"a".repeat(40),"notice":"First-party fixture"});
    let sequence = store
        .chromium_put("fixtures", "same", &original)
        .await
        .unwrap();
    assert_eq!(
        store
            .chromium_put("fixtures", "same", &original)
            .await
            .unwrap(),
        sequence
    );
    assert!(
        store
            .chromium_put("fixtures", "same", &json!({"changed":true}))
            .await
            .is_err()
    );
    let cutoff = store.chromium_cutoff().await.unwrap();
    store
        .chromium_put("fixtures", "later", &json!({"later":true}))
        .await
        .unwrap();
    let frozen = store
        .chromium_rows("fixtures", 0, 100, Some(cutoff))
        .await
        .unwrap();
    assert_eq!(frozen.len(), 1);
    assert_eq!(frozen[0].key, "same");

    let batch = [
        Write {
            kind: "fixtures".into(),
            key: "atomic-new".into(),
            data: json!({"new":true}),
        },
        Write {
            kind: "fixtures".into(),
            key: "same".into(),
            data: json!({"conflict":true}),
        },
    ];
    assert!(store.chromium_put_many(&batch).await.is_err());
    assert!(
        store
            .chromium_get("fixtures", "atomic-new")
            .await
            .unwrap()
            .is_none(),
        "colliding batch rolls back"
    );
    let state = json!({"frozen_roots":["a".repeat(40)],"pending_parents":["b".repeat(40)],"synthetic":true});
    store
        .chromium_set_state("checkpoint", &state)
        .await
        .unwrap();
    assert!(store.chromium_get("../unsafe", "key").await.is_err());
    assert!(
        store
            .chromium_rows("fixtures", 0, 1001, None)
            .await
            .is_err()
    );

    let owner:i32=sqlx::query_scalar("SELECT pid FROM pg_locks WHERE locktype='advisory' AND classid=1835365490 AND objid=1 AND objsubid=2 AND granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database())").fetch_one(&inspection).await.unwrap();
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT pg_terminate_backend($1)")
            .bind(owner)
            .fetch_one(&inspection)
            .await
            .unwrap()
    );
    assert!(
        store
            .chromium_set_state("after-loss", &json!(true))
            .await
            .is_err()
    );
    assert!(
        store
            .chromium_put("fixtures", "after-loss", &json!(true))
            .await
            .is_err()
    );
    drop(store);
    wait_owner_release(&inspection).await;
    let restarted = PgBlobStore::connect(url.as_str(), root.path())
        .await
        .expect("restart");
    assert_eq!(
        restarted
            .chromium_get("fixtures", "same")
            .await
            .unwrap()
            .unwrap()
            .data,
        original
    );
    assert_eq!(
        restarted.chromium_state("checkpoint").await.unwrap(),
        Some(state)
    );
    assert!(
        restarted
            .chromium_get("fixtures", "atomic-new")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        restarted
            .w3c_get("acceptance", "before-chromium")
            .await
            .unwrap()
            .unwrap()
            .data,
        old
    );
    drop(restarted);
    inspection.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP DATABASE {database} WITH (FORCE)"
    )))
    .execute(&admin)
    .await
    .expect("remove owned database");
    admin.close().await;
}

async fn wait_owner_release(pool: &sqlx::PgPool) {
    for _ in 0..50 {
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND classid=1835365490 AND objid=1 AND objsubid=2 AND granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database())").fetch_one(pool).await.unwrap();
        if count == 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("owned PostgreSQL session did not release its fence");
}

// Remove only schema-ten metadata in this task-owned fixture database. Retained
// captures, source rows, and permanent filesystem evidence remain untouched.
async fn remove_integrity_schema(pool: &sqlx::PgPool) {
    sqlx::raw_sql(
        r#"
DO $fixture$
DECLARE retained_column record;
BEGIN
    FOR retained_column IN
        SELECT table_schema,table_name,column_name FROM information_schema.columns
        WHERE table_schema='public' AND left(table_name,7)='devres_'
          AND right(column_name,10)='_integrity'
    LOOP
        EXECUTE format('ALTER TABLE %I.%I DROP COLUMN %I',
            retained_column.table_schema,retained_column.table_name,retained_column.column_name);
    END LOOP;
END;
$fixture$;
DROP TABLE devres_integrity_staged_state;
DROP TABLE devres_integrity_provider_cutoffs;
DROP TABLE devres_integrity_graph_progress;
DROP TABLE devres_integrity_files;
DROP TABLE devres_content_aliases;
DROP TABLE devres_integrity_control;
"#,
    )
    .execute(pool)
    .await
    .expect("remove schema-ten-only fixture metadata");
}

// Simulate the original SHA-only capture representation after removing schema-ten
// seals. Keep the already retained BLAKE3 body file as permanent source evidence.
async fn seed_legacy_capture(
    pool: &sqlx::PgPool,
    root: &std::path::Path,
    current: &devres_domain::Capture,
    bytes: &[u8],
) -> devres_domain::Capture {
    use sha2::{Digest, Sha256};
    let body_hash = hex::encode(Sha256::digest(bytes));
    let id = hex::encode(Sha256::digest(
        format!(
            "{}\0{}\0{}\0{body_hash}",
            current.key, current.source_url, current.media_type
        )
        .as_bytes(),
    ));
    let original_body = root.join(
        devres_adapters::integrity::relative_path(&current.body_hash).expect("retained body path"),
    );
    assert_eq!(
        tokio::fs::read(&original_body)
            .await
            .expect("retained body"),
        bytes
    );
    tokio::fs::hard_link(&original_body, root.join(&body_hash))
        .await
        .expect("retain legacy SHA body path");
    let mut tx = pool.begin().await.expect("fixture capture conversion");
    let inserted = sqlx::query("INSERT INTO devres_captures(id,source_key,source_url,body_hash,media_type,retrieved_at) SELECT $1,source_key,source_url,$2,media_type,retrieved_at FROM devres_captures WHERE id=$3")
        .bind(&id).bind(&body_hash).bind(&current.id)
        .execute(&mut *tx).await.expect("seed original SHA capture metadata");
    assert_eq!(inserted.rows_affected(), 1);
    for statement in [
        "UPDATE devres_heads SET capture_id=$1 WHERE capture_id=$2",
        "UPDATE devres_observations SET capture_id=$1 WHERE capture_id=$2",
        "UPDATE devres_rfc_import_observations SET capture_id=$1 WHERE capture_id=$2",
    ] {
        sqlx::query(statement)
            .bind(&id)
            .bind(&current.id)
            .execute(&mut *tx)
            .await
            .expect("preserve retained capture observations");
    }
    let removed = sqlx::query("DELETE FROM devres_captures WHERE id=$1")
        .bind(&current.id)
        .execute(&mut *tx)
        .await
        .expect("replace only fixture capture representation");
    assert_eq!(removed.rows_affected(), 1);
    tx.commit().await.expect("commit fixture legacy capture");
    devres_domain::Capture {
        id,
        body_hash,
        ..current.clone()
    }
}
