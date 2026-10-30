//! Real PostgreSQL coverage for streamed, restartable offline seal batches.
use devres_adapters::{PgBlobStore, integrity};
use devres_application::Store;
use devres_domain::{FetchRequest, FetchResponse, Validators};
use serde_json::json;
use sqlx::Row;
use std::{sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

#[tokio::test]
#[ignore = "requires disposable PostgreSQL; run scripts/test-postgres.sh"]
async fn streamed_migration_seals_cancel_rollback_resume_and_verify_without_rewrites() {
    let base = std::env::var("DEVRES_TEST_DATABASE_URL").expect("disposable PostgreSQL required");
    let admin = sqlx::PgPool::connect(&base).await.unwrap();
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let database = format!("devres_batching_{suffix}");
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {database}")))
        .execute(&admin)
        .await
        .unwrap();
    let mut url = url::Url::parse(&base).unwrap();
    url.set_path(&format!("/{database}"));
    let pool = sqlx::PgPool::connect(url.as_str()).await.unwrap();
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let store = Arc::new(
        PgBlobStore::connect(url.as_str(), root.path())
            .await
            .unwrap(),
    );
    let published = store
        .publish(
            &FetchRequest {
                key: "fixture:batching".into(),
                url: "https://fixtures.invalid/batching".into(),
                ttl_secs: 3600,
                max_bytes: 128,
                media_type: "text/plain".into(),
            },
            FetchResponse {
                status: 200,
                body: b"retained public batching fixture".to_vec(),
                validators: Validators::default(),
            },
            10,
        )
        .await
        .unwrap();
    // Only this owned disposable database is converted to pending legacy seals.
    sqlx::raw_sql("UPDATE devres_integrity_control SET active=false,files_complete=false,sql_complete=false,graph_complete=false; ALTER TABLE devres_mdn_evidence ALTER COLUMN data_integrity DROP NOT NULL; ALTER TABLE devres_mdn_evidence ALTER COLUMN sequence_integrity DROP NOT NULL; ALTER TABLE devres_advisory_records ALTER COLUMN data_integrity DROP NOT NULL; ALTER TABLE devres_heads ALTER COLUMN head_integrity DROP NOT NULL; ALTER TABLE devres_observations ALTER COLUMN event_integrity DROP NOT NULL;")
        .execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO devres_mdn_evidence(kind,key,data) SELECT 'fixture-metadata','item-'||n,jsonb_build_object('public',n) FROM generate_series(1,2001) n")
        .execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO devres_advisory_records(id,data) SELECT 'record-'||n,jsonb_build_object('public',n) FROM generate_series(1,2001) n")
        .execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO devres_observations(capture_id,validated_at,status) SELECT $1,n,304 FROM generate_series(1,2001) n")
        .bind(&published.capture.id).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO devres_heads(source_key,capture_id,validated_at) SELECT 'head-'||n,$1,n FROM generate_series(1,2001) n")
        .bind(&published.capture.id).execute(&pool).await.unwrap();
    // A large single admitted representation must not be multiplied by batch size.
    let large = json!({"public": "x".repeat(9 * 1024 * 1024)});
    sqlx::query("INSERT INTO devres_advisory_records(id,data) VALUES('large',$1)")
        .bind(sqlx::types::Json(&large))
        .execute(&pool)
        .await
        .unwrap();

    // Cancellation after UPDATE but before COMMIT must roll the whole page back.
    let mut blocker = pool.acquire().await.unwrap();
    sqlx::query("SELECT pg_advisory_lock(802171101,1)")
        .execute(&mut *blocker)
        .await
        .unwrap();
    sqlx::raw_sql("CREATE FUNCTION devres_batch_pause() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(802171101,1); RETURN NULL; END $$; CREATE TRIGGER devres_batch_pause BEFORE UPDATE ON devres_mdn_evidence FOR EACH STATEMENT EXECUTE FUNCTION devres_batch_pause();")
        .execute(&pool).await.unwrap();
    let cancel = CancellationToken::new();
    let task_store = store.clone();
    let task_cancel = cancel.clone();
    let task = tokio::spawn(async move { task_store.migrate_storage(task_cancel).await });
    let waiting = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND classid=802171101 AND objid=1 AND NOT granted)")
                .fetch_one(&pool).await.unwrap();
            if waiting { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await;
    cancel.cancel();
    sqlx::query("SELECT pg_advisory_unlock(802171101,1)")
        .execute(&mut *blocker)
        .await
        .unwrap();
    waiting.expect("migration reached first bounded update");
    assert_eq!(task.await.unwrap().unwrap_err().code, "cancelled");
    let sealed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM devres_mdn_evidence WHERE sequence_integrity IS NOT NULL",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        sealed, 0,
        "cancelled transaction published no sequence seals"
    );
    sqlx::raw_sql("DROP TRIGGER devres_batch_pause ON devres_mdn_evidence; DROP FUNCTION devres_batch_pause(); CREATE FUNCTION devres_batch_skip() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.key='item-1001' THEN RETURN NULL; END IF; RETURN NEW; END $$; CREATE TRIGGER devres_batch_skip BEFORE UPDATE ON devres_mdn_evidence FOR EACH ROW EXECUTE FUNCTION devres_batch_skip();")
        .execute(&pool).await.unwrap();
    assert_eq!(
        store
            .migrate_storage(CancellationToken::new())
            .await
            .unwrap_err()
            .code,
        "integrity"
    );
    let sealed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM devres_mdn_evidence WHERE sequence_integrity IS NOT NULL",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        sealed, 1000,
        "mismatched second page rolls back, first page survives"
    );
    sqlx::raw_sql(
        "DROP TRIGGER devres_batch_skip ON devres_mdn_evidence; DROP FUNCTION devres_batch_skip();",
    )
    .execute(&pool)
    .await
    .unwrap();

    store
        .migrate_storage(CancellationToken::new())
        .await
        .unwrap();
    let missing: i64 = sqlx::query_scalar("SELECT (SELECT count(*) FROM devres_mdn_evidence WHERE sequence_integrity IS NULL OR data_integrity IS NULL)+(SELECT count(*) FROM devres_advisory_records WHERE data_integrity IS NULL)+(SELECT count(*) FROM devres_observations WHERE event_integrity IS NULL)+(SELECT count(*) FROM devres_heads WHERE head_integrity IS NULL)")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(missing, 0);
    let sample = sqlx::query("SELECT sequence,kind,key,data,sequence_integrity,data_integrity FROM devres_mdn_evidence WHERE key='item-1001'")
        .fetch_one(&pool).await.unwrap();
    let sequence: i64 = sample.get("sequence");
    let data: sqlx::types::Json<serde_json::Value> = sample.get("data");
    assert_eq!(sample.get::<String,_>("sequence_integrity"), integrity::canonical_hash(
        &json!({"version":1,"namespace":"devres_mdn_evidence","kind":"fixture-metadata","key":"item-1001","sequence":sequence})).unwrap());
    assert_eq!(sample.get::<String,_>("data_integrity"), integrity::canonical_hash(
        &json!({"version":1,"namespace":"devres_mdn_evidence","key":["fixture-metadata","item-1001"],"payload":data.0})).unwrap());
    let retained: sqlx::types::Json<serde_json::Value> =
        sqlx::query_scalar("SELECT data FROM devres_advisory_records WHERE id='large'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(retained.0, large, "single large payload survives unchanged");
    let identities: Vec<(String, String)> =
        sqlx::query_as("SELECT id,ctid::text FROM devres_advisory_records ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
    // Restart qualification verifies committed seals and never rewrites them.
    store
        .migrate_storage(CancellationToken::new())
        .await
        .unwrap();
    let after: Vec<(String, String)> =
        sqlx::query_as("SELECT id,ctid::text FROM devres_advisory_records ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(identities, after);
    sqlx::query("UPDATE devres_advisory_records SET data=jsonb_build_object('corrupt',true) WHERE id='record-1001'")
        .execute(&pool).await.unwrap();
    assert_eq!(
        store
            .migrate_storage(CancellationToken::new())
            .await
            .unwrap_err()
            .code,
        "integrity"
    );
    drop(store);
    drop(blocker);
    pool.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP DATABASE {database} WITH (FORCE)"
    )))
    .execute(&admin)
    .await
    .unwrap();
    admin.close().await;
}
