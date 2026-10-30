//! A lost dedicated owner must roll back an in-flight offline seal batch.
use devres_adapters::PgBlobStore;
use std::{sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

#[tokio::test]
#[ignore = "requires disposable PostgreSQL; run scripts/test-postgres.sh"]
async fn owner_loss_during_seal_update_publishes_no_batch_and_never_reconnects() {
    let base = std::env::var("DEVRES_TEST_DATABASE_URL").expect("disposable PostgreSQL required");
    let admin = sqlx::PgPool::connect(&base).await.unwrap();
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let database = format!("devres_seal_owner_loss_{suffix}");
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
    // This isolated fixture alone permits the old unsealed representation.
    sqlx::raw_sql("UPDATE devres_integrity_control SET active=false,files_complete=false,sql_complete=false,graph_complete=false; ALTER TABLE devres_mdn_evidence ALTER COLUMN data_integrity DROP NOT NULL; ALTER TABLE devres_mdn_evidence ALTER COLUMN sequence_integrity DROP NOT NULL;")
        .execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO devres_mdn_evidence(kind,key,data) SELECT 'fixture-metadata','item-'||n,jsonb_build_object('public',n) FROM generate_series(1,1001) n")
        .execute(&pool).await.unwrap();
    let before: Vec<(String, String)> =
        sqlx::query_as("SELECT key,ctid::text FROM devres_mdn_evidence ORDER BY key")
            .fetch_all(&pool)
            .await
            .unwrap();
    let owner: i32 = sqlx::query_scalar("SELECT a.pid FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE l.locktype='advisory' AND l.classid=1835365490 AND l.objid=1 AND l.objsubid=2 AND l.granted AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database())")
        .fetch_one(&pool).await.unwrap();

    // The dedicated writer blocks inside its first UPDATE transaction. Waiting
    // for that exact backend's ungranted lock avoids timing-based termination.
    let mut blocker = pool.acquire().await.unwrap();
    sqlx::query("SELECT pg_advisory_lock(802171102,1)")
        .execute(&mut *blocker)
        .await
        .unwrap();
    sqlx::raw_sql("CREATE FUNCTION devres_seal_owner_pause() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(802171102,1); RETURN NULL; END $$; CREATE TRIGGER devres_seal_owner_pause BEFORE UPDATE ON devres_mdn_evidence FOR EACH STATEMENT EXECUTE FUNCTION devres_seal_owner_pause();")
        .execute(&pool).await.unwrap();
    let cancel = CancellationToken::new();
    let task_store = store.clone();
    let task_cancel = cancel.clone();
    let mut task = tokio::spawn(async move { task_store.migrate_storage(task_cancel).await });
    let waiting = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND classid=802171102 AND objid=1 AND NOT granted)")
                .bind(owner).fetch_one(&pool).await.unwrap();
            if waiting {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    if waiting.is_ok() {
        let terminated: bool = sqlx::query_scalar("SELECT pg_terminate_backend($1,5000)")
            .bind(owner)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(terminated, "the blocked dedicated owner was terminated");
    } else {
        // Always unblock and join the task even when this fixture's observation
        // deadline fails, rather than leaving a background migration writer.
        cancel.cancel();
    }
    sqlx::query("SELECT pg_advisory_unlock(802171102,1)")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let result = match tokio::time::timeout(Duration::from_secs(15), &mut task).await {
        Ok(result) => result.unwrap(),
        Err(_) => {
            task.abort();
            let _ = task.await;
            panic!("terminated owner must stop the migration task");
        }
    };
    waiting.expect("the first seal UPDATE reached the deterministic owner gate");
    assert!(
        result.is_err(),
        "lost ownership cannot publish a seal batch"
    );
    let sealed: i64 = sqlx::query_scalar("SELECT count(*) FROM devres_mdn_evidence WHERE sequence_integrity IS NOT NULL OR data_integrity IS NOT NULL")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(sealed, 0, "no row in the interrupted batch was published");
    let after: Vec<(String, String)> =
        sqlx::query_as("SELECT key,ctid::text FROM devres_mdn_evidence ORDER BY key")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(before, after, "the original unsealed tuples remain visible");
    assert!(store.check_health().await.is_err());
    assert!(
        store
            .migrate_storage(CancellationToken::new())
            .await
            .is_err(),
        "the same handle must not reconnect or restart a writer"
    );
    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND classid=1835365490 AND objid=1 AND objsubid=2 AND granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database())")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(remaining, 0, "no replacement migration owner was created");

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
