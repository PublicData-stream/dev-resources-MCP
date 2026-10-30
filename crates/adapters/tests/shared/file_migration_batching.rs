//! Real PostgreSQL coverage for filesystem barriers followed by atomic checkpoints.
use devres_adapters::{PgBlobStore, integrity};
use sha2::{Digest, Sha256};
use std::{path::Path, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

fn assert_no_stages(root: &Path) {
    let mut directories = vec![root.to_owned()];
    while let Some(directory) = directories.pop() {
        for entry in std::fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            assert!(
                !entry.file_name().to_string_lossy().starts_with(".stage-"),
                "completed or failed batch retained a staging file"
            );
            if entry.file_type().unwrap().is_dir() {
                directories.push(entry.path());
            }
        }
    }
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL; run scripts/test-postgres.sh"]
async fn file_checkpoint_batches_reject_conflicts_cancel_atomically_and_resume() {
    let base = std::env::var("DEVRES_TEST_DATABASE_URL").expect("disposable PostgreSQL required");
    let admin = sqlx::PgPool::connect(&base).await.unwrap();
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let database = format!("devres_file_batching_{suffix}");
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
    // Convert only this owned empty fixture to pending offline qualification.
    sqlx::raw_sql("UPDATE devres_integrity_control SET active=false,files_complete=false,sql_complete=false,graph_complete=false; DELETE FROM devres_integrity_graph_progress;")
        .execute(&pool).await.unwrap();
    drop(store);
    let store = Arc::new(
        PgBlobStore::connect_for_migration(url.as_str(), root.path())
            .await
            .unwrap(),
    );
    let first = b"permanent public source one";
    let second = b"permanent public source two";
    let legacy_body = b"retained public legacy body";
    let legacy = hex::encode(Sha256::digest(legacy_body));
    let canonical = integrity::hash(legacy_body);
    let files = [
        ("first.txt", first.as_slice()),
        ("second.txt", second.as_slice()),
        (legacy.as_str(), legacy_body.as_slice()),
    ];
    for (path, body) in files {
        std::fs::write(root.path().join(path), body).unwrap();
    }

    // All three source files fit one batch. A pre-existing conflicting row must
    // roll back every newly inserted checkpoint and alias in that transaction.
    let wrong = integrity::hash(b"different public source");
    sqlx::query("INSERT INTO devres_integrity_files(path,digest,bytes) VALUES('first.txt',$1,$2)")
        .bind(&wrong)
        .bind(first.len() as i64)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        store
            .migrate_storage(CancellationToken::new())
            .await
            .unwrap_err()
            .code,
        "integrity"
    );
    let checkpoints: Vec<(String, String)> =
        sqlx::query_as("SELECT path,digest FROM devres_integrity_files ORDER BY path")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(checkpoints, vec![("first.txt".into(), wrong.clone())]);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM devres_content_aliases")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0,
        "checkpoint conflict committed no alias"
    );
    assert_no_stages(root.path());
    sqlx::query("DELETE FROM devres_integrity_files WHERE path='first.txt'")
        .execute(&pool)
        .await
        .unwrap();

    // A conflicting alias must likewise roll back the whole file checkpoint
    // batch. The already durable descriptors are retained for verified reuse.
    let key = serde_json::to_string(&("body", &legacy)).unwrap();
    let mapping_seal = integrity::canonical_hash(&serde_json::json!({
        "version": 1,
        "namespace": "devres_content_aliases",
        "key": key,
        "payload": {"namespace": "body", "legacy": legacy, "canonical": wrong}
    }))
    .unwrap();
    sqlx::query("INSERT INTO devres_content_aliases(namespace,legacy,canonical,mapping_integrity) VALUES('body',$1,$2,$3)")
        .bind(&legacy).bind(&wrong).bind(mapping_seal).execute(&pool).await.unwrap();
    assert_eq!(
        store
            .migrate_storage(CancellationToken::new())
            .await
            .unwrap_err()
            .code,
        "integrity"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM devres_integrity_files")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0,
        "alias conflict committed no file checkpoint"
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT canonical FROM devres_content_aliases WHERE namespace='body' AND legacy=$1"
        )
        .bind(&legacy)
        .fetch_one(&pool)
        .await
        .unwrap(),
        wrong
    );
    assert_no_stages(root.path());
    sqlx::query("DELETE FROM devres_content_aliases WHERE namespace='body' AND legacy=$1")
        .bind(&legacy)
        .execute(&pool)
        .await
        .unwrap();

    // Pause checkpoint INSERT after both filesystem barriers, request
    // cancellation, then let PostgreSQL continue. No part of this page commits.
    let mut blocker = pool.acquire().await.unwrap();
    sqlx::query("SELECT pg_advisory_lock(802171102,1)")
        .execute(&mut *blocker)
        .await
        .unwrap();
    sqlx::raw_sql("CREATE FUNCTION devres_file_batch_pause() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(802171102,1); RETURN NULL; END $$; CREATE TRIGGER devres_file_batch_pause BEFORE INSERT ON devres_integrity_files FOR EACH STATEMENT EXECUTE FUNCTION devres_file_batch_pause();")
        .execute(&pool).await.unwrap();
    let cancel = CancellationToken::new();
    let task_store = store.clone();
    let task_cancel = cancel.clone();
    let task = tokio::spawn(async move { task_store.migrate_storage(task_cancel).await });
    let waiting = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND classid=802171102 AND objid=1 AND NOT granted)")
                .fetch_one(&pool).await.unwrap();
            if waiting {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    cancel.cancel();
    sqlx::query("SELECT pg_advisory_unlock(802171102,1)")
        .execute(&mut *blocker)
        .await
        .unwrap();
    waiting.expect("file migration reached transactional checkpoint publication");
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(15), task)
            .await
            .expect("cancelled migration must drain its writer")
            .unwrap()
            .unwrap_err()
            .code,
        "cancelled"
    );
    let committed: (i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM devres_integrity_files),(SELECT count(*) FROM devres_content_aliases)")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(committed, (0, 0));
    assert_no_stages(root.path());
    sqlx::raw_sql("DROP TRIGGER devres_file_batch_pause ON devres_integrity_files; DROP FUNCTION devres_file_batch_pause();")
        .execute(&pool).await.unwrap();

    store
        .migrate_storage(CancellationToken::new())
        .await
        .unwrap();
    for (path, body) in files {
        assert_eq!(std::fs::read(root.path().join(path)).unwrap(), body);
        let expected: (String, i64) =
            sqlx::query_as("SELECT digest,bytes FROM devres_integrity_files WHERE path=$1")
                .bind(path)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(expected, (integrity::hash(body), body.len() as i64));
        let descriptor = integrity::evidence_path(root.path(), &root.path().join(path)).unwrap();
        let evidence: integrity::FileEvidence =
            serde_json::from_slice(&std::fs::read(descriptor).unwrap()).unwrap();
        assert_eq!(evidence.path, path);
        assert_eq!(evidence.digest, integrity::hash(body));
        assert_eq!(evidence.bytes, body.len() as u64);
    }
    assert_eq!(
        std::fs::read(
            root.path()
                .join(integrity::relative_path(&canonical).unwrap())
        )
        .unwrap(),
        legacy_body
    );
    let alias: (String, bool) = sqlx::query_as("SELECT canonical,mapping_integrity IS NOT NULL FROM devres_content_aliases WHERE namespace='body' AND legacy=$1")
        .bind(&legacy).fetch_one(&pool).await.unwrap();
    assert_eq!(alias, (canonical, true));
    // A second pass inventories any newly created canonical link. Repeating
    // qualification after that must preserve checkpoint tuple identities.
    store
        .migrate_storage(CancellationToken::new())
        .await
        .unwrap();
    let before: Vec<(String, String, i64, String)> = sqlx::query_as(
        "SELECT path,digest,bytes,ctid::text FROM devres_integrity_files ORDER BY path",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    store
        .migrate_storage(CancellationToken::new())
        .await
        .unwrap();
    let after: Vec<(String, String, i64, String)> = sqlx::query_as(
        "SELECT path,digest,bytes,ctid::text FROM devres_integrity_files ORDER BY path",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        before, after,
        "resume does not rewrite committed checkpoints"
    );
    assert_no_stages(root.path());

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
