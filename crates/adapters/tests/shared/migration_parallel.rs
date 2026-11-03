//! Real legacy-history migration parity; no provider acquisition or package execution.
use devres_adapters::{
    MigrationExecution, MigrationExecutionOptions, MigrationSettings, PgBlobStore, integrity,
    migrate_storage_graphs_with_execution,
};
use devres_application::Store;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

const SOURCE_KEY: &str = "fixture:parallel-history";
const SOURCE_URL: &str = "https://fixtures.invalid/parallel-history";
const BODIES: [&[u8]; 2] = [
    b"first retained public historical body",
    b"second retained public historical body",
];

fn legacy_capture(body: &[u8]) -> (String, String) {
    let digest = hex::encode(Sha256::digest(body));
    let id = hex::encode(Sha256::digest(
        format!("{SOURCE_KEY}\0{SOURCE_URL}\0text/plain\0{digest}").as_bytes(),
    ));
    (id, digest)
}

fn canonical_capture(body: &[u8]) -> String {
    let digest = integrity::hash(body);
    integrity::hash(format!("{SOURCE_KEY}\0{SOURCE_URL}\0text/plain\0{digest}").as_bytes())
}

async fn seed_legacy_history(pool: &sqlx::PgPool, root: &Path) {
    // This is the original schema, rather than a fresh schema-ten store with
    // activation flags reset. connect_for_migration must perform every upgrade.
    sqlx::raw_sql(
        "CREATE TABLE devres_schema(singleton boolean PRIMARY KEY CHECK(singleton),version integer NOT NULL); \
         INSERT INTO devres_schema VALUES(true,1); \
         CREATE TABLE devres_captures(id text PRIMARY KEY,source_key text NOT NULL,source_url text NOT NULL,body_hash text NOT NULL,media_type text NOT NULL,retrieved_at bigint NOT NULL); \
         CREATE TABLE devres_heads(source_key text PRIMARY KEY,capture_id text NOT NULL REFERENCES devres_captures(id),validated_at bigint NOT NULL,etag text,last_modified text); \
         CREATE TABLE devres_observations(id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,capture_id text NOT NULL REFERENCES devres_captures(id),validated_at bigint NOT NULL,status smallint NOT NULL CHECK(status IN (200,304)));",
    )
    .execute(pool)
    .await
    .unwrap();
    for (index, body) in BODIES.iter().enumerate() {
        let (id, digest) = legacy_capture(body);
        std::fs::write(root.join(&digest), body).unwrap();
        let retrieved_at = (index as i64 + 1) * 10;
        sqlx::query("INSERT INTO devres_captures VALUES($1,$2,$3,$4,'text/plain',$5)")
            .bind(&id)
            .bind(SOURCE_KEY)
            .bind(SOURCE_URL)
            .bind(&digest)
            .bind(retrieved_at)
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO devres_observations(capture_id,validated_at,status) VALUES($1,$2,200),($1,$3,304)")
            .bind(&id)
            .bind(retrieved_at)
            .bind(retrieved_at + 5)
            .execute(pool)
            .await
            .unwrap();
    }
    sqlx::query("INSERT INTO devres_heads VALUES($1,$2,25,'fixture-etag','fixture-last-modified')")
        .bind(SOURCE_KEY)
        .bind(legacy_capture(BODIES[1]).0)
        .execute(pool)
        .await
        .unwrap();
}

fn descriptor_inventory(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let base = root.join(".devres-integrity");
    let mut directories = vec![base.clone()];
    let mut inventory = BTreeMap::new();
    while let Some(directory) = directories.pop() {
        for entry in std::fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            assert!(
                !kind.is_symlink(),
                "fixture has no linked integrity metadata"
            );
            assert!(
                !entry.file_name().to_string_lossy().starts_with(".stage-"),
                "returned migration retained an unpublished stage"
            );
            if kind.is_dir() {
                directories.push(entry.path());
            } else {
                assert!(kind.is_file());
                let path = entry.path();
                inventory.insert(
                    path.strip_prefix(&base).unwrap().to_str().unwrap().into(),
                    std::fs::read(path).unwrap(),
                );
            }
        }
    }
    inventory
}

async fn durable_rows(pool: &sqlx::PgPool) -> BTreeMap<String, Vec<Value>> {
    let mut inventory = BTreeMap::new();
    // to_jsonb includes all durable column values and seals but no physical
    // ctid/xmin metadata. Every comparison has an explicit stable logical order.
    for (table, order) in [
        ("devres_schema", "singleton"),
        ("devres_captures", "id"),
        ("devres_heads", "source_key"),
        ("devres_observations", "id"),
        ("devres_content_aliases", "namespace,legacy"),
        ("devres_integrity_files", "path"),
        ("devres_integrity_control", "singleton"),
        ("devres_integrity_graph_progress", "provider"),
        ("devres_integrity_provider_cutoffs", "provider"),
        ("devres_integrity_staged_state", "provider,key"),
    ] {
        let rows: Vec<sqlx::types::Json<Value>> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT to_jsonb(retained) FROM {table} retained ORDER BY {order}"
        )))
        .fetch_all(pool)
        .await
        .unwrap();
        inventory.insert(
            table.to_owned(),
            rows.into_iter().map(|row| row.0).collect(),
        );
    }
    inventory
}

async fn cancel_activation_before_commit(
    store: &Arc<PgBlobStore>,
    pool: &sqlx::PgPool,
    root: &Path,
    execution: &MigrationExecution,
) {
    let before = durable_rows(pool).await;
    let descriptors = descriptor_inventory(root);
    let mut blocker = pool.acquire().await.unwrap();
    sqlx::query("SELECT pg_advisory_lock(802171109,1)")
        .execute(&mut *blocker)
        .await
        .unwrap();
    sqlx::raw_sql("CREATE FUNCTION devres_activation_pause() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(802171109,1); RETURN NEW; END $$; CREATE TRIGGER devres_activation_pause BEFORE UPDATE ON devres_integrity_control FOR EACH ROW WHEN (NEW.active AND NOT OLD.active) EXECUTE FUNCTION devres_activation_pause();")
        .execute(pool).await.unwrap();
    let cancel = CancellationToken::new();
    let task_cancel = cancel.clone();
    let task_store = store.clone();
    let task_execution = execution.clone();
    let task = tokio::spawn(async move {
        task_store
            .activate_storage_with_execution(task_cancel, &task_execution)
            .await
    });
    let waiting = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND classid=802171109 AND objid=1 AND NOT granted)")
                .fetch_one(pool).await.unwrap();
            if blocked {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    cancel.cancel();
    sqlx::query("SELECT pg_advisory_unlock(802171109,1)")
        .execute(&mut *blocker)
        .await
        .unwrap();
    waiting.expect("activation reached its final transactional publication");
    let result = tokio::time::timeout(Duration::from_secs(15), task)
        .await
        .expect("activation must drain rollback before returning")
        .unwrap();
    assert_eq!(result.unwrap_err().code, "cancelled");
    assert_eq!(durable_rows(pool).await, before);
    assert_eq!(descriptor_inventory(root), descriptors);
    assert_eq!(execution.snapshot().active, 0);
    // This fails immediately if the canceled owner still retains its transaction
    // lock, even though another ordinary snapshot SELECT could read old rows.
    let _: bool = sqlx::query_scalar(
        "SELECT active FROM devres_integrity_control WHERE singleton FOR UPDATE NOWAIT",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    sqlx::raw_sql("DROP TRIGGER devres_activation_pause ON devres_integrity_control; DROP FUNCTION devres_activation_pause();")
        .execute(pool).await.unwrap();
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL; run scripts/test-postgres.sh"]
async fn legacy_history_is_identical_after_serial_and_parallel_activation() {
    let base = std::env::var("DEVRES_TEST_DATABASE_URL").expect("disposable PostgreSQL required");
    let admin = sqlx::PgPool::connect(&base).await.unwrap();
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut serial_rows = None;
    let mut serial_descriptors = None;
    let mut serial_retrieval = None;
    for workers in [1, 2, 64] {
        let database = format!("devres_parallel_{suffix}_{workers}");
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {database}")))
            .execute(&admin)
            .await
            .unwrap();
        let mut url = url::Url::parse(&base).unwrap();
        url.set_path(&format!("/{database}"));
        let pool = sqlx::PgPool::connect(url.as_str()).await.unwrap();
        let root = tempfile::tempdir_in("/tmp").unwrap();
        seed_legacy_history(&pool, root.path()).await;
        assert!(
            PgBlobStore::connect(url.as_str(), root.path())
                .await
                .is_err()
        );
        let store = Arc::new(
            PgBlobStore::connect_for_migration(url.as_str(), root.path())
                .await
                .unwrap(),
        );
        let execution = MigrationExecution::new(
            MigrationExecutionOptions::new(workers, 64 * 1024 * 1024).unwrap(),
        )
        .unwrap();
        let migrated = migrate_storage_graphs_with_execution(
            &MigrationSettings::default(),
            store.clone(),
            CancellationToken::new(),
            &execution,
        )
        .await
        .unwrap();
        assert_eq!(migrated["phase"], "ready_for_activation");
        drop(store);
        let verifier = Arc::new(
            PgBlobStore::connect_for_verification(url.as_str(), root.path())
                .await
                .unwrap(),
        );
        let before_verify = durable_rows(&pool).await;
        let before_descriptors = descriptor_inventory(root.path());
        verifier
            .verify_storage_with_execution(CancellationToken::new(), &execution)
            .await
            .unwrap();
        assert_eq!(durable_rows(&pool).await, before_verify);
        assert_eq!(descriptor_inventory(root.path()), before_descriptors);
        drop(verifier);
        let store = Arc::new(
            PgBlobStore::connect_for_activation(url.as_str(), root.path())
                .await
                .unwrap(),
        );
        if workers == 2 {
            cancel_activation_before_commit(&store, &pool, root.path(), &execution).await;
        }
        store
            .activate_storage_with_execution(CancellationToken::new(), &execution)
            .await
            .unwrap();
        assert_eq!(execution.snapshot().active, 0);
        assert!(execution.snapshot().high_water <= workers);
        drop(store);
        let store = PgBlobStore::connect(url.as_str(), root.path())
            .await
            .unwrap();
        let mut retrieval = Vec::new();
        for (index, body) in BODIES.iter().enumerate() {
            for id in [legacy_capture(body).0, canonical_capture(body)] {
                let captured = store.capture(&id).await.unwrap();
                assert_eq!(captured.capture.id, id);
                assert_eq!(captured.body.as_ref(), *body);
                assert_eq!(captured.capture.retrieved_at, (index as i64 + 1) * 10);
                assert_eq!(captured.capture.validated_at, (index as i64 + 1) * 10 + 5);
                retrieval.push(json!({"capture":captured.capture,"body":captured.body.as_ref()}));
            }
        }
        let latest = store.latest(SOURCE_KEY).await.unwrap().unwrap();
        assert_eq!(latest.stored.capture.id, canonical_capture(BODIES[1]));
        assert_eq!(latest.stored.body.as_ref(), BODIES[1]);
        assert_eq!(latest.stored.capture.validated_at, 25);
        assert_eq!(latest.validators.etag.as_deref(), Some("fixture-etag"));
        assert_eq!(
            latest.validators.last_modified.as_deref(),
            Some("fixture-last-modified")
        );
        retrieval.push(json!({"latest":latest.stored.capture,"body":latest.stored.body.as_ref(),"etag":latest.validators.etag,"last_modified":latest.validators.last_modified}));
        let rows = durable_rows(&pool).await;
        assert_eq!(rows["devres_captures"].len(), 4);
        assert_eq!(rows["devres_observations"].len(), 4);
        assert_eq!(rows["devres_integrity_control"][0]["active"], true);
        let descriptors = descriptor_inventory(root.path());
        assert!(!descriptors.is_empty());
        if workers == 1 {
            serial_rows = Some(rows);
            serial_descriptors = Some(descriptors);
            serial_retrieval = Some(retrieval);
        } else {
            assert_eq!(Some(&rows), serial_rows.as_ref(), "workers={workers}");
            assert_eq!(
                Some(&descriptors),
                serial_descriptors.as_ref(),
                "workers={workers}"
            );
            assert_eq!(
                Some(&retrieval),
                serial_retrieval.as_ref(),
                "workers={workers}"
            );
        }
        drop(store);
        pool.close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP DATABASE {database} WITH(FORCE)"
        )))
        .execute(&admin)
        .await
        .unwrap();
    }
    admin.close().await;
}
