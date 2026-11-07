//! SQL-only retained evidence fixtures: no acquisition or package execution.
use super::*;
use std::time::Duration;

struct RowFixture {
    admin: sqlx::PgPool,
    pool: sqlx::PgPool,
    store: Arc<PgBlobStore>,
    root: tempfile::TempDir,
    database: String,
    maps: crate::MigrationMap,
    pairs: Vec<(String, String)>,
}

impl RowFixture {
    async fn new(count: usize, padding: usize, observations: usize) -> Self {
        let base = std::env::var("DEVRES_TEST_DATABASE_URL").expect("disposable PostgreSQL");
        let admin = sqlx::PgPool::connect(&base).await.unwrap();
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let database = format!("devres_crate_rows_{suffix}");
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {database}")))
            .execute(&admin)
            .await
            .unwrap();
        let mut url = url::Url::parse(&base).unwrap();
        url.set_path(&format!("/{database}"));
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let store = Arc::new(
            PgBlobStore::connect(url.as_str(), root.path())
                .await
                .unwrap(),
        );
        let pool = sqlx::PgPool::connect(url.as_str()).await.unwrap();
        let mut maps = crate::MigrationMap::new();
        let mut pairs = Vec::new();
        let body = b"public synthetic retained crate evidence";
        let legacy_body = crate::integrity::legacy_hash(body);
        let canonical_body = hash(body);
        for ordinal in 0..count {
            let key = format!("cargo:derived:row-fixture-{ordinal:06}");
            let source_url = format!("https://fixtures.invalid/crate/{ordinal}");
            let old = crate::integrity::legacy_hash(
                format!("{key}\0{source_url}\0text/plain\0{legacy_body}").as_bytes(),
            );
            let new = hash(format!("{key}\0{source_url}\0text/plain\0{canonical_body}").as_bytes());
            for (id, body_hash) in [(&old, &legacy_body), (&new, &canonical_body)] {
                let capture = devres_domain::Capture {
                    id: id.clone(),
                    key: key.clone(),
                    source_url: source_url.clone(),
                    body_hash: body_hash.clone(),
                    media_type: "text/plain".into(),
                    retrieved_at: 17,
                    validated_at: 17,
                };
                sqlx::query("INSERT INTO devres_captures(id,source_key,source_url,body_hash,media_type,retrieved_at,metadata_integrity) VALUES($1,$2,$3,$4,$5,$6,$7)")
                    .bind(id).bind(&key).bind(&source_url).bind(body_hash).bind("text/plain").bind(17_i64)
                    .bind(crate::storage::capture_metadata_digest(&capture).unwrap()).execute(&pool).await.unwrap();
            }
            let provenance = json!({"synthetic":true,"capture":old,"ordinal":ordinal,"padding":"x".repeat(padding)});
            let seal = payload_integrity::digest(
                "devres_crate_artifacts",
                "",
                &old,
                &payload_integrity::crate_artifact_payload(body.len() as u64, &provenance),
            )
            .unwrap();
            sqlx::query("INSERT INTO devres_crate_artifacts(capture_id,bytes,provenance,provenance_integrity) VALUES($1,$2,$3,$4)")
                .bind(&old).bind(body.len() as i64).bind(Json(&provenance)).bind(seal).execute(&pool).await.unwrap();
            for _ in 0..observations {
                let mut connection = pool.acquire().await.unwrap();
                append_crate_observation(&mut connection, &old, 17, "derived_or_git", &provenance)
                    .await
                    .unwrap();
            }
            crate::migration_map::insert(&mut maps, format!("capture:{old}"), new.clone()).unwrap();
            pairs.push((old, new));
        }
        Self {
            admin,
            pool,
            store,
            root,
            database,
            maps,
            pairs,
        }
    }

    fn execution(workers: usize, graph_bytes: usize) -> crate::MigrationExecution {
        crate::MigrationExecution::new_with_graph_options(
            crate::MigrationExecutionOptions::new(workers, 64 * 1024 * 1024).unwrap(),
            crate::MigrationGraphOptions::new(graph_bytes).unwrap(),
        )
        .unwrap()
    }

    async fn canonical_tuples(&self) -> Vec<(String, String)> {
        sqlx::query_as("SELECT capture_id,ctid::text FROM devres_crate_artifacts WHERE capture_id LIKE 'blake3:%' ORDER BY capture_id")
            .fetch_all(&self.pool).await.unwrap()
    }

    async fn semantic_rows(&self) -> Vec<Value> {
        let rows: Vec<Json<Value>> = sqlx::query_scalar("SELECT to_jsonb(a) FROM devres_crate_artifacts a WHERE capture_id LIKE 'blake3:%' ORDER BY capture_id")
            .fetch_all(&self.pool).await.unwrap();
        let mut values: Vec<Value> = rows.into_iter().map(|value| value.0).collect();
        let rows: Vec<Json<Value>> = sqlx::query_scalar("SELECT to_jsonb(o) FROM devres_crate_observations o WHERE capture_id LIKE 'blake3:%' ORDER BY sequence")
            .fetch_all(&self.pool).await.unwrap();
        values.extend(rows.into_iter().map(|value| value.0));
        let rows: Vec<Json<Value>> = sqlx::query_scalar("SELECT to_jsonb(s) FROM devres_integrity_staged_state s WHERE provider='crate' ORDER BY key")
            .fetch_all(&self.pool).await.unwrap();
        values.extend(rows.into_iter().map(|value| value.0));
        values
    }

    async fn transaction_log(&self, table: &str) {
        assert!(matches!(
            table,
            "devres_crate_artifacts" | "devres_crate_observations" | "devres_crate_staging"
        ));
        sqlx::raw_sql("CREATE TABLE fixture_transactions(xid bigint NOT NULL); CREATE FUNCTION fixture_record_tx() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN INSERT INTO fixture_transactions VALUES(txid_current()); RETURN NEW; END $$;")
            .execute(&self.pool).await.unwrap();
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE TRIGGER fixture_record_tx AFTER INSERT ON {table} FOR EACH ROW WHEN (NEW.{} LIKE 'blake3:%') EXECUTE FUNCTION fixture_record_tx()", if table == "devres_crate_staging" { "inventory" } else { "capture_id" })))
            .execute(&self.pool).await.unwrap();
    }

    async fn batch_sizes(&self) -> Vec<i64> {
        sqlx::query_scalar("SELECT count(*) FROM fixture_transactions GROUP BY xid ORDER BY xid")
            .fetch_all(&self.pool)
            .await
            .unwrap()
    }

    async fn close(self) {
        let Self {
            admin,
            pool,
            store,
            root,
            database,
            maps,
            ..
        } = self;
        drop(maps);
        drop(store);
        pool.close().await;
        drop(root);
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP DATABASE {database} WITH (FORCE)"
        )))
        .execute(&admin)
        .await
        .unwrap();
        admin.close().await;
    }
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL; crate row windows, ordering and resume"]
async fn crate_row_pipeline_serial_parallel_boundaries_and_occurrence_resume() {
    for count in [127, 128, 129] {
        let mut reference = None;
        for workers in [1, 2, 8] {
            let fixture = RowFixture::new(count, 4096, 2).await;
            fixture.transaction_log("devres_crate_artifacts").await;
            let execution = RowFixture::execution(workers, 1024 * 1024 * 1024);
            let cancel = CancellationToken::new();
            fixture
                .store
                .migrate_artifact_rows(&fixture.maps, &cancel, &execution)
                .await
                .unwrap();
            let sizes = fixture.batch_sizes().await;
            assert_eq!(sizes.iter().sum::<i64>(), count as i64);
            assert!(sizes.iter().all(|size| *size <= 128));
            assert_eq!(
                sizes.len(),
                count.div_ceil(128),
                "row batches are independent of worker count"
            );
            fixture
                .store
                .migrate_observation_rows(&fixture.maps, &cancel, &execution)
                .await
                .unwrap();
            let observations: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM devres_crate_observations WHERE capture_id LIKE 'blake3:%'",
            )
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
            let receipts: i64 = sqlx::query_scalar("SELECT count(*) FROM devres_integrity_staged_state WHERE provider='crate' AND key LIKE 'observation:%'")
                .fetch_one(&fixture.pool).await.unwrap();
            assert_eq!(
                observations,
                (count * 2) as i64,
                "same-second identical occurrences remain distinct"
            );
            assert_eq!(
                receipts, observations,
                "one retained receipt per source occurrence"
            );
            let before = fixture.canonical_tuples().await;
            let receipt_tuples:Vec<(String,String)> = sqlx::query_as("SELECT key,ctid::text FROM devres_integrity_staged_state WHERE provider='crate' ORDER BY key")
                .fetch_all(&fixture.pool).await.unwrap();
            let semantic = fixture.semantic_rows().await;
            if let Some(expected) = &reference {
                assert_eq!(
                    &semantic, expected,
                    "worker settings preserve exact SQL evidence and occurrence sequences"
                );
            } else {
                reference = Some(semantic.clone());
            }
            fixture
                .store
                .migrate_artifact_rows(&fixture.maps, &cancel, &execution)
                .await
                .unwrap();
            fixture
                .store
                .migrate_observation_rows(&fixture.maps, &cancel, &execution)
                .await
                .unwrap();
            assert_eq!(
                before,
                fixture.canonical_tuples().await,
                "resume does not rewrite canonical artifacts"
            );
            assert_eq!(
                semantic,
                fixture.semantic_rows().await,
                "resume consumes no additional observations or receipts"
            );
            let after:Vec<(String,String)>=sqlx::query_as("SELECT key,ctid::text FROM devres_integrity_staged_state WHERE provider='crate' ORDER BY key")
                .fetch_all(&fixture.pool).await.unwrap();
            assert_eq!(
                receipt_tuples, after,
                "committed receipts retain tuple identities"
            );
            let snapshot = execution.snapshot();
            assert!(snapshot.graph_high_water <= workers);
            assert!(snapshot.high_water <= workers);
            assert_eq!(snapshot.active, 0);
            assert_eq!(snapshot.graph_active, 0);
            assert_eq!(snapshot.graph_memory_bytes, 0);
            if workers > 1 {
                assert!(
                    snapshot.graph_high_water > 1,
                    "parallel row preparation actually overlaps"
                );
            }
            fixture.close().await;
        }
    }
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL; byte-boundary and exclusive oversized crate rows"]
async fn crate_row_pipeline_byte_windows_and_oversized_singletons() {
    let fixture = RowFixture::new(10, 900_000, 0).await;
    fixture.transaction_log("devres_crate_artifacts").await;
    let execution = RowFixture::execution(8, 1024 * 1024 * 1024);
    fixture
        .store
        .migrate_artifact_rows(&fixture.maps, &CancellationToken::new(), &execution)
        .await
        .unwrap();
    let sizes = fixture.batch_sizes().await;
    assert_eq!(sizes.iter().sum::<i64>(), 10);
    assert!(
        sizes.len() > 1,
        "encoded publication arguments cross eight MiB before 128 rows"
    );
    fixture.close().await;

    let fixture = RowFixture::new(2, 9 * 1024 * 1024, 0).await;
    fixture.transaction_log("devres_crate_artifacts").await;
    let execution = RowFixture::execution(8, 1024);
    fixture
        .store
        .migrate_artifact_rows(&fixture.maps, &CancellationToken::new(), &execution)
        .await
        .unwrap();
    assert_eq!(
        fixture.batch_sizes().await,
        vec![1, 1],
        "valid oversized retained units run individually"
    );
    let snapshot = execution.snapshot();
    assert_eq!(snapshot.graph_high_water, 1);
    assert!(snapshot.graph_memory_high_water > 1024);
    assert_eq!(snapshot.graph_memory_bytes, 0);
    fixture.close().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL; checked crate source and canonical replay"]
async fn crate_row_pipeline_rejects_corrupt_source_target_and_receipt() {
    let fixture = RowFixture::new(2, 64, 2).await;
    let execution = RowFixture::execution(2, 1024 * 1024 * 1024);
    let cancel = CancellationToken::new();
    fixture
        .store
        .migrate_artifact_rows(&fixture.maps, &cancel, &execution)
        .await
        .unwrap();
    fixture
        .store
        .migrate_observation_rows(&fixture.maps, &cancel, &execution)
        .await
        .unwrap();
    let (old, new) = &fixture.pairs[0];
    let source: Json<Value> =
        sqlx::query_scalar("SELECT provenance FROM devres_crate_artifacts WHERE capture_id=$1")
            .bind(old)
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    sqlx::query("UPDATE devres_crate_artifacts SET provenance=provenance||'{\"changed\":true}'::jsonb WHERE capture_id=$1")
        .bind(old).execute(&fixture.pool).await.unwrap();
    assert_eq!(
        fixture
            .store
            .migrate_artifact_rows(&fixture.maps, &cancel, &execution)
            .await
            .unwrap_err()
            .code,
        "integrity"
    );
    sqlx::query("UPDATE devres_crate_artifacts SET provenance=$2 WHERE capture_id=$1")
        .bind(old)
        .bind(source)
        .execute(&fixture.pool)
        .await
        .unwrap();
    let target: Json<Value> =
        sqlx::query_scalar("SELECT provenance FROM devres_crate_artifacts WHERE capture_id=$1")
            .bind(new)
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    let changed_seal = payload_integrity::digest(
        "devres_crate_artifacts",
        "",
        new,
        &payload_integrity::crate_artifact_payload(999, &target.0),
    )
    .unwrap();
    sqlx::query(
        "UPDATE devres_crate_artifacts SET bytes=999,provenance_integrity=$2 WHERE capture_id=$1",
    )
    .bind(new)
    .bind(changed_seal)
    .execute(&fixture.pool)
    .await
    .unwrap();
    assert_eq!(
        fixture
            .store
            .migrate_artifact_rows(&fixture.maps, &cancel, &execution)
            .await
            .unwrap_err()
            .code,
        "integrity",
        "a self-consistent conflicting target must not be accepted by ON CONFLICT"
    );
    sqlx::query("UPDATE devres_integrity_staged_state SET data=data||'{\"sequence\":999999}'::jsonb WHERE provider='crate' AND key=(SELECT min(key) FROM devres_integrity_staged_state WHERE provider='crate')")
        .execute(&fixture.pool).await.unwrap();
    assert_eq!(
        fixture
            .store
            .migrate_observation_rows(&fixture.maps, &cancel, &execution)
            .await
            .unwrap_err()
            .code,
        "integrity"
    );
    assert_eq!(execution.snapshot().graph_memory_bytes, 0);
    fixture.close().await;
}

async fn wait_for_gate(
    pool: &sqlx::PgPool,
) -> std::result::Result<(), tokio::time::error::Elapsed> {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND classid=802171201 AND objid=1 AND NOT granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database()))")
                .fetch_one(pool).await.unwrap();
            if waiting {break;}
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL; later crate batch rollback and exact resume"]
async fn crate_row_pipeline_cancel_later_batches_preserves_prior_artifacts_and_receipts() {
    for observations in [false, true] {
        let fixture = RowFixture::new(129, 64, if observations { 2 } else { 0 }).await;
        let execution = RowFixture::execution(8, 1024 * 1024 * 1024);
        if observations {
            fixture
                .store
                .migrate_artifact_rows(&fixture.maps, &CancellationToken::new(), &execution)
                .await
                .unwrap();
        }
        let gate = if observations {
            "NEW.sequence=387".to_owned() // 258 retained source occurrences + 129th target.
        } else {
            let old:String=sqlx::query_scalar("SELECT capture_id FROM devres_crate_artifacts WHERE capture_id NOT LIKE 'blake3:%' ORDER BY capture_id OFFSET 128 LIMIT 1")
                .fetch_one(&fixture.pool).await.unwrap();
            let target = fixture.maps.get(&format!("capture:{old}")).unwrap();
            format!("NEW.capture_id='{target}'")
        };
        let table = if observations {
            "devres_crate_observations"
        } else {
            "devres_crate_artifacts"
        };
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE FUNCTION fixture_pause() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF {gate} THEN PERFORM pg_advisory_xact_lock(802171201,1); END IF; RETURN NEW; END $$; CREATE TRIGGER fixture_pause BEFORE INSERT ON {table} FOR EACH ROW WHEN (NEW.capture_id LIKE 'blake3:%') EXECUTE FUNCTION fixture_pause();")))
            .execute(&fixture.pool).await.unwrap();
        let mut blocker = fixture.pool.acquire().await.unwrap();
        sqlx::query("SELECT pg_advisory_lock(802171201,1)")
            .execute(&mut *blocker)
            .await
            .unwrap();
        let cancel = CancellationToken::new();
        let token = cancel.clone();
        let store = fixture.store.clone();
        let maps = fixture.maps.clone();
        let runner = execution.clone();
        let task = tokio::spawn(async move {
            if observations {
                store.migrate_observation_rows(&maps, &token, &runner).await
            } else {
                store.migrate_artifact_rows(&maps, &token, &runner).await
            }
        });
        let waiting = wait_for_gate(&fixture.pool).await;
        let before: Vec<(String, String)> = if observations {
            sqlx::query_as("SELECT key,ctid::text FROM devres_integrity_staged_state WHERE provider='crate' ORDER BY key")
                .fetch_all(&fixture.pool).await.unwrap()
        } else {
            fixture.canonical_tuples().await
        };
        cancel.cancel();
        sqlx::query("SELECT pg_advisory_unlock(802171201,1)")
            .execute(&mut *blocker)
            .await
            .unwrap();
        let result = tokio::time::timeout(Duration::from_secs(30), task)
            .await
            .expect("cooperative cancellation joins row tasks")
            .unwrap();
        waiting.expect("the second batch reached its exact SQL publication gate");
        assert_eq!(result.unwrap_err().code, "cancelled");
        assert_eq!(
            before.len(),
            128,
            "the previous complete batch is durably visible"
        );
        let after: Vec<(String, String)> = if observations {
            sqlx::query_as("SELECT key,ctid::text FROM devres_integrity_staged_state WHERE provider='crate' ORDER BY key")
                .fetch_all(&fixture.pool).await.unwrap()
        } else {
            fixture.canonical_tuples().await
        };
        assert_eq!(
            before, after,
            "the incomplete batch rolled back without rewriting prior commits"
        );
        let count: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT count(*) FROM {table} WHERE capture_id LIKE 'blake3:%'"
        )))
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
        assert_eq!(count, 128, "observation and receipt publication are atomic");
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "DROP TRIGGER fixture_pause ON {table}; DROP FUNCTION fixture_pause();"
        )))
        .execute(&fixture.pool)
        .await
        .unwrap();
        let fresh = CancellationToken::new();
        if observations {
            fixture
                .store
                .migrate_observation_rows(&fixture.maps, &fresh, &execution)
                .await
                .unwrap();
        } else {
            fixture
                .store
                .migrate_artifact_rows(&fixture.maps, &fresh, &execution)
                .await
                .unwrap();
        }
        let count: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT count(*) FROM {table} WHERE capture_id LIKE 'blake3:%'"
        )))
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
        assert_eq!(count, if observations { 258 } else { 129 });
        let completed: Vec<(String, String)> = if observations {
            sqlx::query_as("SELECT key,ctid::text FROM devres_integrity_staged_state WHERE provider='crate' ORDER BY key")
                .fetch_all(&fixture.pool).await.unwrap()
        } else {
            fixture.canonical_tuples().await
        };
        assert!(
            before.iter().all(|tuple| completed.contains(tuple)),
            "resume preserves all previously committed tuple identities"
        );
        assert_eq!(execution.snapshot().graph_memory_bytes, 0);
        assert_eq!(execution.snapshot().active, 0);
        assert_eq!(execution.snapshot().graph_active, 0);
        drop(blocker);
        fixture.close().await;
    }
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL; dedicated crate writer loss"]
async fn crate_row_pipeline_owner_loss_never_reconnects_or_publishes_partial_batch() {
    let fixture = RowFixture::new(129, 64, 0).await;
    let execution = RowFixture::execution(8, 1024 * 1024 * 1024);
    let old:String=sqlx::query_scalar("SELECT capture_id FROM devres_crate_artifacts WHERE capture_id NOT LIKE 'blake3:%' ORDER BY capture_id OFFSET 128 LIMIT 1")
        .fetch_one(&fixture.pool).await.unwrap();
    let target = fixture.maps.get(&format!("capture:{old}")).unwrap();
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE FUNCTION fixture_pause() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.capture_id='{target}' THEN PERFORM pg_advisory_xact_lock(802171201,1); END IF; RETURN NEW; END $$; CREATE TRIGGER fixture_pause BEFORE INSERT ON devres_crate_artifacts FOR EACH ROW WHEN (NEW.capture_id LIKE 'blake3:%') EXECUTE FUNCTION fixture_pause();")))
        .execute(&fixture.pool).await.unwrap();
    let mut blocker = fixture.pool.acquire().await.unwrap();
    sqlx::query("SELECT pg_advisory_lock(802171201,1)")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let owner: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *fixture.store.owner.lock().await)
        .await
        .unwrap();
    let cancel = CancellationToken::new();
    let token = cancel.clone();
    let store = fixture.store.clone();
    let maps = fixture.maps.clone();
    let runner = execution.clone();
    let task =
        tokio::spawn(async move { store.migrate_artifact_rows(&maps, &token, &runner).await });
    let waiting = wait_for_gate(&fixture.pool).await;
    if waiting.is_ok() {
        let terminated: bool = sqlx::query_scalar("SELECT pg_terminate_backend($1,5000)")
            .bind(owner)
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
        assert!(terminated);
    } else {
        cancel.cancel();
    }
    sqlx::query("SELECT pg_advisory_unlock(802171201,1)")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(30), task)
        .await
        .expect("lost owner drains row tasks")
        .unwrap();
    waiting.expect("second batch reached owner-loss gate");
    assert!(result.is_err());
    assert_eq!(fixture.canonical_tuples().await.len(), 128);
    assert!(
        fixture
            .store
            .migrate_artifact_rows(&fixture.maps, &CancellationToken::new(), &execution)
            .await
            .is_err(),
        "the same store does not replace its lost writer"
    );
    assert_eq!(execution.snapshot().graph_memory_bytes, 0);
    drop(blocker);
    fixture.close().await;
}

async fn staging_fixture(fixture: &RowFixture, ordinal: usize, count: usize) -> (String, String) {
    let revision = format!("{ordinal:040x}");
    let old = crate::integrity::legacy_hash(format!("crate-inventory:1:{revision}").as_bytes());
    let new = hash(format!("crate-inventory:1:{revision}").as_bytes());
    for id in [&old, &new] {
        sqlx::query("INSERT INTO devres_crate_inventories(id,revision,created_at,validated_at) VALUES($1,$2,17,17)")
            .bind(id).bind(&revision).execute(&fixture.pool).await.unwrap();
    }
    for index in 0..count {
        let name = match index % 4 {
            0 => format!("a-{index:06}"),
            1 => format!("a_{index:06}"),
            2 => format!("a{index:06}"),
            _ => "a".into(),
        };
        let version = format!("0.{index}.0");
        let record = json!({"name":name,"vers":version,"yanked":false,"fixture":ordinal});
        let metadata = &fixture.pairs[index % fixture.pairs.len()].0;
        let key = format!("{name}@{version}");
        let seal = payload_integrity::digest(
            "devres_crate_staging",
            &old,
            &key,
            &payload_integrity::crate_staging_payload(metadata, &record),
        )
        .unwrap();
        sqlx::query("INSERT INTO devres_crate_staging(inventory,name,version,metadata_capture,record,record_integrity) VALUES($1,$2,$3,$4,$5,$6)")
            .bind(&old).bind(name).bind(version).bind(metadata).bind(Json(record)).bind(seal)
            .execute(&fixture.pool).await.unwrap();
    }
    (old, new)
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL; exact staging collation and inventory restart"]
async fn crate_row_pipeline_staging_preserves_sql_order_and_rebuilds_temporary_catalog() {
    let fixture = RowFixture::new(2, 64, 0).await;
    let execution = RowFixture::execution(8, 1024 * 1024 * 1024);
    fixture.transaction_log("devres_crate_staging").await;
    sqlx::raw_sql("CREATE TABLE fixture_staging_order(ordinal bigserial,inventory text,name text,version text); CREATE FUNCTION fixture_stage_order() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN INSERT INTO fixture_staging_order(inventory,name,version) VALUES(NEW.inventory,NEW.name,NEW.version); RETURN NEW; END $$; CREATE TRIGGER fixture_stage_order AFTER INSERT ON devres_crate_staging FOR EACH ROW WHEN (NEW.inventory LIKE 'blake3:%') EXECUTE FUNCTION fixture_stage_order();")
        .execute(&fixture.pool).await.unwrap();
    for inventory in 0..2 {
        let (old, new) = staging_fixture(&fixture, inventory, 257).await;
        let source_order:Vec<String>=sqlx::query_scalar("SELECT name||'@'||version FROM devres_crate_staging WHERE inventory=$1 ORDER BY name||'@'||version")
            .bind(&old).fetch_all(&fixture.pool).await.unwrap();
        fixture
            .store
            .migrate_staging_rows(
                &old,
                &new,
                &fixture.maps,
                &CancellationToken::new(),
                &execution,
            )
            .await
            .unwrap();
        let actual:Vec<String>=sqlx::query_scalar("SELECT name||'@'||version FROM fixture_staging_order WHERE inventory=$1 ORDER BY ordinal")
            .bind(&new).fetch_all(&fixture.pool).await.unwrap();
        assert_eq!(
            source_order, actual,
            "staging retains PostgreSQL concatenation order rather than tuple or Rust ordering"
        );
        let before:Vec<(String,String)>=sqlx::query_as("SELECT name||'@'||version,ctid::text FROM devres_crate_staging WHERE inventory=$1 ORDER BY name||'@'||version")
            .bind(&new).fetch_all(&fixture.pool).await.unwrap();
        fixture
            .store
            .migrate_staging_rows(
                &old,
                &new,
                &fixture.maps,
                &CancellationToken::new(),
                &execution,
            )
            .await
            .unwrap();
        let after:Vec<(String,String)>=sqlx::query_as("SELECT name||'@'||version,ctid::text FROM devres_crate_staging WHERE inventory=$1 ORDER BY name||'@'||version")
            .bind(&new).fetch_all(&fixture.pool).await.unwrap();
        assert_eq!(
            before, after,
            "rebuilding the scratch catalog preserves canonical tuples"
        );
    }
    assert_eq!(fixture.batch_sizes().await, vec![128, 128, 1, 128, 128, 1]);
    assert_eq!(execution.snapshot().graph_memory_bytes, 0);
    fixture.close().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL; ambiguous retained staging keys fail closed"]
async fn crate_row_pipeline_staging_rejects_ambiguous_concatenated_keys() {
    let fixture = RowFixture::new(1, 0, 0).await;
    let (old, new) = staging_fixture(&fixture, 0, 0).await;
    for (name, version) in [("a@b", "c"), ("a", "b@c")] {
        let record = json!({"name":name,"vers":version});
        let seal = payload_integrity::digest(
            "devres_crate_staging",
            &old,
            "a@b@c",
            &payload_integrity::crate_staging_payload(&fixture.pairs[0].0, &record),
        )
        .unwrap();
        sqlx::query("INSERT INTO devres_crate_staging(inventory,name,version,metadata_capture,record,record_integrity) VALUES($1,$2,$3,$4,$5,$6)")
            .bind(&old).bind(name).bind(version).bind(&fixture.pairs[0].0).bind(Json(record)).bind(seal)
            .execute(&fixture.pool).await.unwrap();
    }
    let execution = RowFixture::execution(8, 1024 * 1024 * 1024);
    assert_eq!(
        fixture
            .store
            .migrate_staging_rows(
                &old,
                &new,
                &fixture.maps,
                &CancellationToken::new(),
                &execution
            )
            .await
            .unwrap_err()
            .code,
        "integrity"
    );
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM devres_crate_staging WHERE inventory=$1")
            .bind(&new)
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    assert_eq!(count, 0);
    fixture.close().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL; inventory headers are verified without rewrites"]
async fn crate_row_pipeline_inventory_header_resume_preserves_tuple_sequence_and_rejects_mismatch()
{
    let mut fixture = RowFixture::new(2, 0, 0).await;
    let (_old, new) = staging_fixture(&fixture, 0, 129).await;
    let execution = RowFixture::execution(2, 1024 * 1024 * 1024);
    let mut aliases = crate::migration_map::MigrationAliases::new(&mut fixture.maps).unwrap();
    let before:(String,i64,i64)=sqlx::query_as("SELECT ctid::text,sequence,(SELECT last_value FROM devres_crate_inventories_sequence_seq) FROM devres_crate_inventories WHERE id=$1")
        .bind(&new).fetch_one(&fixture.pool).await.unwrap();
    for _ in 0..2 {
        fixture
            .store
            .migrate_crate_inventories(
                &mut fixture.maps,
                &mut aliases,
                &CancellationToken::new(),
                &execution,
            )
            .await
            .unwrap();
        let after:(String,i64,i64)=sqlx::query_as("SELECT ctid::text,sequence,(SELECT last_value FROM devres_crate_inventories_sequence_seq) FROM devres_crate_inventories WHERE id=$1")
            .bind(&new).fetch_one(&fixture.pool).await.unwrap();
        assert_eq!(
            before, after,
            "existing canonical inventory is checked without consuming a sequence or rewriting its tuple"
        );
    }
    sqlx::query("UPDATE devres_crate_inventories SET validated_at=validated_at+1 WHERE id=$1")
        .bind(&new)
        .execute(&fixture.pool)
        .await
        .unwrap();
    assert_eq!(
        fixture
            .store
            .migrate_crate_inventories(
                &mut fixture.maps,
                &mut aliases,
                &CancellationToken::new(),
                &execution
            )
            .await
            .unwrap_err()
            .code,
        "integrity"
    );
    drop(aliases);
    fixture.close().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL; staging cancellation rebuilds disposable catalog"]
async fn crate_row_pipeline_staging_cancel_releases_catalog_and_resumes_prior_batch() {
    let fixture = RowFixture::new(2, 0, 0).await;
    let (old, new) = staging_fixture(&fixture, 0, 129).await;
    let key:String=sqlx::query_scalar("SELECT name||'@'||version FROM devres_crate_staging WHERE inventory=$1 ORDER BY name||'@'||version OFFSET 128 LIMIT 1")
        .bind(&old).fetch_one(&fixture.pool).await.unwrap();
    assert!(
        key.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b))
    );
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE FUNCTION fixture_pause() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.inventory='{new}' AND NEW.name||'@'||NEW.version='{key}' THEN PERFORM pg_advisory_xact_lock(802171201,1); END IF; RETURN NEW; END $$; CREATE TRIGGER fixture_pause BEFORE INSERT ON devres_crate_staging FOR EACH ROW WHEN (NEW.inventory LIKE 'blake3:%') EXECUTE FUNCTION fixture_pause();")))
        .execute(&fixture.pool).await.unwrap();
    let mut blocker = fixture.pool.acquire().await.unwrap();
    sqlx::query("SELECT pg_advisory_lock(802171201,1)")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let execution = RowFixture::execution(8, 1024 * 1024 * 1024);
    let cancel = CancellationToken::new();
    let token = cancel.clone();
    let store = fixture.store.clone();
    let maps = fixture.maps.clone();
    let runner = execution.clone();
    let source = old.clone();
    let target = new.clone();
    let task = tokio::spawn(async move {
        store
            .migrate_staging_rows(&source, &target, &maps, &token, &runner)
            .await
    });
    let waiting = wait_for_gate(&fixture.pool).await;
    let before:Vec<(String,String)>=sqlx::query_as("SELECT name||'@'||version,ctid::text FROM devres_crate_staging WHERE inventory=$1 ORDER BY name||'@'||version")
        .bind(&new).fetch_all(&fixture.pool).await.unwrap();
    cancel.cancel();
    sqlx::query("SELECT pg_advisory_unlock(802171201,1)")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(30), task)
        .await
        .expect("staging cancellation drains owner queries")
        .unwrap();
    waiting.expect("second staging batch reached deterministic gate");
    assert_eq!(result.unwrap_err().code, "cancelled");
    assert_eq!(before.len(), 128);
    let remains: bool =
        sqlx::query_scalar("SELECT to_regclass('pg_temp.devres_crate_migration_keys') IS NOT NULL")
            .fetch_one(&mut *fixture.store.owner.lock().await)
            .await
            .unwrap();
    assert!(
        !remains,
        "cooperative cancellation removes its session-local source key catalog"
    );
    fixture
        .store
        .migrate_staging_rows(
            &old,
            &new,
            &fixture.maps,
            &CancellationToken::new(),
            &execution,
        )
        .await
        .unwrap();
    let after:Vec<(String,String)>=sqlx::query_as("SELECT name||'@'||version,ctid::text FROM devres_crate_staging WHERE inventory=$1 ORDER BY name||'@'||version")
        .bind(&new).fetch_all(&fixture.pool).await.unwrap();
    assert_eq!(after.len(), 129);
    assert!(before.iter().all(|tuple| after.contains(tuple)));
    assert_eq!(execution.snapshot().graph_memory_bytes, 0);
    drop(blocker);
    fixture.close().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL; compressed retained keys stay accounted and supported"]
async fn crate_row_pipeline_staging_long_compressible_versions_use_exclusive_admission() {
    let fixture = RowFixture::new(1, 0, 0).await;
    let (old, new) = staging_fixture(&fixture, 0, 0).await;
    fixture.transaction_log("devres_crate_staging").await;
    for ordinal in 0..3 {
        // PostgreSQL can retain these compressed indexed strings. Migration must
        // account them before materializing key/payload windows, not reject them
        // using a newly invented key-length policy.
        let version = format!("0.{}.{ordinal}", "1".repeat(32 * 1024));
        let record = json!({"name":"fixture","vers":version,"synthetic":true});
        let key = format!("fixture@{version}");
        let seal = payload_integrity::digest(
            "devres_crate_staging",
            &old,
            &key,
            &payload_integrity::crate_staging_payload(&fixture.pairs[0].0, &record),
        )
        .unwrap();
        sqlx::query("INSERT INTO devres_crate_staging(inventory,name,version,metadata_capture,record,record_integrity) VALUES($1,'fixture',$2,$3,$4,$5)")
            .bind(&old).bind(version).bind(&fixture.pairs[0].0).bind(Json(record)).bind(seal)
            .execute(&fixture.pool).await.unwrap();
    }
    let source:Vec<String>=sqlx::query_scalar("SELECT name||'@'||version FROM devres_crate_staging WHERE inventory=$1 ORDER BY name||'@'||version")
        .bind(&old).fetch_all(&fixture.pool).await.unwrap();
    let execution = RowFixture::execution(8, 1024);
    fixture
        .store
        .migrate_staging_rows(
            &old,
            &new,
            &fixture.maps,
            &CancellationToken::new(),
            &execution,
        )
        .await
        .unwrap();
    let retained:Vec<String>=sqlx::query_scalar("SELECT name||'@'||version FROM devres_crate_staging WHERE inventory=$1 ORDER BY name||'@'||version")
        .bind(&new).fetch_all(&fixture.pool).await.unwrap();
    assert_eq!(source, retained);
    assert_eq!(fixture.batch_sizes().await, vec![1, 1, 1]);
    let snapshot = execution.snapshot();
    assert_eq!(snapshot.graph_high_water, 1);
    assert!(snapshot.graph_memory_high_water > 1024);
    assert_eq!(snapshot.graph_memory_bytes, 0);
    fixture.close().await;
}
