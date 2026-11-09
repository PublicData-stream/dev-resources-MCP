use super::*;
use devres_application::{Fetcher, Retrieval};
use devres_domain::{FetchRequest, FetchResponse, Validators};

struct OfflineOnly;
#[async_trait::async_trait]
impl Fetcher for OfflineOnly {
    async fn fetch(&self, _: &FetchRequest, _: Option<&Validators>) -> Result<FetchResponse> {
        Err(Error::integrity(
            "Offline migration fixture attempted acquisition.",
        ))
    }
}

async fn prepare(
    store: &Arc<PgBlobStore>,
    original: &Snapshot,
    reference: &Value,
    old: &str,
    source_seal: &str,
    maps: &crate::MigrationMap,
    execution: &crate::MigrationExecution,
) -> Result<Snapshot> {
    let token = CancellationToken::new();
    let adoption = store
        .crate_snapshot_adoption(maps, &token, execution)
        .await?;
    let prepared = execution
        .graph_run(256 * 1024 * 1024, &token, |token| async move {
            store
                .prepare_crate_snapshot(
                    SnapshotSource {
                        legacy: old,
                        integrity: source_seal,
                        adoption: &adoption,
                    },
                    original.clone(),
                    reference.clone(),
                    maps,
                    &token,
                    execution,
                )
                .await
        })
        .await?;
    Ok(prepared.into_inner_after_commit())
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL; real crate index and legacy partial checkpoint resume"]
async fn crate_snapshot_preparation_receipts_resume_before_and_after_publication() {
    let _index_gate = crate::crates_io::index::TEST_BUILD.lock().await;
    let base = std::env::var("DEVRES_TEST_DATABASE_URL").expect("disposable database");
    let admin = sqlx_postgres::PgPool::connect(&base).await.unwrap();
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let database = format!("devres_crate_resume_{suffix}");
    sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!(
        "CREATE DATABASE {database}"
    )))
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
    let artifact = store
        .save_text(
            "cargo:derived:migration-receipt",
            "https://fixtures.invalid/migration-receipt",
            "public synthetic source",
            json!({"synthetic":true}),
            10,
        )
        .await
        .unwrap();
    let inventory = store.begin_inventory(&"a".repeat(40), 10).await.unwrap();
    store.stage_crate(&inventory.id,"fixture",&[VersionRecord {
        name:"fixture".into(),version:"1.0.0".into(),metadata_capture:artifact.id.clone(),
        record:json!({"name":"fixture","vers":"1.0.0","cksum":"0".repeat(64),"deps":[],"yanked":false}),metadata_status:None,
    }],"fixture").await.unwrap();
    store
        .commit_inventory(&inventory.id, &artifact.id)
        .await
        .unwrap();
    let mut original = store.prepare_snapshot(&inventory.id, 20).await.unwrap();
    let retrieval = Arc::new(Retrieval::new(store.clone(), Arc::new(OfflineOnly)));
    let reference = crate::crates_io::index::build(
        store.clone(),
        retrieval,
        root.path().to_owned(),
        original.clone(),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    let second_reference = crate::crates_io::index::build(
        store.clone(),
        Arc::new(Retrieval::new(store.clone(), Arc::new(OfflineOnly))),
        root.path().to_owned(),
        original.clone(),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_ne!(
        reference["path"], second_reference["path"],
        "equivalent retained generations remain physically distinct"
    );
    let old = crate::integrity::legacy_hash(b"retained crate snapshot before alias sealing");
    original.id = old.clone();
    let source_seal = crate::integrity::canonical_hash(
        &json!({"source":old,"snapshot":original,"index":reference}),
    )
    .unwrap();
    let maps = crate::MigrationMap::new();
    let execution = crate::MigrationExecution::new(
        crate::MigrationExecutionOptions::new(2, 1024 * 1024).unwrap(),
    )
    .unwrap();
    let first = prepare(
        &store,
        &original,
        &reference,
        &old,
        &source_seal,
        &maps,
        &execution,
    )
    .await
    .unwrap();
    let expected = serde_json::to_value(&first).unwrap();
    let checkpoint = format!("snapshot-prepared:{old}");
    let pool = sqlx_postgres::PgPool::connect(url.as_str()).await.unwrap();
    assert_eq!(
        sqlx_core::query_scalar::query_scalar::<_, i64>(
            "SELECT count(*) FROM devres_crate_snapshots"
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        0,
        "preparation receipt precedes snapshot publication"
    );
    sqlx_core::query::query("UPDATE devres_integrity_control SET active=false WHERE singleton")
        .execute(&pool)
        .await
        .unwrap();
    drop(store);
    let store = Arc::new(
        PgBlobStore::connect_for_migration(url.as_str(), root.path())
            .await
            .unwrap(),
    );
    let resumed = prepare(
        &store,
        &original,
        &reference,
        &old,
        &source_seal,
        &maps,
        &execution,
    )
    .await
    .unwrap();
    assert_eq!(serde_json::to_value(&resumed).unwrap(), expected);
    let mut fresh_adoption = store
        .crate_snapshot_adoption(&maps, &CancellationToken::new(), &execution)
        .await
        .unwrap();
    assert_eq!(
        fresh_adoption.cutoff, 0,
        "fresh replay freezes its empty candidate set before publication"
    );
    let published = store.commit_prepared_crate_snapshot(resumed).await.unwrap();
    let before:(String,i64,i64)=sqlx_core::query_as::query_as("SELECT ctid::text,sequence,(SELECT last_value FROM devres_crate_snapshots_sequence_seq) FROM devres_crate_snapshots WHERE id=$1").bind(&published.id).fetch_one(&pool).await.unwrap();
    drop(store);
    let store = Arc::new(
        PgBlobStore::connect_for_migration(url.as_str(), root.path())
            .await
            .unwrap(),
    );
    let resumed = prepare(
        &store,
        &original,
        &reference,
        &old,
        &source_seal,
        &maps,
        &execution,
    )
    .await
    .unwrap();
    assert_eq!(
        store
            .commit_prepared_crate_snapshot(resumed)
            .await
            .unwrap()
            .id,
        published.id
    );
    let after:(String,i64,i64)=sqlx_core::query_as::query_as("SELECT ctid::text,sequence,(SELECT last_value FROM devres_crate_snapshots_sequence_seq) FROM devres_crate_snapshots WHERE id=$1").bind(&published.id).fetch_one(&pool).await.unwrap();
    assert_eq!(
        before, after,
        "replay neither rewrites a committed tuple nor consumes a new sequence"
    );
    // Receiptless canonical rows are the interruption shape of the old binary.
    sqlx_core::query::query(
        "DELETE FROM devres_integrity_staged_state WHERE provider='crate' AND key=$1",
    )
    .bind(&checkpoint)
    .execute(&pool)
    .await
    .unwrap();
    let adopted = prepare(
        &store,
        &original,
        &reference,
        &old,
        &source_seal,
        &maps,
        &execution,
    )
    .await
    .unwrap();
    assert_eq!(adopted.id, published.id);
    assert_eq!(adopted.index_manifest, published.index_manifest);
    assert_eq!(
        sqlx_core::query_scalar::query_scalar::<_, i64>(
            "SELECT count(*) FROM devres_crate_snapshots"
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );
    assert_eq!(
        prepare(
            &store,
            &original,
            &reference,
            &old,
            &crate::integrity::hash(b"changed source"),
            &maps,
            &execution
        )
        .await
        .unwrap_err()
        .code,
        "integrity"
    );
    // A second original generation has the same metadata and postings. A fresh
    // replay must not reuse the first target just published in an earlier window.
    let second_old = crate::integrity::legacy_hash(b"second retained equivalent crate generation");
    let mut second_original = original.clone();
    second_original.id = second_old.clone();
    let second_seal = crate::integrity::canonical_hash(
        &json!({"source":second_old,"snapshot":second_original,"index":second_reference}),
    )
    .unwrap();
    let token = CancellationToken::new();
    let second_prepared = {
        let store = &store;
        let original = &second_original;
        let reference = &second_reference;
        let old = &second_old;
        let seal = &second_seal;
        let adoption = &fresh_adoption;
        let maps = &maps;
        let execution = &execution;
        execution
            .graph_run(256 * 1024 * 1024, &token, |token| async move {
                store
                    .prepare_crate_snapshot(
                        SnapshotSource {
                            legacy: old,
                            integrity: seal,
                            adoption,
                        },
                        original.clone(),
                        reference.clone(),
                        maps,
                        &token,
                        execution,
                    )
                    .await
            })
            .await
            .unwrap()
            .into_inner_after_commit()
    };
    let second_published = store
        .commit_prepared_crate_snapshot(second_prepared)
        .await
        .unwrap();
    fresh_adoption
        .claim(&second_old, &second_published.id)
        .unwrap();
    assert_ne!(
        published.id, second_published.id,
        "distinct legacy occurrences must not merge across fresh replay windows"
    );
    assert_eq!(
        snapshot_base(&published).unwrap(),
        snapshot_base(&second_published).unwrap()
    );
    let before_pair: Vec<(String, String, i64)> = sqlx_core::query_as::query_as(
        "SELECT id,ctid::text,sequence FROM devres_crate_snapshots ORDER BY sequence",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(before_pair.len(), 2);
    // Reproduce an older binary that committed both generations before writing
    // either legacy ownership receipt. Adoption follows retained legacy order.
    sqlx_core::query::query("DELETE FROM devres_integrity_staged_state WHERE provider='crate' AND key LIKE 'snapshot-prepared:%'")
        .execute(&pool).await.unwrap();
    let mut adoption = store
        .crate_snapshot_adoption(&maps, &token, &execution)
        .await
        .unwrap();
    assert!(adoption.cutoff > 0);
    assert_eq!(adoption.owners.len(), 0);
    let mut aliased = maps.scratch().unwrap();
    let mut aliases = crate::migration_map::MigrationAliases::new(&mut aliased).unwrap();
    for (old, seal, source, retained, expected) in [
        (&old, &source_seal, &original, &reference, &published),
        (
            &second_old,
            &second_seal,
            &second_original,
            &second_reference,
            &second_published,
        ),
    ] {
        let prepared = {
            let store = &store;
            let maps = &maps;
            let execution = &execution;
            let adoption = &adoption;
            execution
                .graph_run(256 * 1024 * 1024, &token, |token| async move {
                    store
                        .prepare_crate_snapshot(
                            SnapshotSource {
                                legacy: old,
                                integrity: seal,
                                adoption,
                            },
                            source.clone(),
                            retained.clone(),
                            maps,
                            &token,
                            execution,
                        )
                        .await
                })
                .await
                .unwrap()
                .into_inner_after_commit()
        };
        adoption
            .claim(old, &snapshot_identity(&prepared).unwrap())
            .unwrap();
        let committed = store
            .commit_prepared_crate_snapshot(prepared)
            .await
            .unwrap();
        assert_eq!(committed.id, expected.id);
        id_alias(&mut aliased, &mut aliases, "snapshots", old, &committed.id).unwrap();
    }
    assert_eq!(aliases.len(), 2);
    assert_ne!(
        aliased.get(&format!("crate:snapshots:{old}")),
        aliased.get(&format!("crate:snapshots:{second_old}"))
    );
    let after_pair: Vec<(String, String, i64)> = sqlx_core::query_as::query_as(
        "SELECT id,ctid::text,sequence FROM devres_crate_snapshots ORDER BY sequence",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        before_pair, after_pair,
        "ordered adoption preserves both committed tuples and their chronology"
    );
    let ownership = store
        .crate_snapshot_adoption(&maps, &token, &execution)
        .await
        .unwrap();
    assert!(!ownership.permits(&second_old, &published.id));
    assert!(!ownership.permits(&old, &second_published.id));
    use std::io::Write;
    let manifest = root
        .path()
        .join(published.index_manifest["path"].as_str().unwrap())
        .join("manifest.json");
    std::fs::OpenOptions::new()
        .append(true)
        .open(manifest)
        .unwrap()
        .write_all(b"corrupt")
        .unwrap();
    assert_eq!(
        prepare(
            &store,
            &original,
            &reference,
            &old,
            &source_seal,
            &maps,
            &execution
        )
        .await
        .unwrap_err()
        .code,
        "integrity",
        "receipt reuse must reverify every canonical index byte"
    );
    assert_eq!(execution.snapshot().active, 0);
    assert_eq!(execution.snapshot().graph_active, 0);
    assert_eq!(execution.snapshot().graph_memory_bytes, 0);
    drop(store);
    pool.close().await;
    sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!(
        "DROP DATABASE {database} WITH (FORCE)"
    )))
    .execute(&admin)
    .await
    .unwrap();
    admin.close().await;
}

#[path = "storage_migration_row_tests.rs"]
mod row_pipeline;
