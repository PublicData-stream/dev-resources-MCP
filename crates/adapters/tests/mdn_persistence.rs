//! Real PostgreSQL MDN evidence checks, confined to a newly created fixture database.
use devres_adapters::PgBlobStore;
use devres_application::mdn::{MdnStore, MdnWrite, Snapshot, View};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn snapshot(repository: &str, revision: &str, index: Value) -> Snapshot {
    Snapshot {
        id: digest(format!("{repository}:{revision}").as_bytes()),
        repository: repository.into(),
        revision: revision.into(),
        tree: "c".repeat(40),
        parents: Vec::new(),
        committed_at: 1,
        inventory: "d".repeat(64),
        processor_version: 1,
        index,
        coverage: json!({"accounted":true,"members":0,"projection_gaps":0}),
    }
}
fn view(content: &Snapshot, compatibility: &Snapshot, observed_at: i64) -> View {
    let content_observation = format!("content-observation:{}", content.revision);
    let compatibility_observation = format!("compatibility-observation:{}", compatibility.revision);
    let id = digest(
        &serde_json::to_vec(&(
            &content.id,
            &compatibility.id,
            &content_observation,
            &compatibility_observation,
            observed_at,
        ))
        .expect("view identity"),
    );
    View {
        id,
        content: content.id.clone(),
        compatibility: compatibility.id.clone(),
        content_observation,
        compatibility_observation,
        validated_at: observed_at,
    }
}
async fn publish_evidence(
    store: &PgBlobStore,
    snapshot: &Snapshot,
    observation: &str,
    observed_at: i64,
) {
    store
        .mdn_put(
            "snapshots",
            &snapshot.id,
            &serde_json::to_value(snapshot).expect("snapshot"),
        )
        .await
        .expect("retain snapshot");
    store.mdn_put("observations",observation,&json!({"repo":snapshot.repository,"main_revision":snapshot.revision,"observed_at":observed_at})).await.expect("retain observation");
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL; run scripts/test-postgres.sh"]
async fn mdn_owner_fenced_immutable_pair_budget_and_restart() {
    let base =
        std::env::var("DEVRES_TEST_DATABASE_URL").expect("explicit disposable database required");
    let admin = sqlx::PgPool::connect(&base).await.expect("fixture admin");
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let database = format!("devres_mdn_fixture_{}_{}", std::process::id(), suffix);
    // The identifier contains only a fixed ASCII prefix and locally generated decimal integers.
    assert!(
        database
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    );
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {database}")))
        .execute(&admin)
        .await
        .expect("create owned fixture database");
    let mut database_url = url::Url::parse(&base).expect("database URL");
    database_url.set_path(&format!("/{database}"));
    let root = tempfile::tempdir().expect("owned fixture blobs");
    let store = PgBlobStore::connect(database_url.as_str(), root.path())
        .await
        .expect("schema migration");
    let database_pool = sqlx::PgPool::connect(database_url.as_str())
        .await
        .expect("fixture inspection");
    assert_eq!(
        sqlx::query_scalar::<_, i32>("SELECT version FROM devres_schema WHERE singleton")
            .fetch_one(&database_pool)
            .await
            .expect("schema version"),
        5
    );
    assert_eq!(
        PgBlobStore::connect(database_url.as_str(), root.path())
            .await
            .err()
            .expect("second owner rejected")
            .code,
        "capacity"
    );
    let original = json!({"public":"retained MDN source"});
    let numeric = json!({"scientific":1e18});
    let numeric_sequence = store
        .mdn_put("numeric-fixtures", "numeric-replay", &numeric)
        .await
        .expect("numeric evidence");
    assert_eq!(
        store
            .mdn_put("numeric-fixtures", "numeric-replay", &numeric)
            .await
            .expect("JSONB numeric replay"),
        numeric_sequence
    );
    assert_eq!(
        store
            .mdn_put(
                "numeric-fixtures",
                "numeric-replay",
                &json!({"scientific":1e19})
            )
            .await
            .expect_err("different numeric evidence")
            .code,
        "integrity"
    );
    let sequence = store
        .mdn_put("fixtures", "same", &original)
        .await
        .expect("first immutable row");
    assert_eq!(
        store
            .mdn_put("fixtures", "same", &original)
            .await
            .expect("idempotent immutable row"),
        sequence
    );
    assert_eq!(
        store
            .mdn_put("fixtures", "same", &json!({"public":"replacement"}))
            .await
            .expect_err("collision")
            .code,
        "integrity"
    );
    assert_eq!(
        store
            .mdn_get("fixtures", "same")
            .await
            .expect("read after collision")
            .expect("retained")
            .data,
        original
    );
    let rejected_batch = vec![
        MdnWrite {
            kind: "batch-fixtures".into(),
            key: "must-rollback".into(),
            data: json!({"new":true}),
        },
        MdnWrite {
            kind: "fixtures".into(),
            key: "same".into(),
            data: json!({"public":"collision in batch"}),
        },
    ];
    assert_eq!(
        store
            .mdn_put_many(&rejected_batch)
            .await
            .expect_err("batch collision")
            .code,
        "integrity"
    );
    assert!(
        store
            .mdn_get("batch-fixtures", "must-rollback")
            .await
            .expect("rollback read")
            .is_none(),
        "collision must roll back every new batch row"
    );
    let numeric_batch = vec![
        MdnWrite {
            kind: "batch-fixtures".into(),
            key: "numeric".into(),
            data: json!({"number":1e18}),
        },
        MdnWrite {
            kind: "fixtures".into(),
            key: "same".into(),
            data: original.clone(),
        },
    ];
    store
        .mdn_put_many(&numeric_batch)
        .await
        .expect("mixed existing and new batch");
    store
        .mdn_put_many(&numeric_batch)
        .await
        .expect("idempotent SQL JSONB numeric comparison");
    let mut conflicting_duplicates = numeric_batch.clone();
    conflicting_duplicates.push(MdnWrite {
        kind: "batch-fixtures".into(),
        key: "numeric".into(),
        data: json!({"number":42}),
    });
    assert_eq!(
        store
            .mdn_put_many(&conflicting_duplicates)
            .await
            .expect_err("conflicting repeated key")
            .code,
        "integrity"
    );
    assert_eq!(
        store
            .mdn_get("batch-fixtures", "numeric")
            .await
            .expect("unchanged numeric")
            .expect("row")
            .data["number"]
            .as_f64(),
        Some(1e18)
    );
    assert_eq!(
        store
            .mdn_put_many(&vec![numeric_batch[0].clone(); 1001])
            .await
            .expect_err("batch row bound")
            .code,
        "capacity"
    );
    let oversized_batch = vec![
        MdnWrite {
            kind: "batch-fixtures".into(),
            key: "large-a".into(),
            data: json!({"body":"x".repeat(9*1024*1024)}),
        },
        MdnWrite {
            kind: "batch-fixtures".into(),
            key: "large-b".into(),
            data: json!({"body":"x".repeat(9*1024*1024)}),
        },
    ];
    assert_eq!(
        store
            .mdn_put_many(&oversized_batch)
            .await
            .expect_err("aggregate write budget")
            .code,
        "capacity"
    );
    drop(oversized_batch);
    assert!(
        store
            .mdn_get("batch-fixtures", "large-a")
            .await
            .expect("write rejected before publication")
            .is_none()
    );
    let cutoff = store.mdn_cutoff().await.expect("publication cutoff");
    store
        .mdn_put("fixtures", "later", &json!({"later":true}))
        .await
        .expect("later row");
    assert_eq!(
        store
            .mdn_rows("fixtures", 0, 100, Some(cutoff))
            .await
            .expect("frozen page")
            .len(),
        1
    );
    let content = snapshot(
        "content",
        &"a".repeat(40),
        json!({"manifest":"synthetic-content-index"}),
    );
    let compatibility = snapshot(
        "compat",
        &"b".repeat(40),
        json!({"manifest":"synthetic-compatibility-index"}),
    );
    let current = view(&content, &compatibility, 1_700_000_000);
    publish_evidence(
        &store,
        &content,
        &current.content_observation,
        current.validated_at,
    )
    .await;
    publish_evidence(
        &store,
        &compatibility,
        &current.compatibility_observation,
        current.validated_at,
    )
    .await;
    store
        .mdn_publish_view(&current)
        .await
        .expect("atomic default pair");
    assert_eq!(
        store.mdn_state("default-view").await.expect("default"),
        Some(json!(current.id))
    );
    let broken = snapshot("compat", &"e".repeat(40), Value::Null);
    let rejected = view(&content, &broken, current.validated_at);
    publish_evidence(
        &store,
        &broken,
        &rejected.compatibility_observation,
        current.validated_at,
    )
    .await;
    assert_eq!(
        store
            .mdn_publish_view(&rejected)
            .await
            .expect_err("unpublished index cannot activate")
            .code,
        "integrity"
    );
    assert_eq!(
        store
            .mdn_state("default-view")
            .await
            .expect("prior default"),
        Some(json!(current.id))
    );
    assert!(
        store
            .mdn_get("views", &rejected.id)
            .await
            .expect("rejected view")
            .is_none()
    );
    let incomplete = Snapshot {
        coverage: json!({"accounted":false}),
        ..snapshot("compat", &"f".repeat(40), json!({}))
    };
    let rejected_accounting = view(&content, &incomplete, current.validated_at);
    publish_evidence(
        &store,
        &incomplete,
        &rejected_accounting.compatibility_observation,
        current.validated_at,
    )
    .await;
    assert_eq!(
        store
            .mdn_publish_view(&rejected_accounting)
            .await
            .expect_err("unaccounted inventory cannot activate")
            .code,
        "integrity"
    );
    let mut synthetic = snapshot(
        "content",
        &"9".repeat(40),
        json!({"manifest":"synthetic-only"}),
    );
    synthetic.coverage["synthetic"] = json!(true);
    let rejected_synthetic = view(&synthetic, &compatibility, current.validated_at);
    publish_evidence(
        &store,
        &synthetic,
        &rejected_synthetic.content_observation,
        current.validated_at,
    )
    .await;
    assert_eq!(
        store
            .mdn_publish_view(&rejected_synthetic)
            .await
            .expect_err("synthetic data cannot become the production default")
            .code,
        "integrity"
    );
    assert_eq!(
        store
            .mdn_state("default-view")
            .await
            .expect("unchanged default"),
        Some(json!(current.id))
    );
    // Five individually valid rows exceed the aggregate 64-MiB read budget.
    let large = json!({"body":"x".repeat(14*1024*1024)});
    let mut keys = Vec::new();
    for index in 0..5 {
        let key = format!("large-{index}");
        store
            .mdn_put("budget-fixtures", &key, &large)
            .await
            .expect("bounded row");
        keys.push(key);
    }
    assert_eq!(
        store
            .mdn_get_many("budget-fixtures", &keys)
            .await
            .expect_err("aggregate batch budget")
            .code,
        "capacity"
    );
    assert_eq!(
        store
            .mdn_rows("budget-fixtures", 0, 5, None)
            .await
            .expect_err("aggregate page budget")
            .code,
        "capacity"
    );
    assert_eq!(
        store
            .mdn_get_many("budget-fixtures", &keys[..1])
            .await
            .expect("single bounded row")
            .len(),
        1
    );
    assert_eq!(
        store
            .mdn_get_many("budget-fixtures", &vec!["large-0".into(); 1001])
            .await
            .expect_err("key-count budget")
            .code,
        "capacity"
    );
    assert_eq!(
        store
            .mdn_put(
                "budget-fixtures",
                "oversized",
                &json!({"body":"x".repeat(16*1024*1024)})
            )
            .await
            .expect_err("row budget")
            .code,
        "capacity"
    );
    drop(large);
    // Kill only this fixture database's dedicated owner to verify fail-closed reads.
    let owner:i32=sqlx::query_scalar("SELECT pid FROM pg_locks WHERE locktype='advisory' AND classid=1835365490 AND objid=1 AND objsubid=2 AND granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database())").fetch_one(&database_pool).await.expect("owned fixture lock");
    sqlx::query("SELECT pg_terminate_backend($1)")
        .bind(owner)
        .execute(&database_pool)
        .await
        .expect("terminate owned fixture owner");
    assert_eq!(
        store
            .mdn_get("fixtures", "same")
            .await
            .expect_err("lost owner read")
            .code,
        "unavailable"
    );
    assert!(
        store
            .mdn_set_state("after-owner-loss", &json!(true))
            .await
            .is_err()
    );
    drop(store);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let restarted = PgBlobStore::connect(database_url.as_str(), root.path())
        .await
        .expect("restart with retained evidence");
    assert_eq!(
        restarted
            .mdn_get("fixtures", "same")
            .await
            .expect("history after restart")
            .expect("row")
            .data,
        original
    );
    assert_eq!(
        restarted
            .mdn_state("default-view")
            .await
            .expect("default pair after restart"),
        Some(json!(current.id))
    );
    assert!(
        restarted
            .mdn_get("views", &rejected.id)
            .await
            .expect("no half-publication after restart")
            .is_none()
    );
    drop(restarted);
    database_pool.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP DATABASE {database} WITH (FORCE)"
    )))
    .execute(&admin)
    .await
    .expect("remove owned fixture database");
    admin.close().await;
}
