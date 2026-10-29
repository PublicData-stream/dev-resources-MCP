//! Real PostgreSQL WHATWG checks confined to a newly created disposable fixture database.
use devres_adapters::PgBlobStore;
use devres_application::whatwg::{Snapshot, View, WhatwgStore, Write};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

fn digest(value: &impl serde::Serialize) -> String {
    devres_adapters::integrity::hash(&serde_json::to_vec(value).expect("fixture identity"))
}
fn view(catalog: &str, snapshot: &Snapshot, validated_at: i64) -> View {
    let snapshots = BTreeMap::from([(snapshot.standard.clone(), snapshot.id.clone())]);
    let validations = BTreeMap::from([(snapshot.standard.clone(), validated_at)]);
    let index = snapshot.index.clone();
    let id = digest(&(catalog, &snapshots, &index, &validations, validated_at));
    View {
        id,
        catalog: catalog.into(),
        snapshots,
        index,
        validations,
        validated_at,
    }
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL; run scripts/test-postgres.sh"]
async fn whatwg_owner_fenced_atomic_evidence_default_and_restart() {
    let base =
        std::env::var("DEVRES_TEST_DATABASE_URL").expect("explicit disposable PostgreSQL required");
    let admin = sqlx::PgPool::connect(&base).await.expect("fixture admin");
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let database = format!("devres_whatwg_fixture_{}_{suffix}", std::process::id());
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
    let root = tempfile::tempdir().expect("owned fixture blobs");
    let store = PgBlobStore::connect(url.as_str(), root.path())
        .await
        .expect("current schema migration");
    let inspection = sqlx::PgPool::connect(url.as_str())
        .await
        .expect("fixture inspection");
    assert_eq!(
        sqlx::query_scalar::<_, i32>("SELECT version FROM devres_schema WHERE singleton")
            .fetch_one(&inspection)
            .await
            .expect("schema"),
        10
    );
    assert_eq!(
        PgBlobStore::connect(url.as_str(), root.path())
            .await
            .err()
            .expect("second owner denied")
            .code,
        "capacity"
    );
    let original = json!({"public":"retained synthetic WHATWG source","synthetic":true});
    let sequence = store
        .whatwg_put("fixtures", "same", &original)
        .await
        .expect("first evidence");
    assert_eq!(
        store
            .whatwg_put("fixtures", "same", &original)
            .await
            .expect("immutable replay"),
        sequence
    );
    assert_eq!(
        store
            .whatwg_put("fixtures", "same", &json!({"replacement":true}))
            .await
            .expect_err("collision")
            .code,
        "integrity"
    );
    let batch = [
        Write {
            kind: "fixtures".into(),
            key: "must-rollback".into(),
            data: json!({"new":true}),
        },
        Write {
            kind: "fixtures".into(),
            key: "same".into(),
            data: json!({"replacement":true}),
        },
    ];
    assert_eq!(
        store
            .whatwg_put_many(&batch)
            .await
            .expect_err("atomic batch collision")
            .code,
        "integrity"
    );
    assert!(
        store
            .whatwg_get("fixtures", "must-rollback")
            .await
            .expect("rollback read")
            .is_none()
    );
    assert_eq!(
        store
            .whatwg_get("fixtures", "same")
            .await
            .expect("retained read")
            .expect("row")
            .data,
        original
    );
    let cutoff = store.whatwg_cutoff().await.expect("frozen cutoff");
    store
        .whatwg_put("fixtures", "later", &json!({"later":true}))
        .await
        .expect("later source");
    assert_eq!(
        store
            .whatwg_rows("fixtures", 0, 100, Some(cutoff))
            .await
            .expect("stable page")
            .len(),
        1
    );
    let numeric = [Write {
        kind: "fixtures".into(),
        key: "numeric".into(),
        data: json!({"number":1e18}),
    }];
    store
        .whatwg_put_many(&numeric)
        .await
        .expect("numeric source");
    store
        .whatwg_put_many(&numeric)
        .await
        .expect("JSONB numeric replay");
    let mut duplicates = numeric.to_vec();
    duplicates.push(Write {
        kind: "fixtures".into(),
        key: "numeric".into(),
        data: json!({"number":42}),
    });
    assert_eq!(
        store
            .whatwg_put_many(&duplicates)
            .await
            .expect_err("conflicting duplicate")
            .code,
        "integrity"
    );
    assert_eq!(
        store
            .whatwg_put_many(&vec![numeric[0].clone(); 1001])
            .await
            .expect_err("row bound")
            .code,
        "capacity"
    );

    // Structurally valid online evidence is simulated only inside this fixture DB.
    let observed_at = 1_700_000_000;
    let catalog_id = digest(&"WHATWG fixture catalog");
    store.whatwg_put("catalogs",&catalog_id,&json!({"id":catalog_id,"observed_at":observed_at,"standards":[{"id":"dom","title":"DOM fixture","url":"https://dom.spec.whatwg.org/","repository":"whatwg/dom","metadata":{}}],"gaps":[]})).await.expect("catalog evidence");
    let publication_id = digest(&"WHATWG fixture publication");
    store.whatwg_put("publications",&publication_id,&json!({"id":publication_id,"standard":"dom","url":{"url":"https://dom.spec.whatwg.org/","host":"dom.spec.whatwg.org"},"observed_at":observed_at,"status":200,"artifact":{"body_hash":"e".repeat(64),"bytes":0,"relative_path":"synthetic-publication"},"links":[],"gaps":[],"repositories":["whatwg/dom"]})).await.expect("publication observation");
    let inventory = devres_adapters::whatwg::inventory::empty(&store)
        .await
        .expect("empty fixture inventory");
    let snapshot = Snapshot {
        id: digest(&"WHATWG fixture snapshot"),
        standard: "dom".into(),
        repository: "https://dom.spec.whatwg.org/".into(),
        revision: publication_id.clone(),
        tree: "e".repeat(64),
        parents: vec![],
        committed_at: observed_at,
        inventory,
        processor_version: 1,
        index: json!({"manifest":"synthetic-index"}),
        coverage: json!({"accounted":true,"usable":true,"members":1,"publication":publication_id,"projection_gaps":0}),
        source_url: "https://dom.spec.whatwg.org/".into(),
        representation: "html".into(),
        validated_at: observed_at,
    };
    store
        .whatwg_put("snapshots", &snapshot.id, &json!(snapshot))
        .await
        .expect("snapshot evidence");
    let expected_statistics =
        json!({"snapshots":1,"publications":1,"projection_gaps":0,"index_gaps":0});
    assert_eq!(
        store
            .whatwg_statistics()
            .await
            .expect("retained statistics"),
        expected_statistics
    );
    store
        .whatwg_put("snapshots", &snapshot.id, &json!(snapshot))
        .await
        .expect("snapshot replay");
    assert_eq!(
        store
            .whatwg_statistics()
            .await
            .expect("replay does not double count"),
        expected_statistics
    );
    let rollback_snapshot = Snapshot {
        id: digest(&"rollback statistics fixture"),
        ..snapshot.clone()
    };
    let rejected_statistics = [
        Write {
            kind: "snapshots".into(),
            key: rollback_snapshot.id.clone(),
            data: json!(rollback_snapshot),
        },
        Write {
            kind: "fixtures".into(),
            key: "same".into(),
            data: json!({"collision":true}),
        },
    ];
    assert_eq!(
        store
            .whatwg_put_many(&rejected_statistics)
            .await
            .expect_err("statistics transaction rollback")
            .code,
        "integrity"
    );
    assert!(
        store
            .whatwg_get("snapshots", &rollback_snapshot.id)
            .await
            .expect("snapshot transaction rollback")
            .is_none()
    );
    assert_eq!(
        store
            .whatwg_statistics()
            .await
            .expect("rolled back counters"),
        expected_statistics
    );
    let current = view(&catalog_id, &snapshot, observed_at);
    store
        .whatwg_publish_view(&current)
        .await
        .expect("atomic default publication");
    assert_eq!(
        store.whatwg_state("default").await.expect("default"),
        Some(json!(current))
    );
    let missing_snapshot = Snapshot {
        id: digest(&"missing WHATWG snapshot"),
        ..snapshot.clone()
    };
    let missing = view(&catalog_id, &missing_snapshot, observed_at);
    assert_eq!(
        store
            .whatwg_publish_view(&missing)
            .await
            .expect_err("missing snapshot rejected")
            .code,
        "integrity"
    );
    let missing_catalog = view(&digest(&"missing catalog"), &snapshot, observed_at);
    assert_eq!(
        store
            .whatwg_publish_view(&missing_catalog)
            .await
            .expect_err("missing catalog rejected")
            .code,
        "integrity"
    );
    let broken_snapshot = Snapshot {
        id: digest(&"broken WHATWG snapshot"),
        index: Value::Null,
        ..snapshot.clone()
    };
    store
        .whatwg_put("snapshots", &broken_snapshot.id, &json!(broken_snapshot))
        .await
        .expect("raw broken evidence retained");
    let broken = view(&catalog_id, &broken_snapshot, observed_at);
    assert_eq!(
        store
            .whatwg_publish_view(&broken)
            .await
            .expect_err("missing index rejected")
            .code,
        "integrity"
    );
    assert_eq!(
        store
            .whatwg_state("default")
            .await
            .expect("prior default survives"),
        Some(json!(current))
    );
    for rejected in [&missing, &missing_catalog, &broken] {
        assert!(
            store
                .whatwg_get("views", &rejected.id)
                .await
                .expect("rejected view not published")
                .is_none()
        );
    }

    for (label, mut invalid) in [
        ("synthetic", snapshot.clone()),
        ("wrong-body", snapshot.clone()),
    ] {
        invalid.id = digest(&label);
        if label == "synthetic" {
            invalid.coverage["synthetic"] = json!(true);
        } else {
            invalid.tree = "f".repeat(64);
        }
        store
            .whatwg_put("snapshots", &invalid.id, &json!(invalid))
            .await
            .expect("retain rejected fixture evidence");
        let rejected = view(&catalog_id, &invalid, observed_at);
        assert_eq!(
            store
                .whatwg_publish_view(&rejected)
                .await
                .expect_err("synthetic or mismatched publication rejected")
                .code,
            "integrity"
        );
        assert!(
            store
                .whatwg_get("views", &rejected.id)
                .await
                .expect("rejected evidence cannot activate")
                .is_none()
        );
    }
    assert_eq!(
        store
            .whatwg_state("default")
            .await
            .expect("default survives invalid provenance"),
        Some(json!(current))
    );

    let mut gap_snapshot = Snapshot {
        id: digest(&"counted snapshot gap fixture"),
        ..snapshot.clone()
    };
    gap_snapshot.coverage["projection_gaps"] = json!(3);
    gap_snapshot.coverage["index_gaps"] = json!(2);
    store
        .whatwg_put("snapshots", &gap_snapshot.id, &json!(gap_snapshot))
        .await
        .expect("counted retained gaps");
    let final_statistics = store
        .whatwg_statistics()
        .await
        .expect("retained snapshot gap statistics");
    assert_eq!(
        final_statistics,
        json!({"snapshots":5,"publications":1,"projection_gaps":3,"index_gaps":2})
    );

    // Terminate only the fixture database's own dedicated ownership session.
    let owner:i32=sqlx::query_scalar("SELECT pid FROM pg_locks WHERE locktype='advisory' AND classid=1835365490 AND objid=1 AND objsubid=2 AND granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database())").fetch_one(&inspection).await.expect("owned lock");
    let terminated: bool = sqlx::query_scalar("SELECT pg_terminate_backend($1,5000)")
        .bind(owner)
        .fetch_one(&inspection)
        .await
        .expect("stop own fixture owner");
    assert!(
        terminated,
        "owned fixture backend must terminate before testing lost ownership"
    );
    assert_eq!(
        store
            .whatwg_get("fixtures", "same")
            .await
            .expect_err("lost-owner read denied")
            .code,
        "unavailable"
    );
    assert!(
        store
            .whatwg_put("fixtures", "after-loss", &json!(true))
            .await
            .is_err()
    );
    assert!(
        store
            .whatwg_set_state("after-loss", &json!(true))
            .await
            .is_err()
    );
    drop(store);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let restarted = PgBlobStore::connect(url.as_str(), root.path())
        .await
        .expect("restart retained evidence");
    assert_eq!(
        restarted
            .whatwg_get("fixtures", "same")
            .await
            .expect("retained source")
            .expect("row")
            .data,
        original
    );
    assert_eq!(
        restarted
            .whatwg_state("default")
            .await
            .expect("retained default"),
        Some(json!(current))
    );
    assert_eq!(
        restarted
            .whatwg_get("snapshots", &snapshot.id)
            .await
            .expect("retained snapshot")
            .expect("row")
            .data,
        json!(snapshot)
    );
    assert!(
        restarted
            .whatwg_get("views", &broken.id)
            .await
            .expect("failed publication absent after restart")
            .is_none()
    );
    assert_eq!(
        restarted
            .whatwg_statistics()
            .await
            .expect("statistics survive restart"),
        final_statistics
    );
    drop(restarted);
    inspection.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP DATABASE {database} WITH (FORCE)"
    )))
    .execute(&admin)
    .await
    .expect("remove owned fixture DB");
    admin.close().await;
}
