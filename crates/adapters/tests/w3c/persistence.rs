//! Real PostgreSQL W3C checks confined to a newly created disposable fixture database.
use devres_adapters::PgBlobStore;
use devres_application::{
    Store,
    w3c::{Snapshot, View, W3cStore, Write},
    whatwg::WhatwgStore,
};
use devres_domain::{FetchRequest, FetchResponse, Validators};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

fn digest(value: &impl serde::Serialize) -> String {
    hex::encode(Sha256::digest(
        serde_json::to_vec(value).expect("fixture identity"),
    ))
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

/// Structural online observations below are synthetic and confined to the task-owned database.
async fn aggregate_edition_default_regression(
    store: &PgBlobStore,
    base: &Snapshot,
    previous: &View,
) {
    let now = devres_domain::unix_now();
    let older = now - 120;
    let root_url = "https://www.w3.org/TR/dom/";
    let chapter_url = "https://www.w3.org/TR/dom/chapter.html";
    let root_publication = digest(&"aggregate PG root publication");
    let chapter_publication = digest(&"aggregate PG older chapter publication");
    let publication = |id: &str, url: &str, time: i64, report: &str, hash: &str| {
        json!({
            "id":id,"standard":report,"url":{"url":url,"host":url::Url::parse(url).expect("fixture publication URL").host_str().map(str::to_owned).expect("fixture publication host"),"qualification":"https://www.w3.org/TR/"},
            "observed_at":time,"status":200,"artifact":{"body_hash":hash,"bytes":0,"relative_path":"synthetic-aggregate-publication"},
            "license":{"decision":"approved","copyright":"Synthetic edition fixture authors","notice":"Synthetic fixture, not live W3C evidence."},
            "links":[],"repositories":[],"gaps":[],"advertisements":[],"exclusions":[]
        })
    };
    store
        .w3c_put(
            "publications",
            &root_publication,
            &publication(&root_publication, root_url, now, "dom", &"1".repeat(64)),
        )
        .await
        .expect("new canonical observation");
    store
        .w3c_put(
            "publications",
            &chapter_publication,
            &publication(
                &chapter_publication,
                chapter_url,
                older,
                "dom",
                &"2".repeat(64),
            ),
        )
        .await
        .expect("older approved chapter observation");
    let mut canonical = base.clone();
    canonical.id = digest(&"aggregate PG canonical snapshot");
    canonical.source_url = root_url.into();
    canonical.repository = root_url.into();
    canonical.revision = root_publication.clone();
    canonical.tree = "1".repeat(64);
    canonical.validated_at = now;
    canonical.coverage["publication"] = json!(root_publication);
    store
        .w3c_put("snapshots", &canonical.id, &json!(canonical))
        .await
        .expect("fixed canonical root snapshot");
    let catalog = digest(&"aggregate PG catalog");
    store.w3c_put("catalogs",&catalog,&json!({"id":catalog,"observed_at":now,"standards":[{"id":"dom","title":"Synthetic aggregate edition","url":root_url,"repository":"","metadata":{}}],"gaps":[]})).await.expect("aggregate catalog");
    let publications = BTreeMap::from([
        (root_url.to_owned(), root_publication.clone()),
        (chapter_url.to_owned(), chapter_publication.clone()),
    ]);
    let manifest = json!({"version":1,"root_snapshot":canonical.id,"inventory":canonical.inventory,"publications":publications,"missing":[],"validated_at":older});
    let manifest_id = digest(&manifest);
    store
        .w3c_put("editions", &manifest_id, &manifest)
        .await
        .expect("immutable edition dependency manifest");
    let mut aggregate = canonical.clone();
    aggregate.id = digest(&"aggregate PG two-document snapshot");
    aggregate.validated_at = older;
    aggregate.coverage["edition_manifest"] = json!(manifest_id);
    aggregate.coverage["edition_root_snapshot"] = json!(canonical.id);
    aggregate.coverage["edition_documents"] = json!(2);
    aggregate.coverage["edition_inventory_complete"] = json!(true);
    store
        .w3c_put("snapshots", &aggregate.id, &json!(aggregate))
        .await
        .expect("aggregate snapshot");
    let approved = view(&catalog, &aggregate, older);
    store
        .w3c_publish_view(&approved)
        .await
        .expect("older chapter and newer canonical publish at minimum validation time");
    assert_eq!(
        store.w3c_state("default").await.expect("aggregate default"),
        Some(json!(approved))
    );

    for label in [
        "absent-manifest",
        "wrong-manifest-hash",
        "wrong-inventory",
        "wrong-root",
        "too-fresh-manifest",
        "too-fresh-view",
        "foreign-report",
        "foreign-url",
        "outside-edition-url",
        "cross-origin-url",
        "absent-artifact",
        "missing-publication",
        "unlicensed-publication",
        "replaced-root-dependency",
    ] {
        let mut candidate = aggregate.clone();
        candidate.id = digest(&("invalid aggregate snapshot", label));
        let mut dependency_manifest = manifest.clone();
        match label {
            "wrong-inventory" => {
                dependency_manifest["inventory"] = json!(digest(&"different inventory"))
            }
            "wrong-root" => dependency_manifest["root_snapshot"] = json!(base.id),
            "too-fresh-manifest" => {
                dependency_manifest["validated_at"] = json!(now);
                candidate.validated_at = now;
            }
            "replaced-root-dependency" => {
                dependency_manifest["publications"][root_url] = json!(chapter_publication)
            }
            "foreign-report" | "foreign-url" | "absent-artifact" | "unlicensed-publication" => {
                let id = digest(&("invalid aggregate dependency", label));
                let mut row = publication(&id, chapter_url, older, "dom", &"3".repeat(64));
                match label {
                    "foreign-report" => row["standard"] = json!("foreign"),
                    "foreign-url" => {
                        row["url"]["url"] = json!("https://www.w3.org/TR/foreign/chapter.html")
                    }
                    "absent-artifact" => row["artifact"] = Value::Null,
                    "unlicensed-publication" => row["license"]["decision"] = json!("unresolved"),
                    _ => unreachable!("bounded fixture case"),
                }
                store
                    .w3c_put("publications", &id, &row)
                    .await
                    .expect("retain rejected dependency metadata");
                dependency_manifest["publications"][chapter_url] = json!(id);
            }
            "outside-edition-url" | "cross-origin-url" => {
                let id = digest(&("outside edition dependency", label));
                let url = if label == "outside-edition-url" {
                    "https://www.w3.org/TR/foreign/chapter.html"
                } else {
                    "https://other.w3.org/TR/dom/chapter.html"
                };
                let row = publication(&id, url, older, "dom", &"4".repeat(64));
                store
                    .w3c_put("publications", &id, &row)
                    .await
                    .expect("same-report dependency outside canonical edition");
                dependency_manifest["publications"]
                    .as_object_mut()
                    .unwrap()
                    .remove(chapter_url);
                dependency_manifest["publications"][url] = json!(id);
            }
            "missing-publication" => {
                dependency_manifest["publications"][chapter_url] =
                    json!(digest(&"absent aggregate dependency"))
            }
            _ => {}
        }
        let mut id = digest(&dependency_manifest);
        if matches!(label, "absent-manifest" | "wrong-manifest-hash") {
            id = digest(&("unbound manifest identity", label));
        }
        if label != "absent-manifest" {
            store
                .w3c_put("editions", &id, &dependency_manifest)
                .await
                .expect("retain candidate immutable edition manifest");
        }
        candidate.coverage["edition_manifest"] = json!(id);
        store
            .w3c_put("snapshots", &candidate.id, &json!(candidate))
            .await
            .expect("retain rejected aggregate snapshot metadata");
        let selected_time = if label == "too-fresh-view" {
            now
        } else {
            candidate.validated_at
        };
        let rejected = view(&catalog, &candidate, selected_time);
        assert_eq!(
            store
                .w3c_publish_view(&rejected)
                .await
                .expect_err(label)
                .code,
            "integrity",
            "{label}"
        );
        assert_eq!(
            store
                .w3c_state("default")
                .await
                .expect("failed aggregate cannot replace default"),
            Some(json!(approved)),
            "{label}"
        );
        assert!(
            store
                .w3c_get("views", &rejected.id)
                .await
                .expect("failed view remains unpublished")
                .is_none(),
            "{label}"
        );
    }
    // Restore the earlier approved fixture default for the caller's restart assertions.
    store
        .w3c_publish_view(previous)
        .await
        .expect("restore earlier approved immutable default");
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL; run scripts/test-postgres.sh"]
async fn w3c_owner_fenced_atomic_evidence_default_and_restart() {
    let base =
        std::env::var("DEVRES_TEST_DATABASE_URL").expect("explicit disposable PostgreSQL required");
    let admin = sqlx::PgPool::connect(&base).await.expect("fixture admin");
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let database = format!("devres_w3c_fixture_{}_{suffix}", std::process::id());
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
        .expect("schema seven migration");
    let inspection = sqlx::PgPool::connect(url.as_str())
        .await
        .expect("fixture inspection");
    assert_eq!(
        sqlx::query_scalar::<_, i32>("SELECT version FROM devres_schema WHERE singleton")
            .fetch_one(&inspection)
            .await
            .expect("schema"),
        9
    );
    // Exercise the actual version-six migration branch with retained older-provider evidence.
    let retained_whatwg = json!({"synthetic":true,"body":"WHATWG evidence predating W3C schema"});
    store
        .whatwg_put("migration-fixtures", "before-w3c", &retained_whatwg)
        .await
        .expect("retain schema-six WHATWG evidence");
    let request = FetchRequest {
        key: "fixture:schema-six-public-capture".into(),
        url: "https://fixtures.invalid/schema-six".into(),
        ttl_secs: 3600,
        max_bytes: 4096,
        media_type: "text/plain".into(),
    };
    let legacy_body = b"Synthetic public capture retained across schema six to seven\n";
    let legacy = store
        .publish(
            &request,
            FetchResponse {
                status: 200,
                body: legacy_body.to_vec(),
                validators: Validators::default(),
            },
            1234,
        )
        .await
        .expect("retain schema-six immutable capture");
    let legacy_capture = legacy.capture.clone();
    drop(legacy);
    assert_eq!(sqlx::query_scalar::<_,i64>("SELECT (SELECT count(*) FROM devres_w3c_evidence)+(SELECT count(*) FROM devres_w3c_state)+(SELECT count(*) FROM devres_w3c_statistics)").fetch_one(&inspection).await.expect("empty new-provider tables"),0);
    drop(store);
    let mut owner_released = false;
    for _ in 0..50 {
        let owners=sqlx::query_scalar::<_,i64>("SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND classid=1835365490 AND objid=1 AND objsubid=2 AND granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database())").fetch_one(&inspection).await.expect("fixture ownership inspection");
        if owners == 0 {
            owner_released = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        owner_released,
        "schema maintenance requires no serving owner"
    );
    // Drop only new-provider tables in this task-created fixture database; earlier captures remain.
    sqlx::raw_sql("DROP TABLE devres_npm_state; DROP TABLE devres_npm_evidence; DROP TABLE devres_chromium_statistics; DROP TABLE devres_chromium_state; DROP TABLE devres_chromium_evidence; DROP TABLE devres_w3c_statistics; DROP TABLE devres_w3c_state; DROP TABLE devres_w3c_evidence; UPDATE devres_schema SET version=6 WHERE singleton").execute(&inspection).await.expect("prepare isolated schema-six fixture");
    let store = PgBlobStore::connect(url.as_str(), root.path())
        .await
        .expect("migrate retained schema six to current");
    assert_eq!(
        sqlx::query_scalar::<_, i32>("SELECT version FROM devres_schema WHERE singleton")
            .fetch_one(&inspection)
            .await
            .expect("upgraded schema"),
        9
    );
    assert_eq!(
        store
            .whatwg_get("migration-fixtures", "before-w3c")
            .await
            .expect("old-provider retained row")
            .expect("old-provider identity")
            .data,
        retained_whatwg
    );
    let restored = store
        .capture(&legacy_capture.id)
        .await
        .expect("old immutable capture remains readable");
    assert_eq!(restored.capture.id, legacy_capture.id);
    assert_eq!(restored.capture.body_hash, legacy_capture.body_hash);
    assert_eq!(restored.capture.source_url, legacy_capture.source_url);
    assert_eq!(restored.capture.retrieved_at, 1234);
    assert_eq!(restored.body.as_ref(), legacy_body);
    assert_eq!(
        store
            .latest(&request.key)
            .await
            .expect("old source head")
            .expect("old head retained")
            .stored
            .capture
            .id,
        legacy_capture.id
    );
    assert_eq!(
        PgBlobStore::connect(url.as_str(), root.path())
            .await
            .err()
            .expect("second owner denied")
            .code,
        "capacity"
    );
    let original = json!({"public":"retained synthetic W3C source","synthetic":true});
    let sequence = store
        .w3c_put("fixtures", "same", &original)
        .await
        .expect("first evidence");
    assert_eq!(
        store
            .w3c_put("fixtures", "same", &original)
            .await
            .expect("immutable replay"),
        sequence
    );
    assert_eq!(
        store
            .w3c_put("fixtures", "same", &json!({"replacement":true}))
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
            .w3c_put_many(&batch)
            .await
            .expect_err("atomic batch collision")
            .code,
        "integrity"
    );
    assert!(
        store
            .w3c_get("fixtures", "must-rollback")
            .await
            .expect("rollback read")
            .is_none()
    );
    assert_eq!(
        store
            .w3c_get("fixtures", "same")
            .await
            .expect("retained read")
            .expect("row")
            .data,
        original
    );
    let cutoff = store.w3c_cutoff().await.expect("frozen cutoff");
    store
        .w3c_put("fixtures", "later", &json!({"later":true}))
        .await
        .expect("later source");
    assert_eq!(
        store
            .w3c_rows("fixtures", 0, 100, Some(cutoff))
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
    store.w3c_put_many(&numeric).await.expect("numeric source");
    store
        .w3c_put_many(&numeric)
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
            .w3c_put_many(&duplicates)
            .await
            .expect_err("conflicting duplicate")
            .code,
        "integrity"
    );
    assert_eq!(
        store
            .w3c_put_many(&vec![numeric[0].clone(); 1001])
            .await
            .expect_err("row bound")
            .code,
        "capacity"
    );

    // Structurally valid online evidence is simulated only inside this fixture DB.
    let observed_at = 1_700_000_000;
    let catalog_id = digest(&"W3C fixture catalog");
    store.w3c_put("catalogs",&catalog_id,&json!({"id":catalog_id,"observed_at":observed_at,"standards":[{"id":"dom","title":"DOM fixture","url":"https://www.w3.org/TR/dom/","repository":"w3c/dom","metadata":{}}],"gaps":[]})).await.expect("catalog evidence");
    let publication_id = digest(&"W3C fixture publication");
    store.w3c_put("publications",&publication_id,&json!({"id":publication_id,"standard":"dom","url":{"url":"https://www.w3.org/TR/dom/","host":"www.w3.org"},"observed_at":observed_at,"status":200,"artifact":{"body_hash":"e".repeat(64),"bytes":0,"relative_path":"synthetic-publication"},"links":[],"gaps":[],"repositories":["w3c/dom"]})).await.expect("publication observation");
    let inventory = devres_adapters::w3c::inventory::empty(&store)
        .await
        .expect("empty fixture inventory");
    let snapshot = Snapshot {
        id: digest(&"W3C fixture snapshot"),
        standard: "dom".into(),
        repository: "https://www.w3.org/TR/dom/".into(),
        revision: publication_id.clone(),
        tree: "e".repeat(64),
        parents: vec![],
        committed_at: observed_at,
        inventory,
        processor_version: 1,
        index: json!({"manifest":"synthetic-index"}),
        coverage: json!({"accounted":true,"usable":true,"members":1,"publication":publication_id,"projection_gaps":0,"publication_role":"latest_tr","publication_status":"REC","license":{"decision":"approved","copyright":"Synthetic fixture authors","license_url":"https://www.w3.org/copyright/document-license-2023/","notice":"Synthetic licensed observation; not actual W3C acceptance."}}),
        source_url: "https://www.w3.org/TR/dom/".into(),
        representation: "html".into(),
        validated_at: observed_at,
    };
    store
        .w3c_put("snapshots", &snapshot.id, &json!(snapshot))
        .await
        .expect("snapshot evidence");
    let expected_statistics =
        json!({"snapshots":1,"publications":1,"projection_gaps":0,"index_gaps":0});
    assert_eq!(
        store.w3c_statistics().await.expect("retained statistics"),
        expected_statistics
    );
    store
        .w3c_put("snapshots", &snapshot.id, &json!(snapshot))
        .await
        .expect("snapshot replay");
    assert_eq!(
        store
            .w3c_statistics()
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
            .w3c_put_many(&rejected_statistics)
            .await
            .expect_err("statistics transaction rollback")
            .code,
        "integrity"
    );
    assert!(
        store
            .w3c_get("snapshots", &rollback_snapshot.id)
            .await
            .expect("snapshot transaction rollback")
            .is_none()
    );
    assert_eq!(
        store.w3c_statistics().await.expect("rolled back counters"),
        expected_statistics
    );
    let current = view(&catalog_id, &snapshot, observed_at);
    store
        .w3c_publish_view(&current)
        .await
        .expect("atomic default publication");
    assert_eq!(
        store.w3c_state("default").await.expect("default"),
        Some(json!(current))
    );
    let missing_snapshot = Snapshot {
        id: digest(&"missing W3C snapshot"),
        ..snapshot.clone()
    };
    let missing = view(&catalog_id, &missing_snapshot, observed_at);
    assert_eq!(
        store
            .w3c_publish_view(&missing)
            .await
            .expect_err("missing snapshot rejected")
            .code,
        "integrity"
    );
    let missing_catalog = view(&digest(&"missing catalog"), &snapshot, observed_at);
    assert_eq!(
        store
            .w3c_publish_view(&missing_catalog)
            .await
            .expect_err("missing catalog rejected")
            .code,
        "integrity"
    );
    let broken_snapshot = Snapshot {
        id: digest(&"broken W3C snapshot"),
        index: Value::Null,
        ..snapshot.clone()
    };
    store
        .w3c_put("snapshots", &broken_snapshot.id, &json!(broken_snapshot))
        .await
        .expect("raw broken evidence retained");
    let broken = view(&catalog_id, &broken_snapshot, observed_at);
    assert_eq!(
        store
            .w3c_publish_view(&broken)
            .await
            .expect_err("missing index rejected")
            .code,
        "integrity"
    );
    assert_eq!(
        store
            .w3c_state("default")
            .await
            .expect("prior default survives"),
        Some(json!(current))
    );
    for rejected in [&missing, &missing_catalog, &broken] {
        assert!(
            store
                .w3c_get("views", &rejected.id)
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
            .w3c_put("snapshots", &invalid.id, &json!(invalid))
            .await
            .expect("retain rejected fixture evidence");
        let rejected = view(&catalog_id, &invalid, observed_at);
        assert_eq!(
            store
                .w3c_publish_view(&rejected)
                .await
                .expect_err("synthetic or mismatched publication rejected")
                .code,
            "integrity"
        );
        assert!(
            store
                .w3c_get("views", &rejected.id)
                .await
                .expect("rejected evidence cannot activate")
                .is_none()
        );
    }
    assert_eq!(
        store
            .w3c_state("default")
            .await
            .expect("default survives invalid provenance"),
        Some(json!(current))
    );

    for decision in ["unresolved", "blocked"] {
        let mut metadata_only = snapshot.clone();
        metadata_only.id = digest(&("metadata-only-license", decision));
        metadata_only.coverage["license"]["decision"] = json!(decision);
        store
            .w3c_put("snapshots", &metadata_only.id, &json!(metadata_only))
            .await
            .expect("retain metadata-only disposition");
        let rejected = view(&catalog_id, &metadata_only, observed_at);
        assert_eq!(
            store
                .w3c_publish_view(&rejected)
                .await
                .expect_err("unresolved license cannot publish a current content default")
                .code,
            "integrity"
        );
        assert!(
            store
                .w3c_get("views", &rejected.id)
                .await
                .expect("rejected metadata-only default")
                .is_none()
        );
        assert_eq!(
            store
                .w3c_state("default")
                .await
                .expect("approved prior default survives license rejection"),
            Some(json!(current))
        );
    }

    let mut gap_snapshot = Snapshot {
        id: digest(&"counted snapshot gap fixture"),
        ..snapshot.clone()
    };
    gap_snapshot.coverage["projection_gaps"] = json!(3);
    gap_snapshot.coverage["index_gaps"] = json!(2);
    store
        .w3c_put("snapshots", &gap_snapshot.id, &json!(gap_snapshot))
        .await
        .expect("counted retained gaps");
    let final_statistics = store
        .w3c_statistics()
        .await
        .expect("retained snapshot gap statistics");
    assert_eq!(
        final_statistics,
        json!({"snapshots":7,"publications":1,"projection_gaps":3,"index_gaps":2})
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
            .w3c_get("fixtures", "same")
            .await
            .expect_err("lost-owner read denied")
            .code,
        "unavailable"
    );
    assert!(
        store
            .w3c_put("fixtures", "after-loss", &json!(true))
            .await
            .is_err()
    );
    assert!(
        store
            .w3c_set_state("after-loss", &json!(true))
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
            .w3c_get("fixtures", "same")
            .await
            .expect("retained source")
            .expect("row")
            .data,
        original
    );
    assert_eq!(
        restarted
            .w3c_state("default")
            .await
            .expect("retained default"),
        Some(json!(current))
    );
    assert_eq!(
        restarted
            .w3c_get("snapshots", &snapshot.id)
            .await
            .expect("retained snapshot")
            .expect("row")
            .data,
        json!(snapshot)
    );
    assert!(
        restarted
            .w3c_get("views", &broken.id)
            .await
            .expect("failed publication absent after restart")
            .is_none()
    );
    assert_eq!(
        restarted
            .w3c_statistics()
            .await
            .expect("statistics survive restart"),
        final_statistics
    );
    aggregate_edition_default_regression(&restarted, &snapshot, &current).await;
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
