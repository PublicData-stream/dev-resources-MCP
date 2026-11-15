//! Metadata-only corruption fixtures for retained recovery graph verification.
use super::*;

async fn fixture(complete: bool) -> (PgBlobStore, tempfile::TempDir, String, Value, Value) {
    let base = std::env::var("DEVRES_TEST_DATABASE_URL").unwrap();
    let admin = sqlx_postgres::PgPool::connect(&base).await.unwrap();
    let label = if complete { "complete" } else { "pending" };
    let name = format!("devres_recovery_verify_{label}_{}", std::process::id());
    sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!(
        "CREATE DATABASE {name}"
    )))
    .execute(&admin)
    .await
    .unwrap();
    let mut url = url::Url::parse(&base).unwrap();
    url.set_path(&format!("/{name}"));
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let store = PgBlobStore::connect(url.as_str(), root.path())
        .await
        .unwrap();
    let id = crate::integrity::hash(b"exact retained verification fixture acquisition");
    let body = crate::integrity::hash(b"retained fixture export descriptor");
    let source = json!({"snapshot":id,"artifact":{"body_hash":body,"bytes":34,"relative_path":crate::integrity::relative_path(&body).unwrap().to_string_lossy()},"validated_at":devres_domain::unix_now(),"next":1,"records":0,"gaps":0,"expanded":0,"done":true,"failed":"capacity","processor_version":PROCESSOR_VERSION,"failure_context":{"version":1,"code":"capacity","materialization_deadline":true}});
    store.npm_set_state("advisory-job", &source).await.unwrap();
    let operation = crate::integrity::hash(label.as_bytes());
    let state = crate::integrity::hash(b"exact original admission authority");
    let mut evidence = RecoveryEvidenceReceipt {
        version: 1,
        job_id: id.clone(),
        revision: 1,
        state_digest: state.clone(),
        artifact_digest: body,
        artifact_bytes: 34,
        members: 2,
        next_member: 1,
        records: 0,
        gaps: 0,
        expanded_bytes: 0,
        prefix_digest: crate::integrity::hash(b"empty committed directory prefix"),
        evidence_digest: String::new(),
    };
    evidence.evidence_digest = receipt_hash(&evidence).unwrap();
    let checkpoint = RecoveryCheckpoint {
        version: 1,
        schema: 19,
        store_id: "retained-checkpoint-authority".into(),
        archive_epoch: 1,
        system_identifier: "12345".into(),
        coordinated: true,
        restoration_verified: true,
        receipt_digest: crate::integrity::hash(b"operator recovery checkpoint"),
    };
    let admission = json!({"version":1,"operation_id":operation,"job_id":id,"revision":1,"recipe":NPM_RECOVERY_RECIPE,"expected_state":state,"evidence":evidence,"checkpoint":checkpoint,"job":source});
    let mut job = source.clone();
    job["done"] = json!(complete);
    job.as_object_mut().unwrap().remove("failed");
    let mut work = json!({"version":1,"operation_id":operation,"job_id":id,"revision":1,"job":job,"status":"pending","attempts":0,"claim":null,"publication_snapshot":null});
    if complete {
        work["status"] = json!("complete");
        work["attempts"] = json!(1);
        work["claim"] = json!(crate::integrity::hash(b"recorded completed claim"));
        work["job"]["next"] = json!(2);
        let mut snapshot = json!({"lane":"advisories","artifact":source["artifact"],"validated_at":source["validated_at"],"records":0,"gaps":0,"accounted":true,"complete":true,"source":"osv_npm_export","processor_version":PROCESSOR_VERSION,"membership":id});
        snapshot["id"] = json!(crate::npm::corpus::identity(&snapshot).unwrap());
        let snapshot_id = snapshot["id"].as_str().unwrap();
        store
            .npm_put("snapshots", snapshot_id, &snapshot)
            .await
            .unwrap();
        store
            .npm_set_state(
                &format!("ready:{snapshot_id}"),
                &json!({"id":snapshot_id,"records":0,"accounted":true}),
            )
            .await
            .unwrap();
        work["publication_snapshot"] = json!(snapshot_id);
        work["completion_receipt"] = json!({"version":1,"operation_id":operation,"job_id":id,"snapshot":snapshot_id,"historical_only":true,"default_promoted":false});
    }
    {
        let mut owner = store.owner.lock().await;
        let mut tx = owner.begin().await.unwrap();
        sqlx_core::query::query("INSERT INTO devres_npm_advisory_recoveries(operation_id,job_id,recipe,data,data_integrity) VALUES($1,$2,$3,$4,$5)")
            .bind(&operation).bind(&id).bind(NPM_RECOVERY_RECIPE).bind(Json(&admission)).bind(payload_integrity::digest(JOURNAL,"",&operation,&admission).unwrap()).execute(&mut *tx).await.unwrap();
        sqlx_core::query::query("INSERT INTO devres_npm_recovery_work(operation_id,data,data_integrity) VALUES($1,$2,$3)")
            .bind(&operation).bind(Json(&work)).bind(payload_integrity::digest(WORK,"",&operation,&work).unwrap()).execute(&mut *tx).await.unwrap();
        tx.commit().await.unwrap();
        verify_history(&mut owner, &CancellationToken::new())
            .await
            .unwrap();
    }
    (store, root, operation, admission, work)
}

async fn replace_payload(conn: &mut PgConnection, table: &str, operation: &str, data: &Value) {
    let sql = format!("UPDATE {table} SET data=$2,data_integrity=$3 WHERE operation_id=$1");
    sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(sql))
        .bind(operation)
        .bind(Json(data))
        .bind(payload_integrity::digest(table, "", operation, data).unwrap())
        .execute(&mut *conn)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires disposable DEVRES_TEST_DATABASE_URL PostgreSQL"]
async fn recovery_verifier_rejects_missing_and_resealed_admission_queue_references() {
    let (store, _root, operation, admission, work) = fixture(false).await;
    for mutation in [
        "missing_history",
        "missing_work",
        "missing_admission",
        "wrong_history_cause",
        "wrong_admission_job",
        "wrong_admission_column",
        "wrong_evidence",
        "changed_queue_identity",
        "rewound_queue_cursor",
    ] {
        let mut owner = store.owner.lock().await;
        let mut tx = owner.begin().await.unwrap();
        sqlx_core::raw_sql::raw_sql("SET LOCAL session_replication_role=replica")
            .execute(&mut *tx)
            .await
            .unwrap();
        match mutation {
            "missing_history" => {
                sqlx_core::query::query(
                    "DELETE FROM devres_npm_advisory_job_history WHERE job_id=$1",
                )
                .bind(admission["job_id"].as_str().unwrap())
                .execute(&mut *tx)
                .await
                .unwrap();
            }
            "missing_work" => {
                sqlx_core::query::query(
                    "DELETE FROM devres_npm_recovery_work WHERE operation_id=$1",
                )
                .bind(&operation)
                .execute(&mut *tx)
                .await
                .unwrap();
            }
            "missing_admission" => {
                sqlx_core::query::query(
                    "DELETE FROM devres_npm_advisory_recoveries WHERE operation_id=$1",
                )
                .bind(&operation)
                .execute(&mut *tx)
                .await
                .unwrap();
            }
            "wrong_history_cause" => {
                let row=sqlx_core::query::query("SELECT data FROM devres_npm_advisory_job_history WHERE job_id=$1 AND revision=1").bind(admission["job_id"].as_str().unwrap()).fetch_one(&mut *tx).await.unwrap();
                let mut data = row.try_get::<Json<Value>, _>("data").unwrap().0;
                data["cause_authoritative"] = json!(false);
                sqlx_core::query::query("UPDATE devres_npm_advisory_job_history SET data=$2,data_integrity=$3 WHERE job_id=$1 AND revision=1").bind(admission["job_id"].as_str().unwrap()).bind(Json(&data)).bind(payload_integrity::digest(HISTORY,admission["job_id"].as_str().unwrap(),"1",&data).unwrap()).execute(&mut *tx).await.unwrap();
            }
            "wrong_admission_job" => {
                let mut data = admission.clone();
                data["job"]["validated_at"] =
                    json!(data["job"]["validated_at"].as_i64().unwrap() - 1);
                replace_payload(&mut tx, JOURNAL, &operation, &data).await;
            }
            "wrong_admission_column" => {
                sqlx_core::query::query(
                    "UPDATE devres_npm_advisory_recoveries SET job_id=$2 WHERE operation_id=$1",
                )
                .bind(&operation)
                .bind(crate::integrity::hash(b"different column identity"))
                .execute(&mut *tx)
                .await
                .unwrap();
            }
            "wrong_evidence" => {
                let mut data = admission.clone();
                let mut receipt: RecoveryEvidenceReceipt =
                    serde_json::from_value(data["evidence"].clone()).unwrap();
                receipt.artifact_digest = crate::integrity::hash(b"other original bytes");
                receipt.evidence_digest = receipt_hash(&receipt).unwrap();
                data["evidence"] = serde_json::to_value(receipt).unwrap();
                replace_payload(&mut tx, JOURNAL, &operation, &data).await;
            }
            "changed_queue_identity" => {
                let mut data = work.clone();
                data["job"]["validated_at"] =
                    json!(data["job"]["validated_at"].as_i64().unwrap() - 1);
                replace_payload(&mut tx, WORK, &operation, &data).await;
            }
            "rewound_queue_cursor" => {
                let mut data = work.clone();
                data["job"]["next"] = json!(0);
                replace_payload(&mut tx, WORK, &operation, &data).await;
            }
            _ => unreachable!(),
        }
        assert!(
            verify_history(&mut tx, &CancellationToken::new())
                .await
                .is_err(),
            "{mutation}"
        );
        tx.rollback().await.unwrap();
        verify_history(&mut owner, &CancellationToken::new())
            .await
            .unwrap();
    }
}

#[tokio::test]
#[ignore = "requires disposable DEVRES_TEST_DATABASE_URL PostgreSQL"]
async fn recovery_verifier_rejects_missing_publication_and_forged_completion_links() {
    let (store, _root, operation, _admission, work) = fixture(true).await;
    for mutation in [
        "missing_snapshot",
        "missing_ready",
        "forged_receipt",
        "forged_snapshot",
        "cursor_incomplete",
    ] {
        let mut owner = store.owner.lock().await;
        let mut tx = owner.begin().await.unwrap();
        sqlx_core::raw_sql::raw_sql("SET LOCAL session_replication_role=replica")
            .execute(&mut *tx)
            .await
            .unwrap();
        let snapshot_id = work["publication_snapshot"].as_str().unwrap();
        match mutation {
            "missing_snapshot" => {
                sqlx_core::query::query(
                    "DELETE FROM devres_npm_evidence WHERE kind='snapshots' AND key=$1",
                )
                .bind(snapshot_id)
                .execute(&mut *tx)
                .await
                .unwrap();
            }
            "missing_ready" => {
                sqlx_core::query::query("DELETE FROM devres_npm_state WHERE key=$1")
                    .bind(format!("ready:{snapshot_id}"))
                    .execute(&mut *tx)
                    .await
                    .unwrap();
            }
            "forged_receipt" => {
                let mut data = work.clone();
                data["completion_receipt"]["default_promoted"] = json!(true);
                replace_payload(&mut tx, WORK, &operation, &data).await;
            }
            "forged_snapshot" => {
                let row = sqlx_core::query::query(
                    "SELECT data FROM devres_npm_evidence WHERE kind='snapshots' AND key=$1",
                )
                .bind(snapshot_id)
                .fetch_one(&mut *tx)
                .await
                .unwrap();
                let mut data = row.try_get::<Json<Value>, _>("data").unwrap().0;
                data["source"] = json!("unrelated export");
                sqlx_core::query::query("UPDATE devres_npm_evidence SET data=$2,data_integrity=$3 WHERE kind='snapshots' AND key=$1").bind(snapshot_id).bind(Json(&data)).bind(payload_integrity::digest("devres_npm_evidence","snapshots",snapshot_id,&data).unwrap()).execute(&mut *tx).await.unwrap();
            }
            "cursor_incomplete" => {
                let mut data = work.clone();
                data["job"]["next"] = json!(1);
                replace_payload(&mut tx, WORK, &operation, &data).await;
            }
            _ => unreachable!(),
        }
        assert!(
            verify_history(&mut tx, &CancellationToken::new())
                .await
                .is_err(),
            "{mutation}"
        );
        tx.rollback().await.unwrap();
        verify_history(&mut owner, &CancellationToken::new())
            .await
            .unwrap();
    }
}
