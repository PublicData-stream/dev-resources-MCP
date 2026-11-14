use super::*;
use devres_application::{
    advisory::AdvisoryCurrentOperation,
    collection::{Failure, Phase},
};
use devres_domain::Capture;

fn snapshot(seed: &str, format: &str) -> AdvisorySnapshot {
    let now = devres_domain::unix_now();
    let revision = "a".repeat(40);
    let body = format!("Synthetic inert public advisory fixture {seed}");
    let capture = |key: String, source_url: String| Capture {
        id: hash(format!("{seed}:{key}").as_bytes()),
        key,
        source_url,
        body_hash: hash(b"synthetic capture"),
        media_type: "text/plain".into(),
        retrieved_at: now,
        validated_at: now,
    };
    AdvisorySnapshot {
        id: hash(seed.as_bytes()),
        revision: revision.clone(),
        format: format.into(),
        created_at: now,
        validated_at: Some(now),
        historical: false,
        complete: true,
        records: vec![AdvisoryRecord {
            id: "RUSTSEC-2024-0001".into(),
            package: "fixture".into(),
            format: format.into(),
            path: "crates/fixture/RUSTSEC-2024-0001.md".into(),
            body_hash: hash(body.as_bytes()),
            body,
            metadata: json!({"classification":"vulnerability"}),
        }],
        captures: vec![
            capture(
                "rustsec:head".into(),
                "https://api.github.com/repos/RustSec/advisory-db/commits/main".into(),
            ),
            capture(
                format!("rustsec:bundle:{revision}"),
                format!("https://codeload.github.com/RustSec/advisory-db/tar.gz/{revision}"),
            ),
        ],
        coverage: json!({"complete":true,"processor_version":ADVISORY_PROCESSOR_VERSION,"fixture":true}),
        parents: vec![],
        committed_at: 0,
    }
}
fn attempt(snapshot: &AdvisorySnapshot, seed: &str) -> AdvisoryCurrentDiagnostic {
    AdvisoryCurrentDiagnostic {
        version: 1,
        attempt: hash(seed.as_bytes()),
        operation: AdvisoryCurrentOperation::CurrentRefresh,
        outcome: AdvisoryAttemptOutcome::Running,
        stage: AdvisoryCurrentStage::Publication,
        started_at: devres_domain::unix_now(),
        finished_at: None,
        head_capture: Some(snapshot.captures[0].id.clone()),
        bundle_capture: Some(snapshot.captures[1].id.clone()),
        revision: Some(snapshot.revision.clone()),
        snapshot: Some(snapshot.id.clone()),
        failure: None,
    }
}
async fn save_attempt(store: &PgBlobStore, attempt: &AdvisoryCurrentDiagnostic) {
    store
        .set_advisory_state(CURRENT_DIAGNOSTICS_KEY, &json!(attempt))
        .await
        .unwrap();
}
#[tokio::test]
#[ignore = "requires disposable PostgreSQL; run scripts/test-postgres.sh"]
async fn rustsec_current_atomic_publication_and_reconciliation() {
    let base = std::env::var("DEVRES_TEST_DATABASE_URL").expect("disposable PostgreSQL required");
    let admin = sqlx_postgres::PgPool::connect(&base).await.unwrap();
    let database = format!("devres_rustsec_current_{}", std::process::id());
    sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!(
        "CREATE DATABASE {database}"
    )))
    .execute(&admin)
    .await
    .unwrap();
    let mut url = url::Url::parse(&base).unwrap();
    url.set_path(&format!("/{database}"));
    let root = tempfile::tempdir().unwrap();
    let store = PgBlobStore::connect(url.as_str(), root.path())
        .await
        .unwrap();
    let pool = sqlx_postgres::PgPool::connect(url.as_str()).await.unwrap();
    let old = snapshot("old canonical snapshot", "rustsec");
    let osv = snapshot("old OSV snapshot", "osv");
    store.publish_advisory_snapshot(&old, true).await.unwrap();
    store.publish_advisory_snapshot(&osv, true).await.unwrap();
    let old_public = json!({"last_attempt":1,"last_success":1,"snapshot":old.id,"error":null});
    store
        .set_advisory_state("current", &old_public)
        .await
        .unwrap();
    for (index, (table, condition)) in [
        ("devres_advisory_records", ""),
        ("devres_advisory_snapshots", ""),
        ("devres_advisory_members", ""),
        ("devres_advisory_defaults", ""),
        ("devres_advisory_state", " WHEN (NEW.key='current')"),
        (
            "devres_advisory_state",
            " WHEN (NEW.key='diagnostics-current')",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let candidate = snapshot(&format!("rejected candidate {index}"), "rustsec");
        let attempt = attempt(&candidate, &format!("rejected attempt {index}"));
        save_attempt(&store, &attempt).await;
        let before: i64 =
            sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM devres_advisory_records")
                .fetch_one(&pool)
                .await
                .unwrap();
        sqlx_core::raw_sql::raw_sql("CREATE FUNCTION fixture_reject() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic publication rejection'; END $$").execute(&pool).await.unwrap();
        sqlx_core::raw_sql::raw_sql(sqlx_core::sql_str::AssertSqlSafe(format!("CREATE TRIGGER fixture_reject BEFORE INSERT OR UPDATE ON {table} FOR EACH ROW{condition} EXECUTE FUNCTION fixture_reject()"))).execute(&pool).await.unwrap();
        assert!(matches!(
            store.publish_current_advisory(&candidate, &attempt).await,
            Err(AdvisoryPublicationError::Rejected(_))
        ));
        sqlx_core::raw_sql::raw_sql(sqlx_core::sql_str::AssertSqlSafe(format!(
            "DROP TRIGGER fixture_reject ON {table}; DROP FUNCTION fixture_reject()"
        )))
        .execute(&pool)
        .await
        .unwrap();
        assert!(
            store
                .advisory_snapshot(Some(&candidate.id), "rustsec")
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store
                .advisory_snapshot(None, "rustsec")
                .await
                .unwrap()
                .unwrap()
                .id,
            old.id
        );
        assert_eq!(
            store
                .advisory_snapshot(None, "osv")
                .await
                .unwrap()
                .unwrap()
                .id,
            osv.id
        );
        assert_eq!(
            store.advisory_state("current").await.unwrap().unwrap(),
            old_public
        );
        assert_eq!(
            store
                .advisory_state(CURRENT_DIAGNOSTICS_KEY)
                .await
                .unwrap()
                .unwrap()["outcome"],
            "running"
        );
        let after: i64 =
            sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM devres_advisory_records")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            after, before,
            "record inserts must roll back with later publication failure"
        );
    }
    let candidate = snapshot("commit rejected candidate", "rustsec");
    let interrupted = attempt(&candidate, "commit rejected attempt");
    save_attempt(&store, &interrupted).await;
    sqlx_core::raw_sql::raw_sql("CREATE FUNCTION fixture_reject() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic deferred commit rejection'; END $$; CREATE CONSTRAINT TRIGGER fixture_reject AFTER INSERT OR UPDATE ON devres_advisory_state DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.key='current') EXECUTE FUNCTION fixture_reject()").execute(&pool).await.unwrap();
    assert!(matches!(
        store
            .publish_current_advisory(&candidate, &interrupted)
            .await,
        Err(AdvisoryPublicationError::CommitUnknown(_))
    ));
    sqlx_core::raw_sql::raw_sql(
        "DROP TRIGGER fixture_reject ON devres_advisory_state; DROP FUNCTION fixture_reject()",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        store.reconcile_current_advisory_attempt().await.unwrap(),
        AdvisoryAttemptOutcome::Failed
    );
    assert_eq!(
        store
            .advisory_snapshot(None, "rustsec")
            .await
            .unwrap()
            .unwrap()
            .id,
        old.id
    );
    assert_eq!(
        store.advisory_state("current").await.unwrap().unwrap()["last_success"],
        1
    );
    let candidate = snapshot("successful candidate", "rustsec");
    let succeeded = attempt(&candidate, "successful attempt");
    save_attempt(&store, &succeeded).await;
    store
        .publish_current_advisory(&candidate, &succeeded)
        .await
        .unwrap();
    assert_eq!(
        store.reconcile_current_advisory_attempt().await.unwrap(),
        AdvisoryAttemptOutcome::Succeeded
    );
    let status = store.advisory_status().await.unwrap();
    assert!(!status.to_string().contains(CURRENT_DIAGNOSTICS_KEY));
    let mut late = succeeded.clone();
    late.outcome = AdvisoryAttemptOutcome::Failed;
    late.failure = Some(Failure::from_error(
        &Error::unavailable("late synthetic failure"),
        Phase::ViewPublication,
        devres_domain::unix_now(),
    ));
    assert!(!store.finish_current_advisory_attempt(&late).await.unwrap());
    assert_eq!(
        store.advisory_state("current").await.unwrap().unwrap()["snapshot"],
        candidate.id
    );
    let unfinished = attempt(
        &snapshot("unfinished candidate", "rustsec"),
        "unfinished attempt",
    );
    save_attempt(&store, &unfinished).await;
    drop(store);
    let reopened = PgBlobStore::connect(url.as_str(), root.path())
        .await
        .unwrap();
    assert_eq!(
        reopened.reconcile_current_advisory_attempt().await.unwrap(),
        AdvisoryAttemptOutcome::Failed
    );
    assert_eq!(
        reopened
            .advisory_snapshot(None, "rustsec")
            .await
            .unwrap()
            .unwrap()
            .id,
        candidate.id
    );
    assert_eq!(
        reopened
            .advisory_snapshot(None, "osv")
            .await
            .unwrap()
            .unwrap()
            .id,
        osv.id
    );
    drop(reopened);
    pool.close().await;
    sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!(
        "DROP DATABASE {database} WITH (FORCE)"
    )))
    .execute(&admin)
    .await
    .unwrap();
}
