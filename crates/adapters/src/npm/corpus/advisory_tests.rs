fn advisory_export() -> (Vec<u8>, Vec<u8>) {
    let raw = br#"{ "id":"GHSA-2345-6789-cfgh", "modified":"2026-10-27T00:00:00Z", "affected":[{"package":{"ecosystem":"npm","name":"fixture"},"versions":["1.0.0"]}] }"#.to_vec();
    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    writer
        .start_file(
            "GHSA-2345-6789-cfgh.json",
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
    writer.write_all(&raw).unwrap();
    (writer.finish().unwrap().into_inner(), raw)
}

async fn retained_advisory_job(corpus: &NpmCorpus, store: &Memory) -> (Value, Vec<u8>) {
    let (export, raw) = advisory_export();
    let artifact = corpus
        .raw
        .capture_bytes(export, CancellationToken::new())
        .await
        .unwrap();
    let job = json!({"snapshot":digest(b"fixture acquisition"),"artifact":artifact,"validated_at":devres_domain::unix_now(),"next":0,"records":0,"gaps":0,"done":false});
    store.npm_set_state("advisory-job", &job).await.unwrap();
    let url = Operation::AdvisoryExport.url().unwrap();
    store
        .npm_set_state(
            &state_key("source-response", &url),
            &json!({"artifact":artifact,"validators":{"etag":"fixture-export"}}),
        )
        .await
        .unwrap();
    (job, raw)
}

#[tokio::test]
async fn advisory_failures_resume_exact_export_at_each_durable_cut() {
    for (point, stage) in [
        ("advisories", "record_retention"),
        ("advisory-raw", "raw_retention"),
        ("advisory-members", "member_retention"),
        ("advisory-packages", "package_link_retention"),
        ("checkpoint", "job_checkpoint"),
        ("ready", "ready_marker"),
        ("publication", "publication"),
        ("validator", "validator_acceptance"),
        ("completion", "completion_checkpoint"),
    ] {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let store = Arc::new(Memory::default());
        let broker =
            Arc::new(BulkBroker::fixture(url::Url::parse("http://127.0.0.1:9").unwrap()).unwrap());
        let corpus = corpus(store.clone(), broker.clone(), root.path());
        let (original_job, raw) = retained_advisory_job(&corpus, &store).await;
        *store.1.lock().await = Some(point);
        let error = corpus
            .collect_advisories(CancellationToken::new())
            .await
            .unwrap_err();
        assert_eq!(error.message, "Fixture interrupted operation.", "{point}");
        assert_eq!(
            error.details.as_ref().unwrap()["private"],
            "never-copy-this-fixture-body"
        );
        let diagnostic = store
            .npm_state("diagnostics-advisories")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(diagnostic["stage"], stage, "{point}");
        assert_eq!(diagnostic["last_failure"]["stage"], stage, "{point}");
        assert_eq!(
            diagnostic["last_failure"]["job"]["artifact_capture"],
            original_job["artifact"]["body_hash"]
        );
        assert!(!diagnostic.to_string().contains("never-copy"));
        let checkpoint = store.npm_state("advisory-job").await.unwrap().unwrap();
        assert_eq!(checkpoint["done"], false, "{point}");
        let retained = store.0.lock().await.1.clone();
        drop(corpus);
        let restarted = self::corpus(store.clone(), broker.clone(), root.path());
        restarted
            .collect_advisories(CancellationToken::new())
            .await
            .unwrap();
        let final_job = store.npm_state("advisory-job").await.unwrap().unwrap();
        assert_eq!(final_job["done"], true, "{point}");
        assert_eq!(final_job["snapshot"], original_job["snapshot"]);
        assert_eq!(final_job["artifact"], original_job["artifact"]);
        assert_eq!(final_job["next"], 1);
        assert_eq!(final_job["records"], 1);
        let final_rows = store.0.lock().await.1.clone();
        for (key, row) in retained {
            let after = &final_rows[&key];
            assert_eq!(after.sequence, row.sequence, "{point}");
            assert_eq!(after.data, row.data, "{point}");
        }
        assert_eq!(
            store
                .npm_rows("advisory-members", 0, 10, None, None)
                .await
                .unwrap()
                .len(),
            1
        );
        let raw_rows = store
            .npm_rows("advisory-raw", 0, 10, None, None)
            .await
            .unwrap();
        assert_eq!(raw_rows.len(), 1);
        let artifact: BulkArtifact =
            serde_json::from_value(raw_rows[0].data["artifact"].clone()).unwrap();
        assert_eq!(
            restarted
                .bytes(&artifact, 1024 * 1024, CancellationToken::new())
                .await
                .unwrap(),
            raw
        );
        let published = store
            .npm_state("default-advisories")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(published["records"], 1);
        assert_eq!(published["membership"], original_job["snapshot"]);
        let diagnostic = store
            .npm_state("diagnostics-advisories")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(diagnostic["outcome"], "succeeded");
        assert_eq!(diagnostic["last_success"]["snapshot"], published["id"]);
        assert_eq!(diagnostic["last_failure"]["stage"], stage);
        assert_eq!(broker.attempt_count(), 0, "{point}");
    }
}

#[tokio::test]
async fn typed_materialization_deadline_preserves_advisory_job_but_other_capacity_is_terminal() {
    use devres_application::collection::{LimitKind, Phase, limited};
    let typed = limited(
        Error::capacity("Fixture deadline."),
        Phase::Materialization,
        LimitKind::Deadline,
        None,
        None,
    );
    let cases = [
        (typed.clone(), false),
        (Error::capacity("Unknown capacity."), true),
        (limited(Error::capacity("Immutable expansion bound."), Phase::Traversal, LimitKind::ExpandedBytes, Some(65), Some(64)), true),
        (limited(Error::capacity("Cache quota."), Phase::Materialization, LimitKind::CacheWorkingSet, None, None), true),
        (Error::capacity("Malformed context.").with_details(json!({"collector":{"phase":"materialization","limit":{"kind":"deadline","private":"body"}}})), true),
    ];
    for (error, terminal) in cases {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let store = Arc::new(Memory::default());
        let broker =
            Arc::new(BulkBroker::fixture(url::Url::parse("http://127.0.0.1:9").unwrap()).unwrap());
        let corpus = corpus(store.clone(), broker.clone(), root.path());
        let (job, _) = retained_advisory_job(&corpus, &store).await;
        corpus
            .record_failure("advisories", None, &error)
            .await
            .unwrap();
        let after = store.npm_state("advisory-job").await.unwrap().unwrap();
        assert_eq!(after["done"], terminal);
        if !terminal {
            assert_eq!(after, job);
            store
                .npm_set_state("advisory-retry", &json!(0))
                .await
                .unwrap();
            corpus
                .collect_advisories(CancellationToken::new())
                .await
                .unwrap();
            assert!(
                store
                    .npm_state("default-advisories")
                    .await
                    .unwrap()
                    .is_some()
            );
            assert_eq!(broker.attempt_count(), 0);
        }
    }
}

#[tokio::test]
async fn terminal_legacy_job_is_not_linked_to_new_acquisition_failure() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let store = Arc::new(Memory::default());
    let broker =
        Arc::new(BulkBroker::fixture(url::Url::parse("http://127.0.0.1:9").unwrap()).unwrap());
    let corpus = corpus(store.clone(), broker, root.path());
    let (mut job, _) = retained_advisory_job(&corpus, &store).await;
    job["done"] = json!(true);
    job["failed"] = json!("capacity");
    store.npm_set_state("advisory-job", &job).await.unwrap();
    let error = corpus
        .collect_advisories(CancellationToken::new())
        .await
        .unwrap_err();
    assert_eq!(error.code, "unavailable");
    assert_eq!(store.npm_state("advisory-job").await.unwrap().unwrap(), job);
    let diagnostic = store
        .npm_state("diagnostics-advisories")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(diagnostic["stage"], "acquisition");
    assert!(diagnostic["job"].is_null());
    assert!(diagnostic["last_failure"]["job"].is_null());
}

#[tokio::test]
async fn empty_operator_catalog_keeps_advisory_collection_independent() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let store = Arc::new(Memory::default());
    let broker =
        Arc::new(BulkBroker::fixture(url::Url::parse("http://127.0.0.1:9").unwrap()).unwrap());
    let corpus = Arc::new(
        NpmCorpus::new(
            store.clone(),
            broker.clone(),
            root.path(),
            NpmConfig {
                enabled: true,
                packages: Vec::new(),
                ..NpmConfig::default()
            },
        )
        .unwrap(),
    );
    retained_advisory_job(&corpus, &store).await;
    let cancel = CancellationToken::new();
    let worker = {
        let corpus = corpus.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move { corpus.run(cancel).await })
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if store
                .npm_state("default-advisories")
                .await
                .unwrap()
                .is_some()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    cancel.cancel();
    worker.await.unwrap().unwrap();
    assert!(store.npm_state("default-research").await.unwrap().is_none());
    assert!(store.npm_state("package-rotation").await.unwrap().is_none());
    assert_eq!(broker.attempt_count(), 0);
}

#[tokio::test]
async fn incomplete_or_cancelled_export_does_not_publish_a_default() {
    for cancel_before_open in [false, true] {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let store = Arc::new(Memory::default());
        let broker =
            Arc::new(BulkBroker::fixture(url::Url::parse("http://127.0.0.1:9").unwrap()).unwrap());
        let corpus = corpus(store.clone(), broker.clone(), root.path());
        let (mut job, _) = retained_advisory_job(&corpus, &store).await;
        if !cancel_before_open {
            job["artifact"] = serde_json::to_value(
                corpus
                    .raw
                    .capture_bytes(b"truncated ZIP fixture".to_vec(), CancellationToken::new())
                    .await
                    .unwrap(),
            )
            .unwrap();
            store.npm_set_state("advisory-job", &job).await.unwrap();
        }
        let cancel = CancellationToken::new();
        if cancel_before_open {
            cancel.cancel();
        }
        assert!(corpus.collect_advisories(cancel).await.is_err());
        assert_eq!(store.npm_state("advisory-job").await.unwrap().unwrap(), job);
        assert!(
            store
                .npm_state("default-advisories")
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(broker.attempt_count(), 0);
    }
}

#[tokio::test]
async fn failed_diagnostic_storage_preserves_the_original_collection_error() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let store = Arc::new(Memory::default());
    let broker =
        Arc::new(BulkBroker::fixture(url::Url::parse("http://127.0.0.1:9").unwrap()).unwrap());
    let corpus = corpus(store.clone(), broker.clone(), root.path());
    let (job, _) = retained_advisory_job(&corpus, &store).await;
    *store.1.lock().await = Some("advisories");
    store.2.store(true, Ordering::SeqCst);
    let error = corpus
        .collect_advisories(CancellationToken::new())
        .await
        .unwrap_err();
    assert_eq!(error.code, "unavailable");
    assert_eq!(error.message, "Fixture interrupted operation.");
    assert_eq!(
        error.details.unwrap()["private"],
        "never-copy-this-fixture-body"
    );
    assert!(
        store
            .npm_state("diagnostics-advisories")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(store.npm_state("advisory-job").await.unwrap().unwrap(), job);
    assert_eq!(broker.attempt_count(), 0);
}

#[tokio::test]
async fn advisory_backoff_and_fresh_default_preserve_failure_and_progress_history() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let store = Arc::new(Memory::default());
    let broker =
        Arc::new(BulkBroker::fixture(url::Url::parse("http://127.0.0.1:9").unwrap()).unwrap());
    let corpus = corpus(store.clone(), broker.clone(), root.path());
    retained_advisory_job(&corpus, &store).await;
    *store.1.lock().await = Some("publication");
    assert!(
        corpus
            .collect_advisories(CancellationToken::new())
            .await
            .is_err()
    );
    let failed = store
        .npm_state("diagnostics-advisories")
        .await
        .unwrap()
        .unwrap();
    store
        .npm_set_state("advisory-retry", &json!(devres_domain::unix_now() + 60))
        .await
        .unwrap();
    corpus
        .collect_advisories(CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(
        store
            .npm_state("diagnostics-advisories")
            .await
            .unwrap()
            .unwrap(),
        failed
    );
    store
        .npm_set_state("advisory-retry", &json!(0))
        .await
        .unwrap();
    corpus
        .collect_advisories(CancellationToken::new())
        .await
        .unwrap();
    let succeeded = store
        .npm_state("diagnostics-advisories")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(succeeded["last_failure"], failed["last_failure"]);
    assert_eq!(succeeded["last_progress"], failed["last_progress"]);
    corpus
        .collect_advisories(CancellationToken::new())
        .await
        .unwrap();
    let idle = store
        .npm_state("diagnostics-advisories")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(idle["outcome"], "yielded");
    assert_eq!(idle["last_failure"], failed["last_failure"]);
    assert_eq!(idle["last_progress"], failed["last_progress"]);
    assert_eq!(idle["last_success"], succeeded["last_success"]);
    assert_eq!(broker.attempt_count(), 0);
}

#[tokio::test]
async fn retained_artifact_open_failure_resumes_after_exact_bytes_return() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let store = Arc::new(Memory::default());
    let broker =
        Arc::new(BulkBroker::fixture(url::Url::parse("http://127.0.0.1:9").unwrap()).unwrap());
    let corpus = corpus(store.clone(), broker.clone(), root.path());
    let (job, _) = retained_advisory_job(&corpus, &store).await;
    let path = root
        .path()
        .join("npm/raw-artifacts")
        .join(job["artifact"]["relative_path"].as_str().unwrap());
    let parked = root.path().join("parked-fixture-export");
    std::fs::rename(&path, &parked).unwrap();
    assert!(
        corpus
            .collect_advisories(CancellationToken::new())
            .await
            .is_err()
    );
    let diagnostic = store
        .npm_state("diagnostics-advisories")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(diagnostic["stage"], "materialization");
    assert_eq!(
        diagnostic["job"]["artifact_capture"],
        job["artifact"]["body_hash"]
    );
    assert_eq!(store.npm_state("advisory-job").await.unwrap().unwrap(), job);
    assert!(
        store
            .npm_state("default-advisories")
            .await
            .unwrap()
            .is_none()
    );
    std::fs::rename(&parked, &path).unwrap();
    corpus
        .collect_advisories(CancellationToken::new())
        .await
        .unwrap();
    assert!(
        store
            .npm_state("default-advisories")
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(broker.attempt_count(), 0);
}

#[tokio::test]
async fn fully_scanned_malformed_matching_and_rights_gaps_publish_honest_coverage() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let store = Arc::new(Memory::default());
    let broker =
        Arc::new(BulkBroker::fixture(url::Url::parse("http://127.0.0.1:9").unwrap()).unwrap());
    let corpus = corpus(store.clone(), broker.clone(), root.path());
    let (mut job, _) = retained_advisory_job(&corpus, &store).await;
    let (_, supported) = advisory_export();
    let mut rights: Value = serde_json::from_slice(&supported).unwrap();
    rights["id"] = json!("UNKNOWN-123");
    let mut unsupported: Value = serde_json::from_slice(&supported).unwrap();
    unsupported["id"] = json!("GHSA-3456-789c-fghj");
    unsupported["schema_version"] = json!("2.0.0");
    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (name, bytes) in [
        ("supported.json", supported),
        ("rights.json", serde_json::to_vec(&rights).unwrap()),
        (
            "unsupported.json",
            serde_json::to_vec(&unsupported).unwrap(),
        ),
        ("malformed.json", b"{invalid JSON".to_vec()),
    ] {
        writer
            .start_file(name, zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(&bytes).unwrap();
    }
    let bytes = writer.finish().unwrap().into_inner();
    job["artifact"] = serde_json::to_value(
        corpus
            .raw
            .capture_bytes(bytes, CancellationToken::new())
            .await
            .unwrap(),
    )
    .unwrap();
    store.npm_set_state("advisory-job", &job).await.unwrap();
    corpus
        .collect_advisories(CancellationToken::new())
        .await
        .unwrap();
    let published = store
        .npm_state("default-advisories")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(published["complete"], false);
    assert_eq!(published["records"], 3);
    assert_eq!(published["gaps"], 3);
    assert_eq!(
        store.npm_state("advisory-job").await.unwrap().unwrap()["next"],
        4
    );
    assert_eq!(
        store
            .npm_rows("advisory-raw", 0, 10, None, None)
            .await
            .unwrap()
            .len(),
        2
    );
    assert_eq!(broker.attempt_count(), 0);
}

#[tokio::test(start_paused = true)]
async fn stalled_diagnostic_write_observes_its_budget_and_preserves_source_error() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let store = Arc::new(Memory::default());
    let broker =
        Arc::new(BulkBroker::fixture(url::Url::parse("http://127.0.0.1:9").unwrap()).unwrap());
    let corpus = corpus(store.clone(), broker.clone(), root.path());
    let (job, _) = retained_advisory_job(&corpus, &store).await;
    *store.1.lock().await = Some("advisories");
    store.3.store(true, Ordering::SeqCst);
    let started = tokio::time::Instant::now();
    let error = corpus
        .collect_advisories(CancellationToken::new())
        .await
        .unwrap_err();
    assert_eq!(started.elapsed(), DIAGNOSTIC_TIMEOUT);
    assert_eq!(error.code, "unavailable");
    assert_eq!(error.message, "Fixture interrupted operation.");
    assert_eq!(
        error.details.unwrap()["private"],
        "never-copy-this-fixture-body"
    );
    assert_eq!(store.npm_state("advisory-job").await.unwrap().unwrap(), job);
    assert!(store.0.try_lock().is_ok());
    assert_eq!(broker.attempt_count(), 0);
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL; run scripts/test-postgres.sh"]
async fn npm_advisory_diagnostic_row_lock_preserves_source_error_and_owner_reuse() {
    use sqlx_core::connection::Connection as _;
    let base = std::env::var("DEVRES_TEST_DATABASE_URL").unwrap();
    let admin = sqlx_postgres::PgPool::connect(&base).await.unwrap();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let database = format!("devres_npm_diagnostic_{}_{nonce}", std::process::id());
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
        crate::PgBlobStore::connect(url.as_str(), root.path())
            .await
            .unwrap(),
    );
    let broker =
        Arc::new(BulkBroker::fixture(url::Url::parse("http://127.0.0.1:9").unwrap()).unwrap());
    let corpus = NpmCorpus::new(
        store.clone(),
        broker.clone(),
        root.path(),
        NpmConfig {
            enabled: false,
            packages: Vec::new(),
            ..NpmConfig::default()
        },
    )
    .unwrap();
    let (export, _) = advisory_export();
    let artifact = corpus
        .raw
        .capture_bytes(export, CancellationToken::new())
        .await
        .unwrap();
    let job = json!({"snapshot":digest(b"postgres advisory acquisition"),"artifact":artifact,"validated_at":devres_domain::unix_now(),"next":0,"records":0,"gaps":0,"done":false});
    store.npm_set_state("advisory-job", &job).await.unwrap();
    let mut attempt = Attempt::begin(None);
    store
        .npm_set_state("diagnostics-advisories", &attempt.value().unwrap())
        .await
        .unwrap();
    let original = root
        .path()
        .join("npm/raw-artifacts")
        .join(&artifact.relative_path);
    let parked = root.path().join("parked-postgres-export");
    std::fs::rename(&original, &parked).unwrap();
    let source_error = match corpus
        .raw
        .open(
            &artifact.body_hash,
            crate::bulk::MAX_ARTIFACT_BYTES,
            CancellationToken::new(),
        )
        .await
    {
        Ok(_) => panic!("missing fixture artifact unexpectedly opened"),
        Err(error) => error,
    };
    let (before_statement, before_lock) = {
        let mut owner = store.owner.lock().await;
        sqlx_core::raw_sql::raw_sql("SET statement_timeout='13s'; SET lock_timeout='11s'")
            .execute(&mut *owner)
            .await
            .unwrap();
        let statement: String = sqlx_core::query_scalar::query_scalar("SHOW statement_timeout")
            .fetch_one(&mut *owner)
            .await
            .unwrap();
        let lock: String = sqlx_core::query_scalar::query_scalar("SHOW lock_timeout")
            .fetch_one(&mut *owner)
            .await
            .unwrap();
        (statement, lock)
    };
    let mut locker = store.pool.begin().await.unwrap();
    sqlx_core::query::query(
        "SELECT key FROM devres_npm_state WHERE key='diagnostics-advisories' FOR UPDATE",
    )
    .fetch_one(&mut *locker)
    .await
    .unwrap();
    let error = tokio::time::timeout(
        Duration::from_secs(5),
        corpus.collect_advisories(CancellationToken::new()),
    )
    .await
    .expect("optional diagnostic row lock must not stall collection")
    .unwrap_err();
    assert_eq!(error.code, source_error.code);
    assert_eq!(error.message, source_error.message);
    assert_eq!(error.details, source_error.details);
    // The diagnostic row lock remains held: the owner must already have drained
    // the failed statement, rolled back, and restored transaction-local GUCs.
    tokio::time::timeout(
        Duration::from_secs(2),
        store.npm_set_state("diagnostic-owner-reuse", &json!({"verified":true})),
    )
    .await
    .expect("primary owner must remain usable while diagnostic lock is held")
    .unwrap();
    {
        let mut owner = store.owner.lock().await;
        owner.ping().await.unwrap();
        let statement: String = sqlx_core::query_scalar::query_scalar("SHOW statement_timeout")
            .fetch_one(&mut *owner)
            .await
            .unwrap();
        let lock: String = sqlx_core::query_scalar::query_scalar("SHOW lock_timeout")
            .fetch_one(&mut *owner)
            .await
            .unwrap();
        assert_eq!(statement, before_statement);
        assert_eq!(lock, before_lock);
    }
    assert_eq!(store.npm_state("advisory-job").await.unwrap().unwrap(), job);
    assert!(
        store
            .npm_state("default-advisories")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(broker.attempt_count(), 0);
    locker.rollback().await.unwrap();
    std::fs::rename(&parked, &original).unwrap();
    corpus
        .collect_advisories(CancellationToken::new())
        .await
        .unwrap();
    assert!(
        store
            .npm_state("default-advisories")
            .await
            .unwrap()
            .is_some()
    );
    drop(corpus);
    store.pool.close().await;
    drop(store);
    sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!(
        "DROP DATABASE {database} WITH (FORCE)"
    )))
    .execute(&admin)
    .await
    .unwrap();
    admin.close().await;
}
