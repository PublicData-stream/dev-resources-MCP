#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires disposable DEVRES_TEST_DATABASE_URL PostgreSQL"]
async fn npm_acquisition_terminal_failures_preserve_unrelated_terminal_history() {
    for (label, response, code) in [
        (
            "capacity",
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/zip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                crate::bulk::MAX_ARTIFACT_BYTES + 1
            ),
            "capacity",
        ),
        (
            "integrity",
            "HTTP/1.1 304 Not Modified\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
            "integrity",
        ),
    ] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut connection, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 8192];
            let _ = tokio::io::AsyncReadExt::read(&mut connection, &mut request)
                .await
                .unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut connection, response.as_bytes())
                .await
                .unwrap();
            tokio::io::AsyncWriteExt::shutdown(&mut connection)
                .await
                .unwrap();
        });
        let base = std::env::var("DEVRES_TEST_DATABASE_URL").unwrap();
        let admin = sqlx_postgres::PgPool::connect(&base).await.unwrap();
        let name = format!("devres_npm_provenance_{label}_{}", std::process::id());
        sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!(
            "CREATE DATABASE {name}"
        )))
        .execute(&admin)
        .await
        .unwrap();
        let mut url = url::Url::parse(&base).unwrap();
        url.set_path(&format!("/{name}"));
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let store = Arc::new(
            crate::PgBlobStore::connect(url.as_str(), root.path())
                .await
                .unwrap(),
        );
        let broker = Arc::new(
            BulkBroker::fixture(url::Url::parse(&format!("http://{address}")).unwrap()).unwrap(),
        );
        let corpus = NpmCorpus::new(
            store.clone(),
            broker,
            root.path(),
            NpmConfig {
                enabled: false,
                ..NpmConfig::default()
            },
        )
        .unwrap();
        let (bytes, _) = advisory_export();
        let artifact = corpus
            .raw
            .capture_bytes(bytes, CancellationToken::new())
            .await
            .unwrap();
        let old = json!({"snapshot":digest(label.as_bytes()),"artifact":artifact,"validated_at":devres_domain::unix_now(),"next":0,"records":0,"gaps":0,"expanded":0,"done":true,"failed":"capacity","processor_version":PROCESSOR_VERSION,"failure_context":{"version":1,"code":"capacity","materialization_deadline":true}});
        store.npm_set_state("advisory-job", &old).await.unwrap();
        // The persisted previous attempt matches the old subject exactly. The
        // new acquisition must still have no active selected job provenance.
        let mut prior = Attempt::begin(None);
        prior.progress(&old).unwrap();
        prior.stage(Stage::Materialization);
        prior.fail(&Error::capacity("old selected attempt"));
        store
            .npm_set_state("diagnostics-advisories", &prior.value().unwrap())
            .await
            .unwrap();
        let history = || {
            sqlx_core::query_as::query_as::<_,(i64,String,sqlx_core::types::Json<Value>,String)>("SELECT revision,state_digest,data,data_integrity FROM devres_npm_advisory_job_history WHERE job_id=$1 ORDER BY revision").bind(old["snapshot"].as_str().unwrap())
        };
        let before = history().fetch_all(&store.pool).await.unwrap();
        let error = corpus
            .collect_advisories(CancellationToken::new())
            .await
            .unwrap_err();
        assert_eq!(error.code, code);
        corpus
            .record_failure("advisories", None, &error)
            .await
            .unwrap();
        assert_eq!(
            store.npm_state("advisory-job").await.unwrap(),
            Some(old.clone())
        );
        assert_eq!(history().fetch_all(&store.pool).await.unwrap(), before);
        let diagnostic = store
            .npm_state("diagnostics-advisories")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(diagnostic["stage"], "acquisition");
        assert!(diagnostic["job"].is_null());
        assert!(diagnostic["last_failure"]["job"].is_null());
        assert_eq!(
            diagnostic["last_progress"]["job"]["snapshot"],
            old["snapshot"]
        );
        server.await.unwrap();
    }
}

#[tokio::test]
async fn npm_live_attempt_refuses_changed_checkpoint_before_terminal_cause_write() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let store = Arc::new(Memory::default());
    let broker =
        Arc::new(BulkBroker::fixture(url::Url::parse("http://127.0.0.1:9").unwrap()).unwrap());
    let corpus = corpus(store.clone(), broker, root.path());
    let (job, _) = retained_advisory_job(&corpus, &store).await;
    let mut active = Attempt::begin(None);
    active.checkpoint(&job).unwrap();
    active.stage(Stage::Scanner);
    let mut advanced = job.clone();
    advanced["next"] = json!(1);
    store
        .npm_set_state("advisory-job", &advanced)
        .await
        .unwrap();
    corpus
        .fail_active_advisory_job(
            &mut active,
            &Error::integrity("uncertain checkpoint failure"),
        )
        .await
        .unwrap();
    corpus
        .record_failure(
            "advisories",
            None,
            &Error::integrity("uncertain checkpoint failure"),
        )
        .await
        .unwrap();
    assert_eq!(
        store.npm_state("advisory-job").await.unwrap(),
        Some(advanced)
    );
}
