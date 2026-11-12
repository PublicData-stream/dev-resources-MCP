//! Concurrent evidence readers hold lifecycle authority, never publication authority.
use super::*;

impl PgBlobStore {
    pub(super) async fn attach_reader(
        selected_root: &Path,
        s3: Option<crate::object_storage::S3Config>,
        pool: PgPool,
        mut owner: PgConnection,
        owner_pid: i32,
        owner_started: String,
    ) -> Result<Self> {
        let mut tx = owner.begin().await.map_err(|_| storage_error())?;
        let version: i32 = sqlx_core::query_scalar::query_scalar(
            "SELECT version FROM devres_schema WHERE singleton",
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| storage_error())?;
        if version != 15 {
            return Err(Error::unavailable(
                "Concurrent serving requires storage schema fifteen.",
            ));
        }
        let active: bool = sqlx_core::query_scalar::query_scalar(
            "SELECT active FROM devres_integrity_control WHERE singleton",
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| storage_error())?;
        if !active {
            return Err(Error::unavailable("Storage activation is incomplete."));
        }
        attribution_storage::verify_supported_control(&mut tx).await?;
        let valid: bool = sqlx_core::query_scalar::query_scalar("SELECT backend=$1 AND pending_binding IS NULL AND NOT initializing_s3 FROM devres_archive_control WHERE singleton")
            .bind(if s3.is_some() { "s3" } else { "filesystem" })
            .fetch_one(&mut *tx).await.map_err(|_| storage_error())?;
        if !valid {
            return Err(Error::unavailable(
                "Committed archive configuration required.",
            ));
        }
        tx.commit().await.map_err(|_| storage_error())?;
        if s3.is_some() {
            tokio::fs::create_dir_all(selected_root)
                .await
                .map_err(|_| storage_error())?;
        }
        let root = tokio::fs::canonicalize(selected_root)
            .await
            .map_err(|_| storage_error())?;
        let store = Self {
            pool,
            active: AtomicBool::new(true),
            reader: true,
            lifecycle_shared: true,
            visibility: tokio::sync::OnceCell::new(),
            enrichment_membership: Mutex::new(std::collections::BTreeSet::new()),
            root,
            read_budget: Arc::new(Semaphore::new(128)),
            owner: Arc::new(Mutex::new(owner)),
            archive: std::sync::OnceLock::new(),
            owner_pid,
            owner_started,
            artifact_budget: std::sync::OnceLock::new(),
            attribution_progress: std::sync::Mutex::new(attribution_storage::Progress::default()),
        };
        if let Some(config) = s3 {
            let archive = crate::durable_archive::Archive::attach_reader(
                store.root.clone(),
                config,
                store.pool.clone(),
                store.owner.clone(),
                store.owner_pid,
                store.owner_started.clone(),
            )
            .await?;
            store.archive.set(archive).map_err(|_| storage_error())?;
        }
        store.verify_visibility_registry().await?;
        crate_storage::enrichment_v2::initialize_membership(&store).await?;
        store.check_health().await?;
        Ok(store)
    }

    pub(super) async fn lifecycle_fence(&self) -> Result<()> {
        // A pool reconnect must never replace the dedicated session holding this lock.
        let held: bool = sqlx_core::query_scalar::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE l.locktype='advisory' AND l.classid=1835365490 AND l.objid=2 AND l.objsubid=2 AND l.granted AND l.mode=$3 AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND a.pid=$1 AND EXTRACT(EPOCH FROM a.backend_start)::text=$2)")
            .bind(self.owner_pid).bind(&self.owner_started)
            .bind(if self.lifecycle_shared { "ShareLock" } else { "ExclusiveLock" })
            .fetch_one(&self.pool).await.map_err(|_| storage_error())?;
        if !held {
            return Err(Error::unavailable(
                "Storage lifecycle ownership lost; restart required",
            ));
        }
        if self.reader {
            let supported: bool = sqlx_core::query_scalar::query_scalar("SELECT version=15 AND (SELECT active FROM devres_integrity_control WHERE singleton) AND to_regclass('public.devres_archive_restore_pending') IS NULL FROM devres_schema WHERE singleton")
                .fetch_one(&self.pool).await.map_err(|_| storage_error())?;
            if !supported {
                return Err(Error::unavailable(
                    "Reader storage state changed; restart required",
                ));
            }
            if self.archive.get().is_none() {
                let local: bool = sqlx_core::query_scalar::query_scalar("SELECT backend='filesystem' AND pending_binding IS NULL AND NOT initializing_s3 FROM devres_archive_control WHERE singleton")
                    .fetch_one(&self.pool).await.map_err(|_| storage_error())?;
                if !local {
                    return Err(Error::unavailable(
                        "Reader archive backend changed; restart required",
                    ));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s3_fixture_configs(
        suffix: &str,
    ) -> (
        crate::object_storage::S3Config,
        crate::object_storage::S3Config,
    ) {
        let path = std::env::var_os("DEVRES_TEST_S3_CONFIG")
            .expect("disposable S3 writer configuration required");
        let mut writer: crate::object_storage::S3Config =
            toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let mut reader = std::env::var_os("DEVRES_TEST_S3_READER_CONFIG").map_or_else(
            || writer.clone(),
            |path| toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap(),
        );
        writer.prefix.push_str(suffix);
        reader.prefix.push_str(suffix);
        assert_eq!(
            crate::durable_archive::config_binding(&writer).unwrap(),
            crate::durable_archive::config_binding(&reader).unwrap(),
            "fixture role credentials must address the same archive"
        );
        (writer, reader)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires disposable PostgreSQL; run scripts/test-postgres.sh"]
    async fn concurrent_filesystem_reader_has_no_publication_or_maintenance_authority() {
        let base = std::env::var("DEVRES_TEST_DATABASE_URL").expect("disposable database required");
        let admin = PgPool::connect(&base).await.unwrap();
        sqlx_core::query::query("CREATE DATABASE devres_reader_fixture")
            .execute(&admin)
            .await
            .unwrap();
        let mut writer_url = url::Url::parse(&base).unwrap();
        writer_url.set_path("/devres_reader_fixture");
        let root = tempfile::tempdir().unwrap();
        let writer = PgBlobStore::connect(writer_url.as_str(), root.path())
            .await
            .unwrap();
        sqlx_core::raw_sql::raw_sql("CREATE ROLE devres_reader_fixture LOGIN PASSWORD 'disposable-reader'; GRANT CONNECT ON DATABASE devres_reader_fixture TO devres_reader_fixture;")
            .execute(&admin).await.unwrap();
        sqlx_core::raw_sql::raw_sql("GRANT USAGE ON SCHEMA public TO devres_reader_fixture; GRANT SELECT ON ALL TABLES IN SCHEMA public TO devres_reader_fixture;")
            .execute(&writer.pool).await.unwrap();
        let mut reader_url = writer_url.clone();
        reader_url.set_username("devres_reader_fixture").unwrap();
        reader_url.set_password(Some("disposable-reader")).unwrap();
        let reader = PgBlobStore::connect_reader(reader_url.as_str(), root.path(), None)
            .await
            .unwrap();
        assert!(reader.is_reader());
        assert!(!writer.is_reader());
        assert!(
            sqlx_core::query::query("UPDATE devres_schema SET version=12")
                .execute(&reader.pool)
                .await
                .is_err()
        );
        let request = FetchRequest {
            key: "fixture:reader".into(),
            url: "https://fixtures.invalid/reader".into(),
            ttl_secs: 60,
            max_bytes: 128,
            media_type: "text/plain".into(),
        };
        let response = || FetchResponse {
            status: 200,
            body: b"committed public evidence".to_vec(),
            validators: Validators::default(),
        };
        assert!(reader.publish(&request, response(), 10).await.is_err());
        let captured = writer.publish(&request, response(), 10).await.unwrap();
        assert_eq!(
            &*reader.capture(&captured.capture.id).await.unwrap().body,
            b"committed public evidence"
        );
        assert!(
            reader
                .revalidate(
                    &request.key,
                    &captured.capture.id,
                    Validators::default(),
                    20
                )
                .await
                .is_err()
        );
        assert!(
            PgBlobStore::connect(writer_url.as_str(), root.path())
                .await
                .is_err()
        );
        assert!(
            PgBlobStore::connect_for_verification(writer_url.as_str(), root.path())
                .await
                .is_err()
        );
        assert!(
            PgBlobStore::connect_archive_for_maintenance(writer_url.as_str(), root.path(), None)
                .await
                .is_err()
        );
        let second_reader = PgBlobStore::connect_reader(reader_url.as_str(), root.path(), None)
            .await
            .unwrap();
        let pid = reader.owner_pid;
        sqlx_core::query::query("SELECT pg_terminate_backend($1)")
            .bind(pid)
            .execute(&admin)
            .await
            .unwrap();
        assert!(reader.check_ownership().await.is_err());
        assert!(reader.capture(&captured.capture.id).await.is_err());
        assert!(writer.check_health().await.is_ok());
        drop(reader);
        let writer_pid = writer.owner_pid;
        sqlx_core::query::query("SELECT pg_terminate_backend($1)")
            .bind(writer_pid)
            .execute(&admin)
            .await
            .unwrap();
        assert!(writer.check_health().await.is_err());
        assert!(second_reader.check_health().await.is_ok());
        assert!(
            PgBlobStore::connect_archive_for_maintenance(writer_url.as_str(), root.path(), None)
                .await
                .is_err()
        );
        assert_eq!(
            &*second_reader
                .capture(&captured.capture.id)
                .await
                .unwrap()
                .body,
            b"committed public evidence"
        );
        assert!(
            PgBlobStore::connect_for_verification(writer_url.as_str(), root.path())
                .await
                .is_err()
        );
        assert!(
            PgBlobStore::connect_archive_for_maintenance(writer_url.as_str(), root.path(), None)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    #[ignore = "requires disposable PostgreSQL; run scripts/test-postgres.sh"]
    async fn reader_refuses_legacy_schema_and_pending_restore() {
        let base = std::env::var("DEVRES_TEST_DATABASE_URL").expect("disposable database required");
        let admin = PgPool::connect(&base).await.unwrap();
        sqlx_core::query::query("CREATE DATABASE devres_reader_admission_fixture")
            .execute(&admin)
            .await
            .unwrap();
        let mut url = url::Url::parse(&base).unwrap();
        url.set_path("/devres_reader_admission_fixture");
        let root = tempfile::tempdir().unwrap();
        let writer = PgBlobStore::connect(url.as_str(), root.path())
            .await
            .unwrap();
        sqlx_core::query::query("UPDATE devres_schema SET version=12 WHERE singleton")
            .execute(&writer.pool)
            .await
            .unwrap();
        assert!(
            PgBlobStore::connect_reader(url.as_str(), root.path(), None)
                .await
                .is_err()
        );
        sqlx_core::query::query("UPDATE devres_schema SET version=15 WHERE singleton")
            .execute(&writer.pool)
            .await
            .unwrap();
        sqlx_core::query::query("CREATE TABLE devres_archive_restore_pending(singleton boolean)")
            .execute(&writer.pool)
            .await
            .unwrap();
        assert!(
            PgBlobStore::connect_reader(url.as_str(), root.path(), None)
                .await
                .is_err()
        );
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires disposable PostgreSQL and RustFS; run scripts/test-s3.sh"]
    async fn s3_committed_reopen_and_verification_preserve_reader_admission() {
        let base = std::env::var("DEVRES_TEST_DATABASE_URL").expect("disposable database required");
        let (config, reader_config) = s3_fixture_configs("/committed-reopen");
        let admin = PgPool::connect(&base).await.unwrap();
        sqlx_core::query::query("CREATE DATABASE devres_s3_reopen_fixture")
            .execute(&admin)
            .await
            .unwrap();
        let mut url = url::Url::parse(&base).unwrap();
        url.set_path("/devres_s3_reopen_fixture");
        let root = tempfile::tempdir().unwrap();
        let writer = PgBlobStore::connect_archive(url.as_str(), root.path(), Some(config.clone()))
            .await
            .unwrap();
        let request = FetchRequest {
            key: "fixture:s3-reopen".into(),
            url: "https://fixtures.invalid/s3-reopen".into(),
            ttl_secs: 60,
            max_bytes: 128,
            media_type: "text/plain".into(),
        };
        let captured = writer
            .publish(
                &request,
                FetchResponse {
                    status: 200,
                    body: b"retained across committed reopen".to_vec(),
                    validators: Validators::default(),
                },
                10,
            )
            .await
            .unwrap();
        let committed: (i64, String) = sqlx_core::query_as::query_as(
            "SELECT epoch,binding FROM devres_archive_control WHERE singleton AND backend='s3' AND pending_binding IS NULL AND NOT initializing_s3",
        ).fetch_one(&writer.pool).await.unwrap();
        drop(writer);
        // Ordinary restarts and offline publication (such as storage-probe) must
        // preserve exactly the committed binding rather than begin a transfer.
        for maintenance in [false, true, false] {
            let writer = if maintenance {
                PgBlobStore::connect_archive_for_maintenance(
                    url.as_str(),
                    root.path(),
                    Some(config.clone()),
                )
                .await
                .unwrap()
            } else {
                PgBlobStore::connect_archive(url.as_str(), root.path(), Some(config.clone()))
                    .await
                    .unwrap()
            };
            let control: (i64, String) = sqlx_core::query_as::query_as(
                "SELECT epoch,binding FROM devres_archive_control WHERE singleton AND pending_binding IS NULL AND NOT initializing_s3",
            ).fetch_one(&writer.pool).await.unwrap();
            assert_eq!(control, committed);
            if !maintenance {
                let cold = tempfile::tempdir().unwrap();
                let reader = PgBlobStore::connect_reader(
                    url.as_str(),
                    cold.path(),
                    Some(reader_config.clone()),
                )
                .await
                .unwrap();
                assert_eq!(
                    &*reader.capture(&captured.capture.id).await.unwrap().body,
                    b"retained across committed reopen"
                );
            }
        }
        let transfer = Arc::new(
            PgBlobStore::connect_for_object_transfer(url.as_str(), root.path(), config.clone())
                .await
                .unwrap(),
        );
        transfer
            .transfer_object_archive(
                "verify-object-storage",
                tokio_util::sync::CancellationToken::new(),
            )
            .await
            .unwrap();
        drop(transfer);
        let cold = tempfile::tempdir().unwrap();
        let reader =
            PgBlobStore::connect_reader(url.as_str(), cold.path(), Some(reader_config.clone()))
                .await
                .unwrap();
        assert_eq!(
            &*reader.capture(&captured.capture.id).await.unwrap().body,
            b"retained across committed reopen"
        );
        let pool = PgPool::connect(url.as_str()).await.unwrap();
        drop(reader);
        // An ambiguous preexisting transition is never committed by reopening.
        for initializing in [false, true] {
            sqlx_core::query::query("UPDATE devres_archive_control SET pending_binding=binding,initializing_s3=$1 WHERE singleton")
                .bind(initializing).execute(&pool).await.unwrap();
            let writer =
                PgBlobStore::connect_archive(url.as_str(), root.path(), Some(config.clone()))
                    .await
                    .unwrap();
            let pending: (Option<String>, bool) = sqlx_core::query_as::query_as(
                "SELECT pending_binding,initializing_s3 FROM devres_archive_control WHERE singleton",
            ).fetch_one(&pool).await.unwrap();
            assert_eq!(pending, (Some(committed.1.clone()), initializing));
            let cold = tempfile::tempdir().unwrap();
            assert!(
                PgBlobStore::connect_reader(url.as_str(), cold.path(), Some(reader_config.clone()))
                    .await
                    .is_err()
            );
            drop(writer);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires disposable PostgreSQL and RustFS; run scripts/test-s3.sh"]
    async fn s3_concurrent_reader_cold_cache_observes_only_committed_writer_publication() {
        let base = std::env::var("DEVRES_TEST_DATABASE_URL").expect("disposable database required");
        let (config, reader_config) = s3_fixture_configs("/reader-isolation");
        let admin = PgPool::connect(&base).await.unwrap();
        sqlx_core::query::query("CREATE DATABASE devres_s3_reader_fixture")
            .execute(&admin)
            .await
            .unwrap();
        let mut writer_url = url::Url::parse(&base).unwrap();
        writer_url.set_path("/devres_s3_reader_fixture");
        let writer_root = tempfile::tempdir().unwrap();
        let writer = PgBlobStore::connect_archive(
            writer_url.as_str(),
            writer_root.path(),
            Some(config.clone()),
        )
        .await
        .unwrap();
        sqlx_core::query::query(
            "CREATE ROLE devres_s3_reader_fixture LOGIN PASSWORD 'disposable-reader'",
        )
        .execute(&admin)
        .await
        .unwrap();
        sqlx_core::raw_sql::raw_sql("GRANT CONNECT ON DATABASE devres_s3_reader_fixture TO devres_s3_reader_fixture; GRANT USAGE ON SCHEMA public TO devres_s3_reader_fixture; GRANT SELECT ON ALL TABLES IN SCHEMA public TO devres_s3_reader_fixture;")
            .execute(&writer.pool).await.unwrap();
        let mut reader_url = writer_url.clone();
        reader_url.set_username("devres_s3_reader_fixture").unwrap();
        reader_url.set_password(Some("disposable-reader")).unwrap();
        let index = crate::npm::index::NpmIndex::new(writer_root.path()).unwrap();
        let document_id = hash(b"reader nested immutable search document");
        let index_reference = index
            .publish(
                None,
                vec![crate::npm::index::IndexDocument {
                    id: document_id.clone(),
                    name: "fixture-package".into(),
                    version: "1.0.0".into(),
                    path: "README.md".into(),
                    title: "Fixture package".into(),
                    text: "immutable transport evidence".into(),
                    kind: "section".into(),
                    metadata: serde_json::json!({}),
                }],
                tokio_util::sync::CancellationToken::new(),
            )
            .await
            .unwrap();
        let cache = tempfile::tempdir().unwrap();
        let reader =
            PgBlobStore::connect_reader(reader_url.as_str(), cache.path(), Some(reader_config))
                .await
                .unwrap();
        let request = FetchRequest {
            key: "fixture:s3-reader".into(),
            url: "https://fixtures.invalid/s3-reader".into(),
            ttl_secs: 60,
            max_bytes: 128,
            media_type: "text/plain".into(),
        };
        assert!(reader.latest(&request.key).await.unwrap().is_none());
        let captured = writer
            .publish(
                &request,
                FetchResponse {
                    status: 200,
                    body: b"new committed S3 publication".to_vec(),
                    validators: Validators::default(),
                },
                10,
            )
            .await
            .unwrap();
        assert_eq!(
            &*reader.capture(&captured.capture.id).await.unwrap().body,
            b"new committed S3 publication"
        );
        assert_eq!(
            reader
                .latest(&request.key)
                .await
                .unwrap()
                .unwrap()
                .stored
                .capture
                .id,
            captured.capture.id
        );
        assert!(!cache.path().join("npm-search").exists());
        let reader_index = crate::npm::index::NpmIndex::for_verification(cache.path()).unwrap();
        let results = reader_index
            .search(
                &index_reference,
                [document_id].into_iter().collect(),
                crate::npm::index::SearchSpec {
                    query: Some("transport".into()),
                    ..Default::default()
                },
                tokio_util::sync::CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(results["total"], 1);
        assert!(
            reader_index
                .publish(None, Vec::new(), tokio_util::sync::CancellationToken::new())
                .await
                .is_err()
        );
        assert!(reader.owner_fence().await.is_err());
        assert!(
            PgBlobStore::connect_for_verification(writer_url.as_str(), writer_root.path())
                .await
                .is_err()
        );
    }
}
