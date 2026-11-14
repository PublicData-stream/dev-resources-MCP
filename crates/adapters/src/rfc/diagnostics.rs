//! Bounded selected RFC metadata inspection; no engine or serving-cache attachment.
use super::*;
use devres_application::{collection::Failure, corpus::Snapshot};

const MAX_MANIFEST: u64 = 2 * 1024 * 1024;
const MAX_FILES: usize = 10_000;
const MAX_INDEX: u64 = 32 * 1024 * 1024 * 1024;

pub(super) fn rfc_job_identity(key: &str) -> Result<(u32, &str, &str)> {
    let (number, format, assurance) = if let Some(number) = key.strip_prefix("rfc:text:") {
        (number, "txt", "https")
    } else if let Some(value) = key.strip_prefix("rfc:format:") {
        let (number, format) = value.split_once(':').ok_or_else(invalid)?;
        if !matches!(format, "html" | "xml" | "pdf") {
            return Err(invalid());
        }
        (number, format, "https")
    } else if let Some(value) = key.strip_prefix("rfc:rsync:") {
        let (number, format) = value.split_once(':').ok_or_else(invalid)?;
        if !matches!(format, "txt" | "html" | "xml" | "pdf") {
            return Err(invalid());
        }
        (number, format, "rsync")
    } else {
        return Err(invalid());
    };
    let parsed = number.parse::<u32>().map_err(|_| invalid())?;
    if !(1..=999999).contains(&parsed) || number != parsed.to_string() {
        return Err(invalid());
    }
    Ok((parsed, format, assurance))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    files: BTreeMap<String, Member>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Member {
    bytes: u64,
    #[serde(alias = "sha256")]
    digest: String,
}
fn member_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && !name.contains("..")
        && name != "."
        && name != "integrity.json"
        && !name.ends_with(".lock")
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}
fn checked_manifest(bytes: &[u8]) -> Result<Manifest> {
    let manifest: Manifest = serde_json::from_slice(bytes).map_err(|_| failed())?;
    if !matches!(manifest.version, 1 | 2)
        || manifest.files.len() > MAX_FILES
        || !manifest.files.contains_key("meta.json")
    {
        return Err(failed());
    }
    let mut total = 0_u64;
    for (name, member) in &manifest.files {
        if !member_name(name)
            || !integrity::valid_hash(&member.digest)
            || manifest.version == 2 && !member.digest.starts_with("blake3:")
        {
            return Err(failed());
        }
        total = total.checked_add(member.bytes).ok_or_else(failed)?;
        if total > MAX_INDEX {
            return Err(failed());
        }
    }
    Ok(manifest)
}

async fn job(reader: &mut Reader, key: &str, schema: i32) -> Result<Option<Value>> {
    let (number, format, assurance) = rfc_job_identity(key)?;
    let size: Option<i64> = sqlx_core::query_scalar::query_scalar(
        "SELECT octet_length(to_jsonb(j)::text)::bigint FROM devres_rfc_jobs j WHERE source_key=$1",
    )
    .bind(key)
    .fetch_optional(&mut reader.conn)
    .await
    .map_err(|_| unavailable())?;
    let Some(size) = size else { return Ok(None) };
    reader.row_admit(size)?;
    // Only allowlisted columns enter this process; source URLs and capture bodies do not.
    let diagnostic_columns = if schema >= 16 {
        "last_attempt_at,failure"
    } else {
        "NULL::bigint AS last_attempt_at,NULL::jsonb AS failure"
    };
    let sql = format!(
        "SELECT source_key,number,format,assurance,status,attempts,due_at,last_error,capture_id IS NOT NULL AS has_capture,{diagnostic_columns} FROM devres_rfc_jobs WHERE source_key=$1"
    );
    let row = sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(sql))
        .bind(key)
        .fetch_one(&mut reader.conn)
        .await
        .map_err(|_| unavailable())?;
    if row.try_get::<i64, _>("number").map_err(|_| failed())? != i64::from(number)
        || row.try_get::<String, _>("format").map_err(|_| failed())? != format
        || row
            .try_get::<String, _>("assurance")
            .map_err(|_| failed())?
            != assurance
    {
        return Err(failed());
    }
    let status: String = row.try_get("status").map_err(|_| failed())?;
    if !matches!(
        status.as_str(),
        "pending" | "running" | "captured" | "failed"
    ) {
        return Err(failed());
    }
    let attempts: i64 = row.try_get("attempts").map_err(|_| failed())?;
    let attempts = u32::try_from(attempts).map_err(|_| failed())?;
    let error: Option<String> = row.try_get("last_error").map_err(|_| failed())?;
    let value: Option<sqlx_core::types::Json<Value>> =
        row.try_get("failure").map_err(|_| failed())?;
    let failure = value
        .map(|value| {
            if serde_json::to_vec(&value.0).map_err(|_| failed())?.len() > 4096 {
                return Err(failed());
            }
            let mut failure: Failure = serde_json::from_value(value.0).map_err(|_| failed())?;
            if failure
                .http_status
                .is_some_and(|status| !(100..=599).contains(&status))
            {
                return Err(failed());
            }
            failure.code = safe_code(&failure.code).into();
            serde_json::to_value(failure).map_err(|_| failed())
        })
        .transpose()?;
    Ok(Some(json!({
        "key":key,"number":number,"format":format,"assurance":assurance,
        "status":status,"attempts":attempts,"next_due":row.try_get::<i64,_>("due_at").map_err(|_|failed())?,
        "has_capture":row.try_get::<bool,_>("has_capture").map_err(|_|failed())?,
        "last_attempt_at":row.try_get::<Option<i64>,_>("last_attempt_at").map_err(|_|failed())?,
        "error":error.as_deref().map(safe_code),"failure":failure,
        "failure_phase_known":failure.is_some()
    })))
}

/// Check the committed SQL and independent remote descriptor, never the member body.
async fn binding(reader: &mut Reader, path: &str, member: &Member) -> Result<()> {
    checked_relative(path)?;
    reader.budget.admit(16 * 1024)?;
    let row = sqlx_core::query::query("SELECT digest,bytes,evidence FROM devres_archive_file WHERE path=$1 AND complete AND octet_length(evidence)<=16384")
        .bind(path).fetch_optional(&mut reader.conn).await.map_err(|_|unavailable())?
        .ok_or_else(unavailable)?;
    let encoded: String = row.try_get("evidence").map_err(|_| failed())?;
    let binding: ArchiveBinding = serde_json::from_str(&encoded).map_err(|_| failed())?;
    let digest: String = row.try_get("digest").map_err(|_| failed())?;
    let bytes: i64 = row.try_get("bytes").map_err(|_| failed())?;
    if binding.version != 1
        || binding.path != path
        || binding.digest != digest
        || binding.bytes != u64::try_from(bytes).map_err(|_| failed())?
        || binding.bytes != member.bytes
        || !digest.starts_with("blake3:")
        || !integrity::valid_hash(&digest)
        || member.digest.starts_with("blake3:") && digest != member.digest
    {
        return Err(failed());
    }
    let remote = reader.remote.as_ref().ok_or_else(unavailable)?;
    let descriptor = remote
        .get_bytes_with_cancel(
            &format!("bindings/{}.json", blake3::hash(path.as_bytes()).to_hex()),
            16 * 1024,
            &reader.budget.cancel,
        )
        .await?;
    if descriptor != encoded.as_bytes() {
        return Err(failed());
    }
    Ok(())
}

pub(super) async fn inspect_rfc(
    reader: &mut Reader,
    report: &mut CollectionDiagnosis,
    options: &DiagnosisOptions,
) -> Result<()> {
    report.diagnostics.push(json!({"operation":"rfc_metadata","engine_readability":"not_checked","member_bytes":"not_checked","jobs":[],"snapshot":null,"index":null}));
    for key in &options.job_keys {
        match job(reader, key, report.schema).await? {
            Some(job) => report.diagnostics[0]["jobs"]
                .as_array_mut()
                .ok_or_else(failed)?
                .push(job),
            None => {
                report.complete = false;
                report.outcome = DiagnosisOutcome::SelectedEvidenceUnavailable;
                report.diagnostics[0]["jobs"]
                    .as_array_mut()
                    .ok_or_else(failed)?
                    .push(json!({"key":key,"outcome":"not_found"}));
            }
        }
    }
    let id = options.snapshot.as_deref().ok_or_else(invalid)?;
    let size: Option<i64> = sqlx_core::query_scalar::query_scalar(
        "SELECT octet_length(data::text)::bigint FROM devres_rfc_snapshots WHERE id=$1",
    )
    .bind(id)
    .fetch_optional(&mut reader.conn)
    .await
    .map_err(|_| unavailable())?;
    let Some(size) = size else {
        return Err(unavailable());
    };
    reader.row_admit(size)?;
    let row = sqlx_core::query::query("SELECT published_order,catalogue_capture,errata_capture,created_at,complete,''::text AS kind,id AS key,data,data_integrity FROM devres_rfc_snapshots WHERE id=$1")
        .bind(id).fetch_one(&mut reader.conn).await.map_err(|_|unavailable())?;
    let value = payload_integrity::row("devres_rfc_snapshots", &row)?;
    let snapshot: Snapshot = serde_json::from_value(value).map_err(|_| failed())?;
    if snapshot.id != id {
        return Err(failed());
    }
    report.cutoff = row.try_get("published_order").map_err(|_| failed())?;
    report.diagnostics[0]["snapshot"] = json!({"id":snapshot.id,"created_at":snapshot.created_at,"complete":snapshot.complete,"sealed_metadata":"verified","representations":snapshot.documents.len(),"search_representations":snapshot.search_documents.len()});
    let relative = snapshot.index_path.as_deref().ok_or_else(unavailable)?;
    let suffix = relative.strip_prefix("rfc-indexes/").ok_or_else(failed)?;
    let index_id = suffix
        .strip_prefix("blake3/")
        .map_or_else(|| suffix.to_owned(), |hex| format!("blake3:{hex}"));
    if !integrity::valid_hash(&index_id)
        || integrity::relative_path(&index_id)?.to_string_lossy() != suffix
    {
        return Err(failed());
    }
    let bytes = reader
        .file(&format!("{relative}/integrity.json"), MAX_MANIFEST)
        .await?;
    let manifest = checked_manifest(&bytes)?;
    let legacy = manifest
        .files
        .values()
        .any(|member| !member.digest.starts_with("blake3:"));
    report.diagnostics[0]["index"] = json!({"id":index_id,"manifest_digest":integrity::hash(&bytes),"manifest_version":manifest.version,"manifest_shape":"verified","declared_members":manifest.files.len(),"declared_bytes":manifest.files.values().map(|member|member.bytes).sum::<u64>(),"archive_bindings_checked":0,"legacy_member_digests":"not_checked"});
    if reader.remote.is_some() {
        reader.budget.admit(8)?;
        let bound_files: i64 = sqlx_core::query_scalar::query_scalar("SELECT count(*)::bigint FROM (SELECT 1 FROM devres_archive_file WHERE complete AND starts_with(path,$1) LIMIT 10002) files")
            .bind(format!("{relative}/")).fetch_one(&mut reader.conn).await.map_err(|_|unavailable())?;
        if bound_files > MAX_FILES as i64 + 1 {
            return Err(capacity());
        }
        report.diagnostics[0]["index"]["archive_files_including_manifest"] = json!(bound_files);
        if bound_files != manifest.files.len() as i64 + 1 {
            return Err(failed());
        }
        for (name, member) in &manifest.files {
            binding(reader, &format!("{relative}/{name}"), member).await?;
            let checked = report.diagnostics[0]["index"]["archive_bindings_checked"]
                .as_u64()
                .ok_or_else(failed)?;
            report.diagnostics[0]["index"]["archive_bindings_checked"] = json!(checked + 1);
        }
        report.diagnostics[0]["index"]["manifest_archive_binding"] = json!("verified");
        report.diagnostics[0]["index"]["member_bindings"] = json!("verified");
        if legacy {
            report.complete = false;
            report.diagnostics[0]["index"]["legacy_member_digests"] =
                json!("unverified_against_canonical_bindings");
        }
    } else {
        report.diagnostics[0]["index"]["manifest_archive_binding"] =
            json!("not_applicable_filesystem");
        report.diagnostics[0]["index"]["member_bindings"] = json!("not_applicable_filesystem");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use devres_application::{
        Store,
        corpus::{Dataset, JobSpec, RfcCorpusStore},
    };
    use devres_domain::{FetchRequest, FetchResponse, Validators};

    fn options(snapshot: &str) -> DiagnosisOptions {
        DiagnosisOptions {
            provider: DiagnosisProvider::Rfc,
            max_total_bytes: MAX_BYTES,
            timeout_secs: 30,
            scan_retained_dump: false,
            snapshot: Some(snapshot.into()),
            job_keys: vec!["rfc:text:9000".into()],
            commit: None,
            attribution_target: None,
        }
    }

    #[test]
    fn rfc_selectors_and_manifest_shape_are_bounded() {
        let id = integrity::hash(b"selected snapshot");
        let mut options = options(&id);
        assert!(options.validate().is_ok());
        for key in [
            "rfc:text:09000",
            "rfc:text:0",
            "rfc:format:9000:txt",
            "rfc:text:1000000",
            "rfc:format:9000:html/secret",
            "https://private.invalid",
        ] {
            assert!(rfc_job_identity(key).is_err(), "{key}");
        }
        for key in [
            "rfc:text:9000",
            "rfc:format:9000:html",
            "rfc:rsync:9000:txt",
        ] {
            assert!(rfc_job_identity(key).is_ok());
        }
        options.job_keys.push(options.job_keys[0].clone());
        assert!(options.validate().is_err());
        options.job_keys.pop();
        options.provider = DiagnosisProvider::W3c;
        assert!(options.validate().is_err());
        let member = json!({"bytes":1,"digest":integrity::hash(b"x")});
        assert!(
            checked_manifest(
                &serde_json::to_vec(&json!({"version":2,"files":{"meta.json":member}})).unwrap()
            )
            .is_ok()
        );
        for files in [
            json!({"../meta.json":member}),
            json!({"meta.json":member,"bad.lock":member}),
        ] {
            assert!(
                checked_manifest(&serde_json::to_vec(&json!({"version":2,"files":files})).unwrap())
                    .is_err()
            );
        }
    }

    #[tokio::test]
    #[ignore = "requires disposable PostgreSQL; run scripts/test-postgres.sh"]
    async fn selected_rfc_metadata_is_read_only_schema_aware_and_fails_closed() {
        let base = std::env::var("DEVRES_TEST_DATABASE_URL").expect("disposable database required");
        let mut admin = PgConnection::connect(&base).await.unwrap();
        sqlx_core::raw_sql::raw_sql("CREATE DATABASE devres_rfc_diagnosis_fixture")
            .execute(&mut admin)
            .await
            .unwrap();
        let mut url = url::Url::parse(&base).unwrap();
        url.set_path("/devres_rfc_diagnosis_fixture");
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let writer = crate::PgBlobStore::connect(url.as_str(), root.path())
            .await
            .unwrap();
        let captured = writer
            .publish(
                &FetchRequest {
                    key: "rfc:index".into(),
                    url: "https://www.rfc-editor.org/rfc-index.xml".into(),
                    ttl_secs: 60,
                    max_bytes: 1024,
                    media_type: "application/xml".into(),
                },
                FetchResponse {
                    status: 200,
                    body: b"synthetic catalogue".to_vec(),
                    validators: Validators::default(),
                },
                10,
            )
            .await
            .unwrap();
        writer
            .save_dataset(
                "catalogue",
                &Dataset {
                    capture: captured.capture.clone(),
                    records: Vec::new(),
                },
            )
            .await
            .unwrap();
        writer
            .schedule(&[JobSpec {
                key: "rfc:text:9000".into(),
                number: 9000,
                format: "txt".into(),
                source_url: "https://www.rfc-editor.org/rfc/rfc9000.txt".into(),
                assurance: "https".into(),
                due_at: 20,
            }])
            .await
            .unwrap();
        let id = integrity::hash(b"RFC diagnosis snapshot");
        let index_id = integrity::hash(b"RFC diagnosis index");
        let relative = format!(
            "rfc-indexes/{}",
            integrity::relative_path(&index_id)
                .unwrap()
                .to_string_lossy()
        );
        std::fs::create_dir_all(root.path().join(&relative)).unwrap();
        let path = root.path().join(&relative).join("integrity.json");
        std::fs::write(&path,serde_json::to_vec(&json!({"version":2,"files":{"meta.json":{"bytes":17,"digest":integrity::hash(b"not downloaded")}}})).unwrap()).unwrap();
        writer
            .save_snapshot(&Snapshot {
                id: id.clone(),
                catalogue_capture: captured.capture.id,
                errata_capture: None,
                documents: Vec::new(),
                search_documents: Vec::new(),
                coverage: json!({}),
                created_at: 10,
                complete: false,
                index_path: Some(relative),
                processor_version: 1,
            })
            .await
            .unwrap();
        let mut conn = PgConnection::connect(url.as_str()).await.unwrap();
        let failure = json!({"code":"unavailable","observed_at":30,"phase":"source_validation"});
        sqlx_core::query::query("UPDATE devres_rfc_jobs SET status='failed',last_error='secret-upstream-error',last_attempt_at=20,failure=$1")
            .bind(sqlx_core::types::Json(failure)).execute(&mut conn).await.unwrap();
        sqlx_core::raw_sql::raw_sql("CREATE ROLE devres_rfc_diagnosis_reader LOGIN PASSWORD 'disposable-reader'; GRANT USAGE ON SCHEMA public TO devres_rfc_diagnosis_reader; GRANT SELECT ON ALL TABLES IN SCHEMA public TO devres_rfc_diagnosis_reader;")
            .execute(&mut conn).await.unwrap();
        let mut reader_url = url.clone();
        reader_url
            .set_username("devres_rfc_diagnosis_reader")
            .unwrap();
        reader_url.set_password(Some("disposable-reader")).unwrap();
        let selected = options(&id);
        let report = diagnose_collection(
            reader_url.as_str(),
            root.path(),
            None,
            selected.clone(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(report.complete);
        assert_eq!(report.diagnostics[0]["jobs"][0]["error"], "other");
        assert_eq!(
            report.diagnostics[0]["jobs"][0]["failure"]["phase"],
            "source_validation"
        );
        assert_eq!(report.diagnostics[0]["engine_readability"], "not_checked");
        assert!(!serde_json::to_string(&report).unwrap().contains("secret"));
        assert!(
            !path.parent().unwrap().join("meta.json").exists(),
            "metadata inspection must not read or materialize engine members"
        );
        for schema in [14, 15] {
            sqlx_core::query::query("UPDATE devres_schema SET version=$1 WHERE singleton")
                .bind(schema)
                .execute(&mut conn)
                .await
                .unwrap();
            let report = diagnose_collection(
                reader_url.as_str(),
                root.path(),
                None,
                selected.clone(),
                CancellationToken::new(),
            )
            .await
            .unwrap();
            assert_eq!(report.schema, schema);
            assert!(report.diagnostics[0]["jobs"][0]["failure"].is_null());
            assert!(report.diagnostics[0]["jobs"][0]["last_attempt_at"].is_null());
            assert_eq!(
                sqlx_core::query_scalar::query_scalar::<_, i32>(
                    "SELECT version FROM devres_schema WHERE singleton"
                )
                .fetch_one(&mut conn)
                .await
                .unwrap(),
                schema
            );
        }
        sqlx_core::query::query("UPDATE devres_schema SET version=16 WHERE singleton")
            .execute(&mut conn)
            .await
            .unwrap();
        let mut missing = selected.clone();
        missing.job_keys.push("rfc:text:9999".into());
        let report = diagnose_collection(
            reader_url.as_str(),
            root.path(),
            None,
            missing,
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(!report.complete);
        assert_eq!(
            report.outcome,
            DiagnosisOutcome::SelectedEvidenceUnavailable
        );
        assert_eq!(report.diagnostics[0]["jobs"][1]["outcome"], "not_found");
        let mut tiny = selected.clone();
        tiny.max_total_bytes = 1;
        let report = diagnose_collection(
            reader_url.as_str(),
            root.path(),
            None,
            tiny,
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(report.outcome, DiagnosisOutcome::BudgetExhausted);
        // Let a blocked metadata read resume during cooperative deadline cleanup.
        // Its next budget check must produce an incomplete report, not discard it.
        let mut lock_connection = PgConnection::connect(url.as_str()).await.unwrap();
        let mut lock = lock_connection.begin().await.unwrap();
        sqlx_core::query::query("LOCK TABLE devres_rfc_jobs IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *lock)
            .await
            .unwrap();
        let mut timed = selected.clone();
        timed.timeout_secs = 2;
        let diagnosis = diagnose_collection(
            reader_url.as_str(),
            root.path(),
            None,
            timed,
            CancellationToken::new(),
        );
        let unlock = async move {
            tokio::time::sleep(Duration::from_millis(1200)).await;
            lock.rollback().await.unwrap();
        };
        let (report, ()) = tokio::join!(diagnosis, unlock);
        let report = report.unwrap();
        assert!(!report.complete);
        assert_eq!(report.outcome, DiagnosisOutcome::BudgetExhausted);
        let (mut reader, _) = Reader::open(
            reader_url.as_str(),
            root.path(),
            None,
            &selected,
            CancellationToken::new(),
        )
        .await
        .unwrap();
        let error = sqlx_core::query::query("UPDATE devres_rfc_jobs SET attempts=attempts+1")
            .execute(&mut reader.conn)
            .await
            .unwrap_err();
        assert_eq!(
            error.as_database_error().unwrap().code().as_deref(),
            Some("25006")
        );
        drop(reader);
        sqlx_core::query::query(
            "UPDATE devres_rfc_snapshots SET data=jsonb_set(data,'{complete}','true') WHERE id=$1",
        )
        .bind(&id)
        .execute(&mut conn)
        .await
        .unwrap();
        let report = diagnose_collection(
            reader_url.as_str(),
            root.path(),
            None,
            selected,
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(report.outcome, DiagnosisOutcome::IntegrityFailed);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires disposable PostgreSQL and RustFS; run scripts/test-s3.sh"]
    async fn s3_rfc_metadata_verifies_bindings_without_materializing_engine() {
        let _serial = crate::rfc::index::TEST_SERIAL.lock().await;
        let base = std::env::var("DEVRES_TEST_DATABASE_URL").expect("disposable database required");
        let writer_path = std::env::var("DEVRES_TEST_S3_CONFIG")
            .expect("disposable writer configuration required");
        let reader_path = std::env::var("DEVRES_TEST_S3_READER_CONFIG")
            .expect("disposable reader configuration required");
        let mut writer_config: S3Config =
            toml::from_str(&std::fs::read_to_string(writer_path).unwrap()).unwrap();
        let mut reader_config: S3Config =
            toml::from_str(&std::fs::read_to_string(reader_path).unwrap()).unwrap();
        writer_config.prefix.push_str("/rfc-diagnosis");
        reader_config.prefix.push_str("/rfc-diagnosis");
        let mut admin = PgConnection::connect(&base).await.unwrap();
        sqlx_core::raw_sql::raw_sql("CREATE DATABASE devres_s3_rfc_diagnosis_fixture")
            .execute(&mut admin)
            .await
            .unwrap();
        let mut url = url::Url::parse(&base).unwrap();
        url.set_path("/devres_s3_rfc_diagnosis_fixture");
        let writer_root = tempfile::tempdir_in("/tmp").unwrap();
        let reader_root = tempfile::tempdir_in("/tmp").unwrap();
        let writer = crate::PgBlobStore::connect_archive(
            url.as_str(),
            writer_root.path(),
            Some(writer_config.clone()),
        )
        .await
        .unwrap();
        let publish = |key: &str, url: &str, body: &[u8]| {
            (
                FetchRequest {
                    key: key.into(),
                    url: url.into(),
                    ttl_secs: 60,
                    max_bytes: 1024,
                    media_type: "text/plain".into(),
                },
                FetchResponse {
                    status: 200,
                    body: body.into(),
                    validators: Validators::default(),
                },
            )
        };
        let (request, response) = publish(
            "rfc:index",
            "https://www.rfc-editor.org/rfc-index.xml",
            b"synthetic catalogue",
        );
        let catalogue = writer
            .publish(&request, response, 10)
            .await
            .unwrap()
            .capture;
        writer
            .save_dataset(
                "catalogue",
                &Dataset {
                    capture: catalogue.clone(),
                    records: Vec::new(),
                },
            )
            .await
            .unwrap();
        let (request, response) = publish(
            "rfc:text:9000",
            "https://www.rfc-editor.org/rfc/rfc9000.txt",
            b"synthetic RFC text",
        );
        let captured = writer
            .publish(&request, response, 10)
            .await
            .unwrap()
            .capture;
        writer
            .schedule(&[JobSpec {
                key: request.key,
                number: 9000,
                format: "txt".into(),
                source_url: request.url,
                assurance: "https".into(),
                due_at: 10,
            }])
            .await
            .unwrap();
        writer
            .finish("rfc:text:9000", Some(&captured), None, 100)
            .await
            .unwrap();
        let index_id = integrity::hash(b"S3 RFC metadata-only index");
        let relative = tokio::task::block_in_place(|| {
            let mut builder =
                crate::rfc::index::IndexBuilder::begin(writer_root.path(), &index_id).unwrap();
            builder
                .add_document(crate::rfc::index::IndexDocument {
                    number: 9000,
                    text: "synthetic RFC text".into(),
                })
                .unwrap();
            builder.finish().unwrap()
        });
        let id = integrity::hash(b"S3 RFC metadata-only snapshot");
        let document = devres_application::corpus::Document {
            number: 9000,
            format: "txt".into(),
            capture: captured,
            assurance: "https".into(),
        };
        writer
            .save_snapshot(&Snapshot {
                id: id.clone(),
                catalogue_capture: catalogue.id,
                errata_capture: None,
                documents: vec![document.clone()],
                search_documents: vec![document],
                coverage: json!({}),
                created_at: 10,
                complete: false,
                index_path: Some(relative.clone()),
                processor_version: 1,
            })
            .await
            .unwrap();
        let mut conn = PgConnection::connect(url.as_str()).await.unwrap();
        sqlx_core::raw_sql::raw_sql("CREATE ROLE devres_s3_rfc_diag_reader LOGIN PASSWORD 'disposable-reader'; GRANT USAGE ON SCHEMA public TO devres_s3_rfc_diag_reader; GRANT SELECT ON ALL TABLES IN SCHEMA public TO devres_s3_rfc_diag_reader;").execute(&mut conn).await.unwrap();
        let mut reader_url = url.clone();
        reader_url
            .set_username("devres_s3_rfc_diag_reader")
            .unwrap();
        reader_url.set_password(Some("disposable-reader")).unwrap();
        let selected = options(&id);
        let report = diagnose_collection(
            reader_url.as_str(),
            reader_root.path(),
            Some(reader_config.clone()),
            selected.clone(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(report.complete);
        assert_eq!(
            report.diagnostics[0]["index"]["member_bindings"],
            "verified"
        );
        assert!(
            report.diagnostics[0]["index"]["archive_bindings_checked"]
                .as_u64()
                .unwrap()
                > 0
        );
        assert_eq!(
            std::fs::read_dir(reader_root.path()).unwrap().count(),
            0,
            "metadata reads must not warm a reader cache"
        );
        // Consistently bound metadata must still match the exact object length.
        // Construct a new immutable generation; never overwrite a retained object.
        let overstated_id = integrity::hash(b"overstated RFC manifest generation");
        let overstated_relative = format!(
            "rfc-indexes/{}",
            integrity::relative_path(&overstated_id)
                .unwrap()
                .to_string_lossy()
        );
        let remote = S3Archive::new(writer_config).await.unwrap();
        let rows = sqlx_core::query::query("SELECT path,digest,bytes,device,inode,epoch,evidence FROM devres_archive_file WHERE complete AND starts_with(path,$1) ORDER BY path")
            .bind(format!("{relative}/")).fetch_all(&mut conn).await.unwrap();
        for row in rows {
            let original: String = row.try_get("path").unwrap();
            let path = original.replacen(&relative, &overstated_relative, 1);
            let original_bytes: i64 = row.try_get("bytes").unwrap();
            let declared_bytes = original_bytes + i64::from(original.ends_with("/integrity.json"));
            let mut descriptor: Value =
                serde_json::from_str(&row.try_get::<String, _>("evidence").unwrap()).unwrap();
            descriptor["path"] = json!(path);
            descriptor["bytes"] = json!(declared_bytes);
            let encoded = serde_json::to_vec(&descriptor).unwrap();
            remote
                .put_bytes_immutable(
                    &format!("bindings/{}.json", blake3::hash(path.as_bytes()).to_hex()),
                    &encoded,
                )
                .await
                .unwrap();
            sqlx_core::query::query("INSERT INTO devres_archive_file(path,digest,bytes,device,inode,epoch,evidence,complete) VALUES($1,$2,$3,$4,$5,$6,$7,true)")
                .bind(&path).bind(row.try_get::<String,_>("digest").unwrap()).bind(declared_bytes)
                .bind(row.try_get::<String,_>("device").unwrap()).bind(row.try_get::<String,_>("inode").unwrap())
                .bind(row.try_get::<i64,_>("epoch").unwrap()).bind(String::from_utf8(encoded).unwrap()).execute(&mut conn).await.unwrap();
        }
        let mut overstated_snapshot = writer.snapshot(Some(&id)).await.unwrap().unwrap();
        overstated_snapshot.id = integrity::hash(b"overstated RFC manifest snapshot");
        overstated_snapshot.index_path = Some(overstated_relative);
        writer.save_snapshot(&overstated_snapshot).await.unwrap();
        let report = diagnose_collection(
            reader_url.as_str(),
            reader_root.path(),
            Some(reader_config.clone()),
            options(&overstated_snapshot.id),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(
            report.outcome,
            DiagnosisOutcome::IntegrityFailed,
            "matching SQL and remote descriptors cannot excuse an overstated object length"
        );
        // A matching SQL edit cannot replace independent remote binding authority.
        sqlx_core::query::query("UPDATE devres_archive_file SET digest=$2,evidence=jsonb_set(evidence::jsonb,'{digest}',to_jsonb($2::text))::text WHERE path=$1")
            .bind(format!("{relative}/meta.json")).bind(integrity::hash(b"tampered binding")).execute(&mut conn).await.unwrap();
        let report = diagnose_collection(
            reader_url.as_str(),
            reader_root.path(),
            Some(reader_config),
            selected,
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(report.outcome, DiagnosisOutcome::IntegrityFailed);
        assert_eq!(std::fs::read_dir(reader_root.path()).unwrap().count(), 0);
    }
}
