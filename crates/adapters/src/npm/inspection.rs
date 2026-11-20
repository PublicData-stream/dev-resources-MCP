//! Selected sealed npm metadata. Never opens the retained export or serving caches.
use super::*;
use crate::bulk::{BulkArtifact, MAX_ARTIFACT_BYTES};

fn identifier(value: &Value) -> Result<&str> {
    value
        .as_str()
        .filter(|id| integrity::valid_hash(id))
        .ok_or_else(failed)
}

fn number(value: &Value, max: u64) -> Result<u64> {
    value.as_u64().filter(|n| *n <= max).ok_or_else(failed)
}

fn timestamp(value: &Value) -> Result<i64> {
    value.as_i64().filter(|n| *n >= 0).ok_or_else(failed)
}

/// Migrated npm identities bind frozen occurrences, not rewritten JSON preimages.
async fn evidence(
    reader: &mut Reader,
    report: &mut CollectionDiagnosis,
    kind: &str,
    selected: &str,
) -> Result<Option<(String, Value)>> {
    if !integrity::valid_hash(selected) || !matches!(kind, "snapshots" | "failures") {
        return Err(failed());
    }
    let namespace = format!("npm:{kind}");
    let size: Option<i64> = sqlx_core::query_scalar::query_scalar("SELECT octet_length(canonical)::bigint+COALESCE(octet_length(mapping_integrity),0)::bigint FROM devres_content_aliases WHERE namespace=$1 AND legacy=$2")
        .bind(&namespace).bind(selected).fetch_optional(&mut reader.conn).await.map_err(|_|unavailable())?;
    let canonical = if let Some(size) = size {
        if size > 8192 {
            return Err(failed());
        }
        reader.row_admit(size)?;
        let row = sqlx_core::query::query("SELECT canonical,mapping_integrity FROM devres_content_aliases WHERE namespace=$1 AND legacy=$2")
            .bind(&namespace).bind(selected).fetch_one(&mut reader.conn).await.map_err(|_|unavailable())?;
        let canonical: String = row.try_get("canonical").map_err(|_| failed())?;
        let seal: String = row.try_get("mapping_integrity").map_err(|_| failed())?;
        if !canonical.starts_with("blake3:")
            || !integrity::valid_hash(&canonical)
            || super::super::events::event_digest(
                "devres_content_aliases",
                &super::super::events::mapping_key(&namespace, selected)?,
                &json!({"namespace":namespace,"legacy":selected,"canonical":canonical}),
            )? != seal
        {
            return Err(failed());
        }
        canonical
    } else {
        selected.to_owned()
    };
    let size: Option<i64> = sqlx_core::query_scalar::query_scalar("SELECT octet_length(data::text)::bigint FROM devres_npm_evidence WHERE kind=$1 AND key=$2 AND sequence<=$3")
        .bind(kind).bind(&canonical).bind(report.cutoff).fetch_optional(&mut reader.conn).await.map_err(|_|unavailable())?;
    let Some(size) = size else {
        return if canonical == selected {
            Ok(None)
        } else {
            Err(failed())
        };
    };
    reader.row_admit(size)?;
    let row = sqlx_core::query::query("SELECT sequence,sequence_integrity,kind,key,data,data_integrity FROM devres_npm_evidence WHERE kind=$1 AND key=$2 AND sequence<=$3")
        .bind(kind).bind(&canonical).bind(report.cutoff).fetch_one(&mut reader.conn).await.map_err(|_|unavailable())?;
    let data = payload_integrity::row("devres_npm_evidence", &row)?;
    report.evidence.push(EvidenceSummary {
        kind: kind.into(),
        sequence: row.try_get("sequence").map_err(|_| failed())?,
        identity: canonical.clone(),
        digest: integrity::hash(&serde_json::to_vec(&data).map_err(|_| failed())?),
        bytes: u64::try_from(size).map_err(|_| failed())?,
        page: None,
        observed_at: None,
        body: None,
    });
    Ok(Some((canonical, data)))
}

async fn artifact(reader: &mut Reader, value: &Value) -> Result<Value> {
    let artifact: BulkArtifact = serde_json::from_value(value.clone()).map_err(|_| failed())?;
    if !integrity::valid_hash(&artifact.body_hash) || artifact.bytes > MAX_ARTIFACT_BYTES {
        return Err(failed());
    }
    let suffix = integrity::relative_path(&artifact.body_hash)?;
    if artifact.relative_path != suffix.to_string_lossy() {
        return Err(failed());
    }
    let mut summary = json!({"digest":artifact.body_hash,"bytes":artifact.bytes,
        "archive_binding":"not_applicable_filesystem","object_bytes":"not_checked"});
    if let Some(remote) = &reader.remote {
        // Only the selected immutable binding descriptor is fetched, never objects/*.
        reader.budget.admit(16 * 1024)?; // SQL binding payload.
        let path = format!("npm/raw-artifacts/{}", suffix.to_string_lossy());
        let row = sqlx_core::query::query("SELECT digest,bytes,evidence FROM devres_archive_file WHERE path=$1 AND complete AND octet_length(evidence)<=16384")
            .bind(&path).fetch_optional(&mut reader.conn).await.map_err(|_|unavailable())?
            .ok_or_else(unavailable)?;
        let encoded: String = row.try_get("evidence").map_err(|_| failed())?;
        let binding: ArchiveBinding = serde_json::from_str(&encoded).map_err(|_| failed())?;
        if binding.version != 1
            || binding.path != path
            || binding.digest != artifact.body_hash
            || binding.bytes != artifact.bytes
            || row.try_get::<String, _>("digest").map_err(|_| failed())? != binding.digest
            || row.try_get::<i64, _>("bytes").map_err(|_| failed())?
                != i64::try_from(binding.bytes).map_err(|_| failed())?
        {
            return Err(failed());
        }
        reader.budget.admit(16 * 1024)?; // Independent remote descriptor.
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
        summary["archive_binding"] = json!("verified");
    }
    Ok(summary)
}

fn job_summary(value: &Value) -> Result<Value> {
    let next = number(&value["next"], 1_000_000)?;
    let records = number(&value["records"], next)?;
    let gaps = number(&value["gaps"], next)?;
    let expanded = match value.get("expanded") {
        Some(value) => number(value, 64 * 1024 * 1024 * 1024)?,
        None => 0,
    };
    let done = value["done"].as_bool().ok_or_else(failed)?;
    let version = value
        .get("processor_version")
        .map(|v| number(v, u32::MAX.into()))
        .transpose()?;
    Ok(
        json!({"snapshot":identifier(&value["snapshot"])?,"validated_at":timestamp(&value["validated_at"])?,
        "next_member":next,"records":records,"gaps":gaps,"expanded_bytes":expanded,"done":done,
        "failed":value["failed"].as_str().map(safe_code),"processor_version":version,
        "processor_version_evidence":if version.is_some(){"retained"}else{"legacy_unknown"}}),
    )
}

async fn latest_failure(reader: &mut Reader, report: &mut CollectionDiagnosis) -> Result<Value> {
    // Bound the indexed historical walk before filtering lanes, including on package-heavy stores.
    reader.budget.admit(9 * 24)?;
    let candidates: Vec<(i64,i64,bool)> = sqlx_core::query_as::query_as("SELECT sequence,octet_length(key)::bigint,COALESCE(data->>'lane'='advisories',false) FROM devres_npm_evidence WHERE kind='failures' AND sequence<=$1 ORDER BY sequence DESC LIMIT 9")
        .bind(report.cutoff).fetch_all(&mut reader.conn).await.map_err(|_|unavailable())?;
    report.diagnostics[0]["failure_sample_truncated"] = json!(candidates.len() > 8);
    let Some((sequence, bytes, _)) = candidates.iter().take(8).find(|(_, _, advisory)| *advisory)
    else {
        if candidates.len() > 8 {
            report.complete = false;
            report.outcome = DiagnosisOutcome::AttemptedPayloadUnlinked;
        }
        return Ok(Value::Null);
    };
    if *bytes > 71 {
        return Err(failed());
    }
    reader.row_admit(*bytes)?;
    let key: String = sqlx_core::query_scalar::query_scalar(
        "SELECT key FROM devres_npm_evidence WHERE sequence=$1 AND kind='failures'",
    )
    .bind(sequence)
    .fetch_one(&mut reader.conn)
    .await
    .map_err(|_| unavailable())?;
    let (id, value) = evidence(reader, report, "failures", &key)
        .await?
        .ok_or_else(unavailable)?;
    if value["lane"] != "advisories" {
        return Err(failed());
    }
    Ok(
        json!({"id":id,"lane":"advisories","code":safe_code(value["code"].as_str().ok_or_else(failed)?),
        "at":timestamp(&value["at"])?,"stage":"legacy_unknown","attempt_linkage":"not_checked"}),
    )
}

async fn ready(reader: &mut Reader, id: &str, snapshot: Option<&Value>) -> Result<Value> {
    let Some(value) = reader
        .state(DiagnosisProvider::Npm, &format!("ready:{id}"))
        .await?
    else {
        return Ok(json!("absent"));
    };
    if identifier(&value["id"])? != id || value["accounted"] != true {
        return Err(failed());
    }
    let records = number(&value["records"], 1_000_000)?;
    if snapshot.is_some_and(|snapshot| snapshot["records"].as_u64() != Some(records)) {
        return Err(failed());
    }
    Ok(json!("verified"))
}

async fn default(
    reader: &mut Reader,
    report: &mut CollectionDiagnosis,
    value: &Value,
) -> Result<Value> {
    let selected = identifier(&value["id"])?;
    let (id, retained) = evidence(reader, report, "snapshots", selected)
        .await?
        .ok_or_else(unavailable)?;
    if retained != *value || value["lane"] != "advisories" || value["accounted"] != true {
        return Err(failed());
    }
    let mut result = json!({"id":id,"membership":identifier(&value["membership"])?,
        "validated_at":timestamp(&value["validated_at"])?,"records":number(&value["records"],1_000_000)?,
        "gaps":number(&value["gaps"],1_000_000)?,"complete":value["complete"].as_bool().ok_or_else(failed)?,
        "processor_version":number(&value["processor_version"],u32::MAX.into())?,
        "synthetic":value["synthetic"].as_bool().unwrap_or(false),
        "snapshot_metadata":"verified","export_artifact":null,"ready":ready(reader,&id,Some(value)).await?});
    if result["ready"] != "verified" {
        return Err(unavailable());
    }
    if let Some(value) = value.get("artifact") {
        result["export_artifact"] = artifact(reader, value).await?;
    } else if result["synthetic"] != true {
        return Err(failed());
    }
    Ok(result)
}

pub(super) async fn inspect(reader: &mut Reader, report: &mut CollectionDiagnosis) -> Result<()> {
    report.diagnostics.push(json!({"operation":"npm_advisory_metadata","job":null,"retry_at":null,
        "diagnostic":{"version":1,"outcome":"legacy_unknown","activity":"unknown","active":null},
        "latest_failure":null,"failure_selection_scope":"latest_eight_failure_rows","failure_sample_truncated":false,
        "default":null,"publication_candidates":[],"provider_requests":0,
        "export_bytes":"not_checked","full_membership":"not_checked","attribution_qualified":"not_checked"}));
    let value = reader
        .state(DiagnosisProvider::Npm, "diagnostics-advisories")
        .await?;
    if let Some(value) = value {
        let mut summary = crate::npm::diagnostics::private_summary(value)?;
        summary["activity"] = json!("unknown");
        summary["active"] = Value::Null;
        report.diagnostics[0]["diagnostic"] = summary;
    }
    if let Some(value) = reader
        .state(DiagnosisProvider::Npm, "advisory-retry")
        .await?
    {
        report.diagnostics[0]["retry_at"] = json!(timestamp(&value)?);
    }
    if let Some(value) = reader.state(DiagnosisProvider::Npm, "advisory-job").await? {
        let mut summary = job_summary(&value)?;
        summary["export_artifact"] = artifact(reader, &value["artifact"]).await?;
        report.diagnostics[0]["job"] = summary;
    }
    report.diagnostics[0]["latest_failure"] = latest_failure(reader, report).await?;
    if let Some(value) = reader
        .state(DiagnosisProvider::Npm, "default-advisories")
        .await?
    {
        report.diagnostics[0]["default"] = default(reader, report, &value).await?;
    }
    // A publication attempt can have prepared its exact manifest before setting a default.
    let selected = [
        &report.diagnostics[0]["diagnostic"]["publication_snapshot"],
        &report.diagnostics[0]["diagnostic"]["last_failure"]["publication_snapshot"],
    ]
    .into_iter()
    .filter_map(Value::as_str)
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    for id in selected {
        if !integrity::valid_hash(&id) {
            return Err(failed());
        }
        if report.diagnostics[0]["default"]["id"] != id {
            let retained = evidence(reader, report, "snapshots", &id).await?;
            let state = ready(reader, &id, retained.as_ref().map(|(_, value)| value)).await?;
            if retained.as_ref().is_some_and(|(_, value)| {
                value["lane"] != "advisories" || value["accounted"] != true
            }) {
                return Err(failed());
            }
            report.diagnostics[0]["publication_candidates"].as_array_mut().ok_or_else(failed)?
                .push(json!({"id":id,"ready":state,"snapshot_metadata":if retained.is_some(){"verified"}else{"absent"}}));
        }
    }
    if report.diagnostics[0]["diagnostic"]["outcome"] == "legacy_unknown"
        && !report.diagnostics[0]["latest_failure"].is_null()
    {
        report.complete = false;
        report.outcome = DiagnosisOutcome::AttemptedPayloadUnlinked;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use devres_application::npm::NpmStore;

    fn options() -> DiagnosisOptions {
        DiagnosisOptions {
            provider: DiagnosisProvider::Npm,
            max_total_bytes: MAX_BYTES,
            timeout_secs: 30,
            scan_retained_dump: false,
            scan_runtime_dump: None,
            snapshot: None,
            job_keys: vec![],
            commit: None,
            attribution_target: None,
        }
    }

    fn artifact_value() -> Value {
        let digest = integrity::hash(b"never open these retained export bytes");
        json!({"body_hash":digest,"bytes":220732348,
            "relative_path":integrity::relative_path(&digest).unwrap().to_string_lossy()})
    }

    fn job() -> Value {
        json!({"snapshot":integrity::hash(b"npm retained acquisition"),"artifact":artifact_value(),
            "validated_at":100,"next":21898,"records":21896,"gaps":33,"expanded":49317763,
            "done":true,"failed":"capacity","private":"private-input-canary"})
    }

    fn manifest() -> Value {
        let mut value = json!({"lane":"advisories","membership":integrity::hash(b"npm fixture membership"),
            "validated_at":100,"records":0,"gaps":0,"complete":true,"accounted":true,
            "processor_version":1,"synthetic":true,"source":"synthetic_fixture"});
        value["id"] = json!(integrity::hash(&serde_json::to_vec(&value).unwrap()));
        value
    }

    async fn database(name: &str) -> url::Url {
        let base =
            std::env::var("DEVRES_TEST_DATABASE_URL").expect("disposable PostgreSQL required");
        let mut admin = PgConnection::connect(&base).await.unwrap();
        sqlx_core::raw_sql::raw_sql(sqlx_core::sql_str::AssertSqlSafe(format!(
            "CREATE DATABASE {name}"
        )))
        .execute(&mut admin)
        .await
        .unwrap();
        let mut url = url::Url::parse(&base).unwrap();
        url.set_path(&format!("/{name}"));
        url
    }

    async fn inspect_store(url: &url::Url, root: &Path) -> CollectionDiagnosis {
        diagnose_collection(
            url.as_str(),
            root,
            None,
            options(),
            CancellationToken::new(),
        )
        .await
        .unwrap()
    }

    #[test]
    fn legacy_job_projection_preserves_terminal_state_and_rejects_impossible_counters() {
        let value = job_summary(&job()).unwrap();
        assert_eq!(value["done"], true);
        assert_eq!(value["failed"], "capacity");
        assert_eq!(value["processor_version_evidence"], "legacy_unknown");
        assert!(value["processor_version"].is_null());
        assert!(
            !serde_json::to_string(&value)
                .unwrap()
                .contains("private-input-canary")
        );
        for field in ["next", "records", "gaps", "expanded", "validated_at"] {
            let mut invalid = job();
            invalid[field] = json!(-1);
            assert!(job_summary(&invalid).is_err(), "{field}");
        }
        let mut invalid = job();
        invalid["records"] = json!(21899);
        assert!(job_summary(&invalid).is_err());
    }

    #[tokio::test]
    #[ignore = "requires disposable PostgreSQL; run scripts/test-postgres.sh"]
    async fn npm_metadata_reader_preserves_legacy_jobs_aliases_and_privacy_without_export_reads() {
        let url = database("devres_npm_diagnosis_fixture").await;
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let writer = crate::PgBlobStore::connect(url.as_str(), root.path())
            .await
            .unwrap();
        let absent = inspect_store(&url, root.path()).await;
        assert!(absent.complete);
        assert!(absent.diagnostics[0]["job"].is_null());
        assert_eq!(
            absent.diagnostics[0]["diagnostic"]["outcome"],
            "legacy_unknown"
        );
        let value = job();
        writer.npm_set_state("advisory-job", &value).await.unwrap();
        writer
            .npm_set_state("advisory-retry", &json!(200))
            .await
            .unwrap();
        let failure = json!({"lane":"advisories","name":null,"code":"unavailable","at":120,
            "message":"private-input-canary"});
        writer
            .npm_put(
                "failures",
                &integrity::hash(b"frozen failure occurrence"),
                &failure,
            )
            .await
            .unwrap();
        let report = inspect_store(&url, root.path()).await;
        assert_eq!(report.outcome, DiagnosisOutcome::AttemptedPayloadUnlinked);
        assert_eq!(report.diagnostics[0]["retry_at"], 200);
        assert_eq!(report.diagnostics[0]["job"]["next_member"], 21898);
        assert_eq!(
            report.diagnostics[0]["job"]["export_artifact"]["object_bytes"],
            "not_checked"
        );
        assert_eq!(
            writer.npm_state("advisory-job").await.unwrap(),
            Some(value.clone())
        );
        assert!(
            !serde_json::to_string(&report)
                .unwrap()
                .contains("private-input-canary")
        );
        let attempt = json!({"version":1,"attempt_started_at":121,"updated_at":122,
            "stage":"acquisition","outcome":"failed","job":null,"publication_snapshot":null,
            "last_failure":{"stage":"acquisition","job":null,"publication_snapshot":null,
                "failure":{"code":"unavailable","observed_at":122,"phase":"bulk_operation"}},
            "last_success":null,"last_progress":null});
        writer
            .npm_set_state("diagnostics-advisories", &attempt)
            .await
            .unwrap();
        let report = inspect_store(&url, root.path()).await;
        assert!(report.complete);
        assert!(report.diagnostics[0]["diagnostic"]["job"].is_null());
        assert!(report.diagnostics[0]["diagnostic"]["last_failure"]["job"].is_null());
        assert_eq!(report.diagnostics[0]["diagnostic"]["activity"], "unknown");
        assert_eq!(report.diagnostics[0]["job"]["done"], true);
        assert_eq!(
            writer.npm_state("diagnostics-advisories").await.unwrap(),
            Some(attempt)
        );
        let snapshot = manifest();
        let id = snapshot["id"].as_str().unwrap();
        writer
            .npm_set_state(
                &format!("ready:{id}"),
                &json!({"id":id,"records":0,"accounted":true}),
            )
            .await
            .unwrap();
        writer.npm_publish("advisories", &snapshot).await.unwrap();
        let report = inspect_store(&url, root.path()).await;
        assert_eq!(report.diagnostics[0]["default"]["id"], id);
        assert_eq!(report.diagnostics[0]["default"]["ready"], "verified");
        assert!(report.diagnostics[0]["default"]["export_artifact"].is_null());
        assert_eq!(report.diagnostics[0]["full_membership"], "not_checked");
        // Exercise an occurrence-derived canonical identity whose payload preimage differs.
        let canonical = integrity::hash(b"frozen migrated snapshot occurrence");
        writer
            .npm_put("snapshots", &canonical, &snapshot)
            .await
            .unwrap();
        writer
            .npm_set_state(
                &format!("ready:{canonical}"),
                &json!({"id":canonical,"records":0,"accounted":true}),
            )
            .await
            .unwrap();
        let namespace = "npm:snapshots";
        let seal = super::super::super::events::event_digest(
            "devres_content_aliases",
            &super::super::super::events::mapping_key(namespace, id).unwrap(),
            &json!({"namespace":namespace,"legacy":id,"canonical":canonical}),
        )
        .unwrap();
        let mut conn = PgConnection::connect(url.as_str()).await.unwrap();
        sqlx_core::query::query("INSERT INTO devres_content_aliases(namespace,legacy,canonical,mapping_integrity) VALUES($1,$2,$3,$4)")
            .bind(namespace).bind(id).bind(&canonical).bind(seal).execute(&mut conn).await.unwrap();
        let report = inspect_store(&url, root.path()).await;
        assert_eq!(report.diagnostics[0]["default"]["id"], canonical);
        for at in 0..9 {
            let failure = json!({"lane":"package","code":"unavailable","at":200+at});
            writer
                .npm_put(
                    "failures",
                    &integrity::hash(&serde_json::to_vec(&failure).unwrap()),
                    &failure,
                )
                .await
                .unwrap();
        }
        let report = inspect_store(&url, root.path()).await;
        assert!(!report.complete);
        assert_eq!(report.diagnostics[0]["failure_sample_truncated"], true);
        assert!(
            report.diagnostics[0]["latest_failure"].is_null(),
            "the reader never scans past its finite indexed sample"
        );
        let mut tiny = options();
        tiny.max_total_bytes = 1;
        assert_eq!(
            diagnose_collection(
                url.as_str(),
                root.path(),
                None,
                tiny,
                CancellationToken::new()
            )
            .await
            .unwrap()
            .outcome,
            DiagnosisOutcome::BudgetExhausted
        );
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert_eq!(
            diagnose_collection(url.as_str(), root.path(), None, options(), cancelled)
                .await
                .unwrap_err()
                .code,
            "cancelled"
        );
        let (mut reader, _) = Reader::open(
            url.as_str(),
            root.path(),
            None,
            &options(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        let error =
            sqlx_core::raw_sql::raw_sql("CREATE TABLE forbidden_npm_diagnosis_write(id int)")
                .execute(&mut reader.conn)
                .await
                .unwrap_err();
        assert_eq!(
            error.as_database_error().unwrap().code().as_deref(),
            Some("25006")
        );
        drop(reader);
        sqlx_core::query::query("UPDATE devres_content_aliases SET mapping_integrity=$1 WHERE namespace=$2 AND legacy=$3")
            .bind(integrity::hash(b"invalid alias seal")).bind(namespace).bind(id).execute(&mut conn).await.unwrap();
        assert_eq!(
            inspect_store(&url, root.path()).await.outcome,
            DiagnosisOutcome::IntegrityFailed
        );
        assert_eq!(writer.npm_state("advisory-job").await.unwrap(), Some(value));
        assert!(
            !root.path().join("npm/raw-artifacts").exists(),
            "inspection never opens an export cache"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires disposable PostgreSQL and RustFS; run scripts/test-s3.sh"]
    async fn s3_npm_metadata_checks_descriptors_without_export_object_reads_or_cache() {
        let url = database("devres_s3_npm_diagnosis_fixture").await;
        let mut writer_config: S3Config = toml::from_str(
            &std::fs::read_to_string(std::env::var("DEVRES_TEST_S3_CONFIG").unwrap()).unwrap(),
        )
        .unwrap();
        let mut reader_config: S3Config = toml::from_str(
            &std::fs::read_to_string(std::env::var("DEVRES_TEST_S3_READER_CONFIG").unwrap())
                .unwrap(),
        )
        .unwrap();
        writer_config.prefix.push_str("/npm-diagnosis");
        reader_config.prefix.push_str("/npm-diagnosis");
        let writer_root = tempfile::tempdir_in("/tmp").unwrap();
        let reader_root = tempfile::tempdir_in("/tmp").unwrap();
        let writer = crate::PgBlobStore::connect_archive(
            url.as_str(),
            writer_root.path(),
            Some(writer_config.clone()),
        )
        .await
        .unwrap();
        let retained = job();
        writer
            .npm_set_state("advisory-job", &retained)
            .await
            .unwrap();
        let selected: BulkArtifact = serde_json::from_value(retained["artifact"].clone()).unwrap();
        let path = format!("npm/raw-artifacts/{}", selected.relative_path);
        let descriptor = json!({"version":1,"path":path,"digest":selected.body_hash,"bytes":selected.bytes,
            "device":0,"inode":0});
        let encoded = serde_json::to_vec(&descriptor).unwrap();
        let remote = S3Archive::new(writer_config).await.unwrap();
        let object = format!("objects/{}", selected.relative_path);
        // A deliberately absent export proves the inspector cannot GET/HEAD its body.
        assert!(remote.head(&object).await.unwrap().is_none());
        remote
            .put_bytes_immutable(
                &format!("bindings/{}.json", blake3::hash(path.as_bytes()).to_hex()),
                &encoded,
            )
            .await
            .unwrap();
        let mut conn = PgConnection::connect(url.as_str()).await.unwrap();
        sqlx_core::query::query("INSERT INTO devres_archive_file(path,digest,bytes,device,inode,epoch,evidence,complete) VALUES($1,$2,$3,'0','0',1,$4,true)")
            .bind(&path).bind(&selected.body_hash).bind(selected.bytes as i64)
            .bind(String::from_utf8(encoded).unwrap()).execute(&mut conn).await.unwrap();
        let report = diagnose_collection(
            url.as_str(),
            reader_root.path(),
            Some(reader_config.clone()),
            options(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(report.complete);
        assert_eq!(
            report.diagnostics[0]["job"]["export_artifact"]["archive_binding"],
            "verified"
        );
        assert_eq!(report.diagnostics[0]["export_bytes"], "not_checked");
        assert_eq!(std::fs::read_dir(reader_root.path()).unwrap().count(), 0);
        assert_eq!(
            writer.npm_state("advisory-job").await.unwrap(),
            Some(retained)
        );
        // Two individually bounded descriptors must both consume the aggregate budget.
        let mut tiny = options();
        tiny.max_total_bytes = 16 * 1024 + 1024;
        assert_eq!(
            diagnose_collection(
                url.as_str(),
                reader_root.path(),
                Some(reader_config.clone()),
                tiny,
                CancellationToken::new()
            )
            .await
            .unwrap()
            .outcome,
            DiagnosisOutcome::BudgetExhausted
        );
        // A forged SQL descriptor cannot override its independent immutable remote binding.
        let forged = json!({"version":1,"path":path,"digest":selected.body_hash,"bytes":selected.bytes+1,
            "device":0,"inode":0});
        sqlx_core::query::query(
            "UPDATE devres_archive_file SET bytes=bytes+1,evidence=$1 WHERE path=$2",
        )
        .bind(serde_json::to_string(&forged).unwrap())
        .bind(&path)
        .execute(&mut conn)
        .await
        .unwrap();
        let mut forged_job = job();
        forged_job["artifact"]["bytes"] = json!(selected.bytes + 1);
        writer
            .npm_set_state("advisory-job", &forged_job)
            .await
            .unwrap();
        assert_eq!(
            diagnose_collection(
                url.as_str(),
                reader_root.path(),
                Some(reader_config),
                options(),
                CancellationToken::new()
            )
            .await
            .unwrap()
            .outcome,
            DiagnosisOutcome::IntegrityFailed
        );
        assert_eq!(std::fs::read_dir(reader_root.path()).unwrap().count(), 0);
    }
}
