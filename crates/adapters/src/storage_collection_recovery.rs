//! Exact offline npm recovery. Source acquisition and default promotion are absent.
use super::*;
use crate::bulk::{BulkArtifact, BulkArtifactStore, MAX_ARTIFACT_BYTES};
use crate::collection_recovery::diagnostics::{Diagnostics, Phase, Reason};
use crate::collection_recovery::{
    CollectionRecoveryOptions, CollectionRecoveryReport, NPM_RECOVERY_PROCESSOR_VERSION,
    NPM_RECOVERY_RECIPE, RecoveryCheckpoint, RecoveryEvidenceReceipt,
};
use devres_application::npm::{NpmStore, PROCESSOR_VERSION};
use serde_json::{Value, json};
use sqlx_core::types::Json;
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
#[cfg(test)]
#[path = "storage_collection_recovery_boundary_tests.rs"]
mod boundary_tests;

pub(crate) const SCHEMA_V19: &str = r#"
CREATE TABLE devres_npm_advisory_job_history (
 job_id text NOT NULL, revision bigint NOT NULL CHECK(revision>0),
 state_digest text NOT NULL, data jsonb NOT NULL, data_integrity text NOT NULL,
 PRIMARY KEY(job_id,revision), UNIQUE(job_id,state_digest)
);
CREATE TABLE devres_npm_advisory_recoveries (
 operation_id text PRIMARY KEY, job_id text NOT NULL, recipe text NOT NULL,
 data jsonb NOT NULL, data_integrity text NOT NULL, UNIQUE(job_id,recipe)
);
CREATE TABLE devres_npm_recovery_work (
 operation_id text PRIMARY KEY REFERENCES devres_npm_advisory_recoveries(operation_id),
 data jsonb NOT NULL, data_integrity text NOT NULL
);
CREATE FUNCTION devres_npm_recovery_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_TABLE_NAME='devres_npm_recovery_work' AND TG_OP='UPDATE' AND OLD.data->>'status'<>'complete' THEN RETURN NEW; END IF;
 RAISE EXCEPTION 'npm recovery history is immutable';
END $$;
CREATE TRIGGER devres_npm_history_immutable BEFORE UPDATE OR DELETE ON devres_npm_advisory_job_history
 FOR EACH ROW EXECUTE FUNCTION devres_npm_recovery_immutable();
CREATE TRIGGER devres_npm_admission_immutable BEFORE UPDATE OR DELETE ON devres_npm_advisory_recoveries
 FOR EACH ROW EXECUTE FUNCTION devres_npm_recovery_immutable();
CREATE TRIGGER devres_npm_work_completion_immutable BEFORE UPDATE OR DELETE ON devres_npm_recovery_work
 FOR EACH ROW EXECUTE FUNCTION devres_npm_recovery_immutable();
"#;
const HISTORY: &str = "devres_npm_advisory_job_history";
const JOURNAL: &str = "devres_npm_advisory_recoveries";
const WORK: &str = "devres_npm_recovery_work";
const METADATA_MAX: usize = 8 * 1024 * 1024;
fn invalid() -> Error {
    Error::integrity("Invalid retained collection recovery evidence.")
}
fn require_available_processor(current: u32) -> Result<()> {
    if current != NPM_RECOVERY_PROCESSOR_VERSION {
        return Err(Error::unavailable(
            "Registered recovery scanner version is unavailable.",
        ));
    }
    Ok(())
}
fn unavailable() -> Error {
    Error::unavailable("Collection recovery storage unavailable.")
}
fn cancelled(cancel: &CancellationToken) -> Result<()> {
    if cancel.is_cancelled() {
        Err(Error::new("cancelled", "Collection recovery cancelled."))
    } else {
        Ok(())
    }
}
fn bounded(value: &Value) -> Result<()> {
    if serde_json::to_vec(value).map_err(|_| invalid())?.len() > METADATA_MAX {
        return Err(Error::capacity(
            "Collection recovery metadata exceeds its bound.",
        ));
    }
    Ok(())
}
fn blake(value: &str) -> bool {
    value.starts_with("blake3:") && valid_hash(value)
}
fn hash(value: &Value) -> Result<String> {
    crate::integrity::canonical_hash(value)
}
fn job_id(job: &Value) -> Result<&str> {
    job["snapshot"]
        .as_str()
        .filter(|v| blake(v))
        .ok_or_else(invalid)
}
fn artifact(job: &Value) -> Result<BulkArtifact> {
    let artifact: BulkArtifact =
        serde_json::from_value(job["artifact"].clone()).map_err(|_| invalid())?;
    if !blake(&artifact.body_hash)
        || artifact.bytes > MAX_ARTIFACT_BYTES
        || artifact.relative_path
            != crate::integrity::relative_path(&artifact.body_hash)?.to_string_lossy()
    {
        return Err(invalid());
    }
    Ok(artifact)
}
fn validate_job(job: &Value) -> Result<()> {
    bounded(job)?;
    job_id(job)?;
    artifact(job)?;
    let next = job["next"]
        .as_u64()
        .filter(|v| *v <= 1_000_000)
        .ok_or_else(invalid)?;
    let records = job["records"].as_u64().ok_or_else(invalid)?;
    let gaps = job["gaps"].as_u64().ok_or_else(invalid)?;
    let expanded = job
        .get("expanded")
        .map(|v| v.as_u64().ok_or_else(invalid))
        .transpose()?
        .unwrap_or(0);
    if records > next
        || gaps > next
        || expanded > 64 * 1024 * 1024 * 1024
        || job["done"].as_bool().is_none()
        || job["validated_at"]
            .as_i64()
            .is_none_or(|v| v <= 0 || v > devres_domain::unix_now().saturating_add(300))
    {
        return Err(invalid());
    }
    Ok(())
}
fn eligibility(job: &Value) -> Result<&'static str> {
    validate_job(job)?;
    if job["done"] != true || job["failed"] != "capacity" {
        return Ok("not_terminal_materialization_deadline");
    }
    if job["processor_version"] != NPM_RECOVERY_PROCESSOR_VERSION {
        return Ok("legacy_or_incompatible_processor");
    }
    if job["failure_context"]
        != json!({"version":1,"code":"capacity","materialization_deadline":true})
    {
        return Ok("legacy_unknown");
    }
    Ok("eligible")
}

/// Called inside the same primary transaction as advisory-job replacement.
pub(crate) async fn record_job(conn: &mut PgConnection, job: &Value) -> Result<()> {
    record_job_inner(conn, job, true).await
}
async fn record_job_inner(
    conn: &mut PgConnection,
    job: &Value,
    cause_authoritative: bool,
) -> Result<()> {
    validate_job(job)?;
    let id = job_id(job)?;
    let state = hash(job)?;
    let previous=sqlx_core::query::query("SELECT revision,CASE WHEN octet_length(data::text)<=8388608 THEN data END AS data,data_integrity FROM devres_npm_advisory_job_history WHERE job_id=$1 ORDER BY revision DESC LIMIT 1")
        .bind(id).fetch_optional(&mut *conn).await.map_err(|_|unavailable())?;
    let (revision, previous_digest) = if let Some(row) = previous {
        let revision: i64 = row.try_get("revision").map_err(|_| invalid())?;
        let data: Json<Value> = row.try_get("data").map_err(|_| invalid())?;
        let seal: String = row.try_get("data_integrity").map_err(|_| invalid())?;
        let data = payload_integrity::checked(HISTORY, id, &revision.to_string(), data.0, &seal)?;
        if data["job"] == *job {
            return Ok(());
        }
        (revision.checked_add(1).ok_or_else(invalid)?, Some(seal))
    } else {
        (1, None)
    };
    let data = json!({"version":1,"job_id":id,"revision":revision,"previous_digest":previous_digest,"job":job,"state_digest":state,"cause_authoritative":cause_authoritative});
    let seal = payload_integrity::digest(HISTORY, id, &revision.to_string(), &data)?;
    sqlx_core::query::query("INSERT INTO devres_npm_advisory_job_history(job_id,revision,state_digest,data,data_integrity) VALUES($1,$2,$3,$4,$5)")
        .bind(id).bind(revision).bind(state).bind(Json(&data)).bind(seal).execute(&mut *conn).await.map_err(|_|unavailable())?;
    Ok(())
}
pub(crate) async fn migrate_current_job(conn: &mut PgConnection) -> Result<()> {
    let Some(job) =
        payload_integrity::load(&mut *conn, "devres_npm_state", "", "advisory-job").await?
    else {
        return Ok(());
    };
    record_job_inner(conn, &job.0, false).await
}
async fn verify_recovery_payload(
    conn: &mut PgConnection,
    table: &str,
    operation: &str,
    cancel: &CancellationToken,
) -> Result<Value> {
    cancelled(cancel)?;
    if !matches!(table, JOURNAL | WORK) || !blake(operation) {
        return Err(invalid());
    }
    let sql = format!("SELECT octet_length(data::text)::bigint FROM {table} WHERE operation_id=$1");
    let bytes: Option<i64> =
        sqlx_core::query_scalar::query_scalar(sqlx_core::sql_str::AssertSqlSafe(sql))
            .bind(operation)
            .fetch_optional(&mut *conn)
            .await
            .map_err(|_| unavailable())?;
    if bytes.is_none_or(|v| v < 0 || v > METADATA_MAX as i64) {
        return Err(invalid());
    }
    let sql = format!(
        "SELECT data,CASE WHEN octet_length(data_integrity)<=71 THEN data_integrity END AS data_integrity FROM {table} WHERE operation_id=$1 AND octet_length(data::text)<=8388608"
    );
    let row = sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(sql))
        .bind(operation)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|_| unavailable())?
        .ok_or_else(invalid)?;
    let data: Json<Value> = row.try_get("data").map_err(|_| invalid())?;
    let seal: String = row.try_get("data_integrity").map_err(|_| invalid())?;
    let data = payload_integrity::checked(table, "", operation, data.0, &seal)?;
    if data["version"] != 1 || data["operation_id"] != operation {
        return Err(invalid());
    }
    Ok(data)
}

async fn verify_recovery_admission(
    conn: &mut PgConnection,
    operation: &str,
    admission: &Value,
    cancel: &CancellationToken,
) -> Result<()> {
    cancelled(cancel)?;
    let id = admission["job_id"]
        .as_str()
        .filter(|v| blake(v))
        .ok_or_else(invalid)?;
    let revision = admission["revision"]
        .as_u64()
        .filter(|v| *v > 0 && *v <= i64::MAX as u64)
        .ok_or_else(invalid)?;
    let expected = admission["expected_state"]
        .as_str()
        .filter(|v| blake(v))
        .ok_or_else(invalid)?;
    if admission["version"] != 1
        || admission["operation_id"] != operation
        || admission["recipe"] != NPM_RECOVERY_RECIPE
        || job_id(&admission["job"])? != id
        || eligibility(&admission["job"])? != "eligible"
    {
        return Err(invalid());
    }
    let columns:(String,String)=sqlx_core::query_as::query_as("SELECT CASE WHEN octet_length(job_id)<=71 THEN job_id END AS job_id,CASE WHEN octet_length(recipe)<=128 THEN recipe END AS recipe FROM devres_npm_advisory_recoveries WHERE operation_id=$1")
        .bind(operation).fetch_one(&mut *conn).await.map_err(|_|unavailable())?;
    if columns.0 != id || columns.1 != NPM_RECOVERY_RECIPE {
        return Err(invalid());
    }
    let size:Option<i64>=sqlx_core::query_scalar::query_scalar("SELECT octet_length(data::text)::bigint FROM devres_npm_advisory_job_history WHERE job_id=$1 AND revision=$2")
        .bind(id).bind(revision as i64).fetch_optional(&mut *conn).await.map_err(|_|unavailable())?;
    if size.is_none_or(|v| v < 0 || v > METADATA_MAX as i64) {
        return Err(invalid());
    }
    let row=sqlx_core::query::query("SELECT CASE WHEN octet_length(state_digest)<=71 THEN state_digest END AS state_digest,data,CASE WHEN octet_length(data_integrity)<=71 THEN data_integrity END AS data_integrity FROM devres_npm_advisory_job_history WHERE job_id=$1 AND revision=$2 AND octet_length(data::text)<=8388608")
        .bind(id).bind(revision as i64).fetch_optional(&mut *conn).await.map_err(|_|unavailable())?.ok_or_else(invalid)?;
    let data: Json<Value> = row.try_get("data").map_err(|_| invalid())?;
    let seal: String = row.try_get("data_integrity").map_err(|_| invalid())?;
    let state: String = row.try_get("state_digest").map_err(|_| invalid())?;
    let history = payload_integrity::checked(HISTORY, id, &revision.to_string(), data.0, &seal)?;
    if history["version"] != 1
        || history["job_id"] != id
        || history["revision"] != revision
        || history["job"] != admission["job"]
        || history["cause_authoritative"] != true
        || history["state_digest"] != state
        || state != hash(&history["job"])?
    {
        return Err(invalid());
    }
    let evidence: RecoveryEvidenceReceipt =
        serde_json::from_value(admission["evidence"].clone()).map_err(|_| invalid())?;
    let source = artifact(&admission["job"])?;
    let job = &admission["job"];
    if evidence.version != 1
        || evidence.job_id != id
        || evidence.revision != revision
        || evidence.state_digest != expected
        || evidence.artifact_digest != source.body_hash
        || evidence.artifact_bytes != source.bytes
        || evidence.next_member != job["next"].as_u64().ok_or_else(invalid)?
        || evidence.records != job["records"].as_u64().ok_or_else(invalid)?
        || evidence.gaps != job["gaps"].as_u64().ok_or_else(invalid)?
        || evidence.expanded_bytes != job.get("expanded").and_then(Value::as_u64).unwrap_or(0)
        || evidence.members < evidence.next_member
        || evidence.members > 1_000_000
        || !blake(&evidence.prefix_digest)
        || evidence.evidence_digest != receipt_hash(&evidence)?
    {
        return Err(invalid());
    }
    // Immutable historical checkpoint evidence is checked for its recorded
    // authority. A later archive transfer must not rewrite old admissions.
    let checkpoint: RecoveryCheckpoint =
        serde_json::from_value(admission["checkpoint"].clone()).map_err(|_| invalid())?;
    if checkpoint.version != 1
        || checkpoint.schema != 19
        || checkpoint.store_id.is_empty()
        || checkpoint.store_id.len() > 256
        || checkpoint.store_id.chars().any(char::is_control)
        || checkpoint.archive_epoch <= 0
        || checkpoint.system_identifier.len() > 20
        || checkpoint
            .system_identifier
            .parse::<u64>()
            .ok()
            .is_none_or(|v| v == 0)
        || !checkpoint.coordinated
        || !checkpoint.restoration_verified
        || !blake(&checkpoint.receipt_digest)
    {
        return Err(invalid());
    }
    Ok(())
}

async fn verify_recovery_work(
    conn: &mut PgConnection,
    operation: &str,
    work: &Value,
    admission: &Value,
    cancel: &CancellationToken,
) -> Result<()> {
    cancelled(cancel)?;
    let status = work["status"].as_str().ok_or_else(invalid)?;
    let attempts = work["attempts"].as_u64().ok_or_else(invalid)?;
    if work["version"] != 1
        || work["operation_id"] != operation
        || work["job_id"] != admission["job_id"]
        || work["revision"] != admission["revision"]
        || !matches!(status, "pending" | "running" | "yielded" | "complete")
    {
        return Err(invalid());
    }
    let original = &admission["job"];
    let job = &work["job"];
    validate_job(job)?;
    if job.get("failed").is_some() || job["done"] != json!(status == "complete") {
        return Err(invalid());
    }
    let mut original_fixed = original.clone();
    let mut fixed = job.clone();
    for key in ["done", "failed", "next", "records", "gaps", "expanded"] {
        original_fixed
            .as_object_mut()
            .ok_or_else(invalid)?
            .remove(key);
        fixed.as_object_mut().ok_or_else(invalid)?.remove(key);
    }
    if fixed != original_fixed {
        return Err(invalid());
    }
    let evidence: RecoveryEvidenceReceipt =
        serde_json::from_value(admission["evidence"].clone()).map_err(|_| invalid())?;
    let start = original["next"].as_u64().ok_or_else(invalid)?;
    let next = job["next"].as_u64().ok_or_else(invalid)?;
    if next < start || next > evidence.members {
        return Err(invalid());
    }
    let advanced = next - start;
    for key in ["records", "gaps"] {
        let before = original[key].as_u64().ok_or_else(invalid)?;
        let after = job[key].as_u64().ok_or_else(invalid)?;
        if after < before || after - before > advanced {
            return Err(invalid());
        }
    }
    let old_expanded = original
        .get("expanded")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let expanded = job.get("expanded").and_then(Value::as_u64).unwrap_or(0);
    if expanded < old_expanded || advanced == 0 && expanded != old_expanded {
        return Err(invalid());
    }
    if status == "pending" {
        let mut pending = original.clone();
        pending["done"] = json!(false);
        pending
            .as_object_mut()
            .ok_or_else(invalid)?
            .remove("failed");
        if attempts != 0 || !work["claim"].is_null() || *job != pending {
            return Err(invalid());
        }
    } else if attempts == 0 || work["claim"].as_str().is_none_or(|v| !blake(v)) {
        return Err(invalid());
    }
    if status != "complete" {
        if !work["publication_snapshot"].is_null() || work.get("completion_receipt").is_some() {
            return Err(invalid());
        }
        return Ok(());
    }
    if next != evidence.members {
        return Err(invalid());
    }
    let snapshot_id = work["publication_snapshot"]
        .as_str()
        .filter(|v| blake(v))
        .ok_or_else(invalid)?;
    let bytes:Option<i64>=sqlx_core::query_scalar::query_scalar("SELECT octet_length(data::text)::bigint FROM devres_npm_evidence WHERE kind='snapshots' AND key=$1")
        .bind(snapshot_id).fetch_optional(&mut *conn).await.map_err(|_|unavailable())?;
    if bytes.is_none_or(|v| v < 0 || v > METADATA_MAX as i64) {
        return Err(invalid());
    }
    let row=sqlx_core::query::query("SELECT sequence,kind,key,data,data_integrity,sequence_integrity FROM devres_npm_evidence WHERE kind='snapshots' AND key=$1 AND octet_length(data::text)<=8388608")
        .bind(snapshot_id).fetch_optional(&mut *conn).await.map_err(|_|unavailable())?.ok_or_else(invalid)?;
    let snapshot = payload_integrity::row("devres_npm_evidence", &row)?;
    let source = artifact(job)?;
    let mut expected = json!({"lane":"advisories","artifact":source,"validated_at":job["validated_at"],"records":job["records"],"gaps":job["gaps"],"accounted":true,"complete":job["gaps"]==0,"source":"osv_npm_export","processor_version":NPM_RECOVERY_PROCESSOR_VERSION,"membership":work["job_id"]});
    expected["id"] = json!(crate::npm::corpus::identity(&expected)?);
    if snapshot != expected
        || snapshot["id"] != snapshot_id
        || work["completion_receipt"]
            != json!({"version":1,"operation_id":operation,"job_id":work["job_id"],"snapshot":snapshot_id,"historical_only":true,"default_promoted":false})
    {
        return Err(invalid());
    }
    let ready = payload_integrity::load(
        &mut *conn,
        "devres_npm_state",
        "",
        &format!("ready:{snapshot_id}"),
    )
    .await?
    .ok_or_else(invalid)?;
    if ready.0 != json!({"id":snapshot_id,"records":job["records"],"accounted":true}) {
        return Err(invalid());
    }
    let members:i64=sqlx_core::query_scalar::query_scalar("SELECT count(*)::bigint FROM devres_npm_evidence WHERE kind='advisory-members' AND data->>'snapshot'=$1")
        .bind(work["job_id"].as_str().ok_or_else(invalid)?).fetch_one(&mut *conn).await.map_err(|_|unavailable())?;
    if members < 0 || members as u64 != job["records"].as_u64().ok_or_else(invalid)? {
        return Err(invalid());
    }
    Ok(())
}

pub(crate) async fn verify_history(
    conn: &mut PgConnection,
    cancel: &CancellationToken,
) -> Result<()> {
    let mut after_id = String::new();
    let mut after_revision = 0_i64;
    let mut prior_id = String::new();
    let mut prior_revision = 0_i64;
    let mut prior_seal: Option<String> = None;
    loop {
        cancelled(cancel)?;
        let (bytes,maximum):(i64,i64)=sqlx_core::query_as::query_as("SELECT COALESCE(sum(n),0)::bigint,COALESCE(max(n),0)::bigint FROM (SELECT octet_length(data::text)::bigint AS n FROM devres_npm_advisory_job_history WHERE (job_id,revision)>($1,$2) ORDER BY job_id,revision LIMIT 8) page")
            .bind(&after_id).bind(after_revision).fetch_one(&mut *conn).await.map_err(|_|unavailable())?;
        if bytes > 64 * 1024 * 1024 || maximum > METADATA_MAX as i64 {
            return Err(Error::capacity(
                "Recovery history verification page exceeds its bound.",
            ));
        }
        let rows=sqlx_core::query::query("SELECT CASE WHEN octet_length(job_id)<=71 THEN job_id END AS job_id,revision,CASE WHEN octet_length(state_digest)<=71 THEN state_digest END AS state_digest,data,CASE WHEN octet_length(data_integrity)<=71 THEN data_integrity END AS data_integrity FROM devres_npm_advisory_job_history WHERE (job_id,revision)>($1,$2) ORDER BY job_id,revision LIMIT 8")
            .bind(&after_id).bind(after_revision).fetch_all(&mut *conn).await.map_err(|_|unavailable())?;
        if rows.is_empty() {
            break;
        }
        for row in rows {
            cancelled(cancel)?;
            let id: String = row.try_get("job_id").map_err(|_| invalid())?;
            let revision: i64 = row.try_get("revision").map_err(|_| invalid())?;
            let data: Json<Value> = row.try_get("data").map_err(|_| invalid())?;
            let seal: String = row.try_get("data_integrity").map_err(|_| invalid())?;
            let state: String = row.try_get("state_digest").map_err(|_| invalid())?;
            let data =
                payload_integrity::checked(HISTORY, &id, &revision.to_string(), data.0, &seal)?;
            validate_job(&data["job"])?;
            if prior_id != id {
                prior_revision = 0;
                prior_seal = None;
            }
            if data["version"] != 1
                || data["cause_authoritative"].as_bool().is_none()
                || data["job_id"] != id
                || data["revision"] != revision
                || data["state_digest"] != state
                || state != hash(&data["job"])?
                || job_id(&data["job"])? != id
                || revision != prior_revision + 1
                || data["previous_digest"] != json!(prior_seal)
            {
                return Err(invalid());
            }
            after_id = id.clone();
            after_revision = revision;
            prior_id = id;
            prior_revision = revision;
            prior_seal = Some(seal);
        }
    }
    for table in [JOURNAL, WORK] {
        let mut after = String::new();
        loop {
            cancelled(cancel)?;
            let sql = format!(
                "SELECT COALESCE(sum(n),0)::bigint,COALESCE(max(n),0)::bigint FROM (SELECT octet_length(data::text)::bigint AS n FROM {table} WHERE operation_id>$1 ORDER BY operation_id LIMIT 8) page"
            );
            let (bytes, maximum): (i64, i64) =
                sqlx_core::query_as::query_as(sqlx_core::sql_str::AssertSqlSafe(sql))
                    .bind(&after)
                    .fetch_one(&mut *conn)
                    .await
                    .map_err(|_| unavailable())?;
            if bytes > 64 * 1024 * 1024 || maximum > METADATA_MAX as i64 {
                return Err(Error::capacity(
                    "Recovery journal verification page exceeds its bound.",
                ));
            }
            let sql = format!(
                "SELECT CASE WHEN octet_length(operation_id)<=71 THEN operation_id END AS operation_id FROM {table} WHERE operation_id>$1 ORDER BY operation_id LIMIT 8"
            );
            let ids: Vec<String> =
                sqlx_core::query_scalar::query_scalar(sqlx_core::sql_str::AssertSqlSafe(sql))
                    .bind(&after)
                    .fetch_all(&mut *conn)
                    .await
                    .map_err(|_| unavailable())?;
            if ids.is_empty() {
                break;
            }
            for operation in ids {
                let admission = verify_recovery_payload(conn, JOURNAL, &operation, cancel).await?;
                verify_recovery_admission(conn, &operation, &admission, cancel).await?;
                let work = verify_recovery_payload(conn, WORK, &operation, cancel).await?;
                verify_recovery_work(conn, &operation, &work, &admission, cancel).await?;
                after = operation;
            }
        }
    }
    Ok(())
}

async fn connection(database_url: &str, apply: bool) -> Result<PgConnection> {
    connection_with_diagnostics(database_url, apply, &Diagnostics::default()).await
}
async fn connection_with_diagnostics(
    database_url: &str,
    apply: bool,
    diagnostics: &Diagnostics,
) -> Result<PgConnection> {
    diagnostics.start(Phase::SqlConnect);
    let mut conn = PgConnection::connect(database_url)
        .await
        .map_err(|error| sql_failure(diagnostics, Phase::SqlConnect, &error))?;
    diagnostics.ok(Phase::SqlConnect);
    diagnostics.start(Phase::SqlSetup);
    sqlx_core::raw_sql::raw_sql("SET statement_timeout='3000ms'; SET lock_timeout='1000ms'")
        .execute(&mut conn)
        .await
        .map_err(|error| sql_failure(diagnostics, Phase::SqlSetup, &error))?;
    diagnostics.ok(Phase::SqlSetup);
    diagnostics.start(Phase::Lifecycle);
    let sql = if apply {
        "SELECT pg_try_advisory_lock(1835365490,2)"
    } else {
        "SELECT pg_try_advisory_lock_shared(1835365490,2)"
    };
    let held: bool = sqlx_core::query_scalar::query_scalar(sql)
        .fetch_one(&mut conn)
        .await
        .map_err(|error| sql_failure(diagnostics, Phase::Lifecycle, &error))?;
    if !held {
        diagnostics.fail(Phase::Lifecycle, Reason::LockBusy);
        return Err(Error::capacity(
            "Collection recovery requires stopped participants.",
        ));
    }
    if apply {
        let held: bool =
            sqlx_core::query_scalar::query_scalar("SELECT pg_try_advisory_lock(1835365490,1)")
                .fetch_one(&mut conn)
                .await
                .map_err(|error| sql_failure(diagnostics, Phase::Lifecycle, &error))?;
        if !held {
            return Err(Error::capacity(
                "Collection recovery requires stopped writers.",
            ));
        }
    } else {
        sqlx_core::raw_sql::raw_sql("SET default_transaction_read_only=on")
            .execute(&mut conn)
            .await
            .map_err(|error| sql_failure(diagnostics, Phase::Lifecycle, &error))?;
    }
    diagnostics.ok(Phase::Lifecycle);
    diagnostics.start(Phase::Schema);
    let schema:i32=sqlx_core::query_scalar::query_scalar("SELECT version FROM devres_schema WHERE singleton AND (SELECT active FROM devres_integrity_control WHERE singleton) AND to_regclass('public.devres_archive_restore_pending') IS NULL")
        .fetch_one(&mut conn).await.map_err(|error|sql_failure(diagnostics, Phase::Schema, &error))?;
    if schema != 19 {
        diagnostics.fail(Phase::Schema, Reason::Schema);
        return Err(Error::unavailable(
            "Collection recovery requires active schema 19.",
        ));
    }
    diagnostics.ok(Phase::Schema);
    diagnostics.start(Phase::Policy);
    diagnostics.domain(
        Phase::Policy,
        attribution_storage::verify_control(&mut conn).await,
    )?;
    Ok(conn)
}
fn sql_failure(diagnostics: &Diagnostics, phase: Phase, error: &sqlx_core::Error) -> Error {
    diagnostics.fail(phase, Reason::sql(error));
    unavailable()
}

struct Selected {
    job: Value,
    state_digest: String,
    reason: &'static str,
}
async fn selected(
    conn: &mut PgConnection,
    options: &CollectionRecoveryOptions,
) -> Result<Selected> {
    selected_with_diagnostics(conn, options, &Diagnostics::default()).await
}
async fn selected_with_diagnostics(
    conn: &mut PgConnection,
    options: &CollectionRecoveryOptions,
    diagnostics: &Diagnostics,
) -> Result<Selected> {
    diagnostics.start(Phase::HistorySelect);
    let row=sqlx_core::query::query("SELECT data,data_integrity FROM devres_npm_advisory_job_history WHERE job_id=$1 AND revision=$2 AND octet_length(data::text)<=8388608")
        .bind(&options.job_id).bind(options.revision as i64).fetch_optional(&mut *conn).await.map_err(|error|sql_failure(diagnostics, Phase::HistorySelect, &error))?;
    let row = diagnostics.domain(
        Phase::HistorySelect,
        row.ok_or_else(|| Error::not_found("Exact retained advisory job revision unavailable.")),
    )?;
    let checked = (|| -> Result<_> {
        let data: Json<Value> = row.try_get("data").map_err(|_| invalid())?;
        let seal: String = row.try_get("data_integrity").map_err(|_| invalid())?;
        let data = payload_integrity::checked(
            HISTORY,
            &options.job_id,
            &options.revision.to_string(),
            data.0,
            &seal,
        )?;
        let job = data["job"].clone();
        validate_job(&job)?;
        if job_id(&job)? != options.job_id
            || data["revision"] != options.revision
            || data["state_digest"] != hash(&job)?
        {
            return Err(invalid());
        }
        Ok((data, seal, job))
    })();
    let (data, seal, job) = diagnostics.domain(Phase::HistorySelect, checked)?;
    diagnostics.start(Phase::StateSelect);
    let checked = async {
    let latest: i64 = sqlx_core::query_scalar::query_scalar(
        "SELECT max(revision) FROM devres_npm_advisory_job_history WHERE job_id=$1",
    )
    .bind(&options.job_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(|_| unavailable())?;
    let mut reason = eligibility(&job)?;
    if data["cause_authoritative"] != true {
        reason = "legacy_unknown";
    }
    if latest != options.revision as i64 {
        reason = "stale_job_revision";
    }
    let current = payload_integrity::load(&mut *conn, "devres_npm_state", "", "advisory-job")
        .await?
        .map(|v| hash(&v.0))
        .transpose()?;
    let default = payload_integrity::load(&mut *conn, "devres_npm_state", "", "default-advisories")
        .await?
        .map(|v| hash(&v.0))
        .transpose()?;
    let published:bool=sqlx_core::query_scalar::query_scalar("SELECT EXISTS(SELECT 1 FROM devres_npm_evidence WHERE kind='snapshots' AND data->>'membership'=$1)").bind(&options.job_id).fetch_one(&mut *conn).await.map_err(|_|unavailable())?;
    if published {
        reason = "already_published";
    }
    let archive=sqlx_core::query::query("SELECT epoch,backend,store_id,binding,pending_binding,initializing_s3 FROM devres_archive_control WHERE singleton").fetch_one(&mut *conn).await.map_err(|_|unavailable())?;
    let authority = json!({"epoch":archive.try_get::<i64,_>("epoch").map_err(|_|invalid())?,"backend":archive.try_get::<String,_>("backend").map_err(|_|invalid())?,"store_id":archive.try_get::<String,_>("store_id").map_err(|_|invalid())?,"binding":archive.try_get::<Option<String>,_>("binding").map_err(|_|invalid())?});
    if archive
        .try_get::<Option<String>, _>("pending_binding")
        .map_err(|_| invalid())?
        .is_some()
        || archive
            .try_get::<bool, _>("initializing_s3")
            .map_err(|_| invalid())?
    {
        reason = "archive_transition";
    }
    let state_digest = hash(
        &json!({"version":1,"recipe":options.recipe,"history_seal":seal,"current":current,"default":default,"archive":authority,"latest_revision":latest,"published":published,"policy":devres_domain::attribution::ATTRIBUTION_POLICY_FINGERPRINT}),
    )?;
    Ok(Selected {
        job,
        state_digest,
        reason,
    })
    }.await;
    diagnostics.domain(Phase::StateSelect, checked)
}
fn report(
    options: &CollectionRecoveryOptions,
    selected: &Selected,
    outcome: &str,
) -> CollectionRecoveryReport {
    CollectionRecoveryReport {
        version: 1,
        job_id: options.job_id.clone(),
        revision: options.revision,
        recipe: options.recipe.clone(),
        state_digest: selected.state_digest.clone(),
        eligible: selected.reason == "eligible",
        outcome: outcome.into(),
        reason: selected.reason.into(),
        operation_id: options.operation_id.clone(),
        publication_snapshot: None,
    }
}
fn receipt_hash(receipt: &RecoveryEvidenceReceipt) -> Result<String> {
    let mut value = serde_json::to_value(receipt).map_err(|_| invalid())?;
    value
        .as_object_mut()
        .ok_or_else(invalid)?
        .remove("evidence_digest");
    hash(&value)
}
fn matches_receipt(
    receipt: &RecoveryEvidenceReceipt,
    options: &CollectionRecoveryOptions,
    selected: &Selected,
) -> Result<bool> {
    let artifact = artifact(&selected.job)?;
    Ok(receipt.version == 1
        && receipt.job_id == options.job_id
        && receipt.revision == options.revision
        && receipt.state_digest == selected.state_digest
        && receipt.artifact_digest == artifact.body_hash
        && receipt.artifact_bytes == artifact.bytes
        && receipt.next_member == selected.job["next"].as_u64().ok_or_else(invalid)?
        && receipt.records == selected.job["records"].as_u64().ok_or_else(invalid)?
        && receipt.gaps == selected.job["gaps"].as_u64().ok_or_else(invalid)?
        && receipt.evidence_digest == receipt_hash(receipt)?)
}
pub async fn diagnose_npm_recovery(
    database_url: &str,
    options: &CollectionRecoveryOptions,
    evidence: Option<&RecoveryEvidenceReceipt>,
) -> Result<CollectionRecoveryReport> {
    diagnose_npm_recovery_with_diagnostics(database_url, options, evidence, &Diagnostics::default())
        .await
}
/// Same read-only diagnosis with optional private, closed phase observations.
pub async fn diagnose_npm_recovery_with_diagnostics(
    database_url: &str,
    options: &CollectionRecoveryOptions,
    evidence: Option<&RecoveryEvidenceReceipt>,
    diagnostics: &Diagnostics,
) -> Result<CollectionRecoveryReport> {
    options.validate(false)?;
    let mut conn = connection_with_diagnostics(database_url, false, diagnostics).await?;
    diagnostics.start(Phase::Transaction);
    let mut tx = conn
        .begin()
        .await
        .map_err(|error| sql_failure(diagnostics, Phase::Transaction, &error))?;
    sqlx_core::raw_sql::raw_sql("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *tx)
        .await
        .map_err(|error| sql_failure(diagnostics, Phase::Transaction, &error))?;
    diagnostics.ok(Phase::Transaction);
    let mut found = selected_with_diagnostics(&mut tx, options, diagnostics).await?;
    diagnostics.start(Phase::Eligibility);
    if found.reason == "eligible" && require_available_processor(PROCESSOR_VERSION).is_err() {
        found.reason = "unsupported_recipe_processor";
    }
    if found.reason == "eligible"
        && !evidence
            .map(|v| matches_receipt(v, options, &found))
            .transpose()?
            .unwrap_or(false)
    {
        found.reason = "evidence_not_verified";
    }
    let result = report(
        options,
        &found,
        if found.reason == "eligible" {
            "eligible"
        } else {
            "ineligible"
        },
    );
    diagnostics.ok(Phase::Eligibility);
    diagnostics.start(Phase::Rollback);
    tx.rollback()
        .await
        .map_err(|error| sql_failure(diagnostics, Phase::Rollback, &error))?;
    diagnostics.ok(Phase::Rollback);
    Ok(result)
}

fn member_values(
    job: &Value,
    position: usize,
    result: &Result<Option<crate::npm::corpus::ScannedAdvisory>>,
) -> Result<Vec<(String, String, Value)>> {
    let snapshot = job_id(job)?;
    let export = artifact(job)?;
    let mut values = Vec::new();
    match result {
        Ok(Some(item)) => {
            let record = &item.record;
            if record["matching_complete"] != true || record["rights_gap"] == true {
                let gap = json!({"snapshot":snapshot,"member":position,"code":"unsupported_advisory_coverage","artifact":export.body_hash});
                values.push(("gaps".into(), crate::npm::corpus::identity(&gap)?, gap));
            }
            let id = crate::npm::corpus::identity(record)?;
            values.push(("advisories".into(), id.clone(), record.clone()));
            let raw_id = if record["rights_gap"] == true {
                None
            } else {
                let body_hash = crate::integrity::hash(&item.bytes);
                let member_artifact = BulkArtifact {
                    body_hash: body_hash.clone(),
                    bytes: item.bytes.len() as u64,
                    relative_path: crate::integrity::relative_path(&body_hash)?
                        .to_string_lossy()
                        .into_owned(),
                };
                let data = json!({"record":id,"artifact":member_artifact,"member_path":item.path,"export_hash":export.body_hash,"source_url":crate::npm::source::OSV_EXPORT});
                let key = crate::npm::corpus::identity(&data)?;
                values.push(("advisory-raw".into(), key.clone(), data));
                Some(key)
            };
            let member = json!({"snapshot":snapshot,"id":record["id"],"record":id,"raw":raw_id});
            values.push((
                "advisory-members".into(),
                crate::npm::corpus::identity(&member)?,
                member,
            ));
            let names: Vec<_> = record["packages"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|v| v.as_str().or_else(|| v.get("name").and_then(Value::as_str)))
                .collect();
            for name in if names.is_empty() { vec!["*"] } else { names } {
                let link = json!({"snapshot":snapshot,"name":name,"record":id,"id":record["id"]});
                values.push((
                    "advisory-packages".into(),
                    crate::npm::corpus::identity(&link)?,
                    link,
                ));
            }
        }
        Ok(None) => {}
        Err(error) => {
            let gap = json!({"snapshot":snapshot,"member":position,"code":error.code,"artifact":export.body_hash});
            values.push(("gaps".into(), crate::npm::corpus::identity(&gap)?, gap));
        }
    }
    Ok(values)
}
async fn verify_row(
    conn: &mut PgConnection,
    kind: &str,
    key: &str,
    expected: &Value,
    required: bool,
) -> Result<bool> {
    let row=sqlx_core::query::query("SELECT sequence,kind,key,data,data_integrity,sequence_integrity FROM devres_npm_evidence WHERE kind=$1 AND key=$2 AND octet_length(data::text)<=8388608")
        .bind(kind).bind(key).fetch_optional(&mut *conn).await.map_err(|_|unavailable())?;
    if let Some(row) = row {
        if payload_integrity::row("devres_npm_evidence", &row)? != *expected {
            return Err(invalid());
        }
        Ok(true)
    } else if required {
        Err(Error::integrity(
            "Committed advisory prefix evidence is missing.",
        ))
    } else {
        Ok(false)
    }
}
fn digest_file(
    file: &mut std::fs::File,
    cancel: &CancellationToken,
    deadline: Instant,
) -> Result<(String, u64)> {
    use std::io::{Read, Seek};
    file.rewind().map_err(|_| invalid())?;
    let mut hasher = blake3::Hasher::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 65536];
    loop {
        cancelled(cancel)?;
        if Instant::now() >= deadline {
            return Err(Error::capacity(
                "Recovery evidence verification deadline exceeded.",
            ));
        }
        let count = file.read(&mut buffer).map_err(|_| invalid())?;
        if count == 0 {
            break;
        }
        bytes = bytes
            .checked_add(count as u64)
            .filter(|v| *v <= MAX_ARTIFACT_BYTES)
            .ok_or_else(invalid)?;
        hasher.update(&buffer[..count]);
    }
    file.rewind().map_err(|_| invalid())?;
    Ok((format!("blake3:{}", hasher.finalize().to_hex()), bytes))
}
/// Freeze untrusted local bytes into an anonymous, task-owned file before parsing.
/// The external path is never reopened between verification and publication.
async fn snapshot_artifact(
    path: &Path,
    expected: &BulkArtifact,
    cancel: &CancellationToken,
    deadline: Instant,
) -> Result<std::fs::File> {
    let source = crate::local_evidence::open_private_input(path, MAX_ARTIFACT_BYTES)?;
    let expected = expected.clone();
    let stop = cancel.clone();
    tokio::task::spawn_blocking(move || {
        use std::io::{Read, Seek, Write};
        use std::os::unix::fs::PermissionsExt;
        if source.metadata().map_err(|_| invalid())?.len() != expected.bytes {
            return Err(invalid());
        }
        let root = tempfile::Builder::new()
            .prefix("devres-recovery-bytes-")
            .tempdir_in("/tmp")
            .map_err(|_| unavailable())?;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .map_err(|_| unavailable())?;
        if fs2::available_space(root.path()).map_err(|_| unavailable())?
            < expected.bytes.saturating_add(64 * 1024 * 1024)
        {
            return Err(Error::capacity(
                "Insufficient disposable recovery snapshot headroom.",
            ));
        }
        let mut snapshot = tempfile::tempfile_in(root.path()).map_err(|_| unavailable())?;
        let mut source = source;
        let mut bytes = 0_u64;
        let mut digest = blake3::Hasher::new();
        let mut buffer = [0_u8; 65536];
        loop {
            cancelled(&stop)?;
            if Instant::now() >= deadline {
                return Err(Error::capacity("Recovery snapshot deadline exceeded."));
            }
            let count = source.read(&mut buffer).map_err(|_| invalid())?;
            if count == 0 {
                break;
            }
            bytes = bytes
                .checked_add(count as u64)
                .filter(|v| *v <= expected.bytes)
                .ok_or_else(invalid)?;
            digest.update(&buffer[..count]);
            snapshot
                .write_all(&buffer[..count])
                .map_err(|_| unavailable())?;
        }
        if bytes != expected.bytes
            || format!("blake3:{}", digest.finalize().to_hex()) != expected.body_hash
        {
            return Err(invalid());
        }
        snapshot.rewind().map_err(|_| unavailable())?;
        Ok(snapshot)
    })
    .await
    .map_err(|_| unavailable())?
}

async fn verify_file(
    conn: &mut PgConnection,
    options: &CollectionRecoveryOptions,
    found: &Selected,
    path: &Path,
    cancel: &CancellationToken,
) -> Result<RecoveryEvidenceReceipt> {
    require_available_processor(PROCESSOR_VERSION)?;
    let deadline = Instant::now() + Duration::from_secs(300);
    let file = snapshot_artifact(path, &artifact(&found.job)?, cancel, deadline).await?;
    verify_descriptor(conn, options, found, file, cancel, deadline).await
}

async fn verify_descriptor(
    conn: &mut PgConnection,
    options: &CollectionRecoveryOptions,
    found: &Selected,
    mut file: std::fs::File,
    cancel: &CancellationToken,
    deadline: Instant,
) -> Result<RecoveryEvidenceReceipt> {
    require_available_processor(PROCESSOR_VERSION)?;
    let before = file.metadata().map_err(|_| invalid())?;
    let expected = artifact(&found.job)?;
    let source = file.try_clone().map_err(|_| invalid())?;
    let stop = cancel.clone();
    let (mut file, body, bytes) = tokio::task::spawn_blocking(move || {
        let result = digest_file(&mut file, &stop, deadline)?;
        Ok::<_, Error>((file, result.0, result.1))
    })
    .await
    .map_err(|_| invalid())??;
    if body != expected.body_hash || bytes != expected.bytes {
        return Err(Error::integrity(
            "Exact retained export digest or size differs.",
        ));
    }
    let next = found.job["next"].as_u64().ok_or_else(invalid)?;
    let mut position = 0_usize;
    let mut expanded = 0_u64;
    let mut records = 0_u64;
    let mut gaps = 0_u64;
    let mut prefix = hash(&json!({"version":1,"job":options.job_id}))?;
    let mut prefix_expanded = 0_u64;
    let mut partial_member_key: Option<String> = None;
    loop {
        cancelled(cancel)?;
        if Instant::now() >= deadline {
            return Err(Error::capacity(
                "Recovery evidence verification deadline exceeded.",
            ));
        }
        let (sender, mut receiver) = tokio::sync::mpsc::channel(2);
        let stop = cancel.child_token();
        let worker_stop = stop.clone();
        let scan_file = source.try_clone().map_err(|_| invalid())?;
        let worker = tokio::task::spawn_blocking(move || {
            crate::npm::corpus::scan_export(scan_file, position, expanded, sender, &worker_stop)
        });
        let result=async{
            while let Some((index,size,item))=receiver.recv().await{
                cancelled(cancel)?;
                if Instant::now()>=deadline{return Err(Error::capacity("Recovery evidence verification deadline exceeded."));}
                if index!=position{return Err(invalid());}position=index+1;expanded=size;
                let values=member_values(&found.job,index,&item)?;
                if (index as u64)<next{
                    for (kind,key,value) in &values{verify_row(conn,kind,key,value,true).await?;}
                    if matches!(item,Ok(Some(_))){records+=1;}
                    gaps+=values.iter().filter(|v|v.0=="gaps").count() as u64;
                    prefix=hash(&json!({"previous":prefix,"member":index,"expanded":size,"rows":values.iter().map(|(kind,key,_)|json!([kind,key])).collect::<Vec<_>>()}))?;
                    prefix_expanded=size;
                }else{
                    // A crash may retain deterministic writes for the next member
                    // before committing its cursor. Admit only exact matching rows.
                    for (kind,key,value) in &values{verify_row(conn,kind,key,value,false).await?;}
                    if index as u64==next{partial_member_key=values.iter().find(|v|v.0=="advisory-members").map(|v|v.1.clone());}
                }
            }
            Ok::<(),Error>(())
        }.await;
        if let Err(error) = result {
            stop.cancel();
            drop(receiver);
            let _ = worker.await;
            return Err(error);
        }
        let complete = worker.await.map_err(|_| invalid())??;
        if complete {
            break;
        }
    }
    if next > position as u64
        || records != found.job["records"].as_u64().ok_or_else(invalid)?
        || gaps != found.job["gaps"].as_u64().ok_or_else(invalid)?
        || prefix_expanded
            != found
                .job
                .get("expanded")
                .and_then(Value::as_u64)
                .unwrap_or(0)
    {
        return Err(Error::integrity(
            "Committed advisory cursor or counters differ from retained export.",
        ));
    }
    // Membership may have one partially retained next member, never unexplained
    // later members or duplicate record identities hidden behind the cursor.
    let count:i64=sqlx_core::query_scalar::query_scalar("SELECT count(*)::bigint FROM devres_npm_evidence WHERE kind='advisory-members' AND data->>'snapshot'=$1")
        .bind(&options.job_id).fetch_one(&mut *conn).await.map_err(|_|unavailable())?;
    let partial = if let Some(key) = partial_member_key {
        sqlx_core::query_scalar::query_scalar::<_,i64>("SELECT count(*)::bigint FROM devres_npm_evidence WHERE kind='advisory-members' AND key=$1").bind(key).fetch_one(&mut *conn).await.map_err(|_|unavailable())?
    } else {
        0
    };
    if count != records as i64 + partial {
        return Err(Error::integrity(
            "Retained advisory membership exceeds its committed prefix.",
        ));
    }
    let stop = cancel.clone();
    let (_, digest, read_bytes) = tokio::task::spawn_blocking(move || {
        let result = digest_file(&mut file, &stop, deadline)?;
        Ok::<_, Error>((file, result.0, result.1))
    })
    .await
    .map_err(|_| invalid())??;
    let after = source.metadata().map_err(|_| invalid())?;
    if digest != body
        || read_bytes != bytes
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
    {
        return Err(invalid());
    }
    let mut receipt = RecoveryEvidenceReceipt {
        version: 1,
        job_id: options.job_id.clone(),
        revision: options.revision,
        state_digest: found.state_digest.clone(),
        artifact_digest: body,
        artifact_bytes: bytes,
        members: position as u64,
        next_member: next,
        records,
        gaps,
        expanded_bytes: prefix_expanded,
        prefix_digest: prefix,
        evidence_digest: String::new(),
    };
    receipt.evidence_digest = receipt_hash(&receipt)?;
    Ok(receipt)
}
pub async fn verify_npm_recovery_evidence(
    database_url: &str,
    options: &CollectionRecoveryOptions,
    artifact_path: &Path,
    cancel: &CancellationToken,
) -> Result<RecoveryEvidenceReceipt> {
    options.validate(false)?;
    let mut conn = connection(database_url, false).await?;
    let mut tx = conn.begin().await.map_err(|_| unavailable())?;
    sqlx_core::raw_sql::raw_sql("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *tx)
        .await
        .map_err(|_| unavailable())?;
    let found = selected(&mut tx, options).await?;
    let result = verify_file(&mut tx, options, &found, artifact_path, cancel).await?;
    tx.rollback().await.map_err(|_| unavailable())?;
    Ok(result)
}

pub async fn apply_npm_recovery(
    database_url: &str,
    options: &CollectionRecoveryOptions,
    evidence: &RecoveryEvidenceReceipt,
    artifact_path: &Path,
    checkpoint: &RecoveryCheckpoint,
    cancel: &CancellationToken,
) -> Result<CollectionRecoveryReport> {
    options.validate(true)?;
    cancelled(cancel)?;
    if checkpoint.version != 1
        || checkpoint.schema != 19
        || !checkpoint.coordinated
        || !checkpoint.restoration_verified
        || !blake(&checkpoint.receipt_digest)
    {
        return Err(Error::invalid(
            "A coordinated restoration-verified checkpoint binding is required.",
        ));
    }
    let operation = options.operation_id.as_deref().ok_or_else(invalid)?;
    let mut conn = connection(database_url, true).await?;
    let mut tx = conn.begin().await.map_err(|_| unavailable())?;
    let found = selected(&mut tx, options).await?;
    let authority = sqlx_core::query::query(
        "SELECT store_id,epoch FROM devres_archive_control WHERE singleton",
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| unavailable())?;
    let system: String = sqlx_core::query_scalar::query_scalar(
        "SELECT system_identifier::text FROM pg_control_system()",
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| unavailable())?;
    if checkpoint.store_id
        != authority
            .try_get::<String, _>("store_id")
            .map_err(|_| invalid())?
        || checkpoint.archive_epoch
            != authority
                .try_get::<i64, _>("epoch")
                .map_err(|_| invalid())?
        || checkpoint.system_identifier != system
    {
        return Err(Error::invalid(
            "Checkpoint database/archive binding differs.",
        ));
    }
    let existing=sqlx_core::query::query("SELECT operation_id,data,data_integrity FROM devres_npm_advisory_recoveries WHERE operation_id=$1 OR (job_id=$2 AND recipe=$3)")
        .bind(operation).bind(&options.job_id).bind(&options.recipe).fetch_optional(&mut *tx).await.map_err(|_|unavailable())?;
    if let Some(row) = existing {
        let id: String = row.try_get("operation_id").map_err(|_| invalid())?;
        let data: Json<Value> = row.try_get("data").map_err(|_| invalid())?;
        let seal: String = row.try_get("data_integrity").map_err(|_| invalid())?;
        let data = payload_integrity::checked(JOURNAL, "", &id, data.0, &seal)?;
        if id != operation
            || data["job_id"] != options.job_id
            || data["revision"] != options.revision
            || data["recipe"] != options.recipe
            || data["expected_state"] != json!(options.expected_state)
            || data["evidence"] != serde_json::to_value(evidence).map_err(|_| invalid())?
            || data["checkpoint"] != serde_json::to_value(checkpoint).map_err(|_| invalid())?
        {
            return Err(Error::invalid(
                "Recovery operation identity already binds different admission.",
            ));
        }
        let mut result = report(options, &found, "already_applied");
        result.eligible = false;
        result.reason = "already_applied".into();
        tx.rollback().await.map_err(|_| unavailable())?;
        return Ok(result);
    }
    if found.reason != "eligible"
        || options.expected_state.as_deref() != Some(&found.state_digest)
        || !matches_receipt(evidence, options, &found)?
    {
        return Err(Error::invalid(
            "Recovery eligibility or expected state changed.",
        ));
    }
    let verified = verify_file(&mut tx, options, &found, artifact_path, cancel).await?;
    if verified != *evidence {
        return Err(Error::integrity(
            "Recovery evidence changed after verification.",
        ));
    }
    cancelled(cancel)?;
    let admission = json!({"version":1,"operation_id":operation,"job_id":options.job_id,"revision":options.revision,"recipe":options.recipe,"expected_state":found.state_digest,"evidence":evidence,"checkpoint":checkpoint,"job":found.job});
    bounded(&admission)?;
    sqlx_core::query::query("INSERT INTO devres_npm_advisory_recoveries(operation_id,job_id,recipe,data,data_integrity) VALUES($1,$2,$3,$4,$5)")
        .bind(operation).bind(&options.job_id).bind(&options.recipe).bind(Json(&admission)).bind(payload_integrity::digest(JOURNAL,"",operation,&admission)?).execute(&mut *tx).await.map_err(|_|unavailable())?;
    let mut job = found.job.clone();
    job["done"] = json!(false);
    job.as_object_mut().ok_or_else(invalid)?.remove("failed");
    let work = json!({"version":1,"operation_id":operation,"job_id":options.job_id,"revision":options.revision,"job":job,"status":"pending","claim":null,"attempts":0,"publication_snapshot":null});
    sqlx_core::query::query(
        "INSERT INTO devres_npm_recovery_work(operation_id,data,data_integrity) VALUES($1,$2,$3)",
    )
    .bind(operation)
    .bind(Json(&work))
    .bind(payload_integrity::digest(WORK, "", operation, &work)?)
    .execute(&mut *tx)
    .await
    .map_err(|_| unavailable())?;
    cancelled(cancel)?;
    tx.commit().await.map_err(|_| {
        Error::unavailable(
            "Recovery commit outcome uncertain; reconcile the exact operation identity.",
        )
    })?;
    let mut result = report(options, &found, "applied");
    result.eligible = false;
    result.reason = "queued".into();
    Ok(result)
}

async fn load_work(conn: &mut PgConnection, operation: &str) -> Result<Value> {
    let row=sqlx_core::query::query("SELECT data,data_integrity FROM devres_npm_recovery_work WHERE operation_id=$1 AND octet_length(data::text)<=8388608 FOR UPDATE")
        .bind(operation).fetch_optional(&mut *conn).await.map_err(|_|unavailable())?.ok_or_else(||Error::not_found("Exact recovery operation unavailable."))?;
    let data: Json<Value> = row.try_get("data").map_err(|_| invalid())?;
    let seal: String = row.try_get("data_integrity").map_err(|_| invalid())?;
    let data = payload_integrity::checked(WORK, "", operation, data.0, &seal)?;
    if data["version"] != 1
        || data["operation_id"] != operation
        || !matches!(
            data["status"].as_str(),
            Some("pending" | "running" | "yielded" | "complete")
        )
    {
        return Err(invalid());
    }
    validate_job(&data["job"])?;
    if data["job_id"] != job_id(&data["job"])?
        || data["revision"]
            .as_u64()
            .is_none_or(|v| v == 0 || v > i64::MAX as u64)
        || data["attempts"].as_u64().is_none()
    {
        return Err(invalid());
    }
    Ok(data)
}
async fn save_work(conn: &mut PgConnection, operation: &str, data: &Value) -> Result<()> {
    bounded(data)?;
    let changed = sqlx_core::query::query(
        "UPDATE devres_npm_recovery_work SET data=$2,data_integrity=$3 WHERE operation_id=$1",
    )
    .bind(operation)
    .bind(Json(data))
    .bind(payload_integrity::digest(WORK, "", operation, data)?)
    .execute(&mut *conn)
    .await
    .map_err(|_| unavailable())?;
    if changed.rows_affected() != 1 {
        return Err(invalid());
    }
    Ok(())
}
async fn checkpoint_work(
    store: &PgBlobStore,
    operation: &str,
    claim: &str,
    job: &Value,
    status: &str,
) -> Result<()> {
    store.owner_fence().await?;
    let mut owner = store.owner.lock().await;
    let mut tx = owner.begin().await.map_err(|_| unavailable())?;
    let mut work = load_work(&mut tx, operation).await?;
    if work["claim"] != claim
        || work["status"] != "running"
        || job_id(&work["job"])? != job_id(job)?
    {
        return Err(Error::unavailable("Recovery claim lost."));
    }
    work["job"] = job.clone();
    work["status"] = json!(status);
    save_work(&mut tx, operation, &work).await?;
    tx.commit().await.map_err(|_| {
        Error::unavailable(
            "Recovery checkpoint outcome uncertain; reconcile the exact operation identity.",
        )
    })
}
pub(crate) async fn complete_work(
    conn: &mut PgConnection,
    operation: &str,
    claim: &str,
    snapshot: &Value,
) -> Result<()> {
    let mut work = load_work(conn, operation).await?;
    if work["status"] != "running"
        || work["claim"] != claim
        || snapshot["membership"] != work["job_id"]
        || snapshot["records"] != work["job"]["records"]
        || snapshot["gaps"] != work["job"]["gaps"]
    {
        return Err(Error::unavailable(
            "Recovery completion claim or cursor differs.",
        ));
    }
    work["status"] = json!("complete");
    work["job"]["done"] = json!(true);
    work["publication_snapshot"] = snapshot["id"].clone();
    work["completion_receipt"] = json!({"version":1,"operation_id":operation,"job_id":work["job_id"],"snapshot":snapshot["id"],"historical_only":true,"default_promoted":false});
    save_work(conn, operation, &work).await
}

/// Read-only preflight before archive attachment or any recovery claim.
pub async fn inspect_npm_recovery_operation(
    database_url: &str,
    operation: &str,
) -> Result<CollectionRecoveryReport> {
    if !blake(operation) {
        return Err(Error::invalid("Invalid recovery operation identity."));
    }
    let mut conn = connection(database_url, false).await?;
    let mut tx = conn.begin().await.map_err(|_| unavailable())?;
    sqlx_core::raw_sql::raw_sql("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *tx)
        .await
        .map_err(|_| unavailable())?;
    let row = sqlx_core::query::query("SELECT data,data_integrity FROM devres_npm_advisory_recoveries WHERE operation_id=$1 AND octet_length(data::text)<=8388608")
        .bind(operation).fetch_optional(&mut *tx).await.map_err(|_| unavailable())?.ok_or_else(|| Error::not_found("Recovery admission unavailable."))?;
    let payload: Json<Value> = row.try_get("data").map_err(|_| invalid())?;
    let seal: String = row.try_get("data_integrity").map_err(|_| invalid())?;
    let admission = payload_integrity::checked(JOURNAL, "", operation, payload.0, &seal)?;
    let row = sqlx_core::query::query("SELECT data,data_integrity FROM devres_npm_recovery_work WHERE operation_id=$1 AND octet_length(data::text)<=8388608")
        .bind(operation).fetch_optional(&mut *tx).await.map_err(|_| unavailable())?.ok_or_else(|| Error::not_found("Recovery work unavailable."))?;
    let payload: Json<Value> = row.try_get("data").map_err(|_| invalid())?;
    let seal: String = row.try_get("data_integrity").map_err(|_| invalid())?;
    let work = payload_integrity::checked(WORK, "", operation, payload.0, &seal)?;
    if admission["operation_id"] != operation
        || work["operation_id"] != operation
        || admission["recipe"] != NPM_RECOVERY_RECIPE
        || admission["job_id"] != work["job_id"]
        || admission["revision"] != work["revision"]
    {
        return Err(invalid());
    }
    validate_job(&work["job"])?;
    let result = CollectionRecoveryReport {
        version: 1,
        job_id: work["job_id"].as_str().ok_or_else(invalid)?.into(),
        revision: work["revision"].as_u64().ok_or_else(invalid)?,
        recipe: NPM_RECOVERY_RECIPE.into(),
        state_digest: admission["expected_state"]
            .as_str()
            .ok_or_else(invalid)?
            .into(),
        eligible: false,
        outcome: "inspected".into(),
        reason: "exact_operation_present".into(),
        operation_id: Some(operation.into()),
        publication_snapshot: work["publication_snapshot"].as_str().map(str::to_owned),
    };
    tx.rollback().await.map_err(|_| unavailable())?;
    Ok(result)
}

pub async fn run_npm_recovery(
    store: &PgBlobStore,
    raw: &BulkArtifactStore,
    operation: &str,
    artifact_path: &Path,
    cancel: &CancellationToken,
) -> Result<CollectionRecoveryReport> {
    if !blake(operation) {
        return Err(Error::invalid("Invalid recovery operation identity."));
    }
    cancelled(cancel)?;
    store.owner_fence().await?;
    if raw.root() != store.root.join("npm/raw-artifacts") {
        return Err(Error::invalid("Recovery artifact store binding differs."));
    }
    if store.lifecycle_shared || store.reader || !store.recovery {
        return Err(Error::capacity(
            "Recovery execution requires the bounded recovery attachment.",
        ));
    }
    let (mut work, admission) = {
        let mut owner = store.owner.lock().await;
        // Library callers may hold an existing maintenance store. Retain bounded
        // owner waits after claim commit as well as within the first transaction.
        sqlx_core::raw_sql::raw_sql("SET statement_timeout='3000ms'; SET lock_timeout='1000ms'")
            .execute(&mut *owner)
            .await
            .map_err(|_| unavailable())?;
        let mut tx = owner.begin().await.map_err(|_| unavailable())?;
        sqlx_core::raw_sql::raw_sql(
            "SET LOCAL statement_timeout='3000ms'; SET LOCAL lock_timeout='1000ms'",
        )
        .execute(&mut *tx)
        .await
        .map_err(|_| unavailable())?;
        let schema: i32 = sqlx_core::query_scalar::query_scalar("SELECT version FROM devres_schema WHERE singleton AND (SELECT active FROM devres_integrity_control WHERE singleton) AND to_regclass('public.devres_archive_restore_pending') IS NULL")
            .fetch_one(&mut *tx).await.map_err(|_| unavailable())?;
        if schema != 19 {
            return Err(Error::unavailable(
                "Recovery execution requires active schema nineteen.",
            ));
        }
        attribution_storage::verify_control(&mut tx).await?;
        let row=sqlx_core::query::query("SELECT data,data_integrity FROM devres_npm_advisory_recoveries WHERE operation_id=$1 AND octet_length(data::text)<=8388608")
            .bind(operation).fetch_optional(&mut *tx).await.map_err(|_|unavailable())?.ok_or_else(||Error::not_found("Recovery admission unavailable."))?;
        let data: Json<Value> = row.try_get("data").map_err(|_| invalid())?;
        let seal: String = row.try_get("data_integrity").map_err(|_| invalid())?;
        let admission = payload_integrity::checked(JOURNAL, "", operation, data.0, &seal)?;
        let checkpoint: RecoveryCheckpoint =
            serde_json::from_value(admission["checkpoint"].clone()).map_err(|_| invalid())?;
        let (store_id, epoch): (String, i64) = sqlx_core::query_as::query_as("SELECT store_id,epoch FROM devres_archive_control WHERE singleton AND pending_binding IS NULL AND NOT initializing_s3")
            .fetch_one(&mut *tx).await.map_err(|_| unavailable())?;
        let system: String = sqlx_core::query_scalar::query_scalar(
            "SELECT system_identifier::text FROM pg_control_system()",
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| unavailable())?;
        if checkpoint.version != 1
            || checkpoint.schema != 19
            || !checkpoint.coordinated
            || !checkpoint.restoration_verified
            || !blake(&checkpoint.receipt_digest)
            || checkpoint.store_id != store_id
            || checkpoint.archive_epoch != epoch
            || checkpoint.system_identifier != system
        {
            return Err(Error::invalid("Recovery checkpoint authority changed."));
        }
        let mut work = load_work(&mut tx, operation).await?;
        if work["status"] != "complete" {
            require_available_processor(PROCESSOR_VERSION)?;
            let attempts = work["attempts"]
                .as_u64()
                .and_then(|v| v.checked_add(1))
                .ok_or_else(invalid)?;
            work["attempts"] = json!(attempts);
            work["status"] = json!("running");
            work["claim"] = json!(hash(
                &json!({"operation":operation,"attempt":attempts,"owner_pid":store.owner_pid,"owner_started":store.owner_started})
            )?);
            save_work(&mut tx, operation, &work).await?;
        }
        tx.commit().await.map_err(|_| {
            Error::unavailable(
                "Recovery claim outcome uncertain; reconcile the exact operation identity.",
            )
        })?;
        (work, admission)
    };
    let options = CollectionRecoveryOptions {
        job_id: work["job_id"].as_str().ok_or_else(invalid)?.into(),
        revision: work["revision"].as_u64().ok_or_else(invalid)?,
        recipe: NPM_RECOVERY_RECIPE.into(),
        expected_state: admission["expected_state"].as_str().map(str::to_owned),
        operation_id: Some(operation.into()),
    };
    let found = Selected {
        job: work["job"].clone(),
        state_digest: options.expected_state.clone().ok_or_else(invalid)?,
        reason: "eligible",
    };
    if work["status"] == "complete" {
        let mut result = report(&options, &found, "complete");
        result.eligible = false;
        result.publication_snapshot = work["publication_snapshot"].as_str().map(str::to_owned);
        return Ok(result);
    }
    if admission["job_id"] != work["job_id"]
        || admission["recipe"] != NPM_RECOVERY_RECIPE
        || artifact(&admission["job"])? != artifact(&work["job"])?
        || eligibility(&admission["job"])? != "eligible"
    {
        return Err(invalid());
    }
    let claim = work["claim"].as_str().ok_or_else(invalid)?.to_owned();
    let verification_deadline = Instant::now() + Duration::from_secs(300);
    let file = snapshot_artifact(
        artifact_path,
        &artifact(&found.job)?,
        cancel,
        verification_deadline,
    )
    .await?;
    {
        let mut owner = store.owner.lock().await;
        verify_descriptor(
            &mut owner,
            &options,
            &found,
            file.try_clone().map_err(|_| invalid())?,
            cancel,
            verification_deadline,
        )
        .await?;
    }
    let next = found.job["next"].as_u64().ok_or_else(invalid)? as usize;
    let expanded = found
        .job
        .get("expanded")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let (sender, mut receiver) = tokio::sync::mpsc::channel(2);
    let stop = cancel.child_token();
    let worker_stop = stop.clone();
    let worker = tokio::task::spawn_blocking(move || {
        crate::npm::corpus::scan_export(file, next, expanded, sender, &worker_stop)
    });
    let execution = async {
        while let Some((position, expanded, item)) = receiver.recv().await {
            cancelled(cancel)?;
            store.owner_fence().await?;
            let values = member_values(&work["job"], position, &item)?;
            if let Ok(Some(item)) = &item
                && item.record["rights_gap"] != true
            {
                let captured = raw
                    .capture_bytes(item.bytes.clone(), cancel.clone())
                    .await?;
                if captured.body_hash != crate::integrity::hash(&item.bytes) {
                    return Err(invalid());
                }
            }
            for (kind, key, value) in &values {
                cancelled(cancel)?;
                store.npm_put(kind, key, value).await?;
            }
            if matches!(item, Ok(Some(_))) {
                work["job"]["records"] =
                    json!(work["job"]["records"].as_u64().ok_or_else(invalid)? + 1);
            }
            work["job"]["gaps"] = json!(
                work["job"]["gaps"].as_u64().ok_or_else(invalid)?
                    + values.iter().filter(|v| v.0 == "gaps").count() as u64
            );
            work["job"]["next"] = json!(position + 1);
            work["job"]["expanded"] = json!(expanded);
            checkpoint_work(store, operation, &claim, &work["job"], "running").await?;
        }
        Ok::<(), Error>(())
    }
    .await;
    if let Err(error) = execution {
        stop.cancel();
        drop(receiver);
        let _ = worker.await;
        return Err(error);
    }
    let complete = worker.await.map_err(|_| invalid())??;
    cancelled(cancel)?;
    if !complete {
        checkpoint_work(store, operation, &claim, &work["job"], "yielded").await?;
        let mut result = report(&options, &found, "yielded");
        result.eligible = false;
        result.reason = "bounded_slice_complete".into();
        return Ok(result);
    }
    let job = &work["job"];
    let export = artifact(job)?;
    let mut snapshot = json!({"lane":"advisories","artifact":export,"validated_at":job["validated_at"],"records":job["records"],"gaps":job["gaps"],"accounted":true,"complete":job["gaps"]==0,"source":"osv_npm_export","processor_version":NPM_RECOVERY_PROCESSOR_VERSION,"membership":options.job_id});
    snapshot["id"] = json!(crate::npm::corpus::identity(&snapshot)?);
    let id = snapshot["id"].as_str().ok_or_else(invalid)?;
    store
        .npm_set_state(
            &format!("ready:{id}"),
            &json!({"id":id,"records":job["records"],"accounted":true}),
        )
        .await?;
    cancelled(cancel)?;
    store
        .npm_publish_mode("advisories", &snapshot, Some((operation, &claim)))
        .await?;
    let mut result = report(&options, &found, "complete");
    result.eligible = false;
    result.reason = "historical_publication".into();
    result.publication_snapshot = Some(id.into());
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    fn options(id: &str, revision: u64) -> CollectionRecoveryOptions {
        CollectionRecoveryOptions {
            job_id: id.into(),
            revision,
            recipe: NPM_RECOVERY_RECIPE.into(),
            expected_state: None,
            operation_id: None,
        }
    }
    fn job(id: &str, artifact: &BulkArtifact) -> Value {
        json!({"snapshot":id,"artifact":artifact,"validated_at":devres_domain::unix_now(),"next":0,"records":0,"gaps":0,"expanded":0,"done":true,"failed":"capacity","processor_version":NPM_RECOVERY_PROCESSOR_VERSION,"failure_context":{"version":1,"code":"capacity","materialization_deadline":true}})
    }
    #[test]
    fn exact_recipe_rejects_unknown_causes_processors_and_changed_receipts() {
        let digest = crate::integrity::hash(b"fixture");
        let artifact = BulkArtifact {
            body_hash: digest.clone(),
            bytes: 7,
            relative_path: crate::integrity::relative_path(&digest)
                .unwrap()
                .to_string_lossy()
                .into(),
        };
        let original = job(&digest, &artifact);
        assert_eq!(eligibility(&original).unwrap(), "eligible");
        let mut legacy = original.clone();
        legacy.as_object_mut().unwrap().remove("failure_context");
        assert_eq!(eligibility(&legacy).unwrap(), "legacy_unknown");
        let mut other = original.clone();
        other["failure_context"]["materialization_deadline"] = json!(false);
        assert_ne!(eligibility(&other).unwrap(), "eligible");
        other = original.clone();
        other["processor_version"] = json!(2);
        assert_ne!(eligibility(&other).unwrap(), "eligible");
        let mut selected = options(&digest, 1);
        selected.validate(false).unwrap();
        assert!(selected.validate(true).is_err());
        selected.expected_state = Some(digest.clone());
        selected.operation_id = Some(digest.clone());
        selected.validate(true).unwrap();
        selected.recipe = "arbitrary-reset".into();
        assert!(selected.validate(false).is_err());
        let mut receipt = RecoveryEvidenceReceipt {
            version: 1,
            job_id: digest.clone(),
            revision: 1,
            state_digest: digest.clone(),
            artifact_digest: digest.clone(),
            artifact_bytes: 7,
            members: 0,
            next_member: 0,
            records: 0,
            gaps: 0,
            expanded_bytes: 0,
            prefix_digest: digest,
            evidence_digest: String::new(),
        };
        receipt.evidence_digest = receipt_hash(&receipt).unwrap();
        let seal = receipt.evidence_digest.clone();
        receipt.records = 1;
        assert_ne!(seal, receipt_hash(&receipt).unwrap());
    }
    fn export() -> (Vec<u8>, Vec<(String, Vec<u8>)>) {
        let members=(0..3).map(|n|{
            let name=format!("GHSA-2345-6789-cfg{}.json",["h","j","m"][n]);
            let raw=format!(r#"{{"id":"GHSA-2345-6789-cfg{}","modified":"2026-10-27T00:00:00Z","affected":[{{"package":{{"ecosystem":"npm","name":"fixture"}},"versions":["1.0.0"]}}]}}"#,["h","j","m"][n]).into_bytes();
            (name,raw)
        }).collect::<Vec<_>>();
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (name, raw) in &members {
            zip.start_file(name, zip::write::SimpleFileOptions::default())
                .unwrap();
            zip.write_all(raw).unwrap();
        }
        (zip.finish().unwrap().into_inner(), members)
    }
    async fn fixture_database(suffix: &str) -> (sqlx_postgres::PgPool, String) {
        let base = std::env::var("DEVRES_TEST_DATABASE_URL").unwrap();
        let admin = sqlx_postgres::PgPool::connect(&base).await.unwrap();
        let name = format!("devres_collection_{}_{}", suffix, std::process::id());
        sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!(
            "CREATE DATABASE {name}"
        )))
        .execute(&admin)
        .await
        .unwrap();
        let mut url = url::Url::parse(&base).unwrap();
        url.set_path(&format!("/{name}"));
        (admin, url.to_string())
    }
    async fn checkpoint(store: &PgBlobStore) -> RecoveryCheckpoint {
        let row = sqlx_core::query::query(
            "SELECT store_id,epoch FROM devres_archive_control WHERE singleton",
        )
        .fetch_one(&store.pool)
        .await
        .unwrap();
        RecoveryCheckpoint {
            version: 1,
            schema: 19,
            store_id: row.try_get("store_id").unwrap(),
            archive_epoch: row.try_get("epoch").unwrap(),
            system_identifier: sqlx_core::query_scalar::query_scalar(
                "SELECT system_identifier::text FROM pg_control_system()",
            )
            .fetch_one(&store.pool)
            .await
            .unwrap(),
            coordinated: true,
            restoration_verified: true,
            receipt_digest: crate::integrity::hash(b"fixture coordinated restore receipt"),
        }
    }
    #[tokio::test]
    #[ignore = "requires disposable DEVRES_TEST_DATABASE_URL PostgreSQL"]
    async fn exact_historical_recovery_preserves_current_and_default_through_restart() {
        let (_admin, url) = fixture_database("historical").await;
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let evidence = tempfile::tempdir_in("/tmp").unwrap();
        std::fs::set_permissions(evidence.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = PgBlobStore::connect(&url, root.path()).await.unwrap();
        let raw_root = root.path().join("npm/raw-artifacts");
        std::fs::create_dir_all(&raw_root).unwrap();
        let raw = BulkArtifactStore::new(&raw_root, 64 * 1024 * 1024).unwrap();
        let (bytes, members) = export();
        let export = raw
            .capture_bytes(bytes.clone(), CancellationToken::new())
            .await
            .unwrap();
        let path = evidence.path().join("export.zip");
        std::fs::write(&path, &bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let id = crate::integrity::hash(b"historical acquisition");
        let mut old = job(&id, &export);
        old["done"] = json!(false);
        old.as_object_mut().unwrap().remove("failed");
        old.as_object_mut().unwrap().remove("failure_context");
        store.npm_set_state("advisory-job", &old).await.unwrap();
        // One committed member and deterministic partial writes for the next.
        for (position, (name, bytes)) in members.iter().take(2).enumerate() {
            let record = crate::npm::audit::parse_advisory(bytes).unwrap();
            let item = Ok(Some(crate::npm::corpus::ScannedAdvisory {
                record,
                bytes: bytes.clone(),
                path: name.clone(),
            }));
            raw.capture_bytes(bytes.clone(), CancellationToken::new())
                .await
                .unwrap();
            let values = member_values(&old, position, &item).unwrap();
            for (kind, key, value) in &values {
                store.npm_put(kind, key, value).await.unwrap();
            }
            if position == 0 {
                old["next"] = json!(1);
                old["expanded"] = json!(bytes.len());
                old["records"] = json!(1);
                old["gaps"] = json!(values.iter().filter(|v| v.0 == "gaps").count());
            }
        }
        old["done"] = json!(true);
        old["failed"] = json!("capacity");
        old["failure_context"] =
            json!({"version":1,"code":"capacity","materialization_deadline":true});
        store.npm_set_state("advisory-job", &old).await.unwrap();
        let newer_id = crate::integrity::hash(b"newer acquisition");
        let mut newer = job(&newer_id, &export);
        newer["done"] = json!(false);
        newer.as_object_mut().unwrap().remove("failed");
        store.npm_set_state("advisory-job", &newer).await.unwrap();
        let mut default = json!({"lane":"advisories","artifact":export,"validated_at":devres_domain::unix_now(),"membership":newer_id,"records":0,"gaps":0,"accounted":true,"complete":true,"source":"osv_npm_export","processor_version":NPM_RECOVERY_PROCESSOR_VERSION});
        default["id"] = json!(crate::npm::corpus::identity(&default).unwrap());
        let default_id = default["id"].as_str().unwrap();
        store
            .npm_set_state(
                &format!("ready:{default_id}"),
                &json!({"id":default_id,"records":0,"accounted":true}),
            )
            .await
            .unwrap();
        store.npm_publish("advisories", &default).await.unwrap();
        let validator = json!({"etag":"must-survive-history-recovery"});
        store
            .npm_set_state("source-response:fixture", &validator)
            .await
            .unwrap();
        let backup = checkpoint(&store).await;
        let mut selection = options(&id, 2);
        let dry = diagnose_npm_recovery(&url, &selection, None).await.unwrap();
        assert!(!dry.eligible);
        assert_eq!(dry.reason, "evidence_not_verified");
        let receipt =
            verify_npm_recovery_evidence(&url, &selection, &path, &CancellationToken::new())
                .await
                .unwrap();
        assert_eq!(receipt.members, 3);
        assert_eq!(receipt.next_member, 1);
        let dry = diagnose_npm_recovery(&url, &selection, Some(&receipt))
            .await
            .unwrap();
        assert!(dry.eligible);
        selection.expected_state = Some(dry.state_digest);
        selection.operation_id = Some(crate::integrity::hash(b"exact historical recovery intent"));
        // Serving ownership prevents admission, including with valid evidence.
        assert!(
            apply_npm_recovery(
                &url,
                &selection,
                &receipt,
                &path,
                &backup,
                &CancellationToken::new()
            )
            .await
            .is_err()
        );
        assert_eq!(
            store.npm_state("advisory-job").await.unwrap(),
            Some(newer.clone())
        );
        drop(store);
        let bad_checkpoint = RecoveryCheckpoint {
            archive_epoch: backup.archive_epoch + 1,
            ..backup.clone()
        };
        assert!(
            apply_npm_recovery(
                &url,
                &selection,
                &receipt,
                &path,
                &bad_checkpoint,
                &CancellationToken::new()
            )
            .await
            .is_err()
        );
        let mut changed = receipt.clone();
        changed.members += 1;
        assert!(
            apply_npm_recovery(
                &url,
                &selection,
                &changed,
                &path,
                &backup,
                &CancellationToken::new()
            )
            .await
            .is_err()
        );
        let applied = apply_npm_recovery(
            &url,
            &selection,
            &receipt,
            &path,
            &backup,
            &CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(applied.outcome, "applied");
        let repeated = apply_npm_recovery(
            &url,
            &selection,
            &receipt,
            &path,
            &backup,
            &CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(repeated.outcome, "already_applied");
        let maintenance = PgBlobStore::connect_archive_for_recovery(&url, root.path(), None)
            .await
            .unwrap();
        let operation = selection.operation_id.as_deref().unwrap();
        let stopped = CancellationToken::new();
        stopped.cancel();
        assert!(
            run_npm_recovery(&maintenance, &raw, operation, &path, &stopped)
                .await
                .is_err()
        );
        assert_eq!(
            maintenance.npm_state("advisory-job").await.unwrap(),
            Some(newer.clone())
        );
        drop(maintenance);
        let maintenance = PgBlobStore::connect_archive_for_recovery(&url, root.path(), None)
            .await
            .unwrap();
        sqlx_core::raw_sql::raw_sql("CREATE FUNCTION devres_fixture_cut() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.kind='advisory-packages' AND NEW.data->>'id'='GHSA-2345-6789-cfgm' THEN RAISE EXCEPTION 'fixture durable cut'; END IF; RETURN NEW; END $$; CREATE TRIGGER devres_fixture_cut BEFORE INSERT ON devres_npm_evidence FOR EACH ROW EXECUTE FUNCTION devres_fixture_cut();")
            .execute(&maintenance.pool).await.unwrap();
        assert!(
            run_npm_recovery(
                &maintenance,
                &raw,
                operation,
                &path,
                &CancellationToken::new()
            )
            .await
            .is_err()
        );
        assert_eq!(
            maintenance.npm_state("default-advisories").await.unwrap(),
            Some(default.clone())
        );
        assert_eq!(
            maintenance.npm_state("advisory-job").await.unwrap(),
            Some(newer.clone())
        );
        let resumed_job = {
            let mut owner = maintenance.owner.lock().await;
            let work = load_work(&mut owner, operation).await.unwrap();
            assert_eq!(work["job"]["next"], 2);
            work["job"].clone()
        };
        // The claim transaction has committed. Its former SET LOCAL limits no
        // longer apply; the recovery owner's session limit must bound this wait.
        let mut blocker = PgConnection::connect(&url).await.unwrap();
        let mut locked = blocker.begin().await.unwrap();
        sqlx_core::query::query(
            "SELECT operation_id FROM devres_npm_recovery_work WHERE operation_id=$1 FOR UPDATE",
        )
        .bind(operation)
        .fetch_one(&mut *locked)
        .await
        .unwrap();
        let started = Instant::now();
        let blocked = tokio::time::timeout(
            Duration::from_secs(5),
            checkpoint_work(
                &maintenance,
                operation,
                "stale-claim",
                &resumed_job,
                "running",
            ),
        )
        .await;
        assert!(
            blocked.is_ok(),
            "post-claim row lock must not wait indefinitely"
        );
        assert!(blocked.unwrap().is_err());
        assert!(started.elapsed() < Duration::from_secs(4));
        locked.rollback().await.unwrap();
        assert!(
            checkpoint_work(
                &maintenance,
                operation,
                "stale-claim",
                &resumed_job,
                "running"
            )
            .await
            .is_err()
        );
        sqlx_core::raw_sql::raw_sql("DROP TRIGGER devres_fixture_cut ON devres_npm_evidence; DROP FUNCTION devres_fixture_cut();").execute(&maintenance.pool).await.unwrap();
        drop(maintenance);
        let maintenance = PgBlobStore::connect_archive_for_recovery(&url, root.path(), None)
            .await
            .unwrap();
        let done = run_npm_recovery(
            &maintenance,
            &raw,
            operation,
            &path,
            &CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(done.outcome, "complete");
        let published = maintenance
            .npm_get("snapshots", done.publication_snapshot.as_deref().unwrap())
            .await
            .unwrap()
            .unwrap()
            .data;
        assert_eq!(published["membership"], id);
        assert_eq!(published["records"], 3);
        assert_eq!(
            maintenance.npm_state("default-advisories").await.unwrap(),
            Some(default)
        );
        assert_eq!(
            maintenance.npm_state("advisory-job").await.unwrap(),
            Some(newer)
        );
        assert_eq!(
            maintenance
                .npm_state("source-response:fixture")
                .await
                .unwrap(),
            Some(validator)
        );
        let repeated = run_npm_recovery(
            &maintenance,
            &raw,
            operation,
            &path,
            &CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(repeated.publication_snapshot, done.publication_snapshot);
        let mut owner = maintenance.owner.lock().await;
        verify_history(&mut owner, &CancellationToken::new())
            .await
            .unwrap();
        assert!(
            sqlx_core::query::query("UPDATE devres_npm_advisory_job_history SET revision=revision")
                .execute(&mut *owner)
                .await
                .is_err()
        );
        assert!(
            sqlx_core::query::query("DELETE FROM devres_npm_advisory_recoveries")
                .execute(&mut *owner)
                .await
                .is_err()
        );
        drop(owner);
        let mut expected_states = Vec::new();
        for key in [
            "advisory-job",
            "default-advisories",
            "source-response:fixture",
        ] {
            expected_states.push((key, maintenance.npm_state(key).await.unwrap()));
        }
        drop(maintenance);
        if let Ok(container) = std::env::var("DEVRES_TEST_POSTGRES_CONTAINER") {
            boundary_tests::restore_nonempty_recovery_fixture(
                &container,
                &url,
                root.path(),
                operation,
                &published,
                &export,
                &expected_states,
            )
            .await;
        }
    }
    #[tokio::test]
    #[ignore = "requires disposable DEVRES_TEST_DATABASE_URL PostgreSQL"]
    async fn schema18_migration_retains_exact_job_without_inventing_cause() {
        let (_admin, url) = fixture_database("migration").await;
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let store = PgBlobStore::connect(&url, root.path()).await.unwrap();
        let digest = crate::integrity::hash(b"retained exact legacy export");
        let artifact = BulkArtifact {
            body_hash: digest.clone(),
            bytes: 26,
            relative_path: crate::integrity::relative_path(&digest)
                .unwrap()
                .to_string_lossy()
                .into(),
        };
        let original = job(&crate::integrity::hash(b"legacy acquisition"), &artifact);
        store
            .npm_set_state("advisory-job", &original)
            .await
            .unwrap();
        sqlx_core::raw_sql::raw_sql("DROP TABLE devres_npm_recovery_work,devres_npm_advisory_recoveries,devres_npm_advisory_job_history; DROP FUNCTION devres_npm_recovery_immutable(); UPDATE devres_schema SET version=18 WHERE singleton").execute(&store.pool).await.unwrap();
        drop(store);
        assert!(
            PgBlobStore::connect_reader(&url, root.path(), None)
                .await
                .is_err()
        );
        let migrated = PgBlobStore::connect(&url, root.path()).await.unwrap();
        assert_eq!(
            migrated.npm_state("advisory-job").await.unwrap(),
            Some(original.clone())
        );
        let selection = options(original["snapshot"].as_str().unwrap(), 1);
        let dry = diagnose_npm_recovery(&url, &selection, None).await.unwrap();
        assert_eq!(dry.reason, "legacy_unknown");
        assert!(!dry.eligible);
        let mut owner = migrated.owner.lock().await;
        verify_history(&mut owner, &CancellationToken::new())
            .await
            .unwrap();
    }
}

#[cfg(test)]
#[path = "storage_collection_recovery_verify_tests.rs"]
mod verify_tests;
