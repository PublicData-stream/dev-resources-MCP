//! Rust-verified, versioned integrity envelopes for public SQL payloads.
#[path = "storage_specialized_verify.rs"]
mod specialized_closure;
use devres_domain::{Error, Result};
use futures::TryStreamExt;
use serde_json::{Value, json};
use sqlx::{Column, Connection, Executor, Postgres, Row, postgres::PgRow, types::Json};
use tokio_util::sync::CancellationToken;

fn failure() -> Error {
    Error::integrity("Retained SQL payload integrity failed.")
}

/// Fixed SQL expressions supplied only by the offline seal registries/callers.
pub(super) struct SealTarget<'a> {
    pub table: &'a str,
    pub column: &'a str,
    pub kind_expr: &'a str,
    pub key_expr: &'a str,
}

/// Only identity/locator/seal metadata is retained. Payloads remain one-at-a-time,
/// including the existing large RFC representation allowance.
#[derive(Default)]
pub(super) struct SealBatch {
    locators: Vec<String>,
    kinds: Vec<String>,
    keys: Vec<String>,
    seals: Vec<String>,
    bytes: usize,
}

impl SealBatch {
    const ROWS: usize = 1000;
    const BYTES: usize = 8 * 1024 * 1024;

    pub async fn queue(
        &mut self,
        store: &super::PgBlobStore,
        cancel: &CancellationToken,
        target: &SealTarget<'_>,
        record: (String, String, String, String),
    ) -> Result<()> {
        let (locator, kind, key, seal) = record;
        let bytes = [locator.len(), kind.len(), key.len(), seal.len(), 128]
            .into_iter()
            .try_fold(0_usize, |total, part| total.checked_add(part))
            .filter(|&bytes| bytes <= Self::BYTES)
            .ok_or_else(|| Error::capacity("Migration seal metadata exceeds its batch bound."))?;
        if self.locators.len() >= Self::ROWS || self.bytes > Self::BYTES - bytes {
            self.flush(store, cancel, target).await?;
        }
        self.locators.push(locator);
        self.kinds.push(kind);
        self.keys.push(key);
        self.seals.push(seal);
        self.bytes += bytes;
        Ok(())
    }

    pub async fn flush(
        &mut self,
        store: &super::PgBlobStore,
        cancel: &CancellationToken,
        target: &SealTarget<'_>,
    ) -> Result<()> {
        if self.locators.is_empty() {
            return Ok(());
        }
        seal_not_cancelled(cancel)?;
        store.fence().await?;
        let sql = format!(
            "UPDATE {table} retained SET {column}=requested.seal_value FROM UNNEST($1::text[],$2::text[],$3::text[],$4::text[]) requested(seal_locator,seal_kind,seal_key,seal_value) WHERE retained.ctid=requested.seal_locator::tid AND ({kind})=requested.seal_kind AND ({key})=requested.seal_key AND retained.{column} IS NULL",
            table = target.table,
            column = target.column,
            kind = target.kind_expr,
            key = target.key_expr,
        );
        let mut owner = store.owner.lock().await;
        let mut tx = owner.begin().await.map_err(|_| failure())?;
        let result: Result<()> = async {
            let changed = sqlx::query(sqlx::AssertSqlSafe(sql))
                .bind(&self.locators)
                .bind(&self.kinds)
                .bind(&self.keys)
                .bind(&self.seals)
                .execute(&mut *tx)
                .await
                .map_err(|_| failure())?;
            if changed.rows_affected() != self.locators.len() as u64 {
                return Err(failure());
            }
            seal_not_cancelled(cancel)?;
            store.fence().await?;
            Ok(())
        }
        .await;
        if let Err(error) = result {
            // The owner connection is not returned to a pool. Transaction Drop
            // only queues rollback there, leaving locks until its next command.
            // Drain rollback before exposing a failed/cancelled batch to callers.
            tx.rollback().await.map_err(|_| failure())?;
            return Err(error);
        }
        tx.commit().await.map_err(|_| failure())?;
        self.locators.clear();
        self.kinds.clear();
        self.keys.clear();
        self.seals.clear();
        self.bytes = 0;
        Ok(())
    }
}

pub(super) fn seal_not_cancelled(cancel: &CancellationToken) -> Result<()> {
    if cancel.is_cancelled() {
        Err(Error::new(
            "cancelled",
            "SQL integrity qualification canceled.",
        ))
    } else {
        Ok(())
    }
}

/// Object-key ordering is stable because the workspace uses serde_json's ordered map.
/// The record namespace and key prevent a valid payload being moved to another row.
pub(super) fn digest(table: &str, kind: &str, key: &str, data: &Value) -> Result<String> {
    let envelope = json!({"version":1,"namespace":table,"key":[kind,key],"payload":data});
    crate::integrity::canonical_hash(&envelope)
}

pub(super) fn checked(
    table: &str,
    kind: &str,
    key: &str,
    data: Value,
    expected: &str,
) -> Result<Value> {
    if !expected.starts_with("blake3:") || digest(table, kind, key, &data)? != expected {
        return Err(failure());
    }
    Ok(data)
}

pub(super) fn row(table: &str, row: &PgRow) -> Result<Value> {
    if (table.ends_with("_evidence") || table == "devres_advisory_rows")
        && row
            .columns()
            .iter()
            .any(|column| column.name() == "sequence")
    {
        super::sequence_integrity::verify_row(table, row)?;
    }
    let kind: String = row.try_get("kind").map_err(|_| failure())?;
    let key: String = row.try_get("key").map_err(|_| failure())?;
    let data: Json<Value> = row.try_get("data").map_err(|_| failure())?;
    let expected: String = row.try_get("data_integrity").map_err(|_| failure())?;
    let payload = match table {
        "devres_rfc_snapshots" => rfc_snapshot_payload(
            row.try_get("published_order").map_err(|_| failure())?,
            row.try_get("catalogue_capture").map_err(|_| failure())?,
            row.try_get("errata_capture").map_err(|_| failure())?,
            row.try_get("created_at").map_err(|_| failure())?,
            row.try_get("complete").map_err(|_| failure())?,
            &data.0,
        )?,
        "devres_advisory_snapshots" => advisory_snapshot_payload(
            row.try_get("sequence").map_err(|_| failure())?,
            row.try_get::<String, _>("format")
                .map_err(|_| failure())?
                .as_str(),
            row.try_get::<String, _>("revision")
                .map_err(|_| failure())?
                .as_str(),
            &data.0,
        )?,
        "devres_crate_generations" => crate_generation_payload(
            row.try_get("published_sequence").map_err(|_| failure())?,
            &data.0,
        )?,
        "devres_crate_snapshots" => crate_snapshot_payload(
            row.try_get("sequence").map_err(|_| failure())?,
            row.try_get::<String, _>("inventory")
                .map_err(|_| failure())?
                .as_str(),
            row.try_get("content_sequence").map_err(|_| failure())?,
            &data.0,
        )?,
        _ => data.0.clone(),
    };
    checked(table, &kind, &key, payload, &expected)?;
    Ok(data.0)
}

fn allowed(table: &str) -> bool {
    matches!(
        table,
        "devres_mdn_evidence"
            | "devres_mdn_state"
            | "devres_whatwg_evidence"
            | "devres_whatwg_state"
            | "devres_w3c_evidence"
            | "devres_w3c_state"
            | "devres_chromium_evidence"
            | "devres_chromium_state"
            | "devres_npm_evidence"
            | "devres_npm_state"
            | "devres_advisory_rows"
            | "devres_advisory_state"
            | "devres_advisory_records"
            | "devres_advisory_snapshots"
            | "devres_crate_snapshots"
    )
}

pub(super) async fn load<'e, E>(
    executor: E,
    table: &str,
    kind: &str,
    key: &str,
) -> Result<Option<Json<Value>>>
where
    E: Executor<'e, Database = Postgres>,
{
    if !allowed(table) {
        return Err(failure());
    }
    let query = if table.ends_with("_state") {
        format!(
            "SELECT ''::text AS kind,key,data,data_integrity FROM {table} WHERE key=$2 AND $1::text=''"
        )
    } else if table == "devres_advisory_snapshots" {
        format!(
            "SELECT sequence,format,revision,''::text AS kind,id AS key,data,data_integrity FROM {table} WHERE id=$2 AND $1::text=''"
        )
    } else if table == "devres_crate_snapshots" {
        format!(
            "SELECT sequence,inventory,content_sequence,''::text AS kind,id AS key,data,data_integrity FROM {table} WHERE id=$2 AND $1::text=''"
        )
    } else if table == "devres_advisory_records" {
        format!(
            "SELECT ''::text AS kind,id AS key,data,data_integrity FROM {table} WHERE id=$2 AND $1::text=''"
        )
    } else {
        format!(
            "SELECT sequence,sequence_integrity,kind,key,data,data_integrity FROM {table} WHERE kind=$1 AND key=$2"
        )
    };
    let found = sqlx::query(sqlx::AssertSqlSafe(query))
        .bind(kind)
        .bind(key)
        .fetch_optional(executor)
        .await
        .map_err(|_| failure())?;
    found.map(|found| row(table, &found).map(Json)).transpose()
}

/// Fixed column/identity registry shared by offline qualification and runtime writers.
/// Expressions are constants; no request data enters dynamic SQL identifiers.
pub(super) const SPECIALIZED_PAYLOADS: &[(&str, &str, &str, &str, &str)] = &[
    ("devres_advisory_rows", "data", "kind", "key", "true"),
    ("devres_advisory_state", "data", "''::text", "key", "true"),
    ("devres_advisory_records", "data", "''::text", "id", "true"),
    (
        "devres_advisory_snapshots",
        "data",
        "''::text",
        "id",
        "true",
    ),
    ("devres_rfc_datasets", "data", "kind", "capture_id", "true"),
    ("devres_rfc_snapshots", "data", "''::text", "id", "true"),
    (
        "devres_rfc_jobs",
        "capture_metadata",
        "'capture_metadata'::text",
        "source_key",
        "capture_metadata IS NOT NULL",
    ),
    (
        "devres_crate_artifacts",
        "provenance",
        "''::text",
        "capture_id",
        "true",
    ),
    (
        "devres_crate_observations",
        "provenance",
        "capture_id",
        "sequence::text",
        "true",
    ),
    (
        "devres_crate_staging",
        "record",
        "inventory",
        "name||'@'||version",
        "true",
    ),
    (
        "devres_crate_versions",
        "record",
        "valid_from::text",
        "name||'@'||version",
        "true",
    ),
    (
        "devres_crate_generations",
        "summary",
        "''::text",
        "id",
        "true",
    ),
    (
        "devres_crate_content",
        "attributes",
        "generation",
        "id",
        "true",
    ),
    (
        "devres_crate_enrichment",
        "data",
        "artifact||':'||kind",
        "external_id",
        "true",
    ),
    ("devres_crate_snapshots", "data", "''::text", "id", "true"),
];

/// The caller holds the exclusive storage-owner fence and has not started serving.
/// Qualification never changes payloads, observation order or public identifiers.
pub(super) async fn backfill_specialized(
    store: &super::PgBlobStore,
    cancel: &tokio_util::sync::CancellationToken,
    verify_only: bool,
) -> Result<()> {
    for &(table, column, kind_expr, key_expr, predicate) in SPECIALIZED_PAYLOADS {
        seal_not_cancelled(cancel)?;
        // One statement snapshot sees each original tuple once even when the
        // independent owner connection moves sealed tuples to new ctids.
        let sql = format!(
            "SELECT ctid::text AS locator,{kind_expr} AS kind,{key_expr} AS key,{} AS data,{column}_integrity AS expected FROM {table} WHERE {predicate}",
            specialized_payload_expression(table, column)
        );
        let mut rows = sqlx::query(sqlx::AssertSqlSafe(sql)).fetch(&store.pool);
        let mut batch = SealBatch::default();
        let target = SealTarget {
            table,
            column: &format!("{column}_integrity"),
            kind_expr,
            key_expr,
        };
        while let Some(found) = rows.try_next().await.map_err(|_| failure())? {
            seal_not_cancelled(cancel)?;
            let kind: String = found.try_get("kind").map_err(|_| failure())?;
            let key: String = found.try_get("key").map_err(|_| failure())?;
            let data: Json<Value> = found.try_get("data").map_err(|_| failure())?;
            let expected: Option<String> = found.try_get("expected").map_err(|_| failure())?;
            let digest = digest(table, &kind, &key, &data.0)?;
            if let Some(expected) = expected {
                if expected != digest {
                    return Err(failure());
                }
            } else if verify_only {
                return Err(failure());
            } else {
                batch
                    .queue(
                        store,
                        cancel,
                        &target,
                        (
                            found.try_get("locator").map_err(|_| failure())?,
                            kind,
                            key,
                            digest,
                        ),
                    )
                    .await?;
            }
        }
        batch.flush(store, cancel, &target).await?;
    }
    Ok(())
}

pub(super) async fn stage(
    store: &super::PgBlobStore,
    provider: &str,
    key: &str,
    data: &Value,
) -> Result<()> {
    let expected = digest("devres_integrity_staged_state", provider, key, data)?;
    let mut owner = store.owner.lock().await;
    let mut tx = sqlx::Connection::begin(&mut *owner)
        .await
        .map_err(|_| failure())?;
    sqlx::query("INSERT INTO devres_integrity_staged_state(provider,key,data,data_integrity) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING")
        .bind(provider).bind(key).bind(Json(data)).bind(&expected).execute(&mut *tx).await.map_err(|_|failure())?;
    let retained=sqlx::query("SELECT data,data_integrity FROM devres_integrity_staged_state WHERE provider=$1 AND key=$2")
        .bind(provider).bind(key).fetch_one(&mut *tx).await.map_err(|_|failure())?;
    let value: Json<Value> = retained.try_get("data").map_err(|_| failure())?;
    let checksum: String = retained.try_get("data_integrity").map_err(|_| failure())?;
    if checked(
        "devres_integrity_staged_state",
        provider,
        key,
        value.0,
        &checksum,
    )? != *data
    {
        return Err(failure());
    }
    tx.commit().await.map_err(|_| failure())
}

pub(super) async fn natural_key(
    pool: &sqlx::PgPool,
    provider: &str,
    kind: &str,
    key: &str,
) -> Result<String> {
    // Public representation identifiers stay exact. These explicitly enumerated
    // cache families instead use hashes of source/path/job lookup tuples.
    let hashed_lookup = (provider == "chromium"
        && matches!(
            kind,
            "document-members"
                | "derived-inventories"
                | "license-scopes"
                | "notice-objects"
                | "jobs"
                | "blocked-jobs"
                | "web-map-jobs"
                | "web-page-jobs"
                | "failed-pages"
        ))
        || (provider == "npm" && kind == "artifacts");
    if key.starts_with("blake3:") || (crate::integrity::valid_hash(key) && !hashed_lookup) {
        return Ok(key.into());
    }
    let allowed = match provider {
        "mdn" => matches!(kind, "commits" | "changes-complete" | "snapshot-keys"),
        "whatwg" => matches!(
            kind,
            "acceptance"
                | "catalog-captures"
                | "frozen"
                | "frozen-recoveries"
                | "frozen-index-repairs"
                | "indexed-membership"
                | "recovery-attempts"
                | "recovery-dispositions"
                | "recovery-witnesses"
                | "snapshot-keys"
        ),
        "w3c" => matches!(
            kind,
            "acceptance"
                | "catalog-captures"
                | "frozen"
                | "frozen-recoveries"
                | "frozen-index-repairs"
                | "indexed-membership"
                | "recovery-attempts"
                | "recovery-dispositions"
                | "recovery-witnesses"
                | "snapshot-keys"
                | "discovery-captures"
                | "edition-nodes"
                | "editions"
                | "repository-gaps"
                | "specification-records"
                | "version-memberships"
                | "version-records"
        ),
        "chromium" => matches!(
            kind,
            "blocked-jobs"
                | "commits"
                | "derived-inventories"
                | "document-members"
                | "failed-pages"
                | "freezes"
                | "history-gaps"
                | "index-recoveries"
                | "indexed"
                | "jobs"
                | "license-notices"
                | "license-scopes"
                | "notice-objects"
                | "ref-pages"
                | "sitemaps"
                | "snapshot-keys"
                | "tags"
                | "tree-pages"
                | "trees"
                | "web-map-jobs"
                | "web-page-jobs"
        ),
        "npm" => kind == "artifacts",
        _ => return Err(failure()),
    };
    if !allowed {
        return Ok(key.into());
    }
    let namespace = format!("{provider}:{kind}");
    let canonical=sqlx::query("SELECT canonical,mapping_integrity FROM devres_content_aliases WHERE namespace=$1 AND legacy=$2").bind(&namespace).bind(key).fetch_optional(pool).await.map_err(|_|failure())?;
    if let Some(row) = canonical {
        let canonical: String = row.try_get("canonical").map_err(|_| failure())?;
        let expected: String = row.try_get("mapping_integrity").map_err(|_| failure())?;
        let payload = json!({"namespace":namespace,"legacy":key,"canonical":canonical});
        if super::events::event_digest(
            "devres_content_aliases",
            &super::events::mapping_key(&namespace, key)?,
            &payload,
        )? != expected
        {
            return Err(failure());
        }
        if !canonical.starts_with("blake3:") || !crate::integrity::valid_hash(&canonical) {
            return Err(failure());
        }
        return Ok(canonical);
    }
    Ok(key.into())
}

pub(super) fn crate_record_payload(metadata: &str, valid_to: Option<i64>, record: &Value) -> Value {
    json!({"metadata_capture":metadata,"valid_to":valid_to,"record":record})
}
pub(super) fn crate_staging_payload(metadata: &str, record: &Value) -> Value {
    json!({"metadata_capture":metadata,"record":record})
}
pub(super) fn crate_artifact_payload(bytes: u64, provenance: &Value) -> Value {
    json!({"bytes":bytes,"provenance":provenance})
}
pub(super) fn crate_observation_payload(
    capture: &str,
    time: i64,
    transport: &str,
    provenance: &Value,
) -> Value {
    json!({"capture_id":capture,"observed_at":time,"transport":transport,"provenance":provenance})
}
pub(super) fn crate_content_row(row: &PgRow) -> Result<Value> {
    Ok(
        json!({"id":row.try_get::<String,_>("id").map_err(|_|failure())?,"name":row.try_get::<String,_>("name").map_err(|_|failure())?,"version":row.try_get::<String,_>("version").map_err(|_|failure())?,"target":row.try_get::<String,_>("target").map_err(|_|failure())?,"path":row.try_get::<String,_>("path").map_err(|_|failure())?,"kind":row.try_get::<String,_>("kind").map_err(|_|failure())?,"capture":row.try_get::<String,_>("capture").map_err(|_|failure())?,"metadata_capture":row.try_get::<String,_>("metadata_capture").map_err(|_|failure())?,"archive_capture":row.try_get::<String,_>("archive_capture").map_err(|_|failure())?,"attributes":row.try_get::<Json<Value>,_>("attributes").map_err(|_|failure())?.0}),
    )
}
fn specialized_payload_expression(table: &str, column: &str) -> String {
    match (table, column) {
        ("devres_rfc_snapshots","data")=>"jsonb_build_object('published_order',published_order,'catalogue_capture',catalogue_capture,'errata_capture',errata_capture,'created_at',created_at,'complete',complete,'data',data)".into(),
        ("devres_advisory_snapshots","data")=>"jsonb_build_object('sequence',sequence,'format',format,'revision',revision,'data',data)".into(),
        ("devres_crate_generations","summary")=>"jsonb_build_object('published_sequence',published_sequence,'summary',summary)".into(),
        ("devres_crate_snapshots","data")=>"jsonb_build_object('sequence',sequence,'inventory',inventory,'content_sequence',content_sequence,'data',data)".into(),
        ("devres_crate_staging","record")=>"jsonb_build_object('metadata_capture',metadata_capture,'record',record)".into(),
        ("devres_crate_versions","record")=>"jsonb_build_object('metadata_capture',metadata_capture,'valid_to',valid_to,'record',record)".into(),
        ("devres_crate_artifacts","provenance")=>"jsonb_build_object('bytes',bytes,'provenance',provenance)".into(),
        ("devres_crate_observations","provenance")=>"jsonb_build_object('capture_id',capture_id,'observed_at',observed_at,'transport',transport,'provenance',provenance)".into(),
        ("devres_crate_content","attributes")=>"jsonb_build_object('id',id,'name',name,'version',version,'target',target,'path',path,'kind',kind,'capture',capture,'metadata_capture',metadata_capture,'archive_capture',archive_capture,'attributes',attributes)".into(),
        _=>column.into(),
    }
}

pub(super) fn rfc_snapshot_payload(
    order: i64,
    catalogue: String,
    errata: Option<String>,
    created: i64,
    complete: bool,
    data: &Value,
) -> Result<Value> {
    if data["catalogue_capture"] != catalogue
        || data["errata_capture"] != serde_json::to_value(&errata).map_err(|_| failure())?
        || data["created_at"] != created
        || data["complete"] != complete
    {
        return Err(failure());
    }
    Ok(
        json!({"published_order":order,"catalogue_capture":catalogue,"errata_capture":errata,"created_at":created,"complete":complete,"data":data}),
    )
}
pub(super) fn advisory_snapshot_payload(
    sequence: i64,
    format: &str,
    revision: &str,
    data: &Value,
) -> Result<Value> {
    if data["format"] != format || data["revision"] != revision {
        return Err(failure());
    }
    Ok(json!({"sequence":sequence,"format":format,"revision":revision,"data":data}))
}
pub(super) fn crate_generation_payload(
    published_sequence: Option<i64>,
    summary: &Value,
) -> Result<Value> {
    if published_sequence.is_some_and(|sequence| sequence <= 0) {
        return Err(failure());
    }
    Ok(json!({"published_sequence":published_sequence,"summary":summary}))
}

pub(super) fn crate_snapshot_payload(
    sequence: i64,
    inventory: &str,
    cutoff: i64,
    data: &Value,
) -> Result<Value> {
    if data["inventory"]["id"] != inventory || data["content_sequence"] != cutoff {
        return Err(failure());
    }
    Ok(json!({"sequence":sequence,"inventory":inventory,"content_sequence":cutoff,"data":data}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    #[ignore = "requires disposable PostgreSQL; run the SQL integrity fixture explicitly"]
    async fn sql_payload_integrity_rejects_tampered_points_batches_and_state() {
        use devres_application::crate_corpus::{
            ContentFilter, ContentRecord, CrateCorpusStore, VersionRecord,
        };
        use devres_application::mdn::{MdnStore, MdnWrite};
        let base = std::env::var("DEVRES_TEST_DATABASE_URL").expect("disposable database required");
        let admin = sqlx::PgPool::connect(&base).await.unwrap();
        sqlx::query("CREATE DATABASE devres_sql_integrity_fixture")
            .execute(&admin)
            .await
            .unwrap();
        let mut url = url::Url::parse(&base).unwrap();
        url.set_path("/devres_sql_integrity_fixture");
        let root = tempfile::tempdir().unwrap();
        let store = super::super::PgBlobStore::connect(url.as_str(), root.path())
            .await
            .unwrap();
        let one = crate::integrity::hash(&serde_json::to_vec(&json!({"value":1})).unwrap());
        let two = crate::integrity::hash(&serde_json::to_vec(&json!({"value":2})).unwrap());
        let rows = vec![
            MdnWrite {
                kind: "projections".into(),
                key: one.clone(),
                data: json!({"value":1}),
            },
            MdnWrite {
                kind: "projections".into(),
                key: two.clone(),
                data: json!({"value":2}),
            },
        ];
        store.mdn_put_many(&rows).await.unwrap();
        assert_eq!(
            store
                .mdn_get_many("projections", &[one.clone(), two.clone()])
                .await
                .unwrap()
                .len(),
            2
        );
        store
            .mdn_set_state("fixture", &json!(["scalar", 1]))
            .await
            .unwrap();
        assert_eq!(
            store.mdn_state("fixture").await.unwrap(),
            Some(json!(["scalar", 1]))
        );
        sqlx::query("UPDATE devres_mdn_evidence SET data='{\"value\":999}'::jsonb WHERE kind='projections' AND key=$1").bind(&one).execute(&store.pool).await.unwrap();
        assert_eq!(
            store.mdn_get("projections", &one).await.unwrap_err().code,
            "integrity"
        );
        assert_eq!(
            store
                .mdn_get_many("projections", &[one.clone(), two.clone()])
                .await
                .unwrap_err()
                .code,
            "integrity"
        );
        assert_eq!(
            store
                .mdn_rows("projections", 0, 10, None)
                .await
                .unwrap_err()
                .code,
            "integrity"
        );
        assert_eq!(
            store
                .mdn_put("projections", &one, &json!({"value":999}))
                .await
                .unwrap_err()
                .code,
            "integrity"
        );
        sqlx::query("UPDATE devres_mdn_state SET data='false'::jsonb WHERE key='fixture'")
            .execute(&store.pool)
            .await
            .unwrap();
        assert_eq!(
            store.mdn_state("fixture").await.unwrap_err().code,
            "integrity"
        );
        let first = store
            .save_text(
                "cargo:derived:sql-integrity:first",
                "https://fixtures.invalid/first",
                "first",
                json!({"fixture":true}),
                1,
            )
            .await
            .unwrap();
        let second = store
            .save_text(
                "cargo:derived:sql-integrity:second",
                "https://fixtures.invalid/second",
                "second",
                json!({"fixture":true}),
                2,
            )
            .await
            .unwrap();
        let generation = crate::integrity::hash(b"sql full-content fixture");
        let content = ContentRecord {
            id: crate::integrity::hash(format!("{}\0source\0\0src/lib.rs", first.id).as_bytes()),
            name: "example".into(),
            version: "1.0.0".into(),
            target: String::new(),
            path: "src/lib.rs".into(),
            kind: "source".into(),
            capture: first.id.clone(),
            metadata_capture: first.id.clone(),
            archive_capture: first.id.clone(),
            attributes: json!({"language":"rust"}),
        };
        store.stage_content(&generation, &[content]).await.unwrap();
        store
            .commit_content(&generation, json!({"job_key":"fixture"}))
            .await
            .unwrap();
        let cutoff: i64 = sqlx::query_scalar(
            "SELECT published_sequence FROM devres_crate_generations WHERE id=$1",
        )
        .bind(&generation)
        .fetch_one(&store.pool)
        .await
        .unwrap();
        assert_eq!(
            store
                .contents(cutoff, &ContentFilter::default(), None, 10)
                .await
                .unwrap()
                .len(),
            1
        );
        // An unreferenced generation's publication position is still durable content.
        let standalone = crate::integrity::hash(b"unreferenced generation ordering fixture");
        store
            .commit_content(&standalone, json!({"job_key":"unreferenced"}))
            .await
            .unwrap();
        let standalone_sequence: i64 = sqlx::query_scalar(
            "SELECT published_sequence FROM devres_crate_generations WHERE id=$1",
        )
        .bind(&standalone)
        .fetch_one(&store.pool)
        .await
        .unwrap();
        sqlx::query("UPDATE devres_crate_generations SET published_sequence=$2 WHERE id=$1")
            .bind(&standalone)
            .bind(standalone_sequence + 100_000)
            .execute(&store.pool)
            .await
            .unwrap();
        assert_eq!(
            store
                .commit_content(&standalone, json!({"job_key":"unreferenced"}))
                .await
                .unwrap_err()
                .code,
            "integrity"
        );
        assert_eq!(
            backfill_specialized(&store, &tokio_util::sync::CancellationToken::new(), true)
                .await
                .unwrap_err()
                .code,
            "integrity"
        );
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            sqlx::query("UPDATE devres_crate_generations SET published_sequence=$2 WHERE id=$1")
                .bind(&standalone)
                .bind(standalone_sequence)
                .execute(&store.pool),
        )
        .await
        .expect("rejected publication must release its row lock before returning")
        .unwrap();
        sqlx::query("UPDATE devres_crate_content SET metadata_capture=$2 WHERE generation=$1")
            .bind(&generation)
            .bind(&second.id)
            .execute(&store.pool)
            .await
            .unwrap();
        assert_eq!(
            store
                .contents(cutoff, &ContentFilter::default(), None, 10)
                .await
                .unwrap_err()
                .code,
            "integrity"
        );
        let before = store.begin_inventory(&"a".repeat(40), 10).await.unwrap();
        let record = |metadata: String| VersionRecord {
            name: "example".into(),
            version: "1.0.0".into(),
            metadata_capture: metadata,
            record: json!({"name":"example","vers":"1.0.0","cksum":"a".repeat(64),"deps":[],"features":{},"yanked":false}),
            metadata_status: None,
        };
        store
            .stage_crate(
                &before.id,
                "example",
                &[record(first.id.clone())],
                "example",
            )
            .await
            .unwrap();
        store.commit_inventory(&before.id, &first.id).await.unwrap();
        let next = store.begin_inventory(&"b".repeat(40), 20).await.unwrap();
        store
            .stage_crate(&next.id, "example", &[record(second.id.clone())], "example")
            .await
            .unwrap();
        store.commit_inventory(&next.id, &second.id).await.unwrap();
        assert!(
            store
                .version(&before.id, "example", "1.0.0")
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .version(&next.id, "example", "1.0.0")
                .await
                .unwrap()
                .is_some()
        );
        sqlx::query("UPDATE devres_crate_versions SET metadata_capture=$2 WHERE valid_from=$1")
            .bind(before.sequence)
            .bind(&second.id)
            .execute(&store.pool)
            .await
            .unwrap();
        assert_eq!(
            store
                .version(&before.id, "example", "1.0.0")
                .await
                .unwrap_err()
                .code,
            "integrity"
        );
        stage(&store, "rfc", "fixture", &json!({"capture":"one"}))
            .await
            .unwrap();
        assert_eq!(
            stage(&store, "rfc", "fixture", &json!({"capture":"two"}))
                .await
                .unwrap_err()
                .code,
            "integrity"
        );
    }

    #[test]
    fn payload_integrity_binds_namespace_identity_and_contents() {
        let data = json!({"body":"public fixture","nested":{"b":2,"a":1}});
        let digest = digest("devres_mdn_evidence", "projections", "fixture", &data).unwrap();
        assert_eq!(
            checked(
                "devres_mdn_evidence",
                "projections",
                "fixture",
                data.clone(),
                &digest
            )
            .unwrap(),
            data
        );
        for (table, kind, key, value) in [
            (
                "devres_npm_evidence",
                "projections",
                "fixture",
                data.clone(),
            ),
            ("devres_mdn_evidence", "snapshots", "fixture", data.clone()),
            ("devres_mdn_evidence", "projections", "other", data.clone()),
            (
                "devres_mdn_evidence",
                "projections",
                "fixture",
                json!({"body":"changed"}),
            ),
        ] {
            assert_eq!(
                checked(table, kind, key, value, &digest).unwrap_err().code,
                "integrity"
            );
        }
        assert!(
            checked(
                "devres_mdn_evidence",
                "projections",
                "fixture",
                data,
                &"a".repeat(64)
            )
            .is_err()
        );
    }
}
