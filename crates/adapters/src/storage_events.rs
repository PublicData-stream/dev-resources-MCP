//! Integrity for durable validation events, public heads and compatibility mappings.
use super::{PgBlobStore, storage_error};
use devres_domain::{Error, Result};
use futures::TryStreamExt;
use serde_json::{Value, json};
use sqlx::Row;
use tokio_util::sync::CancellationToken;

fn invalid() -> Error {
    Error::integrity("Retained validation metadata integrity failed.")
}
pub(super) fn event_digest(table: &str, key: &str, payload: &Value) -> Result<String> {
    crate::integrity::canonical_hash(
        &json!({"version":1,"namespace":table,"key":key,"payload":payload}),
    )
}
pub(super) fn mapping_key(namespace: &str, legacy: &str) -> Result<String> {
    serde_json::to_string(&(namespace, legacy)).map_err(|_| invalid())
}
fn verify(table: &str, key: &str, payload: &Value, expected: &str) -> Result<()> {
    if !expected.starts_with("blake3:") || event_digest(table, key, payload)? != expected {
        return Err(invalid());
    }
    Ok(())
}
fn http_payload(row: &sqlx::postgres::PgRow) -> Result<Value> {
    Ok(
        json!({"capture_id":row.try_get::<String,_>("capture_id").map_err(|_|invalid())?,"validated_at":row.try_get::<i64,_>("validated_at").map_err(|_|invalid())?,"status":row.try_get::<i16,_>("status").map_err(|_|invalid())?}),
    )
}
fn import_payload(row: &sqlx::postgres::PgRow) -> Result<Value> {
    Ok(
        json!({"capture_id":row.try_get::<String,_>("capture_id").map_err(|_|invalid())?,"observed_at":row.try_get::<i64,_>("observed_at").map_err(|_|invalid())?,"source_url":row.try_get::<String,_>("source_url").map_err(|_|invalid())?}),
    )
}
fn head_payload(row: &sqlx::postgres::PgRow) -> Result<Value> {
    Ok(
        json!({"source_key":row.try_get::<String,_>("source_key").map_err(|_|invalid())?,"capture_id":row.try_get::<String,_>("capture_id").map_err(|_|invalid())?,"validated_at":row.try_get::<i64,_>("validated_at").map_err(|_|invalid())?,"etag":row.try_get::<Option<String>,_>("etag").map_err(|_|invalid())?,"last_modified":row.try_get::<Option<String>,_>("last_modified").map_err(|_|invalid())?}),
    )
}
fn alias_payload(row: &sqlx::postgres::PgRow) -> Result<Value> {
    Ok(
        json!({"namespace":row.try_get::<String,_>("namespace").map_err(|_|invalid())?,"legacy":row.try_get::<String,_>("legacy").map_err(|_|invalid())?,"canonical":row.try_get::<String,_>("canonical").map_err(|_|invalid())?}),
    )
}

impl PgBlobStore {
    pub(super) async fn backfill_events(
        &self,
        cancel: &CancellationToken,
        verify_only: bool,
    ) -> Result<()> {
        use super::payload_integrity::{SealBatch, SealTarget, seal_not_cancelled};
        self.fence().await?;
        for (table, column, kind_expr, key_expr) in [
            (
                "devres_observations",
                "event_integrity",
                "''::text",
                "id::text",
            ),
            (
                "devres_rfc_import_observations",
                "event_integrity",
                "''::text",
                "id::text",
            ),
            ("devres_heads", "head_integrity", "''::text", "source_key"),
            (
                "devres_content_aliases",
                "mapping_integrity",
                "namespace",
                "legacy",
            ),
        ] {
            seal_not_cancelled(cancel)?;
            let sql = format!("SELECT ctid::text AS seal_locator,* FROM {table}");
            let mut rows = sqlx::query(sqlx::AssertSqlSafe(sql)).fetch(&self.pool);
            let mut batch = SealBatch::default();
            let target = SealTarget {
                table,
                column,
                kind_expr,
                key_expr,
            };
            while let Some(row) = rows.try_next().await.map_err(|_| storage_error())? {
                seal_not_cancelled(cancel)?;
                let (kind, key, payload) = match table {
                    "devres_observations" => (
                        String::new(),
                        row.try_get::<i64, _>("id")
                            .map_err(|_| invalid())?
                            .to_string(),
                        http_payload(&row)?,
                    ),
                    "devres_rfc_import_observations" => (
                        String::new(),
                        row.try_get::<i64, _>("id")
                            .map_err(|_| invalid())?
                            .to_string(),
                        import_payload(&row)?,
                    ),
                    "devres_heads" => (
                        String::new(),
                        row.try_get("source_key").map_err(|_| invalid())?,
                        head_payload(&row)?,
                    ),
                    "devres_content_aliases" => (
                        row.try_get("namespace").map_err(|_| invalid())?,
                        row.try_get("legacy").map_err(|_| invalid())?,
                        alias_payload(&row)?,
                    ),
                    _ => return Err(invalid()),
                };
                let digest_key = if table == "devres_content_aliases" {
                    mapping_key(&kind, &key)?
                } else {
                    key.clone()
                };
                let expected: Option<String> = row.try_get(column).map_err(|_| invalid())?;
                if let Some(expected) = expected {
                    verify(table, &digest_key, &payload, &expected)?;
                } else if verify_only {
                    return Err(invalid());
                } else {
                    batch
                        .queue(
                            self,
                            cancel,
                            &target,
                            (
                                row.try_get("seal_locator").map_err(|_| invalid())?,
                                kind,
                                key,
                                event_digest(table, &digest_key, &payload)?,
                            ),
                        )
                        .await?;
                }
            }
            batch.flush(self, cancel, &target).await?;
        }
        Ok(())
    }

    pub(super) async fn verify_effective_validation(&self, capture_id: &str) -> Result<()> {
        self.fence().await?;
        let aliases=sqlx::query("SELECT namespace,legacy,canonical,mapping_integrity FROM devres_content_aliases WHERE namespace='capture' AND canonical=$1").bind(capture_id).fetch_all(&self.pool).await.map_err(|_|storage_error())?;
        let mut ids = vec![capture_id.to_owned()];
        for alias in aliases {
            let legacy: String = alias.try_get("legacy").map_err(|_| invalid())?;
            verify(
                "devres_content_aliases",
                &mapping_key("capture", &legacy)?,
                &alias_payload(&alias)?,
                &alias
                    .try_get::<String, _>("mapping_integrity")
                    .map_err(|_| invalid())?,
            )?;
            ids.push(legacy);
        }
        if let Some(row)=sqlx::query("SELECT id,capture_id,validated_at,status,event_integrity FROM devres_observations WHERE capture_id=ANY($1::text[]) ORDER BY validated_at DESC,id DESC LIMIT 1").bind(&ids).fetch_optional(&self.pool).await.map_err(|_|storage_error())? {
            verify("devres_observations",&row.try_get::<i64,_>("id").map_err(|_|invalid())?.to_string(),&http_payload(&row)?,&row.try_get::<String,_>("event_integrity").map_err(|_|invalid())?)?;
        }
        if let Some(row)=sqlx::query("SELECT id,capture_id,observed_at,source_url,event_integrity FROM devres_rfc_import_observations WHERE capture_id=ANY($1::text[]) ORDER BY observed_at DESC,id DESC LIMIT 1").bind(&ids).fetch_optional(&self.pool).await.map_err(|_|storage_error())? {
            verify("devres_rfc_import_observations",&row.try_get::<i64,_>("id").map_err(|_|invalid())?.to_string(),&import_payload(&row)?,&row.try_get::<String,_>("event_integrity").map_err(|_|invalid())?)?;
        }
        Ok(())
    }
}

pub(super) async fn append_http(
    tx: &mut sqlx::PgConnection,
    capture: &str,
    time: i64,
    status: i16,
) -> Result<()> {
    let id: i64 =
        sqlx::query_scalar("SELECT nextval(pg_get_serial_sequence('devres_observations','id'))")
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| storage_error())?;
    let payload = json!({"capture_id":capture,"validated_at":time,"status":status});
    let digest = event_digest("devres_observations", &id.to_string(), &payload)?;
    sqlx::query("INSERT INTO devres_observations(id,capture_id,validated_at,status,event_integrity) OVERRIDING SYSTEM VALUE VALUES($1,$2,$3,$4,$5)")
        .bind(id).bind(capture).bind(time).bind(status).bind(digest).execute(&mut *tx).await.map_err(|_|storage_error())?;
    Ok(())
}
pub(super) async fn append_import(
    tx: &mut sqlx::PgConnection,
    capture: &str,
    time: i64,
    url: &str,
) -> Result<()> {
    let id: i64 = sqlx::query_scalar(
        "SELECT nextval(pg_get_serial_sequence('devres_rfc_import_observations','id'))",
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| storage_error())?;
    let payload = json!({"capture_id":capture,"observed_at":time,"source_url":url});
    let digest = event_digest("devres_rfc_import_observations", &id.to_string(), &payload)?;
    sqlx::query("INSERT INTO devres_rfc_import_observations(id,capture_id,observed_at,source_url,event_integrity) OVERRIDING SYSTEM VALUE VALUES($1,$2,$3,$4,$5)")
        .bind(id).bind(capture).bind(time).bind(url).bind(digest).execute(&mut *tx).await.map_err(|_|storage_error())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn event_integrity_binds_occurrence_and_public_validation_time() {
        let value = json!({"capture_id":"fixture","validated_at":123,"status":200});
        let digest = event_digest("devres_observations", "1", &value).unwrap();
        assert!(verify("devres_observations", "1", &value, &digest).is_ok());
        assert!(verify("devres_observations", "2", &value, &digest).is_err());
        let mut changed = value;
        changed["validated_at"] = json!(124);
        assert!(verify("devres_observations", "1", &changed, &digest).is_err());
    }
}
