//! Integrity for durable validation events, public heads and compatibility mappings.
use super::{PgBlobStore, storage_error};
use devres_domain::{Error, Result};
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
        self.fence().await?;
        for table in ["devres_observations", "devres_rfc_import_observations"] {
            let mut after = 0_i64;
            loop {
                if cancel.is_cancelled() {
                    return Err(Error::new(
                        "cancelled",
                        "Validation metadata qualification canceled.",
                    ));
                }
                let sql = format!("SELECT * FROM {table} WHERE id>$1 ORDER BY id LIMIT 100");
                let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(after)
                    .fetch_all(&self.pool)
                    .await
                    .map_err(|_| storage_error())?;
                if rows.is_empty() {
                    break;
                }
                for row in rows {
                    let id: i64 = row.try_get("id").map_err(|_| invalid())?;
                    let payload = if table == "devres_observations" {
                        http_payload(&row)?
                    } else {
                        import_payload(&row)?
                    };
                    let expected: Option<String> =
                        row.try_get("event_integrity").map_err(|_| invalid())?;
                    if let Some(expected) = expected {
                        verify(table, &id.to_string(), &payload, &expected)?;
                    } else if verify_only {
                        return Err(invalid());
                    } else {
                        let sql = format!(
                            "UPDATE {table} SET event_integrity=$2 WHERE id=$1 AND event_integrity IS NULL"
                        );
                        sqlx::query(sqlx::AssertSqlSafe(sql))
                            .bind(id)
                            .bind(event_digest(table, &id.to_string(), &payload)?)
                            .execute(&mut *self.owner.lock().await)
                            .await
                            .map_err(|_| storage_error())?;
                    }
                    after = id;
                }
            }
        }
        let mut after = String::new();
        loop {
            if cancel.is_cancelled() {
                return Err(Error::new(
                    "cancelled",
                    "Head integrity qualification canceled.",
                ));
            }
            let rows = sqlx::query(
                "SELECT * FROM devres_heads WHERE source_key>$1 ORDER BY source_key LIMIT 100",
            )
            .bind(&after)
            .fetch_all(&self.pool)
            .await
            .map_err(|_| storage_error())?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                let key: String = row.try_get("source_key").map_err(|_| invalid())?;
                let payload = head_payload(&row)?;
                let expected: Option<String> =
                    row.try_get("head_integrity").map_err(|_| invalid())?;
                if let Some(expected) = expected {
                    verify("devres_heads", &key, &payload, &expected)?;
                } else if verify_only {
                    return Err(invalid());
                } else {
                    sqlx::query("UPDATE devres_heads SET head_integrity=$2 WHERE source_key=$1 AND head_integrity IS NULL").bind(&key).bind(event_digest("devres_heads",&key,&payload)?).execute(&mut *self.owner.lock().await).await.map_err(|_|storage_error())?;
                }
                after = key;
            }
        }
        let mut after = (String::new(), String::new());
        loop {
            if cancel.is_cancelled() {
                return Err(Error::new(
                    "cancelled",
                    "Mapping integrity qualification canceled.",
                ));
            }
            let rows=sqlx::query("SELECT * FROM devres_content_aliases WHERE (namespace,legacy)>($1,$2) ORDER BY namespace,legacy LIMIT 100").bind(&after.0).bind(&after.1).fetch_all(&self.pool).await.map_err(|_|storage_error())?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                let namespace: String = row.try_get("namespace").map_err(|_| invalid())?;
                let legacy: String = row.try_get("legacy").map_err(|_| invalid())?;
                let key = mapping_key(&namespace, &legacy)?;
                let payload = alias_payload(&row)?;
                let expected: Option<String> =
                    row.try_get("mapping_integrity").map_err(|_| invalid())?;
                if let Some(expected) = expected {
                    verify("devres_content_aliases", &key, &payload, &expected)?;
                } else if verify_only {
                    return Err(invalid());
                } else {
                    sqlx::query("UPDATE devres_content_aliases SET mapping_integrity=$3 WHERE namespace=$1 AND legacy=$2 AND mapping_integrity IS NULL").bind(&namespace).bind(&legacy).bind(event_digest("devres_content_aliases",&key,&payload)?).execute(&mut *self.owner.lock().await).await.map_err(|_|storage_error())?;
                }
                after = (namespace, legacy);
            }
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
