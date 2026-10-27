//! Owner-fenced, append-only MDN evidence and atomic default publication.
use super::{PgBlobStore, hash, storage_error, valid_hash};
use async_trait::async_trait;
use devres_application::mdn::{MdnRow, MdnStore, MdnWrite, Snapshot, View, validate_mdn_writes};
use devres_domain::{Error, Result};
use serde_json::Value;
use sqlx::{Connection, Row, types::Json};

fn checked(kind: &str, key: &str) -> Result<()> {
    if kind.is_empty()
        || kind.len() > 64
        || !kind.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
        || key.is_empty()
        || key.len() > 4096
        || key.chars().any(char::is_control)
    {
        return Err(Error::invalid("Invalid MDN evidence key."));
    }
    Ok(())
}
fn bounded(data: &Value) -> Result<()> {
    let bytes = serde_json::to_vec(data).map_err(|_| Error::integrity("Invalid MDN evidence."))?;
    if bytes.len() > 16 * 1024 * 1024 {
        return Err(Error::capacity("MDN evidence row exceeds its bound."));
    }
    Ok(())
}
fn row(row: sqlx::postgres::PgRow) -> Result<MdnRow> {
    Ok(MdnRow {
        sequence: row.try_get("sequence").map_err(|_| storage_error())?,
        key: row.try_get("key").map_err(|_| storage_error())?,
        data: row
            .try_get::<Json<Value>, _>("data")
            .map_err(|_| storage_error())?
            .0,
    })
}
#[async_trait]
impl MdnStore for PgBlobStore {
    async fn mdn_cutoff(&self) -> Result<i64> {
        self.fence().await?;
        sqlx::query_scalar("SELECT COALESCE(max(sequence),0) FROM devres_mdn_evidence")
            .fetch_one(&self.pool)
            .await
            .map_err(|_| storage_error())
    }
    async fn mdn_get_many(&self, kind: &str, keys: &[String]) -> Result<Vec<MdnRow>> {
        if keys.len() > 1000 {
            return Err(Error::capacity("MDN batch read exceeds its bound."));
        }
        for key in keys {
            checked(kind, key)?;
        }
        self.fence().await?;
        let bytes:i64=sqlx::query_scalar("SELECT COALESCE(sum(octet_length(data::text)),0)::bigint FROM devres_mdn_evidence WHERE kind=$1 AND key=ANY($2::text[])").bind(kind).bind(keys).fetch_one(&self.pool).await.map_err(|_|storage_error())?;
        if bytes > 64 * 1024 * 1024 {
            return Err(Error::capacity("MDN batch read memory bound exceeded."));
        }
        sqlx::query("SELECT sequence,key,data FROM devres_mdn_evidence WHERE kind=$1 AND key=ANY($2::text[])").bind(kind).bind(keys).fetch_all(&self.pool).await.map_err(|_|storage_error())?.into_iter().map(row).collect()
    }
    async fn mdn_get(&self, kind: &str, key: &str) -> Result<Option<MdnRow>> {
        checked(kind, key)?;
        self.fence().await?;
        sqlx::query("SELECT sequence,key,data FROM devres_mdn_evidence WHERE kind=$1 AND key=$2")
            .bind(kind)
            .bind(key)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| storage_error())?
            .map(row)
            .transpose()
    }
    async fn mdn_put(&self, kind: &str, key: &str, data: &Value) -> Result<i64> {
        checked(kind, key)?;
        bounded(data)?;
        let mut owner = self.owner.lock().await;
        // This non-reconnecting connection itself holds the ownership lock. One
        // atomic statement suffices for a new immutable row; cancellation can
        // leave only a replayable, unreferenced public object.
        let inserted:Option<i64>=sqlx::query_scalar("INSERT INTO devres_mdn_evidence(kind,key,data) VALUES($1,$2,$3) ON CONFLICT DO NOTHING RETURNING sequence").bind(kind).bind(key).bind(Json(data)).fetch_optional(&mut *owner).await.map_err(|_|storage_error())?;
        if let Some(sequence) = inserted {
            return Ok(sequence);
        }
        let retained =
            sqlx::query("SELECT sequence,data=$3::jsonb AS identical FROM devres_mdn_evidence WHERE kind=$1 AND key=$2")
                .bind(kind)
                .bind(key)
                .bind(Json(data))
                .fetch_one(&mut *owner)
                .await
                .map_err(|_| storage_error())?;
        if !retained
            .try_get::<bool, _>("identical")
            .map_err(|_| storage_error())?
        {
            return Err(Error::integrity(
                "MDN immutable evidence identity collision.",
            ));
        }
        let sequence = retained.try_get("sequence").map_err(|_| storage_error())?;
        Ok(sequence)
    }
    async fn mdn_put_many(&self, rows: &[MdnWrite]) -> Result<()> {
        validate_mdn_writes(rows)?;
        for row in rows {
            checked(&row.kind, &row.key)?;
        }
        if rows.is_empty() {
            return Ok(());
        }
        let kinds: Vec<_> = rows.iter().map(|r| r.kind.clone()).collect();
        let keys: Vec<_> = rows.iter().map(|r| r.key.clone()).collect();
        let values: Vec<_> = rows.iter().map(|r| Json(r.data.clone())).collect();
        let mut owner = self.owner.lock().await;
        // This connection itself owns the non-reconnecting session fence. All
        // rows and collision checks commit together, without changing durability.
        let mut tx = owner.begin().await.map_err(|_| storage_error())?;
        sqlx::query("INSERT INTO devres_mdn_evidence(kind,key,data) SELECT * FROM UNNEST($1::text[],$2::text[],$3::jsonb[]) ON CONFLICT DO NOTHING")
            .bind(&kinds).bind(&keys).bind(&values).execute(&mut *tx).await.map_err(|_|storage_error())?;
        let matched:i64=sqlx::query_scalar("SELECT count(*)::bigint FROM UNNEST($1::text[],$2::text[],$3::jsonb[]) AS expected(kind,key,data) JOIN devres_mdn_evidence AS retained ON retained.kind=expected.kind AND retained.key=expected.key AND retained.data=expected.data")
            .bind(&kinds).bind(&keys).bind(&values).fetch_one(&mut *tx).await.map_err(|_|storage_error())?;
        if matched != rows.len() as i64 {
            return Err(Error::integrity(
                "MDN immutable evidence identity collision.",
            ));
        }
        tx.commit().await.map_err(|_| storage_error())
    }
    async fn mdn_rows(
        &self,
        kind: &str,
        after: i64,
        limit: usize,
        cutoff: Option<i64>,
    ) -> Result<Vec<MdnRow>> {
        checked(kind, "rows")?;
        if !(1..=1000).contains(&limit) || after < 0 || cutoff.is_some_and(|c| c < 0) {
            return Err(Error::invalid("Invalid MDN evidence page."));
        }
        self.fence().await?;
        let bytes:i64=sqlx::query_scalar("SELECT COALESCE(sum(n),0)::bigint FROM (SELECT octet_length(data::text) AS n FROM devres_mdn_evidence WHERE kind=$1 AND sequence>$2 AND ($3::bigint IS NULL OR sequence<=$3) ORDER BY sequence LIMIT $4) page").bind(kind).bind(after).bind(cutoff).bind(limit as i64).fetch_one(&self.pool).await.map_err(|_|storage_error())?;
        if bytes > 64 * 1024 * 1024 {
            return Err(Error::capacity("MDN evidence page memory bound exceeded."));
        }
        sqlx::query("SELECT sequence,key,data FROM devres_mdn_evidence WHERE kind=$1 AND sequence>$2 AND ($3::bigint IS NULL OR sequence<=$3) ORDER BY sequence LIMIT $4")
            .bind(kind).bind(after).bind(cutoff).bind(limit as i64).fetch_all(&self.pool).await.map_err(|_|storage_error())?.into_iter().map(row).collect()
    }
    async fn mdn_state(&self, key: &str) -> Result<Option<Value>> {
        checked("state", key)?;
        self.fence().await?;
        Ok(
            sqlx::query_scalar::<_, Json<Value>>("SELECT data FROM devres_mdn_state WHERE key=$1")
                .bind(key)
                .fetch_optional(&self.pool)
                .await
                .map_err(|_| storage_error())?
                .map(|j| j.0),
        )
    }
    async fn mdn_set_state(&self, key: &str, data: &Value) -> Result<()> {
        checked("state", key)?;
        bounded(data)?;
        let mut owner = self.owner.lock().await;
        owner.ping().await.map_err(|_| storage_error())?;
        sqlx::query("INSERT INTO devres_mdn_state(key,data) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET data=EXCLUDED.data").bind(key).bind(Json(data)).execute(&mut *owner).await.map_err(|_|storage_error())?;
        Ok(())
    }
    async fn mdn_publish_view(&self, view: &View) -> Result<()> {
        let identity = serde_json::to_vec(&(
            &view.content,
            &view.compatibility,
            &view.content_observation,
            &view.compatibility_observation,
            view.validated_at,
        ))
        .map_err(|_| storage_error())?;
        if !valid_hash(&view.id) || hash(&identity) != view.id || view.validated_at <= 0 {
            return Err(Error::integrity("Invalid MDN view identity."));
        }
        let mut owner = self.owner.lock().await;
        owner.ping().await.map_err(|_| storage_error())?;
        let mut tx = owner.begin().await.map_err(|_| storage_error())?;
        for (id, repository, observation) in [
            (&view.content, "content", &view.content_observation),
            (
                &view.compatibility,
                "compat",
                &view.compatibility_observation,
            ),
        ] {
            let data: Json<Value> = sqlx::query_scalar(
                "SELECT data FROM devres_mdn_evidence WHERE kind='snapshots' AND key=$1",
            )
            .bind(id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| storage_error())?;
            let snapshot: Snapshot = serde_json::from_value(data.0)
                .map_err(|_| Error::integrity("Invalid MDN snapshot."))?;
            let evidence: Json<Value> = sqlx::query_scalar(
                "SELECT data FROM devres_mdn_evidence WHERE kind='observations' AND key=$1",
            )
            .bind(observation)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| storage_error())?;
            if snapshot.coverage["synthetic"] == true
                || snapshot.repository != repository
                || snapshot.index.is_null()
                || snapshot.coverage["accounted"] != true
                || evidence.0["main_revision"].as_str() != Some(&snapshot.revision)
                || evidence.0["observed_at"]
                    .as_i64()
                    .is_none_or(|t| t < view.validated_at)
            {
                return Err(Error::integrity(
                    "MDN default requires validated main evidence and published accounting.",
                ));
            }
        }
        let data = serde_json::to_value(view).map_err(|_| storage_error())?;
        sqlx::query("INSERT INTO devres_mdn_evidence(kind,key,data) VALUES('views',$1,$2) ON CONFLICT DO NOTHING").bind(&view.id).bind(Json(&data)).execute(&mut *tx).await.map_err(|_|storage_error())?;
        let retained: Json<Value> = sqlx::query_scalar(
            "SELECT data FROM devres_mdn_evidence WHERE kind='views' AND key=$1",
        )
        .bind(&view.id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| storage_error())?;
        if retained.0 != data {
            return Err(Error::integrity("MDN view identity collision."));
        }
        sqlx::query("INSERT INTO devres_mdn_state(key,data) VALUES('default-view',$1) ON CONFLICT(key) DO UPDATE SET data=EXCLUDED.data").bind(Json(serde_json::json!(view.id))).execute(&mut *tx).await.map_err(|_|storage_error())?;
        tx.commit().await.map_err(|_| storage_error())
    }
}
pub(super) const SCHEMA_V5: &str = r#"
CREATE TABLE devres_mdn_evidence (
 sequence bigserial PRIMARY KEY,
 kind text NOT NULL,
 key text NOT NULL,
 data jsonb NOT NULL,
 UNIQUE(kind,key)
);
CREATE INDEX devres_mdn_evidence_page ON devres_mdn_evidence(kind,sequence);
CREATE TABLE devres_mdn_state(key text PRIMARY KEY,data jsonb NOT NULL);
"#;
