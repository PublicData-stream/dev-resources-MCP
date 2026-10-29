//! Owner-fenced, append-only MDN evidence and atomic default publication.
use super::{PgBlobStore, hash, payload_integrity, sequence_integrity, storage_error, valid_hash};
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
        data: payload_integrity::row("devres_mdn_evidence", &row)?,
    })
}
#[async_trait]
impl MdnStore for PgBlobStore {
    async fn mdn_cutoff(&self) -> Result<i64> {
        self.fence().await?;
        if let Some(cutoff) = self.migration_cutoff("mdn").await? {
            return Ok(cutoff);
        }
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
        let original_keys = keys;
        let mut resolved = Vec::with_capacity(keys.len());
        for key in keys {
            resolved.push(payload_integrity::natural_key(&self.pool, "mdn", kind, key).await?);
        }
        let keys = &resolved;

        let bytes:i64=sqlx::query_scalar("SELECT COALESCE(sum(octet_length(data::text)),0)::bigint FROM devres_mdn_evidence JOIN UNNEST($2::text[]) AS requested(key) ON requested.key=devres_mdn_evidence.key WHERE kind=$1").bind(kind).bind(keys).fetch_one(&self.pool).await.map_err(|_|storage_error())?;
        if bytes > 64 * 1024 * 1024 {
            return Err(Error::capacity("MDN batch read memory bound exceeded."));
        }
        sqlx::query("SELECT sequence,kind,key,data,data_integrity,sequence_integrity FROM devres_mdn_evidence WHERE kind=$1 AND key=ANY($2::text[])").bind(kind).bind(keys).fetch_all(&self.pool).await.map_err(|_|storage_error())?.into_iter().map(|found|{let found=row(found)?;let matches=resolved.iter().enumerate().filter(|(_,key)|**key==found.key).map(|(position,_)|original_keys[position].clone()).collect::<std::collections::BTreeSet<_>>();Ok(matches.into_iter().map(|key|{let mut value=found.clone();value.key=key;value}).collect::<Vec<_>>())}).collect::<Result<Vec<Vec<_>>>>().map(|rows|rows.into_iter().flatten().collect())
    }
    async fn mdn_migration_rows(
        &self,
        kind: &str,
        after: i64,
        limit: usize,
    ) -> Result<Vec<MdnRow>> {
        checked(kind, "migration-page")?;
        if after < 0 || !(1..=1000).contains(&limit) {
            return Err(Error::invalid(
                "Invalid retained evidence verification page.",
            ));
        }
        self.fence().await?;
        let bytes:i64=sqlx::query_scalar("SELECT COALESCE(sum(n),0)::bigint FROM(SELECT octet_length(data::text) AS n FROM devres_mdn_evidence WHERE kind=$1 AND sequence>$2 ORDER BY sequence LIMIT $3) page").bind(kind).bind(after).bind(limit as i64).fetch_one(&self.pool).await.map_err(|_|storage_error())?;
        if bytes > 64 * 1024 * 1024 {
            return Err(Error::capacity(
                "Retained evidence verification page exceeds memory budget.",
            ));
        }
        sqlx::query("SELECT sequence,kind,key,data,data_integrity,sequence_integrity FROM devres_mdn_evidence WHERE kind=$1 AND sequence>$2 ORDER BY sequence LIMIT $3").bind(kind).bind(after).bind(limit as i64).fetch_all(&self.pool).await.map_err(|_|storage_error())?.into_iter().map(row).collect()
    }
    async fn mdn_migration_kinds(&self) -> Result<Vec<String>> {
        self.fence().await?;
        let kinds: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT kind FROM devres_mdn_evidence ORDER BY kind LIMIT 257",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|_| storage_error())?;
        if kinds.len() > 256 {
            return Err(Error::capacity(
                "Provider evidence kind inventory exceeds bound.",
            ));
        }
        Ok(kinds)
    }
    async fn mdn_migration_state_keys(&self, after: &str, limit: usize) -> Result<Vec<String>> {
        if !(1..=1000).contains(&limit) {
            return Err(Error::invalid("Invalid migration state page."));
        }
        self.fence().await?;
        sqlx::query_scalar("SELECT key FROM devres_mdn_state WHERE key>$1 ORDER BY key LIMIT $2")
            .bind(after)
            .bind(limit as i64)
            .fetch_all(&self.pool)
            .await
            .map_err(|_| storage_error())
    }
    async fn mdn_get(&self, kind: &str, key: &str) -> Result<Option<MdnRow>> {
        checked(kind, key)?;
        self.fence().await?;
        let resolved = payload_integrity::natural_key(&self.pool, "mdn", kind, key).await?;
        sqlx::query("SELECT sequence,kind,key,data,data_integrity,sequence_integrity FROM devres_mdn_evidence WHERE kind=$1 AND key=$2")
            .bind(kind)
            .bind(&resolved)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| storage_error())?
            .map(|found|{let mut found=row(found)?;if resolved!=key {found.key=key.to_owned();}Ok(found)})
            .transpose()
    }
    async fn mdn_put(&self, kind: &str, key: &str, data: &Value) -> Result<i64> {
        checked(kind, key)?;
        bounded(data)?;
        let resolved = payload_integrity::natural_key(&self.pool, "mdn", kind, key).await?;
        let key = resolved.as_str();
        let mut owner = self.owner.lock().await;
        // This non-reconnecting connection itself holds the ownership lock. One
        // atomic statement suffices for a new immutable row; cancellation can
        // leave only a replayable, unreferenced public object.
        if let Some(sequence) =
            sequence_integrity::admit(&mut owner, "devres_mdn_evidence", kind, key, data).await?
        {
            return Ok(sequence);
        }
        let allocated = sequence_integrity::reserve_one(&mut owner, "devres_mdn_evidence").await?;
        let inserted:Option<i64>=sqlx::query_scalar("INSERT INTO devres_mdn_evidence(kind,key,data,data_integrity,sequence,sequence_integrity) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING RETURNING sequence").bind(kind).bind(key).bind(Json(data)).bind(payload_integrity::digest("devres_mdn_evidence",kind,key,data)?).bind(allocated).bind(sequence_integrity::digest("devres_mdn_evidence",kind,key,allocated)?).fetch_optional(&mut *owner).await.map_err(|_|storage_error())?;
        if let Some(sequence) = inserted {
            return Ok(sequence);
        }
        let retained =
            sqlx::query("SELECT sequence,kind,key,data,data_integrity,sequence_integrity,data=$3::jsonb AS identical FROM devres_mdn_evidence WHERE kind=$1 AND key=$2")
                .bind(kind)
                .bind(key)
                .bind(Json(data))
                .fetch_one(&mut *owner)
                .await
                .map_err(|_| storage_error())?;
        payload_integrity::row("devres_mdn_evidence", &retained)?;
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
        let mut resolved_rows = rows.to_vec();
        for row in &mut resolved_rows {
            row.key =
                payload_integrity::natural_key(&self.pool, "mdn", &row.kind, &row.key).await?;
        }
        let rows = resolved_rows.as_slice();
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
        let digests = rows
            .iter()
            .map(|row| {
                payload_integrity::digest("devres_mdn_evidence", &row.kind, &row.key, &row.data)
            })
            .collect::<Result<Vec<_>>>()?;
        let mut owner = self.owner.lock().await;
        // This connection itself owns the non-reconnecting session fence. All
        // rows and collision checks commit together, without changing durability.
        let mut tx = owner.begin().await.map_err(|_| storage_error())?;
        for row in rows {
            sequence_integrity::admit(
                &mut tx,
                "devres_mdn_evidence",
                &row.kind,
                &row.key,
                &row.data,
            )
            .await?;
        }
        let sequences =
            sequence_integrity::reserve(&mut tx, "devres_mdn_evidence", rows.len()).await?;
        let sequence_digests = rows
            .iter()
            .zip(&sequences)
            .map(|(row, sequence)| {
                sequence_integrity::digest("devres_mdn_evidence", &row.kind, &row.key, *sequence)
            })
            .collect::<Result<Vec<_>>>()?;
        sqlx::query("INSERT INTO devres_mdn_evidence(kind,key,data,data_integrity,sequence,sequence_integrity) SELECT * FROM UNNEST($1::text[],$2::text[],$3::jsonb[],$4::text[],$5::bigint[],$6::text[]) ON CONFLICT DO NOTHING")
            .bind(&kinds).bind(&keys).bind(&values).bind(&digests).bind(&sequences).bind(&sequence_digests).execute(&mut *tx).await.map_err(|_|storage_error())?;
        let matched:i64=sqlx::query_scalar("SELECT count(*)::bigint FROM UNNEST($1::text[],$2::text[],$3::jsonb[],$4::text[]) AS expected(kind,key,data,data_integrity) JOIN devres_mdn_evidence AS retained ON retained.kind=expected.kind AND retained.key=expected.key AND retained.data=expected.data AND retained.data_integrity=expected.data_integrity")
            .bind(&kinds).bind(&keys).bind(&values).bind(&digests).fetch_one(&mut *tx).await.map_err(|_|storage_error())?;
        if matched != rows.len() as i64 {
            return Err(Error::integrity(
                "MDN immutable evidence identity collision.",
            ));
        }
        sequence_integrity::verify_keys(&mut tx, "devres_mdn_evidence", &kinds, &keys).await?;
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
        let excluded = self.visibility_aliases("mdn", kind, cutoff).await?;
        let bytes:i64=sqlx::query_scalar("SELECT COALESCE(sum(n),0)::bigint FROM (SELECT octet_length(data::text) AS n FROM devres_mdn_evidence WHERE kind=$1 AND sequence>$2 AND ($3::bigint IS NULL OR sequence<=$3) AND NOT(key=ANY($5::text[])) ORDER BY sequence LIMIT $4) page").bind(kind).bind(after).bind(cutoff).bind(limit as i64).bind(excluded.as_ref()).fetch_one(&self.pool).await.map_err(|_|storage_error())?;
        if bytes > 64 * 1024 * 1024 {
            return Err(Error::capacity("MDN evidence page memory bound exceeded."));
        }
        sqlx::query("SELECT sequence,kind,key,data,data_integrity,sequence_integrity FROM devres_mdn_evidence WHERE kind=$1 AND sequence>$2 AND ($3::bigint IS NULL OR sequence<=$3) AND NOT(key=ANY($5::text[])) ORDER BY sequence LIMIT $4")
            .bind(kind).bind(after).bind(cutoff).bind(limit as i64).bind(excluded.as_ref()).fetch_all(&self.pool).await.map_err(|_|storage_error())?.into_iter().map(row).collect()
    }
    async fn mdn_state(&self, key: &str) -> Result<Option<Value>> {
        checked("state", key)?;
        self.fence().await?;
        Ok(
            payload_integrity::load(&self.pool, "devres_mdn_state", "", key)
                .await?
                .map(|value| value.0),
        )
    }
    async fn mdn_set_state(&self, key: &str, data: &Value) -> Result<()> {
        checked("state", key)?;
        bounded(data)?;
        let mut owner = self.owner.lock().await;
        owner.ping().await.map_err(|_| storage_error())?;
        sqlx::query("INSERT INTO devres_mdn_state(key,data,data_integrity) VALUES($1,$2,$3) ON CONFLICT(key) DO UPDATE SET data=EXCLUDED.data,data_integrity=EXCLUDED.data_integrity").bind(key).bind(Json(data)).bind(payload_integrity::digest("devres_mdn_state","",key,data)?).execute(&mut *owner).await.map_err(|_|storage_error())?;
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
            let data: Json<Value> =
                payload_integrity::load(&mut *tx, "devres_mdn_evidence", "snapshots", id)
                    .await?
                    .ok_or_else(|| Error::integrity("Retained publication evidence missing."))?;
            let snapshot: Snapshot = serde_json::from_value(data.0)
                .map_err(|_| Error::integrity("Invalid MDN snapshot."))?;
            let evidence: Json<Value> = payload_integrity::load(
                &mut *tx,
                "devres_mdn_evidence",
                "observations",
                observation,
            )
            .await?
            .ok_or_else(|| Error::integrity("Retained publication evidence missing."))?;
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
        sequence_integrity::admit(&mut tx, "devres_mdn_evidence", "views", &view.id, &data).await?;
        let allocated = sequence_integrity::reserve_one(&mut tx, "devres_mdn_evidence").await?;
        sqlx::query("INSERT INTO devres_mdn_evidence(kind,key,data,data_integrity,sequence,sequence_integrity) VALUES('views',$1,$2,$3,$4,$5) ON CONFLICT DO NOTHING").bind(&view.id).bind(Json(&data)).bind(payload_integrity::digest("devres_mdn_evidence","views",&view.id,&data)?).bind(allocated).bind(sequence_integrity::digest("devres_mdn_evidence","views",&view.id,allocated)?).execute(&mut *tx).await.map_err(|_|storage_error())?;
        sequence_integrity::verify_keys(
            &mut tx,
            "devres_mdn_evidence",
            &["views".to_owned()],
            std::slice::from_ref(&view.id),
        )
        .await?;
        let retained: Json<Value> =
            payload_integrity::load(&mut *tx, "devres_mdn_evidence", "views", &view.id)
                .await?
                .ok_or_else(|| Error::integrity("Retained publication evidence missing."))?;
        if retained.0 != data {
            return Err(Error::integrity("MDN view identity collision."));
        }
        sqlx::query("INSERT INTO devres_mdn_state(key,data,data_integrity) VALUES('default-view',$1,$2) ON CONFLICT(key) DO UPDATE SET data=EXCLUDED.data,data_integrity=EXCLUDED.data_integrity").bind(Json(serde_json::json!(view.id))).bind(payload_integrity::digest("devres_mdn_state","","default-view",&serde_json::json!(view.id))?).execute(&mut *tx).await.map_err(|_|storage_error())?;
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
