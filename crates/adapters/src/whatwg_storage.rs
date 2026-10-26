//! Owner-fenced, append-only WHATWG evidence and atomic default publication.
use super::{PgBlobStore, hash, storage_error, valid_hash};
use async_trait::async_trait;
use devres_application::whatwg::{Row, Snapshot, View, WhatwgStore, Write, validate_whatwg_writes};
use devres_domain::{Error, Result};
use serde_json::Value;
use sqlx::{Connection, Row as _, types::Json};

fn checked(kind: &str, key: &str) -> Result<()> {
    if kind.is_empty()
        || kind.len() > 64
        || !kind.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
        || key.is_empty()
        || key.len() > 4096
        || key.chars().any(char::is_control)
    {
        return Err(Error::invalid("Invalid WHATWG evidence key."));
    }
    Ok(())
}
fn bounded(data: &Value) -> Result<()> {
    let bytes =
        serde_json::to_vec(data).map_err(|_| Error::integrity("Invalid WHATWG evidence."))?;
    if bytes.len() > 16 * 1024 * 1024 {
        return Err(Error::capacity("WHATWG evidence row exceeds its bound."));
    }
    Ok(())
}
fn row(row: sqlx::postgres::PgRow) -> Result<Row> {
    Ok(Row {
        sequence: row.try_get("sequence").map_err(|_| storage_error())?,
        key: row.try_get("key").map_err(|_| storage_error())?,
        data: row
            .try_get::<Json<Value>, _>("data")
            .map_err(|_| storage_error())?
            .0,
    })
}
#[async_trait]
impl WhatwgStore for PgBlobStore {
    async fn whatwg_existing(
        &self,
        kind: &str,
        keys: &[String],
    ) -> Result<std::collections::BTreeSet<String>> {
        if keys.len() > 1000 {
            return Err(Error::capacity("WHATWG existence batch exceeds its bound."));
        }
        for key in keys {
            checked(kind, key)?;
        }
        self.fence().await?;
        let keys: Vec<String> = sqlx::query_scalar(
            "SELECT key FROM devres_whatwg_evidence WHERE kind=$1 AND key=ANY($2::text[])",
        )
        .bind(kind)
        .bind(keys)
        .fetch_all(&self.pool)
        .await
        .map_err(|_| storage_error())?;
        Ok(keys.into_iter().collect())
    }
    async fn whatwg_statistics(&self) -> Result<Value> {
        self.fence().await?;
        let data:Json<Value>=sqlx::query_scalar("SELECT jsonb_build_object('snapshots',COALESCE(sum(rows) FILTER(WHERE kind='snapshots'),0),'publications',COALESCE(sum(rows) FILTER(WHERE kind='publications'),0),'projection_gaps',COALESCE(sum(projection_gaps),0),'index_gaps',COALESCE(sum(index_gaps),0)) FROM devres_whatwg_statistics").fetch_one(&self.pool).await.map_err(|_|storage_error())?;
        Ok(data.0)
    }
    async fn whatwg_cutoff(&self) -> Result<i64> {
        self.fence().await?;
        sqlx::query_scalar("SELECT COALESCE(max(sequence),0) FROM devres_whatwg_evidence")
            .fetch_one(&self.pool)
            .await
            .map_err(|_| storage_error())
    }
    async fn whatwg_get_many(&self, kind: &str, keys: &[String]) -> Result<Vec<Row>> {
        if keys.len() > 1000 {
            return Err(Error::capacity("WHATWG batch read exceeds its bound."));
        }
        for key in keys {
            checked(kind, key)?;
        }
        self.fence().await?;
        let bytes:i64=sqlx::query_scalar("SELECT COALESCE(sum(octet_length(data::text)),0)::bigint FROM devres_whatwg_evidence WHERE kind=$1 AND key=ANY($2::text[])").bind(kind).bind(keys).fetch_one(&self.pool).await.map_err(|_|storage_error())?;
        if bytes > 64 * 1024 * 1024 {
            return Err(Error::capacity("WHATWG batch read memory bound exceeded."));
        }
        sqlx::query("SELECT sequence,key,data FROM devres_whatwg_evidence WHERE kind=$1 AND key=ANY($2::text[])").bind(kind).bind(keys).fetch_all(&self.pool).await.map_err(|_|storage_error())?.into_iter().map(row).collect()
    }
    async fn whatwg_get(&self, kind: &str, key: &str) -> Result<Option<Row>> {
        checked(kind, key)?;
        self.fence().await?;
        sqlx::query("SELECT sequence,key,data FROM devres_whatwg_evidence WHERE kind=$1 AND key=$2")
            .bind(kind)
            .bind(key)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| storage_error())?
            .map(row)
            .transpose()
    }
    async fn whatwg_put(&self, kind: &str, key: &str, data: &Value) -> Result<i64> {
        checked(kind, key)?;
        bounded(data)?;
        let mut owner = self.owner.lock().await;
        // This non-reconnecting connection itself holds the ownership lock. One
        // atomic statement suffices for a new immutable row; cancellation can
        // leave only a replayable, unreferenced public object.
        let inserted:Option<i64>=sqlx::query_scalar("WITH inserted AS(INSERT INTO devres_whatwg_evidence(kind,key,data) VALUES($1,$2,$3) ON CONFLICT DO NOTHING RETURNING sequence,kind,data),counted AS(INSERT INTO devres_whatwg_statistics(kind,rows,projection_gaps,index_gaps) SELECT kind,1,CASE WHEN kind='snapshots' THEN COALESCE((data#>>'{coverage,projection_gaps}')::bigint,0) ELSE 0 END,CASE WHEN kind='snapshots' THEN COALESCE((data#>>'{coverage,index_gaps}')::bigint,0) ELSE 0 END FROM inserted ON CONFLICT(kind) DO UPDATE SET rows=devres_whatwg_statistics.rows+EXCLUDED.rows,projection_gaps=devres_whatwg_statistics.projection_gaps+EXCLUDED.projection_gaps,index_gaps=devres_whatwg_statistics.index_gaps+EXCLUDED.index_gaps RETURNING kind) SELECT sequence FROM inserted").bind(kind).bind(key).bind(Json(data)).fetch_optional(&mut *owner).await.map_err(|_|storage_error())?;
        if let Some(sequence) = inserted {
            return Ok(sequence);
        }
        let retained =
            sqlx::query("SELECT sequence,data=$3::jsonb AS identical FROM devres_whatwg_evidence WHERE kind=$1 AND key=$2")
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
                "WHATWG immutable evidence identity collision.",
            ));
        }
        let sequence = retained.try_get("sequence").map_err(|_| storage_error())?;
        Ok(sequence)
    }
    async fn whatwg_put_many(&self, rows: &[Write]) -> Result<()> {
        validate_whatwg_writes(rows)?;
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
        sqlx::query("WITH inserted AS(INSERT INTO devres_whatwg_evidence(kind,key,data) SELECT * FROM UNNEST($1::text[],$2::text[],$3::jsonb[]) ON CONFLICT DO NOTHING RETURNING kind,data) INSERT INTO devres_whatwg_statistics(kind,rows,projection_gaps,index_gaps) SELECT kind,count(*)::bigint,COALESCE(sum(CASE WHEN kind='snapshots' THEN COALESCE((data#>>'{coverage,projection_gaps}')::bigint,0) ELSE 0 END),0)::bigint,COALESCE(sum(CASE WHEN kind='snapshots' THEN COALESCE((data#>>'{coverage,index_gaps}')::bigint,0) ELSE 0 END),0)::bigint FROM inserted GROUP BY kind ON CONFLICT(kind) DO UPDATE SET rows=devres_whatwg_statistics.rows+EXCLUDED.rows,projection_gaps=devres_whatwg_statistics.projection_gaps+EXCLUDED.projection_gaps,index_gaps=devres_whatwg_statistics.index_gaps+EXCLUDED.index_gaps")
            .bind(&kinds).bind(&keys).bind(&values).execute(&mut *tx).await.map_err(|_|storage_error())?;
        let matched:i64=sqlx::query_scalar("SELECT count(*)::bigint FROM UNNEST($1::text[],$2::text[],$3::jsonb[]) AS expected(kind,key,data) JOIN devres_whatwg_evidence AS retained ON retained.kind=expected.kind AND retained.key=expected.key AND retained.data=expected.data")
            .bind(&kinds).bind(&keys).bind(&values).fetch_one(&mut *tx).await.map_err(|_|storage_error())?;
        if matched != rows.len() as i64 {
            return Err(Error::integrity(
                "WHATWG immutable evidence identity collision.",
            ));
        }
        tx.commit().await.map_err(|_| storage_error())
    }
    async fn whatwg_rows(
        &self,
        kind: &str,
        after: i64,
        limit: usize,
        cutoff: Option<i64>,
    ) -> Result<Vec<Row>> {
        checked(kind, "rows")?;
        if !(1..=1000).contains(&limit) || after < 0 || cutoff.is_some_and(|c| c < 0) {
            return Err(Error::invalid("Invalid WHATWG evidence page."));
        }
        self.fence().await?;
        let bytes:i64=sqlx::query_scalar("SELECT COALESCE(sum(n),0)::bigint FROM (SELECT octet_length(data::text) AS n FROM devres_whatwg_evidence WHERE kind=$1 AND sequence>$2 AND ($3::bigint IS NULL OR sequence<=$3) ORDER BY sequence LIMIT $4) page").bind(kind).bind(after).bind(cutoff).bind(limit as i64).fetch_one(&self.pool).await.map_err(|_|storage_error())?;
        if bytes > 64 * 1024 * 1024 {
            return Err(Error::capacity(
                "WHATWG evidence page memory bound exceeded.",
            ));
        }
        sqlx::query("SELECT sequence,key,data FROM devres_whatwg_evidence WHERE kind=$1 AND sequence>$2 AND ($3::bigint IS NULL OR sequence<=$3) ORDER BY sequence LIMIT $4")
            .bind(kind).bind(after).bind(cutoff).bind(limit as i64).fetch_all(&self.pool).await.map_err(|_|storage_error())?.into_iter().map(row).collect()
    }
    async fn whatwg_state(&self, key: &str) -> Result<Option<Value>> {
        checked("state", key)?;
        self.fence().await?;
        Ok(sqlx::query_scalar::<_, Json<Value>>(
            "SELECT data FROM devres_whatwg_state WHERE key=$1",
        )
        .bind(key)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| storage_error())?
        .map(|j| j.0))
    }
    async fn whatwg_set_state(&self, key: &str, data: &Value) -> Result<()> {
        checked("state", key)?;
        bounded(data)?;
        let mut owner = self.owner.lock().await;
        owner.ping().await.map_err(|_| storage_error())?;
        sqlx::query("INSERT INTO devres_whatwg_state(key,data) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET data=EXCLUDED.data").bind(key).bind(Json(data)).execute(&mut *owner).await.map_err(|_|storage_error())?;
        Ok(())
    }
    async fn whatwg_publish_view(&self, view: &View) -> Result<()> {
        let identity = serde_json::to_vec(&(
            &view.catalog,
            &view.snapshots,
            &view.index,
            &view.validations,
            view.validated_at,
        ))
        .map_err(|_| Error::integrity("Invalid WHATWG view."))?;
        if hash(&identity) != view.id
            || view.snapshots.len() > 256
            || view.snapshots.is_empty()
            || !valid_hash(&view.catalog)
            || view.validations.len() != view.snapshots.len()
            || view.index.is_null()
        {
            return Err(Error::integrity("Invalid WHATWG view identity."));
        }
        let mut owner = self.owner.lock().await;
        let mut tx = owner.begin().await.map_err(|_| storage_error())?;
        let catalog: Option<Json<Value>> = sqlx::query_scalar(
            "SELECT data FROM devres_whatwg_evidence WHERE kind='catalogs' AND key=$1",
        )
        .bind(&view.catalog)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| storage_error())?;
        let catalog: devres_application::whatwg::Catalog = serde_json::from_value(
            catalog
                .ok_or_else(|| Error::integrity("WHATWG view catalog missing."))?
                .0,
        )
        .map_err(|_| Error::integrity("Invalid WHATWG catalog."))?;
        if view.validated_at
            != view
                .validations
                .values()
                .copied()
                .min()
                .unwrap_or(0)
                .min(catalog.observed_at)
        {
            return Err(Error::integrity("WHATWG view validation time mismatch."));
        }
        for (standard, id) in &view.snapshots {
            let validated_at = view
                .validations
                .get(standard)
                .copied()
                .ok_or_else(|| Error::integrity("WHATWG standard validation missing."))?;
            if !catalog.standards.iter().any(|s| s.id == *standard) {
                return Err(Error::integrity(
                    "WHATWG view standard is outside its catalog.",
                ));
            }
            let data: Json<Value> = sqlx::query_scalar(
                "SELECT data FROM devres_whatwg_evidence WHERE kind='snapshots' AND key=$1",
            )
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| storage_error())?
            .ok_or_else(|| Error::integrity("WHATWG view snapshot missing."))?;
            let snapshot: Snapshot = serde_json::from_value(data.0)
                .map_err(|_| Error::integrity("Invalid WHATWG snapshot."))?;
            if snapshot.standard != *standard
                || snapshot.index.is_null()
                || snapshot.coverage["accounted"] != true
                || snapshot.coverage["synthetic"] == true
                || snapshot.coverage["usable"] != true
            {
                return Err(Error::integrity("Invalid WHATWG publication evidence."));
            }
            if matches!(
                snapshot.representation.as_str(),
                "html" | "pdf" | "text" | "json" | "raw"
            ) {
                let publication = snapshot.coverage["publication"]
                    .as_str()
                    .ok_or_else(|| Error::integrity("WHATWG publication evidence missing."))?;
                let evidence: Json<Value> = sqlx::query_scalar(
                    "SELECT data FROM devres_whatwg_evidence WHERE kind='publications' AND key=$1",
                )
                .bind(publication)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|_| storage_error())?
                .ok_or_else(|| Error::integrity("WHATWG publication evidence missing."))?;
                if evidence.0["standard"].as_str() != Some(standard)
                    || evidence.0["status"] != 200
                    || evidence.0["observed_at"].as_i64() != Some(validated_at)
                    || evidence.0["url"]["url"].as_str() != Some(&snapshot.source_url)
                    || evidence.0["artifact"]["body_hash"].as_str() != Some(&snapshot.tree)
                    || snapshot.revision != publication
                    || snapshot.repository != snapshot.source_url
                {
                    return Err(Error::integrity(
                        "WHATWG default requires matching online publication evidence.",
                    ));
                }
            } else {
                let evidence:Option<Json<Value>>=sqlx::query_scalar("SELECT data FROM devres_whatwg_evidence WHERE kind='observations' AND data->'repo'->>'owner'=$1 AND data->'repo'->>'name'=$2 AND data->>'main_revision'=$3 AND (data->>'observed_at')::bigint >= $4 ORDER BY sequence DESC LIMIT 1").bind(snapshot.repository.split_once('/').map(|p|p.0).unwrap_or("")).bind(snapshot.repository.split_once('/').map(|p|p.1).unwrap_or("")).bind(&snapshot.revision).bind(validated_at).fetch_optional(&mut *tx).await.map_err(|_|storage_error())?;
                if evidence.is_none() {
                    return Err(Error::integrity(
                        "WHATWG default requires matching current Git evidence.",
                    ));
                }
            }
        }
        let data =
            serde_json::to_value(view).map_err(|_| Error::integrity("Invalid WHATWG view."))?;
        bounded(&data)?;
        sqlx::query("INSERT INTO devres_whatwg_evidence(kind,key,data) VALUES('views',$1,$2) ON CONFLICT DO NOTHING").bind(&view.id).bind(Json(&data)).execute(&mut *tx).await.map_err(|_|storage_error())?;
        let identical: bool = sqlx::query_scalar(
            "SELECT data=$2::jsonb FROM devres_whatwg_evidence WHERE kind='views' AND key=$1",
        )
        .bind(&view.id)
        .bind(Json(&data))
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| storage_error())?;
        if !identical {
            return Err(Error::integrity("WHATWG view identity collision."));
        }
        sqlx::query("INSERT INTO devres_whatwg_state(key,data) VALUES('default',$1) ON CONFLICT(key) DO UPDATE SET data=EXCLUDED.data").bind(Json(&data)).execute(&mut *tx).await.map_err(|_|storage_error())?;
        tx.commit().await.map_err(|_| storage_error())
    }
}

pub(super) const SCHEMA_V6: &str = r#"
CREATE TABLE devres_whatwg_evidence (
 sequence bigserial PRIMARY KEY,
 kind text NOT NULL,
 key text NOT NULL,
 data jsonb NOT NULL,
 UNIQUE(kind,key)
);
CREATE INDEX devres_whatwg_evidence_page ON devres_whatwg_evidence(kind,sequence);
CREATE TABLE devres_whatwg_state(key text PRIMARY KEY,data jsonb NOT NULL);
CREATE TABLE devres_whatwg_statistics(kind text PRIMARY KEY,rows bigint NOT NULL,projection_gaps bigint NOT NULL,index_gaps bigint NOT NULL);
"#;
