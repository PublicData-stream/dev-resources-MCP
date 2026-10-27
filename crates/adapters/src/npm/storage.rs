//! PostgreSQL npm evidence: immutable rows, bounded reads, atomic owner-fenced defaults.
use super::{PgBlobStore, hash, storage_error, valid_hash};
use async_trait::async_trait;
use devres_application::npm::{MAX_ROW_BYTES, NpmStore, Row};
use devres_domain::{Error, Result};
use serde_json::{Value, json};
use sqlx::{Connection, Row as _, types::Json};

fn checked(kind: &str, key: &str) -> Result<()> {
    if kind.is_empty()
        || kind.len() > 64
        || !kind.bytes().all(|v| v.is_ascii_lowercase() || v == b'-')
        || key.is_empty()
        || key.len() > 4096
        || key.chars().any(char::is_control)
    {
        return Err(Error::invalid("Invalid npm evidence identity."));
    }
    Ok(())
}
fn bounded(value: &Value) -> Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|_| Error::integrity("Invalid npm evidence."))?;
    if bytes.len() > MAX_ROW_BYTES {
        return Err(Error::capacity("npm evidence row exceeds 8 MiB."));
    }
    Ok(())
}
fn row(value: sqlx::postgres::PgRow) -> Result<Row> {
    Ok(Row {
        sequence: value.try_get("sequence").map_err(|_| storage_error())?,
        key: value.try_get("key").map_err(|_| storage_error())?,
        data: value
            .try_get::<Json<Value>, _>("data")
            .map_err(|_| storage_error())?
            .0,
    })
}
#[async_trait]
impl NpmStore for PgBlobStore {
    async fn npm_get(&self, kind: &str, key: &str) -> Result<Option<Row>> {
        checked(kind, key)?;
        self.fence().await?;
        sqlx::query("SELECT sequence,key,data FROM devres_npm_evidence WHERE kind=$1 AND key=$2")
            .bind(kind)
            .bind(key)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| storage_error())?
            .map(row)
            .transpose()
    }
    async fn npm_put(&self, kind: &str, key: &str, data: &Value) -> Result<i64> {
        checked(kind, key)?;
        bounded(data)?;
        let mut owner = self.owner.lock().await;
        owner.ping().await.map_err(|_| storage_error())?;
        let sequence:Option<i64>=sqlx::query_scalar("INSERT INTO devres_npm_evidence(kind,key,data) VALUES($1,$2,$3) ON CONFLICT DO NOTHING RETURNING sequence")
            .bind(kind).bind(key).bind(Json(data)).fetch_optional(&mut *owner).await.map_err(|_|storage_error())?;
        if let Some(sequence) = sequence {
            return Ok(sequence);
        }
        let retained=sqlx::query("SELECT sequence,data=$3::jsonb AS identical FROM devres_npm_evidence WHERE kind=$1 AND key=$2")
            .bind(kind).bind(key).bind(Json(data)).fetch_one(&mut *owner).await.map_err(|_|storage_error())?;
        if !retained
            .try_get::<bool, _>("identical")
            .map_err(|_| storage_error())?
        {
            return Err(Error::integrity(
                "npm immutable evidence identity collision.",
            ));
        }
        retained.try_get("sequence").map_err(|_| storage_error())
    }
    async fn npm_cutoff(&self) -> Result<i64> {
        self.fence().await?;
        sqlx::query_scalar("SELECT COALESCE(max(sequence),0) FROM devres_npm_evidence")
            .fetch_one(&self.pool)
            .await
            .map_err(|_| storage_error())
    }
    async fn npm_rows(
        &self,
        kind: &str,
        after: i64,
        limit: usize,
        cutoff: Option<i64>,
        filter: Option<&Value>,
    ) -> Result<Vec<Row>> {
        checked(kind, "page")?;
        if after < 0
            || !(1..=1000).contains(&limit)
            || cutoff.is_some_and(|v| v < 0)
            || filter.is_some_and(|v| !v.is_object())
        {
            return Err(Error::invalid("Invalid npm evidence page."));
        }
        if let Some(filter) = filter {
            bounded(filter)?;
        }
        self.fence().await?;
        let bytes:i64=sqlx::query_scalar("SELECT COALESCE(sum(n),0)::bigint FROM (SELECT octet_length(data::text) AS n FROM devres_npm_evidence WHERE kind=$1 AND sequence>$2 AND ($3::bigint IS NULL OR sequence<=$3) AND ($5::jsonb IS NULL OR data @> $5) ORDER BY sequence LIMIT $4) page")
            .bind(kind).bind(after).bind(cutoff).bind(limit as i64).bind(filter.map(Json)).fetch_one(&self.pool).await.map_err(|_|storage_error())?;
        if bytes > 64 * 1024 * 1024 {
            return Err(Error::capacity("npm evidence page exceeds 64 MiB."));
        }
        sqlx::query("SELECT sequence,key,data FROM devres_npm_evidence WHERE kind=$1 AND sequence>$2 AND ($3::bigint IS NULL OR sequence<=$3) AND ($5::jsonb IS NULL OR data @> $5) ORDER BY sequence LIMIT $4")
            .bind(kind).bind(after).bind(cutoff).bind(limit as i64).bind(filter.map(Json))
            .fetch_all(&self.pool).await.map_err(|_|storage_error())?.into_iter().map(row).collect()
    }
    async fn npm_state(&self, key: &str) -> Result<Option<Value>> {
        checked("state", key)?;
        self.fence().await?;
        Ok(
            sqlx::query_scalar::<_, Json<Value>>("SELECT data FROM devres_npm_state WHERE key=$1")
                .bind(key)
                .fetch_optional(&self.pool)
                .await
                .map_err(|_| storage_error())?
                .map(|v| v.0),
        )
    }
    async fn npm_set_state(&self, key: &str, data: &Value) -> Result<()> {
        checked("state", key)?;
        bounded(data)?;
        let mut owner = self.owner.lock().await;
        owner.ping().await.map_err(|_| storage_error())?;
        sqlx::query("INSERT INTO devres_npm_state(key,data) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET data=EXCLUDED.data")
            .bind(key).bind(Json(data)).execute(&mut *owner).await.map_err(|_|storage_error())?;
        Ok(())
    }
    async fn npm_commit_index(&self, index: &Value, ids: &[String]) -> Result<()> {
        bounded(index)?;
        if !index.is_object()
            || ids.len() > 512
            || ids.iter().any(|id| !valid_hash(id))
            || ids.iter().collect::<std::collections::BTreeSet<_>>().len() != ids.len()
        {
            return Err(Error::invalid("Invalid bounded npm index publication."));
        }
        let mut owner = self.owner.lock().await;
        let mut tx = owner.begin().await.map_err(|_| storage_error())?;
        sqlx::query("INSERT INTO devres_npm_evidence(kind,key,data) SELECT 'indexed',id,jsonb_build_object('id',id) FROM UNNEST($1::text[]) AS id ON CONFLICT DO NOTHING")
            .bind(ids).execute(&mut *tx).await.map_err(|_|storage_error())?;
        let matched:i64=sqlx::query_scalar("SELECT count(*)::bigint FROM devres_npm_evidence WHERE kind='indexed' AND key=ANY($1::text[]) AND data=jsonb_build_object('id',key)")
            .bind(ids).fetch_one(&mut *tx).await.map_err(|_|storage_error())?;
        if matched != ids.len() as i64 {
            return Err(Error::integrity("npm index marker identity collision."));
        }
        sqlx::query("INSERT INTO devres_npm_state(key,data) VALUES('index',$1) ON CONFLICT(key) DO UPDATE SET data=EXCLUDED.data")
            .bind(Json(index)).execute(&mut *tx).await.map_err(|_|storage_error())?;
        tx.commit().await.map_err(|_| storage_error())
    }
    async fn npm_commit_rebuilt_index(&self, index: &Value, build: &str) -> Result<()> {
        bounded(index)?;
        if !index.is_object() || !valid_hash(build) {
            return Err(Error::invalid("Invalid npm index rebuild identity."));
        }
        let mut owner = self.owner.lock().await;
        let mut tx = owner.begin().await.map_err(|_| storage_error())?;
        let count:i64=sqlx::query_scalar("SELECT count(*)::bigint FROM devres_npm_evidence WHERE kind='rebuild-index-members' AND data->>'build'=$1")
            .bind(build).fetch_one(&mut *tx).await.map_err(|_|storage_error())?;
        if count > 1_000_000 {
            return Err(Error::capacity(
                "npm rebuilt index membership exceeds one million documents.",
            ));
        }
        let missing:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM devres_npm_evidence AS old WHERE old.kind='indexed' AND NOT EXISTS(SELECT 1 FROM devres_npm_evidence AS member WHERE member.kind='rebuild-index-members' AND member.data->>'build'=$1 AND member.data->>'record'=old.key))")
            .bind(build).fetch_one(&mut *tx).await.map_err(|_|storage_error())?;
        if missing {
            return Err(Error::integrity(
                "npm rebuild omits an already indexed document.",
            ));
        }
        sqlx::query("INSERT INTO devres_npm_evidence(kind,key,data) SELECT 'indexed',data->>'record',jsonb_build_object('id',data->>'record') FROM devres_npm_evidence WHERE kind='rebuild-index-members' AND data->>'build'=$1 ON CONFLICT DO NOTHING")
            .bind(build).execute(&mut *tx).await.map_err(|_|storage_error())?;
        sqlx::query("INSERT INTO devres_npm_state(key,data) VALUES('index',$1) ON CONFLICT(key) DO UPDATE SET data=EXCLUDED.data")
            .bind(Json(index)).execute(&mut *tx).await.map_err(|_|storage_error())?;
        tx.commit().await.map_err(|_| storage_error())
    }
    async fn npm_publish(&self, lane: &str, snapshot: &Value) -> Result<()> {
        if !matches!(lane, "research" | "advisories") {
            return Err(Error::invalid("Invalid npm publication lane."));
        }
        bounded(snapshot)?;
        let id = snapshot["id"]
            .as_str()
            .filter(|v| valid_hash(v))
            .ok_or_else(|| Error::integrity("Invalid npm snapshot identity."))?;
        let mut identity = snapshot.clone();
        identity
            .as_object_mut()
            .ok_or_else(|| Error::integrity("Invalid npm snapshot."))?
            .remove("id");
        if hash(&serde_json::to_vec(&identity).map_err(|_| storage_error())?) != id
            || snapshot["lane"] != lane
            || snapshot["accounted"] != true
            || snapshot["validated_at"].as_i64().is_none_or(|v| v <= 0)
        {
            return Err(Error::integrity("Invalid npm publication evidence."));
        }
        let mut owner = self.owner.lock().await;
        let mut tx = owner.begin().await.map_err(|_| storage_error())?;
        if lane == "research" {
            let packages = snapshot["packages"]
                .as_object()
                .filter(|v| v.len() <= 10_000)
                .ok_or_else(|| Error::integrity("Invalid npm publication catalog."))?;
            for (name, package) in packages {
                let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM devres_npm_evidence WHERE kind='package-snapshots' AND key=$1 AND data->>'name'=$2 AND data->'accounted'='true'::jsonb)")
                    .bind(package.as_str().ok_or_else(||Error::integrity("Invalid npm package snapshot."))?).bind(name)
                    .fetch_one(&mut *tx).await.map_err(|_|storage_error())?;
                if !exists {
                    return Err(Error::integrity(
                        "npm package publication evidence missing.",
                    ));
                }
            }
        } else {
            let ready: Option<Json<Value>> =
                sqlx::query_scalar("SELECT data FROM devres_npm_state WHERE key=$1")
                    .bind(format!("ready:{id}"))
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(|_| storage_error())?;
            if ready.is_none_or(|v| {
                v.0 != json!({"id":id,"records":snapshot["records"],"accounted":true})
            }) {
                return Err(Error::integrity(
                    "npm advisory publication is not fully accounted.",
                ));
            }
            let count:i64=sqlx::query_scalar("SELECT count(*)::bigint FROM devres_npm_evidence WHERE kind='advisory-members' AND data->>'snapshot'=$1")
                .bind(snapshot["membership"].as_str().ok_or_else(||Error::integrity("npm advisory membership missing."))?)
                .fetch_one(&mut *tx).await.map_err(|_|storage_error())?;
            if snapshot["records"].as_i64() != Some(count) {
                return Err(Error::integrity(
                    "npm advisory publication membership count differs.",
                ));
            }
        }
        sqlx::query("INSERT INTO devres_npm_evidence(kind,key,data) VALUES('snapshots',$1,$2) ON CONFLICT DO NOTHING")
            .bind(id).bind(Json(snapshot)).execute(&mut *tx).await.map_err(|_|storage_error())?;
        let same: bool = sqlx::query_scalar(
            "SELECT data=$2::jsonb FROM devres_npm_evidence WHERE kind='snapshots' AND key=$1",
        )
        .bind(id)
        .bind(Json(snapshot))
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| storage_error())?;
        if !same {
            return Err(Error::integrity("npm snapshot identity collision."));
        }
        sqlx::query("INSERT INTO devres_npm_state(key,data) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET data=EXCLUDED.data")
            .bind(format!("default-{lane}")).bind(Json(snapshot)).execute(&mut *tx).await.map_err(|_|storage_error())?;
        tx.commit().await.map_err(|_| storage_error())
    }
    async fn npm_statistics(&self) -> Result<Value> {
        self.fence().await?;
        let rows =
            sqlx::query("SELECT kind,count(*)::bigint AS n FROM devres_npm_evidence GROUP BY kind")
                .fetch_all(&self.pool)
                .await
                .map_err(|_| storage_error())?;
        let mut counts = serde_json::Map::new();
        for row in rows {
            counts.insert(
                row.try_get("kind").map_err(|_| storage_error())?,
                json!(row.try_get::<i64, _>("n").map_err(|_| storage_error())?),
            );
        }
        Ok(Value::Object(counts))
    }
}
pub(super) const SCHEMA_V9: &str = r#"
CREATE TABLE devres_npm_evidence(sequence bigserial PRIMARY KEY,kind text NOT NULL,key text NOT NULL,data jsonb NOT NULL,UNIQUE(kind,key));
CREATE INDEX devres_npm_evidence_page ON devres_npm_evidence(kind,sequence);
CREATE INDEX devres_npm_evidence_snapshot ON devres_npm_evidence(kind,(data->>'snapshot'),sequence);
CREATE INDEX devres_npm_evidence_name ON devres_npm_evidence(kind,(data->>'name'),sequence);
CREATE INDEX devres_npm_evidence_filter ON devres_npm_evidence USING gin(data jsonb_path_ops);
CREATE INDEX devres_npm_rebuild_members ON devres_npm_evidence((data->>'build'),(data->>'record')) WHERE kind='rebuild-index-members';
CREATE TABLE devres_npm_state(key text PRIMARY KEY,data jsonb NOT NULL);
"#;
