//! PostgreSQL npm evidence: immutable rows, bounded reads, atomic owner-fenced defaults.
use super::{PgBlobStore, hash, payload_integrity, sequence_integrity, storage_error, valid_hash};
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
        data: payload_integrity::row("devres_npm_evidence", &value)?,
    })
}
#[async_trait]
impl NpmStore for PgBlobStore {
    async fn npm_migration_rows(&self, kind: &str, after: i64, limit: usize) -> Result<Vec<Row>> {
        checked(kind, "migration-page")?;
        if after < 0 || !(1..=1000).contains(&limit) {
            return Err(Error::invalid(
                "Invalid retained evidence verification page.",
            ));
        }
        self.fence().await?;
        let bytes:i64=sqlx::query_scalar("SELECT COALESCE(sum(n),0)::bigint FROM(SELECT octet_length(data::text) AS n FROM devres_npm_evidence WHERE kind=$1 AND sequence>$2 ORDER BY sequence LIMIT $3) page").bind(kind).bind(after).bind(limit as i64).fetch_one(&self.pool).await.map_err(|_|storage_error())?;
        if bytes > 64 * 1024 * 1024 {
            return Err(Error::capacity(
                "Retained evidence verification page exceeds memory budget.",
            ));
        }
        sqlx::query("SELECT sequence,kind,key,data,data_integrity,sequence_integrity FROM devres_npm_evidence WHERE kind=$1 AND sequence>$2 ORDER BY sequence LIMIT $3").bind(kind).bind(after).bind(limit as i64).fetch_all(&self.pool).await.map_err(|_|storage_error())?.into_iter().map(row).collect()
    }
    async fn npm_migration_kinds(&self) -> Result<Vec<String>> {
        self.fence().await?;
        let kinds: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT kind FROM devres_npm_evidence ORDER BY kind LIMIT 257",
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
    async fn npm_migration_state_keys(&self, after: &str, limit: usize) -> Result<Vec<String>> {
        if !(1..=1000).contains(&limit) {
            return Err(Error::invalid("Invalid migration state page."));
        }
        self.fence().await?;
        sqlx::query_scalar("SELECT key FROM devres_npm_state WHERE key>$1 ORDER BY key LIMIT $2")
            .bind(after)
            .bind(limit as i64)
            .fetch_all(&self.pool)
            .await
            .map_err(|_| storage_error())
    }
    async fn npm_get(&self, kind: &str, key: &str) -> Result<Option<Row>> {
        checked(kind, key)?;
        self.fence().await?;
        let resolved = payload_integrity::natural_key(&self.pool, "npm", kind, key).await?;
        sqlx::query("SELECT sequence,kind,key,data,data_integrity,sequence_integrity FROM devres_npm_evidence WHERE kind=$1 AND key=$2")
            .bind(kind)
            .bind(&resolved)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| storage_error())?
            .map(|found|{let mut found=row(found)?;if resolved!=key {found.key=key.to_owned();}Ok(found)})
            .transpose()
    }
    async fn npm_put(&self, kind: &str, key: &str, data: &Value) -> Result<i64> {
        checked(kind, key)?;
        bounded(data)?;
        let resolved = payload_integrity::natural_key(&self.pool, "npm", kind, key).await?;
        let key = resolved.as_str();
        let mut owner = self.owner.lock().await;
        owner.ping().await.map_err(|_| storage_error())?;
        if let Some(sequence) =
            sequence_integrity::admit(&mut owner, "devres_npm_evidence", kind, key, data).await?
        {
            return Ok(sequence);
        }
        let allocated = sequence_integrity::reserve_one(&mut owner, "devres_npm_evidence").await?;
        let sequence:Option<i64>=sqlx::query_scalar("INSERT INTO devres_npm_evidence(kind,key,data,data_integrity,sequence,sequence_integrity) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING RETURNING sequence")
            .bind(kind).bind(key).bind(Json(data)).bind(payload_integrity::digest("devres_npm_evidence",kind,key,data)?).bind(allocated).bind(sequence_integrity::digest("devres_npm_evidence",kind,key,allocated)?).fetch_optional(&mut *owner).await.map_err(|_|storage_error())?;
        if let Some(sequence) = sequence {
            return Ok(sequence);
        }
        let retained=sqlx::query("SELECT sequence,kind,key,data,data_integrity,sequence_integrity,data=$3::jsonb AS identical FROM devres_npm_evidence WHERE kind=$1 AND key=$2")
            .bind(kind).bind(key).bind(Json(data)).fetch_one(&mut *owner).await.map_err(|_|storage_error())?;
        payload_integrity::row("devres_npm_evidence", &retained)?;
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
        if let Some(cutoff) = self.migration_cutoff("npm").await? {
            return Ok(cutoff);
        }
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
        let excluded = self.visibility_aliases("npm", kind, cutoff).await?;
        let bytes:i64=sqlx::query_scalar("SELECT COALESCE(sum(n),0)::bigint FROM (SELECT octet_length(data::text) AS n FROM devres_npm_evidence WHERE kind=$1 AND sequence>$2 AND ($3::bigint IS NULL OR sequence<=$3) AND NOT(key=ANY($6::text[])) AND ($5::jsonb IS NULL OR data @> $5) ORDER BY sequence LIMIT $4) page")
            .bind(kind).bind(after).bind(cutoff).bind(limit as i64).bind(filter.map(Json)).bind(excluded.as_ref()).fetch_one(&self.pool).await.map_err(|_|storage_error())?;
        if bytes > 64 * 1024 * 1024 {
            return Err(Error::capacity("npm evidence page exceeds 64 MiB."));
        }
        sqlx::query("SELECT sequence,kind,key,data,data_integrity,sequence_integrity FROM devres_npm_evidence WHERE kind=$1 AND sequence>$2 AND ($3::bigint IS NULL OR sequence<=$3) AND NOT(key=ANY($6::text[])) AND ($5::jsonb IS NULL OR data @> $5) ORDER BY sequence LIMIT $4")
            .bind(kind).bind(after).bind(cutoff).bind(limit as i64).bind(filter.map(Json)).bind(excluded.as_ref())
            .fetch_all(&self.pool).await.map_err(|_|storage_error())?.into_iter().map(row).collect()
    }
    async fn npm_state(&self, key: &str) -> Result<Option<Value>> {
        checked("state", key)?;
        self.fence().await?;
        Ok(
            payload_integrity::load(&self.pool, "devres_npm_state", "", key)
                .await?
                .map(|value| value.0),
        )
    }
    async fn npm_set_state(&self, key: &str, data: &Value) -> Result<()> {
        checked("state", key)?;
        bounded(data)?;
        let mut owner = self.owner.lock().await;
        owner.ping().await.map_err(|_| storage_error())?;
        sqlx::query("INSERT INTO devres_npm_state(key,data,data_integrity) VALUES($1,$2,$3) ON CONFLICT(key) DO UPDATE SET data=EXCLUDED.data,data_integrity=EXCLUDED.data_integrity")
            .bind(key).bind(Json(data)).bind(payload_integrity::digest("devres_npm_state","",key,data)?).execute(&mut *owner).await.map_err(|_|storage_error())?;
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
        put_index_markers(&mut tx, ids).await?;
        let matched:i64=sqlx::query_scalar("SELECT count(*)::bigint FROM devres_npm_evidence WHERE kind='indexed' AND key=ANY($1::text[]) AND data=jsonb_build_object('id',key)")
            .bind(ids).fetch_one(&mut *tx).await.map_err(|_|storage_error())?;
        if matched != ids.len() as i64 {
            return Err(Error::integrity("npm index marker identity collision."));
        }
        sqlx::query("INSERT INTO devres_npm_state(key,data,data_integrity) VALUES('index',$1,$2) ON CONFLICT(key) DO UPDATE SET data=EXCLUDED.data,data_integrity=EXCLUDED.data_integrity")
            .bind(Json(index)).bind(payload_integrity::digest("devres_npm_state","","index",index)?).execute(&mut *tx).await.map_err(|_|storage_error())?;
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
        let mut after = 0;
        loop {
            let rows = verified_members(
                &mut tx,
                "rebuild-index-members",
                after,
                &json!({"build":build}),
            )
            .await?;
            if rows.is_empty() {
                break;
            }
            let mut ids = Vec::with_capacity(rows.len());
            for row in rows {
                after = row.sequence;
                ids.push(
                    row.data["record"]
                        .as_str()
                        .filter(|id| valid_hash(id))
                        .ok_or_else(|| Error::integrity("Invalid rebuilt index membership."))?
                        .to_owned(),
                );
            }
            put_index_markers(&mut tx, &ids).await?;
        }
        sqlx::query("INSERT INTO devres_npm_state(key,data,data_integrity) VALUES('index',$1,$2) ON CONFLICT(key) DO UPDATE SET data=EXCLUDED.data,data_integrity=EXCLUDED.data_integrity")
            .bind(Json(index)).bind(payload_integrity::digest("devres_npm_state","","index",index)?).execute(&mut *tx).await.map_err(|_|storage_error())?;
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
                let exists=sqlx::query("SELECT sequence,kind,key,data,data_integrity,sequence_integrity FROM devres_npm_evidence WHERE kind='package-snapshots' AND key=$1 AND data->>'name'=$2 AND data->'accounted'='true'::jsonb")
                    .bind(package.as_str().ok_or_else(||Error::integrity("Invalid npm package snapshot."))?).bind(name)
                    .fetch_optional(&mut *tx).await.map_err(|_|storage_error())?.map(|row|payload_integrity::row("devres_npm_evidence",&row)).transpose()?;
                if exists.is_none() {
                    return Err(Error::integrity(
                        "npm package publication evidence missing.",
                    ));
                }
            }
        } else {
            let ready =
                payload_integrity::load(&mut *tx, "devres_npm_state", "", &format!("ready:{id}"))
                    .await?;
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
            let mut after = 0;
            let mut verified_count = 0_i64;
            loop {
                let members = verified_members(
                    &mut tx,
                    "advisory-members",
                    after,
                    &json!({"snapshot":snapshot["membership"]}),
                )
                .await?;
                if members.is_empty() {
                    break;
                }
                verified_count += members.len() as i64;
                after = members
                    .last()
                    .ok_or_else(|| Error::integrity("Advisory membership page missing."))?
                    .sequence;
            }
            if verified_count != count {
                return Err(Error::integrity(
                    "Advisory membership integrity accounting mismatch.",
                ));
            }
            if snapshot["records"].as_i64() != Some(count) {
                return Err(Error::integrity(
                    "npm advisory publication membership count differs.",
                ));
            }
        }
        sequence_integrity::admit(&mut tx, "devres_npm_evidence", "snapshots", id, snapshot)
            .await?;
        let allocated = sequence_integrity::reserve_one(&mut tx, "devres_npm_evidence").await?;
        sqlx::query("INSERT INTO devres_npm_evidence(kind,key,data,data_integrity,sequence,sequence_integrity) VALUES('snapshots',$1,$2,$3,$4,$5) ON CONFLICT DO NOTHING")
            .bind(id).bind(Json(snapshot)).bind(payload_integrity::digest("devres_npm_evidence","snapshots",id,snapshot)?).bind(allocated).bind(sequence_integrity::digest("devres_npm_evidence","snapshots",id,allocated)?).execute(&mut *tx).await.map_err(|_|storage_error())?;
        sequence_integrity::verify_keys(
            &mut tx,
            "devres_npm_evidence",
            &["snapshots".to_owned()],
            &[id.to_owned()],
        )
        .await?;
        let same: bool = sqlx::query_scalar(
            "SELECT data=$2::jsonb FROM devres_npm_evidence WHERE kind='snapshots' AND key=$1",
        )
        .bind(id)
        .bind(Json(snapshot))
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| storage_error())?;
        payload_integrity::load(&mut *tx, "devres_npm_evidence", "snapshots", id)
            .await?
            .ok_or_else(|| Error::integrity("Retained npm snapshot missing."))?;
        if !same {
            return Err(Error::integrity("npm snapshot identity collision."));
        }
        sqlx::query("INSERT INTO devres_npm_state(key,data,data_integrity) VALUES($1,$2,$3) ON CONFLICT(key) DO UPDATE SET data=EXCLUDED.data,data_integrity=EXCLUDED.data_integrity")
            .bind(format!("default-{lane}")).bind(Json(snapshot)).bind(payload_integrity::digest("devres_npm_state","",&format!("default-{lane}"),snapshot)?).execute(&mut *tx).await.map_err(|_|storage_error())?;
        tx.commit().await.map_err(|_| storage_error())
    }
    async fn npm_statistics(&self) -> Result<Value> {
        self.fence().await?;
        let mut counts = serde_json::Map::new();
        for kind in self.npm_migration_kinds().await? {
            let mut count = 0_u64;
            let mut after = 0;
            loop {
                let rows = self.npm_rows(&kind, after, 1000, None, None).await?;
                if rows.is_empty() {
                    break;
                }
                count = count
                    .checked_add(rows.len() as u64)
                    .ok_or_else(|| Error::capacity("npm statistics count overflow."))?;
                after = rows
                    .last()
                    .ok_or_else(|| Error::integrity("npm statistics page missing."))?
                    .sequence;
            }
            if count > 0 {
                counts.insert(kind, json!(count));
            }
        }
        Ok(Value::Object(counts))
    }
}
async fn put_index_markers(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ids: &[String],
) -> Result<()> {
    if ids.len() > 1000 {
        return Err(Error::capacity("Index marker batch exceeds bound."));
    }
    let values: Vec<_> = ids.iter().map(|id| json!({"id":id})).collect();
    let digests = ids
        .iter()
        .zip(&values)
        .map(|(id, data)| payload_integrity::digest("devres_npm_evidence", "indexed", id, data))
        .collect::<Result<Vec<_>>>()?;
    let values: Vec<_> = values.iter().map(Json).collect();
    let sequences = sequence_integrity::reserve(tx, "devres_npm_evidence", ids.len()).await?;
    let sequence_digests = ids
        .iter()
        .zip(&sequences)
        .map(|(id, sequence)| {
            sequence_integrity::digest("devres_npm_evidence", "indexed", id, *sequence)
        })
        .collect::<Result<Vec<_>>>()?;
    sqlx::query("INSERT INTO devres_npm_evidence(kind,key,data,data_integrity,sequence,sequence_integrity) SELECT 'indexed',key,data,digest,sequence,sequence_integrity FROM UNNEST($1::text[],$2::jsonb[],$3::text[],$4::bigint[],$5::text[]) AS inserted(key,data,digest,sequence,sequence_integrity) ON CONFLICT DO NOTHING")
        .bind(ids).bind(&values).bind(&digests).bind(&sequences).bind(&sequence_digests).execute(&mut **tx).await.map_err(|_|storage_error())?;
    let matched:i64=sqlx::query_scalar("SELECT count(*)::bigint FROM UNNEST($1::text[],$2::jsonb[],$3::text[]) AS expected(key,data,data_integrity) JOIN devres_npm_evidence retained ON retained.kind='indexed' AND retained.key=expected.key AND retained.data=expected.data AND retained.data_integrity=expected.data_integrity")
        .bind(ids).bind(&values).bind(&digests).fetch_one(&mut **tx).await.map_err(|_|storage_error())?;
    sequence_integrity::verify_keys(
        tx,
        "devres_npm_evidence",
        &vec!["indexed".to_owned(); ids.len()],
        ids,
    )
    .await?;
    if matched != ids.len() as i64 {
        return Err(Error::integrity(
            "Index marker integrity or identity collision.",
        ));
    }
    Ok(())
}

async fn verified_members(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    kind: &str,
    after: i64,
    filter: &Value,
) -> Result<Vec<Row>> {
    let bytes:i64=sqlx::query_scalar("SELECT COALESCE(sum(n),0)::bigint FROM(SELECT octet_length(data::text) AS n FROM devres_npm_evidence WHERE kind=$1 AND sequence>$2 AND data @> $3::jsonb ORDER BY sequence LIMIT 1000) page")
        .bind(kind).bind(after).bind(Json(filter)).fetch_one(&mut **tx).await.map_err(|_|storage_error())?;
    if bytes > 64 * 1024 * 1024 {
        return Err(Error::capacity(
            "Membership integrity page exceeds memory budget.",
        ));
    }
    sqlx::query("SELECT sequence,kind,key,data,data_integrity,sequence_integrity FROM devres_npm_evidence WHERE kind=$1 AND sequence>$2 AND data @> $3::jsonb ORDER BY sequence LIMIT 1000")
        .bind(kind).bind(after).bind(Json(filter)).fetch_all(&mut **tx).await.map_err(|_|storage_error())?.into_iter().map(row).collect()
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
