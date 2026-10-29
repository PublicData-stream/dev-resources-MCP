//! Owner-fenced, append-only W3C evidence and atomic default publication.
use super::{PgBlobStore, hash, payload_integrity, sequence_integrity, storage_error, valid_hash};
use async_trait::async_trait;
use devres_application::w3c::{Row, Snapshot, View, W3cStore, Write, validate_w3c_writes};
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
        return Err(Error::invalid("Invalid W3C evidence key."));
    }
    Ok(())
}
fn bounded(data: &Value) -> Result<()> {
    let bytes = serde_json::to_vec(data).map_err(|_| Error::integrity("Invalid W3C evidence."))?;
    if bytes.len() > 16 * 1024 * 1024 {
        return Err(Error::capacity("W3C evidence row exceeds its bound."));
    }
    Ok(())
}
fn row(row: sqlx::postgres::PgRow) -> Result<Row> {
    Ok(Row {
        sequence: row.try_get("sequence").map_err(|_| storage_error())?,
        key: row.try_get("key").map_err(|_| storage_error())?,
        data: payload_integrity::row("devres_w3c_evidence", &row)?,
    })
}
#[async_trait]
impl W3cStore for PgBlobStore {
    async fn w3c_existing(
        &self,
        kind: &str,
        keys: &[String],
    ) -> Result<std::collections::BTreeSet<String>> {
        if keys.len() > 1000 {
            return Err(Error::capacity("W3C existence batch exceeds its bound."));
        }
        for key in keys {
            checked(kind, key)?;
        }
        Ok(self
            .w3c_get_many(kind, keys)
            .await?
            .into_iter()
            .map(|row| row.key)
            .collect())
    }
    async fn w3c_statistics(&self) -> Result<Value> {
        self.fence().await?;
        let data:Json<Value>=sqlx::query_scalar("SELECT jsonb_build_object('snapshots',COALESCE(sum(rows) FILTER(WHERE kind='snapshots'),0),'publications',COALESCE(sum(rows) FILTER(WHERE kind='publications'),0),'projection_gaps',COALESCE(sum(projection_gaps),0),'index_gaps',COALESCE(sum(index_gaps),0)) FROM devres_w3c_statistics").fetch_one(&self.pool).await.map_err(|_|storage_error())?;
        Ok(data.0)
    }
    async fn w3c_cutoff(&self) -> Result<i64> {
        self.fence().await?;
        if let Some(cutoff) = self.migration_cutoff("w3c").await? {
            return Ok(cutoff);
        }
        sqlx::query_scalar("SELECT COALESCE(max(sequence),0) FROM devres_w3c_evidence")
            .fetch_one(&self.pool)
            .await
            .map_err(|_| storage_error())
    }
    async fn w3c_get_many(&self, kind: &str, keys: &[String]) -> Result<Vec<Row>> {
        if keys.len() > 1000 {
            return Err(Error::capacity("W3C batch read exceeds its bound."));
        }
        for key in keys {
            checked(kind, key)?;
        }
        self.fence().await?;
        let original_keys = keys;
        let mut resolved = Vec::with_capacity(keys.len());
        for key in keys {
            resolved.push(payload_integrity::natural_key(&self.pool, "w3c", kind, key).await?);
        }
        let keys = &resolved;

        let bytes:i64=sqlx::query_scalar("SELECT COALESCE(sum(octet_length(data::text)),0)::bigint FROM devres_w3c_evidence JOIN UNNEST($2::text[]) AS requested(key) ON requested.key=devres_w3c_evidence.key WHERE kind=$1").bind(kind).bind(keys).fetch_one(&self.pool).await.map_err(|_|storage_error())?;
        if bytes > 64 * 1024 * 1024 {
            return Err(Error::capacity("W3C batch read memory bound exceeded."));
        }
        sqlx::query("SELECT sequence,kind,key,data,data_integrity,sequence_integrity FROM devres_w3c_evidence WHERE kind=$1 AND key=ANY($2::text[])").bind(kind).bind(keys).fetch_all(&self.pool).await.map_err(|_|storage_error())?.into_iter().map(|found|{let found=row(found)?;let matches=resolved.iter().enumerate().filter(|(_,key)|**key==found.key).map(|(position,_)|original_keys[position].clone()).collect::<std::collections::BTreeSet<_>>();Ok(matches.into_iter().map(|key|{let mut value=found.clone();value.key=key;value}).collect::<Vec<_>>())}).collect::<Result<Vec<Vec<_>>>>().map(|rows|rows.into_iter().flatten().collect())
    }
    async fn w3c_migration_rows(&self, kind: &str, after: i64, limit: usize) -> Result<Vec<Row>> {
        checked(kind, "migration-page")?;
        if after < 0 || !(1..=1000).contains(&limit) {
            return Err(Error::invalid(
                "Invalid retained evidence verification page.",
            ));
        }
        self.fence().await?;
        let bytes:i64=sqlx::query_scalar("SELECT COALESCE(sum(n),0)::bigint FROM(SELECT octet_length(data::text) AS n FROM devres_w3c_evidence WHERE kind=$1 AND sequence>$2 ORDER BY sequence LIMIT $3) page").bind(kind).bind(after).bind(limit as i64).fetch_one(&self.pool).await.map_err(|_|storage_error())?;
        if bytes > 64 * 1024 * 1024 {
            return Err(Error::capacity(
                "Retained evidence verification page exceeds memory budget.",
            ));
        }
        sqlx::query("SELECT sequence,kind,key,data,data_integrity,sequence_integrity FROM devres_w3c_evidence WHERE kind=$1 AND sequence>$2 ORDER BY sequence LIMIT $3").bind(kind).bind(after).bind(limit as i64).fetch_all(&self.pool).await.map_err(|_|storage_error())?.into_iter().map(row).collect()
    }
    async fn w3c_migration_kinds(&self) -> Result<Vec<String>> {
        self.fence().await?;
        let kinds: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT kind FROM devres_w3c_evidence ORDER BY kind LIMIT 257",
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
    async fn w3c_migration_state_keys(&self, after: &str, limit: usize) -> Result<Vec<String>> {
        if !(1..=1000).contains(&limit) {
            return Err(Error::invalid("Invalid migration state page."));
        }
        self.fence().await?;
        sqlx::query_scalar("SELECT key FROM devres_w3c_state WHERE key>$1 ORDER BY key LIMIT $2")
            .bind(after)
            .bind(limit as i64)
            .fetch_all(&self.pool)
            .await
            .map_err(|_| storage_error())
    }
    async fn w3c_get(&self, kind: &str, key: &str) -> Result<Option<Row>> {
        checked(kind, key)?;
        self.fence().await?;
        let resolved = payload_integrity::natural_key(&self.pool, "w3c", kind, key).await?;
        sqlx::query("SELECT sequence,kind,key,data,data_integrity,sequence_integrity FROM devres_w3c_evidence WHERE kind=$1 AND key=$2")
            .bind(kind)
            .bind(&resolved)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| storage_error())?
            .map(|found|{let mut found=row(found)?;if resolved!=key {found.key=key.to_owned();}Ok(found)})
            .transpose()
    }
    async fn w3c_put(&self, kind: &str, key: &str, data: &Value) -> Result<i64> {
        checked(kind, key)?;
        bounded(data)?;
        let resolved = payload_integrity::natural_key(&self.pool, "w3c", kind, key).await?;
        let key = resolved.as_str();
        let mut owner = self.owner.lock().await;
        // This non-reconnecting connection itself holds the ownership lock. One
        // atomic statement suffices for a new immutable row; cancellation can
        // leave only a replayable, unreferenced public object.
        if let Some(sequence) =
            sequence_integrity::admit(&mut owner, "devres_w3c_evidence", kind, key, data).await?
        {
            return Ok(sequence);
        }
        let allocated = sequence_integrity::reserve_one(&mut owner, "devres_w3c_evidence").await?;
        let inserted:Option<i64>=sqlx::query_scalar("WITH inserted AS(INSERT INTO devres_w3c_evidence(kind,key,data,data_integrity,sequence,sequence_integrity) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING RETURNING sequence,kind,data),counted AS(INSERT INTO devres_w3c_statistics(kind,rows,projection_gaps,index_gaps) SELECT kind,1,CASE WHEN kind='snapshots' THEN COALESCE((data#>>'{coverage,projection_gaps}')::bigint,0) ELSE 0 END,CASE WHEN kind='snapshots' THEN COALESCE((data#>>'{coverage,index_gaps}')::bigint,0) ELSE 0 END FROM inserted ON CONFLICT(kind) DO UPDATE SET rows=devres_w3c_statistics.rows+EXCLUDED.rows,projection_gaps=devres_w3c_statistics.projection_gaps+EXCLUDED.projection_gaps,index_gaps=devres_w3c_statistics.index_gaps+EXCLUDED.index_gaps RETURNING kind) SELECT sequence FROM inserted").bind(kind).bind(key).bind(Json(data)).bind(payload_integrity::digest("devres_w3c_evidence",kind,key,data)?).bind(allocated).bind(sequence_integrity::digest("devres_w3c_evidence",kind,key,allocated)?).fetch_optional(&mut *owner).await.map_err(|_|storage_error())?;
        if let Some(sequence) = inserted {
            return Ok(sequence);
        }
        let retained =
            sqlx::query("SELECT sequence,kind,key,data,data_integrity,sequence_integrity,data=$3::jsonb AS identical FROM devres_w3c_evidence WHERE kind=$1 AND key=$2")
                .bind(kind)
                .bind(key)
                .bind(Json(data))
                .fetch_one(&mut *owner)
                .await
                .map_err(|_| storage_error())?;
        payload_integrity::row("devres_w3c_evidence", &retained)?;
        if !retained
            .try_get::<bool, _>("identical")
            .map_err(|_| storage_error())?
        {
            return Err(Error::integrity(
                "W3C immutable evidence identity collision.",
            ));
        }
        let sequence = retained.try_get("sequence").map_err(|_| storage_error())?;
        Ok(sequence)
    }
    async fn w3c_put_many(&self, rows: &[Write]) -> Result<()> {
        let mut resolved_rows = rows.to_vec();
        for row in &mut resolved_rows {
            row.key =
                payload_integrity::natural_key(&self.pool, "w3c", &row.kind, &row.key).await?;
        }
        let rows = resolved_rows.as_slice();
        validate_w3c_writes(rows)?;
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
                payload_integrity::digest("devres_w3c_evidence", &row.kind, &row.key, &row.data)
            })
            .collect::<Result<Vec<_>>>()?;
        let mut owner = self.owner.lock().await;
        // This connection itself owns the non-reconnecting session fence. All
        // rows and collision checks commit together, without changing durability.
        let mut tx = owner.begin().await.map_err(|_| storage_error())?;
        for row in rows {
            sequence_integrity::admit(
                &mut tx,
                "devres_w3c_evidence",
                &row.kind,
                &row.key,
                &row.data,
            )
            .await?;
        }
        let sequences =
            sequence_integrity::reserve(&mut tx, "devres_w3c_evidence", rows.len()).await?;
        let sequence_digests = rows
            .iter()
            .zip(&sequences)
            .map(|(row, sequence)| {
                sequence_integrity::digest("devres_w3c_evidence", &row.kind, &row.key, *sequence)
            })
            .collect::<Result<Vec<_>>>()?;
        sqlx::query("WITH inserted AS(INSERT INTO devres_w3c_evidence(kind,key,data,data_integrity,sequence,sequence_integrity) SELECT * FROM UNNEST($1::text[],$2::text[],$3::jsonb[],$4::text[],$5::bigint[],$6::text[]) ON CONFLICT DO NOTHING RETURNING kind,data) INSERT INTO devres_w3c_statistics(kind,rows,projection_gaps,index_gaps) SELECT kind,count(*)::bigint,COALESCE(sum(CASE WHEN kind='snapshots' THEN COALESCE((data#>>'{coverage,projection_gaps}')::bigint,0) ELSE 0 END),0)::bigint,COALESCE(sum(CASE WHEN kind='snapshots' THEN COALESCE((data#>>'{coverage,index_gaps}')::bigint,0) ELSE 0 END),0)::bigint FROM inserted GROUP BY kind ON CONFLICT(kind) DO UPDATE SET rows=devres_w3c_statistics.rows+EXCLUDED.rows,projection_gaps=devres_w3c_statistics.projection_gaps+EXCLUDED.projection_gaps,index_gaps=devres_w3c_statistics.index_gaps+EXCLUDED.index_gaps")
            .bind(&kinds).bind(&keys).bind(&values).bind(&digests).bind(&sequences).bind(&sequence_digests).execute(&mut *tx).await.map_err(|_|storage_error())?;
        let matched:i64=sqlx::query_scalar("SELECT count(*)::bigint FROM UNNEST($1::text[],$2::text[],$3::jsonb[],$4::text[]) AS expected(kind,key,data,data_integrity) JOIN devres_w3c_evidence AS retained ON retained.kind=expected.kind AND retained.key=expected.key AND retained.data=expected.data AND retained.data_integrity=expected.data_integrity")
            .bind(&kinds).bind(&keys).bind(&values).bind(&digests).fetch_one(&mut *tx).await.map_err(|_|storage_error())?;
        if matched != rows.len() as i64 {
            return Err(Error::integrity(
                "W3C immutable evidence identity collision.",
            ));
        }
        sequence_integrity::verify_keys(&mut tx, "devres_w3c_evidence", &kinds, &keys).await?;
        tx.commit().await.map_err(|_| storage_error())
    }
    async fn w3c_rows(
        &self,
        kind: &str,
        after: i64,
        limit: usize,
        cutoff: Option<i64>,
    ) -> Result<Vec<Row>> {
        checked(kind, "rows")?;
        if !(1..=1000).contains(&limit) || after < 0 || cutoff.is_some_and(|c| c < 0) {
            return Err(Error::invalid("Invalid W3C evidence page."));
        }
        self.fence().await?;
        let excluded = self.visibility_aliases("w3c", kind, cutoff).await?;
        let bytes:i64=sqlx::query_scalar("SELECT COALESCE(sum(n),0)::bigint FROM (SELECT octet_length(data::text) AS n FROM devres_w3c_evidence WHERE kind=$1 AND sequence>$2 AND ($3::bigint IS NULL OR sequence<=$3) AND NOT(key=ANY($5::text[])) ORDER BY sequence LIMIT $4) page").bind(kind).bind(after).bind(cutoff).bind(limit as i64).bind(excluded.as_ref()).fetch_one(&self.pool).await.map_err(|_|storage_error())?;
        if bytes > 64 * 1024 * 1024 {
            return Err(Error::capacity("W3C evidence page memory bound exceeded."));
        }
        sqlx::query("SELECT sequence,kind,key,data,data_integrity,sequence_integrity FROM devres_w3c_evidence WHERE kind=$1 AND sequence>$2 AND ($3::bigint IS NULL OR sequence<=$3) AND NOT(key=ANY($5::text[])) ORDER BY sequence LIMIT $4")
            .bind(kind).bind(after).bind(cutoff).bind(limit as i64).bind(excluded.as_ref()).fetch_all(&self.pool).await.map_err(|_|storage_error())?.into_iter().map(row).collect()
    }
    async fn w3c_state(&self, key: &str) -> Result<Option<Value>> {
        checked("state", key)?;
        self.fence().await?;
        Ok(
            payload_integrity::load(&self.pool, "devres_w3c_state", "", key)
                .await?
                .map(|value| value.0),
        )
    }
    async fn w3c_set_state(&self, key: &str, data: &Value) -> Result<()> {
        checked("state", key)?;
        bounded(data)?;
        let mut owner = self.owner.lock().await;
        owner.ping().await.map_err(|_| storage_error())?;
        sqlx::query("INSERT INTO devres_w3c_state(key,data,data_integrity) VALUES($1,$2,$3) ON CONFLICT(key) DO UPDATE SET data=EXCLUDED.data,data_integrity=EXCLUDED.data_integrity").bind(key).bind(Json(data)).bind(payload_integrity::digest("devres_w3c_state","",key,data)?).execute(&mut *owner).await.map_err(|_|storage_error())?;
        Ok(())
    }
    async fn w3c_publish_view(&self, view: &View) -> Result<()> {
        let identity = serde_json::to_vec(&(
            &view.catalog,
            &view.snapshots,
            &view.index,
            &view.validations,
            view.validated_at,
        ))
        .map_err(|_| Error::integrity("Invalid W3C view."))?;
        if hash(&identity) != view.id
            || view.snapshots.len() > 10000
            || view.snapshots.is_empty()
            || !valid_hash(&view.catalog)
            || view.validations.len() != view.snapshots.len()
            || view.index.is_null()
        {
            return Err(Error::integrity("Invalid W3C view identity."));
        }
        let mut owner = self.owner.lock().await;
        let mut tx = owner.begin().await.map_err(|_| storage_error())?;
        let catalog: Option<Json<Value>> =
            payload_integrity::load(&mut *tx, "devres_w3c_evidence", "catalogs", &view.catalog)
                .await?;
        let catalog: devres_application::w3c::Catalog = serde_json::from_value(
            catalog
                .ok_or_else(|| Error::integrity("W3C view catalog missing."))?
                .0,
        )
        .map_err(|_| Error::integrity("Invalid W3C catalog."))?;
        if view.validated_at
            != view
                .validations
                .values()
                .copied()
                .min()
                .unwrap_or(0)
                .min(catalog.observed_at)
        {
            return Err(Error::integrity("W3C view validation time mismatch."));
        }
        for (standard, id) in &view.snapshots {
            let validated_at = view
                .validations
                .get(standard)
                .copied()
                .ok_or_else(|| Error::integrity("W3C standard validation missing."))?;
            if !catalog.standards.iter().any(|s| s.id == *standard) {
                return Err(Error::integrity(
                    "W3C view standard is outside its catalog.",
                ));
            }
            let data: Json<Value> =
                payload_integrity::load(&mut *tx, "devres_w3c_evidence", "snapshots", id)
                    .await?
                    .ok_or_else(|| Error::integrity("W3C view snapshot missing."))?;
            let snapshot: Snapshot = serde_json::from_value(data.0)
                .map_err(|_| Error::integrity("Invalid W3C snapshot."))?;
            if snapshot.standard != *standard
                || snapshot.index.is_null()
                || snapshot.coverage["accounted"] != true
                || snapshot.coverage["synthetic"] == true
                || snapshot.coverage["usable"] != true
                || snapshot.coverage["license"]["decision"] != "approved"
            {
                return Err(Error::integrity("Invalid W3C publication evidence."));
            }
            if matches!(
                snapshot.representation.as_str(),
                "html" | "pdf" | "text" | "json" | "xml" | "raw"
            ) {
                let publication = snapshot.coverage["publication"]
                    .as_str()
                    .ok_or_else(|| Error::integrity("W3C publication evidence missing."))?;
                let evidence: Json<Value> = payload_integrity::load(
                    &mut *tx,
                    "devres_w3c_evidence",
                    "publications",
                    publication,
                )
                .await?
                .ok_or_else(|| Error::integrity("W3C publication evidence missing."))?;
                let publication_validation = if let Some(manifest) =
                    snapshot.coverage["edition_manifest"].as_str()
                {
                    validate_edition(&mut tx, &snapshot, standard, manifest, validated_at).await?
                } else {
                    validated_at
                };
                if evidence.0["standard"].as_str() != Some(standard)
                    || evidence.0["status"] != 200
                    || evidence.0["observed_at"].as_i64() != Some(publication_validation)
                    || evidence.0["url"]["url"].as_str() != Some(&snapshot.source_url)
                    || evidence.0["artifact"]["body_hash"].as_str() != Some(&snapshot.tree)
                    || snapshot.revision != publication
                    || snapshot.repository != snapshot.source_url
                {
                    return Err(Error::integrity(
                        "W3C default requires matching online publication evidence.",
                    ));
                }
            } else {
                let evidence = sqlx::query("SELECT sequence,kind,key,data,data_integrity,sequence_integrity FROM devres_w3c_evidence WHERE kind='observations' AND data->'repo'->>'url'=$1 AND data->>'main_revision'=$2 AND (data->>'observed_at')::bigint >= $3 ORDER BY sequence DESC LIMIT 1").bind(&snapshot.repository).bind(&snapshot.revision).bind(validated_at).fetch_optional(&mut *tx).await.map_err(|_|storage_error())?.map(|row|payload_integrity::row("devres_w3c_evidence",&row)).transpose()?;
                if evidence.is_none() {
                    return Err(Error::integrity(
                        "W3C default requires matching current Git evidence.",
                    ));
                }
            }
        }
        let data = serde_json::to_value(view).map_err(|_| Error::integrity("Invalid W3C view."))?;
        bounded(&data)?;
        sequence_integrity::admit(&mut tx, "devres_w3c_evidence", "views", &view.id, &data).await?;
        let allocated = sequence_integrity::reserve_one(&mut tx, "devres_w3c_evidence").await?;
        sqlx::query("INSERT INTO devres_w3c_evidence(kind,key,data,data_integrity,sequence,sequence_integrity) VALUES('views',$1,$2,$3,$4,$5) ON CONFLICT DO NOTHING").bind(&view.id).bind(Json(&data)).bind(payload_integrity::digest("devres_w3c_evidence","views",&view.id,&data)?).bind(allocated).bind(sequence_integrity::digest("devres_w3c_evidence","views",&view.id,allocated)?).execute(&mut *tx).await.map_err(|_|storage_error())?;
        sequence_integrity::verify_keys(
            &mut tx,
            "devres_w3c_evidence",
            &["views".to_owned()],
            std::slice::from_ref(&view.id),
        )
        .await?;
        let identical: bool = sqlx::query_scalar(
            "SELECT data=$2::jsonb FROM devres_w3c_evidence WHERE kind='views' AND key=$1",
        )
        .bind(&view.id)
        .bind(Json(&data))
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| storage_error())?;
        payload_integrity::load(&mut *tx, "devres_w3c_evidence", "views", &view.id)
            .await?
            .ok_or_else(|| Error::integrity("Retained view missing."))?;
        if !identical {
            return Err(Error::integrity("W3C view identity collision."));
        }
        sqlx::query("INSERT INTO devres_w3c_state(key,data,data_integrity) VALUES('default',$1,$2) ON CONFLICT(key) DO UPDATE SET data=EXCLUDED.data,data_integrity=EXCLUDED.data_integrity").bind(Json(&data)).bind(payload_integrity::digest("devres_w3c_state","","default",&data)?).execute(&mut *tx).await.map_err(|_|storage_error())?;
        tx.commit().await.map_err(|_| storage_error())
    }
}

pub(super) const SCHEMA_V7: &str = r#"
CREATE TABLE devres_w3c_evidence (
 sequence bigserial PRIMARY KEY,
 kind text NOT NULL,
 key text NOT NULL,
 data jsonb NOT NULL,
 UNIQUE(kind,key)
);
CREATE INDEX devres_w3c_evidence_page ON devres_w3c_evidence(kind,sequence);
CREATE TABLE devres_w3c_state(key text PRIMARY KEY,data jsonb NOT NULL);
CREATE TABLE devres_w3c_statistics(kind text PRIMARY KEY,rows bigint NOT NULL,projection_gaps bigint NOT NULL,index_gaps bigint NOT NULL);
"#;

async fn validate_edition(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    snapshot: &Snapshot,
    standard: &str,
    key: &str,
    validated_at: i64,
) -> Result<i64> {
    let invalid = || Error::integrity("W3C edition publication proof is invalid.");
    if !valid_hash(key) {
        return Err(invalid());
    }
    let manifest: Json<Value> =
        payload_integrity::load(&mut **tx, "devres_w3c_evidence", "editions", key)
            .await?
            .ok_or_else(invalid)?;
    let encoded = serde_json::to_vec(&manifest.0).map_err(|_| invalid())?;
    if encoded.len() > 16 * 1024 * 1024
        || hash(&encoded) != key
        || manifest.0["version"] != 1
        || manifest.0["inventory"].as_str() != Some(&snapshot.inventory)
        || manifest.0["validated_at"].as_i64() != Some(validated_at)
    {
        return Err(invalid());
    }
    let root_id = manifest.0["root_snapshot"]
        .as_str()
        .filter(|id| valid_hash(id))
        .ok_or_else(invalid)?;
    if snapshot.coverage["edition_root_snapshot"].as_str() != Some(root_id) {
        return Err(invalid());
    }
    let root: Json<Value> =
        payload_integrity::load(&mut **tx, "devres_w3c_evidence", "snapshots", root_id)
            .await?
            .ok_or_else(invalid)?;
    let root: Snapshot = serde_json::from_value(root.0).map_err(|_| invalid())?;
    if root.id != root_id
        || root.standard != standard
        || root.source_url != snapshot.source_url
        || root.tree != snapshot.tree
        || root.revision != snapshot.revision
        || root.representation != snapshot.representation
        || root.coverage["license"]["decision"] != "approved"
    {
        return Err(invalid());
    }
    let publications = manifest.0["publications"].as_object().ok_or_else(invalid)?;
    let missing = manifest.0["missing"].as_array().ok_or_else(invalid)?;
    let mut destinations = publications
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    for missing_url in missing {
        destinations.insert(
            missing_url
                .as_str()
                .filter(|u| u.len() <= 4096)
                .ok_or_else(invalid)?,
        );
    }
    if publications.is_empty()
        || destinations.len() > 10000
        || destinations.iter().map(|u| u.len()).sum::<usize>() > 8 * 1024 * 1024
        || publications.get(&root.source_url).and_then(Value::as_str) != Some(&root.revision)
    {
        return Err(invalid());
    }
    let origin = url::Url::parse(&root.source_url).map_err(|_| invalid())?;
    let parts = origin
        .path()
        .trim_matches('/')
        .split('/')
        .collect::<Vec<_>>();
    let scope = if matches!(origin.host_str(), Some("www.w3.org" | "w3.org"))
        && parts.first() == Some(&"TR")
        && parts.len() >= 2
    {
        if parts[1].len() == 4 && parts[1].bytes().all(|b| b.is_ascii_digit()) && parts.len() >= 3 {
            format!("/TR/{}/{}/", parts[1], parts[2])
        } else {
            format!("/TR/{}/", parts[1])
        }
    } else if origin.path().ends_with('/') {
        origin.path().to_owned()
    } else {
        format!(
            "{}/",
            origin.path().rsplit_once('/').map(|p| p.0).unwrap_or("")
        )
    };
    let mut minimum = i64::MAX;
    let mut root_validation = None;
    for (url, id) in publications {
        let document = url::Url::parse(url).map_err(|_| invalid())?;
        if document.origin() != origin.origin()
            || (url != &root.source_url && !document.path().starts_with(&scope))
        {
            return Err(invalid());
        }
        let id = id
            .as_str()
            .filter(|id| valid_hash(id))
            .ok_or_else(invalid)?;
        let publication: Json<Value> =
            payload_integrity::load(&mut **tx, "devres_w3c_evidence", "publications", id)
                .await?
                .ok_or_else(invalid)?;
        let data = publication.0;
        let observed = data["observed_at"]
            .as_i64()
            .filter(|t| *t >= 0)
            .ok_or_else(invalid)?;
        if data["id"].as_str() != Some(id)
            || data["standard"].as_str() != Some(standard)
            || data["url"]["url"].as_str() != Some(url.as_str())
            || data["status"] != 200
            || data["license"]["decision"] != "approved"
            || !data["artifact"]["body_hash"]
                .as_str()
                .is_some_and(valid_hash)
            || !data["artifact"]["bytes"]
                .as_u64()
                .is_some_and(|bytes| bytes <= crate::bulk::MAX_ARTIFACT_BYTES)
        {
            return Err(invalid());
        }
        minimum = minimum.min(observed);
        if url == &root.source_url {
            root_validation = Some(observed);
        }
    }
    if minimum != validated_at {
        return Err(invalid());
    }
    root_validation.ok_or_else(invalid)
}
