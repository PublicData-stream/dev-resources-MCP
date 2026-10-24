//! Owner-fenced schema-v4 advisory snapshots. Public evidence only.
use super::{PgBlobStore, hash, storage_error, valid_hash};
use async_trait::async_trait;
use devres_application::advisory::{AdvisoryRecord, AdvisoryRow, AdvisorySnapshot, AdvisoryStore};
use devres_domain::{Error, Result};
use serde_json::{Value, json};
use sqlx::{Connection, Row, types::Json};

fn bounded(value: &impl serde::Serialize, limit: usize) -> Result<Value> {
    let bytes =
        serde_json::to_vec(value).map_err(|_| Error::integrity("Invalid advisory evidence."))?;
    if bytes.len() > limit {
        return Err(Error::capacity(
            "Advisory evidence exceeds its storage bound.",
        ));
    }
    serde_json::from_slice(&bytes).map_err(|_| Error::integrity("Invalid advisory evidence."))
}
fn key(kind: &str, value: &str) -> Result<()> {
    if kind.is_empty()
        || kind.len() > 64
        || !kind.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        || value.is_empty()
        || value.len() > 4096
        || value.chars().any(char::is_control)
    {
        return Err(Error::invalid("Invalid advisory evidence key."));
    }
    Ok(())
}
fn row(row: sqlx::postgres::PgRow) -> Result<AdvisoryRow> {
    Ok(AdvisoryRow {
        sequence: row.try_get("sequence").map_err(|_| storage_error())?,
        key: row.try_get("key").map_err(|_| storage_error())?,
        data: row
            .try_get::<Json<Value>, _>("data")
            .map_err(|_| storage_error())?
            .0,
    })
}

#[async_trait]
impl AdvisoryStore for PgBlobStore {
    async fn publish_advisory_snapshot(
        &self,
        snapshot: &AdvisorySnapshot,
        make_default: bool,
    ) -> Result<()> {
        if !valid_hash(&snapshot.id)
            || !matches!(snapshot.format.as_str(), "rustsec" | "osv")
            || snapshot.records.len() > 20_000
            || snapshot.revision.len() != 40
            || !snapshot
                .revision
                .bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            return Err(Error::integrity("Invalid advisory snapshot identity."));
        }
        if make_default
            && (!snapshot.complete
                || snapshot.historical
                || snapshot.validated_at.is_none()
                || snapshot.coverage["synthetic"] == true)
        {
            return Err(Error::integrity(
                "Incomplete historical evidence cannot become the default.",
            ));
        }
        let mut descriptor = bounded(snapshot, 96 * 1024 * 1024)?;
        descriptor["records"] = json!([]);
        let mut descriptor = bounded(&descriptor, 4 * 1024 * 1024)?;
        let mut ids = std::collections::HashSet::new();
        let mut records = Vec::new();
        let mut total = 0usize;
        for record in &snapshot.records {
            if record.format != snapshot.format
                || !valid_hash(&record.body_hash)
                || hash(record.body.as_bytes()) != record.body_hash
                || !ids.insert(&record.id)
            {
                return Err(Error::integrity("Invalid advisory record membership."));
            }
            total = total.saturating_add(record.body.len());
            if record.body.len() > 1024 * 1024 || total > 64 * 1024 * 1024 {
                return Err(Error::capacity("Advisory snapshot body bound exceeded."));
            }
            let data = bounded(record, 4 * 1024 * 1024)?;
            let id = hash(&serde_json::to_vec(&data).map_err(|_| storage_error())?);
            records.push((id, data));
        }
        descriptor["membership_hash"] = json!(hash(
            &serde_json::to_vec(&records.iter().map(|(id, _)| id).collect::<Vec<_>>())
                .map_err(|_| storage_error())?
        ));
        descriptor["record_count"] = json!(records.len());
        let mut owner = self.owner.lock().await;
        owner.ping().await.map_err(|_| storage_error())?;
        let mut tx = owner.begin().await.map_err(|_| storage_error())?;
        // Chunking avoids giant SQL parameters while all memberships remain atomic.
        for chunk in records.chunks(250) {
            let ids: Vec<_> = chunk.iter().map(|(id, _)| id.clone()).collect();
            let data: Vec<_> = chunk.iter().map(|(_, v)| Json(v.clone())).collect();
            sqlx::query("INSERT INTO devres_advisory_records(id,data) SELECT * FROM UNNEST($1::text[],$2::jsonb[]) ON CONFLICT DO NOTHING")
                .bind(ids).bind(data).execute(&mut *tx).await.map_err(|_|storage_error())?;
        }
        sqlx::query("INSERT INTO devres_advisory_snapshots(id,format,revision,data) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING")
            .bind(&snapshot.id).bind(&snapshot.format).bind(&snapshot.revision).bind(Json(&descriptor)).execute(&mut *tx).await.map_err(|_|storage_error())?;
        let retained: Json<Value> =
            sqlx::query_scalar("SELECT data FROM devres_advisory_snapshots WHERE id=$1")
                .bind(&snapshot.id)
                .fetch_one(&mut *tx)
                .await
                .map_err(|_| storage_error())?;
        if retained.0 != descriptor {
            return Err(Error::integrity("Advisory snapshot identity collision."));
        }
        let positions: Vec<i32> = (0..records.len() as i32).collect();
        let record_ids: Vec<_> = records.iter().map(|(id, _)| id.clone()).collect();
        sqlx::query("INSERT INTO devres_advisory_members(snapshot,position,record) SELECT $1,p,r FROM UNNEST($2::integer[],$3::text[]) AS members(p,r) ON CONFLICT DO NOTHING")
            .bind(&snapshot.id).bind(positions).bind(record_ids).execute(&mut *tx).await.map_err(|_|storage_error())?;
        let retained_members: Vec<String> = sqlx::query_scalar(
            "SELECT record FROM devres_advisory_members WHERE snapshot=$1 ORDER BY position",
        )
        .bind(&snapshot.id)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| storage_error())?;
        if !retained_members.iter().eq(records.iter().map(|(id, _)| id)) {
            return Err(Error::integrity("Advisory snapshot membership collision."));
        }
        // Legacy selectors are fixed aliases. A later revalidation cannot rebind one.
        if snapshot.format == "rustsec" {
            for capture in &snapshot.captures {
                if capture.key == "rustsec:head" {
                    sqlx::query("INSERT INTO devres_advisory_aliases(alias,snapshot) VALUES($1,$2) ON CONFLICT DO NOTHING")
                        .bind(&capture.id).bind(&snapshot.id).execute(&mut *tx).await.map_err(|_|storage_error())?;
                }
            }
        }
        if make_default {
            sqlx::query("INSERT INTO devres_advisory_defaults(format,snapshot) VALUES($1,$2) ON CONFLICT(format) DO UPDATE SET snapshot=EXCLUDED.snapshot")
                .bind(&snapshot.format).bind(&snapshot.id).execute(&mut *tx).await.map_err(|_|storage_error())?;
        }
        tx.commit().await.map_err(|_| storage_error())
    }
    async fn advisory_snapshot(
        &self,
        id: Option<&str>,
        format: &str,
    ) -> Result<Option<AdvisorySnapshot>> {
        self.fence().await?;
        if !matches!(format, "rustsec" | "osv") || id.is_some_and(|v| !valid_hash(v)) {
            return Err(Error::invalid("Invalid advisory snapshot selector."));
        }
        let value:Option<(String,Json<Value>)>=sqlx::query_as("SELECT s.id,s.data FROM devres_advisory_snapshots s WHERE s.format=$2 AND s.id=COALESCE($1::text,(SELECT snapshot FROM devres_advisory_defaults WHERE format=$2)) OR (s.format=$2 AND s.id=(SELECT snapshot FROM devres_advisory_aliases WHERE alias=$1)) LIMIT 1")
            .bind(id).bind(format).fetch_optional(&self.pool).await.map_err(|_|storage_error())?;
        let Some((id, value)) = value else {
            return Ok(None);
        };
        let mut snapshot: AdvisorySnapshot = serde_json::from_value(value.0)
            .map_err(|_| Error::integrity("Invalid retained advisory snapshot."))?;
        let records:Vec<Json<Value>>=sqlx::query_scalar("SELECT r.data FROM devres_advisory_members m JOIN devres_advisory_records r ON r.id=m.record WHERE m.snapshot=$1 ORDER BY m.position LIMIT 20001")
            .bind(id).fetch_all(&self.pool).await.map_err(|_|storage_error())?;
        if records.len() > 20_000 {
            return Err(Error::capacity(
                "Retained advisory snapshot exceeds record bound.",
            ));
        }
        let mut total = 0usize;
        for record in records {
            let record: AdvisoryRecord = serde_json::from_value(record.0)
                .map_err(|_| Error::integrity("Invalid retained advisory record."))?;
            total = total.saturating_add(record.body.len());
            if total > 64 * 1024 * 1024 || hash(record.body.as_bytes()) != record.body_hash {
                return Err(Error::integrity(
                    "Retained advisory record integrity failed.",
                ));
            }
            snapshot.records.push(record);
        }
        Ok(Some(snapshot))
    }
    async fn advisory_rows(
        &self,
        kind: &str,
        cutoff: Option<i64>,
        after: i64,
        limit: usize,
    ) -> Result<Vec<AdvisoryRow>> {
        self.fence().await?;
        key(kind, "page")?;
        if after < 0 || cutoff.is_some_and(|v| v < 0) || !(1..=1000).contains(&limit) {
            return Err(Error::invalid("Invalid advisory evidence page."));
        }
        sqlx::query("SELECT sequence,key,data FROM devres_advisory_rows WHERE kind=$1 AND sequence>$2 AND ($3::bigint IS NULL OR sequence<=$3) ORDER BY sequence LIMIT $4")
            .bind(kind).bind(after).bind(cutoff).bind(limit as i64).fetch_all(&self.pool).await.map_err(|_|storage_error())?.into_iter().map(row).collect()
    }
    async fn advisory_row(&self, kind: &str, value: &str) -> Result<Option<AdvisoryRow>> {
        self.fence().await?;
        key(kind, value)?;
        sqlx::query("SELECT sequence,key,data FROM devres_advisory_rows WHERE kind=$1 AND key=$2")
            .bind(kind)
            .bind(value)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| storage_error())?
            .map(row)
            .transpose()
    }
    async fn advisory_cutoff(&self) -> Result<i64> {
        self.fence().await?;
        sqlx::query_scalar("SELECT COALESCE(max(sequence),0) FROM devres_advisory_rows")
            .fetch_one(&self.pool)
            .await
            .map_err(|_| storage_error())
    }
    async fn advisory_rows_by_keys(&self, kind: &str, keys: &[String]) -> Result<Vec<AdvisoryRow>> {
        self.fence().await?;
        if keys.len() > 16 {
            return Err(Error::invalid("Advisory cache batch exceeds 16 records."));
        }
        for value in keys {
            key(kind, value)?;
        }
        sqlx::query("SELECT sequence,key,data FROM devres_advisory_rows WHERE kind=$1 AND key=ANY($2::text[]) ORDER BY sequence")
            .bind(kind).bind(keys).fetch_all(&self.pool).await.map_err(|_|storage_error())?.into_iter().map(row).collect()
    }
    async fn advisory_ref_rows(
        &self,
        ref_name: &str,
        cutoff: i64,
        after: i64,
        limit: usize,
    ) -> Result<Vec<AdvisoryRow>> {
        self.fence().await?;
        key("refs", ref_name)?;
        if cutoff < 0 || after < 0 || !(1..=1000).contains(&limit) {
            return Err(Error::invalid("Invalid advisory history page."));
        }
        let mut tx = self.pool.begin().await.map_err(|_| storage_error())?;
        sqlx::query("SET LOCAL statement_timeout='5s'")
            .execute(&mut *tx)
            .await
            .map_err(|_| storage_error())?;
        let rows=sqlx::query("WITH RECURSIVE latest AS (SELECT data FROM devres_advisory_rows WHERE kind='refs' AND sequence<=$1 ORDER BY COALESCE((data->>'observation_sequence')::bigint,sequence) DESC,sequence DESC LIMIT 1), roots AS (SELECT r->>'peeled_commit' AS oid FROM latest,jsonb_array_elements(data->'refs') r WHERE r->>'name'=$2), ancestry(oid) AS (SELECT oid FROM roots WHERE oid IS NOT NULL UNION SELECT p.value FROM ancestry a JOIN devres_advisory_rows c ON c.kind='commits' AND c.key=a.oid AND c.sequence<=$1 CROSS JOIN LATERAL jsonb_array_elements_text(c.data->'parents') p) SELECT c.sequence,c.key,c.data FROM devres_advisory_rows c JOIN ancestry a ON c.key=a.oid WHERE c.kind='commits' AND c.sequence>$3 AND c.sequence<=$1 ORDER BY c.sequence LIMIT $4")
            .bind(cutoff).bind(ref_name).bind(after).bind(limit as i64).fetch_all(&mut *tx).await.map_err(|_|Error::capacity("Advisory ancestry query exceeded its processing budget."))?;
        tx.commit().await.map_err(|_| storage_error())?;
        rows.into_iter().map(row).collect()
    }
    async fn put_advisory_row(&self, kind: &str, value: &str, data: &Value) -> Result<()> {
        key(kind, value)?;
        let data = bounded(data, 4 * 1024 * 1024)?;
        let mut owner = self.owner.lock().await;
        owner.ping().await.map_err(|_| storage_error())?;
        let mut tx = owner.begin().await.map_err(|_| storage_error())?;
        sqlx::query("INSERT INTO devres_advisory_rows(kind,key,data) VALUES($1,$2,$3) ON CONFLICT DO NOTHING").bind(kind).bind(value).bind(Json(&data)).execute(&mut *tx).await.map_err(|_|storage_error())?;
        let old: Json<Value> =
            sqlx::query_scalar("SELECT data FROM devres_advisory_rows WHERE kind=$1 AND key=$2")
                .bind(kind)
                .bind(value)
                .fetch_one(&mut *tx)
                .await
                .map_err(|_| storage_error())?;
        if old.0 != data {
            return Err(Error::integrity("Immutable advisory evidence collision."));
        }
        tx.commit().await.map_err(|_| storage_error())
    }
    async fn advisory_state(&self, key: &str) -> Result<Option<Value>> {
        self.fence().await?;
        let value: Option<Json<Value>> =
            sqlx::query_scalar("SELECT data FROM devres_advisory_state WHERE key=$1")
                .bind(key)
                .fetch_optional(&self.pool)
                .await
                .map_err(|_| storage_error())?;
        Ok(value.map(|v| v.0))
    }
    async fn set_advisory_state(&self, value: &str, data: &Value) -> Result<()> {
        key("state", value)?;
        let data = bounded(data, 4 * 1024 * 1024)?;
        let mut owner = self.owner.lock().await;
        owner.ping().await.map_err(|_| storage_error())?;
        sqlx::query("INSERT INTO devres_advisory_state(key,data) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET data=EXCLUDED.data").bind(value).bind(Json(data)).execute(&mut *owner).await.map_err(|_|storage_error())?;
        Ok(())
    }
    async fn advisory_status(&self) -> Result<Value> {
        self.fence().await?;
        let counts:Json<Value>=sqlx::query_scalar("SELECT jsonb_build_object('snapshots',(SELECT count(*) FROM devres_advisory_snapshots),'representations',(SELECT count(*) FROM devres_advisory_records),'commits',(SELECT count(*) FROM devres_advisory_rows WHERE kind='commits'),'ref_observations',(SELECT count(DISTINCT data->>'id') FROM devres_advisory_rows WHERE kind='refs'))")
            .fetch_one(&self.pool).await.map_err(|_|storage_error())?;
        let states:Vec<(String,Json<Value>)>=sqlx::query_as("SELECT key,data FROM devres_advisory_state WHERE key IN('current','history','history-error','history-retry','config') ORDER BY key").fetch_all(&self.pool).await.map_err(|_|storage_error())?;
        let snapshots:Vec<(Json<Value>,Json<Value>)>=sqlx::query_as("SELECT s.data,jsonb_build_object('vulnerability',count(*) FILTER(WHERE r.data->'metadata'->>'classification'='vulnerability'),'informational',count(*) FILTER(WHERE r.data->'metadata'->>'classification'='informational'),'withdrawn',count(*) FILTER(WHERE r.data->'metadata'->>'classification'='withdrawn'),'unassessed',count(*) FILTER(WHERE r.data->'metadata'->>'classification'='unassessed')) FROM devres_advisory_defaults d JOIN devres_advisory_snapshots s ON s.id=d.snapshot LEFT JOIN devres_advisory_members m ON m.snapshot=s.id LEFT JOIN devres_advisory_records r ON r.id=m.record GROUP BY s.id,s.data ORDER BY s.format")
            .fetch_all(&self.pool).await.map_err(|_|storage_error())?;
        let now = devres_domain::unix_now();
        let defaults = snapshots
            .into_iter()
            .map(|(mut descriptor, counts)| {
                if let Some(object) = descriptor.0.as_object_mut() {
                    object.remove("records");
                    object.remove("membership_hash");
                }
                let validated = descriptor.0["validated_at"].as_i64();
                descriptor.0["stale"] = json!(
                    validated.is_none_or(|time| time > now || now.saturating_sub(time) > 86400)
                );
                descriptor.0["expired"] = json!(
                    validated.is_none_or(|time| time > now || now.saturating_sub(time) > 7 * 86400)
                );
                descriptor.0["assessment_complete"] = json!(
                    descriptor.0["complete"] == true
                        && descriptor.0["historical"] != true
                        && descriptor.0["expired"] == false
                );
                json!({"snapshot":descriptor.0,"classification_counts":counts.0})
            })
            .collect::<Vec<_>>();
        Ok(
            json!({"counts":counts.0,"defaults":defaults,"collection":states.into_iter().map(|(k,v)|(k,v.0)).collect::<serde_json::Map<_,_>>(),"history_scope":"all_observed_heads_and_tags_reachable_ancestry"}),
        )
    }
}

pub(super) const SCHEMA_V4: &str = r#"
CREATE TABLE devres_advisory_snapshots(sequence bigserial UNIQUE,id text PRIMARY KEY,format text NOT NULL,revision text NOT NULL,data jsonb NOT NULL);
CREATE INDEX devres_advisory_snapshot_revision ON devres_advisory_snapshots(revision,format);
CREATE TABLE devres_advisory_records(id text PRIMARY KEY,data jsonb NOT NULL);
CREATE TABLE devres_advisory_members(snapshot text NOT NULL REFERENCES devres_advisory_snapshots(id),position integer NOT NULL,record text NOT NULL REFERENCES devres_advisory_records(id),PRIMARY KEY(snapshot,position));
CREATE TABLE devres_advisory_defaults(format text PRIMARY KEY,snapshot text NOT NULL REFERENCES devres_advisory_snapshots(id));
CREATE TABLE devres_advisory_aliases(alias text PRIMARY KEY,snapshot text NOT NULL REFERENCES devres_advisory_snapshots(id));
CREATE TABLE devres_advisory_rows(sequence bigserial UNIQUE,kind text NOT NULL,key text NOT NULL,data jsonb NOT NULL,PRIMARY KEY(kind,key));
CREATE INDEX devres_advisory_rows_page ON devres_advisory_rows(kind,sequence);
CREATE TABLE devres_advisory_state(key text PRIMARY KEY,data jsonb NOT NULL);
INSERT INTO devres_advisory_rows(kind,key,data) SELECT 'legacy-heads',id,jsonb_build_object('capture',id) FROM devres_captures WHERE source_key='rustsec:head' ORDER BY retrieved_at,id;
"#;
