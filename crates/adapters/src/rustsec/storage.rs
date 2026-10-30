//! Owner-fenced schema-v4 advisory snapshots. Public evidence only.
use super::{PgBlobStore, hash, payload_integrity, storage_error, valid_hash};
use async_trait::async_trait;
use devres_application::advisory::{
    ADVISORY_PROCESSOR_VERSION, AdvisoryProjectionState, AdvisoryRecord, AdvisoryRow,
    AdvisorySnapshot, AdvisoryStore,
};
use devres_domain::{Error, Result};
use futures::TryStreamExt;
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
    let kind: String = row.try_get("kind").map_err(|_| storage_error())?;
    let mut key: String = row.try_get("key").map_err(|_| storage_error())?;
    let data = payload_integrity::row("devres_advisory_rows", &row)?;
    if key.starts_with("blake3:") && matches!(kind.as_str(), "commits" | "processing") {
        let revision = data["revision"]
            .as_str()
            .ok_or_else(|| Error::integrity("Canonical advisory revision missing."))?;
        key = if kind == "processing" {
            format!(
                "{revision}:{}",
                data["processor_version"]
                    .as_u64()
                    .ok_or_else(|| Error::integrity("Canonical advisory processor missing."))?
            )
        } else {
            revision.to_owned()
        };
    }
    Ok(AdvisoryRow {
        sequence: row.try_get("sequence").map_err(|_| storage_error())?,
        key,
        data,
    })
}

#[async_trait]
impl AdvisoryStore for PgBlobStore {
    async fn publish_advisory_snapshot(
        &self,
        snapshot: &AdvisorySnapshot,
        make_default: bool,
    ) -> Result<()> {
        if !snapshot.id.starts_with("blake3:") {
            let retained = self
                .advisory_snapshot(Some(&snapshot.id), &snapshot.format)
                .await?
                .ok_or_else(|| {
                    Error::integrity("New advisory snapshots require tagged BLAKE3 identities.")
                })?;
            if serde_json::to_value(&retained).map_err(|_| storage_error())?
                != serde_json::to_value(snapshot).map_err(|_| storage_error())?
            {
                return Err(Error::integrity(
                    "Legacy advisory snapshot replay differs from retained evidence.",
                ));
            }
            return Ok(());
        }
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
                || !ids.insert(&record.id)
            {
                return Err(Error::integrity("Invalid advisory record membership."));
            }
            crate::integrity::verify(&record.body_hash, record.body.as_bytes())?;
            total = total.saturating_add(record.body.len());
            if record.body.len() > 1024 * 1024 || total > 64 * 1024 * 1024 {
                return Err(Error::capacity("Advisory snapshot body bound exceeded."));
            }
            let data = bounded(record, 4 * 1024 * 1024)?;
            let id = if record.body_hash.starts_with("blake3:") {
                hash(&serde_json::to_vec(&data).map_err(|_| storage_error())?)
            } else {
                let legacy = crate::integrity::legacy_hash(
                    &serde_json::to_vec(&data).map_err(|_| storage_error())?,
                );
                let retained =
                    payload_integrity::load(&self.pool, "devres_advisory_records", "", &legacy)
                        .await?
                        .ok_or_else(|| {
                            Error::integrity(
                                "New advisory record bodies require BLAKE3 identities.",
                            )
                        })?;
                if retained.0 != data {
                    return Err(Error::integrity(
                        "Legacy advisory record replay differs from retained evidence.",
                    ));
                }
                legacy
            };
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
        let identities: Vec<_> = records.iter().map(|(id, _)| id.clone()).collect();
        let existing: std::collections::HashSet<String> =
            sqlx::query_scalar("SELECT id FROM devres_advisory_records WHERE id=ANY($1::text[])")
                .bind(&identities)
                .fetch_all(&mut *tx)
                .await
                .map_err(|_| storage_error())?
                .into_iter()
                .collect();
        for id in &existing {
            let retained = payload_integrity::load(&mut *tx, "devres_advisory_records", "", id)
                .await?
                .ok_or_else(|| Error::integrity("Retained advisory record missing."))?;
            if records
                .iter()
                .find(|(key, _)| key == id)
                .is_none_or(|(_, data)| *data != retained.0)
            {
                return Err(Error::integrity("Advisory record identity collision."));
            }
        }
        let new_records: Vec<_> = records
            .iter()
            .filter(|(id, _)| !existing.contains(id))
            .collect();
        // Chunking avoids giant SQL parameters while all memberships remain atomic.
        for chunk in new_records.chunks(250) {
            let ids: Vec<_> = chunk.iter().map(|(id, _)| id.clone()).collect();
            let data: Vec<_> = chunk.iter().map(|(_, v)| Json(v.clone())).collect();
            let digests = chunk
                .iter()
                .map(|(id, data)| {
                    payload_integrity::digest("devres_advisory_records", "", id, data)
                })
                .collect::<Result<Vec<_>>>()?;
            sqlx::query("INSERT INTO devres_advisory_records(id,data,data_integrity) SELECT * FROM UNNEST($1::text[],$2::jsonb[],$3::text[]) ON CONFLICT DO NOTHING")
                .bind(ids).bind(data).bind(digests).execute(&mut *tx).await.map_err(|_|storage_error())?;
        }
        let sequence: i64 = sqlx::query_scalar(
            "SELECT nextval(pg_get_serial_sequence('devres_advisory_snapshots','sequence'))",
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| storage_error())?;
        sqlx::query("INSERT INTO devres_advisory_snapshots(id,format,revision,data,data_integrity,sequence) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING")
            .bind(&snapshot.id).bind(&snapshot.format).bind(&snapshot.revision).bind(Json(&descriptor)).bind(payload_integrity::digest("devres_advisory_snapshots","",&snapshot.id,&payload_integrity::advisory_snapshot_payload(sequence,&snapshot.format,&snapshot.revision,&descriptor)?)?).bind(sequence).execute(&mut *tx).await.map_err(|_|storage_error())?;
        let retained: Json<Value> =
            payload_integrity::load(&mut *tx, "devres_advisory_snapshots", "", &snapshot.id)
                .await?
                .ok_or_else(|| Error::integrity("Advisory snapshot missing."))?;
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
        let value:Option<(String,Json<Value>,String,i64,String)>=sqlx::query_as("SELECT s.id,s.data,s.data_integrity,s.sequence,s.revision FROM devres_advisory_snapshots s WHERE s.format=$2 AND s.id=COALESCE($1::text,(SELECT snapshot FROM devres_advisory_defaults WHERE format=$2)) OR (s.format=$2 AND s.id=(SELECT snapshot FROM devres_advisory_aliases WHERE alias=$1)) LIMIT 1")
            .bind(id).bind(format).fetch_optional(&self.pool).await.map_err(|_|storage_error())?;
        let Some((id, value, expected, sequence, revision)) = value else {
            return Ok(None);
        };
        let value = payload_integrity::checked(
            "devres_advisory_snapshots",
            "",
            &id,
            payload_integrity::advisory_snapshot_payload(sequence, format, &revision, &value.0)?,
            &expected,
        )?["data"]
            .clone();
        let membership = value["membership_hash"]
            .as_str()
            .ok_or_else(|| Error::integrity("Advisory membership checksum missing."))?
            .to_owned();
        let count = value["record_count"]
            .as_u64()
            .ok_or_else(|| Error::integrity("Advisory membership count missing."))?;
        let mut snapshot: AdvisorySnapshot = serde_json::from_value(value)
            .map_err(|_| Error::integrity("Invalid retained advisory snapshot."))?;
        let records:Vec<(String,Json<Value>,String)>=sqlx::query_as("SELECT r.id,r.data,r.data_integrity FROM devres_advisory_members m JOIN devres_advisory_records r ON r.id=m.record WHERE m.snapshot=$1 ORDER BY m.position LIMIT 20001")
            .bind(&id).fetch_all(&self.pool).await.map_err(|_|storage_error())?;
        if records.len() > 20_000 {
            return Err(Error::capacity(
                "Retained advisory snapshot exceeds record bound.",
            ));
        }
        if count != records.len() as u64 {
            return Err(Error::integrity("Advisory membership count mismatch."));
        }
        crate::integrity::verify(
            &membership,
            &serde_json::to_vec(&records.iter().map(|(id, _, _)| id).collect::<Vec<_>>())
                .map_err(|_| storage_error())?,
        )?;
        let mut total = 0usize;
        for (id, record, expected) in records {
            let record = payload_integrity::checked(
                "devres_advisory_records",
                "",
                &id,
                record.0,
                &expected,
            )?;
            let record: AdvisoryRecord = serde_json::from_value(record)
                .map_err(|_| Error::integrity("Invalid retained advisory record."))?;
            crate::integrity::verify(&record.body_hash, record.body.as_bytes())?;
            total = total.saturating_add(record.body.len());
            if total > 64 * 1024 * 1024 {
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
        let hidden = self.visibility_aliases("advisory", kind, cutoff).await?;
        let bytes:i64=sqlx::query_scalar("SELECT COALESCE(sum(n),0)::bigint FROM(SELECT octet_length(data::text) AS n FROM devres_advisory_rows WHERE kind=$1 AND sequence>$2 AND ($3::bigint IS NULL OR sequence<=$3) AND NOT(key=ANY($5::text[])) ORDER BY sequence LIMIT $4) page").bind(kind).bind(after).bind(cutoff).bind(limit as i64).bind(hidden.as_ref()).fetch_one(&self.pool).await.map_err(|_|storage_error())?;
        if bytes > 64 * 1024 * 1024 {
            return Err(Error::capacity(
                "Advisory evidence page exceeds memory budget.",
            ));
        }
        sqlx::query("SELECT sequence,sequence_integrity,kind,key,data,data_integrity FROM devres_advisory_rows WHERE kind=$1 AND sequence>$2 AND ($3::bigint IS NULL OR sequence<=$3) AND NOT(key=ANY($5::text[])) ORDER BY sequence LIMIT $4")
            .bind(kind).bind(after).bind(cutoff).bind(limit as i64).bind(hidden.as_ref()).fetch_all(&self.pool).await.map_err(|_|storage_error())?.into_iter().map(row).collect()
    }
    async fn advisory_projection_state(
        &self,
        id: &str,
        format: &str,
    ) -> Result<Option<AdvisoryProjectionState>> {
        self.fence().await?;
        if !valid_hash(id) || !matches!(format, "rustsec" | "osv") {
            return Err(Error::invalid("Invalid advisory snapshot selector."));
        }
        let data = payload_integrity::load(&self.pool, "devres_advisory_snapshots", "", id).await?;
        data.filter(|value| value.0["format"] == format)
            .map(|Json(data)| {
                Ok(AdvisoryProjectionState {
                    complete: data["complete"]
                        .as_bool()
                        .ok_or_else(|| Error::integrity("Invalid advisory projection coverage."))?,
                    processor_version: data["coverage"]["processor_version"]
                        .as_u64()
                        .unwrap_or(1)
                        .try_into()
                        .map_err(|_| Error::integrity("Invalid advisory processing version."))?,
                })
            })
            .transpose()
    }
    async fn advisory_row(&self, kind: &str, value: &str) -> Result<Option<AdvisoryRow>> {
        self.fence().await?;
        key(kind, value)?;
        let resolved = self.advisory_natural_key(kind, value, None).await?;
        sqlx::query("SELECT sequence,sequence_integrity,kind,key,data,data_integrity FROM devres_advisory_rows WHERE kind=$1 AND key=$2")
            .bind(kind)
            .bind(&resolved)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| storage_error())?
            .map(row)
            .transpose()
    }
    async fn advisory_cutoff(&self) -> Result<i64> {
        self.fence().await?;
        if let Some(cutoff) = self.migration_cutoff("advisory").await? {
            return Ok(cutoff);
        }
        let row=sqlx::query("SELECT sequence,sequence_integrity,kind,key FROM devres_advisory_rows ORDER BY sequence DESC LIMIT 1").fetch_optional(&self.pool).await.map_err(|_|storage_error())?;
        row.map(|row| {
            super::sequence_integrity::verify_row("devres_advisory_rows", &row)?;
            row.try_get("sequence").map_err(|_| storage_error())
        })
        .transpose()
        .map(|value| value.unwrap_or(0))
    }
    async fn advisory_commit(
        &self,
        revision: &str,
        cutoff: Option<i64>,
    ) -> Result<Option<AdvisoryRow>> {
        self.fence().await?;
        key("commits", revision)?;
        if cutoff.is_some_and(|value| value < 0) {
            return Err(Error::invalid("Invalid advisory publication cutoff."));
        }
        // Exact generation keys use the existing primary index. The graph's sequence
        // stays fixed while projections are selected at the caller's frozen cutoff.
        let keys = (1..=ADVISORY_PROCESSOR_VERSION)
            .map(|version| format!("{revision}:{version}"))
            .collect::<Vec<_>>();
        let revision_key = self
            .advisory_natural_key("commits", revision, cutoff)
            .await?;
        let mut resolved_keys = Vec::with_capacity(keys.len());
        for key in &keys {
            resolved_keys.push(self.advisory_natural_key("processing", key, cutoff).await?);
        }
        let Some(found) = sqlx::query("SELECT c.sequence,c.sequence_integrity,c.kind,c.key,c.data,c.data_integrity,p.sequence AS processing_sequence,p.key AS processing_key,p.data AS processing_data,p.data_integrity AS processing_integrity,p.sequence_integrity AS processing_sequence_integrity FROM devres_advisory_rows c LEFT JOIN LATERAL (SELECT sequence,sequence_integrity,kind,key,data,data_integrity FROM devres_advisory_rows WHERE kind='processing' AND key=ANY($3::text[]) AND ($2::bigint IS NULL OR sequence<=$2) ORDER BY sequence DESC LIMIT 1) p ON true WHERE c.kind='commits' AND c.key=$1 AND ($2::bigint IS NULL OR c.sequence<=$2)")
            .bind(&revision_key).bind(cutoff).bind(&resolved_keys).fetch_optional(&self.pool).await.map_err(|_|storage_error())? else {return Ok(None);};
        let projection = found
            .try_get::<Option<Json<Value>>, _>("processing_data")
            .map_err(|_| storage_error())?
            .map(|data| {
                let sequence: i64 = found
                    .try_get("processing_sequence")
                    .map_err(|_| storage_error())?;
                let key: String = found
                    .try_get("processing_key")
                    .map_err(|_| storage_error())?;
                if super::sequence_integrity::digest(
                    "devres_advisory_rows",
                    "processing",
                    &key,
                    sequence,
                )? != found
                    .try_get::<String, _>("processing_sequence_integrity")
                    .map_err(|_| storage_error())?
                {
                    return Err(Error::integrity(
                        "Advisory processing occurrence ordering mismatch.",
                    ));
                }
                Ok::<_, Error>(AdvisoryRow {
                    sequence: found
                        .try_get("processing_sequence")
                        .map_err(|_| storage_error())?,
                    key: found
                        .try_get("processing_key")
                        .map_err(|_| storage_error())?,
                    data: payload_integrity::checked(
                        "devres_advisory_rows",
                        "processing",
                        &found
                            .try_get::<String, _>("processing_key")
                            .map_err(|_| storage_error())?,
                        data.0,
                        &found
                            .try_get::<String, _>("processing_integrity")
                            .map_err(|_| storage_error())?,
                    )?,
                })
            })
            .transpose()?;
        let mut result = row(found)?;
        if let Some(mut projection) = projection {
            if projection.key.starts_with("blake3:") {
                projection.key = format!(
                    "{}:{}",
                    projection.data["revision"]
                        .as_str()
                        .ok_or_else(storage_error)?,
                    projection.data["processor_version"]
                        .as_u64()
                        .ok_or_else(storage_error)?
                );
            }
            result.apply_processing(&projection)?;
        }
        Ok(Some(result))
    }
    async fn advisory_rows_by_keys(&self, kind: &str, keys: &[String]) -> Result<Vec<AdvisoryRow>> {
        self.fence().await?;
        if keys.len() > 16 {
            return Err(Error::invalid("Advisory cache batch exceeds 16 records."));
        }
        for value in keys {
            key(kind, value)?;
        }
        sqlx::query("SELECT sequence,sequence_integrity,kind,key,data,data_integrity FROM devres_advisory_rows WHERE kind=$1 AND key=ANY($2::text[]) ORDER BY sequence")
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
        let hidden = self
            .visibility_aliases("advisory", "refs", Some(cutoff))
            .await?;
        let (old_commits, new_commits) = self
            .visibility_pairs("advisory", "commits", Some(cutoff))
            .await?;
        let latest=sqlx::query("SELECT sequence,sequence_integrity,kind,key,data,data_integrity FROM devres_advisory_rows WHERE kind='refs' AND sequence<=$1 AND NOT(key=ANY($2::text[])) ORDER BY COALESCE((data->>'observation_sequence')::bigint,sequence) DESC,sequence DESC LIMIT 1")
            .bind(cutoff).bind(hidden.as_ref()).fetch_optional(&mut *tx).await.map_err(|_|storage_error())?;
        let roots = if let Some(latest) = latest {
            let value = payload_integrity::row("devres_advisory_rows", &latest)?;
            value["refs"]
                .as_array()
                .ok_or_else(|| Error::integrity("Invalid retained ref observation."))?
                .iter()
                .filter(|value| value["name"] == ref_name)
                .filter_map(|value| value["peeled_commit"].as_str().map(str::to_owned))
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let mut result = Vec::new();
        {
            // Every visited parent payload is verified, including ancestors outside the requested page.
            let mut stream=sqlx::query("WITH RECURSIVE mappings(legacy,canonical) AS(SELECT * FROM UNNEST($3::text[],$4::text[])),ancestry(oid) AS(SELECT UNNEST($1::text[]) UNION SELECT p.value FROM ancestry a JOIN devres_advisory_rows c ON c.kind='commits' AND c.key=COALESCE((SELECT canonical FROM mappings WHERE legacy=a.oid),a.oid) AND c.sequence<=$2 CROSS JOIN LATERAL jsonb_array_elements_text(c.data->'parents') p) SELECT c.sequence,c.sequence_integrity,c.kind,c.key,c.data,c.data_integrity FROM devres_advisory_rows c JOIN ancestry a ON c.key=COALESCE((SELECT canonical FROM mappings WHERE legacy=a.oid),a.oid) WHERE c.kind='commits' AND c.sequence<=$2 ORDER BY c.sequence")
                .bind(&roots).bind(cutoff).bind(old_commits.as_ref()).bind(new_commits.as_ref()).fetch(&mut *tx);
            while let Some(found) = stream.try_next().await.map_err(|_| {
                Error::capacity("Advisory ancestry query exceeded its processing budget.")
            })? {
                let found = row(found)?;
                if found.sequence > after && result.len() < limit {
                    result.push(found);
                }
            }
        }
        tx.commit().await.map_err(|_| storage_error())?;
        Ok(result)
    }
    async fn put_advisory_row(&self, kind: &str, value: &str, data: &Value) -> Result<()> {
        key(kind, value)?;
        let data = bounded(data, 4 * 1024 * 1024)?;
        let mut owner = self.owner.lock().await;
        owner.ping().await.map_err(|_| storage_error())?;
        let mut tx = owner.begin().await.map_err(|_| storage_error())?;
        let sequence =
            super::sequence_integrity::reserve_one(&mut tx, "devres_advisory_rows").await?;
        let sequence_integrity =
            super::sequence_integrity::digest("devres_advisory_rows", kind, value, sequence)?;
        sqlx::query("INSERT INTO devres_advisory_rows(sequence,kind,key,data,data_integrity,sequence_integrity) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING").bind(sequence).bind(kind).bind(value).bind(Json(&data)).bind(payload_integrity::digest("devres_advisory_rows",kind,value,&data)?).bind(sequence_integrity).execute(&mut *tx).await.map_err(|_|storage_error())?;
        let old: Json<Value> =
            payload_integrity::load(&mut *tx, "devres_advisory_rows", kind, value)
                .await?
                .ok_or_else(|| Error::integrity("Advisory evidence missing."))?;
        if old.0 != data {
            return Err(Error::integrity("Immutable advisory evidence collision."));
        }
        tx.commit().await.map_err(|_| storage_error())
    }
    async fn advisory_state(&self, key: &str) -> Result<Option<Value>> {
        self.fence().await?;
        Ok(
            payload_integrity::load(&self.pool, "devres_advisory_state", "", key)
                .await?
                .map(|value| value.0),
        )
    }
    async fn set_advisory_state(&self, value: &str, data: &Value) -> Result<()> {
        key("state", value)?;
        let data = bounded(data, 4 * 1024 * 1024)?;
        let mut owner = self.owner.lock().await;
        owner.ping().await.map_err(|_| storage_error())?;
        sqlx::query("INSERT INTO devres_advisory_state(key,data,data_integrity) VALUES($1,$2,$3) ON CONFLICT(key) DO UPDATE SET data=EXCLUDED.data,data_integrity=EXCLUDED.data_integrity").bind(value).bind(Json(&data)).bind(payload_integrity::digest("devres_advisory_state","",value,&data)?).execute(&mut *owner).await.map_err(|_|storage_error())?;
        Ok(())
    }
    async fn advisory_status(&self) -> Result<Value> {
        self.fence().await?;
        let counts:Json<Value>=sqlx::query_scalar("SELECT jsonb_build_object('snapshots',(SELECT count(*) FROM devres_advisory_snapshots s WHERE NOT EXISTS(SELECT 1 FROM devres_content_aliases a WHERE a.namespace='advisory:snapshots' AND a.legacy=s.id)),'representations',(SELECT count(*) FROM devres_advisory_records r WHERE NOT EXISTS(SELECT 1 FROM devres_content_aliases a WHERE a.namespace='advisory:records' AND a.legacy=r.id)),'commits',(SELECT count(*) FROM devres_advisory_rows r WHERE kind='commits' AND NOT EXISTS(SELECT 1 FROM devres_content_aliases a WHERE a.namespace='advisory:commits' AND a.legacy=r.key)),'ref_observations',(SELECT count(DISTINCT data->>'id') FROM devres_advisory_rows r WHERE kind='refs' AND NOT EXISTS(SELECT 1 FROM devres_content_aliases a WHERE a.namespace='advisory:refs' AND a.legacy=r.key)))")
            .fetch_one(&self.pool).await.map_err(|_|storage_error())?;
        let states:Vec<(String,Json<Value>,String)>=sqlx::query_as("SELECT key,data,data_integrity FROM devres_advisory_state WHERE key IN('current','history','history-error','history-retry','config') ORDER BY key").fetch_all(&self.pool).await.map_err(|_|storage_error())?;
        let states = states
            .into_iter()
            .map(|(key, data, expected)| {
                payload_integrity::checked("devres_advisory_state", "", &key, data.0, &expected)
                    .map(|data| (key, Json(data)))
            })
            .collect::<Result<Vec<_>>>()?;
        let defaults:Vec<(String,String)>=sqlx::query_as("SELECT s.id,s.format FROM devres_advisory_defaults d JOIN devres_advisory_snapshots s ON s.id=d.snapshot ORDER BY s.format")
            .fetch_all(&self.pool).await.map_err(|_|storage_error())?;
        let mut snapshots = Vec::new();
        for (id, format) in defaults {
            let snapshot = self
                .advisory_snapshot(Some(&id), &format)
                .await?
                .ok_or_else(|| Error::integrity("Default advisory snapshot missing."))?;
            let mut counts =
                json!({"vulnerability":0,"informational":0,"withdrawn":0,"unassessed":0});
            for record in &snapshot.records {
                if let Some(classification) = record.metadata["classification"].as_str()
                    && let Some(value) = counts.get_mut(classification)
                {
                    *value = json!(value.as_i64().unwrap_or(0) + 1);
                }
            }
            snapshots.push((
                Json(serde_json::to_value(snapshot).map_err(|_| storage_error())?),
                Json(counts),
            ));
        }
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

impl PgBlobStore {
    async fn rewrite_advisory_manifest(
        &self,
        descriptor: &Value,
        mappings: &crate::migration_map::MigrationMap,
        config: &devres_application::advisory::RustSecConfig,
        cancel: &tokio_util::sync::CancellationToken,
    ) -> Result<Value> {
        if descriptor.is_null() {
            return Err(Error::integrity("Advisory manifest descriptor missing."));
        }
        let source: crate::bulk::BulkArtifact = serde_json::from_value(descriptor.clone())
            .map_err(|_| Error::integrity("Invalid advisory manifest descriptor."))?;
        let root = self.root.join("rustsec-history/artifacts");
        let store = crate::bulk::BulkArtifactStore::new(&root, config.min_free_bytes)?
            .with_quota(config.max_archive_storage_bytes)?;
        if source.bytes > 4 * 1024 * 1024 {
            return Err(Error::capacity(
                "Advisory manifest exceeds migration budget.",
            ));
        }
        let verified = store
            .verify(&source.body_hash, 4 * 1024 * 1024, cancel.child_token())
            .await?;
        if verified != source {
            return Err(Error::integrity("Advisory manifest metadata mismatch."));
        }
        use tokio::io::AsyncReadExt;
        let file = tokio::fs::File::open(root.join(&source.relative_path))
            .await
            .map_err(|_| storage_error())?;
        let mut bytes = Vec::with_capacity(source.bytes as usize);
        file.take(4 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| storage_error())?;
        if bytes.len() as u64 != source.bytes {
            return Err(Error::integrity(
                "Advisory manifest changed during bounded read.",
            ));
        }
        crate::integrity::verify(&source.body_hash, &bytes)?;
        crate::rustsec::git::validate_migration_manifest(&bytes)?;
        let mut manifest: Value = serde_json::from_slice(&bytes)
            .map_err(|_| Error::integrity("Invalid retained advisory manifest."))?;
        if manifest["version"] != 1
            || manifest["source_url"] != "https://github.com/rustsec/advisory-db.git"
        {
            return Err(Error::integrity("Unsupported advisory Git manifest."));
        }
        let packs = manifest["packs"]
            .as_array_mut()
            .ok_or_else(|| Error::integrity("Advisory pack inventory missing."))?;
        for pack in packs {
            advisory_migration_cancel(cancel)?;
            migrate_advisory_artifact(&mut pack["artifact"], mappings)?;
            let artifact: crate::bulk::BulkArtifact =
                serde_json::from_value(pack["artifact"].clone()).map_err(|_| storage_error())?;
            let verified = store
                .verify(
                    &artifact.body_hash,
                    crate::bulk::MAX_ARTIFACT_BYTES,
                    cancel.child_token(),
                )
                .await?;
            if verified != artifact {
                return Err(Error::integrity(
                    "Canonical advisory pack reference mismatch.",
                ));
            }
        }
        migrate_advisory_artifact(&mut manifest["commits"], mappings)?;
        let commits: crate::bulk::BulkArtifact =
            serde_json::from_value(manifest["commits"].clone()).map_err(|_| storage_error())?;
        if store
            .verify(
                &commits.body_hash,
                crate::bulk::MAX_ARTIFACT_BYTES,
                cancel.child_token(),
            )
            .await?
            != commits
        {
            return Err(Error::integrity("Canonical commit inventory mismatch."));
        }
        if let Some(refs) = manifest["refs"].as_array_mut() {
            for reference in refs {
                migrate_advisory_owned_refs(reference, mappings)?;
            }
        }
        let encoded = serde_json::to_vec(&manifest).map_err(|_| storage_error())?;
        if encoded.len() > 4 * 1024 * 1024 {
            return Err(Error::capacity(
                "Canonical advisory manifest exceeds migration budget.",
            ));
        }
        crate::rustsec::git::validate_migration_manifest(&encoded)?;
        let canonical = store.capture_bytes(encoded, cancel.child_token()).await?;
        serde_json::to_value(canonical).map_err(|_| storage_error())
    }
    async fn advisory_natural_key(
        &self,
        kind: &str,
        key: &str,
        cutoff: Option<i64>,
    ) -> Result<String> {
        if !matches!(kind, "commits" | "processing") {
            return Ok(key.into());
        }
        let natural = key.split(':').next().unwrap_or("");
        if natural.len() != 40 || !natural.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Ok(key.into());
        }
        let (old, new) = self.visibility_pairs("advisory", kind, cutoff).await?;
        match old.binary_search_by(|old| old.as_str().cmp(key)) {
            Ok(position) => new
                .get(position)
                .cloned()
                .ok_or_else(|| Error::integrity("Advisory alias vector mismatch.")),
            Err(_) => Ok(key.into()),
        }
    }

    pub async fn migrate_advisory_graph(
        &self,
        mappings: &mut crate::migration_map::MigrationMap,
        config: &devres_application::advisory::RustSecConfig,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<crate::migration_map::MigrationAliases> {
        self.fence().await?;
        let mut aliases = crate::migration_map::MigrationAliases::new(mappings)?;
        // Original ref observations are identified by their retained manifest body.
        let mut after = 0_i64;
        loop {
            advisory_migration_cancel(&cancel)?;
            let found=sqlx::query("SELECT sequence,sequence_integrity,kind,key,data,data_integrity FROM devres_advisory_rows WHERE kind='refs' AND key NOT LIKE 'blake3:%' AND key !~ ':processed:' AND sequence>$1 ORDER BY sequence LIMIT 1")
                .bind(after).fetch_optional(&self.pool).await.map_err(|_|storage_error())?;
            let Some(found) = found else {
                break;
            };
            after = found.try_get("sequence").map_err(|_| storage_error())?;
            let old: String = found.try_get("key").map_err(|_| storage_error())?;
            let mut data = payload_integrity::row("devres_advisory_rows", &found)?;
            let manifest = self
                .rewrite_advisory_manifest(&data["manifest"], mappings, config, &cancel)
                .await?;
            let new = manifest["body_hash"]
                .as_str()
                .ok_or_else(storage_error)?
                .to_owned();
            crate::migration_map::insert(
                mappings,
                format!("advisory:manifest:{old}"),
                new.clone(),
            )?;
            data["manifest"] = manifest;
            data["id"] = json!(new);
            data["observation_sequence"] = json!(after);
            self.put_advisory_row("refs", &new, &data).await?;
            crate::migration_map::insert(mappings, format!("advisory:refs:{old}"), new.clone())?;
            {
                let alias = ("manifest".into(), old.clone(), new.clone());
                aliases.push(alias)?;
            }
            {
                let alias = ("refs".into(), old, new);
                aliases.push(alias)?;
            }
        }
        let mut after = 0_i64;
        loop {
            advisory_migration_cancel(&cancel)?;
            let found=sqlx::query("SELECT sequence,id,format FROM devres_advisory_snapshots WHERE id NOT LIKE 'blake3:%' AND sequence>$1 ORDER BY sequence LIMIT 1")
                .bind(after).fetch_optional(&self.pool).await.map_err(|_|storage_error())?;
            let Some(found) = found else {
                break;
            };
            after = found.try_get("sequence").map_err(|_| storage_error())?;
            let old: String = found.try_get("id").map_err(|_| storage_error())?;
            let format: String = found.try_get("format").map_err(|_| storage_error())?;
            let mut snapshot = self
                .advisory_snapshot(Some(&old), &format)
                .await?
                .ok_or_else(|| Error::integrity("Legacy advisory snapshot missing."))?;
            let old_records: Vec<String> = sqlx::query_scalar(
                "SELECT record FROM devres_advisory_members WHERE snapshot=$1 ORDER BY position",
            )
            .bind(&old)
            .fetch_all(&self.pool)
            .await
            .map_err(|_| storage_error())?;
            if old_records.len() != snapshot.records.len() {
                return Err(Error::integrity("Advisory migration membership changed."));
            }
            for (record, old_record) in snapshot.records.iter_mut().zip(old_records) {
                record.body_hash = hash(record.body.as_bytes());
                let value = serde_json::to_value(&*record).map_err(|_| storage_error())?;
                let new_record = hash(&serde_json::to_vec(&value).map_err(|_| storage_error())?);
                let map_key = format!("advisory:records:{old_record}");
                if mappings
                    .get(&map_key)
                    .is_some_and(|value| value != new_record)
                {
                    return Err(Error::integrity(
                        "Conflicting advisory record migration identity.",
                    ));
                }
                if !mappings.contains_key(&map_key) {
                    crate::migration_map::insert(mappings, map_key, new_record.clone())?;
                    let alias = ("records".into(), old_record, new_record);
                    aliases.push(alias)?;
                }
            }
            for capture in &mut snapshot.captures {
                capture.id = advisory_migration_ref("capture", &capture.id, mappings)?;
                capture.body_hash = advisory_migration_ref("body", &capture.body_hash, mappings)?;
            }
            if let Some(observation) = snapshot.coverage["git_observation"].as_str() {
                snapshot.coverage["git_observation"] = json!(advisory_migration_ref(
                    "advisory:manifest",
                    observation,
                    mappings
                )?);
            }
            snapshot.id = String::new();
            let identity = serde_json::to_value((
                "devres:storage-migration:advisory-snapshot:v1",
                &old,
                &snapshot,
            ))
            .map_err(|_| storage_error())?;
            let new = crate::integrity::canonical_hash(&identity)?;
            snapshot.id = new.clone();
            self.publish_advisory_snapshot(&snapshot, false).await?;
            crate::migration_map::insert(
                mappings,
                format!("advisory:snapshots:{old}"),
                new.clone(),
            )?;
            {
                let alias = ("snapshots".into(), old, new);
                aliases.push(alias)?;
            }
        }
        // Natural Git keys keep their source meaning; canonical rows use separate keys.
        let mut after = 0_i64;
        loop {
            advisory_migration_cancel(&cancel)?;
            let found=sqlx::query("SELECT sequence,sequence_integrity,kind,key,data,data_integrity FROM devres_advisory_rows WHERE key NOT LIKE 'blake3:%' AND sequence>$1 ORDER BY sequence LIMIT 1")
                .bind(after).fetch_optional(&self.pool).await.map_err(|_|storage_error())?;
            let Some(found) = found else {
                break;
            };
            after = found.try_get("sequence").map_err(|_| storage_error())?;
            let kind: String = found.try_get("kind").map_err(|_| storage_error())?;
            if !matches!(
                kind.as_str(),
                "refs"
                    | "commits"
                    | "processing"
                    | "git-projections"
                    | "legacy-heads"
                    | "legacy-gaps"
            ) {
                return Err(Error::integrity(
                    "Unrecognized advisory evidence family during migration.",
                ));
            }
            let old: String = found.try_get("key").map_err(|_| storage_error())?;
            if kind == "refs" && !old.contains(":processed:") {
                continue;
            }
            let mut data = payload_integrity::row("devres_advisory_rows", &found)?;
            migrate_advisory_owned_refs(&mut data, mappings)?;
            if kind == "refs"
                && let Some(old_id) = data["id"].as_str()
            {
                data["id"] = json!(advisory_migration_ref(
                    "advisory:manifest",
                    old_id,
                    mappings
                )?);
            }
            if kind == "refs" && data.get("observation_sequence").is_none() {
                data["observation_sequence"] = json!(after);
            }
            let new = crate::integrity::canonical_hash(
                &json!({"version":1,"namespace":"advisory-row","kind":kind,"legacy_key":old,"payload":data}),
            )?;
            self.put_advisory_row(&kind, &new, &data).await?;
            crate::migration_map::insert(mappings, format!("advisory:{kind}:{old}"), new.clone())?;
            {
                let alias = (kind, old, new);
                aliases.push(alias)?;
            }
        }
        let defaults: Vec<(String, String)> =
            sqlx::query_as("SELECT format,snapshot FROM devres_advisory_defaults ORDER BY format")
                .fetch_all(&self.pool)
                .await
                .map_err(|_| storage_error())?;
        for (format, snapshot) in defaults {
            let canonical = advisory_migration_ref("advisory:snapshots", &snapshot, mappings)?;
            payload_integrity::stage(
                self,
                "advisory",
                &format!("default:{format}"),
                &json!({"format":format,"snapshot":canonical}),
            )
            .await?;
        }
        let mut after = String::new();
        loop {
            advisory_migration_cancel(&cancel)?;
            let found=sqlx::query("SELECT ''::text AS kind,key,data,data_integrity FROM devres_advisory_state WHERE key>$1 ORDER BY key LIMIT 1").bind(&after).fetch_optional(&self.pool).await.map_err(|_|storage_error())?;
            let Some(found) = found else {
                break;
            };
            let key: String = found.try_get("key").map_err(|_| storage_error())?;
            let mut data = payload_integrity::row("devres_advisory_state", &found)?;
            if let Some(manifest) = data.get_mut("manifest") {
                *manifest = self
                    .rewrite_advisory_manifest(manifest, mappings, config, &cancel)
                    .await?;
            }
            migrate_advisory_owned_refs(&mut data, mappings)?;
            payload_integrity::stage(
                self,
                "advisory",
                &format!("state:{key}"),
                &json!({"key":key,"data":data}),
            )
            .await?;
            after = key;
        }
        mappings.ensure_healthy()?;
        aliases.ensure_healthy()?;
        Ok(aliases)
    }
}
fn advisory_migration_cancel(cancel: &tokio_util::sync::CancellationToken) -> Result<()> {
    if cancel.is_cancelled() {
        return Err(Error::new(
            "cancelled",
            "Advisory graph migration canceled.",
        ));
    }
    Ok(())
}
fn advisory_migration_ref(
    role: &str,
    value: &str,
    mappings: &crate::migration_map::MigrationMap,
) -> Result<String> {
    if value.starts_with("blake3:") && valid_hash(value) {
        return Ok(value.to_owned());
    }
    mappings
        .get(&format!("{role}:{value}"))
        .ok_or_else(|| Error::integrity("Unresolved advisory migration reference."))
}
fn migrate_advisory_artifact(
    value: &mut Value,
    mappings: &crate::migration_map::MigrationMap,
) -> Result<()> {
    if value.is_null() {
        return Ok(());
    }
    let old = value["body_hash"]
        .as_str()
        .ok_or_else(|| Error::integrity("Invalid retained advisory artifact."))?;
    let new = advisory_migration_ref("body", old, mappings)?;
    value["relative_path"] = json!(crate::integrity::relative_path(&new)?.to_string_lossy());
    value["body_hash"] = json!(new);
    Ok(())
}
/// Only known service-owned fields are rewritten. Advisory text, source metadata,
/// Git revision/object identities and arbitrary upstream JSON remain unchanged.
fn migrate_advisory_owned_refs(
    value: &mut Value,
    mappings: &crate::migration_map::MigrationMap,
) -> Result<()> {
    let Some(object) = value.as_object_mut() else {
        return Ok(());
    };
    for field in ["snapshot", "partial", "historical_snapshot"] {
        if let Some(Value::String(id)) = object.get_mut(field) {
            *id = advisory_migration_ref("advisory:snapshots", id, mappings)?;
        }
    }
    for field in [
        "observation_id",
        "observation",
        "first_observation",
        "git_observation",
    ] {
        if let Some(Value::String(id)) = object.get_mut(field) {
            *id = advisory_migration_ref("advisory:manifest", id, mappings)?;
        }
    }
    if let Some(Value::Object(snapshots)) = object.get_mut("snapshots") {
        for value in snapshots.values_mut() {
            if let Value::String(id) = value {
                *id = advisory_migration_ref("advisory:snapshots", id, mappings)?;
            }
        }
    }
    if let Some(Value::Object(parents)) = object.get_mut("parent_snapshots") {
        for snapshots in parents.values_mut() {
            if let Some(snapshots) = snapshots.as_object_mut() {
                for value in snapshots.values_mut() {
                    if let Value::String(id) = value {
                        *id = advisory_migration_ref("advisory:snapshots", id, mappings)?;
                    }
                }
            }
        }
    }
    if let Some(manifest) = object.get("manifest")
        && !manifest.is_null()
        && !manifest["body_hash"]
            .as_str()
            .is_some_and(|id| id.starts_with("blake3:"))
    {
        return Err(Error::integrity(
            "Advisory manifest must be derived before reference migration.",
        ));
    }
    if let Some(Value::Array(records)) = object.get_mut("records") {
        for record in records {
            if let Some(body) = record["body"].as_str() {
                record["body_hash"] = json!(hash(body.as_bytes()));
            }
        }
    }
    for field in ["refs", "packs"] {
        if let Some(Value::Array(items)) = object.get_mut(field) {
            for item in items {
                migrate_advisory_owned_refs(item, mappings)?;
            }
        }
    }
    if let Some(value) = object.get_mut("artifact") {
        migrate_advisory_artifact(value, mappings)?;
    }
    Ok(())
}

#[cfg(test)]
mod migration_tests {
    use super::*;
    #[test]
    fn typed_advisory_migration_preserves_source_fields() {
        let old = "a".repeat(64);
        let snapshot = hash(b"snapshot");
        let body = hash(b"body");
        let mut maps = crate::migration_map::MigrationMap::new();
        for (key, value) in [
            (format!("advisory:snapshots:{old}"), snapshot.clone()),
            (format!("advisory:manifest:{old}"), body.clone()),
        ] {
            crate::migration_map::insert(&mut maps, key, value).unwrap();
        }
        let mut value = json!({"snapshot":old,"first_observation":old,"revision":old,"metadata":{"snapshot":old,"original":{"body_hash":old}},"refs":[{"snapshots":{"rustsec":old},"oid":old}]});
        migrate_advisory_owned_refs(&mut value, &maps).unwrap();
        assert_eq!(value["snapshot"], snapshot);
        assert_eq!(value["first_observation"], body);
        assert_eq!(value["refs"][0]["snapshots"]["rustsec"], snapshot);
        assert_eq!(value["revision"], old);
        assert_eq!(value["metadata"]["snapshot"], old);
        assert_eq!(value["metadata"]["original"]["body_hash"], old);
        assert_eq!(value["refs"][0]["oid"], old);
    }
}
