//! Schema-v3 crate inventories, immutable projections and resumable acquisition.
use super::{PgBlobStore, hash, storage_error, valid_hash};
use async_trait::async_trait;
use devres_application::crate_corpus::{
    Artifact, CollectionJob, ContentDeltaQuery, ContentFilter, ContentRecord, CrateCorpusStore,
    Inventory, Snapshot, VersionRecord,
};
use devres_domain::{Capture, Error, Result};
use serde_json::{Value, json};
use sqlx::{Connection, Row, types::Json};

fn json_limit(value: &impl serde::Serialize, max: usize) -> Result<Value> {
    let value =
        serde_json::to_value(value).map_err(|_| Error::invalid("Invalid corpus projection."))?;
    if serde_json::to_vec(&value)
        .map_err(|_| Error::invalid("Invalid corpus projection."))?
        .len()
        > max
    {
        return Err(Error::capacity(
            "Corpus projection exceeds its byte budget.",
        ));
    }
    Ok(value)
}
fn checked_id(value: &str) -> Result<()> {
    if !valid_hash(value) {
        return Err(Error::invalid("Invalid corpus identifier."));
    }
    Ok(())
}
fn inventory(row: sqlx::postgres::PgRow) -> Result<Inventory> {
    Ok(Inventory {
        id: row.try_get("id").map_err(|_| storage_error())?,
        sequence: row.try_get("sequence").map_err(|_| storage_error())?,
        revision: row.try_get("revision").map_err(|_| storage_error())?,
        created_at: row.try_get("created_at").map_err(|_| storage_error())?,
        validated_at: row.try_get("validated_at").map_err(|_| storage_error())?,
        cursor: row.try_get("cursor").map_err(|_| storage_error())?,
    })
}
fn page(limit: usize, after: Option<&str>) -> Result<()> {
    if !(1..=1000).contains(&limit) || after.is_some_and(|s| s.len() > 8192) {
        return Err(Error::invalid("Invalid internal corpus page."));
    }
    Ok(())
}

impl PgBlobStore {
    async fn crate_text(
        &self,
        key: &str,
        url: &str,
        body: &[u8],
        provenance: Value,
        now: i64,
    ) -> Result<Capture> {
        let body_hash = hash(body);
        self.write_blob(&body_hash, body).await?;
        let capture = Capture {
            id: hash(format!("{key}\0{url}\0text/plain\0{body_hash}").as_bytes()),
            key: key.into(),
            source_url: url.into(),
            body_hash,
            media_type: "text/plain".into(),
            retrieved_at: now,
            validated_at: now,
        };
        <Self as CrateCorpusStore>::save_artifact(
            self,
            &Artifact {
                capture: capture.clone(),
                bytes: body.len() as u64,
                provenance,
            },
            false,
        )
        .await?;
        Ok(capture)
    }
}

#[async_trait]
impl CrateCorpusStore for PgBlobStore {
    async fn begin_inventory(&self, revision: &str, now: i64) -> Result<Inventory> {
        if revision.len() != 40
            || !revision
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(Error::invalid("Invalid registry revision."));
        }
        let id = hash(format!("crate-inventory:1:{revision}").as_bytes());
        let mut owner = self.owner.lock().await;
        owner.ping().await.map_err(|_| storage_error())?;
        sqlx::query("INSERT INTO devres_crate_inventories(id,revision,created_at,validated_at) VALUES($1,$2,$3,$3) ON CONFLICT(id) DO UPDATE SET validated_at=GREATEST(devres_crate_inventories.validated_at,EXCLUDED.validated_at)").bind(&id).bind(revision).bind(now).execute(&mut *owner).await.map_err(|_|storage_error())?;
        sqlx::query("INSERT INTO devres_crate_inventory_gaps(inventory,name,error) SELECT $1,g.name,g.error FROM devres_crate_inventory_gaps g WHERE g.inventory=(SELECT id FROM devres_crate_inventories WHERE published ORDER BY sequence DESC LIMIT 1) AND EXISTS(SELECT 1 FROM devres_crate_inventories WHERE id=$1 AND NOT published) AND NOT EXISTS(SELECT 1 FROM devres_crate_changes c WHERE c.inventory=$1 AND c.name=g.name) ON CONFLICT DO NOTHING").bind(&id).execute(&mut *owner).await.map_err(|_|storage_error())?;
        inventory(
            sqlx::query("SELECT * FROM devres_crate_inventories WHERE id=$1")
                .bind(&id)
                .fetch_one(&mut *owner)
                .await
                .map_err(|_| storage_error())?,
        )
    }
    async fn pending_inventory(&self) -> Result<Option<Inventory>> {
        self.fence().await?;
        sqlx::query(
            "SELECT * FROM devres_crate_inventories WHERE NOT published ORDER BY sequence LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| storage_error())?
        .map(inventory)
        .transpose()
    }
    async fn latest_inventory(&self) -> Result<Option<Inventory>> {
        self.fence().await?;
        sqlx::query(
            "SELECT * FROM devres_crate_inventories WHERE published ORDER BY sequence DESC LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| storage_error())?
        .map(inventory)
        .transpose()
    }
    async fn stage_crate(
        &self,
        epoch: &str,
        name: &str,
        versions: &[VersionRecord],
        cursor: &str,
    ) -> Result<()> {
        checked_id(epoch)?;
        crate::cargo::validate_name(name)?;
        if cursor.len() > 256
            || versions.len() > 50_000
            || versions
                .iter()
                .any(|r| r.name != name || !valid_hash(&r.metadata_capture))
        {
            return Err(Error::invalid("Invalid staged registry records."));
        }
        let rows = json_limit(&versions, 16 * 1024 * 1024)?;
        let mut owner = self.owner.lock().await;
        owner.ping().await.map_err(|_| storage_error())?;
        let mut tx = owner.begin().await.map_err(|_| storage_error())?;
        let staged = sqlx::query(
            "UPDATE devres_crate_inventories SET cursor=$2 WHERE id=$1 AND NOT published",
        )
        .bind(epoch)
        .bind(cursor)
        .execute(&mut *tx)
        .await
        .map_err(|_| storage_error())?;
        if staged.rows_affected() != 1 {
            return Err(Error::integrity(
                "Inventory is absent or already published.",
            ));
        }
        sqlx::query("DELETE FROM devres_crate_inventory_gaps WHERE inventory=$1 AND name=$2")
            .bind(epoch)
            .bind(name)
            .execute(&mut *tx)
            .await
            .map_err(|_| storage_error())?;
        sqlx::query(
            "INSERT INTO devres_crate_changes(inventory,name) VALUES($1,$2) ON CONFLICT DO NOTHING",
        )
        .bind(epoch)
        .bind(name)
        .execute(&mut *tx)
        .await
        .map_err(|_| storage_error())?;
        sqlx::query("DELETE FROM devres_crate_staging WHERE inventory=$1 AND name=$2")
            .bind(epoch)
            .bind(name)
            .execute(&mut *tx)
            .await
            .map_err(|_| storage_error())?;
        sqlx::query("INSERT INTO devres_crate_staging(inventory,name,version,metadata_capture,record) SELECT $1,r.name,r.version,r.metadata_capture,r.record FROM jsonb_to_recordset($2::jsonb) AS r(name text,version text,metadata_capture text,record jsonb)").bind(epoch).bind(Json(rows)).execute(&mut *tx).await.map_err(|_|storage_error())?;
        tx.commit().await.map_err(|_| storage_error())
    }
    async fn commit_inventory(&self, epoch: &str, manifest: &str) -> Result<Inventory> {
        checked_id(epoch)?;
        checked_id(manifest)?;
        let mut owner = self.owner.lock().await;
        owner.ping().await.map_err(|_| storage_error())?;
        let mut tx = owner.begin().await.map_err(|_| storage_error())?;
        let row = sqlx::query("SELECT * FROM devres_crate_inventories WHERE id=$1 FOR UPDATE")
            .bind(epoch)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| storage_error())?
            .ok_or_else(|| Error::not_found("Inventory not found."))?;
        let published: bool = row.try_get("published").map_err(|_| storage_error())?;
        let inv = inventory(row)?;
        if published {
            return Ok(inv);
        }
        let newer: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM devres_crate_inventories WHERE published AND sequence>$1)",
        )
        .bind(inv.sequence)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| storage_error())?;
        if newer {
            return Err(Error::integrity(
                "An older import cannot replace the current inventory.",
            ));
        }
        sqlx::query("UPDATE devres_crate_versions v SET valid_to=$2 FROM devres_crate_changes c WHERE c.inventory=$1 AND c.name=v.name AND v.valid_to IS NULL").bind(epoch).bind(inv.sequence).execute(&mut *tx).await.map_err(|_|storage_error())?;
        sqlx::query("INSERT INTO devres_crate_versions(name,version,valid_from,metadata_capture,record) SELECT name,version,$2,metadata_capture,record FROM devres_crate_staging WHERE inventory=$1").bind(epoch).bind(inv.sequence).execute(&mut *tx).await.map_err(|_|storage_error())?;
        // Index completeness and archive/documentation acquisition are deliberately independent.
        sqlx::query("INSERT INTO devres_crate_jobs(source_key,kind,name,version,target,checksum,metadata_capture,due_at) SELECT 'archive:'||name||':'||version||':'||(record->>'cksum'),'archive',name,version,'',record->>'cksum',metadata_capture,$2 FROM devres_crate_staging WHERE inventory=$1 ON CONFLICT(source_key) DO NOTHING").bind(epoch).bind(inv.created_at).execute(&mut *tx).await.map_err(|_|storage_error())?;
        sqlx::query("INSERT INTO devres_crate_jobs(source_key,kind,name,version,target,checksum,metadata_capture,due_at) SELECT 'platforms:'||name||':'||version,'platforms',name,version,'',record->>'cksum',metadata_capture,$2 FROM devres_crate_staging WHERE inventory=$1 ON CONFLICT(source_key) DO NOTHING").bind(epoch).bind(inv.created_at).execute(&mut *tx).await.map_err(|_|storage_error())?;
        sqlx::query("UPDATE devres_crate_inventories SET published=true,manifest=$2 WHERE id=$1")
            .bind(epoch)
            .bind(manifest)
            .execute(&mut *tx)
            .await
            .map_err(|_| storage_error())?;
        sqlx::query("DELETE FROM devres_crate_staging WHERE inventory=$1")
            .bind(epoch)
            .execute(&mut *tx)
            .await
            .map_err(|_| storage_error())?;
        tx.commit().await.map_err(|_| storage_error())?;
        Ok(inv)
    }
    async fn stage_gap(&self, epoch: &str, name: &str, error: &str, cursor: &str) -> Result<()> {
        if !matches!(
            error,
            "invalid_input" | "integrity" | "capacity" | "unsupported_format"
        ) {
            return Err(Error::invalid("Invalid inventory gap code."));
        }
        checked_id(epoch)?;
        crate::cargo::validate_name(name)?;
        if cursor.len() > 256 {
            return Err(Error::invalid("Inventory cursor exceeds its bound."));
        }
        let mut owner = self.owner.lock().await;
        owner.ping().await.map_err(|_| storage_error())?;
        let mut tx = owner.begin().await.map_err(|_| storage_error())?;
        let updated = sqlx::query(
            "UPDATE devres_crate_inventories SET cursor=$2 WHERE id=$1 AND NOT published",
        )
        .bind(epoch)
        .bind(cursor)
        .execute(&mut *tx)
        .await
        .map_err(|_| storage_error())?;
        if updated.rows_affected() != 1 {
            return Err(Error::integrity(
                "Gap inventory is absent or already published.",
            ));
        }
        sqlx::query("INSERT INTO devres_crate_inventory_gaps(inventory,name,error) VALUES($1,$2,$3) ON CONFLICT(inventory,name) DO UPDATE SET error=EXCLUDED.error").bind(epoch).bind(name).bind(error).execute(&mut *tx).await.map_err(|_|storage_error())?;
        tx.commit().await.map_err(|_| storage_error())
    }
    async fn versions(
        &self,
        epoch: &str,
        name: Option<&str>,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<VersionRecord>> {
        checked_id(epoch)?;
        page(limit, after)?;
        self.fence().await?;
        let rows=sqlx::query("SELECT v.name,v.version,v.metadata_capture,v.record,g.error AS metadata_error FROM devres_crate_versions v JOIN devres_crate_inventories i ON i.id=$1 AND i.published LEFT JOIN devres_crate_inventory_gaps g ON g.inventory=i.id AND g.name=v.name WHERE v.valid_from<=i.sequence AND (v.valid_to IS NULL OR v.valid_to>i.sequence) AND ($2::text IS NULL OR v.name=$2) AND ($3::text IS NULL OR v.name||'@'||v.version>$3) ORDER BY v.name||'@'||v.version LIMIT $4").bind(epoch).bind(name).bind(after).bind(limit as i64).fetch_all(&self.pool).await.map_err(|_|storage_error())?;
        rows.into_iter()
            .map(|r| {
                Ok(VersionRecord {
                    name: r.try_get("name").map_err(|_| storage_error())?,
                    version: r.try_get("version").map_err(|_| storage_error())?,
                    metadata_capture: r.try_get("metadata_capture").map_err(|_| storage_error())?,
                    metadata_status: r
                        .try_get::<Option<String>, _>("metadata_error")
                        .map_err(|_| storage_error())?
                        .map(|e| format!("stale_due_to_invalid_update:{e}")),
                    record: r
                        .try_get::<Json<Value>, _>("record")
                        .map_err(|_| storage_error())?
                        .0,
                })
            })
            .collect()
    }
    async fn save_artifact(&self, artifact: &Artifact, http: bool) -> Result<()> {
        let c = &artifact.capture;
        checked_id(&c.id)?;
        checked_id(&c.body_hash)?;
        if artifact.bytes > 32 * 1024 * 1024 * 1024_u64
            || c.key.len() > 8192
            || c.source_url.len() > 8192
            || c.media_type.len() > 128
        {
            return Err(Error::capacity("Invalid bulk capture metadata."));
        }
        let provenance = json_limit(&artifact.provenance, 1024 * 1024)?;
        // Verify the immutable object exists and has the exact committed length. Streaming writers verify its hash.
        let meta = tokio::fs::symlink_metadata(self.root.join(&c.body_hash))
            .await
            .map_err(|_| storage_error())?;
        if !meta.is_file() || meta.len() != artifact.bytes {
            return Err(Error::integrity("Bulk artifact is missing or has changed."));
        }
        let mut owner = self.owner.lock().await;
        owner.ping().await.map_err(|_| storage_error())?;
        let mut tx = owner.begin().await.map_err(|_| storage_error())?;
        sqlx::query("INSERT INTO devres_captures(id,source_key,source_url,body_hash,media_type,retrieved_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING").bind(&c.id).bind(&c.key).bind(&c.source_url).bind(&c.body_hash).bind(&c.media_type).bind(c.retrieved_at).execute(&mut *tx).await.map_err(|_|storage_error())?;
        sqlx::query("INSERT INTO devres_crate_artifacts(capture_id,bytes,provenance) VALUES($1,$2,$3) ON CONFLICT DO NOTHING").bind(&c.id).bind(artifact.bytes as i64).bind(Json(provenance)).execute(&mut *tx).await.map_err(|_|storage_error())?;
        sqlx::query("INSERT INTO devres_crate_observations(capture_id,observed_at,transport,provenance) VALUES($1,$2,$3,$4)").bind(&c.id).bind(c.validated_at).bind(if http{"https"}else{"derived_or_git"}).bind(Json(&artifact.provenance)).execute(&mut *tx).await.map_err(|_|storage_error())?;
        tx.commit().await.map_err(|_| storage_error())
    }
    async fn version(
        &self,
        epoch: &str,
        name: &str,
        version: &str,
    ) -> Result<Option<VersionRecord>> {
        checked_id(epoch)?;
        self.fence().await?;
        let row=sqlx::query("SELECT v.*,g.error AS metadata_error FROM devres_crate_versions v JOIN devres_crate_inventories i ON i.id=$1 AND i.published LEFT JOIN devres_crate_inventory_gaps g ON g.inventory=i.id AND g.name=v.name WHERE v.name=$2 AND v.version=$3 AND v.valid_from<=i.sequence AND (v.valid_to IS NULL OR v.valid_to>i.sequence)").bind(epoch).bind(name).bind(version).fetch_optional(&self.pool).await.map_err(|_|storage_error())?;
        row.map(|r| {
            Ok(VersionRecord {
                name: r.try_get("name").map_err(|_| storage_error())?,
                version: r.try_get("version").map_err(|_| storage_error())?,
                metadata_capture: r.try_get("metadata_capture").map_err(|_| storage_error())?,
                metadata_status: r
                    .try_get::<Option<String>, _>("metadata_error")
                    .map_err(|_| storage_error())?
                    .map(|e| format!("stale_due_to_invalid_update:{e}")),
                record: r
                    .try_get::<Json<Value>, _>("record")
                    .map_err(|_| storage_error())?
                    .0,
            })
        })
        .transpose()
    }
    async fn artifact(&self, id: &str) -> Result<Option<Artifact>> {
        checked_id(id)?;
        self.fence().await?;
        let row=sqlx::query("SELECT c.*,a.bytes,a.provenance,(SELECT max(observed_at) FROM devres_crate_observations WHERE capture_id=c.id) AS validated_at FROM devres_captures c JOIN devres_crate_artifacts a ON a.capture_id=c.id WHERE c.id=$1").bind(id).fetch_optional(&self.pool).await.map_err(|_|storage_error())?;
        row.map(read_artifact).transpose()
    }
    async fn latest_artifact(&self, key: &str) -> Result<Option<Artifact>> {
        self.fence().await?;
        let row=sqlx::query("SELECT c.*,a.bytes,a.provenance,o.observed_at AS validated_at FROM devres_crate_observations o JOIN devres_captures c ON c.id=o.capture_id JOIN devres_crate_artifacts a ON a.capture_id=c.id WHERE c.source_key=$1 ORDER BY o.sequence DESC LIMIT 1").bind(key).fetch_optional(&self.pool).await.map_err(|_|storage_error())?;
        row.map(read_artifact).transpose()
    }
    async fn import_metadata(
        &self,
        name: &str,
        revision: &str,
        path: &str,
        oid: &str,
        body: &[u8],
        now: i64,
    ) -> Result<Capture> {
        if crate::cargo::sparse_path(name)? != path
            || revision.len() != 40
            || oid.len() != 40
            || !revision
                .bytes()
                .chain(oid.bytes())
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            || body.len() > 16 * 1024 * 1024
        {
            return Err(Error::invalid("Invalid Git metadata provenance."));
        }
        self.crate_text(&format!("cargo:git-index:{}:{revision}",name.to_ascii_lowercase()),&format!("https://github.com/rust-lang/crates.io-index/blob/{revision}/{path}"),body,json!({"transport":"git","revision":revision,"path":path,"git_blob_oid":oid,"processor_version":1}),now).await
    }
    async fn save_text(
        &self,
        key: &str,
        url: &str,
        text: &str,
        provenance: Value,
        now: i64,
    ) -> Result<Capture> {
        if !key.starts_with("cargo:derived:") || text.len() > 4 * 1024 * 1024 || text.contains('\0')
        {
            return Err(Error::invalid("Invalid derived public text."));
        }
        self.crate_text(key, url, text.as_bytes(), provenance, now)
            .await
    }
    async fn schedule(&self, jobs: &[CollectionJob], due: i64) -> Result<()> {
        if jobs.len() > 1000 {
            return Err(Error::capacity("Collection batch exceeds 1000 jobs."));
        }
        let mut owner = self.owner.lock().await;
        owner.ping().await.map_err(|_| storage_error())?;
        let mut tx = owner.begin().await.map_err(|_| storage_error())?;
        for j in jobs {
            if !matches!(j.kind.as_str(), "archive" | "platforms" | "html" | "json")
                || j.key.len() > 512
                || j.target.len() > 128
            {
                return Err(Error::invalid("Invalid crate collection job."));
            }
            crate::cargo::validate_name(&j.name)?;
            crate::cargo::validate_version(&j.version)?;
            checked_id(&j.metadata_capture)?;
            sqlx::query("INSERT INTO devres_crate_jobs(source_key,kind,name,version,target,checksum,metadata_capture,due_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(source_key) DO NOTHING").bind(&j.key).bind(&j.kind).bind(&j.name).bind(&j.version).bind(&j.target).bind(&j.checksum).bind(&j.metadata_capture).bind(due).execute(&mut *tx).await.map_err(|_|storage_error())?;
        }
        tx.commit().await.map_err(|_| storage_error())
    }
    async fn claim(&self, now: i64, kind: &str) -> Result<Option<CollectionJob>> {
        let mut owner = self.owner.lock().await;
        owner.ping().await.map_err(|_| storage_error())?;
        let row=sqlx::query("UPDATE devres_crate_jobs SET state='running',attempts=attempts+1 WHERE source_key=(SELECT source_key FROM devres_crate_jobs WHERE kind=$2 AND state<>'running' AND due_at<=$1 AND attempts<4294967295 ORDER BY due_at,source_key FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING *").bind(now).bind(kind).fetch_optional(&mut *owner).await.map_err(|_|storage_error())?;
        row.map(|r| {
            Ok(CollectionJob {
                key: r.try_get("source_key").map_err(|_| storage_error())?,
                kind: r.try_get("kind").map_err(|_| storage_error())?,
                name: r.try_get("name").map_err(|_| storage_error())?,
                version: r.try_get("version").map_err(|_| storage_error())?,
                target: r.try_get("target").map_err(|_| storage_error())?,
                checksum: r.try_get("checksum").map_err(|_| storage_error())?,
                metadata_capture: r.try_get("metadata_capture").map_err(|_| storage_error())?,
                attempts: u32::try_from(
                    r.try_get::<i64, _>("attempts")
                        .map_err(|_| storage_error())?,
                )
                .map_err(|_| Error::integrity("Invalid collection attempts."))?,
                artifact: r.try_get("artifact").map_err(|_| storage_error())?,
            })
        })
        .transpose()
    }
    async fn finish(
        &self,
        key: &str,
        artifact: Option<&str>,
        error: Option<&str>,
        next: i64,
    ) -> Result<()> {
        if error.is_some_and(|e| {
            !matches!(
                e,
                "invalid_input"
                    | "not_found"
                    | "unavailable"
                    | "capacity"
                    | "integrity"
                    | "unsupported_format"
            )
        }) {
            return Err(Error::invalid("Invalid collection failure code."));
        }
        let mut owner = self.owner.lock().await;
        owner.ping().await.map_err(|_| storage_error())?;
        let updated=sqlx::query("UPDATE devres_crate_jobs SET state=CASE WHEN $3::text IS NULL THEN 'captured' ELSE 'failed' END,artifact=COALESCE($2,artifact),last_error=$3,due_at=$4,attempts=CASE WHEN $3::text IS NULL THEN 0 ELSE attempts END WHERE source_key=$1 AND state='running'").bind(key).bind(artifact).bind(error).bind(next).execute(&mut *owner).await.map_err(|_|storage_error())?;
        if updated.rows_affected() != 1 {
            return Err(Error::integrity("Collection job is not owned."));
        }
        Ok(())
    }
    async fn stage_content(&self, generation: &str, records: &[ContentRecord]) -> Result<()> {
        checked_id(generation)?;
        if records.len() > 100 {
            return Err(Error::capacity("Content batch exceeds 100 records."));
        }
        for r in records {
            checked_id(&r.id)?;
            checked_id(&r.capture)?;
            checked_id(&r.metadata_capture)?;
            checked_id(&r.archive_capture)?;
            crate::cargo::validate_name(&r.name)?;
            crate::cargo::validate_version(&r.version)?;
            if r.path.len() > 4096
                || r.target.len() > 128
                || !matches!(
                    r.kind.as_str(),
                    "source" | "manifest" | "readme" | "license" | "rustdoc" | "api"
                )
            {
                return Err(Error::invalid("Invalid content identity."));
            }
            json_limit(&r.attributes, 1024 * 1024)?;
        }
        let value = json_limit(&records, 16 * 1024 * 1024)?;
        let mut owner = self.owner.lock().await;
        owner.ping().await.map_err(|_| storage_error())?;
        let mut tx = owner.begin().await.map_err(|_| storage_error())?;
        sqlx::query("INSERT INTO devres_crate_generations(id) VALUES($1) ON CONFLICT DO NOTHING")
            .bind(generation)
            .execute(&mut *tx)
            .await
            .map_err(|_| storage_error())?;
        let committed: bool = sqlx::query_scalar(
            "SELECT published_sequence IS NOT NULL FROM devres_crate_generations WHERE id=$1 FOR UPDATE",
        )
        .bind(generation)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| storage_error())?;
        if !committed {
            sqlx::query("INSERT INTO devres_crate_content(generation,id,name,version,target,path,kind,capture,metadata_capture,archive_capture,attributes) SELECT $1,r.id,r.name,r.version,r.target,r.path,r.kind,r.capture,r.metadata_capture,r.archive_capture,r.attributes FROM jsonb_to_recordset($2::jsonb) AS r(id text,name text,version text,target text,path text,kind text,capture text,metadata_capture text,archive_capture text,attributes jsonb) ON CONFLICT(generation,id) DO NOTHING").bind(generation).bind(Json(value)).execute(&mut *tx).await.map_err(|_|storage_error())?;
        } else {
            for record in records {
                let existing:Option<Json<Value>>=sqlx::query_scalar("SELECT to_jsonb(c)-'generation' FROM devres_crate_content c WHERE generation=$1 AND id=$2").bind(generation).bind(&record.id).fetch_optional(&mut *tx).await.map_err(|_|storage_error())?;
                if existing.as_ref().map(|j| &j.0)
                    != Some(
                        &serde_json::to_value(record)
                            .map_err(|_| Error::integrity("Invalid content record."))?,
                    )
                {
                    return Err(Error::integrity(
                        "Published processing generation is immutable.",
                    ));
                }
            }
        }
        tx.commit().await.map_err(|_| storage_error())
    }
    async fn commit_content(&self, generation: &str, summary: Value) -> Result<()> {
        checked_id(generation)?;
        let summary = json_limit(&summary, 1024 * 1024)?;
        let mut owner = self.owner.lock().await;
        owner.ping().await.map_err(|_| storage_error())?;
        sqlx::query("INSERT INTO devres_crate_generations(id,published_sequence,summary) VALUES($1,nextval('devres_crate_content_sequence'),$2) ON CONFLICT(id) DO UPDATE SET published_sequence=COALESCE(devres_crate_generations.published_sequence,EXCLUDED.published_sequence),summary=CASE WHEN devres_crate_generations.published_sequence IS NULL THEN EXCLUDED.summary ELSE devres_crate_generations.summary END").bind(generation).bind(Json(summary)).execute(&mut *owner).await.map_err(|_|storage_error())?;
        Ok(())
    }
    async fn contents(
        &self,
        cutoff: i64,
        filter: &ContentFilter,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ContentRecord>> {
        page(limit, after)?;
        self.fence().await?;
        let rows=sqlx::query("SELECT * FROM (SELECT DISTINCT ON(c.name,c.version,c.target,c.path,c.kind) c.* FROM devres_crate_content c JOIN devres_crate_generations g ON g.id=c.generation WHERE g.published_sequence<=$1 AND g.published_sequence IN(SELECT max(published_sequence) FROM devres_crate_generations WHERE published_sequence<=$1 GROUP BY COALESCE(summary->>'job_key',id)) AND ($2::text IS NULL OR c.name=$2) AND ($3::text IS NULL OR c.version=$3) AND ($4::text IS NULL OR c.target=$4) AND ($5::text IS NULL OR c.path=$5) AND ($6::text IS NULL OR c.kind=$6) ORDER BY c.name,c.version,c.target,c.path,c.kind,g.published_sequence DESC) q WHERE ($7::text IS NULL OR id>$7) ORDER BY id LIMIT $8").bind(cutoff).bind(&filter.name).bind(&filter.version).bind(&filter.target).bind(&filter.path).bind(&filter.kind).bind(after).bind(limit as i64).fetch_all(&self.pool).await.map_err(|_|storage_error())?;
        rows.into_iter()
            .map(|r| {
                Ok(ContentRecord {
                    id: r.try_get("id").map_err(|_| storage_error())?,
                    name: r.try_get("name").map_err(|_| storage_error())?,
                    version: r.try_get("version").map_err(|_| storage_error())?,
                    target: r.try_get("target").map_err(|_| storage_error())?,
                    path: r.try_get("path").map_err(|_| storage_error())?,
                    kind: r.try_get("kind").map_err(|_| storage_error())?,
                    capture: r.try_get("capture").map_err(|_| storage_error())?,
                    metadata_capture: r.try_get("metadata_capture").map_err(|_| storage_error())?,
                    archive_capture: r.try_get("archive_capture").map_err(|_| storage_error())?,
                    attributes: r
                        .try_get::<Json<Value>, _>("attributes")
                        .map_err(|_| storage_error())?
                        .0,
                })
            })
            .collect()
    }
    async fn put_enrichment(
        &self,
        artifact: &str,
        kind: &str,
        rows: &[(String, Value)],
    ) -> Result<()> {
        checked_id(artifact)?;
        if rows.len() > 1000
            || !matches!(
                kind,
                "crates"
                    | "versions"
                    | "keywords"
                    | "categories"
                    | "crates_keywords"
                    | "crates_categories"
                    | "dependencies"
                    | "crate_downloads"
            )
        {
            return Err(Error::invalid("Invalid metadata enrichment batch."));
        }
        let values: Vec<_> = rows
            .iter()
            .map(|(id, value)| json!({"id":id,"value":value}))
            .collect();
        let value = json_limit(&values, 8 * 1024 * 1024)?;
        let mut owner = self.owner.lock().await;
        owner.ping().await.map_err(|_| storage_error())?;
        sqlx::query("INSERT INTO devres_crate_enrichment(artifact,kind,external_id,data) SELECT $1,$2,r.id,r.value FROM jsonb_to_recordset($3::jsonb) AS r(id text,value jsonb) ON CONFLICT DO NOTHING").bind(artifact).bind(kind).bind(Json(value)).execute(&mut *owner).await.map_err(|_|storage_error())?;
        Ok(())
    }
    async fn content_deltas(&self, query: &ContentDeltaQuery) -> Result<Vec<Value>> {
        let ContentDeltaQuery {
            cutoff,
            name,
            from_version: from,
            to_version: to,
            target,
            kind,
            after,
            limit,
        } = query;
        let (cutoff, target, kind, after, limit) = (
            *cutoff,
            target.as_deref(),
            kind.as_str(),
            after.as_deref(),
            *limit,
        );
        page(limit, after)?;
        self.fence().await?;
        if !matches!(kind, "api" | "text") {
            return Err(Error::invalid("Comparison kind must be api or text."));
        }
        let rows:Vec<Json<Value>>=sqlx::query_scalar("WITH latest AS (SELECT DISTINCT ON(c.version,c.target,c.path,c.kind) c.*,b.body_hash FROM devres_crate_content c JOIN devres_crate_generations g ON g.id=c.generation JOIN devres_captures b ON b.id=c.capture WHERE c.name=$2 AND c.version IN($3,$4) AND g.published_sequence<=$1 AND g.published_sequence IN(SELECT max(published_sequence) FROM devres_crate_generations WHERE published_sequence<=$1 GROUP BY COALESCE(summary->>'job_key',id)) AND ($5::text IS NULL OR c.target=$5) AND (($6='api' AND c.kind='api') OR ($6='text' AND c.kind IN('source','manifest','readme','license'))) ORDER BY c.version,c.target,c.path,c.kind,g.published_sequence DESC), a AS(SELECT * FROM latest WHERE version=$3), b AS(SELECT * FROM latest WHERE version=$4), changes AS(SELECT COALESCE(a.target,b.target)||chr(31)||COALESCE(a.path,b.path) AS cursor,COALESCE(a.path,b.path) AS path,COALESCE(a.target,b.target) AS target,CASE WHEN a.id IS NULL THEN 'added' WHEN b.id IS NULL THEN 'removed' WHEN $6='api' AND a.attributes->'format_version' IS DISTINCT FROM b.attributes->'format_version' THEN 'uncomparable' WHEN $6='api' AND a.attributes->'signature' IS NOT DISTINCT FROM b.attributes->'signature' THEN 'unchanged' WHEN $6='text' AND a.body_hash=b.body_hash THEN 'unchanged' ELSE 'changed' END AS change,to_jsonb(a)-'generation'-'body_hash' AS old,to_jsonb(b)-'generation'-'body_hash' AS new FROM a FULL JOIN b ON a.target=b.target AND a.path=b.path) SELECT jsonb_build_object('cursor',cursor,'path',path,'target',target,'change',change,'from',old,'to',new) FROM changes WHERE change<>'unchanged' AND ($7::text IS NULL OR cursor>$7) ORDER BY cursor LIMIT $8").bind(cutoff).bind(name).bind(from).bind(to).bind(target).bind(kind).bind(after).bind(limit as i64).fetch_all(&self.pool).await.map_err(|_|storage_error())?;
        Ok(rows.into_iter().map(|j| j.0).collect())
    }
    async fn projection_status(
        &self,
        cutoff: i64,
        name: &str,
        version: &str,
        kind: &str,
        target: Option<&str>,
    ) -> Result<Vec<Value>> {
        self.fence().await?;
        let rows:Vec<Json<Value>>=sqlx::query_scalar("SELECT summary FROM devres_crate_generations WHERE published_sequence IN(SELECT max(published_sequence) FROM devres_crate_generations WHERE published_sequence<=$1 AND summary->>'name'=$2 AND summary->>'version'=$3 AND summary->>'kind'=$4 AND ($5::text IS NULL OR summary->>'target'=$5) GROUP BY COALESCE(summary->>'job_key',id)) ORDER BY summary->>'target' LIMIT 1001").bind(cutoff).bind(name).bind(version).bind(kind).bind(target).fetch_all(&self.pool).await.map_err(|_|storage_error())?;
        Ok(rows.into_iter().map(|j| j.0).collect())
    }
    async fn commit_enrichment(&self, artifact: &str) -> Result<()> {
        checked_id(artifact)?;
        let mut owner = self.owner.lock().await;
        owner.ping().await.map_err(|_| storage_error())?;
        sqlx::query(
            "INSERT INTO devres_crate_enrichment_heads(artifact) VALUES($1) ON CONFLICT DO NOTHING",
        )
        .bind(artifact)
        .execute(&mut *owner)
        .await
        .map_err(|_| storage_error())?;
        Ok(())
    }
    async fn enrichment(&self, artifact: Option<&str>, name: &str, version: &str) -> Result<Value> {
        self.fence().await?;
        let Some(artifact) = artifact else {
            return Ok(json!({}));
        };
        let row:Option<Json<Value>>=sqlx::query_scalar("SELECT jsonb_build_object('crate',c.data,'version',v.data,'artifact',$1,'keywords',COALESCE((SELECT CASE WHEN count(*)<=1024 THEN jsonb_agg(k.data->>'keyword' ORDER BY k.data->>'keyword') ELSE jsonb_build_object('capacity_exceeded',true) END FROM devres_crate_enrichment ck JOIN devres_crate_enrichment k ON k.artifact=ck.artifact AND k.kind='keywords' AND k.external_id=ck.data->>'keyword_id' WHERE ck.artifact=c.artifact AND ck.kind='crates_keywords' AND ck.data->>'crate_id'=c.external_id),'[]'::jsonb),'categories',COALESCE((SELECT CASE WHEN count(*)<=1024 THEN jsonb_agg(k.data->>'slug' ORDER BY k.data->>'slug') ELSE jsonb_build_object('capacity_exceeded',true) END FROM devres_crate_enrichment ck JOIN devres_crate_enrichment k ON k.artifact=ck.artifact AND k.kind='categories' AND k.external_id=ck.data->>'category_id' WHERE ck.artifact=c.artifact AND ck.kind='crates_categories' AND ck.data->>'crate_id'=c.external_id),'[]'::jsonb)) FROM devres_crate_enrichment c LEFT JOIN devres_crate_enrichment v ON v.artifact=c.artifact AND v.kind='versions' AND v.data->>'crate_id'=c.external_id AND v.data->>'num'=$3 WHERE c.artifact=$1 AND c.kind='crates' AND lower(c.data->>'name')=lower($2) LIMIT 1").bind(artifact).bind(name).bind(version).fetch_optional(&self.pool).await.map_err(|_|storage_error())?;
        let value = row.map_or_else(|| json!({}), |j| j.0);
        if ["keywords", "categories"]
            .iter()
            .any(|k| value.get(k).is_some_and(|v| !v.is_array()))
        {
            return Err(Error::capacity(
                "Metadata enrichment relation bound exceeded.",
            ));
        }
        json_limit(&value, 2 * 1024 * 1024)?;
        Ok(value)
    }
    async fn prepare_snapshot(&self, epoch: &str, now: i64) -> Result<Snapshot> {
        checked_id(epoch)?;
        let index_manifest = Value::Null;
        let mut owner = self.owner.lock().await;
        owner.ping().await.map_err(|_| storage_error())?;
        let mut tx = owner.begin().await.map_err(|_| storage_error())?;
        let inv = inventory(
            sqlx::query("SELECT * FROM devres_crate_inventories WHERE id=$1 AND published")
                .bind(epoch)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|_| storage_error())?
                .ok_or_else(|| Error::unavailable("No valid inventory is published."))?,
        )?;
        let cutoff: i64 = sqlx::query_scalar(
            "SELECT COALESCE(max(published_sequence),0) FROM devres_crate_generations",
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| storage_error())?;
        let enrichment: Option<String> = sqlx::query_scalar(
            "SELECT artifact FROM devres_crate_enrichment_heads ORDER BY sequence DESC LIMIT 1",
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| storage_error())?;
        let counts:Json<Value>=sqlx::query_scalar("SELECT COALESCE(jsonb_object_agg(kind,stats),'{}'::jsonb) FROM (SELECT kind,jsonb_build_object('total',count(*),'captured',count(artifact),'failed',count(*) FILTER(WHERE last_error IS NOT NULL)) stats FROM devres_crate_jobs GROUP BY kind) q").fetch_one(&mut *tx).await.map_err(|_|storage_error())?;
        let versions:i64=sqlx::query_scalar("SELECT count(*) FROM devres_crate_versions WHERE valid_from<=$1 AND (valid_to IS NULL OR valid_to>$1)").bind(inv.sequence).fetch_one(&mut *tx).await.map_err(|_|storage_error())?;
        let gaps: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM devres_crate_inventory_gaps WHERE inventory=$1",
        )
        .bind(epoch)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| storage_error())?;
        let processing:Json<Value>=sqlx::query_scalar("SELECT jsonb_build_object('published_generations',count(*),'skipped_binary',COALESCE(sum((summary->>'skipped_binary')::bigint),0),'skipped_oversized',COALESCE(sum((summary->>'skipped_oversized')::bigint),0),'unresolved_references',COALESCE(sum((summary->>'unresolved_references')::bigint),0)) FROM devres_crate_generations WHERE published_sequence<=$1").bind(cutoff).fetch_one(&mut *tx).await.map_err(|_|storage_error())?;
        let coverage = json!({"inventory_complete":gaps==0,"inventory_enumeration_complete":true,"metadata_gaps":gaps,"processing_cumulative":processing.0,"versions":versions,"jobs":counts.0,"content_sequence":cutoff,"processor_version":1});
        let id=hash(serde_json::to_vec(&json!({"inventory":inv.id,"inventory_validated_at":inv.validated_at,"content_sequence":cutoff,"enrichment":enrichment,"index":index_manifest,"coverage":coverage})).map_err(|_|Error::integrity("Snapshot identity failed."))?.as_slice());
        let snapshot = Snapshot {
            id: id.clone(),
            inventory: inv,
            content_sequence: cutoff,
            enrichment,
            index_manifest,
            coverage,
            created_at: now,
        };
        tx.commit().await.map_err(|_| storage_error())?;
        Ok(snapshot)
    }
    async fn commit_snapshot(&self, mut snapshot: Snapshot) -> Result<Snapshot> {
        checked_id(&snapshot.inventory.id)?;
        json_limit(&snapshot.index_manifest, 2 * 1024 * 1024)?;
        if !snapshot.index_manifest.is_null()
            && (snapshot.index_manifest["inventory"] != snapshot.inventory.id
                || snapshot.index_manifest["content_sequence"] != snapshot.content_sequence
                || snapshot.index_manifest["enrichment"]
                    != serde_json::to_value(&snapshot.enrichment)
                        .map_err(|_| Error::integrity("Invalid snapshot enrichment."))?)
        {
            return Err(Error::integrity(
                "Index membership differs from the frozen snapshot.",
            ));
        }
        snapshot.id=hash(serde_json::to_vec(&json!({"inventory":snapshot.inventory.id,"inventory_validated_at":snapshot.inventory.validated_at,"content_sequence":snapshot.content_sequence,"enrichment":snapshot.enrichment,"index":snapshot.index_manifest,"coverage":snapshot.coverage})).map_err(|_|Error::integrity("Snapshot identity failed."))?.as_slice());
        let encoded = json_limit(&snapshot, 4 * 1024 * 1024)?;
        let mut owner = self.owner.lock().await;
        owner.ping().await.map_err(|_| storage_error())?;
        let mut tx = owner.begin().await.map_err(|_| storage_error())?;
        sqlx::query("INSERT INTO devres_crate_snapshots(id,inventory,content_sequence,data) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING").bind(&snapshot.id).bind(&snapshot.inventory.id).bind(snapshot.content_sequence).bind(Json(encoded)).execute(&mut *tx).await.map_err(|_|storage_error())?;
        let retained: Json<Value> =
            sqlx::query_scalar("SELECT data FROM devres_crate_snapshots WHERE id=$1")
                .bind(&snapshot.id)
                .fetch_one(&mut *tx)
                .await
                .map_err(|_| storage_error())?;
        tx.commit().await.map_err(|_| storage_error())?;
        serde_json::from_value(retained.0).map_err(|_| Error::integrity("Invalid stored snapshot."))
    }
    async fn publish_snapshot(
        &self,
        epoch: &str,
        index_manifest: Value,
        now: i64,
    ) -> Result<Snapshot> {
        let mut snapshot = self.prepare_snapshot(epoch, now).await?;
        snapshot.index_manifest = index_manifest;
        self.commit_snapshot(snapshot).await
    }
    async fn snapshot(&self, id: Option<&str>) -> Result<Option<Snapshot>> {
        if let Some(id) = id {
            checked_id(id)?;
        }
        self.fence().await?;
        let value:Option<Json<Value>>=sqlx::query_scalar("SELECT data FROM devres_crate_snapshots WHERE ($1::text IS NULL OR id=$1) ORDER BY sequence DESC LIMIT 1").bind(id).fetch_optional(&self.pool).await.map_err(|_|storage_error())?;
        value
            .map(|v| {
                serde_json::from_value(v.0)
                    .map_err(|_| Error::integrity("Invalid stored crate snapshot."))
            })
            .transpose()
    }
    async fn status(&self) -> Result<Value> {
        self.fence().await?;
        let jobs:Json<Value>=sqlx::query_scalar("SELECT COALESCE(jsonb_agg(q),'[]'::jsonb) FROM (SELECT kind,state,count(*) AS count,count(artifact) AS retained,min(due_at) AS next_due FROM devres_crate_jobs GROUP BY kind,state ORDER BY kind,state) q").fetch_one(&self.pool).await.map_err(|_|storage_error())?;
        let errors:Json<Value>=sqlx::query_scalar("SELECT COALESCE(jsonb_agg(q),'[]'::jsonb) FROM (SELECT kind,last_error,count(*) AS count FROM devres_crate_jobs WHERE last_error IS NOT NULL GROUP BY kind,last_error ORDER BY kind,last_error) q").fetch_one(&self.pool).await.map_err(|_|storage_error())?;
        Ok(
            json!({"jobs":jobs.0,"errors":errors.0,"inventory":self.latest_inventory().await?,"snapshot":self.snapshot(None).await?}),
        )
    }
}
fn read_artifact(r: sqlx::postgres::PgRow) -> Result<Artifact> {
    Ok(Artifact {
        capture: Capture {
            id: r.try_get("id").map_err(|_| storage_error())?,
            key: r.try_get("source_key").map_err(|_| storage_error())?,
            source_url: r.try_get("source_url").map_err(|_| storage_error())?,
            body_hash: r.try_get("body_hash").map_err(|_| storage_error())?,
            media_type: r.try_get("media_type").map_err(|_| storage_error())?,
            retrieved_at: r.try_get("retrieved_at").map_err(|_| storage_error())?,
            validated_at: r.try_get("validated_at").map_err(|_| storage_error())?,
        },
        bytes: u64::try_from(r.try_get::<i64, _>("bytes").map_err(|_| storage_error())?)
            .map_err(|_| Error::integrity("Invalid artifact size."))?,
        provenance: r
            .try_get::<Json<Value>, _>("provenance")
            .map_err(|_| storage_error())?
            .0,
    })
}

pub(super) const SCHEMA_V3: &str = r#"
CREATE TABLE devres_crate_artifacts(capture_id text PRIMARY KEY REFERENCES devres_captures(id),bytes bigint NOT NULL CHECK(bytes>=0),provenance jsonb NOT NULL);
CREATE TABLE devres_crate_observations(sequence bigserial PRIMARY KEY,capture_id text NOT NULL REFERENCES devres_crate_artifacts(capture_id),observed_at bigint NOT NULL,transport text NOT NULL,provenance jsonb NOT NULL);
CREATE INDEX devres_crate_observed ON devres_crate_observations(capture_id,sequence DESC);
CREATE TABLE devres_crate_inventories(id text PRIMARY KEY,sequence bigserial UNIQUE,revision text NOT NULL UNIQUE,created_at bigint NOT NULL,validated_at bigint NOT NULL,cursor text,published boolean NOT NULL DEFAULT false,manifest text REFERENCES devres_crate_artifacts(capture_id));
CREATE TABLE devres_crate_inventory_gaps(inventory text NOT NULL REFERENCES devres_crate_inventories(id),name text NOT NULL,error text NOT NULL,PRIMARY KEY(inventory,name));
CREATE TABLE devres_crate_changes(inventory text NOT NULL REFERENCES devres_crate_inventories(id),name text NOT NULL,PRIMARY KEY(inventory,name));
CREATE TABLE devres_crate_staging(inventory text NOT NULL REFERENCES devres_crate_inventories(id),name text NOT NULL,version text NOT NULL,metadata_capture text NOT NULL REFERENCES devres_captures(id),record jsonb NOT NULL,PRIMARY KEY(inventory,name,version));
CREATE TABLE devres_crate_versions(name text NOT NULL,version text NOT NULL,valid_from bigint NOT NULL,valid_to bigint,metadata_capture text NOT NULL REFERENCES devres_captures(id),record jsonb NOT NULL,PRIMARY KEY(name,version,valid_from),CHECK(valid_to IS NULL OR valid_to>valid_from));
CREATE INDEX devres_crate_versions_current ON devres_crate_versions(name,version) WHERE valid_to IS NULL;
CREATE INDEX devres_crate_versions_page ON devres_crate_versions((name||'@'||version));
CREATE TABLE devres_crate_jobs(source_key text PRIMARY KEY,kind text NOT NULL,name text NOT NULL,version text NOT NULL,target text NOT NULL,checksum text NOT NULL,metadata_capture text NOT NULL REFERENCES devres_captures(id),state text NOT NULL DEFAULT 'pending',attempts bigint NOT NULL DEFAULT 0,artifact text REFERENCES devres_crate_artifacts(capture_id),last_error text,due_at bigint NOT NULL);
CREATE INDEX devres_crate_jobs_due ON devres_crate_jobs(kind,due_at,source_key) WHERE state<>'running';
CREATE SEQUENCE devres_crate_content_sequence;
CREATE TABLE devres_crate_generations(id text PRIMARY KEY,published_sequence bigint UNIQUE,summary jsonb NOT NULL DEFAULT '{}'::jsonb);
CREATE TABLE devres_crate_content(generation text NOT NULL REFERENCES devres_crate_generations(id),id text NOT NULL,name text NOT NULL,version text NOT NULL,target text NOT NULL,path text NOT NULL,kind text NOT NULL,capture text NOT NULL REFERENCES devres_captures(id),metadata_capture text NOT NULL REFERENCES devres_captures(id),archive_capture text NOT NULL REFERENCES devres_captures(id),attributes jsonb NOT NULL,PRIMARY KEY(generation,id));
CREATE INDEX devres_crate_content_identity ON devres_crate_content(name,version,target,path,kind);
CREATE INDEX devres_crate_content_page ON devres_crate_content(id);
CREATE TABLE devres_crate_enrichment(artifact text NOT NULL REFERENCES devres_crate_artifacts(capture_id),kind text NOT NULL,external_id text NOT NULL,data jsonb NOT NULL,PRIMARY KEY(artifact,kind,external_id));
CREATE INDEX devres_crate_enrichment_name ON devres_crate_enrichment(artifact,kind,(data->>'name'));
CREATE INDEX devres_crate_enrichment_version ON devres_crate_enrichment(artifact,kind,(data->>'crate_id'),(data->>'num'));
CREATE TABLE devres_crate_enrichment_heads(sequence bigserial UNIQUE,artifact text PRIMARY KEY REFERENCES devres_crate_artifacts(capture_id));
CREATE TABLE devres_crate_snapshots(sequence bigserial UNIQUE,id text PRIMARY KEY,inventory text NOT NULL REFERENCES devres_crate_inventories(id),content_sequence bigint NOT NULL,data jsonb NOT NULL);
"#;
