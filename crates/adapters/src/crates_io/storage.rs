//! Schema-v3 crate inventories, immutable projections and resumable acquisition.
#[path = "storage_migration.rs"]
mod graph_migration;
use super::{PgBlobStore, hash, payload_integrity, storage_error, valid_hash};
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
    let id: String = row.try_get("id").map_err(|_| storage_error())?;
    let revision: String = row.try_get("revision").map_err(|_| storage_error())?;
    crate::integrity::verify(&id, format!("crate-inventory:1:{revision}").as_bytes())?;
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
        let hidden = self
            .visibility_aliases("crate", "inventories", None)
            .await?;
        sqlx::query(
            "SELECT * FROM devres_crate_inventories i WHERE NOT published AND NOT(i.id=ANY($1::text[])) ORDER BY sequence LIMIT 1",
        )
        .bind(hidden.as_ref()).fetch_optional(&self.pool)
        .await
        .map_err(|_| storage_error())?
        .map(inventory)
        .transpose()
    }
    async fn latest_inventory(&self) -> Result<Option<Inventory>> {
        self.fence().await?;
        let hidden = self
            .visibility_aliases("crate", "inventories", None)
            .await?;
        sqlx::query(
            "SELECT * FROM devres_crate_inventories i WHERE published AND NOT(i.id=ANY($1::text[])) ORDER BY sequence DESC LIMIT 1",
        )
        .bind(hidden.as_ref()).fetch_optional(&self.pool)
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
        crate::crates_io::packages::validate_name(name)?;
        if cursor.len() > 256
            || versions.len() > 50_000
            || versions
                .iter()
                .any(|r| r.name != name || !valid_hash(&r.metadata_capture))
        {
            return Err(Error::invalid("Invalid staged registry records."));
        }
        let mut rows = json_limit(&versions, 16 * 1024 * 1024)?;
        for row in rows
            .as_array_mut()
            .ok_or_else(|| Error::integrity("Invalid staged metadata batch."))?
        {
            let key = format!(
                "{}@{}",
                row["name"].as_str().ok_or_else(storage_error)?,
                row["version"].as_str().ok_or_else(storage_error)?
            );
            row["record_integrity"] = json!(payload_integrity::digest(
                "devres_crate_staging",
                epoch,
                &key,
                &payload_integrity::crate_staging_payload(
                    row["metadata_capture"].as_str().ok_or_else(storage_error)?,
                    &row["record"]
                )
            )?);
        }
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
        sqlx::query("INSERT INTO devres_crate_staging(inventory,name,version,metadata_capture,record,record_integrity) SELECT $1,r.name,r.version,r.metadata_capture,r.record,r.record_integrity FROM jsonb_to_recordset($2::jsonb) AS r(name text,version text,metadata_capture text,record jsonb,record_integrity text)").bind(epoch).bind(Json(rows)).execute(&mut *tx).await.map_err(|_|storage_error())?;
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
        close_crate_versions(&mut tx, epoch, inv.sequence).await?;
        let mut after = String::new();
        loop {
            let rows=sqlx::query("SELECT name,version,metadata_capture,record,record_integrity FROM devres_crate_staging WHERE inventory=$1 AND name||'@'||version>$2 ORDER BY name||'@'||version LIMIT 1000").bind(epoch).bind(&after).fetch_all(&mut *tx).await.map_err(|_|storage_error())?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                let name: String = row.try_get("name").map_err(|_| storage_error())?;
                let version: String = row.try_get("version").map_err(|_| storage_error())?;
                let key = format!("{name}@{version}");
                let data: Json<Value> = row.try_get("record").map_err(|_| storage_error())?;
                let expected: String = row
                    .try_get("record_integrity")
                    .map_err(|_| storage_error())?;
                let metadata: String = row
                    .try_get("metadata_capture")
                    .map_err(|_| storage_error())?;
                let data = payload_integrity::checked(
                    "devres_crate_staging",
                    epoch,
                    &key,
                    payload_integrity::crate_staging_payload(&metadata, &data.0),
                    &expected,
                )?["record"]
                    .clone();
                let digest = payload_integrity::digest(
                    "devres_crate_versions",
                    &inv.sequence.to_string(),
                    &key,
                    &payload_integrity::crate_record_payload(&metadata, None, &data),
                )?;
                sqlx::query("INSERT INTO devres_crate_versions(name,version,valid_from,metadata_capture,record,record_integrity) VALUES($1,$2,$3,$4,$5,$6)")
                    .bind(name).bind(version).bind(inv.sequence).bind(row.try_get::<String,_>("metadata_capture").map_err(|_|storage_error())?).bind(Json(data)).bind(digest).execute(&mut *tx).await.map_err(|_|storage_error())?;
                after = key;
            }
        }
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
        crate::crates_io::packages::validate_name(name)?;
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
        let rows=sqlx::query("SELECT v.name,v.version,v.valid_from,v.valid_to,v.metadata_capture,v.record,v.record_integrity,g.error AS metadata_error FROM devres_crate_versions v JOIN devres_crate_inventories i ON i.id=$1 AND i.published LEFT JOIN devres_crate_inventory_gaps g ON g.inventory=i.id AND g.name=v.name WHERE v.valid_from<=i.sequence AND (v.valid_to IS NULL OR v.valid_to>i.sequence) AND ((i.id LIKE 'blake3:%')=(SELECT id LIKE 'blake3:%' FROM devres_crate_inventories WHERE sequence=v.valid_from)) AND ($2::text IS NULL OR v.name=$2) AND ($3::text IS NULL OR v.name||'@'||v.version>$3) ORDER BY v.name||'@'||v.version LIMIT $4").bind(epoch).bind(name).bind(after).bind(limit as i64).fetch_all(&self.pool).await.map_err(|_|storage_error())?;
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
                    record: checked_version(&r)?,
                })
            })
            .collect()
    }
    async fn save_artifact(&self, artifact: &Artifact, http: bool) -> Result<()> {
        let c = &artifact.capture;
        checked_id(&c.id)?;
        checked_id(&c.body_hash)?;
        if !c.id.starts_with("blake3:") || !c.body_hash.starts_with("blake3:") {
            let retained = CrateCorpusStore::artifact(self, &c.id)
                .await?
                .ok_or_else(|| {
                    Error::integrity("New artifact captures require tagged BLAKE3 identities.")
                })?;
            if retained.capture.id != c.id
                || retained.capture.key != c.key
                || retained.capture.source_url != c.source_url
                || retained.capture.body_hash != c.body_hash
                || retained.capture.media_type != c.media_type
                || retained.capture.retrieved_at != c.retrieved_at
                || retained.bytes != artifact.bytes
                || retained.provenance != artifact.provenance
            {
                return Err(Error::integrity(
                    "Legacy artifact replay differs from retained evidence.",
                ));
            }
            return Ok(());
        }
        if artifact.bytes > 32 * 1024 * 1024 * 1024_u64
            || c.key.len() > 8192
            || c.source_url.len() > 8192
            || c.media_type.len() > 128
        {
            return Err(Error::capacity("Invalid bulk capture metadata."));
        }
        let provenance = json_limit(&artifact.provenance, 1024 * 1024)?;
        let archive = crate::bulk::BulkArtifactStore::new(&self.root, 64 * 1024 * 1024)?;
        let verified = archive
            .verify(
                &c.body_hash,
                crate::bulk::MAX_ARTIFACT_BYTES,
                tokio_util::sync::CancellationToken::new(),
            )
            .await?;
        if verified.bytes != artifact.bytes {
            return Err(Error::integrity("Bulk artifact length mismatch."));
        }
        let mut owner = self.owner.lock().await;
        owner.ping().await.map_err(|_| storage_error())?;
        let mut tx = owner.begin().await.map_err(|_| storage_error())?;
        sqlx::query("INSERT INTO devres_captures(id,source_key,source_url,body_hash,media_type,retrieved_at,metadata_integrity) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING").bind(&c.id).bind(&c.key).bind(&c.source_url).bind(&c.body_hash).bind(&c.media_type).bind(c.retrieved_at).bind(super::capture_metadata_digest(c)?).execute(&mut *tx).await.map_err(|_|storage_error())?;
        sqlx::query("INSERT INTO devres_crate_artifacts(capture_id,bytes,provenance,provenance_integrity) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING").bind(&c.id).bind(artifact.bytes as i64).bind(Json(&provenance)).bind(payload_integrity::digest("devres_crate_artifacts","",&c.id,&payload_integrity::crate_artifact_payload(artifact.bytes,&provenance))?).execute(&mut *tx).await.map_err(|_|storage_error())?;
        append_crate_observation(
            &mut tx,
            &c.id,
            c.validated_at,
            if http { "https" } else { "derived_or_git" },
            &artifact.provenance,
        )
        .await?;
        let retained=sqlx::query("SELECT provenance,provenance_integrity,bytes FROM devres_crate_artifacts WHERE capture_id=$1").bind(&c.id).fetch_one(&mut *tx).await.map_err(|_|storage_error())?;
        let retained_data: Json<Value> = retained
            .try_get("provenance")
            .map_err(|_| storage_error())?;
        payload_integrity::checked(
            "devres_crate_artifacts",
            "",
            &c.id,
            payload_integrity::crate_artifact_payload(
                u64::try_from(
                    retained
                        .try_get::<i64, _>("bytes")
                        .map_err(|_| storage_error())?,
                )
                .map_err(|_| Error::integrity("Invalid artifact length."))?,
                &retained_data.0,
            ),
            &retained
                .try_get::<String, _>("provenance_integrity")
                .map_err(|_| storage_error())?,
        )?;
        if retained
            .try_get::<i64, _>("bytes")
            .map_err(|_| storage_error())?
            != artifact.bytes as i64
        {
            return Err(Error::integrity("Artifact provenance identity collision."));
        }
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
        let row=sqlx::query("SELECT v.*,g.error AS metadata_error FROM devres_crate_versions v JOIN devres_crate_inventories i ON i.id=$1 AND i.published LEFT JOIN devres_crate_inventory_gaps g ON g.inventory=i.id AND g.name=v.name WHERE v.name=$2 AND v.version=$3 AND v.valid_from<=i.sequence AND (v.valid_to IS NULL OR v.valid_to>i.sequence) AND ((i.id LIKE 'blake3:%')=(SELECT id LIKE 'blake3:%' FROM devres_crate_inventories WHERE sequence=v.valid_from))").bind(epoch).bind(name).bind(version).fetch_optional(&self.pool).await.map_err(|_|storage_error())?;
        row.map(|r| {
            Ok(VersionRecord {
                name: r.try_get("name").map_err(|_| storage_error())?,
                version: r.try_get("version").map_err(|_| storage_error())?,
                metadata_capture: r.try_get("metadata_capture").map_err(|_| storage_error())?,
                metadata_status: r
                    .try_get::<Option<String>, _>("metadata_error")
                    .map_err(|_| storage_error())?
                    .map(|e| format!("stale_due_to_invalid_update:{e}")),
                record: checked_version(&r)?,
            })
        })
        .transpose()
    }
    async fn artifact(&self, id: &str) -> Result<Option<Artifact>> {
        checked_id(id)?;
        self.fence().await?;
        let row=sqlx::query("SELECT c.*,a.bytes,a.provenance,a.provenance_integrity,o.observed_at AS validated_at,o.sequence AS observed_sequence,o.transport AS observed_transport,o.provenance AS observed_provenance,o.provenance_integrity AS observed_integrity FROM devres_captures c JOIN devres_crate_artifacts a ON a.capture_id=c.id LEFT JOIN LATERAL(SELECT * FROM devres_crate_observations WHERE capture_id=c.id ORDER BY observed_at DESC LIMIT 1) o ON true WHERE c.id=$1").bind(id).fetch_optional(&self.pool).await.map_err(|_|storage_error())?;
        row.map(read_artifact).transpose()
    }
    async fn latest_artifact(&self, key: &str) -> Result<Option<Artifact>> {
        self.fence().await?;
        let row=sqlx::query("SELECT c.*,a.bytes,a.provenance,a.provenance_integrity,o.observed_at AS validated_at,o.sequence AS observed_sequence,o.transport AS observed_transport,o.provenance AS observed_provenance,o.provenance_integrity AS observed_integrity FROM devres_crate_observations o JOIN devres_captures c ON c.id=o.capture_id JOIN devres_crate_artifacts a ON a.capture_id=c.id WHERE c.source_key=$1 ORDER BY o.sequence DESC LIMIT 1").bind(key).fetch_optional(&self.pool).await.map_err(|_|storage_error())?;
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
        if crate::crates_io::packages::sparse_path(name)? != path
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
            crate::crates_io::packages::validate_name(&j.name)?;
            crate::crates_io::packages::validate_version(&j.version)?;
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
        self.fence().await?;
        if !generation.starts_with("blake3:") {
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM devres_crate_generations WHERE id=$1)",
            )
            .bind(generation)
            .fetch_one(&self.pool)
            .await
            .map_err(|_| storage_error())?;
            if !exists {
                return Err(Error::integrity(
                    "New content generations require tagged BLAKE3 identities.",
                ));
            }
        }
        for record in records {
            if !record.id.starts_with("blake3:") {
                let retained =
                    sqlx::query("SELECT * FROM devres_crate_content WHERE generation=$1 AND id=$2")
                        .bind(generation)
                        .bind(&record.id)
                        .fetch_optional(&self.pool)
                        .await
                        .map_err(|_| storage_error())?
                        .ok_or_else(|| {
                            Error::integrity(
                                "New content records require tagged BLAKE3 identities.",
                            )
                        })?;
                checked_attributes(&retained)?;
                if payload_integrity::crate_content_row(&retained)?
                    != serde_json::to_value(record).map_err(|_| storage_error())?
                {
                    return Err(Error::integrity(
                        "Legacy content replay differs from retained evidence.",
                    ));
                }
            }
        }
        if records.len() > 100 {
            return Err(Error::capacity("Content batch exceeds 100 records."));
        }
        for r in records {
            checked_id(&r.id)?;
            checked_id(&r.capture)?;
            checked_id(&r.metadata_capture)?;
            checked_id(&r.archive_capture)?;
            crate::crates_io::packages::validate_name(&r.name)?;
            crate::crates_io::packages::validate_version(&r.version)?;
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
        let mut value = json_limit(&records, 16 * 1024 * 1024)?;
        for row in value
            .as_array_mut()
            .ok_or_else(|| Error::integrity("Invalid content batch."))?
        {
            row["attributes_integrity"] = json!(payload_integrity::digest(
                "devres_crate_content",
                generation,
                row["id"].as_str().ok_or_else(storage_error)?,
                &*row
            )?);
        }
        let mut owner = self.owner.lock().await;
        owner.ping().await.map_err(|_| storage_error())?;
        let mut tx = owner.begin().await.map_err(|_| storage_error())?;
        sqlx::query("INSERT INTO devres_crate_generations(id,summary_integrity) VALUES($1,$2) ON CONFLICT DO NOTHING")
            .bind(generation).bind(payload_integrity::digest("devres_crate_generations","",generation,&payload_integrity::crate_generation_payload(None,&json!({}))?)?)
            .execute(&mut *tx)
            .await
            .map_err(|_| storage_error())?;
        let generation_row = sqlx::query("SELECT published_sequence,summary,summary_integrity FROM devres_crate_generations WHERE id=$1 FOR UPDATE")
            .bind(generation).fetch_one(&mut *tx).await.map_err(|_|storage_error())?;
        let published: Option<i64> = generation_row
            .try_get("published_sequence")
            .map_err(|_| storage_error())?;
        payload_integrity::checked(
            "devres_crate_generations",
            "",
            generation,
            payload_integrity::crate_generation_payload(
                published,
                &generation_row
                    .try_get::<Json<Value>, _>("summary")
                    .map_err(|_| storage_error())?
                    .0,
            )?,
            &generation_row
                .try_get::<String, _>("summary_integrity")
                .map_err(|_| storage_error())?,
        )?;
        let committed = published.is_some();
        if !committed {
            sqlx::query("INSERT INTO devres_crate_content(generation,id,name,version,target,path,kind,capture,metadata_capture,archive_capture,attributes,attributes_integrity) SELECT $1,r.id,r.name,r.version,r.target,r.path,r.kind,r.capture,r.metadata_capture,r.archive_capture,r.attributes,r.attributes_integrity FROM jsonb_to_recordset($2::jsonb) AS r(id text,name text,version text,target text,path text,kind text,capture text,metadata_capture text,archive_capture text,attributes jsonb,attributes_integrity text) ON CONFLICT(generation,id) DO NOTHING").bind(generation).bind(Json(value)).execute(&mut *tx).await.map_err(|_|storage_error())?;
        } else {
            for record in records {
                let existing:Option<Json<Value>>=sqlx::query_scalar("SELECT to_jsonb(c)-'generation'-'attributes_integrity' FROM devres_crate_content c WHERE generation=$1 AND id=$2").bind(generation).bind(&record.id).fetch_optional(&mut *tx).await.map_err(|_|storage_error())?;
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
        for record in records {
            let retained =
                sqlx::query("SELECT * FROM devres_crate_content WHERE generation=$1 AND id=$2")
                    .bind(generation)
                    .bind(&record.id)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(|_| storage_error())?;
            let attributes = checked_attributes(&retained)?;
            if attributes != record.attributes {
                return Err(Error::integrity("Immutable content attributes collision."));
            }
        }
        tx.commit().await.map_err(|_| storage_error())
    }
    async fn commit_content(&self, generation: &str, summary: Value) -> Result<()> {
        checked_id(generation)?;
        self.fence().await?;
        let summary = json_limit(&summary, 1024 * 1024)?;
        let mut owner = self.owner.lock().await;
        owner.ping().await.map_err(|_| storage_error())?;
        let mut tx = owner.begin().await.map_err(|_| storage_error())?;
        let retained = sqlx::query("SELECT published_sequence,summary,summary_integrity FROM devres_crate_generations WHERE id=$1 FOR UPDATE")
            .bind(generation).fetch_optional(&mut *tx).await.map_err(|_|storage_error())?;
        if let Some(row) = retained {
            let published: Option<i64> = row
                .try_get("published_sequence")
                .map_err(|_| storage_error())?;
            let stored: Json<Value> = row.try_get("summary").map_err(|_| storage_error())?;
            payload_integrity::checked(
                "devres_crate_generations",
                "",
                generation,
                payload_integrity::crate_generation_payload(published, &stored.0)?,
                &row.try_get::<String, _>("summary_integrity")
                    .map_err(|_| storage_error())?,
            )?;
            if published.is_some() {
                if !generation.starts_with("blake3:") && stored.0 != summary {
                    return Err(Error::integrity(
                        "Legacy generation replay differs from retained publication.",
                    ));
                }
                return tx.commit().await.map_err(|_| storage_error());
            }
            if !generation.starts_with("blake3:") {
                return Err(Error::integrity(
                    "New content generations require tagged BLAKE3 identities.",
                ));
            }
        } else if !generation.starts_with("blake3:") {
            return Err(Error::integrity(
                "New content generations require tagged BLAKE3 identities.",
            ));
        }
        let sequence: i64 = sqlx::query_scalar("SELECT nextval('devres_crate_content_sequence')")
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| storage_error())?;
        let digest = payload_integrity::digest(
            "devres_crate_generations",
            "",
            generation,
            &payload_integrity::crate_generation_payload(Some(sequence), &summary)?,
        )?;
        sqlx::query("INSERT INTO devres_crate_generations(id,published_sequence,summary,summary_integrity) VALUES($1,$2,$3,$4) ON CONFLICT(id) DO UPDATE SET published_sequence=EXCLUDED.published_sequence,summary=EXCLUDED.summary,summary_integrity=EXCLUDED.summary_integrity")
            .bind(generation).bind(sequence).bind(Json(&summary)).bind(digest).execute(&mut *tx).await.map_err(|_|storage_error())?;
        tx.commit().await.map_err(|_| storage_error())
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
        let hidden = self
            .visibility_aliases("crate", "generations", Some(cutoff))
            .await?;
        let rows=sqlx::query("SELECT * FROM (SELECT DISTINCT ON(c.name,c.version,c.target,c.path,c.kind) c.*,g.summary AS generation_summary,g.published_sequence AS generation_sequence,g.summary_integrity AS generation_integrity FROM devres_crate_content c JOIN devres_crate_generations g ON g.id=c.generation WHERE g.published_sequence<=$1 AND NOT(g.id=ANY($9::text[])) AND g.published_sequence IN(SELECT max(published_sequence) FROM devres_crate_generations WHERE published_sequence<=$1 GROUP BY COALESCE(summary->>'job_key',id)) AND ($2::text IS NULL OR c.name=$2) AND ($3::text IS NULL OR c.version=$3) AND ($4::text IS NULL OR c.target=$4) AND ($5::text IS NULL OR c.path=$5) AND ($6::text IS NULL OR c.kind=$6) ORDER BY c.name,c.version,c.target,c.path,c.kind,g.published_sequence DESC) q WHERE ($7::text IS NULL OR id>$7) ORDER BY id LIMIT $8").bind(cutoff).bind(&filter.name).bind(&filter.version).bind(&filter.target).bind(&filter.path).bind(&filter.kind).bind(after).bind(limit as i64).bind(hidden.as_ref()).fetch_all(&self.pool).await.map_err(|_|storage_error())?;
        rows.into_iter()
            .map(|r| {
                payload_integrity::checked(
                    "devres_crate_generations",
                    "",
                    &r.try_get::<String, _>("generation")
                        .map_err(|_| storage_error())?,
                    payload_integrity::crate_generation_payload(
                        r.try_get("generation_sequence")
                            .map_err(|_| storage_error())?,
                        &r.try_get::<Json<Value>, _>("generation_summary")
                            .map_err(|_| storage_error())?
                            .0,
                    )?,
                    &r.try_get::<String, _>("generation_integrity")
                        .map_err(|_| storage_error())?,
                )?;
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
                    attributes: checked_attributes(&r)?,
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
            .map(|(id,value)|Ok(json!({"id":id,"value":value,"integrity":payload_integrity::digest("devres_crate_enrichment",&format!("{artifact}:{kind}"),id,value)?})))
            .collect::<Result<Vec<_>>>()?.into_iter()
            .collect();
        let value = json_limit(&values, 8 * 1024 * 1024)?;
        let mut owner = self.owner.lock().await;
        owner.ping().await.map_err(|_| storage_error())?;
        let mut tx = owner.begin().await.map_err(|_| storage_error())?;
        sqlx::query("INSERT INTO devres_crate_enrichment(artifact,kind,external_id,data,data_integrity) SELECT $1,$2,r.id,r.value,r.integrity FROM jsonb_to_recordset($3::jsonb) AS r(id text,value jsonb,integrity text) ON CONFLICT DO NOTHING").bind(artifact).bind(kind).bind(Json(value)).execute(&mut *tx).await.map_err(|_|storage_error())?;
        let ids = rows.iter().map(|(id, _)| id.clone()).collect::<Vec<_>>();
        let retained=sqlx::query("SELECT external_id,data,data_integrity FROM devres_crate_enrichment WHERE artifact=$1 AND kind=$2 AND external_id=ANY($3::text[])").bind(artifact).bind(kind).bind(&ids).fetch_all(&mut *tx).await.map_err(|_|storage_error())?;
        for row in retained {
            let key: String = row.try_get("external_id").map_err(|_| storage_error())?;
            let data = payload_integrity::checked(
                "devres_crate_enrichment",
                &format!("{artifact}:{kind}"),
                &key,
                row.try_get::<Json<Value>, _>("data")
                    .map_err(|_| storage_error())?
                    .0,
                &row.try_get::<String, _>("data_integrity")
                    .map_err(|_| storage_error())?,
            )?;
            if rows
                .iter()
                .find(|(id, _)| *id == key)
                .is_none_or(|(_, expected)| *expected != data)
            {
                return Err(Error::integrity("Immutable enrichment identity collision."));
            }
        }
        tx.commit().await.map_err(|_| storage_error())
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
        let hidden = self
            .visibility_aliases("crate", "generations", Some(cutoff))
            .await?;
        if !matches!(kind, "api" | "text") {
            return Err(Error::invalid("Comparison kind must be api or text."));
        }
        let rows:Vec<Json<Value>>=sqlx::query_scalar("WITH latest AS (SELECT DISTINCT ON(c.version,c.target,c.path,c.kind) c.*,b.body_hash,g.published_sequence AS generation_sequence,g.summary AS generation_summary,g.summary_integrity AS generation_integrity FROM devres_crate_content c JOIN devres_crate_generations g ON g.id=c.generation JOIN devres_captures b ON b.id=c.capture WHERE c.name=$2 AND c.version IN($3,$4) AND g.published_sequence<=$1 AND NOT(g.id=ANY($9::text[])) AND g.published_sequence IN(SELECT max(published_sequence) FROM devres_crate_generations WHERE published_sequence<=$1 GROUP BY COALESCE(summary->>'job_key',id)) AND ($5::text IS NULL OR c.target=$5) AND (($6='api' AND c.kind='api') OR ($6='text' AND c.kind IN('source','manifest','readme','license'))) ORDER BY c.version,c.target,c.path,c.kind,g.published_sequence DESC), a AS(SELECT * FROM latest WHERE version=$3), b AS(SELECT * FROM latest WHERE version=$4), changes AS(SELECT COALESCE(a.target,b.target)||chr(31)||COALESCE(a.path,b.path) AS cursor,COALESCE(a.path,b.path) AS path,COALESCE(a.target,b.target) AS target,CASE WHEN a.id IS NULL THEN 'added' WHEN b.id IS NULL THEN 'removed' WHEN $6='api' AND a.attributes->'format_version' IS DISTINCT FROM b.attributes->'format_version' THEN 'uncomparable' WHEN $6='api' AND a.attributes->'signature' IS NOT DISTINCT FROM b.attributes->'signature' THEN 'unchanged' WHEN $6='text' AND a.body_hash=b.body_hash THEN 'unchanged' ELSE 'changed' END AS change,to_jsonb(a)-'body_hash' AS old,to_jsonb(b)-'body_hash' AS new FROM a FULL JOIN b ON a.target=b.target AND a.path=b.path) SELECT jsonb_build_object('cursor',cursor,'path',path,'target',target,'change',change,'from',old,'to',new) FROM changes WHERE change<>'unchanged' AND ($7::text IS NULL OR cursor>$7) ORDER BY cursor LIMIT $8").bind(cutoff).bind(name).bind(from).bind(to).bind(target).bind(kind).bind(after).bind(limit as i64).bind(hidden.as_ref()).fetch_all(&self.pool).await.map_err(|_|storage_error())?;
        rows.into_iter()
            .map(|Json(mut value)| {
                for side in ["from", "to"] {
                    if value[side].is_null() {
                        continue;
                    }
                    let item = &value[side];
                    payload_integrity::checked(
                        "devres_crate_generations",
                        "",
                        item["generation"].as_str().ok_or_else(storage_error)?,
                        payload_integrity::crate_generation_payload(
                            Some(
                                item["generation_sequence"]
                                    .as_i64()
                                    .ok_or_else(storage_error)?,
                            ),
                            &item["generation_summary"],
                        )?,
                        item["generation_integrity"]
                            .as_str()
                            .ok_or_else(storage_error)?,
                    )?;
                    payload_integrity::checked(
                        "devres_crate_content",
                        item["generation"].as_str().ok_or_else(storage_error)?,
                        item["id"].as_str().ok_or_else(storage_error)?,
                        {
                            let mut payload = item.clone();
                            let object = payload.as_object_mut().ok_or_else(storage_error)?;
                            object.remove("generation");
                            object.remove("attributes_integrity");
                            object.remove("generation_sequence");
                            object.remove("generation_summary");
                            object.remove("generation_integrity");
                            payload
                        },
                        item["attributes_integrity"]
                            .as_str()
                            .ok_or_else(storage_error)?,
                    )?;
                    if let Some(object) = value[side].as_object_mut() {
                        object.remove("generation");
                        object.remove("attributes_integrity");
                        object.remove("generation_sequence");
                        object.remove("generation_summary");
                        object.remove("generation_integrity");
                    }
                }
                Ok(value)
            })
            .collect()
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
        let hidden = self
            .visibility_aliases("crate", "generations", Some(cutoff))
            .await?;
        let rows=sqlx::query("SELECT published_sequence,''::text AS kind,id AS key,summary AS data,summary_integrity AS data_integrity FROM devres_crate_generations WHERE published_sequence IN(SELECT max(published_sequence) FROM devres_crate_generations WHERE published_sequence<=$1 AND NOT(id=ANY($6::text[])) AND summary->>'name'=$2 AND summary->>'version'=$3 AND summary->>'kind'=$4 AND ($5::text IS NULL OR summary->>'target'=$5) GROUP BY COALESCE(summary->>'job_key',id)) ORDER BY summary->>'target' LIMIT 1001").bind(cutoff).bind(name).bind(version).bind(kind).bind(target).bind(hidden.as_ref()).fetch_all(&self.pool).await.map_err(|_|storage_error())?;
        rows.into_iter()
            .map(|row| payload_integrity::row("devres_crate_generations", &row))
            .collect()
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
        let Some(found)=sqlx::query("SELECT external_id,data,data_integrity FROM devres_crate_enrichment WHERE artifact=$1 AND kind='crates' AND lower(data->>'name')=lower($2) LIMIT 1")
            .bind(artifact).bind(name).fetch_optional(&self.pool).await.map_err(|_|storage_error())? else{return Ok(json!({}));};
        let crate_id: String = found.try_get("external_id").map_err(|_| storage_error())?;
        let crate_data = checked_enrichment(artifact, "crates", &found)?;
        let version_data=sqlx::query("SELECT external_id,data,data_integrity FROM devres_crate_enrichment WHERE artifact=$1 AND kind='versions' AND data->>'crate_id'=$2 AND data->>'num'=$3 LIMIT 1")
            .bind(artifact).bind(&crate_id).bind(version).fetch_optional(&self.pool).await.map_err(|_|storage_error())?
            .map(|row|checked_enrichment(artifact,"versions",&row)).transpose()?.unwrap_or(Value::Null);
        let mut result = json!({"crate":crate_data,"version":version_data,"artifact":artifact});
        for (relation, target, reference, field, output) in [
            (
                "crates_keywords",
                "keywords",
                "keyword_id",
                "keyword",
                "keywords",
            ),
            (
                "crates_categories",
                "categories",
                "category_id",
                "slug",
                "categories",
            ),
        ] {
            let rows=sqlx::query("SELECT external_id,data,data_integrity FROM devres_crate_enrichment WHERE artifact=$1 AND kind=$2 AND data->>'crate_id'=$3 LIMIT 1025")
                .bind(artifact).bind(relation).bind(&crate_id).fetch_all(&self.pool).await.map_err(|_|storage_error())?;
            if rows.len() > 1024 {
                return Err(Error::capacity(
                    "Metadata enrichment relation bound exceeded.",
                ));
            }
            let mut values = Vec::new();
            for row in rows {
                let relation_data = checked_enrichment(artifact, relation, &row)?;
                let Some(key) = json_text(&relation_data[reference]) else {
                    continue;
                };
                if let Some(found)=sqlx::query("SELECT external_id,data,data_integrity FROM devres_crate_enrichment WHERE artifact=$1 AND kind=$2 AND external_id=$3")
                    .bind(artifact).bind(target).bind(key).fetch_optional(&self.pool).await.map_err(|_|storage_error())? {
                    let data=checked_enrichment(artifact,target,&found)?;
                    values.push(json_text(&data[field]));
                }
            }
            values.sort_by(|a, b| match (a, b) {
                (None, None) => std::cmp::Ordering::Equal,
                (None, _) => std::cmp::Ordering::Greater,
                (_, None) => std::cmp::Ordering::Less,
                (Some(a), Some(b)) => a.cmp(b),
            });
            result[output] = serde_json::to_value(values).map_err(|_| storage_error())?;
        }
        json_limit(&result, 2 * 1024 * 1024)?;
        Ok(result)
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
        let versions:i64=sqlx::query_scalar("SELECT count(*) FROM devres_crate_versions v WHERE valid_from<=$1 AND (valid_to IS NULL OR valid_to>$1) AND ($2=(SELECT id LIKE 'blake3:%' FROM devres_crate_inventories WHERE sequence=v.valid_from))").bind(inv.sequence).bind(inv.id.starts_with("blake3:")).fetch_one(&mut *tx).await.map_err(|_|storage_error())?;
        let gaps: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM devres_crate_inventory_gaps WHERE inventory=$1",
        )
        .bind(epoch)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| storage_error())?;
        let hidden = self
            .visibility_aliases("crate", "generations", Some(cutoff))
            .await?;
        {
            use futures::TryStreamExt;
            let mut stream=sqlx::query("SELECT published_sequence,''::text AS kind,id AS key,summary AS data,summary_integrity AS data_integrity FROM devres_crate_generations g WHERE published_sequence<=$1 AND NOT(g.id=ANY($2::text[]))").bind(cutoff).bind(hidden.as_ref()).fetch(&mut *tx);
            while let Some(row) = stream.try_next().await.map_err(|_| storage_error())? {
                payload_integrity::row("devres_crate_generations", &row)?;
            }
        }
        let processing:Json<Value>=sqlx::query_scalar("SELECT jsonb_build_object('published_generations',count(*),'skipped_binary',COALESCE(sum((summary->>'skipped_binary')::bigint),0),'skipped_oversized',COALESCE(sum((summary->>'skipped_oversized')::bigint),0),'unresolved_references',COALESCE(sum((summary->>'unresolved_references')::bigint),0)) FROM devres_crate_generations g WHERE published_sequence<=$1 AND NOT(g.id=ANY($2::text[]))").bind(cutoff).bind(hidden.as_ref()).fetch_one(&mut *tx).await.map_err(|_|storage_error())?;
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
        let sequence: i64 = sqlx::query_scalar(
            "SELECT nextval(pg_get_serial_sequence('devres_crate_snapshots','sequence'))",
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| storage_error())?;
        sqlx::query("INSERT INTO devres_crate_snapshots(id,inventory,content_sequence,data,data_integrity,sequence) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING").bind(&snapshot.id).bind(&snapshot.inventory.id).bind(snapshot.content_sequence).bind(Json(&encoded)).bind(payload_integrity::digest("devres_crate_snapshots","",&snapshot.id,&payload_integrity::crate_snapshot_payload(sequence,&snapshot.inventory.id,snapshot.content_sequence,&encoded)?)?).bind(sequence).execute(&mut *tx).await.map_err(|_|storage_error())?;
        let retained: Json<Value> =
            payload_integrity::load(&mut *tx, "devres_crate_snapshots", "", &snapshot.id)
                .await?
                .ok_or_else(|| Error::integrity("Crate snapshot missing."))?;
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
        let value=sqlx::query("SELECT sequence,inventory,content_sequence,''::text AS kind,id AS key,data,data_integrity FROM devres_crate_snapshots WHERE ($1::text IS NULL OR id=$1) ORDER BY sequence DESC LIMIT 1").bind(id).fetch_optional(&self.pool).await.map_err(|_|storage_error())?;
        value
            .map(|v| {
                serde_json::from_value(payload_integrity::row("devres_crate_snapshots", &v)?)
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
fn json_text(value: &Value) -> Option<String> {
    match value {
        Value::Null => None,
        Value::String(value) => Some(value.clone()),
        value => Some(value.to_string()),
    }
}
fn checked_enrichment(artifact: &str, kind: &str, row: &sqlx::postgres::PgRow) -> Result<Value> {
    payload_integrity::checked(
        "devres_crate_enrichment",
        &format!("{artifact}:{kind}"),
        &row.try_get::<String, _>("external_id")
            .map_err(|_| storage_error())?,
        row.try_get::<Json<Value>, _>("data")
            .map_err(|_| storage_error())?
            .0,
        &row.try_get::<String, _>("data_integrity")
            .map_err(|_| storage_error())?,
    )
}
fn checked_version(row: &sqlx::postgres::PgRow) -> Result<Value> {
    let key = format!(
        "{}@{}",
        row.try_get::<String, _>("name")
            .map_err(|_| storage_error())?,
        row.try_get::<String, _>("version")
            .map_err(|_| storage_error())?
    );
    let record: Json<Value> = row.try_get("record").map_err(|_| storage_error())?;
    let payload = payload_integrity::crate_record_payload(
        &row.try_get::<String, _>("metadata_capture")
            .map_err(|_| storage_error())?,
        row.try_get::<Option<i64>, _>("valid_to")
            .map_err(|_| storage_error())?,
        &record.0,
    );
    payload_integrity::checked(
        "devres_crate_versions",
        &row.try_get::<i64, _>("valid_from")
            .map_err(|_| storage_error())?
            .to_string(),
        &key,
        payload,
        &row.try_get::<String, _>("record_integrity")
            .map_err(|_| storage_error())?,
    )?;
    Ok(record.0)
}
fn checked_attributes(row: &sqlx::postgres::PgRow) -> Result<Value> {
    let payload = payload_integrity::crate_content_row(row)?;
    let attributes = payload["attributes"].clone();
    payload_integrity::checked(
        "devres_crate_content",
        &row.try_get::<String, _>("generation")
            .map_err(|_| storage_error())?,
        &row.try_get::<String, _>("id")
            .map_err(|_| storage_error())?,
        payload,
        &row.try_get::<String, _>("attributes_integrity")
            .map_err(|_| storage_error())?,
    )?;
    Ok(attributes)
}
fn read_artifact(row: sqlx::postgres::PgRow) -> Result<Artifact> {
    let capture = Capture {
        id: row.try_get("id").map_err(|_| storage_error())?,
        key: row.try_get("source_key").map_err(|_| storage_error())?,
        source_url: row.try_get("source_url").map_err(|_| storage_error())?,
        body_hash: row.try_get("body_hash").map_err(|_| storage_error())?,
        media_type: row.try_get("media_type").map_err(|_| storage_error())?,
        retrieved_at: row.try_get("retrieved_at").map_err(|_| storage_error())?,
        validated_at: row.try_get("validated_at").map_err(|_| storage_error())?,
    };
    if super::capture_metadata_digest(&capture)?
        != row
            .try_get::<String, _>("metadata_integrity")
            .map_err(|_| storage_error())?
    {
        return Err(Error::integrity("Capture metadata integrity failed."));
    }
    let bytes = u64::try_from(
        row.try_get::<i64, _>("bytes")
            .map_err(|_| storage_error())?,
    )
    .map_err(|_| Error::integrity("Invalid artifact size."))?;
    let observation: Json<Value> = row
        .try_get("observed_provenance")
        .map_err(|_| storage_error())?;
    let transport: String = row
        .try_get("observed_transport")
        .map_err(|_| storage_error())?;
    let sequence: i64 = row
        .try_get("observed_sequence")
        .map_err(|_| storage_error())?;
    payload_integrity::checked(
        "devres_crate_observations",
        &capture.id,
        &sequence.to_string(),
        payload_integrity::crate_observation_payload(
            &capture.id,
            capture.validated_at,
            &transport,
            &observation.0,
        ),
        &row.try_get::<String, _>("observed_integrity")
            .map_err(|_| storage_error())?,
    )?;
    let provenance: Json<Value> = row.try_get("provenance").map_err(|_| storage_error())?;
    payload_integrity::checked(
        "devres_crate_artifacts",
        "",
        &capture.id,
        payload_integrity::crate_artifact_payload(bytes, &provenance.0),
        &row.try_get::<String, _>("provenance_integrity")
            .map_err(|_| storage_error())?,
    )?;
    Ok(Artifact {
        capture,
        bytes,
        provenance: provenance.0,
    })
}
async fn append_crate_observation(
    tx: &mut sqlx::PgConnection,
    capture: &str,
    time: i64,
    transport: &str,
    provenance: &Value,
) -> Result<i64> {
    let sequence: i64 = sqlx::query_scalar(
        "SELECT nextval(pg_get_serial_sequence('devres_crate_observations','sequence'))",
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| storage_error())?;
    let payload =
        payload_integrity::crate_observation_payload(capture, time, transport, provenance);
    let digest = payload_integrity::digest(
        "devres_crate_observations",
        capture,
        &sequence.to_string(),
        &payload,
    )?;
    sqlx::query("INSERT INTO devres_crate_observations(sequence,capture_id,observed_at,transport,provenance,provenance_integrity) VALUES($1,$2,$3,$4,$5,$6)").bind(sequence).bind(capture).bind(time).bind(transport).bind(Json(provenance)).bind(digest).execute(&mut *tx).await.map_err(|_|storage_error())?;
    Ok(sequence)
}
async fn close_crate_versions(
    tx: &mut sqlx::PgConnection,
    epoch: &str,
    sequence: i64,
) -> Result<()> {
    let mut after = (String::new(), String::new(), 0_i64);
    loop {
        let row=sqlx::query("SELECT v.* FROM devres_crate_versions v WHERE v.valid_to IS NULL AND (v.name,v.version,v.valid_from)>($2,$3,$4) AND EXISTS(SELECT 1 FROM devres_crate_changes c WHERE c.inventory=$1 AND c.name=v.name) AND ((SELECT id LIKE 'blake3:%' FROM devres_crate_inventories WHERE id=$1)=(SELECT id LIKE 'blake3:%' FROM devres_crate_inventories WHERE sequence=v.valid_from)) ORDER BY v.name,v.version,v.valid_from LIMIT 1 FOR UPDATE OF v")
            .bind(epoch).bind(&after.0).bind(&after.1).bind(after.2).fetch_optional(&mut *tx).await.map_err(|_|storage_error())?;
        let Some(row) = row else {
            break;
        };
        let record = checked_version(&row)?;
        let name: String = row.try_get("name").map_err(|_| storage_error())?;
        let version: String = row.try_get("version").map_err(|_| storage_error())?;
        let from: i64 = row.try_get("valid_from").map_err(|_| storage_error())?;
        let metadata: String = row
            .try_get("metadata_capture")
            .map_err(|_| storage_error())?;
        let digest = payload_integrity::digest(
            "devres_crate_versions",
            &from.to_string(),
            &format!("{name}@{version}"),
            &payload_integrity::crate_record_payload(&metadata, Some(sequence), &record),
        )?;
        let changed=sqlx::query("UPDATE devres_crate_versions SET valid_to=$4,record_integrity=$5 WHERE name=$1 AND version=$2 AND valid_from=$3 AND valid_to IS NULL").bind(&name).bind(&version).bind(from).bind(sequence).bind(digest).execute(&mut *tx).await.map_err(|_|storage_error())?;
        if changed.rows_affected() != 1 {
            return Err(Error::integrity(
                "Crate version interval changed during publication.",
            ));
        }
        after = (name, version, from);
    }
    Ok(())
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
