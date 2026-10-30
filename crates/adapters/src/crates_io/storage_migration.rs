//! Offline canonical crate graph copies. Legacy rows and source bytes are retained.
use super::*;
use std::{collections::BTreeMap, sync::Arc};
use tokio_util::sync::CancellationToken;

fn stop(cancel: &CancellationToken) -> Result<()> {
    if cancel.is_cancelled() {
        Err(Error::new("cancelled", "Crate graph migration canceled."))
    } else {
        Ok(())
    }
}
fn mapped(maps: &crate::migration_map::MigrationMap, role: &str, id: &str) -> Result<String> {
    if id.starts_with("blake3:") && valid_hash(id) {
        return Ok(id.into());
    }
    maps.get(&format!("{role}:{id}"))
        .ok_or_else(|| Error::integrity("Unresolved crate migration reference."))
}
fn remap_fields(value: &mut Value, maps: &crate::migration_map::MigrationMap) -> Result<()> {
    let Some(object) = value.as_object_mut() else {
        return Ok(());
    };
    for field in [
        "capture",
        "source_capture",
        "metadata_capture",
        "archive_capture",
        "artifact",
        "platform_capture",
    ] {
        if let Some(Value::String(id)) = object.get_mut(field) {
            *id = mapped(maps, "capture", id)?;
        }
    }
    Ok(())
}
fn id_alias(
    maps: &mut crate::migration_map::MigrationMap,
    aliases: &mut crate::migration_map::MigrationAliases,
    kind: &str,
    old: &str,
    new: &str,
) -> Result<()> {
    let key = format!("crate:{kind}:{old}");
    if maps.get(&key).is_some_and(|value| value != new) {
        return Err(Error::integrity("Conflicting crate migration identity."));
    }
    if maps.get(&key).is_some_and(|value| value == new) {
        return Ok(());
    }
    crate::migration_map::insert(maps, key, new.into())?;
    {
        let alias = (kind.into(), old.into(), new.into());
        aliases.push(alias)?;
    }
    Ok(())
}

impl PgBlobStore {
    pub async fn migrate_crate_graph(
        self: &Arc<Self>,
        maps: &mut crate::migration_map::MigrationMap,
        cancel: CancellationToken,
    ) -> Result<crate::migration_map::MigrationAliases> {
        self.fence().await?;
        let mut aliases = crate::migration_map::MigrationAliases::new(maps)?;
        self.migrate_crate_artifacts(maps, &cancel).await?;
        self.migrate_crate_inventories(maps, &mut aliases, &cancel)
            .await?;
        let generations = self
            .migrate_crate_generations(maps, &mut aliases, &cancel)
            .await?;
        self.migrate_crate_enrichment(maps, &cancel).await?;
        let mut after = 0_i64;
        loop {
            stop(&cancel)?;
            let row=sqlx::query("SELECT sequence,inventory,content_sequence,''::text AS kind,id AS key,data,data_integrity FROM devres_crate_snapshots WHERE id NOT LIKE 'blake3:%' AND sequence>$1 ORDER BY sequence LIMIT 1").bind(after).fetch_optional(&self.pool).await.map_err(|_|storage_error())?;
            let Some(row) = row else {
                break;
            };
            after = row.try_get("sequence").map_err(|_| storage_error())?;
            let old: String = row.try_get("key").map_err(|_| storage_error())?;
            let mut snapshot: Snapshot =
                serde_json::from_value(payload_integrity::row("devres_crate_snapshots", &row)?)
                    .map_err(|_| storage_error())?;
            let old_index = snapshot.index_manifest.take();
            let inventory_id = mapped(maps, "crate:inventories", &snapshot.inventory.id)?;
            snapshot.inventory = inventory(
                sqlx::query("SELECT * FROM devres_crate_inventories WHERE id=$1")
                    .bind(&inventory_id)
                    .fetch_one(&self.pool)
                    .await
                    .map_err(|_| storage_error())?,
            )?;
            snapshot.content_sequence = *generations
                .range(..=snapshot.content_sequence)
                .next_back()
                .map(|(_, value)| value)
                .unwrap_or(&0);
            if let Some(id) = &snapshot.enrichment {
                snapshot.enrichment = Some(mapped(maps, "capture", id)?);
            }
            remap_fields(&mut snapshot.coverage, maps)?;
            snapshot.coverage["content_sequence"] = json!(snapshot.content_sequence);
            if !old_index.is_null() {
                let maps = Arc::new(maps.clone());
                let rewrite = Arc::new(move |value: &mut Value| -> Result<()> {
                    let is_content = value["class"] == "content";
                    if let Some(record) = value.get_mut("record") {
                        remap_fields(record, &maps)?;
                        if is_content {
                            let id = record["id"].as_str().ok_or_else(storage_error)?.to_owned();
                            record["id"] = json!(mapped(&maps, "crate:content", &id)?);
                        }
                    } else {
                        remap_fields(value, &maps)?;
                    }
                    if let Some(enrichment) = value.get_mut("enrichment") {
                        remap_fields(enrichment, &maps)?;
                    }
                    Ok(())
                });
                snapshot.index_manifest = crate::crates_io::index::rebuild_frozen(
                    self.clone(),
                    self.root.clone(),
                    old_index,
                    snapshot.clone(),
                    rewrite,
                    cancel.child_token(),
                )
                .await?;
            }
            let snapshot = self.commit_snapshot(snapshot).await?;
            id_alias(maps, &mut aliases, "snapshots", &old, &snapshot.id)?;
        }
        let mut after = String::new();
        loop {
            stop(&cancel)?;
            let row=sqlx::query("SELECT source_key,metadata_capture,artifact FROM devres_crate_jobs WHERE source_key>$1 ORDER BY source_key LIMIT 1").bind(&after).fetch_optional(&self.pool).await.map_err(|_|storage_error())?;
            let Some(row) = row else {
                break;
            };
            let key: String = row.try_get("source_key").map_err(|_| storage_error())?;
            let metadata: String = row
                .try_get("metadata_capture")
                .map_err(|_| storage_error())?;
            let artifact: Option<String> = row.try_get("artifact").map_err(|_| storage_error())?;
            payload_integrity::stage(self,"crate",&format!("job:{key}"),&json!({"source_key":key,"metadata_capture":mapped(maps,"capture",&metadata)?,"artifact":artifact.as_deref().map(|id|mapped(maps,"capture",id)).transpose()?})).await?;
            after = key;
        }
        maps.ensure_healthy()?;
        aliases.ensure_healthy()?;
        Ok(aliases)
    }

    async fn migrate_crate_artifacts(
        &self,
        maps: &crate::migration_map::MigrationMap,
        cancel: &CancellationToken,
    ) -> Result<()> {
        let mut after = String::new();
        loop {
            stop(cancel)?;
            let row=sqlx::query("SELECT capture_id,bytes,provenance,provenance_integrity FROM devres_crate_artifacts WHERE capture_id NOT LIKE 'blake3:%' AND capture_id>$1 ORDER BY capture_id LIMIT 1").bind(&after).fetch_optional(&self.pool).await.map_err(|_|storage_error())?;
            let Some(row) = row else {
                break;
            };
            let old: String = row.try_get("capture_id").map_err(|_| storage_error())?;
            let new = mapped(maps, "capture", &old)?;
            let data = payload_integrity::checked(
                "devres_crate_artifacts",
                "",
                &old,
                payload_integrity::crate_artifact_payload(
                    u64::try_from(
                        row.try_get::<i64, _>("bytes")
                            .map_err(|_| storage_error())?,
                    )
                    .map_err(|_| Error::integrity("Invalid artifact length."))?,
                    &row.try_get::<Json<Value>, _>("provenance")
                        .map_err(|_| storage_error())?
                        .0,
                ),
                &row.try_get::<String, _>("provenance_integrity")
                    .map_err(|_| storage_error())?,
            )?;
            let mut data = data["provenance"].clone();
            remap_fields(&mut data, maps)?;
            sqlx::query("INSERT INTO devres_crate_artifacts(capture_id,bytes,provenance,provenance_integrity) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING").bind(&new).bind(row.try_get::<i64,_>("bytes").map_err(|_|storage_error())?).bind(Json(&data)).bind(payload_integrity::digest("devres_crate_artifacts","",&new,&payload_integrity::crate_artifact_payload(u64::try_from(row.try_get::<i64,_>("bytes").map_err(|_|storage_error())?).map_err(|_|Error::integrity("Invalid artifact length."))?,&data))?).execute(&mut *self.owner.lock().await).await.map_err(|_|storage_error())?;
            after = old;
        }
        let mut after = 0_i64;
        loop {
            stop(cancel)?;
            let row=sqlx::query("SELECT sequence,capture_id,observed_at,transport,provenance,provenance_integrity FROM devres_crate_observations WHERE capture_id NOT LIKE 'blake3:%' AND sequence>$1 ORDER BY sequence LIMIT 1").bind(after).fetch_optional(&self.pool).await.map_err(|_|storage_error())?;
            let Some(row) = row else {
                break;
            };
            after = row.try_get("sequence").map_err(|_| storage_error())?;
            let old: String = row.try_get("capture_id").map_err(|_| storage_error())?;
            let capture = mapped(maps, "capture", &old)?;
            let time: i64 = row.try_get("observed_at").map_err(|_| storage_error())?;
            let transport: String = row.try_get("transport").map_err(|_| storage_error())?;
            let data = payload_integrity::checked(
                "devres_crate_observations",
                &old,
                &after.to_string(),
                payload_integrity::crate_observation_payload(
                    &old,
                    time,
                    &transport,
                    &row.try_get::<Json<Value>, _>("provenance")
                        .map_err(|_| storage_error())?
                        .0,
                ),
                &row.try_get::<String, _>("provenance_integrity")
                    .map_err(|_| storage_error())?,
            )?;
            let mut data = data["provenance"].clone();
            remap_fields(&mut data, maps)?;
            // The source occurrence sequence is retained in a durable checkpoint, so
            // identical same-second observations remain separate and retries add none.
            let checkpoint = format!("observation:{after}");
            let mut owner = self.owner.lock().await;
            let mut tx = owner.begin().await.map_err(|_| storage_error())?;
            let existing=sqlx::query("SELECT data,data_integrity FROM devres_integrity_staged_state WHERE provider='crate' AND key=$1").bind(&checkpoint).fetch_optional(&mut *tx).await.map_err(|_|storage_error())?;
            if let Some(receipt) = existing {
                let value = payload_integrity::checked(
                    "devres_integrity_staged_state",
                    "crate",
                    &checkpoint,
                    receipt
                        .try_get::<Json<Value>, _>("data")
                        .map_err(|_| storage_error())?
                        .0,
                    &receipt
                        .try_get::<String, _>("data_integrity")
                        .map_err(|_| storage_error())?,
                )?;
                if value["legacy_sequence"] != after || value["capture_id"] != capture {
                    return Err(Error::integrity(
                        "Crate observation checkpoint identity mismatch.",
                    ));
                }
                let target=sqlx::query("SELECT capture_id,observed_at,transport,provenance,provenance_integrity FROM devres_crate_observations WHERE sequence=$1").bind(value["sequence"].as_i64().ok_or_else(storage_error)?).fetch_optional(&mut *tx).await.map_err(|_|storage_error())?.ok_or_else(||Error::integrity("Checkpointed observation missing."))?;
                let target_data = payload_integrity::checked(
                    "devres_crate_observations",
                    &capture,
                    &value["sequence"]
                        .as_i64()
                        .ok_or_else(storage_error)?
                        .to_string(),
                    payload_integrity::crate_observation_payload(
                        &capture,
                        time,
                        &transport,
                        &target
                            .try_get::<Json<Value>, _>("provenance")
                            .map_err(|_| storage_error())?
                            .0,
                    ),
                    &target
                        .try_get::<String, _>("provenance_integrity")
                        .map_err(|_| storage_error())?,
                )?;
                if target_data["provenance"] != data
                    || target
                        .try_get::<String, _>("capture_id")
                        .map_err(|_| storage_error())?
                        != capture
                    || target
                        .try_get::<i64, _>("observed_at")
                        .map_err(|_| storage_error())?
                        != time
                    || target
                        .try_get::<String, _>("transport")
                        .map_err(|_| storage_error())?
                        != transport
                {
                    return Err(Error::integrity(
                        "Checkpointed observation differs from retained occurrence.",
                    ));
                }
            } else {
                let sequence =
                    append_crate_observation(&mut tx, &capture, time, &transport, &data).await?;
                let receipt =
                    json!({"legacy_sequence":after,"sequence":sequence,"capture_id":capture});
                sqlx::query("INSERT INTO devres_integrity_staged_state(provider,key,data,data_integrity) VALUES('crate',$1,$2,$3)").bind(&checkpoint).bind(Json(&receipt)).bind(payload_integrity::digest("devres_integrity_staged_state","crate",&checkpoint,&receipt)?).execute(&mut *tx).await.map_err(|_|storage_error())?;
            }
            tx.commit().await.map_err(|_| storage_error())?;
        }
        Ok(())
    }

    async fn migrate_crate_inventories(
        &self,
        maps: &mut crate::migration_map::MigrationMap,
        aliases: &mut crate::migration_map::MigrationAliases,
        cancel: &CancellationToken,
    ) -> Result<BTreeMap<i64, i64>> {
        let orphaned:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM devres_crate_versions v LEFT JOIN devres_crate_inventories i ON i.sequence=v.valid_from WHERE i.id IS NULL)").fetch_one(&self.pool).await.map_err(|_|storage_error())?;
        if orphaned {
            return Err(Error::integrity(
                "Retained crate version has no inventory occurrence.",
            ));
        }
        let mut sequences = BTreeMap::new();
        let mut after = 0_i64;
        loop {
            stop(cancel)?;
            let row=sqlx::query("SELECT * FROM devres_crate_inventories WHERE id NOT LIKE 'blake3:%' AND sequence>$1 ORDER BY sequence LIMIT 1").bind(after).fetch_optional(&self.pool).await.map_err(|_|storage_error())?;
            let Some(row) = row else {
                break;
            };
            let old: String = row.try_get("id").map_err(|_| storage_error())?;
            after = row.try_get("sequence").map_err(|_| storage_error())?;
            let revision: String = row.try_get("revision").map_err(|_| storage_error())?;
            let new = hash(format!("crate-inventory:1:{revision}").as_bytes());
            let manifest: Option<String> = row.try_get("manifest").map_err(|_| storage_error())?;
            let sequence:i64=sqlx::query_scalar("INSERT INTO devres_crate_inventories(id,revision,created_at,validated_at,cursor,published,manifest) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(id) DO UPDATE SET id=EXCLUDED.id RETURNING sequence")
                .bind(&new).bind(revision).bind(row.try_get::<i64,_>("created_at").map_err(|_|storage_error())?).bind(row.try_get::<i64,_>("validated_at").map_err(|_|storage_error())?).bind(row.try_get::<Option<String>,_>("cursor").map_err(|_|storage_error())?).bind(row.try_get::<bool,_>("published").map_err(|_|storage_error())?).bind(manifest.as_deref().map(|id|mapped(maps,"capture",id)).transpose()?).fetch_one(&mut *self.owner.lock().await).await.map_err(|_|storage_error())?;
            sequences.insert(after, sequence);
            id_alias(maps, aliases, "inventories", &old, &new)?;
            sqlx::query("INSERT INTO devres_crate_inventory_gaps(inventory,name,error) SELECT $2,name,error FROM devres_crate_inventory_gaps WHERE inventory=$1 ON CONFLICT DO NOTHING").bind(&old).bind(&new).execute(&mut *self.owner.lock().await).await.map_err(|_|storage_error())?;
            sqlx::query("INSERT INTO devres_crate_changes(inventory,name) SELECT $2,name FROM devres_crate_changes WHERE inventory=$1 ON CONFLICT DO NOTHING").bind(&old).bind(&new).execute(&mut *self.owner.lock().await).await.map_err(|_|storage_error())?;
            let mut cursor = String::new();
            loop {
                let row=sqlx::query("SELECT * FROM devres_crate_staging WHERE inventory=$1 AND name||'@'||version>$2 ORDER BY name||'@'||version LIMIT 1").bind(&old).bind(&cursor).fetch_optional(&self.pool).await.map_err(|_|storage_error())?;
                let Some(row) = row else {
                    break;
                };
                let name: String = row.try_get("name").map_err(|_| storage_error())?;
                let version: String = row.try_get("version").map_err(|_| storage_error())?;
                cursor = format!("{name}@{version}");
                let record = payload_integrity::checked(
                    "devres_crate_staging",
                    &old,
                    &cursor,
                    payload_integrity::crate_staging_payload(
                        &row.try_get::<String, _>("metadata_capture")
                            .map_err(|_| storage_error())?,
                        &row.try_get::<Json<Value>, _>("record")
                            .map_err(|_| storage_error())?
                            .0,
                    ),
                    &row.try_get::<String, _>("record_integrity")
                        .map_err(|_| storage_error())?,
                )?;
                let record = record["record"].clone();
                let metadata = mapped(
                    maps,
                    "capture",
                    &row.try_get::<String, _>("metadata_capture")
                        .map_err(|_| storage_error())?,
                )?;
                sqlx::query("INSERT INTO devres_crate_staging(inventory,name,version,metadata_capture,record,record_integrity) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING").bind(&new).bind(name).bind(version).bind(mapped(maps,"capture",&row.try_get::<String,_>("metadata_capture").map_err(|_|storage_error())?)?).bind(Json(&record)).bind(payload_integrity::digest("devres_crate_staging",&new,&cursor,&payload_integrity::crate_staging_payload(&metadata,&record))?).execute(&mut *self.owner.lock().await).await.map_err(|_|storage_error())?;
            }
        }
        let mut after = (String::new(), String::new(), 0_i64);
        loop {
            stop(cancel)?;
            let row=sqlx::query("SELECT v.* FROM devres_crate_versions v JOIN devres_crate_inventories i ON i.sequence=v.valid_from WHERE i.id NOT LIKE 'blake3:%' AND (v.name,v.version,v.valid_from)>($1,$2,$3) ORDER BY v.name,v.version,v.valid_from LIMIT 1").bind(&after.0).bind(&after.1).bind(after.2).fetch_optional(&self.pool).await.map_err(|_|storage_error())?;
            let Some(row) = row else {
                break;
            };
            let name: String = row.try_get("name").map_err(|_| storage_error())?;
            let version: String = row.try_get("version").map_err(|_| storage_error())?;
            let from: i64 = row.try_get("valid_from").map_err(|_| storage_error())?;
            let to: Option<i64> = row.try_get("valid_to").map_err(|_| storage_error())?;
            let record = checked_version(&row)?;
            let new_from = *sequences.get(&from).ok_or_else(storage_error)?;
            let new_to = to
                .map(|to| sequences.get(&to).copied().ok_or_else(storage_error))
                .transpose()?;
            let metadata = mapped(
                maps,
                "capture",
                &row.try_get::<String, _>("metadata_capture")
                    .map_err(|_| storage_error())?,
            )?;
            sqlx::query("INSERT INTO devres_crate_versions(name,version,valid_from,valid_to,metadata_capture,record,record_integrity) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING").bind(&name).bind(&version).bind(new_from).bind(new_to).bind(mapped(maps,"capture",&row.try_get::<String,_>("metadata_capture").map_err(|_|storage_error())?)?).bind(Json(&record)).bind(payload_integrity::digest("devres_crate_versions",&new_from.to_string(),&format!("{name}@{version}"),&payload_integrity::crate_record_payload(&metadata,new_to,&record))?).execute(&mut *self.owner.lock().await).await.map_err(|_|storage_error())?;
            after = (name, version, from);
        }
        Ok(sequences)
    }

    async fn migrate_crate_generations(
        &self,
        maps: &mut crate::migration_map::MigrationMap,
        aliases: &mut crate::migration_map::MigrationAliases,
        cancel: &CancellationToken,
    ) -> Result<BTreeMap<i64, i64>> {
        let mut sequences = BTreeMap::new();
        let mut after = String::new();
        let mut generation_after = (i64::MIN, String::new());
        loop {
            let old:Option<String>=sqlx::query_scalar("SELECT id FROM devres_crate_generations WHERE id NOT LIKE 'blake3:%' AND (COALESCE(published_sequence,9223372036854775807),id)>($1,$2) ORDER BY published_sequence NULLS LAST,id LIMIT 1").bind(generation_after.0).bind(&generation_after.1).fetch_optional(&self.pool).await.map_err(|_|storage_error())?;
            let Some(old) = old else {
                break;
            };
            stop(cancel)?;
            let row = sqlx::query("SELECT * FROM devres_crate_generations WHERE id=$1")
                .bind(&old)
                .fetch_one(&self.pool)
                .await
                .map_err(|_| storage_error())?;
            let published: Option<i64> = row
                .try_get("published_sequence")
                .map_err(|_| storage_error())?;
            let mut summary: Value = row
                .try_get::<Json<Value>, _>("summary")
                .map_err(|_| storage_error())?
                .0;
            payload_integrity::checked(
                "devres_crate_generations",
                "",
                &old,
                payload_integrity::crate_generation_payload(published, &summary)?,
                &row.try_get::<String, _>("summary_integrity")
                    .map_err(|_| storage_error())?,
            )?;
            remap_fields(&mut summary, maps)?;
            let new = crate::integrity::canonical_hash(
                &json!({"version":1,"namespace":"crate-generation","legacy_id":old,"summary":summary}),
            )?;
            generation_after = (published.unwrap_or(i64::MAX), old.clone());
            let mut owner = self.owner.lock().await;
            let mut tx = owner.begin().await.map_err(|_| storage_error())?;
            let retained = sqlx::query("SELECT published_sequence,summary,summary_integrity FROM devres_crate_generations WHERE id=$1 FOR UPDATE")
                .bind(&new).fetch_optional(&mut *tx).await.map_err(|_|storage_error())?;
            let canonical: Option<i64> = if let Some(retained) = retained {
                let sequence: Option<i64> = retained
                    .try_get("published_sequence")
                    .map_err(|_| storage_error())?;
                let existing: Json<Value> =
                    retained.try_get("summary").map_err(|_| storage_error())?;
                payload_integrity::checked(
                    "devres_crate_generations",
                    "",
                    &new,
                    payload_integrity::crate_generation_payload(sequence, &existing.0)?,
                    &retained
                        .try_get::<String, _>("summary_integrity")
                        .map_err(|_| storage_error())?,
                )?;
                if existing.0 != summary || sequence.is_some() != published.is_some() {
                    return Err(Error::integrity(
                        "Canonical generation migration replay changed.",
                    ));
                }
                sequence
            } else {
                let sequence = if published.is_some() {
                    Some(
                        sqlx::query_scalar::<_, i64>(
                            "SELECT nextval('devres_crate_content_sequence')",
                        )
                        .fetch_one(&mut *tx)
                        .await
                        .map_err(|_| storage_error())?,
                    )
                } else {
                    None
                };
                sqlx::query("INSERT INTO devres_crate_generations(id,published_sequence,summary,summary_integrity) VALUES($1,$2,$3,$4)")
                    .bind(&new).bind(sequence).bind(Json(&summary))
                    .bind(payload_integrity::digest("devres_crate_generations","",&new,&payload_integrity::crate_generation_payload(sequence,&summary)?)?)
                    .execute(&mut *tx).await.map_err(|_|storage_error())?;
                sequence
            };
            tx.commit().await.map_err(|_| storage_error())?;
            drop(owner);
            if let (Some(old_seq), Some(new_seq)) = (published, canonical) {
                sequences.insert(old_seq, new_seq);
            }
            id_alias(maps, aliases, "generations", &old, &new)?;
            after.clear();
            loop {
                let row=sqlx::query("SELECT * FROM devres_crate_content WHERE generation=$1 AND id>$2 ORDER BY id LIMIT 1").bind(&old).bind(&after).fetch_optional(&self.pool).await.map_err(|_|storage_error())?;
                let Some(row) = row else {
                    break;
                };
                let old_content: String = row.try_get("id").map_err(|_| storage_error())?;
                let attributes = checked_attributes(&row)?;
                let capture = mapped(
                    maps,
                    "capture",
                    &row.try_get::<String, _>("capture")
                        .map_err(|_| storage_error())?,
                )?;
                let kind: String = row.try_get("kind").map_err(|_| storage_error())?;
                let target: String = row.try_get("target").map_err(|_| storage_error())?;
                let path: String = row.try_get("path").map_err(|_| storage_error())?;
                let id = hash(format!("{capture}\0{kind}\0{target}\0{path}").as_bytes());
                let content_payload = json!({"id":id,"name":row.try_get::<String,_>("name").map_err(|_|storage_error())?,"version":row.try_get::<String,_>("version").map_err(|_|storage_error())?,"target":target,"path":path,"kind":kind,"capture":capture,"metadata_capture":mapped(maps,"capture",&row.try_get::<String,_>("metadata_capture").map_err(|_|storage_error())?)?,"archive_capture":mapped(maps,"capture",&row.try_get::<String,_>("archive_capture").map_err(|_|storage_error())?)?,"attributes":attributes});
                sqlx::query("INSERT INTO devres_crate_content(generation,id,name,version,target,path,kind,capture,metadata_capture,archive_capture,attributes,attributes_integrity) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT DO NOTHING")
                    .bind(&new).bind(&id).bind(row.try_get::<String,_>("name").map_err(|_|storage_error())?).bind(row.try_get::<String,_>("version").map_err(|_|storage_error())?).bind(target).bind(path).bind(kind).bind(capture).bind(mapped(maps,"capture",&row.try_get::<String,_>("metadata_capture").map_err(|_|storage_error())?)?).bind(mapped(maps,"capture",&row.try_get::<String,_>("archive_capture").map_err(|_|storage_error())?)?).bind(Json(&attributes)).bind(payload_integrity::digest("devres_crate_content",&new,&id,&content_payload)?).execute(&mut *self.owner.lock().await).await.map_err(|_|storage_error())?;
                id_alias(maps, aliases, "content", &old_content, &id)?;
                after = old_content;
            }
        }
        Ok(sequences)
    }

    async fn migrate_crate_enrichment(
        &self,
        maps: &crate::migration_map::MigrationMap,
        cancel: &CancellationToken,
    ) -> Result<()> {
        let mut after = (String::new(), String::new(), String::new());
        loop {
            stop(cancel)?;
            let row=sqlx::query("SELECT * FROM devres_crate_enrichment WHERE artifact NOT LIKE 'blake3:%' AND (artifact,kind,external_id)>($1,$2,$3) ORDER BY artifact,kind,external_id LIMIT 1").bind(&after.0).bind(&after.1).bind(&after.2).fetch_optional(&self.pool).await.map_err(|_|storage_error())?;
            let Some(row) = row else {
                break;
            };
            let old: String = row.try_get("artifact").map_err(|_| storage_error())?;
            let kind: String = row.try_get("kind").map_err(|_| storage_error())?;
            let key: String = row.try_get("external_id").map_err(|_| storage_error())?;
            let data = checked_enrichment(&old, &kind, &row)?;
            let new = mapped(maps, "capture", &old)?;
            sqlx::query("INSERT INTO devres_crate_enrichment(artifact,kind,external_id,data,data_integrity) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING").bind(&new).bind(&kind).bind(&key).bind(Json(&data)).bind(payload_integrity::digest("devres_crate_enrichment",&format!("{new}:{kind}"),&key,&data)?).execute(&mut *self.owner.lock().await).await.map_err(|_|storage_error())?;
            after = (old, kind, key);
        }
        let heads:Vec<String>=sqlx::query_scalar("SELECT artifact FROM devres_crate_enrichment_heads WHERE artifact NOT LIKE 'blake3:%' ORDER BY sequence").fetch_all(&self.pool).await.map_err(|_|storage_error())?;
        for old in heads {
            sqlx::query("INSERT INTO devres_crate_enrichment_heads(artifact) VALUES($1) ON CONFLICT DO NOTHING").bind(mapped(maps,"capture",&old)?).execute(&mut *self.owner.lock().await).await.map_err(|_|storage_error())?;
        }
        Ok(())
    }
}
