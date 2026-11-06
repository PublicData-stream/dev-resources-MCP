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

async fn reserve_source(
    execution: &crate::MigrationExecution,
    cancel: &CancellationToken,
    bytes: i64,
    nodes: i64,
) -> Result<crate::GraphReservation> {
    let charge = crate::MigrationExecution::graph_input_charge(
        usize::try_from(bytes).map_err(|_| storage_error())?,
        usize::try_from(nodes).map_err(|_| storage_error())?,
    )?;
    execution.graph_reserve(charge, cancel).await
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

/// Only targets retained before this replay can be adopted. Ownership is resolved
/// in legacy order whenever an interrupted older replay left canonical rows.
struct SnapshotAdoption {
    cutoff: i64,
    owners: crate::MigrationMap,
}

impl SnapshotAdoption {
    fn permits(&self, old: &str, canonical: &str) -> bool {
        self.owners
            .get(&format!("canonical:{canonical}"))
            .is_none_or(|owner| owner == old)
            && self
                .owners
                .get(&format!("legacy:{old}"))
                .is_none_or(|target| target == canonical)
    }

    fn claim(&mut self, old: &str, canonical: &str) -> Result<()> {
        if !valid_hash(old)
            || old.starts_with("blake3:")
            || !valid_hash(canonical)
            || !canonical.starts_with("blake3:")
            || !self.permits(old, canonical)
        {
            return Err(Error::integrity(
                "Crate snapshot replay occurrence ownership changed.",
            ));
        }
        crate::migration_map::insert(
            &mut self.owners,
            format!("canonical:{canonical}"),
            old.to_owned(),
        )?;
        crate::migration_map::insert(
            &mut self.owners,
            format!("legacy:{old}"),
            canonical.to_owned(),
        )?;
        self.owners.ensure_healthy()
    }
}

struct SnapshotSource<'a> {
    legacy: &'a str,
    integrity: &'a str,
    adoption: &'a SnapshotAdoption,
}

fn snapshot_identity(snapshot: &Snapshot) -> Result<String> {
    Ok(hash(serde_json::to_vec(&json!({"inventory":snapshot.inventory.id,"inventory_validated_at":snapshot.inventory.validated_at,"content_sequence":snapshot.content_sequence,"enrichment":snapshot.enrichment,"index":snapshot.index_manifest,"coverage":snapshot.coverage}))
        .map_err(|_|Error::integrity("Snapshot identity failed."))?.as_slice()))
}

fn snapshot_base(snapshot: &Snapshot) -> Result<Value> {
    let mut value = serde_json::to_value(snapshot).map_err(|_| storage_error())?;
    let object = value.as_object_mut().ok_or_else(storage_error)?;
    object.remove("id");
    object.remove("index_manifest");
    Ok(value)
}

fn snapshot_rewrite(maps: &crate::MigrationMap) -> crate::crates_io::index::PayloadRewrite {
    let maps = maps.clone();
    Arc::new(move |value: &mut Value| -> Result<()> {
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
    })
}

impl PgBlobStore {
    async fn crate_snapshot_adoption(
        &self,
        maps: &crate::MigrationMap,
        cancel: &CancellationToken,
        execution: &crate::MigrationExecution,
    ) -> Result<SnapshotAdoption> {
        let cutoff: i64 = sqlx::query_scalar("SELECT COALESCE(max(sequence),0)::bigint FROM devres_crate_snapshots WHERE id LIKE 'blake3:%'")
            .fetch_one(&self.pool).await.map_err(|_|storage_error())?;
        let mut adoption = SnapshotAdoption {
            cutoff,
            owners: maps.scratch()?,
        };
        let mut after = String::new();
        loop {
            stop(cancel)?;
            let aliases: Vec<(String,String)> = sqlx::query_as("SELECT legacy,canonical FROM devres_content_aliases WHERE namespace='crate:snapshots' AND legacy>$1 ORDER BY legacy LIMIT 128")
                .bind(&after).fetch_all(&self.pool).await.map_err(|_|storage_error())?;
            if aliases.is_empty() {
                break;
            }
            for (old, canonical) in aliases {
                if maps.get(&format!("crate:snapshots:{old}")).as_ref() != Some(&canonical) {
                    return Err(Error::integrity("Qualified crate snapshot alias changed."));
                }
                adoption.claim(&old, &canonical)?;
                after = old;
            }
        }
        let mut after = String::new();
        loop {
            stop(cancel)?;
            let source: Option<(String,i64,i64)> = sqlx::query_as("SELECT key,octet_length(data::text)::bigint,jsonb_array_length(jsonb_path_query_array(data,'strict $.**.type()'))::bigint FROM devres_integrity_staged_state WHERE provider='crate' AND key LIKE 'snapshot-prepared:%' AND key>$1 ORDER BY key LIMIT 1")
                .bind(&after).fetch_optional(&self.pool).await.map_err(|_|storage_error())?;
            let Some((key, bytes, nodes)) = source else {
                break;
            };
            let _reservation = reserve_source(execution, cancel, bytes, nodes).await?;
            let row = sqlx::query("SELECT data,data_integrity FROM devres_integrity_staged_state WHERE provider='crate' AND key=$1")
                .bind(&key).fetch_one(&self.pool).await.map_err(|_|storage_error())?;
            let data = payload_integrity::checked(
                "devres_integrity_staged_state",
                "crate",
                &key,
                row.try_get::<Json<Value>, _>("data")
                    .map_err(|_| storage_error())?
                    .0,
                &row.try_get::<String, _>("data_integrity")
                    .map_err(|_| storage_error())?,
            )?;
            let old = key
                .strip_prefix("snapshot-prepared:")
                .ok_or_else(storage_error)?;
            if data["version"] != 1
                || data["legacy_id"] != old
                || data["source_integrity"]
                    .as_str()
                    .is_none_or(|seal| !valid_hash(seal) || !seal.starts_with("blake3:"))
            {
                return Err(Error::integrity(
                    "Invalid prepared crate snapshot ownership receipt.",
                ));
            }
            let snapshot: Snapshot =
                serde_json::from_value(data["snapshot"].clone()).map_err(|_| storage_error())?;
            adoption.claim(old, &snapshot_identity(&snapshot)?)?;
            after = key;
        }
        adoption.owners.ensure_healthy()?;
        Ok(adoption)
    }

    async fn validate_prepared_crate_snapshot(
        &self,
        expected: &Snapshot,
        prepared: &Snapshot,
        original_index: &Value,
        maps: &crate::MigrationMap,
        cancel: &CancellationToken,
        execution: &crate::MigrationExecution,
    ) -> Result<bool> {
        if snapshot_base(expected)? != snapshot_base(prepared)? {
            return Err(Error::integrity(
                "Prepared crate snapshot metadata changed.",
            ));
        }
        if original_index.is_null() {
            if !prepared.index_manifest.is_null() {
                return Err(Error::integrity("Prepared crate snapshot added an index."));
            }
        } else {
            if prepared.index_manifest.is_null() {
                return Err(Error::integrity("Prepared crate snapshot lost its index."));
            }
            return crate::crates_io::index::verify_frozen_replay_with_execution(
                self.root.clone(),
                original_index.clone(),
                prepared.index_manifest.clone(),
                prepared.clone(),
                snapshot_rewrite(maps),
                cancel.child_token(),
                execution,
            )
            .await;
        }
        Ok(true)
    }

    async fn prepare_crate_snapshot(
        self: &Arc<Self>,
        source: SnapshotSource<'_>,
        mut snapshot: Snapshot,
        original_index: Value,
        maps: &crate::MigrationMap,
        cancel: &CancellationToken,
        execution: &crate::MigrationExecution,
    ) -> Result<Snapshot> {
        let SnapshotSource {
            legacy: old,
            integrity: source_integrity,
            adoption,
        } = source;
        let checkpoint = format!("snapshot-prepared:{old}");
        let receipt = sqlx::query("SELECT data,data_integrity FROM devres_integrity_staged_state WHERE provider='crate' AND key=$1")
            .bind(&checkpoint).fetch_optional(&self.pool).await.map_err(|_|storage_error())?;
        if let Some(receipt) = receipt {
            let data = payload_integrity::checked(
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
            if data["version"] != 1
                || data["legacy_id"] != old
                || data["source_integrity"] != source_integrity
            {
                return Err(Error::integrity("Prepared crate snapshot source changed."));
            }
            let prepared: Snapshot =
                serde_json::from_value(data["snapshot"].clone()).map_err(|_| storage_error())?;
            if !adoption.permits(old, &snapshot_identity(&prepared)?) {
                return Err(Error::integrity(
                    "Prepared crate snapshot is claimed by another occurrence.",
                ));
            }
            if !self
                .validate_prepared_crate_snapshot(
                    &snapshot,
                    &prepared,
                    &original_index,
                    maps,
                    cancel,
                    execution,
                )
                .await?
            {
                return Err(Error::integrity(
                    "Prepared crate snapshot postings changed.",
                ));
            }
            return Ok(prepared);
        }

        // Older schema-ten binaries could commit a canonical snapshot before
        // sealing its aliases. Adopt only a fully verified matching occurrence.
        let expected_base = snapshot_base(&snapshot)?;
        let mut after = 0_i64;
        let mut adopted = None;
        loop {
            stop(cancel)?;
            let candidate:Option<(i64,String)> = sqlx::query_as("SELECT sequence,id FROM devres_crate_snapshots WHERE id LIKE 'blake3:%' AND sequence>$1 AND data-'id'-'index_manifest'=$2::jsonb AND (data->'index_manifest'<>'null'::jsonb)=$3 AND sequence<=$4 ORDER BY sequence LIMIT 1")
                .bind(after).bind(Json(&expected_base)).bind(!original_index.is_null()).bind(adoption.cutoff).fetch_optional(&self.pool).await.map_err(|_|storage_error())?;
            let Some((sequence, id)) = candidate else {
                break;
            };
            after = sequence;
            if !adoption.permits(old, &id) {
                continue;
            }
            let prepared = <Self as CrateCorpusStore>::snapshot(self, Some(&id))
                .await?
                .ok_or_else(|| Error::integrity("Retained crate snapshot disappeared."))?;
            if snapshot_identity(&prepared)? != prepared.id {
                return Err(Error::integrity(
                    "Retained crate snapshot identity changed.",
                ));
            }
            if self
                .validate_prepared_crate_snapshot(
                    &snapshot,
                    &prepared,
                    &original_index,
                    maps,
                    cancel,
                    execution,
                )
                .await?
            {
                adopted = Some(prepared);
                break;
            }
        }
        if let Some(prepared) = adopted {
            snapshot = prepared;
        } else if !original_index.is_null() {
            snapshot.index_manifest = crate::crates_io::index::rebuild_frozen_with_execution(
                self.clone(),
                self.root.clone(),
                original_index,
                snapshot.clone(),
                snapshot_rewrite(maps),
                cancel.child_token(),
                execution,
            )
            .await?;
        }
        stop(cancel)?;
        // Persist the immutable prepared result before allocating the public
        // snapshot occurrence. A crash after either commit reuses this result.
        payload_integrity::stage(self,"crate",&checkpoint,&json!({"version":1,"legacy_id":old,"source_integrity":source_integrity,"snapshot":snapshot})).await?;
        Ok(snapshot)
    }

    async fn commit_prepared_crate_snapshot(&self, mut snapshot: Snapshot) -> Result<Snapshot> {
        snapshot.id = snapshot_identity(&snapshot)?;
        if let Some(retained) =
            <Self as CrateCorpusStore>::snapshot(self, Some(&snapshot.id)).await?
        {
            if serde_json::to_value(&retained).map_err(|_| storage_error())?
                != serde_json::to_value(&snapshot).map_err(|_| storage_error())?
            {
                return Err(Error::integrity(
                    "Prepared crate snapshot publication changed.",
                ));
            }
            return Ok(retained);
        }
        self.commit_snapshot(snapshot).await
    }

    pub async fn migrate_crate_graph(
        self: &Arc<Self>,
        maps: &mut crate::migration_map::MigrationMap,
        cancel: CancellationToken,
    ) -> Result<crate::migration_map::MigrationAliases> {
        self.migrate_crate_graph_with_execution(maps, cancel, &crate::MigrationExecution::default())
            .await
    }

    pub async fn migrate_crate_graph_with_execution(
        self: &Arc<Self>,
        maps: &mut crate::MigrationMap,
        cancel: CancellationToken,
        execution: &crate::MigrationExecution,
    ) -> Result<crate::migration_map::MigrationAliases> {
        self.fence().await?;
        let mut aliases = crate::migration_map::MigrationAliases::new(maps)?;
        let mut adoption = self
            .crate_snapshot_adoption(maps, &cancel, execution)
            .await?;
        self.migrate_crate_artifacts(maps, &cancel, execution)
            .await?;
        self.migrate_crate_inventories(maps, &mut aliases, &cancel, execution)
            .await?;
        let generations = self
            .migrate_crate_generations(maps, &mut aliases, &cancel, execution)
            .await?;
        self.migrate_crate_enrichment(maps, &cancel, execution)
            .await?;
        const JOB_BYTES: usize = 256 * 1024 * 1024;
        let mut after = 0_i64;
        let mut admitted = 0_u64;
        let mut committed = 0_u64;
        loop {
            stop(&cancel)?;
            let positions: Vec<(i64, String, i64, i64)> = sqlx::query_as(
                "SELECT sequence,id,octet_length(data::text)::bigint,jsonb_array_length(jsonb_path_query_array(data,'strict $.**.type()'))::bigint FROM devres_crate_snapshots WHERE id NOT LIKE 'blake3:%' AND sequence>$1 ORDER BY sequence LIMIT $2"
            ).bind(after).bind(if adoption.cutoff > 0 { 1_i64 } else { execution.options().workers as i64 })
                .fetch_all(&self.pool).await.map_err(|_|storage_error())?;
            if positions.is_empty() {
                break;
            }
            let positions = execution.graph_input_window(
                positions
                    .into_iter()
                    .map(|(seq, id, bytes, nodes)| {
                        let charge = crate::MigrationExecution::graph_input_charge(
                            usize::try_from(bytes).map_err(|_| storage_error())?,
                            usize::try_from(nodes).map_err(|_| storage_error())?,
                        )?
                        .checked_add(JOB_BYTES)
                        .ok_or_else(|| Error::capacity("Crate graph input charge overflow."))?;
                        Ok(((seq, id), charge))
                    })
                    .collect::<Result<Vec<_>>>()?,
            )?;
            after = positions.last().map_or(after, |((seq, _), _)| *seq);
            admitted += positions.len() as u64;
            let window_bytes = positions.iter().map(|(_, bytes)| *bytes).sum();
            execution.report(
                "graph_crate_snapshots",
                admitted,
                committed,
                committed,
                window_bytes,
            );
            let read_maps = &*maps;
            let generations = &generations;
            let read_adoption = &adoption;
            let prepared = execution.graph_map_ordered(
                positions, &cancel,
                |(sequence, old), token| async move {
                    let row=sqlx::query("SELECT sequence,inventory,content_sequence,''::text AS kind,id AS key,data,data_integrity FROM devres_crate_snapshots WHERE id=$1 AND sequence=$2")
                        .bind(&old).bind(sequence).fetch_one(&self.pool).await.map_err(|_|storage_error())?;
            let source_integrity: String = row.try_get("data_integrity").map_err(|_|storage_error())?;
            let mut snapshot: Snapshot =
                serde_json::from_value(payload_integrity::row("devres_crate_snapshots", &row)?)
                    .map_err(|_| storage_error())?;
            let old_index = snapshot.index_manifest.take();
            let inventory_id = mapped(read_maps, "crate:inventories", &snapshot.inventory.id)?;
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
                snapshot.enrichment = Some(mapped(read_maps, "capture", id)?);
            }
            remap_fields(&mut snapshot.coverage, read_maps)?;
            snapshot.coverage["content_sequence"] = json!(snapshot.content_sequence);
            snapshot = self.prepare_crate_snapshot(
                SnapshotSource { legacy: &old, integrity: &source_integrity, adoption: read_adoption },snapshot,old_index,read_maps,&token,execution,
            ).await?;
                    Ok((old, snapshot))
                },
            ).await?;
            execution.report(
                "graph_crate_snapshots",
                admitted,
                admitted,
                committed,
                window_bytes,
            );
            for prepared in prepared {
                stop(&cancel)?;
                let (old, snapshot) = prepared.value();
                adoption.claim(old, &snapshot_identity(snapshot)?)?;
                let snapshot = self
                    .commit_prepared_crate_snapshot(snapshot.clone())
                    .await?;
                id_alias(maps, &mut aliases, "snapshots", old, &snapshot.id)?;
                committed += 1;
                execution.report(
                    "graph_crate_snapshots",
                    admitted,
                    admitted,
                    committed,
                    window_bytes,
                );
            }
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
        execution: &crate::MigrationExecution,
    ) -> Result<()> {
        let mut committed = 0_u64;
        let mut after = String::new();
        loop {
            stop(cancel)?;
            let source_size: Option<(i64,i64)> = sqlx::query_as("SELECT octet_length(to_jsonb(source)::text)::bigint,jsonb_array_length(jsonb_path_query_array(to_jsonb(source),'strict $.**.type()'))::bigint FROM (SELECT capture_id,bytes,provenance,provenance_integrity FROM devres_crate_artifacts WHERE capture_id NOT LIKE 'blake3:%' AND capture_id>$1 ORDER BY capture_id LIMIT 1) source").bind(&after).fetch_optional(&self.pool).await.map_err(|_|storage_error())?;
            let Some((source_bytes, source_nodes)) = source_size else {
                break;
            };
            let _source_reservation =
                reserve_source(execution, cancel, source_bytes, source_nodes).await?;
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
            committed += 1;
            execution.report(
                "graph_crate_artifacts",
                committed,
                committed,
                committed,
                _source_reservation.accounted_bytes(),
            );
        }
        let mut after = 0_i64;
        loop {
            stop(cancel)?;
            let source_size: Option<(i64,i64)> = sqlx::query_as("SELECT octet_length(to_jsonb(source)::text)::bigint,jsonb_array_length(jsonb_path_query_array(to_jsonb(source),'strict $.**.type()'))::bigint FROM (SELECT sequence,capture_id,observed_at,transport,provenance,provenance_integrity FROM devres_crate_observations WHERE capture_id NOT LIKE 'blake3:%' AND sequence>$1 ORDER BY sequence LIMIT 1) source").bind(after).fetch_optional(&self.pool).await.map_err(|_|storage_error())?;
            let Some((source_bytes, source_nodes)) = source_size else {
                break;
            };
            let _source_reservation =
                reserve_source(execution, cancel, source_bytes, source_nodes).await?;
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
        execution: &crate::MigrationExecution,
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
            let source_size: Option<(i64,i64)> = sqlx::query_as("SELECT octet_length(to_jsonb(source)::text)::bigint,jsonb_array_length(jsonb_path_query_array(to_jsonb(source),'strict $.**.type()'))::bigint FROM (SELECT * FROM devres_crate_inventories WHERE id NOT LIKE 'blake3:%' AND sequence>$1 ORDER BY sequence LIMIT 1) source").bind(after).fetch_optional(&self.pool).await.map_err(|_|storage_error())?;
            let Some((source_bytes, source_nodes)) = source_size else {
                break;
            };
            let _source_reservation =
                reserve_source(execution, cancel, source_bytes, source_nodes).await?;
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
            drop(row);
            drop(_source_reservation);
            let mut cursor = String::new();
            loop {
                let source_size: Option<(i64,i64)> = sqlx::query_as("SELECT octet_length(to_jsonb(source)::text)::bigint,jsonb_array_length(jsonb_path_query_array(to_jsonb(source),'strict $.**.type()'))::bigint FROM (SELECT * FROM devres_crate_staging WHERE inventory=$1 AND name||'@'||version>$2 ORDER BY name||'@'||version LIMIT 1) source").bind(&old).bind(&cursor).fetch_optional(&self.pool).await.map_err(|_|storage_error())?;
                let Some((source_bytes, source_nodes)) = source_size else {
                    break;
                };
                let _source_reservation =
                    reserve_source(execution, cancel, source_bytes, source_nodes).await?;
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
            let source_size: Option<(i64,i64)> = sqlx::query_as("SELECT octet_length(to_jsonb(source)::text)::bigint,jsonb_array_length(jsonb_path_query_array(to_jsonb(source),'strict $.**.type()'))::bigint FROM (SELECT v.* FROM devres_crate_versions v JOIN devres_crate_inventories i ON i.sequence=v.valid_from WHERE i.id NOT LIKE 'blake3:%' AND (v.name,v.version,v.valid_from)>($1,$2,$3) ORDER BY v.name,v.version,v.valid_from LIMIT 1) source").bind(&after.0).bind(&after.1).bind(after.2).fetch_optional(&self.pool).await.map_err(|_|storage_error())?;
            let Some((source_bytes, source_nodes)) = source_size else {
                break;
            };
            let _source_reservation =
                reserve_source(execution, cancel, source_bytes, source_nodes).await?;
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
        execution: &crate::MigrationExecution,
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
            let (source_bytes,source_nodes):(i64,i64) = sqlx::query_as("SELECT octet_length(to_jsonb(source)::text)::bigint,jsonb_array_length(jsonb_path_query_array(to_jsonb(source),'strict $.**.type()'))::bigint FROM devres_crate_generations source WHERE id=$1")
                .bind(&old).fetch_one(&self.pool).await.map_err(|_|storage_error())?;
            let _source_reservation =
                reserve_source(execution, cancel, source_bytes, source_nodes).await?;
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
            drop(summary);
            drop(row);
            drop(_source_reservation);
            after.clear();
            loop {
                let source_size: Option<(i64,i64)> = sqlx::query_as("SELECT octet_length(to_jsonb(source)::text)::bigint,jsonb_array_length(jsonb_path_query_array(to_jsonb(source),'strict $.**.type()'))::bigint FROM (SELECT * FROM devres_crate_content WHERE generation=$1 AND id>$2 ORDER BY id LIMIT 1) source").bind(&old).bind(&after).fetch_optional(&self.pool).await.map_err(|_|storage_error())?;
                let Some((source_bytes, source_nodes)) = source_size else {
                    break;
                };
                let _source_reservation =
                    reserve_source(execution, cancel, source_bytes, source_nodes).await?;
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
        execution: &crate::MigrationExecution,
    ) -> Result<()> {
        let mut committed = 0_u64;
        let mut after = (String::new(), String::new(), String::new());
        loop {
            stop(cancel)?;
            let source_size: Option<(i64,i64)> = sqlx::query_as("SELECT octet_length(to_jsonb(source)::text)::bigint,jsonb_array_length(jsonb_path_query_array(to_jsonb(source),'strict $.**.type()'))::bigint FROM (SELECT * FROM devres_crate_enrichment WHERE artifact NOT LIKE 'blake3:%' AND (artifact,kind,external_id)>($1,$2,$3) ORDER BY artifact,kind,external_id LIMIT 1) source").bind(&after.0).bind(&after.1).bind(&after.2).fetch_optional(&self.pool).await.map_err(|_|storage_error())?;
            let Some((source_bytes, source_nodes)) = source_size else {
                break;
            };
            let _source_reservation =
                reserve_source(execution, cancel, source_bytes, source_nodes).await?;
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
            committed += 1;
            execution.report(
                "graph_crate_enrichment",
                committed,
                committed,
                committed,
                _source_reservation.accounted_bytes(),
            );
        }
        let heads:Vec<String>=sqlx::query_scalar("SELECT artifact FROM devres_crate_enrichment_heads WHERE artifact NOT LIKE 'blake3:%' ORDER BY sequence").fetch_all(&self.pool).await.map_err(|_|storage_error())?;
        for old in heads {
            sqlx::query("INSERT INTO devres_crate_enrichment_heads(artifact) VALUES($1) ON CONFLICT DO NOTHING").bind(mapped(maps,"capture",&old)?).execute(&mut *self.owner.lock().await).await.map_err(|_|storage_error())?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "storage_migration_tests.rs"]
mod tests;
