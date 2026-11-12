//! Offline canonical graph reconstruction. Every source/processor generation stays frozen.
use super::*;
use crate::bulk::BulkArtifact;
use std::collections::VecDeque;
type Aliases = crate::migration_map::MigrationAliases;
fn known_evidence_kind(kind: &str) -> bool {
    matches!(
        kind,
        "blocked-jobs"
            | "catalogs"
            | "commits"
            | "derived-inventories"
            | "document-members"
            | "failed-pages"
            | "freezes"
            | "history-gaps"
            | "index-documents"
            | "index-recoveries"
            | "indexed"
            | "jobs"
            | "license-notices"
            | "license-scopes"
            | "nodes"
            | "notice-objects"
            | "observations"
            | "projection-chunks"
            | "projection-references"
            | "projection-sections"
            | "projection-sequences"
            | "projection-symbols"
            | "projections"
            | "publications"
            | "ref-pages"
            | "sitemaps"
            | "snapshot-keys"
            | "snapshots"
            | "tags"
            | "traversal-gaps"
            | "traversal-gap-manifests"
            | "tree-pages"
            | "trees"
            | "views"
            | "validation-failures"
            | "web-map-jobs"
            | "web-page-jobs"
    )
}
fn check(cancel: &CancellationToken) -> Result<()> {
    if cancel.is_cancelled() {
        return Err(Error::new(
            "cancelled",
            "chromium graph migration canceled.",
        ));
    }
    Ok(())
}
fn mapped(mappings: &crate::migration_map::MigrationMap, id: &str) -> Result<String> {
    if id.starts_with("blake3:") && crate::integrity::valid_hash(id) {
        return Ok(id.to_owned());
    }
    let mut found = None;
    for kind in &[
        "snapshot-keys",
        "projections",
        "projection-headers",
        "index-documents",
        "observations",
        "nodes",
        "snapshots",
        "views",
        "changes",
        "projection-chunks",
        "projection-references",
        "projection-sequences",
        "projection-sections",
        "projection-symbols",
        "publications",
        "catalogs",
    ] {
        if let Some(value) =
            crate::integrity::migration_lookup(mappings, &format!("chromium:{kind}"), id)
        {
            if found.as_ref().is_some_and(|prior| prior != &value) {
                return Err(Error::integrity(
                    "Ambiguous chromium migration reference role.",
                ));
            }
            found = Some(value.clone());
        }
    }
    found.ok_or_else(|| Error::integrity("chromium migration reference is not qualified."))
}
fn mapped_role(
    mappings: &crate::migration_map::MigrationMap,
    kind: &str,
    id: &str,
) -> Result<String> {
    if id.starts_with("blake3:") && crate::integrity::valid_hash(id) {
        return Ok(id.to_owned());
    }
    crate::integrity::migration_lookup(mappings, &format!("chromium:{kind}"), id)
        .ok_or_else(|| Error::integrity("Missing typed migration reference."))
}
fn record(
    mappings: &mut crate::migration_map::MigrationMap,
    aliases: &mut Aliases,
    kind: &str,
    old: &str,
    new: &str,
) -> Result<()> {
    let scoped = format!("chromium:{kind}:{old}");
    if let Some(existing) = mappings.get(&scoped)
        && existing != new
    {
        return Err(Error::integrity(
            "Conflicting chromium graph migration mapping.",
        ));
    }
    crate::migration_map::insert(mappings, scoped, new.to_owned())?;
    if old != new {
        {
            let alias = (kind.to_owned(), old.to_owned(), new.to_owned());
            aliases.push(alias)?;
        }
    }
    Ok(())
}
fn artifact(value: &mut Value, mappings: &crate::migration_map::MigrationMap) -> Result<()> {
    let mut item: BulkArtifact = decode(value.clone())?;
    item.body_hash = if item.body_hash.starts_with("blake3:") {
        item.body_hash.clone()
    } else {
        crate::integrity::migration_lookup(mappings, "body", &item.body_hash)
            .ok_or_else(|| Error::integrity("Raw migration body is not qualified."))?
    };
    item.relative_path = crate::integrity::relative_path(&item.body_hash)?
        .to_string_lossy()
        .into_owned();
    *value = encode(&item)?;
    Ok(())
}
fn reference(value: &mut Value, mappings: &crate::migration_map::MigrationMap) -> Result<()> {
    let id = value
        .as_str()
        .ok_or_else(|| Error::integrity("Invalid chromium typed reference."))?;
    *value = json!(mapped(mappings, id)?);
    Ok(())
}
fn array(value: &mut Value, mappings: &crate::migration_map::MigrationMap) -> Result<()> {
    let values = value
        .as_array_mut()
        .ok_or_else(|| Error::integrity("Invalid chromium reference sequence."))?;
    for value in values {
        reference(value, mappings)?;
    }
    Ok(())
}
fn identity(kind: &str, old: &str, data: &Value) -> Result<String> {
    Ok(inventory::digest(
        &serde_json::to_vec(&("devres:storage-migration:chromium:v1", kind, old, data))
            .map_err(|_| failure())?,
    ))
}
impl ChromiumCorpus {
    async fn migration_page(
        &self,
        kind: &str,
        after: i64,
        cutoff: i64,
        extra: usize,
        cancel: &CancellationToken,
        execution: &crate::MigrationExecution,
    ) -> Result<(
        Vec<devres_application::chromium::Row>,
        crate::GraphReservation,
    )> {
        let positions = self
            .store
            .chromium_migration_positions(kind, after, execution.options().workers, cutoff)
            .await?;
        let (count, charge) =
            crate::mdn::corpus::migration::source_window(&positions, extra, execution)?;
        let reservation = execution.graph_reserve(charge, cancel).await?;
        if count == 0 {
            return Ok((Vec::new(), reservation));
        }
        let rows = self
            .store
            .chromium_rows(kind, after, count, Some(cutoff))
            .await?;
        if rows.len() != count
            || rows
                .iter()
                .zip(&positions)
                .any(|(row, position)| row.sequence != position.0 || row.key != position.1)
        {
            return Err(Error::integrity("Frozen provider source page changed."));
        }
        Ok((rows, reservation))
    }

    async fn migration_state(
        &self,
        key: &str,
        extra: usize,
        cancel: &CancellationToken,
        execution: &crate::MigrationExecution,
    ) -> Result<(Option<Value>, crate::GraphReservation)> {
        let size = self.store.chromium_migration_state_bytes(key).await?;
        let charge = size.map_or(Ok(1), |(bytes, nodes)| {
            crate::mdn::corpus::migration::source_charge(bytes, nodes, extra)
        })?;
        let reservation = execution.graph_reserve(charge, cancel).await?;
        Ok((self.store.chromium_state(key).await?, reservation))
    }

    async fn migration_operational_state(
        &self,
        key: &str,
        cancel: &CancellationToken,
        execution: &crate::MigrationExecution,
    ) -> Result<Option<(Value, crate::GraphReservation)>> {
        let staged_key = format!("storage-migration:{key}");
        let mut charge = crate::mdn::corpus::migration::INDEX_REPLAY_BYTES;
        for candidate in [&staged_key, key] {
            if let Some((bytes, nodes)) =
                self.store.chromium_migration_state_bytes(candidate).await?
            {
                charge = charge
                    .checked_add(crate::mdn::corpus::migration::source_charge(
                        bytes, nodes, 0,
                    )?)
                    .ok_or_else(|| Error::capacity("Operational state accounting overflow."))?;
            }
        }
        let reservation = execution.graph_reserve(charge, cancel).await?;
        // The retained checkpoint is still integrity-verified before skipping it.
        if self.store.chromium_state(&staged_key).await?.is_some() {
            return Ok(None);
        }
        let value = self
            .store
            .chromium_state(key)
            .await?
            .ok_or_else(|| Error::integrity("Provider migration state vanished."))?;
        Ok(Some((value, reservation)))
    }

    /// Rebuild canonical content while retaining old snapshots, sequences and indexes.
    /// Only staged head records are written; the owner activates them atomically.
    pub async fn migrate_blake3_graph(
        &self,
        mappings: &mut crate::migration_map::MigrationMap,
        cancel: CancellationToken,
    ) -> Result<Aliases> {
        self.migrate_blake3_graph_with_execution(
            mappings,
            cancel,
            &crate::MigrationExecution::default(),
        )
        .await
    }

    pub async fn migrate_blake3_graph_with_execution(
        &self,
        mappings: &mut crate::migration_map::MigrationMap,
        cancel: CancellationToken,
        execution: &crate::MigrationExecution,
    ) -> Result<Aliases> {
        let _guard = self.processing.lock().await;
        let cutoff = self.store.chromium_cutoff().await?;
        let mut aliases = crate::migration_map::MigrationAliases::new(mappings)?;
        for kind in [
            "projection-chunks",
            "projection-references",
            "index-documents",
        ] {
            let mut after = 0;
            loop {
                check(&cancel)?;
                let (rows, page_reservation) = self
                    .migration_page(kind, after, cutoff, 0, &cancel, execution)
                    .await?;
                if rows.is_empty() {
                    break;
                }
                after = rows.last().map_or(after, |row| row.sequence);
                let mut pending = VecDeque::new();
                for row in rows {
                    if !row.key.starts_with("blake3:") {
                        let charge = crate::MigrationExecution::graph_value_charge(&row.data)?
                            .saturating_mul(3)
                            .saturating_add(4096);
                        pending.push_back((row, charge));
                    }
                }
                while !pending.is_empty() {
                    let prepared = execution
                        .graph_map_ordered_reserved(
                            crate::mdn::corpus::migration::graph_window(&mut pending, execution)
                                .into_iter()
                                .map(|(row, _)| row)
                                .collect(),
                            page_reservation.clone(),
                            &cancel,
                            |row, token| async move {
                                execution
                                    .run(&token, move |token| {
                                        check(&token)?;
                                        let mut data = row.data;
                                        let id = if kind == "index-documents" {
                                            if data["id"].as_str() != Some(&row.key) {
                                                return Err(Error::integrity(
                                                    "chromium frozen posting identity mismatch.",
                                                ));
                                            }
                                            data["id"] = json!("");
                                            let id = identity(kind, &row.key, &data)?;
                                            data["id"] = json!(id);
                                            id
                                        } else {
                                            let bytes =
                                                serde_json::to_vec(&data).map_err(|_| failure())?;
                                            crate::integrity::verify(&row.key, &bytes)?;
                                            inventory::digest(&bytes)
                                        };
                                        Ok((row.key, id, data))
                                    })
                                    .await
                            },
                        )
                        .await?;
                    for prepared in prepared {
                        let (old, id, data) = prepared.value();
                        self.store.chromium_put(kind, id, data).await?;
                        record(mappings, &mut aliases, kind, old, id)?;
                    }
                }
            }
        }
        // Shared objects form an acyclic graph, but kinds are interleaved: text
        // sequences precede section objects, which precede section sequences.
        loop {
            let mut unresolved = 0usize;
            let mut progress = 0usize;
            for kind in [
                "projection-sequences",
                "projection-sections",
                "projection-symbols",
            ] {
                let mut after = 0;
                loop {
                    check(&cancel)?;
                    let (rows, _page_reservation) = self
                        .migration_page(
                            kind,
                            after,
                            cutoff,
                            crate::mdn::corpus::migration::INDEX_REPLAY_BYTES,
                            &cancel,
                            execution,
                        )
                        .await?;
                    if rows.is_empty() {
                        break;
                    }
                    for row in rows {
                        after = row.sequence;
                        if row.key.starts_with("blake3:")
                            || crate::integrity::migration_lookup(
                                mappings,
                                &format!("chromium:{kind}"),
                                &row.key,
                            )
                            .is_some()
                        {
                            continue;
                        }
                        crate::integrity::verify(
                            &row.key,
                            &serde_json::to_vec(&row.data).map_err(|_| failure())?,
                        )?;
                        let mut data = row.data;
                        let resolved = if kind == "projection-sequences" {
                            if data.get("children").is_some() {
                                array(&mut data["children"], mappings)
                            } else if data.get("values").is_some() {
                                array(&mut data["values"], mappings)
                            } else {
                                return Err(Error::integrity(
                                    "Unknown chromium projection sequence.",
                                ));
                            }
                        } else {
                            reference(&mut data["text"], mappings)
                        };
                        if resolved.is_err() {
                            unresolved += 1;
                            continue;
                        }
                        let id =
                            inventory::digest(&serde_json::to_vec(&data).map_err(|_| failure())?);
                        self.store.chromium_put(kind, &id, &data).await?;
                        record(mappings, &mut aliases, kind, &row.key, &id)?;
                        progress += 1;
                    }
                }
            }
            if unresolved == 0 {
                break;
            }
            if progress == 0 {
                return Err(Error::integrity(
                    "Missing or cyclic chromium projection references.",
                ));
            }
        }
        let mut after = 0;
        loop {
            check(&cancel)?;
            let (rows, _page_reservation) = self
                .migration_page(
                    "projections",
                    after,
                    cutoff,
                    crate::mdn::corpus::migration::INDEX_REPLAY_BYTES,
                    &cancel,
                    execution,
                )
                .await?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                after = row.sequence;
                if row.key.starts_with("blake3:") {
                    continue;
                }
                let mut data = row.data;
                if let Some(manifest) = data.get_mut("manifest") {
                    for field in ["text", "sections", "symbols", "references"] {
                        reference(&mut manifest[field], mappings)?;
                    }
                }
                if data.get("artifact").is_some() {
                    artifact(&mut data["artifact"], mappings)?;
                }
                if data.get("index_membership").is_some() {
                    reference(&mut data["index_membership"], mappings)?;
                }
                if data.get("index_ids").is_some() {
                    array(&mut data["index_ids"], mappings)?;
                }
                let id = identity("projections", &row.key, &data)?;
                self.store.chromium_put("projections", &id, &data).await?;
                record(mappings, &mut aliases, "projections", &row.key, &id)?;
            }
        }
        for kind in ["ref-pages", "tree-pages"] {
            let mut after = 0;
            loop {
                check(&cancel)?;
                let (rows, _page_reservation) = self
                    .migration_page(
                        kind,
                        after,
                        cutoff,
                        crate::mdn::corpus::migration::INDEX_REPLAY_BYTES,
                        &cancel,
                        execution,
                    )
                    .await?;
                if rows.is_empty() {
                    break;
                }
                for row in rows {
                    after = row.sequence;
                    if row.key.starts_with("blake3:") {
                        continue;
                    }
                    let bytes = serde_json::to_vec(&row.data).map_err(|_| failure())?;
                    crate::integrity::verify(&row.key, &bytes)?;
                    let id = inventory::digest(&bytes);
                    self.store.chromium_put(kind, &id, &row.data).await?;
                    record(mappings, &mut aliases, kind, &row.key, &id)?;
                }
            }
        }
        let mut proofs = BTreeMap::<String, Value>::new();
        for kind in ["publications", "observations", "catalogs"] {
            let mut after = 0;
            loop {
                check(&cancel)?;
                let (rows, _page_reservation) = self
                    .migration_page(
                        kind,
                        after,
                        cutoff,
                        crate::mdn::corpus::migration::INDEX_REPLAY_BYTES,
                        &cancel,
                        execution,
                    )
                    .await?;
                if rows.is_empty() {
                    break;
                }
                for row in rows {
                    after = row.sequence;
                    if row.key.starts_with("blake3:") {
                        continue;
                    }
                    let mut data = row.data;
                    for field in ["artifact", "manifest", "commits"] {
                        if data[field].is_object() && data[field].get("body_hash").is_some() {
                            artifact(&mut data[field], mappings)?;
                        }
                    }
                    if kind == "observations" {
                        crate::mdn::corpus::migration::rewrite_operational(
                            "chromium", &mut data, mappings, 0,
                        )?;
                    }
                    if kind == "publications" && data["artifact"].is_object() {
                        let raw: BulkArtifact = decode(data["artifact"].clone())?;
                        data["chunk_hashes"] =
                            json!(self.publication_chunks(&raw, cancel.clone()).await?);
                    }
                    if data.get("metadata_parent").is_some_and(Value::is_string) {
                        reference(&mut data["metadata_parent"], mappings)?;
                    }
                    if data.get("id").is_some() {
                        data["id"] = json!("");
                    }
                    let id = identity(kind, &row.key, &data)?;
                    if data.get("id").is_some() {
                        data["id"] = json!(id);
                    }
                    self.store.chromium_put(kind, &id, &data).await?;
                    record(mappings, &mut aliases, kind, &row.key, &id)?;
                    if kind == "publications" {
                        proofs.insert(id.clone(), data["chunk_hashes"].clone());
                        crate::migration_map::insert(
                            mappings,
                            format!("chromium:publication-proofs:{id}"),
                            serde_json::to_string(&data["chunk_hashes"]).map_err(|_| failure())?,
                        )?;
                    }
                    if kind == "catalogs"
                        && self
                            .store
                            .chromium_state("catalog")
                            .await?
                            .as_ref()
                            .and_then(Value::as_str)
                            == Some(&row.key)
                    {
                        self.store
                            .chromium_set_state("storage-migration:catalog", &json!(id))
                            .await?;
                    }
                }
            }
        }
        let mut after = 0;
        loop {
            check(&cancel)?;
            let (rows, reservation) = self
                .migration_page(
                    "snapshots",
                    after,
                    cutoff,
                    crate::mdn::corpus::migration::INDEX_REPLAY_BYTES,
                    &cancel,
                    execution,
                )
                .await?;
            if rows.is_empty() {
                break;
            }
            // Prepare file-only frozen replays concurrently; SQL inventories and
            // snapshot sequences are still published in their original source order.
            let mut references = BTreeMap::new();
            for row in &rows {
                let reference = &row.data["index"];
                if !row.key.starts_with("blake3:") && !reference.is_null() {
                    let key = serde_json::to_string(reference)
                        .map_err(|_| Error::integrity("Invalid frozen index reference."))?;
                    if mappings
                        .get(&format!("chromium:index-reference:{key}"))
                        .is_none()
                    {
                        references.entry(key).or_insert_with(|| reference.clone());
                    }
                }
            }
            let frozen_mappings = &*mappings;
            let prepared_indexes = execution
                .graph_map_ordered_reserved(
                    references.into_iter().collect(),
                    reservation.clone(),
                    &cancel,
                    |(key, reference), token| async move {
                        let canonical = self
                            .replay_frozen_index(&reference, frozen_mappings, token, execution)
                            .await?;
                        Ok((key, canonical))
                    },
                )
                .await?;
            for row in rows {
                after = row.sequence;
                if row.key.starts_with("blake3:") {
                    continue;
                }
                let mut snapshot: Snapshot = decode(row.data)?;
                if snapshot.id != row.key {
                    return Err(Error::integrity(
                        "chromium frozen snapshot identity mismatch.",
                    ));
                }
                let old_root = snapshot.inventory.clone();
                snapshot.inventory =
                    inventory::rebuild_inventory(self.store.as_ref(), &old_root, |mut member| {
                        if let Some(id) = &member.projection {
                            member.projection = Some(mapped_role(mappings, "projections", id)?);
                        }
                        if let Some(raw) = member.raw.as_mut() {
                            if raw["artifact"].is_object() {
                                artifact(&mut raw["artifact"], mappings)?;
                            }
                            if raw["publication"].is_string() {
                                reference(&mut raw["publication"], mappings)?;
                                let id = raw["publication"].as_str().ok_or_else(failure)?;
                                if raw.get("chunk_hashes").is_some() {
                                    raw["chunk_hashes"] =
                                        proofs.get(id).cloned().ok_or_else(|| {
                                            Error::integrity(
                                                "chromium migrated range proofs missing.",
                                            )
                                        })?;
                                }
                            }
                        }
                        Ok(member)
                    })
                    .await?;
                record(
                    mappings,
                    &mut aliases,
                    "nodes",
                    &old_root,
                    &snapshot.inventory,
                )?;
                if snapshot.coverage["publication"].is_string() {
                    reference(&mut snapshot.coverage["publication"], mappings)?;
                }
                if !snapshot.index.is_null() {
                    let cache_key =
                        serde_json::to_string(&snapshot.index).map_err(|_| failure())?;
                    snapshot.index = if let Some(reference) =
                        mappings.get(&format!("chromium:index-reference:{cache_key}"))
                    {
                        serde_json::from_str(&reference)
                            .map_err(|_| Error::integrity("Invalid canonical index reference."))?
                    } else {
                        prepared_indexes
                            .iter()
                            .find(|prepared| prepared.value().0 == cache_key)
                            .map(|prepared| prepared.value().1.clone())
                            .ok_or_else(|| Error::integrity("Frozen index preparation missing."))?
                    };
                    // Every use re-verifies both retained and canonical evidence.
                    drop(
                        self.index
                            .frozen_documents_with_execution(
                                &serde_json::from_str(&cache_key).map_err(|_| {
                                    Error::integrity("Invalid frozen index reference.")
                                })?,
                                cancel.clone(),
                                execution,
                            )
                            .await?,
                    );
                    drop(
                        self.index
                            .frozen_documents_with_execution(
                                &snapshot.index,
                                cancel.clone(),
                                execution,
                            )
                            .await?,
                    );
                    crate::migration_map::insert(
                        mappings,
                        format!("chromium:index-reference:{cache_key}"),
                        serde_json::to_string(&snapshot.index)
                            .map_err(|_| Error::integrity("Invalid canonical index reference."))?,
                    )?;
                }
                snapshot.id.clear();
                let id = identity("snapshots", &row.key, &encode(&snapshot)?)?;
                snapshot.id = id.clone();
                self.store
                    .chromium_put("snapshots", &id, &encode(&snapshot)?)
                    .await?;
                record(mappings, &mut aliases, "snapshots", &row.key, &id)?;
                let collection_version = snapshot.coverage["collection_version"]
                    .as_u64()
                    .unwrap_or(1) as u32;
                let alias = alias_for_collection(
                    &snapshot.component,
                    &snapshot.repository,
                    &snapshot.revision,
                    &snapshot.representation,
                    collection_version,
                )?;
                let old_alias_bytes = if collection_version == 1 {
                    serde_json::to_vec(&(
                        &snapshot.component,
                        &snapshot.repository,
                        &snapshot.revision,
                        &snapshot.representation,
                        snapshot.processor_version,
                    ))
                } else {
                    serde_json::to_vec(&(
                        &snapshot.component,
                        &snapshot.repository,
                        &snapshot.revision,
                        &snapshot.representation,
                        snapshot.processor_version,
                        collection_version,
                    ))
                }
                .map_err(|_| failure())?;
                let old_alias = crate::integrity::legacy_hash(&old_alias_bytes);
                record(mappings, &mut aliases, "snapshot-keys", &old_alias, &alias)?;
                self.store
                    .chromium_put("snapshot-keys", &alias, &json!(id))
                    .await?;
            }
        }
        let selected = {
            let (selected, _reservation) = self
                .migration_state("default", 0, &cancel, execution)
                .await?;
            selected.and_then(|v| v["id"].as_str().map(str::to_owned))
        };
        let mut after = 0;
        loop {
            check(&cancel)?;
            let (rows, _page_reservation) = self
                .migration_page(
                    "views",
                    after,
                    cutoff,
                    crate::mdn::corpus::migration::INDEX_REPLAY_BYTES,
                    &cancel,
                    execution,
                )
                .await?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                after = row.sequence;
                if row.key.starts_with("blake3:") {
                    continue;
                }
                let mut view: View = decode(row.data)?;
                view.catalog = mapped_role(mappings, "catalogs", &view.catalog)?;
                for id in view.snapshots.values_mut() {
                    *id = mapped_role(mappings, "snapshots", id)?;
                }
                if !view.index.is_null() {
                    view.index = self
                        .replay_frozen_index(&view.index, mappings, cancel.clone(), execution)
                        .await?;
                }
                view.id.clear();
                view.id = identity("views", &row.key, &encode(&view)?)?;
                self.store
                    .chromium_put("views", &view.id, &encode(&view)?)
                    .await?;
                record(mappings, &mut aliases, "views", &row.key, &view.id)?;
                if selected.as_deref() == Some(&row.key) {
                    self.store
                        .chromium_set_state("storage-migration:default", &encode(&view)?)
                        .await?;
                }
            }
        }
        {
            let (source_index, _index_reservation) = self
                .migration_state(
                    "index",
                    crate::mdn::corpus::migration::INDEX_REPLAY_BYTES,
                    &cancel,
                    execution,
                )
                .await?;
            if let Some(index) = source_index
                && !index.is_null()
            {
                let canonical = self
                    .replay_frozen_index(&index, mappings, cancel.clone(), execution)
                    .await?;
                crate::migration_map::insert(
                    mappings,
                    format!(
                        "chromium:index-reference:{}",
                        serde_json::to_string(&index)
                            .map_err(|_| Error::integrity("Invalid old index reference."))?
                    ),
                    serde_json::to_string(&canonical)
                        .map_err(|_| Error::integrity("Invalid new index reference."))?,
                )?;
                self.store
                    .chromium_set_state("storage-migration:index", &canonical)
                    .await?;
            }
        }
        self.migrate_auxiliary_graph(mappings, &mut aliases, cutoff, &cancel, execution)
            .await?;
        mappings.ensure_healthy()?;
        aliases.ensure_healthy()?;
        Ok(aliases)
    }
    async fn replay_frozen_index(
        &self,
        reference: &Value,
        mappings: &crate::migration_map::MigrationMap,
        cancel: CancellationToken,
        execution: &crate::MigrationExecution,
    ) -> Result<Value> {
        let mut reader = self
            .index
            .frozen_documents_with_execution(reference, cancel.clone(), execution)
            .await?;
        let mut canonical = None;
        loop {
            check(&cancel)?;
            let (ids, has_more) = reader.next_page(100).await?;
            let mut documents = Vec::new();
            let mut text_bytes = 0_usize;
            for id in ids {
                let canonical_id = mapped_role(mappings, "index-documents", &id)?;
                let row = self
                    .store
                    .chromium_get("index-documents", &canonical_id)
                    .await?
                    .ok_or_else(|| Error::integrity("chromium frozen index payload missing."))?;
                let document: crate::chromium::index::IndexDocument = decode(row.data)?;
                crate::chromium::index::ChromiumIndex::validate_document_bounds(&document)?;
                // Preserve the original 100-ID publication groups and the index
                // engine's existing 64MiB text admission, before retaining more rows.
                text_bytes = text_bytes
                    .checked_add(document.text.len())
                    .ok_or_else(|| Error::capacity("Frozen index replay text size overflow."))?;
                if text_bytes > 64 * 1024 * 1024 {
                    return Err(Error::capacity("Frozen index replay text budget exceeded."));
                }
                documents.push(document);
            }
            canonical = Some(
                self.index
                    .publish_with_execution(
                        canonical.as_ref(),
                        documents,
                        cancel.clone(),
                        execution,
                    )
                    .await?,
            );
            if !has_more {
                break;
            }
        }
        canonical.ok_or_else(failure)
    }
}

impl ChromiumCorpus {
    async fn migrate_auxiliary_graph(
        &self,
        mappings: &mut crate::migration_map::MigrationMap,
        aliases: &mut Aliases,
        cutoff: i64,
        cancel: &CancellationToken,
        execution: &crate::MigrationExecution,
    ) -> Result<()> {
        let kinds = self.store.chromium_migration_kinds().await?;
        const CORE: &[&str] = &[
            "projection-chunks",
            "projection-references",
            "index-documents",
            "projection-sequences",
            "projection-sections",
            "projection-symbols",
            "projections",
            "publications",
            "observations",
            "catalogs",
            "nodes",
            "snapshots",
            "views",
        ];
        const AUX: &[&str] = &[
            "blocked-jobs",
            "commits",
            "derived-inventories",
            "document-members",
            "failed-pages",
            "freezes",
            "history-gaps",
            "index-recoveries",
            "indexed",
            "jobs",
            "license-notices",
            "license-scopes",
            "notice-objects",
            "ref-pages",
            "sitemaps",
            "snapshot-keys",
            "tags",
            "traversal-gaps",
            "traversal-gap-manifests",
            "tree-pages",
            "trees",
            "validation-failures",
            "web-map-jobs",
            "web-page-jobs",
        ];
        for kind in &kinds {
            if !CORE.contains(&kind.as_str()) && !AUX.contains(&kind.as_str()) {
                return Err(Error::integrity(
                    "Unknown chromium migration evidence kind.",
                ));
            }
        }
        loop {
            let mut unresolved = 0usize;
            let mut progress = 0usize;
            for kind in AUX {
                let mut after = 0;
                loop {
                    check(cancel)?;
                    let (rows, _page_reservation) = self
                        .migration_page(
                            kind,
                            after,
                            cutoff,
                            crate::mdn::corpus::migration::INDEX_REPLAY_BYTES,
                            cancel,
                            execution,
                        )
                        .await?;
                    if rows.is_empty() {
                        break;
                    }
                    for row in rows {
                        after = row.sequence;
                        if row.key.starts_with("blake3:") {
                            continue;
                        }
                        if crate::integrity::migration_lookup(
                            mappings,
                            &format!("chromium:{kind}"),
                            &row.key,
                        )
                        .is_some()
                        {
                            continue;
                        }
                        let mut data = row.data;
                        if *kind == "snapshot-keys" && data.is_string() {
                            reference_aux("chromium", &mut data, mappings, "snapshots")?;
                        }
                        if *kind == "indexed-membership" {
                            let old = data["id"].as_str().ok_or_else(|| {
                                Error::integrity("Invalid migrated index marker.")
                            })?;
                            data["id"] = json!(mapped_role(mappings, "index-documents", old)?);
                        }
                        let mut references = Vec::new();
                        crate::mdn::corpus::migration::collect_index_references(
                            &data,
                            0,
                            &mut references,
                        )?;
                        for reference in references {
                            let key = serde_json::to_string(&reference).map_err(|_| {
                                Error::integrity("Invalid retained index reference.")
                            })?;
                            if crate::integrity::migration_lookup(
                                mappings,
                                "chromium:index-reference",
                                &key,
                            )
                            .is_none()
                            {
                                let canonical = self
                                    .replay_frozen_index(
                                        &reference,
                                        mappings,
                                        cancel.clone(),
                                        execution,
                                    )
                                    .await?;
                                crate::migration_map::insert(
                                    mappings,
                                    format!("chromium:index-reference:{key}"),
                                    serde_json::to_string(&canonical).map_err(|_| {
                                        Error::integrity("Invalid canonical index reference.")
                                    })?,
                                )?;
                            }
                        }
                        if let Err(error) = crate::mdn::corpus::migration::rewrite_operational(
                            "chromium", &mut data, mappings, 0,
                        ) {
                            if error.message.contains("Unresolved")
                                || error.message.contains("Missing typed")
                            {
                                unresolved += 1;
                                continue;
                            }
                            return Err(error);
                        }
                        let self_id = data["id"].as_str() == Some(&row.key);
                        if self_id {
                            data["id"] = json!("");
                        }
                        let default_id = inventory::digest(
                            &serde_json::to_vec(&(
                                "devres:storage-migration:chromium:aux:v1",
                                kind,
                                &row.key,
                                &data,
                            ))
                            .map_err(|_| {
                                Error::integrity("Invalid chromium auxiliary migration evidence.")
                            })?,
                        );
                        let id = match *kind {
                            "catalog-captures" => crate::integrity::migration_lookup(
                                mappings,
                                "chromium:catalogs",
                                &row.key,
                            )
                            .ok_or_else(|| {
                                Error::integrity("Missing canonical catalogue companion.")
                            })?,
                            "snapshot-keys" if crate::integrity::valid_hash(&row.key) => {
                                crate::integrity::migration_lookup(
                                    mappings,
                                    "chromium:snapshot-keys",
                                    &row.key,
                                )
                                .ok_or_else(|| {
                                    Error::integrity("Missing canonical snapshot selector.")
                                })?
                            }
                            "indexed-membership" => inventory::digest(
                                format!(
                                    "{}:{}",
                                    data["generation"].as_u64().ok_or_else(|| Error::integrity(
                                        "Invalid index generation."
                                    ))?,
                                    data["id"].as_str().ok_or_else(|| Error::integrity(
                                        "Invalid index identity."
                                    ))?
                                )
                                .as_bytes(),
                            ),
                            _ => default_id,
                        };
                        if self_id {
                            data["id"] = json!(id);
                        }
                        self.store.chromium_put(kind, &id, &data).await?;
                        progress += 1;
                        record(mappings, aliases, kind, &row.key, &id)?;
                        if *kind == "indexed" {
                            let (generation, old) = row.key.split_once(':').ok_or_else(|| {
                                Error::integrity("Invalid Chromium index marker key.")
                            })?;
                            let canonical_doc = mapped_role(mappings, "index-documents", old)?;
                            record(
                                mappings,
                                aliases,
                                kind,
                                &format!("{generation}:{canonical_doc}"),
                                &id,
                            )?;
                        }
                    }
                }
            }

            if unresolved == 0 {
                break;
            }
            if progress == 0 {
                return Err(Error::integrity(
                    "Missing or cyclic chromium auxiliary migration references.",
                ));
            }
        }
        let mut after = String::new();
        loop {
            check(cancel)?;
            let keys = self
                .store
                .chromium_migration_state_keys(&after, 100)
                .await?;
            if keys.is_empty() {
                break;
            }
            for key in keys {
                after = key.clone();
                if key.starts_with("storage-migration:") {
                    continue;
                }
                let Some((mut data, _state_reservation)) = self
                    .migration_operational_state(&key, cancel, execution)
                    .await?
                else {
                    continue;
                };
                let mut references = Vec::new();
                crate::mdn::corpus::migration::collect_index_references(&data, 0, &mut references)?;
                for reference in references {
                    let key = serde_json::to_string(&reference)
                        .map_err(|_| Error::integrity("Invalid retained index reference."))?;
                    if crate::integrity::migration_lookup(
                        mappings,
                        "chromium:index-reference",
                        &key,
                    )
                    .is_none()
                    {
                        let canonical = self
                            .replay_frozen_index(&reference, mappings, cancel.clone(), execution)
                            .await?;
                        crate::migration_map::insert(
                            mappings,
                            format!("chromium:index-reference:{key}"),
                            serde_json::to_string(&canonical).map_err(|_| {
                                Error::integrity("Invalid canonical index reference.")
                            })?,
                        )?;
                    }
                }
                let mut roots = BTreeSet::new();
                crate::mdn::corpus::migration::collect_inventory_roots(&data, 0, &mut roots)?;
                for root in roots {
                    if crate::integrity::migration_lookup(mappings, "chromium:nodes", &root)
                        .is_none()
                    {
                        let canonical =
                            inventory::rebuild_inventory(self.store.as_ref(), &root, |member| {
                                let mut value = crate::mdn::inventory::value(&member)?;
                                crate::mdn::corpus::migration::rewrite_operational(
                                    "chromium", &mut value, mappings, 0,
                                )?;
                                crate::mdn::inventory::decode(value)
                            })
                            .await?;
                        record(mappings, aliases, "nodes", &root, &canonical)?;
                    }
                }
                crate::mdn::corpus::migration::rewrite_operational(
                    "chromium", &mut data, mappings, 0,
                )?;
                let mut target = key.clone();
                if let Some((prefix, suffix)) = key.split_once(':') {
                    let role = match prefix {
                        "snapshot-index" => Some("snapshots"),
                        "view-index" => Some("views"),
                        "revision-alias" => Some("snapshot-keys"),
                        _ => None,
                    };
                    if let Some(role) = role {
                        let namespace = format!("chromium:{role}");
                        if let Some(canonical) = mappings.lookup_legacy_key_hash(&namespace, suffix)
                        {
                            target = format!(
                                "{prefix}:{}",
                                crate::integrity::legacy_hash(canonical.as_bytes())
                            );
                        }
                    }
                    if data.is_string() {
                        let role = match prefix {
                            "current" | "prepared" => Some("snapshots"),
                            "publication" | "publication-usable" => Some("publications"),
                            _ => None,
                        };
                        if let Some(role) = role {
                            reference_aux("chromium", &mut data, mappings, role)?;
                        }
                    }
                }
                self.store
                    .chromium_set_state(&format!("storage-migration:{target}"), &data)
                    .await?;
            }
        }
        self.store
            .chromium_set_state(
                "storage-migration:graph-complete",
                &json!({"version":1,"legacy_cutoff":cutoff,"complete":true}),
            )
            .await?;
        Ok(())
    }
}

fn reference_aux(
    provider: &str,
    value: &mut Value,
    mappings: &crate::migration_map::MigrationMap,
    kind: &str,
) -> Result<()> {
    let old = value
        .as_str()
        .ok_or_else(|| Error::integrity("Invalid auxiliary reference."))?;
    if old.starts_with("blake3:") {
        return Ok(());
    }
    *value = json!(
        crate::integrity::migration_lookup(mappings, &format!("{provider}:{kind}"), old)
            .ok_or_else(|| Error::integrity("Unresolved auxiliary reference."))?
    );
    Ok(())
}

impl ChromiumCorpus {
    /// Read-only closure/integrity verification for every retained generation.
    /// Missing descendants are errors even when all remaining rows hash correctly.
    pub async fn verify_blake3_graph(&self, cancel: CancellationToken) -> Result<()> {
        for kind in self.store.chromium_migration_kinds().await? {
            if !known_evidence_kind(&kind) {
                return Err(Error::integrity("Unknown retained chromium evidence kind."));
            }
        }

        for kind in [
            "commits",
            "traversal-gaps",
            "traversal-gap-manifests",
            "nodes",
            "projection-chunks",
            "projection-sequences",
            "projection-sections",
            "projection-symbols",
            "projection-references",
            "projections",
            "index-documents",
            "snapshots",
            "views",
            "publications",
            "observations",
            "validation-failures",
        ] {
            let mut after = 0;
            loop {
                check(&cancel)?;
                let rows = self.store.chromium_migration_rows(kind, after, 100).await?;
                if rows.is_empty() {
                    break;
                }
                for row in rows {
                    check(&cancel)?;
                    after = row.sequence;
                    match kind {
                        "commits" => {
                            if let Some(proof) = row
                                .data
                                .get("timestamp_proof")
                                .filter(|proof| !proof.is_null())
                            {
                                if !matches!(row.data["component"].as_str(), Some("src" | "site")) {
                                    return Err(Error::integrity(
                                        "Invalid raw timestamp proof component.",
                                    ));
                                }
                                let commit: Commit = decode(row.data["commit"].clone())?;
                                let proof: source::RawTimestampProof = decode(proof.clone())?;
                                proof.validate(&commit)?;
                            }
                        }
                        "validation-failures" => {
                            Self::verify_failed_observation(&row.key, &row.data)?
                        }
                        "traversal-gaps" => self.verify_traversal_gap(&row.key, &row.data).await?,
                        "traversal-gap-manifests" => {
                            crate::integrity::verify(
                                &row.key,
                                &serde_json::to_vec(&row.data).map_err(|_| failure())?,
                            )?;
                            let count = row.data["count"]
                                .as_u64()
                                .filter(|count| *count > 0)
                                .ok_or_else(failure)?;
                            if row.data["gap"].is_string() {
                                self.verify_gap_manifest(&row.key, count, &cancel).await?;
                            } else {
                                if row.data.as_object().is_none_or(|object| object.len() != 3) {
                                    return Err(Error::integrity(
                                        "Invalid Chromium traversal gap branch.",
                                    ));
                                }
                                let mut total = 0_u64;
                                for side in ["left", "right"] {
                                    let child = row.data[side].as_str().ok_or_else(failure)?;
                                    let retained = self
                                        .store
                                        .chromium_get("traversal-gap-manifests", child)
                                        .await?
                                        .ok_or_else(|| {
                                            Error::integrity(
                                                "Chromium traversal gap child is missing.",
                                            )
                                        })?;
                                    total = total
                                        .checked_add(
                                            retained.data["count"].as_u64().ok_or_else(failure)?,
                                        )
                                        .ok_or_else(|| {
                                            Error::integrity(
                                                "Chromium traversal gap count overflow.",
                                            )
                                        })?;
                                }
                                if total != count {
                                    return Err(Error::integrity(
                                        "Chromium traversal gap branch count mismatch.",
                                    ));
                                }
                            }
                        }
                        "nodes" => {
                            let node = inventory::node(self.store.as_ref(), &row.key).await?;
                            for id in node.children.values().chain(node.buckets.values()) {
                                self.verify_edge("nodes", id).await?;
                            }
                            if let Some(member) = node.member {
                                if let Some(projection) = member.projection {
                                    self.verify_edge("projections", &projection).await?;
                                }
                                if let Some(raw) = member.raw
                                    && raw["artifact"].is_object()
                                {
                                    self.verify_raw_descriptor(&raw["artifact"], &cancel)
                                        .await?;
                                }
                            }
                        }
                        "projection-chunks"
                        | "projection-sequences"
                        | "projection-sections"
                        | "projection-symbols"
                        | "projection-references" => {
                            crate::integrity::verify(
                                &row.key,
                                &serde_json::to_vec(&row.data).map_err(|_| failure())?,
                            )?;
                            if kind == "projection-sequences" {
                                if let Some(children) = row.data["children"].as_array() {
                                    for id in children {
                                        self.verify_edge(
                                            "projection-sequences",
                                            id.as_str().ok_or_else(failure)?,
                                        )
                                        .await?;
                                    }
                                } else if let Some(values) = row.data["values"].as_array() {
                                    for id in values {
                                        let id = id.as_str().ok_or_else(failure)?;
                                        let mut present = false;
                                        for target in [
                                            "projection-chunks",
                                            "projection-sections",
                                            "projection-symbols",
                                            "projection-references",
                                            "index-documents",
                                        ] {
                                            present |= self
                                                .store
                                                .chromium_get(target, id)
                                                .await?
                                                .is_some();
                                        }
                                        if !present {
                                            return Err(Error::integrity(
                                                "Retained chromium sequence target is missing.",
                                            ));
                                        }
                                    }
                                } else {
                                    return Err(Error::integrity(
                                        "Unknown chromium sequence variant.",
                                    ));
                                }
                            } else if kind == "projection-sections" || kind == "projection-symbols"
                            {
                                self.verify_sequence(
                                    row.data["text"].as_str().ok_or_else(failure)?,
                                    "projection-chunks",
                                    &cancel,
                                )
                                .await?;
                            }
                        }
                        "projections" => {
                            if let Some(manifest) = row.data.get("manifest") {
                                for (field, target) in [
                                    ("text", "projection-chunks"),
                                    ("sections", "projection-sections"),
                                    ("symbols", "projection-symbols"),
                                    ("references", "projection-references"),
                                ] {
                                    self.verify_sequence(
                                        manifest[field].as_str().ok_or_else(failure)?,
                                        target,
                                        &cancel,
                                    )
                                    .await?;
                                }
                            }
                            if let Some(root) = row.data["index_membership"].as_str() {
                                self.verify_sequence(root, "index-documents", &cancel)
                                    .await?;
                            }
                            if let Some(ids) = row.data["index_ids"].as_array() {
                                for id in ids {
                                    self.verify_edge(
                                        "index-documents",
                                        id.as_str().ok_or_else(failure)?,
                                    )
                                    .await?;
                                }
                            }
                            if row.data["artifact"].is_object() {
                                self.verify_raw_descriptor(&row.data["artifact"], &cancel)
                                    .await?;
                            }
                        }
                        "index-documents" => {
                            let document: IndexDocument = decode(row.data)?;
                            if document.id != row.key {
                                return Err(Error::integrity(
                                    "Retained chromium posting identity mismatch.",
                                ));
                            }
                        }
                        "snapshots" => {
                            let snapshot: Snapshot = decode(row.data)?;
                            if snapshot.id != row.key {
                                return Err(Error::integrity(
                                    "Retained chromium snapshot identity mismatch.",
                                ));
                            }
                            self.verify_edge("nodes", &snapshot.inventory).await?;
                            let gaps = snapshot.coverage["traversal_gaps"].as_u64().unwrap_or(0);
                            if let Some(root) = snapshot.coverage["traversal_gap_root"].as_str() {
                                self.verify_gap_manifest(root, gaps, &cancel).await?;
                            } else if gaps != 0 {
                                return Err(Error::integrity(
                                    "Chromium traversal gap coverage root is missing.",
                                ));
                            }
                            if gaps > 0 && snapshot.coverage["complete"] == true {
                                return Err(Error::integrity(
                                    "Chromium traversal gaps are marked complete.",
                                ));
                            }
                            if !snapshot.index.is_null() {
                                self.verify_frozen_index(&snapshot.index, &cancel).await?;
                            }
                            if let Some(id) = snapshot.coverage["publication"].as_str() {
                                self.verify_edge("publications", id).await?;
                            }
                        }
                        "views" => {
                            let view: View = decode(row.data)?;
                            if view.id != row.key {
                                return Err(Error::integrity(
                                    "Retained chromium view identity mismatch.",
                                ));
                            }
                            self.verify_edge("catalogs", &view.catalog).await?;
                            for id in view.snapshots.values() {
                                self.verify_edge("snapshots", id).await?;
                            }
                            if !view.index.is_null() {
                                self.verify_frozen_index(&view.index, &cancel).await?;
                            }
                        }
                        "publications" => {
                            if row.data["artifact"].is_object() {
                                self.verify_raw_descriptor(&row.data["artifact"], &cancel)
                                    .await?;
                                let artifact: BulkArtifact = decode(row.data["artifact"].clone())?;
                                let chunks: Vec<String> = decode(
                                    row.data
                                        .get("chunk_hashes")
                                        .cloned()
                                        .unwrap_or_else(|| json!([])),
                                )?;
                                if chunks.len() as u64 != artifact.bytes.div_ceil(4 * 1024 * 1024) {
                                    return Err(Error::integrity(
                                        "Retained publication range proof count mismatch.",
                                    ));
                                }
                                for block in 0..chunks.len() {
                                    check(&cancel)?;
                                    self.publication_page(
                                        &artifact,
                                        &chunks,
                                        (block as u64) * 4 * 1024 * 1024,
                                        1,
                                    )
                                    .await?;
                                }
                            }
                            if let Some(parent) = row.data["metadata_parent"].as_str() {
                                self.verify_edge("publications", parent).await?;
                            }
                        }
                        "observations" => {
                            if let Some(pages) = row.data["ref_pages"].as_array() {
                                for id in pages {
                                    self.verify_edge("ref-pages", id.as_str().ok_or_else(failure)?)
                                        .await?;
                                }
                            }
                        }
                        _ => {
                            return Err(Error::integrity(
                                "Unknown retained chromium verification kind.",
                            ));
                        }
                    }
                }
            }
        }
        self.verify_gap_checkpoints(&cancel).await?;
        Ok(())
    }
    async fn verify_gap_coverage(&self, data: &Value, cancel: &CancellationToken) -> Result<()> {
        let count = data["traversal_gaps"].as_u64().unwrap_or(0);
        if let Some(root) = data["traversal_gap_root"].as_str() {
            self.verify_gap_manifest(root, count, cancel).await
        } else if count != 0 {
            Err(Error::integrity(
                "Chromium checkpoint traversal gap root is missing.",
            ))
        } else {
            Ok(())
        }
    }
    pub(super) async fn verify_gap_checkpoints(&self, cancel: &CancellationToken) -> Result<()> {
        let mut after = 0;
        loop {
            check(cancel)?;
            let rows = self
                .store
                .chromium_migration_rows("derived-inventories", after, 100)
                .await?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                after = row.sequence;
                if row.data.is_object() {
                    self.verify_gap_coverage(&row.data, cancel).await?;
                    self.verify_edge("nodes", row.data["inventory"].as_str().ok_or_else(failure)?)
                        .await?;
                } else {
                    self.verify_edge("nodes", row.data.as_str().ok_or_else(failure)?)
                        .await?;
                }
            }
        }
        let mut after = String::new();
        loop {
            check(cancel)?;
            let keys = self
                .store
                .chromium_migration_state_keys(&after, 100)
                .await?;
            if keys.is_empty() {
                break;
            }
            for key in keys {
                after = key.clone();
                if key.starts_with("validation-failure-v1:") {
                    let value = self.store.chromium_state(&key).await?.ok_or_else(failure)?;
                    let id = value.as_str().ok_or_else(failure)?;
                    let row = self
                        .store
                        .chromium_get("validation-failures", id)
                        .await?
                        .ok_or_else(failure)?;
                    Self::verify_failed_observation_pointer(&key, id, &row.data)?;
                }
                if !key.starts_with("work:") {
                    continue;
                }
                let work = self.store.chromium_state(&key).await?.ok_or_else(failure)?;
                self.verify_gap_coverage(&work, cancel).await?;
                self.verify_edge("nodes", work["inventory"].as_str().ok_or_else(failure)?)
                    .await?;
                let frames = work["stack"].as_array().ok_or_else(failure)?;
                if frames.len() > 64 {
                    return Err(Error::capacity(
                        "Chromium retained checkpoint depth exceeds its bound.",
                    ));
                }
                for frame in frames {
                    self.verify_gap_coverage(frame, cancel).await?;
                    self.verify_edge("nodes", frame["inventory"].as_str().ok_or_else(failure)?)
                        .await?;
                }
            }
        }
        Ok(())
    }
    async fn verify_traversal_gap(&self, id: &str, data: &Value) -> Result<()> {
        crate::integrity::verify(id, &serde_json::to_vec(data).map_err(|_| failure())?)?;
        if !data["component"]
            .as_str()
            .is_some_and(|value| COMPONENTS.contains(&value))
            || !data["revision"].as_str().is_some_and(source::valid_oid)
            || !data["parent_tree"].as_str().is_some_and(source::valid_oid)
            || !data["member_oid"].as_str().is_some_and(source::valid_oid)
            || !data["path_hash"]
                .as_str()
                .is_some_and(crate::integrity::valid_hash)
            || !matches!(
                data["code"].as_str(),
                Some("unsupported_path" | "tree_depth_exceeded")
            )
            || data["collection_version"] != COLLECTION_VERSION
        {
            return Err(Error::integrity("Invalid retained Chromium traversal gap."));
        }
        self.verify_edge("trees", data["parent_tree"].as_str().ok_or_else(failure)?)
            .await
    }
    pub(super) async fn verify_gap_manifest(
        &self,
        root: &str,
        count: u64,
        cancel: &CancellationToken,
    ) -> Result<()> {
        let mut pending = vec![(root.to_owned(), count)];
        let mut visited = BTreeSet::new();
        while let Some((id, expected)) = pending.pop() {
            check(cancel)?;
            if !visited.insert(id.clone()) {
                continue;
            }
            if visited.len() > MAX_MEMBERS.saturating_mul(2) {
                return Err(Error::capacity(
                    "Chromium traversal gap graph exceeds its verification bound.",
                ));
            }
            let row = self
                .store
                .chromium_get("traversal-gap-manifests", &id)
                .await?
                .ok_or_else(|| Error::integrity("Chromium traversal gap manifest is missing."))?;
            crate::integrity::verify(&id, &serde_json::to_vec(&row.data).map_err(|_| failure())?)?;
            if expected == 0 || row.data["count"].as_u64() != Some(expected) {
                return Err(Error::integrity("Chromium traversal gap count mismatch."));
            }
            if let Some(gap) = row.data["gap"].as_str() {
                if expected != 1 || row.data.as_object().is_none_or(|object| object.len() != 2) {
                    return Err(Error::integrity("Invalid Chromium traversal gap leaf."));
                }
                let retained = self
                    .store
                    .chromium_get("traversal-gaps", gap)
                    .await?
                    .ok_or_else(|| {
                        Error::integrity("Chromium traversal gap evidence is missing.")
                    })?;
                self.verify_traversal_gap(gap, &retained.data).await?;
            } else {
                if row.data.as_object().is_none_or(|object| object.len() != 3) {
                    return Err(Error::integrity("Invalid Chromium traversal gap branch."));
                }
                let mut total = 0_u64;
                for side in ["left", "right"] {
                    let child = row.data[side].as_str().ok_or_else(failure)?;
                    let retained = self
                        .store
                        .chromium_get("traversal-gap-manifests", child)
                        .await?
                        .ok_or_else(|| {
                            Error::integrity("Chromium traversal gap child is missing.")
                        })?;
                    let count = retained.data["count"].as_u64().ok_or_else(failure)?;
                    total = total.checked_add(count).ok_or_else(|| {
                        Error::integrity("Chromium traversal gap count overflow.")
                    })?;
                    pending.push((child.to_owned(), count));
                }
                if total != expected {
                    return Err(Error::integrity(
                        "Chromium traversal gap branch count mismatch.",
                    ));
                }
            }
        }
        Ok(())
    }
    async fn verify_edge(&self, kind: &str, id: &str) -> Result<()> {
        if self.store.chromium_get(kind, id).await?.is_none() {
            return Err(Error::integrity(
                "Retained chromium graph target is missing.",
            ));
        }
        Ok(())
    }
    async fn verify_sequence(
        &self,
        root: &str,
        kind: &str,
        cancel: &CancellationToken,
    ) -> Result<()> {
        check(cancel)?;
        let sequences = inventory::sequences(self.store.as_ref(), &[root.to_owned()]).await?;
        let ids = sequences
            .get(root)
            .ok_or_else(|| Error::integrity("Retained chromium sequence is missing."))?;
        for chunk in ids.chunks(100) {
            check(cancel)?;
            let unique = chunk
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            let rows = self.store.chromium_get_many(kind, &unique).await?;
            if rows.len() != unique.len() {
                return Err(Error::integrity(
                    "Retained chromium sequence member is missing.",
                ));
            }
        }
        Ok(())
    }
    async fn verify_raw_descriptor(&self, value: &Value, cancel: &CancellationToken) -> Result<()> {
        let artifact: BulkArtifact = decode(value.clone())?;
        let actual = self
            .raw
            .verify(
                &artifact.body_hash,
                crate::bulk::MAX_ARTIFACT_BYTES,
                cancel.clone(),
            )
            .await?;
        if actual != artifact {
            return Err(Error::integrity(
                "Retained chromium raw artifact metadata mismatch.",
            ));
        }
        Ok(())
    }
    async fn verify_frozen_index(&self, index: &Value, cancel: &CancellationToken) -> Result<()> {
        let mut reader = self.index.frozen_documents(index, cancel.clone()).await?;
        loop {
            check(cancel)?;
            let (ids, has_more) = reader.next_page(100).await?;
            let unique = ids
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            let rows = self
                .store
                .chromium_get_many("index-documents", &unique)
                .await?;
            if rows.len() != unique.len() {
                return Err(Error::integrity(
                    "Retained chromium posting payload is missing.",
                ));
            }
            for row in rows {
                let document: IndexDocument = decode(row.data)?;
                if document.id != row.key {
                    return Err(Error::integrity(
                        "Retained chromium posting payload mismatch.",
                    ));
                }
            }
            if !has_more {
                break;
            }
        }
        Ok(())
    }
}
