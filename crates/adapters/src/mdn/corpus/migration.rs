//! Frozen BLAKE3 graph migration. Source text is never reprocessed or fetched.
use super::*;
use crate::bulk::BulkArtifact;

type Aliases = crate::migration_map::MigrationAliases;
fn known_evidence_kind(kind: &str) -> bool {
    matches!(
        kind,
        "changes"
            | "changes-complete"
            | "commits"
            | "index-documents"
            | "nodes"
            | "observations"
            | "projection-headers"
            | "projections"
            | "snapshot-keys"
            | "snapshots"
            | "views"
    )
}
fn check(cancel: &CancellationToken) -> Result<()> {
    if cancel.is_cancelled() {
        return Err(Error::new("cancelled", "MDN graph migration canceled."));
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
            crate::integrity::migration_lookup(mappings, &format!("mdn:{kind}"), id)
        {
            if found.as_ref().is_some_and(|prior| prior != &value) {
                return Err(Error::integrity("Ambiguous mdn migration reference role."));
            }
            found = Some(value.clone());
        }
    }
    found.ok_or_else(|| Error::integrity("MDN migration reference is not qualified."))
}
fn mapped_role(
    mappings: &crate::migration_map::MigrationMap,
    kind: &str,
    id: &str,
) -> Result<String> {
    if id.starts_with("blake3:") && crate::integrity::valid_hash(id) {
        return Ok(id.to_owned());
    }
    crate::integrity::migration_lookup(mappings, &format!("mdn:{kind}"), id)
        .ok_or_else(|| Error::integrity("Missing typed migration reference."))
}
fn record(
    mappings: &mut crate::migration_map::MigrationMap,
    aliases: &mut Aliases,
    kind: &str,
    old: &str,
    new: &str,
) -> Result<()> {
    let scoped = format!("mdn:{kind}:{old}");
    if let Some(existing) = mappings.get(&scoped)
        && existing != new
    {
        return Err(Error::integrity("Conflicting MDN graph migration mapping."));
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
fn artifact(
    artifact: &mut BulkArtifact,
    mappings: &crate::migration_map::MigrationMap,
) -> Result<()> {
    artifact.body_hash = if artifact.body_hash.starts_with("blake3:") {
        artifact.body_hash.clone()
    } else {
        crate::integrity::migration_lookup(mappings, "body", &artifact.body_hash)
            .ok_or_else(|| Error::integrity("MDN raw migration body is not qualified."))?
    };
    artifact.relative_path = crate::integrity::relative_path(&artifact.body_hash)?
        .to_string_lossy()
        .into_owned();
    Ok(())
}
fn member(mut member: Member, mappings: &crate::migration_map::MigrationMap) -> Result<Member> {
    if let Some(path) =
        crate::integrity::migration_lookup(mappings, "mdn:member-path", &member.path)
    {
        member.path = path.clone();
    }
    if let Some(id) = &member.projection {
        member.projection = Some(mapped_role(mappings, "projections", id)?);
    }
    if let Some(raw) = member.raw.as_mut()
        && raw["git"] != true
    {
        let body = raw["body_hash"]
            .as_str()
            .ok_or_else(|| Error::integrity("Invalid MDN raw migration descriptor."))?;
        let body = if body.starts_with("blake3:") {
            body.to_owned()
        } else {
            crate::integrity::migration_lookup(mappings, "body", body)
                .ok_or_else(|| Error::integrity("MDN raw migration body is not qualified."))?
        };
        raw["body_hash"] = json!(body);
        raw["relative_path"] = json!(format!(
            "mdn/raw-artifacts/{}",
            crate::integrity::relative_path(&body)?.display()
        ));
    }
    Ok(member)
}

// Includes a 64 MiB Tantivy writer, bounded frozen pages and decoded input/output.
// This is an admission charge, not a process RSS measurement.
pub(crate) const INDEX_REPLAY_BYTES: usize = 320 * 1024 * 1024;

/// Structural metadata is computed before materializing PostgreSQL JSON values.
/// The charge covers decoded containers, cloned payload/envelope and preparation.
pub(crate) fn source_charge(bytes: usize, nodes: usize, extra: usize) -> Result<usize> {
    crate::MigrationExecution::graph_input_charge(bytes, nodes)?
        .checked_add(extra)
        .ok_or_else(|| Error::capacity("Provider source graph accounting overflow."))
}

pub(crate) fn source_window(
    positions: &[(i64, String, usize, usize)],
    extra: usize,
    execution: &crate::MigrationExecution,
) -> Result<(usize, usize)> {
    let mut count = 0usize;
    let mut charge = 0usize;
    let mut encoded = 0usize;
    let budget = execution.graph_options().memory_budget_bytes;
    let target = budget.saturating_sub(budget / 4).max(1);
    for (_, _, bytes, nodes) in positions.iter().take(execution.graph_window_limit(1)) {
        let item = source_charge(*bytes, *nodes, extra)?;
        let next = charge
            .checked_add(item)
            .ok_or_else(|| Error::capacity("Provider graph window accounting overflow."))?;
        let next_encoded = encoded
            .checked_add(*bytes)
            .ok_or_else(|| Error::capacity("Provider graph source length overflow."))?;
        if count != 0 && (next > target || next_encoded > 64 * 1024 * 1024) {
            break;
        }
        count += 1;
        charge = next;
        encoded = next_encoded;
        // A valid individual row may exceed aggregate admission; it runs alone.
        if charge > target {
            break;
        }
    }
    Ok((count, charge.max(1)))
}

/// Split before submission so completed results retain one bounded graph reservation.
pub(crate) fn graph_window<T>(
    pending: &mut std::collections::VecDeque<(T, usize)>,
    execution: &crate::MigrationExecution,
) -> Vec<(T, usize)> {
    let mut window = Vec::new();
    let mut bytes = 0usize;
    while window.len() < execution.graph_window_limit(1) {
        let Some((_, charge)) = pending.front() else {
            break;
        };
        if !window.is_empty()
            && bytes.saturating_add(*charge) > execution.graph_options().memory_budget_bytes
        {
            break;
        }
        bytes = bytes.saturating_add(*charge);
        if let Some(item) = pending.pop_front() {
            window.push(item);
        }
    }
    window
}

impl MdnCorpus {
    async fn migration_page(
        &self,
        kind: &str,
        after: i64,
        cutoff: i64,
        extra: usize,
        cancel: &CancellationToken,
        execution: &crate::MigrationExecution,
    ) -> Result<(
        Vec<devres_application::mdn::MdnRow>,
        crate::GraphReservation,
    )> {
        let positions = self
            .store
            .mdn_migration_positions(kind, after, execution.options().workers, cutoff)
            .await?;
        let (count, charge) =
            crate::mdn::corpus::migration::source_window(&positions, extra, execution)?;
        let reservation = execution.graph_reserve(charge, cancel).await?;
        if count == 0 {
            return Ok((Vec::new(), reservation));
        }
        let rows = self
            .store
            .mdn_rows(kind, after, count, Some(cutoff))
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
        let size = self.store.mdn_migration_state_bytes(key).await?;
        let charge = size.map_or(Ok(1), |(bytes, nodes)| {
            crate::mdn::corpus::migration::source_charge(bytes, nodes, extra)
        })?;
        let reservation = execution.graph_reserve(charge, cancel).await?;
        Ok((self.store.mdn_state(key).await?, reservation))
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
            if let Some((bytes, nodes)) = self.store.mdn_migration_state_bytes(candidate).await? {
                charge = charge
                    .checked_add(crate::mdn::corpus::migration::source_charge(
                        bytes, nodes, 0,
                    )?)
                    .ok_or_else(|| Error::capacity("Operational state accounting overflow."))?;
            }
        }
        let reservation = execution.graph_reserve(charge, cancel).await?;
        // The retained checkpoint is still integrity-verified before skipping it.
        if self.store.mdn_state(&staged_key).await?.is_some() {
            return Ok(None);
        }
        let value = self
            .store
            .mdn_state(key)
            .await?
            .ok_or_else(|| Error::integrity("Provider migration state vanished."))?;
        Ok(Some((value, reservation)))
    }

    /// Retain every old generation and stage canonical heads for final activation.
    /// The versioned migration preimage includes the original ID to preserve
    /// distinct historical rebuild occurrences with otherwise identical content.
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
        let cutoff = self.store.mdn_cutoff().await?;
        let mut aliases = crate::migration_map::MigrationAliases::new(mappings)?;
        let mut inventory_memo = inventory::MigrationInventory::new_shared(mappings)?;
        for kind in ["projections", "projection-headers", "index-documents"] {
            let mut after = 0;
            loop {
                check(&cancel)?;
                let (rows, page_reservation) = self
                    .migration_page(kind, after, cutoff, 0, &cancel, execution)
                    .await?;
                if rows.is_empty() {
                    break;
                }
                if kind != "projections" {
                    after = rows.last().map_or(after, |row| row.sequence);
                    let mut pending = std::collections::VecDeque::new();
                    for row in rows {
                        if !row.key.starts_with("blake3:") {
                            let charge = crate::MigrationExecution::graph_value_charge(&row.data)?
                                .saturating_mul(3)
                                .saturating_add(4096);
                            pending.push_back((row, charge));
                        }
                    }
                    while !pending.is_empty() {
                        let references = mappings.clone();
                        let prepared = execution
                            .graph_map_ordered_reserved(
                                graph_window(&mut pending, execution)
                                    .into_iter()
                                    .map(|(row, _)| row)
                                    .collect(),
                                page_reservation.clone(),
                                &cancel,
                                |row, token| {
                                    let references = references.clone();
                                    async move {
                                        execution
                                            .run(&token, move |token| {
                                                check(&token)?;
                                                let canonical = mapped_role(
                                                    &references,
                                                    "projections",
                                                    &row.key,
                                                )?;
                                                let mut data = row.data;
                                                if kind == "index-documents" {
                                                    let mut document: IndexDocument =
                                                        decoded(data)?;
                                                    if document.id != row.key {
                                                        return Err(Error::integrity(
                                                            "MDN index document identity mismatch.",
                                                        ));
                                                    }
                                                    document.id = canonical.clone();
                                                    data = encoded(&document)?;
                                                }
                                                Ok((row.key, canonical, data))
                                            })
                                            .await
                                    }
                                },
                            )
                            .await?;
                        drop(references);
                        for prepared in prepared {
                            let (old, canonical, data) = prepared.value();
                            self.store.mdn_put(kind, canonical, data).await?;
                            record(mappings, &mut aliases, kind, old, canonical)?;
                        }
                    }
                    continue;
                }
                for row in rows {
                    after = row.sequence;
                    if row.key.starts_with("blake3:") {
                        continue;
                    }
                    let mut data = row.data;
                    let canonical = if kind == "projections" {
                        crate::integrity::verify(
                            &row.key,
                            &serde_json::to_vec(&data)
                                .map_err(|_| Error::integrity("Invalid MDN projection."))?,
                        )?;
                        if data["candidates"].is_object() {
                            let candidates: BTreeMap<String, Member> =
                                decoded(data["candidates"].clone())?;
                            let mut canonical_candidates = BTreeMap::new();
                            for (key, candidate) in candidates {
                                canonical_candidates.insert(key, member(candidate, mappings)?);
                            }
                            data["candidates"] = encoded(&canonical_candidates)?;
                            if let Some(path) = data["identity"].as_str() {
                                let legacy = format!(
                                    "@ambiguities/{}",
                                    crate::integrity::legacy_hash(path.as_bytes())
                                );
                                let canonical =
                                    format!("@ambiguities/{}", inventory::digest(path.as_bytes()));
                                crate::migration_map::insert(
                                    mappings,
                                    format!("mdn:member-path:{legacy}"),
                                    canonical,
                                )?;
                            }
                        }
                        inventory::digest(
                            &serde_json::to_vec(&data)
                                .map_err(|_| Error::integrity("Invalid MDN projection."))?,
                        )
                    } else {
                        mapped_role(mappings, "projections", &row.key)?
                    };
                    if kind == "index-documents" {
                        let mut document: IndexDocument = decoded(data)?;
                        if document.id != row.key {
                            return Err(Error::integrity("MDN index document identity mismatch."));
                        }
                        document.id = canonical.clone();
                        data = encoded(&document)?;
                    }
                    self.store.mdn_put(kind, &canonical, &data).await?;
                    record(mappings, &mut aliases, kind, &row.key, &canonical)?;
                }
            }
        }
        let mut after = 0;
        loop {
            check(&cancel)?;
            let (rows, _page_reservation) = self
                .migration_page(
                    "observations",
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
                let mut observation: Observation = decoded(row.data)?;
                let original_manifest = observation.manifest.clone();
                observation.manifest = self
                    .git(observation.repo)
                    .migrate_blake3_manifest(&original_manifest, mappings, cancel.clone())
                    .await?;
                {
                    let alias = (
                        "manifest".into(),
                        original_manifest.body_hash,
                        observation.manifest.body_hash.clone(),
                    );

                    aliases.push(alias)?;
                }
                artifact(&mut observation.commits, mappings)?;
                let id = observation_key(&observation);
                self.store
                    .mdn_put("observations", &id, &encoded(&observation)?)
                    .await?;
                record(mappings, &mut aliases, "observations", &row.key, &id)?;
                let key = format!("{}-observation", observation.repo.as_str());
                if let Some(selected) = self.store.mdn_state(&key).await? {
                    let selected: Observation = decoded(selected)?;
                    let old = format!("{}:{}", selected.repo.as_str(), selected.manifest.body_hash);
                    if old == row.key {
                        self.store
                            .mdn_set_state(
                                &format!("storage-migration:{key}"),
                                &encoded(&observation)?,
                            )
                            .await?;
                    }
                }
            }
        }
        let mut after = 0;
        loop {
            check(&cancel)?;
            let (rows, _page_reservation) = self
                .migration_page(
                    "changes",
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
                for side in ["before", "after"] {
                    if !data[side].is_null() {
                        data[side] = encoded(&member(decoded(data[side].clone())?, mappings)?)?;
                    }
                }
                let id = inventory::digest(
                    &serde_json::to_vec(&(
                        "devres:storage-migration:mdn-change:v1",
                        &row.key,
                        &data,
                    ))
                    .map_err(|_| Error::integrity("Invalid MDN migrated change."))?,
                );
                self.store.mdn_put("changes", &id, &data).await?;
                record(mappings, &mut aliases, "changes", &row.key, &id)?;
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
                        .get(&format!("mdn:index-reference:{key}"))
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
                let mut snapshot: Snapshot = decoded(row.data)?;
                if snapshot.id != row.key {
                    return Err(Error::integrity(
                        "MDN snapshot migration identity mismatch.",
                    ));
                }
                let old_root = snapshot.inventory.clone();
                snapshot.inventory = inventory::rebuild_inventory_memoized(
                    self.store.as_ref(),
                    &old_root,
                    |value| member(value, mappings),
                    &mut inventory_memo,
                    &cancel,
                )
                .await?;
                record(
                    mappings,
                    &mut aliases,
                    "nodes",
                    &old_root,
                    &snapshot.inventory,
                )?;
                if !snapshot.index.is_null() {
                    let cache_key = serde_json::to_string(&snapshot.index)
                        .map_err(|_| Error::integrity("Invalid MDN frozen index."))?;
                    snapshot.index = if let Some(reference) =
                        mappings.get(&format!("mdn:index-reference:{cache_key}"))
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
                        format!("mdn:index-reference:{cache_key}"),
                        serde_json::to_string(&snapshot.index)
                            .map_err(|_| Error::integrity("Invalid canonical index reference."))?,
                    )?;
                }
                snapshot.id.clear();
                let identity = (
                    "devres:storage-migration:mdn-snapshot:v1",
                    &row.key,
                    &snapshot,
                );
                let id = inventory::digest(
                    &serde_json::to_vec(&identity)
                        .map_err(|_| Error::integrity("Invalid MDN migrated snapshot."))?,
                );
                snapshot.id = id.clone();
                self.store
                    .mdn_put("snapshots", &id, &encoded(&snapshot)?)
                    .await?;
                record(mappings, &mut aliases, "snapshots", &row.key, &id)?;
                let key = format!(
                    "{}:{}:{}",
                    snapshot.repository, snapshot.revision, snapshot.processor_version
                );
                let selected = self
                    .store
                    .mdn_state(&format!("rebuild-alias:{key}"))
                    .await?
                    .or(self
                        .store
                        .mdn_get("snapshot-keys", &key)
                        .await?
                        .map(|r| r.data));
                if selected.as_ref().and_then(Value::as_str) == Some(&row.key) {
                    self.store
                        .mdn_set_state(
                            &format!("storage-migration:rebuild-alias:{key}"),
                            &json!(id),
                        )
                        .await?;
                }
            }
        }
        let selected = {
            let (selected, _reservation) = self
                .migration_state("default-view", 0, &cancel, execution)
                .await?;
            selected.and_then(|v| v.as_str().map(str::to_owned))
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
                let mut view: View = decoded(row.data)?;
                if view.id != row.key {
                    return Err(Error::integrity("MDN view migration identity mismatch."));
                }
                view.content = mapped_role(mappings, "snapshots", &view.content)?;
                view.compatibility = mapped_role(mappings, "snapshots", &view.compatibility)?;
                view.content_observation =
                    mapped_role(mappings, "observations", &view.content_observation)?;
                view.compatibility_observation =
                    mapped_role(mappings, "observations", &view.compatibility_observation)?;
                view.id = inventory::digest(
                    &serde_json::to_vec(&(
                        &view.content,
                        &view.compatibility,
                        &view.content_observation,
                        &view.compatibility_observation,
                        view.validated_at,
                    ))
                    .map_err(|_| Error::integrity("Invalid MDN migrated view."))?,
                );
                self.store
                    .mdn_put("views", &view.id, &encoded(&view)?)
                    .await?;
                record(mappings, &mut aliases, "views", &row.key, &view.id)?;
                if selected.as_deref() == Some(&row.key) {
                    self.store
                        .mdn_set_state("storage-migration:default-view", &json!(view.id))
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
            if let Some(reference) = source_index
                && !reference.is_null()
            {
                let canonical = self
                    .replay_frozen_index(&reference, mappings, cancel.clone(), execution)
                    .await?;
                crate::migration_map::insert(
                    mappings,
                    format!(
                        "mdn:index-reference:{}",
                        serde_json::to_string(&reference)
                            .map_err(|_| Error::integrity("Invalid old index reference."))?
                    ),
                    serde_json::to_string(&canonical)
                        .map_err(|_| Error::integrity("Invalid new index reference."))?,
                )?;
                self.store
                    .mdn_set_state("storage-migration:index", &canonical)
                    .await?;
            }
        }
        drop(inventory_memo);
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
                    .mdn_get("index-documents", &canonical_id)
                    .await?
                    .ok_or_else(|| Error::integrity("MDN frozen posting payload missing."))?;
                let document: crate::mdn::index::IndexDocument = decoded(row.data)?;
                crate::mdn::index::MdnIndex::validate_document_bounds(&document)?;
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
        canonical.ok_or_else(|| Error::integrity("MDN frozen index migration missing."))
    }
}

impl MdnCorpus {
    async fn migrate_auxiliary_graph(
        &self,
        mappings: &mut crate::migration_map::MigrationMap,
        aliases: &mut Aliases,
        cutoff: i64,
        cancel: &CancellationToken,
        execution: &crate::MigrationExecution,
    ) -> Result<()> {
        let mut inventory_memo = inventory::MigrationInventory::new_shared(mappings)?;
        let kinds = self.store.mdn_migration_kinds().await?;
        const CORE: &[&str] = &[
            "projections",
            "projection-headers",
            "index-documents",
            "observations",
            "nodes",
            "snapshots",
            "views",
            "changes",
        ];
        const AUX: &[&str] = &["commits", "changes-complete", "snapshot-keys"];
        for kind in &kinds {
            if !CORE.contains(&kind.as_str()) && !AUX.contains(&kind.as_str()) {
                return Err(Error::integrity("Unknown mdn migration evidence kind."));
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
                            &format!("mdn:{kind}"),
                            &row.key,
                        )
                        .is_some()
                        {
                            continue;
                        }
                        let mut data = row.data;
                        if *kind == "snapshot-keys" && data.is_string() {
                            reference_aux("mdn", &mut data, mappings, "snapshots")?;
                        }
                        if *kind == "indexed-membership" {
                            let old = data["id"].as_str().ok_or_else(|| {
                                Error::integrity("Invalid migrated index marker.")
                            })?;
                            data["id"] = json!(mapped(mappings, old)?);
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
                                "mdn:index-reference",
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
                                    format!("mdn:index-reference:{key}"),
                                    serde_json::to_string(&canonical).map_err(|_| {
                                        Error::integrity("Invalid canonical index reference.")
                                    })?,
                                )?;
                            }
                        }
                        if let Err(error) = crate::mdn::corpus::migration::rewrite_operational(
                            "mdn", &mut data, mappings, 0,
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
                                "devres:storage-migration:mdn:aux:v1",
                                kind,
                                &row.key,
                                &data,
                            ))
                            .map_err(|_| {
                                Error::integrity("Invalid mdn auxiliary migration evidence.")
                            })?,
                        );
                        let id = match *kind {
                            "catalog-captures" => crate::integrity::migration_lookup(
                                mappings,
                                "mdn:catalogs",
                                &row.key,
                            )
                            .ok_or_else(|| {
                                Error::integrity("Missing canonical catalogue companion.")
                            })?,
                            "snapshot-keys" if crate::integrity::valid_hash(&row.key) => {
                                crate::integrity::migration_lookup(
                                    mappings,
                                    "mdn:snapshot-keys",
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
                        self.store.mdn_put(kind, &id, &data).await?;
                        progress += 1;
                        record(mappings, aliases, kind, &row.key, &id)?;
                    }
                }
            }

            if unresolved == 0 {
                break;
            }
            if progress == 0 {
                return Err(Error::integrity(
                    "Missing or cyclic mdn auxiliary migration references.",
                ));
            }
        }
        let mut after = String::new();
        loop {
            check(cancel)?;
            let keys = self.store.mdn_migration_state_keys(&after, 100).await?;
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
                    if crate::integrity::migration_lookup(mappings, "mdn:index-reference", &key)
                        .is_none()
                    {
                        let canonical = self
                            .replay_frozen_index(&reference, mappings, cancel.clone(), execution)
                            .await?;
                        crate::migration_map::insert(
                            mappings,
                            format!("mdn:index-reference:{key}"),
                            serde_json::to_string(&canonical).map_err(|_| {
                                Error::integrity("Invalid canonical index reference.")
                            })?,
                        )?;
                    }
                }
                let mut roots = BTreeSet::new();
                crate::mdn::corpus::migration::collect_inventory_roots(&data, 0, &mut roots)?;
                for root in roots {
                    if crate::integrity::migration_lookup(mappings, "mdn:nodes", &root).is_none() {
                        let canonical = inventory::rebuild_inventory_memoized(
                            self.store.as_ref(),
                            &root,
                            |member| {
                                let mut value = crate::mdn::inventory::value(&member)?;
                                crate::mdn::corpus::migration::rewrite_operational(
                                    "mdn", &mut value, mappings, 0,
                                )?;
                                crate::mdn::inventory::decode(value)
                            },
                            &mut inventory_memo,
                            cancel,
                        )
                        .await?;
                        record(mappings, aliases, "nodes", &root, &canonical)?;
                    }
                }
                crate::mdn::corpus::migration::rewrite_operational("mdn", &mut data, mappings, 0)?;
                let mut target = key.clone();
                if let Some((prefix, suffix)) = key.split_once(':') {
                    let role = match prefix {
                        "snapshot-index" => Some("snapshots"),
                        "view-index" => Some("views"),
                        "revision-alias" => Some("snapshot-keys"),
                        _ => None,
                    };
                    if let Some(role) = role {
                        let namespace = format!("mdn:{role}");
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
                            reference_aux("mdn", &mut data, mappings, role)?;
                        }
                    }
                }
                self.store
                    .mdn_set_state(&format!("storage-migration:{target}"), &data)
                    .await?;
            }
        }
        self.store
            .mdn_set_state(
                "storage-migration:graph-complete",
                &json!({"version":1,"legacy_cutoff":cutoff,"complete":true}),
            )
            .await?;
        Ok(())
    }
}

/// Only service-owned operational fields are rewritten. Source text, package
/// metadata, license text and upstream object/checksum identities remain opaque.
pub(crate) fn rewrite_operational(
    provider: &str,
    value: &mut Value,
    mappings: &crate::migration_map::MigrationMap,
    depth: usize,
) -> Result<()> {
    if depth > 64 {
        return Err(Error::capacity(
            "Migration state nesting exceeds its bound.",
        ));
    }
    match value {
        Value::Array(values) => {
            for value in values {
                rewrite_operational(provider, value, mappings, depth + 1)?;
            }
        }
        Value::Object(object) => {
            if object
                .get("path")
                .and_then(Value::as_str)
                .is_some_and(|path| path.contains("-indexes/"))
                && (object.get("digest").is_some() || object.get("sha256").is_some())
            {
                if object
                    .get("digest")
                    .and_then(Value::as_str)
                    .is_some_and(|digest| digest.starts_with("blake3:"))
                {
                    return Ok(());
                }
                let old = serde_json::to_string(&Value::Object(object.clone()))
                    .map_err(|_| Error::integrity("Invalid old index reference."))?;
                let canonical = crate::integrity::migration_lookup(
                    mappings,
                    &format!("{provider}:index-reference"),
                    &old,
                )
                .ok_or_else(|| Error::integrity("Unqualified retained index checkpoint."))?;
                let canonical: Value = serde_json::from_str(&canonical)
                    .map_err(|_| Error::integrity("Invalid canonical index reference."))?;
                *object = canonical
                    .as_object()
                    .cloned()
                    .ok_or_else(|| Error::integrity("Invalid canonical index reference."))?;
                return Ok(());
            }
            // BulkArtifact is a closed service-owned descriptor wherever retained.
            if object.get("body_hash").is_some()
                && object.get("relative_path").is_some()
                && object.get("bytes").is_some()
            {
                let mut item: BulkArtifact = serde_json::from_value(Value::Object(object.clone()))
                    .map_err(|_| {
                        Error::integrity("Unknown retained artifact descriptor variant.")
                    })?;
                artifact(&mut item, mappings)?;
                let data = serde_json::to_value(item)
                    .map_err(|_| Error::integrity("Invalid migrated artifact descriptor."))?;
                object.insert("body_hash".into(), data["body_hash"].clone());
                object.insert("relative_path".into(), data["relative_path"].clone());
                return Ok(());
            }
            let publication_proofs = object
                .get("publication")
                .and_then(Value::as_str)
                .filter(|_| object.contains_key("chunk_hashes"))
                .map(|old| {
                    let id = if old.starts_with("blake3:") {
                        old.to_owned()
                    } else {
                        crate::integrity::migration_lookup(
                            mappings,
                            &format!("{provider}:publications"),
                            old,
                        )
                        .ok_or_else(|| Error::integrity("Unresolved raw publication."))?
                    };
                    let data = crate::integrity::migration_lookup(
                        mappings,
                        &format!("{provider}:publication-proofs"),
                        &id,
                    )
                    .ok_or_else(|| {
                        Error::integrity("Unresolved canonical publication range proofs.")
                    })?;
                    serde_json::from_str::<Value>(&data).map_err(|_| {
                        Error::integrity("Invalid canonical publication range proofs.")
                    })
                })
                .transpose()?;
            for (field, data) in object.iter_mut() {
                if field == "manifest"
                    && let Some(old) = data["body_hash"].as_str()
                    && let Some(descriptor) = crate::integrity::migration_lookup(
                        mappings,
                        &format!("{provider}:manifest-descriptor"),
                        old,
                    )
                {
                    *data = serde_json::from_str(&descriptor)
                        .map_err(|_| Error::integrity("Invalid migrated manifest descriptor."))?;
                    continue;
                }
                if field == "path"
                    && let Some(old) = data.as_str()
                    && let Some(path) = crate::integrity::migration_lookup(
                        mappings,
                        &format!("{provider}:member-path"),
                        old,
                    )
                {
                    *data = json!(path);
                    continue;
                }
                if field == "id"
                    && let Some(old) = data.as_str()
                    && crate::integrity::valid_hash(old)
                    && !old.starts_with("blake3:")
                {
                    let mut found = None;
                    for kind in [
                        "snapshots",
                        "views",
                        "catalogs",
                        "publications",
                        "projections",
                        "index-documents",
                        "observations",
                        "frozen",
                        "freezes",
                        "trees",
                        "tree-pages",
                        "edition-nodes",
                        "version-records",
                        "specification-records",
                    ] {
                        if let Some(id) = crate::integrity::migration_lookup(
                            mappings,
                            &format!("{provider}:{kind}"),
                            old,
                        ) {
                            if found.as_ref().is_some_and(|value| value != &id) {
                                return Err(Error::integrity(
                                    "Ambiguous operational identifier role.",
                                ));
                            }
                            found = Some(id.clone());
                        }
                    }
                    if let Some(id) = found {
                        *data = json!(id);
                        continue;
                    }
                }
                if [
                    "ids",
                    "index_ids",
                    "snapshots",
                    "pages",
                    "ref_pages",
                    "publications",
                ]
                .contains(&field.as_str())
                {
                    let role = match field.as_str() {
                        "snapshots" => "snapshots",
                        "pages" => "tree-pages",
                        "ref_pages" => "ref-pages",
                        "publications" => "publications",
                        _ => "index-documents",
                    };
                    if let Some(values) = data.as_array_mut() {
                        for value in values {
                            if value.is_string() {
                                rewrite_role(provider, role, value, mappings)?;
                            } else {
                                rewrite_operational(provider, value, mappings, depth + 1)?;
                            }
                        }
                        continue;
                    }
                    if field == "snapshots"
                        && let Some(values) = data.as_object_mut()
                    {
                        for value in values.values_mut() {
                            rewrite_role(provider, role, value, mappings)?;
                        }
                        continue;
                    }
                }
                let role = match field.as_str() {
                    "capture" | "capture_id" => Some("capture".to_owned()),
                    "body_hash" => Some("body".to_owned()),
                    "snapshot" | "snapshot_id" | "previous" => {
                        Some(format!("{provider}:snapshots"))
                    }
                    "view" | "view_id" => Some(format!("{provider}:views")),
                    "catalog" => Some(format!("{provider}:catalogs")),
                    "publication" | "metadata_parent" => Some(format!("{provider}:publications")),
                    "frozen" | "freeze" | "parent_frozen" | "child_frozen" | "parent" | "child"
                    | "successor" => Some(format!(
                        "{provider}:{}",
                        if provider == "chromium" {
                            "freezes"
                        } else {
                            "frozen"
                        }
                    )),
                    "attempt" => Some(format!("{provider}:recovery-attempts")),
                    "witness" => Some(format!("{provider}:recovery-witnesses")),
                    "disposition" => Some(format!("{provider}:recovery-dispositions")),
                    "projection" | "projection_id" => Some(format!("{provider}:projections")),
                    "root" | "inventory" => Some(format!("{provider}:nodes")),
                    "record" => Some(format!("{provider}:index-documents")),
                    "index_membership" => Some(format!("{provider}:projection-sequences")),
                    _ => None,
                };
                if let Some(role) = &role
                    && let Some(old) = data.as_str()
                    && crate::integrity::valid_hash(old)
                    && !old.starts_with("blake3:")
                {
                    *data = json!(
                        crate::integrity::migration_lookup(mappings, role, old).ok_or_else(
                            || Error::integrity(
                                "Unresolved typed operational migration reference."
                            )
                        )?
                    );
                    continue;
                }
                if role.is_some() && (data.is_object() || data.is_array()) {
                    rewrite_operational(provider, data, mappings, depth + 1)?;
                    continue;
                }
                match field.as_str() {
                    "metadata" | "text" | "body" | "license" | "licensing" | "data" | "source"
                    | "notice" | "diagnostics" => {}
                    "manifest" | "commits" | "artifact" | "observation" | "observations"
                    | "work" | "checkpoint" | "pending" | "snapshots" | "members" | "documents"
                    | "before" | "after" | "frozen" | "evidence" | "raw" | "reference"
                    | "index" | "history" => {
                        rewrite_operational(provider, data, mappings, depth + 1)?
                    }
                    _ => {}
                }
            }
            if let Some(proofs) = publication_proofs {
                object.insert("chunk_hashes".into(), proofs);
            }
        }
        _ => {}
    }
    Ok(())
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

fn rewrite_role(
    provider: &str,
    role: &str,
    value: &mut Value,
    mappings: &crate::migration_map::MigrationMap,
) -> Result<()> {
    let old = value
        .as_str()
        .ok_or_else(|| Error::integrity("Invalid operational reference value."))?;
    if !crate::integrity::valid_hash(old) || old.starts_with("blake3:") {
        return Ok(());
    }
    *value = json!(
        crate::integrity::migration_lookup(mappings, &format!("{provider}:{role}"), old)
            .ok_or_else(|| Error::integrity("Unresolved operational reference array."))?
    );
    Ok(())
}

pub(crate) fn collect_index_references(
    value: &Value,
    depth: usize,
    found: &mut Vec<Value>,
) -> Result<()> {
    if depth > 64 || found.len() > 4096 {
        return Err(Error::capacity(
            "Migration checkpoint references exceed their bound.",
        ));
    }
    match value {
        Value::Array(values) => {
            for value in values {
                collect_index_references(value, depth + 1, found)?;
            }
        }
        Value::Object(object) => {
            if object
                .get("path")
                .and_then(Value::as_str)
                .is_some_and(|path| path.contains("-indexes/"))
                && object.get("sha256").is_some()
            {
                found.push(value.clone());
                return Ok(());
            }
            for (field, value) in object {
                if ![
                    "metadata",
                    "source",
                    "data",
                    "text",
                    "body",
                    "license",
                    "licensing",
                    "notice",
                ]
                .contains(&field.as_str())
                {
                    collect_index_references(value, depth + 1, found)?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

pub(crate) fn collect_inventory_roots(
    value: &Value,
    depth: usize,
    found: &mut BTreeSet<String>,
) -> Result<()> {
    if depth > 64 || found.len() > 4096 {
        return Err(Error::capacity(
            "Migration work inventories exceed their bound.",
        ));
    }
    match value {
        Value::Array(values) => {
            for value in values {
                collect_inventory_roots(value, depth + 1, found)?;
            }
        }
        Value::Object(object) => {
            for (field, value) in object {
                if ["root", "inventory"].contains(&field.as_str())
                    && let Some(id) = value.as_str()
                    && crate::integrity::valid_hash(id)
                    && !id.starts_with("blake3:")
                {
                    found.insert(id.to_owned());
                }
                if ![
                    "metadata",
                    "source",
                    "data",
                    "text",
                    "body",
                    "license",
                    "licensing",
                    "notice",
                ]
                .contains(&field.as_str())
                {
                    collect_inventory_roots(value, depth + 1, found)?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

impl MdnCorpus {
    /// Check all retained immutable edges without publishing or refreshing data.
    pub async fn verify_blake3_graph(&self, cancel: CancellationToken) -> Result<()> {
        for kind in self.store.mdn_migration_kinds().await? {
            if !known_evidence_kind(&kind) {
                return Err(Error::integrity("Unknown retained mdn evidence kind."));
            }
        }

        for kind in [
            "nodes",
            "projections",
            "projection-headers",
            "index-documents",
            "snapshots",
            "views",
            "observations",
        ] {
            let mut after = 0;
            loop {
                check(&cancel)?;
                let rows = self.store.mdn_migration_rows(kind, after, 100).await?;
                if rows.is_empty() {
                    break;
                }
                for row in rows {
                    check(&cancel)?;
                    after = row.sequence;
                    match kind {
                        "nodes" => {
                            let node = inventory::node(self.store.as_ref(), &row.key).await?;
                            for id in node.children.values().chain(node.buckets.values()) {
                                self.verify_edge("nodes", id).await?;
                            }
                            if let Some(member) = node.member {
                                self.verify_member(&member, &cancel).await?;
                            }
                        }
                        "projections" => {
                            crate::integrity::verify(
                                &row.key,
                                &serde_json::to_vec(&row.data)
                                    .map_err(|_| Error::integrity("Invalid MDN projection."))?,
                            )?;
                            if row.data["candidates"].is_object() {
                                let candidates: BTreeMap<String, Member> =
                                    decoded(row.data["candidates"].clone())?;
                                for member in candidates.values() {
                                    self.verify_member(member, &cancel).await?;
                                }
                            }
                        }
                        "projection-headers" => {
                            self.verify_edge("projections", &row.key).await?;
                        }
                        "index-documents" => {
                            self.verify_edge("projections", &row.key).await?;
                            let document: IndexDocument = decoded(row.data)?;
                            if document.id != row.key {
                                return Err(Error::integrity(
                                    "Retained MDN posting identity mismatch.",
                                ));
                            }
                        }
                        "snapshots" => {
                            let snapshot: Snapshot = decoded(row.data)?;
                            if snapshot.id != row.key {
                                return Err(Error::integrity(
                                    "Retained MDN snapshot identity mismatch.",
                                ));
                            }
                            self.verify_edge("nodes", &snapshot.inventory).await?;
                            if !snapshot.index.is_null() {
                                self.verify_frozen_index(&snapshot.index, &cancel).await?;
                            }
                        }
                        "views" => {
                            let view: View = decoded(row.data)?;
                            if view.id != row.key {
                                return Err(Error::integrity(
                                    "Retained MDN view identity mismatch.",
                                ));
                            }
                            for id in [&view.content, &view.compatibility] {
                                self.verify_edge("snapshots", id).await?;
                            }
                            for id in [&view.content_observation, &view.compatibility_observation] {
                                self.verify_edge("observations", id).await?;
                            }
                        }
                        "observations" => {
                            let observation: Observation = decoded(row.data)?;
                            self.git(observation.repo)
                                .verify_retained_manifest(&observation.manifest, cancel.clone())
                                .await?;
                        }
                        _ => return Err(Error::integrity("Unknown retained MDN graph kind.")),
                    }
                }
            }
        }
        Ok(())
    }
    async fn verify_member(&self, member: &Member, cancel: &CancellationToken) -> Result<()> {
        if let Some(id) = &member.projection {
            self.verify_edge("projections", id).await?;
        }
        if let Some(raw) = &member.raw
            && raw["git"] != true
        {
            let expected = raw["body_hash"]
                .as_str()
                .ok_or_else(|| Error::integrity("Invalid MDN raw descriptor."))?;
            let actual = self
                .raw
                .verify(expected, crate::bulk::MAX_ARTIFACT_BYTES, cancel.clone())
                .await?;
            if raw["bytes"].as_u64() != Some(actual.bytes)
                || raw["relative_path"].as_str()
                    != Some(format!("mdn/raw-artifacts/{}", actual.relative_path).as_str())
            {
                return Err(Error::integrity("Retained MDN member metadata mismatch."));
            }
        }
        Ok(())
    }
    async fn verify_edge(&self, kind: &str, id: &str) -> Result<()> {
        if self.store.mdn_get(kind, id).await?.is_none() {
            return Err(Error::integrity("Retained MDN graph target is missing."));
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
            let rows = self.store.mdn_get_many("index-documents", &unique).await?;
            if rows.len() != unique.len() {
                return Err(Error::integrity("Retained MDN posting payload is missing."));
            }
            for row in rows {
                let document: IndexDocument = decoded(row.data)?;
                if document.id != row.key {
                    return Err(Error::integrity("Retained MDN posting payload mismatch."));
                }
            }
            if !has_more {
                break;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod graph_admission_tests {
    use super::*;

    fn execution(budget: usize) -> crate::MigrationExecution {
        crate::MigrationExecution::new_with_graph_options(
            crate::MigrationExecutionOptions::new(8, 64 * 1024 * 1024).expect("workers"),
            crate::MigrationGraphOptions::new(budget).expect("graph budget"),
        )
        .expect("execution")
    }

    #[test]
    fn structural_source_window_preserves_large_rows_as_singletons() {
        let execution = execution(32 * 1024 * 1024);
        let text = json!({"text":"x".repeat(16 * 1024 * 1024)});
        let wide = Value::Object(
            (0..10_000)
                .map(|n| (format!("k{n}"), Value::Null))
                .collect(),
        );
        for value in [text, wide] {
            let encoded = serde_json::to_vec(&value).expect("fixture bytes").len();
            let nodes = if value.get("text").is_some() {
                2
            } else {
                10_001
            };
            let charge = source_charge(encoded, nodes, 0).expect("source charge");
            assert!(
                charge
                    >= crate::MigrationExecution::graph_value_charge(&value)
                        .expect("decoded charge")
                        * 3
            );
            let positions = vec![
                (1, "first".into(), encoded, nodes),
                (2, "second".into(), 10, 1),
            ];
            let (count, admitted) =
                source_window(&positions, 0, &execution).expect("large valid row admitted");
            assert_eq!(count, 1);
            assert_eq!(admitted, charge);
            assert!(admitted > execution.graph_options().memory_budget_bytes);
        }
    }

    #[test]
    fn default_graph_budget_admits_concurrent_index_preparation() {
        let execution = execution(1024 * 1024 * 1024);
        let positions: Vec<_> = (0..8)
            .map(|n| (n, format!("snapshot-{n}"), 2048, 24))
            .collect();
        let (count, charge) =
            source_window(&positions, INDEX_REPLAY_BYTES, &execution).expect("snapshot window");
        assert_eq!(count, 2);
        assert!(charge <= execution.graph_options().memory_budget_bytes);
    }
}
