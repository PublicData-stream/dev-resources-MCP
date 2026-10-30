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

impl MdnCorpus {
    /// Retain every old generation and stage canonical heads for final activation.
    /// The versioned migration preimage includes the original ID to preserve
    /// distinct historical rebuild occurrences with otherwise identical content.
    pub async fn migrate_blake3_graph(
        &self,
        mappings: &mut crate::migration_map::MigrationMap,
        cancel: CancellationToken,
    ) -> Result<Aliases> {
        let _guard = self.processing.lock().await;
        let cutoff = self.store.mdn_cutoff().await?;
        let mut aliases = crate::migration_map::MigrationAliases::new(mappings)?;
        let mut inventory_memo = inventory::MigrationInventory::new();
        for kind in ["projections", "projection-headers", "index-documents"] {
            let mut after = 0;
            loop {
                check(&cancel)?;
                let rows = self.store.mdn_rows(kind, after, 100, Some(cutoff)).await?;
                if rows.is_empty() {
                    break;
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
            let rows = self
                .store
                .mdn_rows("observations", after, 100, Some(cutoff))
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
            let rows = self
                .store
                .mdn_rows("changes", after, 100, Some(cutoff))
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
        let mut indexes = BTreeMap::<String, Value>::new();
        let mut after = 0;
        loop {
            check(&cancel)?;
            let rows = self
                .store
                .mdn_rows("snapshots", after, 50, Some(cutoff))
                .await?;
            if rows.is_empty() {
                break;
            }
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
                    snapshot.index = if let Some(reference) = indexes.get(&cache_key) {
                        reference.clone()
                    } else {
                        let reference = self
                            .migrate_frozen_index(&snapshot.index, mappings, cancel.clone())
                            .await?;
                        if indexes.len() < 4096 {
                            indexes.insert(cache_key.clone(), reference.clone());
                        }
                        reference
                    };
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
        let selected = self
            .store
            .mdn_state("default-view")
            .await?
            .and_then(|v| v.as_str().map(str::to_owned));
        let mut after = 0;
        loop {
            check(&cancel)?;
            let rows = self
                .store
                .mdn_rows("views", after, 100, Some(cutoff))
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
        if let Some(reference) = self.store.mdn_state("index").await?
            && !reference.is_null()
        {
            let canonical = self
                .migrate_frozen_index(&reference, mappings, cancel.clone())
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
        drop(inventory_memo);
        self.migrate_auxiliary_graph(mappings, &mut aliases, cutoff, &cancel)
            .await?;
        mappings.ensure_healthy()?;
        aliases.ensure_healthy()?;
        Ok(aliases)
    }

    async fn migrate_frozen_index(
        &self,
        reference: &Value,
        mappings: &crate::migration_map::MigrationMap,
        cancel: CancellationToken,
    ) -> Result<Value> {
        let mut offset = 0;
        let mut canonical = None;
        loop {
            check(&cancel)?;
            let (ids, next) = self
                .index
                .document_ids(reference, offset, 100, cancel.clone())
                .await?;
            let mut documents = Vec::new();
            for id in ids {
                let canonical_id = mapped_role(mappings, "index-documents", &id)?;
                let row = self
                    .store
                    .mdn_get("index-documents", &canonical_id)
                    .await?
                    .ok_or_else(|| Error::integrity("MDN frozen posting payload missing."))?;
                documents.push(decoded(row.data)?);
            }
            canonical = Some(
                self.index
                    .publish(canonical.as_ref(), documents, cancel.clone())
                    .await?,
            );
            match next {
                Some(next) => offset = next,
                None => break,
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
    ) -> Result<()> {
        let mut inventory_memo = inventory::MigrationInventory::new();
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
                    let rows = self.store.mdn_rows(kind, after, 100, Some(cutoff)).await?;
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
                                    .migrate_frozen_index(&reference, mappings, cancel.clone())
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
                // Dedicated core phases stage selected heads; do not replace them
                // with a generic copy of the legacy generation.
                if self
                    .store
                    .mdn_state(&format!("storage-migration:{key}"))
                    .await?
                    .is_some()
                {
                    continue;
                }
                let Some(mut data) = self.store.mdn_state(&key).await? else {
                    return Err(Error::integrity("mdn migration state vanished."));
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
                            .migrate_frozen_index(&reference, mappings, cancel.clone())
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
        let mut offset = 0;
        loop {
            check(cancel)?;
            let (ids, next) = self
                .index
                .document_ids(index, offset, 100, cancel.clone())
                .await?;
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
            match next {
                Some(next) => offset = next,
                None => break,
            }
        }
        Ok(())
    }
}
