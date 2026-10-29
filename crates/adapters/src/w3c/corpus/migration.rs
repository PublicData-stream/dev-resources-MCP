//! Offline canonical graph reconstruction. Every source/processor generation stays frozen.
use super::*;
use crate::bulk::BulkArtifact;
type Aliases = Vec<(String, String, String)>;
fn known_evidence_kind(kind: &str) -> bool {
    matches!(
        kind,
        "acceptance"
            | "catalog-captures"
            | "catalogs"
            | "discovery-captures"
            | "edition-nodes"
            | "editions"
            | "frozen"
            | "frozen-index-repairs"
            | "frozen-recoveries"
            | "index-documents"
            | "indexed-membership"
            | "nodes"
            | "observations"
            | "projection-chunks"
            | "projection-references"
            | "projection-sections"
            | "projection-sequences"
            | "projection-symbols"
            | "projections"
            | "publications"
            | "recovery-attempts"
            | "recovery-dispositions"
            | "recovery-witnesses"
            | "repository-gaps"
            | "snapshot-keys"
            | "snapshots"
            | "specification-records"
            | "version-memberships"
            | "version-records"
            | "views"
    )
}
fn check(cancel: &CancellationToken) -> Result<()> {
    if cancel.is_cancelled() {
        return Err(Error::new("cancelled", "w3c graph migration canceled."));
    }
    Ok(())
}
fn mapped(mappings: &BTreeMap<String, String>, id: &str) -> Result<String> {
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
            crate::integrity::migration_lookup(mappings, &format!("w3c:{kind}"), id)
        {
            if found.as_ref().is_some_and(|prior| prior != value) {
                return Err(Error::integrity("Ambiguous w3c migration reference role."));
            }
            found = Some(value.clone());
        }
    }
    found.ok_or_else(|| Error::integrity("w3c migration reference is not qualified."))
}
fn mapped_role(mappings: &BTreeMap<String, String>, kind: &str, id: &str) -> Result<String> {
    if id.starts_with("blake3:") && crate::integrity::valid_hash(id) {
        return Ok(id.to_owned());
    }
    crate::integrity::migration_lookup(mappings, &format!("w3c:{kind}"), id)
        .cloned()
        .ok_or_else(|| Error::integrity("Missing typed migration reference."))
}
fn record(
    mappings: &mut BTreeMap<String, String>,
    aliases: &mut Aliases,
    kind: &str,
    old: &str,
    new: &str,
) -> Result<()> {
    let scoped = format!("w3c:{kind}:{old}");
    if let Some(existing) = mappings.get(&scoped)
        && existing != new
    {
        return Err(Error::integrity("Conflicting w3c graph migration mapping."));
    }
    crate::migration_map::insert(mappings, scoped, new.to_owned())?;
    if old != new {
        {
            let alias = (kind.to_owned(), old.to_owned(), new.to_owned());
            crate::migration_map::reserve_alias(mappings, &alias)?;
            aliases.push(alias);
        }
    }
    Ok(())
}
fn artifact(value: &mut Value, mappings: &BTreeMap<String, String>) -> Result<()> {
    let mut item: BulkArtifact = decode(value.clone())?;
    item.body_hash = if item.body_hash.starts_with("blake3:") {
        item.body_hash.clone()
    } else {
        crate::integrity::migration_lookup(mappings, "body", &item.body_hash)
            .cloned()
            .ok_or_else(|| Error::integrity("Raw migration body is not qualified."))?
    };
    item.relative_path = crate::integrity::relative_path(&item.body_hash)?
        .to_string_lossy()
        .into_owned();
    *value = encode(&item)?;
    Ok(())
}
fn reference(value: &mut Value, mappings: &BTreeMap<String, String>) -> Result<()> {
    let id = value
        .as_str()
        .ok_or_else(|| Error::integrity("Invalid w3c typed reference."))?;
    *value = json!(mapped(mappings, id)?);
    Ok(())
}
fn array(value: &mut Value, mappings: &BTreeMap<String, String>) -> Result<()> {
    let values = value
        .as_array_mut()
        .ok_or_else(|| Error::integrity("Invalid w3c reference sequence."))?;
    for value in values {
        reference(value, mappings)?;
    }
    Ok(())
}
fn identity(kind: &str, old: &str, data: &Value) -> Result<String> {
    Ok(inventory::digest(
        &serde_json::to_vec(&("devres:storage-migration:w3c:v1", kind, old, data))
            .map_err(|_| failure())?,
    ))
}
impl W3cCorpus {
    /// Rebuild canonical content while retaining old snapshots, sequences and indexes.
    /// Only staged head records are written; the owner activates them atomically.
    pub async fn migrate_blake3_graph(
        &self,
        mappings: &mut BTreeMap<String, String>,
        cancel: CancellationToken,
    ) -> Result<Aliases> {
        let _guard = self.processing.lock().await;
        let cutoff = self.store.w3c_cutoff().await?;
        let mut aliases = Vec::new();
        for kind in [
            "projection-chunks",
            "projection-references",
            "index-documents",
        ] {
            let mut after = 0;
            loop {
                check(&cancel)?;
                let rows = self.store.w3c_rows(kind, after, 100, Some(cutoff)).await?;
                if rows.is_empty() {
                    break;
                }
                for row in rows {
                    after = row.sequence;
                    if row.key.starts_with("blake3:") {
                        continue;
                    }
                    let mut data = row.data;
                    let id = if kind == "index-documents" {
                        if data["id"].as_str() != Some(&row.key) {
                            return Err(Error::integrity("w3c frozen posting identity mismatch."));
                        }
                        data["id"] = json!("");
                        let id = identity(kind, &row.key, &data)?;
                        data["id"] = json!(id);
                        id
                    } else {
                        crate::integrity::verify(
                            &row.key,
                            &serde_json::to_vec(&data).map_err(|_| failure())?,
                        )?;
                        inventory::digest(&serde_json::to_vec(&data).map_err(|_| failure())?)
                    };
                    self.store.w3c_put(kind, &id, &data).await?;
                    record(mappings, &mut aliases, kind, &row.key, &id)?;
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
                    let rows = self.store.w3c_rows(kind, after, 100, Some(cutoff)).await?;
                    if rows.is_empty() {
                        break;
                    }
                    for row in rows {
                        after = row.sequence;
                        if row.key.starts_with("blake3:")
                            || crate::integrity::migration_lookup(
                                mappings,
                                &format!("w3c:{kind}"),
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
                                return Err(Error::integrity("Unknown w3c projection sequence."));
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
                        self.store.w3c_put(kind, &id, &data).await?;
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
                    "Missing or cyclic w3c projection references.",
                ));
            }
        }
        let mut after = 0;
        loop {
            check(&cancel)?;
            let rows = self
                .store
                .w3c_rows("projections", after, 100, Some(cutoff))
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
                self.store.w3c_put("projections", &id, &data).await?;
                record(mappings, &mut aliases, "projections", &row.key, &id)?;
            }
        }
        let mut proofs = BTreeMap::<String, Value>::new();
        for kind in ["publications", "observations", "catalogs"] {
            let mut after = 0;
            loop {
                check(&cancel)?;
                let rows = self.store.w3c_rows(kind, after, 50, Some(cutoff)).await?;
                if rows.is_empty() {
                    break;
                }
                for row in rows {
                    after = row.sequence;
                    if row.key.starts_with("blake3:") {
                        continue;
                    }
                    let mut data = row.data;
                    if kind == "observations" {
                        let observation: Observation = decode(data.clone())?;
                        let original = observation.manifest;
                        let canonical = self
                            .git(&observation.repo.as_str())?
                            .migrate_blake3_manifest(&original, mappings, cancel.clone())
                            .await?;
                        {
                            let alias = (
                                "manifest".into(),
                                original.body_hash,
                                canonical.body_hash.clone(),
                            );
                            crate::migration_map::reserve_alias(mappings, &alias)?;
                            aliases.push(alias);
                        }
                        data["manifest"] = encode(&canonical)?;
                    }
                    for field in ["artifact", "manifest", "commits"] {
                        if data[field].is_object() && data[field].get("body_hash").is_some() {
                            artifact(&mut data[field], mappings)?;
                        }
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
                    self.store.w3c_put(kind, &id, &data).await?;
                    record(mappings, &mut aliases, kind, &row.key, &id)?;
                    if kind == "publications" {
                        proofs.insert(id.clone(), data["chunk_hashes"].clone());
                        crate::migration_map::insert(
                            mappings,
                            format!("w3c:publication-proofs:{id}"),
                            serde_json::to_string(&data["chunk_hashes"]).map_err(|_| failure())?,
                        )?;
                    }
                    if kind == "catalogs"
                        && self
                            .store
                            .w3c_state("catalog")
                            .await?
                            .as_ref()
                            .and_then(Value::as_str)
                            == Some(&row.key)
                    {
                        self.store
                            .w3c_set_state("storage-migration:catalog", &json!(id))
                            .await?;
                    }
                }
            }
        }
        let mut indexes = BTreeMap::<String, Value>::new();
        let mut after = 0;
        loop {
            check(&cancel)?;
            let rows = self
                .store
                .w3c_rows("snapshots", after, 25, Some(cutoff))
                .await?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                after = row.sequence;
                if row.key.starts_with("blake3:") {
                    continue;
                }
                let mut snapshot: Snapshot = decode(row.data)?;
                if snapshot.id != row.key {
                    return Err(Error::integrity("w3c frozen snapshot identity mismatch."));
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
                                            Error::integrity("w3c migrated range proofs missing.")
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
                    snapshot.index = if let Some(index) = indexes.get(&cache_key) {
                        index.clone()
                    } else {
                        let index = self
                            .migrate_frozen_index(&snapshot.index, mappings, cancel.clone())
                            .await?;
                        if indexes.len() < 4096 {
                            indexes.insert(cache_key.clone(), index.clone());
                        }
                        index
                    };
                    crate::migration_map::insert(
                        mappings,
                        format!("w3c:index-reference:{cache_key}"),
                        serde_json::to_string(&snapshot.index)
                            .map_err(|_| Error::integrity("Invalid canonical index reference."))?,
                    )?;
                }
                snapshot.id.clear();
                let id = identity("snapshots", &row.key, &encode(&snapshot)?)?;
                snapshot.id = id.clone();
                self.store
                    .w3c_put("snapshots", &id, &encode(&snapshot)?)
                    .await?;
                record(mappings, &mut aliases, "snapshots", &row.key, &id)?;
                let alias = inventory::digest(
                    &serde_json::to_vec(&(
                        &snapshot.standard,
                        &snapshot.repository,
                        &snapshot.revision,
                        &snapshot.representation,
                        snapshot.processor_version,
                    ))
                    .map_err(|_| failure())?,
                );
                let old_alias = crate::integrity::legacy_hash(
                    &serde_json::to_vec(&(
                        &snapshot.standard,
                        &snapshot.repository,
                        &snapshot.revision,
                        &snapshot.representation,
                        snapshot.processor_version,
                    ))
                    .map_err(|_| failure())?,
                );
                record(mappings, &mut aliases, "snapshot-keys", &old_alias, &alias)?;
                self.store
                    .w3c_put("snapshot-keys", &alias, &json!(id))
                    .await?;
            }
        }
        let selected = self
            .store
            .w3c_state("default")
            .await?
            .and_then(|v| v["id"].as_str().map(str::to_owned));
        let mut after = 0;
        loop {
            check(&cancel)?;
            let rows = self
                .store
                .w3c_rows("views", after, 25, Some(cutoff))
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
                        .migrate_frozen_index(&view.index, mappings, cancel.clone())
                        .await?;
                }
                view.id.clear();
                view.id = identity("views", &row.key, &encode(&view)?)?;
                self.store
                    .w3c_put("views", &view.id, &encode(&view)?)
                    .await?;
                record(mappings, &mut aliases, "views", &row.key, &view.id)?;
                if selected.as_deref() == Some(&row.key) {
                    self.store
                        .w3c_set_state("storage-migration:default", &encode(&view)?)
                        .await?;
                }
            }
        }
        if let Some(index) = self.store.w3c_state("index").await?
            && !index.is_null()
        {
            let canonical = self
                .migrate_frozen_index(&index, mappings, cancel.clone())
                .await?;
            crate::migration_map::insert(
                mappings,
                format!(
                    "w3c:index-reference:{}",
                    serde_json::to_string(&index)
                        .map_err(|_| Error::integrity("Invalid old index reference."))?
                ),
                serde_json::to_string(&canonical)
                    .map_err(|_| Error::integrity("Invalid new index reference."))?,
            )?;
            self.store
                .w3c_set_state("storage-migration:index", &canonical)
                .await?;
        }
        self.migrate_auxiliary_graph(mappings, &mut aliases, cutoff, &cancel)
            .await?;
        Ok(aliases)
    }
    async fn migrate_frozen_index(
        &self,
        reference: &Value,
        mappings: &BTreeMap<String, String>,
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
                    .w3c_get("index-documents", &canonical_id)
                    .await?
                    .ok_or_else(|| Error::integrity("w3c frozen index payload missing."))?;
                documents.push(decode(row.data)?);
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
        canonical.ok_or_else(failure)
    }
}

impl W3cCorpus {
    async fn migrate_auxiliary_graph(
        &self,
        mappings: &mut BTreeMap<String, String>,
        aliases: &mut Aliases,
        cutoff: i64,
        cancel: &CancellationToken,
    ) -> Result<()> {
        let kinds = self.store.w3c_migration_kinds().await?;
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
            "acceptance",
            "catalog-captures",
            "discovery-captures",
            "edition-nodes",
            "editions",
            "frozen",
            "frozen-recoveries",
            "frozen-index-repairs",
            "indexed-membership",
            "recovery-attempts",
            "recovery-dispositions",
            "recovery-witnesses",
            "repository-gaps",
            "snapshot-keys",
            "specification-records",
            "version-memberships",
            "version-records",
        ];
        for kind in &kinds {
            if !CORE.contains(&kind.as_str()) && !AUX.contains(&kind.as_str()) {
                return Err(Error::integrity("Unknown w3c migration evidence kind."));
            }
        }
        loop {
            let mut unresolved = 0usize;
            let mut progress = 0usize;
            for kind in AUX {
                let mut after = 0;
                loop {
                    check(cancel)?;
                    let rows = self.store.w3c_rows(kind, after, 100, Some(cutoff)).await?;
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
                            &format!("w3c:{kind}"),
                            &row.key,
                        )
                        .is_some()
                        {
                            continue;
                        }
                        let mut data = row.data;
                        if *kind == "snapshot-keys" && data.is_string() {
                            reference_aux("w3c", &mut data, mappings, "snapshots")?;
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
                                "w3c:index-reference",
                                &key,
                            )
                            .is_none()
                            {
                                let canonical = self
                                    .migrate_frozen_index(&reference, mappings, cancel.clone())
                                    .await?;
                                crate::migration_map::insert(
                                    mappings,
                                    format!("w3c:index-reference:{key}"),
                                    serde_json::to_string(&canonical).map_err(|_| {
                                        Error::integrity("Invalid canonical index reference.")
                                    })?,
                                )?;
                            }
                        }
                        if let Err(error) = crate::mdn::corpus::migration::rewrite_operational(
                            "w3c", &mut data, mappings, 0,
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
                                "devres:storage-migration:w3c:aux:v1",
                                kind,
                                &row.key,
                                &data,
                            ))
                            .map_err(|_| {
                                Error::integrity("Invalid w3c auxiliary migration evidence.")
                            })?,
                        );
                        let id = match *kind {
                            "catalog-captures" => crate::integrity::migration_lookup(
                                mappings,
                                "w3c:catalogs",
                                &row.key,
                            )
                            .cloned()
                            .ok_or_else(|| {
                                Error::integrity("Missing canonical catalogue companion.")
                            })?,
                            "snapshot-keys" if crate::integrity::valid_hash(&row.key) => {
                                crate::integrity::migration_lookup(
                                    mappings,
                                    "w3c:snapshot-keys",
                                    &row.key,
                                )
                                .cloned()
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
                        self.store.w3c_put(kind, &id, &data).await?;
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
                    "Missing or cyclic w3c auxiliary migration references.",
                ));
            }
        }
        let mut after = String::new();
        loop {
            check(cancel)?;
            let keys = self.store.w3c_migration_state_keys(&after, 100).await?;
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
                    .w3c_state(&format!("storage-migration:{key}"))
                    .await?
                    .is_some()
                {
                    continue;
                }
                let Some(mut data) = self.store.w3c_state(&key).await? else {
                    return Err(Error::integrity("w3c migration state vanished."));
                };
                let mut references = Vec::new();
                crate::mdn::corpus::migration::collect_index_references(&data, 0, &mut references)?;
                for reference in references {
                    let key = serde_json::to_string(&reference)
                        .map_err(|_| Error::integrity("Invalid retained index reference."))?;
                    if crate::integrity::migration_lookup(mappings, "w3c:index-reference", &key)
                        .is_none()
                    {
                        let canonical = self
                            .migrate_frozen_index(&reference, mappings, cancel.clone())
                            .await?;
                        crate::migration_map::insert(
                            mappings,
                            format!("w3c:index-reference:{key}"),
                            serde_json::to_string(&canonical).map_err(|_| {
                                Error::integrity("Invalid canonical index reference.")
                            })?,
                        )?;
                    }
                }
                let mut roots = BTreeSet::new();
                crate::mdn::corpus::migration::collect_inventory_roots(&data, 0, &mut roots)?;
                for root in roots {
                    if crate::integrity::migration_lookup(mappings, "w3c:nodes", &root).is_none() {
                        let canonical =
                            inventory::rebuild_inventory(self.store.as_ref(), &root, |member| {
                                let mut value = crate::mdn::inventory::value(&member)?;
                                crate::mdn::corpus::migration::rewrite_operational(
                                    "w3c", &mut value, mappings, 0,
                                )?;
                                crate::mdn::inventory::decode(value)
                            })
                            .await?;
                        record(mappings, aliases, "nodes", &root, &canonical)?;
                    }
                }
                crate::mdn::corpus::migration::rewrite_operational("w3c", &mut data, mappings, 0)?;
                let mut target = key.clone();
                if let Some((prefix, suffix)) = key.split_once(':') {
                    let role = match prefix {
                        "snapshot-index" => Some("snapshots"),
                        "view-index" => Some("views"),
                        "revision-alias" => Some("snapshot-keys"),
                        _ => None,
                    };
                    if let Some(role) = role {
                        let namespace = format!("w3c:{role}:");
                        for (old, canonical) in mappings.iter() {
                            if let Some(old) = old.strip_prefix(&namespace)
                                && crate::integrity::legacy_hash(old.as_bytes()) == suffix
                            {
                                target = format!(
                                    "{prefix}:{}",
                                    crate::integrity::legacy_hash(canonical.as_bytes())
                                );
                                break;
                            }
                        }
                    }
                    if data.is_string() {
                        let role = match prefix {
                            "current" | "prepared" => Some("snapshots"),
                            "publication" | "publication-usable" => Some("publications"),
                            _ => None,
                        };
                        if let Some(role) = role {
                            reference_aux("w3c", &mut data, mappings, role)?;
                        }
                    }
                }
                self.store
                    .w3c_set_state(&format!("storage-migration:{target}"), &data)
                    .await?;
            }
        }
        self.store
            .w3c_set_state(
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
    mappings: &BTreeMap<String, String>,
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

impl W3cCorpus {
    /// Read-only closure/integrity verification for every retained generation.
    /// Missing descendants are errors even when all remaining rows hash correctly.
    pub async fn verify_blake3_graph(&self, cancel: CancellationToken) -> Result<()> {
        for kind in self.store.w3c_migration_kinds().await? {
            if !known_evidence_kind(&kind) {
                return Err(Error::integrity("Unknown retained w3c evidence kind."));
            }
        }

        for kind in [
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
        ] {
            let mut after = 0;
            loop {
                check(&cancel)?;
                let rows = self.store.w3c_migration_rows(kind, after, 100).await?;
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
                                            present |=
                                                self.store.w3c_get(target, id).await?.is_some();
                                        }
                                        if !present {
                                            return Err(Error::integrity(
                                                "Retained w3c sequence target is missing.",
                                            ));
                                        }
                                    }
                                } else {
                                    return Err(Error::integrity("Unknown w3c sequence variant."));
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
                                    "Retained w3c posting identity mismatch.",
                                ));
                            }
                        }
                        "snapshots" => {
                            let snapshot: Snapshot = decode(row.data)?;
                            if snapshot.id != row.key {
                                return Err(Error::integrity(
                                    "Retained w3c snapshot identity mismatch.",
                                ));
                            }
                            self.verify_edge("nodes", &snapshot.inventory).await?;
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
                                    "Retained w3c view identity mismatch.",
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
                            let observation: Observation = decode(row.data)?;
                            self.git(&observation.repo.as_str())?
                                .verify_retained_manifest(&observation.manifest, cancel.clone())
                                .await?;
                        }
                        _ => {
                            return Err(Error::integrity(
                                "Unknown retained w3c verification kind.",
                            ));
                        }
                    }
                }
            }
        }
        Ok(())
    }
    async fn verify_edge(&self, kind: &str, id: &str) -> Result<()> {
        if self.store.w3c_get(kind, id).await?.is_none() {
            return Err(Error::integrity("Retained w3c graph target is missing."));
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
            .ok_or_else(|| Error::integrity("Retained w3c sequence is missing."))?;
        for chunk in ids.chunks(100) {
            check(cancel)?;
            let unique = chunk
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            let rows = self.store.w3c_get_many(kind, &unique).await?;
            if rows.len() != unique.len() {
                return Err(Error::integrity("Retained w3c sequence member is missing."));
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
                "Retained w3c raw artifact metadata mismatch.",
            ));
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
            let rows = self.store.w3c_get_many("index-documents", &unique).await?;
            if rows.len() != unique.len() {
                return Err(Error::integrity("Retained w3c posting payload is missing."));
            }
            for row in rows {
                let document: IndexDocument = decode(row.data)?;
                if document.id != row.key {
                    return Err(Error::integrity("Retained w3c posting payload mismatch."));
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
