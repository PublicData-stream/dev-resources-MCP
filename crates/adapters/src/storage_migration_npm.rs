//! Frozen npm graph replay; upstream package metadata remains opaque.
use super::PgBlobStore;
use crate::{
    integrity,
    npm::index::{IndexDocument, NpmIndex},
};
use devres_application::npm::NpmStore;
use devres_domain::{Error, Result};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

fn mapped(mappings: &crate::migration_map::MigrationMap, role: &str, old: &str) -> Result<String> {
    if old.starts_with("blake3:") && integrity::valid_hash(old) {
        return Ok(old.to_owned());
    }
    integrity::migration_lookup(mappings, role, old)
        .ok_or_else(|| Error::integrity("npm migration reference is missing qualified evidence."))
}
fn field(
    data: &mut Value,
    key: &str,
    role: &str,
    mappings: &crate::migration_map::MigrationMap,
) -> Result<()> {
    let Some(value) = data.get_mut(key) else {
        return Ok(());
    };
    if value.is_null() {
        return Ok(());
    }
    let old = value
        .as_str()
        .ok_or_else(|| Error::integrity("Invalid npm migration reference shape."))?;
    *value = json!(mapped(mappings, role, old)?);
    Ok(())
}
fn artifact(data: &mut Value, mappings: &crate::migration_map::MigrationMap) -> Result<()> {
    let old = data["body_hash"]
        .as_str()
        .ok_or_else(|| Error::integrity("Invalid retained npm artifact."))?
        .to_owned();
    let expected = integrity::relative_path(&old)?
        .to_string_lossy()
        .into_owned();
    if data["relative_path"] != expected || data["bytes"].as_u64().is_none() {
        return Err(Error::integrity(
            "Invalid retained npm artifact path or length.",
        ));
    }
    let digest = mapped(mappings, "body", &old)?;
    data["body_hash"] = json!(digest);
    data["relative_path"] = json!(integrity::relative_path(&digest)?.to_string_lossy());
    Ok(())
}

/// Each case names service-owned fields. Normalized upstream advisory objects,
/// package manifests, source text, licenses and unknown nested JSON are opaque.
pub(super) fn rewrite_references(
    kind: &str,
    value: &mut Value,
    mappings: &crate::migration_map::MigrationMap,
) -> Result<()> {
    if matches!(kind, "advisories" | "failures") || !value.is_object() {
        return Ok(());
    }
    if value.get("body_hash").is_some() {
        return artifact(value, mappings);
    }
    for key in ["artifact", "metadata"] {
        if let Some(data) = value.get_mut(key) {
            if data.is_object() && data.get("body_hash").is_some() {
                artifact(data, mappings)?;
            } else if data.is_string() {
                field(value, key, "body", mappings)?;
            }
        }
    }
    let fields: &[&str] = match kind {
        "metadata-captures" | "package-snapshots" | "snapshots" | "indexed" | "state" => &[
            "id",
            "membership",
            "snapshot",
            "previous",
            "reprocessed_from",
        ],
        "members" => &["snapshot", "record"],
        "advisory-members" => &["snapshot", "record", "raw"],
        "advisory-packages" => &["snapshot", "record"],
        "advisory-raw" => &["record"],
        "documents" | "projections" => &["release"],
        "gaps" => &["snapshot", "document"],
        "rebuild-index-members" => &["record"],
        "versions" | "artifacts" | "archive-observations" | "source-observations" => &[],
        _ => {
            return Err(Error::integrity(
                "Unsupported npm migration payload family.",
            ));
        }
    };
    for key in fields {
        field(value, key, "npm:id", mappings)?;
    }
    field(value, "export_hash", "body", mappings)?;
    if kind == "projections"
        && let Some(ids) = value.get_mut("documents").and_then(Value::as_array_mut)
    {
        for id in ids {
            let old = id
                .as_str()
                .ok_or_else(|| Error::integrity("Invalid npm document membership."))?;
            *id = json!(mapped(mappings, "npm:id", old)?);
        }
    }
    if matches!(kind, "snapshots" | "state")
        && let Some(packages) = value.get_mut("packages").and_then(Value::as_object_mut)
    {
        for id in packages.values_mut() {
            let old = id
                .as_str()
                .ok_or_else(|| Error::integrity("Invalid npm package membership."))?;
            *id = json!(mapped(mappings, "npm:id", old)?);
        }
    }
    Ok(())
}

impl PgBlobStore {
    pub async fn migrate_npm_graph(
        self: &Arc<Self>,
        mappings: &mut crate::migration_map::MigrationMap,
        cancel: CancellationToken,
    ) -> Result<crate::migration_map::MigrationAliases> {
        self.migrate_npm_graph_with_execution(
            mappings,
            cancel,
            &crate::MigrationExecution::default(),
        )
        .await
    }

    pub async fn migrate_npm_graph_with_execution(
        self: &Arc<Self>,
        mappings: &mut crate::MigrationMap,
        cancel: CancellationToken,
        execution: &crate::MigrationExecution,
    ) -> Result<crate::migration_map::MigrationAliases> {
        let cutoff = self.npm_cutoff().await?;
        let kinds = self.npm_migration_kinds().await?;
        for kind in &kinds {
            if !matches!(
                kind.as_str(),
                "advisories"
                    | "advisory-members"
                    | "advisory-packages"
                    | "advisory-raw"
                    | "archive-observations"
                    | "artifacts"
                    | "documents"
                    | "failures"
                    | "gaps"
                    | "indexed"
                    | "members"
                    | "metadata-captures"
                    | "package-snapshots"
                    | "projections"
                    | "rebuild-index-members"
                    | "snapshots"
                    | "source-observations"
                    | "versions"
            ) {
                return Err(Error::integrity("Unknown retained npm evidence kind."));
            }
        }
        // A repeated identity across companion rows (documents/indexed, etc.) must
        // remain one identity. Its preimage is frozen legacy occurrence evidence;
        // rewritten payload integrity is bound independently by the SQL envelope.
        for kind in &kinds {
            let mut after = 0;
            loop {
                if cancel.is_cancelled() {
                    return Err(Error::new("cancelled", "npm migration canceled."));
                }
                let shape: Option<(i64,i64)> = sqlx_core::query_as::query_as("SELECT octet_length(data::text)::bigint,jsonb_array_length(jsonb_path_query_array(data,'strict $.**.type()'))::bigint FROM devres_npm_evidence WHERE kind=$1 AND sequence>$2 AND sequence<=$3 ORDER BY sequence LIMIT 1")
                    .bind(kind).bind(after).bind(cutoff).fetch_optional(&self.pool).await.map_err(|_|super::storage_error())?;
                let Some((bytes, nodes)) = shape else {
                    break;
                };
                let _input = execution
                    .graph_reserve(
                        crate::MigrationExecution::graph_input_charge(
                            usize::try_from(bytes).map_err(|_| super::storage_error())?,
                            usize::try_from(nodes).map_err(|_| super::storage_error())?,
                        )?,
                        &cancel,
                    )
                    .await?;
                let rows = self.npm_rows(kind, after, 1, Some(cutoff), None).await?;
                if rows.is_empty() {
                    break;
                }
                for row in rows {
                    after = row.sequence;
                    if !row.key.starts_with("blake3:")
                        && integrity::migration_lookup(mappings, "npm:id", &row.key).is_none()
                    {
                        let id = integrity::canonical_hash(&json!([
                            "devres:npm:migration-occurrence:v1",
                            row.key,
                            row.data
                        ]))?;
                        crate::migration_map::insert(mappings, format!("npm:id:{}", row.key), id)?;
                    }
                    for field in
                        if matches!(kind.as_str(), "advisory-members" | "advisory-packages") {
                            vec!["snapshot"]
                        } else if kind == "snapshots" {
                            vec!["membership"]
                        } else {
                            Vec::new()
                        }
                    {
                        if let Some(group) = row.data.get(field).and_then(Value::as_str)
                            && !group.starts_with("blake3:")
                            && integrity::migration_lookup(mappings, "npm:id", group).is_none()
                        {
                            let id = integrity::canonical_hash(&json!([
                                "devres:npm:migration-membership:v1",
                                group
                            ]))?;
                            crate::migration_map::insert(mappings, format!("npm:id:{group}"), id)?;
                        }
                    }
                }
            }
        }
        let mut state_cursor = String::new();
        loop {
            let keys = self.npm_migration_state_keys(&state_cursor, 100).await?;
            if keys.is_empty() {
                break;
            }
            for key in keys {
                state_cursor = key.clone();
                if key.starts_with("storage-migration:") {
                    continue;
                }
                let _input = self
                    .migration_state_reservation("npm", &key, 0, execution, &cancel)
                    .await?;
                if let Some(data) = self.npm_state(&key).await? {
                    for field in ["snapshot", "membership"] {
                        if let Some(group) = data.get(field).and_then(Value::as_str)
                            && !group.starts_with("blake3:")
                            && integrity::migration_lookup(mappings, "npm:id", group).is_none()
                        {
                            let id = integrity::canonical_hash(&json!([
                                "devres:npm:migration-membership:v1",
                                group
                            ]))?;
                            crate::migration_map::insert(mappings, format!("npm:id:{group}"), id)?;
                        }
                    }
                }
            }
        }
        let index = NpmIndex::new(&self.root)?;
        let mut aliases = crate::migration_map::MigrationAliases::new(mappings)?;
        // Source identifiers are small; decoded rows are loaded only after graph admission.
        const JOB_BYTES: usize = 256 * 1024 * 1024;
        let mut graph_admitted = 0_u64;
        let mut graph_committed = 0_u64;
        for kind in &kinds {
            let mut after = 0_i64;
            loop {
                if cancel.is_cancelled() {
                    return Err(Error::new("cancelled", "npm migration canceled."));
                }
                let positions: Vec<(i64, String, i64, i64, bool)> = sqlx_core::query_as::query_as(
                    "SELECT sequence,key,octet_length(data::text)::bigint,jsonb_array_length(jsonb_path_query_array(data,'strict $.**.type()'))::bigint,(data->'index' IS NOT NULL AND data->'index' <> 'null'::jsonb) FROM devres_npm_evidence WHERE kind=$1 AND sequence>$2 AND sequence<=$3 ORDER BY sequence LIMIT $4"
                ).bind(kind).bind(after).bind(cutoff).bind(execution.options().workers as i64)
                    .fetch_all(&self.pool).await.map_err(|_| super::storage_error())?;
                if positions.is_empty() {
                    break;
                }
                let positions = execution.graph_input_window(
                    positions
                        .into_iter()
                        .map(|(seq, id, bytes, nodes, indexed)| {
                            let charge = crate::MigrationExecution::graph_input_charge(
                                usize::try_from(bytes).map_err(|_| super::storage_error())?,
                                usize::try_from(nodes).map_err(|_| super::storage_error())?,
                            )?
                            .checked_add(if indexed { JOB_BYTES } else { 0 })
                            .ok_or_else(|| Error::capacity("npm graph input charge overflow."))?;
                            Ok(((seq, id), charge))
                        })
                        .collect::<Result<Vec<_>>>()?,
                )?;
                after = positions.last().map_or(after, |((seq, _), _)| *seq);
                graph_admitted += positions.len() as u64;
                let read_mappings = &*mappings;
                let index = &index;
                let prepared = execution
                    .graph_map_ordered(positions, &cancel, |(sequence, old), token| async move {
                        let Some(new) = integrity::migration_lookup(read_mappings, "npm:id", &old)
                        else {
                            return Ok(None);
                        };
                        let row = self
                            .npm_rows(kind, sequence - 1, 1, Some(cutoff), None)
                            .await?
                            .into_iter()
                            .next()
                            .ok_or_else(|| Error::integrity("Frozen npm row disappeared."))?;
                        if row.key != old || row.sequence != sequence {
                            return Err(Error::integrity("Frozen npm row changed."));
                        }
                        let mut data = row.data;
                        let frozen_mappings = read_mappings.clone();
                        let frozen_kind = kind.clone();
                        let (mut data, original_index) = execution
                            .run(&token, move |token| {
                                if token.is_cancelled() {
                                    return Err(Error::new("cancelled", "npm migration canceled."));
                                }
                                let original =
                                    data.get("index").filter(|value| !value.is_null()).cloned();
                                rewrite_references(&frozen_kind, &mut data, &frozen_mappings)?;
                                Ok((data, original))
                            })
                            .await?;
                        if let Some(original) = original_index {
                            data["index"] = self
                                .rebuild_npm_frozen_index(
                                    index,
                                    &original,
                                    read_mappings,
                                    token,
                                    execution,
                                )
                                .await?;
                        }
                        Ok(Some((old, new, data)))
                    })
                    .await?;
                for result in prepared {
                    if cancel.is_cancelled() {
                        return Err(Error::new("cancelled", "npm migration canceled."));
                    }
                    if let Some((old, new, data)) = result.value() {
                        self.npm_put(kind, new, data).await?;
                        aliases.push((kind.clone(), old.clone(), new.clone()))?;
                        graph_committed += 1;
                    }
                }
                execution.report(
                    "graph_npm_rows",
                    graph_admitted,
                    graph_admitted,
                    graph_committed,
                    0,
                );
            }
        }
        let mut after_state = String::new();
        loop {
            let keys = self.npm_migration_state_keys(&after_state, 100).await?;
            if keys.is_empty() {
                break;
            }
            for key in keys {
                after_state = key.clone();
                if key.starts_with("storage-migration:") {
                    continue;
                }
                let _input = self
                    .migration_state_reservation("npm", &key, JOB_BYTES, execution, &cancel)
                    .await?;
                let mut data = self
                    .npm_state(&key)
                    .await?
                    .ok_or_else(|| Error::integrity("Retained npm state missing."))?;
                let original_index = if key == "index" {
                    Some(data.clone())
                } else {
                    data.get("index").filter(|v| !v.is_null()).cloned()
                };
                rewrite_references("state", &mut data, mappings)?;
                if let Some(reference) = original_index {
                    let rebuilt = self
                        .rebuild_npm_frozen_index(
                            &index,
                            &reference,
                            mappings,
                            cancel.clone(),
                            execution,
                        )
                        .await?;
                    if key == "index" {
                        data = rebuilt;
                    } else {
                        data["index"] = rebuilt;
                    }
                }
                // Scheduling/source-cache lookup keys retain their established derivation.
                let staged_key = if let Some(old) = key.strip_prefix("ready:") {
                    integrity::migration_lookup(mappings, "npm:id", old)
                        .map_or_else(|| key.clone(), |new| format!("ready:{new}"))
                } else {
                    key.clone()
                };
                self.npm_set_state(&format!("storage-migration:{staged_key}"), &data)
                    .await?;
            }
        }
        mappings.ensure_healthy()?;
        aliases.ensure_healthy()?;
        Ok(aliases)
    }

    async fn rebuild_npm_frozen_index(
        &self,
        index: &NpmIndex,
        reference: &Value,
        mappings: &crate::migration_map::MigrationMap,
        cancel: CancellationToken,
        execution: &crate::MigrationExecution,
    ) -> Result<Value> {
        let mut reader = index
            .frozen_documents_with_execution(reference, cancel.clone(), execution)
            .await?;
        let mut rebuilt = None;
        let mut docs = Vec::new();
        let mut text_bytes = 0_usize;
        loop {
            let (ids, has_more) = reader.next_page(128).await?;
            for old in ids {
                let row = self
                    .npm_get("documents", &old)
                    .await?
                    .ok_or_else(|| Error::integrity("Frozen npm index document missing."))?;
                let id = integrity::migration_lookup(mappings, "npm:id", &old)
                    .ok_or_else(|| Error::integrity("Frozen npm document mapping missing."))?
                    .clone();
                let mut data = row.data;
                rewrite_references("documents", &mut data, mappings)?;
                let doc = IndexDocument {
                    id,
                    name: data["name"].as_str().unwrap_or_default().into(),
                    version: data["version"].as_str().unwrap_or_default().into(),
                    path: data["path"].as_str().unwrap_or_default().into(),
                    title: data["path"].as_str().unwrap_or_default().into(),
                    text: data["text"]
                        .as_str()
                        .ok_or_else(|| Error::integrity("Frozen npm index text missing."))?
                        .into(),
                    kind: data["kind"].as_str().unwrap_or("source").into(),
                    metadata: json!({}),
                };
                NpmIndex::validate_document(&doc, &cancel)?;
                if !docs.is_empty()
                    && (text_bytes.saturating_add(doc.text.len()) > 16 * 1024 * 1024
                        || docs.len() >= 512)
                {
                    rebuilt = Some(
                        index
                            .publish_generation_with_execution(
                                rebuilt.as_ref(),
                                std::mem::take(&mut docs),
                                cancel.clone(),
                                "blake3-migration",
                                execution,
                            )
                            .await?,
                    );
                    text_bytes = 0;
                }
                text_bytes = text_bytes.saturating_add(doc.text.len());
                docs.push(doc);
            }
            if !has_more {
                break;
            }
        }
        if !docs.is_empty() {
            rebuilt = Some(
                index
                    .publish_generation_with_execution(
                        rebuilt.as_ref(),
                        docs,
                        cancel.clone(),
                        "blake3-migration",
                        execution,
                    )
                    .await?,
            );
        }
        match rebuilt {
            Some(reference) => Ok(reference),
            None => {
                index
                    .publish_generation_with_execution(
                        None,
                        Vec::new(),
                        cancel,
                        "blake3-migration",
                        execution,
                    )
                    .await
            }
        }
    }
}
