//! Read-only referential closure checks for specialized retained corpus generations.
use super::super::{PgBlobStore, capture_metadata_digest, payload_integrity, storage_error};
use devres_application::{
    advisory::AdvisoryStore,
    crate_corpus::{ContentFilter, CrateCorpusStore},
};
use devres_domain::{Capture, Error, Result};
use serde_json::Value;
use sqlx::Row;
use std::collections::BTreeSet;
use tokio_util::sync::CancellationToken;

fn invalid() -> Error {
    Error::integrity("Retained specialized corpus reference is invalid.")
}
fn stop(cancel: &CancellationToken) -> Result<()> {
    if cancel.is_cancelled() {
        Err(Error::new(
            "cancelled",
            "Specialized corpus verification canceled.",
        ))
    } else {
        Ok(())
    }
}

async fn capture(store: &PgBlobStore, id: &str) -> Result<Capture> {
    let row=sqlx::query("SELECT id,source_key,source_url,body_hash,media_type,retrieved_at,metadata_integrity FROM devres_captures WHERE id=$1").bind(id).fetch_optional(&store.pool).await.map_err(|_|storage_error())?.ok_or_else(invalid)?;
    let capture = Capture {
        id: row.try_get("id").map_err(|_| invalid())?,
        key: row.try_get("source_key").map_err(|_| invalid())?,
        source_url: row.try_get("source_url").map_err(|_| invalid())?,
        body_hash: row.try_get("body_hash").map_err(|_| invalid())?,
        media_type: row.try_get("media_type").map_err(|_| invalid())?,
        retrieved_at: row.try_get("retrieved_at").map_err(|_| invalid())?,
        validated_at: 0,
    };
    if capture_metadata_digest(&capture)?
        != row
            .try_get::<String, _>("metadata_integrity")
            .map_err(|_| invalid())?
    {
        return Err(invalid());
    }
    crate::integrity::verify(
        &capture.id,
        format!(
            "{}\0{}\0{}\0{}",
            capture.key, capture.source_url, capture.media_type, capture.body_hash
        )
        .as_bytes(),
    )?;
    let path = store
        .root
        .join(crate::integrity::relative_path(&capture.body_hash)?);
    if !tokio::fs::symlink_metadata(path)
        .await
        .map_err(|_| invalid())?
        .is_file()
    {
        return Err(invalid());
    }
    Ok(capture)
}
async fn capture_matches(store: &PgBlobStore, expected: &Capture) -> Result<()> {
    let found = capture(store, &expected.id).await?;
    if found.id != expected.id
        || found.key != expected.key
        || found.source_url != expected.source_url
        || found.body_hash != expected.body_hash
        || found.media_type != expected.media_type
        || found.retrieved_at != expected.retrieved_at
    {
        return Err(invalid());
    }
    Ok(())
}
async fn snapshot_capture_fields(store: &PgBlobStore, value: &Value) -> Result<()> {
    for field in ["capture", "metadata_capture", "archive_capture"] {
        if let Some(id) = value[field].as_str() {
            capture(store, id).await?;
        }
    }
    Ok(())
}
impl PgBlobStore {
    pub(crate) async fn verify_specialized_graphs(&self, cancel: &CancellationToken) -> Result<()> {
        self.fence().await?;
        let mut after = (String::new(), String::new());
        loop {
            stop(cancel)?;
            let found=sqlx::query("SELECT kind,capture_id AS key,data,data_integrity FROM devres_rfc_datasets WHERE (kind,capture_id)>($1,$2) ORDER BY kind,capture_id LIMIT 1").bind(&after.0).bind(&after.1).fetch_optional(&self.pool).await.map_err(|_|storage_error())?;
            let Some(found) = found else {
                break;
            };
            let kind: String = found.try_get("kind").map_err(|_| invalid())?;
            let key: String = found.try_get("key").map_err(|_| invalid())?;
            let value: devres_application::corpus::Dataset =
                serde_json::from_value(payload_integrity::row("devres_rfc_datasets", &found)?)
                    .map_err(|_| invalid())?;
            if value.capture.id != key {
                return Err(invalid());
            }
            capture_matches(self, &value.capture).await?;
            after = (kind, key);
        }
        let mut after = String::new();
        loop {
            stop(cancel)?;
            let found=sqlx::query("SELECT published_order,catalogue_capture,errata_capture,created_at,complete,''::text AS kind,id AS key,data,data_integrity FROM devres_rfc_snapshots WHERE id>$1 ORDER BY id LIMIT 1").bind(&after).fetch_optional(&self.pool).await.map_err(|_|storage_error())?;
            let Some(found) = found else {
                break;
            };
            let key: String = found.try_get("key").map_err(|_| invalid())?;
            let value: devres_application::corpus::Snapshot =
                serde_json::from_value(payload_integrity::row("devres_rfc_snapshots", &found)?)
                    .map_err(|_| invalid())?;
            if value.id != key {
                return Err(invalid());
            }
            for (kind, id) in [
                ("catalogue", Some(&value.catalogue_capture)),
                ("errata", value.errata_capture.as_ref()),
            ] {
                if let Some(id) = id {
                    capture(self, id).await?;
                    let dataset=sqlx::query("SELECT kind,capture_id AS key,data,data_integrity FROM devres_rfc_datasets WHERE kind=$1 AND capture_id=$2").bind(kind).bind(id).fetch_optional(&self.pool).await.map_err(|_|storage_error())?.ok_or_else(invalid)?;
                    payload_integrity::row("devres_rfc_datasets", &dataset)?;
                }
            }
            let mut selected = BTreeSet::new();
            for document in &value.documents {
                capture_matches(self, &document.capture).await?;
            }
            for document in &value.search_documents {
                if !selected.insert(document.number)
                    || !value.documents.iter().any(|original| {
                        original.number == document.number
                            && original.format == document.format
                            && original.assurance == document.assurance
                            && original.capture.id == document.capture.id
                    })
                {
                    return Err(invalid());
                }
                capture_matches(self, &document.capture).await?;
            }
            if let Some(path) = value.index_path {
                let root = self.root.clone();
                let child = cancel.child_token();
                let expected = selected.clone();
                tokio::task::spawn_blocking(move || {
                    let mut after = 0;
                    let mut actual = BTreeSet::new();
                    loop {
                        stop(&child)?;
                        let (rows, next) =
                            crate::rfc::index::export_documents(&root, &path, after, 1)?;
                        for row in rows {
                            if !actual.insert(row.number) {
                                return Err(invalid());
                            }
                        }
                        match next {
                            Some(next) => after = next,
                            None => break,
                        }
                    }
                    if actual != expected {
                        return Err(invalid());
                    }
                    Ok(())
                })
                .await
                .map_err(|_| invalid())??;
            }
            after = key;
        }
        let mut after = String::new();
        loop {
            stop(cancel)?;
            let found: Option<(String, String)> = sqlx::query_as(
                "SELECT id,format FROM devres_advisory_snapshots WHERE id>$1 ORDER BY id LIMIT 1",
            )
            .bind(&after)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| storage_error())?;
            let Some((key, format)) = found else {
                break;
            };
            let snapshot = self
                .advisory_snapshot(Some(&key), &format)
                .await?
                .ok_or_else(invalid)?;
            if snapshot.id != key || snapshot.format != format {
                return Err(invalid());
            }
            for referenced in &snapshot.captures {
                capture_matches(self, referenced).await?;
            }
            if let Some(observation) = snapshot.coverage["git_observation"].as_str() {
                let value = payload_integrity::load(
                    &self.pool,
                    "devres_advisory_rows",
                    "refs",
                    observation,
                )
                .await?
                .ok_or_else(invalid)?;
                if value.0["id"] != observation {
                    return Err(invalid());
                }
            }
            after = key;
        }
        let mut after = String::new();
        loop {
            stop(cancel)?;
            let found=sqlx::query("SELECT sequence,inventory,content_sequence,''::text AS kind,id AS key,data,data_integrity FROM devres_crate_snapshots WHERE id>$1 ORDER BY id LIMIT 1").bind(&after).fetch_optional(&self.pool).await.map_err(|_|storage_error())?;
            let Some(found) = found else {
                break;
            };
            let key: String = found.try_get("key").map_err(|_| invalid())?;
            let snapshot: devres_application::crate_corpus::Snapshot =
                serde_json::from_value(payload_integrity::row("devres_crate_snapshots", &found)?)
                    .map_err(|_| invalid())?;
            if snapshot.id != key {
                return Err(invalid());
            }
            let inventory = sqlx::query(
                "SELECT id,sequence,revision,created_at FROM devres_crate_inventories WHERE id=$1",
            )
            .bind(&snapshot.inventory.id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| storage_error())?
            .ok_or_else(invalid)?;
            if inventory
                .try_get::<i64, _>("sequence")
                .map_err(|_| invalid())?
                != snapshot.inventory.sequence
                || inventory
                    .try_get::<String, _>("revision")
                    .map_err(|_| invalid())?
                    != snapshot.inventory.revision
                || inventory
                    .try_get::<i64, _>("created_at")
                    .map_err(|_| invalid())?
                    != snapshot.inventory.created_at
            {
                return Err(invalid());
            }
            if let Some(enrichment) = &snapshot.enrichment {
                capture(self, enrichment).await?;
                let exists: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM devres_crate_artifacts WHERE capture_id=$1)",
                )
                .bind(enrichment)
                .fetch_one(&self.pool)
                .await
                .map_err(|_| storage_error())?;
                if !exists {
                    return Err(invalid());
                }
            }
            let mut content_after = None;
            loop {
                stop(cancel)?;
                let rows = self
                    .contents(
                        snapshot.content_sequence,
                        &ContentFilter::default(),
                        content_after.as_deref(),
                        1,
                    )
                    .await?;
                if rows.is_empty() {
                    break;
                }
                for row in rows {
                    for id in [&row.capture, &row.metadata_capture, &row.archive_capture] {
                        capture(self, id).await?;
                    }
                    crate::integrity::verify(
                        &row.id,
                        format!(
                            "{}\0{}\0{}\0{}",
                            row.capture, row.kind, row.target, row.path
                        )
                        .as_bytes(),
                    )?;
                    content_after = Some(row.id);
                }
            }
            if !snapshot.index_manifest.is_null() {
                let root = self.root.clone();
                let reference = snapshot.index_manifest.clone();
                let child = cancel.child_token();
                let mut offset = 0_usize;
                loop {
                    stop(cancel)?;
                    let root = root.clone();
                    let reference = reference.clone();
                    let child = child.clone();
                    let (rows, next) = tokio::task::spawn_blocking(move || {
                        crate::crates_io::index::export_documents(
                            &root, &reference, offset, 1, &child,
                        )
                    })
                    .await
                    .map_err(|_| invalid())??;
                    for (payload, _) in rows {
                        snapshot_capture_fields(self, &payload["record"]).await?;
                        if let Some(id) = payload["enrichment"]["artifact"].as_str() {
                            capture(self, id).await?;
                        }
                        if payload["class"] == "content" {
                            let record = &payload["record"];
                            let id = record["id"].as_str().ok_or_else(invalid)?;
                            let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM devres_crate_content c JOIN devres_crate_generations g ON g.id=c.generation WHERE c.id=$1 AND g.published_sequence<=$2)").bind(id).bind(snapshot.content_sequence).fetch_one(&self.pool).await.map_err(|_|storage_error())?;
                            if !exists {
                                return Err(invalid());
                            }
                        } else if payload["class"] == "version" {
                            let record = &payload["record"];
                            let found = self
                                .version(
                                    &snapshot.inventory.id,
                                    record["name"].as_str().ok_or_else(invalid)?,
                                    record["version"].as_str().ok_or_else(invalid)?,
                                )
                                .await?
                                .ok_or_else(invalid)?;
                            if record["metadata_capture"] != found.metadata_capture
                                || record["record"] != found.record
                            {
                                return Err(invalid());
                            }
                        } else {
                            return Err(invalid());
                        }
                    }
                    match next {
                        Some(next) => offset = next,
                        None => break,
                    }
                }
            }
            after = key;
        }
        Ok(())
    }
}
