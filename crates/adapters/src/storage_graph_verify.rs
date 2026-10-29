//! Read-only reference closure checks supplement per-record BLAKE3 verification.
use super::{PgBlobStore, storage_error};
use crate::{integrity, npm::index::NpmIndex};
use devres_application::npm::NpmStore;
use devres_domain::{Error, Result};
use serde_json::Value;
use sqlx::Row;
use tokio_util::sync::CancellationToken;

fn missing() -> Error {
    Error::integrity("Retained graph reference is missing or invalid.")
}
fn stop(cancel: &CancellationToken) -> Result<()> {
    if cancel.is_cancelled() {
        return Err(Error::new(
            "cancelled",
            "Storage graph verification canceled.",
        ));
    }
    Ok(())
}

impl PgBlobStore {
    pub(super) async fn verify_migration_alias_targets(
        &self,
        cancel: &CancellationToken,
    ) -> Result<()> {
        let mut after = String::new();
        loop {
            stop(cancel)?;
            let rows=sqlx::query("SELECT namespace,legacy,canonical,namespace||chr(1)||legacy AS page_key FROM devres_content_aliases WHERE namespace||chr(1)||legacy>$1 ORDER BY namespace||chr(1)||legacy LIMIT 100")
                .bind(&after).fetch_all(&self.pool).await.map_err(|_|storage_error())?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                let namespace: String = row.try_get("namespace").map_err(|_| storage_error())?;
                let target: String = row.try_get("canonical").map_err(|_| storage_error())?;
                let exists: bool = match namespace.as_str() {
                    "body" => sqlx::query_scalar(
                        "SELECT EXISTS(SELECT 1 FROM devres_integrity_files WHERE digest=$1)",
                    )
                    .bind(&target)
                    .fetch_one(&self.pool)
                    .await
                    .map_err(|_| storage_error())?,
                    "capture" => sqlx::query_scalar(
                        "SELECT EXISTS(SELECT 1 FROM devres_captures WHERE id=$1)",
                    )
                    .bind(&target)
                    .fetch_one(&self.pool)
                    .await
                    .map_err(|_| storage_error())?,
                    _ => {
                        let (provider, kind) = namespace.split_once(':').ok_or_else(missing)?;
                        if kind == "manifest" {
                            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM devres_integrity_files WHERE digest=$1)").bind(&target).fetch_one(&self.pool).await.map_err(|_|storage_error())?
                        } else if provider == "rfc" {
                            if let Some(kind) = kind.strip_prefix("dataset-") {
                                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM devres_rfc_datasets WHERE kind=$1 AND capture_id=$2)").bind(kind).bind(&target).fetch_one(&self.pool).await.map_err(|_|storage_error())?
                            } else if kind == "snapshots" {
                                sqlx::query_scalar(
                                    "SELECT EXISTS(SELECT 1 FROM devres_rfc_snapshots WHERE id=$1)",
                                )
                                .bind(&target)
                                .fetch_one(&self.pool)
                                .await
                                .map_err(|_| storage_error())?
                            } else {
                                return Err(missing());
                            }
                        } else if provider == "crate" {
                            let table = match kind {
                                "inventories" => "devres_crate_inventories",
                                "generations" => "devres_crate_generations",
                                "content" => "devres_crate_content",
                                "snapshots" => "devres_crate_snapshots",
                                _ => return Err(missing()),
                            };
                            let query = format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE id=$1)");
                            sqlx::query_scalar(sqlx::AssertSqlSafe(query))
                                .bind(&target)
                                .fetch_one(&self.pool)
                                .await
                                .map_err(|_| storage_error())?
                        } else if provider == "advisory" && matches!(kind, "records" | "snapshots")
                        {
                            let table = if kind == "records" {
                                "devres_advisory_records"
                            } else {
                                "devres_advisory_snapshots"
                            };
                            let query = format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE id=$1)");
                            sqlx::query_scalar(sqlx::AssertSqlSafe(query))
                                .bind(&target)
                                .fetch_one(&self.pool)
                                .await
                                .map_err(|_| storage_error())?
                        } else {
                            let table = match provider {
                                "mdn" => "devres_mdn_evidence",
                                "whatwg" => "devres_whatwg_evidence",
                                "w3c" => "devres_w3c_evidence",
                                "chromium" => "devres_chromium_evidence",
                                "npm" => "devres_npm_evidence",
                                "advisory" => "devres_advisory_rows",
                                _ => return Err(missing()),
                            };
                            let query = format!(
                                "SELECT EXISTS(SELECT 1 FROM {table} WHERE kind=$1 AND key=$2)"
                            );
                            sqlx::query_scalar(sqlx::AssertSqlSafe(query))
                                .bind(kind)
                                .bind(&target)
                                .fetch_one(&self.pool)
                                .await
                                .map_err(|_| storage_error())?
                        }
                    }
                };
                if !exists {
                    return Err(missing());
                }
                after = row.try_get("page_key").map_err(|_| storage_error())?;
            }
        }
        Ok(())
    }

    async fn npm_edge(&self, kind: &str, value: &Value) -> Result<()> {
        if value.is_null() {
            return Ok(());
        }
        let key = value.as_str().ok_or_else(missing)?;
        if self.npm_get(kind, key).await?.is_none() {
            return Err(missing());
        }
        Ok(())
    }

    async fn npm_body(&self, value: &Value) -> Result<()> {
        if value.is_null() {
            return Ok(());
        }
        let (hash, expected_bytes) = if let Some(hash) = value.as_str() {
            (hash, None)
        } else {
            let hash = value["body_hash"].as_str().ok_or_else(missing)?;
            let bytes = value["bytes"].as_u64().ok_or_else(missing)?;
            if value["relative_path"] != integrity::relative_path(hash)?.to_string_lossy().as_ref()
            {
                return Err(missing());
            }
            (hash, Some(bytes))
        };
        let relative =
            std::path::Path::new("npm/raw-artifacts").join(integrity::relative_path(hash)?);
        let path = self.root.join(&relative);
        let metadata = tokio::fs::symlink_metadata(&path)
            .await
            .map_err(|_| missing())?;
        if !metadata.is_file() || expected_bytes.is_some_and(|n| n != metadata.len()) {
            return Err(missing());
        }
        let digest = if hash.starts_with("blake3:") {
            hash.to_owned()
        } else {
            sqlx::query_scalar("SELECT digest FROM devres_integrity_files WHERE path=$1")
                .bind(relative.to_string_lossy().as_ref())
                .fetch_optional(&self.pool)
                .await
                .map_err(|_| storage_error())?
                .ok_or_else(missing)?
        };
        // The full physical inventory subsequently recomputes these digests once
        // per file; reference traversal checks the frozen descriptor and length.
        integrity::verify_legacy_digest(&path, &digest, metadata.len())
    }

    pub(super) async fn verify_npm_graph(&self, cancel: &CancellationToken) -> Result<()> {
        let index = NpmIndex::for_verification(&self.root)?;
        for kind in self.npm_migration_kinds().await? {
            let mut after = 0;
            loop {
                stop(cancel)?;
                let rows = self.npm_migration_rows(&kind, after, 1).await?;
                if rows.is_empty() {
                    break;
                }
                for row in rows {
                    after = row.sequence;
                    let data = &row.data;
                    match kind.as_str() {
                        "advisories" | "failures" => {}
                        "source-observations"
                        | "archive-observations"
                        | "artifacts"
                        | "metadata-captures" => {
                            if data.get("artifact").is_some() {
                                self.npm_body(&data["artifact"]).await?;
                            }
                        }
                        "versions" => self.npm_body(&data["metadata"]).await?,
                        "documents" | "projections" => {
                            self.npm_body(&data["artifact"]).await?;
                            self.npm_edge("versions", &data["release"]).await?;
                            if let Some(ids) = data["documents"].as_array() {
                                for id in ids {
                                    self.npm_edge("documents", id).await?;
                                }
                            }
                        }
                        "advisory-raw" => {
                            self.npm_body(&data["artifact"]).await?;
                            self.npm_edge("advisories", &data["record"]).await?;
                        }
                        "members" => {
                            let target = match data["kind"].as_str() {
                                Some("version") => "versions",
                                Some("archive") => "artifacts",
                                Some("projection") => "projections",
                                Some("document" | "indexed-document") => "documents",
                                _ => return Err(missing()),
                            };
                            self.npm_edge(target, &data["record"]).await?;
                            if data["kind"] == "indexed-document" {
                                self.npm_edge("indexed", &data["record"]).await?;
                            }
                        }
                        "advisory-members" | "advisory-packages" => {
                            self.npm_edge("advisories", &data["record"]).await?;
                            if data.get("raw").is_some() {
                                self.npm_edge("advisory-raw", &data["raw"]).await?;
                            }
                        }
                        "snapshots" | "package-snapshots" => {
                            for field in ["previous", "reprocessed_from"] {
                                if let Some(id) = data.get(field) {
                                    self.npm_edge(kind.as_str(), id).await?;
                                }
                            }
                            if data.get("artifact").is_some() {
                                self.npm_body(&data["artifact"]).await?;
                            }
                            if data.get("metadata").is_some() {
                                self.npm_body(&data["metadata"]).await?;
                            }
                            if let Some(packages) = data["packages"].as_object() {
                                for id in packages.values() {
                                    self.npm_edge("package-snapshots", id).await?;
                                }
                            }
                        }
                        "indexed" | "rebuild-index-members" => {
                            self.npm_edge("documents", data.get("record").unwrap_or(&data["id"]))
                                .await?
                        }
                        "gaps" => {
                            if let Some(body) = data.get("artifact") {
                                self.npm_body(body).await?;
                            }
                            if let Some(body) = data.get("metadata") {
                                self.npm_body(body).await?;
                            }
                            if let Some(id) = data.get("document") {
                                self.npm_edge("documents", id).await?;
                            }
                        }
                        _ => return Err(missing()),
                    }
                    if let Some(reference) = data.get("index").filter(|v| !v.is_null()) {
                        let mut position = 0;
                        loop {
                            let (ids, next) = index
                                .document_ids(reference, position, 128, cancel.clone())
                                .await?;
                            for id in ids {
                                self.npm_edge("documents", &Value::String(id)).await?;
                            }
                            match next {
                                Some(next) => position = next,
                                None => break,
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
