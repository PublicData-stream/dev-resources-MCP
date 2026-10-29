//! Private, offline, resumable BLAKE3 qualification. Never performs network I/O.
use super::{PgBlobStore, payload_integrity, storage_error};
use crate::integrity::{self, FileEvidence};
use devres_domain::{Error, Result};
use serde_json::{Value, json};
use sqlx::{Connection, Row, types::Json};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;

const PROVIDERS: &[&str] = &["mdn", "whatwg", "w3c", "chromium", "npm"];
const JSON_TABLES: &[(&str, &str)] = &[
    ("devres_advisory_rows", "data"),
    ("devres_advisory_state", "data"),
    ("devres_advisory_records", "data"),
    ("devres_advisory_snapshots", "data"),
    ("devres_rfc_datasets", "data"),
    ("devres_rfc_snapshots", "data"),
    ("devres_rfc_jobs", "capture_metadata"),
    ("devres_crate_artifacts", "provenance"),
    ("devres_crate_observations", "provenance"),
    ("devres_crate_staging", "record"),
    ("devres_crate_versions", "record"),
    ("devres_crate_generations", "summary"),
    ("devres_crate_content", "attributes"),
    ("devres_crate_enrichment", "data"),
    ("devres_crate_snapshots", "data"),
];

pub(super) async fn prepare(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    fresh: bool,
) -> Result<()> {
    sqlx::raw_sql(r#"
CREATE TABLE devres_integrity_control(singleton boolean PRIMARY KEY CHECK(singleton),active boolean NOT NULL,files_complete boolean NOT NULL DEFAULT false,sql_complete boolean NOT NULL DEFAULT false,graph_complete boolean NOT NULL DEFAULT false);
CREATE TABLE devres_content_aliases(namespace text NOT NULL,legacy text NOT NULL,canonical text NOT NULL CHECK(canonical ~ '^blake3:[0-9a-f]{64}$'),mapping_integrity text CHECK(mapping_integrity IS NULL OR mapping_integrity ~ '^blake3:[0-9a-f]{64}$'),PRIMARY KEY(namespace,legacy),UNIQUE(namespace,canonical,legacy));
CREATE TABLE devres_integrity_files(path text PRIMARY KEY,digest text NOT NULL CHECK(digest ~ '^blake3:[0-9a-f]{64}$'),bytes bigint NOT NULL CHECK(bytes>=0));
CREATE TABLE devres_integrity_graph_progress(provider text PRIMARY KEY,complete boolean NOT NULL,aliases_count bigint NOT NULL CHECK(aliases_count>=0),aliases_digest text NOT NULL CHECK(aliases_digest ~ '^blake3:[0-9a-f]{64}$'),progress_integrity text NOT NULL CHECK(progress_integrity ~ '^blake3:[0-9a-f]{64}$'));
CREATE TABLE devres_integrity_provider_cutoffs(provider text PRIMARY KEY,legacy_cutoff bigint NOT NULL CHECK(legacy_cutoff>=0),cutoff_integrity text NOT NULL CHECK(cutoff_integrity ~ '^blake3:[0-9a-f]{64}$'));
CREATE TABLE devres_integrity_staged_state(provider text NOT NULL,key text NOT NULL,data jsonb NOT NULL,data_integrity text NOT NULL CHECK(data_integrity ~ '^blake3:[0-9a-f]{64}$'),PRIMARY KEY(provider,key));
ALTER TABLE devres_observations ADD COLUMN event_integrity text CHECK(event_integrity IS NULL OR event_integrity ~ '^blake3:[0-9a-f]{64}$');
ALTER TABLE devres_rfc_import_observations ADD COLUMN event_integrity text CHECK(event_integrity IS NULL OR event_integrity ~ '^blake3:[0-9a-f]{64}$');
ALTER TABLE devres_heads ADD COLUMN head_integrity text CHECK(head_integrity IS NULL OR head_integrity ~ '^blake3:[0-9a-f]{64}$');
ALTER TABLE devres_captures ADD COLUMN metadata_integrity text CHECK(metadata_integrity IS NULL OR metadata_integrity ~ '^blake3:[0-9a-f]{64}$');
ALTER TABLE devres_captures DROP CONSTRAINT IF EXISTS devres_captures_id_check;
ALTER TABLE devres_captures DROP CONSTRAINT IF EXISTS devres_captures_body_hash_check;
ALTER TABLE devres_captures ADD CHECK(id ~ '^(blake3:)?[0-9a-f]{64}$'),ADD CHECK(body_hash ~ '^(blake3:)?[0-9a-f]{64}$');
ALTER TABLE devres_rfc_snapshots DROP CONSTRAINT IF EXISTS devres_rfc_snapshots_id_check;
ALTER TABLE devres_crate_inventories DROP CONSTRAINT IF EXISTS devres_crate_inventories_revision_key;
ALTER TABLE devres_rfc_snapshots ADD CHECK(id ~ '^(blake3:)?[0-9a-f]{64}$');
"#).execute(&mut **tx).await.map_err(|_| storage_error())?;
    sqlx::query("INSERT INTO devres_integrity_control(singleton,active,files_complete,sql_complete,graph_complete) VALUES(true,$1,$1,$1,$1)")
        .bind(fresh).execute(&mut **tx).await.map_err(|_| storage_error())?;
    for provider in PROVIDERS {
        for suffix in ["evidence", "state"] {
            let table = format!("devres_{provider}_{suffix}");
            add_column(tx, &table, "data").await?;
        }
    }
    for (table, column) in JSON_TABLES {
        add_column(tx, table, column).await?;
    }
    for provider in ["mdn", "whatwg", "w3c", "chromium", "npm", "advisory"] {
        let table = if provider == "advisory" {
            "devres_advisory_rows".to_owned()
        } else {
            format!("devres_{provider}_evidence")
        };
        let query = format!(
            "ALTER TABLE {table} ADD COLUMN sequence_integrity text CHECK(sequence_integrity IS NULL OR sequence_integrity ~ '^blake3:[0-9a-f]{{64}}$')"
        );
        sqlx::raw_sql(sqlx::AssertSqlSafe(query))
            .execute(&mut **tx)
            .await
            .map_err(|_| storage_error())?;
    }
    if fresh {
        for provider in [
            "mdn",
            "whatwg",
            "w3c",
            "chromium",
            "npm",
            "advisory",
            "crate_inventory",
            "crate_generation",
            "crate_snapshot",
        ] {
            let proof = super::events::event_digest(
                "devres_integrity_provider_cutoffs",
                provider,
                &json!({"provider":provider,"legacy_cutoff":0}),
            )?;
            sqlx::query("INSERT INTO devres_integrity_provider_cutoffs(provider,legacy_cutoff,cutoff_integrity) VALUES($1,0,$2)").bind(provider).bind(proof).execute(&mut **tx).await.map_err(|_|storage_error())?;
        }
        for provider in [
            "body", "capture", "rfc", "advisory", "crate", "npm", "mdn", "whatwg", "w3c",
            "chromium",
        ] {
            let (count, digest) = super::visibility::AliasMembership::new(provider)?.finish();
            let proof = super::events::event_digest(
                "devres_integrity_graph_progress",
                provider,
                &json!({"provider":provider,"complete":true,"aliases_count":count,"aliases_digest":digest}),
            )?;
            sqlx::query("INSERT INTO devres_integrity_graph_progress(provider,complete,aliases_count,aliases_digest,progress_integrity) VALUES($1,true,$2,$3,$4)")
                .bind(provider).bind(count).bind(digest).bind(proof).execute(&mut **tx).await.map_err(|_|storage_error())?;
        }
        enforce_constraints(tx).await?;
    }
    sqlx::query("UPDATE devres_schema SET version=10 WHERE singleton")
        .execute(&mut **tx)
        .await
        .map_err(|_| storage_error())?;
    Ok(())
}

async fn enforce_constraints(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>) -> Result<()> {
    for provider in PROVIDERS {
        for suffix in ["evidence", "state"] {
            let query = format!(
                "ALTER TABLE devres_{provider}_{suffix} ALTER COLUMN data_integrity SET NOT NULL"
            );
            sqlx::raw_sql(sqlx::AssertSqlSafe(query))
                .execute(&mut **tx)
                .await
                .map_err(|_| storage_error())?;
        }
    }
    for (table, column) in JSON_TABLES {
        let query = if *table == "devres_rfc_jobs" {
            format!(
                "ALTER TABLE {table} ADD CONSTRAINT devres_rfc_capture_integrity_required CHECK (({column} IS NULL)=({column}_integrity IS NULL))"
            )
        } else {
            format!("ALTER TABLE {table} ALTER COLUMN {column}_integrity SET NOT NULL")
        };
        sqlx::raw_sql(sqlx::AssertSqlSafe(query))
            .execute(&mut **tx)
            .await
            .map_err(|_| storage_error())?;
    }
    for provider in ["mdn", "whatwg", "w3c", "chromium", "npm", "advisory"] {
        let table = if provider == "advisory" {
            "devres_advisory_rows".to_owned()
        } else {
            format!("devres_{provider}_evidence")
        };
        let query = format!("ALTER TABLE {table} ALTER COLUMN sequence_integrity SET NOT NULL");
        sqlx::raw_sql(sqlx::AssertSqlSafe(query))
            .execute(&mut **tx)
            .await
            .map_err(|_| storage_error())?;
    }
    sqlx::raw_sql("ALTER TABLE devres_captures ALTER COLUMN metadata_integrity SET NOT NULL; ALTER TABLE devres_observations ALTER COLUMN event_integrity SET NOT NULL; ALTER TABLE devres_rfc_import_observations ALTER COLUMN event_integrity SET NOT NULL; ALTER TABLE devres_heads ALTER COLUMN head_integrity SET NOT NULL; ALTER TABLE devres_content_aliases ALTER COLUMN mapping_integrity SET NOT NULL")
        .execute(&mut **tx).await.map_err(|_|storage_error())?;
    Ok(())
}

async fn add_column(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    table: &str,
    column: &str,
) -> Result<()> {
    // Identifiers originate exclusively in the fixed provider/table allowlists above.
    let query = format!(
        "ALTER TABLE {table} ADD COLUMN {column}_integrity text CHECK({column}_integrity IS NULL OR {column}_integrity ~ '^blake3:[0-9a-f]{{64}}$')"
    );
    sqlx::raw_sql(sqlx::AssertSqlSafe(query))
        .execute(&mut **tx)
        .await
        .map_err(|_| storage_error())?;
    Ok(())
}

fn canceled(cancel: &CancellationToken) -> Result<()> {
    if cancel.is_cancelled() {
        return Err(Error::new("cancelled", "Storage migration canceled."));
    }
    Ok(())
}

impl PgBlobStore {
    /// Qualifies every permanent file and SQL payload before graph activation.
    /// Re-running verifies committed checkpoints rather than trusting their presence.
    pub async fn migrate_storage(&self, cancel: CancellationToken) -> Result<Value> {
        self.fence().await?;
        let active: bool =
            sqlx::query_scalar("SELECT active FROM devres_integrity_control WHERE singleton")
                .fetch_one(&self.pool)
                .await
                .map_err(|_| storage_error())?;
        if active {
            return Err(Error::invalid(
                "Storage is already BLAKE3 active; use verify-storage.",
            ));
        }
        self.verify_visibility_registry().await?;
        self.prepare_graph_cutoffs().await?;
        self.qualify_files(&cancel).await?;
        super::sequence_integrity::backfill(self, &cancel, false).await?;
        self.qualify_sql(&cancel, false).await?;
        payload_integrity::backfill_specialized(self, &cancel, false).await?;
        self.backfill_events(&cancel, false).await?;
        self.canonicalize_captures(&cancel).await?;
        sqlx::query("UPDATE devres_integrity_control SET files_complete=true,sql_complete=true WHERE singleton")
            .execute(&mut *self.owner.lock().await).await.map_err(|_| storage_error())?;
        Ok(json!({"format":1,"algorithm":"blake3","phase":"qualified","active":false}))
    }

    async fn qualify_files(&self, cancel: &CancellationToken) -> Result<()> {
        let root = self.root.clone();
        let mut stack = vec![root.clone()];
        while let Some(directory) = stack.pop() {
            canceled(cancel)?;
            let mut entries = tokio::fs::read_dir(&directory)
                .await
                .map_err(|_| storage_error())?;
            while let Some(entry) = entries.next_entry().await.map_err(|_| storage_error())? {
                canceled(cancel)?;
                let name = entry.file_name();
                let name = name
                    .to_str()
                    .ok_or_else(|| Error::integrity("Unsupported retained path encoding."))?;
                if name == ".devres-integrity"
                    || name == ".devres-git-owned"
                    || name.starts_with(".stage-")
                    || name.starts_with(".bulk-stage-")
                    || name.ends_with(".lock")
                {
                    continue;
                }
                let path = entry.path();
                let kind = entry.file_type().await.map_err(|_| storage_error())?;
                if kind.is_symlink() {
                    return Err(Error::integrity("Unexpected retained storage link."));
                }
                if kind.is_dir() {
                    // Bare mirrors are disposable; permanent packs/manifests live in archive roots.
                    if name.ends_with(".git") || name == "git-index" || name == "mirrors" {
                        continue;
                    }
                    if stack.len() >= 1024
                        || path.components().count() > root.components().count() + 32
                    {
                        return Err(Error::capacity("Storage traversal bound exceeded."));
                    }
                    stack.push(path);
                } else if kind.is_file() {
                    self.qualify_file(&path, cancel).await?;
                } else {
                    return Err(Error::integrity("Unsupported retained filesystem member."));
                }
            }
        }
        Ok(())
    }

    async fn qualify_file(&self, path: &Path, cancel: &CancellationToken) -> Result<()> {
        canceled(cancel)?;
        let relative = path
            .strip_prefix(&self.root)
            .ok()
            .and_then(Path::to_str)
            .ok_or_else(|| Error::integrity("Invalid retained path."))?
            .to_owned();
        let owned = path.to_path_buf();
        let (digest, bytes) = tokio::task::spawn_blocking(move || {
            integrity::file_digest(
                &owned,
                crate::bulk::MAX_ARTIFACT_BYTES,
                Instant::now() + Duration::from_secs(3600),
            )
        })
        .await
        .map_err(|_| storage_error())??;
        canceled(cancel)?;
        // Content-addressed source files have authoritative legacy filename evidence.
        if let Some(name) = path.file_name().and_then(|v| v.to_str())
            && let Some(hex) = name.strip_suffix(".json")
            && path
                .parent()
                .and_then(Path::file_name)
                .and_then(|v| v.to_str())
                == Some("manifests")
            && integrity::valid_hash(hex)
        {
            let canonical = path
                .parent()
                .and_then(Path::parent)
                .and_then(Path::file_name)
                .and_then(|v| v.to_str())
                == Some("blake3");
            if !canonical {
                verify_legacy_sha_file(path, hex)?;
            }
        }
        if let Some(name) = path.file_name().and_then(|v| v.to_str())
            && integrity::valid_hash(name)
            && !name.starts_with("blake3:")
            && path
                .parent()
                .and_then(Path::file_name)
                .and_then(|v| v.to_str())
                != Some("blake3")
        {
            verify_legacy_sha_file(path, name)?;
            let parent = path.parent().ok_or_else(storage_error)?;
            publish_link(path, &parent.join(integrity::relative_path(&digest)?)).await?;
            let namespace = "body";
            sqlx::query("INSERT INTO devres_content_aliases(namespace,legacy,canonical,mapping_integrity) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING")
                .bind(namespace).bind(name).bind(&digest).bind(mapping_digest(namespace,name,&digest)?).execute(&mut *self.owner.lock().await).await.map_err(|_|storage_error())?;
            let matches: bool = sqlx::query_scalar(
                "SELECT canonical=$3 FROM devres_content_aliases WHERE namespace=$1 AND legacy=$2",
            )
            .bind(namespace)
            .bind(name)
            .bind(&digest)
            .fetch_one(&self.pool)
            .await
            .map_err(|_| storage_error())?;
            if !matches {
                return Err(Error::integrity("Conflicting retained content mapping."));
            }
        }
        let prior = sqlx::query("SELECT digest,bytes FROM devres_integrity_files WHERE path=$1")
            .bind(&relative)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| storage_error())?;
        if let Some(prior) = prior {
            let old: String = prior.try_get("digest").map_err(|_| storage_error())?;
            let old_bytes: i64 = prior.try_get("bytes").map_err(|_| storage_error())?;
            if old != digest || old_bytes != bytes as i64 {
                return Err(Error::integrity("Retained migration checkpoint changed."));
            }
        }
        let evidence = FileEvidence {
            version: 1,
            path: relative.clone(),
            bytes,
            digest: digest.clone(),
        };
        let target = integrity::evidence_path(&self.root, path)?;
        let encoded = serde_json::to_vec(&evidence).map_err(|_| storage_error())?;
        publish_metadata(&target, &encoded).await?;
        sqlx::query("INSERT INTO devres_integrity_files(path,digest,bytes) VALUES($1,$2,$3) ON CONFLICT(path) DO NOTHING")
            .bind(&relative).bind(&digest).bind(bytes as i64).execute(&mut *self.owner.lock().await).await.map_err(|_| storage_error())?;
        Ok(())
    }

    async fn qualify_sql(&self, cancel: &CancellationToken, verify_only: bool) -> Result<()> {
        for provider in PROVIDERS {
            for suffix in ["evidence", "state"] {
                canceled(cancel)?;
                let table = format!("devres_{provider}_{suffix}");
                let mut after = String::new();
                loop {
                    canceled(cancel)?;
                    let query = if suffix == "state" {
                        format!(
                            "SELECT ''::text AS kind,key,data,data_integrity,key AS page_key FROM {table} WHERE key>$1 ORDER BY key LIMIT 1"
                        )
                    } else {
                        format!(
                            "SELECT kind,key,data,data_integrity,kind||chr(1)||key AS page_key FROM {table} WHERE kind||chr(1)||key>$1 ORDER BY kind||chr(1)||key LIMIT 1"
                        )
                    };
                    let rows = sqlx::query(sqlx::AssertSqlSafe(query))
                        .bind(&after)
                        .fetch_all(&self.pool)
                        .await
                        .map_err(|_| storage_error())?;
                    if rows.is_empty() {
                        break;
                    }
                    let mut owner = self.owner.lock().await;
                    let mut tx = owner.begin().await.map_err(|_| storage_error())?;
                    for row in rows {
                        let kind: String = row.try_get("kind").map_err(|_| storage_error())?;
                        let key: String = row.try_get("key").map_err(|_| storage_error())?;
                        let data: Json<Value> = row.try_get("data").map_err(|_| storage_error())?;
                        let expected: Option<String> =
                            row.try_get("data_integrity").map_err(|_| storage_error())?;
                        let digest = payload_integrity::digest(&table, &kind, &key, &data.0)?;
                        if let Some(expected) = expected {
                            if digest != expected {
                                return Err(Error::integrity("Retained SQL payload changed."));
                            }
                        } else if verify_only {
                            return Err(Error::integrity("Retained SQL integrity missing."));
                        } else {
                            let update = if suffix == "state" {
                                format!(
                                    "UPDATE {table} SET data_integrity=$3 WHERE key=$2 AND $1::text=''"
                                )
                            } else {
                                format!(
                                    "UPDATE {table} SET data_integrity=$3 WHERE kind=$1 AND key=$2"
                                )
                            };
                            sqlx::query(sqlx::AssertSqlSafe(update))
                                .bind(&kind)
                                .bind(&key)
                                .bind(&digest)
                                .execute(&mut *tx)
                                .await
                                .map_err(|_| storage_error())?;
                        }
                        after = row.try_get("page_key").map_err(|_| storage_error())?;
                    }
                    tx.commit().await.map_err(|_| storage_error())?;
                }
            }
        }
        Ok(())
    }

    async fn canonicalize_captures(&self, cancel: &CancellationToken) -> Result<()> {
        let mut after = String::new();
        loop {
            canceled(cancel)?;
            let rows = sqlx::query("SELECT * FROM devres_captures WHERE id>$1 AND id NOT LIKE 'blake3:%' ORDER BY id LIMIT 100")
                .bind(&after).fetch_all(&self.pool).await.map_err(|_| storage_error())?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                canceled(cancel)?;
                let id: String = row.try_get("id").map_err(|_| storage_error())?;
                let body_hash: String = row.try_get("body_hash").map_err(|_| storage_error())?;
                let key: String = row.try_get("source_key").map_err(|_| storage_error())?;
                let url: String = row.try_get("source_url").map_err(|_| storage_error())?;
                let media: String = row.try_get("media_type").map_err(|_| storage_error())?;
                let time: i64 = row.try_get("retrieved_at").map_err(|_| storage_error())?;
                integrity::verify(
                    &id,
                    format!("{key}\0{url}\0{media}\0{body_hash}").as_bytes(),
                )?;
                let legacy_capture = devres_domain::Capture {
                    id: id.clone(),
                    key: key.clone(),
                    source_url: url.clone(),
                    body_hash: body_hash.clone(),
                    media_type: media.clone(),
                    retrieved_at: time,
                    validated_at: time,
                };
                let legacy_metadata = super::capture_metadata_digest(&legacy_capture)?;
                let prior: Option<String> = row
                    .try_get("metadata_integrity")
                    .map_err(|_| storage_error())?;
                if prior.as_ref().is_some_and(|v| v != &legacy_metadata) {
                    return Err(Error::integrity("Legacy capture metadata changed."));
                }
                sqlx::query("UPDATE devres_captures SET metadata_integrity=$2 WHERE id=$1 AND metadata_integrity IS NULL")
                    .bind(&id).bind(&legacy_metadata).execute(&mut *self.owner.lock().await).await.map_err(|_| storage_error())?;
                let source = self.root.join(integrity::relative_path(&body_hash)?);
                let evidence =
                    sqlx::query("SELECT digest FROM devres_integrity_files WHERE path=$1")
                        .bind(
                            integrity::relative_path(&body_hash)?
                                .to_string_lossy()
                                .as_ref(),
                        )
                        .fetch_optional(&self.pool)
                        .await
                        .map_err(|_| storage_error())?;
                let Some(evidence) = evidence else {
                    return Err(Error::integrity(
                        "Captured source file missing from migration.",
                    ));
                };
                let digest: String = evidence.try_get("digest").map_err(|_| storage_error())?;
                let canonical =
                    integrity::hash(format!("{key}\0{url}\0{media}\0{digest}").as_bytes());
                let target = self.root.join(integrity::relative_path(&digest)?);
                publish_link(&source, &target).await?;
                let mut owner = self.owner.lock().await;
                let mut tx = owner.begin().await.map_err(|_| storage_error())?;
                let metadata_digest = super::capture_metadata_digest(&devres_domain::Capture {
                    id: canonical.clone(),
                    body_hash: digest.clone(),
                    ..legacy_capture
                })?;
                sqlx::query("INSERT INTO devres_captures(id,source_key,source_url,body_hash,media_type,retrieved_at,metadata_integrity) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING")
                    .bind(&canonical).bind(&key).bind(&url).bind(&digest).bind(&media).bind(time).bind(&metadata_digest).execute(&mut *tx).await.map_err(|_| storage_error())?;
                sqlx::query("INSERT INTO devres_content_aliases(namespace,legacy,canonical,mapping_integrity) VALUES('capture',$1,$2,$3) ON CONFLICT DO NOTHING")
                    .bind(&id).bind(&canonical).bind(mapping_digest("capture",&id,&canonical)?).execute(&mut *tx).await.map_err(|_| storage_error())?;
                let matches: bool = sqlx::query_scalar("SELECT canonical=$2 FROM devres_content_aliases WHERE namespace='capture' AND legacy=$1")
                    .bind(&id).bind(&canonical).fetch_one(&mut *tx).await.map_err(|_| storage_error())?;
                if !matches {
                    return Err(Error::integrity("Conflicting capture migration mapping."));
                }
                // Legacy observations remain exact; canonical reads consult their alias.
                let head=sqlx::query("SELECT source_key,validated_at,etag,last_modified FROM devres_heads WHERE capture_id=$1").bind(&id).fetch_optional(&mut *tx).await.map_err(|_|storage_error())?;
                if let Some(head) = head {
                    let key: String = head.try_get("source_key").map_err(|_| storage_error())?;
                    let data = json!({"source_key":key,"capture_id":canonical,"validated_at":head.try_get::<i64,_>("validated_at").map_err(|_|storage_error())?,"etag":head.try_get::<Option<String>,_>("etag").map_err(|_|storage_error())?,"last_modified":head.try_get::<Option<String>,_>("last_modified").map_err(|_|storage_error())?});
                    let stage = format!("head:{key}");
                    let digest = payload_integrity::digest(
                        "devres_integrity_staged_state",
                        "capture",
                        &stage,
                        &data,
                    )?;
                    sqlx::query("INSERT INTO devres_integrity_staged_state(provider,key,data,data_integrity) VALUES('capture',$1,$2,$3) ON CONFLICT DO NOTHING")
                        .bind(stage).bind(Json(&data)).bind(digest).execute(&mut *tx).await.map_err(|_|storage_error())?;
                }
                tx.commit().await.map_err(|_| storage_error())?;
                after = id;
            }
        }
        Ok(())
    }

    pub async fn migration_mappings(&self) -> Result<std::collections::BTreeMap<String, String>> {
        self.fence().await?;
        let (count,bytes):(i64,i64)=sqlx::query_as("SELECT count(*)::bigint,COALESCE(sum(octet_length(namespace)+octet_length(legacy)+octet_length(canonical)+129),0)::bigint FROM devres_content_aliases")
            .fetch_one(&self.pool).await.map_err(|_|storage_error())?;
        if count > 1_000_000 || bytes > 64 * 1024 * 1024 {
            return Err(Error::capacity("Migration mapping memory bound exceeded."));
        }
        let rows=sqlx::query("SELECT namespace,legacy,canonical,mapping_integrity FROM devres_content_aliases ORDER BY namespace,legacy LIMIT 1000001")
            .fetch_all(&self.pool).await.map_err(|_|storage_error())?;
        if rows.len() > 1_000_000 {
            return Err(Error::capacity("Migration mapping memory bound exceeded."));
        }
        let mut mappings = std::collections::BTreeMap::new();
        let mut bytes = 0_usize;
        for row in rows {
            let namespace: String = row.try_get("namespace").map_err(|_| storage_error())?;
            let old: String = row.try_get("legacy").map_err(|_| storage_error())?;
            let new: String = row.try_get("canonical").map_err(|_| storage_error())?;
            let expected: String = row
                .try_get("mapping_integrity")
                .map_err(|_| storage_error())?;
            if mapping_digest(&namespace, &old, &new)? != expected {
                return Err(Error::integrity("Migration mapping integrity failed."));
            }
            let key = format!("{namespace}:{old}");
            bytes = bytes.saturating_add(key.len() + new.len());
            if bytes > 64 * 1024 * 1024 {
                return Err(Error::capacity("Migration mapping byte bound exceeded."));
            }
            crate::migration_map::insert(&mut mappings, key, new)?;
        }
        Ok(mappings)
    }

    pub async fn prepare_graph_cutoffs(&self) -> Result<()> {
        self.fence().await?;
        for provider in [
            "mdn",
            "whatwg",
            "w3c",
            "chromium",
            "npm",
            "advisory",
            "crate_inventory",
            "crate_generation",
            "crate_snapshot",
        ] {
            let (table, column) = match provider {
                "advisory" => ("devres_advisory_rows".to_owned(), "sequence"),
                "crate_inventory" => ("devres_crate_inventories".to_owned(), "sequence"),
                "crate_generation" => ("devres_crate_generations".to_owned(), "published_sequence"),
                "crate_snapshot" => ("devres_crate_snapshots".to_owned(), "sequence"),
                _ => (format!("devres_{provider}_evidence"), "sequence"),
            };
            let query = format!("SELECT COALESCE(max({column}),0)::bigint FROM {table}");
            let value: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(query))
                .fetch_one(&self.pool)
                .await
                .map_err(|_| storage_error())?;
            let digest = super::events::event_digest(
                "devres_integrity_provider_cutoffs",
                provider,
                &json!({"provider":provider,"legacy_cutoff":value}),
            )?;
            sqlx::query("INSERT INTO devres_integrity_provider_cutoffs(provider,legacy_cutoff,cutoff_integrity) VALUES($1,$2,$3) ON CONFLICT DO NOTHING")
                .bind(provider).bind(value).bind(digest).execute(&mut *self.owner.lock().await).await.map_err(|_|storage_error())?;
        }
        Ok(())
    }

    pub async fn migration_graph_done(&self, provider: &str) -> Result<bool> {
        self.fence().await?;
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM devres_integrity_graph_progress WHERE provider=$1 AND complete)").bind(provider)
            .fetch_one(&self.pool).await.map_err(|_|storage_error())
    }

    pub async fn finish_graph_migration(
        self: &std::sync::Arc<Self>,
        cancel: CancellationToken,
    ) -> Result<Value> {
        let ready:bool=sqlx::query_scalar("SELECT count(*)=8 FROM devres_integrity_graph_progress WHERE complete AND provider IN ('mdn','whatwg','w3c','chromium','npm','advisory','rfc','crate')")
            .fetch_one(&self.pool).await.map_err(|_|storage_error())?;
        if !ready {
            return Err(Error::integrity("Provider graph migration is incomplete."));
        }
        self.qualify_files(&cancel).await?;
        self.seal_alias_membership("body").await?;
        self.seal_alias_membership("capture").await?;
        self.verify_complete_visibility_registry().await?;
        let receipt = self.verify_storage(cancel).await?;
        sqlx::query("UPDATE devres_integrity_control SET graph_complete=true WHERE singleton AND NOT active")
            .execute(&mut *self.owner.lock().await).await.map_err(|_|storage_error())?;
        Ok(json!({"phase":"ready_for_activation","active":false,"verification":receipt}))
    }

    pub async fn record_migration_aliases(
        &self,
        provider: &str,
        aliases: &[(String, String, String)],
    ) -> Result<()> {
        if !matches!(
            provider,
            "mdn" | "whatwg" | "w3c" | "chromium" | "npm" | "rfc" | "crate" | "advisory"
        ) {
            return Err(Error::invalid("Invalid migration provider."));
        }
        for chunk in aliases.chunks(100) {
            let mut owner = self.owner.lock().await;
            let mut tx = owner.begin().await.map_err(|_| storage_error())?;
            for (kind, old, new) in chunk {
                if kind.is_empty()
                    || kind.len() > 64
                    || !new.starts_with("blake3:")
                    || !integrity::valid_hash(new)
                {
                    return Err(Error::integrity("Invalid migration mapping."));
                }
                let namespace = format!("{provider}:{kind}");
                sqlx::query("INSERT INTO devres_content_aliases(namespace,legacy,canonical,mapping_integrity) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING")
                    .bind(&namespace).bind(old).bind(new).bind(mapping_digest(&namespace,old,new)?).execute(&mut *tx).await.map_err(|_|storage_error())?;
                let matches: bool = sqlx::query_scalar("SELECT canonical=$3 FROM devres_content_aliases WHERE namespace=$1 AND legacy=$2")
                    .bind(&namespace).bind(old).bind(new).fetch_one(&mut *tx).await.map_err(|_|storage_error())?;
                if !matches {
                    return Err(Error::integrity("Conflicting migration mapping."));
                }
            }
            tx.commit().await.map_err(|_| storage_error())?;
        }
        self.seal_alias_membership(provider).await?;
        Ok(())
    }

    async fn seal_alias_membership(&self, provider: &str) -> Result<()> {
        use futures::TryStreamExt;
        let mut stream=sqlx::query("SELECT namespace,legacy,canonical FROM devres_content_aliases WHERE namespace=$1 OR namespace LIKE $1||':%' ORDER BY namespace COLLATE \"C\",legacy COLLATE \"C\"").bind(provider).fetch(&self.pool);
        let mut manifest = super::visibility::AliasMembership::new(provider)?;
        while let Some(row) = stream.try_next().await.map_err(|_| storage_error())? {
            manifest.push(
                &row.try_get::<String, _>("namespace")
                    .map_err(|_| storage_error())?,
                &row.try_get::<String, _>("legacy")
                    .map_err(|_| storage_error())?,
                &row.try_get::<String, _>("canonical")
                    .map_err(|_| storage_error())?,
            )?;
        }
        drop(stream);
        let (count, digest) = manifest.finish();
        let data = json!({"provider":provider,"complete":true,"aliases_count":count,"aliases_digest":digest});
        let proof =
            super::events::event_digest("devres_integrity_graph_progress", provider, &data)?;
        let mut owner = self.owner.lock().await;
        let existing=sqlx::query("SELECT complete,aliases_count,aliases_digest,progress_integrity FROM devres_integrity_graph_progress WHERE provider=$1").bind(provider).fetch_optional(&mut *owner).await.map_err(|_|storage_error())?;
        if let Some(existing) = existing {
            let complete: bool = existing.try_get("complete").map_err(|_| storage_error())?;
            let old_count: i64 = existing
                .try_get("aliases_count")
                .map_err(|_| storage_error())?;
            let old_digest: String = existing
                .try_get("aliases_digest")
                .map_err(|_| storage_error())?;
            let old_proof: String = existing
                .try_get("progress_integrity")
                .map_err(|_| storage_error())?;
            if !complete || old_count != count || old_digest != digest || old_proof != proof {
                return Err(Error::integrity("Completed alias membership changed."));
            }
        } else {
            sqlx::query("INSERT INTO devres_integrity_graph_progress(provider,complete,aliases_count,aliases_digest,progress_integrity) VALUES($1,true,$2,$3,$4)")
                .bind(provider).bind(count).bind(digest).bind(proof).execute(&mut *owner).await.map_err(|_|storage_error())?;
        }
        Ok(())
    }

    pub async fn verify_storage(
        self: &std::sync::Arc<Self>,
        cancel: CancellationToken,
    ) -> Result<Value> {
        self.fence().await?;
        super::sequence_integrity::backfill(self, &cancel, true).await?;
        self.qualify_sql(&cancel, true).await?;
        payload_integrity::backfill_specialized(self, &cancel, true).await?;
        self.backfill_events(&cancel, true).await?;
        self.verify_visibility_registry().await?;
        self.verify_capture_inventory(&cancel).await?;
        self.verify_migration_alias_targets(&cancel).await?;
        self.verify_npm_graph(&cancel).await?;
        self.verify_specialized_graphs(&cancel).await?;
        crate::storage_migration_runner::verify_provider_graphs(
            &crate::MigrationSettings::default(),
            self.clone(),
            cancel.clone(),
        )
        .await?;
        let mut after = String::new();
        let mut files = 0_u64;
        loop {
            canceled(&cancel)?;
            let rows = sqlx::query("SELECT path,digest,bytes FROM devres_integrity_files WHERE path>$1 ORDER BY path LIMIT 100")
                .bind(&after).fetch_all(&self.pool).await.map_err(|_| storage_error())?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                let relative: String = row.try_get("path").map_err(|_| storage_error())?;
                let path = self.root.join(&relative);
                let expected: String = row.try_get("digest").map_err(|_| storage_error())?;
                let bytes: i64 = row.try_get("bytes").map_err(|_| storage_error())?;
                let target = path.clone();
                let (actual, length) = tokio::task::spawn_blocking(move || {
                    integrity::file_digest(
                        &target,
                        crate::bulk::MAX_ARTIFACT_BYTES,
                        Instant::now() + Duration::from_secs(3600),
                    )
                })
                .await
                .map_err(|_| storage_error())??;
                if actual != expected || length != bytes as u64 {
                    return Err(Error::integrity("Retained checkpoint verification failed."));
                }
                integrity::verify_legacy_digest(&path, &actual, length)?;
                after = relative;
                files += 1;
            }
        }
        let inventoried = self.verify_file_inventory(&cancel).await?;
        if files > inventoried {
            return Err(Error::integrity("Retained file inventory is incomplete."));
        }
        Ok(json!({"format":1,"algorithm":"blake3","verified_files":inventoried}))
    }

    async fn verify_capture_inventory(&self, cancel: &CancellationToken) -> Result<()> {
        let mut after = String::new();
        loop {
            canceled(cancel)?;
            let rows =
                sqlx::query("SELECT * FROM devres_captures WHERE id>$1 ORDER BY id LIMIT 100")
                    .bind(&after)
                    .fetch_all(&self.pool)
                    .await
                    .map_err(|_| storage_error())?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                let capture = devres_domain::Capture {
                    id: row.try_get("id").map_err(|_| storage_error())?,
                    key: row.try_get("source_key").map_err(|_| storage_error())?,
                    source_url: row.try_get("source_url").map_err(|_| storage_error())?,
                    body_hash: row.try_get("body_hash").map_err(|_| storage_error())?,
                    media_type: row.try_get("media_type").map_err(|_| storage_error())?,
                    retrieved_at: row.try_get("retrieved_at").map_err(|_| storage_error())?,
                    validated_at: 0,
                };
                let expected: String = row
                    .try_get("metadata_integrity")
                    .map_err(|_| Error::integrity("Capture metadata integrity missing."))?;
                if super::capture_metadata_digest(&capture)? != expected {
                    return Err(Error::integrity("Capture metadata verification failed."));
                }
                integrity::verify(
                    &capture.id,
                    format!(
                        "{}\0{}\0{}\0{}",
                        capture.key, capture.source_url, capture.media_type, capture.body_hash
                    )
                    .as_bytes(),
                )?;
                let path = self
                    .root
                    .join(integrity::relative_path(&capture.body_hash)?);
                let metadata = tokio::fs::symlink_metadata(path)
                    .await
                    .map_err(|_| Error::integrity("Retained capture body missing."))?;
                if !metadata.is_file() {
                    return Err(Error::integrity("Invalid retained capture body."));
                }
                after = capture.id;
            }
        }
        Ok(())
    }

    async fn verify_file_inventory(&self, cancel: &CancellationToken) -> Result<u64> {
        let mut stack = vec![self.root.clone()];
        let mut count = 0_u64;
        while let Some(directory) = stack.pop() {
            canceled(cancel)?;
            let mut entries = tokio::fs::read_dir(&directory)
                .await
                .map_err(|_| storage_error())?;
            while let Some(entry) = entries.next_entry().await.map_err(|_| storage_error())? {
                canceled(cancel)?;
                let name = entry.file_name();
                let name = name
                    .to_str()
                    .ok_or_else(|| Error::integrity("Invalid retained file encoding."))?;
                if name == ".devres-integrity" {
                    self.verify_descriptor_inventory(&directory, cancel).await?;
                    continue;
                }
                if name == ".devres-git-owned"
                    || name.starts_with(".stage-")
                    || name.starts_with(".bulk-stage-")
                    || name.ends_with(".lock")
                {
                    continue;
                }
                let kind = entry.file_type().await.map_err(|_| storage_error())?;
                if kind.is_symlink() {
                    return Err(Error::integrity("Retained storage symlink rejected."));
                }
                let path = entry.path();
                if kind.is_dir() {
                    if name.ends_with(".git") || name == "git-index" || name == "mirrors" {
                        continue;
                    }
                    if stack.len() >= 1024
                        || path.components().count() > self.root.components().count() + 32
                    {
                        return Err(Error::capacity("Retained file traversal exceeds bound."));
                    }
                    stack.push(path);
                } else if kind.is_file() {
                    let target = path.clone();
                    let (digest, bytes) = tokio::task::spawn_blocking(move || {
                        integrity::file_digest(
                            &target,
                            crate::bulk::MAX_ARTIFACT_BYTES,
                            Instant::now() + Duration::from_secs(3600),
                        )
                    })
                    .await
                    .map_err(|_| storage_error())??;
                    integrity::verify_legacy_digest(&path, &digest, bytes)?;
                    // Explicit BLAKE3 filenames are authoritative independently of descriptors.
                    if path
                        .parent()
                        .and_then(Path::file_name)
                        .and_then(|v| v.to_str())
                        == Some("blake3")
                    {
                        let hex = name.strip_suffix(".json").unwrap_or(name);
                        if integrity::valid_hash(hex) && digest != format!("blake3:{hex}") {
                            return Err(Error::integrity("BLAKE3 file address mismatch."));
                        }
                    }
                    count = count
                        .checked_add(1)
                        .ok_or_else(|| Error::capacity("Retained file count overflow."))?;
                } else {
                    return Err(Error::integrity("Unexpected retained filesystem object."));
                }
            }
        }
        Ok(count)
    }

    async fn verify_descriptor_inventory(
        &self,
        root: &Path,
        cancel: &CancellationToken,
    ) -> Result<()> {
        let directory = root.join(".devres-integrity/files");
        let meta = tokio::fs::symlink_metadata(&directory)
            .await
            .map_err(|_| Error::integrity("Integrity descriptor directory missing."))?;
        if !meta.is_dir() {
            return Err(Error::integrity("Invalid integrity descriptor directory."));
        }
        let mut entries = tokio::fs::read_dir(&directory)
            .await
            .map_err(|_| storage_error())?;
        while let Some(entry) = entries.next_entry().await.map_err(|_| storage_error())? {
            canceled(cancel)?;
            let name = entry.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| Error::integrity("Invalid integrity evidence name."))?;
            if super::stage_name(name) {
                continue;
            }
            let metadata = tokio::fs::symlink_metadata(entry.path())
                .await
                .map_err(|_| storage_error())?;
            if !metadata.is_file() || metadata.len() > 16384 {
                return Err(Error::integrity("Invalid integrity evidence file."));
            }
            let bytes = tokio::fs::read(entry.path())
                .await
                .map_err(|_| storage_error())?;
            let evidence: FileEvidence = serde_json::from_slice(&bytes)
                .map_err(|_| Error::integrity("Invalid integrity evidence record."))?;
            let relative = Path::new(&evidence.path);
            if evidence.version != 1
                || relative.is_absolute()
                || relative
                    .components()
                    .any(|v| !matches!(v, std::path::Component::Normal(_)))
                || !evidence.digest.starts_with("blake3:")
                || !integrity::valid_hash(&evidence.digest)
            {
                return Err(Error::integrity("Invalid retained evidence identity."));
            }
            let target = root.join(relative);
            if integrity::evidence_path(root, &target)? != entry.path() {
                return Err(Error::integrity("Integrity descriptor address mismatch."));
            }
            let owned = target.clone();
            let limit = evidence.bytes;
            let (digest, length) = tokio::task::spawn_blocking(move || {
                integrity::file_digest(&owned, limit, Instant::now() + Duration::from_secs(3600))
            })
            .await
            .map_err(|_| storage_error())??;
            if digest != evidence.digest || length != evidence.bytes {
                return Err(Error::integrity(
                    "Retained evidence source missing or corrupt.",
                ));
            }
        }
        Ok(())
    }

    async fn apply_staged_activation(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ) -> Result<()> {
        for provider in PROVIDERS {
            let table = format!("devres_{provider}_state");
            let mut after = String::new();
            loop {
                let query = format!(
                    "SELECT key,data,data_integrity FROM {table} WHERE key LIKE 'storage-migration:%' AND key>$1 ORDER BY key LIMIT 1"
                );
                let found = sqlx::query(sqlx::AssertSqlSafe(query))
                    .bind(&after)
                    .fetch_optional(&mut **tx)
                    .await
                    .map_err(|_| storage_error())?;
                let Some(row) = found else {
                    break;
                };
                let staged: String = row.try_get("key").map_err(|_| storage_error())?;
                let key = staged
                    .strip_prefix("storage-migration:")
                    .ok_or_else(storage_error)?
                    .to_owned();
                after = staged.clone();
                let data: Json<Value> = row.try_get("data").map_err(|_| storage_error())?;
                let digest: String = row.try_get("data_integrity").map_err(|_| storage_error())?;
                let data = payload_integrity::checked(&table, "", &staged, data.0, &digest)?;
                if key == "graph-complete" {
                    continue;
                }
                let digest = payload_integrity::digest(&table, "", &key, &data)?;
                let update = format!(
                    "INSERT INTO {table}(key,data,data_integrity) VALUES($1,$2,$3) ON CONFLICT(key) DO UPDATE SET data=EXCLUDED.data,data_integrity=EXCLUDED.data_integrity"
                );
                sqlx::query(sqlx::AssertSqlSafe(update))
                    .bind(&key)
                    .bind(Json(&data))
                    .bind(digest)
                    .execute(&mut **tx)
                    .await
                    .map_err(|_| storage_error())?;
            }
        }
        let mut after = String::new();
        loop {
            let found=sqlx::query("SELECT provider,key,data,data_integrity,provider||chr(1)||key AS page_key FROM devres_integrity_staged_state WHERE provider||chr(1)||key>$1 ORDER BY provider||chr(1)||key LIMIT 1")
                .bind(&after).fetch_optional(&mut **tx).await.map_err(|_|storage_error())?;
            let Some(row) = found else {
                break;
            };
            let provider: String = row.try_get("provider").map_err(|_| storage_error())?;
            let key: String = row.try_get("key").map_err(|_| storage_error())?;
            let data: Json<Value> = row.try_get("data").map_err(|_| storage_error())?;
            let expected: String = row.try_get("data_integrity").map_err(|_| storage_error())?;
            let data = payload_integrity::checked(
                "devres_integrity_staged_state",
                &provider,
                &key,
                data.0,
                &expected,
            )?;
            let text = |field: &str| -> Result<&str> {
                data[field]
                    .as_str()
                    .ok_or_else(|| Error::integrity("Invalid staged migration field."))
            };
            if provider == "capture" && key.starts_with("head:") {
                let source = text("source_key")?;
                let proof = super::events::event_digest("devres_heads", source, &data)?;
                sqlx::query("UPDATE devres_heads SET capture_id=$2,validated_at=$3,etag=$4,last_modified=$5,head_integrity=$6 WHERE source_key=$1")
                    .bind(source).bind(text("capture_id")?).bind(data["validated_at"].as_i64().ok_or_else(storage_error)?).bind(data["etag"].as_str()).bind(data["last_modified"].as_str()).bind(proof).execute(&mut **tx).await.map_err(|_|storage_error())?;
            } else if provider == "rfc" && key.starts_with("job:") {
                let source = text("source_key")?;
                let metadata = data["capture_metadata"].clone();
                let digest = payload_integrity::digest(
                    "devres_rfc_jobs",
                    "capture_metadata",
                    source,
                    &metadata,
                )?;
                sqlx::query("UPDATE devres_rfc_jobs SET capture_id=$2,capture_metadata=$3,capture_metadata_integrity=$4 WHERE source_key=$1")
                    .bind(source).bind(text("capture_id")?).bind(Json(metadata)).bind(digest).execute(&mut **tx).await.map_err(|_|storage_error())?;
            } else if provider == "rfc" && key.starts_with("dataset-head:") {
                sqlx::query("UPDATE devres_rfc_dataset_heads SET capture_id=$2 WHERE kind=$1")
                    .bind(text("kind")?)
                    .bind(text("capture_id")?)
                    .execute(&mut **tx)
                    .await
                    .map_err(|_| storage_error())?;
            } else if provider == "advisory" && key.starts_with("default:") {
                sqlx::query("UPDATE devres_advisory_defaults SET snapshot=$2 WHERE format=$1")
                    .bind(text("format")?)
                    .bind(text("snapshot")?)
                    .execute(&mut **tx)
                    .await
                    .map_err(|_| storage_error())?;
            } else if provider == "advisory" && key.starts_with("state:") {
                let key = text("key")?;
                let payload = &data["data"];
                let digest = payload_integrity::digest("devres_advisory_state", "", key, payload)?;
                sqlx::query(
                    "UPDATE devres_advisory_state SET data=$2,data_integrity=$3 WHERE key=$1",
                )
                .bind(key)
                .bind(Json(payload))
                .bind(digest)
                .execute(&mut **tx)
                .await
                .map_err(|_| storage_error())?;
            } else if provider == "crate" && key.starts_with("job:") {
                sqlx::query("UPDATE devres_crate_jobs SET metadata_capture=$2,artifact=$3 WHERE source_key=$1")
                    .bind(text("source_key")?).bind(text("metadata_capture")?).bind(data["artifact"].as_str()).execute(&mut **tx).await.map_err(|_|storage_error())?;
            } else if provider == "crate" && key.starts_with("observation:") {
                // Immutable, checksummed replay receipt. Its target occurrence was
                // verified during qualification; it is not an activation update.
            } else {
                return Err(Error::integrity("Unknown staged migration operation."));
            }
            after = row.try_get("page_key").map_err(|_| storage_error())?;
        }
        Ok(())
    }

    pub async fn activate_storage(
        self: &std::sync::Arc<Self>,
        cancel: CancellationToken,
    ) -> Result<Value> {
        let active: bool =
            sqlx::query_scalar("SELECT active FROM devres_integrity_control WHERE singleton")
                .fetch_one(&self.pool)
                .await
                .map_err(|_| storage_error())?;
        if active {
            return Err(Error::invalid("Storage is already BLAKE3 active."));
        }
        self.verify_complete_visibility_registry().await?;
        let receipt = self.verify_storage(cancel).await?;
        let mut owner = self.owner.lock().await;
        let mut tx = owner.begin().await.map_err(|_| storage_error())?;
        let ready: bool = sqlx::query_scalar("SELECT files_complete AND sql_complete AND graph_complete FROM devres_integrity_control WHERE singleton FOR UPDATE")
            .fetch_one(&mut *tx).await.map_err(|_| storage_error())?;
        if !ready {
            return Err(Error::integrity(
                "Canonical graph migration is incomplete; activation refused.",
            ));
        }
        self.apply_staged_activation(&mut tx).await?;
        for provider in ["whatwg", "w3c", "chromium"] {
            let clear = format!("DELETE FROM devres_{provider}_statistics");
            sqlx::query(sqlx::AssertSqlSafe(clear))
                .execute(&mut *tx)
                .await
                .map_err(|_| storage_error())?;
            let query = format!(
                "INSERT INTO devres_{provider}_statistics(kind,rows,projection_gaps,index_gaps) SELECT kind,count(*)::bigint,COALESCE(sum(CASE WHEN kind='snapshots' THEN COALESCE((data#>>'{{coverage,projection_gaps}}')::bigint,0) ELSE 0 END),0)::bigint,COALESCE(sum(CASE WHEN kind='snapshots' THEN COALESCE((data#>>'{{coverage,index_gaps}}')::bigint,0) ELSE 0 END),0)::bigint FROM devres_{provider}_evidence e WHERE NOT EXISTS(SELECT 1 FROM devres_content_aliases a WHERE a.namespace=$1||':'||e.kind AND a.legacy=e.key) GROUP BY kind"
            );
            sqlx::query(sqlx::AssertSqlSafe(query))
                .bind(provider)
                .execute(&mut *tx)
                .await
                .map_err(|_| storage_error())?;
        }
        enforce_constraints(&mut tx).await?;
        sqlx::query("UPDATE devres_integrity_control SET active=true WHERE singleton")
            .execute(&mut *tx)
            .await
            .map_err(|_| storage_error())?;
        tx.commit().await.map_err(|_| storage_error())?;
        self.active
            .store(true, std::sync::atomic::Ordering::Release);
        Ok(json!({"active":true,"verification":receipt}))
    }
}

fn verify_legacy_sha_file(path: &Path, expected: &str) -> Result<()> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut file = std::fs::File::open(path).map_err(|_| storage_error())?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 65536];
    loop {
        let n = file.read(&mut buffer).map_err(|_| storage_error())?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    if hex::encode(hash.finalize()) != expected {
        return Err(Error::integrity("Corrupt legacy source object."));
    }
    Ok(())
}

async fn publish_metadata(target: &Path, bytes: &[u8]) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    let parent = target.parent().ok_or_else(storage_error)?;
    crate::integrity::ensure_directory(parent).await?;
    let (mut file, guard) = loop {
        let stage = parent.join(format!(
            ".stage-{}-{}",
            std::process::id(),
            super::STAGE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        match tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&stage)
            .await
        {
            Ok(file) => break (file, super::StageGuard(stage)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(storage_error()),
        }
    };
    file.write_all(bytes).await.map_err(|_| storage_error())?;
    file.sync_all().await.map_err(|_| storage_error())?;
    drop(file);
    let destination = target.to_path_buf();
    let created = tokio::task::spawn_blocking(move || {
        let guard = guard;
        match std::fs::hard_link(&guard.0, &destination) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(_) => Err(storage_error()),
        }
    })
    .await
    .map_err(|_| storage_error())??;
    if !created {
        let metadata = tokio::fs::symlink_metadata(target)
            .await
            .map_err(|_| storage_error())?;
        if !metadata.is_file()
            || metadata.len() != bytes.len() as u64
            || tokio::fs::read(target).await.map_err(|_| storage_error())? != bytes
        {
            return Err(Error::integrity("Conflicting retained integrity evidence."));
        }
    }
    sync_dir(parent.to_path_buf()).await?;
    if let Some(directory) = parent.parent() {
        sync_dir(directory.to_path_buf()).await?;
        if let Some(root) = directory.parent() {
            sync_dir(root.to_path_buf()).await?;
        }
    }
    Ok(())
}

async fn publish_link(source: &Path, target: &Path) -> Result<()> {
    let parent = target.parent().ok_or_else(storage_error)?;
    crate::integrity::ensure_directory(parent).await?;
    match tokio::fs::hard_link(source, target).await {
        Ok(()) => (),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let (digest, _) = integrity::file_digest(
                target,
                crate::bulk::MAX_ARTIFACT_BYTES,
                Instant::now() + Duration::from_secs(3600),
            )?;
            if target.file_name().and_then(|s| s.to_str()) != Some(integrity::digest_hex(&digest)?)
            {
                return Err(Error::integrity("Conflicting BLAKE3 object."));
            }
        }
        Err(_) => return Err(storage_error()),
    }
    sync_dir(parent.to_path_buf()).await?;
    if let Some(ancestor) = parent.parent() {
        sync_dir(ancestor.to_path_buf()).await?;
    }
    Ok(())
}

async fn sync_dir(directory: PathBuf) -> Result<()> {
    tokio::task::spawn_blocking(move || std::fs::File::open(directory)?.sync_all())
        .await
        .map_err(|_| storage_error())?
        .map_err(|_| storage_error())
}

fn mapping_digest(namespace: &str, old: &str, new: &str) -> Result<String> {
    super::events::event_digest(
        "devres_content_aliases",
        &super::events::mapping_key(namespace, old)?,
        &json!({"namespace":namespace,"legacy":old,"canonical":new}),
    )
}
