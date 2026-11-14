//! PostgreSQL publication follows immutable, fsynced content-addressed blob writes.
use async_trait::async_trait;
use devres_application::{Cached, Store};
use devres_domain::{
    Body, Capture, Error, FetchRequest, FetchResponse, Result, StoredCapture, Validators,
};
use sqlx_core::{connection::Connection, row::Row};
use sqlx_postgres::{PgConnection, PgPool, PgPoolOptions};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};
use tokio::{
    io::AsyncReadExt,
    sync::{Mutex, Semaphore},
};

#[cfg(test)]
#[path = "storage_acceptance.rs"]
mod acceptance;
#[path = "rustsec/storage.rs"]
mod advisory_storage;
#[path = "storage_attribution.rs"]
mod attribution_storage;
pub use attribution_storage::recovery::{
    RUSTSEC_CAPTURE_REPAIR_VERSION, RustSecRecoveryOptions, RustSecRecoveryOutcome,
    RustSecRecoveryReport, recover_rustsec_attribution,
};
#[path = "chromium/storage.rs"]
mod chromium_storage;
#[path = "collection_diagnostics.rs"]
pub(crate) mod collection_diagnostics;
#[path = "rfc/storage.rs"]
mod corpus_storage;
#[path = "crates_io/storage.rs"]
mod crate_storage;
#[path = "storage_events.rs"]
mod events;
#[path = "storage_graph_verify.rs"]
mod graph_verify;
#[path = "mdn/storage.rs"]
mod mdn_storage;
#[path = "storage_migration.rs"]
mod migration;
#[path = "storage_migration_npm.rs"]
mod migration_npm;
#[path = "npm/storage.rs"]
mod npm_storage;
#[cfg(test)]
#[path = "object_archive_tests.rs"]
mod object_archive_tests;
#[path = "storage_integrity.rs"]
mod payload_integrity;
/// Shared conservative JSON residency accounting for private offline jobs.
pub(crate) fn migration_value_charge(value: &serde_json::Value) -> devres_domain::Result<usize> {
    payload_integrity::pipeline::value_charge(value, 0)
}

impl PgBlobStore {
    /// Source state stays resident only after command-wide graph admission.
    pub(crate) async fn migration_state_reservation(
        &self,
        provider: &str,
        key: &str,
        extra: usize,
        execution: &crate::MigrationExecution,
        cancel: &tokio_util::sync::CancellationToken,
    ) -> Result<crate::GraphReservation> {
        let table = match provider {
            "npm" => "devres_npm_state",
            "advisory" => "devres_advisory_state",
            _ => return Err(Error::invalid("Unknown graph state provider.")),
        };
        self.fence().await?;
        let sql = format!(
            "SELECT octet_length(data::text)::bigint,jsonb_array_length(jsonb_path_query_array(data,'strict $.**.type()'))::bigint FROM {table} WHERE key=$1"
        );
        let shape: Option<(i64, i64)> =
            sqlx_core::query_as::query_as(sqlx_core::sql_str::AssertSqlSafe(sql))
                .bind(key)
                .fetch_optional(&self.pool)
                .await
                .map_err(|_| storage_error())?;
        let (bytes, nodes) = shape.unwrap_or((0, 0));
        let charge = crate::MigrationExecution::graph_input_charge(
            usize::try_from(bytes).map_err(|_| storage_error())?,
            usize::try_from(nodes).map_err(|_| storage_error())?,
        )?
        .checked_add(extra)
        .ok_or_else(|| Error::capacity("Graph state charge overflow."))?;
        execution.graph_reserve(charge, cancel).await
    }
}

#[path = "storage_reader.rs"]
mod reader;
#[path = "storage_sequence.rs"]
mod sequence_integrity;
#[path = "storage_visibility.rs"]
mod visibility;
#[path = "w3c/storage.rs"]
mod w3c_storage;
#[path = "whatwg/storage.rs"]
mod whatwg_storage;
#[path = "wikipedia/storage.rs"]
mod wikipedia_storage;

const MAX_BLOB: usize = 128 * 1024 * 1024;
static STAGE: AtomicU64 = AtomicU64::new(0);
struct StageGuard(PathBuf);
impl Drop for StageGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let _ = crate::durable_archive::forget_local(&self.0);
    }
}
fn stage_name(name: &str) -> bool {
    name.strip_prefix(".stage-")
        .and_then(|v| v.split_once('-'))
        .is_some_and(|(pid, counter)| {
            !pid.is_empty()
                && !counter.is_empty()
                && pid.bytes().all(|b| b.is_ascii_digit())
                && counter.bytes().all(|b| b.is_ascii_digit())
        })
}

pub struct PgBlobStore {
    pub(crate) pool: PgPool,
    active: AtomicBool,
    reader: bool,
    lifecycle_shared: bool,
    visibility: tokio::sync::OnceCell<visibility::VisibilityRegistry>,
    enrichment_membership: Mutex<std::collections::BTreeSet<String>>,
    root: PathBuf,
    read_budget: Arc<Semaphore>,
    // A dedicated non-reconnecting connection holds the single-server fence.
    pub(crate) owner: Arc<Mutex<PgConnection>>,
    archive: std::sync::OnceLock<Arc<crate::durable_archive::Archive>>,
    owner_pid: i32,
    owner_started: String,
    artifact_budget: std::sync::OnceLock<Arc<crate::bulk::BulkArtifactStore>>,
    attribution_progress: std::sync::Mutex<attribution_storage::Progress>,
}
fn storage_error() -> Error {
    Error::unavailable("Durable storage unavailable")
}
fn hash(bytes: &[u8]) -> String {
    crate::integrity::hash(bytes)
}
fn valid_hash(value: &str) -> bool {
    crate::integrity::valid_hash(value)
}

fn capture_metadata_digest(capture: &Capture) -> Result<String> {
    crate::integrity::canonical_hash(&serde_json::json!({
        "version":1,"namespace":"capture-metadata",
        "id":capture.id,"key":capture.key,"source_url":capture.source_url,
        "body_hash":capture.body_hash,"media_type":capture.media_type,
        "retrieved_at":capture.retrieved_at
    }))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OpenMode {
    Serve,
    Migrate,
    Inspect,
    Activate,
    Transfer,
    RestoreCheck,
    Reader,
    Maintenance,
}

impl PgBlobStore {
    pub async fn connect(database_url: &str, root: impl AsRef<Path>) -> Result<Self> {
        Self::connect_inner(database_url, root, OpenMode::Serve, None).await
    }
    /// Open the optional operator-configured immutable object archive.
    pub async fn connect_archive(
        database_url: &str,
        root: impl AsRef<Path>,
        config: Option<crate::object_storage::S3Config>,
    ) -> Result<Self> {
        Self::connect_inner(database_url, root, OpenMode::Serve, config).await
    }

    /// Open a publication-capable offline task only while all runtime participants stop.
    pub async fn connect_archive_for_maintenance(
        database_url: &str,
        root: impl AsRef<Path>,
        config: Option<crate::object_storage::S3Config>,
    ) -> Result<Self> {
        Self::connect_inner(database_url, root, OpenMode::Maintenance, config).await
    }

    /// Open committed evidence without acquiring writer authority or changing storage.
    /// Filesystem roots must be mounted read-only; S3 roots are private disposable caches.
    pub async fn connect_reader(
        database_url: &str,
        root: impl AsRef<Path>,
        config: Option<crate::object_storage::S3Config>,
    ) -> Result<Self> {
        Self::connect_inner(database_url, root, OpenMode::Reader, config).await
    }
    pub const fn is_reader(&self) -> bool {
        self.reader
    }

    pub async fn connect_for_object_transfer(
        database_url: &str,
        root: impl AsRef<Path>,
        config: crate::object_storage::S3Config,
    ) -> Result<Self> {
        Self::connect_inner(database_url, root, OpenMode::Transfer, Some(config)).await
    }
    pub(crate) async fn connect_for_restore_verification(
        database_url: &str,
        root: impl AsRef<Path>,
        config: crate::object_storage::S3Config,
    ) -> Result<Self> {
        Self::connect_inner(database_url, root, OpenMode::RestoreCheck, Some(config)).await
    }
    pub async fn transfer_object_archive(
        self: &Arc<Self>,
        action: &str,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<serde_json::Value> {
        let backend: String = sqlx_core::query_scalar::query_scalar(
            "SELECT backend FROM devres_archive_control WHERE singleton",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|_| storage_error())?;
        if backend == "filesystem" {
            self.verify_storage(cancel.clone()).await?;
        }
        let receipt = self
            .archive
            .get()
            .ok_or_else(storage_error)?
            .transfer(action, cancel.clone())
            .await?;
        if backend == "s3" {
            self.verify_storage(cancel).await?;
        }
        Ok(receipt)
    }

    /// Private operator maintenance; never starts collectors or listeners.
    pub async fn connect_for_migration(database_url: &str, root: impl AsRef<Path>) -> Result<Self> {
        Self::connect_inner(database_url, root, OpenMode::Migrate, None).await
    }
    pub async fn connect_for_verification(
        database_url: &str,
        root: impl AsRef<Path>,
    ) -> Result<Self> {
        Self::connect_inner(database_url, root, OpenMode::Inspect, None).await
    }
    pub async fn connect_for_activation(
        database_url: &str,
        root: impl AsRef<Path>,
    ) -> Result<Self> {
        Self::connect_inner(database_url, root, OpenMode::Activate, None).await
    }

    /// Private maintenance verification of schema-eleven attribution only.
    /// This does not acquire source evidence or replace full storage verification.
    pub async fn verify_attribution_for_maintenance(
        &self,
        cancel: &tokio_util::sync::CancellationToken,
    ) -> Result<()> {
        self.fence().await?;
        let version: i32 = sqlx_core::query_scalar::query_scalar(
            "SELECT version FROM devres_schema WHERE singleton",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|_| storage_error())?;
        if !matches!(version, 11..=17) {
            return Err(Error::unavailable(
                "Attribution maintenance requires schema eleven.",
            ));
        }
        self.verify_attribution_storage(cancel).await
    }
    async fn connect_inner(
        database_url: &str,
        root: impl AsRef<Path>,
        mode: OpenMode,
        s3: Option<crate::object_storage::S3Config>,
    ) -> Result<Self> {
        if let Some(config) = &s3 {
            config.validate()?;
        }
        let reader = mode == OpenMode::Reader;
        // Maintenance publication needs normal archive initialization/recovery,
        // but its exclusive lifecycle lock must precede all of those operations.
        let maintenance = !matches!(
            mode,
            OpenMode::Serve | OpenMode::Reader | OpenMode::Maintenance
        );
        let lifecycle_exclusive = !matches!(mode, OpenMode::Serve | OpenMode::Reader);
        let allow_migration = mode == OpenMode::Migrate;
        let read_only = matches!(mode, OpenMode::Inspect | OpenMode::Reader);
        let mut owner = PgConnection::connect(database_url)
            .await
            .map_err(|_| storage_error())?;
        let lifecycle_sql = if lifecycle_exclusive {
            "SELECT pg_try_advisory_lock(1835365490, 2)"
        } else {
            "SELECT pg_try_advisory_lock_shared(1835365490, 2)"
        };
        let lifecycle: bool = sqlx_core::query_scalar::query_scalar(lifecycle_sql)
            .fetch_one(&mut owner)
            .await
            .map_err(|_| storage_error())?;
        if !lifecycle {
            return Err(Error::capacity(
                "Storage maintenance requires all readers and writers to stop.",
            ));
        }
        let acquired: bool = if reader {
            true
        } else {
            sqlx_core::query_scalar::query_scalar("SELECT pg_try_advisory_lock(1835365490, 1)")
                .fetch_one(&mut owner)
                .await
                .map_err(|_| storage_error())?
        };
        if !acquired {
            return Err(Error::capacity(
                "Only one serving instance may own this database",
            ));
        }
        let restore_pending: bool = sqlx_core::query_scalar::query_scalar(
            "SELECT to_regclass('public.devres_archive_restore_pending') IS NOT NULL",
        )
        .fetch_one(&mut owner)
        .await
        .map_err(|_| storage_error())?;
        if restore_pending && mode != OpenMode::RestoreCheck {
            return Err(Error::unavailable(
                "Object archive restore is pending verification.",
            ));
        }
        let identity=sqlx_core::query::query("SELECT pid,EXTRACT(EPOCH FROM backend_start)::text AS started FROM pg_stat_activity WHERE pid=pg_backend_pid()")
            .fetch_one(&mut owner).await.map_err(|_|storage_error())?;
        let owner_pid = identity.try_get("pid").map_err(|_| storage_error())?;
        let owner_started = identity.try_get("started").map_err(|_| storage_error())?;
        if read_only {
            sqlx_core::query::query("SET default_transaction_read_only=on")
                .execute(&mut owner)
                .await
                .map_err(|_| storage_error())?;
        }
        let pool = PgPoolOptions::new()
            .after_connect(move |connection, _metadata| {
                Box::pin(async move {
                    if read_only {
                        sqlx_core::query::query("SET default_transaction_read_only=on")
                            .execute(connection)
                            .await?;
                    }
                    Ok(())
                })
            })
            .max_connections(8)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect(database_url)
            .await
            .map_err(|_| storage_error())?;
        if reader {
            return Self::attach_reader(root.as_ref(), s3, pool, owner, owner_pid, owner_started)
                .await;
        }
        let existed: bool = sqlx_core::query_scalar::query_scalar(
            "SELECT to_regclass('devres_schema') IS NOT NULL",
        )
        .fetch_one(&mut owner)
        .await
        .map_err(|_| storage_error())?;
        if !existed && matches!(mode, OpenMode::Inspect | OpenMode::Activate) {
            return Err(Error::unavailable(
                "No initialized storage schema to inspect.",
            ));
        }
        if existed && !allow_migration {
            let existing: i32 = sqlx_core::query_scalar::query_scalar(
                "SELECT version FROM devres_schema WHERE singleton",
            )
            .fetch_one(&mut owner)
            .await
            .map_err(|_| storage_error())?;
            if existing < 10 {
                return Err(Error::unavailable(
                    "Offline BLAKE3 storage migration required.",
                ));
            }
        }
        let mut tx = owner.begin().await.map_err(|_| storage_error())?;
        if !matches!(mode, OpenMode::Inspect | OpenMode::Activate) {
            sqlx_core::raw_sql::raw_sql(SCHEMA)
                .execute(&mut *tx)
                .await
                .map_err(|_| storage_error())?;
        }
        let version: i32 = sqlx_core::query_scalar::query_scalar(
            "SELECT version FROM devres_schema WHERE singleton",
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| storage_error())?;
        let schema_upgrade_lock = version < 17 && mode == OpenMode::Serve;
        if schema_upgrade_lock {
            let exclusive: bool =
                sqlx_core::query_scalar::query_scalar("SELECT pg_try_advisory_lock(1835365490, 2)")
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(|_| storage_error())?;
            if !exclusive {
                return Err(Error::capacity(
                    "Stop serving readers before the storage schema upgrade.",
                ));
            }
        }
        if version == 1 {
            sqlx_core::raw_sql::raw_sql(corpus_storage::SCHEMA_V2)
                .execute(&mut *tx)
                .await
                .map_err(|_| storage_error())?;
            sqlx_core::query::query(
                "UPDATE devres_schema SET version=2 WHERE singleton AND version=1",
            )
            .execute(&mut *tx)
            .await
            .map_err(|_| storage_error())?;
        } else if !(2..=17).contains(&version) {
            return Err(Error::integrity("Unsupported storage schema version"));
        }
        if version <= 2 {
            sqlx_core::raw_sql::raw_sql(crate_storage::SCHEMA_V3)
                .execute(&mut *tx)
                .await
                .map_err(|_| storage_error())?;
            sqlx_core::query::query("UPDATE devres_schema SET version=3 WHERE singleton")
                .execute(&mut *tx)
                .await
                .map_err(|_| storage_error())?;
        }
        if version <= 3 {
            sqlx_core::raw_sql::raw_sql(advisory_storage::SCHEMA_V4)
                .execute(&mut *tx)
                .await
                .map_err(|_| storage_error())?;
            sqlx_core::query::query("UPDATE devres_schema SET version=4 WHERE singleton")
                .execute(&mut *tx)
                .await
                .map_err(|_| storage_error())?;
        }
        if version <= 4 {
            sqlx_core::raw_sql::raw_sql(mdn_storage::SCHEMA_V5)
                .execute(&mut *tx)
                .await
                .map_err(|_| storage_error())?;
            sqlx_core::query::query("UPDATE devres_schema SET version=5 WHERE singleton")
                .execute(&mut *tx)
                .await
                .map_err(|_| storage_error())?;
        }
        if version <= 5 {
            sqlx_core::raw_sql::raw_sql(whatwg_storage::SCHEMA_V6)
                .execute(&mut *tx)
                .await
                .map_err(|_| storage_error())?;
            sqlx_core::query::query("UPDATE devres_schema SET version=6 WHERE singleton")
                .execute(&mut *tx)
                .await
                .map_err(|_| storage_error())?;
        }
        if version <= 6 {
            sqlx_core::raw_sql::raw_sql(w3c_storage::SCHEMA_V7)
                .execute(&mut *tx)
                .await
                .map_err(|_| storage_error())?;
            sqlx_core::query::query("UPDATE devres_schema SET version=7 WHERE singleton")
                .execute(&mut *tx)
                .await
                .map_err(|_| storage_error())?;
        }
        if version <= 7 {
            sqlx_core::raw_sql::raw_sql(chromium_storage::SCHEMA_V8)
                .execute(&mut *tx)
                .await
                .map_err(|_| storage_error())?;
            sqlx_core::query::query("UPDATE devres_schema SET version=8 WHERE singleton")
                .execute(&mut *tx)
                .await
                .map_err(|_| storage_error())?;
        }
        if version <= 8 {
            sqlx_core::raw_sql::raw_sql(npm_storage::SCHEMA_V9)
                .execute(&mut *tx)
                .await
                .map_err(|_| storage_error())?;
            sqlx_core::query::query("UPDATE devres_schema SET version=9 WHERE singleton")
                .execute(&mut *tx)
                .await
                .map_err(|_| storage_error())?;
        }
        if version <= 9 {
            migration::prepare(&mut tx, !existed).await?;
        }
        let active: bool = sqlx_core::query_scalar::query_scalar(
            "SELECT active FROM devres_integrity_control WHERE singleton",
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| storage_error())?;
        if !maintenance && !active {
            return Err(Error::unavailable(
                "BLAKE3 storage migration is pending activation.",
            ));
        }
        if !maintenance && version <= 10 {
            attribution_storage::prepare(&mut tx).await?;
        }
        if version >= 11 {
            if !maintenance {
                attribution_storage::promote_control(&mut tx).await?;
            } else {
                attribution_storage::verify_supported_control(&mut tx).await?;
            }
        }
        if mode == OpenMode::Transfer && version < 11 {
            return Err(Error::unavailable(
                "Activate schema eleven before object archive migration.",
            ));
        }
        if !matches!(mode, OpenMode::Inspect | OpenMode::Activate) {
            sqlx_core::raw_sql::raw_sql(crate::durable_archive::SCHEMA)
                .execute(&mut *tx)
                .await
                .map_err(|_| storage_error())?;
        }
        if s3.is_some() {
            if !existed && matches!(mode, OpenMode::Serve | OpenMode::Maintenance) {
                let binding =
                    crate::durable_archive::config_binding(s3.as_ref().ok_or_else(storage_error)?)?;
                // Namespace authority and fresh origin commit with the schema,
                // before any fallible filesystem/transport initialization.
                sqlx_core::query::query("UPDATE devres_archive_control SET initializing_s3=true,pending_binding=$1,epoch=epoch+1 WHERE singleton").bind(binding).execute(&mut *tx).await.map_err(|_|storage_error())?;
            }
        } else if version >= 12 {
            let remote: bool = sqlx_core::query_scalar::query_scalar("SELECT backend='s3' OR pending_binding IS NOT NULL FROM devres_archive_control WHERE singleton").fetch_one(&mut *tx).await.map_err(|_| storage_error())?;
            if remote {
                return Err(Error::unavailable("Object archive configuration required."));
            }
        }
        if version < 14
            && matches!(
                mode,
                OpenMode::Serve
                    | OpenMode::Maintenance
                    | OpenMode::Transfer
                    | OpenMode::RestoreCheck
            )
        {
            sqlx_core::raw_sql::raw_sql(wikipedia_storage::SCHEMA_V14)
                .execute(&mut *tx)
                .await
                .map_err(|_| storage_error())?;
        }
        if version < 15
            && matches!(
                mode,
                OpenMode::Serve
                    | OpenMode::Maintenance
                    | OpenMode::Transfer
                    | OpenMode::RestoreCheck
            )
        {
            sqlx_core::raw_sql::raw_sql(crate_storage::SCHEMA_V15)
                .execute(&mut *tx)
                .await
                .map_err(|_| storage_error())?;
        }
        if version < 16
            && matches!(
                mode,
                OpenMode::Serve
                    | OpenMode::Maintenance
                    | OpenMode::Transfer
                    | OpenMode::RestoreCheck
            )
        {
            sqlx_core::raw_sql::raw_sql(corpus_storage::SCHEMA_V16)
                .execute(&mut *tx)
                .await
                .map_err(|_| storage_error())?;
        }
        if matches!(
            mode,
            OpenMode::Serve | OpenMode::Maintenance | OpenMode::Transfer | OpenMode::RestoreCheck
        ) {
            if version < 17 {
                sqlx_core::raw_sql::raw_sql(attribution_storage::recovery::SCHEMA_V17)
                    .execute(&mut *tx)
                    .await
                    .map_err(|_| storage_error())?;
            }
            sqlx_core::query::query("UPDATE devres_schema SET version=17 WHERE singleton")
                .execute(&mut *tx)
                .await
                .map_err(|_| storage_error())?;
        }
        if !maintenance {
            sqlx_core::query::query(
                "UPDATE devres_rfc_jobs SET status='pending' WHERE status='running'",
            )
            .execute(&mut *tx)
            .await
            .map_err(|_| storage_error())?;
            sqlx_core::query::query(
                "UPDATE devres_crate_jobs SET state='pending' WHERE state='running'",
            )
            .execute(&mut *tx)
            .await
            .map_err(|_| storage_error())?;
        }
        tx.commit().await.map_err(|_| storage_error())?;
        if schema_upgrade_lock {
            let released: bool =
                sqlx_core::query_scalar::query_scalar("SELECT pg_advisory_unlock(1835365490, 2)")
                    .fetch_one(&mut owner)
                    .await
                    .map_err(|_| storage_error())?;
            if !released {
                return Err(storage_error());
            }
        }
        if !matches!(mode, OpenMode::Inspect | OpenMode::Activate) {
            tokio::fs::create_dir_all(root.as_ref())
                .await
                .map_err(|_| storage_error())?;
        }
        let root = tokio::fs::canonicalize(root.as_ref())
            .await
            .map_err(|_| storage_error())?;
        if matches!(mode, OpenMode::Inspect | OpenMode::Activate) {
            for path in [
                root.join(".devres-integrity"),
                root.join(".devres-integrity/files"),
            ] {
                if !tokio::fs::symlink_metadata(path)
                    .await
                    .map_err(|_| Error::integrity("Integrity metadata directory missing."))?
                    .is_dir()
                {
                    return Err(Error::integrity("Invalid integrity metadata directory."));
                }
            }
        } else {
            crate::integrity::ensure_directory(&root.join(".devres-integrity/files")).await?;
        }
        // The exclusive database owner fence is held; no serving writer can own these stages.
        let mut entries = tokio::fs::read_dir(&root)
            .await
            .map_err(|_| storage_error())?;
        while let Some(entry) = entries.next_entry().await.map_err(|_| storage_error())? {
            if !maintenance
                && stage_name(&entry.file_name().to_string_lossy())
                && entry
                    .file_type()
                    .await
                    .map_err(|_| storage_error())?
                    .is_file()
            {
                tokio::fs::remove_file(entry.path())
                    .await
                    .map_err(|_| storage_error())?;
            }
        }
        let directory = root.clone();
        tokio::task::spawn_blocking(move || std::fs::File::open(directory)?.sync_all())
            .await
            .map_err(|_| storage_error())?
            .map_err(|_| storage_error())?;
        let store = Self {
            active: AtomicBool::new(active),
            reader: false,
            lifecycle_shared: !lifecycle_exclusive,
            visibility: tokio::sync::OnceCell::new(),
            enrichment_membership: Mutex::new(std::collections::BTreeSet::new()),
            pool,
            root,
            read_budget: Arc::new(Semaphore::new(128)),
            owner: Arc::new(Mutex::new(owner)),
            archive: std::sync::OnceLock::new(),
            owner_pid,
            owner_started,
            artifact_budget: std::sync::OnceLock::new(),
            attribution_progress: std::sync::Mutex::new(attribution_storage::Progress::default()),
        };
        if let Some(config) = s3 {
            let archive = crate::durable_archive::Archive::attach(
                store.root.clone(),
                config,
                store.pool.clone(),
                store.owner.clone(),
                store.owner_pid,
                store.owner_started.clone(),
                if matches!(mode, OpenMode::Transfer | OpenMode::RestoreCheck) {
                    crate::durable_archive::ArchiveAdmission::Transfer
                } else if !existed {
                    crate::durable_archive::ArchiveAdmission::Fresh
                } else {
                    crate::durable_archive::ArchiveAdmission::Existing
                },
            )
            .await?;
            store.archive.set(archive).map_err(|_| storage_error())?;
        }
        if active {
            store.verify_visibility_registry().await?;
            if mode == OpenMode::Serve {
                crate_storage::enrichment_v2::initialize_membership(&store).await?;
            }
        }
        Ok(store)
    }
    pub(crate) async fn retained_file_lease(
        &self,
        path: &Path,
        cancel: &tokio_util::sync::CancellationToken,
    ) -> Result<crate::durable_archive::ArchiveLease> {
        if self.archive.get().is_none() {
            return Ok(crate::durable_archive::ArchiveLease::default());
        }
        let selected = path.to_owned();
        let stopping = cancel.clone();
        tokio::task::spawn_blocking(move || {
            crate::durable_archive::materialize_file(
                &selected,
                crate::bulk::MAX_ARTIFACT_BYTES,
                std::time::Instant::now() + std::time::Duration::from_secs(3600),
                &stopping,
            )
        })
        .await
        .map_err(|_| storage_error())?
    }
    pub(crate) fn root_path(&self) -> &Path {
        &self.root
    }
    pub fn attach_artifact_budget(
        &self,
        budget: Arc<crate::bulk::BulkArtifactStore>,
    ) -> Result<()> {
        self.artifact_budget
            .set(budget)
            .map_err(|_| Error::integrity("Archive budget already attached."))
    }
    /// Fail closed if the dedicated serving owner connection is lost.
    pub async fn check_health(&self) -> Result<()> {
        self.fence().await
    }
    pub async fn check_ownership(&self) -> Result<()> {
        if self.reader {
            self.lifecycle_fence().await
        } else {
            self.owner_fence().await
        }
    }
    pub fn has_object_archive(&self) -> bool {
        self.archive.get().is_some()
    }

    async fn fence(&self) -> Result<()> {
        if self.reader {
            self.lifecycle_fence().await?;
        } else {
            self.owner_fence().await?;
        }
        if let Some(archive) = self.archive.get() {
            archive.health().await?;
        }
        Ok(())
    }
    async fn owner_fence(&self) -> Result<()> {
        if self.reader {
            return Err(Error::unavailable("Reader storage cannot publish."));
        }
        self.lifecycle_fence().await?;
        // Reads and supervision must not wait behind a bulk publication on the owner
        // connection. Verify its exact live backend and advisory lock independently;
        // backend_start also prevents PID reuse from impersonating a lost owner.
        let owned:bool=sqlx_core::query_scalar::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE l.locktype='advisory' AND l.classid=1835365490 AND l.objid=1 AND l.objsubid=2 AND l.granted AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND a.pid=$1 AND EXTRACT(EPOCH FROM a.backend_start)::text=$2)")
            .bind(self.owner_pid).bind(&self.owner_started).fetch_one(&self.pool).await.map_err(|_|storage_error())?;
        if !owned {
            return Err(Error::unavailable(
                "Storage ownership lost; restart required",
            ));
        }
        Ok(())
    }
    async fn blob(&self, content_hash: &str) -> Result<Body> {
        if !valid_hash(content_hash) {
            return Err(Error::integrity("Invalid content hash"));
        }
        let path = self
            .root
            .join(crate::integrity::relative_path(content_hash)?);
        let selected = path.clone();
        let cache_lease = tokio::task::spawn_blocking(move || {
            crate::durable_archive::materialize_file(
                &selected,
                MAX_BLOB as u64,
                std::time::Instant::now() + std::time::Duration::from_secs(15),
                &tokio_util::sync::CancellationToken::new(),
            )
        })
        .await
        .map_err(|_| storage_error())??;
        let _cache_lease = cache_lease;
        let metadata = tokio::fs::symlink_metadata(&path)
            .await
            .map_err(|_| storage_error())?;
        if !metadata.is_file() {
            return Err(Error::integrity("Invalid stored blob"));
        }
        if metadata.len() > MAX_BLOB as u64 {
            return Err(Error::capacity(
                "Bulk binary capture requires typed bounded processing.",
            ));
        }
        // Charge in MiB, rounded up. The lease lives inside returned shared bytes,
        // not merely around this I/O future, so projections/clones stay bounded.
        let units = metadata.len().div_ceil(1024 * 1024).max(1) as u32;
        let lease = self
            .read_budget
            .clone()
            .try_acquire_many_owned(units)
            .map_err(|_| Error::capacity("Capture body memory budget exhausted"))?;
        let mut file = tokio::fs::File::open(path)
            .await
            .map_err(|_| storage_error())?;
        let mut body = vec![0; metadata.len() as usize];
        file.read_exact(&mut body)
            .await
            .map_err(|_| storage_error())?;
        let mut extra = [0_u8; 1];
        if file.read(&mut extra).await.map_err(|_| storage_error())? != 0
            || crate::integrity::verify(content_hash, &body).is_err()
        {
            return Err(Error::integrity("Stored blob checksum or length mismatch"));
        }
        if !content_hash.starts_with(crate::integrity::BLAKE3_PREFIX) {
            crate::integrity::verify_legacy_digest(
                &self.root.join(content_hash),
                &hash(&body),
                body.len() as u64,
            )?;
        }
        Ok(Body::with_lease(body, lease))
    }
    async fn verify_resident_publication(&self, content_hash: &str, bytes: u64) -> Result<()> {
        let path = self
            .root
            .join(crate::integrity::relative_path(content_hash)?);
        let expected = content_hash.to_owned();
        tokio::task::spawn_blocking(move || {
            let (digest, length) = crate::integrity::file_digest_local(
                &path,
                MAX_BLOB as u64,
                std::time::Instant::now() + std::time::Duration::from_secs(15),
                &tokio_util::sync::CancellationToken::new(),
            )?;
            if digest != expected || length != bytes {
                return Err(Error::integrity("Immutable publication bytes mismatch."));
            }
            Ok(())
        })
        .await
        .map_err(|_| storage_error())?
    }
    async fn write_blob(&self, content_hash: &str, body: &[u8]) -> Result<()> {
        self.owner_fence().await?;
        if !content_hash.starts_with(crate::integrity::BLAKE3_PREFIX) {
            return Err(Error::integrity("New immutable objects require BLAKE3."));
        }
        if body.len() > MAX_BLOB {
            return Err(Error::capacity("Blob size exceeds storage limit"));
        }
        crate::integrity::verify(content_hash, body)?;
        let final_path = self
            .root
            .join(crate::integrity::relative_path(content_hash)?);
        let selected = final_path.clone();
        let retained_lease = tokio::task::spawn_blocking(move || {
            crate::durable_archive::materialize_if_retained(
                &selected,
                MAX_BLOB as u64,
                std::time::Instant::now() + std::time::Duration::from_secs(15),
                &tokio_util::sync::CancellationToken::new(),
            )
        })
        .await
        .map_err(|_| storage_error())??;
        let _retained_lease = retained_lease;
        crate::durable_archive::admit_write(&final_path, 0)?;
        let parent = final_path.parent().ok_or_else(storage_error)?;
        crate::integrity::ensure_directory(parent).await?;
        let directory = self.root.clone();
        tokio::task::spawn_blocking(move || std::fs::File::open(directory)?.sync_all())
            .await
            .map_err(|_| storage_error())?
            .map_err(|_| storage_error())?;
        if tokio::fs::try_exists(&final_path)
            .await
            .map_err(|_| storage_error())?
        {
            self.verify_resident_publication(content_hash, body.len() as u64)
                .await?;
            let root = self.root.clone();
            let path = final_path.clone();
            let digest = content_hash.to_owned();
            let bytes = body.len() as u64;
            tokio::task::spawn_blocking(move || {
                crate::integrity::record_file(&root, &path, &digest, bytes)
            })
            .await
            .map_err(|_| storage_error())??;
            return Ok(());
        }
        let free = fs2::available_space(&self.root).map_err(|_| storage_error())?;
        if free < body.len() as u64 + 64 * 1024 * 1024 {
            return Err(Error::capacity(
                "Insufficient archive space; history is preserved",
            ));
        }
        let stage = self.root.join(format!(
            ".stage-{}-{}",
            std::process::id(),
            STAGE.fetch_add(1, Ordering::Relaxed)
        ));
        let mut reservation = self
            .artifact_budget
            .get()
            .map(|budget| budget.reserve_bytes(body.len() as u64))
            .transpose()?;
        let result = async {
            let owned_stage = stage.clone();
            let bytes = body.to_vec();
            let stage_guard = tokio::task::spawn_blocking(move || {
                use std::io::Write;
                let guard = StageGuard(owned_stage.clone());
                let mut file = std::fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&owned_stage)
                    .map_err(|_| storage_error())?;
                crate::durable_archive::with_write_budget(&owned_stage, bytes.len() as u64, || {
                    file.write_all(&bytes)
                })
                .map_err(|_| storage_error())?;
                file.sync_all().map_err(|_| storage_error())?;
                Ok::<_, Error>(guard)
            })
            .await
            .map_err(|_| storage_error())??;
            // hard_link atomically publishes without replacing an existing immutable object.
            let target = final_path.clone();
            let reservation = reservation.take();
            let published = tokio::task::spawn_blocking(move || {
                // Keep staging ownership and quota with the filesystem operation even if its await is canceled.
                let stage_guard = stage_guard;
                match std::fs::hard_link(&stage_guard.0, &target) {
                    Ok(()) => {
                        crate::durable_archive::observe_local(&target)?;
                        if let Some(reservation) = reservation {
                            reservation.retain_at(&target)?;
                        }
                        Ok(true)
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
                    Err(_) => Err(storage_error()),
                }
            })
            .await
            .map_err(|_| storage_error())??;
            if !published {
                self.verify_resident_publication(content_hash, body.len() as u64)
                    .await?;
            }
            let dir = final_path.parent().ok_or_else(storage_error)?.to_path_buf();
            tokio::task::spawn_blocking(move || std::fs::File::open(dir)?.sync_all())
                .await
                .map_err(|_| storage_error())?
                .map_err(|_| storage_error())?;
            let root = self.root.clone();
            let path = final_path.clone();
            let digest = content_hash.to_owned();
            let bytes = body.len() as u64;
            tokio::task::spawn_blocking(move || {
                crate::integrity::record_file(&root, &path, &digest, bytes)
            })
            .await
            .map_err(|_| storage_error())??;
            Ok(())
        }
        .await;
        let _ = tokio::fs::remove_file(stage).await;
        result
    }
    async fn load_row(&self, row: sqlx_postgres::PgRow, head: bool) -> Result<StoredCapture> {
        let capture = Capture {
            id: row.try_get("id").map_err(|_| storage_error())?,
            key: row.try_get("source_key").map_err(|_| storage_error())?,
            source_url: row.try_get("source_url").map_err(|_| storage_error())?,
            body_hash: row.try_get("body_hash").map_err(|_| storage_error())?,
            media_type: row.try_get("media_type").map_err(|_| storage_error())?,
            retrieved_at: row.try_get("retrieved_at").map_err(|_| storage_error())?,
            validated_at: row
                .try_get(if head {
                    "head_validated_at"
                } else {
                    "capture_validated_at"
                })
                .map_err(|_| storage_error())?,
        };
        let expected: String = row
            .try_get("metadata_integrity")
            .map_err(|_| Error::integrity("Capture integrity evidence missing."))?;
        if capture_metadata_digest(&capture)? != expected {
            return Err(Error::integrity("Capture metadata integrity failed."));
        }
        crate::integrity::verify(
            &capture.id,
            format!(
                "{}\0{}\0{}\0{}",
                capture.key, capture.source_url, capture.media_type, capture.body_hash
            )
            .as_bytes(),
        )?;
        if head {
            let proof: String = row
                .try_get("head_integrity")
                .map_err(|_| Error::integrity("Source head integrity missing."))?;
            let payload = serde_json::json!({"source_key":capture.key,"capture_id":capture.id,"validated_at":capture.validated_at,"etag":row.try_get::<Option<String>,_>("etag").map_err(|_|storage_error())?,"last_modified":row.try_get::<Option<String>,_>("last_modified").map_err(|_|storage_error())?});
            if events::event_digest("devres_heads", &capture.key, &payload)? != proof {
                return Err(Error::integrity("Source head integrity failed."));
            }
        }
        self.verify_effective_validation(&capture.id).await?;
        let body = self.blob(&capture.body_hash).await?;
        Ok(StoredCapture { capture, body })
    }
}
#[async_trait]
impl Store for PgBlobStore {
    async fn latest(&self, key: &str) -> Result<Option<Cached>> {
        self.fence().await?;
        let row = sqlx_core::query::query("SELECT c.*, h.validated_at AS head_validated_at, h.etag, h.last_modified,h.head_integrity FROM devres_heads h JOIN devres_captures c ON c.id=h.capture_id WHERE h.source_key=$1")
            .bind(key).fetch_optional(&self.pool).await.map_err(|_| storage_error())?;
        match row {
            None => Ok(None),
            Some(row) => {
                let validators = Validators {
                    etag: row.try_get("etag").map_err(|_| storage_error())?,
                    last_modified: row.try_get("last_modified").map_err(|_| storage_error())?,
                };
                Ok(Some(Cached {
                    stored: self.load_row(row, true).await?,
                    validators,
                }))
            }
        }
    }
    async fn capture(&self, id: &str) -> Result<StoredCapture> {
        self.fence().await?;
        if !valid_hash(id) {
            return Err(Error::invalid("Invalid capture identifier"));
        }
        let row = sqlx_core::query::query("SELECT c.*, GREATEST(COALESCE((SELECT MAX(o.validated_at) FROM devres_observations o WHERE o.capture_id=c.id OR o.capture_id IN (SELECT legacy FROM devres_content_aliases WHERE namespace='capture' AND canonical=c.id)),c.retrieved_at),COALESCE((SELECT MAX(o.observed_at) FROM devres_rfc_import_observations o WHERE o.capture_id=c.id OR o.capture_id IN (SELECT legacy FROM devres_content_aliases WHERE namespace='capture' AND canonical=c.id)),c.retrieved_at)) AS capture_validated_at FROM devres_captures c WHERE c.id=$1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| storage_error())?
            .ok_or_else(|| Error::not_found("Capture not found"))?;
        self.load_row(row, false).await
    }
    async fn publish(
        &self,
        request: &FetchRequest,
        response: FetchResponse,
        now: i64,
    ) -> Result<StoredCapture> {
        self.owner_fence().await?;
        self.fence().await?;
        if response.status != 200 || response.body.len() > request.max_bytes {
            return Err(Error::invalid(
                "Only successful bounded source bodies may be published",
            ));
        }
        let imported = corpus_storage::imported_source(&request.key, &request.url)?;
        let body_hash = hash(&response.body);
        let id = hash(
            format!(
                "{}\0{}\0{}\0{}",
                request.key, request.url, request.media_type, body_hash
            )
            .as_bytes(),
        );
        let metadata_digest = capture_metadata_digest(&Capture {
            id: id.clone(),
            key: request.key.clone(),
            source_url: request.url.clone(),
            body_hash: body_hash.clone(),
            media_type: request.media_type.clone(),
            retrieved_at: now,
            validated_at: now,
        })?;
        self.write_blob(&body_hash, &response.body).await?;
        let mut owner = self.owner.lock().await;
        owner.ping().await.map_err(|_| storage_error())?;
        // Publication uses the same connection that owns the serving fence.
        let mut tx = owner.begin().await.map_err(|_| storage_error())?;
        sqlx_core::query::query("INSERT INTO devres_captures (id,source_key,source_url,body_hash,media_type,retrieved_at,metadata_integrity) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(id) DO NOTHING")
            .bind(&id).bind(&request.key).bind(&request.url).bind(&body_hash).bind(&request.media_type).bind(now).bind(&metadata_digest).execute(&mut *tx).await.map_err(|_| storage_error())?;
        let head_payload = serde_json::json!({"source_key":request.key,"capture_id":id,"validated_at":now,"etag":response.validators.etag,"last_modified":response.validators.last_modified});
        let head_integrity = events::event_digest("devres_heads", &request.key, &head_payload)?;
        sqlx_core::query::query("INSERT INTO devres_heads (source_key,capture_id,validated_at,etag,last_modified,head_integrity) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT(source_key) DO UPDATE SET capture_id=EXCLUDED.capture_id,validated_at=EXCLUDED.validated_at,etag=EXCLUDED.etag,last_modified=EXCLUDED.last_modified,head_integrity=EXCLUDED.head_integrity")
            .bind(&request.key).bind(&id).bind(now).bind(&response.validators.etag).bind(&response.validators.last_modified).bind(head_integrity).execute(&mut *tx).await.map_err(|_| storage_error())?;
        if imported {
            events::append_import(&mut tx, &id, now, &request.url).await?;
        } else {
            events::append_http(&mut tx, &id, now, 200).await?;
        }
        tx.commit().await.map_err(|_| storage_error())?;
        drop(owner);
        let mut stored = self.capture(&id).await?;
        stored.capture.validated_at = now;
        Ok(stored)
    }
    async fn revalidate(
        &self,
        key: &str,
        id: &str,
        validators: Validators,
        now: i64,
    ) -> Result<StoredCapture> {
        self.owner_fence().await?;
        if key.starts_with("rfc:rsync:")
            || key.starts_with("cargo:git-index:")
            || key.starts_with("cargo:derived:")
        {
            return Err(Error::invalid(
                "Imported RFC captures cannot receive HTTP revalidation",
            ));
        }
        let mut owner = self.owner.lock().await;
        owner.ping().await.map_err(|_| storage_error())?;
        let mut tx = owner.begin().await.map_err(|_| storage_error())?;
        let prior=sqlx_core::query::query("SELECT source_key,capture_id,validated_at,etag,last_modified,head_integrity FROM devres_heads WHERE source_key=$1 AND capture_id=$2 FOR UPDATE")
            .bind(key).bind(id).fetch_optional(&mut *tx).await.map_err(|_|storage_error())?.ok_or_else(||Error::integrity("Source head changed during revalidation"))?;
        let prior_payload = serde_json::json!({"source_key":key,"capture_id":id,"validated_at":prior.try_get::<i64,_>("validated_at").map_err(|_|storage_error())?,"etag":prior.try_get::<Option<String>,_>("etag").map_err(|_|storage_error())?,"last_modified":prior.try_get::<Option<String>,_>("last_modified").map_err(|_|storage_error())?});
        let proof: String = prior
            .try_get("head_integrity")
            .map_err(|_| storage_error())?;
        if events::event_digest("devres_heads", key, &prior_payload)? != proof {
            return Err(Error::integrity("Source head integrity failed."));
        }
        let etag = validators
            .etag
            .or(prior.try_get("etag").map_err(|_| storage_error())?);
        let modified = validators.last_modified.or(prior
            .try_get("last_modified")
            .map_err(|_| storage_error())?);
        let payload = serde_json::json!({"source_key":key,"capture_id":id,"validated_at":now,"etag":etag,"last_modified":modified});
        let proof = events::event_digest("devres_heads", key, &payload)?;
        sqlx_core::query::query("UPDATE devres_heads SET validated_at=$3,etag=$4,last_modified=$5,head_integrity=$6 WHERE source_key=$1 AND capture_id=$2")
            .bind(key).bind(id).bind(now).bind(etag).bind(modified).bind(proof).execute(&mut *tx).await.map_err(|_|storage_error())?;
        events::append_http(&mut tx, id, now, 304).await?;
        tx.commit().await.map_err(|_| storage_error())?;
        drop(owner);
        let mut stored = self.capture(id).await?;
        stored.capture.validated_at = now;
        Ok(stored)
    }
}
const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS devres_schema (singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton), version integer NOT NULL);
INSERT INTO devres_schema VALUES(true,1) ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS devres_captures (
 id text PRIMARY KEY CHECK(length(id)=64), source_key text NOT NULL, source_url text NOT NULL,
 body_hash text NOT NULL CHECK(length(body_hash)=64), media_type text NOT NULL, retrieved_at bigint NOT NULL
);
CREATE TABLE IF NOT EXISTS devres_heads (
 source_key text PRIMARY KEY, capture_id text NOT NULL REFERENCES devres_captures(id), validated_at bigint NOT NULL,
 etag text, last_modified text
);
CREATE TABLE IF NOT EXISTS devres_observations (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, capture_id text NOT NULL REFERENCES devres_captures(id),
 validated_at bigint NOT NULL, status smallint NOT NULL CHECK(status IN (200,304))
);
CREATE INDEX IF NOT EXISTS devres_observation_capture ON devres_observations(capture_id);
"#;
