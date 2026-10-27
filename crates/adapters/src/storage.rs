//! PostgreSQL publication follows immutable, fsynced content-addressed blob writes.
use async_trait::async_trait;
use devres_application::{Cached, Store};
use devres_domain::{
    Body, Capture, Error, FetchRequest, FetchResponse, Result, StoredCapture, Validators,
};
use sha2::{Digest, Sha256};
use sqlx::{Connection, PgConnection, PgPool, Row, postgres::PgPoolOptions};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Mutex, Semaphore},
};

#[path = "rustsec/storage.rs"]
mod advisory_storage;
#[path = "chromium/storage.rs"]
mod chromium_storage;
#[path = "rfc/storage.rs"]
mod corpus_storage;
#[path = "crates_io/storage.rs"]
mod crate_storage;
#[path = "mdn/storage.rs"]
mod mdn_storage;
#[path = "npm/storage.rs"]
mod npm_storage;
#[path = "w3c/storage.rs"]
mod w3c_storage;
#[path = "whatwg/storage.rs"]
mod whatwg_storage;

const MAX_BLOB: usize = 128 * 1024 * 1024;
static STAGE: AtomicU64 = AtomicU64::new(0);
struct StageGuard(PathBuf);
impl Drop for StageGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
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
    pool: PgPool,
    root: PathBuf,
    read_budget: Arc<Semaphore>,
    // A dedicated non-reconnecting connection holds the single-server fence.
    owner: Mutex<PgConnection>,
    owner_pid: i32,
    owner_started: String,
    artifact_budget: std::sync::OnceLock<Arc<crate::bulk::BulkArtifactStore>>,
}
fn storage_error() -> Error {
    Error::unavailable("Durable storage unavailable")
}
fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
}

impl PgBlobStore {
    pub async fn connect(database_url: &str, root: impl AsRef<Path>) -> Result<Self> {
        let mut owner = PgConnection::connect(database_url)
            .await
            .map_err(|_| storage_error())?;
        let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock(1835365490, 1)")
            .fetch_one(&mut owner)
            .await
            .map_err(|_| storage_error())?;
        if !acquired {
            return Err(Error::capacity(
                "Only one serving instance may own this database",
            ));
        }
        let identity=sqlx::query("SELECT pid,EXTRACT(EPOCH FROM backend_start)::text AS started FROM pg_stat_activity WHERE pid=pg_backend_pid()")
            .fetch_one(&mut owner).await.map_err(|_|storage_error())?;
        let owner_pid = identity.try_get("pid").map_err(|_| storage_error())?;
        let owner_started = identity.try_get("started").map_err(|_| storage_error())?;
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect(database_url)
            .await
            .map_err(|_| storage_error())?;
        let mut tx = owner.begin().await.map_err(|_| storage_error())?;
        sqlx::raw_sql(SCHEMA)
            .execute(&mut *tx)
            .await
            .map_err(|_| storage_error())?;
        let version: i32 = sqlx::query_scalar("SELECT version FROM devres_schema WHERE singleton")
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| storage_error())?;
        if version == 1 {
            sqlx::raw_sql(corpus_storage::SCHEMA_V2)
                .execute(&mut *tx)
                .await
                .map_err(|_| storage_error())?;
            sqlx::query("UPDATE devres_schema SET version=2 WHERE singleton AND version=1")
                .execute(&mut *tx)
                .await
                .map_err(|_| storage_error())?;
        } else if !(2..=9).contains(&version) {
            return Err(Error::integrity("Unsupported storage schema version"));
        }
        if version <= 2 {
            sqlx::raw_sql(crate_storage::SCHEMA_V3)
                .execute(&mut *tx)
                .await
                .map_err(|_| storage_error())?;
            sqlx::query("UPDATE devres_schema SET version=3 WHERE singleton")
                .execute(&mut *tx)
                .await
                .map_err(|_| storage_error())?;
        }
        if version <= 3 {
            sqlx::raw_sql(advisory_storage::SCHEMA_V4)
                .execute(&mut *tx)
                .await
                .map_err(|_| storage_error())?;
            sqlx::query("UPDATE devres_schema SET version=4 WHERE singleton")
                .execute(&mut *tx)
                .await
                .map_err(|_| storage_error())?;
        }
        if version <= 4 {
            sqlx::raw_sql(mdn_storage::SCHEMA_V5)
                .execute(&mut *tx)
                .await
                .map_err(|_| storage_error())?;
            sqlx::query("UPDATE devres_schema SET version=5 WHERE singleton")
                .execute(&mut *tx)
                .await
                .map_err(|_| storage_error())?;
        }
        if version <= 5 {
            sqlx::raw_sql(whatwg_storage::SCHEMA_V6)
                .execute(&mut *tx)
                .await
                .map_err(|_| storage_error())?;
            sqlx::query("UPDATE devres_schema SET version=6 WHERE singleton")
                .execute(&mut *tx)
                .await
                .map_err(|_| storage_error())?;
        }
        if version <= 6 {
            sqlx::raw_sql(w3c_storage::SCHEMA_V7)
                .execute(&mut *tx)
                .await
                .map_err(|_| storage_error())?;
            sqlx::query("UPDATE devres_schema SET version=7 WHERE singleton")
                .execute(&mut *tx)
                .await
                .map_err(|_| storage_error())?;
        }
        if version <= 7 {
            sqlx::raw_sql(chromium_storage::SCHEMA_V8)
                .execute(&mut *tx)
                .await
                .map_err(|_| storage_error())?;
            sqlx::query("UPDATE devres_schema SET version=8 WHERE singleton")
                .execute(&mut *tx)
                .await
                .map_err(|_| storage_error())?;
        }
        if version <= 8 {
            sqlx::raw_sql(npm_storage::SCHEMA_V9)
                .execute(&mut *tx)
                .await
                .map_err(|_| storage_error())?;
            sqlx::query("UPDATE devres_schema SET version=9 WHERE singleton")
                .execute(&mut *tx)
                .await
                .map_err(|_| storage_error())?;
        }
        sqlx::query("UPDATE devres_rfc_jobs SET status='pending' WHERE status='running'")
            .execute(&mut *tx)
            .await
            .map_err(|_| storage_error())?;
        sqlx::query("UPDATE devres_crate_jobs SET state='pending' WHERE state='running'")
            .execute(&mut *tx)
            .await
            .map_err(|_| storage_error())?;
        tx.commit().await.map_err(|_| storage_error())?;
        tokio::fs::create_dir_all(root.as_ref())
            .await
            .map_err(|_| storage_error())?;
        let root = tokio::fs::canonicalize(root.as_ref())
            .await
            .map_err(|_| storage_error())?;
        // The exclusive database owner fence is held; no serving writer can own these stages.
        let mut entries = tokio::fs::read_dir(&root)
            .await
            .map_err(|_| storage_error())?;
        while let Some(entry) = entries.next_entry().await.map_err(|_| storage_error())? {
            if stage_name(&entry.file_name().to_string_lossy())
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
        Ok(Self {
            pool,
            root,
            read_budget: Arc::new(Semaphore::new(128)),
            owner: Mutex::new(owner),
            owner_pid,
            owner_started,
            artifact_budget: std::sync::OnceLock::new(),
        })
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

    async fn fence(&self) -> Result<()> {
        // Reads and supervision must not wait behind a bulk publication on the owner
        // connection. Verify its exact live backend and advisory lock independently;
        // backend_start also prevents PID reuse from impersonating a lost owner.
        let owned:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE l.locktype='advisory' AND l.classid=1835365490 AND l.objid=1 AND l.objsubid=2 AND l.granted AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND a.pid=$1 AND EXTRACT(EPOCH FROM a.backend_start)::text=$2)")
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
        let path = self.root.join(content_hash);
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
            || hash(&body) != content_hash
        {
            return Err(Error::integrity("Stored blob checksum or length mismatch"));
        }
        Ok(Body::with_lease(body, lease))
    }
    async fn write_blob(&self, content_hash: &str, body: &[u8]) -> Result<()> {
        if body.len() > MAX_BLOB {
            return Err(Error::capacity("Blob size exceeds storage limit"));
        }
        let final_path = self.root.join(content_hash);
        if tokio::fs::try_exists(&final_path)
            .await
            .map_err(|_| storage_error())?
        {
            self.blob(content_hash).await?;
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
            let mut file = tokio::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&stage)
                .await
                .map_err(|_| storage_error())?;
            let stage_guard = StageGuard(stage.clone());
            file.write_all(body).await.map_err(|_| storage_error())?;
            file.sync_all().await.map_err(|_| storage_error())?;
            drop(file);
            // hard_link atomically publishes without replacing an existing immutable object.
            let target = final_path.clone();
            let reservation = reservation.take();
            let published = tokio::task::spawn_blocking(move || {
                // Keep staging ownership and quota with the filesystem operation even if its await is canceled.
                let stage_guard = stage_guard;
                match std::fs::hard_link(&stage_guard.0, &target) {
                    Ok(()) => {
                        if let Some(reservation) = reservation {
                            reservation.retain();
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
                self.blob(content_hash).await?;
            }
            let dir = self.root.clone();
            tokio::task::spawn_blocking(move || std::fs::File::open(dir)?.sync_all())
                .await
                .map_err(|_| storage_error())?
                .map_err(|_| storage_error())?;
            Ok(())
        }
        .await;
        let _ = tokio::fs::remove_file(stage).await;
        result
    }
    async fn load_row(&self, row: sqlx::postgres::PgRow, head: bool) -> Result<StoredCapture> {
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
        let body = self.blob(&capture.body_hash).await?;
        Ok(StoredCapture { capture, body })
    }
}
#[async_trait]
impl Store for PgBlobStore {
    async fn latest(&self, key: &str) -> Result<Option<Cached>> {
        self.fence().await?;
        let row = sqlx::query("SELECT c.*, h.validated_at AS head_validated_at, h.etag, h.last_modified FROM devres_heads h JOIN devres_captures c ON c.id=h.capture_id WHERE h.source_key=$1")
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
        let row = sqlx::query("SELECT c.*, GREATEST(COALESCE((SELECT MAX(o.validated_at) FROM devres_observations o WHERE o.capture_id=c.id),c.retrieved_at),COALESCE((SELECT MAX(o.observed_at) FROM devres_rfc_import_observations o WHERE o.capture_id=c.id),c.retrieved_at)) AS capture_validated_at FROM devres_captures c WHERE c.id=$1")
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
        self.write_blob(&body_hash, &response.body).await?;
        let mut owner = self.owner.lock().await;
        owner.ping().await.map_err(|_| storage_error())?;
        // Publication uses the same connection that owns the serving fence.
        let mut tx = owner.begin().await.map_err(|_| storage_error())?;
        sqlx::query("INSERT INTO devres_captures (id,source_key,source_url,body_hash,media_type,retrieved_at) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT(id) DO NOTHING")
            .bind(&id).bind(&request.key).bind(&request.url).bind(&body_hash).bind(&request.media_type).bind(now).execute(&mut *tx).await.map_err(|_| storage_error())?;
        sqlx::query("INSERT INTO devres_heads (source_key,capture_id,validated_at,etag,last_modified) VALUES ($1,$2,$3,$4,$5) ON CONFLICT(source_key) DO UPDATE SET capture_id=EXCLUDED.capture_id,validated_at=EXCLUDED.validated_at,etag=EXCLUDED.etag,last_modified=EXCLUDED.last_modified")
            .bind(&request.key).bind(&id).bind(now).bind(&response.validators.etag).bind(&response.validators.last_modified).execute(&mut *tx).await.map_err(|_| storage_error())?;
        if imported {
            sqlx::query("INSERT INTO devres_rfc_import_observations(capture_id,observed_at,source_url) VALUES($1,$2,$3)")
                .bind(&id).bind(now).bind(&request.url).execute(&mut *tx).await.map_err(|_| storage_error())?;
        } else {
            sqlx::query("INSERT INTO devres_observations (capture_id,validated_at,status) VALUES ($1,$2,200)")
                .bind(&id).bind(now).execute(&mut *tx).await.map_err(|_| storage_error())?;
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
        let updated = sqlx::query("UPDATE devres_heads SET validated_at=$3,etag=COALESCE($4,etag),last_modified=COALESCE($5,last_modified) WHERE source_key=$1 AND capture_id=$2")
            .bind(key).bind(id).bind(now).bind(validators.etag).bind(validators.last_modified).execute(&mut *tx).await.map_err(|_| storage_error())?;
        if updated.rows_affected() != 1 {
            return Err(Error::integrity("Source head changed during revalidation"));
        }
        sqlx::query(
            "INSERT INTO devres_observations (capture_id,validated_at,status) VALUES ($1,$2,304)",
        )
        .bind(id)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|_| storage_error())?;
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
