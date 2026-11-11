//! Coordinated private S3 archive backup/restore. Never accepts package SQL.
//! Receipts publish last, and incomplete restores remain fenced from serving.
use crate::{
    PgBlobStore,
    object_storage::{S3Archive, S3Config},
};
use devres_domain::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx_core::{connection::Connection, row::Row};
use sqlx_postgres::PgConnection;
use std::{
    path::Path,
    process::Stdio,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio_util::sync::CancellationToken;

const RECEIPT_KEY: &str = "backup/receipt.json";
const DUMP_KEY: &str = "backup/database.dump";
const MANIFEST_KEY: &str = "backup/files.jsonl";
const RESERVE: u64 = 64 * 1024 * 1024;
const DEADLINE: Duration = Duration::from_secs(24 * 60 * 60);

fn unavailable() -> Error {
    Error::unavailable("Object archive backup or restore unavailable.")
}
fn integrity() -> Error {
    Error::integrity("Object archive backup verification failed.")
}
fn capacity() -> Error {
    Error::capacity("Object archive backup working set exceeds its capacity.")
}
fn stopping(cancel: &CancellationToken) -> Result<()> {
    if cancel.is_cancelled() {
        return Err(Error::new(
            "cancelled",
            "Object archive maintenance canceled.",
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileBinding {
    version: u32,
    path: String,
    digest: String,
    bytes: u64,
    device: u64,
    inode: u64,
}
impl FileBinding {
    fn decode(encoded: &str) -> Result<Self> {
        if encoded.len() > 16 * 1024 {
            return Err(integrity());
        }
        let binding: Self = serde_json::from_str(encoded).map_err(|_| integrity())?;
        if binding.version != 1
            || !binding.digest.starts_with("blake3:")
            || !crate::integrity::valid_hash(&binding.digest)
            || binding.path.is_empty()
            || binding.path.len() > 4096
            || binding
                .path
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            || binding.path.chars().any(|ch| ch.is_control() || ch == '\\')
            || !Path::new(&binding.path)
                .components()
                .all(|part| matches!(part, std::path::Component::Normal(_)))
        {
            return Err(integrity());
        }
        Ok(binding)
    }
    fn object(&self) -> Result<String> {
        Ok(format!(
            "objects/{}",
            crate::integrity::relative_path(&self.digest)?.to_string_lossy()
        ))
    }
    fn descriptor(&self) -> String {
        format!(
            "bindings/{}.json",
            blake3::hash(self.path.as_bytes()).to_hex()
        )
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetainedFile {
    key: String,
    digest: String,
    bytes: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupReceipt {
    version: u32,
    kind: String,
    schema: i32,
    store_id: String,
    source_binding: String,
    destination_binding: String,
    files: u64,
    database: RetainedFile,
    manifest: RetainedFile,
    claim_digest: String,
}
impl BackupReceipt {
    fn validate(&self) -> Result<()> {
        if self.version != 1
            || self.kind != "devres-object-archive-backup"
            || !matches!(self.schema, 12..=14)
            || self.store_id.is_empty()
            || self.store_id.len() > 128
            || self.store_id.chars().any(char::is_control)
            || self.database.key != DUMP_KEY
            || self.manifest.key != MANIFEST_KEY
            || [
                &self.source_binding,
                &self.destination_binding,
                &self.database.digest,
                &self.manifest.digest,
                &self.claim_digest,
            ]
            .iter()
            .any(|digest| !digest.starts_with("blake3:") || !crate::integrity::valid_hash(digest))
        {
            return Err(integrity());
        }
        Ok(())
    }
}

fn binding(config: &S3Config) -> Result<String> {
    crate::integrity::canonical_hash(
        &json!({"version":1,"endpoint":config.endpoint,"bucket":config.bucket,"region":config.region,"prefix":config.prefix,"path_style":config.path_style}),
    )
}

fn scratch(limit: u64) -> Result<tempfile::TempDir> {
    if limit < RESERVE {
        return Err(capacity());
    }
    let temporary = tempfile::Builder::new()
        .prefix("devres-object-backup-")
        .tempdir_in("/tmp")
        .map_err(|_| unavailable())?;
    headroom(temporary.path(), 0, limit)?;
    Ok(temporary)
}
fn headroom(root: &Path, needed: u64, available_budget: u64) -> Result<()> {
    if needed > available_budget
        || fs2::available_space(root).map_err(|_| unavailable())? < needed.saturating_add(RESERVE)
    {
        return Err(capacity());
    }
    Ok(())
}
async fn digest(path: &Path, max: u64, cancel: &CancellationToken) -> Result<(String, u64)> {
    let path = path.to_owned();
    let cancel = cancel.clone();
    tokio::task::spawn_blocking(move || {
        crate::integrity::file_digest_local(&path, max, Instant::now() + DEADLINE, &cancel)
    })
    .await
    .map_err(|_| unavailable())?
}

/// libpq does not expand a URI taken from PGDATABASE. Resolve the same SQLx
/// options as the owner connection and pass individual runtime-only variables.
/// Do not derive Debug: the values include the operator's database password.
struct DatabaseEnvironment(Vec<(String, String)>);
impl DatabaseEnvironment {
    fn new(database_url: &str) -> Result<Self> {
        let original = url::Url::parse(database_url).map_err(|_| unavailable())?;
        let options: sqlx_postgres::PgConnectOptions =
            database_url.parse().map_err(|_| unavailable())?;
        let host = match options.get_socket() {
            Some(socket) => socket.to_str().ok_or_else(unavailable)?.to_owned(),
            None => options
                .get_host()
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_owned(),
        };
        let mode = match options.get_ssl_mode() {
            sqlx_postgres::PgSslMode::Disable => "disable",
            sqlx_postgres::PgSslMode::Allow => "allow",
            sqlx_postgres::PgSslMode::Prefer => "prefer",
            sqlx_postgres::PgSslMode::Require => "require",
            sqlx_postgres::PgSslMode::VerifyCa => "verify-ca",
            sqlx_postgres::PgSslMode::VerifyFull => "verify-full",
        };
        let mut values = vec![
            ("PGHOST".into(), host),
            ("PGPORT".into(), options.get_port().to_string()),
            ("PGUSER".into(), options.get_username().to_owned()),
            (
                "PGDATABASE".into(),
                options
                    .get_database()
                    .unwrap_or(options.get_username())
                    .to_owned(),
            ),
            ("PGSSLMODE".into(), mode.into()),
            // Match SQLx's TLS transport. libpq's GSS preference can otherwise
            // select a different encrypted path and bypass TLS CA validation.
            ("PGGSSENCMODE".into(), "disable".into()),
            ("PGCONNECT_TIMEOUT".into(), "10".into()),
            (
                "PGAPPNAME".into(),
                options
                    .get_application_name()
                    .unwrap_or("devres-object-archive-maintenance")
                    .to_owned(),
            ),
        ];
        // SQLx uses these defaults before applying URL parameters; resolve them
        // once, then clear all unrelated ambient libpq variables for the child.
        for key in [
            "PGPASSWORD",
            "PGPASSFILE",
            "PGSSLROOTCERT",
            "PGSSLCERT",
            "PGSSLKEY",
        ] {
            if let Ok(value) = std::env::var(key) {
                values.push((key.into(), value));
            }
        }
        if let Some(password) = original.password() {
            let value = percent_encoding::percent_decode_str(password)
                .decode_utf8()
                .map_err(|_| unavailable())?;
            values.push(("PGPASSWORD".into(), value.into_owned()));
        }
        for (key, value) in original.query_pairs() {
            let variable = match key.as_ref() {
                "password" => "PGPASSWORD",
                "sslrootcert" | "ssl-root-cert" | "ssl-ca" => "PGSSLROOTCERT",
                "sslcert" | "ssl-cert" => "PGSSLCERT",
                "sslkey" | "ssl-key" => "PGSSLKEY",
                _ => continue,
            };
            values.push((variable.into(), value.into_owned()));
        }
        if matches!(
            options.get_ssl_mode(),
            sqlx_postgres::PgSslMode::VerifyCa | sqlx_postgres::PgSslMode::VerifyFull
        ) && !values.iter().any(|(key, _)| key == "PGSSLROOTCERT")
        {
            let root = std::env::var_os("SSL_CERT_FILE")
                .map(std::path::PathBuf::from)
                .or_else(|| {
                    ["/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/cert.pem"]
                        .into_iter()
                        .map(std::path::PathBuf::from)
                        .find(|path| path.is_file())
                })
                .ok_or_else(unavailable)?;
            values.push((
                "PGSSLROOTCERT".into(),
                root.to_str().ok_or_else(unavailable)?.to_owned(),
            ));
        }
        if let Some(value) = options.get_options() {
            values.push(("PGOPTIONS".into(), value.to_owned()));
        }
        if values.iter().any(|(_, value)| value.contains('\0')) {
            return Err(unavailable());
        }
        Ok(Self(values))
    }
    fn apply(&self, command: &mut tokio::process::Command) {
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("PG") {
                command.env_remove(key);
            }
        }
        command.envs(self.0.iter().map(|(key, value)| (key, value)));
    }
}

async fn dump_database(
    database_url: &str,
    target: &Path,
    max_bytes: u64,
    cancel: &CancellationToken,
) -> Result<()> {
    let environment = DatabaseEnvironment::new(database_url)?;
    let mut command = tokio::process::Command::new("pg_dump");
    environment.apply(&mut command);
    let mut child = command
        .args(["--format=custom", "--no-owner", "--no-acl"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| unavailable())?;
    let mut stdout = child.stdout.take().ok_or_else(unavailable)?;
    let mut file = tokio::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(target)
        .await
        .map_err(|_| unavailable())?;
    let operation = async {
        let mut bytes = 0_u64;
        let mut buffer = vec![0_u8; 65536];
        loop {
            stopping(cancel)?;
            let n = stdout.read(&mut buffer).await.map_err(|_| unavailable())?;
            if n == 0 {
                break;
            }
            bytes = bytes
                .checked_add(n as u64)
                .filter(|v| *v <= max_bytes)
                .ok_or_else(capacity)?;
            headroom(
                target.parent().ok_or_else(unavailable)?,
                n as u64,
                max_bytes,
            )?;
            file.write_all(&buffer[..n])
                .await
                .map_err(|_| unavailable())?;
        }
        file.sync_all().await.map_err(|_| unavailable())?;
        if !child.wait().await.map_err(|_| unavailable())?.success() {
            return Err(unavailable());
        }
        Ok(())
    };
    tokio::select! {
        biased;
        _=cancel.cancelled()=>Err(Error::new("cancelled","Object archive maintenance canceled.")),
        result=tokio::time::timeout(DEADLINE,operation)=>result.map_err(|_|capacity())?,
    }
}

async fn restore_database(
    database_url: &str,
    dump: &Path,
    cancel: &CancellationToken,
) -> Result<()> {
    // The empty explicit connection string selects the individually resolved
    // environment variables. Without --dbname pg_restore emits SQL instead.
    let environment = DatabaseEnvironment::new(database_url)?;
    let mut command = tokio::process::Command::new("pg_restore");
    environment.apply(&mut command);
    let mut child = command
        .args([
            "--dbname=",
            "--single-transaction",
            "--exit-on-error",
            "--no-owner",
            "--no-acl",
        ])
        .arg(dump)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| unavailable())?;
    let status = tokio::select! {
        biased;
        _=cancel.cancelled()=>return Err(Error::new("cancelled","Object archive maintenance canceled.")),
        result=tokio::time::timeout(DEADLINE,child.wait())=>result.map_err(|_|capacity())?.map_err(|_|unavailable())?,
    };
    if !status.success() {
        return Err(unavailable());
    }
    Ok(())
}

async fn copy_file(
    source: &S3Archive,
    target: &S3Archive,
    file: &FileBinding,
    scratch: &Path,
    max_bytes: u64,
    cancel: &CancellationToken,
) -> Result<()> {
    stopping(cancel)?;
    let key = file.object()?;
    if target.head(&key).await?.is_some() {
        target
            .verify_object(&key, &file.digest, file.bytes, cancel)
            .await?;
    } else {
        headroom(scratch, file.bytes, max_bytes)?;
        let path = scratch.join("object.stage");
        let (digest, bytes) = source.get_to_file(&key, &path, file.bytes, cancel).await?;
        let outcome = async {
            if digest != file.digest || bytes != file.bytes {
                return Err(integrity());
            }
            target
                .put_file_immutable(&key, &path, &file.digest, file.bytes, cancel)
                .await
        }
        .await;
        tokio::fs::remove_file(&path)
            .await
            .map_err(|_| unavailable())?;
        outcome?;
    }
    Ok(())
}

/// Stop writers and copy a complete S3 corpus plus PostgreSQL into a fresh prefix.
pub async fn backup(
    database_url: &str,
    root: &Path,
    source: S3Config,
    destination: S3Config,
    cancel: CancellationToken,
) -> Result<Value> {
    let source_binding = binding(&source)?;
    let destination_binding = binding(&destination)?;
    if source_binding == destination_binding {
        return Err(Error::invalid("Backup requires a distinct object prefix."));
    }
    let limit = source.cache_max_bytes.min(destination.cache_max_bytes);
    let temporary = scratch(limit)?;
    let store = Arc::new(
        PgBlobStore::connect_for_object_transfer(database_url, root, source.clone()).await?,
    );
    let active: String = sqlx_core::query_scalar::query_scalar(
        "SELECT backend FROM devres_archive_control WHERE singleton",
    )
    .fetch_one(&store.pool)
    .await
    .map_err(|_| unavailable())?;
    if active != "s3" {
        return Err(Error::invalid("Backup requires an activated S3 archive."));
    }
    store
        .transfer_object_archive("verify-object-storage", cancel.clone())
        .await?;
    let source = S3Archive::new(source).await?;
    let target = S3Archive::new(destination).await?;
    if !target.prefix_is_empty().await? {
        return Err(Error::invalid(
            "Backup requires an empty destination prefix.",
        ));
    }
    let store_id: String = sqlx_core::query_scalar::query_scalar(
        "SELECT store_id FROM devres_archive_control WHERE singleton",
    )
    .fetch_one(&store.pool)
    .await
    .map_err(|_| unavailable())?;
    let claim = source
        .get_bytes_with_cancel("store.json", 16 * 1024, &cancel)
        .await?;
    if serde_json::from_slice::<Value>(&claim).map_err(|_| integrity())?
        != json!({"version":1,"store_id":store_id})
    {
        return Err(integrity());
    }
    target
        .put_bytes_immutable_with_cancel("store.json", &claim, &cancel)
        .await?;
    let dump = temporary.path().join("database.dump");
    dump_database(database_url, &dump, limit, &cancel).await?;
    let (dump_digest, dump_bytes) = digest(&dump, limit, &cancel).await?;
    target
        .put_file_immutable(DUMP_KEY, &dump, &dump_digest, dump_bytes, &cancel)
        .await?;
    let manifest = temporary.path().join("files.jsonl");
    let mut output = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&manifest)
        .await
        .map_err(|_| unavailable())?;
    let mut after = String::new();
    let mut count = 0_u64;
    let mut manifest_bytes = 0_u64;
    loop {
        stopping(&cancel)?;
        let row:Option<(String,String)>=sqlx_core::query_as::query_as(r#"SELECT path,evidence FROM devres_archive_file WHERE complete AND path COLLATE "C">$1 COLLATE "C" ORDER BY path COLLATE "C" LIMIT 1"#).bind(&after).fetch_optional(&store.pool).await.map_err(|_|unavailable())?;
        let Some((path, encoded)) = row else {
            break;
        };
        let file = FileBinding::decode(&encoded)?;
        if file.path != path {
            return Err(integrity());
        }
        if source
            .get_bytes_with_cancel(&file.descriptor(), 16 * 1024, &cancel)
            .await?
            != encoded.as_bytes()
        {
            return Err(integrity());
        }
        let remaining = limit
            .checked_sub(dump_bytes)
            .and_then(|v| v.checked_sub(manifest_bytes))
            .ok_or_else(capacity)?;
        copy_file(
            &source,
            &target,
            &file,
            temporary.path(),
            remaining,
            &cancel,
        )
        .await?;
        target
            .put_bytes_immutable_with_cancel(&file.descriptor(), encoded.as_bytes(), &cancel)
            .await?;
        manifest_bytes = manifest_bytes
            .checked_add(encoded.len() as u64 + 1)
            .filter(|v| v.saturating_add(dump_bytes) <= limit)
            .ok_or_else(capacity)?;
        output
            .write_all(encoded.as_bytes())
            .await
            .map_err(|_| unavailable())?;
        output.write_all(b"\n").await.map_err(|_| unavailable())?;
        count = count.checked_add(1).ok_or_else(capacity)?;
        after = path;
    }
    output.sync_all().await.map_err(|_| unavailable())?;
    drop(output);
    let (manifest_digest, manifest_bytes) =
        digest(&manifest, limit.saturating_sub(dump_bytes), &cancel).await?;
    target
        .put_file_immutable(
            MANIFEST_KEY,
            &manifest,
            &manifest_digest,
            manifest_bytes,
            &cancel,
        )
        .await?;
    let schema: i32 =
        sqlx_core::query_scalar::query_scalar("SELECT version FROM devres_schema WHERE singleton")
            .fetch_one(&store.pool)
            .await
            .map_err(|_| unavailable())?;
    let receipt = BackupReceipt {
        version: 1,
        kind: "devres-object-archive-backup".into(),
        schema,
        store_id,
        source_binding,
        destination_binding,
        files: count,
        database: RetainedFile {
            key: DUMP_KEY.into(),
            digest: dump_digest,
            bytes: dump_bytes,
        },
        manifest: RetainedFile {
            key: MANIFEST_KEY.into(),
            digest: manifest_digest,
            bytes: manifest_bytes,
        },
        claim_digest: crate::integrity::hash(&claim),
    };
    receipt.validate()?;
    let encoded = serde_json::to_vec(&receipt).map_err(|_| integrity())?;
    // The held store still fences writers. Check ownership immediately before the
    // receipt that makes this backup usable by restore.
    store.check_health().await?;
    stopping(&cancel)?;
    target
        .put_bytes_immutable_with_cancel(RECEIPT_KEY, &encoded, &cancel)
        .await?;
    Ok(
        json!({"version":1,"action":"backup-object-storage","files":count,"receipt":crate::integrity::hash(&encoded),"verified":true}),
    )
}

/// Restore only into an empty database and fresh prefix. Failure leaves a marker
/// that prevents all ordinary serving and maintenance startup.
pub async fn restore(
    database_url: &str,
    root: &Path,
    destination: S3Config,
    backup: S3Config,
    cancel: CancellationToken,
) -> Result<Value> {
    if !root.is_absolute() {
        return Err(Error::invalid(
            "Restore requires an absolute empty local cache directory.",
        ));
    }
    match std::fs::symlink_metadata(root) {
        Ok(metadata) => {
            if !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || std::fs::read_dir(root)
                    .map_err(|_| unavailable())?
                    .next()
                    .is_some()
            {
                return Err(Error::invalid(
                    "Restore requires an empty local cache directory.",
                ));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(_) => return Err(unavailable()),
    }
    let target_binding = binding(&destination)?;
    let backup_binding = binding(&backup)?;
    if target_binding == backup_binding {
        return Err(Error::invalid("Restore requires a distinct object prefix."));
    }
    let limit = destination.cache_max_bytes.min(backup.cache_max_bytes);
    let temporary = scratch(limit)?;
    let source = S3Archive::new(backup).await?;
    let target = S3Archive::new(destination.clone()).await?;
    let encoded = source
        .get_bytes_with_cancel(RECEIPT_KEY, 64 * 1024, &cancel)
        .await?;
    let receipt: BackupReceipt = serde_json::from_slice(&encoded).map_err(|_| integrity())?;
    receipt.validate()?;
    if receipt.destination_binding != backup_binding || receipt.source_binding == target_binding {
        return Err(Error::invalid(
            "Restore requires a fresh archive destination.",
        ));
    }
    let claim = source
        .get_bytes_with_cancel("store.json", 16 * 1024, &cancel)
        .await?;
    if crate::integrity::hash(&claim) != receipt.claim_digest
        || serde_json::from_slice::<Value>(&claim).map_err(|_| integrity())?
            != json!({"version":1,"store_id":receipt.store_id})
    {
        return Err(integrity());
    }
    let working = receipt
        .database
        .bytes
        .checked_add(receipt.manifest.bytes)
        .filter(|v| *v <= limit)
        .ok_or_else(capacity)?;
    headroom(temporary.path(), working, limit)?;
    let dump = temporary.path().join("database.dump");
    let manifest = temporary.path().join("files.jsonl");
    for (file, path) in [(&receipt.database, &dump), (&receipt.manifest, &manifest)] {
        let (digest, bytes) = source
            .get_to_file(&file.key, path, file.bytes, &cancel)
            .await?;
        if digest != file.digest || bytes != file.bytes {
            return Err(integrity());
        }
    }
    let mut owner = PgConnection::connect(database_url)
        .await
        .map_err(|_| unavailable())?;
    let lifecycle: bool =
        sqlx_core::query_scalar::query_scalar("SELECT pg_try_advisory_lock(1835365490,2)")
            .fetch_one(&mut owner)
            .await
            .map_err(|_| unavailable())?;
    if !lifecycle {
        return Err(Error::capacity(
            "Restore requires all readers and writers to stop.",
        ));
    }
    let acquired: bool =
        sqlx_core::query_scalar::query_scalar("SELECT pg_try_advisory_lock(1835365490,1)")
            .fetch_one(&mut owner)
            .await
            .map_err(|_| unavailable())?;
    if !acquired {
        return Err(Error::capacity(
            "Only one serving instance may own this database",
        ));
    }
    let present:i64=sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p','m','v','S')").fetch_one(&mut owner).await.map_err(|_|unavailable())?;
    if present != 0 {
        return Err(Error::invalid(
            "Restore requires an empty PostgreSQL database.",
        ));
    }
    if !target.prefix_is_empty().await? {
        return Err(Error::invalid(
            "Restore requires an empty destination prefix.",
        ));
    }
    sqlx_core::query::query("CREATE TABLE devres_archive_restore_pending(receipt text NOT NULL,destination text NOT NULL)").execute(&mut owner).await.map_err(|_|unavailable())?;
    sqlx_core::query::query(
        "INSERT INTO devres_archive_restore_pending(receipt,destination) VALUES($1,$2)",
    )
    .bind(crate::integrity::hash(&encoded))
    .bind(&target_binding)
    .execute(&mut owner)
    .await
    .map_err(|_| unavailable())?;
    target
        .put_bytes_immutable_with_cancel("store.json", &claim, &cancel)
        .await?;
    let mut count = 0_u64;
    let mut after = String::new();
    let mut reader = BufReader::new(
        tokio::fs::File::open(&manifest)
            .await
            .map_err(|_| unavailable())?,
    );
    while let Some(line) = bounded_line(&mut reader).await? {
        let file = FileBinding::decode(&line)?;
        if file.path <= after {
            return Err(Error::integrity(
                "Object archive backup inventory ordering is invalid.",
            ));
        }
        if source
            .get_bytes_with_cancel(&file.descriptor(), 16 * 1024, &cancel)
            .await?
            != line.as_bytes()
        {
            return Err(integrity());
        }
        copy_file(
            &source,
            &target,
            &file,
            temporary.path(),
            limit - working,
            &cancel,
        )
        .await?;
        target
            .put_bytes_immutable_with_cancel(&file.descriptor(), line.as_bytes(), &cancel)
            .await?;
        count = count
            .checked_add(1)
            .filter(|v| *v <= receipt.files)
            .ok_or_else(integrity)?;
        after = file.path;
    }
    if count != receipt.files {
        return Err(integrity());
    }
    restore_database(database_url, &dump, &cancel).await?;
    let control = sqlx_core::query::query(
        "SELECT store_id,binding,epoch FROM devres_archive_control WHERE singleton",
    )
    .fetch_one(&mut owner)
    .await
    .map_err(|_| unavailable())?;
    let store_id: String = control.try_get("store_id").map_err(|_| integrity())?;
    let old_binding: Option<String> = control.try_get("binding").map_err(|_| integrity())?;
    let epoch: i64 = control
        .try_get::<i64, _>("epoch")
        .map_err(|_| integrity())?
        .checked_add(1)
        .ok_or_else(integrity)?;
    if store_id != receipt.store_id || old_binding.as_deref() != Some(&receipt.source_binding) {
        return Err(integrity());
    }
    let mut tx = owner.begin().await.map_err(|_| unavailable())?;
    // This restored target does not own the original host's retained filesystem
    // source. Preserve its migration receipt while releasing that local-path
    // reservation for a fresh empty cache on the restore host.
    sqlx_core::query::query("ALTER TABLE devres_archive_transfer ADD COLUMN IF NOT EXISTS source_protected boolean NOT NULL DEFAULT true").execute(&mut *tx).await.map_err(|_|unavailable())?;
    sqlx_core::query::query("UPDATE devres_archive_transfer SET source_protected=false")
        .execute(&mut *tx)
        .await
        .map_err(|_| unavailable())?;
    sqlx_core::query::query("UPDATE devres_archive_control SET backend='s3',binding=$1,pending_binding=NULL,epoch=$2 WHERE singleton").bind(&target_binding).bind(epoch).execute(&mut *tx).await.map_err(|_|unavailable())?;
    sqlx_core::query::query("UPDATE devres_archive_file SET epoch=$1")
        .bind(epoch)
        .execute(&mut *tx)
        .await
        .map_err(|_| unavailable())?;
    tx.commit().await.map_err(|_| unavailable())?;
    // The marker blocks ordinary startup while the verifier takes the owner fence.
    owner.close().await.map_err(|_| unavailable())?;
    let store = Arc::new(
        PgBlobStore::connect_for_restore_verification(database_url, root, destination).await?,
    );
    verify_manifest_database(&store, &manifest, receipt.files, &cancel).await?;
    // The transfer verifier checks remote closure first and then the complete
    // PostgreSQL/corpus graph, including cold-cache materialization.
    store
        .transfer_object_archive("verify-object-storage", cancel.clone())
        .await?;
    stopping(&cancel)?;
    store.check_health().await?;
    let mut owner = store.owner.lock().await;
    sqlx_core::query::query("DROP TABLE devres_archive_restore_pending")
        .execute(&mut *owner)
        .await
        .map_err(|_| unavailable())?;
    Ok(
        json!({"version":1,"action":"restore-object-storage","files":count,"receipt":crate::integrity::hash(&encoded),"verified":true}),
    )
}

async fn verify_manifest_database(
    store: &PgBlobStore,
    path: &Path,
    expected: u64,
    cancel: &CancellationToken,
) -> Result<()> {
    let total: i64 =
        sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM devres_archive_file")
            .fetch_one(&store.pool)
            .await
            .map_err(|_| unavailable())?;
    if u64::try_from(total).ok() != Some(expected) {
        return Err(integrity());
    }
    let mut reader = BufReader::new(
        tokio::fs::File::open(path)
            .await
            .map_err(|_| unavailable())?,
    );
    while let Some(line) = bounded_line(&mut reader).await? {
        stopping(cancel)?;
        let file = FileBinding::decode(&line)?;
        let matches:bool=sqlx_core::query_scalar::query_scalar("SELECT EXISTS(SELECT 1 FROM devres_archive_file WHERE path=$1 AND evidence=$2 AND digest=$3 AND bytes=$4 AND device=$5 AND inode=$6 AND complete)").bind(&file.path).bind(&line).bind(&file.digest).bind(i64::try_from(file.bytes).map_err(|_|integrity())?).bind(file.device.to_string()).bind(file.inode.to_string()).fetch_one(&store.pool).await.map_err(|_|unavailable())?;
        if !matches {
            return Err(integrity());
        }
    }
    Ok(())
}

async fn bounded_line(reader: &mut BufReader<tokio::fs::File>) -> Result<Option<String>> {
    let mut bytes = Vec::new();
    let read = reader
        .take(16 * 1024 + 1)
        .read_until(b'\n', &mut bytes)
        .await
        .map_err(|_| unavailable())?;
    if read == 0 {
        return Ok(None);
    }
    if bytes.len() > 16 * 1024 || bytes.pop() != Some(b'\n') {
        return Err(integrity());
    }
    String::from_utf8(bytes).map(Some).map_err(|_| integrity())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn libpq_environment_preserves_credentials_tls_and_operator_query_overrides() {
        let environment=DatabaseEnvironment::new("postgres://u%40ser:p%2Bass%3Aword@db.example:5544/a%20database?ssl-mode=verify-full&ssl-root-cert=%2Ftmp%2Ffixture-ca.pem&ssl-cert=%2Ftmp%2Ffixture-cert.pem&ssl-key=%2Ftmp%2Ffixture-key.pem&options[search_path]=public").unwrap();
        let values: std::collections::BTreeMap<_, _> = environment.0.into_iter().collect();
        assert_eq!(values["PGHOST"], "db.example");
        assert_eq!(values["PGPORT"], "5544");
        assert_eq!(values["PGUSER"], "u@ser");
        assert_eq!(values["PGPASSWORD"], "p+ass:word");
        assert_eq!(values["PGDATABASE"], "a database");
        assert_eq!(values["PGSSLMODE"], "verify-full");
        assert_eq!(values["PGGSSENCMODE"], "disable");
        assert_eq!(values["PGSSLROOTCERT"], "/tmp/fixture-ca.pem");
        assert_eq!(values["PGSSLCERT"], "/tmp/fixture-cert.pem");
        assert_eq!(values["PGSSLKEY"], "/tmp/fixture-key.pem");
        assert!(values["PGOPTIONS"].contains("search_path=public"));
        let environment=DatabaseEnvironment::new("postgres://before:old@db.example/before?user=after&password=a%2Bb&dbname=after&host=%2Ftmp%2Ffixture-postgres&port=5545").unwrap();
        let values: std::collections::BTreeMap<_, _> = environment.0.into_iter().collect();
        assert_eq!(values["PGHOST"], "/tmp/fixture-postgres");
        assert_eq!(values["PGPORT"], "5545");
        assert_eq!(values["PGUSER"], "after");
        assert_eq!(values["PGPASSWORD"], "a+b");
        assert_eq!(values["PGDATABASE"], "after");
    }
    #[test]
    fn backup_manifest_rejects_unqualified_and_escaping_bindings() {
        let digest = crate::integrity::hash(b"body");
        let valid = json!({"version":1,"path":"blake3/file","digest":digest,"bytes":4,"device":1,"inode":2});
        assert!(FileBinding::decode(&valid.to_string()).is_ok());
        for path in ["../escape", "/absolute", "a/../../b", "a\\b", "a\nb"] {
            let mut invalid = valid.clone();
            invalid["path"] = json!(path);
            assert!(FileBinding::decode(&invalid.to_string()).is_err());
        }
        let mut invalid = valid;
        invalid["digest"] = json!("0123456789");
        assert!(FileBinding::decode(&invalid.to_string()).is_err());
    }
    #[tokio::test]
    async fn inventory_lines_are_bounded_and_require_complete_records() {
        let temp = tempfile::tempdir_in("/tmp").unwrap();
        let path = temp.path().join("manifest");
        for bytes in [vec![b'x'; 16 * 1024 + 1], b"incomplete".to_vec()] {
            std::fs::write(&path, bytes).unwrap();
            let mut reader = BufReader::new(tokio::fs::File::open(&path).await.unwrap());
            assert!(bounded_line(&mut reader).await.is_err());
        }
        std::fs::write(&path, b"first\nsecond\n").unwrap();
        let mut reader = BufReader::new(tokio::fs::File::open(&path).await.unwrap());
        assert_eq!(
            bounded_line(&mut reader).await.unwrap().as_deref(),
            Some("first")
        );
        assert_eq!(
            bounded_line(&mut reader).await.unwrap().as_deref(),
            Some("second")
        );
        assert!(bounded_line(&mut reader).await.unwrap().is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires disposable PostgreSQL and RustFS; run scripts/test-s3.sh"]
    async fn s3_backup_restore_preserves_capture_identity_in_fresh_database_and_cache() {
        use devres_application::Store;
        use devres_domain::{FetchRequest, FetchResponse, Validators};
        let base = std::env::var("DEVRES_TEST_DATABASE_URL").expect("disposable database required");
        let configured =
            std::env::var("DEVRES_TEST_S3_CONFIG").expect("disposable S3 config required");
        let original: S3Config =
            toml::from_str(&std::fs::read_to_string(configured).unwrap()).unwrap();
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut source = original.clone();
        source.prefix = format!("{}/backup-source-{suffix}", original.prefix);
        let mut saved = original.clone();
        saved.prefix = format!("{}/backup-saved-{suffix}", original.prefix);
        let mut destination = original;
        destination.prefix = format!("{}/backup-restored-{suffix}", destination.prefix);
        let admin = sqlx_postgres::PgPool::connect(&base).await.unwrap();
        sqlx_core::query::query("CREATE DATABASE devres_s3_backup_source")
            .execute(&admin)
            .await
            .unwrap();
        sqlx_core::query::query("CREATE DATABASE devres_s3_backup_restored")
            .execute(&admin)
            .await
            .unwrap();
        let mut source_url = url::Url::parse(&base).unwrap();
        source_url.set_path("/devres_s3_backup_source");
        let mut destination_url = url::Url::parse(&base).unwrap();
        destination_url.set_path("/devres_s3_backup_restored");
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let store = PgBlobStore::connect(source_url.as_str(), root.path())
            .await
            .unwrap();
        let request = FetchRequest {
            key: "fixture:backup".into(),
            url: "https://fixtures.invalid/backup".into(),
            ttl_secs: 3600,
            max_bytes: 128,
            media_type: "text/plain".into(),
        };
        let captured = store
            .publish(
                &request,
                FetchResponse {
                    status: 200,
                    body: b"retained backup evidence".to_vec(),
                    validators: Validators::default(),
                },
                10,
            )
            .await
            .unwrap();
        let id = captured.capture.id.clone();
        let old_body = captured.capture.body_hash.clone();
        drop(captured);
        drop(store);
        let transfer = Arc::new(
            PgBlobStore::connect_for_object_transfer(
                source_url.as_str(),
                root.path(),
                source.clone(),
            )
            .await
            .unwrap(),
        );
        transfer
            .transfer_object_archive("migrate-object-storage", CancellationToken::new())
            .await
            .unwrap();
        transfer
            .transfer_object_archive("activate-object-storage", CancellationToken::new())
            .await
            .unwrap();
        drop(transfer);
        let cache = tempfile::tempdir_in("/tmp").unwrap();
        let store =
            PgBlobStore::connect_archive(source_url.as_str(), cache.path(), Some(source.clone()))
                .await
                .unwrap();
        let newer = store
            .publish(
                &request,
                FetchResponse {
                    status: 200,
                    body: b"new S3-only backup evidence".to_vec(),
                    validators: Validators::default(),
                },
                11,
            )
            .await
            .unwrap();
        let newer_id = newer.capture.id.clone();
        let newer_body = newer.capture.body_hash.clone();
        drop(newer);
        drop(store);
        let receipt = backup(
            source_url.as_str(),
            cache.path(),
            source,
            saved.clone(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(receipt["verified"], true);
        let cold = tempfile::tempdir_in("/tmp").unwrap();
        let restored = restore(
            destination_url.as_str(),
            cold.path(),
            destination.clone(),
            saved,
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(restored["verified"], true);
        let reader_cache = tempfile::tempdir_in("/tmp").unwrap();
        let reader = PgBlobStore::connect_reader(
            destination_url.as_str(),
            reader_cache.path(),
            Some(destination.clone()),
        )
        .await
        .unwrap();
        assert_eq!(
            &*reader.capture(&id).await.unwrap().body,
            b"retained backup evidence"
        );
        assert_eq!(
            &*reader.capture(&newer_id).await.unwrap().body,
            b"new S3-only backup evidence"
        );
        drop(reader);
        let store =
            PgBlobStore::connect_archive(destination_url.as_str(), cold.path(), Some(destination))
                .await
                .unwrap();
        let captured = store.capture(&id).await.unwrap();
        assert_eq!(captured.capture.id, id);
        assert_eq!(&*captured.body, b"retained backup evidence");
        let newer = store.capture(&newer_id).await.unwrap();
        assert_eq!(newer.capture.id, newer_id);
        assert_eq!(&*newer.body, b"new S3-only backup evidence");
        assert_eq!(
            std::fs::read(
                root.path()
                    .join(crate::integrity::relative_path(&old_body).unwrap())
            )
            .unwrap(),
            b"retained backup evidence"
        );
        assert!(
            !root
                .path()
                .join(crate::integrity::relative_path(&newer_body).unwrap())
                .exists()
        );
        let restored_protection: bool = sqlx_core::query_scalar::query_scalar(
            "SELECT source_protected FROM devres_archive_transfer WHERE singleton",
        )
        .fetch_one(&store.pool)
        .await
        .unwrap();
        assert!(!restored_protection);
        let source_pool = sqlx_postgres::PgPool::connect(source_url.as_str())
            .await
            .unwrap();
        let source_protection: bool = sqlx_core::query_scalar::query_scalar(
            "SELECT source_protected FROM devres_archive_transfer WHERE singleton",
        )
        .fetch_one(&source_pool)
        .await
        .unwrap();
        assert!(source_protection);
        let pending: bool = sqlx_core::query_scalar::query_scalar(
            "SELECT to_regclass('public.devres_archive_restore_pending') IS NOT NULL",
        )
        .fetch_one(&store.pool)
        .await
        .unwrap();
        assert!(!pending);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    #[ignore = "requires disposable PostgreSQL and RustFS; run scripts/test-s3.sh"]
    async fn s3_single_runtime_worker_concurrent_capture_publication() {
        use devres_application::Store;
        use devres_domain::{FetchRequest, FetchResponse, Validators};
        let base = std::env::var("DEVRES_TEST_DATABASE_URL").expect("disposable database required");
        let path = std::env::var("DEVRES_TEST_S3_CONFIG").expect("disposable S3 config required");
        let mut config: S3Config = toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        config.prefix.push_str("/single-runtime-worker");
        let admin = sqlx_postgres::PgPool::connect(&base).await.unwrap();
        sqlx_core::query::query("CREATE DATABASE devres_s3_single_worker")
            .execute(&admin)
            .await
            .unwrap();
        let mut url = url::Url::parse(&base).unwrap();
        url.set_path("/devres_s3_single_worker");
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let store = Arc::new(
            PgBlobStore::connect_archive(url.as_str(), root.path(), Some(config))
                .await
                .unwrap(),
        );
        let mut tasks = Vec::new();
        for number in 0..8 {
            let store = store.clone();
            tasks.push(tokio::spawn(async move {
                let request = FetchRequest {
                    key: format!("fixture:runtime:{number}"),
                    url: format!("https://fixtures.invalid/runtime/{number}"),
                    ttl_secs: 3600,
                    max_bytes: 128,
                    media_type: "text/plain".into(),
                };
                store
                    .publish(
                        &request,
                        FetchResponse {
                            status: 200,
                            body: format!("fixture-{number}").into_bytes(),
                            validators: Validators::default(),
                        },
                        10,
                    )
                    .await
            }));
        }
        tokio::time::timeout(Duration::from_secs(20), async {
            for task in tasks {
                task.await.unwrap().unwrap();
            }
        })
        .await
        .expect("runtime must keep its original I/O drivers progressing");
        store.check_health().await.unwrap();
    }
}
