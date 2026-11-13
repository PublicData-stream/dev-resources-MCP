//! Private bounded inspection. No collector, writer, archive cache, or provider client.
use super::{capture_metadata_digest, payload_integrity};
use crate::{
    integrity,
    object_storage::{S3Archive, S3Config},
};
use devres_application::collection::{CollectorStatus, safe_code};
use devres_domain::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx_core::{connection::Connection, row::Row};
use sqlx_postgres::PgConnection;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;

const MAX_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ROW: u64 = 16 * 1024 * 1024;
const MAX_REPORT: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosisProvider {
    W3c,
    Chromium,
    Crates,
    Rfc,
}
impl DiagnosisProvider {
    fn tables(self) -> Result<(&'static str, &'static str)> {
        match self {
            Self::W3c => Ok(("devres_w3c_evidence", "devres_w3c_state")),
            Self::Chromium => Ok(("devres_chromium_evidence", "devres_chromium_state")),
            Self::Crates | Self::Rfc => Err(invalid()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct DiagnosisOptions {
    pub provider: DiagnosisProvider,
    pub max_total_bytes: u64,
    pub timeout_secs: u64,
    pub scan_retained_dump: bool,
    pub snapshot: Option<String>,
    pub job_keys: Vec<String>,
}
impl DiagnosisOptions {
    pub fn validate(&self) -> Result<()> {
        if self.max_total_bytes == 0
            || self.max_total_bytes > MAX_BYTES
            || self.timeout_secs == 0
            || self.timeout_secs > 300
            || (self.scan_retained_dump && self.provider != DiagnosisProvider::Crates)
        {
            return Err(invalid());
        }
        if self.provider == DiagnosisProvider::Rfc {
            if !self.snapshot.as_deref().is_some_and(integrity::valid_hash)
                || !(1..=2).contains(&self.job_keys.len())
                || self
                    .job_keys
                    .iter()
                    .any(|key| rfc_job_identity(key).is_err())
                || self.job_keys.iter().collect::<BTreeSet<_>>().len() != self.job_keys.len()
            {
                return Err(invalid());
            }
        } else if self.snapshot.is_some() || !self.job_keys.is_empty() {
            return Err(invalid());
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub struct CollectionDiagnosis {
    pub version: u32,
    pub provider: DiagnosisProvider,
    pub schema: i32,
    pub observed_at: i64,
    pub cutoff: i64,
    pub bytes_read: u64,
    pub complete: bool,
    pub outcome: DiagnosisOutcome,
    pub evidence: Vec<EvidenceSummary>,
    pub collectors: Vec<CollectorStatus>,
    pub diagnostics: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dump: Option<Value>,
}
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosisOutcome {
    Inspected,
    NoRetainedFailure,
    AttemptedPayloadUnlinked,
    BudgetExhausted,
    IntegrityFailed,
    SelectedEvidenceUnavailable,
}
#[derive(Debug, Serialize)]
pub struct EvidenceSummary {
    pub kind: String,
    pub sequence: i64,
    pub identity: String,
    pub digest: String,
    pub bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<BodySummary>,
}
#[derive(Debug, Serialize)]
pub struct BodySummary {
    pub digest: String,
    pub bytes: u64,
    pub parser_accepted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub row: Option<u32>,
}

fn invalid() -> Error {
    Error::invalid("Invalid collection diagnosis options.")
}
fn failed() -> Error {
    Error::integrity("Collection evidence verification failed.")
}
fn unavailable() -> Error {
    Error::unavailable("Collection evidence unavailable.")
}
fn capacity() -> Error {
    Error::capacity("Collection diagnosis budget exhausted.")
}

/// Walk trusted directory descriptors, so symlink ancestors cannot redirect mkdir.
pub fn create_diagnosis_output(path: &Path) -> Result<std::fs::File> {
    use nix::{
        fcntl::{OFlag, open, openat},
        sys::stat::{Mode, fstat, mkdirat},
    };
    let invalid = || {
        Error::invalid(
            "Diagnosis output requires a private owned directory below /tmp and a new regular file.",
        )
    };
    let relative = path.strip_prefix("/tmp").map_err(|_| invalid())?;
    let parts = relative
        .components()
        .map(|part| match part {
            std::path::Component::Normal(name) => Ok(name),
            _ => Err(invalid()),
        })
        .collect::<Result<Vec<_>>>()?;
    if parts.len() < 2 {
        return Err(invalid());
    }
    let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let mut directory = open(Path::new("/tmp"), flags, Mode::empty()).map_err(|_| invalid())?;
    for (index, name) in parts[..parts.len() - 1].iter().enumerate() {
        directory = match openat(&directory, *name, flags, Mode::empty()) {
            Ok(next) => next,
            Err(nix::errno::Errno::ENOENT) if index == parts.len() - 2 => {
                mkdirat(&directory, *name, Mode::from_bits_truncate(0o700))
                    .map_err(|_| invalid())?;
                openat(&directory, *name, flags, Mode::empty()).map_err(|_| invalid())?
            }
            Err(_) => return Err(invalid()),
        };
    }
    let metadata = fstat(&directory).map_err(|_| invalid())?;
    let status = std::fs::read_to_string("/proc/self/status").map_err(|_| invalid())?;
    let uid = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|uid| uid.parse::<u32>().ok())
        .ok_or_else(invalid)?;
    if metadata.st_uid != uid || metadata.st_mode & 0o077 != 0 {
        return Err(invalid());
    }
    let file = openat(
        &directory,
        parts[parts.len() - 1],
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(|_| invalid())?;
    Ok(std::fs::File::from(file))
}

struct Budget {
    remaining: u64,
    read: u64,
    deadline: Instant,
    cancel: CancellationToken,
}
impl Budget {
    fn check(&self) -> Result<()> {
        if self.cancel.is_cancelled() {
            return Err(Error::new("cancelled", "Collection diagnosis canceled."));
        }
        if Instant::now() >= self.deadline {
            return Err(capacity());
        }
        Ok(())
    }
    fn admit(&mut self, bytes: u64) -> Result<()> {
        self.check()?;
        self.remaining = self.remaining.checked_sub(bytes).ok_or_else(capacity)?;
        self.read += bytes;
        Ok(())
    }
}

struct Reader {
    conn: PgConnection,
    root: PathBuf,
    remote: Option<S3Archive>,
    budget: Budget,
    bodies: BTreeMap<String, Vec<u8>>,
}

impl Reader {
    async fn open(
        database: &str,
        root: &Path,
        s3: Option<S3Config>,
        options: &DiagnosisOptions,
        cancel: CancellationToken,
    ) -> Result<(Self, i32)> {
        let mut conn =
            tokio::time::timeout(Duration::from_secs(5), PgConnection::connect(database))
                .await
                .map_err(|_| unavailable())?
                .map_err(|_| unavailable())?;
        sqlx_core::raw_sql::raw_sql("SET default_transaction_read_only=on; SET statement_timeout='15000ms'; SET lock_timeout='3000ms'")
            .execute(&mut conn).await.map_err(|_| unavailable())?;
        let held: bool = sqlx_core::query_scalar::query_scalar(
            "SELECT pg_try_advisory_lock_shared(1835365490,2)",
        )
        .fetch_one(&mut conn)
        .await
        .map_err(|_| unavailable())?;
        if !held {
            return Err(unavailable());
        }
        sqlx_core::raw_sql::raw_sql("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut conn)
            .await
            .map_err(|_| unavailable())?;
        let schema: i32 = sqlx_core::query_scalar::query_scalar("SELECT version FROM devres_schema WHERE singleton AND (SELECT active FROM devres_integrity_control WHERE singleton) AND to_regclass('public.devres_archive_restore_pending') IS NULL")
            .fetch_one(&mut conn).await.map_err(|_| unavailable())?;
        if !matches!(schema, 14..=16) {
            return Err(unavailable());
        }
        let row = sqlx_core::query::query("SELECT backend,binding,store_id FROM devres_archive_control WHERE singleton AND pending_binding IS NULL AND NOT initializing_s3")
            .fetch_one(&mut conn).await.map_err(|_| unavailable())?;
        let backend: String = row.try_get("backend").map_err(|_| failed())?;
        let mut budget = Budget {
            remaining: options.max_total_bytes,
            read: 0,
            deadline: Instant::now() + Duration::from_secs(options.timeout_secs),
            cancel,
        };
        let remote = match s3 {
            Some(config) => {
                if backend != "s3"
                    || row
                        .try_get::<Option<String>, _>("binding")
                        .map_err(|_| failed())?
                        .as_deref()
                        != Some(crate::durable_archive::config_binding(&config)?.as_str())
                {
                    return Err(failed());
                }
                let remote = S3Archive::new_reader(config).await?;
                budget.admit(16 * 1024)?;
                let descriptor = remote
                    .get_bytes_with_cancel("store.json", 16 * 1024, &budget.cancel)
                    .await?;
                let expected = json!({"version":1,"store_id":row.try_get::<String,_>("store_id").map_err(|_| failed())?});
                if serde_json::from_slice::<Value>(&descriptor).map_err(|_| failed())? != expected {
                    return Err(failed());
                }
                Some(remote)
            }
            None if backend == "filesystem" => None,
            None => return Err(unavailable()),
        };
        Ok((
            Self {
                conn,
                root: root.to_path_buf(),
                remote,
                budget,
                bodies: BTreeMap::new(),
            },
            schema,
        ))
    }

    async fn state(&mut self, provider: DiagnosisProvider, key: &str) -> Result<Option<Value>> {
        let (_, table) = provider.tables()?;
        let size_sql = format!("SELECT octet_length(data::text)::bigint FROM {table} WHERE key=$1");
        let bytes: Option<i64> =
            sqlx_core::query_scalar::query_scalar(sqlx_core::sql_str::AssertSqlSafe(size_sql))
                .bind(key)
                .fetch_optional(&mut self.conn)
                .await
                .map_err(|_| unavailable())?;
        let Some(bytes) = bytes else {
            return Ok(None);
        };
        self.row_admit(bytes)?;
        let sql =
            format!("SELECT ''::text AS kind,key,data,data_integrity FROM {table} WHERE key=$1");
        let row = sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(sql))
            .bind(key)
            .fetch_one(&mut self.conn)
            .await
            .map_err(|_| unavailable())?;
        Ok(Some(payload_integrity::row(table, &row)?))
    }
    fn row_admit(&mut self, bytes: i64) -> Result<()> {
        let bytes = u64::try_from(bytes).map_err(|_| failed())?;
        if bytes > MAX_ROW {
            return Err(capacity());
        }
        self.budget.admit(bytes)
    }
    async fn evidence(
        &mut self,
        provider: DiagnosisProvider,
        kind: &str,
        key: Option<&str>,
        cutoff: i64,
    ) -> Result<Option<(i64, String, Value)>> {
        let (table, _) = provider.tables()?;
        // Resolve a selected legacy alias only after checking its immutable seal.
        let namespace = match provider {
            DiagnosisProvider::W3c => format!("w3c:{kind}"),
            DiagnosisProvider::Chromium => format!("chromium:{kind}"),
            _ => return Err(invalid()),
        };
        let sql = format!(
            "SELECT sequence,key,octet_length(data::text)::bigint AS bytes FROM {table} WHERE kind=$1 AND ($2::text IS NULL OR key=$2) AND sequence<=$3 ORDER BY sequence DESC LIMIT 1"
        );
        let position = sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(sql))
            .bind(kind)
            .bind(key)
            .bind(cutoff)
            .fetch_optional(&mut self.conn)
            .await
            .map_err(|_| unavailable())?;
        let Some(position) = position else {
            return Ok(None);
        };
        self.row_admit(position.try_get("bytes").map_err(|_| failed())?)?;
        let mut sequence: i64 = position.try_get("sequence").map_err(|_| failed())?;
        let mut key: String = position.try_get("key").map_err(|_| failed())?;
        let alias_size:Option<(i64,i64)>=sqlx_core::query_as::query_as("SELECT octet_length(canonical)::bigint,COALESCE(octet_length(mapping_integrity),0)::bigint FROM devres_content_aliases WHERE namespace=$1 AND legacy=$2")
            .bind(&namespace).bind(&key).fetch_optional(&mut self.conn).await.map_err(|_|unavailable())?;
        if alias_size.is_some_and(|(key, seal)| key > 4096 || seal > 128 || seal == 0) {
            return Err(failed());
        }
        let alias=sqlx_core::query::query("SELECT canonical,mapping_integrity FROM devres_content_aliases WHERE namespace=$1 AND legacy=$2")
            .bind(&namespace).bind(&key).fetch_optional(&mut self.conn).await.map_err(|_|unavailable())?;
        if let Some(alias) = alias {
            self.budget.admit(8192)?;
            let canonical: String = alias.try_get("canonical").map_err(|_| failed())?;
            let seal: String = alias.try_get("mapping_integrity").map_err(|_| failed())?;
            let payload = json!({"namespace":namespace,"legacy":key,"canonical":canonical});
            if super::events::event_digest(
                "devres_content_aliases",
                &super::events::mapping_key(&namespace, &key)?,
                &payload,
            )? != seal
                || !canonical.starts_with("blake3:")
                || !integrity::valid_hash(&canonical)
            {
                return Err(failed());
            }
            let sql = format!(
                "SELECT sequence,octet_length(data::text)::bigint AS bytes FROM {table} WHERE kind=$1 AND key=$2 AND sequence<=$3"
            );
            let target = sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(sql))
                .bind(kind)
                .bind(&canonical)
                .bind(cutoff)
                .fetch_one(&mut self.conn)
                .await
                .map_err(|_| failed())?;
            self.row_admit(target.try_get("bytes").map_err(|_| failed())?)?;
            sequence = target.try_get("sequence").map_err(|_| failed())?;
            key = canonical;
        }
        let sql = format!(
            "SELECT sequence,kind,key,data,data_integrity,sequence_integrity FROM {table} WHERE sequence=$1"
        );
        let row = sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(sql))
            .bind(sequence)
            .fetch_one(&mut self.conn)
            .await
            .map_err(|_| unavailable())?;
        let data = payload_integrity::row(table, &row)?;
        integrity::verify(&key, &serde_json::to_vec(&data).map_err(|_| failed())?)?;
        Ok(Some((sequence, key, data)))
    }

    async fn body(&mut self, relative: &str, expected: &str, size: u64) -> Result<Vec<u8>> {
        self.budget.check()?;
        if let Some(bytes) = self.bodies.get(expected) {
            if bytes.len() as u64 != size {
                return Err(failed());
            }
            checked_relative(relative)?;
            return Ok(bytes.clone());
        }
        if size > 8 * 1024 * 1024 {
            return Err(capacity());
        }
        let bytes = self.file(relative, size).await?;
        if bytes.len() as u64 != size {
            return Err(failed());
        }
        integrity::verify(expected, &bytes)?;
        self.bodies.insert(expected.to_owned(), bytes.clone());
        Ok(bytes)
    }
    async fn file(&mut self, relative: &str, max: u64) -> Result<Vec<u8>> {
        checked_relative(relative)?;
        if let Some(remote) = &self.remote {
            self.budget.admit(16 * 1024)?;
            let row=sqlx_core::query::query("SELECT digest,bytes,evidence FROM devres_archive_file WHERE path=$1 AND complete AND octet_length(evidence)<=16384")
                .bind(relative).fetch_one(&mut self.conn).await.map_err(|_| unavailable())?;
            let encoded: String = row.try_get("evidence").map_err(|_| failed())?;
            let binding: ArchiveBinding = serde_json::from_str(&encoded).map_err(|_| failed())?;
            let digest: String = row.try_get("digest").map_err(|_| failed())?;
            let bytes: i64 = row.try_get("bytes").map_err(|_| failed())?;
            if binding.version != 1
                || binding.path != relative
                || binding.digest != digest
                || binding.bytes != u64::try_from(bytes).map_err(|_| failed())?
                || !digest.starts_with("blake3:")
                || !integrity::valid_hash(&digest)
                || binding.bytes > max
            {
                return Err(failed());
            }
            let descriptor_key = format!(
                "bindings/{}.json",
                blake3::hash(relative.as_bytes()).to_hex()
            );
            let descriptor = remote
                .get_bytes_with_cancel(&descriptor_key, 16 * 1024, &self.budget.cancel)
                .await?;
            if descriptor != encoded.as_bytes() {
                return Err(failed());
            }
            self.budget.admit(binding.bytes)?;
            let key = format!(
                "objects/{}",
                integrity::relative_path(&digest)?.to_string_lossy()
            );
            let bytes = remote
                .get_bytes_with_cancel(&key, binding.bytes, &self.budget.cancel)
                .await?;
            if bytes.len() as u64 != binding.bytes {
                return Err(failed());
            }
            integrity::verify(&digest, &bytes)?;
            Ok(bytes)
        } else {
            let path = self.root.join(relative);
            let metadata = std::fs::symlink_metadata(&path).map_err(|_| unavailable())?;
            if metadata.len() > max || !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(failed());
            }
            self.budget.admit(metadata.len())?;
            read_local(&path, max, &self.budget)
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveBinding {
    version: u32,
    path: String,
    digest: String,
    bytes: u64,
    #[serde(rename = "device")]
    _device: u64,
    #[serde(rename = "inode")]
    _inode: u64,
}

fn checked_relative(relative: &str) -> Result<()> {
    if relative.is_empty()
        || relative.len() > 4096
        || relative.contains('\\')
        || relative.chars().any(char::is_control)
        || !Path::new(relative)
            .components()
            .all(|part| matches!(part, std::path::Component::Normal(_)))
    {
        return Err(failed());
    }
    Ok(())
}
fn read_local(path: &Path, max: u64, budget: &Budget) -> Result<Vec<u8>> {
    for ancestor in path.ancestors().skip(1) {
        let meta = std::fs::symlink_metadata(ancestor).map_err(|_| unavailable())?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err(failed());
        }
    }
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| unavailable())?;
    let expected = file.metadata().map_err(|_| unavailable())?;
    if !expected.is_file() || expected.len() > max {
        return Err(failed());
    }
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 65536];
    loop {
        budget.check()?;
        let n = file.read(&mut chunk).map_err(|_| unavailable())?;
        if n == 0 {
            break;
        }
        if bytes.len() as u64 + n as u64 > max {
            return Err(capacity());
        }
        bytes.extend_from_slice(&chunk[..n]);
    }
    if bytes.len() as u64 != expected.len() {
        return Err(failed());
    }
    Ok(bytes)
}

fn retained_local_path(root: &Path, relative: &Path, expected: u64) -> Result<Option<PathBuf>> {
    let path = root.join(relative);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(unavailable()),
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() != expected {
        return Err(failed());
    }
    for ancestor in path.ancestors().skip(1) {
        let metadata = std::fs::symlink_metadata(ancestor).map_err(|_| unavailable())?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(failed());
        }
    }
    Ok(Some(path))
}

fn summary(kind: &str, sequence: i64, key: &str, data: &Value) -> Result<EvidenceSummary> {
    Ok(EvidenceSummary {
        kind: kind.into(),
        sequence,
        identity: if integrity::valid_hash(key) {
            key.into()
        } else {
            integrity::hash(key.as_bytes())
        },
        digest: integrity::canonical_hash(data)?,
        bytes: serde_json::to_vec(data).map_err(|_| failed())?.len() as u64,
        page: data["page"].as_u64(),
        observed_at: data["observed_at"].as_i64(),
        body: None,
    })
}

async fn inspect_w3c(reader: &mut Reader, report: &mut CollectionDiagnosis) -> Result<()> {
    let provider = DiagnosisProvider::W3c;
    for key in ["collector-catalog", "collector-current"] {
        if let Some(value) = reader.state(provider, key).await? {
            let mut status: CollectorStatus =
                serde_json::from_value(value).map_err(|_| failed())?;
            if let Some(failure) = &mut status.failure {
                failure.code = safe_code(&failure.code).into();
            }
            report.collectors.push(status);
        }
    }
    let Some((sequence, key, failure)) = reader
        .evidence(provider, "catalog-failures", None, report.cutoff)
        .await?
    else {
        report.outcome = DiagnosisOutcome::NoRetainedFailure;
        return Ok(());
    };
    report
        .evidence
        .push(summary("catalog-failures", sequence, &key, &failure)?);
    let (diagnostic, attempt) = crate::w3c::corpus::diagnose_catalog_failure(failure.clone())?;
    report.diagnostics.push(diagnostic);
    let pages = failure["work"]["pages"].as_array().ok_or_else(failed)?;
    if pages.len() > 1000 {
        return Err(capacity());
    }
    let mut previous: Option<String> = None;
    let mut previous_has_next = true;
    let mut ids = BTreeSet::new();
    for (offset, id) in pages.iter().enumerate() {
        let id = id
            .as_str()
            .filter(|id| integrity::valid_hash(id))
            .ok_or_else(failed)?;
        let (sequence, key, page) = reader
            .evidence(provider, "catalog-pages", Some(id), report.cutoff)
            .await?
            .ok_or_else(failed)?;
        if !previous_has_next
            || page["page"] != json!(offset + 1)
            || page["previous"] != json!(previous)
            || page["generation"] != failure["work"]["generation"]
        {
            return Err(failed());
        }
        let mut info = summary("catalog-pages", sequence, &key, &page)?;
        let artifact: crate::bulk::BulkArtifact =
            serde_json::from_value(page["artifact"].clone()).map_err(|_| failed())?;
        let relative = format!(
            "w3c/raw-artifacts/{}",
            integrity::relative_path(&artifact.body_hash)?.to_string_lossy()
        );
        if artifact.relative_path
            != integrity::relative_path(&artifact.body_hash)?.to_string_lossy()
        {
            return Err(failed());
        }
        let bytes = reader
            .body(&relative, &artifact.body_hash, artifact.bytes)
            .await?;
        crate::w3c::corpus::verify_diagnostic_catalog_page(page.clone(), &bytes)?;
        let parsed = crate::w3c::catalog::parse_page_diagnostic(
            &bytes,
            page["observed_at"].as_i64().ok_or_else(failed)?,
        )
        .map_err(|_| failed())?;
        for standard in &parsed.standards {
            if !ids.insert(standard.id.clone()) {
                return Err(failed());
            }
        }
        info.body = Some(BodySummary {
            digest: artifact.body_hash,
            bytes: artifact.bytes,
            parser_accepted: true,
            reason: None,
            row: None,
        });
        report.evidence.push(info);
        previous = Some(id.to_owned());
        previous_has_next = page["has_next"].as_bool().ok_or_else(failed)?;
    }
    if failure["work"]["standards"].as_u64() != Some(ids.len() as u64) {
        return Err(failed());
    }
    if failure["work"]["complete"].as_bool() != Some(!previous_has_next) {
        return Err(failed());
    }
    if let Some(artifact) = attempt {
        let relative = format!(
            "w3c/raw-artifacts/{}",
            integrity::relative_path(&artifact.body_hash)?.to_string_lossy()
        );
        let bytes = reader
            .body(&relative, &artifact.body_hash, artifact.bytes)
            .await?;
        let mut info = summary("catalog-failures", sequence, &key, &failure)?;
        let (accepted, reason, row) = match crate::w3c::catalog::parse_page_diagnostic(
            &bytes,
            failure["observed_at"].as_i64().ok_or_else(failed)?,
        ) {
            Ok(_) => (true, None, None),
            Err(failure) => (
                false,
                Some(serde_json::to_value(failure.reason).map_err(|_| failed())?),
                failure.row,
            ),
        };
        info.body = Some(BodySummary {
            digest: artifact.body_hash,
            bytes: artifact.bytes,
            parser_accepted: accepted,
            reason,
            row,
        });
        report.evidence.push(info);
    } else {
        // Legacy failures have no attempted-body linkage. Never infer page N+1.
        report.outcome = DiagnosisOutcome::AttemptedPayloadUnlinked;
        report.complete = false;
    }
    Ok(())
}

async fn inspect_chromium(reader: &mut Reader, report: &mut CollectionDiagnosis) -> Result<()> {
    let provider = DiagnosisProvider::Chromium;
    for component in ["src", "site", "chrome", "chrome-archive"] {
        for lane in ["current", "history"] {
            let id = format!("{component}:{lane}");
            let key = format!("collector:{}", integrity::legacy_hash(id.as_bytes()));
            if let Some(value) = reader.state(provider, &key).await? {
                let mut status: CollectorStatus =
                    serde_json::from_value(value).map_err(|_| failed())?;
                if let Some(failure) = &mut status.failure {
                    failure.code = safe_code(&failure.code).into();
                }
                report.collectors.push(status);
            }
        }
    }
    if let Some((sequence, key, value)) = reader
        .evidence(provider, "validation-failures", None, report.cutoff)
        .await?
    {
        report
            .diagnostics
            .push(crate::chromium::corpus::diagnose_validation_failure(
                value.clone(),
            )?);
        report
            .evidence
            .push(summary("validation-failures", sequence, &key, &value)?);
        report.outcome = DiagnosisOutcome::Inspected;
    } else {
        report.outcome = DiagnosisOutcome::AttemptedPayloadUnlinked;
    }
    // Digests identify an attempted response, but do not provide bytes for parser replay.
    report.complete = false;
    Ok(())
}

/// Inspection accepts schemas 14 through 16 without upgrading the selected store.
pub async fn diagnose_collection(
    database: &str,
    root: &Path,
    s3: Option<S3Config>,
    options: DiagnosisOptions,
    cancel: CancellationToken,
) -> Result<CollectionDiagnosis> {
    options.validate()?;
    if cancel.is_cancelled() {
        return Err(Error::new("cancelled", "Collection diagnosis canceled."));
    }
    let limit = if options.scan_retained_dump {
        Duration::from_secs(1800)
    } else {
        Duration::from_secs(options.timeout_secs)
    };
    // Reserve bounded cooperative cleanup inside the caller's hard time ceiling.
    let cleanup = Duration::from_secs(20).min(limit / 2);
    let hard_deadline = tokio::time::Instant::now() + limit;
    let stopping = cancel.child_token();
    let worker_cancel = stopping.clone();
    let internal_deadline = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let work = async {
        let (mut reader, schema) =
            Reader::open(database, root, s3, &options, worker_cancel).await?;
        let cutoff = if matches!(
            options.provider,
            DiagnosisProvider::Crates | DiagnosisProvider::Rfc
        ) {
            0
        } else {
            let (table, _) = options.provider.tables()?;
            sqlx_core::query_scalar::query_scalar(sqlx_core::sql_str::AssertSqlSafe(format!(
                "SELECT COALESCE(max(sequence),0) FROM {table}"
            )))
            .fetch_one(&mut reader.conn)
            .await
            .map_err(|_| unavailable())?
        };
        let mut report = CollectionDiagnosis {
            version: 1,
            provider: options.provider,
            schema,
            observed_at: devres_domain::unix_now(),
            cutoff,
            bytes_read: 0,
            complete: true,
            outcome: DiagnosisOutcome::Inspected,
            evidence: Vec::new(),
            collectors: Vec::new(),
            diagnostics: Vec::new(),
            dump: None,
        };
        let result = match options.provider {
            DiagnosisProvider::W3c => inspect_w3c(&mut reader, &mut report).await,
            DiagnosisProvider::Chromium => inspect_chromium(&mut reader, &mut report).await,
            DiagnosisProvider::Rfc => inspect_rfc(&mut reader, &mut report, &options).await,
            DiagnosisProvider::Crates => {
                inspect_crates(&mut reader, &mut report, options.scan_retained_dump).await
            }
        };
        if let Err(error) = result {
            if error.code == "capacity"
                || error.code == "cancelled"
                    && internal_deadline.load(std::sync::atomic::Ordering::Acquire)
                    && !cancel.is_cancelled()
            {
                report.complete = false;
                report.outcome = DiagnosisOutcome::BudgetExhausted;
            } else if error.code == "integrity" {
                report.complete = false;
                report.outcome = DiagnosisOutcome::IntegrityFailed;
            } else if options.provider == DiagnosisProvider::Rfc && error.code == "unavailable" {
                report.complete = false;
                report.outcome = DiagnosisOutcome::SelectedEvidenceUnavailable;
            } else {
                return Err(error);
            }
        }
        report.bytes_read = reader.budget.read;
        sqlx_core::raw_sql::raw_sql("ROLLBACK")
            .execute(&mut reader.conn)
            .await
            .map_err(|_| unavailable())?;
        if serde_json::to_vec(&report).map_err(|_| failed())?.len() > MAX_REPORT {
            return Err(capacity());
        }
        Ok(report)
    };
    tokio::pin!(work);
    tokio::select! {
        result=&mut work=>result,
        _=tokio::time::sleep(limit-cleanup)=>{
            internal_deadline.store(true, std::sync::atomic::Ordering::Release);
            stopping.cancel();
            match tokio::time::timeout_at(hard_deadline,work).await {
                Ok(result) => result,
                Err(_) => Err(capacity()),
            }
        },
        _=cancel.cancelled()=>{
            stopping.cancel();let _=tokio::time::timeout_at(hard_deadline.min(tokio::time::Instant::now()+cleanup),work).await;Err(Error::new("cancelled","Collection diagnosis canceled."))
        }
    }
}

#[path = "rfc/diagnostics.rs"]
mod rfc_diagnostics;
use rfc_diagnostics::{inspect_rfc, rfc_job_identity};

async fn inspect_crates(
    reader: &mut Reader,
    report: &mut CollectionDiagnosis,
    scan: bool,
) -> Result<()> {
    if report.schema >= 15 {
        let size:Option<i64>=sqlx_core::query_scalar::query_scalar("SELECT octet_length(diagnostic::text)::bigint FROM devres_crate_dump_failures ORDER BY observed_at DESC,id DESC LIMIT 1")
            .fetch_optional(&mut reader.conn).await.map_err(|_|unavailable())?;
        if let Some(size) = size {
            if size > 4096 {
                return Err(capacity());
            }
            reader.row_admit(size)?;
            let row=sqlx_core::query::query("SELECT * FROM devres_crate_dump_failures ORDER BY observed_at DESC,id DESC LIMIT 1")
                .fetch_one(&mut reader.conn).await.map_err(|_|unavailable())?;
            let (_, diagnostic) = super::crate_storage::enrichment_v2::checked_dump_failure(&row)?;
            report.diagnostics.push(diagnostic);
        }
    }
    // Resolve exactly one retained dump observation, never trigger acquisition.
    let size:Option<i64>=sqlx_core::query_scalar::query_scalar("SELECT octet_length(to_jsonb(c)::text)::bigint+octet_length(a.provenance::text)+octet_length(o.provenance::text) FROM devres_crate_observations o JOIN devres_captures c ON c.id=o.capture_id JOIN devres_crate_artifacts a ON a.capture_id=c.id WHERE c.source_key='cargo:database-dump' ORDER BY o.sequence DESC LIMIT 1")
        .fetch_optional(&mut reader.conn).await.map_err(|_|unavailable())?;
    let Some(size) = size else {
        report.outcome = DiagnosisOutcome::NoRetainedFailure;
        return Ok(());
    };
    reader.row_admit(size)?;
    let row=sqlx_core::query::query("SELECT c.*,a.bytes,a.provenance,a.provenance_integrity,o.observed_at AS validated_at,o.sequence AS observed_sequence,o.transport AS observed_transport,o.provenance AS observed_provenance,o.provenance_integrity AS observed_integrity FROM devres_crate_observations o JOIN devres_captures c ON c.id=o.capture_id JOIN devres_crate_artifacts a ON a.capture_id=c.id WHERE c.source_key='cargo:database-dump' ORDER BY o.sequence DESC LIMIT 1")
        .fetch_one(&mut reader.conn).await.map_err(|_|unavailable())?;
    let artifact = super::crate_storage::read_artifact(row)?;
    // Capture metadata is verified by the shared typed reader, never printed.
    let _ = capture_metadata_digest(&artifact.capture)?;
    report.dump = Some(
        json!({"capture":artifact.capture.id,"body_hash":artifact.capture.body_hash,"bytes":artifact.bytes,"scan_requested":scan}),
    );
    report.complete = false;
    report.outcome = DiagnosisOutcome::AttemptedPayloadUnlinked;
    if scan {
        const COMPRESSED: u64 = 4 * 1024 * 1024 * 1024;
        const EXPANDED: u64 = 8 * 1024 * 1024 * 1024;
        if artifact.bytes > COMPRESSED {
            return Err(capacity());
        }
        let relative = integrity::relative_path(&artifact.capture.body_hash)?;
        // Metadata snapshot is frozen; do not hold a long read transaction during decompression.
        sqlx_core::raw_sql::raw_sql("COMMIT")
            .execute(&mut reader.conn)
            .await
            .map_err(|_| unavailable())?;
        let scratch = tempfile::Builder::new()
            .prefix("devres-dump-diagnosis-")
            .tempdir_in("/tmp")
            .map_err(|_| unavailable())?;
        let deadline = Instant::now() + Duration::from_secs(1800);
        let mut download = false;
        let cached = retained_local_path(&reader.root, &relative, artifact.bytes)?;
        let path = if let Some(path) = cached {
            path
        } else if let Some(remote) = &reader.remote {
            let key = relative.to_str().ok_or_else(failed)?;
            let row=sqlx_core::query::query("SELECT digest,bytes,evidence FROM devres_archive_file WHERE path=$1 AND complete AND octet_length(evidence)<=16384")
                .bind(key).fetch_one(&mut reader.conn).await.map_err(|_|unavailable())?;
            reader.budget.admit(16 * 1024)?;
            let encoded: String = row.try_get("evidence").map_err(|_| failed())?;
            let binding: ArchiveBinding = serde_json::from_str(&encoded).map_err(|_| failed())?;
            if binding.version != 1
                || binding.path != key
                || binding.digest != artifact.capture.body_hash
                || binding.bytes != artifact.bytes
                || row.try_get::<String, _>("digest").map_err(|_| failed())? != binding.digest
                || row.try_get::<i64, _>("bytes").map_err(|_| failed())?
                    != i64::try_from(binding.bytes).map_err(|_| failed())?
            {
                return Err(failed());
            }
            let descriptor = remote
                .get_bytes_with_cancel(
                    &format!("bindings/{}.json", blake3::hash(key.as_bytes()).to_hex()),
                    16 * 1024,
                    &reader.budget.cancel,
                )
                .await?;
            if descriptor != encoded.as_bytes() {
                return Err(failed());
            }
            let path = scratch.path().join("retained.dump");
            let object = format!(
                "objects/{}",
                integrity::relative_path(&binding.digest)?.to_string_lossy()
            );
            let (digest, bytes) = remote
                .get_to_file(&object, &path, COMPRESSED, &reader.budget.cancel)
                .await?;
            if digest != binding.digest || bytes != artifact.bytes {
                return Err(failed());
            }
            download = true;
            path
        } else {
            return Err(unavailable());
        };
        let token = reader.budget.cancel.clone();
        let inspection = tokio::task::spawn_blocking(move || {
            crate::crates_io::dump::inspect_dump(path, token, deadline, COMPRESSED, EXPANDED)
        })
        .await
        .map_err(|_| unavailable())??;
        report.complete = inspection.complete;
        report.outcome = DiagnosisOutcome::Inspected;
        if let Some(dump) = report.dump.as_mut().and_then(Value::as_object_mut) {
            dump.insert(
                "inspection".into(),
                serde_json::to_value(inspection).map_err(|_| failed())?,
            );
            dump.insert("remote_artifact_verified".into(), json!(download));
            dump.insert("local_prefix_only".into(), json!(!download));
            dump.insert("compressed_limit".into(), json!(COMPRESSED));
            dump.insert("expanded_limit".into(), json!(EXPANDED));
        }
        // Reestablish a read-only transaction for the common cleanup path.
        sqlx_core::raw_sql::raw_sql("BEGIN READ ONLY")
            .execute(&mut reader.conn)
            .await
            .map_err(|_| unavailable())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use devres_application::w3c::W3cStore;
    #[test]
    fn diagnosis_limits_and_paths_fail_before_io() {
        let mut options = DiagnosisOptions {
            provider: DiagnosisProvider::W3c,
            max_total_bytes: MAX_BYTES,
            timeout_secs: 300,
            scan_retained_dump: false,
            snapshot: None,
            job_keys: Vec::new(),
        };
        assert!(options.validate().is_ok());
        options.max_total_bytes += 1;
        assert!(options.validate().is_err());
        options.max_total_bytes = 1;
        options.timeout_secs = 301;
        assert!(options.validate().is_err());
        for path in ["../secret", "/secret", "a/../secret", "a\\b", ""] {
            assert!(checked_relative(path).is_err());
        }
    }
    #[test]
    fn local_reader_rejects_links_and_checks_cancellation() {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let path = root.path().join("raw");
        std::fs::write(&path, b"inert").unwrap();
        let cancel = CancellationToken::new();
        let mut budget = Budget {
            remaining: 5,
            read: 0,
            deadline: Instant::now() + Duration::from_secs(5),
            cancel: cancel.clone(),
        };
        assert_eq!(read_local(&path, 5, &budget).unwrap(), b"inert");
        assert!(budget.admit(6).is_err());
        assert_eq!(budget.read, 0);
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read_local(&link, 5, &budget).is_err());
        cancel.cancel();
        assert_eq!(read_local(&path, 5, &budget).unwrap_err().code, "cancelled");
    }

    #[tokio::test]
    #[ignore = "requires disposable PostgreSQL; run scripts/test-postgres.sh"]
    async fn diagnostic_reader_is_read_only_and_rejects_tampered_aliases_and_keys() {
        let base = std::env::var("DEVRES_TEST_DATABASE_URL").expect("disposable database required");
        let mut admin = PgConnection::connect(&base).await.unwrap();
        sqlx_core::raw_sql::raw_sql("CREATE DATABASE devres_diagnosis_fixture")
            .execute(&mut admin)
            .await
            .unwrap();
        let mut url = url::Url::parse(&base).unwrap();
        url.set_path("/devres_diagnosis_fixture");
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let writer = super::super::PgBlobStore::connect(url.as_str(), root.path())
            .await
            .unwrap();
        let options = DiagnosisOptions {
            provider: DiagnosisProvider::W3c,
            max_total_bytes: MAX_BYTES,
            timeout_secs: 30,
            scan_retained_dump: false,
            snapshot: None,
            job_keys: Vec::new(),
        };
        let mut latest = String::new();
        for now in [10, 11] {
            let value = json!({"version":1,"work":{"version":1,"generation":integrity::hash(format!("generation-{now}").as_bytes()),"started_at":now,"predecessor":null,"pages":[],"standards":0,"complete":false},"code":"integrity","context":null,"observed_at":now});
            latest = integrity::hash(&serde_json::to_vec(&value).unwrap());
            writer
                .w3c_put("catalog-failures", &latest, &value)
                .await
                .unwrap();
        }
        let report = diagnose_collection(
            url.as_str(),
            root.path(),
            None,
            options.clone(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(report.evidence.len(), 1);
        assert_eq!(report.evidence[0].identity, latest);
        assert_eq!(report.outcome, DiagnosisOutcome::AttemptedPayloadUnlinked);
        let mut tiny = options.clone();
        tiny.max_total_bytes = 1;
        let report = diagnose_collection(
            url.as_str(),
            root.path(),
            None,
            tiny,
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(report.outcome, DiagnosisOutcome::BudgetExhausted);
        assert_eq!(report.bytes_read, 0);
        let (mut reader, _) = Reader::open(
            url.as_str(),
            root.path(),
            None,
            &options,
            CancellationToken::new(),
        )
        .await
        .unwrap();
        let error = sqlx_core::raw_sql::raw_sql("CREATE TABLE forbidden_diagnosis_write(id int)")
            .execute(&mut reader.conn)
            .await
            .unwrap_err();
        assert_eq!(
            error.as_database_error().unwrap().code().as_deref(),
            Some("25006")
        );
        drop(reader);
        let mut conn = PgConnection::connect(url.as_str()).await.unwrap();
        let missing = integrity::hash(b"missing target");
        // A syntactically valid but incorrect seal reaches reader verification;
        // an arbitrary string would be rejected by the database CHECK first.
        sqlx_core::query::query("INSERT INTO devres_content_aliases(namespace,legacy,canonical,mapping_integrity) VALUES('w3c:catalog-failures',$1,$2,$3)")
            .bind(&latest).bind(&missing).bind(integrity::hash(b"incorrect mapping seal")).execute(&mut conn).await.unwrap();
        assert_eq!(
            diagnose_collection(
                url.as_str(),
                root.path(),
                None,
                options.clone(),
                CancellationToken::new()
            )
            .await
            .unwrap()
            .outcome,
            DiagnosisOutcome::IntegrityFailed
        );
        // Even a correctly sealed mapping must not hide a missing target.
        let seal = super::super::events::event_digest(
            "devres_content_aliases",
            &super::super::events::mapping_key("w3c:catalog-failures", &latest).unwrap(),
            &json!({"namespace":"w3c:catalog-failures","legacy":latest,"canonical":missing}),
        )
        .unwrap();
        sqlx_core::query::query("UPDATE devres_content_aliases SET mapping_integrity=$1 WHERE namespace='w3c:catalog-failures' AND legacy=$2")
            .bind(seal).bind(&latest).execute(&mut conn).await.unwrap();
        assert_eq!(
            diagnose_collection(
                url.as_str(),
                root.path(),
                None,
                options.clone(),
                CancellationToken::new()
            )
            .await
            .unwrap()
            .outcome,
            DiagnosisOutcome::IntegrityFailed
        );
        sqlx_core::query::query(
            "DELETE FROM devres_content_aliases WHERE namespace='w3c:catalog-failures'",
        )
        .execute(&mut conn)
        .await
        .unwrap();
        // Re-seal a changed payload under the old content identity. SQL sealing alone
        // cannot make a content-addressed row legitimate.
        let value = json!({"changed":true});
        let seal =
            payload_integrity::digest("devres_w3c_evidence", "catalog-failures", &latest, &value)
                .unwrap();
        sqlx_core::query::query("UPDATE devres_w3c_evidence SET data=$1,data_integrity=$2 WHERE kind='catalog-failures' AND key=$3")
            .bind(sqlx_core::types::Json(value)).bind(seal).bind(latest).execute(&mut conn).await.unwrap();
        assert_eq!(
            diagnose_collection(
                url.as_str(),
                root.path(),
                None,
                options,
                CancellationToken::new()
            )
            .await
            .unwrap()
            .outcome,
            DiagnosisOutcome::IntegrityFailed
        );
    }

    #[tokio::test]
    async fn pre_cancelled_diagnosis_does_not_wait_for_connection() {
        let cancel = CancellationToken::new();
        cancel.cancel();
        let options = DiagnosisOptions {
            provider: DiagnosisProvider::W3c,
            max_total_bytes: MAX_BYTES,
            timeout_secs: 1,
            scan_retained_dump: false,
            snapshot: None,
            job_keys: Vec::new(),
        };
        let started = Instant::now();
        let result = diagnose_collection(
            "postgres://invalid:invalid@192.0.2.1:5432/invalid",
            Path::new("/tmp"),
            None,
            options,
            cancel,
        )
        .await;
        assert_eq!(result.unwrap_err().code, "cancelled");
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
