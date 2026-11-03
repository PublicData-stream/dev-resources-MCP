//! Deterministic offline fixture timing, never a complete schema-nine corpus benchmark.
//! The shell harness owns the disposable database, and credentials enter through env.
use devres_adapters::{
    MigrationExecution, MigrationExecutionOptions, MigrationSettings, PgBlobStore,
    migrate_storage_graphs_with_execution,
};
use devres_application::Store;
use devres_domain::{FetchRequest, FetchResponse, Validators};
use serde_json::{Value, json};
use sqlx::Row;
use std::{collections::BTreeMap, error::Error, path::Path, sync::Arc, time::Instant};
use tokio_util::sync::CancellationToken;

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const BODY: &[u8] = b"synthetic public migration benchmark capture v1";
const KEY: &str = "fixture:migration-benchmark";
const FIXTURE_MARKER: &str = "devres:synthetic-migration-benchmark:v1";
const MARKER_FILE: &str = ".devres-benchmark-fixture";

async fn require_empty_database(pool: &sqlx::PgPool) -> Result<()> {
    // Inspect only PostgreSQL catalogs, in a read-only transaction, before any
    // schema initialization or fixture-root creation. Never reinterpret an
    // existing application database as disposable benchmark state.
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION READ ONLY")
        .execute(&mut *tx)
        .await?;
    let empty: bool = sqlx::query_scalar(
        "SELECT NOT EXISTS (SELECT 1 FROM pg_namespace WHERE NOT starts_with(nspname,'pg_') AND nspname NOT IN ('public','information_schema')) \
         AND NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public') \
         AND NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public') \
         AND NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='public') \
         AND NOT EXISTS (SELECT 1 FROM pg_event_trigger) \
         AND NOT EXISTS (SELECT 1 FROM pg_extension WHERE extname<>'plpgsql') \
         AND NOT EXISTS (SELECT 1 FROM pg_foreign_server)"
    ).fetch_one(&mut *tx).await?;
    tx.rollback().await?;
    if !empty {
        return Err("benchmark preparation requires a completely empty disposable database".into());
    }
    Ok(())
}

async fn require_fixture(pool: &sqlx::PgPool, root: &Path) -> Result<()> {
    let marker = root.join(MARKER_FILE);
    let metadata = std::fs::symlink_metadata(&marker)?;
    if !metadata.is_file()
        || metadata.len() != FIXTURE_MARKER.len() as u64
        || std::fs::read(&marker)? != FIXTURE_MARKER.as_bytes()
    {
        return Err("benchmark fixture-root marker mismatch".into());
    }
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION READ ONLY")
        .execute(&mut *tx)
        .await?;
    let exists: bool =
        sqlx::query_scalar("SELECT to_regclass('public.devres_benchmark_fixture') IS NOT NULL")
            .fetch_one(&mut *tx)
            .await?;
    if !exists {
        tx.rollback().await?;
        return Err("benchmark database fixture marker missing".into());
    }
    let markers: Vec<String> =
        sqlx::query_scalar("SELECT identity FROM public.devres_benchmark_fixture")
            .fetch_all(&mut *tx)
            .await?;
    tx.rollback().await?;
    if markers != [FIXTURE_MARKER] {
        return Err("benchmark database fixture marker mismatch".into());
    }
    Ok(())
}

fn count(value: Option<&String>, default: usize, maximum: usize) -> Result<usize> {
    let result = value.map_or(Ok(default), |value| value.parse::<usize>())?;
    if result == 0 || result > maximum {
        return Err("fixture option outside its bounded positive range".into());
    }
    Ok(result)
}

async fn prepare(url: &str, root: &Path, args: &[String]) -> Result<Value> {
    let rows = count(args.first(), 128, 4096)?;
    let payload_kib = count(args.get(1), 256, 2048)?;
    let files = count(args.get(2), 16, 128)?;
    let file_mib = count(args.get(3), 8, 32)?;
    if root.exists() || args.len() > 4 {
        return Err("prepare requires a new fixture root and bounded arguments".into());
    }
    let pool = sqlx::PgPool::connect(url).await?;
    require_empty_database(&pool).await?;
    std::fs::create_dir(root)?;
    let store = PgBlobStore::connect(url, root).await?;
    sqlx::raw_sql("CREATE TABLE public.devres_benchmark_fixture(singleton boolean PRIMARY KEY CHECK(singleton),identity text NOT NULL)")
        .execute(&pool).await?;
    sqlx::query("INSERT INTO public.devres_benchmark_fixture VALUES(true,$1)")
        .bind(FIXTURE_MARKER)
        .execute(&pool)
        .await?;
    std::fs::write(root.join(MARKER_FILE), FIXTURE_MARKER)?;
    let capture = store
        .publish(
            &FetchRequest {
                key: KEY.into(),
                url: "https://fixtures.invalid/migration-benchmark".into(),
                ttl_secs: 3600,
                max_bytes: 1024,
                media_type: "text/plain".into(),
            },
            FetchResponse {
                status: 200,
                body: BODY.to_vec(),
                validators: Validators::default(),
            },
            1_700_000_000,
        )
        .await?;
    drop(store);
    // Only the harness's fresh database is converted to pending qualification.
    // Empty provider graphs still traverse the real replay/activation gates.
    // Fresh initialization installed the final RFC constraint already; remove
    // it only in this disposable conversion so activation installs it normally.
    sqlx::raw_sql("UPDATE devres_integrity_control SET active=false,files_complete=false,sql_complete=false,graph_complete=false; DELETE FROM devres_integrity_graph_progress; ALTER TABLE devres_advisory_records ALTER COLUMN data_integrity DROP NOT NULL; ALTER TABLE devres_rfc_jobs DROP CONSTRAINT devres_rfc_capture_integrity_required;")
        .execute(&pool).await?;
    let payload = "synthetic public fixture payload ".repeat((payload_kib * 1024).div_ceil(33));
    for ordinal in 0..rows {
        let data = json!({"synthetic":true,"ordinal":ordinal,"payload":payload,
            "exact_number":serde_json::from_str::<Value>("12345678901234567890.123450000")?});
        sqlx::query("INSERT INTO devres_advisory_records(id,data) VALUES($1,$2)")
            .bind(format!("fixture-{ordinal:08}"))
            .bind(sqlx::types::Json(data))
            .execute(&pool)
            .await?;
    }
    let mut body = vec![0_u8; file_mib * 1024 * 1024];
    for (position, byte) in body.iter_mut().enumerate() {
        *byte = (position.wrapping_mul(37).wrapping_add(position / 4096) % 251) as u8;
    }
    for ordinal in 0..files {
        body[0..8].copy_from_slice(&(ordinal as u64).to_le_bytes());
        std::fs::write(root.join(format!("retained-{ordinal:04}.bin")), &body)?;
    }
    // A retained pair is durable before migration. Do not charge delayed writes
    // from synthetic fixture generation to the timed migration barriers.
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            std::fs::File::open(entry.path())?.sync_all()?;
        }
    }
    let directory = std::fs::File::open(root)?;
    directory.sync_all()?;
    sqlx::query("CHECKPOINT").execute(&pool).await?;
    nix::unistd::syncfs(&directory)?;
    pool.close().await;
    Ok(
        json!({"fixture":"pending-schema10-synthetic-v1","full_schema9_corpus":false,"durable_before_timing":true,
        "rows":rows,"payload_kib":payload_kib,"files":files,"file_mib":file_mib,
        "capture":capture.capture.id,"seed_outside_timing":true}),
    )
}

fn proc_values(path: &str) -> BTreeMap<String, u64> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            Some((key.into(), value.split_whitespace().next()?.parse().ok()?))
        })
        .collect()
}

async fn metrics(pool: &sqlx::PgPool) -> Result<Value> {
    let stat = std::fs::read_to_string("/proc/self/stat")?;
    let fields: Vec<_> = stat
        .rsplit_once(')')
        .ok_or("invalid process stat")?
        .1
        .split_whitespace()
        .collect();
    let ticks = |index: usize| -> Result<u64> {
        Ok(fields
            .get(index)
            .ok_or("missing process counter")?
            .parse()?)
    };
    let wal: String =
        sqlx::query_scalar("SELECT pg_wal_lsn_diff(pg_current_wal_lsn(),'0/0')::text")
            .fetch_one(pool)
            .await?;
    let io = proc_values("/proc/self/io");
    let status = proc_values("/proc/self/status");
    Ok(json!({"user_ticks":ticks(11)?,"system_ticks":ticks(12)?,
        "read_bytes":io.get("read_bytes"),"write_bytes":io.get("write_bytes"),
        "rss_high_water_kib":status.get("VmHWM"),"wal_position_bytes":wal.parse::<u64>()?}))
}

async fn phase<F, T>(
    name: &str,
    pool: &sqlx::PgPool,
    work: F,
    reports: &mut Vec<Value>,
) -> Result<T>
where
    F: std::future::Future<Output = Result<T>>,
{
    let before = metrics(pool).await?;
    let start = Instant::now();
    let result = work.await?;
    let elapsed = start.elapsed().as_secs_f64();
    let after = metrics(pool).await?;
    let delta = |key: &str| {
        after[key]
            .as_u64()
            .unwrap_or(0)
            .saturating_sub(before[key].as_u64().unwrap_or(0))
    };
    reports.push(json!({"phase":name,"wall_secs":elapsed,
        "user_ticks":delta("user_ticks"),"system_ticks":delta("system_ticks"),
        "read_bytes":delta("read_bytes"),"write_bytes":delta("write_bytes"),
        "wal_bytes":delta("wal_position_bytes"),"process_rss_high_water_kib":after["rss_high_water_kib"]}));
    Ok(result)
}

async fn fingerprint(pool: &sqlx::PgPool, root: &Path) -> Result<String> {
    use futures::TryStreamExt;
    let mut digest = blake3::Hasher::new();
    digest.update(b"devres:synthetic-migration-fingerprint:v1\0");
    // Compare all retained fixture SQL evidence, excluding physical tuple IDs,
    // connection statistics and execution timing. Table/row ordering is explicit.
    for table in [
        "devres_benchmark_fixture",
        "devres_advisory_records",
        "devres_captures",
        "devres_heads",
        "devres_observations",
        "devres_content_aliases",
        "devres_integrity_files",
        "devres_integrity_control",
        "devres_integrity_graph_progress",
        "devres_integrity_provider_cutoffs",
        "devres_integrity_staged_state",
    ] {
        digest.update(table.as_bytes());
        let query =
            format!("SELECT to_jsonb(t)::text AS data FROM {table} t ORDER BY to_jsonb(t)::text");
        let mut rows = sqlx::query(sqlx::AssertSqlSafe(query)).fetch(pool);
        while let Some(row) = rows.try_next().await? {
            let data: String = row.try_get("data")?;
            digest.update(&(data.len() as u64).to_le_bytes());
            digest.update(data.as_bytes());
        }
    }
    fn visit(root: &Path, current: &Path, digest: &mut blake3::Hasher) -> Result<()> {
        use std::io::Read;
        let mut entries = std::fs::read_dir(current)?.collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let kind = entry.file_type()?;
            if kind.is_symlink() {
                return Err("unexpected fixture symlink".into());
            }
            if kind.is_dir() {
                visit(root, &entry.path(), digest)?;
            } else if kind.is_file() {
                if entry.file_name().to_string_lossy().starts_with(".stage-") {
                    return Err("unpublished fixture stage remained".into());
                }
                let path = entry.path();
                let relative = path
                    .strip_prefix(root)?
                    .to_str()
                    .ok_or("non-UTF8 fixture path")?;
                digest.update(&(relative.len() as u64).to_le_bytes());
                digest.update(relative.as_bytes());
                digest.update(&entry.metadata()?.len().to_le_bytes());
                let mut file = std::fs::File::open(path)?;
                let mut buffer = [0_u8; 65536];
                loop {
                    let count = file.read(&mut buffer)?;
                    if count == 0 {
                        break;
                    }
                    digest.update(&buffer[..count]);
                }
            } else {
                return Err("unexpected fixture file kind".into());
            }
        }
        Ok(())
    }
    visit(root, root, &mut digest)?;
    Ok(digest.finalize().to_hex().to_string())
}

async fn readback(url: &str, root: &Path, pool: &sqlx::PgPool) -> Result<String> {
    require_fixture(pool, root).await?;
    let store = PgBlobStore::connect(url, root).await?;
    store.check_health().await?;
    let id: String = sqlx::query_scalar("SELECT capture_id FROM devres_heads WHERE source_key=$1")
        .bind(KEY)
        .fetch_one(pool)
        .await?;
    if store.capture(&id).await?.body.as_ref() != BODY {
        return Err("retained capture mismatch".into());
    }
    drop(store);
    fingerprint(pool, root).await
}

async fn run(url: &str, root: &Path, workers: usize, budget_mib: usize) -> Result<Value> {
    let execution = MigrationExecution::new(MigrationExecutionOptions::new(
        workers,
        budget_mib
            .checked_mul(1024 * 1024)
            .ok_or("payload budget overflow")?,
    )?)?;
    execution.enable_progress();
    let pool = sqlx::PgPool::connect(url).await?;
    require_fixture(&pool, root).await?;
    let store = Arc::new(PgBlobStore::connect_for_migration(url, root).await?);
    let mut reports = Vec::new();
    phase(
        "migrate_including_graph_and_finish_verification",
        &pool,
        async {
            migrate_storage_graphs_with_execution(
                &MigrationSettings::default(),
                store.clone(),
                CancellationToken::new(),
                &execution,
            )
            .await?;
            Ok(())
        },
        &mut reports,
    )
    .await?;
    phase(
        "standalone_verification",
        &pool,
        async {
            store
                .verify_storage_with_execution(CancellationToken::new(), &execution)
                .await?;
            Ok(())
        },
        &mut reports,
    )
    .await?;
    phase(
        "activation_including_verification",
        &pool,
        async {
            store
                .activate_storage_with_execution(CancellationToken::new(), &execution)
                .await?;
            Ok(())
        },
        &mut reports,
    )
    .await?;
    drop(store);
    let durable_fingerprint = phase(
        "startup_readback_and_durable_fingerprint",
        &pool,
        readback(url, root, &pool),
        &mut reports,
    )
    .await?;
    pool.close().await;
    let snapshot = execution.snapshot();
    if snapshot.active != 0 || snapshot.admitted != snapshot.completed {
        return Err("benchmark returned with unfinished work".into());
    }
    Ok(
        json!({"fixture":"pending-schema10-synthetic-v1","full_schema9_corpus":false,
        "workers":workers,"payload_budget_mib":budget_mib,"phases":reports,
        "durable_fingerprint":durable_fingerprint,"jobs_high_water":snapshot.high_water,
        "window_high_water":snapshot.window_high_water,"worker_wait_micros":snapshot.worker_wait_micros,
        "publication_micros":snapshot.publication_micros,"rss_note":"process high water, cumulative across phases; excludes PostgreSQL",
        "timing_note":"fixture generation excluded; warm cache, no host cache drop"}),
    )
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let command = args
        .first()
        .ok_or("usage: migration-benchmark prepare|run|check ROOT [OPTIONS]")?;
    let root = Path::new(args.get(1).ok_or("fixture root required")?);
    if !root.is_absolute()
        || !root.starts_with("/tmp")
        || root
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err("fixture root must be below /tmp".into());
    }
    let parent = root
        .parent()
        .ok_or("fixture parent required")?
        .canonicalize()?;
    if !parent.starts_with("/tmp") || parent == Path::new("/tmp") || root.is_symlink() {
        return Err("fixture requires an owned harness directory below /tmp".into());
    }
    let url = std::env::var("DEVRES_TEST_DATABASE_URL")?;
    let parsed = url::Url::parse(&url)?;
    let expected_database = if command == "check" {
        "/devres_benchmark_restored"
    } else {
        "/devres_benchmark"
    };
    if parsed.host_str() != Some("127.0.0.1") || parsed.path() != expected_database {
        return Err("benchmark only accepts its disposable loopback database".into());
    }
    let result = match command.as_str() {
        "prepare" => prepare(&url, root, &args[2..]).await?,
        "run" if args.len() <= 4 => {
            run(
                &url,
                root,
                count(args.get(2), 1, 64)?,
                count(args.get(3), 64, 4096)?,
            )
            .await?
        }
        "check" if args.len() == 2 => {
            let pool = sqlx::PgPool::connect(&url).await?;
            let digest = readback(&url, root, &pool).await?;
            pool.close().await;
            json!({"durable_fingerprint":digest,"restored_startup_readback":true})
        }
        _ => return Err("invalid benchmark command arguments".into()),
    };
    println!("{result}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires disposable PostgreSQL; never use a retained database"]
    async fn populated_database_is_rejected_without_root_creation_or_sql_changes() -> Result<()> {
        let base = std::env::var("DEVRES_TEST_DATABASE_URL")?;
        let admin = sqlx::PgPool::connect(&base).await?;
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let database = format!("devres_benchmark_guard_{suffix}");
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {database}")))
            .execute(&admin)
            .await?;
        let mut url = url::Url::parse(&base)?;
        url.set_path(&format!("/{database}"));
        let pool = sqlx::PgPool::connect(url.as_str()).await?;
        sqlx::raw_sql("CREATE TABLE sentinel(value text NOT NULL); INSERT INTO sentinel VALUES('must remain unchanged')")
            .execute(&pool).await?;
        let temporary = tempfile::tempdir_in("/tmp")?;
        let root = temporary.path().join("uncreated");
        let result = prepare(url.as_str(), &root, &[]).await;
        assert!(result.is_err());
        assert!(!root.exists(), "rejection precedes root creation");
        let sentinel: String = sqlx::query_scalar("SELECT value FROM sentinel")
            .fetch_one(&pool)
            .await?;
        assert_eq!(sentinel, "must remain unchanged");
        let relations: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'")
            .fetch_one(&pool).await?;
        assert_eq!(relations, 1, "no application schema was initialized");
        assert!(require_fixture(&pool, temporary.path()).await.is_err());
        std::fs::write(temporary.path().join(MARKER_FILE), FIXTURE_MARKER)?;
        assert!(
            require_fixture(&pool, temporary.path()).await.is_err(),
            "file marker alone cannot authorize a database"
        );
        sqlx::raw_sql("DROP TABLE sentinel; CREATE TABLE devres_benchmark_fixture(identity text); INSERT INTO devres_benchmark_fixture VALUES('wrong fixture')")
            .execute(&pool).await?;
        assert!(
            require_fixture(&pool, temporary.path()).await.is_err(),
            "mismatched SQL marker is rejected"
        );
        pool.close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP DATABASE {database} WITH (FORCE)"
        )))
        .execute(&admin)
        .await?;
        admin.close().await;
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires disposable PostgreSQL; never use a retained database"]
    async fn prepared_fixture_migrates_verifies_activates_and_reopens() -> Result<()> {
        let base = std::env::var("DEVRES_TEST_DATABASE_URL")?;
        let admin = sqlx::PgPool::connect(&base).await?;
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let database = format!("devres_benchmark_happy_{suffix}");
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {database}")))
            .execute(&admin)
            .await?;
        let mut url = url::Url::parse(&base)?;
        url.set_path(&format!("/{database}"));
        let temporary = tempfile::tempdir_in("/tmp")?;
        let root = temporary.path().join("blobs");
        let options = ["2", "1", "2", "1"].map(String::from);
        prepare(url.as_str(), &root, &options).await?;
        let report = run(url.as_str(), &root, 2, 64).await?;
        let phases = report["phases"]
            .as_array()
            .ok_or("missing benchmark phases")?;
        assert_eq!(
            phases.len(),
            4,
            "migration, verify, activation and startup all completed"
        );
        let pool = sqlx::PgPool::connect(url.as_str()).await?;
        let active: bool =
            sqlx::query_scalar("SELECT active FROM devres_integrity_control WHERE singleton")
                .fetch_one(&pool)
                .await?;
        assert!(active);
        let required_constraints: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_constraint WHERE conrelid='devres_rfc_jobs'::regclass AND conname='devres_rfc_capture_integrity_required'")
            .fetch_one(&pool).await?;
        assert_eq!(
            required_constraints, 1,
            "activation restored exactly one ordinary RFC integrity constraint"
        );
        let reopened = readback(url.as_str(), &root, &pool).await?;
        assert_eq!(
            report["durable_fingerprint"].as_str(),
            Some(reopened.as_str())
        );
        pool.close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP DATABASE {database} WITH (FORCE)"
        )))
        .execute(&admin)
        .await?;
        admin.close().await;
        Ok(())
    }
}
