//! Deterministic offline fixture timing, never a complete schema-nine corpus benchmark.
//! The shell harness owns the disposable database, and credentials enter through env.
use devres_adapters::{
    MigrationExecution, MigrationExecutionOptions, MigrationGraphOptions, MigrationSettings,
    PgBlobStore, migrate_storage_graphs_with_execution,
};
use devres_application::{
    Fetcher, Retrieval, Store,
    corpus::{Dataset, JobSpec, RfcCorpusStore, Snapshot},
};
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
const GRAPH_DOCUMENTS: usize = 32;

#[path = "migration-benchmark-crates.rs"]
mod crate_fixture;

struct OfflineOnly;
#[async_trait::async_trait]
impl Fetcher for OfflineOnly {
    async fn fetch(
        &self,
        _: &FetchRequest,
        _: Option<&Validators>,
    ) -> devres_domain::Result<FetchResponse> {
        Err(devres_domain::Error::integrity(
            "Benchmark attempted source acquisition.",
        ))
    }
}

fn fixture_kind(graph_snapshots: usize) -> &'static str {
    if graph_snapshots == 0 {
        "pending-schema10-synthetic-v1"
    } else {
        "pending-schema10-graph-v1"
    }
}

fn payload_seal(
    table: &str,
    kind: &str,
    key: &str,
    payload: &Value,
) -> devres_domain::Result<String> {
    devres_adapters::integrity::canonical_hash(
        &json!({"version":1,"namespace":table,"key":[kind,key],"payload":payload}),
    )
}

/// Build a real retained index through public offline maintenance; no provider is called.
async fn seed_graphs(
    store: &Arc<PgBlobStore>,
    pool: &sqlx::PgPool,
    root: &Path,
    snapshots: usize,
    generations: usize,
) -> Result<()> {
    let catalogue = store
        .publish(
            &FetchRequest {
                key: "rfc:index".into(),
                url: "https://www.rfc-editor.org/rfc-index.xml".into(),
                ttl_secs: 86400,
                max_bytes: 1024,
                media_type: "application/xml".into(),
            },
            FetchResponse {
                status: 200,
                body: b"<rfc-index/>".to_vec(),
                validators: Validators::default(),
            },
            1_700_000_000,
        )
        .await?;
    store.save_dataset("catalogue", &Dataset {
        capture:catalogue.capture.clone(),
        records:(1..=GRAPH_DOCUMENTS).map(|number| json!({"number":number,"title":format!("Synthetic RFC {number}"),"formats":["txt"]})).collect(),
    }).await?;
    for number in 1..=GRAPH_DOCUMENTS {
        let key = format!("rfc:text:{number}");
        let url = format!("https://www.rfc-editor.org/rfc/rfc{number}.txt");
        let text = format!(
            "RFC {number} migrationanchor secure transport clients negotiate reliable protocols. {}",
            "Bounded historical fixture text with immutable postings. ".repeat(512)
        );
        let captured = store
            .publish(
                &FetchRequest {
                    key: key.clone(),
                    url: url.clone(),
                    ttl_secs: 86400,
                    max_bytes: 65536,
                    media_type: "text/plain".into(),
                },
                FetchResponse {
                    status: 200,
                    body: text.into_bytes(),
                    validators: Validators::default(),
                },
                1_700_000_000,
            )
            .await?;
        store
            .schedule(&[JobSpec {
                key: key.clone(),
                number: number as u32,
                format: "txt".into(),
                source_url: url,
                assurance: "https".into(),
                due_at: 0,
            }])
            .await?;
        store
            .finish(&key, Some(&captured.capture), None, 1_700_086_400)
            .await?;
    }
    let retrieval = Arc::new(Retrieval::new(store.clone(), Arc::new(OfflineOnly)));
    let corpus =
        devres_adapters::RfcCorpus::new(retrieval, store.clone(), root, Default::default())?;
    let mut frozen = Vec::with_capacity(generations);
    for generation in 0..generations {
        if generation != 0 {
            let number = GRAPH_DOCUMENTS;
            let key = format!("rfc:text:{number}");
            let url = format!("https://www.rfc-editor.org/rfc/rfc{number}.txt");
            let text = format!(
                "RFC {number} migrationanchor secure transport clients negotiate reliable protocols generation{generation}. {}",
                "Bounded historical fixture text with immutable postings. ".repeat(512),
            );
            let captured = store
                .publish(
                    &FetchRequest {
                        key: key.clone(),
                        url,
                        ttl_secs: 86400,
                        max_bytes: 65536,
                        media_type: "text/plain".into(),
                    },
                    FetchResponse {
                        status: 200,
                        body: text.into_bytes(),
                        validators: Validators::default(),
                    },
                    1_700_000_000 + generation as i64,
                )
                .await?;
            store
                .finish(
                    &key,
                    Some(&captured.capture),
                    None,
                    1_700_086_400 + generation as i64,
                )
                .await?;
        }
        let built = corpus.rebuild_index().await?;
        let snapshot: Snapshot = store
            .snapshot(built["snapshot"].as_str())
            .await?
            .ok_or("source RFC snapshot missing")?;
        if snapshot.search_documents.len() != GRAPH_DOCUMENTS || snapshot.index_path.is_none() {
            return Err("source RFC index fixture has incomplete membership".into());
        }
        frozen.push(snapshot);
    }
    // Only disposable fixture state is converted into retained legacy evidence.
    sqlx::query("DELETE FROM devres_rfc_snapshots")
        .execute(pool)
        .await?;
    for ordinal in 0..snapshots {
        use sha2::{Digest, Sha256};
        let mut snapshot = frozen[ordinal % generations].clone();
        snapshot.id = hex::encode(Sha256::digest(format!("fixture-rfc-snapshot-{ordinal}")));
        snapshot.created_at = 1_700_000_000 + ordinal as i64;
        snapshot.complete = false;
        snapshot.coverage = json!({"synthetic":true,"documents":GRAPH_DOCUMENTS,"ordinal":ordinal});
        let order: i64 = sqlx::query_scalar(
            "SELECT nextval(pg_get_serial_sequence('devres_rfc_snapshots','published_order'))",
        )
        .fetch_one(pool)
        .await?;
        let data = serde_json::to_value(&snapshot)?;
        let payload = json!({"published_order":order,"catalogue_capture":snapshot.catalogue_capture,"errata_capture":snapshot.errata_capture,"created_at":snapshot.created_at,"complete":snapshot.complete,"data":data});
        sqlx::query("INSERT INTO devres_rfc_snapshots(id,catalogue_capture,errata_capture,data,created_at,complete,published_order,data_integrity) OVERRIDING SYSTEM VALUE VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(&snapshot.id).bind(&snapshot.catalogue_capture).bind(&snapshot.errata_capture).bind(sqlx::types::Json(&data))
            .bind(snapshot.created_at).bind(snapshot.complete).bind(order).bind(payload_seal("devres_rfc_snapshots","",&snapshot.id,&payload)?).execute(pool).await?;
    }
    // Independent provider lanes with retained evidence exercise cross-provider scheduling.
    for (table, kind) in [
        ("devres_npm_evidence", "failures"),
        ("devres_advisory_rows", "legacy-gaps"),
    ] {
        for ordinal in 0..snapshots * 4 {
            let key = format!("fixture-graph-{ordinal:08}");
            let data = json!({"synthetic":true,"ordinal":ordinal,"payload":"public graph work ".repeat(4096)});
            let sequence: i64 =
                sqlx::query_scalar("SELECT nextval(pg_get_serial_sequence($1,'sequence'))")
                    .bind(table)
                    .fetch_one(pool)
                    .await?;
            let sequence_seal = devres_adapters::integrity::canonical_hash(
                &json!({"version":1,"namespace":table,"kind":kind,"key":key,"sequence":sequence}),
            )?;
            sqlx::query(sqlx::AssertSqlSafe(format!("INSERT INTO {table}(sequence,kind,key,data,data_integrity,sequence_integrity) OVERRIDING SYSTEM VALUE VALUES($1,$2,$3,$4,$5,$6)")))
                .bind(sequence).bind(kind).bind(&key).bind(sqlx::types::Json(&data)).bind(payload_seal(table,kind,&key,&data)?).bind(sequence_seal).execute(pool).await?;
        }
    }
    Ok(())
}

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
    let graph_snapshots = args
        .get(4)
        .map(|value| value.parse::<usize>())
        .transpose()?
        .unwrap_or(0);
    if graph_snapshots > 64 {
        return Err("graph snapshots exceed their bounded range".into());
    }
    let graph_generations = count(args.get(5), 1, 64)?;
    if (graph_snapshots == 0 && graph_generations != 1)
        || (graph_snapshots > 0 && graph_generations > graph_snapshots)
    {
        return Err("graph generations must fit enabled graph snapshots".into());
    }
    let crate_artifacts = args
        .get(6)
        .map(|value| count(Some(value), 16384, 16384))
        .transpose()?
        .unwrap_or(0);
    let crate_staging_rows = count(args.get(7), 1024, 16384)?;
    if crate_artifacts > 0 && graph_snapshots > 0 {
        return Err("crate and RFC benchmark profiles cannot be mixed".into());
    }
    if root.exists() || args.len() > 8 {
        return Err("prepare requires a new fixture root and bounded arguments".into());
    }
    let pool = sqlx::PgPool::connect(url).await?;
    require_empty_database(&pool).await?;
    std::fs::create_dir(root)?;
    let store = Arc::new(PgBlobStore::connect(url, root).await?);
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
    if graph_snapshots > 0 {
        seed_graphs(&store, &pool, root, graph_snapshots, graph_generations).await?;
    }
    if crate_artifacts > 0 {
        crate_fixture::seed(&pool, root, crate_artifacts, crate_staging_rows).await?;
    }
    drop(store);
    // Only the harness's fresh database is converted to pending qualification.
    // Empty provider graphs still traverse the real replay/activation gates.
    // Fresh initialization installed the final RFC constraint already; remove
    // it only in this disposable conversion so activation installs it normally.
    sqlx::raw_sql("UPDATE devres_integrity_control SET active=false,files_complete=false,sql_complete=false,graph_complete=false; DELETE FROM devres_integrity_graph_progress; ALTER TABLE devres_advisory_records ALTER COLUMN data_integrity DROP NOT NULL; ALTER TABLE devres_rfc_jobs DROP CONSTRAINT devres_rfc_capture_integrity_required;")
        .execute(&pool).await?;
    if graph_snapshots > 0 || crate_artifacts > 0 {
        sqlx::query("DELETE FROM devres_integrity_provider_cutoffs")
            .execute(&pool)
            .await?;
    }
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
        json!({"fixture":if crate_artifacts > 0 { crate_fixture::KIND } else {fixture_kind(graph_snapshots)},"full_schema9_corpus":false,"durable_before_timing":true,
        "rows":rows,"payload_kib":payload_kib,"files":files,"file_mib":file_mib,
        "capture":capture.capture.id,"seed_outside_timing":true,"crate_artifacts":crate_artifacts,"crate_staging_rows_per_inventory":if crate_artifacts>0 {crate_staging_rows}else{0},"graph_snapshots":graph_snapshots,"graph_generations":graph_generations,"rfc_index_documents":if graph_snapshots>0 {GRAPH_DOCUMENTS}else{0}}),
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

fn open_file_descriptors() -> Result<usize> {
    let mut count = 0_usize;
    for entry in std::fs::read_dir("/proc/self/fd")? {
        entry?;
        count = count.checked_add(1).ok_or("descriptor count overflow")?;
    }
    Ok(count)
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
    let mut sampled_fd_high_water = open_file_descriptors()?;
    let mut sampling = tokio::time::interval(std::time::Duration::from_millis(10));
    sampling.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    tokio::pin!(work);
    let result = loop {
        tokio::select! {
            biased;
            result = &mut work => break result?,
            _ = sampling.tick() => {
                sampled_fd_high_water = sampled_fd_high_water.max(open_file_descriptors()?);
            }
        }
    };
    sampled_fd_high_water = sampled_fd_high_water.max(open_file_descriptors()?);
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
        "wal_bytes":delta("wal_position_bytes"),"sampled_fd_high_water":sampled_fd_high_water,"process_rss_high_water_kib":after["rss_high_water_kib"]}));
    Ok(result)
}

async fn fingerprint(pool: &sqlx::PgPool, root: &Path) -> Result<String> {
    use futures::TryStreamExt;
    let graph_fixture: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM devres_rfc_snapshots)")
            .fetch_one(pool)
            .await?;
    let mut digest = blake3::Hasher::new();
    digest.update(b"devres:synthetic-migration-fingerprint:v1\0");
    // Compare all retained fixture SQL evidence, excluding physical tuple IDs,
    // connection statistics and execution timing. Table/row ordering is explicit.
    let mut tables = vec![
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
    ];
    if crate_fixture::artifact_count(pool).await? > 0 {
        tables.extend(crate_fixture::TABLES);
    }
    if graph_fixture {
        tables.extend([
            "devres_rfc_datasets",
            "devres_rfc_dataset_heads",
            "devres_rfc_jobs",
            "devres_rfc_snapshots",
            "devres_npm_evidence",
            "devres_advisory_rows",
        ]);
    }
    if crate_fixture::artifact_count(pool).await? > 0 {
        let sequences: Vec<String> = sqlx::query_scalar("SELECT jsonb_build_object('name',sequencename,'last_value',last_value)::text FROM pg_sequences WHERE schemaname='public' AND starts_with(sequencename,'devres_crate_') ORDER BY sequencename").fetch_all(pool).await?;
        digest.update(b"crate-sequence-state");
        for sequence in sequences {
            digest.update(sequence.as_bytes());
        }
    }
    for table in tables {
        digest.update(table.as_bytes());
        // Tantivy segment UUIDs and the fixture's original unique build directory
        // are physical artifacts. Full verification checks them; compare frozen
        // manifests, rows and public query semantics independently of their names.
        let query = if graph_fixture && table == "devres_rfc_snapshots" {
            "SELECT ((to_jsonb(t)-'data_integrity') || jsonb_build_object('data',data-'index_path'))::text AS data FROM devres_rfc_snapshots t ORDER BY published_order".into()
        } else if graph_fixture && table == "devres_integrity_files" {
            "SELECT to_jsonb(t)::text AS data FROM devres_integrity_files t WHERE path NOT LIKE 'rfc-indexes/%' ORDER BY path".into()
        } else {
            format!("SELECT to_jsonb(t)::text AS data FROM {table} t ORDER BY to_jsonb(t)::text")
        };
        let mut rows = sqlx::query(sqlx::AssertSqlSafe(query)).fetch(pool);
        while let Some(row) = rows.try_next().await? {
            let data: String = row.try_get("data")?;
            digest.update(&(data.len() as u64).to_le_bytes());
            digest.update(data.as_bytes());
        }
    }
    fn visit(
        root: &Path,
        current: &Path,
        digest: &mut blake3::Hasher,
        graph_fixture: bool,
    ) -> Result<()> {
        use std::io::Read;
        let mut entries = std::fs::read_dir(current)?.collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let kind = entry.file_type()?;
            if kind.is_symlink() {
                return Err("unexpected fixture symlink".into());
            }
            if kind.is_dir() {
                if graph_fixture
                    && current == root
                    && matches!(entry.file_name().to_str(), Some("rfc-indexes"))
                {
                    continue;
                }
                visit(root, &entry.path(), digest, graph_fixture)?;
            } else if kind.is_file() {
                if entry.file_name().to_string_lossy().starts_with(".stage-") {
                    return Err("unpublished fixture stage remained".into());
                }
                let path = entry.path();
                if graph_fixture && path.starts_with(root.join(".devres-integrity/files")) {
                    if entry.metadata()?.len() > 16 * 1024 {
                        return Err("fixture integrity descriptor exceeds its bound".into());
                    }
                    let evidence: devres_adapters::integrity::FileEvidence =
                        serde_json::from_slice(&std::fs::read(&path)?)?;
                    // Only nondeterministic physical index descriptors normalize out.
                    // Raw capture/file descriptors remain permanent fingerprint evidence.
                    if evidence.path.starts_with("rfc-indexes/") {
                        continue;
                    }
                }
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
    visit(root, root, &mut digest, graph_fixture)?;
    Ok(digest.finalize().to_hex().to_string())
}

async fn readback(url: &str, root: &Path, pool: &sqlx::PgPool) -> Result<String> {
    require_fixture(pool, root).await?;
    let store = Arc::new(PgBlobStore::connect(url, root).await?);
    store.check_health().await?;
    let id: String = sqlx::query_scalar("SELECT capture_id FROM devres_heads WHERE source_key=$1")
        .bind(KEY)
        .fetch_one(pool)
        .await?;
    if store.capture(&id).await?.body.as_ref() != BODY {
        return Err("retained capture mismatch".into());
    }
    crate_fixture::readback(&store, pool).await?;
    let durable = fingerprint(pool, root).await?;
    let snapshots: Vec<String> =
        sqlx::query_scalar("SELECT id FROM devres_rfc_snapshots ORDER BY published_order")
            .fetch_all(pool)
            .await?;
    if snapshots.is_empty() {
        return Ok(durable);
    }
    let retrieval = Arc::new(Retrieval::new(store.clone(), Arc::new(OfflineOnly)));
    let corpus = Arc::new(devres_adapters::RfcCorpus::new(
        retrieval.clone(),
        store,
        root,
        Default::default(),
    )?);
    let research = devres_adapters::Research::new(retrieval)
        .await?
        .with_corpus(corpus);
    let mut digest = blake3::Hasher::new();
    digest.update(durable.as_bytes());
    for snapshot in snapshots {
        for (query, mode) in [("migrationanchor", "technical"), ("clients", "english")] {
            let result = research
                .call(
                    "rfc.fulltext_search",
                    json!({"query":query,"mode":mode,"snapshot":snapshot,"limit":100}),
                )
                .await?;
            if result["total"] != GRAPH_DOCUMENTS as u64 {
                return Err("RFC graph readback changed retained searchable membership".into());
            }
            digest.update(&serde_json::to_vec(&result)?);
        }
    }
    Ok(digest.finalize().to_hex().to_string())
}

async fn run(
    url: &str,
    root: &Path,
    workers: usize,
    budget_mib: usize,
    graph_budget_mib: usize,
) -> Result<Value> {
    let execution = MigrationExecution::new_with_graph_options(
        MigrationExecutionOptions::new(
            workers,
            budget_mib
                .checked_mul(1024 * 1024)
                .ok_or("payload budget overflow")?,
        )?,
        MigrationGraphOptions::new(
            graph_budget_mib
                .checked_mul(1024 * 1024)
                .ok_or("graph budget overflow")?,
        )?,
    )?;
    execution.enable_progress();
    let pool = sqlx::PgPool::connect(url).await?;
    require_fixture(&pool, root).await?;
    let graph_snapshots: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM devres_rfc_snapshots WHERE id NOT LIKE 'blake3:%'",
    )
    .fetch_one(&pool)
    .await?;
    let graph_generations: i64 = sqlx::query_scalar(
        "SELECT count(DISTINCT data->>'index_path') FROM devres_rfc_snapshots WHERE id NOT LIKE 'blake3:%'",
    ).fetch_one(&pool).await?;
    let crate_artifacts = crate_fixture::artifact_count(&pool).await?;
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
    if snapshot.active != 0
        || snapshot.admitted != snapshot.completed
        || snapshot.graph_active != 0
        || snapshot.graph_memory_bytes != 0
        || snapshot.graph_admitted != snapshot.graph_completed
    {
        return Err("benchmark returned with unfinished work".into());
    }
    Ok(
        json!({"fixture":if crate_artifacts > 0 {crate_fixture::KIND}else{fixture_kind(graph_snapshots as usize)},"full_schema9_corpus":false,
        "workers":workers,"payload_budget_mib":budget_mib,"phases":reports,
        "crate_artifacts":crate_artifacts,"crate_phase_micros":execution.phase_timings(),
        "durable_fingerprint":durable_fingerprint,"jobs_high_water":snapshot.high_water,
        "window_high_water":snapshot.window_high_water,"worker_wait_micros":snapshot.worker_wait_micros,
        "publication_micros":snapshot.publication_micros,
        "graph_memory_budget_mib":graph_budget_mib,"graph_snapshots":graph_snapshots,"graph_generations":graph_generations.max(1),
        "graph_jobs_high_water":snapshot.graph_high_water,"graph_jobs_admitted":snapshot.graph_admitted,
        "graph_memory_high_water":snapshot.graph_memory_high_water,
        "fingerprint_kind":if graph_snapshots>0 {"logical SQL, non-index file bytes and full RFC query results; physical index files independently verified"}else{"logical SQL and all retained file bytes"},
        "rss_note":"process high water, cumulative across phases; excludes PostgreSQL",
        "fd_note":"10 ms sampled process descriptor high water; includes sampler directory; excludes PostgreSQL",
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
        "prepare-crates" if args.len() <= 4 => {
            let artifacts = count(args.get(2), 16384, 16384)?;
            let staging = count(args.get(3), 1024, 16384)?;
            let options = [
                "2".into(),
                "1".into(),
                "2".into(),
                "1".into(),
                "0".into(),
                "1".into(),
                artifacts.to_string(),
                staging.to_string(),
            ];
            prepare(&url, root, &options).await?
        }
        "run" if args.len() <= 5 => {
            run(
                &url,
                root,
                count(args.get(2), 1, 64)?,
                count(args.get(3), 64, 4096)?,
                count(args.get(4), 1024, 65536)?,
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
        let report = run(url.as_str(), &root, 2, 64, 1024).await?;
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

    #[tokio::test]
    #[ignore = "requires disposable PostgreSQL; real frozen-index replay, no provider traffic"]
    async fn graph_fixture_has_serial_parallel_semantic_parity_and_bounded_work() -> Result<()> {
        let base = std::env::var("DEVRES_TEST_DATABASE_URL")?;
        let admin = sqlx::PgPool::connect(&base).await?;
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let mut baseline = None;
        for workers in [1, 2] {
            let database = format!("devres_benchmark_graph_{suffix}_{workers}");
            sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {database}")))
                .execute(&admin)
                .await?;
            let mut url = url::Url::parse(&base)?;
            url.set_path(&format!("/{database}"));
            let temporary = tempfile::tempdir_in("/tmp")?;
            let root = temporary.path().join("blobs");
            prepare(
                url.as_str(),
                &root,
                &["2", "1", "2", "1", "4", "2"].map(String::from),
            )
            .await?;
            let report = run(url.as_str(), &root, workers, 64, 1024).await?;
            assert_eq!(report["fixture"], "pending-schema10-graph-v1");
            assert_eq!(report["graph_snapshots"], 4);
            assert_eq!(report["graph_generations"], 2);
            assert!(
                report["phases"]
                    .as_array()
                    .ok_or("missing phases")?
                    .iter()
                    .all(|phase| phase["sampled_fd_high_water"]
                        .as_u64()
                        .is_some_and(|count| count > 0))
            );
            assert!(report["graph_jobs_admitted"].as_u64().unwrap_or(0) >= 4);
            let high_water = report["graph_jobs_high_water"]
                .as_u64()
                .ok_or("missing graph concurrency evidence")?;
            assert!(high_water >= 1 && high_water <= workers as u64);
            if workers > 1 {
                assert!(
                    high_water > 1,
                    "graph fixture must execute actual overlapping units"
                );
            }
            assert!(
                report["graph_memory_high_water"]
                    .as_u64()
                    .ok_or("missing graph memory evidence")?
                    <= 1024 * 1024 * 1024
            );
            if let Some(expected) = &baseline {
                assert_eq!(&report["durable_fingerprint"], expected);
            } else {
                baseline = Some(report["durable_fingerprint"].clone());
            }
            let pool = sqlx::PgPool::connect(url.as_str()).await?;
            let verified = fingerprint(&pool, &root).await?;
            let body: String = sqlx::query_scalar("SELECT c.body_hash FROM devres_captures c JOIN devres_heads h ON h.capture_id=c.id WHERE h.source_key='rfc:text:1'")
                .fetch_one(&pool).await?;
            let descriptor = devres_adapters::integrity::evidence_path(
                &root,
                &root.join(devres_adapters::integrity::relative_path(&body)?),
            )?;
            let original = std::fs::read(&descriptor)?;
            std::fs::remove_file(&descriptor)?;
            assert_ne!(
                fingerprint(&pool, &root).await?,
                verified,
                "loss of an unselected raw capture descriptor must change graph evidence"
            );
            std::fs::write(&descriptor, original)?;
            assert_eq!(fingerprint(&pool, &root).await?, verified);
            sqlx::query("DELETE FROM devres_rfc_dataset_heads WHERE kind='catalogue'")
                .execute(&pool)
                .await?;
            assert_ne!(
                fingerprint(&pool, &root).await?,
                verified,
                "catalogue head selection is durable graph evidence"
            );
            pool.close().await;
            sqlx::query(sqlx::AssertSqlSafe(format!(
                "DROP DATABASE {database} WITH (FORCE)"
            )))
            .execute(&admin)
            .await?;
        }
        admin.close().await;
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires disposable PostgreSQL; real retained crate replay, no provider traffic"]
    async fn crate_fixture_has_serial_parallel_parity_and_detects_lost_receipts() -> Result<()> {
        let base = std::env::var("DEVRES_TEST_DATABASE_URL")?;
        let admin = sqlx::PgPool::connect(&base).await?;
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let mut expected = None;
        for workers in [1, 2] {
            let database = format!("devres_benchmark_crate_{suffix}_{workers}");
            sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {database}")))
                .execute(&admin)
                .await?;
            let mut url = url::Url::parse(&base)?;
            url.set_path(&format!("/{database}"));
            let temporary = tempfile::tempdir_in("/tmp")?;
            let root = temporary.path().join("blobs");
            prepare(
                url.as_str(),
                &root,
                &["2", "1", "2", "1", "0", "1", "129", "129"].map(String::from),
            )
            .await?;
            let result = run(url.as_str(), &root, workers, 64, 1024).await?;
            assert_eq!(result["fixture"], crate_fixture::KIND);
            assert_eq!(result["crate_artifacts"], 129);
            assert!(
                result["crate_phase_micros"]["graph_crate_artifacts"]
                    .as_u64()
                    .is_some_and(|n| n > 0)
            );
            if let Some(expected) = &expected {
                assert_eq!(&result["durable_fingerprint"], expected);
            } else {
                expected = Some(result["durable_fingerprint"].clone());
            }
            let pool = sqlx::PgPool::connect(url.as_str()).await?;
            assert_eq!(
                readback(url.as_str(), &root, &pool).await?,
                result["durable_fingerprint"]
                    .as_str()
                    .ok_or("missing fingerprint")?
            );
            let original = fingerprint(&pool, &root).await?;
            sqlx::query("DELETE FROM devres_integrity_staged_state WHERE provider='crate' AND key=(SELECT min(key) FROM devres_integrity_staged_state WHERE provider='crate' AND key LIKE 'observation:%')").execute(&pool).await?;
            assert_ne!(
                fingerprint(&pool, &root).await?,
                original,
                "receipt membership is durable evidence"
            );
            let store = Arc::new(PgBlobStore::connect(url.as_str(), &root).await?);
            assert!(
                crate_fixture::readback(&store, &pool).await.is_err(),
                "readback must reject a lost occurrence receipt"
            );
            drop(store);
            pool.close().await;
            sqlx::query(sqlx::AssertSqlSafe(format!(
                "DROP DATABASE {database} WITH (FORCE)"
            )))
            .execute(&admin)
            .await?;
        }
        admin.close().await;
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires disposable PostgreSQL; opt-in aggregate crate publication diagnostics"]
    async fn crate_fixture_graph_only_publication_diagnostics() -> Result<()> {
        let artifacts = match std::env::var("DEVRES_DIAGNOSTIC_CRATE_ARTIFACTS") {
            Ok(value) => count(Some(&value), 129, 16384)?,
            Err(std::env::VarError::NotPresent) => 129,
            Err(error) => return Err(error.into()),
        };
        let staging = if artifacts > 129 { 4096 } else { 129 };
        let base = std::env::var("DEVRES_TEST_DATABASE_URL")?;
        let admin = sqlx::PgPool::connect(&base).await?;
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let database = format!("devres_crate_diagnostic_{suffix}");
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {database}")))
            .execute(&admin)
            .await?;
        let result: Result<_> = async {
            let mut url = url::Url::parse(&base)?;
            url.set_path(&format!("/{database}"));
            let temporary = tempfile::tempdir_in("/tmp")?;
            let root = temporary.path().join("blobs");
            prepare(
                url.as_str(),
                &root,
                &[
                    "2".into(),
                    "1".into(),
                    "2".into(),
                    "1".into(),
                    "0".into(),
                    "1".into(),
                    artifacts.to_string(),
                    staging.to_string(),
                ],
            )
            .await?;
            let execution = MigrationExecution::new_with_graph_options(
                MigrationExecutionOptions::new(8, 64 * 1024 * 1024)?,
                MigrationGraphOptions::new(1024 * 1024 * 1024)?,
            )?;
            execution.enable_progress();
            let token = CancellationToken::new();
            let store = Arc::new(PgBlobStore::connect_for_migration(url.as_str(), &root).await?);
            store
                .migrate_storage_with_execution(token.clone(), &execution)
                .await?;
            let mut mappings = store.migration_mappings().await?;
            let aliases = store
                .migrate_crate_graph_with_execution(&mut mappings, token, &execution)
                .await?;
            aliases.ensure_healthy()?;
            mappings.ensure_healthy()?;
            let pool = sqlx::PgPool::connect(url.as_str()).await?;
            let canonical: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM devres_crate_artifacts WHERE capture_id LIKE 'blake3:%'",
            )
            .fetch_one(&pool)
            .await?;
            let active: bool =
                sqlx::query_scalar("SELECT active FROM devres_integrity_control WHERE singleton")
                    .fetch_one(&pool)
                    .await?;
            let counters = execution.snapshot();
            let report = json!({"event":"crate_publication_diagnostic", "artifacts":artifacts,
                "staging_rows_per_inventory":staging,"workers":8,
                "canonical_artifacts":canonical,"active":active,
                "phase_micros":execution.phase_timings(),
                "jobs_admitted":counters.admitted,"jobs_completed":counters.completed,
                "jobs_active":counters.active,"jobs_high_water":counters.high_water,
                "graph_jobs_admitted":counters.graph_admitted,
                "graph_jobs_completed":counters.graph_completed,
                "graph_jobs_active":counters.graph_active,
                "graph_jobs_high_water":counters.graph_high_water,
                "graph_memory_bytes":counters.graph_memory_bytes,
                "graph_memory_high_water":counters.graph_memory_high_water});
            drop(aliases);
            drop(mappings);
            drop(store);
            pool.close().await;
            Ok((canonical, active, counters, report))
        }
        .await;
        // This test creates exactly one fresh database. Clean it even when an
        // ordinary migration error occurs; never touch the caller's base database.
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP DATABASE {database} WITH (FORCE)"
        )))
        .execute(&admin)
        .await?;
        admin.close().await;
        let (canonical, active, counters, report) = result?;
        assert_eq!(canonical, artifacts as i64);
        assert!(!active, "graph-only diagnosis must not activate storage");
        assert_eq!(counters.active, 0);
        assert_eq!(counters.admitted, counters.completed);
        assert_eq!(counters.graph_active, 0);
        assert_eq!(counters.graph_admitted, counters.graph_completed);
        assert_eq!(counters.graph_memory_bytes, 0);
        assert!(counters.high_water <= 8 && counters.graph_high_water <= 8);
        assert!(counters.graph_memory_high_water <= 1024 * 1024 * 1024);
        println!("{report}");
        Ok(())
    }
}
