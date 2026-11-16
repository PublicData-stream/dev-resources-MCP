//! SELECT-only observation reuses active source identities and verified origin traversal.
use super::*;
use devres_application::attribution_observation::{
    AttributionObservationSession, AttributionObservationStore, ObservationCounts, ObservationPage,
};
use sqlx_core::transaction::Transaction;
use sqlx_postgres::Postgres;
use std::collections::BTreeMap;

struct SourceScan {
    provider: &'static str,
    source: Source,
    after: String,
    cutoff: String,
}
enum Scan {
    Source(SourceScan),
    Origins(&'static str, origins::ObservationOrigins),
}
struct Lane {
    scan: Scan,
    complete: bool,
}
struct Session {
    tx: Transaction<'static, Postgres>,
    lanes: Vec<Lane>,
    next: usize,
}

/// Internal binding only: never exposed in public responses or diagnostics.
async fn binding(conn: &mut PgConnection) -> Result<String> {
    verify_control(conn).await?;
    let value: Json<Value> = sqlx_core::query_scalar::query_scalar(
        "SELECT jsonb_build_object('schema',(SELECT to_jsonb(s) FROM devres_schema s WHERE singleton),'active',(SELECT active FROM devres_integrity_control WHERE singleton),'restore_pending',to_regclass('public.devres_archive_restore_pending') IS NOT NULL,'policy',(SELECT to_jsonb(p) FROM devres_attribution_control p WHERE singleton),'archive',(SELECT jsonb_build_object('epoch',epoch,'binding',binding,'backend',backend,'pending_binding',pending_binding,'initializing_s3',initializing_s3) FROM devres_archive_control WHERE singleton),'cutoffs',(SELECT jsonb_agg(to_jsonb(c) ORDER BY provider) FROM (SELECT provider,legacy_cutoff,cutoff_integrity FROM devres_integrity_provider_cutoffs ORDER BY provider LIMIT 11) c),'visibility',(SELECT jsonb_agg(to_jsonb(g) ORDER BY provider) FROM (SELECT provider,complete,aliases_count,aliases_digest,progress_integrity FROM devres_integrity_graph_progress ORDER BY provider LIMIT 12) g))"
    ).fetch_one(conn).await.map_err(source_error)?;
    if value.0["active"] != true || value.0["restore_pending"] != false {
        return Err(Error::unavailable(
            "Attribution observation storage changed.",
        ));
    }
    crate::integrity::canonical_hash(&value.0)
}

#[async_trait]
impl AttributionObservationStore for PgBlobStore {
    async fn begin_observation(&self) -> Result<(String, Box<dyn AttributionObservationSession>)> {
        if !self.is_reader() {
            return Err(Error::unavailable(
                "Attribution observation requires reader storage.",
            ));
        }
        self.fence().await?;
        let mut tx = self.pool.begin().await.map_err(source_error)?;
        sqlx_core::raw_sql::raw_sql("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY; SET LOCAL statement_timeout='2s'; SET LOCAL lock_timeout='250ms'")
            .execute(&mut *tx).await.map_err(source_error)?;
        let selected_binding = binding(&mut tx).await?;
        let mut lanes = Vec::new();
        for &provider in PROVIDERS {
            for source in sources(provider)? {
                let cursor = source.cursor();
                let base = format!(
                    "SELECT {} FROM {} t WHERE {}",
                    source.select, source.table, source.filter
                );
                let sql = format!(
                    "SELECT {} FROM ({base}) s ORDER BY {} LIMIT 1",
                    cursor.position(),
                    cursor.order(true)
                );
                let cutoff = sqlx_core::query_scalar::query_scalar::<_, String>(
                    sqlx_core::sql_str::AssertSqlSafe(sql),
                )
                .fetch_optional(&mut *tx)
                .await
                .map_err(source_error)?
                .unwrap_or_else(|| cursor.initial());
                lanes.push(Lane {
                    scan: Scan::Source(SourceScan {
                        provider,
                        source,
                        after: cursor.initial(),
                        cutoff,
                    }),
                    complete: false,
                });
            }
            if origins::supports(provider) {
                lanes.push(Lane {
                    scan: Scan::Origins(
                        provider,
                        origins::ObservationOrigins::new(&mut tx, provider).await?,
                    ),
                    complete: false,
                });
            }
        }
        Ok((selected_binding, Box::new(Session { tx, lanes, next: 0 })))
    }
    async fn validate_observation(&self, expected: &str) -> Result<()> {
        if !self.is_reader() {
            return Err(Error::unavailable(
                "Attribution observation requires reader storage.",
            ));
        }
        self.fence().await?;
        let mut conn = self.pool.acquire().await.map_err(source_error)?;
        let current = binding(&mut conn).await?;
        if current != expected {
            return Err(Error::unavailable(
                "Attribution observation binding changed.",
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl AttributionObservationSession for Session {
    async fn next_page(&mut self) -> Result<ObservationPage> {
        let mut counts = BTreeMap::<String, ObservationCounts>::new();
        let total = self.lanes.len();
        for _ in 0..total {
            let index = self.next;
            self.next = (self.next + 1) % total;
            let lane = &mut self.lanes[index];
            if lane.complete {
                continue;
            }
            match &mut lane.scan {
                Scan::Source(scan) => {
                    let (targets, complete) = source_page(&mut self.tx, scan).await?;
                    for target in targets {
                        observe_target(&mut self.tx, &target, &mut counts).await?;
                    }
                    lane.complete = complete;
                }
                Scan::Origins(provider, scan) => {
                    let (targets, gaps, complete) = scan.page(&mut self.tx, provider).await?;
                    counts
                        .entry((*provider).to_owned())
                        .or_default()
                        .origin_gaps = gaps;
                    for target in targets {
                        observe_target(&mut self.tx, &target, &mut counts).await?;
                    }
                    lane.complete = complete;
                }
            }
            break;
        }
        Ok(ObservationPage {
            counts,
            complete: self.lanes.iter().all(|lane| lane.complete),
        })
    }
}

async fn source_page(
    conn: &mut PgConnection,
    scan: &mut SourceScan,
) -> Result<(Vec<AttributionTarget>, bool)> {
    let source = &scan.source;
    let cursor = source.cursor();
    let base = format!(
        "SELECT {} FROM {} t WHERE {}",
        source.select, source.table, source.filter
    );
    let sql = format!(
        "SELECT {} FROM ({base}) s WHERE {} AND {} ORDER BY {} LIMIT {PAGE}",
        cursor.position(),
        cursor.comparison(">", 1),
        cursor.comparison("<=", 2),
        cursor.order(false)
    );
    let positions =
        sqlx_core::query_scalar::query_scalar::<_, String>(sqlx_core::sql_str::AssertSqlSafe(sql))
            .bind(&scan.after)
            .bind(&scan.cutoff)
            .fetch_all(&mut *conn)
            .await
            .map_err(source_error)?;
    let complete = positions.is_empty();
    let mut output = Vec::new();
    let mut bytes = 0_usize;
    let started = std::time::Instant::now();
    for position in positions {
        if !output.is_empty() && started.elapsed() >= std::time::Duration::from_secs(1) {
            break;
        }
        let exact = cursor.comparison("=", 1);
        let sql =
            format!("SELECT octet_length(to_jsonb(s)::text)::bigint FROM ({base}) s WHERE {exact}");
        let charge = usize::try_from(
            sqlx_core::query_scalar::query_scalar::<_, i64>(sqlx_core::sql_str::AssertSqlSafe(sql))
                .bind(&position)
                .fetch_one(&mut *conn)
                .await
                .map_err(source_error)?,
        )
        .map_err(|_| invalid())?;
        if charge > 64 * 1024 * 1024 {
            return Err(Error::capacity(
                "Retained source exceeds the supported decoder bound.",
            ));
        }
        if bytes.saturating_add(charge) > MAX_VALUE && !output.is_empty() {
            break;
        }
        let sql = format!("SELECT * FROM ({base}) s WHERE {exact}");
        let row = sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(sql))
            .bind(&position)
            .fetch_one(&mut *conn)
            .await
            .map_err(source_error)?;
        output.push(candidate(
            scan.provider,
            source.table,
            &row,
            charge > MAX_VALUE,
        )?);
        bytes = bytes.saturating_add(charge);
        scan.after = position;
    }
    Ok((output, complete))
}

async fn observe_target(
    conn: &mut PgConnection,
    target: &AttributionTarget,
    counts: &mut BTreeMap<String, ObservationCounts>,
) -> Result<()> {
    checked_target(target)?;
    origins::verify_target(conn, target).await?;
    let observed = counts.entry(target.subject.provider.clone()).or_default();
    observed.examined = observed.examined.saturating_add(1);
    let row = admitted_attribution_row(conn, TABLE_TARGETS, &target_id(&target.subject)?).await?;
    let mut ready = false;
    if let Some(row) = row {
        let state = state(&row)?;
        if state.target != *target {
            return Err(invalid());
        }
        if let Some(id) = state.generation {
            let row = admitted_attribution_row(conn, TABLE_GENERATIONS, &id)
                .await?
                .ok_or_else(invalid)?;
            let value = qualified(&row)?;
            ready = value.generation.subject == target.subject
                && value.generation.policy_epoch == ATTRIBUTION_POLICY_EPOCH
                && value.generation.policy_fingerprint == ATTRIBUTION_POLICY_FINGERPRINT
                && !value.generation.notices.is_empty()
                && !value.generation.receipts.is_empty();
        }
    }
    if ready {
        observed.ready = observed.ready.saturating_add(1);
    } else {
        observed.unqualified = observed.unqualified.saturating_add(1);
    }
    Ok(())
}

/// Admit scalar byte counts before PostgreSQL sends an untrusted JSON row.
/// Both admission and materialization use the session's same MVCC snapshot.
async fn admitted_attribution_row(
    conn: &mut PgConnection,
    table: &'static str,
    id: &str,
) -> Result<Option<PgRow>> {
    if !matches!(table, TABLE_TARGETS | TABLE_GENERATIONS) {
        return Err(invalid());
    }
    let sql = format!(
        "SELECT octet_length(data::text)::bigint,octet_length(to_jsonb(t)::text)::bigint FROM {table} t WHERE id=$1"
    );
    let size: Option<(i64, i64)> =
        sqlx_core::query_as::query_as(sqlx_core::sql_str::AssertSqlSafe(sql))
            .bind(id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(source_error)?;
    let Some((data_bytes, row_bytes)) = size else {
        return Ok(None);
    };
    // Extra metadata has its own fixed allowance; it cannot hide a large field
    // in a column other than data and bypass the payload decoder's limit.
    const ROW_BYTES: usize = MAX_VALUE + 64 * 1024;
    if !(0..=MAX_VALUE as i64).contains(&data_bytes) || !(0..=ROW_BYTES as i64).contains(&row_bytes)
    {
        return Err(Error::capacity(
            "Attribution observation row exceeds its decoder bound.",
        ));
    }
    let sql = format!(
        "SELECT * FROM {table} t WHERE id=$1 AND octet_length(data::text)<=$2 AND octet_length(to_jsonb(t)::text)<=$3"
    );
    let row = sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(sql))
        .bind(id)
        .bind(MAX_VALUE as i64)
        .bind(ROW_BYTES as i64)
        .fetch_optional(conn)
        .await
        .map_err(source_error)?
        .ok_or_else(invalid)?;
    Ok(Some(row))
}

#[cfg(test)]
mod tests {
    use super::*;
    use devres_application::Store;
    use devres_domain::{FetchRequest, FetchResponse, Validators};
    use sqlx_postgres::PgPool;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires disposable PostgreSQL; run scripts/test-postgres.sh"]
    async fn observation_snapshot_is_select_only_and_does_not_enqueue_or_advance_sweeps() {
        let base = std::env::var("DEVRES_TEST_DATABASE_URL").expect("disposable database required");
        let admin = PgPool::connect(&base).await.unwrap();
        sqlx_core::query::query("CREATE DATABASE devres_observation_fixture")
            .execute(&admin)
            .await
            .unwrap();
        let mut url = url::Url::parse(&base).unwrap();
        url.set_path("/devres_observation_fixture");
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let writer = PgBlobStore::connect(url.as_str(), root.path())
            .await
            .unwrap();
        let request = |number| FetchRequest {
            key: format!("rfc:text:{number}"),
            url: format!("https://fixtures.invalid/rfc{number}.txt"),
            ttl_secs: 60,
            max_bytes: 128,
            media_type: "text/plain".into(),
        };
        let response = || FetchResponse {
            status: 200,
            body: b"public synthetic fixture".to_vec(),
            validators: Validators::default(),
        };
        writer.publish(&request(1), response(), 100).await.unwrap();
        sqlx_core::raw_sql::raw_sql("CREATE ROLE devres_observation_reader LOGIN PASSWORD 'fixture-observer'; GRANT CONNECT ON DATABASE devres_observation_fixture TO devres_observation_reader")
            .execute(&admin).await.unwrap();
        sqlx_core::raw_sql::raw_sql("GRANT USAGE ON SCHEMA public TO devres_observation_reader; GRANT SELECT ON ALL TABLES IN SCHEMA public TO devres_observation_reader")
            .execute(&writer.pool).await.unwrap();
        url.set_username("devres_observation_reader").unwrap();
        url.set_password(Some("fixture-observer")).unwrap();
        let reader = PgBlobStore::connect_reader(url.as_str(), root.path(), None)
            .await
            .unwrap();
        let before: (i64, i64, i64) = sqlx_core::query_as::query_as("SELECT (SELECT count(*) FROM devres_attribution_targets),(SELECT count(*) FROM devres_attribution_sweeps),(SELECT count(*) FROM devres_attribution_origins)")
            .fetch_one(&writer.pool).await.unwrap();
        let (binding, mut scan) = reader.begin_observation().await.unwrap();
        writer.publish(&request(2), response(), 200).await.unwrap();
        let mut examined = 0;
        for _ in 0..256 {
            let page = scan.next_page().await.unwrap();
            examined += page.counts.get("rfc").map_or(0, |counts| counts.examined);
            if page.complete {
                break;
            }
        }
        // The later capture is excluded by both the fixed cutoff and MVCC snapshot.
        assert_eq!(examined, 1);
        reader.validate_observation(&binding).await.unwrap();
        let after: (i64, i64, i64) = sqlx_core::query_as::query_as("SELECT (SELECT count(*) FROM devres_attribution_targets),(SELECT count(*) FROM devres_attribution_sweeps),(SELECT count(*) FROM devres_attribution_origins)")
            .fetch_one(&writer.pool).await.unwrap();
        assert_eq!(before, after);
        assert!(
            sqlx_core::query::query("UPDATE devres_schema SET version=19")
                .execute(&reader.pool)
                .await
                .is_err()
        );
        let owned: bool = sqlx_core::query_scalar::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND objid=1 AND granted)")
            .bind(reader.owner_pid).fetch_one(&reader.pool).await.unwrap();
        assert!(!owned);
        drop(scan);

        // Raw synthetic rows deliberately bypass normal publication admission.
        // Their seals are genuine, so size admission must run before decoding
        // either the target state or its referenced generation.
        let evidence = json!({"source_url":"https://fixtures.invalid/observation"});
        let target = AttributionTarget {
            subject: AttributionSubject {
                provider: "rfc".into(),
                namespace: "fixture".into(),
                key: "oversized-observation".into(),
                fingerprint: crate::integrity::canonical_hash(&evidence).unwrap(),
            },
            evidence,
        };
        let target_id = target_id(&target.subject).unwrap();
        let mut oversized = serde_json::to_value(State::new(target.clone(), 0)).unwrap();
        oversized["failure"] = json!("x".repeat(MAX_VALUE + 1));
        let seal = payload_integrity::digest(TABLE_TARGETS, "", &target_id, &oversized).unwrap();
        sqlx_core::query::query("INSERT INTO devres_attribution_targets(id,provider,policy_epoch,status,priority,retry_at,data,data_integrity) VALUES($1,'rfc',$2,'pending',0,0,$3,$4)")
            .bind(&target_id).bind(ATTRIBUTION_POLICY_EPOCH as i32).bind(Json(&oversized)).bind(seal)
            .execute(&writer.pool).await.unwrap();
        let mut tx = reader.pool.begin().await.unwrap();
        sqlx_core::raw_sql::raw_sql("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *tx)
            .await
            .unwrap();
        let error = observe_target(&mut tx, &target, &mut BTreeMap::new())
            .await
            .unwrap_err();
        assert_eq!(error.code, "capacity");
        tx.rollback().await.unwrap();

        let generation = json!({"oversized_fixture":"x".repeat(MAX_VALUE + 1)});
        let generation_id = crate::integrity::canonical_hash(&generation).unwrap();
        let seal =
            payload_integrity::digest(TABLE_GENERATIONS, "", &generation_id, &generation).unwrap();
        sqlx_core::query::query(
            "INSERT INTO devres_attribution_generations(id,data,data_integrity) VALUES($1,$2,$3)",
        )
        .bind(&generation_id)
        .bind(Json(&generation))
        .bind(seal)
        .execute(&writer.pool)
        .await
        .unwrap();
        let mut state = State::new(target.clone(), 0);
        state.status = "ready".into();
        state.generation = Some(generation_id);
        let data = bounded(&state).unwrap();
        let seal = payload_integrity::digest(TABLE_TARGETS, "", &target_id, &data).unwrap();
        sqlx_core::query::query("UPDATE devres_attribution_targets SET status='ready',data=$1,data_integrity=$2 WHERE id=$3")
            .bind(Json(&data)).bind(seal).bind(&target_id).execute(&writer.pool).await.unwrap();
        let mut tx = reader.pool.begin().await.unwrap();
        sqlx_core::raw_sql::raw_sql("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *tx)
            .await
            .unwrap();
        let error = observe_target(&mut tx, &target, &mut BTreeMap::new())
            .await
            .unwrap_err();
        assert_eq!(error.code, "capacity");
        tx.rollback().await.unwrap();

        sqlx_core::query::query("UPDATE devres_archive_control SET epoch=epoch+1 WHERE singleton")
            .execute(&writer.pool)
            .await
            .unwrap();
        assert!(reader.validate_observation(&binding).await.is_err());
    }
}
