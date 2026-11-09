//! Bounded SQL-only crate replay. Source ordering and durable ownership stay on
//! the existing owner connection; blocking envelope work uses command admission.
use super::*;
use crate::{GraphPrepared, MigrationExecution, MigrationMap};
use sqlx_core::transaction::Transaction;
use sqlx_postgres::{PgRow, Postgres};
use std::ops::Range;

const ROWS: usize = 128;
const ARGUMENT_BYTES: usize = 8 * 1024 * 1024;

/// Unlike index windows, a row page need not stop at the worker count: one
/// worker may prepare an entire publication batch sequentially. Reserve the
/// complete resident window before fetching decoded payloads.
fn metadata_window<T>(
    positions: Vec<(T, i64, i64)>,
    execution: &MigrationExecution,
) -> Result<(Vec<T>, usize)> {
    let mut selected = Vec::new();
    let mut total = 0_usize;
    for (key, bytes, nodes) in positions {
        let charge = MigrationExecution::graph_input_charge(
            usize::try_from(bytes).map_err(|_| storage_error())?,
            usize::try_from(nodes).map_err(|_| storage_error())?,
        )?;
        let next = total
            .checked_add(charge)
            .ok_or_else(|| Error::capacity("Crate row memory charge overflow."))?;
        if !selected.is_empty()
            && (selected.len() == ROWS || next > execution.graph_options().memory_budget_bytes)
        {
            break;
        }
        selected.push(key);
        total = next;
        if total > execution.graph_options().memory_budget_bytes {
            break;
        }
    }
    Ok((selected, total))
}

trait PublicationRow {
    fn argument_bytes(&self) -> Result<usize>;
}

fn argument_bytes(value: &Value, fields: &[&str]) -> Result<usize> {
    // JSON encoding is charged independently of its decoded working set.
    // Slack includes array headers, scalar arguments, receipts and bind buffers.
    fields.iter().try_fold(
        serde_json::to_vec(value)
            .map_err(|_| storage_error())?
            .len()
            .checked_add(1024)
            .ok_or_else(|| Error::capacity("Crate publication charge overflow."))?,
        |total, field| {
            total
                .checked_add(field.len())
                .ok_or_else(|| Error::capacity("Crate publication charge overflow."))
        },
    )
}

fn publication_ranges<T: PublicationRow>(rows: &[GraphPrepared<T>]) -> Result<Vec<Range<usize>>> {
    let mut ranges = Vec::new();
    let mut start = 0;
    let mut bytes = 0_usize;
    for (index, row) in rows.iter().enumerate() {
        let charge = row.argument_bytes()?;
        let next = bytes
            .checked_add(charge)
            .ok_or_else(|| Error::capacity("Crate publication charge overflow."))?;
        if index > start && (index - start == ROWS || next > ARGUMENT_BYTES) {
            ranges.push(start..index);
            start = index;
            bytes = 0;
        }
        bytes = bytes
            .checked_add(charge)
            .ok_or_else(|| Error::capacity("Crate publication charge overflow."))?;
    }
    if start < rows.len() {
        ranges.push(start..rows.len());
    }
    Ok(ranges)
}

async fn finish_batch(
    tx: Transaction<'_, Postgres>,
    result: Result<()>,
    cancel: &CancellationToken,
) -> Result<()> {
    match result.and_then(|()| stop(cancel)) {
        Ok(()) => tx.commit().await.map_err(|_| storage_error()),
        Err(error) => {
            tx.rollback().await.map_err(|_| storage_error())?;
            Err(error)
        }
    }
}

struct ArtifactRow {
    old: String,
    capture: String,
    bytes: i64,
    provenance: Value,
    seal: String,
}
impl PublicationRow for ArtifactRow {
    fn argument_bytes(&self) -> Result<usize> {
        argument_bytes(&self.provenance, &[&self.capture, &self.seal])
    }
}

fn prepare_artifact(row: PgRow, maps: &MigrationMap) -> Result<ArtifactRow> {
    let old: String = row.try_get("capture_id").map_err(|_| storage_error())?;
    let bytes: i64 = row.try_get("bytes").map_err(|_| storage_error())?;
    let length = u64::try_from(bytes).map_err(|_| Error::integrity("Invalid artifact length."))?;
    let checked = payload_integrity::checked(
        "devres_crate_artifacts",
        "",
        &old,
        payload_integrity::crate_artifact_payload(
            length,
            &row.try_get::<Json<Value>, _>("provenance")
                .map_err(|_| storage_error())?
                .0,
        ),
        &row.try_get::<String, _>("provenance_integrity")
            .map_err(|_| storage_error())?,
    )?;
    let capture = mapped(maps, "capture", &old)?;
    let mut provenance = checked["provenance"].clone();
    remap_fields(&mut provenance, maps)?;
    let seal = payload_integrity::digest(
        "devres_crate_artifacts",
        "",
        &capture,
        &payload_integrity::crate_artifact_payload(length, &provenance),
    )?;
    maps.ensure_healthy()?;
    Ok(ArtifactRow {
        old,
        capture,
        bytes,
        provenance,
        seal,
    })
}

struct ObservationRow {
    legacy_sequence: i64,
    capture: String,
    time: i64,
    transport: String,
    provenance: Value,
}
impl PublicationRow for ObservationRow {
    fn argument_bytes(&self) -> Result<usize> {
        argument_bytes(&self.provenance, &[&self.capture, &self.transport])
    }
}

fn prepare_observation(row: PgRow, maps: &MigrationMap) -> Result<ObservationRow> {
    let legacy_sequence: i64 = row.try_get("sequence").map_err(|_| storage_error())?;
    let old: String = row.try_get("capture_id").map_err(|_| storage_error())?;
    let time: i64 = row.try_get("observed_at").map_err(|_| storage_error())?;
    let transport: String = row.try_get("transport").map_err(|_| storage_error())?;
    let checked = payload_integrity::checked(
        "devres_crate_observations",
        &old,
        &legacy_sequence.to_string(),
        payload_integrity::crate_observation_payload(
            &old,
            time,
            &transport,
            &row.try_get::<Json<Value>, _>("provenance")
                .map_err(|_| storage_error())?
                .0,
        ),
        &row.try_get::<String, _>("provenance_integrity")
            .map_err(|_| storage_error())?,
    )?;
    let capture = mapped(maps, "capture", &old)?;
    let mut provenance = checked["provenance"].clone();
    remap_fields(&mut provenance, maps)?;
    maps.ensure_healthy()?;
    Ok(ObservationRow {
        legacy_sequence,
        capture,
        time,
        transport,
        provenance,
    })
}

struct StagingRow {
    name: String,
    version: String,
    metadata: String,
    record: Value,
    seal: String,
}
impl PublicationRow for StagingRow {
    fn argument_bytes(&self) -> Result<usize> {
        argument_bytes(
            &self.record,
            &[&self.name, &self.version, &self.metadata, &self.seal],
        )
    }
}

fn prepare_staging(row: PgRow, old: &str, new: &str, maps: &MigrationMap) -> Result<StagingRow> {
    let name: String = row.try_get("name").map_err(|_| storage_error())?;
    let version: String = row.try_get("version").map_err(|_| storage_error())?;
    let key = format!("{name}@{version}");
    let legacy_metadata: String = row
        .try_get("metadata_capture")
        .map_err(|_| storage_error())?;
    let checked = payload_integrity::checked(
        "devres_crate_staging",
        old,
        &key,
        payload_integrity::crate_staging_payload(
            &legacy_metadata,
            &row.try_get::<Json<Value>, _>("record")
                .map_err(|_| storage_error())?
                .0,
        ),
        &row.try_get::<String, _>("record_integrity")
            .map_err(|_| storage_error())?,
    )?;
    let metadata = mapped(maps, "capture", &legacy_metadata)?;
    let record = checked["record"].clone();
    let seal = payload_integrity::digest(
        "devres_crate_staging",
        new,
        &key,
        &payload_integrity::crate_staging_payload(&metadata, &record),
    )?;
    maps.ensure_healthy()?;
    Ok(StagingRow {
        name,
        version,
        metadata,
        record,
        seal,
    })
}

impl PgBlobStore {
    pub(super) async fn migrate_artifact_rows(
        &self,
        maps: &MigrationMap,
        cancel: &CancellationToken,
        execution: &MigrationExecution,
    ) -> Result<()> {
        let _phase = execution.timed_phase("graph_crate_artifacts");
        let mut after = String::new();
        let mut committed = 0_u64;
        loop {
            stop(cancel)?;
            let metadata = {
                let _timing = execution.timed_phase("crate_artifact_metadata");
                sqlx_core::query_as::query_as::<_, (String, i64, i64)>(
                    "SELECT capture_id,octet_length(to_jsonb(source)::text)::bigint,jsonb_array_length(jsonb_path_query_array(to_jsonb(source),'strict $.**.type()'))::bigint FROM (SELECT capture_id,bytes,provenance,provenance_integrity FROM devres_crate_artifacts WHERE capture_id NOT LIKE 'blake3:%' AND capture_id>$1 ORDER BY capture_id LIMIT 128) source ORDER BY capture_id",
                ).bind(&after).fetch_all(&self.pool).await.map_err(|_|storage_error())?
            };
            let (keys, charge) = metadata_window(metadata, execution)?;
            if keys.is_empty() {
                break;
            }
            let reservation = execution.graph_reserve(charge, cancel).await?;
            let rows = {
                let _timing = execution.timed_phase("crate_artifact_payload");
                sqlx_core::query::query("SELECT capture_id,bytes,provenance,provenance_integrity FROM devres_crate_artifacts WHERE capture_id=ANY($1::text[]) ORDER BY capture_id")
                    .bind(&keys).fetch_all(&self.pool).await.map_err(|_|storage_error())?
            };
            if rows.len() != keys.len()
                || rows.iter().zip(&keys).any(|(row, key)| {
                    row.try_get::<String, _>("capture_id").ok().as_ref() != Some(key)
                })
            {
                return Err(Error::integrity("Crate artifact source window changed."));
            }
            let prepared = {
                let _timing = execution.timed_phase("crate_artifact_prepare");
                execution
                    .graph_map_ordered_reserved(rows, reservation, cancel, |row, token| {
                        let maps = maps.clone();
                        async move {
                            execution
                                .run(&token, move |token| {
                                    stop(&token)?;
                                    prepare_artifact(row, &maps)
                                })
                                .await
                        }
                    })
                    .await?
            };
            for range in publication_ranges(&prepared)? {
                stop(cancel)?;
                let batch = &prepared[range.clone()];
                let captures: Vec<&str> = batch.iter().map(|row| row.capture.as_str()).collect();
                let lengths: Vec<i64> = batch.iter().map(|row| row.bytes).collect();
                let provenance: Vec<Json<&Value>> =
                    batch.iter().map(|row| Json(&row.provenance)).collect();
                let seals: Vec<&str> = batch.iter().map(|row| row.seal.as_str()).collect();
                let mut owner = {
                    let _timing = execution.timed_phase("crate_artifact_owner_wait");
                    self.owner.lock().await
                };
                let _timing = execution.timed_phase("crate_artifact_commit");
                let mut tx = {
                    let _begin = execution.timed_phase("crate_artifact_begin");
                    owner.begin().await.map_err(|_| storage_error())?
                };
                let result = async {
                    let insert = execution.timed_phase("crate_artifact_insert");
                    // The exclusive owner serializes artifact writers. Skip existing
                    // targets and choose the first occurrence before plain insertion,
                    // avoiding speculative-insertion WAL. Every requested occurrence
                    // still receives the full post-statement stored-target check.
                    sqlx_core::query::query("INSERT INTO devres_crate_artifacts(capture_id,bytes,provenance,provenance_integrity) SELECT capture,bytes,provenance,seal FROM (SELECT DISTINCT ON (capture) capture,bytes,provenance,seal,ordinal FROM UNNEST($1::text[],$2::bigint[],$3::jsonb[],$4::text[]) WITH ORDINALITY input(capture,bytes,provenance,seal,ordinal) ORDER BY capture,ordinal) requested WHERE NOT EXISTS (SELECT 1 FROM devres_crate_artifacts retained WHERE retained.capture_id=requested.capture) ORDER BY ordinal")
                        .bind(&captures).bind(&lengths).bind(&provenance).bind(&seals).execute(&mut *tx).await.map_err(|_|storage_error())?;
                    drop(insert);
                    // Compare canonical JSON text and the freshly computed seal rather
                    // than trusting a skipped insert or fetching unbounded targets.
                    let _verify = execution.timed_phase("crate_artifact_target_check");
                    let verified: bool = sqlx_core::query_scalar::query_scalar("SELECT count(*)=$5 AND COALESCE(bool_and(COALESCE(retained.bytes=requested.bytes AND retained.provenance::text=requested.provenance::text AND retained.provenance_integrity=requested.seal,false)),false) FROM UNNEST($1::text[],$2::bigint[],$3::jsonb[],$4::text[]) requested(capture,bytes,provenance,seal) LEFT JOIN devres_crate_artifacts retained ON retained.capture_id=requested.capture")
                        .bind(&captures).bind(&lengths).bind(&provenance).bind(&seals).bind(batch.len() as i64).fetch_one(&mut *tx).await.map_err(|_|storage_error())?;
                    if !verified {
                        return Err(Error::integrity("Canonical crate artifact differs from retained source."));
                    }
                    Ok(())
                }.await;
                {
                    let _commit = execution.timed_phase("crate_artifact_durable_commit");
                    finish_batch(tx, result, cancel).await?;
                }
                drop(owner);
                committed += batch.len() as u64;
                after = batch.last().ok_or_else(storage_error)?.old.clone();
                execution.report(
                    "graph_crate_artifacts",
                    committed,
                    committed,
                    committed,
                    charge,
                );
            }
        }
        Ok(())
    }

    pub(super) async fn migrate_observation_rows(
        &self,
        maps: &MigrationMap,
        cancel: &CancellationToken,
        execution: &MigrationExecution,
    ) -> Result<()> {
        let _phase = execution.timed_phase("graph_crate_observations");
        let mut after = 0_i64;
        let mut committed = 0_u64;
        loop {
            stop(cancel)?;
            let metadata = sqlx_core::query_as::query_as::<_, (i64, i64, i64)>("SELECT sequence,octet_length(to_jsonb(source)::text)::bigint,jsonb_array_length(jsonb_path_query_array(to_jsonb(source),'strict $.**.type()'))::bigint FROM (SELECT sequence,capture_id,observed_at,transport,provenance,provenance_integrity FROM devres_crate_observations WHERE capture_id NOT LIKE 'blake3:%' AND sequence>$1 ORDER BY sequence LIMIT 128) source ORDER BY sequence")
                .bind(after).fetch_all(&self.pool).await.map_err(|_|storage_error())?;
            let (keys, charge) = metadata_window(metadata, execution)?;
            if keys.is_empty() {
                break;
            }
            let reservation = execution.graph_reserve(charge, cancel).await?;
            let rows = sqlx_core::query::query("SELECT sequence,capture_id,observed_at,transport,provenance,provenance_integrity FROM devres_crate_observations WHERE sequence=ANY($1::bigint[]) ORDER BY sequence")
                .bind(&keys).fetch_all(&self.pool).await.map_err(|_|storage_error())?;
            if rows.len() != keys.len()
                || rows
                    .iter()
                    .zip(&keys)
                    .any(|(row, key)| row.try_get::<i64, _>("sequence").ok().as_ref() != Some(key))
            {
                return Err(Error::integrity("Crate observation source window changed."));
            }
            let prepared = execution
                .graph_map_ordered_reserved(rows, reservation, cancel, |row, token| {
                    let maps = maps.clone();
                    async move {
                        execution
                            .run(&token, move |token| {
                                stop(&token)?;
                                prepare_observation(row, &maps)
                            })
                            .await
                    }
                })
                .await?;
            for range in publication_ranges(&prepared)? {
                stop(cancel)?;
                let batch = &prepared[range];
                let mut owner = self.owner.lock().await;
                let mut tx = owner.begin().await.map_err(|_| storage_error())?;
                let result = async {
                    for row in batch {
                        stop(cancel)?;
                        replay_observation(&mut tx, row).await?;
                    }
                    Ok(())
                }
                .await;
                finish_batch(tx, result, cancel).await?;
                drop(owner);
                committed += batch.len() as u64;
                after = batch.last().ok_or_else(storage_error)?.legacy_sequence;
                execution.report(
                    "graph_crate_observations",
                    committed,
                    committed,
                    committed,
                    charge,
                );
            }
        }
        Ok(())
    }

    pub(super) async fn migrate_staging_rows(
        &self,
        old: &str,
        new: &str,
        maps: &MigrationMap,
        cancel: &CancellationToken,
        execution: &MigrationExecution,
    ) -> Result<()> {
        let _phase = execution.timed_phase("graph_crate_staging");
        // Only source keys are materialized. PostgreSQL performs the original
        // concatenation sort once, preserving its collation exactly. A retry
        // rebuilds this disposable session-local catalogue from retained rows.
        let result = async {
            {
                let mut owner=self.owner.lock().await;
                sqlx_core::query::query("DROP TABLE IF EXISTS pg_temp.devres_crate_migration_keys").execute(&mut *owner).await.map_err(|_|storage_error())?;
                sqlx_core::query::query("CREATE TEMP TABLE devres_crate_migration_keys(ordinal bigint PRIMARY KEY,name text NOT NULL,version text NOT NULL) ON COMMIT PRESERVE ROWS").execute(&mut *owner).await.map_err(|_|storage_error())?;
                let ambiguous:bool=sqlx_core::query_scalar::query_scalar("SELECT EXISTS(SELECT 1 FROM devres_crate_staging WHERE inventory=$1 AND name||'@'||version>'' GROUP BY name||'@'||version HAVING count(*)>1)").bind(old).fetch_one(&mut *owner).await.map_err(|_|storage_error())?;
                if ambiguous {return Err(Error::integrity("Ambiguous retained crate staging order."));}
                stop(cancel)?;
                // Await the owner query even if cancellation arrives while it runs.
                sqlx_core::query::query("INSERT INTO pg_temp.devres_crate_migration_keys SELECT row_number() OVER(ORDER BY name||'@'||version),name,version FROM devres_crate_staging WHERE inventory=$1 AND name||'@'||version>''").bind(old).execute(&mut *owner).await.map_err(|_|storage_error())?;
            }
            let mut after=0_i64;
            let mut committed=0_u64;
            loop {
                stop(cancel)?;
                let positions:Vec<(i64,i64,i64)>={
                    let mut owner=self.owner.lock().await;
                    sqlx_core::query_as::query_as("SELECT keys.ordinal,octet_length(to_jsonb(source)::text)::bigint,jsonb_array_length(jsonb_path_query_array(to_jsonb(source),'strict $.**.type()'))::bigint FROM pg_temp.devres_crate_migration_keys keys JOIN devres_crate_staging source ON source.inventory=$1 AND source.name=keys.name AND source.version=keys.version WHERE keys.ordinal>$2 ORDER BY keys.ordinal LIMIT 128")
                        .bind(old).bind(after).fetch_all(&mut *owner).await.map_err(|_|storage_error())?
                };
                let (ordinals,charge)=metadata_window(positions,execution)?;
                if ordinals.is_empty(){break;}
                let reservation=execution.graph_reserve(charge,cancel).await?;
                // Names and versions have no retained SQL length constraint.
                // Materialize them only after the complete input is charged.
                let keys:Vec<(i64,String,String)>={
                    let mut owner=self.owner.lock().await;
                    sqlx_core::query_as::query_as("SELECT ordinal,name,version FROM pg_temp.devres_crate_migration_keys WHERE ordinal=ANY($1::bigint[]) ORDER BY ordinal")
                        .bind(&ordinals).fetch_all(&mut *owner).await.map_err(|_|storage_error())?
                };
                if keys.len()!=ordinals.len() || keys.iter().zip(&ordinals).any(|((ordinal,_,_),expected)|ordinal!=expected){
                    return Err(Error::integrity("Crate staging key window changed."));
                }
                let names:Vec<&str>=keys.iter().map(|(_,name,_)|name.as_str()).collect();
                let versions:Vec<&str>=keys.iter().map(|(_,_,version)|version.as_str()).collect();
                let rows=sqlx_core::query::query("SELECT source.* FROM UNNEST($2::text[],$3::text[]) WITH ORDINALITY requested(name,version,ordinal) JOIN devres_crate_staging source ON source.inventory=$1 AND source.name=requested.name AND source.version=requested.version ORDER BY requested.ordinal")
                    .bind(old).bind(&names).bind(&versions).fetch_all(&self.pool).await.map_err(|_|storage_error())?;
                if rows.len()!=keys.len() || rows.iter().zip(&keys).any(|(row,(_,name,version))| row.try_get::<String,_>("name").ok().as_ref()!=Some(name)||row.try_get::<String,_>("version").ok().as_ref()!=Some(version)){
                    return Err(Error::integrity("Crate staging source window changed."));
                }
                let prepared=execution.graph_map_ordered_reserved(rows,reservation,cancel,|row,token|{
                    let maps=maps.clone();let old=old.to_owned();let new=new.to_owned();
                    async move{execution.run(&token,move|token|{stop(&token)?;prepare_staging(row,&old,&new,&maps)}).await}
                }).await?;
                for range in publication_ranges(&prepared)?{
                    stop(cancel)?;
                    let batch=&prepared[range.clone()];
                    let names:Vec<&str>=batch.iter().map(|row|row.name.as_str()).collect();
                    let versions:Vec<&str>=batch.iter().map(|row|row.version.as_str()).collect();
                    let metadata:Vec<&str>=batch.iter().map(|row|row.metadata.as_str()).collect();
                    let records:Vec<Json<&Value>>=batch.iter().map(|row|Json(&row.record)).collect();
                    let seals:Vec<&str>=batch.iter().map(|row|row.seal.as_str()).collect();
                    let mut owner=self.owner.lock().await;
                    let mut tx=owner.begin().await.map_err(|_|storage_error())?;
                    let result=async{
                        sqlx_core::query::query("INSERT INTO devres_crate_staging(inventory,name,version,metadata_capture,record,record_integrity) SELECT $1,name,version,metadata,record,seal FROM UNNEST($2::text[],$3::text[],$4::text[],$5::jsonb[],$6::text[]) WITH ORDINALITY requested(name,version,metadata,record,seal,ordinal) ORDER BY ordinal ON CONFLICT DO NOTHING")
                            .bind(new).bind(&names).bind(&versions).bind(&metadata).bind(&records).bind(&seals).execute(&mut *tx).await.map_err(|_|storage_error())?;
                        let verified:bool=sqlx_core::query_scalar::query_scalar("SELECT count(*)=$7 AND COALESCE(bool_and(COALESCE(retained.metadata_capture=requested.metadata AND retained.record::text=requested.record::text AND retained.record_integrity=requested.seal,false)),false) FROM UNNEST($2::text[],$3::text[],$4::text[],$5::jsonb[],$6::text[]) requested(name,version,metadata,record,seal) LEFT JOIN devres_crate_staging retained ON retained.inventory=$1 AND retained.name=requested.name AND retained.version=requested.version")
                            .bind(new).bind(&names).bind(&versions).bind(&metadata).bind(&records).bind(&seals).bind(batch.len() as i64).fetch_one(&mut *tx).await.map_err(|_|storage_error())?;
                        if !verified{return Err(Error::integrity("Canonical crate staging differs from retained source."));}
                        Ok(())
                    }.await;
                    finish_batch(tx,result,cancel).await?;
                    drop(owner);
                    committed+=batch.len() as u64;
                    after=keys.get(range.end-1).ok_or_else(storage_error)?.0;
                    execution.report("graph_crate_staging",committed,committed,committed,charge);
                }
            }
            Ok(())
        }.await;
        // Clean the catalogue on both success and cooperative failure. Its session
        // also drops it if owner loss makes cleanup impossible.
        let cleanup =
            sqlx_core::query::query("DROP TABLE IF EXISTS pg_temp.devres_crate_migration_keys")
                .execute(&mut *self.owner.lock().await)
                .await
                .map_err(|_| storage_error());
        match result {
            Err(error) => Err(error),
            Ok(()) => cleanup.map(|_| ()),
        }
    }
}

async fn replay_observation(
    tx: &mut sqlx_postgres::PgConnection,
    row: &ObservationRow,
) -> Result<()> {
    let checkpoint = format!("observation:{}", row.legacy_sequence);
    let existing=sqlx_core::query::query("SELECT CASE WHEN octet_length(data::text)<=4096 THEN data ELSE NULL END AS data,data_integrity FROM devres_integrity_staged_state WHERE provider='crate' AND key=$1").bind(&checkpoint).fetch_optional(&mut *tx).await.map_err(|_|storage_error())?;
    if let Some(receipt) = existing {
        let value = payload_integrity::checked(
            "devres_integrity_staged_state",
            "crate",
            &checkpoint,
            receipt
                .try_get::<Option<Json<Value>>, _>("data")
                .map_err(|_| storage_error())?
                .ok_or_else(|| Error::integrity("Crate observation receipt exceeds its bound."))?
                .0,
            &receipt
                .try_get::<String, _>("data_integrity")
                .map_err(|_| storage_error())?,
        )?;
        if value["legacy_sequence"] != row.legacy_sequence || value["capture_id"] != row.capture {
            return Err(Error::integrity(
                "Crate observation checkpoint identity mismatch.",
            ));
        }
        let sequence = value["sequence"].as_i64().ok_or_else(storage_error)?;
        let expected_seal = payload_integrity::digest(
            "devres_crate_observations",
            &row.capture,
            &sequence.to_string(),
            &payload_integrity::crate_observation_payload(
                &row.capture,
                row.time,
                &row.transport,
                &row.provenance,
            ),
        )?;
        let target: Option<bool> = sqlx_core::query_scalar::query_scalar("SELECT capture_id=$3 AND observed_at=$4 AND transport=$5 AND provenance_integrity=$6 AND provenance::text=$2::jsonb::text FROM devres_crate_observations WHERE sequence=$1")
            .bind(sequence).bind(Json(&row.provenance)).bind(&row.capture).bind(row.time).bind(&row.transport).bind(&expected_seal)
            .fetch_optional(&mut *tx).await.map_err(|_|storage_error())?;
        let matches =
            target.ok_or_else(|| Error::integrity("Checkpointed observation missing."))?;
        if !matches {
            return Err(Error::integrity(
                "Checkpointed observation differs from retained occurrence.",
            ));
        }
    } else {
        let sequence =
            append_crate_observation(tx, &row.capture, row.time, &row.transport, &row.provenance)
                .await?;
        let receipt = json!({"legacy_sequence":row.legacy_sequence,"sequence":sequence,"capture_id":row.capture});
        sqlx_core::query::query("INSERT INTO devres_integrity_staged_state(provider,key,data,data_integrity) VALUES('crate',$1,$2,$3)").bind(&checkpoint).bind(Json(&receipt)).bind(payload_integrity::digest("devres_integrity_staged_state","crate",&checkpoint,&receipt)?).execute(&mut *tx).await.map_err(|_|storage_error())?;
    }
    Ok(())
}
