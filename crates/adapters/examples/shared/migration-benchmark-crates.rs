//! Bounded public synthetic SQL evidence. Never acquires or executes packages.
use super::{Result, payload_seal};
use devres_adapters::{PgBlobStore, integrity};
use devres_application::crate_corpus::CrateCorpusStore;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx_core::{query_builder::QueryBuilder, row::Row, types::Json};
use sqlx_postgres::Postgres;
use std::{path::Path, sync::Arc};

pub(super) const KIND: &str = "pending-schema10-crates-v1";
pub(super) const TABLES: [&str; 13] = [
    "devres_crate_artifacts",
    "devres_crate_observations",
    "devres_crate_inventories",
    "devres_crate_inventory_gaps",
    "devres_crate_changes",
    "devres_crate_staging",
    "devres_crate_versions",
    "devres_crate_jobs",
    "devres_crate_generations",
    "devres_crate_content",
    "devres_crate_enrichment",
    "devres_crate_enrichment_heads",
    "devres_crate_snapshots",
];
const INVENTORIES: usize = 3;

pub(super) async fn artifact_count(pool: &sqlx_postgres::PgPool) -> Result<i64> {
    Ok(sqlx_core::query_scalar::query_scalar(
        "SELECT count(*) FROM devres_crate_artifacts WHERE capture_id NOT LIKE 'blake3:%'",
    )
    .fetch_one(pool)
    .await?)
}

/// Most provenance resembles small archive/API origin records; occasional bounded
/// manifest details exercise larger inputs without padding every row with fake CPU work.
fn provenance(ordinal: usize, capture: &str) -> Value {
    let mut value = json!({"capture":capture,"source":"synthetic retained crates.io evidence",
        "name":format!("fixture-crate-{ordinal:05}"),"version":"1.0.0",
        "registry_checksum":"0".repeat(64),"transport":"https"});
    if ordinal.is_multiple_of(64) {
        value["manifest"] = json!({"license":"MIT OR Apache-2.0", "features":
            (0..128).map(|n| (format!("feature-{n}"),json!([format!("dependency-{n}/std")]))).collect::<serde_json::Map<String,Value>>()});
    }
    value
}

pub(super) async fn seed(
    pool: &sqlx_postgres::PgPool,
    root: &Path,
    artifacts: usize,
    staging: usize,
) -> Result<()> {
    if !(1..=16384).contains(&artifacts) || !(1..=16384).contains(&staging) {
        return Err("crate fixture exceeds its bounded range".into());
    }
    let body = b"public synthetic published crate evidence; never executed";
    let body_hash = hex::encode(Sha256::digest(body));
    std::fs::write(root.join(&body_hash), body)?;
    let mut captures = Vec::with_capacity(artifacts);
    for start in (0..artifacts).step_by(128) {
        let mut metadata = Vec::new();
        let mut artifact_rows = Vec::new();
        for ordinal in start..(start + 128).min(artifacts) {
            let key = format!("cargo:archive:fixture-crate-{ordinal:05}:1.0.0");
            let url = format!("https://fixtures.invalid/crates/fixture-crate-{ordinal:05}/1.0.0");
            let id = hex::encode(Sha256::digest(format!(
                "{key}\0{url}\0application/gzip\0{body_hash}"
            )));
            let seal = integrity::canonical_hash(
                &json!({"version":1,"namespace":"capture-metadata", "id":id,"key":key,"source_url":url,"body_hash":body_hash,"media_type":"application/gzip","retrieved_at":1_700_000_000}),
            )?;
            let provenance = provenance(ordinal, &id);
            let provenance_seal = payload_seal(
                "devres_crate_artifacts",
                "",
                &id,
                &json!({"bytes":body.len(),"provenance":provenance}),
            )?;
            captures.push(id.clone());
            metadata.push((id.clone(), key, url, seal));
            artifact_rows.push((id, provenance, provenance_seal));
        }
        let mut tx = pool.begin().await?;
        let mut query = QueryBuilder::<Postgres>::new(
            "INSERT INTO devres_captures(id,source_key,source_url,body_hash,media_type,retrieved_at,metadata_integrity) ",
        );
        query.push_values(&metadata, |mut row, (id, key, url, seal)| {
            row.push_bind(id)
                .push_bind(key)
                .push_bind(url)
                .push_bind(&body_hash)
                .push_bind("application/gzip")
                .push_bind(1_700_000_000_i64)
                .push_bind(seal);
        });
        query.build().execute(&mut *tx).await?;
        let mut query = QueryBuilder::<Postgres>::new(
            "INSERT INTO devres_crate_artifacts(capture_id,bytes,provenance,provenance_integrity) ",
        );
        query.push_values(&artifact_rows, |mut row, (id, provenance, seal)| {
            row.push_bind(id)
                .push_bind(body.len() as i64)
                .push_bind(Json(provenance))
                .push_bind(seal);
        });
        query.build().execute(&mut *tx).await?;
        // Same-second, byte-identical observations must remain distinct occurrences.
        let sequences: Vec<i64> = sqlx_core::query_scalar::query_scalar("SELECT nextval(pg_get_serial_sequence('devres_crate_observations','sequence')) FROM generate_series(1,$1::bigint)").bind((artifact_rows.len()*2) as i64).fetch_all(&mut *tx).await?;
        let mut observations = Vec::new();
        for ((id, provenance, _), sequences) in
            artifact_rows.iter().zip(sequences.as_chunks::<2>().0)
        {
            for &sequence in sequences {
                let data = json!({"capture_id":id,"observed_at":1_700_000_001_i64,"transport":"https","provenance":provenance});
                observations.push((
                    sequence,
                    id,
                    provenance,
                    payload_seal(
                        "devres_crate_observations",
                        id,
                        &sequence.to_string(),
                        &data,
                    )?,
                ));
            }
        }
        let mut query = QueryBuilder::<Postgres>::new(
            "INSERT INTO devres_crate_observations(sequence,capture_id,observed_at,transport,provenance,provenance_integrity) ",
        );
        query.push_values(
            &observations,
            |mut row, (sequence, id, provenance, seal)| {
                row.push_bind(*sequence)
                    .push_bind(*id)
                    .push_bind(1_700_000_001_i64)
                    .push_bind("https")
                    .push_bind(Json(*provenance))
                    .push_bind(seal);
            },
        );
        query.build().execute(&mut *tx).await?;
        tx.commit().await?;
    }
    let manifest = captures
        .first()
        .ok_or("crate fixture has no manifest capture")?;
    for inventory in 0..INVENTORIES {
        let revision = format!("{inventory:040x}");
        let id = hex::encode(Sha256::digest(format!("crate-inventory:1:{revision}")));
        sqlx_core::query::query("INSERT INTO devres_crate_inventories(id,revision,created_at,validated_at,cursor,published,manifest) VALUES($1,$2,1700000000,1700000001,'fixture-complete',true,$3)").bind(&id).bind(&revision).bind(manifest).execute(pool).await?;
        sqlx_core::query::query("INSERT INTO devres_crate_inventory_gaps(inventory,name,error) VALUES($1,'missing-synthetic-crate','unavailable')").bind(&id).execute(pool).await?;
        for start in (0..staging).step_by(128) {
            let mut rows = Vec::new();
            for ordinal in start..(start + 128).min(staging) {
                let name = format!("fixture-crate-{ordinal:05}");
                let version = format!("1.{inventory}.0");
                let capture = &captures[ordinal % captures.len()];
                let record = json!({"name":name,"vers":version,"deps":[],"cksum":"0".repeat(64),"features":{},"yanked":false});
                let seal = payload_seal(
                    "devres_crate_staging",
                    &id,
                    &format!("{name}@{version}"),
                    &json!({"metadata_capture":capture,"record":record}),
                )?;
                rows.push((name, version, capture, record, seal));
            }
            let mut query = QueryBuilder::<Postgres>::new(
                "INSERT INTO devres_crate_staging(inventory,name,version,metadata_capture,record,record_integrity) ",
            );
            query.push_values(&rows, |mut row, (name, version, capture, record, seal)| {
                row.push_bind(&id)
                    .push_bind(name)
                    .push_bind(version)
                    .push_bind(*capture)
                    .push_bind(Json(record))
                    .push_bind(seal);
            });
            query.build().execute(pool).await?;
            let mut query =
                QueryBuilder::<Postgres>::new("INSERT INTO devres_crate_changes(inventory,name) ");
            query.push_values(&rows, |mut row, (name, _, _, _, _)| {
                row.push_bind(&id).push_bind(name);
            });
            query.build().execute(pool).await?;
        }
    }
    Ok(())
}

pub(super) async fn readback(store: &Arc<PgBlobStore>, pool: &sqlx_postgres::PgPool) -> Result<()> {
    let count = artifact_count(pool).await?;
    if count == 0 {
        return Ok(());
    }
    let canonical: i64 = sqlx_core::query_scalar::query_scalar(
        "SELECT count(*) FROM devres_crate_artifacts WHERE capture_id LIKE 'blake3:%'",
    )
    .fetch_one(pool)
    .await?;
    let observations: i64 = sqlx_core::query_scalar::query_scalar(
        "SELECT count(*) FROM devres_crate_observations WHERE capture_id LIKE 'blake3:%'",
    )
    .fetch_one(pool)
    .await?;
    if canonical != count || observations != count * 2 {
        return Err("crate replay lost artifacts or duplicate observations".into());
    }
    let missing: bool=sqlx_core::query_scalar::query_scalar("SELECT EXISTS(SELECT 1 FROM devres_crate_observations o WHERE o.capture_id NOT LIKE 'blake3:%' AND NOT EXISTS(SELECT 1 FROM devres_integrity_staged_state s WHERE s.provider='crate' AND s.key='observation:'||o.sequence::text))").fetch_one(pool).await?;
    if missing {
        return Err("crate replay lost an occurrence receipt".into());
    }
    let ids: Vec<String>=sqlx_core::query_scalar::query_scalar("(SELECT capture_id FROM devres_crate_artifacts WHERE capture_id LIKE 'blake3:%' ORDER BY capture_id LIMIT 1) UNION (SELECT capture_id FROM devres_crate_artifacts WHERE capture_id LIKE 'blake3:%' ORDER BY capture_id DESC LIMIT 1)").fetch_all(pool).await?;
    for id in ids {
        let artifact = store
            .artifact(&id)
            .await?
            .ok_or("canonical artifact readback missing")?;
        if artifact.bytes
            != b"public synthetic published crate evidence; never executed".len() as u64
        {
            return Err("canonical artifact readback length changed".into());
        }
    }
    let rows=sqlx_core::query::query("SELECT (SELECT count(*) FROM devres_crate_staging s JOIN devres_crate_inventories i ON i.id=s.inventory WHERE i.id NOT LIKE 'blake3:%') AS legacy,(SELECT count(*) FROM devres_crate_staging s JOIN devres_crate_inventories i ON i.id=s.inventory WHERE i.id LIKE 'blake3:%') AS canonical").fetch_one(pool).await?;
    if rows.try_get::<i64, _>("legacy")? != rows.try_get::<i64, _>("canonical")? {
        return Err("canonical staging readback membership changed".into());
    }
    Ok(())
}
