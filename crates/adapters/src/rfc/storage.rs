//! Owner-fenced durable RFC jobs, immutable projections, and snapshot manifests.
use super::{PgBlobStore, payload_integrity, storage_error, valid_hash};
use async_trait::async_trait;
use devres_application::corpus::{Dataset, Document, Job, JobSpec, RfcCorpusStore, Snapshot};
use devres_domain::{Capture, Error, Result};
use serde::Serialize;
use serde_json::{Value, json};
use sqlx_core::{connection::Connection, row::Row, types::Json};

const MAX_JSON: usize = 64 * 1024 * 1024;

#[cfg(test)]
#[path = "storage_snapshot_batch_tests.rs"]
mod snapshot_batch_tests;

fn kind_checked(kind: &str) -> Result<()> {
    if matches!(kind, "catalogue" | "errata") {
        Ok(())
    } else {
        Err(Error::invalid("Unsupported RFC dataset kind"))
    }
}

fn encoded<T: Serialize>(value: &T) -> Result<Value> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| Error::integrity("Invalid RFC corpus representation"))?;
    if bytes.len() > MAX_JSON {
        return Err(Error::capacity("RFC corpus representation exceeds limit"));
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| Error::integrity("Invalid RFC corpus representation"))
}

fn capture_checked(capture: &Capture) -> Result<()> {
    if !valid_hash(&capture.id)
        || !valid_hash(&capture.body_hash)
        || capture.key.len() > 2048
        || capture.source_url.len() > 4096
        || capture.media_type.len() > 128
    {
        return Err(Error::invalid("Invalid RFC capture metadata"));
    }
    Ok(())
}

fn job_checked(job: &JobSpec) -> Result<()> {
    if !(1..=999999).contains(&job.number)
        || !matches!(job.format.as_str(), "txt" | "html" | "xml" | "pdf")
    {
        return Err(Error::invalid("Invalid RFC job identity"));
    }
    let (key, url) = match job.assurance.as_str() {
        "https" => (
            if job.format == "txt" {
                format!("rfc:text:{}", job.number)
            } else {
                format!("rfc:format:{}:{}", job.number, job.format)
            },
            format!(
                "https://www.rfc-editor.org/rfc/rfc{}.{}",
                job.number, job.format
            ),
        ),
        "rsync" => (
            format!("rfc:rsync:{}:{}", job.number, job.format),
            format!(
                "rsync://rsync.rfc-editor.org/rfcs/rfc{}.{}",
                job.number, job.format
            ),
        ),
        _ => return Err(Error::invalid("Invalid RFC transport assurance")),
    };
    if job.key != key || job.source_url != url {
        return Err(Error::invalid("RFC job source does not match its identity"));
    }
    Ok(())
}

fn decode<T: serde::de::DeserializeOwned>(value: Value) -> Result<T> {
    serde_json::from_value(value)
        .map_err(|_| Error::integrity("Invalid stored RFC corpus representation"))
}

pub(super) fn imported_source(key: &str, url: &str) -> Result<bool> {
    if let Some(identity) = key.strip_prefix("rfc:rsync:") {
        let (number, format) = identity
            .split_once(':')
            .ok_or_else(|| Error::invalid("Invalid RFC import identity"))?;
        let number = number
            .parse()
            .map_err(|_| Error::invalid("Invalid RFC import number"))?;
        job_checked(&JobSpec {
            key: key.into(),
            number,
            format: format.into(),
            source_url: url.into(),
            assurance: "rsync".into(),
            due_at: 0,
        })?;
        return Ok(true);
    }
    if url::Url::parse(url).is_ok_and(|parsed| parsed.scheme() == "rsync") {
        return Err(Error::invalid(
            "RFC import requires its own source namespace",
        ));
    }
    Ok(false)
}

async fn check_capture(
    connection: &mut sqlx_postgres::PgConnection,
    capture: &Capture,
) -> Result<()> {
    capture_checked(capture)?;
    let matches: bool = sqlx_core::query_scalar::query_scalar("SELECT EXISTS(SELECT 1 FROM devres_captures WHERE id=$1 AND source_key=$2 AND source_url=$3 AND body_hash=$4 AND media_type=$5 AND retrieved_at=$6)")
        .bind(&capture.id).bind(&capture.key).bind(&capture.source_url).bind(&capture.body_hash)
        .bind(&capture.media_type).bind(capture.retrieved_at)
        .fetch_one(connection).await.map_err(|_| storage_error())?;
    if !matches {
        return Err(Error::integrity(
            "RFC projection references a different or missing capture",
        ));
    }
    Ok(())
}

async fn check_captures(
    connection: &mut sqlx_postgres::PgConnection,
    captures: &[&Capture],
) -> Result<()> {
    if captures.is_empty() {
        return Ok(());
    }
    for capture in captures {
        capture_checked(capture)?;
    }
    let ids: Vec<_> = captures.iter().map(|capture| capture.id.as_str()).collect();
    let keys: Vec<_> = captures
        .iter()
        .map(|capture| capture.key.as_str())
        .collect();
    let urls: Vec<_> = captures
        .iter()
        .map(|capture| capture.source_url.as_str())
        .collect();
    let bodies: Vec<_> = captures
        .iter()
        .map(|capture| capture.body_hash.as_str())
        .collect();
    let media: Vec<_> = captures
        .iter()
        .map(|capture| capture.media_type.as_str())
        .collect();
    let times: Vec<_> = captures
        .iter()
        .map(|capture| capture.retrieved_at)
        .collect();
    // Keep each requested occurrence, including duplicate capture IDs. A count
    // of matching distinct rows would change the scalar check's semantics.
    // IS NOT TRUE also rejects corrupt NULL fields rather than letting SQL's
    // three-valued logic hide a mismatched representation.
    let matches: bool = sqlx_core::query_scalar::query_scalar(
        "SELECT NOT EXISTS(SELECT 1 FROM UNNEST($1::text[],$2::text[],$3::text[],$4::text[],$5::text[],$6::bigint[]) AS requested(id,source_key,source_url,body_hash,media_type,retrieved_at) LEFT JOIN devres_captures AS retained ON retained.id=requested.id WHERE retained.id IS NULL OR (retained.source_key=requested.source_key AND retained.source_url=requested.source_url AND retained.body_hash=requested.body_hash AND retained.media_type=requested.media_type AND retained.retrieved_at=requested.retrieved_at) IS NOT TRUE)",
    )
    .bind(ids)
    .bind(keys)
    .bind(urls)
    .bind(bodies)
    .bind(media)
    .bind(times)
    .fetch_one(connection)
    .await
    .map_err(|_| storage_error())?;
    if !matches {
        return Err(Error::integrity(
            "RFC projection references a different or missing capture",
        ));
    }
    Ok(())
}

#[async_trait]
impl RfcCorpusStore for PgBlobStore {
    async fn save_dataset(&self, kind: &str, dataset: &Dataset) -> Result<()> {
        self.owner_fence().await?;
        kind_checked(kind)?;
        capture_checked(&dataset.capture)?;
        let expected_key = if kind == "catalogue" {
            "rfc:index"
        } else {
            "rfc:errata"
        };
        if dataset.capture.key != expected_key || dataset.records.len() > 100_000 {
            return Err(Error::invalid("RFC dataset does not match its source"));
        }
        let value = encoded(dataset)?;
        let mut owner = self.owner.lock().await;
        owner.ping().await.map_err(|_| storage_error())?;
        check_capture(&mut owner, &dataset.capture).await?;
        let mut tx = owner.begin().await.map_err(|_| storage_error())?;
        let saved: Option<String> = sqlx_core::query_scalar::query_scalar("INSERT INTO devres_rfc_datasets(kind,capture_id,data,data_integrity) VALUES($1,$2,$3,$4) ON CONFLICT(kind,capture_id) DO UPDATE SET capture_id=EXCLUDED.capture_id WHERE devres_rfc_datasets.data->'records'=EXCLUDED.data->'records' RETURNING capture_id")
            .bind(kind).bind(&dataset.capture.id).bind(Json(&value)).bind(payload_integrity::digest("devres_rfc_datasets",kind,&dataset.capture.id,&value)?)
            .fetch_optional(&mut *tx).await.map_err(|_| storage_error())?;
        if saved.is_none() {
            return Err(Error::integrity("Immutable RFC dataset cannot be replaced"));
        }
        let retained=sqlx_core::query::query("SELECT kind,capture_id AS key,data,data_integrity FROM devres_rfc_datasets WHERE kind=$1 AND capture_id=$2").bind(kind).bind(&dataset.capture.id).fetch_one(&mut *tx).await.map_err(|_|storage_error())?;
        payload_integrity::row("devres_rfc_datasets", &retained)?;
        sqlx_core::query::query("INSERT INTO devres_rfc_dataset_heads(kind,capture_id) SELECT $1,$2 WHERE EXISTS(SELECT 1 FROM devres_heads WHERE source_key=$3 AND capture_id=$2) ON CONFLICT(kind) DO UPDATE SET capture_id=EXCLUDED.capture_id")
            .bind(kind).bind(&dataset.capture.id).bind(expected_key).execute(&mut *tx).await.map_err(|_| storage_error())?;
        tx.commit().await.map_err(|_| storage_error())
    }

    async fn dataset(&self, kind: &str, capture: Option<&str>) -> Result<Option<Dataset>> {
        kind_checked(kind)?;
        if capture.is_some_and(|id| !valid_hash(id)) {
            return Err(Error::invalid("Invalid RFC dataset capture"));
        }
        self.fence().await?;
        let row = sqlx_core::query::query("SELECT d.kind,d.capture_id AS key,d.data,d.data_integrity,COALESCE((SELECT MAX(validated_at) FROM devres_observations WHERE capture_id=d.capture_id),c.retrieved_at) AS validated_at FROM devres_rfc_datasets d JOIN devres_captures c ON c.id=d.capture_id WHERE d.kind=$1 AND d.capture_id=COALESCE($2,(SELECT capture_id FROM devres_rfc_dataset_heads WHERE kind=$1))")
            .bind(kind).bind(capture).fetch_optional(&self.pool).await.map_err(|_| storage_error())?;
        row.map(|row| {
            let value = payload_integrity::row("devres_rfc_datasets", &row)?;
            let mut dataset: Dataset = decode(value)?;
            dataset.capture.validated_at =
                row.try_get("validated_at").map_err(|_| storage_error())?;
            Ok(dataset)
        })
        .transpose()
    }

    async fn schedule(&self, jobs: &[JobSpec]) -> Result<()> {
        self.owner_fence().await?;
        if jobs.len() > 100 {
            return Err(Error::capacity("RFC scheduling batch exceeds 100 jobs"));
        }
        for job in jobs {
            job_checked(job)?;
        }
        let mut owner = self.owner.lock().await;
        owner.ping().await.map_err(|_| storage_error())?;
        let mut tx = owner.begin().await.map_err(|_| storage_error())?;
        for job in jobs {
            sqlx_core::query::query("INSERT INTO devres_rfc_jobs(source_key,number,format,source_url,assurance,due_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(source_key) DO NOTHING")
                .bind(&job.key).bind(i64::from(job.number)).bind(&job.format).bind(&job.source_url)
                .bind(&job.assurance).bind(job.due_at).execute(&mut *tx).await.map_err(|_| storage_error())?;
            let same: bool = sqlx_core::query_scalar::query_scalar("SELECT EXISTS(SELECT 1 FROM devres_rfc_jobs WHERE source_key=$1 AND number=$2 AND format=$3 AND source_url=$4 AND assurance=$5)")
                .bind(&job.key).bind(i64::from(job.number)).bind(&job.format).bind(&job.source_url).bind(&job.assurance)
                .fetch_one(&mut *tx).await.map_err(|_| storage_error())?;
            if !same {
                return Err(Error::integrity("RFC job identity cannot change"));
            }
        }
        tx.commit().await.map_err(|_| storage_error())
    }

    async fn claim(&self, now: i64) -> Result<Option<Job>> {
        self.owner_fence().await?;
        let mut owner = self.owner.lock().await;
        owner.ping().await.map_err(|_| storage_error())?;
        let row = sqlx_core::query::query("UPDATE devres_rfc_jobs SET status='running',attempts=attempts+1 WHERE source_key=(SELECT source_key FROM devres_rfc_jobs WHERE assurance='https' AND status<>'running' AND due_at<=$1 AND attempts<4294967295 ORDER BY due_at,source_key FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING *")
            .bind(now).fetch_optional(&mut *owner).await.map_err(|_| storage_error())?;
        row.map(|row| {
            let number: i64 = row.try_get("number").map_err(|_| storage_error())?;
            let attempts: i64 = row.try_get("attempts").map_err(|_| storage_error())?;
            Ok(Job {
                spec: JobSpec {
                    key: row.try_get("source_key").map_err(|_| storage_error())?,
                    number: u32::try_from(number)
                        .map_err(|_| Error::integrity("Invalid stored RFC number"))?,
                    format: row.try_get("format").map_err(|_| storage_error())?,
                    source_url: row.try_get("source_url").map_err(|_| storage_error())?,
                    assurance: row.try_get("assurance").map_err(|_| storage_error())?,
                    due_at: row.try_get("due_at").map_err(|_| storage_error())?,
                },
                attempts: u32::try_from(attempts)
                    .map_err(|_| Error::integrity("Invalid RFC job attempt count"))?,
            })
        })
        .transpose()
    }

    async fn finish(
        &self,
        key: &str,
        capture: Option<&Capture>,
        error: Option<&str>,
        next_due: i64,
    ) -> Result<()> {
        self.owner_fence().await?;
        if key.len() > 2048
            || capture.is_some() == error.is_some()
            || error.is_some_and(|error| {
                error.is_empty() || error.len() > 512 || error.chars().any(char::is_control)
            })
        {
            return Err(Error::invalid("Invalid RFC job outcome"));
        }
        let value = capture.map(encoded).transpose()?;
        let mut owner = self.owner.lock().await;
        owner.ping().await.map_err(|_| storage_error())?;
        if let Some(capture) = capture {
            check_capture(&mut owner, capture).await?;
            if capture.key != key {
                return Err(Error::integrity(
                    "RFC job capture belongs to another source",
                ));
            }
        }
        let integrity = value
            .as_ref()
            .map(|value| {
                payload_integrity::digest("devres_rfc_jobs", "capture_metadata", key, value)
            })
            .transpose()?;
        let result = sqlx_core::query::query("UPDATE devres_rfc_jobs SET status=CASE WHEN $2::text IS NULL THEN 'failed' ELSE 'captured' END,capture_id=COALESCE($2,capture_id),capture_metadata=COALESCE($3,capture_metadata),capture_metadata_integrity=COALESCE($7,capture_metadata_integrity),last_error=$4,due_at=$5 WHERE source_key=$1 AND ($2::text IS NULL OR source_url=$6)")
            .bind(key).bind(capture.map(|capture| capture.id.as_str())).bind(value.map(Json))
            .bind(error).bind(next_due).bind(capture.map(|capture| capture.source_url.as_str())).bind(integrity)
            .execute(&mut *owner).await.map_err(|_| storage_error())?;
        if result.rows_affected() != 1 {
            return Err(Error::integrity(
                "RFC job is absent or its capture source differs",
            ));
        }
        Ok(())
    }

    async fn documents(&self) -> Result<Vec<Document>> {
        self.fence().await?;
        let rows = sqlx_core::query::query("SELECT source_key,number,format,assurance,capture_metadata,capture_metadata_integrity FROM devres_rfc_jobs WHERE capture_id IS NOT NULL ORDER BY number,format,assurance")
            .fetch_all(&self.pool).await.map_err(|_| storage_error())?;
        rows.into_iter()
            .map(|row| {
                let number: i64 = row.try_get("number").map_err(|_| storage_error())?;
                let Json(value): Json<Value> = row
                    .try_get("capture_metadata")
                    .map_err(|_| storage_error())?;
                Ok(Document {
                    number: u32::try_from(number)
                        .map_err(|_| Error::integrity("Invalid stored RFC number"))?,
                    format: row.try_get("format").map_err(|_| storage_error())?,
                    assurance: row.try_get("assurance").map_err(|_| storage_error())?,
                    capture: decode(payload_integrity::checked(
                        "devres_rfc_jobs",
                        "capture_metadata",
                        &row.try_get::<String, _>("source_key")
                            .map_err(|_| storage_error())?,
                        value,
                        &row.try_get::<String, _>("capture_metadata_integrity")
                            .map_err(|_| storage_error())?,
                    )?)?,
                })
            })
            .collect()
    }

    async fn save_snapshot(&self, snapshot: &Snapshot) -> Result<()> {
        self.owner_fence().await?;
        if !snapshot.id.starts_with("blake3:") {
            let retained = RfcCorpusStore::snapshot(self, Some(&snapshot.id))
                .await?
                .ok_or_else(|| {
                    Error::integrity("New RFC snapshots require tagged BLAKE3 identities.")
                })?;
            if encoded(&retained)? != encoded(snapshot)? {
                return Err(Error::integrity(
                    "Legacy RFC snapshot replay differs from retained evidence.",
                ));
            }
            return Ok(());
        }
        if !valid_hash(&snapshot.id)
            || !valid_hash(&snapshot.catalogue_capture)
            || snapshot
                .errata_capture
                .as_ref()
                .is_some_and(|id| !valid_hash(id))
            || snapshot.processor_version == 0
            || snapshot.documents.len() > 200_000
            || snapshot.search_documents.len() > 50_000
            || snapshot
                .index_path
                .as_ref()
                .is_some_and(|path| path.len() > 4096 || path.chars().any(char::is_control))
        {
            return Err(Error::invalid("Invalid RFC snapshot manifest"));
        }
        let representations = snapshot
            .documents
            .iter()
            .map(|document| {
                (
                    (
                        document.number,
                        document.format.as_str(),
                        document.assurance.as_str(),
                        document.capture.id.as_str(),
                    ),
                    &document.capture,
                )
            })
            .collect::<std::collections::HashMap<_, _>>();
        let mut searchable_numbers = std::collections::HashSet::new();
        for document in &snapshot.search_documents {
            let key = (
                document.number,
                document.format.as_str(),
                document.assurance.as_str(),
                document.capture.id.as_str(),
            );
            let original = representations.get(&key).ok_or_else(|| {
                Error::invalid("RFC search representation is absent from its snapshot")
            })?;
            if document.format == "pdf"
                || !searchable_numbers.insert(document.number)
                || encoded(*original)? != encoded(&document.capture)?
            {
                return Err(Error::invalid("Invalid RFC searchable representation"));
            }
        }
        let value = encoded(snapshot)?;
        let mut unique = std::collections::HashSet::new();
        for batch in snapshot.documents.chunks(100) {
            let mut owner = self.owner.lock().await;
            owner.ping().await.map_err(|_| storage_error())?;
            let mut captures = Vec::with_capacity(batch.len());
            for document in batch {
                let locally_valid = if !unique.insert((
                    document.number,
                    document.format.as_str(),
                    document.assurance.as_str(),
                )) {
                    Err(Error::invalid("Duplicate RFC snapshot representation"))
                } else {
                    job_checked(&JobSpec {
                        key: document.capture.key.clone(),
                        number: document.number,
                        format: document.format.clone(),
                        source_url: document.capture.source_url.clone(),
                        assurance: document.assurance.clone(),
                        due_at: 0,
                    })
                    .and_then(|()| capture_checked(&document.capture))
                };
                if let Err(error) = locally_valid {
                    // The scalar loop checked earlier captures before reaching
                    // this local error. Preserve that failure priority without
                    // issuing one database request per valid representation.
                    check_captures(&mut owner, &captures).await?;
                    return Err(error);
                }
                captures.push(&document.capture);
            }
            check_captures(&mut owner, &captures).await?;
        }
        let mut owner = self.owner.lock().await;
        owner.ping().await.map_err(|_| storage_error())?;
        let datasets_present: bool = sqlx_core::query_scalar::query_scalar("SELECT EXISTS(SELECT 1 FROM devres_rfc_datasets WHERE kind='catalogue' AND capture_id=$1) AND ($2::text IS NULL OR EXISTS(SELECT 1 FROM devres_rfc_datasets WHERE kind='errata' AND capture_id=$2))")
            .bind(&snapshot.catalogue_capture).bind(&snapshot.errata_capture).fetch_one(&mut *owner).await.map_err(|_| storage_error())?;
        if !datasets_present {
            return Err(Error::integrity(
                "RFC snapshot references an absent dataset",
            ));
        }
        for (kind, id) in [
            ("catalogue", Some(&snapshot.catalogue_capture)),
            ("errata", snapshot.errata_capture.as_ref()),
        ] {
            if let Some(id) = id {
                let row=sqlx_core::query::query("SELECT kind,capture_id AS key,data,data_integrity FROM devres_rfc_datasets WHERE kind=$1 AND capture_id=$2").bind(kind).bind(id).fetch_one(&mut *owner).await.map_err(|_|storage_error())?;
                payload_integrity::row("devres_rfc_datasets", &row)?;
            }
        }
        let order: i64 = sqlx_core::query_scalar::query_scalar(
            "SELECT nextval(pg_get_serial_sequence('devres_rfc_snapshots','published_order'))",
        )
        .fetch_one(&mut *owner)
        .await
        .map_err(|_| storage_error())?;
        let integrity = payload_integrity::digest(
            "devres_rfc_snapshots",
            "",
            &snapshot.id,
            &payload_integrity::rfc_snapshot_payload(
                order,
                snapshot.catalogue_capture.clone(),
                snapshot.errata_capture.clone(),
                snapshot.created_at,
                snapshot.complete,
                &value,
            )?,
        )?;
        let result: Option<String> = sqlx_core::query_scalar::query_scalar("INSERT INTO devres_rfc_snapshots(id,catalogue_capture,errata_capture,created_at,complete,data,data_integrity,published_order) OVERRIDING SYSTEM VALUE VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(id) DO UPDATE SET id=EXCLUDED.id WHERE devres_rfc_snapshots.data=EXCLUDED.data RETURNING id")
            .bind(&snapshot.id).bind(&snapshot.catalogue_capture).bind(&snapshot.errata_capture)
            .bind(snapshot.created_at).bind(snapshot.complete).bind(Json(&value)).bind(integrity).bind(order)
            .fetch_optional(&mut *owner).await.map_err(|_| storage_error())?;
        if result.is_none() {
            return Err(Error::integrity(
                "Immutable RFC snapshot cannot be replaced",
            ));
        }
        let retained=sqlx_core::query::query("SELECT published_order,catalogue_capture,errata_capture,created_at,complete,''::text AS kind,id AS key,data,data_integrity FROM devres_rfc_snapshots WHERE id=$1").bind(&snapshot.id).fetch_one(&mut *owner).await.map_err(|_|storage_error())?;
        payload_integrity::row("devres_rfc_snapshots", &retained)?;
        Ok(())
    }

    async fn snapshot(&self, id: Option<&str>) -> Result<Option<Snapshot>> {
        if id.is_some_and(|id| !valid_hash(id)) {
            return Err(Error::invalid("Invalid RFC snapshot identifier"));
        }
        self.fence().await?;
        let row = sqlx_core::query::query("SELECT published_order,catalogue_capture,errata_capture,created_at,complete,''::text AS kind,id AS key,data,data_integrity FROM devres_rfc_snapshots WHERE ($1::text IS NULL OR id=$1) ORDER BY complete DESC,published_order DESC LIMIT 1")
            .bind(id).fetch_optional(&self.pool).await.map_err(|_| storage_error())?;
        row.map(|row| decode(payload_integrity::row("devres_rfc_snapshots", &row)?))
            .transpose()
    }

    async fn status(&self) -> Result<Value> {
        self.fence().await?;
        let rows = sqlx_core::query::query("SELECT status,count(*) AS count,count(capture_id) AS retained_count,min(due_at) AS earliest_due FROM devres_rfc_jobs GROUP BY status ORDER BY status")
            .fetch_all(&self.pool).await.map_err(|_| storage_error())?;
        let mut counts = serde_json::Map::new();
        let mut total_jobs = 0_i64;
        let mut captured_documents = 0_i64;
        let mut outstanding_jobs = 0_i64;
        for row in rows {
            let status: String = row.try_get("status").map_err(|_| storage_error())?;
            let count: i64 = row.try_get("count").map_err(|_| storage_error())?;
            let earliest_due: i64 = row.try_get("earliest_due").map_err(|_| storage_error())?;
            let retained: i64 = row.try_get("retained_count").map_err(|_| storage_error())?;
            total_jobs += count;
            captured_documents += retained;
            if status != "captured" {
                outstanding_jobs += count;
            }
            counts.insert(status, json!({"count":count,"earliest_due":earliest_due}));
        }
        let errors = sqlx_core::query::query("SELECT source_key,last_error,due_at FROM devres_rfc_jobs WHERE last_error IS NOT NULL ORDER BY due_at,source_key LIMIT 20")
            .fetch_all(&self.pool).await.map_err(|_| storage_error())?;
        let errors = errors.into_iter().map(|row| {
            Ok(json!({"key":row.try_get::<String,_>("source_key").map_err(|_| storage_error())?,"error":row.try_get::<String,_>("last_error").map_err(|_| storage_error())?,"next_due":row.try_get::<i64,_>("due_at").map_err(|_| storage_error())?}))
        }).collect::<Result<Vec<_>>>()?;
        let latest = self.snapshot(None).await?;
        let partial = sqlx_core::query::query("SELECT published_order,catalogue_capture,errata_capture,complete,id,id AS key,''::text AS kind,created_at,data,data_integrity FROM devres_rfc_snapshots WHERE NOT complete ORDER BY published_order DESC LIMIT 1").fetch_optional(&self.pool).await.map_err(|_|storage_error())?.map(|row|Ok::<_,Error>(json!({"id":row.try_get::<String,_>("id").map_err(|_|storage_error())?,"created_at":row.try_get::<i64,_>("created_at").map_err(|_|storage_error())?,"coverage":payload_integrity::row("devres_rfc_snapshots",&row)?["coverage"]}))).transpose()?;
        Ok(
            json!({"jobs":counts,"total_jobs":total_jobs,"captured_documents":captured_documents,"pending_documents":total_jobs-captured_documents,"outstanding_jobs":outstanding_jobs,"errors":errors,"latest_partial":partial,"snapshot":latest.map(|snapshot| json!({"id":snapshot.id,"complete":snapshot.complete,"created_at":snapshot.created_at,"coverage":snapshot.coverage}))}),
        )
    }
}

pub(super) const SCHEMA_V2: &str = r#"
CREATE TABLE devres_rfc_datasets (
 kind text NOT NULL CHECK(kind IN ('catalogue','errata')),
 capture_id text NOT NULL REFERENCES devres_captures(id),data jsonb NOT NULL,
 PRIMARY KEY(kind,capture_id)
);
CREATE TABLE devres_rfc_dataset_heads (
 kind text PRIMARY KEY,capture_id text NOT NULL,
 FOREIGN KEY(kind,capture_id) REFERENCES devres_rfc_datasets(kind,capture_id)
);
CREATE TABLE devres_rfc_jobs (
 source_key text PRIMARY KEY,number bigint NOT NULL CHECK(number BETWEEN 1 AND 999999),
 format text NOT NULL CHECK(format IN ('txt','html','xml','pdf')),source_url text NOT NULL,
 assurance text NOT NULL CHECK(assurance IN ('https','rsync')),due_at bigint NOT NULL,
 attempts bigint NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 4294967295),
 status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','running','captured','failed')),
 last_error text,capture_id text REFERENCES devres_captures(id),capture_metadata jsonb,
 CHECK((capture_id IS NULL)=(capture_metadata IS NULL))
);
CREATE INDEX devres_rfc_jobs_due ON devres_rfc_jobs(due_at,source_key) WHERE status<>'running';
CREATE TABLE devres_rfc_snapshots (
 published_order bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
 id text PRIMARY KEY CHECK(length(id)=64),catalogue_capture text NOT NULL REFERENCES devres_captures(id),
 errata_capture text REFERENCES devres_captures(id),created_at bigint NOT NULL,complete boolean NOT NULL,data jsonb NOT NULL
);
CREATE INDEX devres_rfc_snapshots_latest ON devres_rfc_snapshots(complete DESC,published_order DESC);
CREATE TABLE devres_rfc_import_observations (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,capture_id text NOT NULL REFERENCES devres_captures(id),
 observed_at bigint NOT NULL,source_url text NOT NULL
);
CREATE INDEX devres_rfc_import_capture ON devres_rfc_import_observations(capture_id);
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn import_provenance_requires_canonical_separate_identity() {
        assert!(
            imported_source(
                "rfc:rsync:9000:txt",
                "rsync://rsync.rfc-editor.org/rfcs/rfc9000.txt"
            )
            .unwrap()
        );
        assert!(
            !imported_source(
                "rfc:text:9000",
                "https://www.rfc-editor.org/rfc/rfc9000.txt"
            )
            .unwrap()
        );
        for (key, url) in [
            (
                "rfc:text:9000",
                "rsync://rsync.rfc-editor.org/rfcs/rfc9000.txt",
            ),
            (
                "rfc:rsync:9000:txt",
                "https://www.rfc-editor.org/rfc/rfc9000.txt",
            ),
            (
                "rfc:rsync:9000:txt",
                "rsync://attacker.invalid/rfcs/rfc9000.txt",
            ),
            (
                "rfc:rsync:09000:txt",
                "rsync://rsync.rfc-editor.org/rfcs/rfc9000.txt",
            ),
            (
                "rfc:rsync:0:txt",
                "rsync://rsync.rfc-editor.org/rfcs/rfc0.txt",
            ),
        ] {
            assert!(imported_source(key, url).is_err());
        }
    }
}

impl PgBlobStore {
    /// Build canonical RFC generations from exact retained source/index evidence.
    /// Publication pointers are staged; original rows and ordering remain untouched.
    pub async fn migrate_rfc_graph(
        &self,
        mappings: &mut crate::migration_map::MigrationMap,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<crate::migration_map::MigrationAliases> {
        self.owner_fence().await?;
        self.migrate_rfc_graph_with_execution(
            mappings,
            cancel,
            &crate::MigrationExecution::default(),
        )
        .await
    }

    pub async fn migrate_rfc_graph_with_execution(
        &self,
        mappings: &mut crate::migration_map::MigrationMap,
        cancel: tokio_util::sync::CancellationToken,
        execution: &crate::MigrationExecution,
    ) -> Result<crate::migration_map::MigrationAliases> {
        self.owner_fence().await?;
        self.fence().await?;
        let mut aliases = crate::migration_map::MigrationAliases::new(mappings)?;
        let mut after = (String::new(), String::new());
        loop {
            migration_cancel(&cancel)?;
            let metadata=sqlx_core::query::query("SELECT kind,capture_id AS key,octet_length(data::text)::bigint AS payload_bytes,jsonb_array_length(jsonb_path_query_array(data,'strict $.**.type()'))::bigint AS payload_nodes FROM devres_rfc_datasets WHERE capture_id NOT LIKE 'blake3:%' AND (kind,capture_id)>($1,$2) ORDER BY kind,capture_id LIMIT 1")
                .bind(&after.0).bind(&after.1).fetch_optional(&self.pool).await.map_err(|_|storage_error())?;
            let Some(metadata) = metadata else {
                break;
            };
            let kind: String = metadata.try_get("kind").map_err(|_| storage_error())?;
            let old: String = metadata.try_get("key").map_err(|_| storage_error())?;
            let charge = rfc_migration_input_charge(&metadata)?;
            let _reservation = execution.graph_reserve(charge, &cancel).await?;
            let row = sqlx_core::query::query("SELECT kind,capture_id AS key,data,data_integrity FROM devres_rfc_datasets WHERE kind=$1 AND capture_id=$2")
                .bind(&kind).bind(&old).fetch_one(&self.pool).await.map_err(|_| storage_error())?;
            let mut dataset: Dataset =
                decode(payload_integrity::row("devres_rfc_datasets", &row)?)?;
            migrate_rfc_capture(&mut dataset.capture, mappings)?;
            self.save_dataset(&kind, &dataset).await?;
            aliases.push((
                format!("dataset-{kind}"),
                old.clone(),
                dataset.capture.id.clone(),
            ))?;
            after = (kind, old);
        }
        let mut after = 0_i64;
        let mut index_cache = crate::rfc::index::MigrationRebuildCache::default();
        let mut admitted = 0_u64;
        let mut committed = 0_u64;
        loop {
            migration_cancel(&cancel)?;
            let mut window = Vec::new();
            let mut window_bytes = 0_usize;
            let mut next = after;
            while window.len()
                < execution
                    .options()
                    .workers
                    .min(crate::migration_execution::MIGRATION_WINDOW_RECORDS)
            {
                let found=sqlx_core::query::query("SELECT published_order,id AS key,octet_length(data::text)::bigint AS payload_bytes,jsonb_array_length(jsonb_path_query_array(data,'strict $.**.type()'))::bigint AS payload_nodes FROM devres_rfc_snapshots WHERE id NOT LIKE 'blake3:%' AND published_order>$1 ORDER BY published_order LIMIT 1")
                    .bind(next).fetch_optional(&self.pool).await.map_err(|_|storage_error())?;
                let Some(found) = found else {
                    break;
                };
                let payload_bytes = usize::try_from(
                    found
                        .try_get::<i64, _>("payload_bytes")
                        .map_err(|_| storage_error())?,
                )
                .map_err(|_| storage_error())?;
                // Typed snapshots, checksum envelopes and temporary JSON clones
                // remain charged alongside a 64 MiB writer, queued documents,
                // export page, pending document and membership bookkeeping.
                let payload_nodes = usize::try_from(
                    found
                        .try_get::<i64, _>("payload_nodes")
                        .map_err(|_| storage_error())?,
                )
                .map_err(|_| storage_error())?;
                let estimated_bytes =
                    crate::MigrationExecution::graph_input_charge(payload_bytes, payload_nodes)?
                        .checked_add(192 * 1024 * 1024)
                        .ok_or_else(|| {
                            Error::capacity("RFC migration memory accounting overflow.")
                        })?;
                let proposed = window_bytes
                    .checked_add(estimated_bytes)
                    .ok_or_else(|| Error::capacity("RFC migration memory accounting overflow."))?;
                if !window.is_empty() && proposed > execution.graph_options().memory_budget_bytes {
                    break;
                }
                let old: String = found.try_get("key").map_err(|_| storage_error())?;
                next = found
                    .try_get("published_order")
                    .map_err(|_| storage_error())?;
                window.push(((next, old), estimated_bytes));
                window_bytes = proposed;
                if window_bytes > execution.graph_options().memory_budget_bytes {
                    break;
                }
            }
            if window.is_empty() {
                break;
            }
            admitted += window.len() as u64;
            let previous = index_cache.clone();
            let read_mappings: &crate::migration_map::MigrationMap = mappings;
            let prepared = execution
                .graph_map_ordered(
                    window,
                    &cancel,
                    |(order, old), token| {
                        let mut cache = previous.clone();
                        let root = self.root.clone();
                        async move {
                            migration_cancel(&token)?;
                            let found = sqlx_core::query::query("SELECT published_order,catalogue_capture,errata_capture,created_at,complete,''::text AS kind,id AS key,data,data_integrity FROM devres_rfc_snapshots WHERE published_order=$1 AND id=$2")
                                .bind(order).bind(&old).fetch_one(&self.pool).await.map_err(|_| storage_error())?;
                            let mut snapshot: Snapshot =
                                decode(payload_integrity::row("devres_rfc_snapshots", &found)?)?;
                            snapshot.catalogue_capture =
                                migration_reference(&snapshot.catalogue_capture, read_mappings)?;
                            snapshot.errata_capture = snapshot
                                .errata_capture
                                .as_deref()
                                .map(|id| migration_reference(id, read_mappings))
                                .transpose()?;
                            for document in snapshot
                                .documents
                                .iter_mut()
                                .chain(snapshot.search_documents.iter_mut())
                            {
                                migrate_rfc_capture(&mut document.capture, read_mappings)?;
                            }
                            let original_index = snapshot.index_path.take();
                            snapshot.id = String::new();
                            let identity =
                                serde_json::to_value(("devres:storage-migration:snapshot:v1", &old, &snapshot))
                                    .map_err(|_| storage_error())?;
                            snapshot.id = crate::integrity::canonical_hash(&identity)?;
                            let changed_cache = if let Some(path) = original_index {
                                snapshot.index_path = Some(
                                    crate::rfc::index::rebuild_frozen_cached_with_execution(
                                        root,
                                        path,
                                        snapshot.id.clone(),
                                        token,
                                        &mut cache,
                                        execution,
                                    )
                                    .await?,
                                );
                                Some(cache)
                            } else {
                                None
                            };
                            Ok((order, old, snapshot, changed_cache))
                        }
                    },
                )
                .await?;
            execution.report(
                "graph_rfc_indexes",
                admitted,
                admitted,
                committed,
                window_bytes,
            );
            for prepared in prepared {
                migration_cancel(&cancel)?;
                let (order, old, snapshot, _) = prepared.value();
                let publication = std::time::Instant::now();
                self.save_snapshot(snapshot).await?;
                execution.record_publication(publication.elapsed());
                if mappings
                    .get(&format!("rfc:snapshots:{old}"))
                    .is_some_and(|prior| prior != snapshot.id)
                {
                    return Err(Error::integrity("Ambiguous RFC migration identity."));
                }
                crate::migration_map::insert(
                    mappings,
                    format!("rfc:snapshots:{old}"),
                    snapshot.id.clone(),
                )?;
                aliases.push(("snapshots".into(), old.clone(), snapshot.id.clone()))?;
                after = *order;
                let (_, _, _, cache) = prepared.into_inner_after_commit();
                if let Some(cache) = cache {
                    index_cache = cache;
                }
                committed += 1;
                execution.report(
                    "graph_rfc_indexes",
                    admitted,
                    admitted,
                    committed,
                    window_bytes,
                );
            }
        }
        let heads: Vec<(String, String)> = sqlx_core::query_as::query_as(
            "SELECT kind,capture_id FROM devres_rfc_dataset_heads ORDER BY kind",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|_| storage_error())?;
        for (kind, capture) in heads {
            let canonical = migration_reference(&capture, mappings)?;
            payload_integrity::stage(
                self,
                "rfc",
                &format!("dataset-head:{kind}"),
                &json!({"kind":kind,"capture_id":canonical}),
            )
            .await?;
        }
        let mut after = String::new();
        loop {
            migration_cancel(&cancel)?;
            let metadata=sqlx_core::query::query("SELECT source_key,octet_length(capture_metadata::text)::bigint AS payload_bytes,jsonb_array_length(jsonb_path_query_array(capture_metadata,'strict $.**.type()'))::bigint AS payload_nodes FROM devres_rfc_jobs WHERE capture_metadata IS NOT NULL AND source_key>$1 ORDER BY source_key LIMIT 1")
                .bind(&after).fetch_optional(&self.pool).await.map_err(|_|storage_error())?;
            let Some(metadata) = metadata else {
                break;
            };
            let key: String = metadata
                .try_get("source_key")
                .map_err(|_| storage_error())?;
            let charge = rfc_migration_input_charge(&metadata)?;
            let _reservation = execution.graph_reserve(charge, &cancel).await?;
            let found = sqlx_core::query::query("SELECT source_key,capture_id,capture_metadata,capture_metadata_integrity FROM devres_rfc_jobs WHERE source_key=$1 AND capture_metadata IS NOT NULL")
                .bind(&key).fetch_one(&self.pool).await.map_err(|_| storage_error())?;
            let data: Json<Value> = found
                .try_get("capture_metadata")
                .map_err(|_| storage_error())?;
            let data = payload_integrity::checked(
                "devres_rfc_jobs",
                "capture_metadata",
                &key,
                data.0,
                &found
                    .try_get::<String, _>("capture_metadata_integrity")
                    .map_err(|_| storage_error())?,
            )?;
            let mut capture: Capture = decode(data)?;
            migrate_rfc_capture(&mut capture, mappings)?;
            payload_integrity::stage(
                self,
                "rfc",
                &format!("job:{key}"),
                &json!({"source_key":key,"capture_id":capture.id,"capture_metadata":capture}),
            )
            .await?;
            after = key;
        }
        mappings.ensure_healthy()?;
        aliases.ensure_healthy()?;
        Ok(aliases)
    }
}

fn rfc_migration_input_charge(metadata: &sqlx_postgres::PgRow) -> Result<usize> {
    let encoded_bytes = usize::try_from(
        metadata
            .try_get::<i64, _>("payload_bytes")
            .map_err(|_| storage_error())?,
    )
    .map_err(|_| storage_error())?;
    let nodes = usize::try_from(
        metadata
            .try_get::<i64, _>("payload_nodes")
            .map_err(|_| storage_error())?,
    )
    .map_err(|_| storage_error())?;
    crate::MigrationExecution::graph_input_charge(encoded_bytes, nodes)
}

fn migration_cancel(cancel: &tokio_util::sync::CancellationToken) -> Result<()> {
    if cancel.is_cancelled() {
        return Err(Error::new("cancelled", "RFC graph migration canceled."));
    }
    Ok(())
}
fn migration_reference(
    value: &str,
    mappings: &crate::migration_map::MigrationMap,
) -> Result<String> {
    if value.starts_with("blake3:") && valid_hash(value) {
        return Ok(value.to_owned());
    }
    mappings
        .get(&format!("capture:{value}"))
        .ok_or_else(|| Error::integrity("Unresolved RFC migration reference."))
}
fn migrate_rfc_capture(
    capture: &mut Capture,
    mappings: &crate::migration_map::MigrationMap,
) -> Result<()> {
    capture.id = migration_reference(&capture.id, mappings)?;
    if !capture.body_hash.starts_with("blake3:") {
        capture.body_hash = mappings
            .get(&format!("body:{}", capture.body_hash))
            .ok_or_else(|| Error::integrity("Unresolved RFC body reference."))?;
    }
    Ok(())
}

#[cfg(test)]
mod migration_tests {
    use super::*;
    #[tokio::test]
    #[ignore = "requires disposable PostgreSQL; run scripts/test-postgres.sh"]
    async fn rfc_graph_parallel_publication_preserves_order_and_legacy_partial_resume() {
        use devres_application::Store;
        use devres_domain::{FetchRequest, FetchResponse, Validators};
        use std::sync::Arc;
        let _indexes = crate::rfc::index::TEST_SERIAL.lock().await;
        let base =
            std::env::var("DEVRES_TEST_DATABASE_URL").expect("disposable PostgreSQL required");
        let admin = sqlx_postgres::PgPool::connect(&base).await.unwrap();
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut expected = None;
        for (workers, partial, small_budget) in [
            (1, false, false),
            (3, false, false),
            (3, true, false),
            (3, true, true),
        ] {
            let database = format!("devres_rfc_graph_{suffix}_{workers}_{partial}_{small_budget}");
            sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!(
                "CREATE DATABASE {database}"
            )))
            .execute(&admin)
            .await
            .unwrap();
            let mut url = url::Url::parse(&base).unwrap();
            url.set_path(&format!("/{database}"));
            let root = tempfile::tempdir_in("/tmp").unwrap();
            let store = PgBlobStore::connect(url.as_str(), root.path())
                .await
                .unwrap();
            let pool = sqlx_postgres::PgPool::connect(url.as_str()).await.unwrap();
            let mut captures = Vec::new();
            for (key, url, body) in [
                (
                    "rfc:index",
                    "https://www.rfc-editor.org/rfc-index.xml",
                    "catalogue",
                ),
                (
                    "rfc:text:1",
                    "https://www.rfc-editor.org/rfc/rfc1.txt",
                    "transport cats",
                ),
                (
                    "rfc:text:2",
                    "https://www.rfc-editor.org/rfc/rfc2.txt",
                    "transport dogs",
                ),
            ] {
                captures.push(
                    store
                        .publish(
                            &FetchRequest {
                                key: key.into(),
                                url: url.into(),
                                ttl_secs: 3600,
                                max_bytes: 1024,
                                media_type: "text/plain".into(),
                            },
                            FetchResponse {
                                status: 200,
                                body: body.as_bytes().to_vec(),
                                validators: Validators::default(),
                            },
                            1,
                        )
                        .await
                        .unwrap()
                        .capture,
                );
            }
            let records = vec![Value::Array(vec![Value::Null; 2048])];
            store
                .save_dataset(
                    "catalogue",
                    &Dataset {
                        capture: captures[0].clone(),
                        records: records.clone(),
                    },
                )
                .await
                .unwrap();
            let mut legacy_catalogue = captures[0].clone();
            legacy_catalogue.body_hash = crate::integrity::legacy_hash(b"catalogue");
            legacy_catalogue.id = crate::integrity::legacy_hash(
                format!(
                    "{}\0{}\0{}\0{}",
                    legacy_catalogue.key,
                    legacy_catalogue.source_url,
                    legacy_catalogue.media_type,
                    legacy_catalogue.body_hash
                )
                .as_bytes(),
            );
            std::fs::write(root.path().join(&legacy_catalogue.body_hash), b"catalogue").unwrap();
            let metadata_proof = super::super::capture_metadata_digest(&legacy_catalogue).unwrap();
            sqlx_core::query::query("INSERT INTO devres_captures(id,source_key,source_url,body_hash,media_type,retrieved_at,metadata_integrity) VALUES($1,$2,$3,$4,$5,$6,$7)")
                .bind(&legacy_catalogue.id).bind(&legacy_catalogue.key).bind(&legacy_catalogue.source_url).bind(&legacy_catalogue.body_hash).bind(&legacy_catalogue.media_type).bind(legacy_catalogue.retrieved_at).bind(metadata_proof).execute(&pool).await.unwrap();
            let legacy_dataset = serde_json::to_value(Dataset {
                capture: legacy_catalogue.clone(),
                records,
            })
            .unwrap();
            let dataset_proof = payload_integrity::digest(
                "devres_rfc_datasets",
                "catalogue",
                &legacy_catalogue.id,
                &legacy_dataset,
            )
            .unwrap();
            sqlx_core::query::query("INSERT INTO devres_rfc_datasets(kind,capture_id,data,data_integrity) VALUES('catalogue',$1,$2,$3)")
                .bind(&legacy_catalogue.id).bind(Json(legacy_dataset)).bind(dataset_proof).execute(&pool).await.unwrap();
            store
                .schedule(&[JobSpec {
                    key: captures[1].key.clone(),
                    number: 1,
                    format: "txt".into(),
                    source_url: captures[1].source_url.clone(),
                    assurance: "https".into(),
                    due_at: 0,
                }])
                .await
                .unwrap();
            store
                .finish(&captures[1].key, Some(&captures[1]), None, 10)
                .await
                .unwrap();
            let documents: Vec<_> = (1..=2)
                .map(|number| Document {
                    number,
                    format: "txt".into(),
                    capture: captures[number as usize].clone(),
                    assurance: "https".into(),
                })
                .collect();
            let source = crate::rfc::index::build(
                root.path(),
                &crate::integrity::legacy_hash(b"retained RFC graph index"),
                vec![
                    crate::rfc::index::IndexDocument {
                        number: 1,
                        text: "transport cats".into(),
                    },
                    crate::rfc::index::IndexDocument {
                        number: 2,
                        text: "transport dogs".into(),
                    },
                ],
            )
            .unwrap();
            let mut originals = Vec::new();
            for order in 1..=3_i64 {
                let old = crate::integrity::legacy_hash(
                    format!("retained RFC graph snapshot {order}").as_bytes(),
                );
                let snapshot = Snapshot {
                    id: old.clone(),
                    catalogue_capture: legacy_catalogue.id.clone(),
                    errata_capture: None,
                    documents: documents.clone(),
                    search_documents: documents.clone(),
                    coverage: json!({"fixture":order,"wide":vec![Value::Null;2048]}),
                    created_at: order + 10,
                    complete: order != 2,
                    index_path: Some(source.clone()),
                    processor_version: 1,
                };
                let value = encoded(&snapshot).unwrap();
                let proof = payload_integrity::digest(
                    "devres_rfc_snapshots",
                    "",
                    &old,
                    &payload_integrity::rfc_snapshot_payload(
                        order,
                        snapshot.catalogue_capture.clone(),
                        None,
                        snapshot.created_at,
                        snapshot.complete,
                        &value,
                    )
                    .unwrap(),
                )
                .unwrap();
                sqlx_core::query::query("INSERT INTO devres_rfc_snapshots(id,catalogue_capture,errata_capture,created_at,complete,data,data_integrity,published_order) OVERRIDING SYSTEM VALUE VALUES($1,$2,NULL,$3,$4,$5,$6,$7)")
                    .bind(&old).bind(&snapshot.catalogue_capture).bind(snapshot.created_at).bind(snapshot.complete).bind(Json(value)).bind(proof).bind(order).execute(&pool).await.unwrap();
                let coverage_nodes: i64 = sqlx_core::query_scalar::query_scalar("SELECT jsonb_array_length(jsonb_path_query_array(data->'coverage','strict $.**.type()'))::bigint FROM devres_rfc_snapshots WHERE id=$1")
                    .bind(&old).fetch_one(&pool).await.unwrap();
                assert_eq!(
                    coverage_nodes, 2051,
                    "actual PostgreSQL recursive shape metadata counts each JSON value"
                );
                originals.push(snapshot);
            }
            sqlx_core::query::query(
                "SELECT setval(pg_get_serial_sequence('devres_rfc_snapshots','published_order'),3)",
            )
            .execute(&pool)
            .await
            .unwrap();
            sqlx_core::query::query("UPDATE devres_integrity_control SET active=false,files_complete=false,sql_complete=false,graph_complete=false WHERE singleton").execute(&pool).await.unwrap();
            if partial {
                // Produce the exact checkpoint shape written by the old serial
                // schema-ten implementation, then reopen it in another invocation.
                let mut canonical = originals[0].clone();
                let old = canonical.id.clone();
                canonical.catalogue_capture = captures[0].id.clone();
                canonical.index_path = None;
                canonical.id.clear();
                canonical.id = crate::integrity::canonical_hash(
                    &serde_json::to_value((
                        "devres:storage-migration:snapshot:v1",
                        &old,
                        &canonical,
                    ))
                    .unwrap(),
                )
                .unwrap();
                canonical.index_path = Some(
                    crate::rfc::index::rebuild_frozen(
                        root.path().to_owned(),
                        source.clone(),
                        canonical.id.clone(),
                        tokio_util::sync::CancellationToken::new(),
                    )
                    .await
                    .unwrap(),
                );
                store.save_snapshot(&canonical).await.unwrap();
            }
            drop(store);
            let store = Arc::new(
                PgBlobStore::connect_for_migration(url.as_str(), root.path())
                    .await
                    .unwrap(),
            );
            let budget = if small_budget {
                8 * 1024 * 1024
            } else {
                1024 * 1024 * 1024
            };
            let context = crate::MigrationExecution::new_with_graph_options(
                crate::MigrationExecutionOptions::new(workers, 64 * 1024 * 1024).unwrap(),
                crate::MigrationGraphOptions::new(budget).unwrap(),
            )
            .unwrap();
            let mut mappings = crate::migration_map::MigrationMap::new();
            crate::migration_map::insert(
                &mut mappings,
                format!("capture:{}", legacy_catalogue.id),
                captures[0].id.clone(),
            )
            .unwrap();
            crate::migration_map::insert(
                &mut mappings,
                format!("body:{}", legacy_catalogue.body_hash),
                captures[0].body_hash.clone(),
            )
            .unwrap();
            let aliases = store
                .migrate_rfc_graph_with_execution(
                    &mut mappings,
                    tokio_util::sync::CancellationToken::new(),
                    &context,
                )
                .await
                .unwrap();
            assert_eq!(aliases.try_chunks(100).next().unwrap().unwrap().len(), 4);
            let staged_job: Json<Value> = sqlx_core::query_scalar::query_scalar(
                "SELECT data FROM devres_integrity_staged_state WHERE provider='rfc' AND key=$1",
            )
            .bind(format!("job:{}", captures[1].key))
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(
                staged_job.0["capture_metadata"],
                serde_json::to_value(&captures[1]).unwrap()
            );
            let rows: Vec<Json<Value>> = sqlx_core::query_scalar::query_scalar("SELECT data FROM devres_rfc_snapshots WHERE id LIKE 'blake3:%' ORDER BY published_order").fetch_all(&pool).await.unwrap();
            let rows: Vec<Value> = rows.into_iter().map(|row| row.0).collect();
            assert_eq!(rows.len(), 3);
            assert_eq!(
                rows.iter()
                    .map(|row| row["coverage"]["fixture"].as_i64().unwrap())
                    .collect::<Vec<_>>(),
                [1, 2, 3]
            );
            assert_eq!(
                store.snapshot(None).await.unwrap().unwrap().id,
                rows[2]["id"].as_str().unwrap()
            );
            let legacy_count: i64 = sqlx_core::query_scalar::query_scalar(
                "SELECT count(*) FROM devres_rfc_snapshots WHERE id NOT LIKE 'blake3:%'",
            )
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(legacy_count, 3);
            if let Some(expected) = &expected {
                assert_eq!(&rows, expected);
            } else {
                expected = Some(rows);
            }
            assert_eq!(context.snapshot().active, 0);
            assert_eq!(context.snapshot().graph_active, 0);
            assert_eq!(context.snapshot().graph_memory_bytes, 0);
            if small_budget {
                assert_eq!(context.snapshot().graph_high_water, 1);
                assert!(
                    context.snapshot().graph_memory_high_water > budget,
                    "a structurally wide valid singleton runs exclusively above the aggregate budget"
                );
            } else if workers > 1 {
                assert!(context.snapshot().graph_high_water > 1);
            }
            drop(aliases);
            drop(mappings);
            drop(store);
            pool.close().await;
            sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!(
                "DROP DATABASE {database} WITH(FORCE)"
            )))
            .execute(&admin)
            .await
            .unwrap();
        }
        admin.close().await;
    }

    #[test]
    fn capture_migration_keeps_body_and_capture_namespaces_distinct() {
        let old = "a".repeat(64);
        let capture_id = crate::integrity::hash(b"capture identity");
        let body = crate::integrity::hash(b"source body");
        let mut maps = crate::migration_map::MigrationMap::new();
        for (key, value) in [
            (format!("capture:{old}"), capture_id.clone()),
            (format!("body:{old}"), body.clone()),
        ] {
            crate::migration_map::insert(&mut maps, key, value).unwrap();
        }
        let mut capture = Capture {
            id: old.clone(),
            body_hash: old.clone(),
            key: "rfc:text:1".into(),
            source_url: format!("https://fixtures.invalid/{old}"),
            media_type: "text/plain".into(),
            retrieved_at: 1,
            validated_at: 2,
        };
        migrate_rfc_capture(&mut capture, &maps).unwrap();
        assert_eq!(capture.id, capture_id);
        assert_eq!(capture.body_hash, body);
        assert_eq!(
            capture.source_url,
            format!("https://fixtures.invalid/{old}")
        );
        assert_eq!((capture.retrieved_at, capture.validated_at), (1, 2));
    }
}
