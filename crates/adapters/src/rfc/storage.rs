//! Owner-fenced durable RFC jobs, immutable projections, and snapshot manifests.
use super::{PgBlobStore, storage_error, valid_hash};
use async_trait::async_trait;
use devres_application::corpus::{Dataset, Document, Job, JobSpec, RfcCorpusStore, Snapshot};
use devres_domain::{Capture, Error, Result};
use serde::Serialize;
use serde_json::{Value, json};
use sqlx::{Connection, Row, types::Json};

const MAX_JSON: usize = 64 * 1024 * 1024;

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

async fn check_capture(connection: &mut sqlx::PgConnection, capture: &Capture) -> Result<()> {
    capture_checked(capture)?;
    let matches: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM devres_captures WHERE id=$1 AND source_key=$2 AND source_url=$3 AND body_hash=$4 AND media_type=$5 AND retrieved_at=$6)")
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

#[async_trait]
impl RfcCorpusStore for PgBlobStore {
    async fn save_dataset(&self, kind: &str, dataset: &Dataset) -> Result<()> {
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
        let saved: Option<String> = sqlx::query_scalar("INSERT INTO devres_rfc_datasets(kind,capture_id,data) VALUES($1,$2,$3) ON CONFLICT(kind,capture_id) DO UPDATE SET capture_id=EXCLUDED.capture_id WHERE devres_rfc_datasets.data->'records'=EXCLUDED.data->'records' RETURNING capture_id")
            .bind(kind).bind(&dataset.capture.id).bind(Json(&value))
            .fetch_optional(&mut *tx).await.map_err(|_| storage_error())?;
        if saved.is_none() {
            return Err(Error::integrity("Immutable RFC dataset cannot be replaced"));
        }
        sqlx::query("INSERT INTO devres_rfc_dataset_heads(kind,capture_id) SELECT $1,$2 WHERE EXISTS(SELECT 1 FROM devres_heads WHERE source_key=$3 AND capture_id=$2) ON CONFLICT(kind) DO UPDATE SET capture_id=EXCLUDED.capture_id")
            .bind(kind).bind(&dataset.capture.id).bind(expected_key).execute(&mut *tx).await.map_err(|_| storage_error())?;
        tx.commit().await.map_err(|_| storage_error())
    }

    async fn dataset(&self, kind: &str, capture: Option<&str>) -> Result<Option<Dataset>> {
        kind_checked(kind)?;
        if capture.is_some_and(|id| !valid_hash(id)) {
            return Err(Error::invalid("Invalid RFC dataset capture"));
        }
        self.fence().await?;
        let row = sqlx::query("SELECT d.data,COALESCE((SELECT MAX(validated_at) FROM devres_observations WHERE capture_id=d.capture_id),c.retrieved_at) AS validated_at FROM devres_rfc_datasets d JOIN devres_captures c ON c.id=d.capture_id WHERE d.kind=$1 AND d.capture_id=COALESCE($2,(SELECT capture_id FROM devres_rfc_dataset_heads WHERE kind=$1))")
            .bind(kind).bind(capture).fetch_optional(&self.pool).await.map_err(|_| storage_error())?;
        row.map(|row| {
            let Json(value): Json<Value> = row.try_get("data").map_err(|_| storage_error())?;
            let mut dataset: Dataset = decode(value)?;
            dataset.capture.validated_at =
                row.try_get("validated_at").map_err(|_| storage_error())?;
            Ok(dataset)
        })
        .transpose()
    }

    async fn schedule(&self, jobs: &[JobSpec]) -> Result<()> {
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
            sqlx::query("INSERT INTO devres_rfc_jobs(source_key,number,format,source_url,assurance,due_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(source_key) DO NOTHING")
                .bind(&job.key).bind(i64::from(job.number)).bind(&job.format).bind(&job.source_url)
                .bind(&job.assurance).bind(job.due_at).execute(&mut *tx).await.map_err(|_| storage_error())?;
            let same: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM devres_rfc_jobs WHERE source_key=$1 AND number=$2 AND format=$3 AND source_url=$4 AND assurance=$5)")
                .bind(&job.key).bind(i64::from(job.number)).bind(&job.format).bind(&job.source_url).bind(&job.assurance)
                .fetch_one(&mut *tx).await.map_err(|_| storage_error())?;
            if !same {
                return Err(Error::integrity("RFC job identity cannot change"));
            }
        }
        tx.commit().await.map_err(|_| storage_error())
    }

    async fn claim(&self, now: i64) -> Result<Option<Job>> {
        let mut owner = self.owner.lock().await;
        owner.ping().await.map_err(|_| storage_error())?;
        let row = sqlx::query("UPDATE devres_rfc_jobs SET status='running',attempts=attempts+1 WHERE source_key=(SELECT source_key FROM devres_rfc_jobs WHERE assurance='https' AND status<>'running' AND due_at<=$1 AND attempts<4294967295 ORDER BY due_at,source_key FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING *")
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
        let result = sqlx::query("UPDATE devres_rfc_jobs SET status=CASE WHEN $2::text IS NULL THEN 'failed' ELSE 'captured' END,capture_id=COALESCE($2,capture_id),capture_metadata=COALESCE($3,capture_metadata),last_error=$4,due_at=$5 WHERE source_key=$1 AND ($2::text IS NULL OR source_url=$6)")
            .bind(key).bind(capture.map(|capture| capture.id.as_str())).bind(value.map(Json))
            .bind(error).bind(next_due).bind(capture.map(|capture| capture.source_url.as_str()))
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
        let rows = sqlx::query("SELECT number,format,assurance,capture_metadata FROM devres_rfc_jobs WHERE capture_id IS NOT NULL ORDER BY number,format,assurance")
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
                    capture: decode(value)?,
                })
            })
            .collect()
    }

    async fn save_snapshot(&self, snapshot: &Snapshot) -> Result<()> {
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
            for document in batch {
                if !unique.insert((
                    document.number,
                    document.format.as_str(),
                    document.assurance.as_str(),
                )) {
                    return Err(Error::invalid("Duplicate RFC snapshot representation"));
                }
                job_checked(&JobSpec {
                    key: document.capture.key.clone(),
                    number: document.number,
                    format: document.format.clone(),
                    source_url: document.capture.source_url.clone(),
                    assurance: document.assurance.clone(),
                    due_at: 0,
                })?;
                check_capture(&mut owner, &document.capture).await?;
            }
        }
        let mut owner = self.owner.lock().await;
        owner.ping().await.map_err(|_| storage_error())?;
        let datasets_present: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM devres_rfc_datasets WHERE kind='catalogue' AND capture_id=$1) AND ($2::text IS NULL OR EXISTS(SELECT 1 FROM devres_rfc_datasets WHERE kind='errata' AND capture_id=$2))")
            .bind(&snapshot.catalogue_capture).bind(&snapshot.errata_capture).fetch_one(&mut *owner).await.map_err(|_| storage_error())?;
        if !datasets_present {
            return Err(Error::integrity(
                "RFC snapshot references an absent dataset",
            ));
        }
        let result: Option<String> = sqlx::query_scalar("INSERT INTO devres_rfc_snapshots(id,catalogue_capture,errata_capture,created_at,complete,data) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(id) DO UPDATE SET id=EXCLUDED.id WHERE devres_rfc_snapshots.data=EXCLUDED.data RETURNING id")
            .bind(&snapshot.id).bind(&snapshot.catalogue_capture).bind(&snapshot.errata_capture)
            .bind(snapshot.created_at).bind(snapshot.complete).bind(Json(&value))
            .fetch_optional(&mut *owner).await.map_err(|_| storage_error())?;
        if result.is_none() {
            return Err(Error::integrity(
                "Immutable RFC snapshot cannot be replaced",
            ));
        }
        Ok(())
    }

    async fn snapshot(&self, id: Option<&str>) -> Result<Option<Snapshot>> {
        if id.is_some_and(|id| !valid_hash(id)) {
            return Err(Error::invalid("Invalid RFC snapshot identifier"));
        }
        self.fence().await?;
        let row: Option<Json<Value>> = sqlx::query_scalar("SELECT data FROM devres_rfc_snapshots WHERE ($1::text IS NULL OR id=$1) ORDER BY complete DESC,published_order DESC LIMIT 1")
            .bind(id).fetch_optional(&self.pool).await.map_err(|_| storage_error())?;
        row.map(|Json(value)| decode(value)).transpose()
    }

    async fn status(&self) -> Result<Value> {
        self.fence().await?;
        let rows = sqlx::query("SELECT status,count(*) AS count,count(capture_id) AS retained_count,min(due_at) AS earliest_due FROM devres_rfc_jobs GROUP BY status ORDER BY status")
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
        let errors = sqlx::query("SELECT source_key,last_error,due_at FROM devres_rfc_jobs WHERE last_error IS NOT NULL ORDER BY due_at,source_key LIMIT 20")
            .fetch_all(&self.pool).await.map_err(|_| storage_error())?;
        let errors = errors.into_iter().map(|row| {
            Ok(json!({"key":row.try_get::<String,_>("source_key").map_err(|_| storage_error())?,"error":row.try_get::<String,_>("last_error").map_err(|_| storage_error())?,"next_due":row.try_get::<i64,_>("due_at").map_err(|_| storage_error())?}))
        }).collect::<Result<Vec<_>>>()?;
        let latest = self.snapshot(None).await?;
        let partial = sqlx::query("SELECT id,created_at,data->'coverage' AS coverage FROM devres_rfc_snapshots WHERE NOT complete ORDER BY published_order DESC LIMIT 1").fetch_optional(&self.pool).await.map_err(|_|storage_error())?.map(|row|Ok::<_,Error>(json!({"id":row.try_get::<String,_>("id").map_err(|_|storage_error())?,"created_at":row.try_get::<i64,_>("created_at").map_err(|_|storage_error())?,"coverage":row.try_get::<Json<Value>,_>("coverage").map_err(|_|storage_error())?.0}))).transpose()?;
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
