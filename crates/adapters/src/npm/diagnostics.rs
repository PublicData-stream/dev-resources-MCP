//! Closed private advisory-attempt metadata. Package inputs and source text never enter it.
use devres_application::collection::{Failure, LimitKind, Phase, context, safe_code};
use devres_domain::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Stage {
    Selection,
    Acquisition,
    JobCheckpoint,
    Materialization,
    Scanner,
    GapRetention,
    RecordRetention,
    RawRetention,
    MemberRetention,
    PackageLinkRetention,
    ReadyMarker,
    Publication,
    ValidatorAcceptance,
    CompletionCheckpoint,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    Running,
    Yielded,
    Failed,
    Succeeded,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Job {
    snapshot: String,
    artifact_capture: String,
    artifact_bytes: u64,
    next_member: u64,
    records: u64,
    gaps: u64,
    expanded_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FailedAttempt {
    stage: Stage,
    job: Option<Job>,
    publication_snapshot: Option<String>,
    failure: Failure,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Success {
    at: i64,
    snapshot: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Progress {
    at: i64,
    job: Job,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Attempt {
    version: u32,
    attempt_started_at: i64,
    updated_at: i64,
    stage: Stage,
    outcome: Outcome,
    job: Option<Job>,
    publication_snapshot: Option<String>,
    last_failure: Option<FailedAttempt>,
    last_success: Option<Success>,
    last_progress: Option<Progress>,
}

fn invalid() -> Error {
    Error::integrity("Invalid private npm advisory diagnostics.")
}

impl Job {
    fn validate(&self) -> Result<()> {
        if !crate::integrity::valid_hash(&self.snapshot)
            || !crate::integrity::valid_hash(&self.artifact_capture)
            || self.artifact_bytes > crate::bulk::MAX_ARTIFACT_BYTES
            || self.next_member > 1_000_000
            || self.records > self.next_member
            || self.gaps > self.next_member
            || self.expanded_bytes > 64 * 1024 * 1024 * 1024
        {
            return Err(invalid());
        }
        Ok(())
    }
}

impl Attempt {
    pub(super) fn begin(previous: Option<Value>) -> Self {
        let previous = previous.and_then(|value| decode(value).ok());
        let now = devres_domain::unix_now();
        Self {
            version: 1,
            attempt_started_at: now,
            updated_at: now,
            stage: Stage::Selection,
            outcome: Outcome::Running,
            job: None,
            publication_snapshot: None,
            last_failure: previous.as_ref().and_then(|v| v.last_failure.clone()),
            last_progress: previous.as_ref().and_then(|v| v.last_progress.clone()),
            last_success: previous.and_then(|v| v.last_success),
        }
    }

    pub(super) fn stage(&mut self, stage: Stage) {
        self.stage = stage;
    }

    pub(super) fn publication(&mut self, snapshot: &str) {
        self.publication_snapshot = Some(snapshot.into());
    }

    /// Called only after selecting this unfinished job or committing a new job.
    pub(super) fn checkpoint(&mut self, job: &Value) -> Result<()> {
        let job = Job {
            snapshot: job["snapshot"].as_str().ok_or_else(invalid)?.into(),
            artifact_capture: job["artifact"]["body_hash"]
                .as_str()
                .ok_or_else(invalid)?
                .into(),
            artifact_bytes: job["artifact"]["bytes"].as_u64().ok_or_else(invalid)?,
            next_member: job["next"].as_u64().ok_or_else(invalid)?,
            records: job["records"].as_u64().ok_or_else(invalid)?,
            gaps: job["gaps"].as_u64().ok_or_else(invalid)?,
            expanded_bytes: job
                .get("expanded")
                .map_or(Ok(0), |v| v.as_u64().ok_or_else(invalid))?,
        };
        job.validate()?;
        self.job = Some(job);
        Ok(())
    }

    pub(super) fn fail(&mut self, error: &Error) {
        self.outcome = Outcome::Failed;
        self.updated_at = devres_domain::unix_now();
        self.last_failure = Some(FailedAttempt {
            stage: self.stage,
            job: self.job.clone(),
            publication_snapshot: self.publication_snapshot.clone(),
            failure: Failure::from_error(error, Phase::BulkOperation, self.updated_at),
        });
    }

    pub(super) fn progress(&mut self, job: &Value) -> Result<()> {
        self.checkpoint(job)?;
        if let Some(job) = self.job.clone() {
            self.last_progress = Some(Progress {
                at: devres_domain::unix_now(),
                job,
            });
        }
        Ok(())
    }

    pub(super) fn yielded(&mut self) {
        self.outcome = Outcome::Yielded;
    }

    pub(super) fn succeed(&mut self, snapshot: &str) {
        self.outcome = Outcome::Succeeded;
        self.last_success = Some(Success {
            at: devres_domain::unix_now(),
            snapshot: snapshot.into(),
        });
    }

    pub(super) fn value(&mut self) -> Result<Value> {
        self.updated_at = devres_domain::unix_now();
        private_summary(serde_json::to_value(self).map_err(|_| invalid())?)
    }
}

fn decode(value: Value) -> Result<Attempt> {
    let attempt: Attempt = serde_json::from_value(value).map_err(|_| invalid())?;
    if attempt.version != 1
        || attempt.attempt_started_at < 0
        || attempt.updated_at < attempt.attempt_started_at
    {
        return Err(invalid());
    }
    if let Some(job) = &attempt.job {
        job.validate()?;
    }
    if let Some(progress) = &attempt.last_progress {
        if progress.at < 0 {
            return Err(invalid());
        }
        progress.job.validate()?;
    }
    if attempt
        .publication_snapshot
        .as_deref()
        .is_some_and(|v| !crate::integrity::valid_hash(v))
    {
        return Err(invalid());
    }
    if let Some(failed) = &attempt.last_failure {
        let failure = &failed.failure;
        if failure.observed_at < 0
            || safe_code(&failure.code) != failure.code
            || failure
                .http_status
                .is_some_and(|v| !(100..=599).contains(&v))
            || failed
                .publication_snapshot
                .as_deref()
                .is_some_and(|v| !crate::integrity::valid_hash(v))
        {
            return Err(invalid());
        }
        if let Some(job) = &failed.job {
            job.validate()?;
        }
    }
    if attempt
        .last_success
        .as_ref()
        .is_some_and(|v| v.at < 0 || !crate::integrity::valid_hash(&v.snapshot))
    {
        return Err(invalid());
    }
    Ok(attempt)
}

/// Strict finite projection shared by the private collector and read-only inspector.
pub(crate) fn private_summary(value: Value) -> Result<Value> {
    serde_json::to_value(decode(value)?).map_err(|_| invalid())
}

/// Only this explicitly typed transient capacity preserves the retained advisory job.
pub(super) fn materialization_deadline(error: &Error) -> bool {
    error.code == "capacity"
        && context(error).is_some_and(|context| {
            context.phase == Phase::Materialization
                && context
                    .limit
                    .is_some_and(|limit| limit.kind == LimitKind::Deadline)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn private_projection_preserves_independent_history_and_rejects_unbounded_fields() {
        let hash = crate::integrity::hash(b"public fixture");
        let job = json!({"snapshot":hash,"artifact":{"body_hash":hash,"bytes":10},"next":1,"records":1,"gaps":0,"expanded":20});
        let mut previous = Attempt::begin(None);
        previous.progress(&job).unwrap();
        previous.stage(Stage::Publication);
        previous.publication(&hash);
        previous.fail(
            &Error::unavailable("private source text")
                .with_details(json!({"credential":"private"})),
        );
        previous.succeed(&hash);
        let history = previous.value().unwrap();
        assert!(!history.to_string().contains("private"));
        let mut fresh = Attempt::begin(Some(history.clone()));
        fresh.stage(Stage::Acquisition);
        fresh.fail(&Error::unavailable("new failure"));
        let value = fresh.value().unwrap();
        assert!(value["job"].is_null());
        assert!(value["last_failure"]["job"].is_null());
        assert_eq!(value["last_progress"], history["last_progress"]);
        assert_eq!(value["last_success"], history["last_success"]);
        for (field, bad) in [
            ("version", json!(2)),
            ("stage", json!("/private/path")),
            ("outcome", json!("body")),
            ("attempt_started_at", json!(-1)),
            ("publication_snapshot", json!("invalid hash")),
            ("arbitrary_body", json!("secret")),
        ] {
            let mut invalid = value.clone();
            invalid[field] = bad;
            assert!(private_summary(invalid).is_err(), "{field}");
        }
        let mut invalid = history;
        invalid["job"]["next_member"] = json!(-1);
        assert!(private_summary(invalid).is_err());
    }
}
