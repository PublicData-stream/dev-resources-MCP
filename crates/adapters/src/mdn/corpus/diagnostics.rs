//! Bounded attempt metadata. Source paths, bodies and arbitrary errors never enter it.
use super::*;
use futures::future::BoxFuture;
use std::{cell::RefCell, future::Future};

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Phase {
    ObservationLookup,
    Acquisition,
    ObservationPublication,
    Recovery,
    CommitLookup,
    InventoryEnumeration,
    ObjectAccess,
    RawRetention,
    Projection,
    InventoryApply,
    EntryPublication,
    InventoryCheckpoint,
    SnapshotPreparation,
    IndexPublication,
    IndexCheckpoint,
    SnapshotPublication,
    ChangesPublication,
    HistoryCheckpoint,
    DefaultPublication,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CheckpointUnit {
    Entries,
    IndexSequence,
    Bytes,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Operation {
    Current,
    History,
    Acquisition,
    Recovery,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    Running,
    Yielded,
    Idle,
    Succeeded,
    Failed,
}

#[derive(Clone, Serialize, Deserialize)]
struct Position {
    phase: Phase,
    repository: Option<Repo>,
    revision: Option<String>,
    observation: Option<String>,
    at: i64,
    checkpoint: Option<u64>,
    checkpoint_unit: Option<CheckpointUnit>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Failure {
    #[serde(flatten)]
    position: Position,
    code: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct Record {
    version: u32,
    operation: Operation,
    phase: Phase,
    repository: Option<Repo>,
    revision: Option<String>,
    observation: Option<String>,
    outcome: Outcome,
    attempted_at: i64,
    finished_at: Option<i64>,
    last_progress: Option<Position>,
    last_success: Option<Position>,
    last_failure: Option<Failure>,
    #[serde(skip)]
    progressed: bool,
    #[serde(skip)]
    completed: bool,
}

tokio::task_local! {
    static ATTEMPT: RefCell<Record>;
}

fn invalid() -> Error {
    Error::integrity("Invalid MDN diagnostic metadata.")
}

fn validate_position(position: &Position) -> Result<()> {
    validate_identity(
        position.revision.as_deref(),
        position.observation.as_deref(),
    )
}

fn validate_identity(revision: Option<&str>, observation: Option<&str>) -> Result<()> {
    if revision.is_some_and(|revision| {
        revision.len() != 40
            || !revision
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }) || observation.is_some_and(|id| !devres_domain::valid_content_id(id))
    {
        return Err(invalid());
    }
    Ok(())
}

fn decode(value: Value) -> Result<Record> {
    let mut record: Record = serde_json::from_value(value).map_err(|_| invalid())?;
    if record.version != 1 {
        return Err(invalid());
    }
    validate_identity(record.revision.as_deref(), record.observation.as_deref())?;
    for position in [&record.last_progress, &record.last_success]
        .into_iter()
        .flatten()
    {
        validate_position(position)?;
    }
    if let Some(failure) = &mut record.last_failure {
        validate_position(&failure.position)?;
        failure.code = devres_application::collection::safe_code(&failure.code).into();
    }
    Ok(record)
}

/// Validate persisted metadata and emit only this closed projection.
/// Saved attempts never prove that the original process is still running.
pub(crate) fn private_summary(value: Value) -> Result<Value> {
    let record = decode(value)?;
    let mut value = encoded(&record)?;
    value["active"] = Value::Null;
    value["activity"] = json!("unknown");
    Ok(value)
}

pub(super) fn public_summary(value: Option<Value>) -> Result<Value> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(json!({"active":null,"activity":"unknown","outcome":"legacy_unknown"}));
    };
    let record = decode(value)?;
    Ok(json!({
        "active":null,"activity":"unknown","phase":record.phase,"outcome":record.outcome,
        "repository":record.repository,"last_attempt":record.attempted_at,
        "finished_at":record.finished_at,
        "last_progress":record.last_progress.as_ref().map(|position|json!({"phase":position.phase,"at":position.at})),
        "last_success":record.last_success.as_ref().map(|position|json!({"phase":position.phase,"at":position.at})),
        "failure":record.last_failure.as_ref().map(|failure|json!({"phase":failure.position.phase,"at":failure.position.at,"code":failure.code}))
    }))
}

fn modify(update: impl FnOnce(&mut Record)) {
    // Calls outside a collector attempt (for example offline rebuilds) remain inert.
    let _ = ATTEMPT.try_with(|record| update(&mut record.borrow_mut()));
}

pub(super) fn phase(phase: Phase) {
    modify(|record| record.phase = phase);
}

pub(super) fn input(repo: Repo, revision: Option<&str>, observation: Option<&str>) {
    modify(|record| {
        record.repository = Some(repo);
        record.revision = revision.map(str::to_owned);
        record.observation = observation.map(str::to_owned);
    });
}

pub(super) fn shared() {
    modify(|record| {
        record.repository = None;
        record.revision = None;
        record.observation = None;
    });
}

fn position(record: &Record, checkpoint: Option<u64>) -> Position {
    Position {
        phase: record.phase,
        repository: record.repository,
        revision: record.revision.clone(),
        observation: record.observation.clone(),
        at: devres_domain::unix_now(),
        checkpoint,
        checkpoint_unit: checkpoint.map(|_| match record.phase {
            Phase::HistoryCheckpoint => CheckpointUnit::Bytes,
            Phase::IndexCheckpoint => CheckpointUnit::IndexSequence,
            _ => CheckpointUnit::Entries,
        }),
    }
}

pub(super) fn progress(checkpoint: u64) {
    modify(|record| {
        record.last_progress = Some(position(record, Some(checkpoint)));
        record.progressed = true;
    });
}

pub(super) fn completed() {
    modify(|record| {
        record.last_success = Some(position(record, None));
        record.completed = true;
        record.progressed = true;
    });
}

/// Record a finite attempt without changing the caller's original error code/message.
/// A failed telemetry write cannot replace an operation failure. After an otherwise
/// successful operation it is explicit unavailability, not a successful observation.
pub(super) fn run<'a, T: Send + 'a>(
    store: &'a dyn MdnStore,
    key: &'a str,
    future: impl Future<Output = Result<T>> + Send + 'a,
) -> BoxFuture<'a, Result<T>> {
    run_with(store, key, Box::pin(future), |_| true)
}

pub(super) fn run_slice<'a>(
    store: &'a dyn MdnStore,
    key: &'a str,
    future: impl Future<Output = Result<bool>> + Send + 'a,
) -> BoxFuture<'a, Result<bool>> {
    run_with(store, key, Box::pin(future), |complete| *complete)
}

fn run_with<'a, T: Send + 'a>(
    store: &'a dyn MdnStore,
    key: &'a str,
    future: BoxFuture<'a, Result<T>>,
    is_complete: impl Fn(&T) -> bool + Send + 'a,
) -> BoxFuture<'a, Result<T>> {
    // Erase the potentially large processing future at this boundary. Otherwise
    // each attempt/scope wrapper embeds another full copy in its async layout.
    Box::pin(async move {
        let operation = match key {
            "diagnostics-current" => Operation::Current,
            "diagnostics-history" => Operation::History,
            "diagnostics-acquisition-content" | "diagnostics-acquisition-compat" => {
                Operation::Acquisition
            }
            "diagnostics-recovery" => Operation::Recovery,
            _ => return Err(invalid()),
        };
        let previous = store
            .mdn_state(key)
            .await?
            .filter(|value| !value.is_null())
            .map(decode)
            .transpose()?;
        let record = Record {
            version: 1,
            operation,
            phase: match operation {
                Operation::Acquisition => Phase::Acquisition,
                Operation::Recovery => Phase::Recovery,
                Operation::Current | Operation::History => Phase::ObservationLookup,
            },
            repository: None,
            revision: None,
            observation: None,
            outcome: Outcome::Running,
            attempted_at: devres_domain::unix_now(),
            finished_at: None,
            last_progress: previous
                .as_ref()
                .and_then(|value| value.last_progress.clone()),
            last_success: previous
                .as_ref()
                .and_then(|value| value.last_success.clone()),
            last_failure: previous.and_then(|value| value.last_failure),
            progressed: false,
            completed: false,
        };
        let initial_write = store.mdn_set_state(key, &encoded(&record)?).await;
        let previous_success = record.last_success.clone();
        let (result, record) = ATTEMPT
            .scope(RefCell::new(record), async move {
                let result = future.await;
                let record = ATTEMPT.with(|record| {
                    let mut record = record.borrow_mut();
                    record.finished_at = Some(devres_domain::unix_now());
                    if result.as_ref().is_ok_and(|value| !is_complete(value)) {
                        record.completed = false;
                        record.last_success = previous_success;
                    }
                    record.outcome = match &result {
                        Err(error) => {
                            record.last_failure = Some(Failure {
                                position: position(&record, None),
                                code: devres_application::collection::safe_code(&error.code).into(),
                            });
                            Outcome::Failed
                        }
                        Ok(_) if record.completed => Outcome::Succeeded,
                        Ok(_) if record.progressed => Outcome::Yielded,
                        Ok(_) => Outcome::Idle,
                    };
                    record.clone()
                });
                (result, record)
            })
            .await;
        let final_write = store.mdn_set_state(key, &encoded(&record)?).await;
        match result {
            Err(error) => Err(error),
            Ok(value) => {
                if initial_write.is_err() || final_write.is_err() {
                    Err(Error::unavailable("MDN diagnostic observation incomplete."))
                } else {
                    Ok(value)
                }
            }
        }
    })
}
