//! Owner-fenced attribution state. SQL indexes are checked against sealed payloads.
use super::{PgBlobStore, capture_metadata_digest, payload_integrity, storage_error};
use async_trait::async_trait;
use devres_application::attribution::AttributionStore;
use devres_domain::{Capture, Error, Result, attribution::*};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx_core::{connection::Connection, row::Row, types::Json};
use sqlx_postgres::{PgConnection, PgRow};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio_util::sync::CancellationToken;

const MAX_VALUE: usize = 8 * 1024 * 1024;
const PAGE: i64 = 128;
const PROVIDERS: &[&str] = &[
    "rfc",
    "crates",
    "rustsec",
    "mdn",
    "whatwg",
    "w3c",
    "chromium",
    "npm",
    "wikipedia",
];
static CLAIM: AtomicU64 = AtomicU64::new(0);
const TABLE_TARGETS: &str = "devres_attribution_targets";
const TABLE_GENERATIONS: &str = "devres_attribution_generations";

#[derive(Serialize)]
pub(super) struct Progress {
    started_at: i64,
    providers: std::collections::BTreeMap<String, TransitionCounts>,
}
impl Default for Progress {
    fn default() -> Self {
        Self {
            started_at: devres_domain::unix_now(),
            providers: std::collections::BTreeMap::new(),
        }
    }
}
#[derive(Default, Serialize)]
struct TransitionCounts {
    enqueued: u64,
    claimed: u64,
    ready: u64,
    retry: u64,
    blocked: u64,
}
impl Progress {
    fn record(&mut self, provider: &str, event: &str) {
        let counts = self.providers.entry(provider.into()).or_default();
        let counter = match event {
            "enqueued" => &mut counts.enqueued,
            "claimed" => &mut counts.claimed,
            "ready" => &mut counts.ready,
            "retry" => &mut counts.retry,
            "blocked" => &mut counts.blocked,
            _ => return,
        };
        *counter = counter.saturating_add(1);
    }
}

pub(super) const SCHEMA: &str = r#"
CREATE TABLE devres_attribution_control(singleton boolean PRIMARY KEY CHECK(singleton),data jsonb NOT NULL,data_integrity text NOT NULL);
CREATE TABLE devres_attribution_generations(id text PRIMARY KEY,data jsonb NOT NULL,data_integrity text NOT NULL);
CREATE TABLE devres_attribution_targets(id text PRIMARY KEY,provider text NOT NULL,policy_epoch integer NOT NULL CHECK(policy_epoch>0),status text NOT NULL,priority integer NOT NULL CHECK(priority BETWEEN 0 AND 1),retry_at bigint NOT NULL,data jsonb NOT NULL,data_integrity text NOT NULL);
CREATE INDEX devres_attribution_pending ON devres_attribution_targets(policy_epoch,provider,status,priority,retry_at,id);
CREATE TABLE devres_attribution_sweeps(provider text PRIMARY KEY,data jsonb NOT NULL,data_integrity text NOT NULL);
"#;
fn invalid() -> Error {
    Error::integrity("Attribution evidence integrity failed.")
}
fn bounded<T: Serialize>(v: &T) -> Result<Value> {
    let bytes = serde_json::to_vec(v).map_err(|_| invalid())?;
    if bytes.len() > MAX_VALUE {
        return Err(Error::capacity(
            "Attribution evidence exceeds its storage bound.",
        ));
    }
    serde_json::from_slice(&bytes).map_err(|_| invalid())
}
fn provider(v: &str) -> Result<()> {
    if PROVIDERS.contains(&v) {
        Ok(())
    } else {
        Err(Error::invalid("Unknown attribution provider."))
    }
}
fn subject(v: &AttributionSubject) -> Result<()> {
    provider(&v.provider)?;
    if v.namespace.is_empty()
        || v.namespace.len() > 256
        || v.key.is_empty()
        || v.key.len() > 8192
        || !crate::integrity::valid_hash(&v.fingerprint)
        || v.namespace
            .chars()
            .chain(v.key.chars())
            .any(char::is_control)
    {
        return Err(invalid());
    }
    Ok(())
}
fn checked_target(v: &AttributionTarget) -> Result<()> {
    subject(&v.subject)?;
    bounded(v)?;
    if crate::integrity::canonical_hash(&v.evidence)? != v.subject.fingerprint {
        return Err(invalid());
    }
    Ok(())
}
fn target_id_at(v: &AttributionSubject, epoch: u32) -> Result<String> {
    subject(v)?;
    crate::integrity::canonical_hash(&json!({"version":1,"policy_epoch":epoch,"subject":v}))
}
fn target_id(v: &AttributionSubject) -> Result<String> {
    target_id_at(v, ATTRIBUTION_POLICY_EPOCH)
}
fn known_policy(epoch: u32, fingerprint: &str, registry: &[AttributionPolicyManifest]) -> bool {
    registry
        .iter()
        .any(|p| p.epoch == epoch && p.fingerprint == fingerprint)
}
fn control_for(policy: AttributionPolicyManifest) -> Value {
    json!({"format_version":1,"required_policy_epoch":policy.epoch,"required_policy_fingerprint":policy.fingerprint})
}
fn control() -> Value {
    control_for(ATTRIBUTION_REQUIRED_POLICY)
}
fn supported_control(
    data: &Value,
    required: AttributionPolicyManifest,
    registry: &[AttributionPolicyManifest],
) -> Result<u32> {
    let epoch = data["required_policy_epoch"]
        .as_u64()
        .and_then(|v| u32::try_from(v).ok())
        .ok_or_else(invalid)?;
    let fingerprint = data["required_policy_fingerprint"]
        .as_str()
        .ok_or_else(invalid)?;
    if data["format_version"] != 1
        || epoch > required.epoch
        || !known_policy(epoch, fingerprint, registry)
    {
        return Err(Error::unavailable(
            "Attribution policy is unsupported; a matching server is required.",
        ));
    }
    if data.as_object().is_none_or(|v| v.len() != 3) {
        return Err(invalid());
    }
    Ok(epoch)
}

pub(super) async fn prepare(
    tx: &mut sqlx_core::transaction::Transaction<'_, sqlx_postgres::Postgres>,
) -> Result<()> {
    sqlx_core::query::query("SET LOCAL lock_timeout='2s'")
        .execute(&mut **tx)
        .await
        .map_err(|_| storage_error())?;
    sqlx_core::raw_sql::raw_sql(SCHEMA)
        .execute(&mut **tx)
        .await
        .map_err(|_| storage_error())?;
    let data = control();
    sqlx_core::query::query("INSERT INTO devres_attribution_control VALUES(true,$1,$2)")
        .bind(Json(&data))
        .bind(payload_integrity::digest(
            "devres_attribution_control",
            "",
            "singleton",
            &data,
        )?)
        .execute(&mut **tx)
        .await
        .map_err(|_| storage_error())?;
    sqlx_core::query::query("UPDATE devres_schema SET version=11 WHERE singleton AND version=10")
        .execute(&mut **tx)
        .await
        .map_err(|_| storage_error())?;
    Ok(())
}

pub(super) async fn promote_control(
    tx: &mut sqlx_core::transaction::Transaction<'_, sqlx_postgres::Postgres>,
) -> Result<()> {
    promote_control_for(
        tx,
        ATTRIBUTION_REQUIRED_POLICY,
        ATTRIBUTION_POLICY_MANIFESTS,
    )
    .await
}
async fn promote_control_for(
    tx: &mut sqlx_core::transaction::Transaction<'_, sqlx_postgres::Postgres>,
    required: AttributionPolicyManifest,
    registry: &[AttributionPolicyManifest],
) -> Result<()> {
    if !known_policy(required.epoch, required.fingerprint, registry) {
        return Err(invalid());
    }
    let row = sqlx_core::query::query(
        "SELECT data,data_integrity FROM devres_attribution_control WHERE singleton FOR UPDATE",
    )
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| invalid())?;
    let data = checked("devres_attribution_control", "singleton", &row)?;
    let epoch = supported_control(&data, required, registry)?;
    if epoch == required.epoch {
        return Ok(());
    }
    let rows=sqlx_core::query::query("SELECT provider,data,data_integrity FROM devres_attribution_sweeps ORDER BY provider LIMIT 10").fetch_all(&mut **tx).await.map_err(|_|invalid())?;
    for row in rows {
        let p: String = row.try_get("provider").map_err(|_| invalid())?;
        provider(&p)?;
        let _: Sweep = serde_json::from_value(checked("devres_attribution_sweeps", &p, &row)?)
            .map_err(|_| invalid())?;
    }
    // Only nine small sweep checkpoints reset; retained generations and old jobs
    // remain sealed and addressable. No corpus backfill occurs in startup.
    sqlx_core::query::query("DELETE FROM devres_attribution_sweeps")
        .execute(&mut **tx)
        .await
        .map_err(|_| storage_error())?;
    let data = control_for(required);
    sqlx_core::query::query(
        "UPDATE devres_attribution_control SET data=$1,data_integrity=$2 WHERE singleton",
    )
    .bind(Json(&data))
    .bind(payload_integrity::digest(
        "devres_attribution_control",
        "",
        "singleton",
        &data,
    )?)
    .execute(&mut **tx)
    .await
    .map_err(|_| storage_error())?;
    Ok(())
}
pub(super) async fn verify_supported_control(conn: &mut PgConnection) -> Result<()> {
    let row = sqlx_core::query::query(
        "SELECT data,data_integrity FROM devres_attribution_control WHERE singleton",
    )
    .fetch_one(conn)
    .await
    .map_err(|_| invalid())?;
    let data = checked("devres_attribution_control", "singleton", &row)?;
    supported_control(
        &data,
        ATTRIBUTION_REQUIRED_POLICY,
        ATTRIBUTION_POLICY_MANIFESTS,
    )?;
    Ok(())
}
pub(super) async fn verify_control(conn: &mut PgConnection) -> Result<()> {
    let row = sqlx_core::query::query(
        "SELECT data,data_integrity FROM devres_attribution_control WHERE singleton",
    )
    .fetch_one(conn)
    .await
    .map_err(|_| invalid())?;
    let data = checked("devres_attribution_control", "singleton", &row)?;
    if data != control() {
        return Err(Error::unavailable(
            "Attribution policy is unsupported; a matching server is required.",
        ));
    }
    Ok(())
}
fn checked(table: &str, key: &str, row: &PgRow) -> Result<Value> {
    let Json(data): Json<Value> = row.try_get("data").map_err(|_| invalid())?;
    let seal: String = row.try_get("data_integrity").map_err(|_| invalid())?;
    bounded(&data)?;
    payload_integrity::checked(table, "", key, data, &seal)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    target: AttributionTarget,
    policy_epoch: u32,
    status: String,
    priority: u8,
    retry_at: i64,
    claim: Option<String>,
    attempts: u32,
    generation: Option<String>,
    failure: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    classification: Option<AttributionFailure>,
}
impl State {
    fn new(target: AttributionTarget, priority: u8) -> Self {
        Self {
            target,
            policy_epoch: ATTRIBUTION_POLICY_EPOCH,
            status: "pending".into(),
            priority,
            retry_at: 0,
            claim: None,
            attempts: 0,
            generation: None,
            failure: None,
            classification: None,
        }
    }
}
fn state_for_registry(row: &PgRow, registry: &[AttributionPolicyManifest]) -> Result<State> {
    let id: String = row.try_get("id").map_err(|_| invalid())?;
    let data = checked(TABLE_TARGETS, &id, row)?;
    let value: State = serde_json::from_value(data).map_err(|_| invalid())?;
    checked_target(&value.target)?;
    if target_id_at(&value.target.subject, value.policy_epoch)? != id
        || !registry.iter().any(|p| p.epoch == value.policy_epoch)
        || row
            .try_get::<i32, _>("policy_epoch")
            .map_err(|_| invalid())?
            != i32::try_from(value.policy_epoch).map_err(|_| invalid())?
        || row
            .try_get::<String, _>("provider")
            .map_err(|_| invalid())?
            != value.target.subject.provider
        || row.try_get::<String, _>("status").map_err(|_| invalid())? != value.status
        || row.try_get::<i32, _>("priority").map_err(|_| invalid())? != i32::from(value.priority)
        || row.try_get::<i64, _>("retry_at").map_err(|_| invalid())? != value.retry_at
        || !matches!(
            value.status.as_str(),
            "pending" | "running" | "retry" | "blocked" | "ready"
        )
        || value.priority > 1
        || (value.status == "running") != value.claim.is_some()
        || (value.status == "ready") != value.generation.is_some()
    {
        return Err(invalid());
    }
    Ok(value)
}
fn state(row: &PgRow) -> Result<State> {
    state_for_registry(row, ATTRIBUTION_POLICY_MANIFESTS)
}
async fn save(conn: &mut PgConnection, value: &State) -> Result<()> {
    let id = target_id_at(&value.target.subject, value.policy_epoch)?;
    let data = bounded(value)?;
    sqlx_core::query::query("INSERT INTO devres_attribution_targets(id,provider,status,priority,retry_at,data,data_integrity,policy_epoch) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(id) DO UPDATE SET provider=EXCLUDED.provider,status=EXCLUDED.status,priority=EXCLUDED.priority,retry_at=EXCLUDED.retry_at,data=EXCLUDED.data,data_integrity=EXCLUDED.data_integrity,policy_epoch=EXCLUDED.policy_epoch")
        .bind(&id).bind(&value.target.subject.provider).bind(&value.status).bind(i32::from(value.priority)).bind(value.retry_at)
        .bind(Json(&data)).bind(payload_integrity::digest(TABLE_TARGETS,"",&id,&data)?)
        .bind(i32::try_from(value.policy_epoch).map_err(|_|invalid())?)
        .execute(conn).await.map_err(|_| storage_error())?;
    Ok(())
}
async fn enqueue(
    conn: &mut PgConnection,
    target: &AttributionTarget,
    priority: u8,
) -> Result<bool> {
    enqueue_initial(conn, target, priority, false).await
}
async fn enqueue_initial(
    conn: &mut PgConnection,
    target: &AttributionTarget,
    priority: u8,
    oversized: bool,
) -> Result<bool> {
    let priority = priority.min(1);
    let id = target_id(&target.subject)?;
    checked_target(target)?;
    let old =
        sqlx_core::query::query("SELECT * FROM devres_attribution_targets WHERE id=$1 FOR UPDATE")
            .bind(&id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(|_| storage_error())?;
    let inserted = old.is_none();
    let value = if let Some(row) = old {
        let mut old = state(&row)?;
        if old.target != *target {
            return Err(invalid());
        }
        old.priority = old.priority.max(priority);
        old
    } else {
        let mut initial = State::new(target.clone(), priority);
        if oversized {
            initial.status = "blocked".into();
            initial.failure = Some("oversized_evidence".into());
            initial.classification = Some(AttributionFailure::new(
                AttributionPhase::Mapping,
                AttributionFailureReason::PayloadBound,
                AttributionDisposition::Blocked,
            ));
        }
        initial
    };
    save(conn, &value).await?;
    Ok(inserted)
}
fn receipt_url(value: &Value) -> bool {
    value.as_str().is_some_and(|value| {
        value.len() <= 16384
            && url::Url::parse(value).is_ok_and(|url| {
                url.scheme() == "https"
                    && url.host_str().is_some()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.fragment().is_none()
                    && url.port().is_none_or(|p| p == 443)
            })
    })
}
fn verify_receipts(
    value: &AttributionGeneration,
    registry: &[AttributionPolicyManifest],
    depth: usize,
    budget: &mut usize,
) -> Result<()> {
    let source_subject = binding(value)?
        .map(|target| target.subject)
        .unwrap_or_else(|| value.subject.clone());
    let mut acquired = false;
    for receipt in &value.receipts {
        if receipt["kind"] == "dependency_generation" {
            if depth >= 8 || *budget == 0 {
                return Err(Error::capacity(
                    "Attribution dependency proof bound exceeded.",
                ));
            }
            *budget -= 1;
            let target: AttributionTarget =
                serde_json::from_value(receipt["target"].clone()).map_err(|_| invalid())?;
            let child: AttributionGeneration =
                serde_json::from_value(receipt["generation"].clone()).map_err(|_| invalid())?;
            checked_target(&target)?;
            if child.subject != target.subject
                || child.subject.provider != value.subject.provider
                || child.subject == value.subject
                || child.policy_epoch != value.policy_epoch
                || child.policy_fingerprint != value.policy_fingerprint
            {
                return Err(invalid());
            }
            generation_at(&child, registry, depth + 1, budget)?;
            continue;
        }
        if receipt["kind"] == "retained_subject_binding" {
            continue;
        }
        let synthetic = receipt["kind"] == "synthetic_fixture_validation";
        if !receipt.is_object()
            || !receipt_url(&receipt["source_url"])
            || !receipt["body_hash"]
                .as_str()
                .is_some_and(devres_domain::valid_content_id)
            || !receipt["validated_at"]
                .as_i64()
                .is_some_and(|t| t >= 0 && t <= devres_domain::unix_now().saturating_add(300))
            || receipt["policy_epoch"].as_u64() != Some(u64::from(value.policy_epoch))
            || receipt["policy_fingerprint"].as_str() != Some(value.policy_fingerprint.as_str())
        {
            return Err(invalid());
        }
        if synthetic {
            if receipt["synthetic"] != true
                || receipt["status"] != 200
                || receipt["source_fingerprint"].as_str()
                    != Some(source_subject.fingerprint.as_str())
                || value
                    .notices
                    .iter()
                    .any(|notice| notice.evidence["synthetic"] != true)
            {
                return Err(invalid());
            }
        } else {
            if receipt
                .get("kind")
                .is_some_and(|kind| kind != "upstream_validation")
            {
                return Err(invalid());
            }
            match receipt["status"].as_u64() {
                Some(200) => {}
                Some(304)
                    if receipt["verified_retained_body"] == true
                        && receipt["verified_notice_dependencies"] == true => {}
                _ => return Err(invalid()),
            }
        }
        acquired = true;
    }
    if !acquired {
        return Err(invalid());
    }
    Ok(())
}
fn generation_at(
    value: &AttributionGeneration,
    registry: &[AttributionPolicyManifest],
    depth: usize,
    budget: &mut usize,
) -> Result<Value> {
    if depth > 8 {
        return Err(Error::capacity(
            "Attribution dependency proof bound exceeded.",
        ));
    }
    subject(&value.subject)?;
    if !known_policy(value.policy_epoch, &value.policy_fingerprint, registry)
        || value.notices.is_empty()
        || value.notices.len() > 128
        || value.receipts.is_empty()
        || value.receipts.len() > 256
        || value.receipts.iter().any(|r| !r.is_object())
        || value
            .notices
            .iter()
            .any(|n| n.text.is_empty() || n.source_url.is_empty() || n.source_url.len() > 16384)
    {
        return Err(invalid());
    }
    verify_receipts(value, registry, depth, budget)?;
    bounded(value)
}
fn generation_for_registry(
    value: &AttributionGeneration,
    registry: &[AttributionPolicyManifest],
) -> Result<Value> {
    generation_at(value, registry, 0, &mut 128)
}
fn generation(value: &AttributionGeneration) -> Result<Value> {
    generation_for_registry(value, ATTRIBUTION_POLICY_MANIFESTS)
}
fn binding(value: &AttributionGeneration) -> Result<Option<AttributionTarget>> {
    let mut bindings = value
        .receipts
        .iter()
        .filter(|r| r["kind"] == "retained_subject_binding");
    let Some(receipt) = bindings.next() else {
        return Ok(None);
    };
    if bindings.next().is_some() {
        return Err(invalid());
    }
    let retained: AttributionSubject =
        serde_json::from_value(receipt["retained_subject"].clone()).map_err(|_| invalid())?;
    let target: AttributionTarget =
        serde_json::from_value(receipt["source_target"].clone()).map_err(|_| invalid())?;
    if retained != value.subject
        || target.subject.provider != retained.provider
        || target.subject == retained
    {
        return Err(invalid());
    }
    checked_target(&target)?;
    Ok(Some(target))
}
fn bound_generation(
    value: &AttributionGeneration,
    target: &AttributionTarget,
) -> AttributionGeneration {
    let mut canonical = value.clone();
    canonical.subject = target.subject.clone();
    canonical
        .receipts
        .retain(|r| r["kind"] != "retained_subject_binding");
    canonical
}
fn publication_entries(
    target: &AttributionTarget,
    value: &AttributionGeneration,
    registry: &[AttributionPolicyManifest],
) -> Result<Vec<(AttributionTarget, AttributionGeneration)>> {
    let mut output = Vec::new();
    collect_publications(target, value, registry, 0, &mut 128, &mut output)?;
    Ok(output)
}
fn collect_publications(
    target: &AttributionTarget,
    value: &AttributionGeneration,
    registry: &[AttributionPolicyManifest],
    depth: usize,
    budget: &mut usize,
    output: &mut Vec<(AttributionTarget, AttributionGeneration)>,
) -> Result<()> {
    if depth > 8 || *budget == 0 {
        return Err(Error::capacity(
            "Attribution dependency publication bound exceeded.",
        ));
    }
    *budget -= 1;
    checked_target(target)?;
    generation_for_registry(value, registry)?;
    if target.subject != value.subject {
        return Err(invalid());
    }
    let canonical = binding(value)?;
    // A raw occurrence may qualify only the source deterministically compiled
    // from its own sealed evidence. A same-provider proof is not a source link.
    if target.evidence.get("table").is_some() {
        let expected = crate::attribution_providers::retained_target(
            value.policy_epoch,
            &value.policy_fingerprint,
            target,
        )?
        .ok_or_else(invalid)?;
        if canonical.as_ref() != Some(&expected) {
            return Err(invalid());
        }
    } else if canonical.is_some() {
        return Err(invalid());
    }
    if let Some(canonical) = canonical {
        collect_publications(
            &canonical,
            &bound_generation(value, &canonical),
            registry,
            depth + 1,
            budget,
            output,
        )?;
    } else {
        let expected = match target.evidence.get("dependencies") {
            None => Vec::new(),
            Some(Value::Array(values)) if values.len() <= 128 => values
                .iter()
                .map(|v| {
                    serde_json::from_value::<AttributionTarget>(v.clone()).map_err(|_| invalid())
                })
                .collect::<Result<Vec<_>>>()?,
            _ => return Err(invalid()),
        };
        let mut seen = std::collections::BTreeSet::new();
        for receipt in &value.receipts {
            if receipt["kind"] == "dependency_generation" {
                let child: AttributionTarget =
                    serde_json::from_value(receipt["target"].clone()).map_err(|_| invalid())?;
                let generation: AttributionGeneration =
                    serde_json::from_value(receipt["generation"].clone()).map_err(|_| invalid())?;
                if !expected.contains(&child)
                    || !seen.insert(target_id_at(&child.subject, generation.policy_epoch)?)
                {
                    return Err(invalid());
                }
                collect_publications(&child, &generation, registry, depth + 1, budget, output)?;
            }
        }
        if seen.len() != expected.len() {
            return Err(invalid());
        }
    }
    output.push((target.clone(), value.clone()));
    Ok(())
}
async fn publish_generation(
    conn: &mut PgConnection,
    value: &AttributionGeneration,
) -> Result<String> {
    let data = generation(value)?;
    let id = crate::integrity::canonical_hash(&data)?;
    sqlx_core::query::query("INSERT INTO devres_attribution_generations(id,data,data_integrity) VALUES($1,$2,$3) ON CONFLICT DO NOTHING")
        .bind(&id).bind(Json(&data)).bind(payload_integrity::digest(TABLE_GENERATIONS,"",&id,&data)?)
        .execute(&mut *conn).await.map_err(|_|storage_error())?;
    let retained =
        sqlx_core::query::query("SELECT * FROM devres_attribution_generations WHERE id=$1")
            .bind(&id)
            .fetch_one(conn)
            .await
            .map_err(|_| invalid())?;
    if qualified(&retained)?.generation != *value {
        return Err(invalid());
    }
    Ok(id)
}
fn qualified_for_registry(
    row: &PgRow,
    registry: &[AttributionPolicyManifest],
) -> Result<QualifiedAttribution> {
    let id: String = row.try_get("id").map_err(|_| invalid())?;
    let value = checked(TABLE_GENERATIONS, &id, row)?;
    if crate::integrity::canonical_hash(&value)? != id {
        return Err(invalid());
    }
    let generation: AttributionGeneration = serde_json::from_value(value).map_err(|_| invalid())?;
    generation_for_registry(&generation, registry)?;
    Ok(QualifiedAttribution { id, generation })
}
fn qualified(row: &PgRow) -> Result<QualifiedAttribution> {
    qualified_for_registry(row, ATTRIBUTION_POLICY_MANIFESTS)
}

#[async_trait]
impl AttributionStore for PgBlobStore {
    async fn attribution_enqueue(&self, target: &AttributionTarget, priority: u8) -> Result<()> {
        self.owner_fence().await?;
        self.fence().await?;
        let mut owner = self.owner.lock().await;
        verify_control(&mut owner).await?;
        let mut tx = owner.begin().await.map_err(|_| storage_error())?;
        let mut inserted = false;
        let result = async {
            inserted = enqueue(&mut tx, target, priority).await?;
            self.fence().await
        }
        .await;
        match result {
            Ok(()) => {
                tx.commit().await.map_err(|_| storage_error())?;
                if inserted {
                    self.record_attribution(&target.subject.provider, "enqueued");
                }
                Ok(())
            }
            Err(error) => {
                tx.rollback().await.map_err(|_| storage_error())?;
                Err(error)
            }
        }
    }
    async fn attribution_ready(
        &self,
        v: &AttributionSubject,
    ) -> Result<Option<QualifiedAttribution>> {
        self.fence().await?;
        self.check_attribution_control().await?;
        let id = target_id(v)?;
        let row = sqlx_core::query::query("SELECT * FROM devres_attribution_targets WHERE id=$1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| storage_error())?;
        let Some(row) = row else {
            return Ok(None);
        };
        let state = state(&row)?;
        let state_policy = state.policy_epoch;
        let Some(id) = state.generation else {
            return Ok(None);
        };
        let value = self.attribution_bundle(&id).await?;
        if value.generation.subject != *v || value.generation.policy_epoch != state_policy {
            return Err(invalid());
        }
        Ok(Some(value))
    }
    async fn attribution_claim(
        &self,
        enabled: &[String],
        now: i64,
        admission: u64,
    ) -> Result<Option<AttributionJob>> {
        self.owner_fence().await?;
        if enabled.len() > PROVIDERS.len() || now < 0 {
            return Err(Error::invalid("Invalid attribution admission."));
        }
        for p in enabled {
            provider(p)?;
        }
        let enabled: Vec<_> = PROVIDERS
            .iter()
            .filter(|p| enabled.iter().any(|v| v == **p))
            .map(|p| (*p).to_owned())
            .collect();
        self.fence().await?;
        let mut owner = self.owner.lock().await;
        verify_control(&mut owner).await?;
        let mut tx = owner.begin().await.map_err(|_| storage_error())?;
        let result:Result<Option<AttributionJob>>=async {
            sqlx_core::query::query("SET LOCAL lock_timeout='250ms'").execute(&mut *tx).await.map_err(source_error)?;
            sqlx_core::query::query("SET LOCAL statement_timeout='2s'").execute(&mut *tx).await.map_err(source_error)?;
            let admission=admission%((enabled.len().max(1)*15) as u64);
            let background=admission%5==4;
            let turn=if background { admission/5 } else {4*(admission/5)+admission%5};
            let buckets=enabled.len()*3;
            let desired=if buckets==0 {0} else {(turn%(buckets as u64)) as usize};
            let wanted_priority=if background {0} else {1};
            let mut head:Option<(u8,u8,i64,String)>=None;
            for (provider_index,p) in enabled.iter().enumerate() {for (status_index,status) in ["pending","retry","running"].into_iter().enumerate() {for priority in [0i32,1] {
                // Each equality prefix and ordered due range is one bounded seek
                // into the existing pending index. Never sort the whole queue.
                let found:Option<(String,i64)>=sqlx_core::query_as::query_as("SELECT id,retry_at FROM devres_attribution_targets WHERE policy_epoch=$1 AND provider=$2 AND status=$3 AND priority=$4 AND retry_at<=$5 ORDER BY retry_at,id LIMIT 1")
                    .bind(ATTRIBUTION_POLICY_EPOCH as i32).bind(p).bind(status).bind(priority).bind(now).fetch_optional(&mut *tx).await.map_err(source_error)?;
                if let Some((id,retry_at))=found {
                    let priority_rank=u8::from(priority!=wanted_priority);
                    let bucket_rank=u8::from(provider_index*3+status_index!=desired);
                    let candidate=(priority_rank,bucket_rank,retry_at,id);
                    if head.as_ref().is_none_or(|old|candidate<*old){head=Some(candidate);}
                }
            }}}
            let Some((_,_,_,id))=head else{return Ok(None)};
            let row=sqlx_core::query::query("SELECT * FROM devres_attribution_targets WHERE id=$1 FOR UPDATE").bind(id).fetch_one(&mut *tx).await.map_err(source_error)?;
            let mut value=state(&row)?;
            if value.policy_epoch!=ATTRIBUTION_POLICY_EPOCH||!enabled.contains(&value.target.subject.provider)||!matches!(value.status.as_str(),"pending"|"retry"|"running")||value.retry_at>now{return Err(invalid());}
            let claim=crate::integrity::canonical_hash(&json!({"subject":value.target.subject,"policy_epoch":value.policy_epoch,"pid":self.owner_pid,"started":self.owner_started,"counter":CLAIM.fetch_add(1,Ordering::Relaxed),"now":now}))?;
            value.status="running".into();value.retry_at=now.saturating_add(300);value.attempts=value.attempts.saturating_add(1);value.claim=Some(claim.clone());save(&mut tx,&value).await?;
            self.fence().await?;Ok(Some(AttributionJob{target:value.target,claim,attempts:value.attempts}))
        }.await;
        match result {
            Ok(job) => {
                tx.commit().await.map_err(|_| storage_error())?;
                if let Some(job) = &job {
                    self.record_attribution(&job.target.subject.provider, "claimed");
                }
                Ok(job)
            }
            Err(error) => {
                tx.rollback().await.map_err(|_| storage_error())?;
                Err(error)
            }
        }
    }
    async fn attribution_complete(
        &self,
        job: &AttributionJob,
        value: &AttributionGeneration,
    ) -> Result<()> {
        self.owner_fence().await?;
        if value.policy_epoch != ATTRIBUTION_POLICY_EPOCH
            || value.policy_fingerprint != ATTRIBUTION_POLICY_FINGERPRINT
        {
            return Err(invalid());
        }
        self.fence().await?;
        let mut owner = self.owner.lock().await;
        verify_control(&mut owner).await?;
        let mut tx = owner.begin().await.map_err(|_| storage_error())?;
        let mut newly_ready = Vec::new();
        let mut newly_enqueued = Vec::new();
        let result: Result<()> = async {
            let row = sqlx_core::query::query(
                "SELECT * FROM devres_attribution_targets WHERE id=$1 FOR UPDATE",
            )
            .bind(target_id(&job.target.subject)?)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| invalid())?;
            let root = state(&row)?;
            check_claim(&root, job, true)?;
            let entries = publication_entries(&root.target, value, ATTRIBUTION_POLICY_MANIFESTS)?;
            for (target, generation) in entries {
                let row = sqlx_core::query::query(
                    "SELECT * FROM devres_attribution_targets WHERE id=$1 FOR UPDATE",
                )
                .bind(target_id(&target.subject)?)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|_| storage_error())?;
                let mut current = if let Some(row) = row {
                    state(&row)?
                } else {
                    newly_enqueued.push(target.subject.provider.clone());
                    State::new(target.clone(), 0)
                };
                if current.target != target {
                    return Err(invalid());
                }
                if current.status == "running" && target.subject != job.target.subject {
                    return Err(Error::unavailable(
                        "Dependent attribution repair has an active claim.",
                    ));
                }
                if current.status != "ready" {
                    newly_ready.push(target.subject.provider.clone());
                }
                let id = publish_generation(&mut tx, &generation).await?;
                current.status = "ready".into();
                current.claim = None;
                current.generation = Some(id);
                current.failure = None;
                current.classification = None;
                current.retry_at = 0;
                save(&mut tx, &current).await?;
            }
            self.fence().await
        }
        .await;
        match result {
            Ok(()) => {
                tx.commit().await.map_err(|_| storage_error())?;
                for p in newly_enqueued {
                    self.record_attribution(&p, "enqueued");
                }
                for p in newly_ready {
                    self.record_attribution(&p, "ready");
                }
                Ok(())
            }
            Err(error) => {
                tx.rollback().await.map_err(|_| storage_error())?;
                Err(error)
            }
        }
    }
    async fn attribution_fail(
        &self,
        job: &AttributionJob,
        retry_at: Option<i64>,
        code: &str,
    ) -> Result<()> {
        self.fail_attribution(job, retry_at, code, None).await
    }
    async fn attribution_fail_classified(
        &self,
        job: &AttributionJob,
        retry_at: Option<i64>,
        code: &str,
        classification: &AttributionFailure,
    ) -> Result<()> {
        self.fail_attribution(job, retry_at, code, Some(classification))
            .await
    }
    async fn attribution_bundle(&self, id: &str) -> Result<QualifiedAttribution> {
        if !crate::integrity::valid_hash(id) {
            return Err(Error::invalid("Invalid attribution generation."));
        }
        self.fence().await?;
        self.check_attribution_control().await?;
        let row =
            sqlx_core::query::query("SELECT * FROM devres_attribution_generations WHERE id=$1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|_| storage_error())?
                .ok_or_else(|| Error::not_found("Attribution generation is absent."))?;
        qualified(&row)
    }
    async fn attribution_status(&self) -> Result<Value> {
        self.fence().await?;
        self.check_attribution_control().await?;
        let rows=sqlx_core::query::query("SELECT provider,status,count(*)::bigint AS count FROM devres_attribution_targets WHERE policy_epoch=$1 GROUP BY provider,status ORDER BY provider,status LIMIT 64")
            .bind(ATTRIBUTION_POLICY_EPOCH as i32).fetch_all(&self.pool).await.map_err(|_|storage_error())?;
        let mut counts = Vec::new();
        for r in rows {
            counts.push(json!({"provider":r.try_get::<String,_>("provider").map_err(|_|invalid())?,"status":r.try_get::<String,_>("status").map_err(|_|invalid())?,"count":r.try_get::<i64,_>("count").map_err(|_|invalid())?}));
        }
        let rows=sqlx_core::query::query("SELECT provider,data,data_integrity FROM devres_attribution_sweeps ORDER BY provider LIMIT 10").fetch_all(&self.pool).await.map_err(|_|storage_error())?;
        let mut sweeps = Vec::new();
        for row in rows {
            let name: String = row.try_get("provider").map_err(|_| invalid())?;
            provider(&name)?;
            let sweep: Sweep =
                serde_json::from_value(checked("devres_attribution_sweeps", &name, &row)?)
                    .map_err(|_| invalid())?;
            sweeps.push(json!({"provider":name,"completed_passes":sweep.passes,"scan_complete":sweep.complete,"source":sweep.source,"membership":"indexed_range_enumeration"}));
        }
        let all_scanned = PROVIDERS.iter().all(|p| {
            sweeps.iter().any(|v| {
                v["provider"] == *p && v["completed_passes"].as_u64().is_some_and(|n| n > 0)
            })
        });
        let repair_complete_for_enqueued_targets =
            !counts.is_empty() && counts.iter().all(|v| v["status"] == "ready");
        let observed_at = devres_domain::unix_now();
        let mut samples = Vec::new();
        let mut sample_bytes = 2_usize;
        let mut omitted_sample_rows = 0_usize;
        const SAMPLE_BUDGET: usize = 24 * 1024;
        // Each lateral subquery is one bounded seek into the queue index. Only
        // scalar observations cross this boundary; never target bodies or keys.
        let rows = sqlx_core::query::query("SELECT p.provider,s.status,q.priority,t.retry_at,t.namespace,t.attempts,t.failure,t.classification FROM unnest($2::text[]) AS p(provider) CROSS JOIN (VALUES ('pending'),('retry'),('running'),('blocked')) AS s(status) CROSS JOIN (VALUES (0),(1)) AS q(priority) CROSS JOIN LATERAL (SELECT retry_at,data#>>'{target,subject,namespace}' AS namespace,data->>'attempts' AS attempts,data->>'failure' AS failure,data->'classification' AS classification FROM devres_attribution_targets WHERE policy_epoch=$1 AND provider=p.provider AND status=s.status AND priority=q.priority ORDER BY retry_at,id LIMIT 2) t")
            .bind(ATTRIBUTION_POLICY_EPOCH as i32).bind(PROVIDERS)
            .fetch_all(&self.pool).await.map_err(|_|storage_error())?;
        for row in rows {
            let provider: String = row.try_get("provider").map_err(|_| invalid())?;
            let status: String = row.try_get("status").map_err(|_| invalid())?;
            let priority: i32 = row.try_get("priority").map_err(|_| invalid())?;
            let namespace: String = row.try_get("namespace").map_err(|_| invalid())?;
            let attempts: String = row.try_get("attempts").map_err(|_| invalid())?;
            let attempts: u32 = attempts.parse().map_err(|_| invalid())?;
            let retry_at: i64 = row.try_get("retry_at").map_err(|_| invalid())?;
            let failure: Option<String> = row.try_get("failure").map_err(|_| invalid())?;
            let classification: Option<Json<AttributionFailure>> =
                row.try_get("classification").map_err(|_| invalid())?;
            let sample = json!({"provider":provider,"status":status,"priority":priority,
                "namespace":diagnostic_namespace(&namespace),"attempts":attempts,"retry_at":retry_at,
                "eligible":status!="blocked"&&retry_at<=observed_at,
                "failure":diagnostic_failure(failure.as_deref()),"classification":classification.map(|v|v.0)});
            let charge = serde_json::to_vec(&sample)
                .map_err(|_| invalid())?
                .len()
                .saturating_add(1);
            if sample_bytes.saturating_add(charge) <= SAMPLE_BUDGET {
                sample_bytes += charge;
                samples.push(sample);
            } else {
                omitted_sample_rows += 1;
            }
        }
        let progress = {
            let progress = self
                .attribution_progress
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            json!({"scope":"this_store_process","started_at":progress.started_at,"providers":progress.providers})
        };
        Ok(
            json!({"policy_epoch":ATTRIBUTION_POLICY_EPOCH,"counts":counts,"sweeps":sweeps,"progress":progress,
                "diagnostics":{"sampled":true,"limit_per_bucket":2,"ordering":"retry_at_then_id",
                    "sample_budget_bytes":SAMPLE_BUDGET,"truncated":omitted_sample_rows>0,
                    "omitted_sample_rows":omitted_sample_rows,"omission_scope":"bounded_candidates_only",
                    "observed_at":observed_at,"pending_age_available":false,"samples":samples},
                "repair_complete_for_enqueued_targets":repair_complete_for_enqueued_targets,
                "initial_scan_passes_complete":all_scanned,
                "completion_scope":"observed_sweep_cutoffs",
                "complete":false,"corpus_complete":false}),
        )
    }
    async fn attribution_sweep_page(&self, name: &str) -> Result<Vec<AttributionTarget>> {
        self.owner_fence().await?;
        self.sweep_attribution(name).await
    }
}
fn check_claim(state: &State, job: &AttributionJob, require_live: bool) -> Result<()> {
    if state.target != job.target
        || state.claim.as_deref() != Some(job.claim.as_str())
        || state.status != "running"
        || state.attempts != job.attempts
        || (require_live && state.retry_at <= devres_domain::unix_now())
    {
        return Err(Error::unavailable(
            "Attribution repair claim was superseded.",
        ));
    }
    Ok(())
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Sweep {
    source: usize,
    after: String,
    cutoff: Option<String>,
    passes: u64,
    complete: bool,
}
struct Source {
    table: &'static str,
    select: &'static str,
    filter: &'static str,
}
#[derive(Clone, Copy)]
enum Cursor {
    Key(&'static str),
    Sequence(&'static str),
    Pair(&'static str, &'static str),
    Version,
}
impl Source {
    fn cursor(&self) -> Cursor {
        match self.table {
            "devres_captures" | "devres_advisory_records" => Cursor::Key("id"),
            "devres_rfc_datasets" => Cursor::Pair("kind", "capture_id"),
            "devres_rfc_snapshots" => Cursor::Sequence("published_order"),
            "devres_crate_content" => Cursor::Pair("generation", "id"),
            "devres_crate_versions" => Cursor::Version,
            table
                if table.ends_with("_evidence")
                    || matches!(
                        table,
                        "devres_advisory_rows"
                            | "devres_advisory_snapshots"
                            | "devres_crate_snapshots"
                    ) =>
            {
                Cursor::Sequence("sequence")
            }
            _ => Cursor::Key("key"),
        }
    }
}
impl Cursor {
    fn initial(self) -> String {
        match self {
            Self::Key(_) => String::new(),
            Self::Sequence(_) => "0".into(),
            Self::Pair(_, _) => "[\"\",\"\"]".into(),
            Self::Version => "[\"\",\"\",0]".into(),
        }
    }
    fn position(self) -> String {
        match self {
            Self::Key(k) => k.into(),
            Self::Sequence(k) => format!("{k}::text"),
            Self::Pair(a, b) => format!("jsonb_build_array({a},{b})::text"),
            Self::Version => "jsonb_build_array(name,version,valid_from)::text".into(),
        }
    }
    fn order(self, descending: bool) -> String {
        let dir = if descending { "DESC" } else { "ASC" };
        match self {
            Self::Key(k) | Self::Sequence(k) => format!("s.{k} {dir}"),
            Self::Pair(a, b) => format!("s.{a} {dir},s.{b} {dir}"),
            Self::Version => format!("s.name {dir},s.version {dir},s.valid_from {dir}"),
        }
    }
    fn comparison(self, operator: &str, parameter: u8) -> String {
        match self {
            Self::Key(k) => format!("{k}{operator}${parameter}"),
            Self::Sequence(k) => format!("{k}{operator}${parameter}::bigint"),
            Self::Pair(a, b) => {
                format!("({a},{b}){operator}((${parameter}::jsonb->>0),(${parameter}::jsonb->>1))")
            }
            Self::Version => format!(
                "(name,version,valid_from){operator}((${parameter}::jsonb->>0),(${parameter}::jsonb->>1),(${parameter}::jsonb->>2)::bigint)"
            ),
        }
    }
}
fn source_error(error: sqlx_core::error::Error) -> Error {
    if error
        .as_database_error()
        .and_then(|v| v.code())
        .is_some_and(|v| matches!(v.as_ref(), "57014" | "55P03"))
    {
        Error::capacity("Attribution sweep reached its bounded SQL admission deadline.")
    } else {
        storage_error()
    }
}

fn diagnostic_namespace(namespace: &str) -> String {
    let (table, kind) = namespace.split_once('/').unwrap_or((namespace, ""));
    if table == "source" && kind.is_empty() {
        return table.into();
    }
    if !matches!(
        table,
        "devres_captures"
            | "devres_rfc_datasets"
            | "devres_rfc_snapshots"
            | "devres_crate_versions"
            | "devres_crate_content"
            | "devres_crate_snapshots"
            | "devres_advisory_rows"
            | "devres_advisory_state"
            | "devres_advisory_records"
            | "devres_advisory_snapshots"
            | "devres_mdn_evidence"
            | "devres_mdn_state"
            | "devres_whatwg_evidence"
            | "devres_whatwg_state"
            | "devres_w3c_evidence"
            | "devres_w3c_state"
            | "devres_chromium_evidence"
            | "devres_chromium_state"
            | "devres_npm_evidence"
            | "devres_npm_state"
            | "devres_wikipedia_evidence"
    ) {
        return "other".into();
    }
    if kind.is_empty() {
        return table.into();
    }
    let kind = if matches!(
        kind,
        "captures"
            | "catalogs"
            | "commits"
            | "nodes"
            | "trees"
            | "projections"
            | "projection-sections"
            | "projection-chunks"
            | "projection-headers"
            | "projection-references"
            | "index-documents"
            | "indexed-membership"
            | "changes"
            | "snapshots"
            | "views"
            | "observations"
            | "jobs"
            | "blocked-jobs"
            | "history-gaps"
            | "license-scopes"
            | "processing"
            | "git-projections"
            | "advisories"
            | "advisory-members"
            | "advisory-packages"
            | "advisory-raw"
            | "catalogue"
            | "errata"
            | "documents"
    ) {
        kind
    } else {
        "other"
    };
    format!("{table}/{kind}")
}

fn diagnostic_failure(failure: Option<&str>) -> Option<&'static str> {
    failure.map(|failure| match failure {
        "oversized_evidence" => "oversized_evidence",
        "integrity" => "integrity",
        "capacity" => "capacity",
        "blocked" => "blocked",
        "retryable" => "retryable",
        "cancelled" => "cancelled",
        "publication_deferred" => "publication_deferred",
        _ => "legacy_unknown",
    })
}
fn sources(name: &str) -> Result<Vec<Source>> {
    provider(name)?;
    // Scan the shared capture primary key exactly once. Filtering an id-ordered
    // scan by source_key would repeatedly walk the full corpus for sparse sources.
    let capture_filter = if name == "rfc" { "true" } else { "false" };
    let mut list = vec![Source {
        table: "devres_captures",
        select: "t.*,id AS key,''::text AS kind,to_jsonb(t) AS metadata",
        filter: capture_filter,
    }];
    match name {
        "wikipedia" => {
            list.push(Source {
                table: "devres_wikipedia_evidence",
                select: "t.*,to_jsonb(t)-'data' AS metadata",
                filter: "kind='captures'",
            });
        }
        "rfc" => {
            list.push(Source {
                table: "devres_rfc_datasets",
                select: "t.*,capture_id AS key,to_jsonb(t)-'data' AS metadata",
                filter: "true",
            });
            list.push(Source {
                table: "devres_rfc_snapshots",
                select: "t.*,id AS key,''::text AS kind,to_jsonb(t)-'data' AS metadata",
                filter: "true",
            });
        }
        "crates" => {
            list.push(Source {
                table: "devres_crate_snapshots",
                select: "t.*,id AS key,''::text AS kind,to_jsonb(t)-'data' AS metadata",
                filter: "true",
            });
            list.push(Source{table:"devres_crate_versions",select:"t.*,name||'@'||version AS key,valid_from::text AS kind,to_jsonb(t)-'record' AS metadata",filter:"true"});
            list.push(Source {
                table: "devres_crate_content",
                select: "t.*,generation||'/'||id AS key,to_jsonb(t)-'attributes' AS metadata",
                filter: "true",
            });
        }
        "rustsec" => {
            list.push(Source {
                table: "devres_advisory_rows",
                select: "t.*,to_jsonb(t)-'data' AS metadata",
                filter: "kind <> 'processing'",
            });
            list.push(Source {
                table: "devres_advisory_state",
                select: "t.*,''::text AS kind,to_jsonb(t)-'data' AS metadata",
                filter: "true",
            });
            list.push(Source {
                table: "devres_advisory_records",
                select: "t.*,id AS key,''::text AS kind,to_jsonb(t)-'data' AS metadata",
                filter: "true",
            });
            list.push(Source {
                table: "devres_advisory_snapshots",
                select: "t.*,id AS key,''::text AS kind,to_jsonb(t)-'data' AS metadata",
                filter: "true",
            });
        }
        _ => {
            let (table, state) = match name {
                "mdn" => ("devres_mdn_evidence", "devres_mdn_state"),
                "whatwg" => ("devres_whatwg_evidence", "devres_whatwg_state"),
                "w3c" => ("devres_w3c_evidence", "devres_w3c_state"),
                "chromium" => ("devres_chromium_evidence", "devres_chromium_state"),
                "npm" => ("devres_npm_evidence", "devres_npm_state"),
                _ => return Err(invalid()),
            };
            list.push(Source {
                table,
                select: "t.*,to_jsonb(t)-'data' AS metadata",
                filter: match name {
                    "w3c" => "kind NOT IN ('catalog-pages','catalog-failures')",
                    "chromium" => {
                        "kind NOT IN ('trees','traversal-gaps','traversal-gap-manifests')"
                    }
                    _ => "true",
                },
            });
            list.push(Source {
                table: state,
                select: "t.*,''::text AS kind,to_jsonb(t)-'data' AS metadata",
                filter: match name {
                    "w3c" => "key NOT IN ('status','failure','catalog-work') AND NOT starts_with(key,'collector-')",
                    "mdn" => "key NOT IN ('status','failure','content-retry','compat-retry')",
                    _ => "key NOT IN ('status','failure')",
                },
            });
        }
    }
    Ok(list)
}
fn compact_identity(value: &Value, depth: usize) -> Value {
    if depth > 12 {
        return Value::Null;
    }
    match value {
        Value::Object(object) => {
            let mut out = serde_json::Map::new();
            for (key, value) in object {
                if matches!(
                    key.as_str(),
                    "before"
                        | "after"
                        | "parent"
                        | "parents"
                        | "raw"
                        | "artifact"
                        | "sources"
                        | "captures"
                        | "metadata"
                        | "source_url"
                        | "revision"
                        | "revision_id"
                        | "page_id"
                        | "representation"
                        | "observed_at"
                        | "acquisition_policy_epoch"
                        | "acquisition_policy_fingerprint"
                        | "repository"
                        | "component"
                        | "source_path"
                        | "path"
                        | "member_path"
                        | "body_hash"
                        | "sha256"
                        | "oid"
                        | "object_oid"
                        | "media_type"
                        | "id"
                        | "key"
                        | "source_key"
                        | "name"
                        | "version"
                        | "format"
                        | "kind"
                        | "capture"
                        | "capture_id"
                        | "metadata_capture"
                        | "archive_capture"
                        | "source_capture"
                        | "source"
                        | "provenance"
                        | "selection"
                        | "license"
                        | "source_metadata"
                        | "decision"
                        | "evidence"
                        | "notice"
                        | "notice_path"
                        | "license_path"
                        | "notice_hash"
                        | "notice_oid"
                        | "license_url"
                        | "copyright"
                        | "attribution"
                        | "attribution_url"
                        | "url"
                        | "derived_notice"
                        | "derivation"
                        | "publication_status"
                        | "title"
                ) {
                    if key == "raw" && !value.is_object() {
                        continue;
                    }
                    let compact = compact_identity(value, depth + 1);
                    if serde_json::to_vec(&compact).is_ok_and(|v| v.len() <= 256 * 1024) {
                        out.insert(key.clone(), compact);
                    }
                }
            }
            Value::Object(out)
        }
        Value::Array(values) if values.len() <= 128 => Value::Array(
            values
                .iter()
                .map(|value| compact_identity(value, depth + 1))
                .collect(),
        ),
        Value::Array(_) => Value::Null,
        Value::String(s) if s.len() > 128 * 1024 => Value::Null,
        v => v.clone(),
    }
}
fn candidate(name: &str, table: &str, row: &PgRow, oversized: bool) -> Result<AttributionTarget> {
    let key: String = row.try_get("key").map_err(|_| invalid())?;
    let kind: String = row.try_get("kind").map_err(|_| invalid())?;
    let Json(metadata): Json<Value> = row.try_get("metadata").map_err(|_| invalid())?;
    let name = if table == "devres_captures" {
        match metadata["source_key"]
            .as_str()
            .and_then(|v| v.split(':').next())
        {
            Some("cargo" | "crate" | "crates") => "crates",
            Some("rustsec" | "advisory") => "rustsec",
            Some("npm") => "npm",
            Some("mdn") => "mdn",
            Some("whatwg") => "whatwg",
            Some("w3c") => "w3c",
            Some("chromium") => "chromium",
            Some("wikipedia") => "wikipedia",
            _ => "rfc",
        }
    } else {
        name
    };
    let data = match table {
        "devres_captures" => {
            let capture = Capture {
                id: metadata["id"].as_str().ok_or_else(invalid)?.into(),
                key: metadata["source_key"].as_str().ok_or_else(invalid)?.into(),
                source_url: metadata["source_url"].as_str().ok_or_else(invalid)?.into(),
                body_hash: metadata["body_hash"].as_str().ok_or_else(invalid)?.into(),
                media_type: metadata["media_type"].as_str().ok_or_else(invalid)?.into(),
                retrieved_at: metadata["retrieved_at"].as_i64().ok_or_else(invalid)?,
                validated_at: metadata["retrieved_at"].as_i64().ok_or_else(invalid)?,
            };
            if metadata["metadata_integrity"].as_str() != Some(&capture_metadata_digest(&capture)?)
            {
                return Err(invalid());
            }
            crate::integrity::verify(
                &capture.id,
                format!(
                    "{}\0{}\0{}\0{}",
                    capture.key, capture.source_url, capture.media_type, capture.body_hash
                )
                .as_bytes(),
            )?;
            bounded(&capture)?
        }
        "devres_crate_versions" => {
            let Json(value): Json<Value> = row.try_get("record").map_err(|_| invalid())?;
            let payload = payload_integrity::crate_record_payload(
                metadata["metadata_capture"].as_str().ok_or_else(invalid)?,
                metadata["valid_to"].as_i64(),
                &value,
            );
            payload_integrity::checked(
                table,
                &kind,
                &key,
                payload,
                row.try_get::<String, _>("record_integrity")
                    .map_err(|_| invalid())?
                    .as_str(),
            )?;
            value
        }
        "devres_crate_content" => {
            let value = payload_integrity::crate_content_row(row)?;
            payload_integrity::checked(
                table,
                metadata["generation"].as_str().ok_or_else(invalid)?,
                metadata["id"].as_str().ok_or_else(invalid)?,
                value.clone(),
                row.try_get::<String, _>("attributes_integrity")
                    .map_err(|_| invalid())?
                    .as_str(),
            )?;
            value
        }
        _ => payload_integrity::row(table, row)?,
    };
    let verified_data_fingerprint = crate::integrity::canonical_hash(&data)?;
    let mut evidence = json!({"table":table,"kind":kind,"key":key,"data":compact_identity(&data,0),"metadata":metadata,"verified_data_fingerprint":verified_data_fingerprint});
    if oversized {
        evidence.as_object_mut().ok_or_else(invalid)?.remove("data");
        evidence["gap"] = json!("oversized_evidence");
    }
    bounded(&evidence)?;
    Ok(AttributionTarget {
        subject: AttributionSubject {
            provider: name.into(),
            namespace: if kind.is_empty() {
                table.into()
            } else {
                format!("{table}/{kind}")
            },
            key,
            fingerprint: crate::integrity::canonical_hash(&evidence)?,
        },
        evidence,
    })
}
impl PgBlobStore {
    fn record_attribution(&self, provider: &str, event: &str) {
        self.attribution_progress
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .record(provider, event);
    }
    async fn fail_attribution(
        &self,
        job: &AttributionJob,
        retry_at: Option<i64>,
        code: &str,
        classification: Option<&AttributionFailure>,
    ) -> Result<()> {
        self.owner_fence().await?;
        if code.is_empty()
            || code.len() > 64
            || !code.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
            || retry_at.is_some_and(|t| t < 0)
        {
            return Err(Error::invalid("Invalid attribution failure state."));
        }
        self.fence().await?;
        let mut owner = self.owner.lock().await;
        verify_control(&mut owner).await?;
        let mut tx = owner.begin().await.map_err(|_| storage_error())?;
        let row = sqlx_core::query::query(
            "SELECT * FROM devres_attribution_targets WHERE id=$1 FOR UPDATE",
        )
        .bind(target_id(&job.target.subject)?)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| invalid())?;
        let mut value = state(&row)?;
        if let Err(error) = check_claim(&value, job, false) {
            tx.rollback().await.map_err(|_| storage_error())?;
            return Err(error);
        }
        value.status = if retry_at.is_some() {
            "retry"
        } else {
            "blocked"
        }
        .into();
        value.retry_at = retry_at.unwrap_or(0);
        value.claim = None;
        value.failure = Some(code.into());
        value.classification = classification.copied();
        save(&mut tx, &value).await?;
        self.fence().await?;
        tx.commit().await.map_err(|_| storage_error())?;
        self.record_attribution(&job.target.subject.provider, &value.status);
        Ok(())
    }
    async fn historical_attribution_bundle(&self, id: &str) -> Result<QualifiedAttribution> {
        let row =
            sqlx_core::query::query("SELECT * FROM devres_attribution_generations WHERE id=$1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|_| storage_error())?
                .ok_or_else(invalid)?;
        qualified(&row)
    }
    async fn check_attribution_control(&self) -> Result<()> {
        let row = sqlx_core::query::query(
            "SELECT data,data_integrity FROM devres_attribution_control WHERE singleton",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|_| invalid())?;
        if checked("devres_attribution_control", "singleton", &row)? != control() {
            return Err(Error::unavailable(
                "Attribution policy is unsupported; a matching server is required.",
            ));
        }
        Ok(())
    }
    async fn sweep_attribution(&self, name: &str) -> Result<Vec<AttributionTarget>> {
        self.owner_fence().await?;
        let sources = sources(name)?;
        self.fence().await?;
        let mut owner = self.owner.lock().await;
        verify_control(&mut owner).await?;
        let mut tx = owner.begin().await.map_err(|_| storage_error())?;
        let mut inserted = Vec::new();
        let result:Result<Vec<AttributionTarget>>=async {
            sqlx_core::query::query("SET LOCAL lock_timeout='250ms'").execute(&mut *tx).await.map_err(source_error)?;
            sqlx_core::query::query("SET LOCAL statement_timeout='2s'").execute(&mut *tx).await.map_err(source_error)?;
            let existing=sqlx_core::query::query("SELECT data,data_integrity FROM devres_attribution_sweeps WHERE provider=$1 FOR UPDATE").bind(name).fetch_optional(&mut *tx).await.map_err(source_error)?;
            let mut sweep=if let Some(row)=existing{serde_json::from_value::<Sweep>(checked("devres_attribution_sweeps",name,&row)?).map_err(|_|invalid())?}else{Sweep{source:0,after:String::new(),cutoff:None,passes:0,complete:false}};
            if sweep.source>=sources.len(){return Err(invalid());}
            let source=&sources[sweep.source];let cursor=source.cursor();
            let base=format!("SELECT {} FROM {} t WHERE {}",source.select,source.table,source.filter);
            if sweep.cutoff.is_none(){
                sweep.after=cursor.initial();
                let sql=format!("SELECT {} FROM ({base}) s ORDER BY {} LIMIT 1",cursor.position(),cursor.order(true));
                sweep.cutoff=Some(sqlx_core::query_scalar::query_scalar::<_,String>(sqlx_core::sql_str::AssertSqlSafe(sql)).fetch_optional(&mut *tx).await.map_err(source_error)?.unwrap_or_else(||cursor.initial()));
            }
            let sql=format!("SELECT {} AS position FROM ({base}) s WHERE {} AND {} ORDER BY {} LIMIT {PAGE}",cursor.position(),cursor.comparison(">",1),cursor.comparison("<=",2),cursor.order(false));
            let positions=sqlx_core::query_scalar::query_scalar::<_,String>(sqlx_core::sql_str::AssertSqlSafe(sql)).bind(&sweep.after).bind(&sweep.cutoff).fetch_all(&mut *tx).await.map_err(source_error)?;
            let mut output=Vec::new();let mut bytes=0usize;
            let page_started=std::time::Instant::now();
            for position in &positions {
                if !output.is_empty()&&page_started.elapsed()>=std::time::Duration::from_secs(1){break;}
                let exact=cursor.comparison("=",1);
                let sql=format!("SELECT octet_length(to_jsonb(s)::text)::bigint FROM ({base}) s WHERE {exact}");
                let charge=usize::try_from(sqlx_core::query_scalar::query_scalar::<_,i64>(sqlx_core::sql_str::AssertSqlSafe(sql)).bind(position).fetch_one(&mut *tx).await.map_err(source_error)?).map_err(|_|invalid())?;
                if charge>64*1024*1024{return Err(Error::capacity("Retained source exceeds the supported decoder bound."));}
                if bytes.saturating_add(charge)>MAX_VALUE&&!output.is_empty(){break;}
                let oversized=charge>MAX_VALUE;
                let sql=format!("SELECT * FROM ({base}) s WHERE {exact}");
                let row=sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(sql)).bind(position).fetch_one(&mut *tx).await.map_err(source_error)?;
                let target=candidate(name,source.table,&row,oversized)?;
                if enqueue_initial(&mut tx,&target,0,oversized).await? { inserted.push((target.subject.provider.clone(),oversized)); }
                output.push(target);bytes=bytes.saturating_add(charge);sweep.after=position.clone();
            }
            if positions.is_empty(){sweep.source+=1;sweep.after.clear();sweep.cutoff=None;if sweep.source==sources.len(){sweep.source=0;sweep.passes=sweep.passes.saturating_add(1);sweep.complete=true;}}else{sweep.complete=false;}
            let data=bounded(&sweep)?;
            sqlx_core::query::query("INSERT INTO devres_attribution_sweeps(provider,data,data_integrity) VALUES($1,$2,$3) ON CONFLICT(provider) DO UPDATE SET data=EXCLUDED.data,data_integrity=EXCLUDED.data_integrity").bind(name).bind(Json(&data)).bind(payload_integrity::digest("devres_attribution_sweeps","",name,&data)?).execute(&mut *tx).await.map_err(source_error)?;
            self.fence().await?;Ok(output)
        }.await;
        match result {
            Ok(output) => {
                tx.commit().await.map_err(|_| storage_error())?;
                for (p, oversized) in inserted {
                    self.record_attribution(&p, "enqueued");
                    if oversized {
                        self.record_attribution(&p, "blocked");
                    }
                }
                Ok(output)
            }
            Err(error) => {
                tx.rollback().await.map_err(|_| storage_error())?;
                Err(error)
            }
        }
    }
    pub(super) async fn verify_attribution_storage(
        &self,
        cancel: &CancellationToken,
    ) -> Result<()> {
        let version: i32 = sqlx_core::query_scalar::query_scalar(
            "SELECT version FROM devres_schema WHERE singleton",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|_| storage_error())?;
        if version < 11 {
            return Ok(());
        }
        {
            let mut owner = self.owner.lock().await;
            verify_supported_control(&mut owner).await?;
        }
        for table in [
            TABLE_TARGETS,
            TABLE_GENERATIONS,
            "devres_attribution_sweeps",
        ] {
            let key = if table == "devres_attribution_sweeps" {
                "provider"
            } else {
                "id"
            };
            let mut after = String::new();
            loop {
                if cancel.is_cancelled() {
                    return Err(Error::unavailable("Attribution verification canceled."));
                }
                let sql = format!(
                    "SELECT {key} AS cursor,octet_length(data::text)::bigint AS bytes FROM {table} WHERE {key}>$1 ORDER BY {key} LIMIT {PAGE}"
                );
                let rows = sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(sql))
                    .bind(&after)
                    .fetch_all(&self.pool)
                    .await
                    .map_err(|_| storage_error())?;
                if rows.is_empty() {
                    break;
                }
                for row in rows {
                    let cursor: String = row.try_get("cursor").map_err(|_| invalid())?;
                    if row.try_get::<i64, _>("bytes").map_err(|_| invalid())? > MAX_VALUE as i64 {
                        return Err(invalid());
                    }
                    let sql = format!("SELECT * FROM {table} WHERE {key}=$1");
                    let row = sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(sql))
                        .bind(&cursor)
                        .fetch_one(&self.pool)
                        .await
                        .map_err(|_| storage_error())?;
                    match table {
                        TABLE_TARGETS => {
                            let state = state(&row)?;
                            if let Some(id) = state.generation {
                                let qualified = self.historical_attribution_bundle(&id).await?;
                                if qualified.generation.subject != state.target.subject
                                    || qualified.generation.policy_epoch != state.policy_epoch
                                {
                                    return Err(invalid());
                                }
                            }
                        }
                        TABLE_GENERATIONS => {
                            let qualified = qualified(&row)?;
                            let target_row = sqlx_core::query::query(
                                "SELECT * FROM devres_attribution_targets WHERE id=$1",
                            )
                            .bind(target_id_at(
                                &qualified.generation.subject,
                                qualified.generation.policy_epoch,
                            )?)
                            .fetch_optional(&self.pool)
                            .await
                            .map_err(|_| storage_error())?
                            .ok_or_else(invalid)?;
                            let target = state(&target_row)?.target;
                            for (_, generation) in publication_entries(
                                &target,
                                &qualified.generation,
                                ATTRIBUTION_POLICY_MANIFESTS,
                            )? {
                                let id = crate::integrity::canonical_hash(&self::generation(
                                    &generation,
                                )?)?;
                                if self.historical_attribution_bundle(&id).await?.generation
                                    != generation
                                {
                                    return Err(invalid());
                                }
                            }
                            if let Some(target) = binding(&qualified.generation)? {
                                let canonical = bound_generation(&qualified.generation, &target);
                                let id =
                                    crate::integrity::canonical_hash(&generation(&canonical)?)?;
                                if self.historical_attribution_bundle(&id).await?.generation
                                    != canonical
                                {
                                    return Err(invalid());
                                }
                            }
                        }
                        _ => {
                            provider(&cursor)?;
                            let sweep: Sweep =
                                serde_json::from_value(checked(table, &cursor, &row)?)
                                    .map_err(|_| invalid())?;
                            if sweep.source >= sources(&cursor)?.len() {
                                return Err(invalid());
                            }
                        }
                    }
                    after = cursor;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use devres_application::{Store, mdn::MdnStore};
    use devres_domain::{FetchRequest, FetchResponse, Validators};
    use std::sync::Arc;

    fn target(key: &str) -> AttributionTarget {
        let evidence =
            json!({"source_url":"https://www.rfc-editor.org/rfc/rfc9000.txt","fixture":key});
        AttributionTarget {
            subject: AttributionSubject {
                provider: "rfc".into(),
                namespace: "fixture".into(),
                key: key.into(),
                fingerprint: crate::integrity::canonical_hash(&evidence).unwrap(),
            },
            evidence,
        }
    }
    fn generation_for(target: &AttributionTarget) -> AttributionGeneration {
        AttributionGeneration {
            subject: target.subject.clone(),
            policy_epoch: ATTRIBUTION_POLICY_EPOCH,
            policy_fingerprint: ATTRIBUTION_POLICY_FINGERPRINT.into(),
            notices: vec![AttributionNotice {
                source_url: "https://www.rfc-editor.org/rfc/rfc9000.txt".into(),
                license: Some("fixture-only".into()),
                copyright: Some("Synthetic fixture authors".into()),
                text: "Synthetic attribution storage fixture; not upstream legal evidence.".into(),
                evidence: json!({"synthetic":true}),
            }],
            receipts: vec![
                json!({"kind":"synthetic_fixture_validation","synthetic":true,"status":200,"source_url":"https://www.rfc-editor.org/rfc/rfc9000.txt","body_hash":crate::integrity::hash(b"synthetic fixture"),"source_fingerprint":target.subject.fingerprint,"validated_at":devres_domain::unix_now(),"policy_epoch":ATTRIBUTION_POLICY_EPOCH,"policy_fingerprint":ATTRIBUTION_POLICY_FINGERPRINT}),
            ],
        }
    }
    #[test]
    fn attribution_identity_binds_occurrence_policy_and_authoritative_state() {
        let first = target("first");
        let mut second = first.clone();
        second.subject.key = "second".into();
        assert_ne!(
            target_id(&first.subject).unwrap(),
            target_id(&second.subject).unwrap()
        );
        let state = State::new(first, 0);
        let mut changed = state.clone();
        changed.priority = 1;
        let one = bounded(&state).unwrap();
        let two = bounded(&changed).unwrap();
        assert_ne!(
            payload_integrity::digest(TABLE_TARGETS, "", "id", &one).unwrap(),
            payload_integrity::digest(TABLE_TARGETS, "", "id", &two).unwrap()
        );
        let mut tampered = second.clone();
        tampered.evidence["unbound"] = json!(true);
        assert!(checked_target(&tampered).is_err());
        let mut unknown = generation_for(&second);
        unknown.policy_epoch += 1;
        assert!(generation(&unknown).is_err());
        let mut no_receipt = generation_for(&second);
        no_receipt.receipts.clear();
        assert!(generation(&no_receipt).is_err());
    }
    #[test]
    fn diagnostic_metadata_never_echoes_arbitrary_namespace_or_failure_text() {
        assert_eq!(
            diagnostic_namespace("devres_mdn_evidence/projections"),
            "devres_mdn_evidence/projections"
        );
        for namespace in [
            "https://private.example/secret",
            "source/private-key",
            "devres_mdn_state/https://private.example",
            "devres_mdn_evidence/private-input",
        ] {
            let safe = diagnostic_namespace(namespace);
            assert!(!safe.contains("private"));
            assert!(!safe.contains("https"));
        }
        assert_eq!(
            diagnostic_failure(Some("user_supplied_secret")),
            Some("legacy_unknown")
        );
        assert_eq!(
            diagnostic_failure(Some("oversized_evidence")),
            Some("oversized_evidence")
        );
    }
    #[test]
    fn acquisition_receipts_require_successful_exact_policy_bound_evidence() {
        let original = generation_for(&target("receipts"));
        assert!(generation(&original).is_ok());
        for (key, bad) in [
            ("status", json!(404)),
            ("source_url", json!("file:///tmp/private")),
            ("body_hash", json!("invalid")),
            ("validated_at", json!(-1)),
            ("policy_epoch", json!(99)),
            ("policy_fingerprint", json!("wrong")),
            ("source_fingerprint", json!("wrong")),
        ] {
            let mut value = original.clone();
            value.receipts[0][key] = bad;
            assert!(generation(&value).is_err(), "invalid receipt {key}");
        }
        let mut upstream = original.clone();
        upstream.receipts[0]["kind"] = json!("upstream_validation");
        upstream.receipts[0]["status"] = json!(304);
        assert!(generation(&upstream).is_err());
        upstream.receipts[0]["verified_retained_body"] = json!(true);
        assert!(generation(&upstream).is_err());
        upstream.receipts[0]["verified_notice_dependencies"] = json!(true);
        assert!(generation(&upstream).is_ok());
        let mut forged = original;
        forged.notices[0].evidence = json!({});
        assert!(generation(&forged).is_err());
    }
    fn composite(
        child: &AttributionTarget,
        child_generation: &AttributionGeneration,
        key: &str,
    ) -> (AttributionTarget, AttributionGeneration) {
        let mut parent = target(key);
        parent.evidence = json!({"version":1,"dependencies":[child]});
        parent.subject.fingerprint = crate::integrity::canonical_hash(&parent.evidence).unwrap();
        let mut generation = generation_for(&parent);
        generation.receipts.push(
            json!({"kind":"dependency_generation","target":child,"generation":child_generation}),
        );
        (parent, generation)
    }
    #[test]
    fn compact_history_retains_both_exact_sources_without_copied_bodies() {
        let original = json!({"repository":"content","parent":"a".repeat(40),"revision":"b".repeat(40),"before":{"path":"files/en-us/web/a/index.md","raw":{"oid":"c".repeat(40)},"text":"old copied prose"},"after":{"path":"files/en-us/web/a/index.md","raw":{"oid":"d".repeat(40)},"text":"new copied prose"},"postings":["copied postings"],"raw":"raw source body"});
        let compact = compact_identity(&original, 0);
        assert!(compact.get("postings").is_none());
        assert!(compact.get("raw").is_none());
        assert!(compact["before"].get("text").is_none());
        let compiled =
            crate::attribution_providers::candidate("mdn", "changes", "fixture-history", &compact)
                .unwrap()
                .unwrap();
        assert_eq!(
            compiled.evidence["dependencies"].as_array().unwrap().len(),
            2
        );
    }
    #[test]
    fn dependency_proofs_bind_declared_targets_and_bound_depth() {
        let child = target("dependency");
        let child_generation = generation_for(&child);
        let (parent, generation) = composite(&child, &child_generation, "parent");
        assert_eq!(
            publication_entries(&parent, &generation, ATTRIBUTION_POLICY_MANIFESTS)
                .unwrap()
                .len(),
            2
        );
        let mut missing = generation.clone();
        missing.receipts.pop();
        assert!(publication_entries(&parent, &missing, ATTRIBUTION_POLICY_MANIFESTS).is_err());
        let mut foreign = generation.clone();
        foreign.receipts[1]["target"]["subject"]["key"] = json!("foreign");
        assert!(self::generation(&foreign).is_err());
        let mut wrong_policy = generation.clone();
        wrong_policy.receipts[1]["generation"]["policy_epoch"] = json!(99);
        assert!(self::generation(&wrong_policy).is_err());
        let (mut deep_target, mut deep_generation) = (child, child_generation);
        for n in 0..9 {
            (deep_target, deep_generation) =
                composite(&deep_target, &deep_generation, &format!("level-{n}"));
        }
        assert!(self::generation(&deep_generation).is_err());
    }
    #[test]
    fn registered_policy_versions_preserve_history_and_fence_unknown_future() {
        let next = AttributionPolicyManifest {
            epoch: 2,
            fingerprint: "fixture-only-policy-v2",
        };
        let registry = [ATTRIBUTION_REQUIRED_POLICY, next];
        assert_eq!(supported_control(&control(), next, &registry).unwrap(), 1);
        assert!(
            supported_control(&control_for(next), ATTRIBUTION_REQUIRED_POLICY, &registry).is_err()
        );
        assert!(supported_control(&control_for(next), next, ATTRIBUTION_POLICY_MANIFESTS).is_err());
        let prior = generation_for(&target("policy-history"));
        assert!(generation_for_registry(&prior, &registry).is_ok());
        assert_ne!(
            target_id_at(&prior.subject, 1).unwrap(),
            target_id_at(&prior.subject, 2).unwrap()
        );
        let mut future = prior;
        future.policy_epoch = 2;
        future.policy_fingerprint = next.fingerprint.into();
        future.receipts[0]["policy_epoch"] = json!(next.epoch);
        future.receipts[0]["policy_fingerprint"] = json!(next.fingerprint);
        assert!(generation_for_registry(&future, &registry).is_ok());
        assert!(generation(&future).is_err());
    }
    #[tokio::test]
    #[ignore = "requires disposable DEVRES_TEST_DATABASE_URL PostgreSQL"]
    async fn attribution_storage_fair_claims_recover_due_work_and_bound_diagnostics() {
        let base = std::env::var("DEVRES_TEST_DATABASE_URL").unwrap();
        let admin = sqlx_postgres::PgPool::connect(&base).await.unwrap();
        let name = format!("devres_attribution_fair_{}", std::process::id());
        sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!(
            "CREATE DATABASE {name}"
        )))
        .execute(&admin)
        .await
        .unwrap();
        let mut url = url::Url::parse(&base).unwrap();
        url.set_path(&format!("/{name}"));
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let store = PgBlobStore::connect(url.as_str(), root.path())
            .await
            .unwrap();
        let now = devres_domain::unix_now();
        let mut originals = std::collections::BTreeMap::new();
        {
            let mut owner = store.owner.lock().await;
            for provider in ["rfc", "mdn"] {
                for status in ["pending", "retry", "running"] {
                    for priority in [0, 1] {
                        let mut target =
                            target(&format!("never-emit-{provider}-{status}-{priority}"));
                        target.subject.provider = provider.into();
                        let mut value = State::new(target, priority);
                        value.status = status.into();
                        if status != "pending" {
                            value.retry_at = now - 1;
                            value.attempts = 1;
                        }
                        if status == "running" {
                            value.claim = Some("expired-owner-claim".into());
                        }
                        save(&mut owner, &value).await.unwrap();
                        originals.insert(value.target.subject.key.clone(), value);
                    }
                }
            }
            let mut future = State::new(target("never-emit-future-retry"), 1);
            future.status = "retry".into();
            future.retry_at = now + 600;
            save(&mut owner, &future).await.unwrap();
            let mut disabled = State::new(target("never-emit-disabled-provider"), 1);
            disabled.target.subject.provider = "crates".into();
            save(&mut owner, &disabled).await.unwrap();
            for n in 0..7 {
                let mut value = State::new(target(&format!("never-emit-blocked-{n}")), 0);
                value.status = "blocked".into();
                value.target.subject.namespace = "https://never-emit.example/secret".into();
                value.failure = Some("never_emit_error_text".into());
                save(&mut owner, &value).await.unwrap();
            }
        }
        // A real row-lock admission timeout must remain retryable scheduling work.
        let expected = originals.get("never-emit-rfc-pending-1").unwrap();
        let mut locked = store.pool.begin().await.unwrap();
        sqlx_core::query::query("SELECT id FROM devres_attribution_targets WHERE id=$1 FOR UPDATE")
            .bind(target_id(&expected.target.subject).unwrap())
            .fetch_one(&mut *locked)
            .await
            .unwrap();
        let enabled = vec!["mdn".into(), "rfc".into(), "mdn".into()];
        assert_eq!(
            store
                .attribution_claim(&enabled, now, 0)
                .await
                .unwrap_err()
                .code,
            "capacity"
        );
        locked.rollback().await.unwrap();
        let mut seen = std::collections::BTreeSet::new();
        for admission in 0..30 {
            let job = store
                .attribution_claim(&enabled, now, admission)
                .await
                .unwrap()
                .unwrap();
            let original = originals
                .get(&job.target.subject.key)
                .expect("future/disabled work cannot be admitted");
            seen.insert((
                original.target.subject.provider.clone(),
                original.status.clone(),
                original.priority,
            ));
            assert_eq!(job.attempts, original.attempts + 1);
            if original.status == "running" {
                let stale = AttributionJob {
                    target: original.target.clone(),
                    claim: original.claim.clone().unwrap(),
                    attempts: original.attempts,
                };
                assert!(
                    store
                        .attribution_fail(&stale, None, "stale_owner")
                        .await
                        .is_err()
                );
            }
            // Keep every bucket nonempty throughout, including perpetual pending
            // work with retry_at=0; finite fairness must not depend on draining it.
            let mut owner = store.owner.lock().await;
            save(&mut owner, original).await.unwrap();
        }
        assert_eq!(
            seen.len(),
            12,
            "both priorities and all provider/status buckets must advance in 15P admissions"
        );
        let job = store
            .attribution_claim(&enabled, now, u64::MAX)
            .await
            .unwrap()
            .unwrap();
        let classification = AttributionFailure::new(
            AttributionPhase::Acquisition,
            AttributionFailureReason::UpstreamUnavailable,
            AttributionDisposition::Retry,
        );
        store
            .attribution_fail_classified(&job, Some(now + 60), "retryable", &classification)
            .await
            .unwrap();
        let row = sqlx_core::query::query("SELECT * FROM devres_attribution_targets WHERE id=$1")
            .bind(target_id(&job.target.subject).unwrap())
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(state(&row).unwrap().classification, Some(classification));
        let status = store.attribution_status().await.unwrap();
        let diagnostics = &status["diagnostics"];
        assert_eq!(diagnostics["sampled"], true);
        assert!(!diagnostics.to_string().contains("never-emit"));
        assert!(!diagnostics.to_string().contains("never_emit"));
        let samples = diagnostics["samples"].as_array().unwrap();
        assert_eq!(
            samples
                .iter()
                .filter(|s| s["provider"] == "rfc"
                    && s["status"] == "blocked"
                    && s["priority"] == 0)
                .count(),
            2
        );
        assert!(
            samples
                .iter()
                .any(|s| s["classification"]["reason"] == "upstream_unavailable")
        );
        assert_eq!(status["progress"]["scope"], "this_store_process");
        assert_eq!(
            status["progress"]["providers"]["rfc"]["claimed"]
                .as_u64()
                .unwrap_or(0)
                + status["progress"]["providers"]["mdn"]["claimed"]
                    .as_u64()
                    .unwrap_or(0),
            31
        );
        {
            let mut owner = store.owner.lock().await;
            for provider in PROVIDERS {
                for status in ["pending", "retry", "running", "blocked"] {
                    for priority in [0, 1] {
                        for index in 0..2 {
                            let mut value = State::new(
                                target(&format!("bounded-{provider}-{status}-{priority}-{index}")),
                                priority,
                            );
                            value.target.subject.provider = (*provider).into();
                            value.target.subject.namespace =
                                "devres_chromium_evidence/projection-references".into();
                            value.status = status.into();
                            value.retry_at = now - 1;
                            value.attempts = u32::MAX;
                            value.claim = (status == "running").then(|| "fixture-claim".into());
                            value.classification = Some(AttributionFailure::new(
                                AttributionPhase::Qualification,
                                AttributionFailureReason::UnqualifiedScope,
                                AttributionDisposition::Blocked,
                            ));
                            save(&mut owner, &value).await.unwrap();
                        }
                    }
                }
            }
        }
        let maximum = store.attribution_status().await.unwrap();
        assert_eq!(maximum["diagnostics"]["truncated"], true);
        assert!(
            maximum["diagnostics"]["omitted_sample_rows"]
                .as_u64()
                .unwrap()
                > 0
        );
        assert!(
            serde_json::to_vec(&maximum["diagnostics"]["samples"])
                .unwrap()
                .len()
                <= 24 * 1024
        );
        assert!(
            serde_json::to_vec(&maximum).unwrap().len() < 48 * 1024,
            "leave private RPC envelope headroom"
        );
        drop(store);
        sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!(
            "DROP DATABASE {name} WITH (FORCE)"
        )))
        .execute(&admin)
        .await
        .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires disposable DEVRES_TEST_DATABASE_URL PostgreSQL"]
    async fn attribution_storage_upgrade_claims_sweep_restart_and_integrity() {
        let base = std::env::var("DEVRES_TEST_DATABASE_URL").unwrap();
        let admin = sqlx_postgres::PgPool::connect(&base).await.unwrap();
        let name = format!("devres_attribution_{}", std::process::id());
        sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!(
            "CREATE DATABASE {name}"
        )))
        .execute(&admin)
        .await
        .unwrap();
        let mut url = url::Url::parse(&base).unwrap();
        url.set_path(&format!("/{name}"));
        let root = tempfile::tempdir().unwrap();
        let store = Arc::new(
            PgBlobStore::connect(url.as_str(), root.path())
                .await
                .unwrap(),
        );
        let version: i32 = sqlx_core::query_scalar::query_scalar(
            "SELECT version FROM devres_schema WHERE singleton",
        )
        .fetch_one(&store.pool)
        .await
        .unwrap();
        assert_eq!(version, 14);
        let request = FetchRequest {
            key: "rfc:9000".into(),
            url: "https://www.rfc-editor.org/rfc/rfc9000.txt".into(),
            ttl_secs: 3600,
            max_bytes: 4096,
            media_type: "text/plain".into(),
        };
        let capture = store
            .publish(
                &request,
                FetchResponse {
                    status: 200,
                    body: b"Synthetic RFC attribution fixture".to_vec(),
                    validators: Validators::default(),
                },
                devres_domain::unix_now(),
            )
            .await
            .unwrap();
        // With sequential scans disabled, every scan/cutoff uses an existing
        // native index. No expression index or whole-corpus startup backfill.
        let mut planner = store.pool.acquire().await.unwrap();
        sqlx_core::query::query("SET enable_seqscan=off")
            .execute(&mut *planner)
            .await
            .unwrap();
        sqlx_core::query::query("SET enable_bitmapscan=off")
            .execute(&mut *planner)
            .await
            .unwrap();
        fn unbounded_plan(v: &Value) -> bool {
            match v {
                Value::Object(o) => {
                    o.get("Node Type")
                        .and_then(Value::as_str)
                        .is_some_and(|n| matches!(n, "Seq Scan" | "Sort"))
                        || o.values().any(unbounded_plan)
                }
                Value::Array(a) => a.iter().any(unbounded_plan),
                _ => false,
            }
        }
        for provider in PROVIDERS {
            for source in sources(provider).unwrap() {
                if source.filter == "false" {
                    continue;
                }
                let cursor = source.cursor();
                let base = format!(
                    "SELECT {} FROM {} t WHERE {}",
                    source.select, source.table, source.filter
                );
                let sql = format!(
                    "EXPLAIN (FORMAT JSON) SELECT {} FROM ({base}) s ORDER BY {} LIMIT 1",
                    cursor.position(),
                    cursor.order(true)
                );
                let plan: Json<Value> =
                    sqlx_core::query_scalar::query_scalar(sqlx_core::sql_str::AssertSqlSafe(sql))
                        .fetch_one(&mut *planner)
                        .await
                        .unwrap();
                assert!(
                    !unbounded_plan(&plan.0),
                    "unindexed cutoff {}: {}",
                    source.table,
                    plan.0
                );
                let high = match cursor {
                    Cursor::Key(_) => "zzzz".into(),
                    Cursor::Sequence(_) => i64::MAX.to_string(),
                    Cursor::Pair(_, _) => "[\"zzzz\",\"zzzz\"]".into(),
                    Cursor::Version => format!("[\"zzzz\",\"zzzz\",{}]", i64::MAX),
                };
                let sql = format!(
                    "EXPLAIN (FORMAT JSON) SELECT {} FROM ({base}) s WHERE {} AND {} ORDER BY {} LIMIT {PAGE}",
                    cursor.position(),
                    cursor.comparison(">", 1),
                    cursor.comparison("<=", 2),
                    cursor.order(false)
                );
                let plan: Json<Value> =
                    sqlx_core::query_scalar::query_scalar(sqlx_core::sql_str::AssertSqlSafe(sql))
                        .bind(cursor.initial())
                        .bind(high)
                        .fetch_one(&mut *planner)
                        .await
                        .unwrap();
                assert!(
                    !unbounded_plan(&plan.0),
                    "unindexed page {}: {}",
                    source.table,
                    plan.0
                );
            }
        }
        let plan:Json<Value>=sqlx_core::query_scalar::query_scalar("EXPLAIN (FORMAT JSON) SELECT id,retry_at FROM devres_attribution_targets WHERE policy_epoch=1 AND provider='rfc' AND status='pending' AND priority=1 AND retry_at<=100 ORDER BY retry_at,id LIMIT 1").fetch_one(&mut *planner).await.unwrap();
        assert!(!unbounded_plan(&plan.0), "unindexed queue head: {}", plan.0);
        sqlx_core::query::query("RESET enable_bitmapscan")
            .execute(&mut *planner)
            .await
            .unwrap();
        sqlx_core::query::query("RESET enable_seqscan")
            .execute(&mut *planner)
            .await
            .unwrap();
        drop(planner);
        let page = store.attribution_sweep_page("rfc").await.unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].evidence["data"]["id"], capture.capture.id);
        let queued: i64 = sqlx_core::query_scalar::query_scalar(
            "SELECT count(*) FROM devres_attribution_targets",
        )
        .fetch_one(&store.pool)
        .await
        .unwrap();
        assert_eq!(queued, 1);
        // Bind an actual sealed capture sweep occurrence to its exact compiler
        // result; unrelated valid same-provider evidence cannot qualify it.
        let now = devres_domain::unix_now();
        let raw_job = store
            .attribution_claim(&["rfc".into()], now, 0)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(raw_job.target, page[0]);
        let canonical = crate::attribution_providers::retained_target(
            ATTRIBUTION_POLICY_EPOCH,
            ATTRIBUTION_POLICY_FINGERPRINT,
            &raw_job.target,
        )
        .unwrap()
        .unwrap();
        assert!(
            store
                .attribution_complete(&raw_job, &generation_for(&raw_job.target))
                .await
                .is_err()
        );
        let unrelated = target("unrelated-qualified-source");
        let unrelated_proof = generation_for(&unrelated);
        assert!(generation(&unrelated_proof).is_ok());
        let mut wrong_binding = unrelated_proof;
        wrong_binding.subject = raw_job.target.subject.clone();
        wrong_binding.receipts.push(json!({"kind":"retained_subject_binding","source_target":unrelated,"retained_subject":raw_job.target.subject}));
        assert!(
            store
                .attribution_complete(&raw_job, &wrong_binding)
                .await
                .is_err()
        );
        assert!(
            store
                .attribution_ready(&raw_job.target.subject)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .attribution_ready(&unrelated.subject)
                .await
                .unwrap()
                .is_none()
        );
        let mut bound = generation_for(&canonical);
        bound.subject = raw_job.target.subject.clone();
        bound.receipts.push(json!({"kind":"retained_subject_binding","source_target":canonical,"retained_subject":raw_job.target.subject}));
        store.attribution_complete(&raw_job, &bound).await.unwrap();
        assert_eq!(
            store
                .attribution_ready(&canonical.subject)
                .await
                .unwrap()
                .unwrap()
                .generation
                .subject,
            canonical.subject
        );
        store
            .verify_attribution_for_maintenance(&CancellationToken::new())
            .await
            .unwrap();
        // Even a correctly sealed generation cannot bypass the same relation
        // check during read-only historical verification.
        let wrong_data = generation(&wrong_binding).unwrap();
        let wrong_id = crate::integrity::canonical_hash(&wrong_data).unwrap();
        sqlx_core::query::query(
            "INSERT INTO devres_attribution_generations(id,data,data_integrity) VALUES($1,$2,$3)",
        )
        .bind(&wrong_id)
        .bind(Json(&wrong_data))
        .bind(payload_integrity::digest(TABLE_GENERATIONS, "", &wrong_id, &wrong_data).unwrap())
        .execute(&store.pool)
        .await
        .unwrap();
        assert!(
            store
                .verify_attribution_for_maintenance(&CancellationToken::new())
                .await
                .is_err()
        );
        sqlx_core::query::query("DELETE FROM devres_attribution_generations WHERE id=$1")
            .bind(&wrong_id)
            .execute(&store.pool)
            .await
            .unwrap();
        let status = store.attribution_status().await.unwrap();
        assert_eq!(status["repair_complete_for_enqueued_targets"], true);
        assert_eq!(status["initial_scan_passes_complete"], false);
        assert_eq!(status["completion_scope"], "observed_sweep_cutoffs");
        assert_eq!(status["complete"], false);
        assert_eq!(status["corpus_complete"], false);
        let first = target("first");
        store.attribution_enqueue(&first, 1).await.unwrap();
        assert!(
            store
                .attribution_ready(&first.subject)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .attribution_claim(&[], now, 0)
                .await
                .unwrap()
                .is_none()
        );
        let old = store
            .attribution_claim(&["rfc".into()], now, 0)
            .await
            .unwrap()
            .unwrap();
        store
            .attribution_fail(&old, Some(now + 20), "upstream_unavailable")
            .await
            .unwrap();
        store.attribution_enqueue(&first, 255).await.unwrap();
        assert!(
            store
                .attribution_claim(&["rfc".into()], now, 0)
                .await
                .unwrap()
                .is_none()
        );
        let current = store
            .attribution_claim(&["rfc".into()], now + 21, 0)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(current.attempts, 2);
        let generation = generation_for(&first);
        assert!(store.attribution_complete(&old, &generation).await.is_err());
        store
            .attribution_complete(&current, &generation)
            .await
            .unwrap();
        let qualified = store
            .attribution_ready(&first.subject)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(qualified.generation, generation);
        assert_eq!(
            store.attribution_bundle(&qualified.id).await.unwrap(),
            qualified
        );
        let expired = target("expired");
        store.attribution_enqueue(&expired, 1).await.unwrap();
        let expired_job = store
            .attribution_claim(&["rfc".into()], now - 301, 0)
            .await
            .unwrap()
            .unwrap();
        assert!(
            store
                .attribution_complete(&expired_job, &generation_for(&expired))
                .await
                .is_err()
        );
        store
            .attribution_fail(&expired_job, None, "expired")
            .await
            .unwrap();
        let second = target("concurrent");
        store.attribution_enqueue(&second, 1).await.unwrap();
        let enabled = vec!["rfc".into()];
        let (a, b) = tokio::join!(
            store.attribution_claim(&enabled, now, 0),
            store.attribution_claim(&enabled, now, 0)
        );
        let claimed = a.unwrap().into_iter().chain(b.unwrap()).collect::<Vec<_>>();
        assert_eq!(claimed.len(), 1);
        store
            .attribution_fail(&claimed[0], None, "fixture_done")
            .await
            .unwrap();
        for key in ["status", "failure", "content-retry", "compat-retry"] {
            store
                .mdn_set_state(key, &json!({"at":1,"status":"synthetic"}))
                .await
                .unwrap();
        }
        let key = crate::integrity::hash(b"synthetic-mdn-attribution-row");
        store
            .mdn_put(
                "projections",
                &key,
                &json!({"synthetic":true,"text":"inert fixture"}),
            )
            .await
            .unwrap();
        assert!(
            store
                .attribution_sweep_page("mdn")
                .await
                .unwrap()
                .is_empty()
        );
        let page = store.attribution_sweep_page("mdn").await.unwrap();
        assert_eq!(page.len(), 1);
        assert!(page[0].evidence["data"].get("text").is_none());
        assert!(
            page[0].evidence["verified_data_fingerprint"]
                .as_str()
                .unwrap()
                .starts_with("blake3:")
        );
        store
            .verify_attribution_storage(&CancellationToken::new())
            .await
            .unwrap();
        for key in ["status", "failure", "content-retry", "compat-retry"] {
            store
                .mdn_set_state(key, &json!({"at":2,"status":"changed"}))
                .await
                .unwrap();
        }
        for _ in 0..12 {
            store.attribution_sweep_page("mdn").await.unwrap();
        }
        let operational:i64=sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM devres_attribution_targets WHERE provider='mdn' AND data#>>'{target,subject,namespace}'='devres_mdn_state' AND data#>>'{target,subject,key}' IN ('status','failure','content-retry','compat-retry')").fetch_one(&store.pool).await.unwrap();
        assert_eq!(
            operational, 0,
            "operational updates must not create attribution occurrences"
        );
        let large = json!({"synthetic":true,"text":"x".repeat(9*1024*1024)});
        let large_key = crate::integrity::canonical_hash(&large).unwrap();
        store
            .mdn_put("projections", &large_key, &large)
            .await
            .unwrap();
        let mut oversized = None;
        for _ in 0..12 {
            for candidate in store.attribution_sweep_page("mdn").await.unwrap() {
                if candidate.subject.key == large_key {
                    oversized = Some(candidate);
                }
            }
            if oversized.is_some() {
                break;
            }
        }
        let oversized = oversized.unwrap();
        assert_eq!(oversized.evidence["gap"], "oversized_evidence");
        assert!(oversized.evidence.get("data").is_none());
        let row = sqlx_core::query::query("SELECT * FROM devres_attribution_targets WHERE id=$1")
            .bind(target_id(&oversized.subject).unwrap())
            .fetch_one(&store.pool)
            .await
            .unwrap();
        let blocked = state(&row).unwrap();
        assert_eq!(blocked.status, "blocked");
        assert_eq!(blocked.failure.as_deref(), Some("oversized_evidence"));
        store.attribution_enqueue(&oversized, 1).await.unwrap();
        let mut preserved = blocked.clone();
        preserved.priority = 1;
        preserved.attempts = 7;
        preserved.failure = Some("fixture_preserved".into());
        {
            let mut owner = store.owner.lock().await;
            save(&mut owner, &preserved).await.unwrap();
        }
        let mut repeated = false;
        for _ in 0..12 {
            repeated |= store
                .attribution_sweep_page("mdn")
                .await
                .unwrap()
                .iter()
                .any(|candidate| candidate == &oversized);
            if repeated {
                break;
            }
        }
        assert!(
            repeated,
            "second sweep must revisit the same retained evidence"
        );
        let row = sqlx_core::query::query("SELECT * FROM devres_attribution_targets WHERE id=$1")
            .bind(target_id(&oversized.subject).unwrap())
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(
            bounded(&state(&row).unwrap()).unwrap(),
            bounded(&preserved).unwrap()
        );
        let child = target("durable-dependency");
        let child_generation = generation_for(&child);
        let (parent, parent_generation) = composite(&child, &child_generation, "durable-parent");
        store.attribution_enqueue(&child, 1).await.unwrap();
        let child_job = store
            .attribution_claim(&["rfc".into()], now, 0)
            .await
            .unwrap()
            .unwrap();
        store.attribution_enqueue(&parent, 0).await.unwrap();
        let parent_job = store
            .attribution_claim(&["rfc".into()], now, 0)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(parent_job.target, parent);
        assert!(
            store
                .attribution_complete(&parent_job, &parent_generation)
                .await
                .is_err()
        );
        assert!(
            store
                .attribution_ready(&child.subject)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .attribution_ready(&parent.subject)
                .await
                .unwrap()
                .is_none()
        );
        store
            .attribution_fail(&child_job, None, "fixture_released")
            .await
            .unwrap();
        store
            .attribution_complete(&parent_job, &parent_generation)
            .await
            .unwrap();
        assert_eq!(
            store
                .attribution_ready(&child.subject)
                .await
                .unwrap()
                .unwrap()
                .generation,
            child_generation
        );
        store
            .verify_attribution_storage(&CancellationToken::new())
            .await
            .unwrap();
        drop(store);
        let store = Arc::new(
            PgBlobStore::connect(url.as_str(), root.path())
                .await
                .unwrap(),
        );
        assert!(
            store
                .attribution_ready(&child.subject)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .attribution_ready(&parent.subject)
                .await
                .unwrap()
                .is_some()
        );
        let row = sqlx_core::query::query("SELECT * FROM devres_attribution_targets WHERE id=$1")
            .bind(target_id(&oversized.subject).unwrap())
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(
            bounded(&state(&row).unwrap()).unwrap(),
            bounded(&preserved).unwrap()
        );
        assert_eq!(
            store.attribution_status().await.unwrap()["progress"]["providers"],
            json!({}),
            "new process-local store counters start empty"
        );
        // The bootstrap is additive and preserves capture identities and bytes.
        sqlx_core::raw_sql::raw_sql("DROP TABLE devres_attribution_sweeps,devres_attribution_targets,devres_attribution_generations,devres_attribution_control;UPDATE devres_schema SET version=10 WHERE singleton").execute(&store.pool).await.unwrap();
        drop(store);
        let direct = sqlx_postgres::PgPool::connect(url.as_str()).await.unwrap();
        sqlx_core::query::query("UPDATE devres_integrity_control SET active=false WHERE singleton")
            .execute(&direct)
            .await
            .unwrap();
        direct.close().await;
        assert!(
            PgBlobStore::connect(url.as_str(), root.path())
                .await
                .is_err()
        );
        let direct = sqlx_postgres::PgPool::connect(url.as_str()).await.unwrap();
        let absent: bool = sqlx_core::query_scalar::query_scalar(
            "SELECT to_regclass('devres_attribution_control') IS NULL",
        )
        .fetch_one(&direct)
        .await
        .unwrap();
        assert!(absent);
        sqlx_core::query::query("UPDATE devres_integrity_control SET active=true WHERE singleton")
            .execute(&direct)
            .await
            .unwrap();
        direct.close().await;
        let store = Arc::new(
            PgBlobStore::connect(url.as_str(), root.path())
                .await
                .unwrap(),
        );
        assert_eq!(
            store
                .capture(&capture.capture.id)
                .await
                .unwrap()
                .body
                .as_ref(),
            b"Synthetic RFC attribution fixture"
        );
        let version: i32 = sqlx_core::query_scalar::query_scalar(
            "SELECT version FROM devres_schema WHERE singleton",
        )
        .fetch_one(&store.pool)
        .await
        .unwrap();
        assert_eq!(version, 14);
        store.attribution_enqueue(&first, 1).await.unwrap();
        let job = store
            .attribution_claim(&["rfc".into()], now, 0)
            .await
            .unwrap()
            .unwrap();
        store.attribution_complete(&job, &generation).await.unwrap();
        drop(store);
        let inspect = Arc::new(
            PgBlobStore::connect_for_verification(url.as_str(), root.path())
                .await
                .unwrap(),
        );
        inspect
            .verify_attribution_storage(&CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(
            inspect.attribution_bundle(&qualified.id).await.unwrap(),
            qualified
        );
        drop(inspect);
        let store = Arc::new(
            PgBlobStore::connect(url.as_str(), root.path())
                .await
                .unwrap(),
        );
        let future = json!({"format_version":1,"required_policy_epoch":ATTRIBUTION_POLICY_EPOCH+1,"required_policy_fingerprint":"future-policy"});
        sqlx_core::query::query(
            "UPDATE devres_attribution_control SET data=$1,data_integrity=$2 WHERE singleton",
        )
        .bind(Json(&future))
        .bind(
            payload_integrity::digest("devres_attribution_control", "", "singleton", &future)
                .unwrap(),
        )
        .execute(&store.pool)
        .await
        .unwrap();
        assert!(
            store
                .attribution_claim(&["rfc".into()], now, 0)
                .await
                .is_err()
        );
        assert!(store.attribution_ready(&first.subject).await.is_err());
        assert!(store.attribution_bundle(&qualified.id).await.is_err());
        let original = control();
        sqlx_core::query::query(
            "UPDATE devres_attribution_control SET data=$1,data_integrity=$2 WHERE singleton",
        )
        .bind(Json(&original))
        .bind(
            payload_integrity::digest("devres_attribution_control", "", "singleton", &original)
                .unwrap(),
        )
        .execute(&store.pool)
        .await
        .unwrap();
        // SQL index corruption cannot redirect or hide ready evidence from validation.
        sqlx_core::query::query("UPDATE devres_attribution_targets SET provider='npm'")
            .execute(&store.pool)
            .await
            .unwrap();
        assert!(store.attribution_ready(&first.subject).await.is_err());
        assert!(
            store
                .verify_attribution_storage(&CancellationToken::new())
                .await
                .is_err()
        );
        sqlx_core::query::query(
            "UPDATE devres_attribution_targets SET provider=data#>>'{target,subject,provider}'",
        )
        .execute(&store.pool)
        .await
        .unwrap();
        let next = AttributionPolicyManifest {
            epoch: 2,
            fingerprint: "fixture-only-policy-v2",
        };
        let registry = [ATTRIBUTION_REQUIRED_POLICY, next];
        let prior_count: i64 = sqlx_core::query_scalar::query_scalar(
            "SELECT count(*) FROM devres_attribution_generations",
        )
        .fetch_one(&store.pool)
        .await
        .unwrap();
        let mut owner = store.owner.lock().await;
        let mut upgrade = owner.begin().await.unwrap();
        promote_control_for(&mut upgrade, next, &registry)
            .await
            .unwrap();
        upgrade.commit().await.unwrap();
        drop(owner);
        let prior =
            sqlx_core::query::query("SELECT * FROM devres_attribution_generations WHERE id=$1")
                .bind(&qualified.id)
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert_eq!(
            qualified_for_registry(&prior, &registry).unwrap(),
            qualified
        );
        let old = sqlx_core::query::query("SELECT * FROM devres_attribution_targets WHERE id=$1")
            .bind(target_id(&first.subject).unwrap())
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(state_for_registry(&old, &registry).unwrap().policy_epoch, 1);
        let mut new_state = State::new(first.clone(), 1);
        new_state.policy_epoch = 2;
        let mut owner = store.owner.lock().await;
        save(&mut owner, &new_state).await.unwrap();
        drop(owner);
        let later = sqlx_core::query::query("SELECT * FROM devres_attribution_targets WHERE id=$1")
            .bind(target_id_at(&first.subject, 2).unwrap())
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(
            state_for_registry(&later, &registry).unwrap().status,
            "pending"
        );
        let preserved: i64 = sqlx_core::query_scalar::query_scalar(
            "SELECT count(*) FROM devres_attribution_generations",
        )
        .fetch_one(&store.pool)
        .await
        .unwrap();
        assert_eq!(preserved, prior_count);
        let sweeps: i64 =
            sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM devres_attribution_sweeps")
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert_eq!(sweeps, 0);
        assert!(store.attribution_ready(&first.subject).await.is_err());
        drop(store);
        sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!(
            "DROP DATABASE {name} WITH (FORCE)"
        )))
        .execute(&admin)
        .await
        .unwrap();
    }
}
