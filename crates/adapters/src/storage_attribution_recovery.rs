//! Exact, offline RustSec queue recovery. This never acquires provider evidence.
use super::*;

const REPAIR_V1: &str = "rustsec-captures-v1";
pub const RUSTSEC_CAPTURE_REPAIR_VERSION: &str = REPAIR_V1;
/// Explicitly selected repair for current-policy successors. The established
/// v1 option defaults and immutable journal dispatch remain pinned to v1.
pub const RUSTSEC_CAPTURE_REPAIR_VERSION_V2: &str = "rustsec-captures-v2";
// This recipe's rights-policy identity is immutable. A later active policy or
// repair implementation must retain this dispatch for the permanent journal.
const REPAIR_POLICY_V1: AttributionPolicyManifest = AttributionPolicyManifest {
    epoch: 1,
    fingerprint: "devres-attribution-v1:exact-reacquisition:member-scopes:readable-notices",
};
const TABLE: &str = "devres_attribution_recoveries";

pub(crate) const SCHEMA_V17: &str = r#"
CREATE TABLE devres_attribution_recoveries(
 id text PRIMARY KEY, target_id text NOT NULL REFERENCES devres_attribution_targets(id),
 policy_epoch integer NOT NULL CHECK(policy_epoch>0), repair_version text NOT NULL,
 data jsonb NOT NULL, data_integrity text NOT NULL,
 UNIQUE(target_id,policy_epoch,repair_version)
);
CREATE FUNCTION devres_attribution_recovery_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'Attribution recovery records are immutable'; END $$;
CREATE TRIGGER devres_attribution_recovery_immutable BEFORE UPDATE OR DELETE ON devres_attribution_recoveries
 FOR EACH ROW EXECUTE FUNCTION devres_attribution_recovery_immutable();
"#;

#[derive(Clone, Debug)]
pub struct RustSecRecoveryOptions {
    pub target_id: String,
    pub expected_state: Option<String>,
    pub policy_epoch: u32,
    pub policy_fingerprint: String,
    pub repair_version: String,
}
impl Default for RustSecRecoveryOptions {
    fn default() -> Self {
        Self {
            target_id: String::new(),
            expected_state: None,
            policy_epoch: REPAIR_POLICY_V1.epoch,
            policy_fingerprint: REPAIR_POLICY_V1.fingerprint.into(),
            repair_version: RUSTSEC_CAPTURE_REPAIR_VERSION.into(),
        }
    }
}
impl RustSecRecoveryOptions {
    pub fn current_policy() -> Self {
        Self {
            policy_epoch: ATTRIBUTION_POLICY_EPOCH,
            policy_fingerprint: ATTRIBUTION_POLICY_FINGERPRINT.into(),
            repair_version: RUSTSEC_CAPTURE_REPAIR_VERSION_V2.into(),
            ..Self::default()
        }
    }
    pub fn validate(&self, apply: bool) -> Result<()> {
        if !crate::integrity::valid_hash(&self.target_id)
            || !self.target_id.starts_with("blake3:")
            || self
                .expected_state
                .as_deref()
                .is_some_and(|v| !v.starts_with("blake3:") || !crate::integrity::valid_hash(v))
            || (apply && self.expected_state.is_none())
            || recipe_policy(
                &self.repair_version,
                self.policy_epoch,
                &self.policy_fingerprint,
                ATTRIBUTION_POLICY_MANIFESTS,
            )
            .is_err()
        {
            return Err(Error::invalid("Invalid RustSec recovery options."));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RustSecRecoveryOutcome {
    Eligible,
    Ineligible,
    SchemaUpgradeRequired,
    AlreadyApplied,
    Applied,
}

#[derive(Clone, Debug, Serialize)]
pub struct RustSecRecoveryReport {
    pub version: u32,
    pub schema: i32,
    pub target_id: String,
    pub policy_epoch: u32,
    pub policy_fingerprint: String,
    pub repair_version: String,
    pub state_digest: String,
    pub eligible: bool,
    pub outcome: RustSecRecoveryOutcome,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Recovery {
    version: u32,
    target_id: String,
    policy_epoch: u32,
    policy_fingerprint: String,
    repair_version: String,
    previous_state: Value,
    previous_digest: String,
    applied_at: i64,
}

fn recovery_id(target_id: &str, epoch: u32, recipe: &str) -> Result<String> {
    crate::integrity::canonical_hash(&json!({
        "version":1,"target_id":target_id,"policy_epoch":epoch,"repair_version":recipe
    }))
}

fn recipe_policy(
    recipe: &str,
    epoch: u32,
    fingerprint: &str,
    registry: &[AttributionPolicyManifest],
) -> Result<AttributionPolicyManifest> {
    match recipe {
        REPAIR_V1
            if epoch == REPAIR_POLICY_V1.epoch
                && fingerprint == REPAIR_POLICY_V1.fingerprint
                && known_policy(epoch, fingerprint, registry) =>
        {
            Ok(REPAIR_POLICY_V1)
        }
        RUSTSEC_CAPTURE_REPAIR_VERSION_V2
            if epoch == 2
                && fingerprint
                    == "devres-attribution-v2:verified-forward-origins:member-scopes:readable-notices"
                && known_policy(epoch, fingerprint, registry) =>
        {
            Ok(AttributionPolicyManifest {
                epoch: 2,
                fingerprint: "devres-attribution-v2:verified-forward-origins:member-scopes:readable-notices",
            })
        }
        _ => Err(invalid()),
    }
}

fn eligible(value: &State) -> Result<bool> {
    if value.policy_epoch != ATTRIBUTION_POLICY_EPOCH {
        return Ok(false);
    }
    let policy = recipe_policy(
        RUSTSEC_CAPTURE_REPAIR_VERSION_V2,
        ATTRIBUTION_POLICY_EPOCH,
        ATTRIBUTION_POLICY_FINGERPRINT,
        ATTRIBUTION_POLICY_MANIFESTS,
    )?;
    eligible_v1(value, policy)
}

// Keep both this predicate and the retained v1 compiler when newer recipes are
// introduced. Historical verification does not adopt the active rearm policy.
fn eligible_v1(value: &State, policy: AttributionPolicyManifest) -> Result<bool> {
    if value.target.subject.provider != "rustsec"
        || value.policy_epoch != policy.epoch
        || value.status != "blocked"
        || value.claim.is_some()
        || value.generation.is_some()
        || value.classification.as_ref().is_none_or(|failure| {
            failure.phase != AttributionPhase::Mapping
                || failure.reason != AttributionFailureReason::UnsupportedSource
                || failure.disposition != AttributionDisposition::Blocked
        })
    {
        return Ok(false);
    }
    let compiled;
    let target = if value.target.evidence.get("table").is_some() {
        compiled = crate::attribution_providers::retained_target(
            policy.epoch,
            policy.fingerprint,
            &value.target,
        )?;
        let Some(target) = &compiled else {
            return Ok(false);
        };
        target
    } else {
        &value.target
    };
    Ok(crate::attribution_providers::rustsec_capture_supported(
        target,
    ))
}

/// The caller must size-admit the exact SQL row before loading it.
pub(crate) fn checked_target_summary(row: &PgRow) -> Result<Value> {
    let value = state(row)?;
    let digest: String = row.try_get("data_integrity").map_err(|_| invalid())?;
    let manifest = ATTRIBUTION_POLICY_MANIFESTS
        .iter()
        .find(|policy| policy.epoch == value.policy_epoch)
        .ok_or_else(invalid)?;
    let recipe = if value.policy_epoch == REPAIR_POLICY_V1.epoch {
        RUSTSEC_CAPTURE_REPAIR_VERSION
    } else {
        RUSTSEC_CAPTURE_REPAIR_VERSION_V2
    };
    Ok(
        json!({"target_id":row.try_get::<String,_>("id").map_err(|_|invalid())?,
        "subject":value.target.subject,"policy_epoch":value.policy_epoch,
        "policy_fingerprint":manifest.fingerprint,"status":value.status,
        "classification":value.classification,"state_digest":digest,
        "repair_version":recipe,"eligible":eligible(&value)?}),
    )
}

fn checked_recovery(row: &PgRow) -> Result<Recovery> {
    let id: String = row.try_get("id").map_err(|_| invalid())?;
    let payload = checked(TABLE, &id, row)?;
    let recovery: Recovery = serde_json::from_value(payload).map_err(|_| invalid())?;
    let previous: State =
        serde_json::from_value(recovery.previous_state.clone()).map_err(|_| invalid())?;
    validate_state(&previous, ATTRIBUTION_POLICY_MANIFESTS)?;
    let policy = recipe_policy(
        &recovery.repair_version,
        recovery.policy_epoch,
        &recovery.policy_fingerprint,
        ATTRIBUTION_POLICY_MANIFESTS,
    )?;
    if recovery.version != 1
        || recovery.applied_at < 0
        || recovery.applied_at > devres_domain::unix_now().saturating_add(300)
        || target_id_at(&previous.target.subject, previous.policy_epoch)? != recovery.target_id
        || payload_integrity::digest(
            TABLE_TARGETS,
            "",
            &recovery.target_id,
            &recovery.previous_state,
        )? != recovery.previous_digest
        || !eligible_v1(&previous, policy)?
        || recovery_id(
            &recovery.target_id,
            recovery.policy_epoch,
            &recovery.repair_version,
        )? != id
        || row
            .try_get::<String, _>("target_id")
            .map_err(|_| invalid())?
            != recovery.target_id
        || row
            .try_get::<i32, _>("policy_epoch")
            .map_err(|_| invalid())?
            != i32::try_from(recovery.policy_epoch).map_err(|_| invalid())?
        || row
            .try_get::<String, _>("repair_version")
            .map_err(|_| invalid())?
            != recovery.repair_version
    {
        return Err(invalid());
    }
    Ok(recovery)
}

async fn load_target(conn: &mut PgConnection, id: &str, lock: bool) -> Result<PgRow> {
    let bytes: Option<i64> = sqlx_core::query_scalar::query_scalar(
        "SELECT octet_length(data::text)::bigint FROM devres_attribution_targets WHERE id=$1",
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|_| storage_error())?;
    if bytes.ok_or_else(|| Error::not_found("Selected attribution target unavailable."))?
        > MAX_VALUE as i64
    {
        return Err(Error::capacity(
            "Selected attribution target exceeds its bound.",
        ));
    }
    let sql = if lock {
        "SELECT * FROM devres_attribution_targets WHERE id=$1 AND octet_length(data::text)<=$2 FOR UPDATE"
    } else {
        "SELECT * FROM devres_attribution_targets WHERE id=$1 AND octet_length(data::text)<=$2"
    };
    sqlx_core::query::query(sql)
        .bind(id)
        .bind(MAX_VALUE as i64)
        .fetch_one(conn)
        .await
        .map_err(|_| storage_error())
}

/// Uses no archive, collector, listener, migration, or PgBlobStore initialization.
/// Apply requires stopped runtime participants and active schema seventeen or eighteen.
pub async fn recover_rustsec_attribution(
    database_url: &str,
    options: &RustSecRecoveryOptions,
    apply: bool,
) -> Result<RustSecRecoveryReport> {
    options.validate(apply)?;
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        recover(database_url, options, apply),
    )
    .await
    .map_err(|_| Error::capacity("RustSec recovery deadline exceeded."))?
}

async fn recover(
    database_url: &str,
    options: &RustSecRecoveryOptions,
    apply: bool,
) -> Result<RustSecRecoveryReport> {
    let mut conn = PgConnection::connect(database_url)
        .await
        .map_err(|_| storage_error())?;
    sqlx_core::raw_sql::raw_sql("SET statement_timeout='3000ms'; SET lock_timeout='1000ms'")
        .execute(&mut conn)
        .await
        .map_err(|_| storage_error())?;
    let lifecycle_sql = if apply {
        "SELECT pg_try_advisory_lock(1835365490,2)"
    } else {
        "SELECT pg_try_advisory_lock_shared(1835365490,2)"
    };
    let held: bool = sqlx_core::query_scalar::query_scalar(lifecycle_sql)
        .fetch_one(&mut conn)
        .await
        .map_err(|_| storage_error())?;
    if !held {
        return Err(Error::capacity(
            "RustSec recovery requires compatible storage ownership.",
        ));
    }
    if apply {
        let held: bool =
            sqlx_core::query_scalar::query_scalar("SELECT pg_try_advisory_lock(1835365490,1)")
                .fetch_one(&mut conn)
                .await
                .map_err(|_| storage_error())?;
        if !held {
            return Err(Error::capacity(
                "RustSec recovery requires stopped writers.",
            ));
        }
    } else {
        sqlx_core::raw_sql::raw_sql("SET default_transaction_read_only=on")
            .execute(&mut conn)
            .await
            .map_err(|_| storage_error())?;
    }
    let mut tx = conn.begin().await.map_err(|_| storage_error())?;
    if !apply {
        sqlx_core::raw_sql::raw_sql("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *tx)
            .await
            .map_err(|_| storage_error())?;
    }
    let schema:i32 = sqlx_core::query_scalar::query_scalar("SELECT version FROM devres_schema WHERE singleton AND (SELECT active FROM devres_integrity_control WHERE singleton) AND to_regclass('public.devres_archive_restore_pending') IS NULL")
        .fetch_one(&mut *tx).await.map_err(|_|storage_error())?;
    if !(14..=18).contains(&schema) || (apply && schema < 17) {
        return Err(Error::unavailable(
            "RustSec recovery requires a supported active schema.",
        ));
    }
    verify_control(&mut tx).await?;
    let row = load_target(&mut tx, &options.target_id, apply).await?;
    let mut value = state(&row)?;
    if value.target.subject.provider != "rustsec" || value.policy_epoch != options.policy_epoch {
        return Err(Error::invalid(
            "Selected target does not match RustSec recovery policy.",
        ));
    }
    let digest: String = row.try_get("data_integrity").map_err(|_| invalid())?;
    let mut report = RustSecRecoveryReport {
        version: 1,
        schema,
        target_id: options.target_id.clone(),
        policy_epoch: options.policy_epoch,
        policy_fingerprint: options.policy_fingerprint.clone(),
        repair_version: options.repair_version.clone(),
        state_digest: digest.clone(),
        eligible: eligible(&value)?,
        outcome: RustSecRecoveryOutcome::Ineligible,
    };
    let journal_id = recovery_id(
        &options.target_id,
        options.policy_epoch,
        &options.repair_version,
    )?;
    if schema >= 17 {
        let bytes:Option<i64> = sqlx_core::query_scalar::query_scalar("SELECT octet_length(data::text)::bigint FROM devres_attribution_recoveries WHERE id=$1")
            .bind(&journal_id).fetch_optional(&mut *tx).await.map_err(|_|storage_error())?;
        if let Some(bytes) = bytes {
            if bytes > MAX_VALUE as i64 {
                return Err(invalid());
            }
            let journal =
                sqlx_core::query::query("SELECT * FROM devres_attribution_recoveries WHERE id=$1")
                    .bind(&journal_id)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(|_| storage_error())?;
            let recovery = checked_recovery(&journal)?;
            if apply && options.expected_state.as_deref() != Some(recovery.previous_digest.as_str())
            {
                return Err(Error::invalid("RustSec recovery state changed."));
            }
            report.eligible = false;
            report.outcome = RustSecRecoveryOutcome::AlreadyApplied;
            tx.rollback().await.map_err(|_| storage_error())?;
            return Ok(report);
        }
    }
    if !apply {
        report.outcome = if schema < 17 {
            RustSecRecoveryOutcome::SchemaUpgradeRequired
        } else if report.eligible {
            RustSecRecoveryOutcome::Eligible
        } else {
            RustSecRecoveryOutcome::Ineligible
        };
        if schema < 17 {
            report.eligible = false;
        }
        tx.rollback().await.map_err(|_| storage_error())?;
        return Ok(report);
    }
    if options.expected_state.as_deref() != Some(digest.as_str()) {
        return Err(Error::invalid("RustSec recovery state changed."));
    }
    if !report.eligible {
        return Err(Error::invalid(
            "Selected attribution target is not eligible for this recovery.",
        ));
    }
    let previous_state = checked(TABLE_TARGETS, &options.target_id, &row)?;
    let recovery = Recovery {
        version: 1,
        target_id: options.target_id.clone(),
        policy_epoch: options.policy_epoch,
        policy_fingerprint: options.policy_fingerprint.clone(),
        repair_version: options.repair_version.clone(),
        previous_state,
        previous_digest: digest,
        applied_at: devres_domain::unix_now(),
    };
    let payload = bounded(&recovery)?;
    sqlx_core::query::query("INSERT INTO devres_attribution_recoveries(id,target_id,policy_epoch,repair_version,data,data_integrity) VALUES($1,$2,$3,$4,$5,$6)")
        .bind(&journal_id).bind(&options.target_id).bind(i32::try_from(options.policy_epoch).map_err(|_|invalid())?)
        .bind(&options.repair_version).bind(Json(&payload)).bind(payload_integrity::digest(TABLE,"",&journal_id,&payload)?)
        .execute(&mut *tx).await.map_err(|_|storage_error())?;
    value.status = "pending".into();
    value.retry_at = 0;
    value.failure = None;
    value.classification = None;
    save(&mut tx, &value).await?;
    verify_control(&mut tx).await?;
    tx.commit().await.map_err(|_| storage_error())?;
    report.outcome = RustSecRecoveryOutcome::Applied;
    report.eligible = false;
    Ok(report)
}

pub(super) async fn verify_journal(store: &PgBlobStore, cancel: &CancellationToken) -> Result<()> {
    let mut after = String::new();
    loop {
        if cancel.is_cancelled() {
            return Err(Error::unavailable("Attribution verification canceled."));
        }
        let rows=sqlx_core::query::query("SELECT id,octet_length(data::text)::bigint AS bytes FROM devres_attribution_recoveries WHERE id>$1 ORDER BY id LIMIT 128")
            .bind(&after).fetch_all(&store.pool).await.map_err(|_|storage_error())?;
        if rows.is_empty() {
            break;
        }
        for row in rows {
            if cancel.is_cancelled() {
                return Err(Error::unavailable("Attribution verification canceled."));
            }
            let id: String = row.try_get("id").map_err(|_| invalid())?;
            if row.try_get::<i64, _>("bytes").map_err(|_| invalid())? > MAX_VALUE as i64 {
                return Err(invalid());
            }
            let row =
                sqlx_core::query::query("SELECT * FROM devres_attribution_recoveries WHERE id=$1")
                    .bind(&id)
                    .fetch_one(&store.pool)
                    .await
                    .map_err(|_| storage_error())?;
            let recovery = checked_recovery(&row)?;
            let target = load_target(
                &mut *store.pool.acquire().await.map_err(|_| storage_error())?,
                &recovery.target_id,
                false,
            )
            .await?;
            let previous: State =
                serde_json::from_value(recovery.previous_state).map_err(|_| invalid())?;
            let current = state(&target)?;
            if current.target != previous.target
                || current.policy_epoch != previous.policy_epoch
                || current.attempts < previous.attempts
            {
                return Err(invalid());
            }
            after = id;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocked(label: &str) -> State {
        let source = json!({"id":crate::integrity::hash(label.as_bytes()),
            "body_hash":crate::integrity::hash(b"synthetic exact head"),
            "source_url":"https://api.github.com/repos/RustSec/advisory-db/commits/main",
            "media_type":"application/json"});
        let target = crate::attribution_providers::targets("rustsec", &source)
            .unwrap()
            .pop()
            .unwrap();
        let mut value = State::new(target, 1);
        value.status = "blocked".into();
        value.attempts = 3;
        value.failure = Some("blocked".into());
        value.classification = Some(AttributionFailure::new(
            AttributionPhase::Mapping,
            AttributionFailureReason::UnsupportedSource,
            AttributionDisposition::Blocked,
        ));
        value
    }

    #[test]
    fn historical_recipe_uses_registered_v1_instead_of_a_later_policy_entry() {
        let later = AttributionPolicyManifest {
            epoch: 2,
            fingerprint: "fixture-only-future-policy",
        };
        let registry = [later, REPAIR_POLICY_V1];
        let selected = recipe_policy(
            REPAIR_V1,
            REPAIR_POLICY_V1.epoch,
            REPAIR_POLICY_V1.fingerprint,
            &registry,
        )
        .unwrap();
        assert_eq!(selected, REPAIR_POLICY_V1);
        let mut historical = blocked("historical recipe");
        historical.policy_epoch = REPAIR_POLICY_V1.epoch;
        assert!(eligible_v1(&historical, selected).unwrap());
        assert!(recipe_policy(REPAIR_V1, 1, REPAIR_POLICY_V1.fingerprint, &[later]).is_err());
        assert!(
            recipe_policy(
                "unregistered-repair",
                1,
                REPAIR_POLICY_V1.fingerprint,
                &registry
            )
            .is_err()
        );
        assert!(recipe_policy(REPAIR_V1, later.epoch, later.fingerprint, &registry).is_err());
        assert!(recipe_policy(REPAIR_V1, 1, "unregistered-policy", &registry).is_err());
    }

    #[test]
    fn recovery_is_restricted_to_exact_new_recipe_and_known_mapping_blocks() {
        let value = blocked("unit");
        assert!(eligible(&value).unwrap());
        let mut invalid_priority = value.clone();
        invalid_priority.priority = 255;
        assert!(validate_state(&invalid_priority, ATTRIBUTION_POLICY_MANIFESTS).is_err());
        for status in ["ready", "running", "retry", "pending"] {
            let mut changed = value.clone();
            changed.status = status.into();
            assert!(!eligible(&changed).unwrap());
        }
        let mut changed = value.clone();
        changed.classification = None;
        assert!(!eligible(&changed).unwrap());
        changed.classification = Some(AttributionFailure::new(
            AttributionPhase::Qualification,
            AttributionFailureReason::MissingNotice,
            AttributionDisposition::Blocked,
        ));
        assert!(!eligible(&changed).unwrap());
        let mut options = RustSecRecoveryOptions {
            target_id: target_id(&value.target.subject).unwrap(),
            ..RustSecRecoveryOptions::current_policy()
        };
        assert!(options.validate(false).is_ok());
        assert!(options.validate(true).is_err());
        options.expected_state = Some(crate::integrity::hash(b"state"));
        assert!(options.validate(true).is_ok());
        options.repair_version = "unregistered".into();
        assert!(options.validate(false).is_err());
        options.repair_version = RUSTSEC_CAPTURE_REPAIR_VERSION.into();
        options.policy_epoch = 2;
        assert!(options.validate(false).is_err());
        assert_ne!(
            recovery_id(&options.target_id, 1, "v1").unwrap(),
            recovery_id(&options.target_id, 1, "v2").unwrap()
        );
    }

    #[tokio::test]
    #[ignore = "requires disposable DEVRES_TEST_DATABASE_URL PostgreSQL"]
    async fn attribution_storage_exact_recovery_preserves_history_and_is_atomic() {
        let base = std::env::var("DEVRES_TEST_DATABASE_URL").unwrap();
        let admin = sqlx_postgres::PgPool::connect(&base).await.unwrap();
        let name = format!("devres_recovery_{}", std::process::id());
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
        let original = blocked("selected");
        let rollback = blocked("rollback");
        let mut unrelated = blocked("legitimate-notice-gap");
        unrelated.classification = Some(AttributionFailure::new(
            AttributionPhase::Qualification,
            AttributionFailureReason::MissingNotice,
            AttributionDisposition::Blocked,
        ));
        {
            let mut owner = store.owner.lock().await;
            save(&mut owner, &original).await.unwrap();
            save(&mut owner, &rollback).await.unwrap();
            save(&mut owner, &unrelated).await.unwrap();
        }
        let mut options = RustSecRecoveryOptions {
            target_id: target_id(&original.target.subject).unwrap(),
            ..RustSecRecoveryOptions::current_policy()
        };
        // Simulate the immediately preceding active schema without changing targets.
        sqlx_core::raw_sql::raw_sql("DROP TABLE devres_attribution_origins; DROP TABLE devres_attribution_recoveries; DROP FUNCTION devres_attribution_recovery_immutable(); UPDATE devres_schema SET version=16 WHERE singleton")
            .execute(&store.pool).await.unwrap();
        let legacy = recover_rustsec_attribution(url.as_str(), &options, false)
            .await
            .unwrap();
        assert_eq!(
            legacy.outcome,
            RustSecRecoveryOutcome::SchemaUpgradeRequired
        );
        assert!(!legacy.eligible);
        options.expected_state = Some(legacy.state_digest.clone());
        assert!(
            recover_rustsec_attribution(url.as_str(), &options, true)
                .await
                .is_err()
        );
        drop(store);
        let store = PgBlobStore::connect(url.as_str(), root.path())
            .await
            .unwrap();
        let dry = recover_rustsec_attribution(url.as_str(), &options, false)
            .await
            .unwrap();
        assert_eq!(dry.outcome, RustSecRecoveryOutcome::Eligible);
        assert_eq!(
            dry.state_digest, legacy.state_digest,
            "upgrade preserves the sealed target"
        );
        options.expected_state = Some(dry.state_digest);
        assert!(
            recover_rustsec_attribution(url.as_str(), &options, true)
                .await
                .is_err(),
            "live owner fences apply"
        );
        let records: i64 = sqlx_core::query_scalar::query_scalar(
            "SELECT count(*) FROM devres_attribution_recoveries",
        )
        .fetch_one(&store.pool)
        .await
        .unwrap();
        assert_eq!(records, 0);
        drop(store);
        let applied = recover_rustsec_attribution(url.as_str(), &options, true)
            .await
            .unwrap();
        assert_eq!(applied.outcome, RustSecRecoveryOutcome::Applied);
        let repeated = recover_rustsec_attribution(url.as_str(), &options, true)
            .await
            .unwrap();
        assert_eq!(repeated.outcome, RustSecRecoveryOutcome::AlreadyApplied);
        let mut stale = options.clone();
        stale.expected_state = Some(crate::integrity::hash(b"wrong"));
        assert!(
            recover_rustsec_attribution(url.as_str(), &stale, true)
                .await
                .is_err()
        );
        let pool = sqlx_postgres::PgPool::connect(url.as_str()).await.unwrap();
        let row = sqlx_core::query::query("SELECT * FROM devres_attribution_targets WHERE id=$1")
            .bind(&options.target_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        let pending = state(&row).unwrap();
        assert_eq!(pending.status, "pending");
        assert_eq!(pending.attempts, original.attempts);
        assert_eq!(pending.target, original.target);
        let journal = sqlx_core::query::query("SELECT * FROM devres_attribution_recoveries")
            .fetch_one(&pool)
            .await
            .unwrap();
        let journal = checked_recovery(&journal).unwrap();
        assert_eq!(journal.previous_state, bounded(&original).unwrap());
        let other = sqlx_core::query::query("SELECT * FROM devres_attribution_targets WHERE id=$1")
            .bind(target_id(&unrelated.target.subject).unwrap())
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            checked(
                TABLE_TARGETS,
                &target_id(&unrelated.target.subject).unwrap(),
                &other
            )
            .unwrap(),
            bounded(&unrelated).unwrap()
        );
        assert!(
            sqlx_core::query::query("UPDATE devres_attribution_recoveries SET data=data")
                .execute(&pool)
                .await
                .is_err()
        );
        assert!(
            sqlx_core::query::query("DELETE FROM devres_attribution_recoveries")
                .execute(&pool)
                .await
                .is_err()
        );
        let rollback_options = RustSecRecoveryOptions {
            target_id: target_id(&rollback.target.subject).unwrap(),
            ..RustSecRecoveryOptions::current_policy()
        };
        let dry = recover_rustsec_attribution(url.as_str(), &rollback_options, false)
            .await
            .unwrap();
        let rollback_options = RustSecRecoveryOptions {
            expected_state: Some(dry.state_digest),
            ..rollback_options
        };
        sqlx_core::raw_sql::raw_sql("CREATE FUNCTION devres_recovery_fixture_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture recovery save failure'; END $$; CREATE TRIGGER devres_recovery_fixture_fail BEFORE UPDATE ON devres_attribution_targets FOR EACH ROW EXECUTE FUNCTION devres_recovery_fixture_fail();")
            .execute(&pool).await.unwrap();
        assert!(
            recover_rustsec_attribution(url.as_str(), &rollback_options, true)
                .await
                .is_err()
        );
        let count: i64 = sqlx_core::query_scalar::query_scalar(
            "SELECT count(*) FROM devres_attribution_recoveries",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(count, 1, "failed target update rolls journal back");
        sqlx_core::raw_sql::raw_sql("DROP TRIGGER devres_recovery_fixture_fail ON devres_attribution_targets; DROP FUNCTION devres_recovery_fixture_fail();")
            .execute(&pool).await.unwrap();
        let store = PgBlobStore::connect(url.as_str(), root.path())
            .await
            .unwrap();
        store
            .verify_attribution_storage(&CancellationToken::new())
            .await
            .unwrap();
        let old_token = rollback_options.expected_state.clone();
        {
            let mut owner = store.owner.lock().await;
            let mut changed = rollback.clone();
            changed.priority = 0;
            save(&mut owner, &changed).await.unwrap();
        }
        drop(store);
        assert!(
            recover_rustsec_attribution(url.as_str(), &rollback_options, true)
                .await
                .is_err(),
            "priority changes invalidate the whole-state token"
        );
        let dry = recover_rustsec_attribution(url.as_str(), &rollback_options, false)
            .await
            .unwrap();
        assert_ne!(Some(dry.state_digest), old_token);
        // Correct checksums cannot legitimize an impossible historical queue state.
        let journal_row = sqlx_core::query::query("SELECT * FROM devres_attribution_recoveries")
            .fetch_one(&pool)
            .await
            .unwrap();
        let journal_id: String = journal_row.try_get("id").unwrap();
        let Json(original_payload): Json<Value> = journal_row.try_get("data").unwrap();
        let mut malformed: Recovery = serde_json::from_value(original_payload.clone()).unwrap();
        malformed.previous_state["priority"] = json!(255);
        malformed.previous_digest = payload_integrity::digest(
            TABLE_TARGETS,
            "",
            &malformed.target_id,
            &malformed.previous_state,
        )
        .unwrap();
        for (payload, invalid_prior) in [
            (bounded(&malformed).unwrap(), true),
            (original_payload, false),
        ] {
            let mut change = pool.begin().await.unwrap();
            sqlx_core::raw_sql::raw_sql("ALTER TABLE devres_attribution_recoveries DISABLE TRIGGER devres_attribution_recovery_immutable")
                .execute(&mut *change).await.unwrap();
            sqlx_core::query::query(
                "UPDATE devres_attribution_recoveries SET data=$1,data_integrity=$2 WHERE id=$3",
            )
            .bind(Json(&payload))
            .bind(payload_integrity::digest(TABLE, "", &journal_id, &payload).unwrap())
            .bind(&journal_id)
            .execute(&mut *change)
            .await
            .unwrap();
            sqlx_core::raw_sql::raw_sql("ALTER TABLE devres_attribution_recoveries ENABLE TRIGGER devres_attribution_recovery_immutable")
                .execute(&mut *change).await.unwrap();
            change.commit().await.unwrap();
            let store = PgBlobStore::connect(url.as_str(), root.path())
                .await
                .unwrap();
            assert_eq!(
                store
                    .verify_attribution_storage(&CancellationToken::new())
                    .await
                    .is_err(),
                invalid_prior
            );
            drop(store);
        }
        sqlx_core::raw_sql::raw_sql("ALTER TABLE devres_attribution_recoveries DISABLE TRIGGER devres_attribution_recovery_immutable; UPDATE devres_attribution_recoveries SET data_integrity='blake3:0000000000000000000000000000000000000000000000000000000000000000'; ALTER TABLE devres_attribution_recoveries ENABLE TRIGGER devres_attribution_recovery_immutable")
            .execute(&pool).await.unwrap();
        let store = PgBlobStore::connect(url.as_str(), root.path())
            .await
            .unwrap();
        assert!(
            store
                .verify_attribution_storage(&CancellationToken::new())
                .await
                .is_err(),
            "corrupt journal seals fail storage verification"
        );
        drop(store);
        pool.close().await;
        sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!(
            "DROP DATABASE {name} WITH (FORCE)"
        )))
        .execute(&admin)
        .await
        .unwrap();
    }
}
