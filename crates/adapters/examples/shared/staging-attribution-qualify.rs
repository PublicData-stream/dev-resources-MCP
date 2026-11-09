//! One-shot real-source qualification for the fixed staging RFC/MDN acceptance.
//! No listeners, sweeps, collectors, audit requests or inspected-code execution.
use async_trait::async_trait;
use devres_adapters::{
    AttributionAdapter, PgBlobStore, Research, RfcConfig, attribution_providers,
    bulk::{BulkBroker, BulkConfig},
};
use devres_application::{
    Fetcher, Retrieval,
    attribution::AttributionStore,
    attribution_gate::AttributionGate,
    attribution_runtime::{AttributionAcquirer, AttributionRuntime},
};
use devres_domain::{Error, FetchRequest, FetchResponse, Result, Validators, attribution::*};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx_core::row::Row;
use sqlx_postgres::{PgPool, PgPoolOptions};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::Arc,
    time::Duration,
};
use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;

const RELEASE: &str = "0.1.0-build.78c2e9c5";
const SOURCE: &str = "https://github.com/PublicData-stream/dev-resources-MCP/releases/download/0.1.0-build.78c2e9c5/source.tar.gz";
const DEADLINE: i64 = 1794344340;
const MAX_TARGETS: usize = 128;
const REQUESTS: usize = 20;
const MDN_SNAPSHOT: &str = "10b23b616473f7534f3ba617c16453f88f5934eaa4d6e18b94b1a6a71e501f8a";
const MDN_PATH: &str = "files/en-us/games/anatomy/index.md";

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    version: u32,
    release: String,
    live_acquisition: bool,
    deadline_at: i64,
    original_enabled_providers: Vec<String>,
    rfc_capture: String,
    mdn_snapshot: String,
    mdn_path: String,
    mdn_history_snapshots: Vec<i64>,
}

fn invalid() -> Error {
    Error::integrity("Fixed attribution qualification failed.")
}
fn bounded() -> Error {
    Error::capacity("Fixed attribution qualification bound exceeded.")
}
fn require(value: bool) -> Result<()> {
    if value { Ok(()) } else { Err(invalid()) }
}
fn hash64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

impl Plan {
    fn validate(&self) -> Result<()> {
        require(
            self.version == 1
                && self.release == RELEASE
                && self.live_acquisition
                && self.deadline_at == DEADLINE
                && hash64(&self.rfc_capture)
                && self.original_enabled_providers == ["mdn", "rfc"]
                && self.mdn_snapshot == MDN_SNAPSHOT
                && self.mdn_path == MDN_PATH
                && self.mdn_history_snapshots == [16383636, 16384653],
        )
    }
}

struct NoNetwork;
#[async_trait]
impl Fetcher for NoNetwork {
    async fn fetch(&self, _: &FetchRequest, _: Option<&Validators>) -> Result<FetchResponse> {
        Err(Error::unavailable(
            "Qualification selectors require retained evidence.",
        ))
    }
}

fn id(target: &AttributionTarget) -> Result<String> {
    devres_adapters::integrity::canonical_hash(
        &json!({"version":1,"policy_epoch":ATTRIBUTION_POLICY_EPOCH,"subject":target.subject}),
    )
}

fn insert(
    targets: &mut BTreeMap<String, AttributionTarget>,
    target: AttributionTarget,
) -> Result<()> {
    require(matches!(target.subject.provider.as_str(), "rfc" | "mdn"))?;
    require(
        devres_adapters::integrity::canonical_hash(&target.evidence)? == target.subject.fingerprint,
    )?;
    let identity = id(&target)?;
    if let Some(previous) = targets.get(&identity) {
        require(previous == &target)?;
    } else {
        if targets.len() >= MAX_TARGETS {
            return Err(bounded());
        }
        targets.insert(identity, target);
    }
    Ok(())
}

fn collect(
    provider: &str,
    value: &Value,
    targets: &mut BTreeMap<String, AttributionTarget>,
) -> Result<()> {
    for target in attribution_providers::targets(provider, value)? {
        insert(targets, target)?;
    }
    Ok(())
}

fn closure(
    target: &AttributionTarget,
    depth: usize,
    targets: &mut BTreeMap<String, AttributionTarget>,
) -> Result<()> {
    if depth > 8 {
        return Err(bounded());
    }
    let identity = id(target)?;
    if let Some(previous) = targets.get(&identity) {
        return require(previous == target);
    }
    insert(targets, target.clone())?;
    if target.evidence.get("table").is_some() {
        let compiled = attribution_providers::retained_target(
            ATTRIBUTION_POLICY_EPOCH,
            ATTRIBUTION_POLICY_FINGERPRINT,
            target,
        )?
        .ok_or_else(invalid)?;
        closure(&compiled, depth + 1, targets)?;
    } else if let Some(dependencies) = target.evidence.get("dependencies") {
        let dependencies = dependencies
            .as_array()
            .filter(|v| v.len() <= MAX_TARGETS)
            .ok_or_else(bounded)?;
        for child in dependencies {
            let child: AttributionTarget =
                serde_json::from_value(child.clone()).map_err(|_| invalid())?;
            closure(&child, depth + 1, targets)?;
        }
    }
    Ok(())
}

async fn output_targets(
    research: &Research,
    provider: &str,
    output: Value,
    targets: &mut BTreeMap<String, AttributionTarget>,
) -> Result<()> {
    collect(provider, &output, targets)?;
    if let Some(snapshot) = output.get("snapshot").filter(|v| v.is_object()) {
        collect(provider, &json!({"snapshot":snapshot}), targets)?;
    }
    if let Some(uri) = output.get("resource_uri").and_then(Value::as_str) {
        require(
            uri.starts_with("devres://mdn/")
                || uri.starts_with("devres://capture/")
                || uri.starts_with("devres://rfc/"),
        )?;
        let uri = if output["representation"] == "bytes" {
            format!("{uri}?limit=8")
        } else {
            uri.to_owned()
        };
        collect(provider, &research.read_resource(&uri).await?, targets)?;
    }
    Ok(())
}

async fn selections(
    research: &Research,
    pool: &PgPool,
    plan: &Plan,
) -> Result<BTreeMap<String, AttributionTarget>> {
    let mut targets = BTreeMap::new();
    let resource = research
        .read_resource(&format!("devres://capture/{}", plan.rfc_capture))
        .await?;
    require(
        resource
            .pointer("/contents/0/_meta/source_evidence/capture/source_url")
            .and_then(Value::as_str)
            == Some("https://www.rfc-editor.org/rfc/rfc9000.txt"),
    )?;
    collect("rfc", &resource, &mut targets)?;
    let canonical_rfc: Option<String> = sqlx_core::query_scalar::query_scalar(
        "SELECT canonical FROM devres_content_aliases WHERE namespace='capture' AND legacy=$1",
    )
    .bind(&plan.rfc_capture)
    .fetch_optional(pool)
    .await
    .map_err(|_| invalid())?;
    if let Some(canonical) = canonical_rfc {
        require(canonical.strip_prefix("blake3:").is_some_and(hash64))?;
        collect(
            "rfc",
            &research
                .read_resource(&format!("devres://capture/{canonical}"))
                .await?,
            &mut targets,
        )?;
    }
    output_targets(
        research,
        "rfc",
        research
            .call(
                "rfc.fulltext_search",
                json!({"query":"multiplexed","limit":3}),
            )
            .await?,
        &mut targets,
    )
    .await?;
    let canonical_mdn: String = sqlx_core::query_scalar::query_scalar("SELECT canonical FROM devres_content_aliases WHERE namespace='mdn:snapshots' AND legacy=$1")
        .bind(&plan.mdn_snapshot).fetch_one(pool).await.map_err(|_| invalid())?;
    require(canonical_mdn.strip_prefix("blake3:").is_some_and(hash64))?;
    for snapshot in [&plan.mdn_snapshot, &canonical_mdn] {
        for representation in ["text", "bytes"] {
            let value = research.call("mdn.get", json!({"repository":"content","snapshot":snapshot,"path":plan.mdn_path,"representation":representation,"limit":32768})).await?;
            output_targets(research, "mdn", value, &mut targets).await?;
        }
        let value = research
            .call(
                "mdn.search",
                json!({"snapshot":snapshot,"path":plan.mdn_path,"limit":1}),
            )
            .await?;
        output_targets(research, "mdn", value, &mut targets).await?;
    }
    for cutoff in &plan.mdn_history_snapshots {
        let value = research
            .call(
                "mdn.snapshots",
                json!({"repository":"content","limit":1,"history_snapshot":cutoff}),
            )
            .await?;
        output_targets(research, "mdn", value, &mut targets).await?;
    }
    let value = research
        .call("mdn.snapshots", json!({"repository":"content","limit":1}))
        .await?;
    output_targets(research, "mdn", value, &mut targets).await?;
    require(
        !targets.is_empty()
            && targets.values().any(|v| v.subject.provider == "rfc")
            && targets.values().any(|v| v.subject.provider == "mdn"),
    )?;
    Ok(targets)
}

async fn queue_guard(
    store: &PgBlobStore,
    pool: &PgPool,
    roots: &BTreeMap<String, AttributionTarget>,
    allowed: &BTreeMap<String, AttributionTarget>,
    cancel: &CancellationToken,
) -> Result<()> {
    // Reject an unrelated serving/sweep database before the sealed verifier can
    // traverse its history. Every subsequent walk is bounded to this fixed set.
    let swept: bool = sqlx_core::query_scalar::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM devres_attribution_sweeps)",
    )
    .fetch_one(pool)
    .await
    .map_err(|_| invalid())?;
    require(!swept)?;
    let rows = sqlx_core::query::query(
        "SELECT id,provider,status FROM devres_attribution_targets ORDER BY id LIMIT 129",
    )
    .fetch_all(pool)
    .await
    .map_err(|_| invalid())?;
    if rows.len() > MAX_TARGETS {
        return Err(bounded());
    }
    for row in &rows {
        let identity: String = row.try_get("id").map_err(|_| invalid())?;
        let provider: String = row.try_get("provider").map_err(|_| invalid())?;
        let status: String = row.try_get("status").map_err(|_| invalid())?;
        let target = allowed.get(&identity).ok_or_else(invalid)?;
        require(
            target.subject.provider == provider
                && (status == "ready" || roots.contains_key(&identity)),
        )?;
    }
    let generations = sqlx_core::query::query(
        "SELECT id FROM devres_attribution_generations ORDER BY id LIMIT 129",
    )
    .fetch_all(pool)
    .await
    .map_err(|_| invalid())?;
    if generations.len() > MAX_TARGETS {
        return Err(bounded());
    }
    for row in generations {
        let generation_id: String = row.try_get("id").map_err(|_| invalid())?;
        let subject: Value = sqlx_core::query_scalar::query_scalar("SELECT data->'subject' FROM devres_attribution_generations WHERE id=$1 AND octet_length(data::text)<=8388608")
            .bind(generation_id).fetch_one(pool).await.map_err(|_| invalid())?;
        require(
            allowed.values().any(|target| {
                serde_json::to_value(&target.subject).ok().as_ref() == Some(&subject)
            }),
        )?;
    }
    store.verify_attribution_for_maintenance(cancel).await?;
    for row in rows {
        if row.try_get::<String, _>("status").map_err(|_| invalid())? == "ready" {
            let identity: String = row.try_get("id").map_err(|_| invalid())?;
            let target = allowed.get(&identity).ok_or_else(invalid)?;
            require(store.attribution_ready(&target.subject).await?.is_some())?;
        }
    }
    Ok(())
}

fn readable(value: &QualifiedAttribution) -> Result<String> {
    require(
        value.generation.policy_epoch == ATTRIBUTION_POLICY_EPOCH
            && value.generation.policy_fingerprint == ATTRIBUTION_POLICY_FINGERPRINT
            && !value.generation.notices.is_empty()
            && !value.generation.receipts.is_empty(),
    )?;
    let mut seen = BTreeSet::new();
    let mut text = Vec::new();
    for notice in &value.generation.notices {
        require(!notice.text.trim().is_empty() && notice.source_url.starts_with("https://"))?;
        let entry = format!("{}\n{}", notice.source_url, notice.text);
        if seen.insert(entry.clone()) {
            text.push(entry);
        }
    }
    let text = text.join("\n\n");
    if text.len() > 4 * 1024 * 1024 {
        return Err(bounded());
    }
    Ok(text)
}

async fn notice_roundtrip(
    gate: &AttributionRuntime,
    qualified: &QualifiedAttribution,
) -> Result<()> {
    let expected = readable(qualified)?;
    let mut bytes = Vec::new();
    let mut offset = 0;
    for _ in 0..65 {
        let value = gate.bundle(&qualified.id, offset, 65536).await?;
        let content = value.pointer("/contents/0").ok_or_else(invalid)?;
        require(
            content
                .pointer("/_meta/attribution/policy_epoch")
                .and_then(Value::as_u64)
                == Some(u64::from(ATTRIBUTION_POLICY_EPOCH)),
        )?;
        require(
            value["contents"].as_array().is_some_and(|v| v.len() == 1)
                && content["uri"] == format!("devres://attribution/{}", qualified.id)
                && content["mimeType"] == "text/plain"
                && content["_meta"]["attribution"]["id"] == qualified.id
                && content["_meta"]["attribution"]["subject"]
                    == serde_json::to_value(&qualified.generation.subject)
                        .map_err(|_| invalid())?
                && content["_meta"]["offset"].as_u64() == Some(offset as u64)
                && content["_meta"]["total_bytes"].as_u64() == Some(expected.len() as u64),
        )?;
        let text = content
            .get("text")
            .and_then(Value::as_str)
            .ok_or_else(invalid)?;
        bytes.extend_from_slice(text.as_bytes());
        if bytes.len() > 4 * 1024 * 1024 {
            return Err(bounded());
        }
        match content
            .pointer("/_meta/next_offset")
            .and_then(Value::as_u64)
        {
            Some(next) => {
                let next = usize::try_from(next).map_err(|_| bounded())?;
                require(next > offset && next == bytes.len())?;
                offset = next;
            }
            None => return require(bytes == expected.as_bytes()),
        }
    }
    Err(bounded())
}

async fn run(
    config: &Value,
    plan: &Plan,
    plan_sha256: &str,
    cancel: &CancellationToken,
) -> Result<Value> {
    let database = config
        .pointer("/storage/database_url")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    let root = config
        .pointer("/storage/blob_dir")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    require(
        root == "/data/blobs"
            && config.pointer("/source/url").and_then(Value::as_str) == Some(SOURCE),
    )?;
    let url = url::Url::parse(database).map_err(|_| invalid())?;
    require(
        url.scheme() == "postgres"
            && url.host_str() == Some("postgres")
            && url.port() == Some(5432)
            && url.path() == "/devres"
            && url.username() == "devres"
            && url.password().is_some(),
    )?;
    for provider in [
        "rfc", "crates", "rustsec", "mdn", "whatwg", "w3c", "chromium", "npm",
    ] {
        require(
            config
                .pointer(&format!("/{provider}/enabled"))
                .and_then(Value::as_bool)
                == Some(false),
        )?;
    }
    // connect takes the same exclusive advisory owner fence as normal serving,
    // initializes schema11, and composes no background worker or network task.
    let store = Arc::new(PgBlobStore::connect(database, root).await?);
    let pool = PgPoolOptions::new().max_connections(1).after_connect(|connection, _| Box::pin(async move {
        sqlx_core::raw_sql::raw_sql("SET default_transaction_read_only=on; SET statement_timeout='10s'; SET lock_timeout='200ms'")
            .execute(connection).await?; Ok(())
    })).connect(database).await.map_err(|_| invalid())?;
    let schema: i32 =
        sqlx_core::query_scalar::query_scalar("SELECT version FROM devres_schema WHERE singleton")
            .fetch_one(&pool)
            .await
            .map_err(|_| invalid())?;
    let active: bool = sqlx_core::query_scalar::query_scalar(
        "SELECT active FROM devres_integrity_control WHERE singleton",
    )
    .fetch_one(&pool)
    .await
    .map_err(|_| invalid())?;
    require(schema == 11 && active)?;
    let broker = Arc::new(BulkBroker::new(BulkConfig::default())?.with_attempt_budget(REQUESTS)?);
    let retrieval = Arc::new(Retrieval::new(store.clone(), Arc::new(NoNetwork)));
    let rfc = Arc::new(devres_adapters::rfc::RfcCorpus::new(
        retrieval.clone(),
        store.clone(),
        root,
        RfcConfig {
            enabled: false,
            ..Default::default()
        },
    )?);
    let mdn = Arc::new(devres_adapters::mdn::research::MdnResearch::new(
        store.clone(),
        Path::new(root),
    )?);
    let research = Research::new(retrieval)
        .await?
        .with_corpus(rfc)
        .with_mdn_research(mdn);
    let roots = selections(&research, &pool, plan).await?;
    let mut allowed = BTreeMap::new();
    for target in roots.values() {
        closure(target, 0, &mut allowed)?;
    }
    queue_guard(&store, &pool, &roots, &allowed, cancel).await?;
    for target in roots.values() {
        if store.attribution_ready(&target.subject).await?.is_none() {
            store.attribution_enqueue(target, 1).await?;
        }
    }
    let acquirer = Arc::new(AttributionAdapter::new(broker.clone(), store.clone()));
    let providers = vec!["mdn".to_owned(), "rfc".to_owned()];
    for _ in 0..MAX_TARGETS {
        if cancel.is_cancelled() {
            return Err(Error::new("cancelled", "Qualification cancelled."));
        }
        let mut remaining = false;
        for target in roots.values() {
            remaining |= store.attribution_ready(&target.subject).await?.is_none();
        }
        if !remaining {
            break;
        }
        queue_guard(&store, &pool, &roots, &allowed, cancel).await?;
        let job = store
            .attribution_claim(&providers, devres_domain::unix_now())
            .await?
            .ok_or_else(invalid)?;
        require(roots.get(&id(&job.target)?) == Some(&job.target))?;
        let result = acquirer.repair(&job.target, cancel.child_token()).await;
        match result {
            Ok(generation) => store.attribution_complete(&job, &generation).await?,
            Err(error) => {
                store
                    .attribution_fail(&job, None, "qualification_failed")
                    .await?;
                return Err(error);
            }
        }
        queue_guard(&store, &pool, &roots, &allowed, cancel).await?;
    }
    let gate = AttributionRuntime::new(store.clone(), acquirer, Vec::new())?;
    for target in roots.values() {
        let qualified = store
            .attribution_ready(&target.subject)
            .await?
            .ok_or_else(invalid)?;
        require(qualified.generation.subject == target.subject)?;
        notice_roundtrip(&gate, &qualified).await?;
    }
    queue_guard(&store, &pool, &roots, &allowed, cancel).await?;
    store.verify_attribution_for_maintenance(cancel).await?;
    let ids: Vec<&String> = roots.keys().collect();
    let digest = devres_adapters::integrity::canonical_hash(&json!(ids))?;
    Ok(
        json!({"version":1,"release":RELEASE,"schema":11,"integrity_active":true,
        "scope":"fixed_retained_rfc_mdn","plan_sha256":plan_sha256,
        "policy_epoch":ATTRIBUTION_POLICY_EPOCH,"policy_fingerprint":ATTRIBUTION_POLICY_FINGERPRINT,
        "qualified_targets":roots.len(),"providers":providers,"request_attempts":broker.attempt_count(),
        "maximum_requests":REQUESTS,"ready":true,"notices_verified":true,"attribution_storage_verified":true,
        "target_set_digest":digest}),
    )
}

async fn program() -> Result<Value> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    require(args.len() == 2)?;
    let config_bytes = bounded_read(Path::new(&args[0]), 65536).await?;
    let plan_bytes = bounded_read(Path::new(&args[1]), 512 * 1024).await?;
    let config: toml::Value =
        toml::from_str(std::str::from_utf8(&config_bytes).map_err(|_| invalid())?)
            .map_err(|_| invalid())?;
    let config = serde_json::to_value(config).map_err(|_| invalid())?;
    let plan: Plan = serde_json::from_slice(&plan_bytes).map_err(|_| invalid())?;
    plan.validate()?;
    let seconds = u64::try_from(plan.deadline_at - devres_domain::unix_now())
        .map_err(|_| invalid())?
        .min(1200);
    require(seconds > 0)?;
    let digest = hex::encode(Sha256::digest(&plan_bytes));
    let cancel = CancellationToken::new();
    let operation = run(&config, &plan, &digest, &cancel);
    tokio::pin!(operation);
    let mut signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| invalid())?;
    tokio::select! {
        result = &mut operation => result,
        _ = tokio::time::sleep(Duration::from_secs(seconds)) => { cancel.cancel(); let _ = operation.await; Err(Error::unavailable("Qualification deadline exceeded.")) },
        _ = signal.recv() => { cancel.cancel(); let _ = operation.await; Err(Error::new("cancelled","Qualification cancelled.")) },
        _ = tokio::signal::ctrl_c() => { cancel.cancel(); let _ = operation.await; Err(Error::new("cancelled","Qualification cancelled.")) },
    }
}

async fn bounded_read(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let file = tokio::fs::File::open(path).await.map_err(|_| invalid())?;
    require(file.metadata().await.map_err(|_| invalid())?.is_file())?;
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| invalid())?;
    if bytes.len() > limit {
        return Err(bounded());
    }
    Ok(bytes)
}

#[tokio::main]
async fn main() {
    match program().await {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("{}", json!({"qualification_failed":true,"code":error.code}));
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn plan() -> Plan {
        Plan {
            version: 1,
            release: RELEASE.into(),
            live_acquisition: true,
            deadline_at: DEADLINE,
            original_enabled_providers: vec!["mdn".into(), "rfc".into()],
            rfc_capture: "a".repeat(64),
            mdn_snapshot: MDN_SNAPSHOT.into(),
            mdn_path: MDN_PATH.into(),
            mdn_history_snapshots: vec![16383636, 16384653],
        }
    }
    #[test]
    fn refuses_unapproved_scope_and_selectors() {
        assert!(plan().validate().is_ok());
        let mut value = plan();
        value.live_acquisition = false;
        assert!(value.validate().is_err());
        let mut value = plan();
        value.original_enabled_providers.push("npm".into());
        assert!(value.validate().is_err());
        let mut value = plan();
        value.mdn_path = "../../private".into();
        assert!(value.validate().is_err());
        let mut value = plan();
        value.deadline_at += 1;
        assert!(value.validate().is_err());
        let mut value = plan();
        value.rfc_capture = "private-input".into();
        assert!(value.validate().is_err());
    }
    fn target(provider: &str, evidence: Value) -> AttributionTarget {
        AttributionTarget {
            subject: AttributionSubject {
                provider: provider.into(),
                namespace: "fixture".into(),
                key: "fixture".into(),
                fingerprint: devres_adapters::integrity::canonical_hash(&evidence).unwrap(),
            },
            evidence,
        }
    }
    #[test]
    fn closure_rejects_other_providers_and_conflicting_evidence() {
        let child = target(
            "rfc",
            json!({"source_url":"https://www.rfc-editor.org/rfc/rfc9000.txt"}),
        );
        let root = target("mdn", json!({"dependencies":[child]}));
        let mut targets = BTreeMap::new();
        closure(&root, 0, &mut targets).unwrap();
        assert_eq!(targets.len(), 2);
        let bad = target("npm", json!({"url":"https://registry.npmjs.org"}));
        assert!(closure(&bad, 0, &mut targets).is_err());
        let mut wrong = root;
        wrong.evidence = json!({"different":true});
        assert!(insert(&mut targets, wrong).is_err());
    }
    #[tokio::test]
    #[ignore = "requires disposable DEVRES_TEST_DATABASE_URL PostgreSQL"]
    async fn fixed_queue_scope_precedes_sealed_walk_and_claim() {
        let base = std::env::var("DEVRES_TEST_DATABASE_URL").unwrap();
        let admin = PgPool::connect(&base).await.unwrap();
        let name = format!("devres_fixed_qualification_{}", std::process::id());
        sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!(
            "CREATE DATABASE {name}"
        )))
        .execute(&admin)
        .await
        .unwrap();
        let mut url = url::Url::parse(&base).unwrap();
        url.set_path(&format!("/{name}"));
        let directory = tempfile::tempdir_in("/tmp").unwrap();
        let store = PgBlobStore::connect(url.as_str(), directory.path())
            .await
            .unwrap();
        let pool = PgPool::connect(url.as_str()).await.unwrap();
        let fixed = target(
            "rfc",
            json!({"source_url":"https://www.rfc-editor.org/rfc/rfc9000.txt","fixture":"fixed"}),
        );
        let mut roots = BTreeMap::new();
        insert(&mut roots, fixed.clone()).unwrap();
        let cancel = CancellationToken::new();
        queue_guard(&store, &pool, &roots, &roots, &cancel)
            .await
            .unwrap();
        store.attribution_enqueue(&fixed, 1).await.unwrap();
        queue_guard(&store, &pool, &roots, &roots, &cancel)
            .await
            .unwrap();
        let other = target(
            "rfc",
            json!({"source_url":"https://www.rfc-editor.org/rfc/rfc9000.txt","fixture":"unrelated"}),
        );
        store.attribution_enqueue(&other, 1).await.unwrap();
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert_eq!(
            queue_guard(&store, &pool, &roots, &roots, &cancelled)
                .await
                .unwrap_err()
                .code,
            "integrity"
        );
        let running: i64 = sqlx_core::query_scalar::query_scalar(
            "SELECT count(*) FROM devres_attribution_targets WHERE status='running'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(running, 0); // The scope guard never claims unrelated jobs.
        sqlx_core::query::query("DELETE FROM devres_attribution_targets WHERE id=$1")
            .bind(id(&other).unwrap())
            .execute(&pool)
            .await
            .unwrap();
        sqlx_core::query::query("UPDATE devres_attribution_targets SET priority=0 WHERE id=$1")
            .bind(id(&fixed).unwrap())
            .execute(&pool)
            .await
            .unwrap();
        assert!(
            queue_guard(&store, &pool, &roots, &roots, &cancel)
                .await
                .is_err()
        );
        sqlx_core::query::query("UPDATE devres_attribution_targets SET priority=1 WHERE id=$1")
            .bind(id(&fixed).unwrap())
            .execute(&pool)
            .await
            .unwrap();
        queue_guard(&store, &pool, &roots, &roots, &cancel)
            .await
            .unwrap();
        // A bounded metadata preflight rejects table growth before cancellation
        // could reach the sealed walk, and before any acquisition or claim.
        for number in 0..128 {
            let value = target(
                "rfc",
                json!({"source_url":"https://www.rfc-editor.org/rfc/rfc9000.txt","fixture":number}),
            );
            store.attribution_enqueue(&value, 1).await.unwrap();
        }
        assert_eq!(
            queue_guard(&store, &pool, &roots, &roots, &cancelled)
                .await
                .unwrap_err()
                .code,
            "capacity"
        );
        sqlx_core::query::query("DELETE FROM devres_attribution_targets WHERE id<>$1")
            .bind(id(&fixed).unwrap())
            .execute(&pool)
            .await
            .unwrap();
        for number in 0..129 {
            sqlx_core::query::query("INSERT INTO devres_attribution_generations(id,data,data_integrity) VALUES($1,$2,'fixture-only-invalid-seal')")
                .bind(format!("fixture-{number:03}")).bind(sqlx_core::types::Json(json!({"subject":fixed.subject}))).execute(&pool).await.unwrap();
        }
        assert_eq!(
            queue_guard(&store, &pool, &roots, &roots, &cancelled)
                .await
                .unwrap_err()
                .code,
            "capacity"
        );
        pool.close().await;
        drop(store);
        sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!(
            "DROP DATABASE {name} WITH (FORCE)"
        )))
        .execute(&admin)
        .await
        .unwrap();
        admin.close().await;
    }
    #[tokio::test]
    async fn file_reads_reject_overflow_without_loading_whole_input() {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let path = root.path().join("input");
        tokio::fs::write(&path, b"12345").await.unwrap();
        assert_eq!(bounded_read(&path, 5).await.unwrap(), b"12345");
        assert_eq!(bounded_read(&path, 4).await.unwrap_err().code, "capacity");
        assert!(bounded_read(root.path(), 5).await.is_err());
    }
}
