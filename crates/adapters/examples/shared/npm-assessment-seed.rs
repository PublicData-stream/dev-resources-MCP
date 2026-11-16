//! First-party synthetic Kubernetes assessment seed. Never accepts retained inputs.
use devres_adapters::{PgBlobStore, collection_recovery::NPM_RECOVERY_PROCESSOR_VERSION};
use devres_application::npm::NpmStore;
use serde_json::json;
use sqlx_core::connection::Connection;
use sqlx_postgres::PgConnection;
use std::path::Path;

async fn seed() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("DEVRES_SYNTHETIC_ASSESSMENT").as_deref() != Ok("1") {
        return Err("synthetic assessment admission required".into());
    }
    let database = std::env::var("DATABASE_URL")?;
    let url = url::Url::parse(&database)?;
    if url.host_str() != Some("postgres.devres-acceptance.svc.cluster.local")
        || url.path() != "/devres_assessment_fixture"
        || url.username() != "devres"
    {
        return Err("owned fixture database required".into());
    }
    let root = "/tmp/devres-assessment-seed";
    if Path::new(root).exists() {
        return Err("fresh synthetic seed directory required".into());
    }
    let mut connection = PgConnection::connect(&database).await?;
    let existing: bool = sqlx_core::query_scalar::query_scalar(
        "SELECT to_regclass('public.devres_schema') IS NOT NULL",
    )
    .fetch_one(&mut connection)
    .await?;
    if existing {
        return Err("fresh synthetic database required".into());
    }
    let store = PgBlobStore::connect(&database, root).await?;
    let digest = format!("blake3:{}", blake3::hash(b"devres:synthetic:legacy-npm:v1"));
    let artifact = format!(
        "blake3:{}",
        blake3::hash(b"synthetic retained export metadata")
    );
    let hex = artifact
        .strip_prefix("blake3:")
        .ok_or("invalid synthetic digest")?;
    let relative = format!("blake3/{hex}");
    let job = json!({"snapshot":digest,"artifact":{"body_hash":artifact,"bytes":34,"relative_path":relative},
        "validated_at":devres_domain::unix_now(),"next":0,"records":0,"gaps":0,"expanded":0,
        "done":true,"failed":"capacity","processor_version":NPM_RECOVERY_PROCESSOR_VERSION});
    store.npm_set_state("advisory-job", &job).await?;
    // Reproduce a legacy migration using fixed first-party synthetic state. There
    // is deliberately no historical failure_context or authoritative cause.
    sqlx_core::raw_sql::raw_sql("DROP TABLE devres_npm_recovery_work,devres_npm_advisory_recoveries,devres_npm_advisory_job_history; DROP FUNCTION devres_npm_recovery_immutable(); UPDATE devres_schema SET version=18 WHERE singleton").execute(&mut connection).await?;
    drop(store);
    let migrated = PgBlobStore::connect(&database, root).await?;
    let history: (String, i64, bool) = sqlx_core::query_as::query_as(
        "SELECT job_id,revision,(data->>'cause_authoritative')::boolean FROM devres_npm_advisory_job_history",
    ).fetch_one(&mut connection).await?;
    if history != (digest.clone(), 1, false) {
        return Err("synthetic legacy migration differs".into());
    }
    drop(migrated);
    println!(
        "{}",
        json!({"version":1,"schema":19,"job_id":digest,"revision":1,"cause_authoritative":false,"synthetic":true})
    );
    Ok(())
}

#[tokio::main]
async fn main() {
    // Never render database connection errors or their credential-bearing inputs.
    if seed().await.is_err() {
        eprintln!("synthetic npm assessment seed failed");
        std::process::exit(1);
    }
}
