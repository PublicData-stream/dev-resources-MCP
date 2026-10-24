//! Offline persistence acceptance utility. Credentials enter only through env.
use devres_adapters::PgBlobStore;
use devres_application::Store;
use devres_application::advisory::{AdvisoryRecord, AdvisorySnapshot, AdvisoryStore};
use devres_domain::{FetchRequest, FetchResponse, Validators};
use serde_json::json;
use sha2::{Digest, Sha256};

const FIXTURE_IDENTITY: &[u8] = b"devres:storage-probe:rustsec:v1";
const FIXTURE_SOURCE: &str = "https://fixtures.invalid/devres/storage-probe/advisory";
const ADVISORY: &str = "```toml\n[advisory]\nid = \"RUSTSEC-2024-0001\"\npackage = \"example\"\ndate = \"2024-01-01\"\nurl = \"https://fixtures.invalid/devres/storage-probe/advisory\"\nlicense = \"CC0-1.0\"\n[versions]\npatched = [\">= 1.0.1\"]\n```\n\n# Synthetic storage-probe advisory\n\nOffline acceptance fixture only. This is not an upstream RustSec advisory.\n";

async fn seed_advisory(store: &PgBlobStore) -> Result<(), Box<dyn std::error::Error>> {
    let id = hex::encode(Sha256::digest(FIXTURE_IDENTITY));
    if store
        .advisory_snapshot(Some(&id), "rustsec")
        .await?
        .is_some()
    {
        return Ok(());
    }
    let mut parsed: rustsec::Advisory = ADVISORY.parse()?;
    parsed.metadata.collection = Some(rustsec::Collection::Crates);
    let capture = store
        .publish(
            &FetchRequest {
                key: "fixture:storage-probe:advisory".into(),
                url: FIXTURE_SOURCE.into(),
                ttl_secs: 3600,
                max_bytes: 4096,
                media_type: "text/plain".into(),
            },
            FetchResponse {
                status: 200,
                body: ADVISORY.as_bytes().to_vec(),
                validators: Validators::default(),
            },
            devres_domain::unix_now(),
        )
        .await?;
    let now = devres_domain::unix_now();
    let record = AdvisoryRecord {
        id: "RUSTSEC-2024-0001".into(),
        package: "example".into(),
        format: "rustsec".into(),
        path: "crates/example/RUSTSEC-2024-0001.md".into(),
        body: ADVISORY.into(),
        body_hash: hex::encode(Sha256::digest(ADVISORY.as_bytes())),
        metadata: json!({"id":"RUSTSEC-2024-0001","package":"example","title":parsed.title(),
            "classification":"vulnerability","date":parsed.metadata.date,"withdrawn":null,"informational":null,
            "aliases":[],"categories":[],"keywords":[],"patched":parsed.versions.patched(),"unaffected":parsed.versions.unaffected(),
            "affected":parsed.affected,"applicability_known":true,"matching_complete":true,"format":"rustsec",
            "url":FIXTURE_SOURCE,"attribution_url":FIXTURE_SOURCE,"license":"CC0-1.0","original":parsed}),
    };
    let revision = hex::encode(Sha256::digest(
        b"devres:synthetic:storage-probe:revision:v1",
    ))[..40]
        .to_owned();
    store.publish_advisory_snapshot(&AdvisorySnapshot {
        id,revision,format:"rustsec".into(),created_at:now,validated_at:Some(now),historical:false,complete:true,
        records:vec![record],captures:vec![capture.capture],parents:vec![],committed_at:0,
        coverage:json!({"complete":true,"enumerated":1,"parsed":1,"gaps":[],"synthetic":true,
            "source_url":FIXTURE_SOURCE,"note":"Synthetic acceptance data and revision; not an upstream Git commit or advisory."}),
    },false).await?;
    Ok(())
}

async fn check_advisory(store: &PgBlobStore) -> Result<(), Box<dyn std::error::Error>> {
    let id = hex::encode(Sha256::digest(FIXTURE_IDENTITY));
    let snapshot = store
        .advisory_snapshot(Some(&id), "rustsec")
        .await?
        .ok_or("Synthetic advisory snapshot missing")?;
    if snapshot.coverage["synthetic"] != true
        || snapshot.records.len() != 1
        || snapshot.records[0].body != ADVISORY
    {
        return Err("Synthetic advisory snapshot mismatch".into());
    }
    Ok(())
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database = std::env::var("DATABASE_URL")?;
    let root = std::env::var("BLOB_DIR")?;
    let store = PgBlobStore::connect(&database, root).await?;
    let request = FetchRequest {
        key: "fixture:storage-probe".into(),
        url: "https://fixtures.invalid/devres/storage-probe".into(),
        ttl_secs: 3600,
        max_bytes: 4096,
        media_type: "text/plain".into(),
    };
    let stored = match std::env::args().nth(1).as_deref() {
        Some("write") => {
            seed_advisory(&store).await?;
            store
                .publish(
                    &request,
                    FetchResponse {
                        status: 200,
                        body: b"Synthetic dev-resources persistence acceptance fixture\n".to_vec(),
                        validators: Validators::default(),
                    },
                    devres_domain::unix_now(),
                )
                .await?
        }
        Some("read") => {
            store
                .latest(&request.key)
                .await?
                .ok_or("Fixture not captured")?
                .stored
        }
        _ => return Err("Expected write or read".into()),
    };
    if stored.body != b"Synthetic dev-resources persistence acceptance fixture\n" {
        return Err("Fixture mismatch".into());
    }
    check_advisory(&store).await?;
    println!("{} {}", stored.capture.id, stored.capture.body_hash);
    Ok(())
}
