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
const MDN_CONTENT_IDENTITY: &[u8] = b"devres:storage-probe:mdn-content:v1";
const MDN_COMPAT_IDENTITY: &[u8] = b"devres:storage-probe:mdn-compat:v1";
const MDN_PATH: &str = "files/en-us/web/fixture/index.md";
const MDN_TEXT: &str =
    "Synthetic MDN storage fixture\n\nOffline acceptance text about fetch network.\n";
const MDN_SOURCE: &str = "---\ntitle: Synthetic MDN storage fixture\nslug: Web/Fixture\npage-type: guide\nbrowser-compat: api.fixtureFetch\n---\n\nSynthetic MDN storage fixture\n\nOffline acceptance text about fetch network.\n";
fn fixture_hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
async fn fixture_projection(
    store: &PgBlobStore,
    value: serde_json::Value,
) -> Result<String, Box<dyn std::error::Error>> {
    use devres_application::mdn::MdnStore;
    let id = fixture_hash(&serde_json::to_vec(&value)?);
    store.mdn_put("projections", &id, &value).await?;
    let mut header = value;
    if let Some(object) = header.as_object_mut() {
        object.remove("text");
    }
    store.mdn_put("projection-headers", &id, &header).await?;
    Ok(id)
}
async fn seed_mdn(
    store: &PgBlobStore,
    root: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    use devres_adapters::{
        bulk::BulkArtifactStore,
        mdn_index::{IndexDocument, MdnIndex},
        mdn_inventory as inventory,
    };
    use devres_application::mdn::{MdnStore, Member, Snapshot};
    use tokio_util::sync::CancellationToken;
    let content_id = fixture_hash(MDN_CONTENT_IDENTITY);
    let compat_id = fixture_hash(MDN_COMPAT_IDENTITY);
    if store.mdn_get("snapshots", &content_id).await?.is_some()
        && store.mdn_get("snapshots", &compat_id).await?.is_some()
    {
        return Ok(());
    }
    let raw = BulkArtifactStore::new(root.join("mdn/raw-artifacts"), 64 * 1024 * 1024)?;
    let mut roots = [
        inventory::empty(store).await?,
        inventory::empty(store).await?,
    ];
    let source = raw
        .capture_bytes(MDN_SOURCE.as_bytes().to_vec(), CancellationToken::new())
        .await?;
    let descriptor = json!({"body_hash":source.body_hash,"relative_path":format!("mdn/raw-artifacts/{}",source.body_hash),"bytes":source.bytes,"source_path":MDN_PATH});
    let projection = json!({"slug":"Web/Fixture","title":"Synthetic MDN storage fixture","page_type":"guide","status":[],"compatibility_keys":["api.fixtureFetch"],"headings":[],"links":[],"spec_urls":[],"text":MDN_TEXT,"metadata":{"synthetic":true},"macros":[],"gaps":[],"dependencies":[]});
    let article = fixture_projection(store, projection).await?;
    roots[0] = inventory::update(
        store,
        &roots[0],
        MDN_PATH,
        Some(Member {
            path: MDN_PATH.into(),
            oid: fixture_hash(MDN_SOURCE.as_bytes())[..40].into(),
            mode: "100644".into(),
            kind: "article".into(),
            projection: Some(article.clone()),
            raw: Some(descriptor),
            gaps: vec![],
        }),
    )
    .await?;
    let feature_data = json!({"description":"Synthetic fetch fixture only","support":{"fixture_browser":{"version_added":"1"}},"status":{"experimental":false,"deprecated":false,"standard_track":false},"mdn_url":"https://fixtures.invalid/mdn/Web/Fixture"});
    let browser_data = json!({"name":"Synthetic Fixture Browser","type":"desktop","releases":{"1":{"engine":"FixtureEngine","engine_version":"1","status":"current"}}});
    let mut feature_id = String::new();
    for (kind, key, path, value, prefix) in [
        (
            "feature",
            "api.fixtureFetch",
            "api/fixtureFetch.json",
            json!({"api":{"fixtureFetch":{"__compat":feature_data.clone()}}}),
            "@features",
        ),
        (
            "browser",
            "fixture_browser",
            "browsers/fixture_browser.json",
            json!({"browsers":{"fixture_browser":browser_data.clone()}}),
            "@browsers",
        ),
    ] {
        let bytes = serde_json::to_vec(&value)?;
        let artifact = raw
            .capture_bytes(bytes.clone(), CancellationToken::new())
            .await?;
        let descriptor = json!({"body_hash":artifact.body_hash,"relative_path":format!("mdn/raw-artifacts/{}",artifact.body_hash),"bytes":artifact.bytes,"source_path":path});
        let projection = fixture_projection(
            store,
            json!({"key":key,"data":if kind=="feature"{&feature_data}else{&browser_data}}),
        )
        .await?;
        if kind == "feature" {
            feature_id = projection.clone();
        }
        roots[1] = inventory::update(
            store,
            &roots[1],
            path,
            Some(Member {
                path: path.into(),
                oid: fixture_hash(&bytes)[..40].into(),
                mode: "100644".into(),
                kind: "bcd".into(),
                projection: None,
                raw: Some(descriptor.clone()),
                gaps: vec![],
            }),
        )
        .await?;
        let synthetic_path = format!("{prefix}/{key}");
        roots[1] = inventory::update(
            store,
            &roots[1],
            &synthetic_path,
            Some(Member {
                path: synthetic_path.clone(),
                oid: fixture_hash(&bytes)[..40].into(),
                mode: "100644".into(),
                kind: kind.into(),
                projection: Some(projection),
                raw: Some(descriptor),
                gaps: vec![],
            }),
        )
        .await?;
    }
    let index = MdnIndex::new(root)?;
    let reference=index.publish(None,vec![IndexDocument{id:article,kind:"article".into(),slug:"Web/Fixture".into(),title:"Synthetic MDN storage fixture".into(),path:MDN_PATH.into(),text:MDN_TEXT.into(),metadata:json!({"page_type":"guide","compatibility_key":["api.fixtureFetch"]})},IndexDocument{id:feature_id,kind:"feature".into(),slug:"api.fixtureFetch".into(),title:"Synthetic fetch fixture only".into(),path:"@features/api.fixtureFetch".into(),text:"Synthetic fetch fixture only".into(),metadata:json!({"feature":"api.fixtureFetch","browser":["fixture_browser"],"experimental":false,"deprecated":false,"standard_track":false})}],CancellationToken::new()).await?;
    for (repository, id, inventory) in [
        ("content", content_id, roots[0].clone()),
        ("compat", compat_id, roots[1].clone()),
    ] {
        let snapshot = Snapshot {
            id: id.clone(),
            repository: repository.into(),
            revision: fixture_hash(format!("synthetic-mdn-{repository}").as_bytes())[..40].into(),
            tree: fixture_hash(format!("synthetic-mdn-tree-{repository}").as_bytes())[..40].into(),
            parents: vec![],
            committed_at: 0,
            inventory,
            processor_version: 1,
            index: reference.clone(),
            coverage: json!({"synthetic":true,"accounted":true,"source_url":"https://fixtures.invalid/devres/storage-probe/mdn","note":"Synthetic acceptance data; no upstream Git revision or provider observation."}),
        };
        store
            .mdn_put("snapshots", &id, &serde_json::to_value(snapshot)?)
            .await?;
    }
    Ok(())
}
async fn check_mdn(
    store: &PgBlobStore,
    root: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    use devres_adapters::{
        mdn_index::{MdnIndex, SearchSpec},
        mdn_inventory,
    };
    use devres_application::mdn::{MdnStore, Snapshot};
    use std::collections::BTreeSet;
    use tokio_util::sync::CancellationToken;
    let index = MdnIndex::new(root)?;
    for identity in [MDN_CONTENT_IDENTITY, MDN_COMPAT_IDENTITY] {
        let row = store
            .mdn_get("snapshots", &fixture_hash(identity))
            .await?
            .ok_or("Synthetic MDN snapshot missing")?;
        let snapshot: Snapshot = serde_json::from_value(row.data)?;
        if snapshot.coverage["synthetic"] != true {
            return Err("MDN fixture lost synthetic provenance".into());
        }
        let members = mdn_inventory::members(store, &snapshot.inventory, 100).await?;
        let ids: BTreeSet<_> = members
            .iter()
            .filter(|m| matches!(m.kind.as_str(), "article" | "feature"))
            .filter_map(|m| m.projection.clone())
            .collect();
        let found = index
            .search(
                &snapshot.index,
                ids,
                SearchSpec {
                    query: Some("fetch".into()),
                    ..Default::default()
                },
                CancellationToken::new(),
            )
            .await?;
        if found["total"] != 1 {
            return Err("Synthetic MDN search fixture mismatch".into());
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database = std::env::var("DATABASE_URL")?;
    let root = std::env::var("BLOB_DIR")?;
    let store = PgBlobStore::connect(&database, &root).await?;
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
            seed_mdn(&store, std::path::Path::new(&root)).await?;
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
    check_mdn(&store, std::path::Path::new(&root)).await?;
    println!("{} {}", stored.capture.id, stored.capture.body_hash);
    Ok(())
}
