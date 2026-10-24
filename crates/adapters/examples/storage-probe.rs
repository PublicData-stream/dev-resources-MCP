//! Offline persistence acceptance utility. Credentials enter only through env.
use devres_adapters::PgBlobStore;
use devres_application::Store;
use devres_domain::{FetchRequest, FetchResponse, Validators};
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
    println!("{} {}", stored.capture.id, stored.capture.body_hash);
    Ok(())
}
