//! Offline provider replay shared by the CLI and disposable acceptance fixtures.
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Default)]
pub struct MigrationSettings {
    pub crates: crate::CrateConfig,
    pub rustsec: crate::RustSecConfig,
    pub mdn: crate::MdnConfig,
    pub whatwg: crate::WhatwgConfig,
    pub w3c: crate::W3cConfig,
    pub chromium: crate::ChromiumConfig,
    pub npm: crate::NpmConfig,
}

pub async fn migrate_storage_graphs(
    config: &MigrationSettings,
    store: Arc<crate::PgBlobStore>,
    cancel: CancellationToken,
) -> devres_domain::Result<serde_json::Value> {
    store.migrate_storage(cancel.clone()).await?;
    let mut mappings = store.migration_mappings().await?;
    macro_rules! migrate {
        ($provider:literal,$operation:expr) => {
            if !store.migration_graph_done($provider).await? {
                let aliases = $operation.await?;
                store.record_migration_aliases($provider, &aliases).await?;
                drop(aliases);
                crate::migration_map::reset_aliases(&mut mappings)?;
            }
        };
    }
    migrate!(
        "rfc",
        store.migrate_rfc_graph(&mut mappings, cancel.clone())
    );
    migrate!(
        "advisory",
        store.migrate_advisory_graph(&mut mappings, &config.rustsec, cancel.clone())
    );
    migrate!(
        "crate",
        store.migrate_crate_graph(&mut mappings, cancel.clone())
    );
    migrate!(
        "npm",
        store.migrate_npm_graph(&mut mappings, cancel.clone())
    );
    // These handles provide retained-file/SQL replay only. No collector task or
    // HTTP request is started by construction or by the migration methods.
    let broker = Arc::new(
        crate::bulk::BulkBroker::new(config.crates.bulk_config())?.with_npm_rates(
            config.npm.registry_requests_per_second,
            config.npm.advisory_requests_per_second,
        )?,
    );
    let mdn = crate::MdnCorpus::new(
        store.clone(),
        broker.clone(),
        store.root_path(),
        config.mdn.clone(),
    )?;
    migrate!(
        "mdn",
        mdn.migrate_blake3_graph(&mut mappings, cancel.clone())
    );
    let whatwg = crate::WhatwgCorpus::new(
        store.clone(),
        broker.clone(),
        store.root_path(),
        config.whatwg.clone(),
    )?;
    migrate!(
        "whatwg",
        whatwg.migrate_blake3_graph(&mut mappings, cancel.clone())
    );
    let w3c = crate::W3cCorpus::new(
        store.clone(),
        broker.clone(),
        store.root_path(),
        config.w3c.clone(),
    )?;
    migrate!(
        "w3c",
        w3c.migrate_blake3_graph(&mut mappings, cancel.clone())
    );
    let chromium = crate::ChromiumCorpus::new(
        store.clone(),
        broker,
        store.root_path(),
        config.chromium.clone(),
    )?;
    migrate!(
        "chromium",
        chromium.migrate_blake3_graph(&mut mappings, cancel.clone())
    );
    store.finish_graph_migration(cancel).await
}

/// Read-only graph traversal; handles never start source acquisition.
pub(crate) async fn verify_provider_graphs(
    config: &MigrationSettings,
    store: Arc<crate::PgBlobStore>,
    cancel: CancellationToken,
) -> devres_domain::Result<()> {
    let broker = Arc::new(
        crate::bulk::BulkBroker::new(config.crates.bulk_config())?.with_npm_rates(
            config.npm.registry_requests_per_second,
            config.npm.advisory_requests_per_second,
        )?,
    );
    crate::MdnCorpus::for_verification(
        store.clone(),
        broker.clone(),
        store.root_path(),
        config.mdn.clone(),
    )?
    .verify_blake3_graph(cancel.clone())
    .await?;
    crate::WhatwgCorpus::for_verification(
        store.clone(),
        broker.clone(),
        store.root_path(),
        config.whatwg.clone(),
    )?
    .verify_blake3_graph(cancel.clone())
    .await?;
    crate::W3cCorpus::for_verification(
        store.clone(),
        broker.clone(),
        store.root_path(),
        config.w3c.clone(),
    )?
    .verify_blake3_graph(cancel.clone())
    .await?;
    crate::ChromiumCorpus::for_verification(
        store.clone(),
        broker,
        store.root_path(),
        config.chromium.clone(),
    )?
    .verify_blake3_graph(cancel)
    .await?;
    Ok(())
}
