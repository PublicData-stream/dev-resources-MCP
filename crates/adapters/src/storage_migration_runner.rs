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
    migrate_storage_graphs_with_execution(
        config,
        store,
        cancel,
        &crate::MigrationExecution::default(),
    )
    .await
}

pub async fn migrate_storage_graphs_with_execution(
    config: &MigrationSettings,
    store: Arc<crate::PgBlobStore>,
    cancel: CancellationToken,
    execution: &crate::MigrationExecution,
) -> devres_domain::Result<serde_json::Value> {
    store
        .migrate_storage_with_execution(cancel.clone(), execution)
        .await?;
    let mappings = store.migration_mappings_with_cancel(&cancel).await?;
    let providers = [
        "rfc", "advisory", "crate", "npm", "mdn", "whatwg", "w3c", "chromium",
    ];
    let stopping = cancel.child_token();
    let mut pending = Vec::new();
    for provider in providers {
        if !store.migration_graph_done(provider).await? {
            pending.push((provider, mappings.fork(provider)?));
        }
    }
    // Provider coordinators are not worker jobs: leaf work owns global admission.
    // In particular, holding a graph permit here would deadlock nested replay at one worker.
    if execution.options().workers == 1 {
        for (provider, mappings) in pending {
            migrate_provider(
                provider,
                mappings,
                config,
                store.clone(),
                stopping.clone(),
                execution,
            )
            .await?;
        }
    } else {
        use futures::{StreamExt, stream::FuturesUnordered};
        let mut lanes = FuturesUnordered::new();
        for (ordinal, (provider, mappings)) in pending.into_iter().enumerate() {
            let store = store.clone();
            let stopping = stopping.clone();
            lanes.push(async move {
                (
                    ordinal,
                    migrate_provider(provider, mappings, config, store, stopping, execution).await,
                )
            });
        }
        let mut failures = Vec::new();
        while let Some((ordinal, result)) = lanes.next().await {
            if let Err(error) = result {
                stopping.cancel();
                failures.push((ordinal, error));
            }
        }
        failures.sort_by_key(|(ordinal, _)| *ordinal);
        if let Some(index) = failures
            .iter()
            .position(|(_, error)| error.code != "cancelled")
        {
            return Err(failures.remove(index).1);
        }
        if let Some((_, error)) = failures.into_iter().next() {
            return Err(error);
        }
    }
    mappings.ensure_healthy()?;
    store
        .finish_graph_migration_with_execution(cancel, execution)
        .await
}

/// SQL publication remains on the existing non-reconnecting owner connection.
/// Each lane preserves its original operation order; table-local sequences are independent.
async fn migrate_provider(
    provider: &str,
    mut mappings: crate::MigrationMap,
    config: &MigrationSettings,
    store: Arc<crate::PgBlobStore>,
    cancel: CancellationToken,
    execution: &crate::MigrationExecution,
) -> devres_domain::Result<()> {
    let broker = Arc::new(
        crate::bulk::BulkBroker::new(config.crates.bulk_config())?.with_npm_rates(
            config.npm.registry_requests_per_second,
            config.npm.advisory_requests_per_second,
        )?,
    );
    execution.report(&format!("graph_{provider}"), 0, 0, 0, 0);
    let aliases = match provider {
        "rfc" => {
            store
                .migrate_rfc_graph_with_execution(&mut mappings, cancel.clone(), execution)
                .await?
        }
        "advisory" => {
            store
                .migrate_advisory_graph_with_execution(
                    &mut mappings,
                    &config.rustsec,
                    cancel.clone(),
                    execution,
                )
                .await?
        }
        "crate" => {
            store
                .migrate_crate_graph_with_execution(&mut mappings, cancel.clone(), execution)
                .await?
        }
        "npm" => {
            store
                .migrate_npm_graph_with_execution(&mut mappings, cancel.clone(), execution)
                .await?
        }
        "mdn" => {
            crate::MdnCorpus::new(store.clone(), broker, store.root_path(), config.mdn.clone())?
                .migrate_blake3_graph_with_execution(&mut mappings, cancel.clone(), execution)
                .await?
        }
        "whatwg" => {
            crate::WhatwgCorpus::new(
                store.clone(),
                broker,
                store.root_path(),
                config.whatwg.clone(),
            )?
            .migrate_blake3_graph_with_execution(&mut mappings, cancel.clone(), execution)
            .await?
        }
        "w3c" => {
            crate::W3cCorpus::new(store.clone(), broker, store.root_path(), config.w3c.clone())?
                .migrate_blake3_graph_with_execution(&mut mappings, cancel.clone(), execution)
                .await?
        }
        "chromium" => {
            crate::ChromiumCorpus::new(
                store.clone(),
                broker,
                store.root_path(),
                config.chromium.clone(),
            )?
            .migrate_blake3_graph_with_execution(&mut mappings, cancel.clone(), execution)
            .await?
        }
        _ => {
            return Err(devres_domain::Error::invalid(
                "Unknown offline migration provider.",
            ));
        }
    };
    mappings.ensure_healthy()?;
    aliases.ensure_healthy()?;
    if cancel.is_cancelled() {
        return Err(devres_domain::Error::new(
            "cancelled",
            "Graph migration canceled.",
        ));
    }
    store.record_migration_aliases(provider, &aliases).await?;
    crate::migration_map::reset_aliases(&mut mappings)?;
    Ok(())
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
