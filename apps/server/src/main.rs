use devres_server::{
    ServerBuilder, ServerError,
    config::{AccessPolicy, Config},
    http::{HealthEndpoint, HttpEndpoint},
    registry::server_info_registry,
    webtransport::WebTransportEndpoint,
};
use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> Result<(), ServerError> {
    // No request/provider payload or tracing HTTP middleware is installed.
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("devres_server=info"))
        .init();
    let args: Vec<_> = std::env::args().skip(1).collect();
    let mdn_rebuild = matches!(args.as_slice(),[command,_] if command=="rebuild-mdn-index");
    let whatwg_rebuild = matches!(args.as_slice(),[command,_] if command=="rebuild-whatwg-index");
    let w3c_rebuild = matches!(args.as_slice(),[command,_] if command=="rebuild-w3c-index");
    let chromium_rebuild =
        matches!(args.as_slice(),[command,_] if command=="rebuild-chromium-index");
    let args = if mdn_rebuild || whatwg_rebuild || w3c_rebuild || chromium_rebuild {
        vec![args[1].clone()]
    } else {
        args
    };
    let (refresh, rebuild, import, crate_command, config_path) = match args.as_slice() {
        [path] => (false, false, None, None, path),
        [command, path] if command == "refresh-advisories" => (true, false, None, None, path),
        [command,path] if command=="rebuild-rfc-index" => (false,true,None,None,path),
        [command,path] if command=="rebuild-crate-index" => (false,false,None,Some(("rebuild",None)),path),
        [command,path,flag,hash] if command=="import-crate-corpus" && flag=="--manifest" => (false,false,None,Some(("import",Some(hash.as_str()))),path),
        [command, path, flag, budget] if command == "import-rfcs" && flag == "--max-bytes" => (false, false, Some(budget.parse::<u64>().map_err(|_| "invalid RFC import byte budget")?), None, path),
        _ => return Err("usage: devres-server CONFIG.toml | refresh-advisories CONFIG.toml | rebuild-rfc-index CONFIG.toml | rebuild-crate-index CONFIG.toml | rebuild-mdn-index CONFIG.toml | rebuild-whatwg-index CONFIG.toml | rebuild-w3c-index CONFIG.toml | rebuild-chromium-index CONFIG.toml | import-crate-corpus CONFIG.toml --manifest SHA256 | import-rfcs CONFIG.toml --max-bytes N".into()),
    };
    let config = Config::load(Path::new(config_path)).await?;
    let store = Arc::new(
        devres_adapters::PgBlobStore::connect(
            &config.storage.database_url,
            &config.storage.blob_dir,
        )
        .await?,
    );
    let broker = Arc::new(devres_adapters::bulk::BulkBroker::new(
        config.crates.bulk_config(),
    )?);
    let fetcher = Arc::new(devres_adapters::HttpFetcher::with_broker(broker.clone())?);
    let retrieval = Arc::new(devres_application::Retrieval::new(store.clone(), fetcher));
    let corpus = Arc::new(devres_adapters::RfcCorpus::new(
        retrieval.clone(),
        store.clone(),
        &config.storage.blob_dir,
        config.rfc.clone(),
    )?);
    corpus.recover_stages().await?;
    let crate_corpus = Arc::new(devres_adapters::CrateCorpus::new(
        store.clone(),
        retrieval.clone(),
        broker.clone(),
        &config.storage.blob_dir,
        config.crates.clone(),
    )?);
    store.attach_artifact_budget(crate_corpus.artifact_budget())?;
    crate_corpus.recover_stages().await?;
    let advisory_corpus = Arc::new(devres_adapters::AdvisoryCorpus::new(
        retrieval.clone(),
        store.clone(),
        broker.clone(),
        &config.storage.blob_dir,
        config.rustsec.clone(),
    )?);
    let mdn_corpus = Arc::new(devres_adapters::MdnCorpus::new(
        store.clone(),
        broker.clone(),
        &config.storage.blob_dir,
        config.mdn.clone(),
    )?);
    mdn_corpus.initialize_status().await?;
    let whatwg_corpus = Arc::new(devres_adapters::WhatwgCorpus::new(
        store.clone(),
        broker.clone(),
        &config.storage.blob_dir,
        config.whatwg.clone(),
    )?);
    whatwg_corpus.initialize_status().await?;
    let w3c_corpus = Arc::new(devres_adapters::W3cCorpus::new(
        store.clone(),
        broker.clone(),
        &config.storage.blob_dir,
        config.w3c.clone(),
    )?);
    w3c_corpus.initialize_status().await?;
    let chromium_corpus = Arc::new(devres_adapters::ChromiumCorpus::new(
        store.clone(),
        broker,
        &config.storage.blob_dir,
        config.chromium.clone(),
    )?);
    chromium_corpus.initialize_status().await?;
    if chromium_rebuild {
        let shutdown = CancellationToken::new();
        let signal = shutdown.clone();
        let task = tokio::spawn(async move {
            shutdown_signal().await;
            signal.cancel();
        });
        let result = chromium_corpus.rebuild_index(shutdown).await;
        task.abort();
        let _ = task.await;
        println!("{}", result?);
        return Ok(());
    }
    if w3c_rebuild {
        let shutdown = CancellationToken::new();
        let signal = shutdown.clone();
        let task = tokio::spawn(async move {
            shutdown_signal().await;
            signal.cancel();
        });
        let result = w3c_corpus.rebuild_index(shutdown).await;
        task.abort();
        let _ = task.await;
        println!("{}", result?);
        return Ok(());
    }
    if whatwg_rebuild {
        let shutdown = CancellationToken::new();
        let signal = shutdown.clone();
        let task = tokio::spawn(async move {
            shutdown_signal().await;
            signal.cancel();
        });
        let result = whatwg_corpus.rebuild_index(shutdown).await;
        task.abort();
        let _ = task.await;
        println!("{}", result?);
        return Ok(());
    }
    if mdn_rebuild {
        let shutdown = CancellationToken::new();
        let signal = shutdown.clone();
        let task = tokio::spawn(async move {
            shutdown_signal().await;
            signal.cancel();
        });
        let result = mdn_corpus.rebuild_index(shutdown).await;
        task.abort();
        let _ = task.await;
        println!("{}", result?);
        return Ok(());
    }
    let research = Arc::new(
        devres_adapters::Research::new(retrieval)
            .await?
            .with_corpus(corpus.clone())
            .with_crate_corpus(crate_corpus.clone())
            .with_advisory_corpus(advisory_corpus.clone())
            .with_mdn_research(mdn_corpus.research())
            .with_whatwg_corpus(whatwg_corpus.clone())
            .with_w3c_corpus(w3c_corpus.clone())
            .with_chromium_corpus(chromium_corpus.clone()),
    );
    if let Some((command, manifest)) = crate_command {
        let shutdown = CancellationToken::new();
        let signal = shutdown.clone();
        let signal_task = tokio::spawn(async move {
            shutdown_signal().await;
            signal.cancel();
        });
        let result = if command == "rebuild" {
            crate_corpus.rebuild_index(shutdown).await
        } else {
            crate_corpus
                .import_inventory(manifest.ok_or("missing inventory manifest")?, shutdown)
                .await
        };
        signal_task.abort();
        let _ = signal_task.await;
        println!("{}", result?);
        return Ok(());
    }
    if refresh {
        research.refresh_advisories().await?;
        println!("RustSec public advisory snapshot refreshed.");
        return Ok(());
    }
    if let Some(budget) = import {
        let shutdown = CancellationToken::new();
        let signal = shutdown.clone();
        let task = tokio::spawn(async move {
            shutdown_signal().await;
            signal.cancel();
        });
        let result = corpus.import_rsync(budget, shutdown).await;
        task.abort();
        let _ = task.await;
        println!("{}", result?);
        return Ok(());
    }
    if rebuild {
        println!("{}", corpus.rebuild_index().await?);
        return Ok(());
    }
    let mut registry = server_info_registry(config.source.url.clone())?;
    registry.register_research(research)?;
    let mut server = ServerBuilder::new(registry, config.limits, config.source.url);
    server.register_worker("rfc-collector", move |shutdown| async move {
        corpus.run(shutdown).await.map_err(Into::into)
    })?;
    server.register_worker("crate-collector", move |shutdown| async move {
        crate_corpus.run(shutdown).await.map_err(Into::into)
    })?;
    let current = advisory_corpus.clone();
    server.register_worker("rustsec-current", move |shutdown| async move {
        current.run_current(shutdown).await.map_err(Into::into)
    })?;
    server.register_worker("rustsec-history", move |shutdown| async move {
        advisory_corpus
            .run_history(shutdown)
            .await
            .map_err(Into::into)
    })?;
    let mdn_current = mdn_corpus.clone();
    server.register_worker("mdn-current", move |shutdown| async move {
        mdn_current.run_current(shutdown).await.map_err(Into::into)
    })?;
    server.register_worker("mdn-history", move |shutdown| async move {
        mdn_corpus.run_history(shutdown).await.map_err(Into::into)
    })?;
    let whatwg_current = whatwg_corpus.clone();
    server.register_worker("whatwg-current", move |shutdown| async move {
        whatwg_current
            .run_current(shutdown)
            .await
            .map_err(Into::into)
    })?;
    server.register_worker("whatwg-history", move |shutdown| async move {
        whatwg_corpus
            .run_history(shutdown)
            .await
            .map_err(Into::into)
    })?;
    let chromium_current = chromium_corpus.clone();
    server.register_worker("chromium-current", move |shutdown| async move {
        chromium_current
            .run_current(shutdown)
            .await
            .map_err(Into::into)
    })?;
    server.register_worker("chromium-history", move |shutdown| async move {
        chromium_corpus
            .run_history(shutdown)
            .await
            .map_err(Into::into)
    })?;
    let w3c_current = w3c_corpus.clone();
    server.register_worker("w3c-current", move |shutdown| async move {
        w3c_current.run_current(shutdown).await.map_err(Into::into)
    })?;
    server.register_worker("w3c-history", move |shutdown| async move {
        w3c_corpus.run_history(shutdown).await.map_err(Into::into)
    })?;
    server.register_endpoint(HttpEndpoint {
        bind: config.http.bind,
        access: AccessPolicy {
            allowed_hosts: config.http.allowed_hosts,
            allowed_origins: config.http.allowed_origins,
        },
        tls: config.http.tls,
        edge_mtls: config.edge_mtls.clone(),
    })?;
    server.register_endpoint(WebTransportEndpoint {
        bind: config.webtransport.bind,
        certificate: config.webtransport.certificate,
        private_key: config.webtransport.private_key,
        access: AccessPolicy {
            allowed_hosts: config.webtransport.allowed_hosts,
            allowed_origins: config.webtransport.allowed_origins,
        },
        edge_mtls: config.edge_mtls,
    })?;
    let storage_ready = Arc::new(AtomicBool::new(true));
    let monitor_ready = storage_ready.clone();
    server.register_worker("storage-ownership", move |shutdown| async move {
        loop {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => return Ok(()),
                result = async {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    tokio::time::timeout(Duration::from_secs(5), store.check_health()).await
                } => {
                    if !matches!(result, Ok(Ok(()))) {
                        monitor_ready.store(false, Ordering::Release);
                        return Err("storage ownership or connectivity lost; restart required".into());
                    }
                }
            }
        }
    })?;
    server.register_endpoint(
        HealthEndpoint {
            bind: config.health.bind,
        }
        .with_metrics(String::new)
        .with_readiness(move || storage_ready.load(Ordering::Acquire)),
    )?;
    let server = server.bind().await?;
    let shutdown = CancellationToken::new();
    let signal = shutdown.clone();
    let signal_task = tokio::spawn(async move {
        shutdown_signal().await;
        signal.cancel();
    });
    let result = server.run(shutdown).await;
    signal_task.abort();
    let _ = signal_task.await;
    result
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        if let Ok(mut term) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! {_=tokio::signal::ctrl_c()=>{},_=term.recv()=>{}}
        } else {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
