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
    let (refresh, rebuild, import, config_path) = match args.as_slice() {
        [path] => (false, false, None, path),
        [command, path] if command == "refresh-advisories" => (true, false, None, path),
        [command,path] if command=="rebuild-rfc-index" => (false,true,None,path),
        [command, path, flag, budget] if command == "import-rfcs" && flag == "--max-bytes" => (false, false, Some(budget.parse::<u64>().map_err(|_| "invalid RFC import byte budget")?), path),
        _ => return Err("usage: devres-server [refresh-advisories] CONFIG.toml | import-rfcs CONFIG.toml --max-bytes N".into()),
    };
    let config = Config::load(Path::new(config_path)).await?;
    let store = Arc::new(
        devres_adapters::PgBlobStore::connect(
            &config.storage.database_url,
            &config.storage.blob_dir,
        )
        .await?,
    );
    let fetcher = Arc::new(devres_adapters::HttpFetcher::new()?);
    let retrieval = Arc::new(devres_application::Retrieval::new(store.clone(), fetcher));
    let corpus = Arc::new(devres_adapters::RfcCorpus::new(
        retrieval.clone(),
        store.clone(),
        &config.storage.blob_dir,
        config.rfc.clone(),
    )?);
    corpus.recover_stages().await?;
    let research = Arc::new(
        devres_adapters::Research::new(retrieval)
            .await?
            .with_corpus(corpus.clone()),
    );
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
