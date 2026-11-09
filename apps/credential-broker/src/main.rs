use axum::{
    Router,
    extract::{Request, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use devres_adapters::credential_broker::{Broker, BrokerConfig, BrokerError};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::io::AsyncReadExt;
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        self,
        pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    },
};
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> Result<(), BrokerError> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 2 && args[0] == "issuer-fingerprint" {
        let config = BrokerConfig::read(&PathBuf::from(&args[1])).await?;
        println!("{}", config.issuer_secret_fingerprint().await?);
        return Ok(());
    }
    if args.len() == 2 && args[0] == "profile-fingerprints" {
        let config = BrokerConfig::read(&PathBuf::from(&args[1])).await?;
        let fingerprints: std::collections::BTreeMap<_, _> = config
            .profiles
            .iter()
            .map(|profile| Ok((profile.application_id.clone(), profile.fingerprint()?)))
            .collect::<Result<_, BrokerError>>()?;
        println!(
            "{}",
            serde_json::to_string(&fingerprints).map_err(|_| BrokerError::Invalid)?
        );
        return Ok(());
    }
    if args.len() != 1 {
        return Err(BrokerError::Invalid);
    }
    let path = PathBuf::from(&args[0]);
    let config = BrokerConfig::load(&path).await?;
    let broker = Broker::open(path).await?;
    let tls = tls(&config).await?;
    let listener = tokio::net::TcpListener::bind(config.bind)
        .await
        .map_err(|_| BrokerError::Unavailable)?;
    let stop = CancellationToken::new();
    let shutdown = stop.clone();
    let signal = tokio::spawn(async move {
        #[cfg(unix)]
        {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(mut terminate) => {
                    tokio::select! {_=tokio::signal::ctrl_c()=>{},_=terminate.recv()=>{}}
                }
                Err(_) => {
                    let _ = tokio::signal::ctrl_c().await;
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
        shutdown.cancel();
    });
    let worker_broker = broker.clone();
    let worker_stop = stop.clone();
    let maintenance = tokio::spawn(async move {
        let mut timer = tokio::time::interval(Duration::from_secs(10));
        loop {
            tokio::select! {_=worker_stop.cancelled()=>break,_=timer.tick()=>{
                // Errors are deliberately redacted and never copied from HTTP/database clients.
                let _=worker_broker.maintain().await;
            }}
        }
    });
    let app = router(broker);
    let permits = Arc::new(tokio::sync::Semaphore::new(32));
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            _=stop.cancelled()=>break,
            Some(_)=tasks.join_next(),if !tasks.is_empty()=>{},
            accepted=listener.accept()=>{
                let (socket,_)=accepted.map_err(|_|BrokerError::Unavailable)?;
                let Ok(permit)=permits.clone().try_acquire_owned() else {continue;};
                let acceptor=tls.clone();let app=app.clone();let shutdown=stop.clone();
                tasks.spawn(async move{
                    let _permit=permit;
                    let Ok(Ok(stream))=tokio::time::timeout(Duration::from_secs(5),acceptor.accept(socket)).await else{return;};
                    let mut builder=hyper::server::conn::http1::Builder::new();
                    builder.timer(hyper_util::rt::TokioTimer::new()).header_read_timeout(Duration::from_secs(5))
                        .max_headers(16).max_buf_size(24576).keep_alive(false);
                    let connection=builder.serve_connection(hyper_util::rt::TokioIo::new(stream),
                        hyper_util::service::TowerToHyperService::new(app));
                    tokio::select!{_=shutdown.cancelled()=>{},_=tokio::time::timeout(Duration::from_secs(45),connection)=>{}}
                });
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    maintenance.abort();
    let _ = maintenance.await;
    signal.abort();
    let _ = signal.await;
    Ok(())
}
fn router(broker: Broker) -> Router {
    Router::new()
        .route("/v1/credentials", get(credentials))
        .route("/healthz", get(health))
        .fallback(|| async { StatusCode::NOT_FOUND })
        .with_state(broker)
}
async fn health(State(broker): State<Broker>) -> StatusCode {
    if broker.ready() {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}
async fn credentials(State(broker): State<Broker>, request: Request) -> Response {
    if request.uri().query().is_some()
        || request.headers().contains_key(header::ORIGIN)
        || request.headers().contains_key(header::TRANSFER_ENCODING)
        || request
            .headers()
            .get(header::CONTENT_LENGTH)
            .is_some_and(|v| v != "0")
    {
        return failure(BrokerError::Invalid);
    }
    let mut values = request.headers().get_all(header::AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return failure(BrokerError::Unauthorized);
    };
    if values.next().is_some() {
        return failure(BrokerError::Unauthorized);
    }
    let Ok(value) = value.to_str() else {
        return failure(BrokerError::Unauthorized);
    };
    let result = tokio::time::timeout(Duration::from_secs(40), broker.credentials(value)).await;
    match result {
        Ok(Ok(value)) => (
            [
                (header::CACHE_CONTROL, "no-store"),
                (header::PRAGMA, "no-cache"),
            ],
            axum::Json(value),
        )
            .into_response(),
        Ok(Err(error)) => failure(error),
        Err(_) => failure(BrokerError::Unavailable),
    }
}
fn failure(error: BrokerError) -> Response {
    let status = match error {
        BrokerError::Invalid => StatusCode::BAD_REQUEST,
        BrokerError::Unauthorized => StatusCode::UNAUTHORIZED,
        BrokerError::Forbidden => StatusCode::FORBIDDEN,
        BrokerError::Capacity => StatusCode::TOO_MANY_REQUESTS,
        BrokerError::Unavailable | BrokerError::Integrity => StatusCode::SERVICE_UNAVAILABLE,
    };
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        "Credential request unavailable.",
    )
        .into_response()
}
async fn tls(config: &BrokerConfig) -> Result<TlsAcceptor, BrokerError> {
    async fn read(path: &std::path::Path, limit: u64) -> Result<Vec<u8>, BrokerError> {
        let file = tokio::fs::File::open(path)
            .await
            .map_err(|_| BrokerError::Unavailable)?;
        let mut bytes = Vec::new();
        file.take(limit + 1)
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| BrokerError::Unavailable)?;
        if bytes.len() as u64 > limit {
            return Err(BrokerError::Invalid);
        }
        Ok(bytes)
    }
    let cert = read(&config.tls_certificate_file, 1024 * 1024).await?;
    let key = read(&config.tls_private_key_file, 65536).await?;
    if cert.len() > 1024 * 1024 || key.len() > 65536 {
        return Err(BrokerError::Invalid);
    }
    let certs = CertificateDer::pem_slice_iter(&cert)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| BrokerError::Invalid)?;
    let key = PrivateKeyDer::from_pem_slice(&key).map_err(|_| BrokerError::Invalid)?;
    let mut server = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .map_err(|_| BrokerError::Invalid)?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .map_err(|_| BrokerError::Invalid)?;
    server.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(server)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn credential_failure_never_exposes_internal_error_context() {
        for error in [
            BrokerError::Invalid,
            BrokerError::Unauthorized,
            BrokerError::Forbidden,
            BrokerError::Capacity,
            BrokerError::Unavailable,
            BrokerError::Integrity,
        ] {
            let response = failure(error);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert_ne!(response.status(), StatusCode::OK);
        }
    }
}
