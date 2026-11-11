//! Private source-only acquisition RPC. Audit requests never enter this interface.
use crate::{
    ServerError,
    config::{WriterClientConfig, WriterListenerConfig},
    endpoint::{Binding, BoundEndpoint, Endpoint, EndpointContext, Network},
};
use async_trait::async_trait;
use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    extract::{DefaultBodyLimit, Request, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use devres_adapters::credential_broker::identity::PodAuthenticator;
use devres_application::acquisition::{
    Acquisition, AcquisitionDelegate, SourceStatus, WriterEffect,
};
use devres_domain::{Capture, Error, Result};
use futures::FutureExt;
use serde::{Deserialize, Serialize};
use std::{path::Path, sync::Arc, time::Duration};
use tokio::io::AsyncReadExt;
use tokio_rustls::TlsAcceptor;
use wtransport::tls::rustls;

const REQUEST_LIMIT: usize = 8 * 1024 * 1024 + 4096;
const RESPONSE_LIMIT: usize = 64 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Operation {
    Acquire {
        source: Acquisition,
    },
    Effect {
        effect: WriterEffect,
    },
    RfcSnapshot,
    WikipediaRequest {
        title: Option<String>,
        page_id: Option<u64>,
    },
    WikipediaSearch {
        query: String,
        limit: usize,
    },
    AttributionStatus,
    SourceStatus {
        source: SourceStatus,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Reply {
    Capture { capture: Capture },
    Complete,
    Snapshot { id: String },
    WikipediaSearch { result: serde_json::Value },
    AttributionStatus { status: serde_json::Value },
    SourceStatus { status: serde_json::Value },
    Failure { error: Error },
}

async fn secret(path: &Path) -> Result<String> {
    let mut bytes = Vec::new();
    tokio::fs::File::open(path)
        .await
        .map_err(|_| unavailable())?
        .take(16385)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| unavailable())?;
    let value = std::str::from_utf8(&bytes)
        .map_err(|_| unavailable())?
        .trim_end_matches(['\n', '\r']);
    if value.is_empty() || value.len() > 16384 || value.chars().any(char::is_control) {
        return Err(unavailable());
    }
    Ok(value.into())
}
fn unavailable() -> Error {
    Error::unavailable("Private source acquisition is unavailable.")
}

pub struct WriterClient {
    config: WriterClientConfig,
    client: reqwest::Client,
}
impl WriterClient {
    pub fn new(
        config: WriterClientConfig,
        timeout: Duration,
    ) -> std::result::Result<Self, ServerError> {
        config.validate()?;
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(Duration::from_secs(5))
            .timeout(timeout);
        if let Some(path) = &config.ca_file {
            builder = builder
                .add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(path)?)?);
        }
        Ok(Self {
            config,
            client: builder.build()?,
        })
    }
    async fn call(&self, operation: Operation) -> Result<Reply> {
        let encoded = serde_json::to_vec(&operation)
            .map_err(|_| Error::invalid("Invalid private source operation."))?;
        if encoded.len() > REQUEST_LIMIT {
            return Err(Error::capacity(
                "Private source operation exceeds its limit.",
            ));
        }
        let token = secret(&self.config.token_file).await?;
        let mut response = self
            .client
            .post(&self.config.endpoint)
            .header(header::AUTHORIZATION, token)
            .header(header::CONTENT_TYPE, "application/json")
            .body(encoded)
            .send()
            .await
            .map_err(|_| unavailable())?;
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|n| n > RESPONSE_LIMIT as u64)
        {
            return Err(unavailable());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| unavailable())? {
            if bytes
                .len()
                .checked_add(chunk.len())
                .is_none_or(|n| n > RESPONSE_LIMIT)
            {
                return Err(unavailable());
            }
            bytes.extend_from_slice(&chunk);
        }
        let reply: Reply = serde_json::from_slice(&bytes).map_err(|_| unavailable())?;
        match reply {
            Reply::Failure { error } => Err(error),
            reply => Ok(reply),
        }
    }
}
#[async_trait]
impl AcquisitionDelegate for WriterClient {
    async fn wikipedia_request(&self, title: Option<String>, page_id: Option<u64>) -> Result<()> {
        match self
            .call(Operation::WikipediaRequest { title, page_id })
            .await?
        {
            Reply::Complete => Ok(()),
            _ => Err(unavailable()),
        }
    }
    async fn wikipedia_search(&self, query: String, limit: usize) -> Result<serde_json::Value> {
        match self
            .call(Operation::WikipediaSearch { query, limit })
            .await?
        {
            Reply::WikipediaSearch { result } => Ok(result),
            _ => Err(unavailable()),
        }
    }

    async fn acquire(&self, source: Acquisition) -> Result<Capture> {
        match self.call(Operation::Acquire { source }).await? {
            Reply::Capture { capture } => Ok(capture),
            _ => Err(unavailable()),
        }
    }
    async fn effect(&self, effect: WriterEffect) -> Result<()> {
        match self.call(Operation::Effect { effect }).await? {
            Reply::Complete => Ok(()),
            _ => Err(unavailable()),
        }
    }
    async fn source_status(&self, source: SourceStatus) -> Result<serde_json::Value> {
        match self.call(Operation::SourceStatus { source }).await? {
            Reply::SourceStatus { status } => Ok(status),
            _ => Err(unavailable()),
        }
    }
    async fn attribution_status(&self) -> Result<serde_json::Value> {
        match self.call(Operation::AttributionStatus).await? {
            Reply::AttributionStatus { status } => Ok(status),
            _ => Err(unavailable()),
        }
    }
    async fn rfc_snapshot(&self) -> Result<String> {
        match self.call(Operation::RfcSnapshot).await? {
            Reply::Snapshot { id } if devres_domain::valid_content_id(&id) => Ok(id),
            _ => Err(unavailable()),
        }
    }
}

struct RpcState {
    coordinator: Arc<dyn AcquisitionDelegate>,
    authenticator: PodAuthenticator,
    config: WriterListenerConfig,
    context: EndpointContext,
}
pub struct WriterEndpoint {
    pub config: WriterListenerConfig,
    pub coordinator: Arc<dyn AcquisitionDelegate>,
}
impl Endpoint for WriterEndpoint {
    fn id(&self) -> &str {
        "writer"
    }
    fn bindings(&self) -> Vec<Binding> {
        vec![Binding {
            network: Network::Tcp,
            address: self.config.bind,
        }]
    }
    async fn bind(
        self,
        context: EndpointContext,
    ) -> std::result::Result<BoundEndpoint, ServerError> {
        if self.config.allowed_clients.is_empty() || self.config.allowed_clients.len() > 128 {
            return Err("writer requires bounded explicit clients".into());
        }
        let authenticator = PodAuthenticator::new(self.config.auth.clone())?;
        let (certificates, key) =
            crate::edge_mtls::server_identity(&self.config.certificate, &self.config.private_key)
                .await?;
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(certificates, key)?;
        tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let listener = tokio::net::TcpListener::bind(self.config.bind).await?;
        let address = listener.local_addr()?;
        let state = Arc::new(RpcState {
            coordinator: self.coordinator,
            authenticator,
            config: self.config,
            context: context.clone(),
        });
        let app = Router::new()
            .route("/v1/acquire", post(acquire))
            .layer(DefaultBodyLimit::max(REQUEST_LIMIT))
            .with_state(state);
        Ok(BoundEndpoint {
            id: "writer".into(),
            addresses: vec![address],
            run: async move {
                crate::http::serve_bounded(
                    listener,
                    app,
                    context,
                    Some(TlsAcceptor::from(Arc::new(tls))),
                )
                .await
            }
            .boxed(),
        })
    }
}
async fn acquire(State(state): State<Arc<RpcState>>, request: Request) -> Response {
    if state.context.shutdown.is_cancelled() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let Ok(_permit) = state.context.requests.clone().try_acquire_owned() else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    let (operation, body_permit) = match tokio::time::timeout(
        Duration::from_secs(state.context.limits.io_timeout_secs),
        authorize_operation(&state, request),
    )
    .await
    {
        Ok(Ok(operation)) => operation,
        Ok(Err(status)) => return status.into_response(),
        Err(_) => return StatusCode::REQUEST_TIMEOUT.into_response(),
    };
    let work = futures::stream::once(async move {
        // The acquisition future belongs to this response body. A disconnected
        // client drops it, including provider permits and uncommitted publication.
        let reply = tokio::select! {
            biased;
            _=state.context.shutdown.cancelled()=>Reply::Failure {error:unavailable()},
            result=tokio::time::timeout(Duration::from_secs(state.context.limits.search_timeout_secs),async {
                match operation {Operation::WikipediaRequest{title,page_id}=>state.coordinator.wikipedia_request(title,page_id).await.map(|()|Reply::Complete),Operation::WikipediaSearch{query,limit}=>state.coordinator.wikipedia_search(query,limit).await.map(|result|Reply::WikipediaSearch{result}),Operation::Acquire {source}=>state.coordinator.acquire(source).await.map(|capture|Reply::Capture {capture}),Operation::Effect {effect}=>state.coordinator.effect(effect).await.map(|()|Reply::Complete),Operation::RfcSnapshot=>state.coordinator.rfc_snapshot().await.map(|id|Reply::Snapshot {id}),Operation::AttributionStatus=>state.coordinator.attribution_status().await.map(|status|Reply::AttributionStatus {status}),Operation::SourceStatus {source}=>state.coordinator.source_status(source).await.map(|status|Reply::SourceStatus {status})}
            })=>match result {Ok(Ok(reply))=>reply,Ok(Err(error))=>Reply::Failure {error},Err(_)=>Reply::Failure {error:unavailable()}}
        };
        let mut bytes = serde_json::to_vec(&reply).unwrap_or_default();
        if bytes.is_empty() || bytes.len() > RESPONSE_LIMIT {
            bytes = serde_json::to_vec(&Reply::Failure {
                error: Error::capacity("Private source result exceeds its limit."),
            })
            .unwrap_or_default();
        }
        // Retain shared request admission until body completion/cancellation.
        drop(body_permit);
        drop(_permit);
        Ok::<Bytes, std::convert::Infallible>(Bytes::from(bytes))
    });
    // Flush headers promptly even while acquisition is pending. JSON permits
    // this initial whitespace; the subsequent stream owns the actual operation.
    use futures::StreamExt;
    let body = Body::from_stream(
        futures::stream::once(async {
            Ok::<Bytes, std::convert::Infallible>(Bytes::from_static(b" "))
        })
        .chain(work),
    );
    (
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::CONTENT_TYPE, "application/json"),
        ],
        body,
    )
        .into_response()
}

async fn authorize_operation(
    state: &RpcState,
    request: Request,
) -> std::result::Result<(Operation, tokio::sync::OwnedSemaphorePermit), StatusCode> {
    let token = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let identity = state
        .authenticator
        .authenticate(token)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    if !state
        .config
        .allowed_clients
        .iter()
        .any(|p| p.namespace == identity.namespace && p.service_account == identity.service_account)
    {
        return Err(StatusCode::FORBIDDEN);
    }
    let (bytes, permit) = admitted_body(request, state.context.buffers.clone()).await?;
    let operation = serde_json::from_slice(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok((operation, permit))
}

async fn admitted_body(
    request: Request,
    buffers: Arc<tokio::sync::Semaphore>,
) -> std::result::Result<(Bytes, tokio::sync::OwnedSemaphorePermit), StatusCode> {
    let declared = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .map(|value| {
            value
                .to_str()
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
                .ok_or(StatusCode::BAD_REQUEST)
        })
        .transpose()?;
    if let Some(length) = declared {
        if length > REQUEST_LIMIT {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        let permit = buffers
            .try_acquire_many_owned(length as u32)
            .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
        let bytes = to_bytes(request.into_body(), length)
            .await
            .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;
        return Ok((bytes, permit));
    }
    // Chunked input reserves actual bytes before retaining each chunk. Merging
    // permits from this same semaphore keeps bookkeeping independent of chunk count.
    use futures::StreamExt;
    let mut permit = buffers
        .clone()
        .try_acquire_many_owned(0)
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
    let mut stream = request.into_body().into_data_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| StatusCode::BAD_REQUEST)?;
        if bytes
            .len()
            .checked_add(chunk.len())
            .is_none_or(|length| length > REQUEST_LIMIT)
        {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        let chunk_permit = buffers
            .clone()
            .try_acquire_many_owned(chunk.len() as u32)
            .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
        permit.merge(chunk_permit);
        bytes.extend_from_slice(&chunk);
    }
    Ok((Bytes::from(bytes), permit))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeRole {
    Serve,
    Collect,
}
/// An old CONFIG invocation now explicitly aliases serving only; combined mode is gone.
pub fn runtime_arguments(
    mut args: Vec<String>,
) -> std::result::Result<(RuntimeRole, Vec<String>), ServerError> {
    let role = match args.first().map(String::as_str) {
        Some("serve") => {
            args.remove(0);
            RuntimeRole::Serve
        }
        Some("collect") => {
            args.remove(0);
            RuntimeRole::Collect
        }
        _ => RuntimeRole::Serve,
    };
    if args.is_empty() {
        return Err("usage: devres-server serve|collect CONFIG.toml".into());
    }
    Ok((role, args))
}

#[cfg(test)]
mod tests;
