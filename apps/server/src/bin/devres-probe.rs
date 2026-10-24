//! Native custom WebTransport acceptance client. Never prints tool payloads.
use devres_server::{
    ServerError,
    framing::{FrameReader, write_json},
};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use tokio::{sync::Semaphore, time::timeout};
use wtransport::{
    ClientConfig, Endpoint, Identity,
    endpoint::ConnectOptions,
    tls::{Certificate, rustls},
};
const MAX: usize = 8 * 1024 * 1024;

#[tokio::main]
async fn main() -> Result<(), ServerError> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if !matches!(args.len(), 3 | 4 | 6) {
        return Err(
            "usage: devres-probe URL CA_PATH REVISION [ORIGIN] [CLIENT_CERT CLIENT_KEY]".into(),
        );
    }
    let revision = &args[2];
    if !matches!(revision.as_str(), "2026-07-28" | "2025-11-25") {
        return Err("unsupported revision".into());
    }
    let certificate = Certificate::load_pemfile(&args[1]).await?;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls::pki_types::CertificateDer::from(
        certificate.der().to_vec(),
    ))?;
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots);
    let mut tls = if args.len() == 6 {
        let identity = Identity::load_pemfiles(&args[4], &args[5]).await?;
        let chain = identity
            .certificate_chain()
            .as_slice()
            .iter()
            .map(|c| rustls::pki_types::CertificateDer::from(c.der().to_vec()))
            .collect();
        let key = rustls::pki_types::PrivateKeyDer::try_from(
            identity.private_key().secret_der().to_vec(),
        )?;
        builder.with_client_auth_cert(chain, key)?
    } else {
        builder.with_no_client_auth()
    };
    tls.alpn_protocols = vec![wtransport::tls::WEBTRANSPORT_ALPN.to_vec()];
    let endpoint = Endpoint::client(
        ClientConfig::builder()
            .with_bind_default()
            .with_custom_tls(tls)
            .build(),
    )?;
    // The pinned edge validates the draft02 wire marker explicitly; wtransport
    // does not add this negotiation header on its own.
    let mut options =
        ConnectOptions::builder(&args[0]).add_header("sec-webtransport-http3-draft02", "1");
    if let Some(origin) = args.get(3) {
        options = options.add_header("origin", origin);
    }
    let connection = timeout(Duration::from_secs(10), endpoint.connect(options.build())).await??;
    let (mut send, recv) = timeout(Duration::from_secs(10), async {
        Ok::<_, ServerError>(connection.open_bi().await?.await?)
    })
    .await??;
    let budget = Arc::new(Semaphore::new(32 * 1024 * 1024));
    let mut reader = FrameReader::new(
        recv,
        MAX,
        budget.clone(),
        Duration::from_secs(10),
        Duration::from_secs(10),
    );
    let discover = if revision == "2025-11-25" {
        let value = exchange(&mut send, &mut reader, &budget, json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":revision,"capabilities":{},"clientInfo":{"name":"devres-probe","version":"1"}}})).await?;
        write_json(
            &mut send,
            &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            MAX,
            &budget,
            Duration::from_secs(10),
        )
        .await?;
        value
    } else {
        exchange(&mut send, &mut reader, &budget, json!({"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":metadata(revision)}})).await?
    };
    let instructions = discover["result"]["instructions"]
        .as_str()
        .ok_or("missing source instructions")?;
    if !instructions.contains("AGPL-3.0-only") {
        return Err("missing license offer".into());
    }
    for (id, method, mut params) in [
        (2, "tools/list", json!({})),
        (
            3,
            "tools/call",
            json!({"name":"server_info","arguments":{}}),
        ),
    ] {
        if revision == "2026-07-28" {
            params["_meta"] = metadata(revision);
        }
        let value = exchange(
            &mut send,
            &mut reader,
            &budget,
            json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}),
        )
        .await?;
        if method == "tools/list"
            && !value["result"]["tools"]
                .as_array()
                .is_some_and(|v| v.iter().any(|tool| tool["name"] == "server_info"))
        {
            return Err("server_info missing".into());
        }
        if method == "tools/call" {
            let info = &value["result"]["structuredContent"];
            if info["product"] != "dev-resources-MCP" || info["license"] != "AGPL-3.0-only" {
                return Err("server identity mismatch".into());
            }
            let source = info["sourceUrl"].as_str().ok_or("source offer missing")?;
            devres_server::config::SourceOffer::new(source)?;
            if !instructions.contains(source) {
                return Err("source offer mismatch".into());
            }
        }
    }
    connection.close(0_u32.into(), b"probe complete");
    endpoint.close(0_u32.into(), b"probe complete");
    timeout(Duration::from_secs(2), endpoint.wait_idle()).await?;
    println!("WebTransport {revision}: discovery, tool listing, and server identity verified.");
    Ok(())
}
fn metadata(revision: &str) -> Value {
    json!({"io.modelcontextprotocol/protocolVersion":revision,"io.modelcontextprotocol/clientInfo":{"name":"devres-probe","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}})
}
async fn exchange(
    send: &mut wtransport::SendStream,
    reader: &mut FrameReader<wtransport::RecvStream>,
    budget: &Arc<Semaphore>,
    request: Value,
) -> Result<Value, ServerError> {
    let id = request["id"].clone();
    write_json(send, &request, MAX, budget, Duration::from_secs(10)).await?;
    loop {
        let frame = reader.read().await?.ok_or("response stream closed")?;
        let value: Value = serde_json::from_slice(&frame.bytes)?;
        if value["id"] == id {
            if value.get("error").is_some() || value["result"]["isError"] == true {
                return Err("MCP operation failed".into());
            }
            return Ok(value);
        }
    }
}
