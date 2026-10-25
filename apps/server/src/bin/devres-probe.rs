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
    let mut has_rfc_corpus = false;
    let mut has_crate_corpus = false;
    let mut has_advisory_corpus = false;
    let mut has_mdn_corpus = false;
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
        if method == "tools/list" {
            has_rfc_corpus = value["result"]["tools"]
                .as_array()
                .is_some_and(|tools| tools.iter().any(|tool| tool["name"] == "rfc_corpus_status"));
            has_crate_corpus = value["result"]["tools"].as_array().is_some_and(|tools| {
                tools
                    .iter()
                    .any(|tool| tool["name"] == "crate_corpus_status")
            });
            has_mdn_corpus = value["result"]["tools"].as_array().is_some_and(|tools| {
                [
                    "mdn_search",
                    "mdn_get",
                    "mdn_compat_search",
                    "mdn_compat_get",
                    "mdn_browser_get",
                    "mdn_history",
                    "mdn_snapshots",
                    "mdn_corpus_status",
                ]
                .iter()
                .all(|name| tools.iter().any(|tool| tool["name"] == *name))
            });
            has_advisory_corpus = value["result"]["tools"].as_array().is_some_and(|tools| {
                tools
                    .iter()
                    .any(|tool| tool["name"] == "advisory_corpus_status")
            });
        }
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
    if has_rfc_corpus {
        let mut params = json!({"name":"rfc_corpus_status","arguments":{}});
        if revision == "2026-07-28" {
            params["_meta"] = metadata(revision);
        }
        let result = exchange(
            &mut send,
            &mut reader,
            &budget,
            json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":params}),
        )
        .await?;
        if !result["result"]["structuredContent"]["collection_enabled"].is_boolean() {
            return Err("RFC corpus status was not available through WebTransport".into());
        }
    }
    if has_crate_corpus {
        let mut params = json!({"name":"crate_corpus_status","arguments":{}});
        if revision == "2026-07-28" {
            params["_meta"] = metadata(revision);
        }
        let result = exchange(
            &mut send,
            &mut reader,
            &budget,
            json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":params}),
        )
        .await?;
        if !result["result"]["structuredContent"]["collection_enabled"].is_boolean() {
            return Err("Crate corpus status was not available through WebTransport".into());
        }
    }
    if has_advisory_corpus {
        let mut params = json!({"name":"advisory_corpus_status","arguments":{}});
        if revision == "2026-07-28" {
            params["_meta"] = metadata(revision);
        }
        let result = exchange(
            &mut send,
            &mut reader,
            &budget,
            json!({"jsonrpc":"2.0","id":6,"method":"tools/call","params":params}),
        )
        .await?;
        let status = &result["result"]["structuredContent"];
        if !status["counts"].is_object() {
            return Err("Advisory corpus status was not available through WebTransport".into());
        }
        if let Ok(snapshot) = std::env::var("DEVRES_PROBE_ADVISORY_SNAPSHOT") {
            if snapshot.len() != 64
                || !snapshot
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            {
                return Err("invalid explicit advisory fixture snapshot".into());
            }
            let lockfile = "# devres-smoke-private-comment-4d1a8e7c\nversion = 4\n[[package]]\nname = \"example\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n";
            let mut params = json!({"name":"audit_lockfile","arguments":{"lockfile":lockfile,"advisory_snapshot":&snapshot}});
            if revision == "2026-07-28" {
                params["_meta"] = metadata(revision);
            }
            let result = exchange(
                &mut send,
                &mut reader,
                &budget,
                json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":params}),
            )
            .await?;
            let report = &result["result"]["structuredContent"];
            if report["snapshot"]["coverage"]["synthetic"] != true
                || report["snapshot"]["source_url"]
                    != "https://fixtures.invalid/devres/storage-probe/advisory"
                || report["complete"] != true
                || report["vulnerability_count"] != 1
                || report["snapshot"]["id"] != snapshot
                || report
                    .to_string()
                    .contains("devres-smoke-private-comment-4d1a8e7c")
            {
                return Err("Synthetic advisory assessment failed through WebTransport".into());
            }
        }
    }
    if has_mdn_corpus {
        let status = tool_exchange(
            &mut send,
            &mut reader,
            &budget,
            revision,
            8,
            "mdn_corpus_status",
            json!({}),
        )
        .await?;
        if !status["collection_enabled"].is_boolean() {
            return Err("MDN corpus status missing through WebTransport".into());
        }
        if let Ok(snapshot) = std::env::var("DEVRES_PROBE_MDN_SNAPSHOT") {
            let compatibility = std::env::var("DEVRES_PROBE_MDN_COMPAT_SNAPSHOT")?;
            for id in [&snapshot, &compatibility] {
                if id.len() != 64
                    || !id
                        .bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                {
                    return Err("Invalid explicit synthetic MDN snapshot".into());
                }
            }
            let detail=tool_exchange(&mut send,&mut reader,&budget,revision,9,"mdn_get",json!({"slug":"Web/Fixture","snapshot":snapshot,"compatibility_snapshot":compatibility})).await?;
            if detail["provenance"]["snapshot"] != snapshot
                || detail["provenance"]["coverage"]["synthetic"] != true
                || !detail["source_url"]
                    .as_str()
                    .is_some_and(|s| s.starts_with("https://fixtures.invalid/"))
                || !detail["page"]["text"].as_str().is_some_and(|s| {
                    s.contains("Synthetic MDN storage fixture") && s.contains("fixture_browser")
                })
            {
                return Err("Synthetic MDN document mismatch through WebTransport".into());
            }
            let found = tool_exchange(
                &mut send,
                &mut reader,
                &budget,
                revision,
                10,
                "mdn_search",
                json!({"query":"fetch","snapshot":snapshot}),
            )
            .await?;
            if found["total"] != 1 || found["results"][0]["slug"] != "Web/Fixture" {
                return Err("Synthetic MDN search mismatch through WebTransport".into());
            }
            let compat = tool_exchange(
                &mut send,
                &mut reader,
                &budget,
                revision,
                11,
                "mdn_compat_get",
                json!({"feature":"api.fixtureFetch","snapshot":compatibility}),
            )
            .await?;
            if compat["original"]["fixture_browser"]["version_added"] != "1"
                || compat["resolved"] != compat["original"]
            {
                return Err("Synthetic BCD evidence mismatch through WebTransport".into());
            }
            let browser = tool_exchange(
                &mut send,
                &mut reader,
                &budget,
                revision,
                12,
                "mdn_browser_get",
                json!({"browser":"fixture_browser","snapshot":compatibility}),
            )
            .await?;
            if browser["releases"][0]["version"] != "1" {
                return Err("Synthetic browser release mismatch through WebTransport".into());
            }
            let original = tool_exchange(
                &mut send,
                &mut reader,
                &budget,
                revision,
                13,
                "mdn_get",
                json!({"slug":"Web/Fixture","snapshot":snapshot,"representation":"source"}),
            )
            .await?;
            if !original["page"]["text"]
                .as_str()
                .is_some_and(|s| s.starts_with("---\ntitle: Synthetic MDN"))
            {
                return Err("Original MDN source lost through WebTransport".into());
            }
            let features = tool_exchange(
                &mut send,
                &mut reader,
                &budget,
                revision,
                14,
                "mdn_compat_search",
                json!({"query":"fetch","snapshot":compatibility}),
            )
            .await?;
            if features["total"] != 1 {
                return Err("Synthetic BCD search mismatch through WebTransport".into());
            }
            for (id, selected) in [(15, &detail), (16, &original)] {
                let uri = selected["resource_uri"]
                    .as_str()
                    .ok_or("Missing immutable MDN resource")?;
                let mut params = json!({"uri":uri});
                if revision == "2026-07-28" {
                    params["_meta"] = metadata(revision);
                }
                let resource = exchange(
                    &mut send,
                    &mut reader,
                    &budget,
                    json!({"jsonrpc":"2.0","id":id,"method":"resources/read","params":params}),
                )
                .await?;
                let content = &resource["result"]["contents"][0];
                if content["text"] != selected["page"]["text"]
                    || content["_meta"]["provenance"]["coverage"]["synthetic"] != true
                    || !content["_meta"]["license"].is_object()
                {
                    return Err(
                        "Immutable MDN resource lost content or attribution through WebTransport"
                            .into(),
                    );
                }
            }
        }
    }
    connection.close(0_u32.into(), b"probe complete");
    endpoint.close(0_u32.into(), b"probe complete");
    timeout(Duration::from_secs(2), endpoint.wait_idle()).await?;
    println!("WebTransport {revision}: discovery, tool listing, and server identity verified.");
    Ok(())
}
async fn tool_exchange(
    send: &mut wtransport::SendStream,
    reader: &mut FrameReader<wtransport::RecvStream>,
    budget: &Arc<Semaphore>,
    revision: &str,
    id: u64,
    name: &str,
    arguments: Value,
) -> Result<Value, ServerError> {
    let mut params = json!({"name":name,"arguments":arguments});
    if revision == "2026-07-28" {
        params["_meta"] = metadata(revision);
    }
    let result = exchange(
        send,
        reader,
        budget,
        json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":params}),
    )
    .await?;
    Ok(result["result"]["structuredContent"].clone())
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
