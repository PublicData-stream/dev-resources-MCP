//! Native custom WebTransport acceptance client. Never prints tool payloads.
use devres_server::{
    ServerError,
    framing::{FrameReader, write_json},
};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use tokio::{io::AsyncReadExt, sync::Semaphore, time::timeout};
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
    let mut has_whatwg_corpus = false;
    let mut has_w3c_corpus = false;
    let mut has_chromium_corpus = false;
    let mut has_npm_corpus = false;
    let mut has_wikipedia_corpus = false;
    for (id, method, mut params) in [
        (2, "tools/list", json!({})),
        (
            3,
            "tools/call",
            json!({"name":"server.info","arguments":{}}),
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
            let tools = value["result"]["tools"]
                .as_array()
                .ok_or("missing tool list")?;
            let expected: Vec<String> =
                serde_json::from_str(include_str!("../../tests/tool-names.json"))?;
            let actual = tools
                .iter()
                .map(|tool| tool["name"].as_str().ok_or("missing tool name"))
                .collect::<Result<Vec<_>, _>>()?;
            if actual != expected {
                return Err("unexpected public tool inventory".into());
            }
            has_wikipedia_corpus = tools
                .iter()
                .any(|tool| tool["name"] == "wikipedia.corpus_status");
            has_rfc_corpus = value["result"]["tools"]
                .as_array()
                .is_some_and(|tools| tools.iter().any(|tool| tool["name"] == "rfc.corpus_status"));
            has_crate_corpus = value["result"]["tools"].as_array().is_some_and(|tools| {
                tools
                    .iter()
                    .any(|tool| tool["name"] == "packages.crate.corpus_status")
            });
            has_mdn_corpus = value["result"]["tools"].as_array().is_some_and(|tools| {
                [
                    "mdn.search",
                    "mdn.get",
                    "mdn.compat_search",
                    "mdn.compat_get",
                    "mdn.browser_get",
                    "mdn.history",
                    "mdn.snapshots",
                    "mdn.corpus_status",
                ]
                .iter()
                .all(|name| tools.iter().any(|tool| tool["name"] == *name))
            });
            has_whatwg_corpus = value["result"]["tools"].as_array().is_some_and(|tools| {
                [
                    "whatwg.catalog_search",
                    "whatwg.search",
                    "whatwg.get",
                    "whatwg.symbol_search",
                    "whatwg.symbol_get",
                    "whatwg.references",
                    "whatwg.history",
                    "whatwg.snapshots",
                    "whatwg.compare",
                    "whatwg.corpus_status",
                ]
                .iter()
                .all(|name| tools.iter().any(|tool| tool["name"] == *name))
            });
            has_w3c_corpus = value["result"]["tools"].as_array().is_some_and(|tools| {
                [
                    "w3c.catalog_search",
                    "w3c.search",
                    "w3c.get",
                    "w3c.symbol_search",
                    "w3c.symbol_get",
                    "w3c.references",
                    "w3c.history",
                    "w3c.snapshots",
                    "w3c.compare",
                    "w3c.corpus_status",
                ]
                .iter()
                .all(|name| tools.iter().any(|tool| tool["name"] == *name))
            });
            has_chromium_corpus = value["result"]["tools"].as_array().is_some_and(|tools| {
                [
                    "chromium.catalog_search",
                    "chromium.search",
                    "chromium.get",
                    "chromium.symbol_search",
                    "chromium.symbol_get",
                    "chromium.references",
                    "chromium.history",
                    "chromium.snapshots",
                    "chromium.compare",
                    "chromium.corpus_status",
                ]
                .iter()
                .all(|name| tools.iter().any(|tool| tool["name"] == *name))
            });
            has_advisory_corpus = value["result"]["tools"].as_array().is_some_and(|tools| {
                tools
                    .iter()
                    .any(|tool| tool["name"] == "packages.crate.advisory_corpus_status")
            });
            has_npm_corpus = value["result"]["tools"].as_array().is_some_and(|tools| {
                [
                    "packages.npm.metadata",
                    "packages.npm.source_read",
                    "packages.npm.content_search",
                    "packages.npm.contract_get",
                    "packages.npm.audit_lockfile",
                    "packages.npm.corpus_status",
                ]
                .iter()
                .all(|name| tools.iter().any(|tool| tool["name"] == *name))
            });
        }
        if method == "tools/list"
            && !value["result"]["tools"]
                .as_array()
                .is_some_and(|v| v.iter().any(|tool| tool["name"] == "server.info"))
        {
            return Err("server.info missing".into());
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
    let obsolete: Vec<String> =
        serde_json::from_str(include_str!("../../tests/obsolete-package-tool-names.json"))?;
    let rejected_names = obsolete
        .iter()
        .cloned()
        .chain(obsolete.iter().map(|name| name.replacen('.', "_", 1)))
        .chain(
            [
                "server_info",
                "rfc_catalog_search",
                "rfc.catalog.search",
                "packages.crate.api.search",
                "packages.npm.advisory.get",
                "packages.crates.search",
            ]
            .map(str::to_owned),
        );
    for (index, name) in rejected_names.enumerate() {
        let id = 200 + index;
        let mut params = json!({"name":name,"arguments":{}});
        if revision == "2026-07-28" {
            params["_meta"] = metadata(revision);
        }
        let rejected = exchange_response(
            &mut send,
            &mut reader,
            &budget,
            json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":params}),
        )
        .await?;
        if rejected["error"]["code"] != -32602 || rejected["error"]["message"] != "unknown tool" {
            return Err("obsolete or nested tool name was accepted".into());
        }
    }
    if has_rfc_corpus {
        let mut params = json!({"name":"rfc.corpus_status","arguments":{}});
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
        let mut params = json!({"name":"packages.crate.corpus_status","arguments":{}});
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
        let mut params = json!({"name":"packages.crate.advisory_corpus_status","arguments":{}});
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
            if !devres_domain::valid_content_id(&snapshot) {
                return Err("invalid explicit advisory fixture snapshot".into());
            }
            let lockfile = "# devres-smoke-private-comment-4d1a8e7c\nversion = 4\n[[package]]\nname = \"example\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n";
            let mut params = json!({"name":"packages.crate.audit_lockfile","arguments":{"lockfile":lockfile,"advisory_snapshot":&snapshot}});
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
            "mdn.corpus_status",
            json!({}),
        )
        .await?;
        if !status["collection_enabled"].is_boolean() {
            return Err("MDN corpus status missing through WebTransport".into());
        }
        if let Ok(snapshot) = std::env::var("DEVRES_PROBE_MDN_SNAPSHOT") {
            let compatibility = std::env::var("DEVRES_PROBE_MDN_COMPAT_SNAPSHOT")?;
            for id in [&snapshot, &compatibility] {
                if !devres_domain::valid_content_id(id) {
                    return Err("Invalid explicit synthetic MDN snapshot".into());
                }
            }
            let detail=tool_exchange(&mut send,&mut reader,&budget,revision,9,"mdn.get",json!({"slug":"Web/Fixture","snapshot":snapshot,"compatibility_snapshot":compatibility})).await?;
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
                "mdn.search",
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
                "mdn.compat_get",
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
                "mdn.browser_get",
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
                "mdn.get",
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
                "mdn.compat_search",
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
    if has_whatwg_corpus {
        let status = tool_exchange(
            &mut send,
            &mut reader,
            &budget,
            revision,
            30,
            "whatwg.corpus_status",
            json!({}),
        )
        .await?;
        if !status["collection_enabled"].is_boolean() {
            return Err("WHATWG corpus status missing through WebTransport".into());
        }
    }
    if let Ok(snapshot) = std::env::var("DEVRES_PROBE_WHATWG_SNAPSHOT") {
        if !has_whatwg_corpus {
            return Err("WHATWG discovery missing through WebTransport".into());
        }
        if !devres_domain::valid_content_id(&snapshot) {
            return Err("Invalid synthetic WHATWG snapshot".into());
        }
        let detail = tool_exchange(
            &mut send,
            &mut reader,
            &budget,
            revision,
            31,
            "whatwg.get",
            json!({"standard":"fixture","snapshot":snapshot}),
        )
        .await?;
        if detail["selection"]["snapshot"] != snapshot
            || detail["selection"]["coverage"]["synthetic"] != true
            || !detail["selection"]["source_url"]
                .as_str()
                .is_some_and(|s| s.starts_with("https://fixtures.invalid/"))
            || !detail["page"]["text"].as_str().is_some_and(|s| {
                s.contains("Synthetic WHATWG storage fixture")
                    && !s.contains("fixture_hidden_script")
            })
        {
            return Err(
                "Synthetic WHATWG document/provenance mismatch through WebTransport".into(),
            );
        }
        let original = tool_exchange(
            &mut send,
            &mut reader,
            &budget,
            revision,
            32,
            "whatwg.get",
            json!({"standard":"fixture","snapshot":snapshot,"representation":"source"}),
        )
        .await?;
        if !original["page"]["text"].as_str().is_some_and(|s| {
            s.starts_with("<h1 id=fixture>") && s.contains("fixture_hidden_script()")
        }) {
            return Err("Original WHATWG source changed through WebTransport".into());
        }
        let found = tool_exchange(
            &mut send,
            &mut reader,
            &budget,
            revision,
            33,
            "whatwg.search",
            json!({"snapshot":snapshot,"query":"token"}),
        )
        .await?;
        if found["total"] != 1 || found["results"][0]["standard"] != "fixture" {
            return Err("WHATWG snapshot search mismatch through WebTransport".into());
        }
        let symbol=tool_exchange(&mut send,&mut reader,&budget,revision,34,"whatwg.symbol_get",json!({"standard":"fixture","snapshot":snapshot,"kind":"definition","name":"FixtureToken"})).await?;
        if symbol["page"]["text"] != "FixtureToken" {
            return Err("WHATWG symbol mismatch through WebTransport".into());
        }
        for (id, selected) in [(35, &detail), (36, &original), (37, &symbol)] {
            let uri = selected["resource_uri"]
                .as_str()
                .ok_or("Missing immutable WHATWG resource")?;
            if !uri.starts_with(&format!("devres://whatwg/fixture/{snapshot}/")) {
                return Err("WHATWG resource lost snapshot binding".into());
            }
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
            if resource["result"]["contents"][0]["text"] != selected["page"]["text"] {
                return Err("Immutable WHATWG resource changed through WebTransport".into());
            }
        }
    }
    if has_w3c_corpus {
        let status = tool_exchange(
            &mut send,
            &mut reader,
            &budget,
            revision,
            40,
            "w3c.corpus_status",
            json!({}),
        )
        .await?;
        if !status["collection_enabled"].is_boolean() {
            return Err("W3C corpus status missing through WebTransport".into());
        }
    }
    if let Ok(snapshot) = std::env::var("DEVRES_PROBE_W3C_SNAPSHOT") {
        if !has_w3c_corpus {
            return Err("W3C discovery missing through WebTransport".into());
        }
        if !devres_domain::valid_content_id(&snapshot) {
            return Err("Invalid synthetic W3C snapshot".into());
        }
        let detail = tool_exchange(
            &mut send,
            &mut reader,
            &budget,
            revision,
            41,
            "w3c.get",
            json!({"specification":"fixture","snapshot":snapshot}),
        )
        .await?;
        if detail["selection"]["snapshot"] != snapshot
            || detail["selection"]["coverage"]["synthetic"] != true
            || !detail["selection"]["source_url"]
                .as_str()
                .is_some_and(|s| s.starts_with("https://fixtures.invalid/"))
            || !detail["page"]["text"].as_str().is_some_and(|s| {
                s.contains("Synthetic W3C storage fixture") && !s.contains("fixture_hidden_script")
            })
        {
            return Err("Synthetic W3C document/provenance mismatch through WebTransport".into());
        }
        let original = tool_exchange(
            &mut send,
            &mut reader,
            &budget,
            revision,
            42,
            "w3c.get",
            json!({"specification":"fixture","snapshot":snapshot,"representation":"source"}),
        )
        .await?;
        if !original["page"]["text"].as_str().is_some_and(|s| {
            s.starts_with("<h1 id=fixture>") && s.contains("fixture_hidden_script()")
        }) {
            return Err("Original W3C source changed through WebTransport".into());
        }
        let found = tool_exchange(
            &mut send,
            &mut reader,
            &budget,
            revision,
            43,
            "w3c.search",
            json!({"snapshot":snapshot,"query":"token"}),
        )
        .await?;
        if found["total"] != 1 || found["results"][0]["specification"] != "fixture" {
            return Err("W3C snapshot search mismatch through WebTransport".into());
        }
        let symbol=tool_exchange(&mut send,&mut reader,&budget,revision,44,"w3c.symbol_get",json!({"specification":"fixture","snapshot":snapshot,"kind":"definition","name":"FixtureToken"})).await?;
        if symbol["page"]["text"] != "FixtureToken"
            || symbol["source_metadata"]["copyright"] != "Synthetic fixture authors"
            || !symbol["derived_notice"].is_string()
        {
            return Err("W3C symbol mismatch through WebTransport".into());
        }
        for (id, selected) in [(45, &detail), (46, &original), (47, &symbol)] {
            let uri = selected["resource_uri"]
                .as_str()
                .ok_or("Missing immutable W3C resource")?;
            if !uri.starts_with(&format!("devres://w3c/fixture/{snapshot}/")) {
                return Err("W3C resource lost snapshot binding".into());
            }
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
            if resource["result"]["contents"][0]["text"] != selected["page"]["text"]
                || resource["result"]["contents"][0]["_meta"]["source_metadata"]["copyright"]
                    != "Synthetic fixture authors"
            {
                return Err("Immutable W3C resource changed through WebTransport".into());
            }
        }
        let binary = tool_exchange(&mut send, &mut reader, &budget, revision, 48, "w3c.get", json!({"specification":"fixture","snapshot":snapshot,"representation":"bytes","limit":8})).await?;
        if binary["page"]["base64"] != "PGgxIGlkPWY=" {
            return Err("W3C byte page changed through WebTransport".into());
        }
        let uri = format!(
            "{}?limit=8",
            binary["resource_uri"]
                .as_str()
                .ok_or("Missing W3C bytes resource")?
        );
        let mut params = json!({"uri":uri});
        if revision == "2026-07-28" {
            params["_meta"] = metadata(revision);
        }
        let bytes_resource = exchange(
            &mut send,
            &mut reader,
            &budget,
            json!({"jsonrpc":"2.0","id":49,"method":"resources/read","params":params}),
        )
        .await?;
        if bytes_resource["result"]["contents"][0]["blob"] != "PGgxIGlkPWY="
            || bytes_resource["result"]["contents"][0]["_meta"]["source_metadata"]["copyright"]
                != "Synthetic fixture authors"
        {
            return Err("Immutable W3C bytes or notices changed through WebTransport".into());
        }
    }
    if has_npm_corpus {
        let status = tool_exchange(
            &mut send,
            &mut reader,
            &budget,
            revision,
            90,
            "packages.npm.corpus_status",
            json!({}),
        )
        .await?;
        if !status["collection_enabled"].is_boolean() {
            return Err("npm corpus status missing through WebTransport".into());
        }
    }
    if std::env::var("DEVRES_PROBE_NPM_FIXTURE").as_deref() == Ok("1") {
        if !has_npm_corpus {
            return Err("npm discovery missing through WebTransport".into());
        }
        let versions = tool_exchange(
            &mut send,
            &mut reader,
            &budget,
            revision,
            91,
            "packages.npm.versions",
            json!({"name":"npm-fixture"}),
        )
        .await?;
        if versions["total"] != 2 {
            return Err("npm fixture inventory changed through WebTransport".into());
        }
        let snapshot = versions["snapshot"]["id"].clone();
        let document = tool_exchange(
            &mut send,
            &mut reader,
            &budget,
            revision,
            92,
            "packages.npm.document_get",
            json!({"name":"npm-fixture","version":"1.0.0","snapshot":snapshot,"path":"README.md"}),
        )
        .await?;
        if !document["page"]["text"]
            .as_str()
            .is_some_and(|v| v.contains("Synthetic npm storage fixture"))
        {
            return Err("npm source changed through WebTransport".into());
        }
        let mut params = json!({"uri":document["resource_uri"]});
        if revision == "2026-07-28" {
            params["_meta"] = metadata(revision);
        }
        let resource = exchange(
            &mut send,
            &mut reader,
            &budget,
            json!({"jsonrpc":"2.0","id":93,"method":"resources/read","params":params}),
        )
        .await?;
        if resource["result"]["contents"][0]["text"] != document["page"]["text"] {
            return Err("npm resource lost snapshot binding through WebTransport".into());
        }
        let found = tool_exchange(
            &mut send,
            &mut reader,
            &budget,
            revision,
            94,
            "packages.npm.content_search",
            json!({"snapshot":snapshot,"query":"FixtureToken"}),
        )
        .await?;
        if found["total"].as_u64().unwrap_or(0) == 0 {
            return Err("npm content index missing through WebTransport".into());
        }
        let advisory = tool_exchange(
            &mut send,
            &mut reader,
            &budget,
            revision,
            95,
            "packages.npm.advisory_lookup",
            json!({"name":"npm-fixture","version":"1.0.0"}),
        )
        .await?;
        if advisory["total"] != 1 {
            return Err("npm advisory fixture missing through WebTransport".into());
        }
        let lockfile = serde_json::to_string(
            &json!({"lockfileVersion":3,"name":"PRIVATE_NPM_PROBE_MARKER","packages":{"node_modules/npm-fixture":{"version":"1.0.0"}}}),
        )?;
        let audit = tool_exchange(&mut send,&mut reader,&budget,revision,96,"packages.npm.audit_lockfile",json!({"lockfile":lockfile,"lockfile_format":"npm","advisory_snapshot":advisory["snapshot"]["id"],"registry_context":{"default":"npmjs"}})).await?;
        if audit["vulnerability_count"] != 1
            || audit.to_string().contains("PRIVATE_NPM_PROBE_MARKER")
        {
            return Err(
                "npm isolated assessment failed privacy or matching through WebTransport".into(),
            );
        }
    }
    if has_chromium_corpus {
        let status = tool_exchange(
            &mut send,
            &mut reader,
            &budget,
            revision,
            50,
            "chromium.corpus_status",
            json!({}),
        )
        .await?;
        if !status["collection_enabled"].is_boolean() {
            return Err("CHROMIUM corpus status missing through WebTransport".into());
        }
    }
    if let Ok(snapshot) = std::env::var("DEVRES_PROBE_CHROMIUM_SNAPSHOT") {
        if !has_chromium_corpus {
            return Err("CHROMIUM discovery missing through WebTransport".into());
        }
        if !devres_domain::valid_content_id(&snapshot) {
            return Err("Invalid synthetic CHROMIUM snapshot".into());
        }
        let detail = tool_exchange(
            &mut send,
            &mut reader,
            &budget,
            revision,
            51,
            "chromium.get",
            json!({"component":"src","path":"docs/fixture.html","snapshot":snapshot}),
        )
        .await?;
        if detail["selection"]["snapshot"] != snapshot
            || detail["selection"]["coverage"]["synthetic"] != true
            || !detail["selection"]["source_url"]
                .as_str()
                .is_some_and(|s| s.starts_with("https://fixtures.invalid/"))
            || !detail["page"]["text"].as_str().is_some_and(|s| {
                s.contains("Synthetic CHROMIUM storage fixture")
                    && !s.contains("fixture_hidden_script")
            })
        {
            return Err(
                "Synthetic CHROMIUM document/provenance mismatch through WebTransport".into(),
            );
        }
        let original = tool_exchange(
            &mut send,
            &mut reader,
            &budget,
            revision,
            52,
            "chromium.get",
            json!({"component":"src","path":"docs/fixture.html","snapshot":snapshot,"representation":"source"}),
        )
        .await?;
        if !original["page"]["text"].as_str().is_some_and(|s| {
            s.starts_with("<h1 id=fixture>") && s.contains("fixture_hidden_script()")
        }) {
            return Err("Original CHROMIUM source changed through WebTransport".into());
        }
        let found = tool_exchange(
            &mut send,
            &mut reader,
            &budget,
            revision,
            53,
            "chromium.search",
            json!({"snapshot":snapshot,"query":"token"}),
        )
        .await?;
        if found["total"] != 1 || found["results"][0]["component"] != "src" {
            return Err("CHROMIUM snapshot search mismatch through WebTransport".into());
        }
        let symbol=tool_exchange(&mut send,&mut reader,&budget,revision,54,"chromium.symbol_get",json!({"component":"src","path":"docs/fixture.html","snapshot":snapshot,"kind":"definition","name":"FixtureToken"})).await?;
        if symbol["page"]["text"] != "FixtureToken"
            || symbol["source_metadata"]["copyright"] != "Synthetic fixture authors"
            || !symbol["derived_notice"].is_string()
        {
            return Err("CHROMIUM symbol mismatch through WebTransport".into());
        }
        for (id, selected) in [(55, &detail), (56, &original), (57, &symbol)] {
            let uri = selected["resource_uri"]
                .as_str()
                .ok_or("Missing immutable CHROMIUM resource")?;
            if !uri.starts_with(&format!("devres://chromium/src/{snapshot}/")) {
                return Err("CHROMIUM resource lost snapshot binding".into());
            }
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
            if resource["result"]["contents"][0]["text"] != selected["page"]["text"]
                || resource["result"]["contents"][0]["_meta"]["source_metadata"]["copyright"]
                    != "Synthetic fixture authors"
            {
                return Err("Immutable CHROMIUM resource changed through WebTransport".into());
            }
        }
        let binary = tool_exchange(&mut send, &mut reader, &budget, revision, 58, "chromium.get", json!({"component":"src","path":"docs/fixture.html","snapshot":snapshot,"representation":"bytes","limit":8})).await?;
        if binary["page"]["base64"] != "PGgxIGlkPWY=" {
            return Err("CHROMIUM byte page changed through WebTransport".into());
        }
        let uri = format!(
            "{}?limit=8",
            binary["resource_uri"]
                .as_str()
                .ok_or("Missing CHROMIUM bytes resource")?
        );
        let mut params = json!({"uri":uri});
        if revision == "2026-07-28" {
            params["_meta"] = metadata(revision);
        }
        let bytes_resource = exchange(
            &mut send,
            &mut reader,
            &budget,
            json!({"jsonrpc":"2.0","id":59,"method":"resources/read","params":params}),
        )
        .await?;
        if bytes_resource["result"]["contents"][0]["blob"] != "PGgxIGlkPWY="
            || bytes_resource["result"]["contents"][0]["_meta"]["source_metadata"]["copyright"]
                != "Synthetic fixture authors"
        {
            return Err("Immutable CHROMIUM bytes or notices changed through WebTransport".into());
        }
    }
    if has_wikipedia_corpus {
        let status = tool_exchange(
            &mut send,
            &mut reader,
            &budget,
            revision,
            60,
            "wikipedia.corpus_status",
            json!({}),
        )
        .await?;
        if !status["coverage"].is_string() {
            return Err("Wikipedia corpus status missing through WebTransport".into());
        }
    }
    if std::env::var_os("DEVRES_PROBE_WIKIPEDIA_FIXTURE").is_some() {
        if !has_wikipedia_corpus {
            return Err("Wikipedia discovery missing through WebTransport".into());
        }
        let snapshot = "blake3:c5ee72b3887673dbe6e11e14111592a490149a0cfc7e7d4373bb5888183c0358";
        let selection = json!({"page_id":777,"snapshot":snapshot});
        let detail = tool_exchange(
            &mut send,
            &mut reader,
            &budget,
            revision,
            61,
            "wikipedia.get",
            selection.clone(),
        )
        .await?;
        let text = detail["page"]["text"]
            .as_str()
            .ok_or("Wikipedia text missing through WebTransport")?;
        if !text.contains("Synthetic Wikipedia storage fixture")
            || text.contains("fixture_hidden_script")
            || detail["capture"]["license"]["synthetic"] != true
            || !detail["attribution"]["readable_notice"]
                .as_str()
                .is_some_and(|s| s.contains("First-party synthetic acceptance fixture"))
        {
            return Err(
                "Wikipedia synthetic projection or first-party notice changed through WebTransport"
                    .into(),
            );
        }
        let markdown = tool_exchange(
            &mut send,
            &mut reader,
            &budget,
            revision,
            62,
            "wikipedia.get",
            json!({"page_id":777,"snapshot":snapshot,"representation":"markdown"}),
        )
        .await?;
        if !markdown["page"]["text"]
            .as_str()
            .is_some_and(|s| s.contains("E=mc^2") && !s.contains("fixture_hidden_script"))
        {
            return Err("Wikipedia Markdown/math changed through WebTransport".into());
        }
        let source = tool_exchange(
            &mut send,
            &mut reader,
            &budget,
            revision,
            63,
            "wikipedia.get",
            json!({"page_id":777,"snapshot":snapshot,"representation":"wikitext"}),
        )
        .await?;
        if !source["page"]["text"]
            .as_str()
            .is_some_and(|s| s.starts_with("= Synthetic Wikipedia"))
        {
            return Err("Wikipedia wikitext changed through WebTransport".into());
        }
        let found = tool_exchange(
            &mut send,
            &mut reader,
            &budget,
            revision,
            64,
            "wikipedia.rg",
            json!({"snapshot":snapshot,"pattern":"CPU|fixture_opcode"}),
        )
        .await?;
        if !found["items"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
        {
            return Err("Wikipedia regex fixture missing through WebTransport".into());
        }
        let history = tool_exchange(
            &mut send,
            &mut reader,
            &budget,
            revision,
            65,
            "wikipedia.history",
            selection,
        )
        .await?;
        if history["items"].as_array().map(Vec::len) != Some(2) {
            return Err("Wikipedia observed history changed through WebTransport".into());
        }
        let uri = detail["resource_uri"]
            .as_str()
            .ok_or("Wikipedia immutable resource missing")?;
        let mut params = json!({"uri":uri});
        if revision == "2026-07-28" {
            params["_meta"] = metadata(revision);
        }
        let resource = exchange(
            &mut send,
            &mut reader,
            &budget,
            json!({"jsonrpc":"2.0","id":66,"method":"resources/read","params":params}),
        )
        .await?;
        if resource["result"]["contents"][0]["text"] != text {
            return Err("Wikipedia immutable resource changed through WebTransport".into());
        }
        let fetched = tool_exchange(
            &mut send,
            &mut reader,
            &budget,
            revision,
            67,
            "fetch",
            json!({"id":uri}),
        )
        .await?;
        if fetched["contents"][0]["text"] != text {
            return Err("Wikipedia immutable generic fetch changed through WebTransport".into());
        }
        let natural = tool_exchange(
            &mut send,
            &mut reader,
            &budget,
            revision,
            68,
            "fetch",
            json!({"id":"wikipedia:Devres synthetic STEM fixture"}),
        )
        .await?;
        if natural["page"]["text"] != text {
            return Err("Wikipedia title generic fetch changed through WebTransport".into());
        }
        let id = detail["capture"]["id"]
            .as_str()
            .ok_or("Wikipedia capture identity missing")?;
        let mut params =
            json!({"name":"fetch","arguments":{"id":format!("devres://capture/{id}")}});
        if revision == "2026-07-28" {
            params["_meta"] = metadata(revision);
        }
        let rejected = exchange_response(
            &mut send,
            &mut reader,
            &budget,
            json!({"jsonrpc":"2.0","id":69,"method":"tools/call","params":params}),
        )
        .await?;
        if rejected["result"]["isError"] != true {
            return Err("Wikipedia raw capture bypass accepted through WebTransport".into());
        }
    }
    if let Ok(path) = std::env::var("DEVRES_PROBE_COLLECTOR_RECEIPTS") {
        let mut raw = Vec::new();
        tokio::fs::File::open(path)
            .await?
            .take(65537)
            .read_to_end(&mut raw)
            .await?;
        let receipts = collector_receipts(&raw)?;
        for (offset, receipt) in receipts.iter().enumerate() {
            let id = 500 + offset as u64 * 2;
            let detail = tool_exchange(
                &mut send,
                &mut reader,
                &budget,
                revision,
                id,
                &receipt.tool,
                receipt.arguments.clone(),
            )
            .await?;
            if detail["selection"]["snapshot"] != receipt.arguments["snapshot"]
                || !detail["page"]["text"]
                    .as_str()
                    .is_some_and(|text| text.contains(&receipt.expected))
                || !detail["attribution"]["readable_notice"]
                    .as_str()
                    .is_some_and(|notice| !notice.is_empty())
            {
                return Err(
                    "Collector-produced pinned content or attribution changed through WebTransport"
                        .into(),
                );
            }
            let mut params = json!({"uri": receipt.resource});
            if revision == "2026-07-28" {
                params["_meta"] = metadata(revision);
            }
            let resource = exchange(
                &mut send,
                &mut reader,
                &budget,
                json!({"jsonrpc":"2.0","id":id+1,"method":"resources/read","params":params}),
            )
            .await?;
            let contents = resource["result"]["contents"]
                .as_array()
                .ok_or("Collector resource contents missing")?;
            if !contents.iter().skip(1).any(|item| {
                item["text"]
                    .as_str()
                    .is_some_and(|text| !text.trim().is_empty())
            }) || !contents[0]["text"]
                .as_str()
                .is_some_and(|text| text.contains(&receipt.expected))
                || contents[0]["_meta"]["license"].is_null()
            {
                return Err(
                    "Collector resource content or attribution changed through WebTransport".into(),
                );
            }
        }
    }
    connection.close(0_u32.into(), b"probe complete");
    endpoint.close(0_u32.into(), b"probe complete");
    timeout(Duration::from_secs(2), endpoint.wait_idle()).await?;
    println!("WebTransport {revision}: discovery, tool listing, and server identity verified.");
    Ok(())
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CollectorReceipt {
    provider: String,
    tool: String,
    arguments: Value,
    resource: String,
    expected: String,
}
fn collector_receipts(raw: &[u8]) -> Result<Vec<CollectorReceipt>, ServerError> {
    if raw.len() > 65536 {
        return Err("Collector receipts exceed bound".into());
    }
    let receipts: Vec<CollectorReceipt> = serde_json::from_slice(raw)?;
    if receipts.len() != 2
        || !["w3c", "chromium"]
            .iter()
            .all(|provider| receipts.iter().filter(|r| r.provider == *provider).count() == 1)
    {
        return Err("Two distinct collector fixture providers required".into());
    }
    for receipt in &receipts {
        if receipt.tool != format!("{}.get", receipt.provider)
            || !receipt.arguments["snapshot"]
                .as_str()
                .is_some_and(devres_domain::valid_content_id)
            || !receipt
                .resource
                .starts_with(&format!("devres://{}/", receipt.provider))
            || receipt.resource.len() > 8192
            || receipt.expected.is_empty()
            || receipt.expected.len() > 256
        {
            return Err("Invalid capture-fixed collector fixture receipt".into());
        }
    }
    Ok(receipts)
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
    let label = operation_label(&request);
    let value = exchange_response(send, reader, budget, request).await?;
    if let Some(failure) = operation_failure(&label, &value) {
        return Err(failure.into());
    }
    Ok(value)
}

/// Labels come exclusively from protocol constants and the compiled tool inventory.
/// Never copy arguments, resource URIs, upstream messages, or error data to logs.
fn operation_label(request: &Value) -> String {
    match request["method"].as_str() {
        Some("initialize") => "initialize".into(),
        Some("server/discover") => "server/discover".into(),
        Some("tools/list") => "tools/list".into(),
        Some("resources/read") => "resources/read".into(),
        Some("tools/call") => {
            let name = request["params"]["name"].as_str().unwrap_or_default();
            let inventory: Vec<String> =
                serde_json::from_str(include_str!("../../tests/tool-names.json"))
                    .unwrap_or_default();
            if inventory.iter().any(|allowed| allowed == name) {
                format!("tools/call {name}")
            } else {
                "tools/call unlisted-tool".into()
            }
        }
        _ => "unlisted-method".into(),
    }
}
fn operation_failure(label: &str, response: &Value) -> Option<String> {
    if response.get("error").is_some() {
        return Some(match response["error"]["code"].as_i64() {
            Some(code) => format!("MCP operation failed: {label}; JSON-RPC code {code}"),
            None => format!("MCP operation failed: {label}; JSON-RPC error"),
        });
    }
    if response["result"]["isError"] == true {
        let code = match response["result"]["structuredContent"]["code"].as_str() {
            Some("invalid_input") => "invalid_input",
            Some("unavailable") => "unavailable",
            Some("not_found") => "not_found",
            Some("capacity") => "capacity",
            Some("integrity") => "integrity",
            Some("wikipedia_withheld") => "wikipedia_withheld",
            Some("attribution_blocked") => "attribution_blocked",
            Some("cancelled") => "cancelled",
            _ => "tool_error",
        };
        return Some(format!("MCP operation failed: {label}; {code}"));
    }
    None
}

async fn exchange_response(
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
            return Ok(value);
        }
    }
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;
    #[test]
    fn collector_receipts_require_distinct_pinned_provider_selections() {
        let rows = ["w3c", "chromium"].map(|provider| json!({"provider":provider,"tool":format!("{provider}.get"),"arguments":{"snapshot":format!("blake3:{}","1".repeat(64))},"resource":format!("devres://{provider}/fixture"),"expected":"synthetic"}));
        assert!(collector_receipts(&serde_json::to_vec(&rows).unwrap()).is_ok());
        let mut rows = rows;
        rows[0]["arguments"] = json!({});
        assert!(collector_receipts(&serde_json::to_vec(&rows).unwrap()).is_err());
        assert!(collector_receipts(&vec![b' '; 65537]).is_err());
    }
    #[test]
    fn fixed_tool_diagnostics_exclude_request_and_response_payloads() {
        let request = json!({"method":"tools/call","params":{"name":"packages.crate.audit_lockfile","arguments":{"lockfile":"private-inventory-unique"}}});
        let response = json!({"result":{"isError":true,"structuredContent":{"code":"capacity","message":"private-upstream-message-unique","details":{"credential":"private-credential-unique"}}}});
        let message = operation_failure(&operation_label(&request), &response).unwrap();
        assert_eq!(
            message,
            "MCP operation failed: tools/call packages.crate.audit_lockfile; capacity"
        );
        assert!(!message.contains("private-"));
        let unlisted =
            json!({"method":"private-method-unique","params":{"name":"private-tool-unique"}});
        assert_eq!(operation_label(&unlisted), "unlisted-method");
    }
    #[test]
    fn expected_wikipedia_rejection_is_a_raw_response_assertion() {
        let request = json!({"id":69,"method":"tools/call","params":{"name":"fetch","arguments":{"id":"devres://capture/private-resource-unique"}}});
        let rejected = json!({"id":69,"result":{"isError":true,"structuredContent":{"code":"not_found","message":"private-body-unique"}}});
        assert_eq!(
            operation_failure(&operation_label(&request), &rejected).as_deref(),
            Some("MCP operation failed: tools/call fetch; not_found")
        );
        assert_eq!(rejected["result"]["isError"], true);
        assert!(operation_failure("tools/list", &json!({"result":{"tools":[]}})).is_none());
    }
}
