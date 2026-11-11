//! Single-send HTML transport. Source admission, accounting and retries belong to callers.
use devres_domain::{Error, Result};
use futures::{Stream, StreamExt};
use http::HeaderMap;
use std::{pin::Pin, time::Duration};

const USER_AGENT: &str =
    "dev-resources-MCP/0.0.0 (+https://github.com/PublicData-stream/dev-resources-MCP)";

#[derive(Clone, Copy)]
pub(crate) enum ProxyPolicy {
    /// Catalog-qualified W3C/Chromium: direct, public-address DNS only.
    Public,
    /// Bulk RFC attribution retains direct egress without adding a new DNS policy.
    Direct,
    /// Foreground RFC retains its existing environment proxy selection.
    Ambient,
}

pub(crate) struct HtmlClient {
    client: wreq::Client,
}

impl HtmlClient {
    pub(crate) fn new(policy: ProxyPolicy) -> Result<Self> {
        Self::builder(policy, true)?
            .build()
            .map(|client| Self { client })
            .map_err(|_| Error::unavailable("HTML HTTP initialization failed."))
    }

    fn builder(policy: ProxyPolicy, https_only: bool) -> Result<wreq::ClientBuilder> {
        // Disable browser headers: changing negotiation could change canonical bytes.
        let profile = wreq_util::Emulation::builder()
            .profile(wreq_util::Profile::Chrome145)
            .platform(wreq_util::Platform::Windows)
            .headers(false)
            .build();
        let roots = wreq::tls::trust::CertStore::builder()
            .set_default_paths()
            .build()
            .map_err(|_| Error::unavailable("HTML TLS roots initialization failed."))?;
        // Emulation overwrites protocol settings; apply all policy constraints after it.
        let mut builder = wreq::Client::builder()
            .emulation(profile)
            .https_only(https_only)
            .retry(wreq::retry::Policy::never())
            .redirect(wreq::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .tls_cert_store(roots)
            .tls_cert_verification(true)
            .tls_verify_hostname(true)
            .user_agent(USER_AGENT);
        match policy {
            ProxyPolicy::Public => {
                builder = builder
                    .no_proxy()
                    .dns_resolver(crate::w3c::network::PublicResolver);
            }
            ProxyPolicy::Direct => builder = builder.no_proxy(),
            ProxyPolicy::Ambient => {}
        }
        Ok(builder)
    }

    #[cfg(test)]
    pub(crate) fn fixture() -> Result<Self> {
        Self::builder(ProxyPolicy::Direct, false)?
            .build()
            .map(|client| Self { client })
            .map_err(|_| Error::unavailable("Fixture HTML initialization failed."))
    }

    pub(crate) async fn send(&self, url: &str, headers: HeaderMap) -> Result<Response> {
        self.client
            .get(url)
            .headers(headers)
            .send()
            .await
            .map(Response::Html)
            .map_err(|_| Error::unavailable("HTML source connection failed."))
    }
}

pub(crate) enum Response {
    Existing(reqwest::Response),
    Html(wreq::Response),
}
impl From<reqwest::Response> for Response {
    fn from(response: reqwest::Response) -> Self {
        Self::Existing(response)
    }
}
impl Response {
    pub(crate) fn status(&self) -> u16 {
        match self {
            Self::Existing(response) => response.status().as_u16(),
            Self::Html(response) => response.status().as_u16(),
        }
    }
    pub(crate) fn headers(&self) -> &HeaderMap {
        match self {
            Self::Existing(response) => response.headers(),
            Self::Html(response) => response.headers(),
        }
    }
    pub(crate) fn content_length(&self) -> Option<u64> {
        match self {
            Self::Existing(response) => response.content_length(),
            Self::Html(response) => response.content_length(),
        }
    }
    pub(crate) fn bytes_stream(
        self,
    ) -> Pin<Box<dyn Stream<Item = std::io::Result<bytes::Bytes>> + Send>> {
        match self {
            Self::Existing(response) => Box::pin(response.bytes_stream().map(|chunk| {
                chunk.map_err(|_| std::io::Error::other("Source body transfer failed."))
            })),
            Self::Html(response) => Box::pin(response.bytes_stream().map(|chunk| {
                chunk.map_err(|_| std::io::Error::other("HTML body transfer failed."))
            })),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    async fn request(socket: &mut tokio::net::TcpStream) -> Vec<u8> {
        let mut request = Vec::new();
        let mut chunk = [0; 1024];
        while !request.windows(4).any(|part| part == b"\r\n\r\n") {
            let count = socket.read(&mut chunk).await.unwrap();
            assert_ne!(count, 0);
            request.extend_from_slice(&chunk[..count]);
            assert!(request.len() < 16384);
        }
        request
    }

    #[tokio::test]
    async fn original_bytes_and_request_negotiation_are_preserved() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/original", listener.local_addr().unwrap());
        let body = b"\x1f\x8b\x00\xff<html>inert<script>fetch('/private')</script></html>";
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let headers = String::from_utf8(request(&mut socket).await)
                .unwrap()
                .to_ascii_lowercase();
            assert!(headers.contains(&format!(
                "user-agent: {}\r\n",
                USER_AGENT.to_ascii_lowercase()
            )));
            assert!(headers.contains("accept: text/html\r\n"));
            assert!(headers.contains("if-none-match: \"original\"\r\n"));
            assert!(!headers.contains("accept-encoding:"));
            assert!(!headers.contains("accept-language:"));
            assert!(!headers.contains("sec-ch-ua"));
            assert!(!headers.contains("cookie:"));
            socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Encoding: gzip\r\nETag: \"original\"\r\nConnection: close\r\n\r\n", body.len()).as_bytes()).await.unwrap();
            socket.write_all(body).await.unwrap();
        });
        let mut headers = HeaderMap::new();
        headers.insert("accept", http::HeaderValue::from_static("text/html"));
        headers.insert(
            "if-none-match",
            http::HeaderValue::from_static("\"original\""),
        );
        let response = HtmlClient::fixture()
            .unwrap()
            .send(&url, headers)
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["etag"], "\"original\"");
        assert_eq!(response.content_length(), Some(body.len() as u64));
        let chunks: Vec<_> = response.bytes_stream().collect().await;
        let actual: Vec<_> = chunks.into_iter().flat_map(|v| v.unwrap()).collect();
        assert_eq!(actual, body);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn redirect_and_transient_status_do_not_make_another_request() {
        for status in [302, 429, 503] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}/initial", listener.local_addr().unwrap());
            let task = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                request(&mut socket).await;
                socket.write_all(format!("HTTP/1.1 {status} Test\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
                drop(socket);
                assert!(
                    tokio::time::timeout(Duration::from_millis(100), listener.accept())
                        .await
                        .is_err()
                );
            });
            let response = HtmlClient::fixture()
                .unwrap()
                .send(&url, HeaderMap::new())
                .await
                .unwrap();
            assert_eq!(response.status(), status);
            task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn connection_failure_is_single_send_and_diagnostic_is_sanitized() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/sensitive-path", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            request(&mut socket).await;
            drop(socket);
            assert!(
                tokio::time::timeout(Duration::from_millis(100), listener.accept())
                    .await
                    .is_err()
            );
        });
        let error = HtmlClient::fixture()
            .unwrap()
            .send(&url, HeaderMap::new())
            .await
            .err()
            .unwrap();
        assert_eq!(error.message, "HTML source connection failed.");
        task.await.unwrap();
    }

    #[tokio::test]
    async fn production_client_rejects_plain_http() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        assert!(
            HtmlClient::new(ProxyPolicy::Direct)
                .unwrap()
                .send(&url, HeaderMap::new())
                .await
                .is_err()
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn public_resolver_rejects_localhost_at_connection_time() {
        use wreq::dns::Resolve;
        assert!(
            crate::w3c::network::PublicResolver
                .resolve("localhost".into())
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn tls_trust_and_hostname_checks_remain_enabled() {
        use std::sync::Arc;
        use tokio_rustls::{TlsAcceptor, rustls};
        let certified = rcgen::generate_simple_self_signed(vec!["fixture.example".into()]).unwrap();
        let certificate = certified.cert.der().clone();
        let key =
            rustls::pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certificate], key.into())
        .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            for _ in 0..3 {
                let (socket, _) = listener.accept().await.unwrap();
                if let Ok(mut stream) = acceptor.accept(socket).await {
                    let mut input = [0; 4096];
                    if stream.read(&mut input).await.is_ok_and(|n| n > 0) {
                        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await.unwrap();
                    }
                }
            }
        });
        let pem = certified.cert.pem();
        for (host, trusted, succeeds) in [
            ("fixture.example", true, true),
            ("fixture.example", false, false),
            ("wrong.example", true, false),
        ] {
            let mut builder = HtmlClient::builder(ProxyPolicy::Direct, true)
                .unwrap()
                .resolve(host, address);
            if trusted {
                let roots = wreq::tls::trust::CertStore::builder()
                    .add_pem_cert(pem.as_bytes())
                    .build()
                    .unwrap();
                builder = builder.tls_cert_store(roots);
            }
            let client = HtmlClient {
                client: builder.build().unwrap(),
            };
            let response = client
                .send(
                    &format!("https://{host}:{}/", address.port()),
                    HeaderMap::new(),
                )
                .await;
            assert_eq!(response.is_ok(), succeeds);
            if let Ok(response) = response {
                assert_eq!(response.status(), 200);
            }
        }
        task.await.unwrap();
    }

    // Run only as a subprocess: environment mutation is isolated from parallel tests.
    #[tokio::test]
    async fn proxy_policy_child() {
        let Ok(case) = std::env::var("DEVRES_HTML_PROXY_CASE") else {
            return;
        };
        let policy = match case.as_str() {
            "ambient" => ProxyPolicy::Ambient,
            "direct" => ProxyPolicy::Direct,
            "public" => ProxyPolicy::Public,
            _ => panic!("invalid fixture case"),
        };
        let url = std::env::var("DEVRES_HTML_PROXY_URL").unwrap();
        let client = HtmlClient::new(policy).unwrap();
        let _ =
            tokio::time::timeout(Duration::from_secs(2), client.send(&url, HeaderMap::new())).await;
    }

    #[tokio::test]
    async fn caller_proxy_policy_and_public_dns_are_enforced_on_connections() {
        for case in ["ambient", "direct", "public"] {
            let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy_url = format!("http://{}", proxy.local_addr().unwrap());
            let host = if case == "public" {
                "localhost"
            } else {
                "127.0.0.1"
            };
            let url = format!("https://{host}:{}/", target.local_addr().unwrap().port());
            let mut command = tokio::process::Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "html_transport::tests::proxy_policy_child",
                    "--nocapture",
                ])
                .env_clear()
                .env("DEVRES_HTML_PROXY_CASE", case)
                .env("DEVRES_HTML_PROXY_URL", url)
                .env("HTTPS_PROXY", proxy_url)
                .env("NO_PROXY", "");
            let child = command.output();
            let proxy_observer = async {
                tokio::time::timeout(Duration::from_millis(800), proxy.accept())
                    .await
                    .is_ok()
            };
            let target_observer = async {
                tokio::time::timeout(Duration::from_millis(800), target.accept())
                    .await
                    .is_ok()
            };
            let (output, reached_proxy, reached_target) =
                tokio::join!(child, proxy_observer, target_observer);
            let output = output.unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(reached_proxy, case == "ambient", "proxy case {case}");
            assert_eq!(reached_target, case == "direct", "target case {case}");
        }
    }
}
