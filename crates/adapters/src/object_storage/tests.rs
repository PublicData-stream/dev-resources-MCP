use super::*;
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    response::Response,
};
use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex},
};

#[derive(Default)]
struct Fixture {
    objects: HashMap<String, Vec<u8>>,
    multipart: HashMap<String, BTreeMap<u32, Vec<u8>>>,
    conditional_writes: usize,
    aborted: usize,
    lose_completion: bool,
    redirect: bool,
    redirected: usize,
    credentials_expired: bool,
    sts_requests: usize,
    hosts: Vec<String>,
}

fn response(status: u16, body: impl Into<Body>) -> Response {
    Response::builder()
        .status(status)
        .body(body.into())
        .unwrap()
}

async fn handler(State(state): State<Arc<Mutex<Fixture>>>, request: Request) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let query: HashMap<String, String> =
        url::form_urlencoded::parse(request.uri().query().unwrap_or("").as_bytes())
            .into_owned()
            .collect();
    let conditional = request
        .headers()
        .get("if-none-match")
        .is_some_and(|value| value == "*");
    let authorization = request.headers().get("authorization").cloned();
    let host = request
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let body = to_bytes(request.into_body(), 64 * 1024 * 1024)
        .await
        .unwrap();
    let mut state = state.lock().unwrap();
    if let Some(host) = host {
        state.hosts.push(host);
    }
    if path == "/redirected" {
        state.redirected += 1;
        return response(200, "unexpected");
    }
    if state.redirect {
        return Response::builder()
            .status(307)
            .header("location", "/redirected")
            .body(Body::empty())
            .unwrap();
    }
    if path == "/credentials" {
        assert_eq!(authorization.as_ref().unwrap(), "fixture-auth");
        let expiration = if state.credentials_expired {
            "2020-01-01T00:00:00Z"
        } else {
            "2035-01-01T00:00:00Z"
        };
        return response(
            200,
            format!(
                r#"{{"AccessKeyId":"fixture-key","SecretAccessKey":"fixture-secret","Token":"fixture-token","Expiration":"{expiration}"}}"#
            ),
        );
    }
    if path == "/" && method == http::Method::POST {
        state.sts_requests += 1;
        let form: HashMap<String, String> =
            url::form_urlencoded::parse(&body).into_owned().collect();
        assert_eq!(
            form.get("Action").map(String::as_str),
            Some("AssumeRoleWithWebIdentity")
        );
        assert_eq!(
            form.get("WebIdentityToken").map(String::as_str),
            Some("fixture-oidc")
        );
        assert!(
            !authorization
                .as_ref()
                .is_some_and(|header| header.to_str().unwrap().contains("fixture-secret"))
        );
        return response(
            200,
            r#"<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>fixture-key</AccessKeyId><SecretAccessKey>fixture-secret</SecretAccessKey><SessionToken>fixture-token</SessionToken><Expiration>2035-01-01T00:00:00Z</Expiration></Credentials><SubjectFromWebIdentityToken>fixture</SubjectFromWebIdentityToken></AssumeRoleWithWebIdentityResult><ResponseMetadata><RequestId>fixture</RequestId></ResponseMetadata></AssumeRoleWithWebIdentityResponse>"#,
        );
    }
    if method == http::Method::HEAD && path.trim_end_matches('/') == "/fixture" {
        return response(200, Body::empty());
    }
    if method == http::Method::GET && query.contains_key("uploads") {
        let entries: String = state
            .multipart
            .keys()
            .map(|key| {
                format!(
                    "<Upload><Key>{}</Key><UploadId>owned-upload</UploadId></Upload>",
                    key.strip_prefix("/fixture/").unwrap()
                )
            })
            .collect();
        return response(
            200,
            format!(
                "<ListMultipartUploadsResult><Bucket>fixture</Bucket><IsTruncated>false</IsTruncated>{entries}</ListMultipartUploadsResult>"
            ),
        );
    }
    if method == http::Method::POST && query.contains_key("uploads") {
        state.multipart.insert(path.clone(), BTreeMap::new());
        return response(
            200,
            "<InitiateMultipartUploadResult><Bucket>fixture</Bucket><Key>key</Key><UploadId>owned-upload</UploadId></InitiateMultipartUploadResult>",
        );
    }
    if query.contains_key("uploadId") {
        if method == http::Method::PUT {
            let part = query["partNumber"].parse().unwrap();
            state
                .multipart
                .get_mut(&path)
                .unwrap()
                .insert(part, body.to_vec());
            return Response::builder()
                .status(200)
                .header("etag", format!("part-{part}"))
                .body(Body::empty())
                .unwrap();
        }
        if method == http::Method::DELETE {
            state.multipart.remove(&path);
            state.aborted += 1;
            return response(204, Body::empty());
        }
        if method == http::Method::POST {
            assert!(conditional);
            state.conditional_writes += 1;
            if state.objects.contains_key(&path) {
                return response(412, "<Error><Code>PreconditionFailed</Code></Error>");
            }
            let Some(parts) = state.multipart.remove(&path) else {
                return response(404, "<Error><Code>NoSuchUpload</Code></Error>");
            };
            state
                .objects
                .insert(path, parts.into_values().flatten().collect());
            if state.lose_completion {
                state.lose_completion = false;
                return response(503, "<Error><Code>ServiceUnavailable</Code></Error>");
            }
            return response(
                200,
                "<CompleteMultipartUploadResult><Location>fixture</Location><Bucket>fixture</Bucket><Key>key</Key><ETag>complete</ETag></CompleteMultipartUploadResult>",
            );
        }
    }
    if method == http::Method::PUT {
        assert!(conditional);
        state.conditional_writes += 1;
        if state.objects.contains_key(&path) {
            return response(412, "<Error><Code>PreconditionFailed</Code></Error>");
        }
        state.objects.insert(path, body.to_vec());
        return response(200, Body::empty());
    }
    if let Some(bytes) = state.objects.get(&path) {
        return Response::builder()
            .status(200)
            .header("content-length", bytes.len())
            .body(if method == http::Method::HEAD {
                Body::empty()
            } else {
                Body::from(bytes.clone())
            })
            .unwrap();
    }
    response(404, "<Error><Code>NoSuchKey</Code></Error>")
}

struct Server {
    endpoint: String,
    state: Arc<Mutex<Fixture>>,
    task: tokio::task::JoinHandle<()>,
    _directory: tempfile::TempDir,
    config: S3Config,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Server {
    async fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let access = directory.path().join("access");
        let secret = directory.path().join("secret");
        std::fs::write(&access, "fixture-key\n").unwrap();
        std::fs::write(&secret, "fixture-secret\n").unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(Fixture::default()));
        let router = Router::new().fallback(handler).with_state(state.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let config = S3Config {
            endpoint: endpoint.clone(),
            bucket: "fixture".into(),
            region: "us-east-1".into(),
            prefix: "namespace".into(),
            path_style: true,
            allow_http: true,
            ca_file: None,
            cache_max_bytes: 64 * 1024 * 1024,
            credentials: S3Credentials::Files {
                access_key_file: access,
                secret_key_file: secret,
                session_token_file: None,
            },
        };
        Self {
            endpoint,
            state,
            task,
            _directory: directory,
            config,
        }
    }
    async fn archive(&self) -> S3Archive {
        S3Archive::new(self.config.clone()).await.unwrap()
    }
}

#[tokio::test]
async fn immutable_duplicate_conflict_streamed_read_and_bounds() {
    let server = Server::new().await;
    let archive = server.archive().await;
    archive.health().await.unwrap();
    archive.put_bytes_immutable("blob", b"first").await.unwrap();
    archive.put_bytes_immutable("blob", b"first").await.unwrap();
    assert_eq!(
        archive
            .put_bytes_immutable("blob", b"second")
            .await
            .unwrap_err()
            .code,
        "integrity"
    );
    assert_eq!(archive.get_bytes("blob", 5).await.unwrap(), b"first");
    assert_eq!(
        archive.get_bytes("blob", 4).await.unwrap_err().code,
        "capacity"
    );
    let path = server._directory.path().join("download");
    let cancel = CancellationToken::new();
    assert_eq!(
        archive
            .get_to_file("blob", &path, 5, &cancel)
            .await
            .unwrap(),
        (crate::integrity::hash(b"first"), 5)
    );
    assert_eq!(std::fs::read(path).unwrap(), b"first");
    assert_eq!(server.state.lock().unwrap().conditional_writes, 3);
}

#[tokio::test]
async fn multipart_completion_ambiguity_reconciles_exact_content() {
    let server = Server::new().await;
    server.state.lock().unwrap().lose_completion = true;
    let archive = server.archive().await;
    let bytes = vec![0x5a_u8; 16 * 1024 * 1024 + 17];
    let path = server._directory.path().join("source");
    std::fs::write(&path, &bytes).unwrap();
    archive
        .put_file_immutable(
            "large",
            &path,
            &crate::integrity::hash(&bytes),
            bytes.len() as u64,
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(
        server.state.lock().unwrap().objects["/fixture/namespace/large"],
        bytes
    );
}

#[tokio::test]
async fn multipart_recovery_aborts_only_the_exact_journaled_key() {
    let server = Server::new().await;
    {
        let mut state = server.state.lock().unwrap();
        state
            .multipart
            .insert("/fixture/namespace/journaled".into(), BTreeMap::new());
        state
            .multipart
            .insert("/fixture/namespace/journaled-other".into(), BTreeMap::new());
    }
    server
        .archive()
        .await
        .abort_incomplete("journaled")
        .await
        .unwrap();
    let state = server.state.lock().unwrap();
    assert_eq!(state.aborted, 1);
    assert!(!state.multipart.contains_key("/fixture/namespace/journaled"));
    assert!(
        state
            .multipart
            .contains_key("/fixture/namespace/journaled-other")
    );
}

#[tokio::test]
async fn wrong_source_digest_never_uploads_and_remote_verification_checks_bytes() {
    let server = Server::new().await;
    let archive = server.archive().await;
    let path = server._directory.path().join("wrong-source");
    std::fs::write(&path, b"source").unwrap();
    assert_eq!(
        archive
            .put_file_immutable(
                "wrong",
                &path,
                &crate::integrity::hash(b"other!"),
                6,
                &CancellationToken::new()
            )
            .await
            .unwrap_err()
            .code,
        "integrity"
    );
    assert!(server.state.lock().unwrap().objects.is_empty());
    archive
        .put_bytes_immutable("valid", b"retained")
        .await
        .unwrap();
    archive
        .verify_object(
            "valid",
            &crate::integrity::hash(b"retained"),
            8,
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(
        archive
            .verify_object(
                "valid",
                &crate::integrity::hash(b"changed!"),
                8,
                &CancellationToken::new()
            )
            .await
            .unwrap_err()
            .code,
        "integrity"
    );
}

#[tokio::test]
async fn cancellation_and_redirects_do_not_publish_or_follow() {
    let server = Server::new().await;
    let archive = server.archive().await;
    let cancel = CancellationToken::new();
    cancel.cancel();
    assert!(
        archive
            .get_bytes_with_cancel("missing", 100, &cancel)
            .await
            .is_err()
    );
    assert!(
        archive
            .put_bytes_immutable_with_cancel("canceled", b"body", &cancel)
            .await
            .is_err()
    );
    assert_eq!(server.state.lock().unwrap().conditional_writes, 0);
    let path = server._directory.path().join("canceled");
    assert!(
        archive
            .get_to_file("missing", &path, 100, &cancel)
            .await
            .is_err()
    );
    assert!(!path.exists());
    server.state.lock().unwrap().redirect = true;
    assert!(archive.head("anything").await.is_err());
    assert_eq!(server.state.lock().unwrap().redirected, 0);
}

#[tokio::test]
async fn control_deadlines_stop_stalled_operations() {
    let server = Server::new().await;
    let archive = server.archive().await;
    let result = archive
        .run_for(
            &CancellationToken::new(),
            Duration::from_millis(10),
            std::future::pending::<Result<()>>(),
        )
        .await;
    assert_eq!(result.unwrap_err().code, "capacity");
}

#[tokio::test]
async fn explicit_container_identity_reloads_and_rejects_expiry() {
    let server = Server::new().await;
    let token = server._directory.path().join("container-token");
    std::fs::write(&token, "fixture-auth").unwrap();
    let provider = ExplicitCredentials {
        source: S3Credentials::Container {
            endpoint: format!("{}/credentials", server.endpoint),
            authorization_token_file: Some(token),
            allow_http: true,
            ca_file: None,
        },
        region: "us-east-1".into(),
        identity_client: Some(http_client(None).unwrap()),
    };
    assert_eq!(
        provider.load().await.unwrap().access_key_id(),
        "fixture-key"
    );
    server.state.lock().unwrap().credentials_expired = true;
    assert!(provider.load().await.is_err());
}

#[tokio::test]
async fn explicit_oidc_identity_uses_only_configured_sts() {
    let server = Server::new().await;
    let token = server._directory.path().join("oidc-token");
    std::fs::write(&token, "fixture-oidc\n").unwrap();
    let provider = ExplicitCredentials {
        source: S3Credentials::Oidc {
            token_file: token,
            role_arn: "arn:aws:iam::123456789012:role/fixture".into(),
            session_name: "fixture-session".into(),
            sts_endpoint: server.endpoint.clone(),
            allow_http: true,
            ca_file: None,
        },
        region: "us-east-1".into(),
        identity_client: Some(http_client(None).unwrap()),
    };
    assert_eq!(
        provider.load().await.unwrap().access_key_id(),
        "fixture-key"
    );
    assert_eq!(server.state.lock().unwrap().sts_requests, 1);
}

#[tokio::test]
async fn virtual_host_requests_keep_custom_port_and_reject_other_origins() {
    let server = Server::new().await;
    let address: url::Url = server.endpoint.parse().unwrap();
    let port = address.port().unwrap();
    let mut config = server.config.clone();
    config.endpoint = format!("http://storage.fixture:{port}");
    config.path_style = false;
    let destination = storage_destination(&config).unwrap();
    assert_eq!(destination.host_str(), Some("fixture.storage.fixture"));
    assert_eq!(destination.port(), Some(port));
    let mut archive = S3Archive::new(config).await.unwrap();
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .resolve(
            "fixture.storage.fixture",
            format!("127.0.0.1:{port}").parse().unwrap(),
        )
        .build()
        .unwrap();
    archive.client = aws_sdk_s3::Client::from_conf(
        archive
            .client
            .config()
            .to_builder()
            .http_client(sdk_http(client.clone(), &destination))
            .build(),
    );
    // A missing key is sufficient to prove the generated SDK request reached
    // exactly the selected bucket host through the guarded connector.
    assert!(archive.head("missing").await.unwrap().is_none());
    assert_eq!(
        server.state.lock().unwrap().hosts.last().unwrap(),
        &format!("fixture.storage.fixture:{port}")
    );
    let connector = Connector {
        client,
        origin: destination.origin(),
    };
    let request = http::Request::builder()
        .uri(format!("http://storage.fixture:{port}/"))
        .body(SdkBody::empty())
        .unwrap();
    assert!(
        connector
            .call(HttpRequest::try_from(request).unwrap())
            .await
            .is_err()
    );
}

#[test]
fn rejects_unsafe_keys_urls_and_ambiguous_credentials() {
    for key in ["", "/a", "../a", "a/../b", "a//b", "a\\b", "a\nb"] {
        assert!(!valid_key(key));
    }
    assert!(valid_key("blake3/0123"));
    for url in [
        "http://store.example",
        "https://name:secret@store.example",
        "https://store.example?token=secret",
        "https://store.example/path",
        "https://store.example#fragment",
    ] {
        assert!(endpoint_url(url, false, false).is_err());
    }
    assert!(endpoint_url("https://store.example", false, false).is_ok());
    assert!(endpoint_url("http://127.0.0.1:9000", true, false).is_ok());
    let parsed = serde_json::from_value::<S3Credentials>(
        serde_json::json!({"mode":"files","access_key_file":"/tmp/a","secret_key_file":"/tmp/b","endpoint":"http://unexpected"}),
    );
    assert!(parsed.is_err());
}

#[tokio::test]
#[ignore = "requires disposable RustFS; run scripts/test-s3.sh"]
async fn s3_rustfs_conditional_and_streamed_multipart_capabilities() {
    let path =
        std::env::var("DEVRES_TEST_S3_CONFIG").expect("disposable S3 configuration required");
    let mut config: S3Config = toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    config.prefix.push_str("/transport-capabilities");
    let archive = S3Archive::new(config).await.unwrap();
    archive.health().await.unwrap();
    archive
        .put_bytes_immutable("conditional", b"retained")
        .await
        .unwrap();
    let rejected = archive
        .client
        .put_object()
        .bucket(&archive.config.bucket)
        .key(archive.key("conditional").unwrap())
        .if_none_match("*")
        .body(ByteStream::from_static(b"replacement"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(rejected.raw_response().unwrap().status().as_u16(), 412);
    assert_eq!(
        archive.get_bytes("conditional", 32).await.unwrap(),
        b"retained"
    );
    let scratch = tempfile::tempdir_in("/tmp").unwrap();
    let data = vec![93_u8; 16 * 1024 * 1024 + 19];
    let source = scratch.path().join("source");
    let fetched = scratch.path().join("fetched");
    std::fs::write(&source, &data).unwrap();
    let digest = crate::integrity::hash(&data);
    archive
        .put_file_immutable(
            "large",
            &source,
            &digest,
            data.len() as u64,
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    let observed = archive
        .get_to_file(
            "large",
            &fetched,
            data.len() as u64,
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(observed, (digest, data.len() as u64));
    // Two independently owned uploads race for one final immutable name. The
    // second completion must reject instead of replacing the published bytes.
    let key = archive.key("completion-race").unwrap();
    let first = archive
        .client
        .create_multipart_upload()
        .bucket(&archive.config.bucket)
        .key(&key)
        .send()
        .await
        .unwrap();
    let second = archive
        .client
        .create_multipart_upload()
        .bucket(&archive.config.bucket)
        .key(&key)
        .send()
        .await
        .unwrap();
    let first_id = first.upload_id().unwrap();
    let second_id = second.upload_id().unwrap();
    let first_part = archive
        .client
        .upload_part()
        .bucket(&archive.config.bucket)
        .key(&key)
        .upload_id(first_id)
        .part_number(1)
        .body(ByteStream::from_static(b"first"))
        .send()
        .await
        .unwrap();
    let second_part = archive
        .client
        .upload_part()
        .bucket(&archive.config.bucket)
        .key(&key)
        .upload_id(second_id)
        .part_number(1)
        .body(ByteStream::from_static(b"second"))
        .send()
        .await
        .unwrap();
    let parts = |etag: &str| {
        aws_sdk_s3::types::CompletedMultipartUpload::builder()
            .parts(
                aws_sdk_s3::types::CompletedPart::builder()
                    .part_number(1)
                    .e_tag(etag)
                    .build(),
            )
            .build()
    };
    archive
        .client
        .complete_multipart_upload()
        .bucket(&archive.config.bucket)
        .key(&key)
        .upload_id(first_id)
        .if_none_match("*")
        .multipart_upload(parts(first_part.e_tag().unwrap()))
        .send()
        .await
        .unwrap();
    let rejected = archive
        .client
        .complete_multipart_upload()
        .bucket(&archive.config.bucket)
        .key(&key)
        .upload_id(second_id)
        .if_none_match("*")
        .multipart_upload(parts(second_part.e_tag().unwrap()))
        .send()
        .await
        .unwrap_err();
    assert_eq!(rejected.raw_response().unwrap().status().as_u16(), 412);
    let abort = archive
        .client
        .abort_multipart_upload()
        .bucket(&archive.config.bucket)
        .key(&key)
        .upload_id(second_id)
        .send()
        .await;
    assert!(
        abort.is_ok()
            || abort
                .err()
                .unwrap()
                .raw_response()
                .is_some_and(|response| response.status().as_u16() == 404)
    );
    assert_eq!(
        archive.get_bytes("completion-race", 32).await.unwrap(),
        b"first"
    );
}
