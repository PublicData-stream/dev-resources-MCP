//! Synthetic public-corpus acceptance. Never downloads, extracts or executes crates.
use super::*;
use async_trait::async_trait;
use devres_application::Fetcher;
use devres_domain::{FetchRequest, FetchResponse};
use flate2::{Compression, write::GzEncoder};
use std::{io::Cursor, process::Stdio};

const DEFAULT_TARGET: &str = "x86_64-unknown-linux-gnu";
const OTHER_TARGET: &str = "thumbv8m.main-none-eabi";
const VERSIONS: [&str; 2] = ["1.2.3", "1.2.4"];

#[derive(Default)]
struct NoFetcher(AtomicUsize);
#[async_trait]
impl Fetcher for NoFetcher {
    async fn fetch(&self, _: &FetchRequest, _: Option<&Validators>) -> Result<FetchResponse> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(Error::integrity(
            "Unexpected source request in offline corpus fixture.",
        ))
    }
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut writer = GzEncoder::new(Vec::new(), Compression::default());
    writer.write_all(bytes).unwrap();
    writer.finish().unwrap()
}
fn archive(version: &str, token: &str) -> Vec<u8> {
    let manifest = format!(
        "[package]\nname=\"example\"\nversion=\"{version}\"\nedition=\"2024\"\nreadme=\"README.md\"\nlicense=\"MIT\"\n[lib]\npath=\"src/lib.rs\"\n"
    );
    let source = format!("// Synthetic public source: {token}\npub fn number() -> u32 {{ 1 }}\n");
    let mut tar = tar::Builder::new(Vec::new());
    for (path, bytes) in [
        ("Cargo.toml", manifest.as_bytes()),
        (
            "README.md",
            b"Synthetic transport documentation: \xce\xa9.".as_slice(),
        ),
        (
            "LICENSE",
            b"Synthetic fixture source; MIT licensing declaration.".as_slice(),
        ),
        ("src/lib.rs", source.as_bytes()),
        ("data.bin", b"\0\xff\x08".as_slice()),
        (
            "build.rs",
            b"compile_error!(\"Inspected fixture build scripts must never execute\");".as_slice(),
        ),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, format!("example-{version}/{path}"), bytes)
            .unwrap();
    }
    gzip(&tar.into_inner().unwrap())
}
fn documentation_zip(marker: &str) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (path, method, text) in [
        (
            "renamed_library/index.html".to_owned(),
            zip::CompressionMethod::Deflated,
            format!("<h1>Transport API</h1><p>{marker}</p><script>never_run_script</script>"),
        ),
        (
            format!("{OTHER_TARGET}/renamed_library/index.html"),
            zip::CompressionMethod::Bzip2,
            format!("<h1>Other target</h1><p>{marker}</p>"),
        ),
        (
            "script.js".to_owned(),
            zip::CompressionMethod::Deflated,
            "throw new Error('must never run')".into(),
        ),
    ] {
        writer
            .start_file(
                path,
                zip::write::SimpleFileOptions::default().compression_method(method),
            )
            .unwrap();
        writer.write_all(text.as_bytes()).unwrap();
    }
    writer.finish().unwrap().into_inner()
}
fn platforms(version: &str) -> Vec<u8> {
    format!("<li><a href='/example/{version}/renamed_library/'>{DEFAULT_TARGET}</a></li><li><a href='/example/{version}/{OTHER_TARGET}/renamed_library/'>{OTHER_TARGET}</a></li>").into_bytes()
}
fn rustdoc(version: &str, target: &str, result_type: &str) -> Vec<u8> {
    let mut value: Value =
        serde_json::from_slice(include_bytes!("../tests/fixtures/docsrs/schema-61.json")).unwrap();
    value["crate_version"] = json!(version);
    value["target"]["triple"] = json!(target);
    value["index"]["3"]["inner"]["function"]["sig"]["output"]["primitive"] = json!(result_type);
    gzip(&serde_json::to_vec(&value).unwrap())
}
fn index(archives: &[Vec<u8>; 2]) -> Vec<u8> {
    let mut result = String::new();
    for (position, version) in VERSIONS.iter().enumerate() {
        let row = json!({"name":"example","vers":version,"deps":[{"name":"itoa","req":"^1.0","features":[],"optional":position==1,"default_features":true,"target":null,"kind":"normal"}],"features":{"default":[]},"cksum":digest(&archives[position]),"yanked":false,"rust_version":"1.85"});
        result.push_str(&row.to_string());
        result.push('\n');
    }
    result.into_bytes()
}

fn git(repository: &Path, args: &[&str], input: &[u8]) -> Vec<u8> {
    let mut command = std::process::Command::new("/usr/bin/git");
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Synthetic public fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
        .env("GIT_COMMITTER_NAME", "Synthetic public fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
        .env("GIT_AUTHOR_DATE", "2026-01-01T00:00:00Z")
        .env("GIT_COMMITTER_DATE", "2026-01-01T00:00:00Z")
        .args([
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "protocol.allow=never",
        ])
        .arg("--git-dir")
        .arg(repository)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "Trusted Git fixture construction failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.len() <= 1024 * 1024);
    output.stdout
}
fn oid(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes).unwrap().trim().to_owned()
}
async fn retained_inventory(
    artifacts: &BulkArtifactStore,
    raw: &[u8],
    observed_at: i64,
) -> (String, BulkArtifact) {
    let root = tempfile::tempdir().unwrap();
    let repository = root.path().join("fixture.git");
    git(
        &repository,
        &[
            "init",
            "--bare",
            "--template=",
            repository.to_str().unwrap(),
        ],
        b"",
    );
    let blob = oid(git(&repository, &["hash-object", "-w", "--stdin"], raw));
    let am = oid(git(
        &repository,
        &["mktree"],
        format!("100644 blob {blob}\texample\n").as_bytes(),
    ));
    let ex = oid(git(
        &repository,
        &["mktree"],
        format!("040000 tree {am}\tam\n").as_bytes(),
    ));
    let tree = oid(git(
        &repository,
        &["mktree"],
        format!("040000 tree {ex}\tex\n").as_bytes(),
    ));
    let revision = oid(git(
        &repository,
        &["commit-tree", &tree],
        b"Synthetic public registry epoch\n",
    ));
    git(
        &repository,
        &["update-ref", "refs/heads/master", &revision],
        b"",
    );
    git(
        &repository,
        &["repack", "-a", "-d", "--no-write-bitmap-index"],
        b"",
    );
    let mut files = Vec::new();
    for entry in std::fs::read_dir(repository.join("objects/pack")).unwrap() {
        let entry = entry.unwrap();
        let artifact = artifacts
            .ingest_file(&entry.path(), MAX_ARTIFACT_BYTES, CancellationToken::new())
            .await
            .unwrap();
        files.push(json!({"name":entry.file_name().to_str().unwrap(),"artifact":artifact}));
    }
    let manifest = json!({"version":1,"source_url":"https://github.com/rust-lang/crates.io-index.git","revision":revision,"previous_revision":null,"observed_at":observed_at,"shallow":[],"files":files});
    let artifact = artifacts
        .capture_bytes(
            serde_json::to_vec(&manifest).unwrap(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    (revision, artifact)
}
async fn seed(
    corpus: &CrateCorpus,
    key: &str,
    source: BulkSource,
    media: &str,
    bytes: Vec<u8>,
) -> Artifact {
    let artifact = corpus
        .artifacts
        .capture_bytes(bytes, CancellationToken::new())
        .await
        .unwrap();
    corpus
        .persist_artifact(
            key,
            &source.url().unwrap(),
            media,
            artifact,
            json!({"transport":"synthetic_fixture","synthetic":true}),
            false,
        )
        .await
        .unwrap()
}
fn source(name: &str, version: &str, operation: DocsOperation) -> BulkSource {
    BulkSource::Documentation {
        name: name.into(),
        version: version.into(),
        operation,
    }
}
async fn process_claim(corpus: &CrateCorpus, kind: &str) -> CollectionJob {
    let job = corpus
        .store
        .claim(unix_now(), kind)
        .await
        .unwrap()
        .expect("expected scheduled fixture job");
    let artifact = corpus
        .process_job(&job, CancellationToken::new())
        .await
        .unwrap();
    corpus
        .store
        .finish(&job.key, Some(&artifact), None, i64::MAX)
        .await
        .unwrap();
    job
}

#[test]
fn supported_public_api_fixture_is_qualified_for_comparison() {
    let compressed = rustdoc(VERSIONS[0], DEFAULT_TARGET, "u32");
    let mut raw = Vec::new();
    flate2::read::MultiGzDecoder::new(compressed.as_slice())
        .read_to_end(&mut raw)
        .unwrap();
    let summary = crate_docs::parse_rustdoc_json(
        Cursor::new(raw),
        VERSIONS[0],
        Some(DEFAULT_TARGET),
        &ProcessingBudget::new(CancellationToken::new()),
        |_| Ok(()),
    )
    .unwrap();
    assert!(summary.version_asserted && summary.target_asserted);
    assert_eq!(
        summary.unresolved_references, 0,
        "A complete synthetic public API must qualify for documented version comparison: {summary:?}"
    );
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL; run scripts/test-postgres.sh"]
async fn crate_corpus_captured_inventory_acquisition_research_and_restart() {
    let base = std::env::var("DEVRES_TEST_DATABASE_URL").expect("disposable PostgreSQL required");
    let admin = sqlx::PgPool::connect(&base).await.unwrap();
    let database_name = "devres_crate_pipeline_fixture";
    sqlx::query("CREATE DATABASE devres_crate_pipeline_fixture")
        .execute(&admin)
        .await
        .unwrap();
    let mut database = url::Url::parse(&base).unwrap();
    database.set_path(&format!("/{database_name}"));
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(
        crate::PgBlobStore::connect(database.as_str(), root.path())
            .await
            .unwrap(),
    );
    let fetcher = Arc::new(NoFetcher::default());
    let retrieval = Arc::new(Retrieval::new(store.clone(), fetcher.clone()));
    // Any accidental bulk call is trapped locally, never sent to a real provider.
    let bulk_calls = Arc::new(AtomicUsize::new(0));
    let counted = bulk_calls.clone();
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let router = axum::Router::new().fallback(move || {
        let counted = counted.clone();
        async move {
            counted.fetch_add(1, Ordering::SeqCst);
            axum::http::StatusCode::BAD_GATEWAY
        }
    });
    let sentinel = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let broker = Arc::new(
        BulkBroker::fixture(url::Url::parse(&format!("http://{address}")).unwrap()).unwrap(),
    );
    let config = CrateConfig {
        enabled: false,
        min_free_bytes: 64 * 1024 * 1024,
        max_git_bytes: 64 * 1024 * 1024,
        ..Default::default()
    };
    let corpus = Arc::new(
        CrateCorpus::new(
            store.clone(),
            retrieval.clone(),
            broker.clone(),
            root.path(),
            config.clone(),
        )
        .unwrap(),
    );
    store
        .attach_artifact_budget(corpus.artifact_budget())
        .unwrap();
    let archives = [
        archive(VERSIONS[0], "oldtransporttoken"),
        archive(VERSIONS[1], "newtransporttoken"),
    ];
    let observed_at = unix_now() - 60;
    let (revision, manifest) =
        retained_inventory(&corpus.artifacts, &index(&archives), observed_at).await;
    corpus
        .import_inventory(&manifest.body_hash, CancellationToken::new())
        .await
        .unwrap();
    let before = store.snapshot(None).await.unwrap().unwrap();
    assert_eq!(before.inventory.revision, revision);
    assert_eq!(before.inventory.validated_at, observed_at);
    assert_eq!(before.coverage["versions"], 2);
    assert_eq!(before.coverage["inventory_complete"], true);
    let research = crate::Research::new(retrieval.clone())
        .await
        .unwrap()
        .with_crate_corpus(corpus.clone());
    assert_eq!(
        research
            .call("crate_content_search", json!({"query":"oldtransporttoken"}))
            .await
            .unwrap()["total"],
        0
    );

    let mut archive_ids = Vec::new();
    let mut documentation_ids = Vec::new();
    for (position, version) in VERSIONS.iter().enumerate() {
        let checksum = digest(&archives[position]);
        let captured = seed(
            &corpus,
            &format!("cargo:archive:example:{version}:{checksum}"),
            BulkSource::CrateArchive {
                name: "example".into(),
                version: (*version).into(),
            },
            "application/gzip",
            archives[position].clone(),
        )
        .await;
        assert_eq!(captured.capture.body_hash, checksum);
        archive_ids.push(captured.capture.id);
        seed(
            &corpus,
            &format!("cargo:docs-platforms:example:{version}"),
            source("example", version, DocsOperation::Platforms),
            "text/html",
            platforms(version),
        )
        .await;
        let html = seed(
            &corpus,
            &format!("cargo:docs-html:example:{version}"),
            source("example", version, DocsOperation::Html),
            "application/zip",
            documentation_zip("original hosted transport docs"),
        )
        .await;
        documentation_ids.push(html.capture.id);
        for target in [DEFAULT_TARGET, OTHER_TARGET] {
            seed(
                &corpus,
                &format!("cargo:docs-json:example:{version}:{target}"),
                source(
                    "example",
                    version,
                    DocsOperation::Json {
                        target: target.into(),
                        format: None,
                    },
                ),
                "application/gzip",
                rustdoc(version, target, if position == 0 { "u32" } else { "u64" }),
            )
            .await;
        }
    }
    for _ in VERSIONS {
        process_claim(&corpus, "archive").await;
        process_claim(&corpus, "platforms").await;
    }
    for _ in VERSIONS {
        process_claim(&corpus, "html").await;
    }
    for _ in 0..4 {
        process_claim(&corpus, "json").await;
    }
    let captured = corpus.publish(CancellationToken::new()).await.unwrap();
    assert!(captured.content_sequence > before.content_sequence);
    assert_eq!(
        captured.coverage["processing_cumulative"]["skipped_binary"],
        2
    );
    let versions = research
        .call("crate_versions", json!({"name":"example"}))
        .await
        .unwrap();
    assert_eq!(versions["total"], 2);
    assert_eq!(
        versions["items"][0]["document"]["record"]["version"],
        VERSIONS[1]
    );
    assert_eq!(
        research
            .call("crate_catalog_search", json!({"name":"example"}))
            .await
            .unwrap()["total"],
        2
    );
    assert_eq!(
        research
            .call(
                "crate_dependencies",
                json!({"name":"example","version":VERSIONS[0]})
            )
            .await
            .unwrap()["items"][0]["name"],
        "itoa"
    );
    assert_eq!(
        research
            .call(
                "crate_dependencies",
                json!({"name":"itoa","direction":"reverse"})
            )
            .await
            .unwrap()["total"],
        2
    );
    assert_eq!(research.call("crate_compare",json!({"name":"example","from_version":VERSIONS[0],"to_version":VERSIONS[1],"kind":"metadata"})).await.unwrap()["changed"],true);
    let hits = research
        .call("crate_content_search", json!({"query":"oldtransporttoken"}))
        .await
        .unwrap();
    assert_eq!(hits["total"], 1);
    assert_eq!(
        research
            .call(
                "crate_content_search",
                json!({"query":"oldtransporttoken","snapshot":before.id})
            )
            .await
            .unwrap()["total"],
        0
    );
    for kind in ["manifest", "readme", "license", "source"] {
        let path = match kind {
            "manifest" => "Cargo.toml",
            "readme" => "README.md",
            "license" => "LICENSE",
            _ => "src/lib.rs",
        };
        let document = research
            .call(
                "crate_document_get",
                json!({"name":"example","version":VERSIONS[0],"kind":kind,"path":path}),
            )
            .await
            .unwrap();
        assert!(!document["page"]["text"].as_str().unwrap().is_empty());
    }
    let old_document = research.call("crate_document_get",json!({"name":"example","version":VERSIONS[0],"kind":"rustdoc","path":"renamed_library/index.html","target":DEFAULT_TARGET})).await.unwrap();
    assert!(
        old_document["page"]["text"]
            .as_str()
            .unwrap()
            .contains("original hosted")
    );
    assert!(
        !old_document["page"]["text"]
            .as_str()
            .unwrap()
            .contains("never_run_script")
    );
    let old_uri = old_document["resource_uri"].as_str().unwrap().to_owned();
    let old_resource = research.read_resource(&old_uri).await.unwrap();
    assert_eq!(
        old_resource["contents"][0]["text"],
        old_document["page"]["text"]
    );
    let api = research.call("crate_api_get",json!({"name":"example","version":VERSIONS[0],"target":OTHER_TARGET,"path":"renamed_library::alias"})).await.unwrap();
    assert_eq!(api["item"]["target"], OTHER_TARGET);
    assert!(
        research
            .call(
                "crate_api_search",
                json!({"query":"Compute","target":OTHER_TARGET})
            )
            .await
            .unwrap()["total"]
            .as_u64()
            .unwrap()
            >= 2
    );
    let comparison = research.call("crate_compare",json!({"name":"example","from_version":VERSIONS[0],"to_version":VERSIONS[1],"kind":"api","target":DEFAULT_TARGET})).await.unwrap();
    assert!(
        comparison["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["path"] == "renamed_library::alias" && item["change"] == "changed")
    );
    let text_comparison=research.call("crate_compare",json!({"name":"example","from_version":VERSIONS[0],"to_version":VERSIONS[1],"kind":"text","path":"src/lib.rs"})).await.unwrap();
    assert_eq!(text_comparison["changed"], true);
    assert!(
        text_comparison["before"]["page"]["text"]
            .as_str()
            .unwrap()
            .contains("oldtransporttoken")
    );
    assert!(
        text_comparison["after"]["page"]["text"]
            .as_str()
            .unwrap()
            .contains("newtransporttoken")
    );
    assert_eq!(research.call("crate_compare",json!({"name":"example","from_version":VERSIONS[0],"to_version":VERSIONS[1],"kind":"text"})).await.unwrap_err().code,"unavailable","Binary source gaps prevent whole-release completeness claims.");
    assert_eq!(research.call("crate_compare",json!({"name":"example","from_version":VERSIONS[0],"to_version":VERSIONS[1],"kind":"text","path":"data.bin"})).await.unwrap_err().code,"unavailable","Skipped binary content must not be mistaken for absent text.");
    assert_eq!(
        research
            .call("crate_corpus_status", json!({}))
            .await
            .unwrap()["collection_enabled"],
        false
    );
    let version = store
        .version(&captured.inventory.id, "example", VERSIONS[0])
        .await
        .unwrap()
        .unwrap();
    let listing = research.call("crate_source_list",json!({"name":"example","version":VERSIONS[0],"metadata_capture":version.metadata_capture,"archive_capture":archive_ids[0]})).await.unwrap();
    assert_eq!(listing["checksum_verified"], true);
    assert_eq!(listing["total"], 6);
    for capture in [&archive_ids[0], &documentation_ids[0]] {
        assert_eq!(
            research
                .read_resource(&format!("devres://capture/{capture}"))
                .await
                .unwrap_err()
                .code,
            "invalid_input"
        );
    }
    let source_text = research.call("crate_source_read",json!({"name":"example","version":VERSIONS[0],"path":"src/lib.rs","metadata_capture":version.metadata_capture,"archive_capture":archive_ids[0]})).await.unwrap();
    assert!(
        source_text["page"]["text"]
            .as_str()
            .unwrap()
            .contains("oldtransporttoken")
    );
    assert_eq!(
        research
            .read_resource(source_text["resource_uri"].as_str().unwrap())
            .await
            .unwrap()["contents"][0]["text"],
        source_text["page"]["text"]
    );

    // A documentation rebuild is a new immutable generation. Old snapshots and
    // citations continue to identify their original text and API evidence.
    let updated = seed(
        &corpus,
        &format!("cargo:docs-html:example:{}", VERSIONS[0]),
        source("example", VERSIONS[0], DocsOperation::Html),
        "application/zip",
        documentation_zip("rebuilt hosted transport docs"),
    )
    .await;
    let html_job = CollectionJob {
        key: format!("html:example:{}", VERSIONS[0]),
        kind: "html".into(),
        name: "example".into(),
        version: VERSIONS[0].into(),
        target: String::new(),
        checksum: version.record["cksum"].as_str().unwrap().into(),
        metadata_capture: version.metadata_capture.clone(),
        attempts: 0,
        artifact: None,
    };
    corpus
        .project(&html_job, &updated, "example", CancellationToken::new())
        .await
        .unwrap();
    let rebuilt = corpus.publish(CancellationToken::new()).await.unwrap();
    assert_ne!(rebuilt.id, captured.id);
    let current = research.call("crate_document_get",json!({"name":"example","version":VERSIONS[0],"kind":"rustdoc","path":"renamed_library/index.html","target":DEFAULT_TARGET})).await.unwrap();
    assert!(
        current["page"]["text"]
            .as_str()
            .unwrap()
            .contains("rebuilt hosted")
    );
    let historical = research.call("crate_document_get",json!({"name":"example","version":VERSIONS[0],"kind":"rustdoc","path":"renamed_library/index.html","target":DEFAULT_TARGET,"snapshot":captured.id})).await.unwrap();
    assert_eq!(historical["page"], old_document["page"]);
    assert_eq!(
        research.read_resource(&old_uri).await.unwrap(),
        old_resource
    );
    assert_eq!(fetcher.0.load(Ordering::SeqCst), 0);
    assert_eq!(bulk_calls.load(Ordering::SeqCst), 0);
    drop(research);
    drop(corpus);
    drop(retrieval);
    drop(store);
    let store = Arc::new(
        crate::PgBlobStore::connect(database.as_str(), root.path())
            .await
            .unwrap(),
    );
    let retrieval = Arc::new(Retrieval::new(store.clone(), fetcher.clone()));
    let corpus = Arc::new(
        CrateCorpus::new(
            store.clone(),
            retrieval.clone(),
            broker,
            root.path(),
            config,
        )
        .unwrap(),
    );
    store
        .attach_artifact_budget(corpus.artifact_budget())
        .unwrap();
    corpus.recover_stages().await.unwrap();
    let research = crate::Research::new(retrieval.clone())
        .await
        .unwrap()
        .with_crate_corpus(corpus.clone());
    assert_eq!(
        research.read_resource(&old_uri).await.unwrap(),
        old_resource
    );
    assert_eq!(
        research
            .call(
                "crate_content_search",
                json!({"query":"oldtransporttoken","snapshot":captured.id})
            )
            .await
            .unwrap()["total"],
        1
    );
    corpus
        .import_inventory(&manifest.body_hash, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(
        store
            .latest_inventory()
            .await
            .unwrap()
            .unwrap()
            .validated_at,
        observed_at
    );
    assert_eq!(fetcher.0.load(Ordering::SeqCst), 0);
    assert_eq!(
        bulk_calls.load(Ordering::SeqCst),
        0,
        "Captured replay must never invoke live Git or HTTP."
    );
    drop(research);
    drop(corpus);
    drop(retrieval);
    drop(store);
    sentinel.abort();
    sqlx::query("DROP DATABASE devres_crate_pipeline_fixture WITH (FORCE)")
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}
