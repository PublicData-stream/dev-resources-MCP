//! Synthetic npm evidence only. Fixtures never execute package code or fetch providers.
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD};
use devres_adapters::{
    npm::{NpmPackages, archive_key, source_input_from_uri},
    npm_processing::*,
};
use devres_application::{Cached, Fetcher, Retrieval, Store};
use devres_domain::{
    Capture, Error, FetchRequest, FetchResponse, Result, StoredCapture, Validators,
};
use flate2::{Compression, write::GzEncoder};
use serde_json::{Value, json};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::sync::Mutex;

static SERIAL: Mutex<()> = Mutex::const_new(());

fn archive(members: &[(&str, &[u8])], special: bool) -> Vec<u8> {
    let mut tar = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::fast()));
    for (path, body) in members {
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        if special {
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_link_name("/etc/passwd").unwrap();
        }
        header.set_cksum();
        tar.append_data(&mut header, path, *body).unwrap();
    }
    tar.into_inner().unwrap().finish().unwrap()
}
fn record(bytes: &[u8]) -> Value {
    json!({"name":"@fixture/package","version":"1.0.0","dist":{"tarball":"https://registry.npmjs.org/@fixture/package/-/package-1.0.0.tgz","integrity":format!("sha512-{}",STANDARD.encode(Sha512::digest(bytes)))}})
}
fn fixture_archive() -> Vec<u8> {
    archive(&[
        ("package/package.json", br##"{"name":"@fixture/package","version":"1.0.0","scripts":{"install":"DO_NOT_EXECUTE"},"exports":{".":{"node":"./node.js","default":"./index.js"},"./features/*":"./lib/*.js","./private/*":null},"imports":{"#external":"external-package","#local":"./local.js"},"types":"./index.d.ts"}"##),
        ("package/index.js", "export const text = '한글';\n".as_bytes()),
        ("package/index.d.ts", b"export declare const text: string;\n"),
        ("package/README.md", b"# Fixture\n<script>untrusted()</script>\n"),
        ("package/LICENSE", b"Fixture notice: original author retains rights.\n"),
        ("package/binary", &[0, 159, 255]),
    ], false)
}

#[test]
fn package_names_and_exact_versions_are_not_dependency_ranges() {
    for good in [
        "example",
        "@scope/example",
        "Historical_Name",
        "@scope/package.name",
    ] {
        validate_name(good).unwrap();
    }
    for bad in [
        "",
        "@scope",
        "scope/name",
        "@scope/name/extra",
        "../x",
        "@scope/..",
        "foo%2Fbar",
        "https://evil",
        ".hidden",
        "_hidden",
        "@/x",
    ] {
        assert!(validate_name(bad).is_err(), "{bad}");
    }
    assert_eq!(
        parse_version("v1.2.3-beta.1+build").unwrap().to_string(),
        "1.2.3-beta.1+build"
    );
    assert_eq!(parse_version("=1.2.3").unwrap().to_string(), "1.2.3");
    for bad in [
        "1.2",
        "^1.2.3",
        "1.2.3 || 2",
        " 1.2.3",
        "1.2.3/evil",
        "1.2.3?x",
        "9007199254740992.0.0",
        "1.0.0-9007199254740992",
    ] {
        assert!(parse_version(bad).is_err(), "{bad}");
    }
}

#[test]
fn metadata_identity_duplicate_keys_and_declarations_are_checked() {
    let value = json!({"name":"@fixture/package","versions":{"1.0.0":{"name":"@fixture/package","version":"1.0.0","dependencies":{"alias":"npm:other@^1","git":"git+https://example.invalid/repo"}}},"dist-tags":{"latest":"1.0.0"}});
    let parsed = parse_packument(&serde_json::to_vec(&value).unwrap(), "@fixture/package").unwrap();
    assert_eq!(
        parsed["versions"]["1.0.0"]["dependencies"]["alias"],
        "npm:other@^1"
    );
    assert!(parse_packument(&serde_json::to_vec(&value).unwrap(), "other").is_err());
    assert!(parse_packument(br#"{"name":"x","name":"x","versions":{}}"#, "x").is_err());
    assert!(
        parse_packument(
            br#"{"name":"x","versions":{"1.0.0":{"name":"x","version":"2.0.0"}}}"#,
            "x"
        )
        .is_err()
    );
    let deep = format!("{}0{}", "[".repeat(65), "]".repeat(65));
    assert!(parse_packument(deep.as_bytes(), "x").is_err());
    // Unparseable historical versions are retained metadata rather than deleting
    // otherwise usable published evidence; selected-version tools qualify them.
    assert!(
        parse_packument(
            br#"{"name":"x","versions":{"historical":{"name":"x","version":"historical"}}}"#,
            "x"
        )
        .is_ok()
    );
}

#[test]
fn aggregate_json_budget_spans_nested_containers() {
    let inner = format!("[{}]", vec!["null"; 20_000].join(","));
    let bytes = format!(
        "{{\"name\":\"x\",\"versions\":{{}},\"extra\":[{}]}}",
        vec![inner; 11].join(",")
    );
    assert!(bytes.len() < MAX_METADATA);
    assert_eq!(
        parse_packument(bytes.as_bytes(), "x").unwrap_err().code,
        "capacity"
    );
}

#[test]
fn qualified_unpublish_tombstone_has_empty_observed_inventory() {
    let bytes=br#"{"name":"example","time":{"unpublished":{"time":"2026-10-27T12:00:00.000Z","versions":["1.0.0"]}}}"#;
    let parsed = parse_packument(bytes, "example").unwrap();
    assert_eq!(parsed["versions"], json!({}));
    assert_eq!(parsed["time"]["unpublished"]["versions"][0], "1.0.0");
    for time in ["invalid", "2026-02-30T12:00:00Z", "2026-10-27T99:00:00Z"] {
        let bytes =
            serde_json::to_vec(&json!({"name":"example","time":{"unpublished":{"time":time}}}))
                .unwrap();
        assert!(parse_packument(&bytes, "example").is_err());
    }
    assert!(parse_packument(br#"{"name":"example"}"#, "example").is_err());
}

#[test]
fn sri_prefers_strongest_digest_without_downgrade() {
    let bytes = b"fixture";
    let weak = format!("sha1-{}", STANDARD.encode(Sha1::digest(bytes)));
    let strong = format!("sha512-{}", STANDARD.encode(Sha512::digest(bytes)));
    assert_eq!(
        verify_integrity(
            bytes,
            &json!({"dist":{"integrity":format!("{weak} {strong}")}})
        )
        .unwrap()["algorithm"],
        "sha512"
    );
    let corrupt = format!("sha512-{}", STANDARD.encode([0u8; 64]));
    assert!(verify_integrity(bytes, &json!({"dist":{"integrity":format!("{weak} {corrupt}"),"shasum":hex::encode(Sha1::digest(bytes))}})).is_err());
    assert!(
        verify_integrity(
            bytes,
            &json!({"dist":{"integrity":"sha999-YQ==","shasum":hex::encode(Sha1::digest(bytes))}})
        )
        .is_err()
    );
    assert!(verify_integrity(bytes, &json!({"dist":{"integrity":"sha512-YQ=="}})).is_err());
    assert!(
        verify_integrity(
            bytes,
            &json!({"dist":{"shasum":hex::encode(Sha1::digest(bytes))}})
        )
        .is_ok()
    );
}

fn zip_fixture() -> Vec<u8> {
    use std::io::Write as _;
    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    writer
        .start_file(
            "GHSA-fixture.json",
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored),
        )
        .unwrap();
    writer.write_all(b"{\"inert\":true}").unwrap();
    writer.finish().unwrap().into_inner()
}
fn zip_file(bytes: &[u8]) -> std::fs::File {
    use std::io::{Seek as _, Write as _};
    let mut file = tempfile::tempfile_in("/tmp").unwrap();
    file.write_all(bytes).unwrap();
    file.rewind().unwrap();
    file
}
fn zip64_header(count: u64, record_size: u64) -> Vec<u8> {
    let mut header = vec![0; 56];
    header[..4].copy_from_slice(b"PK\x06\x06");
    header[4..12].copy_from_slice(&record_size.to_le_bytes());
    header[24..32].copy_from_slice(&count.to_le_bytes());
    header[32..40].copy_from_slice(&count.to_le_bytes());
    let mut locator = vec![0; 20];
    locator[..4].copy_from_slice(b"PK\x06\x07");
    locator[16..20].copy_from_slice(&1u32.to_le_bytes());
    let mut footer = vec![0; 22];
    footer[..4].copy_from_slice(b"PK\x05\x06");
    footer[8..10].copy_from_slice(&u16::MAX.to_le_bytes());
    footer[10..12].copy_from_slice(&u16::MAX.to_le_bytes());
    header.extend(locator);
    header.extend(footer);
    header
}
#[test]
fn zip_preflight_rejects_actual_zip64_count_and_extensible_allocations() {
    assert!(open_advisory_zip(zip_file(&zip64_header(1_000_001, 44))).is_err());
    assert!(open_advisory_zip(zip_file(&zip64_header(0, 1024 * 1024 * 1024))).is_err());
    let mut archive = open_advisory_zip(zip_file(&zip_fixture())).unwrap();
    let mut text = String::new();
    std::io::Read::read_to_string(&mut archive.by_index(0).unwrap(), &mut text).unwrap();
    assert_eq!(text, "{\"inert\":true}");
}
#[test]
fn zip_index_guard_prevents_fallback_to_unvalidated_earlier_footer() {
    let mut bytes = zip_fixture();
    let mut bogus = vec![0; 22];
    bogus[..4].copy_from_slice(b"PK\x05\x06");
    bogus[8..10].copy_from_slice(&1u16.to_le_bytes());
    bogus[10..12].copy_from_slice(&1u16.to_le_bytes());
    bogus[12..16].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
    bytes.extend(bogus);
    // The last footer has small, in-range fields, but its CD is malformed.
    // ZIP9 normally recovers by accepting the older embedded archive footer.
    assert!(validate_zip_file(&mut zip_file(&bytes)).is_ok());
    assert!(zip::ZipArchive::new(zip_file(&bytes)).is_ok());
    assert!(open_advisory_zip(zip_file(&bytes)).is_err());
}

#[test]
fn source_contracts_preserve_order_patterns_null_and_external_imports() {
    let bytes = fixture_archive();
    let projected = inspect_package(&bytes, &record(&bytes)).unwrap();
    let contracts = &projected["contracts"];
    assert_eq!(
        contracts["declarations"]["exports"]["./private/*"],
        Value::Null
    );
    assert_eq!(
        contracts["declarations"]["imports"]["#external"],
        "external-package"
    );
    let exports = contracts["ordered"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["key"] == "exports")
        .unwrap();
    let conditional = &exports["value"]["object"][0]["value"]["object"];
    assert_eq!(conditional[0]["key"], "node");
    assert_eq!(conditional[1]["key"], "default");
    assert_eq!(exports["value"]["object"][1]["key"], "./features/*");
    let documents = projected["documents"].as_array().unwrap();
    assert!(documents.iter().any(|doc| doc["kind"] == "declaration"));
    assert!(documents.iter().any(|doc| doc["kind"] == "license"));
    assert!(documents.iter().any(|doc| {
        doc["text"]
            .as_str()
            .is_some_and(|text| text.contains("DO_NOT_EXECUTE"))
    }));
    assert!(
        projected["gaps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|gap| gap["code"] == "binary_document")
    );
}

#[test]
fn member_listing_keeps_binary_and_oversized_files_as_explicit_gaps() {
    let oversized = vec![b'a'; MAX_DOCUMENT + 1];
    let bytes = archive(
        &[
            ("package/oversized.js", &oversized),
            (
                "package/package.json",
                br#"{"name":"@fixture/package","version":"1.0.0"}"#,
            ),
            ("package/ok.js", b"inert()"),
            ("package/binary", &[0xff]),
        ],
        false,
    );
    let projected = inspect_package(&bytes, &record(&bytes)).unwrap();
    assert_eq!(projected["members"].as_array().unwrap().len(), 4);
    assert_eq!(projected["documents"].as_array().unwrap().len(), 2);
    assert!(
        projected["gaps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|gap| gap["path"] == "oversized.js" && gap["code"] == "document_processing_limit")
    );
    assert_eq!(
        read_member(&bytes, &record(&bytes), "ok.js").unwrap()["text"],
        "inert()"
    );
    assert!(read_member(&bytes, &record(&bytes), "oversized.js").is_err());
}

#[test]
fn archives_reject_links_duplicates_bad_roots_identity_and_trailers() {
    for bytes in [
        archive(&[("package/link", b"")], true),
        archive(&[("other/package.json", b"{}")], false),
        archive(
            &[
                ("package/package.json", b"{}"),
                ("package/package.json", b"{}"),
            ],
            false,
        ),
        archive(
            &[(
                "package/package.json",
                br#"{"name":"other","version":"1.0.0"}"#,
            )],
            false,
        ),
    ] {
        assert!(inspect_package(&bytes, &record(&bytes)).is_err());
    }
    let mut truncated = fixture_archive();
    truncated.truncate(truncated.len() - 6);
    assert!(inspect_package(&truncated, &record(&truncated)).is_err());
    let bytes = archive(
        &[(
            "package/package.json",
            br#"{"name":"@fixture/package","version":"1.0.0","exports":{},"exports":{}}"#,
        )],
        false,
    );
    assert!(inspect_package(&bytes, &record(&bytes)).is_err());

    let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::fast()));
    let mut header = tar::Header::new_gnu();
    let path = b"package/../escape";
    header.as_mut_bytes()[..path.len()].copy_from_slice(path);
    header.set_size(0);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append(&header, &b""[..]).unwrap();
    let bytes = builder.into_inner().unwrap().finish().unwrap();
    assert!(inspect_package(&bytes, &record(&bytes)).is_err());
}

#[test]
fn historical_scoped_basename_root_keeps_exact_manifest_identity() {
    let manifest = br#"{"name":"@types/is-number","version":"7.0.5"}"#;
    let bytes = archive(
        &[
            ("is-number/package.json", manifest),
            ("is-number/index.d.ts", b"export = isNumber;\n"),
        ],
        false,
    );
    let mut selected = record(&bytes);
    selected["name"] = json!("@types/is-number");
    selected["version"] = json!("7.0.5");
    let projection = inspect_package(&bytes, &selected).unwrap();
    assert_eq!(projection["members"].as_array().unwrap().len(), 2);
    assert_eq!(
        read_member(&bytes, &selected, "index.d.ts").unwrap()["kind"],
        "declaration"
    );
    let mut wrong_name = selected.clone();
    wrong_name["name"] = json!("@other/is-number");
    assert!(inspect_package(&bytes, &wrong_name).is_err());
    let mut wrong_version = selected.clone();
    wrong_version["version"] = json!("7.0.4");
    assert!(read_member(&bytes, &wrong_version, "index.d.ts").is_err());
    let mixed = archive(
        &[
            ("is-number/package.json", manifest),
            ("package/index.d.ts", b"inert"),
        ],
        false,
    );
    selected["dist"]["integrity"] = json!(format!(
        "sha512-{}",
        STANDARD.encode(Sha512::digest(&mixed))
    ));
    assert!(inspect_package(&mixed, &selected).is_err());
}

#[derive(Default)]
struct MemoryStore(Mutex<HashMap<String, StoredCapture>>);
#[async_trait]
impl Store for MemoryStore {
    async fn latest(&self, key: &str) -> Result<Option<Cached>> {
        Ok(self
            .0
            .lock()
            .await
            .values()
            .find(|stored| stored.capture.key == key)
            .cloned()
            .map(|stored| Cached {
                stored,
                validators: Validators::default(),
            }))
    }
    async fn capture(&self, id: &str) -> Result<StoredCapture> {
        self.0
            .lock()
            .await
            .get(id)
            .cloned()
            .ok_or_else(|| Error::not_found("Fixture capture absent."))
    }
    async fn publish(
        &self,
        request: &FetchRequest,
        response: FetchResponse,
        now: i64,
    ) -> Result<StoredCapture> {
        let hash = hex::encode(Sha256::digest(&response.body));
        let stored = StoredCapture {
            capture: Capture {
                id: hex::encode(Sha256::digest(format!("{}:{hash}", request.key))),
                key: request.key.clone(),
                source_url: request.url.clone(),
                body_hash: hash,
                media_type: request.media_type.clone(),
                retrieved_at: now,
                validated_at: now,
            },
            body: response.body.into(),
        };
        self.0
            .lock()
            .await
            .insert(stored.capture.id.clone(), stored.clone());
        Ok(stored)
    }
    async fn revalidate(&self, _: &str, id: &str, _: Validators, _: i64) -> Result<StoredCapture> {
        self.capture(id).await
    }
}
struct FixtureFetcher {
    responses: HashMap<String, Vec<u8>>,
    calls: AtomicUsize,
}
#[async_trait]
impl Fetcher for FixtureFetcher {
    async fn fetch(&self, request: &FetchRequest, _: Option<&Validators>) -> Result<FetchResponse> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(FetchResponse {
            status: 200,
            body: self
                .responses
                .get(&request.key)
                .cloned()
                .ok_or_else(|| Error::not_found("Unexpected fixture fetch."))?,
            validators: Validators::default(),
        })
    }
}
fn setup(bytes: Vec<u8>) -> (NpmPackages, Arc<MemoryStore>, Arc<FixtureFetcher>) {
    let manifest = record(&bytes);
    setup_manifest(bytes, manifest)
}
fn setup_manifest(
    bytes: Vec<u8>,
    manifest: Value,
) -> (NpmPackages, Arc<MemoryStore>, Arc<FixtureFetcher>) {
    let key = archive_key("@fixture/package", "1.0.0", &manifest).unwrap();
    let packument = serde_json::to_vec(&json!({"name":"@fixture/package","versions":{"1.0.0":manifest},"dist-tags":{"latest":"1.0.0"}})).unwrap();
    let store = Arc::new(MemoryStore::default());
    let fetcher = Arc::new(FixtureFetcher {
        responses: HashMap::from([
            ("npm:metadata:@fixture/package".into(), packument),
            (key, bytes),
        ]),
        calls: AtomicUsize::new(0),
    });
    (
        NpmPackages::new(Arc::new(Retrieval::new(store.clone(), fetcher.clone()))),
        store,
        fetcher,
    )
}

#[tokio::test]
async fn tools_pin_both_captures_and_page_utf8_without_further_fetches() {
    let _serial = SERIAL.lock().await;
    let (packages, _, fetcher) = setup(fixture_archive());
    let args = json!({"name":"@fixture/package","version":"1.0.0","limit":2});
    let first = packages.call("npm_source_list", args).await.unwrap();
    assert_eq!(first["files"].as_array().unwrap().len(), 2);
    assert_eq!(fetcher.calls.load(Ordering::SeqCst), 2);
    let metadata = first["metadata_capture"]["id"].as_str().unwrap();
    let archive = first["archive_capture"]["id"].as_str().unwrap();
    let page = packages.call("npm_source_read",json!({"name":"@fixture/package","version":"1.0.0","path":"index.js","metadata_capture":metadata,"archive_capture":archive,"offset":21,"limit":4})).await.unwrap();
    assert_eq!(page["page"]["text"], "한");
    assert_eq!(fetcher.calls.load(Ordering::SeqCst), 2);
    let uri = url::Url::parse(page["resource_uri"].as_str().unwrap()).unwrap();
    let parsed = source_input_from_uri(uri.as_str()).unwrap();
    assert_eq!(parsed["path"], "index.js");
    assert!(packages.call("npm_source_read",json!({"name":"@fixture/package","version":"1.0.0","path":"index.js","metadata_capture":metadata})).await.is_err());
    assert!(packages.call("npm_source_read",json!({"name":"@fixture/package","version":"1.0.0","path":"index.js","metadata_capture":metadata,"archive_capture":archive,"offset":22})).await.is_err());
    assert!(source_input_from_uri(&format!("{}&path=evil", uri)).is_err());
}

#[tokio::test]
async fn unsupported_archive_processing_preserves_integrity_verified_capture() {
    let _serial = SERIAL.lock().await;
    let bytes = archive(&[("legacy/package.json", b"{}")], false);
    let (packages, store, fetcher) = setup(bytes);
    let response = packages
        .call(
            "npm_source_list",
            json!({"name":"@fixture/package","version":"1.0.0"}),
        )
        .await
        .unwrap();
    assert_eq!(response["processing_complete"], false);
    assert_eq!(response["checksum_verified"], true);
    assert!(response["archive_capture"]["id"].is_string());
    assert_eq!(store.0.lock().await.len(), 2);
    assert_eq!(fetcher.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn search_capture_paging_stays_inside_fixed_provider_page() {
    let _serial = SERIAL.lock().await;
    let store = Arc::new(MemoryStore::default());
    let objects: Vec<_> = (0..100)
        .map(|n| json!({"package":{"name":format!("fixture-{n}"),"version":"1.0.0"}}))
        .collect();
    let fetcher = Arc::new(FixtureFetcher {
        responses: HashMap::from([(
            "npm:search:fixture:0".into(),
            serde_json::to_vec(&json!({"objects":objects,"total":101})).unwrap(),
        )]),
        calls: AtomicUsize::new(0),
    });
    let packages = NpmPackages::new(Arc::new(Retrieval::new(store, fetcher.clone())));
    let first = packages
        .call(
            "npm_search",
            json!({"query":"fixture","offset":95,"limit":20}),
        )
        .await
        .unwrap();
    assert_eq!(first["items"].as_array().unwrap().len(), 5);
    assert_eq!(first["next_offset"], 100);
    let capture = first["capture"]["id"].as_str().unwrap();
    let second = packages
        .call(
            "npm_search",
            json!({"query":"fixture","offset":96,"limit":2,"capture":capture}),
        )
        .await
        .unwrap();
    assert_eq!(second["items"][0]["name"], "fixture-96");
    assert_eq!(fetcher.calls.load(Ordering::SeqCst), 1);
    assert!(
        packages
            .call("npm_search", json!({"query":"other","capture":capture}))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn checksum_failure_never_publishes_archive_bytes() {
    let _serial = SERIAL.lock().await;
    let bytes = fixture_archive();
    let manifest = record(&bytes);
    let (packages, store, _) = setup_manifest(b"tampered".to_vec(), manifest);
    assert!(
        packages
            .call(
                "npm_source_list",
                json!({"name":"@fixture/package","version":"1.0.0"})
            )
            .await
            .is_err()
    );
    assert_eq!(store.0.lock().await.len(), 1);
}

#[tokio::test]
async fn exact_metadata_does_not_return_other_release_timestamps() {
    let _serial = SERIAL.lock().await;
    let mut time = serde_json::Map::new();
    for index in 0..20_000 {
        time.insert(format!("0.0.{index}"), json!("2020-01-01T00:00:00.000Z"));
    }
    time.insert("created".into(), json!("2019-01-01T00:00:00Z"));
    time.insert("modified".into(), json!("2026-01-01T00:00:00Z"));
    time.insert("1.0.0".into(), json!("2021-01-01T00:00:00Z"));
    let bytes=serde_json::to_vec(&json!({"name":"@fixture/package","versions":{"1.0.0":{"name":"@fixture/package","version":"1.0.0"}},"time":time})).unwrap();
    assert!(bytes.len() > 256 * 1024);
    let store = Arc::new(MemoryStore::default());
    let fetcher = Arc::new(FixtureFetcher {
        responses: HashMap::from([("npm:metadata:@fixture/package".into(), bytes)]),
        calls: AtomicUsize::new(0),
    });
    let packages = NpmPackages::new(Arc::new(Retrieval::new(store.clone(), fetcher)));
    let response = packages
        .call(
            "npm_metadata",
            json!({"name":"@fixture/package","version":"1.0.0"}),
        )
        .await
        .unwrap();
    assert_eq!(response["time"].as_object().unwrap().len(), 3);
    assert_eq!(response["time"]["published"], "2021-01-01T00:00:00Z");
    assert!(serde_json::to_vec(&response).unwrap().len() < 32768);
    let stored = store
        .capture(response["capture"]["id"].as_str().unwrap())
        .await
        .unwrap();
    assert!(stored.body.len() > 256 * 1024);
}
