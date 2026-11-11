//! Synthetic npm evidence only. Fixtures never execute package code or fetch providers.
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD};
use devres_adapters::{
    npm::processing::*,
    npm::{NpmPackages, archive_key, source_input_from_uri},
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

#[tokio::test]
async fn foreground_metadata_numbers_keep_precision_and_literal_marker_objects_stay_objects() {
    let _serial = SERIAL.lock().await;
    let bytes = br#"{"name":"fixture","versions":{"1.0.0":{"name":"fixture","version":"1.0.0","observations":{"decimal":478.37408,"precise":0.123456789012345678901234567890,"huge":184467440737095516161234567890,"exponent":1e400,"negative_zero":-0.0,"nested":[1.25,{"value":2.5}],"literal":{"$serde_json::private::Number":"478.37408"}}}}}"#;
    let fetcher = Arc::new(FixtureFetcher {
        responses: HashMap::from([("npm:metadata:fixture".into(), bytes.to_vec())]),
        calls: AtomicUsize::new(0),
    });
    let packages = NpmPackages::new(Arc::new(Retrieval::new(
        Arc::new(MemoryStore::default()),
        fetcher,
    )));
    let parsed = packages
        .call(
            "packages.npm.metadata",
            json!({"name":"fixture","version":"1.0.0"}),
        )
        .await
        .unwrap();
    let observed = &parsed["metadata"]["observations"];
    for (key, token) in [
        ("decimal", "478.37408"),
        ("precise", "0.123456789012345678901234567890"),
        ("huge", "184467440737095516161234567890"),
        ("exponent", "1e+400"),
        ("negative_zero", "-0.0"),
    ] {
        assert!(observed[key].is_number(), "{key} is a JSON number");
        assert_eq!(observed[key].to_string(), token);
    }
    assert_eq!(observed["nested"][0].to_string(), "1.25");
    assert_eq!(observed["nested"][1]["value"].to_string(), "2.5");
    assert!(observed["literal"].is_object());
    assert_eq!(
        observed["literal"]["$serde_json::private::Number"],
        "478.37408"
    );
    assert_eq!(
        serde_json::to_string(&observed["literal"]).unwrap(),
        r#"{"$serde_json::private::Number":"478.37408"}"#
    );
    let duplicate = br#"{"name":"fixture","versions":{},"literal":{"$serde_json::private::Number":"1","$serde_json::private::Number":"2"}}"#;
    let fetcher = Arc::new(FixtureFetcher {
        responses: HashMap::from([("npm:metadata:fixture".into(), duplicate.to_vec())]),
        calls: AtomicUsize::new(0),
    });
    let packages = NpmPackages::new(Arc::new(Retrieval::new(
        Arc::new(MemoryStore::default()),
        fetcher,
    )));
    assert_eq!(
        packages
            .call(
                "packages.npm.metadata",
                json!({"name":"fixture","version":"1.0.0"})
            )
            .await
            .unwrap_err()
            .code,
        "integrity"
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
fn legacy_collector_and_ordered_contract_numeric_projection_stays_frozen() {
    let package = br#"{"name":"@fixture/package","version":"1.0.0","exports":{".":{"node":"./node.js","default":"./index.js","score":478.37408,"huge":184467440737095516161234567890,"literal":{"$serde_json::private::Number":"1.25"}}}}"#;
    let bytes = archive(&[("package/package.json", package)], false);
    let projected = inspect_package(&bytes, &record(&bytes)).unwrap();
    let contracts = &projected["contracts"];
    let legacy_number = json!({"$serde_json::private::Number":"478.37408"});
    assert_eq!(
        contracts["declarations"]["exports"]["."]["score"],
        legacy_number
    );
    let legacy_metadata = parse_packument(br#"{"name":"fixture","versions":{"1.0.0":{"name":"fixture","version":"1.0.0","score":478.37408}}}"#, "fixture").unwrap();
    assert_eq!(legacy_metadata["versions"]["1.0.0"]["score"], legacy_number);
    let exports = contracts["ordered"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["key"] == "exports")
        .unwrap();
    let entries = exports["value"]["object"][0]["value"]["object"]
        .as_array()
        .unwrap();
    assert_eq!(
        entries
            .iter()
            .map(|entry| entry["key"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["node", "default", "score", "huge", "literal"]
    );
    assert_eq!(
        entries[2]["value"],
        json!({"object":[{"key":"$serde_json::private::Number","value":"478.37408"}]})
    );
    assert_eq!(
        entries[3]["value"],
        json!({"object":[{"key":"$serde_json::private::Number","value":"184467440737095516161234567890"}]})
    );
    assert_eq!(
        entries[4]["value"]["object"][0]["key"],
        "$serde_json::private::Number"
    );
    assert_eq!(entries[4]["value"]["object"][0]["value"], "1.25");
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
    let first = packages
        .call("packages.npm.source_list", args)
        .await
        .unwrap();
    assert_eq!(first["files"].as_array().unwrap().len(), 2);
    assert_eq!(fetcher.calls.load(Ordering::SeqCst), 2);
    let metadata = first["metadata_capture"]["id"].as_str().unwrap();
    let archive = first["archive_capture"]["id"].as_str().unwrap();
    let page = packages.call("packages.npm.source_read",json!({"name":"@fixture/package","version":"1.0.0","path":"index.js","metadata_capture":metadata,"archive_capture":archive,"offset":21,"limit":4})).await.unwrap();
    assert_eq!(page["page"]["text"], "한");
    assert_eq!(fetcher.calls.load(Ordering::SeqCst), 2);
    let uri = url::Url::parse(page["resource_uri"].as_str().unwrap()).unwrap();
    let parsed = source_input_from_uri(uri.as_str()).unwrap();
    assert_eq!(parsed["path"], "index.js");
    assert!(packages.call("packages.npm.source_read",json!({"name":"@fixture/package","version":"1.0.0","path":"index.js","metadata_capture":metadata})).await.is_err());
    assert!(packages.call("packages.npm.source_read",json!({"name":"@fixture/package","version":"1.0.0","path":"index.js","metadata_capture":metadata,"archive_capture":archive,"offset":22})).await.is_err());
    assert!(source_input_from_uri(&format!("{}&path=evil", uri)).is_err());
}

#[tokio::test]
async fn legacy_source_capture_and_resource_keep_distribution_numeric_key() {
    let _serial = SERIAL.lock().await;
    let bytes = fixture_archive();
    let mut manifest = record(&bytes);
    manifest["dist"]["score"] = json!(1.25);
    let raw = serde_json::to_vec(&json!({"name":"@fixture/package","versions":{"1.0.0":manifest}}))
        .unwrap();
    let legacy = parse_packument(&raw, "@fixture/package").unwrap();
    let legacy_manifest = &legacy["versions"]["1.0.0"];
    assert!(legacy_manifest["dist"]["score"].is_object());
    let legacy_key = archive_key("@fixture/package", "1.0.0", legacy_manifest).unwrap();
    assert_ne!(
        legacy_key,
        archive_key("@fixture/package", "1.0.0", &manifest).unwrap()
    );
    let metadata_key = "npm:metadata:@fixture/package".to_owned();
    let metadata_url = "https://registry.npmjs.org/@fixture%2Fpackage".to_owned();
    let archive_url = manifest["dist"]["tarball"].as_str().unwrap().to_owned();
    let store = Arc::new(MemoryStore::default());
    let mut captures = Vec::new();
    for (key, url, media_type, body) in [
        (
            metadata_key.clone(),
            metadata_url,
            "application/json",
            raw.clone(),
        ),
        (
            legacy_key.clone(),
            archive_url,
            "application/gzip",
            bytes.clone(),
        ),
    ] {
        captures.push(
            store
                .publish(
                    &FetchRequest {
                        key,
                        url,
                        ttl_secs: 3600,
                        max_bytes: 128 * 1024 * 1024,
                        media_type: media_type.into(),
                    },
                    FetchResponse {
                        status: 200,
                        body,
                        validators: Validators::default(),
                    },
                    devres_domain::unix_now(),
                )
                .await
                .unwrap(),
        );
    }
    let fetcher = Arc::new(FixtureFetcher {
        responses: HashMap::new(),
        calls: AtomicUsize::new(0),
    });
    let retrieval = Arc::new(Retrieval::new(store.clone(), fetcher.clone()));
    let packages = NpmPackages::new(retrieval.clone());
    let pinned = packages.call("packages.npm.source_read", json!({"name":"@fixture/package","version":"1.0.0","path":"index.js","metadata_capture":captures[0].capture.id,"archive_capture":captures[1].capture.id})).await.unwrap();
    assert_eq!(pinned["archive_capture"]["id"], captures[1].capture.id);
    let mut old_uri = url::Url::parse("devres://npm-source/").unwrap();
    old_uri
        .query_pairs_mut()
        .append_pair("name", "@fixture/package")
        .append_pair("version", "1.0.0")
        .append_pair("path", "index.js")
        .append_pair("metadata_capture", &captures[0].capture.id)
        .append_pair("archive_capture", &captures[1].capture.id)
        .append_pair("offset", "0")
        .append_pair("limit", "32768");
    assert_eq!(pinned["resource_uri"], old_uri.as_str());
    let research = devres_adapters::Research::new(retrieval).await.unwrap();
    assert_eq!(
        research.read_resource(old_uri.as_str()).await.unwrap()["page"],
        pinned["page"]
    );
    let resource = research.read_resource(old_uri.as_str()).await.unwrap();
    assert_eq!(resource["contents"][0]["text"], pinned["page"]["text"]);
    assert_eq!(resource["contents"][0]["uri"], old_uri.as_str());
    assert_eq!(
        resource["contents"][0]["_meta"]["source_evidence"]["archive_capture"]["id"],
        captures[1].capture.id
    );

    let metadata = packages
        .call(
            "packages.npm.metadata",
            json!({"name":"@fixture/package","version":"1.0.0","capture":captures[0].capture.id}),
        )
        .await
        .unwrap();
    assert_eq!(metadata["metadata"]["dist"]["score"].to_string(), "1.25");
    assert!(metadata["metadata"]["dist"]["score"].is_number());
    assert_eq!(fetcher.calls.load(Ordering::SeqCst), 0);

    // A cold source request must select the same distribution key, not mint a
    // new one from the canonical numeric representation used by metadata.
    let cold_store = Arc::new(MemoryStore::default());
    let cold_fetcher = Arc::new(FixtureFetcher {
        responses: HashMap::from([(metadata_key, raw), (legacy_key.clone(), bytes)]),
        calls: AtomicUsize::new(0),
    });
    let cold = NpmPackages::new(Arc::new(Retrieval::new(
        cold_store.clone(),
        cold_fetcher.clone(),
    )));
    let fresh = cold
        .call(
            "packages.npm.source_read",
            json!({"name":"@fixture/package","version":"1.0.0","path":"index.js"}),
        )
        .await
        .unwrap();
    let archive_id = fresh["archive_capture"]["id"].as_str().unwrap();
    assert_eq!(
        cold_store.capture(archive_id).await.unwrap().capture.key,
        legacy_key
    );
    assert_eq!(fresh["resource_uri"], old_uri.as_str());
    assert_eq!(cold_fetcher.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn unsupported_archive_processing_preserves_integrity_verified_capture() {
    let _serial = SERIAL.lock().await;
    let bytes = archive(&[("legacy/package.json", b"{}")], false);
    let (packages, store, fetcher) = setup(bytes);
    let response = packages
        .call(
            "packages.npm.source_list",
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
            "packages.npm.search",
            json!({"query":"fixture","offset":95,"limit":20}),
        )
        .await
        .unwrap();
    assert_eq!(first["items"].as_array().unwrap().len(), 5);
    assert_eq!(first["next_offset"], 100);
    let capture = first["capture"]["id"].as_str().unwrap();
    let second = packages
        .call(
            "packages.npm.search",
            json!({"query":"fixture","offset":96,"limit":2,"capture":capture}),
        )
        .await
        .unwrap();
    assert_eq!(second["items"][0]["name"], "fixture-96");
    assert_eq!(fetcher.calls.load(Ordering::SeqCst), 1);
    assert!(
        packages
            .call(
                "packages.npm.search",
                json!({"query":"other","capture":capture})
            )
            .await
            .is_err()
    );
}

#[tokio::test]
async fn search_and_exact_metadata_numeric_results_survive_json_round_trip_and_pins() {
    let _serial = SERIAL.lock().await;
    let store = Arc::new(MemoryStore::default());
    let fetcher = Arc::new(FixtureFetcher {
        responses: HashMap::from([
            ("npm:search:fixture:0".into(), br#"{"objects":[{"package":{"name":"fixture","version":"1.0.0"},"score":{"final":478.37408,"detail":{"quality":0.123456789012345678901234567890}},"searchScore":1e400}],"total":1}"#.to_vec()),
            ("npm:metadata:fixture".into(), br#"{"name":"fixture","versions":{"1.0.0":{"name":"fixture","version":"1.0.0","observed_score":478.37408,"large_observation":184467440737095516161234567890}}}"#.to_vec()),
        ]),
        calls: AtomicUsize::new(0),
    });
    let packages = NpmPackages::new(Arc::new(Retrieval::new(store, fetcher.clone())));
    for (tool, args, number_path, token) in [
        (
            "packages.npm.search",
            json!({"query":"fixture","limit":1}),
            "/items/0/score/final",
            "478.37408",
        ),
        (
            "packages.npm.metadata",
            json!({"name":"fixture","version":"1.0.0"}),
            "/metadata/large_observation",
            "184467440737095516161234567890",
        ),
    ] {
        let first = packages.call(tool, args.clone()).await.unwrap();
        assert!(first.pointer(number_path).unwrap().is_number());
        assert_eq!(first.pointer(number_path).unwrap().to_string(), token);
        let encoded = serde_json::to_vec(&first).unwrap();
        let decoded: Value = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(first, decoded);
        let mut pinned = args;
        pinned["capture"] = first["capture"]["id"].clone();
        assert_eq!(packages.call(tool, pinned).await.unwrap(), first);
    }
    assert_eq!(fetcher.calls.load(Ordering::SeqCst), 2);
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
                "packages.npm.source_list",
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
            "packages.npm.metadata",
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

fn historical_packument(manifest: Value) -> Vec<u8> {
    let declarations: serde_json::Map<String, Value> = (0..40)
        .map(|index| (format!("dependency-{index}"), json!("^1.0.0")))
        .collect();
    let mut versions = serde_json::Map::new();
    for index in 0..5_000 {
        let version = format!("0.0.{index}");
        versions.insert(
            version.clone(),
            json!({"name":"@fixture/package","version":version,"dependencies":declarations}),
        );
    }
    versions.insert("1.0.0".into(), manifest);
    serde_json::to_vec(&json!({"name":"@fixture/package","versions":versions,"dist-tags":{"latest":"1.0.0"},"time":{"created":"2020-01-01","1.0.0":"2021-01-01","modified":"2026-01-01"}})).unwrap()
}

#[tokio::test]
async fn large_release_history_selects_metadata_and_replays_pinned_sources() {
    let _serial = SERIAL.lock().await;
    let archive = fixture_archive();
    let manifest = record(&archive);
    let metadata = historical_packument(manifest.clone());
    assert!(metadata.len() < MAX_METADATA);
    // The collector retains its existing whole-document materialization bound.
    assert_eq!(
        parse_packument(&metadata, "@fixture/package")
            .unwrap_err()
            .code,
        "capacity"
    );
    let store = Arc::new(MemoryStore::default());
    let fetcher = Arc::new(FixtureFetcher {
        responses: HashMap::from([
            ("npm:metadata:@fixture/package".into(), metadata.clone()),
            (
                archive_key("@fixture/package", "1.0.0", &manifest).unwrap(),
                archive,
            ),
        ]),
        calls: AtomicUsize::new(0),
    });
    let packages = NpmPackages::new(Arc::new(Retrieval::new(store.clone(), fetcher.clone())));
    let response = packages
        .call(
            "packages.npm.metadata",
            json!({"name":"@fixture/package","version":"v1.0.0"}),
        )
        .await
        .unwrap();
    assert_eq!(response["metadata"], manifest);
    assert_eq!(response["time"]["published"], "2021-01-01");
    let capture = response["capture"]["id"].as_str().unwrap();
    assert_eq!(
        store.capture(capture).await.unwrap().body.as_ref(),
        metadata.as_slice()
    );
    let replay = packages
        .call(
            "packages.npm.metadata",
            json!({"name":"@fixture/package","version":"1.0.0","capture":capture}),
        )
        .await
        .unwrap();
    assert_eq!(replay["metadata"], manifest);
    assert_eq!(fetcher.calls.load(Ordering::SeqCst), 1);
    let listing = packages
        .call(
            "packages.npm.source_list",
            json!({"name":"@fixture/package","version":"1.0.0"}),
        )
        .await
        .unwrap();
    let archive_capture = listing["archive_capture"]["id"].as_str().unwrap();
    let read = packages.call("packages.npm.source_read", json!({"name":"@fixture/package","version":"1.0.0","path":"README.md","metadata_capture":capture,"archive_capture":archive_capture})).await.unwrap();
    assert!(read["page"]["text"].as_str().unwrap().contains("# Fixture"));
    assert_eq!(fetcher.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn unrelated_invalid_releases_are_rejected_before_capture_publication() {
    let _serial = SERIAL.lock().await;
    for unrelated in [
        json!({"name":"other","version":"2.0.0"}),
        json!({"name":"@fixture/package","version":"3.0.0"}),
        json!({"name":"@fixture/package","version":"2.0.0","dependencies":{"bad":false}}),
    ] {
        let bytes = serde_json::to_vec(&json!({"name":"@fixture/package","versions":{"1.0.0":{"name":"@fixture/package","version":"1.0.0"},"2.0.0":unrelated}})).unwrap();
        let store = Arc::new(MemoryStore::default());
        let fetcher = Arc::new(FixtureFetcher {
            responses: HashMap::from([("npm:metadata:@fixture/package".into(), bytes.clone())]),
            calls: AtomicUsize::new(0),
        });
        let packages = NpmPackages::new(Arc::new(Retrieval::new(store.clone(), fetcher.clone())));
        assert_eq!(
            packages
                .call(
                    "packages.npm.metadata",
                    json!({"name":"@fixture/package","version":"1.0.0"})
                )
                .await
                .unwrap_err()
                .code,
            "integrity"
        );
        assert!(store.0.lock().await.is_empty());
        // A previously retained capture must pass the same complete validation.
        let capture = store
            .publish(
                &FetchRequest {
                    key: "npm:metadata:@fixture/package".into(),
                    url: "https://registry.npmjs.org/@fixture%2Fpackage".into(),
                    ttl_secs: 3600,
                    max_bytes: MAX_METADATA,
                    media_type: "application/json".into(),
                },
                FetchResponse {
                    status: 200,
                    body: bytes,
                    validators: Validators::default(),
                },
                0,
            )
            .await
            .unwrap();
        assert_eq!(packages.call("packages.npm.metadata", json!({"name":"@fixture/package","version":"1.0.0","capture":capture.capture.id})).await.unwrap_err().code,"integrity");
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn selected_metadata_output_limit_retains_full_capture_and_applies_to_replay() {
    let _serial = SERIAL.lock().await;
    let bytes = serde_json::to_vec(&json!({"name":"@fixture/package","versions":{"1.0.0":{"name":"@fixture/package","version":"1.0.0","description":"x".repeat(256 * 1024)}}})).unwrap();
    let store = Arc::new(MemoryStore::default());
    let fetcher = Arc::new(FixtureFetcher {
        responses: HashMap::from([("npm:metadata:@fixture/package".into(), bytes.clone())]),
        calls: AtomicUsize::new(0),
    });
    let packages = NpmPackages::new(Arc::new(Retrieval::new(store.clone(), fetcher.clone())));
    assert_eq!(
        packages
            .call(
                "packages.npm.metadata",
                json!({"name":"@fixture/package","version":"1.0.0"})
            )
            .await
            .unwrap_err()
            .code,
        "capacity"
    );
    let capture = store.0.lock().await.values().next().cloned().unwrap();
    assert_eq!(capture.body.as_ref(), bytes.as_slice());
    assert_eq!(
        packages
            .call(
                "packages.npm.metadata",
                json!({"name":"@fixture/package","version":"1.0.0","capture":capture.capture.id})
            )
            .await
            .unwrap_err()
            .code,
        "capacity"
    );
    assert_eq!(fetcher.calls.load(Ordering::SeqCst), 1);
}
