//! Synthetic RFC source fixtures; no network, package execution, or archive writes.
use super::*;

fn index(entry: &str) -> Vec<u8> {
    format!("<rfc-index>{entry}</rfc-index>").into_bytes()
}
fn entry(number: &str, fields: &str) -> String {
    format!("<rfc-entry><doc-id>{number}</doc-id><title>Protocol</title>{fields}</rfc-entry>")
}

#[test]
fn rich_metadata_preserves_source_precision_and_all_relationships() {
    let xml = br#"<rfc-index xmlns="https://www.rfc-editor.org/rfc-index"><rfc-entry>
      <doc-id>RFC9000</doc-id><title>QUIC &amp; Transport</title>
      <date><month>May</month><year>2021</year></date>
      <author><name>First Author</name></author><author><name>Second Author</name><title>Editor</title></author>
      <keywords><kw> transport </kw><kw>multiplexing</kw></keywords>
      <abstract><p>First <em>inline</em>.</p><p>Second.</p></abstract>
      <current-status>PROPOSED STANDARD</current-status><stream>IETF</stream><area>Transport</area><wg_acronym>quic</wg_acronym><doi>10.17487/RFC9000</doi>
      <format><file-format>ASCII</file-format><file-format>HTML</file-format><file-format>XML</file-format><file-format>PDF</file-format></format>
      <is-also><doc-id>STD0001</doc-id><doc-id>BCP0002</doc-id><doc-id>FYI0003</doc-id></is-also>
      <updates><doc-id>RFC8999</doc-id></updates><updated-by><doc-id>RFC9001</doc-id></updated-by>
      <obsoletes><doc-id>RFC8998</doc-id></obsoletes><obsoleted-by><doc-id>RFC9002</doc-id></obsoleted-by>
    </rfc-entry></rfc-index>"#;
    let record = parse_index(xml).unwrap().pop().unwrap();
    assert_eq!(record.authors, ["First Author", "Second Author"]);
    assert_eq!(record.keywords, ["transport", "multiplexing"]);
    assert_eq!(record.abstract_text, "First inline. Second.");
    assert_eq!(record.published, "May 2021");
    assert_eq!(record.publication.as_deref(), Some("2021-05"));
    assert_eq!(record.formats, ["txt", "html", "xml", "pdf"]);
    let modern = parse_index(
        &String::from_utf8(xml.to_vec())
            .unwrap()
            .replace(
                "<file-format>ASCII</file-format>",
                "<file-format>TEXT</file-format>",
            )
            .into_bytes(),
    )
    .unwrap();
    assert_eq!(modern[0].formats, ["txt", "html", "xml", "pdf"]);
    assert_eq!(record.series, ["STD0001", "BCP0002", "FYI0003"]);
    assert_eq!(record.stream, "IETF");
    assert_eq!(record.area, "Transport");
    assert_eq!(record.working_group, "quic");
    assert_eq!(record.doi, "10.17487/RFC9000");
    assert_eq!(record.updates, ["RFC8999"]);
    assert_eq!(record.updated_by, ["RFC9001"]);
    assert_eq!(record.obsoletes, ["RFC8998"]);
    assert_eq!(record.obsoleted_by, ["RFC9002"]);
    let record = parse_index(&index(&entry("RFC0001", "<date><year>1969</year></date>")))
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(record.published, "1969");
    assert_eq!(record.publication, None);
}

#[test]
fn rejects_wrong_roots_namespaces_and_field_structure() {
    let valid = entry("RFC1", "");
    for xml in [
        format!("<wrapper>{valid}</wrapper>"),
        format!("<rfc-index>{valid}</rfc-index><rfc-index>{}</rfc-index>", entry("RFC2", "")),
        format!("<rfc-index><wrapper>{valid}</wrapper></rfc-index>"),
        format!("<rfc-index xmlns='https://evil.invalid'>{valid}</rfc-index>"),
        "<rfc-index xmlns='https://www.rfc-editor.org/rfc-index'><rfc-entry xmlns=''><doc-id>RFC1</doc-id><title>A</title></rfc-entry></rfc-index>".into(),
        "<rfc-index><rfc-entry><doc-id><x>RFC1</x></doc-id><title>A</title></rfc-entry></rfc-index>".into(),
        "<rfc-index><rfc-entry><doc-id>RFC1</doc-id><title> </title></rfc-entry></rfc-index>".into(),
        "<rfc-index><rfc-entry><doc-id>RFC1</doc-id><doc-id>RFC2</doc-id><title>A</title></rfc-entry></rfc-index>".into(),
        format!("<rfc-index>{}</rfc-index>", entry("RFC1000000", "")),
        format!("<rfc-index>{}</rfc-index>", entry("RFC0", "")),
        format!("<rfc-index>{}</rfc-index>", entry("RFC1", "<title/>")),
        "<rfc-index><rfc-entry><doc-id>RFC1</doc-id><title>A</title></rfc-index>".into(),
    ] {
        assert!(parse_index(xml.as_bytes()).is_err(), "accepted {xml}");
    }
    assert!(parse_index(&[0xff]).is_err());
}

#[test]
fn split_entities_cdata_and_namespaced_ids_are_preserved() {
    let xml = br#"<i:rfc-index xmlns:i="https://www.rfc-editor.org/rfc-index"><i:rfc-entry><i:doc-id>RFC&#57;000</i:doc-id><i:title><![CDATA[A&B]]>&amp;C</i:title></i:rfc-entry></i:rfc-index>"#;
    let record = parse_index(xml).unwrap().pop().unwrap();
    assert_eq!(record.number, 9000);
    assert_eq!(record.title, "A&B&C");
}

#[test]
fn index_depth_text_and_worker_deadline_are_bounded() {
    let deep = format!(
        "<abstract>{}text{}</abstract>",
        "<p>".repeat(64),
        "</p>".repeat(64)
    );
    assert_eq!(
        parse_index(&index(&entry("RFC1", &deep))).unwrap_err().code,
        "capacity"
    );
    let big = format!(
        "<current-status>{}</current-status>",
        "x".repeat(MAX_ENTRY + 1)
    );
    assert_eq!(
        parse_index(&index(&entry("RFC1", &big))).unwrap_err().code,
        "capacity"
    );
    assert_eq!(
        parse_index_until(&index(&entry("RFC1", "")), Instant::now())
            .unwrap_err()
            .code,
        "capacity"
    );
}

#[test]
fn plain_text_and_pdf_validation_fail_closed() {
    assert_eq!(
        extract_text("txt", "RFC 9000\nUnicode 한글\n".as_bytes()).unwrap(),
        "RFC 9000\nUnicode 한글\n"
    );
    for bytes in [
        b"".as_slice(),
        b" \n",
        b"<html>Error</html>",
        b"\xef\xbb\xbf <html>Error</html>",
        b"RFC\0text",
        &[0xff],
    ] {
        assert!(validate_representation("txt", bytes).is_err());
    }
    validate_representation("pdf", b"%PDF-1.7\nsynthetic\n%%EOF\n").unwrap();
    assert!(validate_representation("pdf", b"<html>%PDF-1.7 %%EOF</html>").is_err());
    assert!(validate_representation("pdf", b"%PDF-1.7\ntruncated").is_err());
    assert!(extract_text("pdf", b"%PDF-1.7\nsynthetic\n%%EOF").is_err());
    assert_eq!(
        validate_representation("txt", &vec![b'x'; MAX_TEXT + 1])
            .unwrap_err()
            .code,
        "capacity"
    );
}

#[test]
fn xml_external_entities_are_inert_and_unresolved_extraction_is_explicit() {
    let xml = br#"<!DOCTYPE rfc SYSTEM "file:///not-read"><rfc><middle><section><name>Heading</name><t>A &amp; B <em>inline</em>.</t><t><![CDATA[Code <text>]]></t></section></middle></rfc>"#;
    validate_representation("xml", xml).unwrap();
    let text = extract_text("xml", xml).unwrap();
    assert!(text.contains("A & B inline."));
    assert!(text.contains("Code <text>"));
    let entity = br#"<!DOCTYPE rfc [<!ENTITY secret SYSTEM "https://not-requested.invalid/">]><rfc><t>&secret;</t></rfc>"#;
    validate_representation("xml", entity).unwrap();
    assert!(extract_text("xml", entity).is_err());
    for xml in [
        "<html><t>wrong</t></html>",
        "<rfc><t>broken</rfc>",
        "<rfc/>outside",
        "<rfc/><rfc/>",
    ] {
        assert!(validate_representation("xml", xml.as_bytes()).is_err());
    }
}

#[test]
fn html_extraction_preserves_inline_text_and_discards_active_content() {
    let html = br#"<!doctype html><html><head><title>skip title</title><style>skip style</style></head><body><p>Proto<em>col</em> &amp; data.</p><script src="https://not-loaded.invalid/">skip script</script><p>Next <a href="https://not-loaded.invalid/">section</a>.</p></body></html>"#;
    let text = extract_text("html", html).unwrap();
    assert!(text.contains("Protocol & data."));
    assert!(text.contains("Next section."));
    assert!(!text.contains("skip"));
    assert!(validate_representation("html", b"upstream failure").is_err());
}

#[test]
fn errata_preserve_raw_fields_and_reject_invalid_or_duplicate_records() {
    let valid = json!({"errata_id":"1234","doc-id":"RFC09000","errata_status_code":"Verified","errata_type_code":"Technical","orig_text":"before", "correct_text":"after", "future_field":{"value":true}});
    let bytes = serde_json::to_vec(&vec![valid.clone()]).unwrap();
    assert_eq!(parse_errata(&bytes).unwrap()[0], valid);
    assert!(
        parse_errata(&serde_json::to_vec(&vec![valid.clone(), valid.clone()]).unwrap()).is_err()
    );
    for field in [
        "errata_id",
        "doc-id",
        "errata_status_code",
        "errata_type_code",
    ] {
        let mut invalid = valid.clone();
        invalid.as_object_mut().unwrap().remove(field);
        assert!(parse_errata(&serde_json::to_vec(&vec![invalid]).unwrap()).is_err());
    }
    for identity in ["+123", "-1", "123x", ""] {
        let mut invalid = valid.clone();
        invalid["errata_id"] = json!(identity);
        assert!(parse_errata(&serde_json::to_vec(&vec![invalid]).unwrap()).is_err());
    }
    assert!(parse_errata(b"{}").is_err());
    assert!(parse_errata(b"[null]").is_err());
    assert!(parse_errata(&serde_json::to_vec(&vec![json!({"errata_id":0,"doc-id":"RFC1","errata_status_code":"Reported","errata_type_code":"Editorial"})]).unwrap()).is_err());
    assert_eq!(parse_errata(b"[]").unwrap(), Vec::<Value>::new());
}

#[derive(Default)]
struct NeverPublish(std::sync::atomic::AtomicUsize);
#[async_trait]
impl devres_application::Store for NeverPublish {
    async fn latest(&self, _: &str) -> Result<Option<devres_application::Cached>> {
        Ok(None)
    }
    async fn capture(&self, _: &str) -> Result<devres_domain::StoredCapture> {
        Err(Error::not_found("No fixture capture."))
    }
    async fn publish(
        &self,
        _: &FetchRequest,
        _: FetchResponse,
        _: i64,
    ) -> Result<devres_domain::StoredCapture> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(Error::integrity(
            "Fixture must never publish invalid input.",
        ))
    }
    async fn revalidate(
        &self,
        _: &str,
        _: &str,
        _: devres_domain::Validators,
        _: i64,
    ) -> Result<devres_domain::StoredCapture> {
        Err(Error::integrity("Unexpected fixture revalidation."))
    }
}
struct MalformedSource;
#[async_trait]
impl devres_application::Fetcher for MalformedSource {
    async fn fetch(
        &self,
        _: &FetchRequest,
        _: Option<&devres_domain::Validators>,
    ) -> Result<FetchResponse> {
        Ok(FetchResponse {
            status: 200,
            body: b"<html>upstream failure</html>".to_vec(),
            validators: devres_domain::Validators::default(),
        })
    }
}

#[tokio::test]
async fn malformed_success_never_promotes_a_durable_source_head() {
    let store = std::sync::Arc::new(NeverPublish::default());
    let retrieval = Retrieval::new(store.clone(), std::sync::Arc::new(MalformedSource));
    let error = retrieval
        .get_validated(
            FetchRequest {
                key: "rfc:text:9000".into(),
                url: "https://www.rfc-editor.org/rfc/rfc9000.txt".into(),
                ttl_secs: 86400,
                max_bytes: MAX_TEXT,
                media_type: "text/plain".into(),
            },
            &Validator,
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, "integrity");
    assert_eq!(store.0.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test]
async fn invalid_text_page_limit_fails_before_source_access() {
    let store = std::sync::Arc::new(NeverPublish::default());
    let retrieval = Retrieval::new(store.clone(), std::sync::Arc::new(MalformedSource));
    let error = get(
        &retrieval,
        GetInput {
            number: 9000,
            offset: 0,
            limit: 0,
            capture: None,
        },
    )
    .await
    .unwrap_err();
    assert_eq!(error.code, "invalid_input");
    assert_eq!(store.0.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[test]
fn streaming_html_rejects_giant_tokens_attributes_and_nesting() {
    let cases = [
        format!(
            "<html><body><p data-value='{}'>content</p></body></html>",
            "x".repeat(128 * 1024)
        ),
        format!(
            "<html><body><{}>content</body></html>",
            "x".repeat(128 * 1024)
        ),
        format!(
            "<html><!--{}--><body>content</body></html>",
            "x".repeat(128 * 1024)
        ),
        format!(
            "<html><body><p {}>content</p></body></html>",
            (0..129).map(|i| format!("a{i}='x' ")).collect::<String>()
        ),
        format!(
            "<html><body>{}content{}</body></html>",
            "<div>".repeat(257),
            "</div>".repeat(257)
        ),
        format!("<html><body>&#{}1;</body></html>", "0".repeat(128 * 1024)),
    ];
    for source in cases {
        assert_eq!(
            extract_text("html", source.as_bytes()).unwrap_err().code,
            "capacity"
        );
    }
    assert_eq!(
        html_text(b"<html><body>content</body></html>", true, Instant::now())
            .unwrap_err()
            .code,
        "capacity"
    );
}

#[test]
fn streaming_html_handles_chunked_unicode_entities_raw_text_and_inert_self_closing_tags() {
    let padding = "é".repeat(HTML_CHUNK / 2 - 31);
    let source = format!(
        "<!doctype html><html><head><title>hidden &amp; title</title><body><p>{padding}α&amp;β Proto<em>col</em></p><script/>hidden <p>script</p></script><style>hidden style</style><template><p>hidden template</p></template><noscript>hidden fallback</noscript><p>visible</p><textarea>A&lt;B</textarea></body></html>"
    );
    let text = extract_text("html", source.as_bytes()).unwrap();
    assert!(text.contains(&format!("{padding}α&β Protocol")));
    assert!(text.contains("visible"));
    assert!(text.contains("A<B"));
    assert!(!text.contains("hidden"));
}

#[tokio::test]
async fn legacy_search_admits_schema_sized_unicode_queries_and_statuses() {
    let retrieval = Retrieval::new(
        std::sync::Arc::new(NeverPublish::default()),
        std::sync::Arc::new(MalformedSource),
    );
    for (query, status, expected) in [
        ("한".repeat(256), Some("Σ".repeat(129)), "integrity"),
        ("한".repeat(257), None, "invalid_input"),
        ("protocol".into(), Some(String::new()), "invalid_input"),
        ("protocol".into(), Some("Σ".repeat(257)), "invalid_input"),
    ] {
        // The malformed fixture yields integrity only after schema-valid input
        // reaches provider validation; no live source or durable head is used.
        let error = search(
            &retrieval,
            SearchInput {
                query,
                status,
                offset: 0,
                limit: 20,
                capture: None,
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, expected);
    }
}

#[test]
fn errata_sequence_and_individual_records_are_bounded_before_materialization() {
    let too_many = format!("[{}]", vec!["{}"; 50001].join(","));
    assert_eq!(
        parse_errata(too_many.as_bytes()).unwrap_err().code,
        "capacity"
    );
    let oversized = format!("[{{\"notes\":\"{}\"}}]", "a".repeat(256 * 1024));
    assert_eq!(
        parse_errata(oversized.as_bytes()).unwrap_err().code,
        "capacity"
    );
    assert!(parse_errata(b"[] []").is_err());
    let records = parse_index(&index(&entry(
        "RFC9000",
        "<format><file-format>TEXT</file-format><file-format>PS</file-format></format>",
    )))
    .unwrap();
    assert_eq!(records[0].formats, ["txt"]);
    assert_eq!(records[0].unsupported_formats, ["PS"]);
}

#[test]
#[ignore = "requires operator-supplied public errata JSON; no network"]
fn captured_official_errata_replay_is_bounded_and_preserves_rfc9000() {
    let path = std::env::var("DEVRES_RFC_ERRATA_REPLAY").expect("public replay path");
    let bytes = std::fs::read(path).unwrap();
    let records = parse_errata(&bytes).unwrap();
    assert!(!records.is_empty());
    assert!(records.iter().any(|r| {
        r["doc-id"]
            .as_str()
            .is_some_and(|id| id.trim_start_matches("RFC").parse::<u32>() == Ok(9000))
    }));
}
