//! Synthetic fixtures; no source programs, network or external resources are used.
use super::*;
use serde_json::json;

fn project(path: &str, source: &str) -> ProcessedDocument {
    process_document(path, source.as_bytes(), CancellationToken::new()).expect("synthetic fixture")
}
fn gap(doc: &ProcessedDocument, code: &str) -> bool {
    doc.gaps.iter().any(|gap| gap.code == code)
}

#[test]
fn retained_whatwg_notice_projection_stays_byte_and_shape_compatible() {
    let source = "Copyright Example\n<script>inert()</script>\n";
    let projected = crate::whatwg::processing::process_document(
        "LICENSE",
        source.as_bytes(),
        CancellationToken::new(),
    )
    .expect("original notice");
    assert_eq!(
        serde_json::to_value(projected).expect("projection"),
        json!({
            "format":"text", "title":"license", "text":source,
            "sections":[{"anchor":"document","title":"license","text":source}],
            "symbols":[],"references":[],"gaps":[]
        })
    );
    assert!(
        crate::whatwg::processing::process_document(
            "legacy.xhtml",
            b"<html/>",
            CancellationToken::new()
        )
        .is_err()
    );
    assert_eq!(
        project(
            "legacy.xhtml",
            "<html xmlns='http://www.w3.org/1999/xhtml'><body><h1>Title</h1></body></html>"
        )
        .format,
        "xhtml"
    );
}
#[test]
fn original_processor_v4_canonical_hashes_remain_compatible() {
    use sha2::{Digest, Sha256};
    // Baselines were obtained by independently compiling the original processor
    // from revision 34130df against this repository's unchanged locked graph.
    for (path, source, expected) in [
        (
            "LICENSE",
            "Copyright Example\n<script>inert()</script>\n",
            "5088375a52ebb3be93777f0e032b375d0b6fb649dd61a8913bd17f49d6a90ab5",
        ),
        (
            "index.html",
            "<h1 id='spec'>Title</h1><dfn id='token'>token</dfn><script>secret()</script>",
            "28ec93e751ff830f74a617e1f460cb317e9d0b01515b465d88965a698537aaf1",
        ),
        (
            "source.bs",
            "## Title {#spec}\n<dfn id='token'>token</dfn>\n[=unexpanded=]",
            "687522d2836719d7455cd1c873e4ce15135d049eebfef27dfd5192ef837a5cad",
        ),
        (
            "README.md",
            "# Title\n\nExample `code` [link](https://example.org/)\n",
            "404896bcf38d01f33b1756573137b9eadb981f55f9aaf0cfd31d32b864525a18",
        ),
        (
            "interfaces.idl",
            "interface Example {};",
            "b8aefcd24f30e37a6e7cb98efc069802b3299402c0271e3e993ba15f846ae0fd",
        ),
        (
            "respec.html",
            "<script>var respecConfig = {};</script><script src='https://www.w3.org/Tools/respec/respec-w3c-common'></script><h1>Title</h1>",
            "1e499d2e1578321bf12fa5795294e8acc867184800610801683f2df52374e8bd",
        ),
        (
            "unicode.html",
            "<h1>Unicode 界</h1><h2 id='same'>First</h2><dfn id='same'>δοκιμή</dfn><h2>Generated</h2><p>Text</p>",
            "052c058096a855fd0dfc76a198f3f262780cabc86e0483cc5474c46e5852083a",
        ),
    ] {
        let legacy = crate::whatwg::processing::process_document(
            path,
            source.as_bytes(),
            CancellationToken::new(),
        )
        .expect("legacy");
        let w3c = project(path, source);
        for document in [legacy, w3c] {
            let canonical = serde_json::to_vec(&document).expect("canonical projection");
            assert_eq!(hex::encode(Sha256::digest(&canonical)), expected, "{path}");
            assert!(!document.text.contains("secret()"));
        }
    }
}
#[test]
fn namespace_aware_xhtml_retains_headings_symbols_and_foreign_text() {
    let document = project(
        "spec.xhtml",
        r##"<?xml version="1.0"?><!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "https://example.invalid/external.dtd"><x:html xmlns:x="http://www.w3.org/1999/xhtml" xmlns:m="http://www.w3.org/1998/Math/MathML"><x:body><x:h1 id="title">XHTML &amp; Symbols</x:h1><x:h2 id="terms">Terms</x:h2><x:p><x:dfn id="token" data-dfn-for="Scope">token</x:dfn> <m:math><m:mi>x</m:mi></m:math></x:p><x:a href="#token">reference</x:a><x:script>secret()</x:script></x:body></x:html>"##,
    );
    assert_eq!(document.format, "xhtml");
    assert_eq!(document.title, "XHTML & Symbols");
    assert!(
        document
            .sections
            .iter()
            .any(|section| section.anchor == "terms")
    );
    assert!(
        document
            .symbols
            .iter()
            .any(|symbol| symbol.name == "token" && symbol.scope.as_deref() == Some("Scope"))
    );
    assert!(
        document
            .references
            .iter()
            .any(|reference| reference.target == "#token")
    );
    assert!(!document.text.contains("secret()"));
    assert!(gap(&document, "inert_xml_doctype"));
}
#[test]
fn xml_namespaced_ids_mixed_text_cdata_and_links_remain_source_evidence() {
    let document = project(
        "vocabulary.rdf",
        r#"<r:RDF xmlns:r="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><r:Description xml:id="term" r:about="https://example.org/term">before<![CDATA[<literal>]]>&amp;after</r:Description></r:RDF>"#,
    );
    let section = document
        .sections
        .iter()
        .find(|section| section.anchor == "term")
        .expect("source ID");
    assert!(
        section
            .title
            .starts_with("{http://www.w3.org/1999/02/22-rdf-syntax-ns#}")
    );
    assert!(section.text.contains("before<literal>&after"));
    assert!(gap(&document, "structured_semantics_unasserted"));
}
#[test]
fn xml_external_doctype_is_inert_and_custom_entities_are_raw_only_gaps() {
    let document = project(
        "spec.xml",
        "<!DOCTYPE spec SYSTEM 'file:///etc/passwd'><spec><p>safe</p></spec>",
    );
    assert!(document.text.contains("safe"));
    assert!(gap(&document, "inert_xml_doctype"));
    for source in [
        "<!DOCTYPE spec [<!ENTITY secret SYSTEM 'file:///etc/passwd'>]><spec>&secret;</spec>",
        "<spec>&undefined;</spec>",
    ] {
        let document = project("spec.xml", source);
        assert!(gap(&document, "unresolved_xml_entity"));
        assert!(document.text.is_empty() && document.sections.is_empty());
    }
}
#[test]
fn xml_malformed_namespaces_and_active_svg_are_handled_without_external_work() {
    for source in ["<spec><p></spec>", "<unknown:spec/>", "<spec/><other/>"] {
        let error = process_document("spec.xml", source.as_bytes(), CancellationToken::new())
            .expect_err("malformed XML");
        assert_eq!(error.code, "integrity");
        assert!(!error.message.contains(source));
    }
    let document = project(
        "spec.svg",
        "<svg xmlns='http://www.w3.org/2000/svg'><text id='label'>Readable</text><script>hidden()</script></svg>",
    );
    assert!(document.text.contains("Readable"));
    assert!(!document.text.contains("hidden()"));
}
#[test]
fn json_pointer_navigation_is_deterministic_and_remote_context_is_inert() {
    let document = project(
        "schema.jsonld",
        r#"{"@context":"https://example.invalid/context","a/b":{"~name":[true,2,"text"]}}"#,
    );
    assert_eq!(document.format, "json");
    assert!(
        document
            .sections
            .iter()
            .any(|section| section.anchor == "data:/a~1b/~0name/2" && section.text == "text")
    );
    assert!(document.text.contains("https://example.invalid/context"));
    assert!(document.references.is_empty());
    assert!(gap(&document, "structured_semantics_unasserted"));
    assert!(process_document("a.json", br#"{"key":1,"key":2}"#, CancellationToken::new()).is_err());
    assert!(process_document("a.json", b"{} {}", CancellationToken::new()).is_err());
}
#[test]
fn structural_depth_scalar_and_aggregate_bounds_fall_back_to_inert_source() {
    let deep = format!("{}0{}", "[".repeat(70), "]".repeat(70));
    assert!(gap(
        &project("deep.json", &deep),
        "structured_projection_limit"
    ));
    let scalar = format!("{{\"value\":\"{}\"}}", "x".repeat(MAX_SCALAR + 1));
    assert!(gap(
        &project("large.json", &scalar),
        "structured_projection_limit"
    ));
    let wide = format!("[{}0]", "0,".repeat(MAX_ITEMS));
    assert!(gap(
        &project("wide.json", &wide),
        "structured_projection_limit"
    ));
    let big = format!("[\"{}\"]", "x".repeat(MAX_STRUCTURED_INPUT));
    let document = project("big.json", &big);
    assert!(gap(&document, "structured_projection_limit"));
    assert!(
        document
            .sections
            .iter()
            .all(|section| section.text.len() <= MAX_SCALAR)
    );
}
#[test]
fn yaml_rejects_aliases_tags_duplicate_keys_and_multiple_documents() {
    for source in [
        "a: &anchor value\nb: *anchor\n",
        "a: !!str value\n",
        "a: 1\na: 2\n",
        "---\na: 1\n---\na: 2\n",
    ] {
        assert!(
            process_document("data.yaml", source.as_bytes(), CancellationToken::new()).is_err(),
            "{source}"
        );
    }
    let document = project("data.yaml", "title: Example\nitems:\n  - alpha\n  - beta\n");
    assert!(
        document
            .sections
            .iter()
            .any(|section| section.anchor == "data:/items/1" && section.text == "beta")
    );
}
#[test]
fn csv_tsv_quoted_cells_and_formulas_remain_inert_strings() {
    let csv = project("data.csv", "name,value\n\"multi\nline\",\"=1+2\"\n");
    assert_eq!(csv.sections.len(), 2);
    assert!(csv.sections[1].text.contains("multi\nline"));
    assert!(csv.sections[1].text.contains("=1+2"));
    let tsv = project("data.tsv", "name\tvalue\na\tb\n");
    assert!(tsv.sections[1].text.contains("column 2: b"));
    for source in [
        "name,value\n\"unclosed,value\n",
        "a\"b,c\n",
        "\"a\"garbage,c\n",
    ] {
        assert!(process_document("bad.csv", source.as_bytes(), CancellationToken::new()).is_err());
    }
}
#[test]
fn unknown_binary_encoding_and_grammar_coverage_are_explicit() {
    let binary =
        process_document("image.bin", b"\xff\x00", CancellationToken::new()).expect("raw gap");
    assert!(gap(&binary, "unsupported_encoding"));
    let executable = project("module.js", "dangerous();");
    assert!(gap(&executable, "unsupported_format") && executable.text.is_empty());
    let grammar = project(
        "schema.ttl",
        "@prefix ex: <https://example.org/> . ex:a ex:b ex:c .",
    );
    assert!(grammar.text.contains("@prefix"));
    assert!(gap(&grammar, "structured_semantics_unasserted"));
    let encoded = project(
        "legacy.xml",
        "<?xml version='1.0' encoding='ISO-8859-1'?><spec>ASCII subset</spec>",
    );
    assert!(gap(&encoded, "unsupported_encoding"));
}
#[test]
fn pre_cancelled_and_general_input_bounds_fail_before_projection() {
    let cancel = CancellationToken::new();
    cancel.cancel();
    assert_eq!(
        process_document("data.json", b"{}", cancel)
            .expect_err("cancelled")
            .code,
        "cancelled"
    );
    assert_eq!(
        process_document(&"x".repeat(MAX_KEY + 1), b"a", CancellationToken::new())
            .expect_err("path bound")
            .code,
        "capacity"
    );
}

#[test]
fn xhtml_respec_is_not_silently_treated_as_fully_rendered() {
    let document = project(
        "respec.xhtml",
        "<html xmlns='http://www.w3.org/1999/xhtml'><head><script>var respecConfig = {};</script><script src='https://www.w3.org/Tools/respec/respec-w3c-common'/></head><body><h1>Draft</h1><p>[[UNEXPANDED]]</p></body></html>",
    );
    assert!(gap(&document, "unexpanded_respec"));
    assert!(!document.text.contains("respecConfig"));
}
