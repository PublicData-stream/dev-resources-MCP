//! First-party PDF helper boundary, using only a synthetic inert document.
use devres_adapters::whatwg_processing::ProcessedDocument;
use devres_domain::Result;
use lopdf::{
    Document, Object, Stream,
    content::{Content, Operation},
    dictionary,
};
use std::{
    io::Write,
    process::{Command, Stdio},
};

fn synthetic_pdf() -> Vec<u8> {
    let mut doc = Document::with_version("1.5");
    let pages = doc.new_object_id();
    let font =
        doc.add_object(dictionary! {"Type"=>"Font","Subtype"=>"Type1","BaseFont"=>"Helvetica"});
    let resources = doc.add_object(dictionary! {"Font"=>dictionary!{"F1"=>font}});
    let content = Content {
        operations: vec![
            Operation::new("BT", vec![]),
            Operation::new("Tf", vec!["F1".into(), 12.into()]),
            Operation::new("Td", vec![20.into(), 20.into()]),
            Operation::new(
                "Tj",
                vec![Object::string_literal("Synthetic worker fixture")],
            ),
            Operation::new("ET", vec![]),
        ],
    };
    let stream = doc.add_object(Stream::new(dictionary! {}, content.encode().unwrap()));
    let page=doc.add_object(dictionary!{"Type"=>"Page","Parent"=>pages,"Contents"=>stream,"Resources"=>resources,"MediaBox"=>vec![0.into(),0.into(),100.into(),100.into()]});
    doc.objects.insert(
        pages,
        dictionary! {"Type"=>"Pages","Kids"=>vec![page.into()],"Count"=>1}.into(),
    );
    let catalog = doc.add_object(dictionary! {"Type"=>"Catalog","Pages"=>pages});
    doc.trailer.set("Root", catalog);
    let mut bytes = Vec::new();
    doc.save_to(&mut bytes).unwrap();
    bytes
}
fn worker(bytes: &[u8]) -> Result<ProcessedDocument> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_devres-pdf-worker"))
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(bytes).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    serde_json::from_slice(&output.stdout).unwrap()
}
#[test]
fn isolated_worker_extracts_synthetic_text_and_sanitizes_errors() {
    let projected = worker(&synthetic_pdf()).unwrap();
    assert!(projected.text.contains("Synthetic worker fixture"));
    assert_eq!(projected.sections[0].anchor, "page-1");
    let error = worker(b"private marker: this is not a PDF").unwrap_err();
    assert_eq!(error.code, "integrity");
    assert!(!error.message.contains("private marker"));
}
