//! PDF parsing runs only in a bounded, fixed sibling process, without inherited credentials.
use super::{MAX_INPUT, ProcessedDocument, Section, limit, malformed};
use devres_domain::{Error, Result};
use std::{
    io::{Read, Write},
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

const MAX_OUTPUT: usize = MAX_INPUT * 3;
static WORKERS: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();

/// Extract inert page text using the installed matching first-party helper.
pub async fn process_pdf(bytes: &[u8], cancel: CancellationToken) -> Result<ProcessedDocument> {
    if bytes.len() > MAX_INPUT {
        return Err(limit());
    }
    if cancel.is_cancelled() {
        return Err(Error::new("cancelled", "WHATWG PDF processing canceled."));
    }
    let _permit = WORKERS
        .get_or_init(|| Arc::new(tokio::sync::Semaphore::new(1)))
        .clone()
        .try_acquire_owned()
        .map_err(|_| limit())?;
    let executable = std::env::current_exe()
        .map_err(|_| Error::unavailable("PDF worker location unavailable."))?;
    let executable = executable
        .parent()
        .ok_or_else(|| Error::unavailable("PDF worker location unavailable."))?
        .join("devres-pdf-worker");
    let mut child = tokio::process::Command::new(executable)
        .env_clear()
        .current_dir("/")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| {
            Error::unavailable("PDF worker unavailable; install the matching sibling executable.")
        })?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| Error::unavailable("PDF worker input unavailable."))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::unavailable("PDF worker output unavailable."))?;
    let operation = async {
        stdin
            .write_all(bytes)
            .await
            .map_err(|_| Error::unavailable("PDF worker input failed."))?;
        stdin
            .shutdown()
            .await
            .map_err(|_| Error::unavailable("PDF worker input failed."))?;
        drop(stdin);
        let mut output = Vec::new();
        stdout
            .take(MAX_OUTPUT as u64 + 1)
            .read_to_end(&mut output)
            .await
            .map_err(|_| Error::unavailable("PDF worker output failed."))?;
        if output.len() > MAX_OUTPUT {
            return Err(limit());
        }
        let status = child
            .wait()
            .await
            .map_err(|_| Error::unavailable("PDF worker wait failed."))?;
        if !status.success() {
            return Err(Error::unavailable(
                "PDF worker exceeded its bounds or failed.",
            ));
        }
        let result: Result<ProcessedDocument> = serde_json::from_slice(&output)
            .map_err(|_| Error::integrity("PDF worker returned invalid output."))?;
        let result = result?;
        result.validate()?;
        Ok(result)
    };
    let result = tokio::select! {
        biased;
        _=cancel.cancelled()=>Err(Error::new("cancelled","WHATWG PDF processing canceled.")),
        result=tokio::time::timeout(Duration::from_secs(60),operation)=>match result {
            Ok(result)=>result,
            Err(_)=>Err(Error::capacity("PDF worker deadline exceeded.")),
        },
    };
    if result.is_err() {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
    result
}

fn extract(bytes: &[u8]) -> Result<ProcessedDocument> {
    if !bytes.starts_with(b"%PDF-") {
        return Err(malformed());
    }
    let document = lopdf::Document::load_mem_with_options(
        bytes,
        lopdf::LoadOptions::with_max_decompressed_size(16 * 1024 * 1024),
    )
    .map_err(|_| malformed())?;
    if document.is_encrypted() {
        return Err(Error::invalid(
            "Encrypted PDF projection is unsupported; original bytes remain retained.",
        ));
    }
    if document.objects.len() > 1_000_000 {
        return Err(limit());
    }
    let pages = document.get_pages();
    if pages.len() > 20_000 {
        return Err(limit());
    }
    let mut result = ProcessedDocument {
        format: "pdf".into(),
        title: "PDF publication".into(),
        ..Default::default()
    };
    for page in pages.keys() {
        let text = document
            .extract_text_with_limit(&[*page], 4 * 1024 * 1024)
            .map_err(|_| {
                Error::integrity("PDF page text extraction failed; original bytes remain retained.")
            })?;
        if result.text.len().saturating_add(text.len() + 1) > MAX_INPUT {
            return Err(limit());
        }
        result.text.push_str(&text);
        result.text.push('\n');
        result.sections.push(Section {
            anchor: format!("page-{page}"),
            title: format!("Page {page}"),
            text,
        });
    }
    result.gap("pdf_text_only","PDF projection preserves extracted page text; layout, images, and glyph decoding completeness are unasserted.");
    if result.text.trim().is_empty() {
        result.gap(
            "pdf_text_unavailable",
            "No supported textual content was decoded; original PDF bytes remain retained.",
        );
    }
    result.validate()?;
    Ok(result)
}
struct BoundedOutput(Vec<u8>);
impl Write for BoundedOutput {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.0.len().saturating_add(bytes.len()) > MAX_OUTPUT {
            return Err(std::io::Error::other("PDF result bound exceeded"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
/// Resource limits are established before any untrusted bytes are read or parsed.
pub fn pdf_worker_main() -> std::io::Result<()> {
    use nix::sys::resource::{Resource, setrlimit};
    setrlimit(Resource::RLIMIT_AS, 1024 * 1024 * 1024, 1024 * 1024 * 1024)
        .map_err(std::io::Error::other)?;
    setrlimit(Resource::RLIMIT_CPU, 55, 60).map_err(std::io::Error::other)?;
    setrlimit(Resource::RLIMIT_CORE, 0, 0).map_err(std::io::Error::other)?;
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(MAX_INPUT as u64 + 1)
        .read_to_end(&mut bytes)?;
    let result = if bytes.len() > MAX_INPUT {
        Err(limit())
    } else {
        extract(&bytes)
    };
    let mut output = BoundedOutput(Vec::new());
    if serde_json::to_writer(&mut output, &result).is_err() {
        output.0.clear();
        let failure: Result<ProcessedDocument> = Err(limit());
        serde_json::to_writer(&mut output, &failure).map_err(std::io::Error::other)?;
    }
    std::io::stdout().lock().write_all(&output.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_pdf_is_typed_and_sanitized() {
        let error = extract(b"private input is not a pdf").unwrap_err();
        assert_eq!(error.code, "integrity");
        assert!(!error.message.contains("private input"));
    }
    #[test]
    fn synthetic_pdf_page_extracts_as_inert_text() {
        use lopdf::{
            Document, Object, Stream,
            content::{Content, Operation},
            dictionary,
        };
        let mut doc = Document::with_version("1.5");
        let pages = doc.new_object_id();
        let font =
            doc.add_object(dictionary! {"Type"=>"Font","Subtype"=>"Type1","BaseFont"=>"Helvetica"});
        let resources = doc.add_object(dictionary! {"Font"=>dictionary!{"F1"=>font}});
        let content = Content {
            operations: vec![
                Operation::new("BT", vec![]),
                Operation::new("Tf", vec!["F1".into(), 12.into()]),
                Operation::new("Td", vec![10.into(), 10.into()]),
                Operation::new(
                    "Tj",
                    vec![Object::string_literal("Inert specification text")],
                ),
                Operation::new("ET", vec![]),
            ],
        }
        .encode()
        .unwrap();
        let content = doc.add_object(Stream::new(dictionary! {}, content));
        let page=doc.add_object(dictionary!{"Type"=>"Page","Parent"=>pages,"Contents"=>content,"Resources"=>resources,"MediaBox"=>vec![0.into(),0.into(),595.into(),842.into()]});
        doc.objects.insert(
            pages,
            Object::Dictionary(dictionary! {"Type"=>"Pages","Kids"=>vec![page.into()],"Count"=>1}),
        );
        let catalog = doc.add_object(dictionary! {"Type"=>"Catalog","Pages"=>pages});
        doc.trailer.set("Root", catalog);
        let mut bytes = Vec::new();
        doc.save_to(&mut bytes).unwrap();
        let result = extract(&bytes).unwrap();
        assert_eq!(result.title, "PDF publication");
        assert!(result.text.contains("Inert specification text"));
        assert_eq!(result.sections[0].anchor, "page-1");
        assert!(result.gaps.iter().any(|gap| gap.code == "pdf_text_only"));
    }
}
