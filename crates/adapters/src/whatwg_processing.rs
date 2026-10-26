//! Bounded, inert projections of retained WHATWG publications and repository inputs.
use devres_domain::{Error, Result};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

mod html;
mod markdown;
mod pdf;
pub use pdf::{pdf_worker_main, process_pdf};

pub const MAX_INPUT: usize = 64 * 1024 * 1024;
const MAX_ITEMS: usize = 100_000;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessingGap {
    pub code: String,
    pub message: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Section {
    pub anchor: String,
    pub title: String,
    pub text: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Symbol {
    pub kind: String,
    pub name: String,
    pub anchor: String,
    pub text: String,
    pub scope: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Reference {
    pub source_anchor: String,
    pub target: String,
    pub label: String,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProcessedDocument {
    pub format: String,
    pub title: String,
    pub text: String,
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
    pub references: Vec<Reference>,
    pub gaps: Vec<ProcessingGap>,
}
impl ProcessedDocument {
    fn gap(&mut self, code: &str, message: &str) {
        if !self.gaps.iter().any(|gap| gap.code == code) {
            self.gaps.push(ProcessingGap {
                code: code.into(),
                message: message.into(),
            });
        }
    }
    fn validate(&self) -> Result<()> {
        self.validate_with_limit(MAX_INPUT * 3)
    }
    fn validate_with_limit(&self, max_bytes: usize) -> Result<()> {
        let bytes = self
            .text
            .len()
            .saturating_add(
                self.sections
                    .iter()
                    .map(|s| s.anchor.len() + s.title.len() + s.text.len())
                    .sum::<usize>(),
            )
            .saturating_add(
                self.symbols
                    .iter()
                    .map(|s| {
                        s.name.len()
                            + s.anchor.len()
                            + s.text.len()
                            + s.scope.as_deref().map_or(0, str::len)
                    })
                    .sum::<usize>(),
            )
            .saturating_add(
                self.references
                    .iter()
                    .map(|r| r.source_anchor.len() + r.target.len() + r.label.len())
                    .sum::<usize>(),
            );
        if bytes > max_bytes
            || self.sections.len() > MAX_ITEMS
            || self.symbols.len() > MAX_ITEMS
            || self.references.len() > MAX_ITEMS
        {
            return Err(limit());
        }
        Ok(())
    }
}
struct Budget {
    deadline: Instant,
    cancel: CancellationToken,
}
impl Budget {
    fn new(cancel: CancellationToken) -> Self {
        Self {
            deadline: Instant::now() + Duration::from_secs(15),
            cancel,
        }
    }
    fn check(&self) -> Result<()> {
        if self.cancel.is_cancelled() {
            return Err(Error::new("cancelled", "WHATWG processing canceled."));
        }
        if Instant::now() >= self.deadline {
            return Err(limit());
        }
        Ok(())
    }
}
fn limit() -> Error {
    Error::capacity("WHATWG processing bounds exceeded.")
}
fn malformed() -> Error {
    Error::integrity("Malformed WHATWG source representation.")
}
fn safe_target(target: &str) -> bool {
    if target.is_empty()
        || target.len() > 4096
        || target.chars().any(char::is_control)
        || target.contains('\\')
    {
        return false;
    }
    if target.starts_with("//") {
        return false;
    }
    match url::Url::parse(target) {
        Ok(url) => {
            matches!(url.scheme(), "http" | "https")
                && url.username().is_empty()
                && url.password().is_none()
        }
        Err(url::ParseError::RelativeUrlWithoutBase) => !target.split('/').any(|part| part == ".."),
        Err(_) => false,
    }
}

/// Pure parser. It never follows links, evaluates templates, or runs repository build tools.
pub fn process_document(
    path: &str,
    bytes: &[u8],
    cancel: CancellationToken,
) -> Result<ProcessedDocument> {
    if bytes.len() > MAX_INPUT || path.len() > 4096 {
        return Err(limit());
    }
    let budget = Budget::new(cancel);
    budget.check()?;
    let source = std::str::from_utf8(bytes).map_err(|_| malformed())?;
    if source.contains('\0') {
        return Err(malformed());
    }
    let lower = path.to_ascii_lowercase();
    let basename = lower.rsplit('/').next().unwrap_or(&lower);
    let mut output = if lower.ends_with(".md") || lower.ends_with(".markdown") {
        markdown::project(source, &budget)?
    } else if lower.ends_with(".bs") {
        html::project_bikeshed(source, &budget)?
    } else if lower.ends_with(".html")
        || lower.ends_with(".htm")
        || lower.ends_with(".wattsi")
        || path.rsplit('/').next() == Some("source")
    {
        html::project(source, &budget)?
    } else if lower.ends_with(".txt")
        || lower.ends_with(".idl")
        || ["license", "copying", "notice"]
            .iter()
            .any(|prefix| basename.starts_with(prefix))
    {
        let mut document = ProcessedDocument {
            title: basename.into(),
            text: source.into(),
            sections: vec![Section {
                anchor: "document".into(),
                title: basename.into(),
                text: source.into(),
            }],
            ..Default::default()
        };
        if lower.ends_with(".idl") {
            for (name, text) in html::idl_declarations(source, &budget)? {
                document.symbols.push(Symbol {
                    kind: "idl".into(),
                    name,
                    anchor: "document".into(),
                    text,
                    scope: None,
                });
            }
        }
        document
    } else {
        return Err(Error::invalid(
            "Unsupported WHATWG projection format; retained raw evidence remains readable.",
        ));
    };
    output.format = if lower.ends_with(".bs") {
        "bikeshed"
    } else if lower.ends_with(".md") || lower.ends_with(".markdown") {
        "markdown"
    } else if path.rsplit('/').next() == Some("source") || lower.ends_with(".wattsi") {
        "whatwg-source"
    } else if lower.ends_with(".idl") {
        "idl"
    } else if lower.ends_with(".txt")
        || ["license", "copying", "notice"]
            .iter()
            .any(|prefix| basename.starts_with(prefix))
    {
        "text"
    } else {
        "html"
    }
    .into();
    if (output.format == "bikeshed" || output.format == "whatwg-source")
        && [
            "{{",
            "[[",
            "[=",
            "[$",
            "<include",
            "<!--INSERT",
            "<!--BOILERPLATE",
        ]
        .iter()
        .any(|marker| source.contains(marker))
    {
        output.gap("unexpanded_source_construct", "Generated source constructs are retained as inert text; rendered expansion is unasserted.");
    }
    if output.text.trim() == "to be deployed" || output.text.trim().is_empty() {
        output.gap(
            "publication_unavailable",
            "The captured representation contains no published specification content.",
        );
    }
    budget.check()?;
    output.validate()?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn aggregate_output_budget_counts_scope_utf8_bytes_at_the_exact_bound() {
        let mut doc = ProcessedDocument {
            text: "body".into(),
            symbols: vec![Symbol {
                kind: "idl".into(),
                name: "Example".into(),
                anchor: "published-id".into(),
                text: "interface Example {};".into(),
                scope: Some("Scope-界".into()),
            }],
            ..Default::default()
        };
        let symbol = &doc.symbols[0];
        let exact = doc.text.len()
            + symbol.name.len()
            + symbol.anchor.len()
            + symbol.text.len()
            + symbol.scope.as_ref().expect("scope").len();
        doc.validate_with_limit(exact)
            .expect("exact UTF-8 byte bound");
        assert_eq!(
            doc.validate_with_limit(exact - 1)
                .expect_err("scope consumes the budget")
                .code,
            "capacity"
        );
        doc.symbols[0].scope = None;
        doc.validate_with_limit(exact - 1)
            .expect("the omitted scope is not charged");
    }
    #[test]
    fn rendered_semantics_and_inert_assets() {
        let doc=process_document("index.html",br#"<head><title>ignored</title></head><body><h1 id="standard">Standard &amp; API</h1><h2 id="events">Events</h2><p><dfn id="event" data-dfn-for="Window">Event</dfn> is defined.</p><pre class="idl">interface Event {};</pre><a href="https://dom.spec.whatwg.org/#event">the event</a><script>secret()</script><iframe>hidden</iframe>"#,CancellationToken::new()).unwrap();
        assert_eq!(doc.title, "Standard & API");
        assert!(
            doc.sections
                .iter()
                .any(|s| s.anchor == "events" && s.text.contains("is defined"))
        );
        assert!(doc.symbols.iter().any(|s| s.kind == "definition"
            && s.name == "Event"
            && s.scope.as_deref() == Some("Window")));
        assert!(doc.symbols.iter().any(|s| s.kind == "idl"));
        assert!(doc.references.iter().any(|r| r.label == "the event"));
        assert!(!doc.text.contains("secret") && !doc.text.contains("hidden"));
    }
    #[test]
    fn unavailable_and_generated_constructs_are_explicit() {
        let doc = process_document(
            "source",
            b"<h1>to be deployed</h1>",
            CancellationToken::new(),
        )
        .unwrap();
        assert!(doc.gaps.iter().any(|g| g.code == "publication_unavailable"));
        let doc = process_document(
            "spec.bs",
            b"<h2>Title</h2><p>[=generated term=]",
            CancellationToken::new(),
        )
        .unwrap();
        assert!(
            doc.gaps
                .iter()
                .any(|g| g.code == "unexpanded_source_construct")
        );
    }
    #[test]
    fn cancellation_and_bad_input_fail_closed() {
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert_eq!(
            process_document("a.html", b"<p>hello", cancel)
                .unwrap_err()
                .code,
            "cancelled"
        );
        assert!(process_document("a.html", b"\xff", CancellationToken::new()).is_err());
        let input = format!("{}x{}", "<div>".repeat(300), "</div>".repeat(300));
        assert_eq!(
            process_document("a.html", input.as_bytes(), CancellationToken::new())
                .unwrap_err()
                .code,
            "capacity"
        );
    }
    #[test]
    fn historical_wattsi_and_original_notices_remain_readable() {
        let doc = process_document(
            "review-drafts/2026-07.wattsi",
            b"<h2 id=history>History</h2><dfn algorithm id=fire>fire an event</dfn>",
            CancellationToken::new(),
        )
        .unwrap();
        assert_eq!(doc.format, "whatwg-source");
        assert!(
            doc.symbols
                .iter()
                .any(|symbol| symbol.kind == "algorithm" && symbol.name == "fire an event")
        );
        let source = b"Copyright Example\nThis <script>text()</script> is original notice text.\n";
        let notice = process_document("LICENSE", source, CancellationToken::new()).unwrap();
        assert_eq!(notice.text.as_bytes(), source);
        let idl = process_document(
            "interfaces.idl",
            b"interface Example {};",
            CancellationToken::new(),
        )
        .unwrap();
        assert_eq!(idl.symbols[0].name, "Example");
    }
}
