//! Compatibility facade for retained WHATWG processor-version-4 evidence.
//! Shared engine dispatch and serialized projections remain unchanged.
pub use crate::standards_processing::{
    MAX_INPUT, ProcessedDocument, ProcessingGap, Reference, Section, Symbol, pdf_worker_main,
    process_document, process_pdf,
};
