//! Network, durable storage, and source-specific research adapters.
mod advisory;
mod archive;
pub mod bulk;
mod cargo;
pub mod crate_docs;
pub mod crate_dump;
pub mod crate_git;
mod network;
mod research;
mod rfc;
mod rfc_corpus;
mod rfc_import;
mod rfc_index;
mod rfc_tools;
mod storage;
/// Private bounded helper entrypoint; never registered as an MCP tool.
pub use advisory::audit_worker_main;
pub use network::HttpFetcher;
pub use research::Research;
pub use rfc_corpus::{RfcConfig, RfcCorpus};
pub use storage::PgBlobStore;
