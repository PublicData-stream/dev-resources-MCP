//! Network, durable storage, and source-specific research adapters.
mod advisory;
mod archive;
mod cargo;
mod network;
mod research;
mod rfc;
mod storage;
/// Private bounded helper entrypoint; never registered as an MCP tool.
pub use advisory::audit_worker_main;
pub use network::HttpFetcher;
pub use research::Research;
pub use storage::PgBlobStore;
