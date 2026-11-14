//! Anonymous developer research MCP over Streamable HTTP and custom WebTransport.
//! Transports share one immutable registry and application service instance.
pub mod config;
mod edge_mtls;
pub mod endpoint;
pub mod framing;
pub mod handler;
pub mod http;
mod http_budget;
mod http_status;
pub mod progress;
mod rate_limit;
pub mod registry;
mod timed_io;
pub mod webtransport;
pub mod writer_rpc;

/// Local diagnostic errors must never be serialized as public tool failures.
pub type ServerError = Box<dyn std::error::Error + Send + Sync>;
pub use endpoint::ServerBuilder;
pub use registry::ToolRegistry;
