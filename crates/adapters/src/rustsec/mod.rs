//! rustsec provider adapters.
pub(crate) mod advisory;
pub(crate) mod corpus;
pub mod git;
pub(crate) mod osv;
pub(crate) mod research;
pub use advisory::audit_worker_main;
pub use corpus::AdvisoryCorpus;
pub use devres_application::advisory::RustSecConfig;
