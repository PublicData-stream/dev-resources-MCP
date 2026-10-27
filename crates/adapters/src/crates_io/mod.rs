//! crates io provider adapters.
pub(crate) mod corpus;
pub mod docs;
pub mod dump;
pub mod git;
pub(crate) mod index;
pub(crate) mod packages;
pub mod research;
pub use corpus::{CrateConfig, CrateCorpus};
