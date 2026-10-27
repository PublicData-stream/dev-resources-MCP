//! w3c provider adapters.
pub mod catalog;
pub mod corpus;
pub mod discovery;
pub mod git;
pub mod index;
pub mod inventory;
pub(crate) mod network;
pub mod processing;
pub mod research;
pub use corpus::W3cCorpus;
pub use devres_application::w3c::W3cConfig;
