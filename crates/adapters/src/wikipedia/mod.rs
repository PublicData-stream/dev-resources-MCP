//! English Wikipedia acquisition and capture-fixed research.
pub(crate) mod attribution;
pub mod cache;
pub mod corpus;
pub mod events;
pub mod processing;
pub mod research;
pub(crate) mod scope;
pub mod source;
pub use corpus::WikipediaCorpus;
pub use devres_application::wikipedia::WikipediaConfig;
