//! whatwg provider adapters.
pub mod catalog;
pub mod corpus;
pub mod git;
pub mod index;
pub mod inventory;
pub mod processing;
pub mod research;
pub use corpus::WhatwgCorpus;
pub use devres_application::whatwg::WhatwgConfig;
