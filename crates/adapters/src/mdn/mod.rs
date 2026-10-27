//! mdn provider adapters.
pub mod corpus;
pub mod git;
pub mod index;
pub mod inventory;
pub mod processing;
pub mod research;
pub use corpus::MdnCorpus;
pub use devres_application::mdn::MdnConfig;
