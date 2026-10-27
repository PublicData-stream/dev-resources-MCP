//! npm provider adapters.
pub mod audit;
pub mod corpus;
pub mod index;
pub(crate) mod lockfile;
mod packages;
pub mod processing;
pub mod research;
pub mod source;
pub use corpus::NpmCorpus;
pub use devres_application::npm::NpmConfig;
pub use packages::*;
