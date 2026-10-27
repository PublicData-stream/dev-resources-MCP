//! Legacy imports remain usable while callers adopt provider namespaces.
use devres_adapters as adapters;

macro_rules! same_type {
    ($legacy:ty, $canonical:ty) => {
        let _: Option<$legacy> = None::<$canonical>;
    };
}

fn same_item<T>(_: T, _: T) {}

#[test]
fn legacy_provider_modules_resolve_to_the_canonical_items() {
    same_type!(
        adapters::advisory_git::AdvisoryHistory,
        adapters::rustsec::git::AdvisoryHistory
    );
    same_type!(
        adapters::chromium_corpus::ChromiumCorpus,
        adapters::chromium::corpus::ChromiumCorpus
    );
    same_type!(
        adapters::chromium_index::ChromiumIndex,
        adapters::chromium::index::ChromiumIndex
    );
    same_item(
        adapters::chromium_inventory::digest,
        adapters::chromium::inventory::digest,
    );
    same_type!(
        adapters::chromium_processing::ProcessedDocument,
        adapters::chromium::processing::ProcessedDocument
    );
    same_type!(
        adapters::chromium_research::ChromiumResearch,
        adapters::chromium::research::ChromiumResearch
    );
    same_type!(
        adapters::chromium_source::ChromiumSource,
        adapters::chromium::source::ChromiumSource
    );
    same_type!(
        adapters::crate_docs::ProcessingBudget,
        adapters::crates_io::docs::ProcessingBudget
    );
    same_item(
        adapters::crate_dump::import_dump,
        adapters::crates_io::dump::import_dump,
    );
    same_type!(
        adapters::crate_git::GitRegistry,
        adapters::crates_io::git::GitRegistry
    );
    same_type!(
        adapters::crate_research::CrateResearch,
        adapters::crates_io::research::CrateResearch
    );
    same_type!(
        adapters::mdn_corpus::MdnCorpus,
        adapters::mdn::corpus::MdnCorpus
    );
    same_type!(adapters::mdn_git::MdnGit, adapters::mdn::git::MdnGit);
    same_type!(
        adapters::mdn_index::MdnIndex,
        adapters::mdn::index::MdnIndex
    );
    same_item(
        adapters::mdn_inventory::digest,
        adapters::mdn::inventory::digest,
    );
    same_type!(
        adapters::mdn_processing::ProcessedDocument,
        adapters::mdn::processing::ProcessedDocument
    );
    same_type!(
        adapters::mdn_research::MdnResearch,
        adapters::mdn::research::MdnResearch
    );
    same_item(adapters::npm_audit::audit, adapters::npm::audit::audit);
    same_type!(
        adapters::npm_corpus::NpmCorpus,
        adapters::npm::corpus::NpmCorpus
    );
    same_type!(
        adapters::npm_index::NpmIndex,
        adapters::npm::index::NpmIndex
    );
    same_item(
        adapters::npm_processing::parse_packument,
        adapters::npm::processing::parse_packument,
    );
    same_type!(
        adapters::npm_research::NpmResearch,
        adapters::npm::research::NpmResearch
    );
    same_type!(
        adapters::npm_source::Operation,
        adapters::npm::source::Operation
    );
    same_type!(
        adapters::w3c_catalog::PublicationUrl,
        adapters::w3c::catalog::PublicationUrl
    );
    same_type!(
        adapters::w3c_corpus::W3cCorpus,
        adapters::w3c::corpus::W3cCorpus
    );
    same_type!(
        adapters::w3c_discovery::DiscoveryOperation,
        adapters::w3c::discovery::DiscoveryOperation
    );
    same_type!(adapters::w3c_git::W3cGit, adapters::w3c::git::W3cGit);
    same_type!(
        adapters::w3c_index::W3cIndex,
        adapters::w3c::index::W3cIndex
    );
    same_item(
        adapters::w3c_inventory::digest,
        adapters::w3c::inventory::digest,
    );
    same_type!(
        adapters::w3c_processing::ProcessedDocument,
        adapters::w3c::processing::ProcessedDocument
    );
    same_type!(
        adapters::w3c_research::W3cResearch,
        adapters::w3c::research::W3cResearch
    );
    same_type!(
        adapters::whatwg_catalog::PublicationUrl,
        adapters::whatwg::catalog::PublicationUrl
    );
    same_type!(
        adapters::whatwg_corpus::WhatwgCorpus,
        adapters::whatwg::corpus::WhatwgCorpus
    );
    same_type!(
        adapters::whatwg_git::WhatwgGit,
        adapters::whatwg::git::WhatwgGit
    );
    same_type!(
        adapters::whatwg_index::WhatwgIndex,
        adapters::whatwg::index::WhatwgIndex
    );
    same_item(
        adapters::whatwg_inventory::digest,
        adapters::whatwg::inventory::digest,
    );
    same_type!(
        adapters::whatwg_processing::ProcessedDocument,
        adapters::whatwg::processing::ProcessedDocument
    );
    same_type!(
        adapters::whatwg_research::WhatwgResearch,
        adapters::whatwg::research::WhatwgResearch
    );
}

#[test]
fn top_level_provider_exports_keep_the_same_types_and_worker() {
    same_type!(adapters::AdvisoryCorpus, adapters::rustsec::AdvisoryCorpus);
    same_type!(adapters::RustSecConfig, adapters::rustsec::RustSecConfig);
    same_type!(adapters::CrateCorpus, adapters::crates_io::CrateCorpus);
    same_type!(adapters::CrateConfig, adapters::crates_io::CrateConfig);
    same_type!(adapters::RfcCorpus, adapters::rfc::RfcCorpus);
    same_type!(adapters::RfcConfig, adapters::rfc::RfcConfig);
    same_type!(adapters::MdnCorpus, adapters::mdn::MdnCorpus);
    same_type!(adapters::MdnConfig, adapters::mdn::MdnConfig);
    same_type!(adapters::NpmCorpus, adapters::npm::NpmCorpus);
    same_type!(adapters::NpmConfig, adapters::npm::NpmConfig);
    same_type!(adapters::W3cCorpus, adapters::w3c::W3cCorpus);
    same_type!(adapters::W3cConfig, adapters::w3c::W3cConfig);
    same_type!(adapters::WhatwgCorpus, adapters::whatwg::WhatwgCorpus);
    same_type!(adapters::WhatwgConfig, adapters::whatwg::WhatwgConfig);
    same_type!(adapters::ChromiumCorpus, adapters::chromium::ChromiumCorpus);
    same_type!(adapters::ChromiumConfig, adapters::chromium::ChromiumConfig);
    same_item(
        adapters::audit_worker_main,
        adapters::rustsec::audit_worker_main,
    );
}

#[test]
fn existing_npm_package_entrypoints_remain_available() {
    let _: Option<adapters::npm::NpmPackages> = None;
    let _ = adapters::npm::NpmPackages::new;
    let _ = adapters::npm::archive_key;
    let _ = adapters::npm::source_input_from_uri;
    let _ = adapters::npm::schemas;
}
