# Synthetic docs.rs processing fixtures

These JSON files are original synthetic records, not downloaded package datasets
or evidence of docs.rs availability. They qualify the documented structural
projection against four actual rustdoc JSON schema revisions:

- [Format 43, Rust 1.87.0](https://github.com/rust-lang/rust/blob/1.87.0/src/rustdoc-json-types/lib.rs): no target envelope; string attributes.
- [Format 55, Rust 1.90.0](https://github.com/rust-lang/rust/blob/1.90.0/src/rustdoc-json-types/lib.rs): target envelope; structured attributes.
- [Format 56, Rust 1.91.0](https://github.com/rust-lang/rust/blob/1.91.0/src/rustdoc-json-types/lib.rs): adds `ItemKind::Attribute`; Crate/ItemEnum/type payload shapes are unchanged from format 55. The fixture includes an external attribute path summary.
- [Format 61, inspected Rust source](https://github.com/rust-lang/rust/blob/df87fa6604e33760d4703cccc777a2281bf15a2d/src/rustdoc-json-types/lib.rs): target envelope and function default instability metadata.

Rust's schema source is available under its original MIT/Apache-2.0 licenses.
Fixture values and documentation are synthetic. Their package version is 1.2.3;
the library name intentionally differs from a hypothetical package name. A
private module is reachable only through its public function reexport. Fixtures
exercise structural normalization, not complete semantic equivalence between
schema revisions. API comparisons must qualify schema compatibility separately.

An opt-in offline replay accepts the retained public `itoa@1.0.15` docs.rs gzip
through `DEVRES_DOCSRS_REPLAY_GZIP`; it never performs HTTP requests. Its fixed
SHA-256 is `f41a8139c7bcf95ddec39950b7bf43c249492793130b35d69b3d19312064a199`.
The observed target is `x86_64-unknown-linux-gnu`, format 56. This full capture is
operator-supplied and is not bundled here; the ordinary suite remains synthetic.
