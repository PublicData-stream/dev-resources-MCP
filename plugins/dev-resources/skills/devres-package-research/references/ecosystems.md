# Ecosystem-specific evidence

Read this reference for source, API and release comparison work. Tool discovery
defines accepted arguments and modes; do not infer fields from tool names.

## Rust

`crate.metadata` reports declared dependencies, features, yanked status and the
published archive checksum. Source tools bind sparse-index metadata and verified
archive captures. `crate.document_get` can retrieve captured source, manifest,
README, license or rustdoc text. Rustdoc target selection must be unambiguous.

`crate.api_get` selects an exact public path; retain normalized signatures,
relationships, target and per-build provenance. Capture-local API IDs are not
stable cross-build identities. API comparisons require qualified coverage on
both sides and compatible projection schemas. Unsupported rustdoc JSON remains
retained raw evidence rather than a fabricated API inventory.

Local crate research defaults to all captured versions. Specify exact release
filters when the question concerns one release. A declared MSRV filter does not
establish a successful build on that compiler. Captured reverse dependencies are
package-name references rather than solved version constraints.

## npm

The operator catalog starts empty. `npm.search`, `npm.metadata` and verified
source retrieval may contact the public registry, but do not enroll packages in
that catalog. Local research and `npm.history`/`npm.snapshots` read retained
observations. Missing local evidence can coexist with successful exact-release
metadata/source retrieval.

`npm.contract_get` exposes manifest contracts, exports/imports and retained type
declarations. Preserve condition ordering, patterns, null targets, aliases and
optional/peer/dev distinctions. Literal paths resolve only to captured files;
external imports stay inert. Declarations and contract text do not establish
runtime behavior. Preserve scoped names and the real identity behind aliases.

Source tools verify declared distribution integrity before inspection; a retained
content hash is separate from distribution-verification assurance. Unsupported
or mismatching integrity is not permission to fall back to a weaker algorithm.

## Comparing retained evidence

Fix both releases and their snapshots/captures. Distinguish source changes,
normalized API/contract changes and absent processing. A retained archive does
not imply successful projection or complete indexing. Historical records cannot
reconstruct releases already removed before observation. Historical selection
does not imply current freshness; report returned validation times and gaps.
