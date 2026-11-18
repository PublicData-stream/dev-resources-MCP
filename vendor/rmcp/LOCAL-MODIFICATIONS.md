# Local patches for rmcp 3.9.0

Upstream: modelcontextprotocol/rust-sdk, crates.io rmcp 3.9.0. The packaged
`.cargo_vcs_info.json` records the upstream revision. Original source and its
LICENSE remain Apache-2.0; they have not been relicensed.

Published archive SHA-256:
`d24a7e92f4bcaa36b97fa93c4fa7ca8f3e669eced949345b3462dba333c7f909`.
Packaged upstream revision: `5596a8a0bba2a1ec5519cc855cdadf23e4dcecdc`,
`crates/rmcp`. The archive hash matches the pre-patch registry Cargo.lock entry.

First-party additions and modifications are AGPL-3.0-only. The transport patch
adds an optional body-budget codec, explicit config plumbing, charged request-body
handoff, direct bounded SSE encoding, and budget-aware JSON/error serialization.
The modified distribution declares `Apache-2.0 AND AGPL-3.0-only`. The transport
hook is absent by default.

The timestamp patch removes the direct Chrono dependency and the Schemars Chrono
integration from the active manifest. It uses Jiff for UTC timestamps and retains
the wire representation and timeout error text. The typed annotation helpers now
take `jiff::Timestamp`. The packaged `Cargo.toml.orig` and `Cargo.lock` are retained
as upstream evidence. The root workspace resolves the active manifest. The
upstream optional `auth` feature can still bring Chrono through OAuth2 when built
outside the root workspace's selected features.

No inspected package code is executed. Dependency resolution remains pinned to
rmcp 3.9.0. One upstream test-comment trailing space was removed for repository
whitespace admission.
