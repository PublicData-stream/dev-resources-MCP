# Local transport patch for rmcp 3.9.0

Upstream: modelcontextprotocol/rust-sdk, crates.io rmcp 3.9.0. The packaged
`.cargo_vcs_info.json` records the upstream revision. Original source and its
LICENSE remain Apache-2.0; they have not been relicensed.

Published archive SHA-256:
`d24a7e92f4bcaa36b97fa93c4fa7ca8f3e669eced949345b3462dba333c7f909`.
Packaged upstream revision: `5596a8a0bba2a1ec5519cc855cdadf23e4dcecdc`,
`crates/rmcp`. The archive hash matches the pre-patch registry Cargo.lock entry.

First-party additions and modifications are AGPL-3.0-only: the optional body-budget
codec, explicit config plumbing, charged request-body handoff, direct bounded SSE
encoding, and budget-aware JSON/error serialization. The modified distribution
therefore declares `Apache-2.0 AND AGPL-3.0-only`. The hook is absent by default;
upstream protocol/session behavior remains unchanged.

Only transport files, exports and package license metadata are modified. No inspected
package code is executed. Dependency resolution remains pinned to rmcp 3.9.0.
One upstream test-comment trailing space was removed for repository whitespace
admission; its test behavior is unchanged.
