# W3C validation evidence

Validation date: 2026-10-27, local Linux amd64. The implementation covers the
official TR catalog and qualified linked sources with permanent licensed evidence,
inert projections and local research. Implementation and corpus completion are
separate claims.

## Executed checks

| Check | Outcome and scope |
| --- | --- |
| `cargo fmt --all -- --check` | Passed |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | Passed, including acceptance examples |
| `cargo test --workspace --locked` | Passed: 448 tests across the workspace, including 389 adapter tests; opt-in provider/PostgreSQL tests remained ignored in this invocation |
| Focused W3C follow-up | Passed: 94 tests, with the retained-body opt-in test ignored |
| Acceptance example tests | Passed: 12 retained-acceptance tests and 3 bounded-live/root/locking tests |
| Python script tests | Passed: 122 tests |
| `cargo audit` | Passed with current advisory data |
| `cargo deny check` | Passed; existing duplicate-dependency warnings remain |
| Shell syntax, local Markdown targets, `git diff --check` | Passed |
| `scripts/test-postgres.sh` | Passed against disposable PostgreSQL, including the separate W3C durability gate |
| `scripts/test-oxibelt.sh` | Passed against the pinned OxiBelt revision with fixture HTTP and native WebTransport traffic |
| `scripts/test-minikube.sh` | Passed: NodePort TCP/UDP, CNI isolation, PVC restart and coordinated restore |
| `scripts/test-image.sh --platform linux/amd64` | Passed: production Dockerfile runtime image, startup and bounded worker fixtures on local amd64 |

The workspace run preceded the final publisher-header mapping correction. Its
focused follow-up and the hash-pinned retained-publication check exercise that
correction. Final strict lint and acceptance-example checks include the correction.
No dependencies or lockfile resolution changed. The shared parser extraction
preserves WHATWG processor version 4 and seven independently pinned original
projection hashes.

The PostgreSQL gate applies schema 6 then migrates to schema 7, preserving existing
capture/source identities, hashes, bodies, timestamps, heads and WHATWG evidence.
It tests older chapter dependencies and rejects mismatched manifests, origins,
identities and dependency timestamps without replacing the approved default.

HTTP and native WebTransport fixture acceptance covers revisions `2026-07-28` and
`2025-11-25`, W3C text/source/bytes/symbol/resource reads, coordinated restart and
restore. It uses seeded local evidence and does not contact providers. Independent
ordinary-agent reviews covered MCP/API, upstream/storage and security boundaries;
identified findings were repaired and reviewed again. This is not a human GitHub
approval or a hosted security-service scan.

## Bounded provider evidence

The completed fixed-record receipt distinguishes fresh requests from retained
licensed evidence. Its last invocation made three requests: two W3C API requests
for retired Canvas 2D metadata and one GitHub smart-HTTPS advertisement. Persisted
budget accounting reached 20 W3C attempts (including conservative reservations
from earlier failed checks) and one GitHub attempt; no further provider checks ran.

- Retained CSS Color 4 publication:
  `https://www.w3.org/TR/2026/CRD-css-color-4-20261026/`.
  Its 1,049,399 bytes have SHA-256
  `a5cef4674c085a5b568773e85affceb20a3c0d121dff371f3dd555fd51ac02f4`.
  Offline license qualification and processing produced 148 sections, 332 symbols,
  2,316 references and the publisher's exact GitHub editor mapping.
- The CSS replay does not claim a fresh latest-edition check or a known upstream
  validation timestamp. The receipt labels local file time separately and states
  that the original API response bytes were not retained. It preserves explicit
  generated-anchor and unresolved-source-reference coverage gaps.
- Canvas API metadata identified `2dcontext` edition `20210128` as `Retired`.
- The qualified `w3c/csswg-drafts` repository returned a successful 191-byte HTTPS
  advertisement response containing the `git-upload-pack` marker. The bounded
  probe checks that marker, not complete packet framing, licensed pack acquisition
  or full ancestry.

Bodies were retained only after license approval. Earlier failed qualification
attempts retained diagnostic metadata rather than publication bytes. Synthetic
fixtures and the opt-in hash-pinned retained-body test remain distinct.

## Kubernetes and image acceptance

The final disposable cluster run passed on Kubernetes 1.37.0 with Calico and
containerd 2.3.4. It verified public NodePort TCP/UDP, positive trusted mTLS/transport
reads, denial of untrusted backend TCP/UDP and private-health access, seeded W3C
reads after PVC restart, and coordinated PostgreSQL/blob restore.

The production Dockerfile also built and passed its runtime image/startup/worker
fixtures locally for Linux amd64. This is working-tree image evidence, not a
published release artifact or hosted CI result.

The initial `/tmp` FUSE filesystem could not support nested image capabilities.
A task-owned ext4 loop filesystem below `/tmp` supplied the required capabilities.
An earlier restrictive daemon umask caused failed SSH and non-root fixture startup;
the final retry used `umask 022` and restored ordinary executable permissions on
host fixture build artifacts. No SSH, container-user or network-policy restrictions
were weakened. These environmental failures were retained separately from the
successful final gate logs.

## Separate operational acceptance

Whole-corpus acquisition, all historical ancestry, complete frozen-corpus processing,
hosted native amd64/arm64 CI, native client UI support, registry publication and
production deployment were not executed. Use the explicit retained commands in
[Operations](operations.md#w3c-validation-and-retained-acceptance) for current/full
corpus acquisition, frozen processing resume and linked recovery. A license block,
missing mapping, unavailable edition or processing gap remains incomplete coverage.

All test databases, daemon state, cluster state and retained probe evidence were
located below `/tmp`. Host Rust build artifacts used `/buildcache/rust/target`.
The shared Docker daemons and configured operator cluster were not modified.
