# npm implementation validation

Observed on 2026-10-27. This records acceptance of the [npm module](npm.md),
separately from full catalog acquisition, historical backfill, hosted CI,
publication, and production use.

## Local checks

| Check | Result |
| --- | --- |
| Rust 1.99.1 formatting and strict workspace/all-target Clippy | Passed |
| Locked workspace tests, one test thread | 535 passed, 18 opt-in tests ignored |
| npm live/retained probe tests | 5 passed |
| Python harness tests | 136 passed |
| Current `cargo audit` | Passed; 476 resolved dependencies scanned |
| `cargo deny check` | Advisories, bans, licenses, and sources passed; existing duplicate-version warnings remain |
| Real PostgreSQL persistence | Passed, including schema 9, restart, immutable publication, and atomic index-marker failure recovery |
| Pinned OxiBelt Docker acceptance | HTTP/WebTransport checks passed for MCP revisions 2025-11-25 and 2026-07-28 |
| Disposable minikube acceptance | NodePort TCP/UDP, CNI isolation, PVC restart, and coordinated restore passed |
| Native Linux amd64 runtime image | Platform identity, build, startup, and Cargo/npm isolated audit-worker fixture checks passed |

Fixtures cover scoped and aliased packages, capture pinning, distribution integrity,
inert archive inspection, manifest contracts, request-only npm/pnpm/Yarn auditing,
registry attribution, advisory boundaries, cancellation, immutable history,
resumable collection, and offline index rebuilding. Transport gates use synthetic
public captures with collectors paused; they do not send fixture identities to
providers. Invalid lockfile responses preserve each MCP revision's existing error
mapping without reflecting supplied text.

The default workspace run skips opt-in database, retained-capture, and live-source
tests. Database acceptance was run separately through `scripts/test-postgres.sh`;
unrelated providers' live and operator-capture probes were not requested.

Earlier concurrent runs encountered existing parser/worker deadlines under heavy
temporary-filesystem I/O. Final gates ran sequentially without increasing deadlines.
The existing MDN prepared-checkpoint fixture now allows its documented bounded
processing yields before requiring a prepared snapshot; its checkpoint and
no-publication assertions remain. Migration fixtures account for the new schema
when simulating older databases. No MDN production behavior changed.

Cargo output used `/buildcache/rust/target`. All fixture, Docker, minikube, and
test-generated state used owned directories below `/tmp`. The isolated Docker
daemon used a task-owned ext4 image below `/tmp`; the configured operator daemon
and cluster profiles were not reused. The tracked Dockerfile now uses the required
Cargo target path; its runtime instructions are unchanged.

## Bounded provider evidence

The opt-in npm live smoke retained two fixed package releases and the fixed OSV
npm export. It consumed four registry attempts and one OSV attempt, including
retries, against a ceiling of 20 attempts per provider. Both archives passed
SHA-512 SRI verification and produced four members and four documents without
projection gaps for these selected releases.

| Fixed record | Retained archive or record SHA-256 |
| --- | --- |
| `is-number@7.0.0` archive, 3,730 bytes | `7b75c1057198cf97696909a9bee176c9c5e9bcb5b03bf3ecef2f484defadd51e` |
| `@types/is-number@7.0.5` archive, 1,669 bytes | `a81ca6b92e6cd09b8aa2d4f7fbeaa1025031579e312e0bef007f91f946c47793` |
| `GHSA-p6mc-m468-83gw` original OSV member | `07a142500c4fef0274340c7124b31683200cbc41eda5008775be57f4a7d483e1` |

The retained export from
`https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip` is 219,181,319
bytes, observed at 2026-10-27T04:04:20Z, with SHA-256
`f04a1e697f2f1485adfc8675c646acbe2d55f6787ff198472ac82c9e9672ab64`.
The probe validates the bounded ZIP index and selects only the named advisory
member. `lodash@4.17.15` matched with a complete supported assessment; this does
not qualify every record in the export.

The scoped package exposed a historical archive layout rooted at `is-number/`.
Production inspection now admits either `package/` or the exact manifest-name
basename as a single consistent root, while retaining identity, integrity, path,
link, and size checks. Regression tests reject mixed roots. The probe also changed
from scanning unrelated ZIP members to validating the exact named member through
the shared guarded ZIP reader. Both corrections were qualified against retained
captures without further provider attempts.

The completed `live-receipt.json` SHA-256 is
`8dd932453ae0bf43db9b1778f04d6096993cbde52828bee0eb7c8dfa048a4c69`.
Offline replay rechecked retained hashes, sizes, projection, and advisory matching
with zero requests. Original observation times and attempt counters were preserved.
Retained public captures remain in a separately marked root below `/tmp`; they are
not disposable fixtures or first-party AGPL source files.

## Review and remaining proof boundaries

Independent MCP/API, Upstream/Storage, and Security Boundary reviews inspected the
integrated implementation and affected callers. Reported issues were repaired and
reviewers closed their inspected scopes. This is agent review, not human GitHub
approval. Codex Security cloud access checking was not performed.

The operator package catalog starts empty. Request retrieval and audits never
enroll dependencies. The independent advisory collector defaults to enabled;
fixtures test bounded ZIP resumption and advisory publication. The bounded live probe
establishes selected provider/parser observations, not full-export semantic
coverage, completed catalog collection, complete historical recovery, or provider
endorsement. Manifest contracts and retained source text do not establish runtime
compatibility or a complete JavaScript/TypeScript symbol model.

No hosted workflow, native ARM64 CI, registry publication, native ChatGPT UI,
production activation, or production capacity claim follows from these results.
