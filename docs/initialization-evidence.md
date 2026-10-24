# Initialization evidence

Observed on Linux amd64, 2026-10-24. Runtime source is commit `0528d4c`; the following
acceptance record changes documentation only. These are local, native-client results.

| Check | Result |
| --- | --- |
| Rust 1.99.1 formatting | Passed |
| Strict workspace Clippy, all targets, locked | Passed |
| Workspace tests | 49 passed; two explicitly opt-in tests run separately below |
| Real audit helper | Sparse/registry equivalence, sanitized errors, kill-on-drop cancellation passed |
| Python MCP smoke-client tests | 8 passed |
| Shell and documentation checks | Shellcheck, syntax, whitespace and local links passed |
| Current cargo-audit | Zero advisories; database revision `84d943a6deeb8cc6c6f632531aaf4f1c62275239` |
| cargo-deny | Advisory, license, source and ban checks passed; duplicate-version warnings remain visible |
| PostgreSQL 18 | Dedicated integration test passed: permanent history, 304 observations, single-owner exclusion/loss, restart, staging cleanup, corrupt-blob detection, retained-body quota and clone/drop release |
| Full captured RustSec replay | Opt-in offline Research replay passed against the official captured head and bundle; no network during replay |
| Pinned OxiBelt Docker gate | Both MCP revisions over HTTP and WebTransport, direct/proxied calls, Host/Origin, path, TLS/mTLS rejection and recovery passed |
| Real minikube | Kubernetes 1.37.0, minikube 1.39.0, Calico: actual TCP/UDP NodePort routing, direct backend transport, valid-certificate untrusted-Pod denials and private-health isolation passed |
| Persistence in Kubernetes | PVC restart, coordinated PostgreSQL/blob backup and restore, and restored capture reads passed |
| Live RFC | Canonical index search and RFC 9000 text/content/capture checks passed |
| Live Cargo | Crate search, exact itoa 1.0.15 metadata, archive checksum, source listing/reading and capture consistency passed |
| Live RustSec | Fresh complete lookup and request-local supplied-lockfile audit passed with snapshot/count/status checks |
| Native release image | Built; non-root UID 65532 and fail-closed missing-configuration startup verified |
| Image platform metadata | Pinned build/runtime OCI indexes contain Linux amd64 and arm64 |
| Native arm64 and hosted CI | Configured; not executed in this local run |
| Publication and production deployment | Not requested; not performed |
| Local delivery | GPG-signed commits with the required assistance trailer; no push |

The final focused runtime run returned `minikube=0 image=0`. Earlier failures were
corrected and their affected gates rerun. The full Docker edge gate and PostgreSQL
quota regression passed after the shared-body changes. Release-image checks are
build/startup checks; positive end-to-end tool calls used the native debug harness.
No browser/ChatGPT UI, production load, full-site ingestion, or hosted CI result is
claimed.

## Source and review evidence

Independent reviews covered MCP/API and transport boundaries, provider identity and
advisory matching, request-owned audit privacy, upstream/cache correctness,
publication fencing, archive integrity and resource bounds, and operational cleanup.
No blocking findings remained at handoff.

Review fixes include sparse-registry advisory matching, a kill-on-drop private
analysis helper, byte-budgeted shared captures, lazy bounded audit pagination,
capture validation observations, original-spelling URL validation, same-connection
fenced writes, and exact Draft02 handshake/CORS integration with the pinned edge.

OxiBelt was built from the clean immutable source revision
`4f3154d8db0e0a49bce7a528c0a0f4c36d169040`; its native configuration check passed.
Its build identity is checked, not presented as cryptographic build attestation.
The reference OpenLegal checkout already contained local transport changes; the
consumed snapshot hashes are recorded in [notices](../THIRD-PARTY-NOTICES.md).
Neither reference repository was edited by this initialization.

The actual RustSec bundle at revision
`84d943a6deeb8cc6c6f632531aaf4f1c62275239` was 518,094 bytes with SHA-256
`1e8630a97b8310f392bc2056b88363a2bf605aed54b134574f6791ad2f6d222c`.
Its exact leading Git commit-comment metadata explained the original parser
rejection. A [439-byte curated fixture](../crates/adapters/tests/fixtures/rustsec/README.md)
retains provenance and CC0 terms; the bulk database is not committed. Offline replay
establishes captured-data parser compatibility, not current provider freshness.

Live tests used fixed public records and a synthetic lockfile. Including earlier
bounded probes and allowing the fetcher's one retry, the conservative totals were RFC at most 11, Cargo at most 12, and RustSec at most
10 HTTP attempts, all below the twenty-attempt ceiling. No public provider was crawled or load-tested.

## Operational observations

Cold PostgreSQL startup initially caused backend Pod restarts; Kubernetes recovered
before readiness. Endpoint/connection propagation after replacement briefly produced
proxy 502s. The harness now waits for bounded, source-free `server_info` routing
readiness before capture validation. Source, audit and restore operations are not
replayed by this readiness loop. The final live run used the corrected official RFC
index URL documented in [Sources](sources.md).

Configured Docker snapshot storage could not mount overlay layers in this environment.
Acceptance therefore used the task-owned isolated Docker/containerd helper on native
local storage, with private state, an explicit context and scoped firewall rules.
Configured daemon files and shared caches were not changed. Test profiles, helper
processes, private networks/state and scoped rules were removed after verification;
normal Rust/OxiBelt build caches remain available.

## RFC corpus implementation acceptance

Observed on native Linux amd64 on 2026-10-24. This record distinguishes signed
source, an immutable reviewed working-tree patch, and the artifacts actually tested.
The signed base is `f02a4cf12f476a0b8de147c4f77beeba3bba3d3e`.

| Evidence | Result |
| --- | --- |
| Final workspace fixtures | 88 passed; four opt-in tests excluded from the ordinary run |
| Strict all-target locked Clippy, formatting, whitespace | Passed |
| Python script tests | 67 passed |
| Current cargo-audit and cargo-deny | Passed; duplicate-version warnings remain visible |
| PostgreSQL 18 acceptance | Two tests passed, including v1 migration, same-second publication order, immutable history, restart, ownership loss and rsync assurance separation |
| RFC errata offline replay | Passed against all 8,103 records in the captured official response |
| Independent reviews | MCP/API, Upstream/Storage and Security boundaries closed; explicit index-worker cancellation and merge-policy follow-up reviewed |
| Native image gates | Combined runtime, server, probe and audit-worker builds/startup/fixture checks passed on amd64 |
| Pinned OxiBelt | Both MCP revisions over HTTP and WebTransport, including corpus status, identity/trust failures, recovery and private-route isolation passed |
| Disposable minikube | TCP/UDP NodePorts, CNI isolation, PVC restart and coordinated database/blob restore passed |
| Bounded live RFC | Metadata and TXT/HTML/XML/PDF passed; corrected canonical errata, TXT and partial full-text research passed in the final narrowed recheck |
| Other bounded live sources | Fixed itoa 1.0.15 search/metadata/checksum/source checks and fresh RustSec lookup/request-local audit passed |
| Native ARM64, hosted CI, browser/ChatGPT UI | Not executed in this run |
| Real full-corpus initialization, publication, deployment | Not performed |

Image, PostgreSQL and edge gates used signed-base plus immutable patch SHA-256
`19d5e4ab37d29c942f18b5dfbef593d9870504abf7608d0b2279394be73748f0`.
The final provider-route correction and Kubernetes/live acceptance used patch
`954084df7bce24b5c82af50f955e40c38d332244251bf96164a4e84223f11aab`
on the same signed base. The runtime delta was the fixed canonical errata destination
and its strict outbound allowlist; the remaining delta updated fixtures, documentation
and the narrower smoke option. A subsequent multi-RFC traversal fixture and this
record do not change runtime behavior. Local image revision labels identify the
signed base, so these checks are not a final registry/release artifact claim.

The first live run passed RFC metadata and all four formats, then stopped because
`/errata.json` returned 302 to `/api/v1/errata.json`. Redirect rejection remained
in force. One bounded request to each endpoint established the canonical path;
the 200 response was 11,775,016 bytes with SHA-256
`23fe2627c26acf3fe70087763fefce39ec9cb5cdfaaaf51977742e844929762c`.
It was replayed offline rather than committed as a bulk fixture. The final
`--live --rfc-text-only` run qualified metadata, text, errata and partial full-text
research without downloading the already-qualified alternate formats again.
Including retry allowances, the conservative total RFC ceiling was 12 + 2 + 6 = 20
attempts. Cargo and RustSec each remained below twenty attempts. No provider was
crawled or load-tested; automatic collection was paused in all live harnesses.

The isolated Docker helper used native local snapshot storage because the configured
daemon could not extract overlay layers. Temporary checkout path lengths were
shortened before the first gate to satisfy Unix-socket limits. Task-owned clusters,
containers, bridges and daemon state were removed; existing Docker contexts and
production archives were not changed. Source and scope guards protected each
immutable acceptance checkout.
