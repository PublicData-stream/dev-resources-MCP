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
