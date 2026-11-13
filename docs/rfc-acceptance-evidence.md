# RFC diagnostics and retained-search acceptance

2026-11-13 implementation verification. This record concerns local first-party
fixtures, not recovery of the production failure described in the RFC handoff.

## Implemented boundaries

RFC retrieval opts into closed phase diagnostics without changing foreground
priority, HTTP attempts, queue retry delays or stale fallback. Schema 16 adds
nullable operational failure/claim metadata; old failures remain unclassified.
Representation-job counters and distinct RFC-number counters remain separate from
snapshot coverage. Existing counter aliases keep their meanings.

Private RFC inspection requires explicit job and snapshot identities. It verifies
bounded selected metadata, manifest shape and archive bindings without attaching
serving caches or opening the search engine. Engine and member-byte readability
remain untested by that command. Actual engine reads are exercised by separate
filesystem and S3 fixtures with serving-reader credentials.

Synthetic cluster fixtures retain two partial snapshot generations, historical
and current RFC 9000 captures, another searchable RFC and one missing
representation. HTTP and WebTransport verify pinned membership, ordering,
pagination, newer default selection, and exact historical body/notice bytes.
Synthetic RFC seeding is excluded from the harness's optional live-provider mode.

## Verification

All Cargo commands use Rust 1.99.1, locked resolution and
`CARGO_TARGET_DIR=/tmp/rust/target`. Generated test state is below `/tmp`.
Local compilation is Linux amd64 evidence.
The full workspace rerun used `RUST_TEST_THREADS=4`; the final PostgreSQL
script kept one test thread and excluded only S3-owned fixtures. Cluster checks
used `scripts/test-minikube.sh --image LOCAL_HARNESS` and its
`--s3 --credential-broker` variant. The final corrected native probe passed
its complete four-test suite and a separate Clippy check.

| Check | Result |
| --- | --- |
| Formatting and Clippy, workspace/all targets | Passed |
| Workspace tests, four test threads | Passed; corrected native probe additionally passed all 4 targeted tests |
| Python script tests | 806 run, 4 skipped; passed |
| `cargo audit` with freshly fetched advisory data | Passed |
| `cargo deny check` with writable temporary advisory cache | Passed; configured warnings retained |
| PostgreSQL persistence script | Passed, including RFC migration/failure history and metadata/deadline fixtures |
| S3/RustFS persistence script | 14 passed |
| Pinned OxiBelt Docker HTTP/WebTransport acceptance | Passed through isolated Docker |
| Minikube filesystem acceptance | Passed: TCP/UDP NodePort, CNI isolation, restart, coordinated restore and RFC readback |
| Minikube S3/credential-broker acceptance | Passed: role enforcement, complete cache loss, database restore and credential cutovers |
| Relative links and whitespace | Passed |

The initial concurrent workspace run failed an unchanged five-second Wikipedia
cooldown assertion; its isolated rerun passed. The initial PostgreSQL run failed
Chromium offline migration with a coarse storage-unavailable error; its isolated
rerun passed. Complete reruns use bounded test concurrency without changing test
assertions or production limits.

The initial S3 run exposed a schema-16 backup-receipt admission omission. The
accepted range and boundary fixture were corrected; the complete S3 rerun passed.
The PostgreSQL-only runner now excludes the S3-prefixed inspector fixture, which
requires its separately provisioned archive credentials and remains covered by
the complete S3 script. Cluster verification was corrected to check RFC's
existing source-evidence and qualified-attribution metadata, including its notice
license; it does not assume the W3C/Chromium resource metadata layout. Exact body
and notice assertions remain enabled.

Independent source reviews covered MCP/API, Upstream/Storage and Security
Boundaries, including the inspector's exact-length check and cooperative deadline
reporting. These reviews are not human GitHub approvals.

Shared Docker image attempts failed before application startup because basic
container executables were missing. Final edge/cluster acceptance uses the
repository's isolated Docker helper with freshly acquired pinned images. Failed
startup attempts are not counted as application acceptance.

## Unverified boundaries

No live provider checks, production metadata inspection, production snapshot
replay, queue recovery, reindex, release or deployment was performed. Native
hosted amd64/arm64 CI and production reader grants remain separate acceptance
boundaries. The production acquisition and selected-index failure causes remain
unidentified; these changes do not establish full-corpus completion or production
recovery.
