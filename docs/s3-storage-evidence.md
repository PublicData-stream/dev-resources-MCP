# S3 storage acceptance evidence

Observed on native Linux amd64 with Rust 1.99.1, 2026-11-08. Final runtime source is
signed commit `015d666`, including initial storage/server commits `89a563b`,
`c19abb8`, `9c978b3` and worker-recovery fix `1f17287`.
This record concerns optional S3 storage; existing public source and MCP contracts
remain defined by the [specification](Specification.md).

| Check | Observed result |
| --- | --- |
| Formatting and locked all-target workspace Clippy with warnings denied | Passed |
| Final ordinary workspace tests | 815 passed, zero failed, 59 ignored; separately executed opt-in gates are recorded below |
| Final focused object-storage helpers | 16 passed; five integration cases excluded here and exercised separately |
| Final Python acceptance/release helper suite | 585 passed |
| Current cargo-audit and cargo-deny | Passed against official advisory revision `309392b18f6b17022f82c701f300433126901068`; duplicate-version warnings remain visible |
| Full PostgreSQL persistence harness | Earlier complete baseline passed, including unchanged filesystem migration and provider regressions; the later recovery regression ran separately |
| Additional worker recovery checks | Six worker/parser tests and a real PostgreSQL same-owner claim recovery regression passed after the recovery fix |
| Real RustFS and PostgreSQL S3 fixtures | Ten passed, zero failed |
| Pinned OxiBelt Docker acceptance | Earlier filesystem baseline passed HTTP and WebTransport for MCP revisions 2026-07-28 and 2025-11-25 |
| Filesystem minikube acceptance | Earlier filesystem baseline passed TCP/UDP transports, CNI isolation, seeded restart and coordinated database/blob restoration |
| Native process S3 outage recovery | Same backend survived a 30-second archive outage, returned readiness 503, and recovered readiness 200 when storage resumed |
| Final S3 minikube acceptance | Passed public/private HTTP and both WebTransport revisions, CNI isolation, seeded restart, warm-cache outage rejection, recovery without a backend restart, complete cache loss and PostgreSQL restore |
| Independent review | MCP/API, Upstream/Storage and Security Boundary reviews closed on the integrated implementation and affected callers |

The real S3 fixtures exercise permanent bodies and all bulk namespaces, retained
Git evidence, RFC/crate/MDN search files, cold historical reads and index ranking,
leased-file pinning, quota accounting across restart/cache loss, and concurrent
publication on a single Tokio worker, plus buffered staging capacity and cleanup.
They also cover conditional object creation,
streamed multipart bodies larger than 16 MiB, conflicting writes, and fresh-start
recovery after missing CA/credential files without permitting namespace changes.

Offline acceptance includes interrupted filesystem transfer, explicit activation,
post-cutover publication, backup to a separate prefix, restoration into a fresh
database/prefix/cache, and both pre- and post-cutover historical reads. Original
filesystem bytes remain intact and protected from source-cache overlap. The
restored database releases only the original host's obsolete source-path fence.

Earlier PostgreSQL runs under concurrent build/test I/O encountered transient
timeouts. The unchanged affected tests and then the complete persistence harness
passed; no assertion or timeout was weakened. An unusable shared advisory cache
was replaced with a fresh disposable official database; policy checks were not
suppressed. Generated credentials, databases, buckets, clusters and other test
state use disposable `/tmp` locations, separate from permanent public captures.

The first S3 cluster outage test exposed fatal propagation from background corpus
workers. S3-only supervision now retries temporary unavailability with cancelled
attempt tokens while the independent ownership monitor retains its fatal fence.
Integrity failures and filesystem worker behavior remain unchanged.

Final S3 Kubernetes acceptance used the local native image manifest
`sha256:811489c827f5a35338bb0aed82f6a0979f3c5fa865250f09b244ccee3ad51ef0`
built from the frozen runtime. Cold reads followed a PostgreSQL restore against the
same frozen S3 inventory; separate-prefix backup/restore was exercised by the real
S3 fixtures. A fixture DNS startup race was corrected with bounded DNS readiness
before the single authenticated bucket-creation request, then the full cluster
scenario passed from a fresh profile.

Reproduce the opt-in fixtures and cluster acceptance using the commands in
[operations](operations.md#s3-transfer-and-recovery). Configuration, credential
modes, limits and the required separate post-migration cache are documented in
[configuration](Configuration.md#optional-s3-archive).

These are local fixture results, not AWS or other provider acceptance. Native
arm64 and hosted Actions are configured but were not executed here. Full-corpus
capacity, production operations, registry publication and native ChatGPT UI were
not tested. Independent agent review is not human GitHub approval. Delivery uses
signed local commits with the assistance trailer; no push or deployment is claimed.

## Static Scaleway IAM (2026-11-10)

Native Linux amd64 validation covers the reader transport guard in signed commit
`6146877`, static production configuration/lifecycle support in `63d2a9b`, and the
accompanying enforcing static credential fixtures. No public tool schema, source
budget, archive layout, database schema or dependency lockfile changed.

| Check | Observed result |
| --- | --- |
| Workspace formatting and locked all-target Clippy with warnings denied | Passed |
| Locked workspace tests | Passed; opt-in database/storage cases ran separately below |
| Current cargo-audit and cargo-deny | Passed using official advisory data |
| Final Python helper regression suite | 757 tests, zero failures, four existing skips |
| Reader method fence | GET/HEAD work with unrestricted fixture credentials; PUT/DELETE and multipart mutations send no outbound mutation requests |
| Complete PostgreSQL persistence harness | Passed |
| RustFS/PostgreSQL S3 acceptance | 13 passed with distinct enforcing writer/reader keys, including cold readers, backup/restore and publication recovery |
| Pinned OxiBelt Docker acceptance | Passed HTTP and WebTransport for both supported MCP revisions |
| Credential broker Docker acceptance | Passed role/prefix enforcement, encrypted restart/reuse, issuance uncertainty, revocation and database isolation |
| Filesystem minikube | Passed routing, CNI/private-service isolation, PVC restart and coordinated restore |
| Static S3 minikube | Passed distinct key enforcement, both transports, warm-cache outage denial, same-process recovery, revoked-key readiness denial, stopped pair replacement, cold reads and database restore |
| Broker S3 minikube | Passed real pod identities, encrypted credential reuse, bounded outage recovery and complete cache loss/restore |
| Stopped broker to static to broker rehearsal | Passed with unchanged archive binding/epoch, cold historical readback in both modes and fresh broker credentials after rollback |
| Independent review | Upstream/Storage and Security Boundary review findings resolved on actual implementation and affected callers |

The production operator tests additionally cover credential-bound static receipts,
fixture/cross-mode/expired receipt rejection, template validation before Secret
writes, stopped rotation, collector pause without broker key changes, preserved
edge evidence and timer ownership, and recovery from partially applied switches.
The runtime/server image used by these local harnesses is a disposable test image,
not a newly qualified production release.

The configured shared Docker stores could not launch the cached PostgreSQL image
entrypoint, including a direct `/bin/sh` probe. Acceptance therefore used the
repository's `with-local-docker.sh` isolated daemon below `/tmp`; shared daemon
state and existing operator clusters were preserved. One initial S3 fixture setup
returned 503 after `/health` had succeeded. Bounded fixture-only creation retries
were added, tested against a real loopback server returning 503 twice then 200,
and the 13-case S3 rerun passed. Per-attempt connect/request limits and the
Kubernetes Job deadline remain enforced; production retry policy was not changed.
All generated test state and Cargo targets remained below `/tmp`.

See the [static operator guide](../deploy/examples/scaleway-static/README.md) for
permission sets, Secret inputs, stopped rotation/cutover and rollback. The broker
remains the production default. Current production image pins predate the guard,
so static production provisioning/start/cutover remain blocked until a separately
qualified immutable release is pinned and real Scaleway permission evidence is
admitted. These synthetic provider and local cluster results do not establish
live Scaleway enforcement, hosted/native arm64 CI, registry publication,
production operations or native ChatGPT UI acceptance. No push or deployment was
performed; independent agent review is not human GitHub approval.
