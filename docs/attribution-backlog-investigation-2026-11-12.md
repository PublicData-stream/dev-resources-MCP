# Attribution backlog investigation, 2026-11-12

## Evidence and limits

The investigation compared deployed `a938112b5af87996661ddd91ae68755dc0d579b9`
(`0.1.0-build.a938112b`, schema 13) with local
`eb54f9668d60f267bbf38ccaf003776f8b933fed`. The newer checkout does not establish
production activation. Read-only production samples used bounded queries; no queue
resets, production SQL writes, policy changes, provider crawls or deployment were authorized.

One global attribution status section at approximately 06:18 UTC reported 752,884
pending, 3,401 retry, 25,494 blocked, 615 ready and two running targets, with policy
epoch 1 and all eight then-deployed providers enabled. Counts describe targets,
not unique documents or independent license decisions. Other provider responses
repeat that global section and must not be summed.

During 09:14:29.915–09:16:20.762 UTC, the MDN total increased by 896 targets:
pending +862, blocked +32, retry +1 and running +1; ready remained 664. W3C gained
two targets; other provider totals had zero net change. These are sampled net
changes, not separately measured gross enqueue/completion rates. Existing npm and
WHATWG running claims retained expired `retry_at` values 1794383623 and 1794408700.
Legacy coarse reasons did not establish why individual targets failed. No conclusion
that every blocked target is recoverable follows from these observations.

The single read-only database snapshot at 09:16:20.762 UTC contained:

| Provider | Pending | Retry | Blocked | Ready | Running | Bounded observations |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Chromium | 4,631 | 6 | 148 | 0 | 0 | Old retries remained at attempt 1; sampled blocks included trees, jobs and state. |
| crates | 30,211 | 0 | 1,198 | 0 | 0 | Sampled capture blocks retained only a coarse label; original causes are unknown. |
| MDN | 325,076 | 1,707 | 10,889 | 664 | 1 | Sampled member/state blocks and old index/projection retries; net growth does not prove all jobs are redundant. |
| npm | 127,889 | 0 | 4,984 | 0 | 1 | The advisory-raw running claim was expired; sampled advisory blocks remain unclassified. |
| RFC | 611 | 4 | 8 | 47 | 0 | Catalogue/errata samples explicitly reported oversized evidence; other old blocks/retries lack exact causes. |
| RustSec | 44,573 | 354 | 1,385 | 0 | 0 | Sampled processing/commit/projection blocks and old record retries retained coarse labels. |
| W3C | 1,215 | 0 | 58 | 0 | 0 | Sampled state blocks; two net new targets in the observation interval. |
| WHATWG | 235,109 | 1,494 | 7,702 | 0 | 1 | The projection-chunk claim was expired; text fragments require originating-source lineage, not blanket exclusion. |
| Total | 769,315 | 3,565 | 26,372 | 711 | 3 | Counts describe exact targets, not distinct documents. |

Samples were indexed heads, not random population estimates. Old retry samples
were still at attempt 1 despite being due. The stored state has no enqueue timestamp,
so pending age cannot be reconstructed honestly. Source disappearance, missing
notices and unsupported historical scope are possible valid blocks; the old labels
do not establish which individual subjects belong to those groups. Only the sampled
oversized RFC records carried an explicit deterministic bound reason. Future finite
classifications and process-scoped counters improve this evidence without rewriting
ambiguous history.

The earlier representative pinned RFC 9000 read had ready attribution, while public
HTTP and IPv4/IPv6 WebTransport succeeded. Stable processes, storage ownership and
free space did not prove the entire attribution corpus was qualified. Concurrent
collector gaps remain a separate investigation.

## Demonstrated implementation paths

- Pending jobs use `retry_at=0`. The previous global ordering by priority, due time
  and target ID placed them ahead of due retries and expired running claims even
  on its background-fairness turn. Continuous pending work could indefinitely
  postpone recovery. Queue scheduling changes preserve indexed bounded seeks and
  introduce finite provider/status admission turns within a 4:1 priority cycle.
- Claim SQL admission has bounded lock/statement deadlines. Its `capacity` error
  previously escaped the runtime and was not retried by the required-worker wrapper,
  unlike sweep capacity. Handling the scheduling gap locally avoids terminating
  the writer on this temporary admission failure.
- Acquisition errors collapsed to `retryable`, `blocked` or `integrity`.
  Deterministic bounds could retry indefinitely and old labels lost their cause.
  Finite optional classifications distinguish operational disposition without
  persisting upstream messages or weakening rights/integrity checks. Historical
  labels retain their uncertainty.
- Sweeps previously replaced an oversized target with a fresh blocked state after
  enqueue, discarding promoted priority, attempts and retained failure state on
  subsequent passes. Initial-only blocking preserves existing authoritative state.
- Enumeration hashed mutable operational state into new occurrence identities.
  Updated status/failure/retry timestamps therefore created distinct jobs without
  new copied documents. Narrow filters omit demonstrated first-party operational
  rows while preserving source-list positions, immutable history and unresolved
  member/fragment lineage gaps.
- The evidence cache admitted every HTTP 200 before the caller checked exact bytes
  or decoded Git identity. A wrong response could remain sticky under the desired
  evidence key. Representation-aware validation now precedes insertion and is
  repeated on cache hits; invalid evidence never qualifies copied content.

These code paths and fixture reproductions explain possible failure mechanisms;
they do not assign a proven cause to every production row. Production provider and
reason populations remain partially unresolved. Permanent source disappearance,
missing governing notices, unsupported scope, payload bounds and integrity failures
can legitimately withhold copied content while historical evidence remains stored.

## Verification and operational acceptance

Fixture tests cover mixed-queue progress, retry eligibility, stale claims,
classification, exact-byte reuse, deduplication and negative qualification. The
minikube test executable acquires only first-party loopback fixture bytes and marks
published generations as synthetic. It compares exact representative subjects,
policy identities, generation IDs and complete UTF-8 notice pages after restart
and restore. Test state remains under `/tmp`; Cargo output is `/tmp/rust/target`.

Negative controls selectively restored the former cache admission, queue ranking
and oversized-state replacement in an isolated first-party source snapshot. The
cache recovery fixture failed on the second exact read, mixed-queue admission
reached only two of twelve eligible buckets, and the repeated-sweep fixture lost
promoted priority and seven retained attempts. These expected failures establish
that the regression fixtures detect the demonstrated defects. Final positive
acceptance uses fresh working-checkout artifacts, separately from those controls.

Required contribution checks and independent MCP/API, Upstream/Storage and Security
Boundary review remain separate gates. Report their actual results; the presence
of a fixture or this document does not establish a passing run. Compilation, local
PostgreSQL, Kubernetes/edge acceptance, live providers, native amd64/arm64 CI and
production operation are distinct evidence categories.

Final local verification uses the working checkout and a fresh local harness image:

| Check | Result |
| --- | --- |
| Rust 1.99.1 workspace tests | Passed: 969 tests; 75 opt-in tests remained ignored by this command. |
| Workspace Clippy and formatting | Passed, with warnings denied for Clippy. |
| Current advisory and dependency policy checks | `cargo audit` found no vulnerabilities; `cargo deny check` passed with existing duplicate-dependency warnings. |
| Python harness/operator tests | Passed: 801 tests, four existing skips. |
| Disposable PostgreSQL suite | Passed: 54 tests, including actual lock timeout, mixed-queue fairness, redacted diagnostic bounds, repeated sweeps and restart. |
| Pinned OxiBelt Docker acceptance | Passed for HTTP/WebTransport, both protocol revisions and existing negative boundaries. |
| Filesystem minikube acceptance | Passed: attribution repair/readback, TCP/UDP NodePort, CNI isolation, restart and coordinated restore. |
| Static-S3 minikube acceptance | Passed: reader/writer isolation, repair/readback, authoritative-storage outage, complete local-cache loss, database restore and both public transports. |
| Independent boundary reviews | MCP/API, Upstream/Storage and Security Boundary reviews completed; the discovered RPC size issue was corrected and re-reviewed. Agent review is not human GitHub approval. |

Both pre-existing Docker caches had incomplete image filesystems. Container checks
used owned Docker/containerd stores under `/tmp`; shared images were not deleted.
Negative-control build artifacts were invalidated before final positive acceptance,
and the replacement image independently passed the corrected cache fixture. One
initial migration-latch test timed out during concurrent build I/O; its unchanged
isolated rerun passed, followed by the complete final PostgreSQL suite. No deadline
or assertion was relaxed, and I/O contention remains a hypothesis rather than a
proved failure cause. The first S3 readback attempt also identified a fixture-only
single-thread runtime; both fixture phases now use the adapter-required two-worker
runtime, and the rebuilt-image S3 suite passed without changing its assertions.

After separately authorized release/deployment, use the finite ten-minute acceptance
procedure in [operations](operations.md#automatic-attribution-upgrade-schema-11).
Require representative recovery and honest remaining counts rather than an empty
queue or universal corpus completion. No production repair or deployment is claimed
by this local patch.
