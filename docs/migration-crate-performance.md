# Crate migration batching and parallel preparation

This work changes private offline replay of crate artifacts, observation
occurrences and inventory staging. Public tools, identities, schema versions,
configuration, worker defaults, retained history and activation gates retain
their existing contracts. The [offline worker limits](operations.md#offline-worker-limits-and-progress)
describe admission and publication bounds.

## Comparison method

The baseline is `bea1cf198b9eb645fe7e824cfb15bb25110470a8` with the common
synthetic fixture and aggregate timing hooks. Its replay algorithm is unchanged.
The [timing-only patch](../scripts/migration-baseline-timing.patch) adds 41 lines
and removes none; apply it with `git apply --unidiff-zero` to that exact revision.
Copy the current benchmark example and its crate fixture helper into the baseline
source tree before building it.

Build both examples with Rust 1.99.1, locked resolution and the release profile.
Keep source copies and all tool state under `/tmp`, and set
`CARGO_TARGET_DIR=/tmp/rust/target` after entering `scripts/with-tmp-state.sh`.
Build sequentially and copy each executable to a separate owned `/tmp` path
immediately. When reusing a target directory across source trees, update the
copied adapter `src/lib.rs` and benchmark entrypoint timestamps before each build
to invalidate stale Cargo artifacts. Preserve the resulting source manifests and
binary hashes; a checkout revision alone is not a build attestation.

The fixed workload has 16,384 artifacts with small origin records and occasional
larger manifest provenance, two identical same-second observations per artifact,
and three inventories containing 4,096 staging rows each. One retained synthetic
body is shared by the captures. Ancillary work is two 1 KiB SQL payloads and two
1 MiB files. No package content is executed and no provider acquisition runs.

The harness alternates baseline/candidate order for three workers-eight pairs,
then executes three fresh candidate pairs at each of workers one, two and four.
It always completes this matrix rather than stopping at a scaling plateau.
Each migration command retains the existing 15-minute bound. Preparation,
checkpoint/syncfs, backup and restore are outside migration timings. PostgreSQL
is limited to two CPUs and 1 GiB; SQL payload and graph budgets are 64 MiB and
1,024 MiB. Caches are warm; the harness never drops host caches.

```sh
scripts/with-tmp-state.sh env \
  CARGO_TARGET_DIR=/tmp/rust/target OXIBELT_TARGET_DIR=/tmp/rust/target \
  scripts/with-local-docker.sh scripts/benchmark-migration.sh \
  --binary /tmp/devres-crate-candidate \
  --baseline-binary /tmp/devres-crate-baseline \
  --baseline-revision bea1cf198b9eb645fe7e824cfb15bb25110470a8 \
  --crate-artifacts 16384 --crate-staging-rows 4096 --repeats 3
```

The fourfold goal compares the complete artifact-only phase at eight workers,
including metadata reads, memory admission, preparation, owner waits, commits
and the final empty-page query. Observation replay and staging have separate
timers. Whole-command time, candidate scaling and backup/restore are reported
separately. Nested component wall times can overlap.

All fresh and restored pairs must have equal durable fingerprints, including
legacy/canonical crate rows, provenance seals, observation receipts, inventory
state, staging, aliases, completion state and sequence state. Readback checks
artifact metadata/length, staging membership and preservation of duplicate
observations. Retained file bytes are independently verified and fingerprinted.

An initial exploratory comparison accidentally copied the same executable for
both algorithms from a shared Cargo target. It was invalidated and contributes
no accepted timing or speedup evidence. The harness now rejects byte-identical
comparison binaries before creating infrastructure; the accepted pair must also
be checked against its source manifests and algorithm instrumentation. A later
same-profile trial of the first batched revision measured 3.17× for its initial
pair and did not establish the fourfold goal. That earlier revision and graph-only
loaded diagnostics are excluded from the final fixed matrix.

The first final-matrix startup failed before producing any measurements because
the image's temporary Unix-socket initialization server was mistaken for the
final server. The harness now waits for TCP readiness; a mocked startup-state
regression also fails against the old socket-only probe. Workload, timers and
resource limits are unchanged by this harness correction.

Existing canonical artifacts are filtered before insertion; repeated mapped
targets are inserted once in original source order. A separate scalar query then
compares every requested occurrence against the stored payload and integrity
seal before the transaction can commit. Conflicting aliases or trigger-altered
rows roll back the whole current batch. Existing canonical tuples are not
rewritten. The owner fence continues to serialize publication; unexpected
concurrent insertion fails the batch rather than silently accepting another row.

## Measurements and acceptance

The timed runtime source is `75a5d9293a4d4bf461071bbeff51e8eb4662631f`;
the timed shell harness is `59e05dd2e4543c9033581958bd544bc175a1d24a`.
Candidate executable SHA-256:
`f68549ab26fff0d37cce11a45366c25c6bd8c46fef0f573011febee8da8959b0`.
Baseline executable SHA-256:
`1a552390ebba26007308a9af1e18378a314c63b1afc1a4c98ecb8d028c6f6d65`.
The final report-text correction names the terminating empty metadata-page query;
recomputing the report changed no numeric result or acceptance rule. The evidence
records both the frozen measurement source hashes and the post-measurement report
hash.

All 15 fresh pairs and their restored copies passed with one durable fingerprint. The
complete artifact phase at eight workers improved from 82.158 s to 11.461 s: **7.168×**,
exceeding the fixed 4× median goal. Every accepted candidate-eight repeat also beat
every baseline repeat by more than 2%.

| Algorithm | Workers | Artifact median, s (range) | Whole-command median, s |
| --- | ---: | ---: | ---: |
| baseline | 8 | 82.158 (57.365–102.684) | 856.43 |
| candidate | 1 | 6.856 (2.812–17.316) | 500.78 |
| candidate | 2 | 3.125 (1.502–16.102) | 469.43 |
| candidate | 4 | 6.239 (1.209–21.698) | 419.64 |
| candidate | 8 | 11.461 (2.495–27.361) | 428.97 |

The whole-command speedup at eight workers is 1.996×. This quantity includes activation
and startup, and differs from artifact-only speedup. GNU process wall time also includes
overhead outside the four measured phases.

| Phase or component | Baseline eight median, s | Candidate eight median, s |
| --- | ---: | ---: |
| Observation replay | 185.260 | 38.199 |
| Inventory staging | 191.378 | 10.385 |
| Migration including graph/finish verification | 524.596 | 95.886 |
| Standalone verification | 7.637 | 7.282 |
| Activation including verification | 313.668 | 324.320 |
| Startup/readback/fingerprint | 1.451 | 1.415 |

| Algorithm/workers | Process RSS peak, MiB | Graph reservation peak, MiB | Graph jobs peak |
| --- | ---: | ---: | ---: |
| baseline/8 | 31.04 | 2.31 | 0 |
| candidate/1 | 28.46 | 33.27 | 1 |
| candidate/2 | 30.53 | 33.27 | 2 |
| candidate/4 | 32.03 | 33.27 | 4 |
| candidate/8 | 46.15 | 33.27 | 8 |

RSS is the process cumulative high-water observation; graph reservation is accounted
admission, not measured RSS. Every candidate run admitted exactly 61,440 graph jobs and
drained them before returning. No candidate exceeded its worker count or the fixed
fixture memory budget. Per-phase process CPU/I/O excludes PostgreSQL; WAL measurements
can include background work.

Across all 15 runs, backup took a median 0.80 s (range 0.77–0.86 s), restore
18.88 s (9.43–28.21 s), and restored startup/readback 1.46 s (1.31–4.53 s).
These separate operations are excluded from artifact and whole-command timings.

These are descriptive three-run medians on a shared host; worker CPU and host I/O were
not exclusively reserved. PostgreSQL retained the fixed two-CPU/1-GiB limit. The
observed variation does not establish a general worker-count recommendation or
production/full-corpus throughput.

See the [allowlisted aggregate evidence](migration-crate-performance.json) for every
run, restored fingerprint, phase resources, exact frozen source hashes and binary
identities.

No complete-corpus, production-cutover or native ARM64 claim follows from these
synthetic local fixtures.

## Local correctness and recovery evidence

- On final runtime revision `75a5d92`, native amd64 workspace runtime tests
  passed 787 tests with 48 ignored. The command's initial doctest compilation
  failed with E0463 after concurrent use of the shared target; an isolated
  `cargo test --workspace --doc --locked` rebuilt dependencies and passed all
  four doctest groups without source changes. The initial batching implementation
  had also passed the complete PostgreSQL gate: 40 tests across 23 command
  results. Final changed-SQL coverage is the separate 14-test gate below.
  Opt-in retained-source/live fixtures are not implied by these results.
- Fourteen PostgreSQL row-pipeline regressions cover workers 1/2/8, 127/128/129-row
  boundaries, encoded-byte crossings, oversized singleton admission, compressed
  long version keys, same-second occurrence multiplicity, source/target/receipt
  corruption, later-batch rollback, owner loss and verified resume without tuple
  or sequence replacement. Four focused cases also exercise mixed fresh/resumed
  targets, identical and contradictory mapped aliases, and BEFORE/AFTER trigger
  interference with fresh or previously committed targets.
- The initial batching fixture server received SIGTERM after its first crate
  batch. The same pair resumed with 128 canonical artifact tuples and five file
  checkpoints unchanged,
  then verified, activated and passed restored readback. Run
  `scripts/test-staging-worker.sh --crate-replay` to reproduce. The existing RFC
  variant separately preserved 210 file checkpoint tuples and restored readback.
- Formatting, workspace/all-targets Clippy with warnings denied, current advisory
  audit, dependency/license/source admission, whitespace and 543 Python tests
  passed. No dependency or policy exception changed.
- The pinned OxiBelt HTTP/WebTransport gate and disposable minikube NodePort
  TCP/UDP, CNI isolation, PVC restart and coordinated restore passed using the
  local Ubuntu fixture image with ID
  `sha256:43efd7ab3203abd6324d509af2a8b75f72704a0974f78b1c0fb446f61780188b`.
  This image also supplied the SIGTERM worker evidence above and predates the
  final missing-target insertion refinement at `75a5d92`; these gates qualify
  that earlier batching implementation. The final SQL refinement is covered by
  the 14 PostgreSQL tests and the fixed migration/restore matrix. No content
  provider was contacted.
- Independent integrated Upstream/Storage and MCP/API/Security Boundary reviews
  found no remaining blockers after the staging predecode-admission correction.
  The verification scripts, timing-only baseline patch and final missing-target
  insertion refinement received follow-up review. Agent review is not human
  GitHub approval.

These checks do not establish hosted/native ARM64 CI, production Alpine packaging,
registry publication, live-provider acceptance or a remote migration/activation.
