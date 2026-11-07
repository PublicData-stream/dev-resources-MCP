# Offline migration parallelism: local evidence

This change preserves schema 10, hash encoding, identities, retained history,
ordered durable publication and all migration/verification/activation gates.
The original measurements below cover SQL/file parallelism; provider graph replay
was serial in that implementation (base `c8904f9`). The graph replay follow-up
records separate measurements and acceptance evidence for the new implementation.

## Reproduce the fixture measurements

Use Rust 1.99.1 and locked resolution. Build the `migration-benchmark` release
example with `CARGO_TARGET_DIR=/tmp/rust/target`, then run:

```sh
scripts/with-tmp-state.sh env \
  CARGO_TARGET_DIR=/tmp/rust/target \
  OXIBELT_TARGET_DIR=/tmp/rust/target \
  scripts/with-local-docker.sh \
  scripts/benchmark-migration.sh \
  --binary /tmp/rust/target/release/examples/migration-benchmark --files 64 --file-mib 32
```

The harness creates a private PostgreSQL container and a new database/blob pair
for every run. It refuses populated databases and requires matching fixture
markers before migration or verification. It never reads a staging/production
pair or acquires public source data. Fixture generation happens outside timings.

The default workload contains 128 synthetic SQL payloads of approximately
256 KiB each and 16 retained 8 MiB files, plus one public synthetic capture and
fixture metadata. It is a pending-schema10 qualification fixture with empty
provider graphs, rather than a complete schema-nine corpus. Worker settings start
at 1 and increase through 4/8/16/32 subject to CPU headroom and the stopping rule.
Each setting gets three equivalent fresh pairs. SQL payload concurrency is 64 MiB;
PostgreSQL is capped at two CPUs and 1 GiB RAM.

Normalized durable SQL/file fingerprints must match across all runs and again
after coordinated database/blob backup and restore. Physical tuple locations,
filesystem inode numbers and execution timings are excluded; the PostgreSQL
resume fixtures separately require committed tuple locations to stay unchanged.
Measurements use warm caches without dropping the host cache. The report records
binary SHA-256, source base, CPU/memory/cgroup limits and exact fixture options.
A source revision alone is not a build attestation.

## Measurements

The accepted run used 64 retained 32 MiB files (2 GiB), the same 128 SQL
payloads, and three fresh pairs per setting on an AMD EPYC 4585PX guest with
18 available logical CPUs, approximately 30 GiB RAM and ext4 storage. Preparation
fsynced fixture files/directories, issued a PostgreSQL checkpoint and completed
`syncfs` before timing. The release binary SHA-256 was
`60b4d886635dfaa48023935de200483534038edfd65ab83c69b7daefdd30dce1`.

| Workers | Measured phase total, median (s) | Whole command, median (s) | Whole command range (s) | Peak process RSS (MiB) |
| --- | ---: | ---: | ---: | ---: |
| 1 | 8.636 | 8.67 | 7.65–8.84 | 53.1 |
| 4 | 3.299 | 3.87 | 3.06–4.10 | 54.1 |
| 8 | 2.372 | 2.41 | 2.33–2.64 | 59.1 |
| 16 | 2.182 | 2.23 | 2.21–3.55 | 109.3 |

The whole benchmark command improved **3.89×** by median at sixteen workers;
the sum of its separately measured phases improved 3.96×. Every selected-setting
repeat beat every serial repeat by more than two percent. Sixteen workers had
the best median; eight had a smaller observed spread and lower peak RSS. The
configured default remains at most eight. Thirty-two workers were skipped because
the matrix reserves two of the eighteen available logical CPUs.

| Timed phase, median (s) | 1 worker | 8 workers | 16 workers |
| --- | ---: | ---: | ---: |
| Migration, including graph replay and finish verification | 3.687 | 0.938 | 0.841 |
| Standalone verification | 1.582 | 0.318 | 0.259 |
| Activation, including verification | 1.603 | 0.322 | 0.292 |
| Startup/readback and durable fingerprint | 0.763 | 0.782 | 0.803 |

Phase totals exclude command preflight/connection overhead, which is included
in whole-command wall time. Individual phase medians need not add to the median
of each run's total. Graph replay is bundled with migration here; these empty
provider graphs do not measure retained-provider replay performance.

All twelve migrated pairs and their twelve restored copies had the same normalized
durable fingerprint:
`ab8d7f7049dbc3f714efa1768494dba76ad0f17178b4fdc46d7287f8ab0cb12c`.
Maximum observed blocking jobs matched the configured worker count. The admitted
window high-water mark was 122 jobs and the SQL payload-work charge peaked at
66,812,206 bytes, below 64 MiB. RSS is a separate cumulative process measurement
and excludes PostgreSQL and filesystem page cache. Phase CPU/I/O and WAL deltas
are retained in the [sanitized measurements](migration-performance.json); CPU/I/O
exclude PostgreSQL, and WAL can include background activity. Process cgroup quota
files were unavailable, so no additional detected hard CPU/RAM quota is claimed.

| Separately measured wall time, median (s) | 1 worker | 8 workers | 16 workers |
| --- | ---: | ---: | ---: |
| Coordinated fixture backup and blob copy | 0.78 | 0.81 | 0.84 |
| PostgreSQL restore | 0.78 | 0.97 | 5.36 |
| Restored startup/readback/fingerprint | 0.83 | 0.87 | 0.88 |

Restore variability is recorded rather than attributed to worker count. These
operations are excluded from the migration ratio and must be measured again for
an actual cutover and rollback reserve.

An earlier small smoke fixture (128 MiB of files) was variable and showed no
end-to-end improvement: median phase totals were 1.473 s at one worker and
1.693 s at four workers, despite faster verification. It lacked an explicit
pre-timing durability checkpoint and was not accepted as the performance
experiment. Its summary is retained alongside the larger run. The larger workload
was chosen before its run to make hashing substantial relative to fixed overhead;
its results do not establish a benefit for every small or SQL-dominated workload.

## Original SQL/file acceptance evidence

- Local native amd64 workspace suite: 725 tests passed; 29 were ignored by that
  command. The separately executed contributor PostgreSQL gate passed, including
  legacy-history parity at workers 1/2/64, read-only verification, activation
  cancellation/rollback, file checkpoint/descriptor parity, owner loss, resumed
  tuple identity, and consecutive valid 65 MiB SQL payloads.
- Final focused tests: six executor/progress tests, twelve filesystem pipeline
  tests (including an isolated actual FD high-water check), seven SQL
  window/accounting tests and two CLI parser tests passed. Additional
  PostgreSQL fixture tests reject populated benchmark databases and verify the
  complete fixture path through activation and reopened readback.
- Formatting, workspace Clippy with warnings denied, current-advisory audit,
  dependency/license/source policy checks, whitespace checks and 439 Python
  script tests passed. No dependency or policy exception was added.
- Independent Upstream/Storage and MCP/API/Security Boundary source reviews
  found no remaining blocking findings after fixes. Agent review is not a human
  GitHub approval.
- Pinned OxiBelt Docker HTTP/WebTransport acceptance passed. Disposable minikube
  NodePort TCP/UDP, CNI isolation, PVC restart and coordinated restore passed.
  Neither gate contacted live public content providers. Runtime image build,
  startup and fixture acceptance also passed locally for linux/amd64.

Hosted native amd64/arm64 CI, registry publication, live-provider acceptance and
production operations are separate evidence and were not established by these
local checks. This work does not relabel or replace an earlier immutable release.

## Remaining cutover gate

Complete-corpus speedup and cutover time remain unmeasured. A separately authorized
attempt needs a fresh coordinated current database/blob pair, one isolated
complete-pair candidate benchmark, backup/restore proof, retained-history
acceptance, and total measured time plus rollback reserve within a newly agreed
outage window. Preserve the earlier failed-migration pair and current live pair.
The previous outage cutoff is not reused.

## Graph replay follow-up

Graph preparation now shares bounded admission across all eight providers and
within their independent phases. Per-provider SQL publication order, schema 10,
identity preimages, per-use source verification and activation remain unchanged.
The separate `--graph-memory-budget-mib` default is 1,024 MiB; progress records
accounted graph memory separately from SQL payload work and process RSS.

The benchmark supports `--graph-snapshots N` (1–64) to add nonempty retained RFC
indexes with historical snapshots plus npm and RustSec evidence. Optional
`--graph-generations N` (default one, at most the snapshot count) selects retained
source generations; generation changes update one document while retaining the
other sources. One generation measures repeated identical-index reuse; multiple
generations measure changed historical indexes. For example, append
`--graph-snapshots 16 --graph-generations 16 --graph-memory-budget-mib 2048 --workers "1 2 4 8"` to the
reproduction command above. The original file/SQL workload remains the default.

Graph runs compare semantic SQL/query fingerprints and restored readback;
physical index files are independently verified in each run. Tantivy segment filenames
and file digests can differ across independently created fresh indexes, so raw
filesystem fingerprints do not establish cross-run graph equivalence. Existing
canonical targets and their integrity evidence must still verify on resume;
normalization never excuses changed retained evidence or changes identity inputs.
Graph fixtures are synthetic local evidence, not a full-corpus or production
migration measurement.

### Retained graph measurements

The graph run used 16 retained RFC snapshots with 16 different source generations,
32 documents per index, npm/RustSec evidence, the default 128 SQL payloads and
16 retained 8 MiB files. Each worker setting used three freshly prepared pairs,
with preparation, checkpoint/syncfs and backup/restore outside migration timings.
The host was the same AMD EPYC 4585PX model with 18 available logical CPUs and
approximately 30 GiB RAM. PostgreSQL was capped at two CPUs and 1 GiB RAM;
the SQL payload budget was 64 MiB and graph budget was 2,048 MiB.

The release example binary SHA-256 was
`bfc2f1bb19395079853a59b43ef7a6c03af0ee035d18430bf4e6db5482d33a98`.
It was built from checkout base `1a6954b` plus this change; that base revision
alone is not a source/build attestation. Exact aggregate measurements, phase CPU,
I/O, WAL, sampled descriptors, and separate backup/restore times are in the
[sanitized graph report](migration-graph-performance.json).

| Workers | Phase total, median (s) | Whole command, median (s) | Whole command range (s) | Peak process RSS (MiB) | Sampled FDs | Graph charge peak (MiB) | Active graph jobs peak |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 12.799 | 12.84 | 11.85–13.85 | 163.2 | 24 | 198.8 | 1 |
| 2 | 11.923 | 11.97 | 10.37–13.21 | 180.4 | 37 | 532.7 | 2 |
| 4 | 9.062 | 9.11 | 7.11–9.46 | 181.9 | 51 | 1065.3 | 4 |
| 8 | 9.592 | 9.65 | 6.36–10.45 | 244.3 | 79 | 1591.9 | 8 |

Four workers improved the whole-command median **1.41×**. Every four-worker
repeat beat every serial repeat by more than two percent. Eight workers did not
improve the median further; these results do not justify raising the existing
worker default. The conservative graph charge stayed below the configured budget.
RSS is measured separately and excludes PostgreSQL/page cache. Descriptor counts
are sampled every 10 ms, include the sampling directory, and can miss brief peaks.

| Timed phase, median (s) | 1 worker | 2 workers | 4 workers | 8 workers |
| --- | ---: | ---: | ---: | ---: |
| Migration, including qualification, graph replay and finish verification | 9.898 | 8.925 | 5.645 | 5.704 |
| Standalone verification | 1.012 | 1.007 | 0.988 | 0.988 |
| Activation, including verification | 1.039 | 1.100 | 1.034 | 1.027 |
| Startup/readback and durable fingerprint | 0.831 | 0.844 | 0.852 | 0.881 |

These timings do not isolate RFC replay from qualification and finish verification.
All twelve pairs and twelve coordinated restored copies had the same normalized
SQL/query/non-index-file fingerprint:
`1a4492f0ae783c438a9dd9ca991b6bb7dbe52188e62ad33fae193531d4fe24c2`.
Each retained index was independently verified. Raw RFC integrity descriptors and
dataset heads remain in the fingerprint; regression tests show their removal is
detected. Only physical RFC index artifact names, paths and seals are normalized.

An earlier experiment with 16 snapshots reusing one source generation produced
phase-total medians of 9.946, 9.195 and 9.174 seconds at workers 1, 2 and 4.
Its 1.084× median ratio had overlapping repeat ranges and did not establish a
reliable improvement. That earlier binary also omitted raw RFC descriptors from
fingerprint comparison, so its report is retained as exploratory timing only,
outside the final correctness evidence. The changing-generation run above uses
the corrected fingerprint; the two experiments are not a controlled comparison
of binaries or workload speed. Neither fixture covers all eight nonempty provider
graphs or a complete schema-nine corpus.

### Graph implementation acceptance

- Native amd64 workspace tests: 745 passed, 33 ignored. The separate real
  PostgreSQL gate covers graph JSON preflight, retained RFC order and older partial
  replay, crate prepared receipts and one-to-one adoption, plus the existing
  provider history, owner, cancellation, integrity and restore fixtures.
- The benchmark PostgreSQL tests cover populated-database refusal, full
  activation/readback, changing/reused historical indexes, serial/parallel parity,
  restored fingerprints, and descriptor/head loss detection.
- Final formatting, workspace Clippy with warnings denied, current-advisory
  audit, dependency/license/source checks, whitespace/Bash checks and 473 Python
  script tests passed. No dependency or policy exception changed.
- Independent integrated MCP/API, Upstream/Storage and Security Boundary source
  reviews found no unresolved blockers. The final benchmark example also received
  an independent review. These are agent reviews, not human GitHub approvals.
- Local native amd64 Ubuntu harness/runtime startup and worker fixtures, pinned
  OxiBelt HTTP/WebTransport, and disposable minikube NodePort TCP/UDP, CNI
  isolation, PVC restart and coordinated restore passed. Production Alpine image
  packaging, hosted/native arm64 CI, live providers and production operations
  were not exercised by these checks.

The complete-corpus cutover gate above still applies. No live rehearsal was resumed,
and no release, registry publication or production deployment is established here.

## Crate SQL replay follow-up

The [crate replay comparison](migration-crate-performance.md) separately qualifies
bounded artifact/observation/staging batches and parallel preparation. It uses an
artifact-heavy synthetic fixture and an unchanged-algorithm baseline; these
earlier SQL/file and RFC graph measurements remain historical evidence.
