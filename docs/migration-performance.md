# Offline migration parallelism: local evidence

This change preserves schema 10, hash encoding, identities, retained history,
ordered durable publication and all migration/verification/activation gates.
Provider graph replay remains serial. The implementation base is `c8904f9`;
the fixture harness and final acceptance coverage are included with this report.

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

## Correctness and acceptance evidence

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
