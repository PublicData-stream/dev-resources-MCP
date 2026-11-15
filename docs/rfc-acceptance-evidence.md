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

## Connected-server RFC checker

The opt-in RFC-only checker exercises the responding server through Streamable
HTTP under both advertised MCP revisions. It does not require paused collectors
and does not change their configuration. Unlike the general live smoke, it never
selects other source families through generic search.
Ordinary unpinned reads can trigger foreground fetching, publication or
attribution repair of retained public evidence.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/rfc_acceptance.py --live \
  --url https://dev-resources.mcp.publicdata.stream/mcp \
  --output-dir /tmp/devres-rfc-acceptance.OWNED \
  --connector-input /tmp/devres-rfc-connector.OWNED.json
```

Use a new output directory below `/tmp`. The checker writes bounded `report.json`
and `report.md` files containing check outcomes and immutable evidence references,
without copying RFC bodies or complete transport responses into the reports.
Full acceptance requires 13 separately collected host connector observations:
`server.info` before and after the nine RFC operations, RFC-only generic `search`,
and `fetch`. Raw `--connector-input` is a bounded JSON array of
`{"name": "rfc_metadata", "args": {"number": 9000}, "result": MCP_RESULT}`
records; `name` uses the connector function suffix and `result` retains the
original tool envelope. The checker sanitizes these records before reporting.
Alternatively, `--connector-observations /tmp/OBSERVATIONS.json` imports records
already sanitized through `Report.add_connector`. The input options are mutually
exclusive. Omitting connector input permits HTTP investigation but necessarily
leaves full acceptance incomplete.
Connector observations do not establish raw HTTP framing or native ChatGPT UI
behavior; their coverage remains separate in the report.

The fixed targets are RFC 9000 and BCP 14. Six direct official-source requests
provide the index, errata and TXT/HTML/XML/PDF comparison references. Downloads are
sequential, paced, size bounded and never retried or redirected. Returned resource
references are read through MCP, not fetched as arbitrary network destinations.
The MCP request ceiling includes imported connector observations. The 15-minute
deadline applies to the HTTP/reference phase; imported host observations precede
that phase and have separate coverage. Background
collector traffic and server-side retries remain outside the checker's control.

A correctly formatted availability error does not prove successful content
retrieval. Any failed or unverified required path produces a nonzero exit status.
Official byte comparison covers sampled pages and total lengths, not an entire
server capture. A difference from a current official reference leaves historical
byte equivalence unverified rather than establishing corruption.

Fixture regression tests run without provider traffic:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s scripts/tests -p test_rfc_acceptance.py
```

## 2026-11-15 connected-server outcome

One HTTP/reference attempt ran from 03:47:24 to 03:49:41 UTC against
`https://dev-resources.mcp.publicdata.stream/mcp`. Server identity remained
`0.1.0-build.33f3c730` before, during and after both revision checks and matched
the separately collected direct connector observations. The staged plugin
connection was not an acceptance target.

The checker exited **1: acceptance incomplete**, with **78 passed and 44
unverified** check rows and no failed contract assertions. The 81 counted MCP
requests comprise 68 HTTP requests and 13 earlier connector calls. Six direct
official-source requests all returned validated references; no retries were made.
These check-row counts include dependency and error-envelope checks, not unique
tools or documents.

| Evidence path | Observed result |
| --- | --- |
| HTTP discovery, RFC inventory and harmless negative cases | Passed under both MCP revisions |
| HTTP RFC search and pinned paging, metadata and catalog filters | Passed under both revisions; RFC 9000 metadata matched the official index |
| HTTP BCP 14 membership and metadata attribution resources | Passed under both revisions; membership matched the official index |
| HTTP RFC 9000 TXT through `rfc.get` and `rfc.format_get` | `capacity` under both revisions; required content success remains unverified |
| HTTP RFC 9000 HTML/XML/PDF | `unavailable` under modern MCP; legacy first/next pages, capture replay, native resources, immutable fetch and attribution passed official-byte comparisons |
| HTTP RFC errata | `unavailable` under both revisions |
| HTTP full-text research | Technical mode unavailable under both revisions; English mode unavailable under modern MCP and passed under legacy MCP |
| Direct connector sample | Metadata, catalog, series, RFC-only generic search and status returned valid results; search/full-text/errata returned `unavailable`, while text/format/fetch returned `capacity` |
| Direct official references | Index, errata, TXT, HTML, XML and PDF acquired and validated independently |

Connector error details identify pending or blocked attribution repair for the
unavailable research calls and `retained_lookup` working-set capacity for text
reads. HTTP collector observations reported an `unavailable` failure during
`artifact_publication`; the earlier connector status reported `index_publication`.
These observations identify public failure boundaries, not a completed root-cause
analysis. Changing availability across revisions is recorded separately rather
than treated as a retry success for the modern revision.

The checks reused research snapshot
`blake3:d874e3526ce9bad0b1d99ebbb6d82abe936622e94c58f426c06979ed33351850`.
TXT byte/resource parity, TXT capture-binding rejection and other dependent
success assertions remain unverified. No product fixes, queue recovery, collector
configuration changes, deployment, minikube qualification or hosted architecture
CI checks were performed by this task. The temporary JSON report retains the
per-check results, reference hashes and observation metadata.

The recorded live attempt used checker revision `2888c1f`. Follow-up `7d77e1d`
separates ordinary `fetch("rfc:9000")` from successful text/parity dependencies,
so a failed text read cannot suppress that independent check. Its regression
passed in the 23-test focused suite; the added standalone HTTP checks were not
rerun live. The earlier connector fetch result remains separate evidence.

### Implementation verification

Checks used Rust 1.99.1, locked resolution and `/tmp/rust/target`; generated test
state and isolated Docker storage stayed below `/tmp`. Checks ran against the
shared working tree, including pre-existing npm work. That work was preserved.

| Check | Result |
| --- | --- |
| RFC checker synthetic regressions | 23 passed |
| Final integrated Python suite | 986 run, 4 skipped; passed |
| Formatting and Clippy, workspace/all targets | Passed |
| Workspace Rust tests | Passed with four test threads; ignored fixtures remain separate |
| `cargo audit` and vendored SDK projection | Passed after refreshing the advisory database |
| `cargo deny check` | Passed; configured duplicate-version warnings retained |
| PostgreSQL persistence | Passed using the isolated Docker helper |
| Python syntax, local documentation links and whitespace | Passed |
| OxiBelt fixture gate | Failed at `synthetic_npm_advisory` in the existing shared smoke script: `npm advisory resource dropped its readable notice` |

The OxiBelt attempt passed initial HTTP and WebTransport discovery/identity checks
before failing the npm resource assertion. It does not establish complete edge
acceptance. The failing shared script and product implementation were left intact;
this required gate remains unresolved.

One full Python run failed an existing five-second S3 concurrency assertion in
`test_parallel_part_failure_drains_before_aborting_exact_owned_id`. Its isolated
60-test module and the subsequent complete 985-test rerun passed without changing
assertions; four tests were skipped. After the checker fetch delta, the final
integrated suite passed all 986 tests with the same four skips.

Independent reviewers inspected the actual implementation and follow-up, covering
MCP/API, Upstream/Storage and Security boundaries. These agent reviews are not
human GitHub approvals. Local compilation, fixtures, direct provider references,
connected-server results and unresolved edge acceptance remain distinct evidence.
