# MDN implementation evidence

Observed locally on Linux amd64, 2026-10-25. The implementation is in signed
commits starting at `6df125d`, through `20e253b`. These results do not establish hosted
arm64 execution, image publication, production deployment or native ChatGPT UI
acceptance.

| Check | Result |
| --- | --- |
| Rust 1.99.1 formatting and strict locked workspace Clippy | Passed |
| Locked workspace tests | Passed, including 220 adapter unit tests and the existing Cargo/RFC/transport suites; explicitly opt-in PostgreSQL tests ran separately |
| Current cargo-audit | Passed against 1,352 advisories and 459 locked dependencies |
| cargo-deny | Advisories, bans, licenses and sources passed; existing duplicate-version warnings remain visible |
| Python smoke-client tests | 80 passed |
| Retained driver regressions | Eight passed, covering durable attempts, legacy allowance, cancellation during exclusive storage accounting, canonical frozen-history sampling and searchable-member selection |
| Shell syntax, whitespace and local Markdown file links | Passed |
| Real PostgreSQL | Passed immutable replay/collision and batch rollback, owner loss, atomic paired views, read/write bounds, restart and full synthetic Git history/research recovery |
| Pinned OxiBelt gate | Passed both MCP revisions over HTTP and WebTransport with pinned synthetic MDN/BCD tools and resources |
| Disposable minikube | Passed TCP/UDP NodePort routing, Calico isolation, PVC restart and coordinated PostgreSQL/blob restore with synthetic MDN/BCD evidence |
| Local amd64 runtime image | Build, startup and executable fixtures passed |
| Independent review | MCP/API, upstream/storage and security boundaries reviewed; no unresolved findings |
| Local delivery | Signed commits include the required assistance trailer; no push or release |

All ordinary acceptance fixtures explicitly disable automatic collectors and label
their MDN evidence synthetic. Their success is separate from upstream coverage.
No upstream JavaScript, package scripts or MDN build tools were executed.
The final full workspace, PostgreSQL, strict workspace Clippy and native amd64
runtime-image gates ran through `20e253b`. All eight focused index tests also
passed, including selected-snapshot scoring, cross-shard prepared membership,
filter-only ordering and cursors, integrity failures, cancellation and deadlines.

## Retained full-source acceptance

The retained run froze these official observations:

| Repository | Main revision | Reachable commits |
| --- | --- | ---: |
| `mdn/content` | `c6a89971a820ca6b76479a7ffc1b32c09aae2415` | 30,648 |
| `mdn/browser-compat-data` | `56e6f1217a54dfe0d25df29d0f67c6a26cdc3901` | 21,678 |

Full-source acceptance passed with exit code 0 and `full_history: true` in the
retained driver's `acceptance.json`. Both ancestry queues finished at processor
generation 3: 30,648 content commits and 21,678 compatibility commits. Canonical
history validation checked every one of these 52,326 frozen commits against its
current-generation snapshot alias, revision, parents and committed time. Separate
snapshot verification validated inventory root hashes and accounting across
retained snapshots. These checks do not establish direct Git-tree equivalence for
every historical inventory. Prior generations remain retained.

The final gate accounted for 57,120 retained snapshots across all generations and
verified the latest index artifacts. Pinned current research passed text search,
document retrieval, compatibility retrieval and resource access. Historical
sampling covered oldest, middle, merge, recent and advertised non-main tip commits
for each repository. All ten samples passed raw-source/resource checks; seven
also passed normalized retrieval and search. Three early snapshots used README
raw-source fallback because they contained no projected article or feature and
explicitly report that inapplicability.
The previously failing content advertised-tip search passed with the unchanged
15-second processing bound.

Offline resumes preserve the same observations. The successful final invocation
made zero new provider requests. The legacy run's durable ledger conservatively
reserves the entire 20-attempt allowance; this upper bound is not a measured count
of actual requests. The retained native volume used approximately 60 GiB with
179 GiB available, within the 256 GiB ceiling and 10 GiB minimum-free requirement.

Processor generation 3 shares normalized article projections across formatting-only
source edits. Each snapshot still identifies its own raw source object; generation
2 captures remain retained. The current content snapshot accounts for 16,404 raw
files and contains 14,719 searchable article members, with 13,246 members carrying
explicit projection gaps. The compatibility snapshot accounts for 3,315 raw files, 20,913 feature
members and one explicit gap. The gate counted 368,935,287 gap memberships across
retained snapshots, including prior generations and repeated memberships; this is
not a count of unique unsupported files. Explicit gaps preserve raw evidence.
These results establish the agreed inert processing and retention scope, not full
upstream Yari rendering equivalence or execution of embedded examples.

During an acceptance restart, two task-owned PostgreSQL containers briefly mounted
the same retained directory. The replacement stayed in startup synchronization;
it was stopped before another probe ran. After both servers stopped, a separate
backup of the database directory was made and kept. PostgreSQL `pg_amcheck --heapallindexed
--parent-check` passed, and an offline application integrity check verified
1,041,210 inventory node hashes, accounting for 1,615 then-retained snapshots and
the latest index artifacts. SQL checks found no missing child, projection or
snapshot-alias references. No restore was required. The runner now holds an
exclusive root lock through child cleanup, rejects surviving owner-labelled
containers and stops its PostgreSQL container gracefully. These checks establish
the inspected checkpoint's integrity; they do not replace the final full-source
gate.

The final gate subsequently passed with the retained driver's successful
`acceptance.json`, both finished ancestry queues, accounted snapshots, validated
index artifacts and pinned current/historical research. The retained database,
Git objects, raw captures, indexes and integrity backup were preserved after
stopping the acceptance PostgreSQL container. See
[operations](operations.md#mdn-collection-repair-and-full-acceptance) for retention,
quotas and recovery.
