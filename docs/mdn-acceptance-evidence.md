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

## 2026-11-14 diagnostic and cursor repair

This change adds bounded private MDN inspection, separate current/history
diagnostics and explicit byte/commit history units. Commit paging now rejects a
retained artifact whose length disagrees with its descriptor, including at EOF.
Source identities, processor generation 3, historical selectors, collection
budgets and the existing paired-view publication transaction remain unchanged.

Validation caught stack growth from the new asynchronous diagnostic wrappers.
Operation futures are now boxed before entering those wrappers; the existing
ambiguity regression passes on its unchanged default test stack. The historical
immutability regression compares the same explicit content selector before and
after publication, preserving the rule that historical content does not receive
implicit compatibility enrichment.

The fixture coverage includes current publication with 103 historical commits
still unprocessed, independent phase failures and replay, preserved defaults and
historical reads, sanitized failures, unavailable diagnostic storage, and byte
cursor integrity. PostgreSQL/S3 inspector fixtures distinguish prepared from
published pairs, retain pinned old history, validate ordinary/rebuilt/migrated
identities, and check each selected archive binding even when two paths contain
identical bytes. Engine readability and attribution qualification remain explicitly
outside metadata inspection.

Independent agent reviews covered MCP/API, upstream/storage and security
boundaries. They are separate from human GitHub approval and executed acceptance.
The November production incident's exact failing operation remains unproven;
these changes do not establish a parser defect, history starvation or a need for
index maintenance. No production deployment or recovery is part of this delivery.

The acceptance driver now establishes its durable attempt ledger before storage
bootstrap creates blob metadata. A real PostgreSQL regression verifies that fresh
startup retains zero attempts, interruption before broker creation preserves that
ledger, and subsequent accounting remains monotonic. Existing legacy conservative
reservations and the shared twenty-attempt ceiling are unchanged. The regression
is included in the PostgreSQL gate.

| Check | Observed result |
| --- | --- |
| Rust 1.99.1 formatting and strict locked workspace Clippy | Passed locally on Linux amd64 |
| Locked workspace tests | Passed |
| Fresh advisory audit, dependency policy and vendored-source audit | Passed; no dependency or policy exceptions added |
| Real PostgreSQL and S3 fixtures | Passed, including MDN inspection and attribution exclusion |
| Acceptance startup/resume regression | Eight ordinary example tests and the new disposable PostgreSQL fixture passed; strict example Clippy passed |
| Pinned OxiBelt HTTP/WebTransport | Passed with synthetic retained evidence |
| Disposable minikube | TCP/UDP routing, CNI isolation, PVC restart and coordinated restore passed |
| Bounded official current-source acceptance | Passed with 6 of 20 allowed attempts and `full_history: false` |

The final optional-index-reference compatibility case was executed in the
PostgreSQL inspector fixture after the full workspace run. The later startup-only
driver fix was checked through its example suite and real PostgreSQL regression.
One concurrent migration fixture run hit its unchanged first-batch deadline;
the unchanged full PostgreSQL gate passed when rerun serially. No cause is inferred
from that timing difference.

The current-source run froze content revision
`deca95e12eeba261ff77a5e4db4575da16d0c1f5` and compatibility revision
`69fcf3608174a8b18716318d31bf3a1031af0244`. Both main snapshots produced paired
view `blake3:a8390b5cc166f2d11e0cb66aee703e38d0667fb101e9d0d731f021735d4fce13`.
Frozen content search, document retrieval, compatibility retrieval and resource
access passed. The current diagnostic reports `succeeded` at `default_publication`.

| Selected snapshot | Raw members | Searchable members | Memberships with explicit projection gaps |
| --- | ---: | ---: | ---: |
| Content main | 16,440 | 14,748 | 13,290 |
| Compatibility main | 3,336 | 20,982 | 1 |

Compatibility features and browsers are derived inventory memberships in addition
to the raw files. Gap memberships are not acquisition failures or unique parser defects.
History processing was not started; the observation graphs contain 30,779 content
and 21,790 compatibility commits, not that many processed historical snapshots.
Current-mode `verification` is null: the full inventory/index/history verification
pass was not run. The driver retains the database, raw evidence, indexes and
checkpoints and requests graceful shutdown of its owned PostgreSQL container.

The earlier October full-history result above remains historical evidence.
Current-source acceptance uses frozen adapter research reads; it does not establish
application attribution qualification, unpinned public MCP serving, native hosted
architecture CI or production acceptance.
