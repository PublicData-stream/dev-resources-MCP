# MDN implementation evidence

Observed locally on Linux amd64, 2026-10-25. The implementation is in signed
commits starting at `6df125d`, through `5b5dabc`. These results do not establish hosted
arm64 execution, image publication, production deployment or native ChatGPT UI
acceptance.

| Check | Result |
| --- | --- |
| Rust 1.99.1 formatting and strict locked workspace Clippy | Passed |
| Locked workspace tests | Passed, including 218 adapter unit tests and the existing Cargo/RFC/transport suites; explicitly opt-in PostgreSQL tests ran separately |
| Current cargo-audit | Passed against 1,352 advisories and 459 locked dependencies |
| cargo-deny | Advisories, bans, licenses and sources passed; existing duplicate-version warnings remain visible |
| Python smoke-client tests | 80 passed |
| Retained driver regressions | Three passed, covering durable attempts, legacy allowance and cancellation during exclusive storage accounting |
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
The full workspace and PostgreSQL gates ran through `7f945fc`; the subsequent
immutable-reader change at `5b5dabc` passed all six targeted index tests and strict
workspace Clippy.

## Retained full-source acceptance

The retained run froze these official observations:

| Repository | Main revision | Reachable commits |
| --- | --- | ---: |
| `mdn/content` | `c6a89971a820ca6b76479a7ffc1b32c09aae2415` | 30,648 |
| `mdn/browser-compat-data` | `56e6f1217a54dfe0d25df29d0f67c6a26cdc3901` | 21,678 |

Full-source acceptance is still processing. Source acquisition succeeded, but
complete projection/index coverage and final historical research checks are not
yet established. Offline resumes preserve the same observations and make no new
provider requests. The legacy run's durable ledger conservatively reserves the
entire 20-attempt allowance.

Processor generation 3 shares normalized article projections across formatting-only
source edits. Each snapshot still identifies its own raw source object; generation
2 captures remain retained. The current content snapshot accounts for 16,404 raw
files and contains 14,719 searchable article members, with 13,246 members carrying
explicit projection gaps. The compatibility snapshot accounts for 3,315 raw files, 20,913 feature
members and one explicit gap. These are current-snapshot counts, not completed
historical acceptance or full upstream rendering equivalence.

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

The final gate requires the retained driver's successful `acceptance.json`, both
finished ancestry queues, accounted snapshots, validated index artifacts and
pinned current/historical research. Explicit projection gaps retain raw evidence;
they must be reported separately. See [operations](operations.md#mdn-collection-repair-and-full-acceptance)
for retention, quotas and recovery.
