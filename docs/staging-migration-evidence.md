# Staging migration continuation: 2026-11-06

This is an operational snapshot at **2026-11-06 08:53:25 UTC**, not a completed
public cutover or complete-corpus performance report. A later direct-cutover
update appears below and supersedes the earlier fresh-rehearsal plan. The
[operator runbook](../deploy/staging/README.md) owns the execution and recovery
procedure.

## Release and implementation

The requested runtime is
[`0.1.0-build.d373818b`](https://github.com/PublicData-stream/dev-resources-MCP/releases/tag/0.1.0-build.d373818b),
commit `d373818b211f9126117ce4ee5709c859e5318b84`.

| Artifact | Verified SHA-256 |
| --- | --- |
| Server image index | `4d73cb12637f737c0e09649cb8e40795e379a77408cc65410509a1c117178e10` |
| Accepted amd64 server manifest | `9e618c899acd0e3a806ceb85b265fb51aa56b9d566d0a951a3c980737b4b87a8` |
| Probe image index | `74b6e9020fe9868e7005f87ed0bc4a785dbd83a09ec9f6952b848f366d4a6512` |
| Corresponding source archive | `2ff98ccd72e9a2dc69423ca680f4a2bedebfdc2b63abb2008f13e30800974d79` |

Anonymous manifest reads matched the release assets, and the downloaded source
archive matched its checksum. The deployment host pulled both image indexes and
reported the expected revision/version labels. The accepted amd64 server artifact
also passed the local server startup and sibling audit-worker fixture gate.

The runtime release's
[native CI](https://github.com/PublicData-stream/dev-resources-MCP/actions/runs/42165225154)
and [image publication](https://github.com/PublicData-stream/dev-resources-MCP/actions/runs/42165225200)
succeeded. Those runs precede these local operator commits:

- `b5f1123`: checkpoint lifecycle, bounded cutover pause, target pins and tests.
- `105b483`: operator documentation and release digests.
- `ff14285`: runtime-directory permissions and explicit same-image bundle updates.

All three commits are GPG-signed and contain the requested Assisted-by trailer.
No push or replacement runtime publication was performed. Specification,
Configuration and OxiRule behavior was preserved.

## Local verification

Local native amd64 verification passed:

- Formatting, workspace/all-targets Clippy with warnings denied, and workspace
  tests: **745 passed, 33 ignored**.
- Current advisory audit and dependency/license/source policy checks.
- The complete PostgreSQL gate: **28 tests across 21 command results** on retry.
- Python operator/release tests: **517 passed** on the final permission-fix tree.
- Pinned OxiBelt HTTP/WebTransport acceptance, and disposable minikube NodePort
  TCP/UDP, CNI isolation, PVC restart and coordinated restore.
- Runtime startup/audit fixtures, including the immutable published amd64 server.
- The [real worker fixture](../scripts/test-staging-worker.sh): SIGTERM during
  RFC graph replay, same-pair continuation, 210 preserved checkpoint tuples,
  verification, activation and restored database query readback.

Independent Storage and Security Boundary reviews inspected the integrated
implementation and affected callers. Agent review is distinct from human GitHub
approval. Disposable test state and caches stayed below `/tmp`; Cargo used
`/tmp/rust/target`. The minikube profile and owned reproduction containers were
cleaned up.

The first PostgreSQL run returned generic `unavailable` in the legacy-history
serial/parallel test. Four unchanged focused repetitions and the full gate retry
passed; the first failure's cause remains unexplained and unreproduced. Minikube
backend startup returned generic `unavailable` while PostgreSQL initialized, then
recovered within the existing rollout bound. No test, timeout or isolation policy
was weakened.

## Remote continuation evidence

The old operator bundle was retained before an atomic directory exchange.
Read-only preflight qualified the actual earlier receipt and capsule; adoption
preserved the original database/blob pair and held snapshots. Helper files from
the earlier session were read and hashed as inert evidence.

The initial worker launch exposed a runtime reconstruction defect: `umask 077`
masked requested config/TLS directory permissions to root-only `0700`. The pair
was cleanly stopped and preserved. After verifying ownership and capsule hashes,
only runtime-directory permissions were normalized, and the same pair resumed.
An actual `upgrade-pause` then produced a clean three-member held checkpoint.

The signed fix explicitly applies `0750` with root:65532 ownership and retains
`0640` files. A strict, explicit old-bundle transition qualified its installation;
the new receipt, identity and provenance were published together. Existing
runtime config/TLS directories were separately preserved to simulate missing
`/tmp` context. The fixed operator rebuilt them with the intended permissions and
started the worker successfully. This exercised missing-runtime reconstruction;
the host was not rebooted as part of that check.

At the observation time:

- The isolated schema-10 rehearsal was running `migrate-storage` using the
  requested server image, eight workers, 64 MiB SQL and 1,024 MiB graph budgets.
- Worker limits were 37 CPUs/128 GiB; PostgreSQL limits were two CPUs/32 GiB.
  These are limits, not measured throughput or reserved capacity.
- Both owned containers were running without an observed OOM. The installed
  six-module bundle hash was
  `a719c7d0422204b2a52e8c80adb4ca6207acf0dcef47f31cc8875fc9eef8ceb0`.
- The last bounded counter observation retained **372 canonical and 5,189 legacy
  RFC snapshots**. These counts do not measure overall migration completion.
- Both live Kubernetes Deployments remained Ready. Public HTTP `server.info`
  succeeded for MCP `2025-11-25` and `2026-07-28`, reporting the existing
  `0.1.0-build.27d35cd6` service. Existing eight collector settings and the empty
  npm package list were retained.
- The backup timer remained paused for the active rehearsal; original timer
  intent and protected recovery snapshots were retained.

## Earlier remaining gates

The resumed pair must still complete verification, activation, retained readback
and both schema-10/schema-9 recovery checks. Its mixed-version, interrupted timing
is unqualified for ordinary cutover.

A root-owned, one-source-token continuation is queued to start a fresh current
complete-pair rehearsal only after those checks and the retained journal archive
succeed. Its controller passed nine bounded guard fixtures and uses only
`upgrade-rehearse --pause-scope rehearsal`. An intentional pause, failed source,
changed bundle or missing recovery proof prevents that launch. It performs no
public cutover and has no automatic retry or boot activation.

After fresh complete timing and recovery evidence are available, agree the actual
outage window and rollback reserve before permanent migration and public
acceptance. New-version public HTTP/WebTransport, isolation, `upgrade-finish`,
collector restoration and post-cutover observation remain pending. Whole-provider
coverage, complete-corpus speedup and native ChatGPT/browser acceptance have not
been established by this record.

## Authorized direct cutover: 2026-11-06 09:48 UTC

The operator authorized an immediate outage and one direct transition. The final
operational deadline is **2026-11-10 23:59 UTC**. The automatic preserving-rollback
cutoff is **2026-11-10 20:59 UTC**, leaving a three-hour recovery reserve; the
reserve does not establish an observed recovery duration.

The queued follow-up rehearsal was disconnected. The running isolated rehearsal
was cleanly paused, then formally adopted into the signed `1a05dcd` operator
bundle and retired with `upgrade-retire-rehearsal`. Its database/evidence pair,
capsules, snapshots and holds remain retained, with unqualified timing. Retirement
restored the original backup timer intent. A new coordinated daily snapshot,
`devres-20261106T093725Z-daily`, and its isolated schema-nine restore passed before
direct admission. The earlier backup failure was an `upgrade_in_progress` refusal,
not a failed data-integrity check.

The installed six-module operator bundle is
`e81e1f13abb6c84acb96c161d32680a99186705fd5445bcb99d26ef6fa6362bb`.
The integrated Python suite passed **526 tests**. Independent review covered
preserving retirement, the direct driver, and the adapted acceptance toolkit;
the latter two passed **11** and **72** mocked tests respectively.

External isolation preflight observed both TCP and UDP ingress at the server,
zero correlated egress, and zero kernel drops. Client TLS and UDP timed out. An
environment-side TCP connect response did not correspond to a server SYN-ACK.
This preflight does not replace the fresh candidate acceptance proof. A fresh
six-route shared-edge baseline was captured and hash-pinned before draining.

A root-owned systemd driver launched the canonical direct command once, with
the exact absolute cutoff and default `rehearsal` pause scope. Its durable launch
marker prevents automatic retries. At this update, the journal was
`pre_upgrade_restore`, both Kubernetes Deployments had zero desired replicas,
and the token-owned rollback timer was active and persistently enabled. The
fresh old-image restore then passed in about nine seconds, and the journal
advanced to `running_migrate_storage` on the permanent pair. The source
`pre-blake3` snapshot retains its protected three-member hold; the older rehearsal
clone is not promoted. The current worker runs the requested immutable release
with eight workers, 64 MiB SQL and 1,024 MiB graph budgets, capped at 37 CPUs and
192 GiB including its scratch space. Its private PostgreSQL is capped at two
CPUs and 16 GiB. Both Kubernetes Deployments remain stopped while these exclusive
writers run on an internal container network without host ports.

Migration, verification, activation, candidate acceptance, `upgrade-finish`,
collector restoration and ten-minute stability observation remain pending.
The separate success barrier records that acceptance is required; it never
accepts or finalizes automatically. Candidate acceptance retains both public
transports/revisions, retained RFC/MDN, mTLS/Host/Origin/CNI/external isolation,
private-health denial and all six shared-route gates. Until those gates pass,
this record does not establish a completed public deployment.

## Preserving rollback: 2026-11-06 10:06 UTC

The first direct attempt rolled back after the operator reported the fixed code
`maintenance_busy`. Its failure diagnostic still showed a running worker, no OOM
or engine error, no application-error event, and **202,240 committed file records**.
The one-minute capacity guard held the shared maintenance lock for about 141 ms;
the diagnostic followed its completion by about 60 ms. The checkpoint heartbeat
used the same nonblocking lock. These observations strongly support transient
lock contention as the cause; an exact historical lock-owner trace was not retained.

The canonical preserving rollback completed at approximately **10:00:44 UTC**.
Independent checks verified the old schema-nine database, exact old image/source,
matching original configuration and Kubernetes Secret, Ready serving pair,
retained RFC bytes and restored collector/timer intent. The failed database and
evidence datasets retain the original journaled GUIDs, are unmounted, and have
clean-shutdown proof. The restored canonical pair has matching origins at the
same protected pre-upgrade snapshot. The completed rollback's watchdog is disabled
and inactive, with no cleanup pending.

Public HTTP and WebTransport both passed both protocol revisions after recovery;
HTTP reported the exact old release and source URL. The first WebTransport check
failed transiently; both repeated checks passed without an edge restart. All six
shared-route and configuration/certificate comparisons passed.

A bounded lock-acquisition fix and separately reviewed second-attempt admission
are required before another permanent migration. The incomplete continuation
scripts remain inert; no temporary SSH authorization or sudoers capability was
installed. The requested new release is **not yet publicly deployed**.

## Second direct attempt: 2026-11-06 10:38 UTC

Signed commit `1f88ffb` adds the bounded lock-acquisition wait described in the
runbook. Only acquisition contention is retried; safety-check failures remain
fatal and time spent waiting counts against the original absolute deadline.
The final Python suite passed **534 tests**. Independent upgrade review included
real short-lived and persistently held locks, safety-check failures, and deadline
and recovery behavior. No Rust runtime or public-contract behavior changed.

The new six-module operator bundle is
`baccc7148563d0b15153edb40b711b8b4b4274baabe45702121a10af74f58c5f`.
A separately reviewed terminal qualifier verified the actual recovered old pair,
configuration/Secret, capacity, collector/timer intent, retained RFC bytes, failed
pair GUIDs, clone origins and protected holds before installation. Its **16**
fixtures included actual atomic directory exchange and interrupted-install
preservation. The unchanged first-attempt journal was archived, the previous
operator retained, and the complete bundle atomically exchanged. A fresh full
six-route comparison requalified the retained pre-cutover baseline; a new R2
baseline was not claimed.

R2 uses separate plan, launch, outcome, log and service identities. It does not
reset the first attempt's markers or adopt/edit its journal. The fixed deadline
remains **2026-11-10 20:59 UTC**, with the same three-hour reserve. The canonical
direct command started at approximately **10:24 UTC**. Its new old-image restore
passed in about nine seconds; its new three-member pre-upgrade snapshot is held.

Independent live checks verified the requested worker/PostgreSQL images and
resource profiles, canonical permanent mounts, exact driver identity, stopped
Kubernetes writers and active/enabled watchdog. The worker continued across
multiple successful periodic guard runs. At this update, it remained in
`running_migrate_storage` without OOM and had committed **235,520 file records**,
beyond the earlier contention failure point. This is not a completion percentage.

The v3 acceptance manifest pins the new bundle and unchanged reviewed helpers.
The optional external continuation server/client and narrowly scoped capability
setup/cleanup passed independent fixture review (**33/16/13/11 tests**). Capability
installation has not executed; the existing SSH-MCP path remains available for
the full manual candidate acceptance. New-release public acceptance, coordinated
post-migration restore, collector restoration and ten-minute stability observation
remain pending.
