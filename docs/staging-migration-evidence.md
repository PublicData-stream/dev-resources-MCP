# Staging migration continuation: 2026-11-07

This records successive operational snapshots. The latest target is
`0.1.0-build.78c2e9c5`, resumed on the preserved permanent pair on
**2026-11-07 14:40 UTC**. Migration and public cutover remain incomplete. The
[operator runbook](../deploy/staging/README.md) owns execution and recovery.

## Preserving target supersession: 2026-11-07

The operator explicitly authorized retrying with
[`0.1.0-build.78c2e9c5`](https://github.com/PublicData-stream/dev-resources-MCP/releases/tag/0.1.0-build.78c2e9c5),
commit `78c2e9c521b68436a7d1cc23bce54ee199ad1948`. The existing outage authority,
**2026-11-10 20:59 UTC** preserving-rollback cutoff and **23:59 UTC** operational
and credential-expiry deadline remain unchanged. The three-hour reserve is an
allowance, not measured recovery-duration evidence.

| Artifact | Verified SHA-256 |
| --- | --- |
| Server image index | `b317a2c87ea6ce337f7c1a69213eb90c22fde469ac4c73d26d9d5a68e635fff5` |
| Native amd64 server manifest | `c37b0c4db9b03025dc417fde7415083f6b5b52906f1e4f06c39a533b0c06d0aa` |
| Probe image index | `820b235d1b267bd934f85a07d020762a234975a52745bccfe80648a69a1ff05b` |
| Native amd64 probe manifest | `35c1afcefd16525568332430cf29519daed339ec965973563ad0d1c6e1fc3eb2` |
| Corresponding source archive | `b597e1a7e3c80fee7fb789724de38b6800974011a27bbb165b38e7a3a5989839` |
| Installed six-module operator bundle | `9483adc9cf45c98967d3297b24bdf2bec77ced163e2d5a4e923a13a502e140fe` |

Anonymous index/child/config reads, image labels and all 373 regular archive
members matched the signed release source or its seven generated stamps, without
extracting or executing inspected package code. Same-SHA
[native CI](https://github.com/PublicData-stream/dev-resources-MCP/actions/runs/42368891431)
and [image publication](https://github.com/PublicData-stream/dev-resources-MCP/actions/runs/42374008921)
passed; a second complete native CI run also passed. Those hosted results cover
the published runtime, separately from local operator/helper changes.

Signed commits `b9951f7` and `eb901e3` add the bounded first-party qualification
and private readback tools, then the explicit target-supersession lifecycle.
Both have the required Assisted-by trailer. No push or replacement image
publication was performed. Specification, Configuration and OxiRule were unchanged.

The old automatic continuation was stopped before any mutating acceptance
attempt. Independent preflight and actual in-host admission checks passed. The
reviewed supersession driver cooperatively stopped the old driver, migration
worker and PostgreSQL, archived the unchanged old journal/operator/configuration
capsule, and created a held coordinated checkpoint of the current partial pair.
The complete operator directory was atomically exchanged and the old installation
retained. The driver exited successfully in `upgrade_superseded_paused`.
The original operation token, dataset GUIDs, rollback snapshot, pause policy and
absolute deadline were preserved; no journal policy was manually widened.

The canonical new operator then explicitly resumed the same permanent pair.
At **14:40:58 UTC**, an owned migration worker was running with the new immutable
index and published revision, with no observed OOM. It retained the 37-CPU/192-GiB
worker profile and two-CPU/16-GiB PostgreSQL profile. The resumed worker was
revalidating retained file checkpoints; file and SQL completion markers remained
true and graph completion remained false. Incomplete lanes rescan their retained
rows, so restarted counters do not imply evidence loss. The original and new
checkpoint snapshots and their three-member holds remain protected. The existing
token-bound watchdog remains armed.

The new version's separate automatic continuation uses a freshly pinned
manifest and attempt namespace, the same explicitly approved task key and exact
sudo rule, unchanged source restriction and expiry, and the retained six-route
baseline. Actual forced-command status authenticated and matched the new target.
The coordinator was observed running in `waiting` with zero mutating attempts;
no new public acceptance or finalization was admitted early.

Before normal serving, one explicitly owned container must initialize schema
11 and qualify only the fixed retained RFC/MDN subjects and bounded compiled
dependencies. It has one global budget of at most twenty upstream attempts,
no collector/sweep runtime, and cannot obtain a new budget through automatic retry.
Its optimized binary, selectors, immutable MDN baseline and private restored-data
reader are independently hash-pinned. An inert, network-disabled loader check
passed in the exact published server image; real-source acquisition is still
pending the offline migration. Pending attribution cannot satisfy acceptance.

Local verification passed on the final implementation:

- Formatting, workspace/all-targets Clippy with denied warnings, workspace Rust
  tests, current advisory audit, and dependency/license/source policy checks.
- All **573** Python tests, including **213** focused operator lifecycle tests.
- The complete real PostgreSQL suite, including fixed queue-scope rejection before
  claims/acquisition, bounded target/generation counts and sealed-state tampering.
- The new restored-MDN reader's seven synthetic byte/history/complete UTF-8 notice
  fixtures, plus 77 acceptance and 36 server/16 client continuation fixtures.
- Pinned OxiBelt HTTP/WebTransport and isolated minikube NodePort TCP/UDP, CNI
  isolation, PVC restart and coordinated restore. The existing verified OxiBelt
  binary was reused. The completed minikube profile and generated state were
  confined to `/tmp` and cleaned up; Cargo used `/tmp/rust/target`.
- Two actual published-binary, synthetic same-pair continuation cases. One stopped
  d373 with 139 of 1,025 canonical artifact rows, then interrupted and completed
  78. The other stopped after 135 occurrence receipts and completed 2,050 under
  78. Existing physical tuples, seals, aliases, checkpoints and nonempty completed
  lanes were retained; the first missing occurrence allocated the next sequence.
  Idempotent replay, verification, activation, startup to schema 11 and restored
  query fingerprints passed. These cases establish bounded compatibility, not
  whole-corpus throughput or real-source attribution qualification.

Independent MCP/API, Storage and Security Boundary review closed the actual
implementation, cross-binary evidence, final artifact/manifests and staging/gate
activation adapters. Review is distinct from human GitHub approval. Local native
amd64 helper checks do not establish native arm64 execution of these new tools.

Remaining production gates are offline migration/verification/activation, real
fixed-source attribution qualification, new backend/public HTTP and WebTransport
for both revisions, retained original bytes and complete notices, isolation and
shared routes, schema-11 coordinated restore, original collector/timer restoration,
21 observations spanning at least ten minutes, and scoped credential cleanup.
Other historical subjects may still need attribution repair. Full-corpus
qualification and a completion time have not been established.

## Earlier release and implementation: d373818b

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

## Gated continuation armed: 2026-11-06 10:44 UTC

After separate explicit approval, the reviewed setup installed a source-restricted,
expiring SSH key for the existing operator account and an exact-command sudo rule
for the pinned root-owned continuation gate. Global SSH policy was unchanged.
The original authorized-key bytes were preserved. Whole-policy `visudo` validation,
exact installed key/rule hashes, actual strict-host-key `status` transport and
rejection of an unapproved command passed. The independent cleanup timer was
confirmed active and enabled for **2026-11-10 23:59 UTC**; successful observation
also removes only this task's key and sudo rule.

A single detached external coordinator is now waiting for R2's exact current
candidate. Its process identity was checked after detachment; its initial state
was `waiting`, with no admitted mutating stages and no transport retries. It
alone owns subsequent proof and acceptance attempts. The sequence remains fresh
external ingress/zero-egress evidence, full candidate acceptance and strict receipt,
canonical finish with coordinated restore, then 21 stability samples over at least
600 seconds and scoped credential cleanup. Every mutating stage is exclusive and
has no automatic retry. This does not claim those future checks have passed.

The coordinator survives its launching tool session; no restart of its execution
environment was tested. Before successful finish, failed progression retains the
server's canonical deadline watchdog. Finish intentionally disarms that watchdog;
a later observation failure is recorded as incomplete and does not imply automatic
rollback of an already completed candidate. At this update the migration still
reported `running_migrate_storage`, with **290,432** committed pathname qualifications
in the current pass and no observed OOM. These counters provide no total denominator
or completion-time estimate.
