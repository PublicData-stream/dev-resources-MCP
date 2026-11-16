# Second schema-19 deployment execution, 2026-11-16

The separately approved second cycle did not accept `0.1.0-build.1d76fbcc`.
Its one physical schema-18 restoration succeeded. The admitted `91c7bcb7`
fallback started both application roles, then failed private acceptance.
Final application state is withdrawn: backend and writer replicas and Pods are
zero, the nine providers are paused, and only PostgreSQL remains ready on schema
18. Neither target nor fallback completed public service acceptance. This record
is separate from the [first cycle](upgrade-1d76fbcc-evidence.md).

## Fresh admission and recovery gates

Signed commit `947aadd` records the fresh-cycle renderer. It rendered the reviewed
corrections from signed commit `93426e7` into a new execution scope. Original
consumed sources, intents and failed journals were retained unchanged. The exact
26-source execution manifest was
`c89d1543fbefa7de5b8c8174f23fffa97da958650dd9ecacb2b4826f381c1259`.
Desired active settings retained the original nine providers; the actually paused
preimage was recorded separately.

Release qualification from the first cycle was reused for the same immutable
target, source archive, server/probe digests and native CI. No rebuild, registry
publication or fresh anonymous-pull qualification is claimed. Both newly copied
native probes passed hash verification and dropped-UID, no-network execution.
The corrected npm Pod passed an exact production server-only admission dry run;
that gate created no Pod and ran no CLI. The integrated preactivation Python
suite passed 1,367 tests with four skips. Earlier local Rust, dependency,
PostgreSQL, OxiBelt and both minikube storage modes are recorded separately in
the first-cycle evidence; this was not a new execution of those gates.

A new clean physical checkpoint and full cache baselines passed isolated old
writer readiness, unchanged retained SQL, fixed reader bytes and complete
current/historical notices. The writer retained its original 64 GiB ceiling.
All proof containers, networks and fences were removed. The fresh completed
checkpoint digest was
`3ad73025e305c5eed8236065b1956c1137fb8e9221ad41791a96c779825753ff`;
its backup receipt digest was
`ebbadb428c0892c78432ff8e119c99370851c1bcf18cfd4cabf539bbac402146`.

The actual new Restore class passed a separate real PostgreSQL/full-cache
rehearsal. The clone-only marker disappeared; database/cache replacement,
restart, cleanup and unchanged production bookends passed. Its receipt digest
was `0c9cd5629901e5ccc19b6f4c4adca429bd1dfbad6f45164a2a14fd4f786ef76c`.
Fresh revalidation preceded main supervisor startup by approximately 107 seconds.
Recovery still assumes the original immutable S3 survives: there is no independent
bucket backup or bucket-loss recovery claim.

## Target and fallback failures

Target apply, writer startup and process-bound schema-19 migration passed.
The corrected restricted-policy npm assessment Pod was created and started, then
deleted approximately two seconds later. Its UID-bound intent, admission and
identity records exist, but no assessment report or completion receipt does.
The stage exited with a generic failure; stderr was empty. Retained events show
normal scheduling/startup, without a warning. Its deleted container logs cannot
establish the underlying CLI/configuration/transfer failure. No npm deferral,
positive eligibility or recovery apply/run is claimed.

Supervision withdrew the applications and used its one automatic physical restore.
The original schema-18 database and baseline caches were installed; S3 binding,
prefix and epoch were not rewound. The post-task schema-19 directory and both
mutated cache generations were preserved with their original identities.
The restoration journal records `preservation=manifest_verified` and
`preserved_directory=true`.

Fallback startup now passed writer, migration, reader and private-before
operational checks. This confirms that the previous Python startup-environment
defect was corrected for this execution. The next private acceptance helper
failed with `AssertionError`. Its old generic exception record retained neither
an assertion location nor the preceding RPC metadata. Exact failed assertion and
request cannot be reconstructed from that record. No public acceptance or
stability observation started. The supervisor withdrew both roles again and
exited with status 1; no further production retry or restore was performed.

## Independent final restoration checks

Complete streamed SQL manifests matched the fresh checkpoint byte-for-byte:
374,733 archive rows and 75,499 capture rows. PostgreSQL was ready on schema 18,
with no restart or publication owner. No maintenance Pod remained. Serving cache
matched its full baseline manifest. Writer cache retained all contents, sizes,
links, path layout, UID/GID and root attributes across 231,074 rows and
11,601,697,103 bytes. Its full current manifest differs in 12,499 POSIX modes:
12,430 files changed from 0644 to 0664, 44 from 0600 to 0660, 22 directories from
02755 to 02775, and three files from 0444 to 0664. This is consistent with volume
fsGroup permission application during fallback startup; the actor was not
independently logged. The Restore class verified the complete baseline before
that startup. No content loss or complete current mode equality is claimed.

The independently verified restoration/withdrawal review digest was
`fda44abbb8b56c94c8e50fdb33a363838531c6d38e60e3a6d4adf0bc7ef4a3ac`.
Free storage at that check was approximately 233 GiB, above the 128 GiB reserve.
Historical source manifests and bounded journals remained unchanged. These
checks establish restoration and withdrawal, not accepted fallback service.

## Subsequent isolated diagnosis

Diagnosis uses copied data with separate owned resources and bounded cleanup;
it does not authorize another production cycle. The first diagnostic drivers
failed before creating any Docker resource: their absence check did not accept
the server Docker CLI's lowercase missing-object message. The fallback diagnostic
had already copied and verified the golden database; the npm diagnostic stopped
before its scratch-scope admission. These are diagnostic defects, not explanations
for either production failure. Both failed units, their sources and records were
retained. Separate successor scopes correct only that closed absence predicate
and execution identities; 28 independent fixture groups passed. Results below
are recorded only after execution and cleanup have been verified. The original
failed-cycle sources and journals are never modified to add retrospective evidence.

The next isolated npm diagnostic stopped before copying or running its CLI:
the currently preserved schema-19 directory no longer matched the restoration
journal's aggregate manifest. Byte size (27,519,699,690) and item count (1,832)
matched, but the original digest
`efeaedb1d0c78a379446fd40810bce36a03a155a9e632d03b76afba70647bbe2`
differed from the current digest
`e4565a542242e53e1be126705af860a80cf7a808e856929830782391e4f84bfa`.
It remained cold and retained its original directory identity. Current files are
0660 and directories 02770, all owned by UID/GID 70. Recursive volume permission
application could explain the change, but no original per-item schema-19
inventory was retained, so content equivalence and a mode-only change are
unproved. The successful restoration-time preservation check remains a dated
claim, not proof that its complete manifest stayed unchanged afterward.

The isolated fallback verified the copied schema-18 system identity and reader's
read-only default, then its reader exited before any MCP exchange. It did not
reproduce the production assertion failure. Its startup logs were not retained before cleanup, so the precise isolated
startup error is unproved. Its golden source stayed unchanged and all diagnostic
containers, networks and fences were removed. The two owned
diagnostic PostgreSQL scratch copies were subsequently discarded after cold-state,
identity, mount and Docker checks, with intent/completion records retained.
Original golden and preserved production generations were untouched.

A separately admitted current-state diagnostic then copied only the cold tree
bound to the new digest above. It explicitly recorded that equivalence to the
original preservation manifest was unproved; it did not qualify a recovery
baseline. Source/copy hashes and source bookends matched that new admission.
The exact target CLI used actual reader SQL credentials, the source-bound parent
process guard, a read-only root and isolated loopback-only PostgreSQL. It produced
a valid 397-byte report: `eligible=false`, `reason=legacy_unknown`. Report SHA-256
was `673fd0daffc072fd62616b21a3d1cb86fbcf06a45882606748c5391990de14e2`.
The exact framed transfer/parser passed. Separate clone-only metadata showed
schema 19, active integrity control, no restore-pending table, and the one selected
revision with `cause_authoritative=false`; that metadata session used local admin
with `SET LOCAL ROLE`, distinct from the actual CLI's reader authentication.
All three owned containers were removed and final cleanup passed. This proves
that copied current state supports the CLI and transport, not why the production
Kubernetes Pod failed. It is not a retrospective production deferral receipt or
proof of an authoritative historical npm failure cause.

The separately reviewed fallback diagnostic with pre-cleanup redacted state/log
capture reached a ready reader. Modern-revision `server/discover` and `tools/list`
returned HTTP 200; its next `packages.npm.corpus_status` exchange exceeded the
15-second diagnostic client deadline (the production canonical client defaults
to 45 seconds). Its metadata cache was fresh and limited to 64 MiB, and this
diagnostic did not run the checkpoint proof's cloned writer initialization. The
recorded exception was `TimeoutError` at canonical
smoke line 185, not the production helper's `AssertionError`. Reader and PostgreSQL
were still running, with zero restarts and no OOM flag; reader logs were empty
and PostgreSQL startup logs were normal. No later smoke calls or pinned-content
controls ran. The golden source stayed unchanged and container/network/fence
cleanup completed. This bounds an isolated failing call; it does not identify
the original production assertion or qualify fallback service acceptance.

Independent actual-diagnostic review digest was
`98ec46f3a0ce300b9c9de7593c9d67f157fe2d4f0a0f64c438c413dd6e43dd6c`.
After that review, the last two disposable PostgreSQL copies were discarded with
separate identity, inactive-unit, removed-container and mount checks. A stale
PID file in the forcibly removed npm test container's copy was recorded, not
interpreted as a live PostgreSQL process. All diagnostic reports, traces, logs,
source pins and discard intents/completion records remain private. The original
golden checkpoint and preserved production generations remain retained. Free
storage returned to approximately 233 GiB. A final parent closure rechecked all
26 frozen source hashes, the four discarded copy paths, retained original
directories and withdrawn replica counts; its digest was
`ca8159ad056ba934c5cc79da1812a0e9ae872604a5bbc016c269e26330667981`. This diagnostic activity issued no
public protocol or source-provider request; the fallback's explicitly permitted
archive S3 access is separate from those zero-count claims.

The local private-acceptance correction retains only the last eight closed RPC
metadata records and six traceback locations. It excludes arguments, request and
response bodies, headers, exception messages and locals. Returned protocol values,
raised exceptions and failed acceptance status remain unchanged. Independent
MCP/API and security/privacy review passed three new privacy/bounds tests and
62 existing acceptance tests.

The npm assessment correction records only a closed local phase, sanitized
exception category/helper locations, and bounded status from already observed
Pods. It does not add requests or relax any UID, restart, deadline or report
acceptance rule. UID-bound cleanup runs first; only successful cleanup permits
best-effort failure-record persistence. Capture/persistence failures preserve the
original exception, and cleanup failure still propagates to the caller's fence.
It excludes messages, arguments, locals, logs, report bytes and raw container IDs.
The full Python suite after both corrections passed 1,379 tests with four skips.
The corrections are recorded in signed commits `f5952cf` and `60fee68`.
Neither correction is installed into either consumed cycle; the existing renderer
still selects its historical source revision. Any future cycle must explicitly
bind newly reviewed sources rather than replaying this renderer's consumed scope.
A later production attempt requires a new explicitly approved cycle, fresh
admission/checkpoint bindings and resolution of its required gates. No final
HTTP/WebTransport matrix, 900-second observation, full provider/corpus acceptance
or native ChatGPT UI acceptance is claimed.
