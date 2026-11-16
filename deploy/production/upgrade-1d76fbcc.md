# Schema-19 production deployment

Use the new `upgrade_1d76fbcc.py`, `checkpoint_1d76fbcc.py`,
`restore_1d76fbcc.py` and `acceptance_1d76fbcc` sources together. Existing frozen
controllers, consumed original/continuation intents and failed evidence remain
unchanged. This procedure starts from the exact withdrawn schema-18 predecessor,
not an accepted running `91c7bcb7` service.

The target is signed release `0.1.0-build.1d76fbcc`, commit
`1d76fbcc5693efc9ca927fd05f942078f667f056`. Qualify its native architecture CI,
source archive, four image families, provenance and anonymous platform downloads
separately. Keep server/probe references pinned to the published image digests.
No rebuild or publication is part of deployment.

The [2026-11-16 execution record](upgrade-1d76fbcc-cycle2-evidence.md) records
that cycle as failed and finally withdrawn after successful restoration. Its
consumed scopes cannot be replayed. The procedure below documents its gates; it
does not authorize another production attempt.

The separately approved 2026-11-16 cycle uses `cycle2_1d76fbcc.py` to render fresh
sources from signed corrective commit `93426e7`. Rendering writes 24 reviewed
source files and their provenance below a new `/tmp` directory; add the two
qualified native-probe records and bind the resulting exact 26-file manifest
before installation. It preserves the consumed first-cycle sources and journals.
The new admission requires that cycle's verified schema-18 restoration and
withdrawn fallback state. Keep the actual paused Secret preimage separate from
the original active source settings retained in its bound fallback-active
configuration. Historical source files, bounded journal/log bytes and directory
inventories are pinned throughout the new cycle. Fresh checkpoint, isolated
reader/writer proof and actual Restore rehearsal evidence remain mandatory.

## Admission and checkpoint

Install the reviewed successor sources root-private in a new versioned directory.
Stage all acceptance sources, the exact canonical smoke client, diagnostic
supervision modules, source archives and qualified native probe identities in a
fresh private task directory. The external source-manifest digest binds every
producer and helper before import; the checkpoint additionally binds its imported
historical dependency sources. Never copy credentials into arguments or evidence.

Require explicit context `default`, namespace `devres`, exact namespace/node/PV
identities, static role-separated S3 credentials, policy 2, archive epoch 2, no
publication owner and no application Pod. Preparation admits four immutable config
candidates: target/fallback, paused/active. Paused serving retains the client section required by the immutable release,
but points it at loopback port 9 and an absent token path in its read-only
projection. This disables foreground delegation as well as all nine collectors
and npm advisories. Active candidates restore the original settings and offer the
matching release source archive.

Create a fresh clean physical PostgreSQL checkpoint while applications remain
stopped. Bind complete ordered capture/archive manifests, original roles/grants,
policy and historical notice generation. Preserve full pre-task serving/writer
caches and Git working state in separate, checksummed durable copies. Preflight
actual concurrent database/cache copies, rehearsal/restoration staging, growth and
128 GiB reserve. Never delete or rotate existing cache generations to pass admission.

The checkpoint state is exposed below `/tmp` through a verified disk-backed bind
mount; the golden checkpoint and recovery journal remain durable. Reject tmpfs
for these large retained artifacts. Rehearse the current schema-18 reader and
`91c7bcb7` writer against cloned SQL and copied caches, with read-only S3 credentials,
independent source-egress denial and no public listener. Verify actual reader
SQL authority, exact fixed RFC bytes and complete current/historical notices.
Then execute the exact new Restore state machine against another isolated real
PostgreSQL copy of that golden checkpoint, including actual clean stop, staged
copy, journalled database/cache replacement and restart. A clone-only SQL marker
must disappear after restoration. Keep the production admission files unchanged;
verify current live PostgreSQL separately. Preserve the original backup receipt
and produce a fresh revalidated envelope after the rehearsal. The target runner
rejects missing, stale, wrong-source or changed-golden rehearsal evidence before
any application mutation.

This recovery proof assumes the original immutable S3 survives. It makes no
independent bucket backup or bucket-loss recovery claim.

If the isolated proof has already consumed its intent and failed, preserve its
journals, source manifest, golden checkpoint and private inputs. Do not replay it
or edit its frozen producer. `proof_continuation_1d76fbcc.py` admits one separate
scope using an externally pinned source and admission digest. It restores only
the copied writer's original cache ceiling: the initial proof's 64 MiB ceiling
cannot hold the retained, non-evictable Git working state. It verifies all original
checkpoint and failed-proof hashes, captures bounded redacted diagnostics before
cleanup, and publishes missing successful evidence with explicit provenance.
Partial publication requires reconciliation; it never permits another proof
attempt. This correction does not change production configuration or establish
the unretained first failure's exact exception.

## Exact incident and rollout

The schema-18 incident job selected by this successor becomes migration-created
revision 1 with `cause_authoritative=false`. Migration does not authenticate its
historical cause. While collection and delegation remain paused, the exact new
CLI verifies its sealed ineligibility and records deferral. It never rearms the
job or invents evidence. Different/new authoritative history is a changed
admission and fails this rollout; this exact successor does not broaden selection.
Positive recovery mechanisms and fixtures remain separate from this incident's
operational outcome and require their own schema-19 checkpoint and admission.

Start target writer first, verify schema 19 and reader grants, perform the exact
read-only npm assessment with an isolated ephemeral maintenance Pod, then renew
the process-bound migration proof before starting the reader. Assessment has no
PVC, hostPath, writer credentials or publication authority. Keep its report in an
owned private directory on the existing `/tmp` emptyDir. After the exact CLI
succeeds, transfer a bounded metadata-and-report frame through private exec,
bookended by the Pod UID and container identity. Delete the Pod before persisting
the root-private report; never place report JSON in container logs. Validate the
exact Pod against production restricted admission before a new deployment cycle.
After private/paused acceptance, restore the exact original nine source settings.
Keep unqualified RFC errata blocked. Do not reset queues, reindex or run a separate
source-provider live probe.

For both protocol revisions, require IPv4 and IPv6 HTTP/native WebTransport,
gzip/Brotli/Zstandard SSE decoding, no-store/Vary, certificate/token negatives,
private isolation, original fixed bytes/notices and matching inventory/source
offer. Run fresh early acceptance, at least 900 monotonic seconds with at least
31 samples (default 32, gaps at most 45 seconds), and fresh late acceptance. Require
one stable writer owner, stable process/restart identities, preserved authority,
settings/archive binding, operational timer entrypoints and disk reserve.

Run the source-bound `deploy.py --runtime target --source-manifest-sha256 HASH`
only after the controller is `stopped` and the checkpoint proof is complete.
Install the versioned supervisor as a root-only systemd oneshot with
`KillMode=control-group`, bounded start/stop deadlines and an `ExecStopPost` fence.
The fence runs after original children stop; SSH loss does not cancel supervision.
SIGKILL during an already consumed restore requires the restore helper's explicit
identity-based reconciliation rather than another automatic restore attempt.
Private diagnostic persistence never delays the independent withdrawal fence.

## One automatic fallback

On target failure, stop all application/maintenance participants and require no
publication owner. Attempt to preserve the post-task database and bounded runtime
evidence. The operator accepts that this preservation can fail and post-task SQL
history can be lost; record that outcome honestly. Never waive exact cluster/PV/
PGDATA identity, clean stopped PostgreSQL, verified golden checkpoint or original
S3 binding. An unproved mandatory fence leaves applications stopped.

Prepare a fresh verified restoration directory, fsync it and use journalled
same-filesystem renames. A lost rename response is reconciled by path/inode
identity, never blind replay. Restore the fresh pre-task schema-18 checkpoint,
restore qualified baseline caches while preserving task-mutated cache generations,
and start pinned PostgreSQL. Keep all S3 objects; never rewind the prefix, binding
or epoch. New objects can remain unreferenced by restored SQL.

Prepare the admitted `91c7bcb7` fallback in the new journal, start its sole writer
before reader and repeat complete paused/active, dual-stack, observation and late
acceptance with its own source/probe identities. Its old failed attempts remain
failed. Fallback failure withdraws applications without another restore or retry.
Select the fallback environment before creating its Python process: the lifetime
guard's `sitecustomize` imports runtime globals before command-line parsing.
Report target acceptance, target failure with accepted fallback, and incomplete
restoration/service recovery as distinct results.

Normal provider clocks are process-local. Preserve original rates and applicable
backoff state and wait at least the slowest configured host interval before writer
restarts; do not claim globally durable normal-collector attempt accounting. No
finite operational probe budget may be replenished by a new root or restored SQL.

## Verification

Run the full contributor checks, Python suite, exact production PostgreSQL fixture,
pinned OxiBelt and both filesystem/S3 credential-broker minikube modes. Test schema
transition and process-bound receipts, changed incident provenance, uncertain
withdrawal, preservation failures, restore copy/fsync/rename crash cuts, retained
newer S3 objects, cache working state and target/fallback failure supervision.
Independent MCP/API, Upstream/Storage and Security Boundary reviews must inspect
actual integrated callers. Agent review is not human GitHub approval.
