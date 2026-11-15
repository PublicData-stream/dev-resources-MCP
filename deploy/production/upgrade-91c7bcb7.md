# Same-schema production upgrade to 91c7bcb7

Deploy the immutable `0.1.0-build.91c7bcb7` release using the reviewed
`upgrade_91c7bcb7.py` successor and `checkpoint_91c7bcb7.py`, with explicit
context `default` and namespace `devres`. This procedure preserves schema 18,
policy 2, static role-separated S3 authentication, all nine existing source
settings, permanent evidence and the admitted SSE compression successor.

The server image index is
`sha256:1b1bf21d339920e8ddd69449d82c9895c3423509e8016a72b2df46a38d8e7b6c`;
the probe index is
`sha256:a0ed3b468b3e7e23b395d2227b66878832cdf149aa4aac28738e8e5aca0cb588`.
Corresponding source has SHA-256
`d92b3850074b3155866a376824b0a625151be17a260e4ea7bae058fb46f224a9`.
Qualify the signed tag, native CI, image provenance, anonymous pulls and source
archive separately before production changes. Do not rebuild or republish it.

## Preparation and checkpoint

Install sources root-private at `/usr/local/libexec/devres-upgrade-91c7bcb7`.
Stage the reviewed `acceptance_91c7bcb7` producers and the exact target revision's
`scripts/mcp_smoke.py` under the task's owned temporary root. Source hashes are
checked before import or receipt aggregation. Preserve the frozen predecessor,
its configuration and every journal. Only application image/source URLs and
bounded pause/resume switches may change; no credential or edge rotation occurs.

After contributor checks and independent boundary reviews, prepare a fresh
inventory within 300 seconds. Acquire the existing S3 store claim once with the
admitted reader credentials. Bind the actual helper/controller/prepared hashes,
selected current attribution target and fixed readable RFC control in checkpoint
inputs. Keep credentials out of arguments, output and committed evidence.

Preflight space for three measured database copies plus working-state growth and
128 GiB reserve. Mount the new durable `checkpoint-volume` directory at the
helper's initially empty `/tmp` checkpoint-state directory; reject tmpfs and
unverified mounts. The golden copy and journal survive disposable cleanup.
Perform live precopy, stop backend before writer, then recheck both cache trees
with runtime exclusions and startup headroom. Insufficient capacity stops the
operation before image mutation; this procedure authorizes no cache deletion or
rotation.

Complete the clean PostgreSQL checkpoint and restart the original database
without restoring it. Rehearse an isolated old reader against the cloned DB,
original S3 and empty cache. Disable all nine collectors, npm advisory collection
and effective writer forwarding in that clone. Require current policy-2 sealed
state/generations, exact capture-fixed RFC bytes, complete current and historical
notice pages, native reader authentication and unchanged SQL authority.

This recovery proof assumes the original immutable S3 survives. It neither makes
an independent S3 backup nor verifies every remote object or bucket-loss recovery.

## Activation and evidence

Use the source-bound phase driver for stop/apply/start/accept/finish operations.
It retains single-use intents and results and attempts guarded application
withdrawal on failure. Never replay an uncertain mutation. Apply requires the
fresh schema-18 checkpoint receipt and admits only its explicitly verified
PostgreSQL process replacement.

Start paused writer before reader, validate archive/history and policy/authority,
then run private acceptance and dual-stack HTTP/WebTransport on both supported
protocol revisions. Require gzip/Brotli/Zstd decoded SSE, `no-store` and
`Vary: Accept-Encoding`, exact inventory/source offer, certificate/token rejection
and private network denial controls. The previously readable RFC control must
remain readable. Restore the exact original collection settings and repeat
active acceptance with unchanged process bookends.

Observe at least 900 monotonic seconds, at least 31 guarded samples and gaps no
larger than 45 seconds. The default loop collects 32 samples to avoid boundary
rounding. Require one unchanged writer owner, stable processes/restart counters,
original archive binding, preserved authority/settings, active timers and disk
reserve. Receipts bind actual producer/source hashes, artifacts, processes and
configuration phase; active observation samples are parsed again by the controller.

Keep deployment acceptance separate from due-retry/expired-lease recovery results.
Do not reset queues, revive terminal jobs, reindex or apply RustSec recovery.
[Terminal recovery design](../../docs/terminal-recovery-design.md) describes later
exact-state recipes without authorizing their implementation/application or
changing policy-2 errata withholding. No separate source-provider live probe is
part of this operation.

If required activation checks fail, stop backend/writer and retain all checkpoint,
new-history and failure evidence. Automatic data restore or old-image swap is not
offered. Reconcile failures before a reviewed forward recovery or explicit restore.
