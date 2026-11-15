# Schema-19 deployment execution, 2026-11-15

The target `0.1.0-build.1d76fbcc` was not accepted. The single automatic physical
restore succeeded, but fallback startup also failed. The final application state
is withdrawn: backend and writer replicas and Pods are zero; PostgreSQL is ready
on schema 18. Neither target nor fallback public service acceptance completed.
No additional deployment or restore was attempted.

## Qualified release and local checks

The target commit is `1d76fbcc5693efc9ca927fd05f942078f667f056`.
Its signed tag, source archive, all four published image families, provenance and
anonymous amd64/arm64 downloads were qualified independently. Native release CI
run `43718346256` completed all 12 jobs; publication run `43724240318` succeeded.
The server index is
`sha256:7f6e3bbe220370c3db65a23c5a44062ebf44dd35ebf7ddf906cee994027cecd7`.
These establish release qualification, not production acceptance.

Local contributor gates passed: formatting, clippy, workspace tests, current
advisory/vendored/dependency checks, both PostgreSQL fixture paths, pinned
OxiBelt, and filesystem/S3 credential-broker minikube acceptance. Local Rust
execution was amd64; hosted arm64 evidence is separate. The initial integrated
Python run completed 1,329 tests with four skips.

## Checkpoint and restore evidence

The clean physical checkpoint retained 25.705 GiB across 1,795 PostgreSQL files,
plus complete writer and serving cache baselines. Original PostgreSQL was first
restarted without restoration. The initial isolated writer proof failed; its
exception output was not retained. Independent inspection proved that its 64 MiB
cache ceiling could not hold approximately 101 MiB of retained, non-evictable
working state. This establishes a definite configuration defect, not the exact
unretained exception.

A separately admitted proof scope restored only the copied writer's original
64 GiB ceiling. Original frozen sources and failed journals stayed unchanged.
Old-writer readiness, retained SQL state, fixed reader bytes and current/historical
notices passed. All proof containers, networks and nft fences were removed.
Independent review checked all 32 backup artifacts. Diagnostics contain duplicated
writer/reader state records and empty-log placeholders; PostgreSQL diagnostics
were omitted by the mixed short/full-ID cap. SQL and readback evidence remain
separate from that diagnostic coverage limitation.

The exact new Restore class then passed against another isolated real PostgreSQL
copy and full baseline caches. Its clone-only marker disappeared; directory/cache
replacement, restart, archive/system identity and cleanup passed. Recorded
production admission/checkpoint bookends were unchanged. The fresh revalidated
backup bound 35 artifacts. Rehearsal receipt
`7b03f7b1375ae258786b2082b5d9986094a54e522853c7d0330c4c7b93f1e07b`
preceded main supervisor startup by approximately 38 seconds.

Recovery assumes the original immutable S3 survives. No independent bucket backup,
bucket-loss recovery or complete remote object reread was performed.

## Attempt and failure causes

The frozen execution manifest was
`f166396d51045a64b9fafda6b4d171c175460a8d5ab0bedc80bffa35f70910a9`.
Its implementation is recorded in signed commit `de61021`; the separate proof
continuation is recorded in signed commit `0fd2f77`.
Target apply, writer startup and process-bound schema-19 migration checks passed.
The npm assessment Pod was rejected before its CLI ran: its report hostPath
violated the namespace's `restricted:latest` PodSecurity policy. A server-only
dry run reproduced the exact rejection without creating a Pod. Consequently,
this execution produced no npm assessment or deferral receipt and performed no
recovery apply/run operation.

Supervision withdrew applications and performed its single automatic restoration
of the original schema-18 database and baseline caches. It retained S3 objects
without rewinding the archive binding or epoch. The restored PostgreSQL process
has no restart recorded.

Independent final verification compared complete streamed SQL manifests:
374,733 archive rows and 75,499 capture rows exactly matched the original bytes.
Both live cache trees exactly matched their baselines. The post-task schema-19
directory was preserved with its original inode and verified manifest;
`preservation=manifest_verified` and `preserved_directory=true`. No publication
owner or maintenance Pod remained.

The fallback child failed before its deployment intent. Python startup imported
`acceptance_common` through `sitecustomize` under the inherited target environment;
subsequent fallback argument parsing could not change those cached globals. A
read-only reproduction confirmed the mismatch. The supervisor fenced both roles
again. This was a launcher failure, not failed public protocol acceptance.

## Corrective preparation

The local correction replaces hostPath reporting with a private ephemeral report
and bounded UID/container-bound exec transfer. Fallback environment selection now
precedes interpreter startup, preserving the parent's target identity and lifetime
guards. Real Python startup tests cover the original mismatch, corrected fallback
identities, child failure and timeout withdrawal.

The exact immutable target image passed the private-file transport exercise under
UID 65532, a read-only root, dropped capabilities and no network. The corrected
Pod and bounded exec transfer also passed a fresh restricted-policy minikube
fixture. That fixture used a fixed public metadata report, so it proves the
transport rather than real incident eligibility or production CLI execution.
An exact server-only dry run also admitted the corrected Pod under the production
restricted policy, preserving its actual node, service account and Localhost
AppArmor profile. No Pod was created and no CLI ran. The candidate source digest
is `4de176ca92fb9dd21f48489bcc2827923cd1d581832643f3bf705d2bf895926a`;
the admitted Pod specification digest is
`433bbb06a47111b133b7c0f3d3d79984c6b293affbf719b33ff6704b912f936e`.
The final integrated Python run completed 1,345 tests with four skips. Independent
review reran 15 assessment, four real fallback-startup and 62 acceptance lifetime/
failure tests, all passing. Whitespace and changed Markdown links also passed.

These corrections were not installed into the consumed remote execution. A new
deployment needs a fresh reviewed execution scope, source/admission bindings and
checkpoint; the consumed target, fallback and restore intents cannot be replayed.
No production stability observation, final dual-stack HTTP/WebTransport matrix,
full provider/corpus acceptance or native ChatGPT UI acceptance is claimed.
