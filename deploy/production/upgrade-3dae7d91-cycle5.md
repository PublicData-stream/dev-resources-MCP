# Fifth-cycle execution of the unchanged 3dae7d91 release

The [fresh-cycle plan](upgrade-3dae7d91-next-cycle-plan.md) was approved on
2026-11-18. The preceding [failed execution](upgrade-3dae7d91-evidence.md), its
installed sources, restoration and consumed intents remain historical evidence.
This cycle permits one new native store-claim admission GET, physical checkpoint,
isolated old-reader/writer proof, actual Restore rehearsal and supervised target
attempt. Target failure permits one physical schema-18 restoration followed by
PostgreSQL-only withdrawal. No fallback application or automatic retry is allowed.

The application remains release `0.1.0-build.3dae7d91`, commit
`3dae7d914baa9379abc402c5a3bcf311e0db01bf`, server index
`sha256:49a899c3c4f0b5d13532ff641f7583b329adea930d1e3877de07a3e5fde91d17`
and probe index
`sha256:de8663204451207ede70d790942fa5903a640ecbd3430967915f806b15dc5f4f`.
The new operational tooling does not rebuild either image.

## Fresh sources and predecessor admission

Render [cycle5_3dae7d91.py](cycle5_3dae7d91.py) into an exclusively created private
directory under `/tmp`, binding the consumed fourth-cycle controller
`8290b5388a4a02391d441dd56bd803830389e01d3037bb30916de487559c8a4e` and source manifest
`a23b1015e38926627bfe2d8883d3ebe46d9c23dadcbe68ba1695529f0808be5e`.
Use the fresh fifth-cycle work, bundle, installation, assessment, probe and journal
scopes defined by the renderer. The local rendering base includes the baseline
correction; it is not the consumed predecessor's actual source identity.

Before construction or installation, independently review the rendered sources,
their affected callers and the complete historical closure. Preserve all older
source inventories and the fourth cycle's additional edge/assessment sources.
The dependency set is exactly the pinned preceding 29 dependencies plus its
eight installed helpers, for 37 paths; an omitted, substituted or 38th dependency
is refused. The frozen predecessor compatibility facade must keep original
files, code objects, globals and environment unchanged, retain source and native
edge checks, and refuse mutation through the facade.

Admit the restored schema-18 PostgreSQL process and withdrawn application
templates as actually observed. Both app templates currently reference the target
image; preserve those preimages separately from the legacy schema-18 image used
only by the isolated old-reader/writer proof. Preserve actual paused Secret
preimages separately from the desired active configuration. The latter must be
derived from its checked historical artifact, including provider flags and URLs,
rather than synthesized from assumed defaults.

Reuse only the exact approved edge receipt
`e1134a7092ac1e05ec97128bda976c174fc25e6b83d98cf9844bee575e57540a`.
Unexpected edge drift stops this cycle; the approval does not broaden that receipt.
Set `DEVRES_ACCEPTANCE_RUNTIME=target`, the externally frozen
`DEVRES_ACCEPTANCE_SOURCE_MANIFEST_SHA256`, and `DEVRES_EDGE_READMISSION_SHA256`.
Use the fixed admitted discovery-cache directory for every Kubernetes-capable
command. Do not use an untracked default cache or create test state outside `/tmp`.

## Inputs, capacity and original-process baseline

Stage all 29 source-manifest members, both native qualification records and the
source archive with SHA-256
`8fbbe7978c6ebf061d803c38d7b8e79205e68433e0c0ed0eb5a59da2b22e0782`.
Copy the native probe, without a hardlink, into the new probe directory. Its ELF
SHA-256 is `ba6dd1e1fa8f1ed5c39b71f15479bd90ee9cd971c3ccddc3e59df719503a2ff7`;
the qualification JSON SHA-256 is separately
`92be56f5f84c61902d7f5474f92d6d04a9a427fde23a4d58c145c558697e5791`.
Require root ownership, no writable or symlinked ancestors, one file link,
executable mode and traversal for the unprivileged public probe. Validate the
canonical smoke source, TLS/CA files, required executables, curl compression
support and active capacity/certificate timers before the target attempt.

The [public-identity preparer](cycle5_public_identity_3dae7d91.py) binds its own
reviewed source and the frozen fourth-cycle preparation helper before use.
Exclusively copy the latter's exact
`58c70e657bad9eb5fc3186486e38d4dc43d20e28c334779a591315661a35b2ef` bytes into
`$WORK/legacy-public-identity-builder.py`, owned by root with mode 0600 and one
link. Preserve the original transfer-owned helper's inode, ownership, permissions
and bytes. Do not change historical file ownership to satisfy a new admission.
Externally pin the new controller, source manifest and render manifest. Preview
and review the candidate, then exclusively create it once. Preserve all four
historical native-helper GETs and their ledger rows, with exactly one new helper
GET permitted. These counters do not count all S3 or edge HTTP traffic. Neither
this preparer nor a preview performs a provider request or store-claim GET.

Retain the existing concurrent-copy/growth and free-inode gates and the 128 GiB
reserve. Reclamation requires a new source-bound helper, exact completion and
ownership evidence, an independently reviewed preview, and mount/process/hardlink
checks. Select only completed isolated proof/rehearsal data copies. Preserve
golden checkpoints, full baseline caches, production generations and every
manifest, journal, receipt and log. Insufficient capacity stops admission.

The [retirement helper](cycle5_reclaim_3dae7d91.py) has two fixed phases with
separate exclusive journals: `cycle4-completed` selects the eight completed
fourth-cycle proof/rehearsal leaves; `cycle5-checkpoint-proof` selects only the
three completed fifth-cycle proof leaves before its actual Restore rehearsal.
Require an independently reviewed runtime-qualified exact preview, helper source
hash and finite approval before either apply. Each apply consumes one intent and
preserves selected root identities. A refused or incomplete apply cannot be
automatically replayed. File-only inventory does not replace namespace, process,
Docker and firewall qualification or current production boundary checks.

Prepare the new controller once, perform the source-bound read-only schema check,
consume the one native store-claim helper GET, and stop the application roles.
At this point, the new cycle's original PostgreSQL process is P1: it is the
process installed by the preceding cycle's completed restoration.

Create the operational baseline immediately after stop, before checkpoint `run`
can restart that process:

```sh
python3 -B "$WORK/operational-proof.py" baseline --label pre-upgrade \
  --controller "$INSTALL/upgrade-controller.py" --controller-sha "$CONTROLLER_SHA" \
  --checkpoint "$INSTALL/physical-checkpoint.py" --checkpoint-sha "$CHECKPOINT_SHA"
```

Require schema 18, old configurations, stopped phase, PostgreSQL only, original
prepared P1, exact source/prepared bindings and exclusive private-file creation.
Validate `require_operational_baseline()` under the controller lock. Never
backfill the baseline after restart or target startup.

## Checkpoint, rehearsal and single supervised target

Create new disk-backed checkpoint/rehearsal binds and the exact checkpoint
approval. Run checkpoint `prepare`, clean checkpoint `run`, and isolated `proof`
once each. Checkpoint prepare alone is an untrusted live precopy. `run` stops
PostgreSQL, verifies the final physical copy and resumes production as P2. The
controller retains its prepared P1 until backup-driven admission rebinds it; do
not run its ordinary original-P1 guard or repeat stop after this restart.

Independently verify checkpoint artifacts, fixed old-reader bytes and notices,
old-writer readiness, full cache baselines and owned cleanup. If capacity requires
retiring this cycle's completed isolated proof bodies, qualify a separate bounded
reclamation after completion and verify all actual Restore/backup dependencies
remain intact. Preserve metadata and all golden artifacts. Do not infer that a
completed proof makes every tree beneath its parent disposable.

Run the actual source-bound Restore class once on isolated real PostgreSQL and
full baseline caches. Verify all rehearsal checks, production bookends, source
pins and the freshly revalidated backup. Enter the root supervisor within its
300-second freshness gate. Attach the exact same source-bound fence as
`ExecStopPost`; retain `KillMode=control-group`, no restart and the reviewed
run/restoration timeout margins. Do not invoke deployment apply outside it.

The lifecycle is apply, bootstrap writer, migration proof, bounded npm assessment,
read-only observer, paused acceptance, controlled activation and active acceptance
including 900 seconds of observation. Complete backend/public HTTP and
WebTransport acceptance using the pinned native probe. Source-bound baseline
admission repeats before deployment intent and before direct apply mutation.

On failure, consume at most one restoration intent, install schema 18 and complete
baseline caches, preserve post-task generations and S3 objects, and withdraw both
application roles. Verify the stop fence and record the actual outcome. Do not
retry a failed production stage, reset an intent or start a fallback application.
Keep local checks, native CI, registry artifacts, isolated proof and production
acceptance as separate evidence. No GitHub push, publication, whole-provider/
corpus acceptance or native ChatGPT UI acceptance is authorized by this cycle.
