# Production upgrade to `0.1.0-build.ce5745e0`

This procedure starts from the [completed fifth-cycle schema-18 restoration](upgrade-3dae7d91-cycle5-evidence.md).
It admits one attempt on the dedicated K3s host, one new native archive store-claim
GET, and at most one physical restoration. The successful end state is schema
19, the historical active source settings, and accepted public MCP.

The [published release](https://github.com/PublicData-stream/dev-resources-MCP/releases/tag/0.1.0-build.ce5745e0)
pins commit `ce5745e0a0a5914dad62cd24f8655276b6f780ce`. The runtime uses the
published server and probe indexes and verifies their Linux amd64 child manifests.
The release archive SHA-256 is
`5b465a79e9f798457f7eb92dd3231ca97a8dfd5da8bab9aed0e4f3524ba9af77`.
The maintained assessment helper comes from that verified archive. The runner
passes `--connect-readiness wait` for the existing restricted assessment CLI.
PostgreSQL transport startup may retry within 30 seconds in the same Pod.
The cause of the previous production connection failure remains unresolved.

## Qualification and staging

Run the [contributor checks](../../CONTRIBUTING.md#checks) and obtain independent
MCP/API, Upstream/Storage, and Security Boundary review of the actual rendered
callers. Follow the [local readiness procedure](../../docs/paused-assessment-acceptance.md#postgresql-startup-readiness-qualification)
with the exact published server image in the Minikube assessment and isolated K3s
fixture. All local test state belongs under `/tmp` and Cargo target state belongs
in `/tmp/rust/target`. Keep the hosted CI, registry, and local fixtures as distinct
receipts.

Verify the signed tag and release metadata. Confirm the anonymous pull of the
probe's amd64 platform and hash the extracted `/usr/local/bin/devres-probe`
against `f7b1b4f1d50b9d7a7cf96cee9c2616d0ac86ab57ddd1c134581d7472c9dfc732`.
The target qualification JSON binds `commit`, `architecture: "amd64"`,
`anonymous_full_pull: true`, `image` (the digest-pinned probe index),
`platform_manifest_digest`, and `binary_sha256`. Use the fifth cycle's exact
`fallback-native-qualification.json` for the retained isolated-proof metadata.

```sh
python3 -B deploy/production/cycle6_ce5745e0.py \
  --output "$RENDER" --source-archive "$RELEASE_SOURCE" --probe "$PROBE" \
  --target-qualification "$TARGET_NATIVE" --fallback-qualification "$PRIOR_NATIVE"
```

Use a fresh absolute `$RENDER` path beneath `/tmp`. After review, hold the
render-manifest, lifecycle source-manifest, launcher, and helper digests
independently of the copied files. Stage each artifact only at the path declared
in `render-manifest.json` using create-new, root-owned private directories and
files. For the native probe only, use mode 0755 on its root-owned, nonwritable
parent and executable so the unprivileged acceptance client can traverse it.
Verify each installed digest before executing any helper.

## Capacity and maintenance window

Verify the consumed predecessor, PostgreSQL-only schema 18, all sources paused,
stable archive binding, zero publication owners, and the pinned edge admission.
Check the timers, certificate leaf margin of at least 24 hours, and the exact
native probe and curl capabilities. Recompute free bytes and inodes on every
volume required by the checkpoint, rehearsal and restore. Keep the 128 GiB
reserve, four PostgreSQL copies and two cache copies at checkpoint admission,
and the existing separate rehearsal and restoration staging guards.

If space requires retiring an isolated completed proof body, use only the
source-bound preview, check current container/process/mount/hardlink and firewall
evidence, then obtain approval of the exact preview and execution source before
deletion. Keep the golden checkpoints, complete cache baselines, receipts,
production generations and all producer paths. Check actual bytes recovered
before proceeding. A later retirement of new, completed clone proof bodies has
its own preview and approval. Insufficient headroom stops the procedure.

## Checkpoint and launch

Work under an operator-confirmed window. Use `ssh-mcp` and the explicit production
context `default`. Run as root with the fixed private environment after staging.

```sh
export DEVRES_ACCEPTANCE_RUNTIME=target
export DEVRES_ACCEPTANCE_SOURCE_MANIFEST_SHA256="$MANIFEST_SHA"
export DEVRES_EDGE_READMISSION_SHA256=e1134a7092ac1e05ec97128bda976c174fc25e6b83d98cf9844bee575e57540a
export KUBECACHEDIR=/tmp/devres-reclaim-discovery-3dae7d91-20261117
WORK=/tmp/devres-upgrade-ce5745e0-cycle6
BUNDLE=/var/lib/devres-production-upgrades/ce5745e0-cycle6
INSTALL=/usr/local/libexec/devres-upgrade-ce5745e0-cycle6

python3 -IB "$WORK/prepare-public-identity.py" \
  --manifest-sha256 "$MANIFEST_SHA" --render-sha256 "$RENDER_SHA" --source-sha256 "$IDENTITY_SHA"
```

After reviewing that finite preview, repeat with `--write` once and review the
expected identity of 45 historical installed dependencies and five spent GET
ledger rows. Prepare the controller, consume the single native store-claim GET,
and record the stopped-role baseline against the original PostgreSQL process.

```sh
python3 -B "$INSTALL/upgrade-controller.py" --context default prepare
python3 -IB "$WORK/store-claim.py" --checkpoint-sha256 "$CHECKPOINT_SHA"
python3 -B "$WORK/phase-driver.py" stop --controller-sha "$CONTROLLER_SHA"
python3 -B "$WORK/operational-proof.py" baseline --label pre-upgrade \
  --controller "$INSTALL/upgrade-controller.py" --controller-sha "$CONTROLLER_SHA" \
  --checkpoint "$INSTALL/physical-checkpoint.py" --checkpoint-sha "$CHECKPOINT_SHA"
```

Create fresh root-private disk-backed `checkpoint-volume` and
`restore-rehearsal-volume` directories under `$BUNDLE`. Bind mount them at
`$WORK/checkpoint-state` and `$WORK/restore-rehearsal-state`, respectively.
Verify that each alias is the same directory inode and device as its physical
volume. Write the exact create-new checkpoint approval required by the staged
helper, binding the controller preparation, store claim, public identity and
checkpoint source. The approval has scope `physical-pg-checkpoint-ce5745e0-cycle6`,
version 1, `approved: true`, `operations: ["prepare", "run", "proof"]`,
`maximum_checkpoints: 1`, `maximum_rehearsals: 1`, and `independent_s3_backup: false`.
Use the values `source_sha256`, `public_identity_sha256`, `store_claim_sha256`,
and `controller_prepared_sha256` read from the admitted files. Write the approval
at `$WORK/checkpoint-approval.json`. Run the staged `physical-checkpoint.py` operations `prepare`,
`run`, and `proof` in order once each. The clean snapshot restarts the original
database as a new process. The accepted backup is its authorized identity rebind.

```sh
python3 -IB "$INSTALL/launch.py" preview \
  --source-manifest-sha256 "$MANIFEST_SHA" --launcher-sha256 "$LAUNCHER_SHA"
```

Before running the rehearsal, bind the printed argv and approval template in
`$BUNDLE/launch-approval.json`, with a current UTC approval and expiry covering
the window. Hash that exact file as `$APPROVAL_SHA`. Run the staged
`restore-rehearsal.py --checkpoint-sha256 "$CHECKPOINT_SHA" --restore-sha256 "$RESTORE_SHA"`
once. It checks the real Restore class with isolated copies and writes both the
rehearsal receipt and the revalidated backup. Within 300 seconds of that passing
receipt, invoke the launcher via a persistent privileged session.

```sh
python3 -IB "$INSTALL/launch.py" launch \
  --source-manifest-sha256 "$MANIFEST_SHA" --launcher-sha256 "$LAUNCHER_SHA" \
  --approval-sha256 "$APPROVAL_SHA"
```

The launcher reserves one durable intent before submitting the root systemd
unit. Monitor the exact unit, final supervisor result and `ExecStopPost` fence
through completion. An unknown SSH or client result requires observation of the
existing unit and journal. It grants no additional submission.

## Acceptance and restoration

The runner applies the target, starts one bootstrap writer, verifies the
schema-19 migration, and completes the restricted npm assessment. Paused
acceptance requires a verified private report, cleanup of the assessment Pod and
its policies, a strict read-only observer, unchanged retained metadata, and
acquisition denial. The active phase restores the saved settings and verifies
the sole writer, backend mTLS, public IPv4/IPv6 HTTP and native WebTransport for
both supported revisions, compression, a fixed retained capture, notices,
corresponding source, and private boundary denial. The observation requires at
least 32 samples over 900 seconds with at most 45 seconds between samples.

On post-mutation failure, the fence withdraws both application roles. One
physical restoration returns schema 18 and the full baseline caches, with the
captured paused Secrets and Deployment images. PostgreSQL and S3 generations
are retained. If an exact candidate cache cannot be renamed, one journaled
discard is allowed only after the staged full baseline and quiesced candidate
identity are verified. Ambiguous cache identity or failed PostgreSQL preservation
requires reconciliation while both applications remain withdrawn.

Record live final state and the matching receipts for the deployment, any
restoration, and the fence. The isolated rehearsal, bounded public smoke, and
fixture qualification do not establish full provider or native ChatGPT UI
acceptance.
