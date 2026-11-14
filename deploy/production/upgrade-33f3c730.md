# Guarded schema-18 production upgrade

This host-specific procedure upgrades the admitted `65236494` Wikipedia
activation to `0.1.0-build.33f3c730`, commit
`33f3c730123319625fe3a25713988201eb5d82e0`. It requires separate operational
authority; installing these files does not activate workloads.

## Identity and preserved boundaries

Use `upgrade_33f3c730.py` with explicit context `default`. Its exact historical
controller dependencies remain installed on the deployment host and are checked
by SHA-256 before import. The initial admission uses the current Wikipedia
activation, including its published CIDR route, rather than the retired generic
operator's startup path or the pre-Wikipedia upgrade guard.

The server image index is
`ghcr.io/publicdata-stream/dev-resources-server@sha256:c13191678b2336f6594521dec7ca040cc97ea55313d098d87726f852eb3f1bde`.
The probe image index is
`ghcr.io/publicdata-stream/dev-resources-probe@sha256:8239d387a0120049eef707a6cd474c2286545991bd7f246c8b7773c8f02a1473`.
Verify their published provenance and anonymous bytes independently. The source
archive SHA-256 is
`46491351a46d4518274982406bc66174908e7559a8a4d6e1bd3f787e2b9b1b0a`.

Only application images, corresponding-source URLs and temporary collector
pause/resume change. Preserve all nine source switches and Wikipedia identity,
credentials, role authority, archive binding, TLS, edge, AppArmor, firewall and
CNI/RBAC. The existing capacity/certificate timers retain their original operator
entrypoints. Those entrypoints do not traverse upgrade journals; their existing
cluster, edge, capacity and emergency-stop checks remain in force.

## Ordered lifecycle

1. Complete contributor checks and independent MCP/API, Upstream/Storage and
   Security Boundary review of the actual controller, checkpoint and operational
   proof sources. Preserve exact-release hosted native CI evidence separately.
2. Install reviewed sources root-private. Capture and prepare a fresh inventory
   within 300 seconds. The controller freezes the actual predecessor chain,
   process/security projections, namespace Secrets and candidate configurations.
3. Obtain one bounded authenticated read of the existing S3 store claim with the
   admitted reader pair. Bind its proof, the reviewed helper hash and prepared
   controller hash to the checkpoint's exclusive approval inputs.
4. Run `checkpoint_33f3c730.py prepare` for a live precopy. Then use the controller's
   `stop` phase to stop backend before writer. Run checkpoint `run` and `proof`:
   cleanly stop PostgreSQL, finalize and fsync the physical copy, restart the
   original PostgreSQL without restoring it, and prove the separate old-reader
   clone with read-only S3 authority. Retain complete archive/capture manifests.
5. Admit the fresh `coordinated-schema15-backup` receipt with controller `apply`.
   It permits only the receipt-bound PostgreSQL process rebind, pauses all nine
   collectors and changes the two application images. Start the sole target
   writer, prove schema 18/policy 2, grants and retained evidence, then start reader.
6. Admit actual private acceptance through `runtime-ready`; admit public HTTP and
   native WebTransport acceptance over IPv4/IPv6 and both supported MCP revisions
   before `activate-existing`. Activation restores exact original source flags.
7. Repeat active private/public checks and observe at least 600 seconds with at
   least 21 samples and gaps no longer than 45 seconds. Finish only with a fresh
   artifact-bound observation receipt. Every mutating phase has a single-use
   approval and fsynced intent; interrupted uncertain operations require review.

The host's `/tmp` tmpfs cannot hold the database and rehearsal. Keep the golden
checkpoint in a root-private disk recovery area and use an owned disk-backed
mount beneath `/tmp` for every clone and scratch path. Require space for three
database copies plus the 128-GiB reserve. Preserve the checkpoint and proof across
reboot; do not treat them as disposable fixture cleanup.

## Forward-only policy and recovery

Schema 15 to 18 and attribution policy 1 to 2 are forward-only. Startup legitimately
resets the nine bounded attribution sweeps and returns running RFC/crates work to
pending. It retains historical captures, archive mappings, generations, notices
and recovery receipts. Do not require queue byte equality or reset other state.

Verify historical notice resources independently of current content admission.
Policy 2 may explicitly withhold a formerly readable page until requalification;
that result is recorded without bypassing policy or launching separate recovery.

The checkpoint proves PostgreSQL recovery while the original immutable S3 survives.
It does not prove bucket-loss recovery or reread every remote object checksum.
After migration begins, failures stop the application roles and preserve all new
state. There is no old-image hot swap, automatic restore or schema decrement.
Any later recovery must preserve post-upgrade permanent evidence.

Never retain caller lockfiles, dependency inventories or audit reports in these
artifacts. Root-private operational evidence must not enter Git; publish only
sanitized results, hashes and explicit verification limits.
