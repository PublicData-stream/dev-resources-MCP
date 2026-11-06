# Staging deployment

These host-specific assets target the published
`0.1.0-build.d373818b` server image into `devres-staging` on `piqua-serve`.
The disposable [foundation](../kubernetes/foundation.yaml) remains separate.
No package code is executed and no administrative HTTP route is added.

The reviewed release commit is `d373818b211f9126117ce4ee5709c859e5318b84`.
Use the immutable public indexes below, including their accepted native amd64 and
arm64 manifests. Do not retag a different build as this version.

| Artifact | SHA-256 |
| --- | --- |
| Server image index | `4d73cb12637f737c0e09649cb8e40795e379a77408cc65410509a1c117178e10` |
| Probe image index | `74b6e9020fe9868e7005f87ed0bc4a785dbd83a09ec9f6952b848f366d4a6512` |
| Corresponding `source.tar.gz` | `2ff98ccd72e9a2dc69423ca680f4a2bedebfdc2b63abb2008f13e30800974d79` |

The public endpoints are
`https://dev-resources.staged.mcp.publicdata.stream/mcp` and
`https://dev-resources.staged.mcp.publicdata.stream/mcp-wt/v1`.
The root path has no landing page. Both MCP revisions and the Draft02
WebTransport binding retain the [service contract](../../docs/Specification.md).

## Private prerequisites

Provision `/mnt/devres-staging/postgres` and `/mnt/devres-staging/evidence`
from the dedicated ZFS subtree before applying `kubernetes.yaml`. PostgreSQL
uses UID/GID 999 and the server uses 65532. PV reclaim policy is `Retain`;
PVC sizes describe placement, while ZFS reference quotas and snapshot limits
enforce the separately configured capacity policy. Do not point a test at
these permanent datasets.

Create `devres-config` in `devres-staging` with these private keys:

| Key | Required content |
| --- | --- |
| `backend.toml` | Filled `backend.toml.example`, with the application role's private PostgreSQL URL |
| `postgres-password` | Random PostgreSQL bootstrap administrator password |
| `init.sql` | Create non-superuser application role `devres`, give it database/schema ownership for startup migrations, revoke public schema creation |

The bootstrap administrator is `devres_admin`, the database is `devres` and the
application role is `devres`. The application role must have `NOSUPERUSER`,
`NOCREATEDB` and `NOCREATEROLE`. Official PostgreSQL initialization executes the
SQL once on a new volume; changing the Secret does not rotate an existing role.
Keep credentials out of arguments, logs, version control and diagnostic archives.

Create `devres-tls` with `backend.pem`, `backend-key.pem` and `client-ca.pem`.
The backend certificate's DNS SAN must contain `devres-k8s`. A separate client
CA issues the edge client certificate with exact DNS SAN `devres-edge.internal`.
Only the backend certificate/key and client CA belong in the backend Secret.
The edge receives `devres-backend-ca.pem`, `devres-client.pem` and
`devres-client-key.pem`; CA private keys remain in root-owned operator storage.

## Shared edge and isolation

Add `devres-k8s:10.0.0.1` to the existing edge's host mapping. Include the two
TOML snippets, append the public hostname to the existing TLS SNI list, and
append `devres-backend-ca.pem` to the existing proxy trust roots. Preserve
existing certificate references, routes, policy, streaming request/response
configuration and disabled cache. Per-route compression and TLS early data
are disabled. Check the complete candidate configuration with the exact pinned
OxiBelt binary before restarting the shared edge; save the prior configuration
for rollback and compare all existing public routes against their baseline.

Backend authorities are `devres-k8s:30081` and `devres-k8s:30434`, matching
`preserve_host=false`. The shared edge alone may reach those NodePorts from
bridge `openlegal-edge0`, address `10.0.0.3`. Install a dedicated firewall table
before creating the Services; reject other sources/addresses and verify the
actual packet source through kube-proxy. Do not change global k3s NodePort
address configuration or existing OpenLegal firewall rules.

NetworkPolicy permits backend ingress only from the edge and database ingress
only from backend Pods in this namespace. Health has no Service port and no
edge route; kubelet probes are private node traffic. Backend egress permits
cluster DNS, this namespace's PostgreSQL and public IPv4 TCP 443, excluding
private/reserved networks and the public node IP. IPv6 backend egress is
denied. This network rule is not a provider hostname allowlist: the existing
application additionally enforces fixed provider hosts and resolved destinations.
Provider-specific budgets and privacy rules remain unchanged.

## Acceptance and activation

Apply the namespace and isolation policies before workloads, then create private
Secrets and apply the remaining resources. Both Deployments initially have zero
replicas. After prerequisites are verified, start PostgreSQL with one replica,
verify initialization/readiness, then start exactly one backend replica.
Qualify both transports and both MCP
revisions with all eight collectors explicitly disabled. Use the allowed Origin
`https://chatgpt.com` for smoke clients; omitted Origin remains valid for native
clients. Reject disallowed Origin/Host, missing certificate, wrong client CA/SAN,
cross-service identity, public NodePort and health access. A Pod with valid
devres client credentials must still fail CNI access when it is not the edge.

Fixed live records use the existing opt-in smoke budget. Retain actual public
evidence in this service, and qualify coordinated snapshot/isolated-clone restore
before enabling collectors. Never insert synthetic storage-probe fixtures in
permanent staging evidence. An empty restore proves mechanics only.

Activate the existing default schedules by changing only all eight collector
`enabled` booleans to `true` in the private configuration and restarting the
single server. npm keeps the empty package list; its advisory lane still runs.
Observe readiness, restarts, corpus statuses, provider errors, capacity and
backup status for ten minutes. This establishes supervised bootstrap, not full
provider coverage, full corpus capacity or native browser/ChatGPT acceptance.

Stop all server/maintenance writers and PostgreSQL before a recursive atomic
snapshot. Keep the matching database, archives, indexes and build/schema identity
together. Recovery clones must be inaccessible publicly with all collectors and
external egress disabled. Scale the server to zero at capacity limits: disabling
collectors alone does not stop foreground retrieval writes. See the maintenance
tool and the [operations guide](../../docs/operations.md) for backup/restore gates.

## Host commands and recovery

### Existing schema-nine deployment

The build above requires schema 10. Do not rerun `prepare` against an existing
deployment or start the new image on schema nine. Install the reviewed operator,
upgrade and restore modules together, retaining the previous bundle privately.
The upgrade changes only release identity and temporarily pauses collectors;
the original eight scheduling settings, npm package list and budgets are restored.

```sh
python3 staging.py refresh-services
python3 staging.py upgrade-rehearse
python3 staging.py upgrade
# Complete independent retained-data, isolation, public HTTP/WebTransport and
# shared-service acceptance; save the private acceptance receipt described below.
python3 staging.py upgrade-finish
# On a failed cutover, preserve its data and restore the matching previous pair:
python3 staging.py upgrade-rollback
```

`refresh-services` installs the reviewed systemd units and reloads their definitions
while preserving timer activation states. An active operation normally refuses
refresh. The token-qualified exception is a fully verified, stopped rehearsal
checkpoint; a permanent cutover must keep its exact installed bundle and watchdog.

Rehearsal uses a protected coordinated snapshot and isolated `/tmp` clones with
no provider egress. It first proves schema-nine recovery, then runs the exact new
binary's `migrate-storage`, `verify-storage` and `activate-storage` commands, and
reads a retained RFC capture. The measured rehearsal sets the cutover deadline
to the larger of thirty minutes and twice the rehearsal duration. Recovery time
is additional. Capacity and clone quotas remain enforced; a successful rehearsal
does not establish whole-corpus capacity.

Each offline migration, verification or activation command has a finite seven-day
ceiling, including nested restore verification. This is an execution bound, not
a completion estimate. Cutover commands remain limited by the smaller remaining
measured outage budget (or direct-mode absolute deadline); the watchdog and
preserving rollback are unchanged. A checkpoint pause preserves its database/blob
pair rather than entering ordinary disposable-clone cleanup. A preserved failure
is not a successful pause: inspect its ownership and recovery state before retrying.
Never extend a running operation by editing its journal.

Only the main migration rehearsal clone has a finite 512 GiB parent quota. Before
creating its temporary runtime directory or ZFS objects, it requires at least
704 GiB of current pool free space: 512 GiB for that clone, 64 GiB for a nested
restore, and the existing 128 GiB pool reserve. Ordinary restores and the nested
schema-nine/schema-ten restore checks retain their 64 GiB parent quotas. This
profile changes neither the permanent datasets' quotas nor the pool's limits;
the capacity guard remains active throughout the rehearsal.

Before draining the real backend, the operator arms and verifies a root timer
bound to that upgrade's token. Once the candidate is awaiting acceptance, an
expired deadline invokes the preserving rollback even if the SSH approval channel
is unavailable. The timer uses the same upgrade lock as migration and finish, and
retries lock contention. Interrupted rollback resumes with the same token and
preserved dataset identities. Finish and rollback disarm their own timer.
Recovery is allowed to complete beyond the cutover deadline.

The main rehearsal migration and ordinary permanent cutover use the same profile:
128 GiB and 37 CPU cores for the offline worker, including a 32 GiB `/tmp` tmpfs,
and 32 GiB and two CPU cores for PostgreSQL with the existing tuned PostgreSQL
settings. Candidate offline commands explicitly use eight workers, a 64 MiB SQL
payload budget and a 1,024 MiB graph-memory budget. These options are bound into
the measured profile; schema-nine restore commands keep their old-image options.
Both paths require at least 32 GiB of host available memory before each offline
worker and during polling; limits are ceilings rather than reserved capacity.
Ordinary and nested restore checks retain their 64 GiB worker, 32 GiB worker tmpfs
and 2 GiB PostgreSQL limits, and restored serving retains its smaller limits.
These scratch files are disposable and never replace the coordinated snapshot.

A successful rehearsal binds its timing to the exact target image, source offer,
operator bundle and migration profile. Changing any of these requires a new
rehearsal before ordinary cutover. Report complete phase, acceptance and recovery
timings, then agree the actual outage window before draining the permanent pair.
The watchdog budget includes public acceptance and the post-cutover backup/restore;
collector observation follows finish. Recheck identities, current data size and
headroom at cutover. Never edit journal deadlines to extend an expired budget.

### Checkpoint pause and explicit resume

The private lifecycle commands are:

```sh
python3 staging.py upgrade-status --token CURRENT_UPGRADE_TOKEN
python3 staging.py upgrade-pause --token CURRENT_UPGRADE_TOKEN
python3 staging.py upgrade-resume --token CURRENT_UPGRADE_TOKEN
```

Starting commands accept `--pause-scope rehearsal|all`, defaulting to `rehearsal`.
Rehearsal checkpoints can be paused by default. Permanent-pair pause/resume requires
`all` recorded when starting that cutover; it is not enabled retroactively by a
pause request. Only its offline migration, verification and activation phases are
eligible, after pre-upgrade recovery proof and before the public candidate starts.
Preparation, snapshotting, restore proof, public acceptance, finish and rollback
are not pause points.

A pause request is token-bound and acknowledged by the owning driver. It signals
only its owned worker with SIGTERM, waits for termination, cleanly stops PostgreSQL,
confirms the cluster is shut down, and creates a held coordinated checkpoint plus
a private integrity-checked recovery capsule. Failed or uncertain shutdown never
reports a clean pause. Checkpoint and failure paths preserve committed progress;
scratch is reconstructed, not treated as migration evidence. Capsules contain
inert configuration and identity data, never executable resume instructions.

Reboot does not automatically resume migration. Explicit resume rechecks the exact
pair, snapshots, ownership, images, bundle and execution profile, then reconstructs
missing owned runtime files under `/tmp`. Durable activation state is reconciled
before choosing the next command, including an activation whose result was lost
after commit. An already-active store is not sent through migration again.

For permanent cutovers, the original absolute deadline continues through pause
and reboot. Keep the enabled token-specific watchdog and zero Kubernetes writers;
expiry wins pause/resume races and runs preserving pair rollback. PID identity is
bound to the boot as well as process birth, so an old journal cannot signal a
reused process. Pausing does not restore collectors, backup timers or public serving.

The specific earlier version-one rehearsal receipt can be imported with:

```sh
python3 staging.py upgrade-adopt-paused --token CURRENT_UPGRADE_TOKEN \
  --receipt /var/lib/devres-staging/upgrade/rehearsal-pause-2.json --check
python3 staging.py upgrade-adopt-paused --token CURRENT_UPGRADE_TOKEN \
  --receipt /var/lib/devres-staging/upgrade/rehearsal-pause-2.json
```

Adoption validates the receipt chain, capsule inventory and hashes, dataset GUIDs,
origins, ownership, held snapshots, stopped containers and clean PostgreSQL state.
It preserves the old records and checkpoints and records the reviewed image/bundle
transition. Legacy Python helpers and free-form command fields are never executed.
The timer intent comes from the original rehearsal record, not a timer state
changed by reboot. A new pre-adoption checkpoint protects the same pair.
The `--check` form performs admission checks without adopting the pair, stopping
the backup timer, changing runtime configuration or creating a snapshot. Use a
separately staged reviewed bundle for this check before replacing installed code.

A reviewed operator-only update may rebind a **formal paused rehearsal** to a new
bundle without changing its candidate image. Use the current receipt's absolute
path and explicitly identify its old bundle hash:

```sh
python3 staging.py upgrade-adopt-paused --token CURRENT_UPGRADE_TOKEN \
  --receipt CURRENT_FORMAL_RECEIPT --from-bundle-sha256 PREVIOUS_BUNDLE_SHA256 --check
python3 staging.py upgrade-adopt-paused --token CURRENT_UPGRADE_TOKEN \
  --receipt CURRENT_FORMAL_RECEIPT --from-bundle-sha256 PREVIOUS_BUNDLE_SHA256
```

Only the executable bundle hash may differ. Image, version, source offer, offline
options, resource profile and pause policy must match exactly. The operation
revalidates the stopped pair and live old service, creates a held checkpoint and
new capsule generation, and retains the old receipt plus transition provenance.
Failed or permanent cutovers cannot use this entrypoint. No worker starts here.
Restored runtime `config` and `tls` directories are explicitly mode 0750 with
root:65532 ownership even under `umask 077`; their files remain 0640. Private
capsules remain root-only and are not made readable to the worker.

To switch from an isolated rehearsal to an explicitly authorized direct cutover,
first disable its owned automatic follow-up and pause it. Retire the clean formal
checkpoint without removing its database/blob pair:

```sh
python3 staging.py upgrade-pause --token CURRENT_REHEARSAL_TOKEN
python3 staging.py upgrade-retire-rehearsal --token CURRENT_REHEARSAL_TOKEN
```

Retirement requires the current reviewed bundle, exact dataset/checkpoint GUIDs
and holds, inert capsule integrity, clean stopped PostgreSQL, matching runtime
configuration/TLS and the unchanged old live service. It archives the journal and
retained-resource inventory, keeps every dataset, checkpoint and capsule, and
publishes terminal `rehearsal_retired` with unqualified timing. It starts no worker
and does not promote the older clone. Running, failed or permanent operations
cannot use this command. Timer restoration is retriable; a pending restoration
blocks a new operation until retirement retry succeeds.

The persistent backup timer may immediately start an overdue backup when its
original active intent is restored. Wait for that owned backup and restore check
to finish before direct admission. The existing `upgrade-abort-rehearsal` remains
destructive cleanup for a separately identified abandoned disposable rehearsal;
it is not the preserving path for changing cutover strategy.

A completed resumed or mixed-version rehearsal proves continuation and recovery
of that frozen pair; its timing is explicitly unqualified. Archive its receipts
and retain the finished pair, then qualify a fresh current complete-pair rehearsal
with the exact target image, bundle and profile before ordinary cutover. Never
promote the older clone while newer live ingestion continues. Restore original
backup-timer intent only at a verified safe terminal boundary; a missed persistent
backup may run immediately and must serialize through the maintenance lock.

`scripts/test-staging-worker.sh` is a separate fixture-only acceptance gate. It
requires the built server and migration-benchmark example, starts disposable
PostgreSQL with bind state below `/tmp`, interrupts real RFC graph replay with
SIGTERM, resumes the same pair, and checks committed checkpoints plus restored
query readback. It performs no provider acquisition and does not establish ZFS,
systemd, remote-corpus or production acceptance. Set `DEVRES_SERVER_BINARY` and
`MIGRATION_BENCHMARK_BINARY` to select already-built binaries; shared-cache Cargo
builds must use the privileged channel and `/tmp/rust/target`.

The real cutover stops all writers, retains a fresh protected database/evidence
snapshot, verifies old-image recovery, and runs the same offline commands on the
permanent pair inside an internal Docker network while the Kubernetes pair is
stopped. Exactly one new backend starts with collectors paused. The capacity
guard remains active; other writer/maintenance entrypoints refuse an active
upgrade. No shared-edge restart or provider smoke occurs in these commands.

Before `upgrade-finish`, the operator must independently verify both MCP revisions
(`2025-11-25`, `2026-07-28`) and both public transports, retained capture/search
continuity, private-route/Host/Origin/mTLS isolation and existing shared services.
Record the current upgrade journal's token and resulting booleans in root-owned mode-0600
`/var/lib/devres-staging/upgrade/acceptance.json`:

```json
{"token":"CURRENT_UPGRADE_TOKEN","version":"0.1.0-build.d373818b","http":true,"webtransport":true,"revisions":["2025-11-25","2026-07-28"],"retained":true,"isolation":true,"shared_services":true}
```

Finish qualifies a schema-ten coordinated backup/isolated restore before
restoring schedules and the original backup timer. Observe ten minutes of
readiness, restarts, provider errors, corpus status and capacity afterwards.
Restart the shared OxiBelt container at most once only when the backend passes
and public connectivity fails, then recheck every existing public route.

Rollback preserves the failed database and evidence datasets, then restores the
matching pre-upgrade pair, previous image and configuration. It never performs
an image-only schema downgrade or discards post-cutover history. Preserved newer
evidence may not be visible through the restored older service. Keep snapshot
holds until the resulting restore is qualified; do not manually clear the
upgrade journal or a capacity fence to resume writes.

### Offline failure diagnostics

Before removing a failed offline worker, the operator rechecks its ownership
label and fixed state fields with a separately bounded 4 KiB inspection, and attempts to retain bounded diagnostic metadata in root-owned0700
`/tmp/devres-offline-diagnostics`, outside disposable clone cleanup. Files are
exclusive0600 JSON; existing files, symlinks, unsafe parent ownership/modes and
64 retained entries refuse new output. The directory is temporary
operator evidence and is separate from permanent corpus storage and receipts.

The Docker log reader requests at most 64 terminal lines and buffers no more than
64 KiB, with a three-second read deadline and at most one further second to reap
its owned Docker client. The ownership/state inspection has the same time limits. A single oversized line is truncated before buffering.
Only fixed progress events with known phases and numeric fields, recognized
application error-code/reason enums, and exit/OOM/engine-error metadata survive
filtering. Raw logs, arbitrary error messages, credentials, request inputs and
source bodies or their hashes are never written. Unknown messages are suppressed
and unrecognized lines counted, so the record may still leave the exact cause
unresolved. Inspect only the structured metadata; never copy private owner tokens
into public evidence or receipts.

Diagnostics are best effort. Read/write failure does not replace the original
fixed error or prevent worker cleanup, and successful commands create no record.
The metadata does not authorize retry, collector changes, recovery or publication.

### Deadline-bound single migration

For a supervised cutover with an absolute deadline, use the reviewed direct mode
instead of repeating a full migration rehearsal. It preserves the backup/restore,
exclusive-writer, integrity, capacity, acceptance and preserving-rollback gates:

```sh
# Preserve an existing clean formal rehearsal before changing strategy:
python3 staging.py upgrade-retire-rehearsal --token CURRENT_REHEARSAL_TOKEN
# Let any restored persistent backup finish before direct admission.
python3 staging.py refresh-services
# UTC epoch seconds; leave time before the operational deadline for recovery
# and ten minutes of collector stability observation.
python3 staging.py upgrade-direct --deadline-at ABSOLUTE_UTC_EPOCH
# Independently complete the same acceptance receipt, then:
python3 staging.py upgrade-finish
```

Run the direct driver as a root-owned systemd service so SSH loss does not end it.
The deadline watchdog can terminate only the recorded driver identity and recover
the matching old pair, including when migration still holds the upgrade lock.
Recovery time is additional; successful deployment is never inferred from expiry.

The migration heartbeat shares a maintenance lock with the periodic capacity
guard. It waits up to ten seconds for lock acquisition, checking again every
100 ms and respecting the existing absolute cutover deadline. After acquiring
the lock it still checks every capacity and maintenance fence. Only acquisition
contention is retried; a failed safety check or a persistently held lock remains
fatal. Recovery retains the bounded wait even after the cutover deadline expires.

Direct mode freezes the original pair, takes a protected coordinated snapshot,
proves its old-image recovery in an isolated clone, then migrates the permanent
pair once. It does not promote an earlier clone while newer ingestion continues.
The candidate must pass the ordinary acceptance and coordinated restore before
collector settings and the previous backup timer state are restored.

The accelerated direct migration admits at most 37 CPU cores and 192 GiB for the
worker (including its 64 GiB `/tmp` tmpfs), plus 2 CPU cores and 16 GiB for its
PostgreSQL container. Its 8 GiB shared buffers, larger WAL/checkpoint budget and
WAL compression reduce avoidable I/O while fsync, full-page writes and synchronous
commit remain enabled. It stops on host available memory below 32 GiB. Ordinary
restore checks retain their smaller limits. These ceilings do not parallelize
serial replay, relax application bounds, or establish a completion-time guarantee.

Abandoned-rehearsal recovery requires the exact upgrade token, root-owned journal,
verified driver identity and disposable object ownership. It retains permanent
snapshots/history and refuses changed ownership or unknown nested resources.
Never recover by deleting the journal or applying a schema-ten image to schema nine.

### Fresh deployment

Install these reviewed assets together in the root-owned
`/usr/local/libexec/devres-staging` directory. Run each command from that directory
as root; the operator owns only the new namespace, datasets, firewall table,
certificates, systemd units and two additive edge snippets.

```sh
python3 staging.py prepare
python3 staging.py start
python3 staging.py edge-prepare
python3 staging.py edge-activate
# Complete offline, fixed-live, private-isolation and shared-edge acceptance.
python3 staging.py backup
python3 staging.py collectors-on
systemctl enable --now devres-staging-backup.timer
```

`prepare` refuses live or terminating writers. It creates random credentials and
private CA material once, applies initial zero-replica manifests, and enables the
NodePort reconciliation and capacity timers. It never regenerates partial or
conflicting credentials automatically. The firewall bootstrap permits existing
k3s to start while the edge is absent, but leaves the new NodePorts blocked.

`edge-prepare` records the complete existing configuration inventory and validates
the candidate with the exact running edge revision and runtime UID. Activation
refuses changed source or candidate files. `edge-rollback` restores only owned
configuration after checking for intervening edits; otherwise perform a reviewed
manual merge. It recreates only the shared OxiBelt container and leaves existing
workloads and routes at their recorded baseline.

`backup` drains backend then PostgreSQL, confirms the on-disk PostgreSQL cluster
was shut down cleanly, takes one atomic recursive snapshot, and resumes in reverse
order. A ZFS hold protects the snapshot during the isolated real-capture restore
check while the capacity guard remains active. Only successful restore checks mark
snapshots verified and authorize seven-day retention cleanup. The restore check
requires the fixed RFC 9000 text capture produced by the approved bounded live gate;
an empty database cannot pass.

The timer runs daily at 03:00 UTC and briefly interrupts staging service. Failed
backups and timer failures remain visible in systemd status and the journal. Inspect
`maintenance.py status` and the relevant service status when a gate fails. State
is root-only under `/var/lib/devres-staging`, outside the snapshot subtree.
A capacity fence stops all backend writes and requires explicit
`python3 maintenance.py resume` after resolving the underlying limit. Do not clear
a fence by deleting evidence or editing its state file.

Live data is limited by reference quotas of 256 GiB for PostgreSQL and 768 GiB
for evidence; the recursive parent quota is 1536 GiB, including snapshots.
The guard stops service at 90% of either live-data quota, 90% of the parent quota,
400 GiB of snapshot changes, or 128 GiB of remaining pool space. These are
admission fences, not a whole-corpus sizing claim. A one-minute guard has a sampling
interval; ZFS hard limits provide the final capacity boundary.

Same-pool snapshots and clone restore checks do not recover from complete server
or pool loss. They preserve permanent history and the latest verified restore
point rather than guaranteeing seven restore points under every workload.
Disposable restore clones and credentials use owned `/tmp` directories, an internal
Docker network and no published ports; they never import synthetic fixture data.

## Host AppArmor compatibility

Ubuntu on this host stacks an `unconfined` label onto subprocesses. The containerd
v2.3.4 default profile does not admit signals to that exact stacked peer, which
blocks PostgreSQL authentication, recovery and clean shutdown. `prepare` compiles
and loads two dedicated Localhost profiles before admitting the new Pods. They
retain the pinned upstream containerd default restrictions and add signals only
to the same workload's exact stacked peer. RuntimeDefault seccomp, nonroot users,
capability drops and namespace policy remain enabled. Existing runtime profiles
are not modified; no cluster-wide policy reload is needed. The standard AppArmor
boot service loads the two files before k3s. Attribution and the complete Apache
license accompany the template.

A bounded `pg_isready` init container gates the backend process on private database
reachability. This avoids a fresh Pod exiting before CNI endpoint policy convergence;
it does not retry provider calls or weaken ownership fencing. For first-time live
RustSec qualification while collectors are paused, perform the documented
[current-only advisory refresh](../../docs/operations.md#rustsec-collection-and-history)
with serving stopped before running advisory/audit assertions. Use a one-shot Pod
with the backend's security, volume and network settings, the same database wait,
`restartPolicy: Never`, and an active deadline; verify its completion and termination
before starting serving again.
