# Staging deployment

These host-specific assets deploy the existing accepted
`0.1.0-build.ed3c13f2` server image into `devres-staging` on `piqua-serve`.
The disposable [foundation](../kubernetes/foundation.yaml) remains separate.
No package code is executed and no administrative HTTP route is added.

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
while preserving timer activation states. It refuses an active upgrade, so finish
an existing rehearsal before refreshing an installed operator bundle.

Rehearsal uses a protected coordinated snapshot and isolated `/tmp` clones with
no provider egress. It first proves schema-nine recovery, then runs the exact new
binary's `migrate-storage`, `verify-storage` and `activate-storage` commands, and
reads a retained RFC capture. The measured rehearsal sets the cutover deadline
to the larger of thirty minutes and twice the rehearsal duration. Recovery time
is additional. Capacity and clone quotas remain enforced; a successful rehearsal
does not establish whole-corpus capacity.

Before draining the real backend, the operator arms and verifies a root timer
bound to that upgrade's token. Once the candidate is awaiting acceptance, an
expired deadline invokes the preserving rollback even if the SSH approval channel
is unavailable. The timer uses the same upgrade lock as migration and finish, and
retries lock contention. Interrupted rollback resumes with the same token and
preserved dataset identities. Finish and rollback disarm their own timer.
Recovery is allowed to complete beyond the cutover deadline.

Each isolated offline command has a 64 GiB memory limit and a separate 32 GiB
`/tmp` tmpfs for reconstructable migration and visibility spill files. Check host
headroom for both before rehearsal; tmpfs usage counts toward the memory limit.
Restored serving retains its smaller independent limits. These scratch files are
disposable and are never a replacement for the coordinated evidence snapshot.

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
{"token":"CURRENT_UPGRADE_TOKEN","version":"0.1.0-build.ed3c13f2","http":true,"webtransport":true,"revisions":["2025-11-25","2026-07-28"],"retained":true,"isolation":true,"shared_services":true}
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
