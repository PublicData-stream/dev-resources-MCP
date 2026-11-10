# Dedicated production deployment

These assets render the separately authorized fresh deployment of
`0.1.0-build.a938112b`. They do not change public APIs, provider defaults, or the
historical staging operator. Rendering does not install anything or create
credentials. The generated Kubernetes `List` is JSON accepted by `kubectl -f`.

The default `broker` authentication method remains gated on provider-confirmed
issuer confinement to the two workload applications. Preparation never
manufactures that acceptance. An explicitly selected `scaleway_static` profile
renders separate static serving/writer key mounts; it requires its own real
storage-permission acceptance and never satisfies broker admission. The pinned
server release includes the role-derived read-only transport guard and passed the
release qualification checks. `STATIC_AUTH_RELEASE_QUALIFIED` permits admission
of independently obtained provider evidence; it does not replace that evidence
or activate workloads. See the [static Scaleway examples](../examples/scaleway-static/README.md).

The dated [original preparation evidence](acceptance-evidence.md) and
[static preparation checkpoint](static-acceptance-evidence.md) distinguish the
published releases, local checks, inactive target state and incomplete gates.

The private [issuer preflight](../../scripts/scaleway-issuer-preflight.py) accepts
a root-owned mode-0600 JSON input with `organization_id`, `project_id`,
`issuer_application_id`, `reader_application_id`, `writer_application_id`,
`issuer_access_key_file`, and `issuer_secret_file`. `inspect` performs bounded
positive identity/list reads and emits only statuses, never credentials.
The explicit `issue --state-root /tmp/NEW_PRIVATE_ROOT` operation creates at most
one 900-second test key per workload after those reads pass. It records intent
before each create and never retries an uncertain create or reuses a state root.
Issued secrets stay in that private root. Reconcile an uncertain intent or verify
its requested expiry before considering another attempt; `/tmp` state is not
reboot-durable on the deployment host. This tool does **not** prove unrelated-key
denial, policy-management denial, actual expiry/revocation, quota or S3 permissions,
and it never emits a passing broker receipt. Those remain separate real gates.

The exact Alpine PostgreSQL initialization/RO/restart fixture runs only through
an isolated Docker daemon with storage below `/tmp`:

```sh
scripts/with-tmp-state.sh scripts/with-local-docker.sh scripts/test-production-postgres.sh
```

```sh
PYTHONDONTWRITEBYTECODE=1 python3 deploy/production/production.py \
  --settings /tmp/devres-production-settings.json \
  --output /tmp/devres-production-rendered
```

Settings accept `storage_auth` (`broker` by default or `scaleway_static`) and contain `node_name` (the actual lowercase Kubernetes node name),
`node_ipv4`, explicit narrow `kube_api_cidrs` and broker-only `iam_cidrs` lists, and
`oxibelt_digest` (the verified 64-character SHA-256 digest). Include both the
Kubernetes Service IP and its actual API endpoint when CNI translation requires
them. IAM destinations must be public IPv4 networks of /24 or narrower. Resolve
and verify these addresses at installation; a changed provider address requires
reviewing the private egress policy. `edge_image` accepts the equivalent immutable
GHCR OxiBelt reference. Omission selects the verified pinned amd64v4 artifact for
OxiBelt revision `4f3154d8`; the operator checks its revision and configuration
before activation.

`production.py.render(output_dir: Path, settings: dict)` returns a mapping of
relative artifact names to output paths. It uses only Python's standard library.
It writes no Secret objects. Populate the TOML templates privately, URL-encode
database password replacements, and keep populated files out of version control
and command arguments.

| Secret | Required keys |
| --- | --- |
| `devres-corpus-postgres` | `postgres-password`, `init.sql` |
| `devres-broker-postgres` | `postgres-password`, `init.sql` |
| `devres-serving-config` | `serving.toml` |
| `devres-writer-config` | `writer.toml` |
| `devres-credential-broker-config` | `credential-broker.toml` |
| `devres-backend-tls` | `backend.pem`, `backend-key.pem`, `client-ca.pem` |
| `devres-writer-tls` | `tls.crt`, `tls.key`, `ca.crt` |
| `devres-broker-trust` | `ca.crt` |
| `devres-credential-broker-private` | `tls.crt`, `tls.key`, `database-url`, `keyring.json`, `issuer-secret-key`, `acceptance-receipt.json` |

For `scaleway_static`, omit all broker-specific Secrets in the table and add
`devres-serving-s3` and `devres-writer-s3`, each with `access-key` and `secret-key`.
Only the matching role mounts each Secret, at `/run/devres-s3`, read-only. Static
output omits the broker workload, database/PV, service account/RBAC, identity
projections, trust material and IAM policy rule. Keep native Secret encryption,
writer authentication, private networking and role-separated database authority.
The renderer writes no populated credentials or passing acceptance receipt.

The corpus PostgreSQL login roles are `devres_reader` and `devres_writer`, with
database `devres` on Service `postgres`. The writer owns its database/schema;
the reader has SELECT-only, NOINHERIT authority and default transaction read-only.
Grant SELECT on existing tables and future tables owned by the writer. The broker
has its own `devres_broker` login/database on `broker-postgres`; neither corpus role
exists in that instance. Initialization SQL and passwords are supplied privately;
changing a Secret does not rotate an initialized database. Both PostgreSQL Pods
use the pinned Alpine image's UID/GID 70 and PostgreSQL 18 data directory.
Database startup probes allow ten minutes for initialization or recovery before
liveness checks can restart a process. TCP loopback probes wait for the final
postmaster, rather than the image's socket-only initialization server. Database
rollout waits include that startup window; application rollout waits remain two
minutes. After interrupted initialization, verify roles and grants explicitly:
an existing data directory does not prove initialization SQL completed.

All five broker Deployments, or the three static Deployments, start at zero replicas. All eight collector switches are
false in both runtime templates; npm's catalog remains empty and its advisory
switch retains true. Apply namespace and deny policies before workloads, provision
private identities and local directories, verify native Secret encryption, then
install the remaining zero-replica objects. The production broker requires the
actual issuer/profile policy fingerprints and an unexpired provider acceptance
receipt; a fixture receipt cannot authorize it.

The root operator has separate commands; every cluster operation requires an
explicit kubeconfig context and the same private bundle:

```sh
python3 scripts/production-operator.py --bundle /var/lib/devres-production \
  --settings /tmp/devres-production-settings.json prepare
python3 scripts/production-operator.py --context default --bundle /var/lib/devres-production install
python3 scripts/production-operator.py --context default --bundle /var/lib/devres-production start-postgres
# Only after actual Scaleway acceptance, using private root-owned inputs:
python3 scripts/production-operator.py --context default --bundle /var/lib/devres-production \
  --inputs /var/lib/devres-production/private-inputs.json provision-runtime
python3 scripts/production-operator.py --context default --bundle /var/lib/devres-production start
# These remain separate from preparation and private runtime startup:
python3 scripts/production-operator.py --context default --bundle /var/lib/devres-production adopt-serve
python3 scripts/production-operator.py --context default --bundle /var/lib/devres-production edge-install
python3 scripts/production-operator.py --context default --bundle /var/lib/devres-production \
  --source-receipt /var/lib/devres-production/source.json \
  --edge-receipt /var/lib/devres-production/edge.json activate-collectors
python3 scripts/production-operator.py --context default --bundle /var/lib/devres-production withdraw
```

For broker authentication, private runtime inputs name `organization_id`, `project_id`, `issuer_access_key`,
`issuer_application_id`, `reader_application_id`, `writer_application_id`,
`reader_policy_sha256`, `writer_policy_sha256`, `issuer_secret_file`, and
`acceptance_receipt_file`. An optional `keyring_file` replaces the locally generated
initial journal keyring. The exact pinned broker's network-disabled fingerprint
utilities verify both canonical profile hashes and issuer-secret binding before
any runtime Secret is applied. The operator never writes a passing provider receipt.
Its state binds kube-system, node and devres namespace UIDs, private settings, exact
release identities, live workload templates and runtime Secret bytes.

For broker authentication, `prepare` creates private PostgreSQL initialization,
separate mTLS identities and journal encryption material. `install` keeps all five
replicas at zero and applies the NodePort firewall before Services. Start both
PostgreSQL instances, the broker, exactly one writer, then serving.

For static authentication, preparation omits the broker database, keyring and
issuer identities. Use `static-fingerprints --inputs PRIVATE_STATIC_INPUTS` to
obtain the binding for an independently verified real storage receipt, then
`provision-runtime` and `start`. The qualified release still refuses admission
without the matching real provider receipt. Rendering does not establish provider
permissions. The [static operator workflow](../examples/scaleway-static/README.md#production-operator-workflow)
lists exact input fields, receipt checks, controlled restart rotation and commands.
For an existing corpus, stop source roles and disable source collector admission
before `prepare-auth-switch --target-bundle NEW --settings STATIC_SETTINGS`.
For an activated broker source, run `pause-collectors` after `stop`; it verifies
stopped serving/writer roles and exact runtime state, changes only the eight
collector flags in their two configurations/Secrets, and preserves all budgets and
the running broker's credentials. Failed updates restore the original role
configurations. Do not reprovision issuer keys or drain the broker before the
actual switch. Preparation refuses enabled source configurations. Privately stage
target credentials, and run
`switch-storage-auth --target-bundle NEW` from the source. The switch leaves roles
stopped, preserves archive/database binding and retains the original broker bundle
and journal for explicit rollback; it does not bootstrap or generically prune
retained storage. Original edge metadata/snapshots and adoption/renewal
qualification accompany the target bundle. Existing capacity/certificate timers
follow the retired source's bounded reciprocal `auth_successor` binding; the
switch changes no systemd unit, edge route or edge process. Target startup returns
to `edge_ready` for separate acceptance/collector activation. Rollback restores
the original bundle and clears its successor.
Use the explicit-context [runtime helper](../../scripts/split-runtime-control.py)
after prerequisites are installed. Validate native projected-token identity,
pod replacement/key expiry, cross-database denial, RO object denial, a refused
second writer, and a cold foreground request delegated to the writer. Never seed
fixture data in this permanent store. Retained captures and public transport
checks remain separate from provider acceptance and full corpus coverage.

The archive is the fresh `dev-resources-mcp/production/` binding in Paris S3 with
`ONEZONE_IA` for newly written objects. It is not a copy or conversion of another
deployment. Permanent corpus/broker PostgreSQL paths are
`/database/devres/{corpus,broker}`; disposable role caches are
`/var/cache/devres/{serving,writer}` (32/64 GiB application cache limits). All four
local PVs use `Retain` and node binding. PV capacity fields are placement requests,
not filesystem quotas or measured corpus capacity. Precreate database directories
owned by 70 and caches owned by 65532, monitor root filesystem headroom and inodes,
and preserve permanent evidence when withdrawing workloads. No scheduled backup
or backup/restore acceptance is claimed in this explicitly deferred scope.

The edge is dedicated to `dev-resources.mcp.publicdata.stream`, with TCP/UDP 443,
one CPU and a 1 GiB memory ceiling,
the existing wildcard certificate filenames, and `devres-net`/`devres-edge0` at
`10.0.0.3`. Install only the generated snippets in the live wildcard include;
unrelated OpenLegal/staging routes must not remain included. Preserve the separate
lego DNS01 service and its private token outside these assets. Require the backend
SAN `devres-k8s`, the exact edge client SAN `devres-edge.internal`, and separate
private writer/broker certificate DNS names matching their Service endpoints.

`adopt-serve` is an explicit stopped-edge operation. It preserves each prior
configuration byte and original owner/group/mode/inode/hash before adopting only
the inventoried uid-1000/root compose and TOML paths. Generic system-file ownership
checks remain strict. It neither reads the existing wildcard TLS key nor changes
lego credentials. Edge installation comments the unrelated original configuration
and retains lego's active service and token-file reference.

The preserved lego service is pinned to image index
`sha256:6f1583fc026a455ea46a7a5858c576105bb69c2e2de69db391cab7f14750350c`.
Its existing YAML, certificate/account store and Cloudflare secret-file mount are
retained. Lego v5's root `--config /.lego.yaml` command obtains or renews according
to that file; an old `renew` subcommand is not appended. See the official
[configuration workflow](https://go-acme.github.io/lego/advanced/file-configuration/)
and [command reference](https://go-acme.github.io/lego/references/ref-flags/).

Only the future, fully gated `edge-install` installs/enables
`devres-cert-renew.timer` and its private `cert-renew` command, scheduled twice daily
with a randomized delay. It verifies the pinned CLI/configuration offline and binds
the exact retained config and service metadata hashes. Preparation installs no
renewal timer and performs no DNS operation. Renewal has its own lock so DNS/ACME
waits do not delay the capacity safety fence. A changed configuration requires
explicit revalidation rather than silently changing DNS scope.

The offline CLI inventory must return the unexpired `publicdata-stream`
certificate, expected public domains and exact `/var/lib/lego/certificates/` path.
Lego can exit successfully with an empty/default inventory after a YAML loading
error; that result is explicitly rejected before timer installation. An opt-in
fixture exercises the actual pinned CLI against valid and malformed YAML, entirely
inside `/tmp` with networking disabled and no Cloudflare token.

Successful renewal validates the public certificate's hostname/expiry and checks
the exact edge configuration. OxiBelt's existing `downstream_tls` polling reloads
the mounted certificate; no forced edge restart occurs on success or failure.
Public hot-reload/readback remains a separate future acceptance check. Renewal
diagnostics and credentials are captured privately, and the token is never passed
as a command argument or copied into generated assets.

Before creating NodePorts, enforce host IPv4/IPv6 rules that admit backend
TCP 30081/UDP 30434 only from the edge bridge/source and keep private PostgreSQL,
writer, broker and health endpoints off public routes. The policies do not expose
health in any Service. Application HTTPS egress excludes private/reserved/node
destinations; application source-specific host validation remains required. Broker
IAM/API egress uses explicit destinations. Confirm the actual packet source at
CNI, since a declarative rule alone does not prove isolation. IPv6 public edge
acceptance and IPv6 backend denial require separate checks.

The installed guard unit currently orders itself before k3s/Docker. Ordering alone
does not establish fail-closed boot when nftables fails. Service start dependencies
were not changed. Before `edge-install`, an independently verified private
`boot-guard-acceptance.json` must bind this release with `fixture=false`,
`k3s_start_denied_when_guard_fails=true`,
`docker_start_denied_when_guard_fails=true`, and `guard_restored=true`.
Completing that guard integration and negative boot test remains an activation
prerequisite; these preparation assets make no reboot-safety claim.

The capacity monitor checks the corpus filesystem every minute and withdraws the
edge and both data roles below 128 GiB free. It preserves PostgreSQL, the broker
journal and permanent S3 objects. A rollout or activation metadata-write failure
attempts to stop both roles and restore disabled collector configuration; recovery
failure is reported explicitly. No automatic schema downgrade, data deletion or
rollback to an older binary occurs.

Run repository-required checks and independent Security Boundary review, plus
the minikube filesystem and credential-broker/S3 acceptance gates using owned
`/tmp` state. Validate the exact edge binary/configuration before starting it,
then check both MCP revisions on HTTP and Draft02 WebTransport, allowed/rejected
Host and Origin, mTLS rejection, private-path denial, and public IPv4/IPv6.
Activate the original eight collector defaults only through the explicit operator
activation step after provider/isolation acceptance, then observe readiness,
restarts, broker leases, corpus progress and capacity for ten minutes. A failure
withdraws the edge and stops serving/writer while retaining both databases,
broker journal and S3 objects. Report each acceptance boundary separately.
