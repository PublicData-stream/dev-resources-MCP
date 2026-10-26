# Operations and acceptance

## Local gates

From the repository root, use the pinned toolchain and a working Docker daemon.
Cargo commands using shared caches require the privileged command channel in the
Codex environment. Docker rootful and rootless operation are both permitted.

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo audit
cargo deny check
python3 -m unittest discover -s scripts/tests
scripts/test-postgres.sh
scripts/test-image.sh
```

If configured Docker snapshot storage cannot support overlay mounts, the optional
`scripts/with-local-docker.sh COMMAND ...` wrapper creates an isolated rootful daemon
and containerd on native local storage. It needs passwordless sudo and refuses
conflicting test address ranges. It does not edit configured daemons or contexts;
cleanup removes only its private processes, bridge and data.

The PostgreSQL gate creates a disposable container and database. It verifies
single-owner exclusion, immutable history, head revalidation, restart recovery,
recognized staging cleanup, and corrupt-blob detection. The crate corpus checks
also exercise durable inventories, metadata joins, processing generations, frozen
snapshot publication, restart and derived-document replacement. It never points tests at
an existing production database. Unit tests require neither Docker nor credentials.

## Pinned edge

The Docker edge gate requires Git, OpenSSL, Python 3, C/C++ build tools, CMake, Perl,
pkg-config, the pinned toolchain, and Docker. It builds a clean Git archive of the
specified OxiBelt revision, leaving supplied checkouts unchanged.

```sh
scripts/build-oxibelt.sh
scripts/test-oxibelt.sh
```

`OXIBELT_SOURCE` selects an existing checkout containing the pinned Git object.
`OXIBELT_BINARY` reuses a binary only after exact clean build-identity validation.
`OXIBELT_TARGET_DIR` selects its independent build cache; default build concurrency
is two. Source-identity validation is not a cryptographic build attestation.

The edge uses origin-only HTTPS upstreams, explicit CA/SNI verification, and backend
mTLS with an exact client SAN. HTTP buffering/cache/compression are disabled for
MCP streaming. Preserve caller Origin and configure backend authorities to match
`preserve_host = false`. The WebTransport route explicitly selects H3 and does not
introduce H2 fallback. The Draft02 request/response markers are explicit. The
WebTransport route permits only the configured test Origin through its CORS action;
backend Origin validation still applies independently. Fixture configuration does not select a protected OxiBelt
operational profile; it does not alter such a profile's documented requirements.

The Docker gate exercises both MCP revisions and both transports through the exact
pinned edge, backend identity/trust rejection and recovery, Host/Origin rejection,
and private-health route absence. Its network is internal and it contacts no
public content providers. Disposable CA private keys remain outside image contexts.

## Disposable Kubernetes

```sh
scripts/test-minikube.sh
# Same isolated gate plus explicitly authorized fixed public-provider checks:
scripts/test-minikube.sh --live
# Narrow RFC recheck after alternate formats passed in the same attempt budget:
scripts/test-minikube.sh --live --rfc-text-only
```

This gate uses rootful Docker and creates a unique minikube profile with Calico,
4 CPUs and 6 GiB RAM. It refuses to reuse an existing profile. It qualifies actual
NodePort TCP/UDP transport paths, CNI backend/health isolation, a persistent-volume
restart, and coordinated PostgreSQL/blob backup and restore. Cleanup deletes only
task-owned resources. It retains build caches but does not leave the test cluster
running. See [deployment assets](../deploy/README.md).

A local gate does not establish arm64 execution or native browser/ChatGPT UI
interoperability. Native architecture CI, image publication, production certificates,
provider coverage, and production deployment require their own evidence.

## Native images and versioned releases

Native CI pairs `ubuntu-26.04` with `linux/amd64` and `ubuntu-26.04-arm` with
`linux/arm64`. It checks the host, Rust compiler and Docker daemon architecture
before building. Local amd64 checks do not establish ARM64 execution.

```sh
scripts/check-native-platform.sh linux/amd64
scripts/test-image.sh --platform linux/amd64
scripts/test-image.sh --platform linux/amd64 --target server
scripts/test-image.sh --platform linux/amd64 --target probe
scripts/test-image.sh --platform linux/amd64 --target audit-worker
```

Use `linux/arm64` on an ARM64 Linux host. Explicit foreign-platform builds require
operator-provided emulation and must be reported as emulated. The native guard
rejects a foreign host even when emulation is installed. `--image IMAGE` checks an
existing image without rebuilding or deleting it. `--oci-output /absolute/new/path`
builds an OCI archive first, loads and smokes that exact archive, and retains its
checksums and content digests. This path requires `skopeo`, Buildx OCI export and a
Docker image store capable of loading OCI archives (the native CI uses the
containerd image store). It cannot be combined with `--image`.
Temporary containers have no network, a read-only filesystem and no capabilities.
The worker uses synthetic public fixtures; no submitted package code is executed.

The release workflow publishes these families under `ghcr.io/publicdata-stream`,
each with amd64 and ARM64 descriptors:

| Image | Executables |
| --- | --- |
| `dev-resources-server` | Server plus its required sibling audit worker |
| `dev-resources-probe` | WebTransport acceptance client |
| `dev-resources-audit-worker` | Private stdin/stdout helper; no remote worker service |

The default Dockerfile target remains the combined compatibility image. Explicit
`--target server`, `--target probe`, and `--target audit-worker` select the separate
images. No Kubernetes manifest or runtime configuration automatically selects them.

Publication is triggered only by an annotated version-tag push whose commit is in
main history: `vX.Y.Z`, `vX.Y.Z-beta.N`, or `vX.Y.Z-build.<8-lowercase-hex-commit>`.
Numeric SemVer identifiers cannot have leading zeros; a build tag must match the
commit prefix. There are no `latest`, branch, major or minor image aliases.
Maintainers must protect these version tags against movement and deletion.

Main retains Cargo version `0.0.0`. Each release CI checkout stamps the version
without `v` into first-party manifests, path dependencies, lock entries and exact
license exceptions. Third-party resolutions are unchanged. Fresh full CI and all
six separate image gates must succeed before registry-writing jobs start. The
tested OCI artifacts are promoted without rebuilding. Immutable platform tags
`VERSION-amd64` and `VERSION-arm64` support an index at `VERSION`, where `VERSION`
is the complete Git tag including `v`. Matching artifact retries are idempotent;
conflicting tags/assets fail rather than overwrite. A partial publication is not a
successful release, even when some platform images are already available.

The GitHub Release contains `source.tar.gz`, its SHA-256 file, release identity,
and three JSON image-digest records. The source archive includes the exact stamped
manifests used for building; the ordinary Git tag archive retains placeholders.
Build the extracted archive with `docker build --target server .`; when using
`scripts/test-image.sh` to build it, supply `--revision` and `--version` from
`release.json` because the archive has no Git history.
Beta/build releases are marked prerelease. Set the configured `source.url` to an
accessible offer for this exact corresponding source before independent deployment.

Before the first independently authorized publication, verify organization package
permissions and set all three GHCR packages public (new packages default private).
After publication, verify native job completion, provenance, source assets, index
and platform digests, and anonymous pulls of both platforms. An authenticated pull
alone does not prove public availability. CI retains tested image/source artifacts
for seven days and index-digest artifacts for thirty days; published GitHub Release
assets remain the durable corresponding-source distribution. Never delete retained
public captures as part of image/test cleanup. Roll back a deployment by selecting
a previously verified digest through a separately authorized deployment operation.

## Persistent operation and recovery

RFC collection is enabled when `[rfc]` is omitted. To pause scheduling, set
`enabled = false` in `[rfc]` and restart; retained jobs/captures remain intact.
The tracked edge/minikube harness explicitly pauses collection. `rfc_corpus_status`
reports missing representations, failures and the default snapshot; `latest_partial`
identifies newer incomplete evidence for explicit queries. Coverage is observed
evidence, not proof of whole-provider coverage.

For an explicitly requested bulk bootstrap, stop serving first and invoke:

```sh
devres-server import-rfcs /etc/devres/server.toml --max-bytes 8589934592
```

This private command opts into the fixed official rsync mirror over TCP 873. It
requires `/usr/bin/rsync` (included in server/combined images), metadata/errata HTTPS
access, at most 1 MiB/second transfer, and disk for twice the byte budget plus
staging/reserved headroom. Each file caps at 16 MiB; the total budget must be
1..128 GiB and the entire import has a 24-hour deadline. SIGINT/SIGTERM cancel it
and reap the owned child. Missing/failed mirror files remain gaps; deletion never
removes history. Unauthenticated rsync evidence never replaces HTTPS heads.
The staging monitor checks every 250 ms and can overshoot the transfer budget
between checks; oversize imports are rejected and per-file headroom is reserved.

Startup removes recognized abandoned index staging directories while holding the
exclusive storage fence; it never deletes published index directories. If a derived
index is corrupt, stop serving and run `devres-server rebuild-rfc-index CONFIG.toml`.
This creates a new immutable snapshot from archived source captures without using
the corrupt base. The older snapshot remains immutable and fails explicitly if its
files are damaged. Keep the original archive for investigation.

Schema v2/v3 upgrades are forward-only. Take a coordinated database/blob backup
before upgrading. Include `rfc-indexes`, `crate-indexes`, permanent Git evidence,
dump/docs.rs captures and derived text; restore snapshots with their exact manifests
and source captures. To roll back to earlier software, restore a matching pre-upgrade
database and blobs in isolation rather than downgrading tables. Fixture checks and
bounded live smoke establish neither production capacity nor real full-corpus
acquisition. All live acceptance runs keep collection paused.

Crate collection is also enabled when `[crates]` is omitted. Set `enabled = false`
in `[crates]` before running disposable or bounded-live acceptance.
`crate_corpus_status` separates inventory enumeration, metadata gaps, retained
artifacts, job failures, projections and search coverage. One successful acquisition
or completed job does not prove whole-registry ingestion. Bootstrap and revalidation
may take substantial storage/time; no completion estimate or whole-corpus load
benchmark is implied.

The hourly Git index and daily public metadata dump are independent clocks. Exact
archives are checksum-bound; docs.rs representations may change on rebuild and
missing documentation is retried. Monitor per-kind failures, last successful
inventory/enrichment/snapshot, storage reserve/quota and explicit processing/index
gaps. Capacity exhaustion pauses admission while retaining historical evidence;
provide storage or reduce intake rather than deleting permanent captures.

Stop serving before either private crate maintenance command:

```sh
devres-server rebuild-crate-index /etc/devres/server.toml
devres-server import-crate-corpus /etc/devres/server.toml --manifest SHA256
```

The rebuild uses retained database/capture evidence and publishes a new immutable
index/snapshot. Large retained search indexes are validated by a cancellable
background prewarm before activation and after restart; transient bootstrap search
unavailability is separate from listener readiness and legacy tool availability.
The import accepts the **body SHA-256 of an already retained Git
evidence manifest**, not a caller URL, package executable or SQL script. It restores
and verifies owned index evidence before publishing inventory; unknown/missing
artifacts fail explicitly. Both commands use the single storage-owner fence and
support SIGINT/SIGTERM cancellation. They do not authorize publication/deployment
or whole-provider network acquisition beyond their stated private operation.

Backups must retain raw artifacts even when parsing/indexing is unavailable. Bare
Git working state and recognized processing stages are disposable; captured Git
objects/manifests and published indexes are evidence. Package archives and docs.rs
ZIPs are never extracted. JSON expansion uses an owned bounded staging file and
removes it on completion/cancellation. Preserve original licensing in exported
captures and keep any quota accounting consistent across restart.

Deploy one serving replica with Recreate updates. PostgreSQL 18 and the blob
filesystem are one logical backup unit. Provision both before starting the service.
Stop the server and any maintenance writers before taking a PostgreSQL dump and
blob-directory archive; retain them together with schema and build identity.
Restore both into an isolated environment and verify capture reads before resuming.
Database snapshots alone cannot recover missing archive bodies.

Only recognized regular `.stage-<pid>-<counter>` files are removed during startup
while exclusive ownership is held. Hash-named permanent objects are never deleted
by maintenance. Canceled stage writes have a cleanup guard; a crash can leave
recoverable stages or unreferenced immutable blobs. Investigate archive integrity
failures and storage exhaustion; do not discard permanent history as a shortcut.
Loss of the dedicated serving-owner database connection fails health supervision
and stops serving until restart. Do not run private refresh maintenance alongside
an active server because it requires the same single-owner storage fence.

Production operators supply hostnames, certificates, credentials, an exact
corresponding-source offer, storage sizing, coordinated backups, and monitoring.
Capacity requests in manifests are initial scheduling choices, not measured load
capacity. Watch disk headroom, storage health, aggregate errors/admission, and
source freshness without logging request bodies or package lists.

## Bounded live sources

Against an already running local test service:

```sh
scripts/live-smoke.sh --live --url https://edge:8443/mcp --ca test-ca.pem
```

The script uses fixed RFC and crate versions and a synthetic lockfile; no user
supplied private lockfile is needed. It has a five-minute bound, no crawling, and
fewer than twenty application HTTP attempts per provider including retry allowances.
Actual adapter requests, source timestamps, and resulting captures define the
observation. Passing this smoke is not full-source acceptance or a load test.

## Offline captured RustSec replay

An additional opt-in test accepts operator-supplied `head.json` and `bundle.tar.gz`
public captures. It performs no network requests and verifies parser/research
compatibility for the captured revision, not current provider freshness:

```sh
DEVRES_RUSTSEC_REPLAY_DIR=/path/to/public-captures \
  cargo test --locked -p devres-adapters --test rustsec_replay -- --ignored
```

The ordinary suite uses the small curated, attributed Git-header fixture. Full
public database downloads are not committed. See the
[initialization evidence](initialization-evidence.md) for actual executed gates.

## RustSec collection and history

Serving supervises hourly current-advisory refresh and daily full branch/tag Git
synchronization. All public advisory tools are local reads. During bootstrap use
`advisory_corpus_status` to distinguish a ready service from available source data,
raw graph acquisition, backfill completion, projection gaps and assessment freshness.
History processing does not block current publication. Set `[rustsec].enabled=false`
to pause new scheduling while retaining snapshots and source evidence.

Schema 4 retains deduplicated advisory records and immutable ordered memberships.
Legacy captures are recovered locally in bounded batches with their recorded source
times. Unsupported historical formats remain retained raw evidence and incomplete
projections. Old binaries reject this schema; rollback requires a coordinated
database/blob restore taken with all writers stopped.

The disposable bare mirror is under `blob_dir/rustsec-history/history.git`;
permanent content-addressed packs/manifests are in its separate `artifacts`
directory. Never remove the artifacts directory as mirror cleanup. Offline restore
verifies all retained graph roots before processing resumes. Quota/free-space
failures preserve evidence; source errors use persisted bounded retry scheduling.

For a current-only maintenance refresh, stop serving and run:

```sh
devres-server refresh-advisories CONFIG.toml
```

This command requires successful source validation; stale fallback is not refresh
success. Start serving again before running `scripts/live-smoke.sh --live`.
Disposable harness configurations keep all automatic collectors disabled so bounded
live acceptance does not accidentally initiate unrelated collection.

An additional opt-in probe operates against **disposable dedicated storage** supplied
through `DATABASE_URL` and `BLOB_DIR`; never run it alongside a serving storage owner:

```sh
CARGO_TARGET_DIR=/buildcache/rust/target cargo build --locked -p devres-adapters --example rustsec-probe
/buildcache/rust/target/debug/examples/rustsec-probe --live current
/buildcache/rust/target/debug/examples/rustsec-probe --live history
```

Each invocation enforces a shared maximum of 20 HTTP attempts, including retries,
without increasing source rates. `DEVRES_RUSTSEC_PROBE_ATTEMPTS` can lower this
ceiling to 1..20 attempts. Current acceptance has a five-minute bound and
checks a fixed positive `odbc` advisory and original-source detail. Full-history
acceptance has a one-hour bound, retains resumable checkpoints, and reports traversal
completion separately from projection completeness. A timeout is incomplete
acceptance; it does not establish full-source coverage. Probe output contains public
source provenance and aggregate counts, never a supplied lockfile.

## MDN collection, repair and full acceptance

Omitted `[mdn]` starts current-main acquisition and resumable complete advertised
branch/tag ancestry processing for both repositories. Set `enabled=false` to pause
scheduling without deleting evidence. `mdn_corpus_status` is aggregate-only;
`mdn_snapshots` exposes frozen commit/ref discovery and `mdn_history` provides
parent-relative source changes. Main publication has priority over backfill.
Unknown historical formats/macros and individual index limits remain explicit
projection gaps; they do not imply missing raw Git evidence.

Stop serving before private offline index maintenance:

```sh
devres-server rebuild-mdn-index /etc/devres/server.toml
```

This uses retained index/projection evidence and publishes new immutable derived
snapshot generations. The older snapshot identifiers remain fixed, including
explicit failure if their derived files are corrupt. Rebuild does not fetch sources
or refresh validation time. Keep the damaged evidence for investigation. Schema 5
requires coordinated PostgreSQL/blob backup; older binaries reject it. Backups
include `mdn/content/artifacts`, `mdn/compat/artifacts`, `mdn/raw-artifacts`, MDN
projection/inventory rows and `mdn-indexes`. Bare `history.git` directories are
reconstructable working state; artifact directories are permanent evidence.

The ordinary PostgreSQL, image, edge and minikube gates use explicitly labeled
synthetic MDN/BCD data. They exercise pinned search/get/compatibility/resources,
HTTP/WebTransport parity, persistence restart and coordinated restore while all
collectors are disabled. They never establish upstream/full-source acceptance.

Explicit source acceptance uses separate retained storage:

```sh
CARGO_TARGET_DIR=/buildcache/rust/target scripts/accept-mdn.sh --live current
CARGO_TARGET_DIR=/buildcache/rust/target scripts/accept-mdn.sh --live full
# Reuse the printed task-owned directory; perform no new source acquisition:
DEVRES_MDN_ACCEPTANCE_ROOT=/tmp/devres-mdn-retained.EXAMPLE \
  CARGO_TARGET_DIR=/buildcache/rust/target scripts/accept-mdn.sh --resume full
```

Each initial invocation creates its own PostgreSQL directory and blobs under `/tmp`
and freezes both official ref observations. The script stops only its labeled
container; it retains database files, raw evidence, projections, indexes and
checkpoints after failure or success. Do not place these artifacts in disposable
fixture cleanup paths. The low-level example requires dedicated `DATABASE_URL`,
`BLOB_DIR` and the matching ownership marker; never point it at production storage.
The driver requires Docker, `flock`, and passwordless `sudo` for fixed read-only storage
accounting of the container-owned PostgreSQL directory. It builds and runs the
locked release probe so full-history processing does not use a debug executable.
The script holds an exclusive directory lock through container cleanup and its
child processes. A second invocation fails before starting PostgreSQL; wait for
the previous invocation to exit before resuming the same directory. A surviving
owned PostgreSQL container also prevents restart. Cleanup requests a graceful
PostgreSQL shutdown before removing only the owned container.

The durable attempt ledger reserves at most 20 shared upstream HTTP attempts,
including retries, before requests are sent. Restart does not renew the allowance;
`--resume` requires both frozen observations and performs no network acquisition.
Older acceptance directories without a ledger conservatively reserve the entire
20-attempt allowance. Existing bounded live smoke keeps its separate original
ceiling and fixed records.

Full acceptance measures database/WAL, mirrors, raw/artifact storage, stages and
indexes against a combined 256 GiB working budget and preserves at least 10 GiB
free space. The monitor waits two seconds between checks, waits for the current
acquisition or resumable processing slice to finish, and pauses collector writes
while measuring storage. A measurement has a
30-second deadline; timeouts stop acceptance. Transient file-movement failures
receive bounded retries while processing remains paused;
this polling measurement is not a kernel filesystem quota. Per-operation budgets,
source admission and cancellation remain active. There is no total processing-time
cap. Capacity exhaustion pauses work and is incomplete acceptance, never permission
to delete permanent history.

Completion requires both frozen ancestry queues to finish, every commit snapshot
to have accounted coverage, validated latest index artifacts, and pinned current
and deterministic historical document/BCD/source/resource research checks. The
runner retains `acceptance.json` on success and reports projection gaps separately.
A bounded clone, successful current query or completed individual job does not
establish that result. Native architecture CI, registry publication, browser/client
UI interoperability and production deployment remain separate acceptance evidence.

On FUSE-backed hosts, a task-owned native filesystem image may back the retained
acceptance directory. Keep the image, `volume.json` and any original pre-migration
copy together. When `volume.json` exists, the driver refuses an unmounted `native`
volume instead of initializing replacement storage. Restore only the recorded
owned mount (with `loop,nodev,nosuid,noexec`) before resuming; image removal is not
fixture cleanup. Storage accounting includes retained original copies, and the
backing filesystem must also keep the stated free-space reserve.

## WHATWG collection and isolated acceptance

WHATWG collection starts automatically unless `[whatwg] enabled=false`. During
bootstrap listeners can remain ready while local standards research is unavailable.
Use `whatwg_corpus_status` to inspect acquisition/projection/index gaps separately.
Stop all serving writers before private maintenance or coordinated backup/restore.
`devres-server rebuild-whatwg-index CONFIG.toml` rebuilds local retained evidence;
it does not establish fresh upstream validation.

For this implementation and its acceptance, all generated state is below `/tmp`:

```sh
export DEVRES_TMP_ROOT=/tmp/devres-whatwg
scripts/with-tmp-state.sh cargo test --workspace --locked
scripts/with-local-docker.sh scripts/test-postgres.sh
scripts/with-local-docker.sh scripts/test-oxibelt.sh
scripts/with-local-docker.sh scripts/test-minikube.sh
scripts/with-local-docker.sh scripts/accept-whatwg.sh --live full
```

The wrapper isolates Cargo/rustup/target, OxiBelt, Python, Docker client, minikube,
kubeconfig and temporary/cache directories without changing HOME. Seed a required
toolchain/cache by copying it into that owned state directory; do not hard-link mutable
cache metadata. The Docker helper confines its separate daemon/containerd data,
images, volumes, build caches and logs there too. Minikube creates a task-owned profile
and confines kubectl discovery cache. Existing profiles/daemons are not reused.

`accept-whatwg.sh --live current|full` creates a retained, ownership-marked directory
under `/tmp`, synchronizes online evidence and saves a frozen observation before
processing. `--resume full` requires `DEVRES_WHATWG_ACCEPTANCE_ROOT` pointing to that
retained directory and continues its frozen work. It never replaces the frozen
observation or deletes its captures/database. Keep retained evidence distinct from
disposable fixtures; `/tmp` persistence depends on the host's cleanup policy.

```sh
DEVRES_WHATWG_ACCEPTANCE_ROOT=/tmp/RETAINED_WHATWG_DIRECTORY   scripts/with-local-docker.sh scripts/accept-whatwg.sh --resume full
```

When a metadata or discovery-policy correction changes the qualified publication
inventory, use the explicit recovery path:

```sh
DEVRES_WHATWG_ACCEPTANCE_ROOT=/tmp/RETAINED_WHATWG_DIRECTORY   scripts/with-local-docker.sh scripts/accept-whatwg.sh --recover full
DEVRES_WHATWG_ACCEPTANCE_ROOT=/tmp/RETAINED_WHATWG_DIRECTORY   scripts/with-local-docker.sh scripts/accept-whatwg.sh --resume-recovery full
```

Recovery reinterprets retained publication bytes and records a successor linked to
the original freeze. It preserves the original `frozen.json`, `acceptance.json`,
failed observations, catalog, Git roots, raw hashes and validation times. Every
inherited publication candidate receives an audited disposition using its source
role, independently of HTTP status. Ordinary linked images and malformed local
references do not become publication obligations. A genuinely advertised but
unavailable publication still blocks completion.

`--recover full` may fetch only newly required qualified publications through the
normal broker and pacing; it does not revalidate the catalog or Git observations.
An unresolved inventory keeps its checkpoint and failure evidence without publishing
a closed successor. Repeat that command to continue recovery. A closed successor is
saved as `frozen-recovery-ID.json`; `recovery-current.json` selects it for the offline
`--resume-recovery full` command. Content-addressed recovery receipts are retained
separately, with `recovery-acceptance.json` pointing to the latest receipt. Preserve
these manifests, receipts and qualification evidence with the original captures.
Failed or cancelled recovery invocations also retain content-addressed failure
records, selected by `last-recovery-failure.json`.
Completed source snapshots and projections can be reused; metadata repair does not
establish fresh upstream validation. Original `--resume full` still addresses the
original freeze and its original obligations.

Nonempty discovery queues from an older or unversioned admission policy cannot
authorize requests under the new policy. They fail closed and remain retained.
Use the explicit recovery path for a completed parent freeze. If an older run has
no frozen parent yet, retain its directory and use a fresh isolated directory for
a new capture rather than treating its queued URLs as current-policy authority.

Full acceptance exceeds the fixed-record smoke request budget and is a separate
explicit operation using normal pacing, not a load test. Reports separate catalog/ref
accounting, raw acquisition, historical processing, index coverage and public research.
A successful full receipt also checks the captured catalog's complete current view,
DOM text/raw retrieval, search, IDL symbol resources and history through the local
research adapter; HTTP/WebTransport framing has separate fixture and edge checks.
A job finishing does not prove missing upstream material exists or unsupported
representations were projected. Local edge/minikube results do not establish hosted
ARM64 CI or production acceptance. Commit authority does not authorize deployment.

When `/tmp` itself is backed by a filesystem incompatible with overlay mounts, place
a task-owned native filesystem mount below `/tmp` and set `DEVRES_DOCKER_STATE_ROOT`
to it before invoking the Docker helper. This keeps images, volumes and node files
under `/tmp` while supporting Docker/minikube overlay mounts. Preserve the backing
image and mount metadata alongside retained acceptance evidence; stop owned containers
and the dedicated daemon before unmounting it. A `vfs` override is available through
`DEVRES_DOCKER_STORAGE_DRIVER=vfs` for Docker-only diagnostics, but is not evidence
that nested Kubernetes container storage supports the underlying filesystem.
