# Operations and acceptance

The [npm module](npm.md) adds schema 9, public catalog/advisory acquisition and
local npm/pnpm/Yarn assessment. Include npm evidence and search data in coordinated
backups. Private maintenance uses `devres-server rebuild-npm-index CONFIG.toml`
with serving stopped and the same ownership fence as other rebuild commands.

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

## Native end-to-end CI

`scripts/ci-e2e.sh build PLATFORM DIRECTORY` builds the fixture harness once per
native architecture and exports a Docker-save artifact through
`scripts/e2e-artifact.py`. `test docker|minikube PLATFORM DIRECTORY` verifies its
platform, commit, version and contents, loads it, and passes `--image` to the
scenario harness without rebuilding. Release builds stamp their sources; consumers
validate the version from the release tag without stamping their checkout.

Harness construction requires native `strip`. It removes debug sections only from
the six staged executable copies before building the image, preserving symbol tables
and shared build outputs. This reduces the archive, Docker and minikube image copies
without changing compiler profiles or acceptance coverage.

The `e2e-build` matrix uses Ubuntu 26.04 amd64 and ARM64 runners with 60-minute
limits. The `e2e` matrix runs Docker and minikube on both architectures with
45-minute limits and fail-fast disabled. The always-running `edge` aggregate
requires both matrices to succeed, including rejecting skipped or cancelled work.
Harness artifacts `e2e-harness-ARCH` live for one day; scenario diagnostics selected
by `DEVRES_E2E_DIAGNOSTICS_DIR` live for seven days. Diagnostics exclude fixture
private keys and request contents.

Storage diagnostics run before and after artifact loading and cluster startup,
then after node image import, including failed stages. They report filesystem
space/inodes, harness image bytes and task-owned directory totals to the console and the diagnostics
artifact's `storage/` directory. Each capture is limited to 64 KiB and 15 seconds;
nonzero console status marks unavailable or partial counters. Artifact write failures
never replace the scenario's exit status. No host software or shared caches are pruned.

The driver enters owned `/tmp` state through `with-tmp-state.sh`, then overrides
Cargo and OxiBelt targets to `/buildcache/rust/target`. It installs Rust 1.99.1
before checking native host/compiler/daemon agreement inside an isolated rootful
`with-local-docker.sh` daemon. Minikube 1.39.0 downloads are checked against pinned
architecture-specific SHA-256 values and use Kubernetes 1.37.0. These disposable
fixture gates perform no publication or live-provider acceptance; hosted native
results and production operations remain separate evidence.

## Native images and versioned releases

### CPU defaults and overrides

The repository Cargo configuration defaults all x86_64 Rust builds to
`-C target-cpu=x86-64-v3`, including local development, tests, examples,
documentation tests, native CI, application images, and the pinned OxiBelt
acceptance harness built from this repository. Build and runtime hosts must expose
the x86-64-v3 instruction set. ARM64 retains its existing target defaults.
OCI platform names remain `linux/amd64` and `linux/arm64`. Native dependencies,
system packages, and the prebuilt Rust standard library retain their existing
compilation policies.

Official builds use the repository default. For a local build on an older x86_64
CPU, standard Cargo flag overrides can select the baseline CPU:

```sh
env -u CARGO_ENCODED_RUSTFLAGS -u CARGO_ENCODED_RUSTDOCFLAGS \
  RUSTFLAGS='-C target-cpu=x86-64' RUSTDOCFLAGS='-C target-cpu=x86-64' \
  cargo build --workspace --bins --locked
```

These variables replace the configured flags; include any other required flags in
the override. Host environment overrides are not automatically forwarded into
Docker builds. See [Cargo flag precedence](https://doc.rust-lang.org/stable/cargo/reference/config.html#buildrustflags).

### Native platform acceptance

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

Publication uses annotated, unprefixed version tags whose commits are in main
history: `X.Y.Z`, `X.Y.Z-beta.N`, or `X.Y.Z-build.<8-lowercase-hex-commit>`.
Stable and beta images require a published GitHub Release; stable releases must
not be prereleases and beta releases must be prereleases. Build candidates start
from tag pushes. Numeric SemVer identifiers cannot have leading zeros; a build tag
must match the commit prefix. There are no `latest`, branch, major or minor image
aliases. Maintainers must protect these version tags against movement and deletion.
The workflow rechecks annotated tag identity and mutable Release identity before
publication. Existing `v`-prefixed tags are not accepted by the new release tooling.

Main retains Cargo version `0.0.0`. Each release CI checkout stamps the version
into first-party manifests, path dependencies, lock entries and exact
license exceptions. Third-party resolutions are unchanged. Publication reuses only
the newest complete successful main-push CI attempt for the exact commit within
24 hours. All ten expanded jobs, including both architectures and both edge
scenarios, must have succeeded in that same attempt. Stale, incomplete, failed,
ambiguous or unavailable evidence requires fresh full stamped release CI.
When ordinary CI is reused, separate native jobs build and smoke the six stamped
release images; fresh release CI already produces those artifacts. An explicit
gate requires exactly one successful path before any registry-writing job starts.
The tested OCI artifacts are promoted without rebuilding. Immutable platform tags
`VERSION-amd64` and `VERSION-arm64` support an index at `VERSION`, where `VERSION`
is the complete unprefixed Git tag. Matching artifact retries are idempotent;
conflicting tags/assets fail rather than overwrite. A partial publication is not a
successful release, even when some platform images are already available.

The GitHub Release contains `source.tar.gz`, its SHA-256 file, release identity,
and three JSON image-digest records. Stable/beta Releases must be mutable: the
workflow appends missing assets after image acceptance, preserves matching assets
and human-written release metadata, and rejects conflicts without replacing them.
All existing required assets are checked before uploading any missing asset.
Immutable stable/beta Releases are rejected before registry publication. Build
candidates retain draft creation, asset upload, and prerelease publication. The source archive includes the exact stamped
manifests used for building; the ordinary Git tag archive retains placeholders.
Build the extracted archive with `docker build --target server .`; when using
`scripts/test-image.sh` to build it, supply `--revision` and `--version` from
`release.json` because the archive has no Git history.
Beta/build releases are marked prerelease. Set the configured `source.url` to an
accessible offer for this exact corresponding source before independent deployment.

Before the first independently authorized publication, verify organization package
permissions and set all three GHCR packages public (new packages default private).
After platform/index publication, workflow acceptance verifies all three version
indexes and all six platform provenance statements, binding the source commit,
tag and publishing workflow. Explicit anonymous Skopeo copies download every
platform image into fresh isolated storage and check manifest/config/layer content
and source labels without executing the images. Only complete acceptance produces
the combined `ghcr-release-digests` artifact and allows corresponding-source
completion. Failures leave partial publication; stable/beta GitHub Releases already
exist at that point. Authenticated pulls or manifest inspection alone do not prove
complete public downloads. CI retains tested image/source artifacts for seven days
and index/accepted-digest artifacts for thirty days; published GitHub Release assets
remain the durable corresponding-source distribution. Never delete retained
public captures as part of image/test cleanup. Roll back a deployment by selecting
a previously verified digest through a separately authorized deployment operation.

## Persistent operation and recovery

RFC collection is enabled when `[rfc]` is omitted. To pause scheduling, set
`enabled = false` in `[rfc]` and restart; retained jobs/captures remain intact.
The tracked edge/minikube harness explicitly pauses collection. `rfc.corpus_status`
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
`crate.corpus_status` separates inventory enumeration, metadata gaps, retained
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
`advisory.corpus_status` to distinguish a ready service from available source data,
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
scheduling without deleting evidence. `mdn.corpus_status` is aggregate-only;
`mdn.snapshots` exposes frozen commit/ref discovery and `mdn.history` provides
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
Use `whatwg.corpus_status` to inspect acquisition/projection/index gaps separately.
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

## W3C validation and retained acceptance

W3C collection defaults to enabled with current published reports ahead of historical
work. Set `[w3c] enabled=false` to pause new acquisition while retaining local
research. Health/metrics remain private; `w3c.corpus_status` reports source coverage,
license blocks, freshness and processing/index gaps separately.

For this environment, build targets use `/buildcache/rust/target` and all disposable
state uses `/tmp`. The existing temporary-state wrapper remains unchanged; apply
shared-cache/build overrides after entering it:

```sh
shared_cargo_cache=${CARGO_HOME:-"$HOME/.cargo"}
shared_rustup_cache=${RUSTUP_HOME:-"$HOME/.rustup"}
export DEVRES_TMP_ROOT=/tmp/devres-w3c
scripts/with-tmp-state.sh env \
  CARGO_HOME="$shared_cargo_cache" RUSTUP_HOME="$shared_rustup_cache" \
  CARGO_TARGET_DIR=/buildcache/rust/target OXIBELT_TARGET_DIR=/buildcache/rust/target \
  CARGO_BUILD_JOBS=2 scripts/with-local-docker.sh scripts/test-minikube.sh
```

Launch the disposable daemon with `umask 022`; keep its task-owned parent directory
private. A daemon inheriting `umask 077` can create non-traversable container roots
and unreadable PID files. Use the native-filesystem workaround above when `/tmp`
cannot support nested container storage.

Use the same wrapper for PostgreSQL and OxiBelt checks. Its dedicated Docker daemon
keeps test images, volumes and caches below `/tmp`; minikube uses a fresh owned
profile and bundled kubectl, never an operator's configured cluster. Seeded W3C
fixtures exercise HTTP/WebTransport reads and coordinated restart/restore without
provider traffic. The tracked backend example disables every collector.

`scripts/live-smoke.sh --live --w3c` is a distinct fixed-record source/parser check.
It requests CSS Color 4 and retired Canvas 2D metadata, the current dated CSS Color
publication and an official source-repository advertisement. Attempts, including
retries, have persisted caps of 20 per provider (W3C and GitHub), with exclusive
root locking. It retains qualified raw publication evidence and a
receipt in a new owned `/tmp` directory. A retained licensed body can be replayed
without another publication request; its receipt distinguishes local file time
from unknown upstream validation time and does not claim metadata revalidation.
It does not run a full Git clone, whole
corpus collection, transport certification or production deployment.

`scripts/accept-w3c.sh --live current|full` explicitly starts retained corpus
acceptance, with ownership-marked PostgreSQL/blobs and frozen inventories under
`/tmp`. Run it inside the same isolated Docker/build wrapper. Full work can be
resumed using `DEVRES_W3C_ACCEPTANCE_ROOT` and `--resume full`. Resume processes the
same frozen evidence without new source traffic. `--recover full` creates linked
successor discovery evidence; `--resume-recovery full` continues that successor.
Original inventories, failures and source validation times remain retained.
Recovery may fetch newly qualified publications through normal pacing while
preserving original catalog/ref observations. Both resume modes reject source I/O.

These corpus commands may require substantial time/storage and are separate from
the bounded smoke. Receipts must distinguish discovery, license qualification,
acquisition, ancestry, projection and index coverage. A blocked license, missing
mapping, unavailable edition or unsupported representation does not become a
successful complete result merely because its metadata was accounted for.

Schema 7 requires a coordinated backup of PostgreSQL, W3C raw artifacts, qualified
Git evidence, inventories and indexes. Older binaries reject this schema. Restore
compatible binaries and the coordinated snapshot together; do not attempt a reverse
migration or discard permanent evidence. Index rebuild is private maintenance via
`devres-server rebuild-w3c-index CONFIG.toml` and does not renew source validation.

## Chromium operation and acceptance

Chromium collection defaults on, prioritizes current documents, and resumes history
from durable checkpoints. Disable `[chromium].enabled` in fixture configurations.
Observe `chromium.corpus_status` for separate discovery, licensing, processing,
indexing, history, freshness, and partial-component state. No public controls exist.
The offline maintenance command is `devres-server rebuild-chromium-index CONFIG.toml`.
Coordinate PostgreSQL/blob backups with all writers stopped; schema 8 is forward-only.

`scripts/live-smoke.sh --live --chromium` is fixed-record opt-in acceptance with
at most 20 attempts/provider including retries. It retains marked public evidence
under `/tmp`. `scripts/accept-chromium.sh --live current|full` starts separate retained
acceptance; `--resume full` continues its existing frozen source observation. It does
not imply whole-source completion unless its final receipt establishes that scope.
Retained public evidence survives runner failure and automatic cleanup.

For shared local caches, enter `scripts/with-tmp-state.sh` first, then override
`CARGO_HOME`/`RUSTUP_HOME` to the shared caches and set
`CARGO_TARGET_DIR=/buildcache/rust/target` and
`OXIBELT_TARGET_DIR=/buildcache/rust/target`. Run Cargo through the privileged channel.
Use `scripts/with-local-docker.sh` for owned Docker state below `/tmp`; minikube tests
create and remove their own profile rather than modify an existing operator profile.
See [Chromium acquisition and research](chromium.md) for source and proof boundaries.
