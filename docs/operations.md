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
recognized staging cleanup, and corrupt-blob detection. It never points tests at
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

Schema v2 upgrades are forward-only. Take a coordinated database/blob backup before
upgrading. Include `rfc-indexes`; restore snapshots with their exact derived manifests
and source captures. To roll back to v1 software, restore a matching pre-upgrade
database and blobs in isolation rather than downgrading tables. Fixture checks and
bounded live smoke establish neither production capacity nor real full-corpus
acquisition. All live acceptance runs keep collection paused.

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
