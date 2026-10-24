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

## Persistent operation and recovery

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
