# Local deployment and acceptance

The examples are a single-replica foundation, not a production deployment.
PostgreSQL coordinates exclusive serving ownership. Permanent public-source
captures occupy PostgreSQL and a content-addressed blob volume together; take
coordinated backups while serving and maintenance writes are stopped.

The application image is built natively on Linux amd64 and arm64:

```sh
scripts/test-image.sh
scripts/test-postgres.sh
```

Use the pinned Rust toolchain, a C/C++ compiler, CMake, Perl, pkg-config, OpenSSL,
Python 3, Git, and Docker for edge acceptance. OxiBelt is built from the immutable
revision named in `scripts/build-oxibelt.sh`. An optional `OXIBELT_SOURCE` checkout
only supplies that Git object; working-tree changes are never built. A supplied
`OXIBELT_BINARY` must report the exact clean revision. Build identity is checked;
this is not cryptographic build attestation.

The pinned edge uses WebTransport H3 draft02. Native clients send
`sec-webtransport-http3-draft02: 1`, and the backend returns
`sec-webtransport-http3-draft: draft02`. The example explicitly permits the
fixture client's Origin through both the edge route CORS policy and backend
allowlist. These WebTransport wire markers are independent of the MCP revision.

```sh
scripts/test-oxibelt.sh
scripts/test-minikube.sh
# Explicit opt-in: fixed, bounded RFC/Cargo/RustSec provider requests.
scripts/test-minikube.sh --live
```

The Docker gate uses an internal network and no provider data. It tests both MCP
revisions on both transports, mTLS identity/CA rejection and recovery, Host/Origin
validation, and absence of public health routes. It does not prove Kubernetes
routing. The minikube gate creates a new rootful Docker profile with Calico,
4 CPUs and 6 GiB RAM; it tests real NodePort TCP/UDP, private backend/health
isolation, persistent-volume restart, and a coordinated database/blob restore.
It refuses to reuse a profile and deletes only its own profile/images/fixtures.
Both gates use disposable certificates and fixed test-only database credentials.

If configured Docker overlay storage is on an incompatible shared filesystem,
the optional helper starts a separate rootful daemon under ignored `target/`,
uses a unique bridge and refuses route collisions, then removes its own state:

```sh
scripts/with-local-docker.sh scripts/test-postgres.sh
scripts/with-local-docker.sh scripts/test-oxibelt.sh
scripts/with-local-docker.sh scripts/test-minikube.sh --live
```

This helper requires passwordless sudo for its task-owned daemon and cleanup.
Its daemon cannot manage host firewall rules; forwarding/NAT use uniquely named,
temporary chains restricted to the checked test ranges. Existing IPv4 forwarding
must already be enabled. Cleanup removes only those chains and hooks.
It leaves configured daemon configuration and caches unchanged. Its `target/` directory
must reside on a native filesystem supporting Docker overlay mounts.

Production operators must supply public hostnames, trusted certificates, private
backend identity/CA material, private credentials, storage capacity/backup policy,
and immutable corresponding-source information for the exact deployed binary.
The OxiBelt example deliberately does not select a protected operational profile;
it does not redefine or weaken OxiBelt's documented profile contracts.

Local native-client results do not establish browser/ChatGPT compatibility,
hosted CI success, arm64 execution, registry publication, or production readiness.
