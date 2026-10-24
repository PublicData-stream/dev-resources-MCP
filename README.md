# dev-resources-MCP

Anonymous, read-only developer knowledge and Rust package research over Streamable
HTTP and a custom WebTransport binding. The initial Rust foundation provides RFC
metadata discovery and text retrieval, crates.io metadata and verified source
browsing, RustSec advisory matching, and supplied Cargo.lock auditing.

Public upstream captures and provenance are permanent. Submitted lockfiles and audit
reports remain request-local. The service never builds or executes inspected packages.

## Development

Install Rust 1.99.1, Docker, Python 3, OpenSSL, and Git; the cluster gate also
uses minikube. From this directory:

```sh
cargo test --workspace --locked
scripts/test-postgres.sh
scripts/test-image.sh
scripts/test-oxibelt.sh
scripts/test-minikube.sh
```

The last two gates qualify the pinned OxiBelt edge and real disposable Kubernetes
routing. They may require substantial local build resources. Native Linux amd64
and arm64 are the declared CI platforms. Local tests do not establish hosted CI,
live client UI interoperability, registry publication, or production readiness.

Copy and adapt [the server example](deploy/oxibelt/backend.toml), supply PostgreSQL,
a persistent blob directory and certificates, then run:

```sh
cargo build --workspace --bins --locked
cargo run --locked -p devres-server --bin devres-server -- server.toml
```

Health is private. Public clients use HTTPS `/mcp`; native WebTransport clients use
`/mcp-wt/v1`. See [Specification](docs/Specification.md),
[Configuration](docs/Configuration.md), [Operations](docs/operations.md), and
[Sources](docs/sources.md). Changes follow [Contributing](CONTRIBUTING.md).

MDN, W3C, Chromium documentation, npm, full-corpus search, a graphical app, and public
citation web pages are future work. The repository is AGPL-3.0-only; upstream source
materials retain their own terms. See [notices](THIRD-PARTY-NOTICES.md).

[Initialization validation](docs/initialization-evidence.md) records the checks
actually executed, source evidence, and the remaining proof boundaries.
