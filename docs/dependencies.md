# Dependency admission

The committed Cargo.lock is the exact bootstrap graph. Rust is pinned to 1.99.1,
rmcp to 3.7.0, wtransport to 0.7.2, sqlx to 0.9.0, and rustsec to 0.33.0.
Manifest semver ranges for support libraries remain bounded by the committed lock;
CI uses locked resolution. No Git dependencies or alternative registries are allowed.

| Group | Need, alternatives, and boundary implications |
| --- | --- |
| rmcp, Axum, Hyper, Tokio, tokio-util, futures | Standard MCP HTTP transport and async runtime; a hand-written HTTP stack would duplicate protocol/security work. Disable rmcp defaults and enable server/HTTP only; no client command execution. |
| wtransport, tokio-rustls, x509-parser | Custom reliable QUIC binding, TLS, exact edge SAN verification. Reuse the reference transport contract instead of inventing framing. wtransport uses ring; rustls provider is selected explicitly where required. |
| serde/json, jsonschema, TOML, URL | Typed schemas, strict configuration, source decoding, and canonical URL construction. Remote schema resolution is disabled. These parsers handle untrusted data under application limits. |
| reqwest | Bounded fixed-source HTTPS with no redirects, gzip auto-expansion, or arbitrary caller URLs. A separate retry owner avoids amplification. rustls+stream only, no default features. |
| sqlx | PostgreSQL transactions and explicit bound queries; no runtime SQL from callers, no compile-time database access or macros. Memory-only storage would not meet retention requirements. |
| SHA-256, hex, fs2 | Content-addressed immutable blobs, exact archive checksum verification, and free-space admission. fs2 provides safe filesystem-space calls rather than adding unsafe local FFI. |
| quick-xml, tar, flate2 | Streaming official RFC metadata and bounded crate/advisory archives. Neither tar extraction nor link following is used. XML general entities and mixed text need parser tests. |
| rustsec, semver | Maintained canonical advisory parsing and version matching rather than reimplementing affected ranges. Disable rustsec defaults, including Git, index lookup, and automatic fix support. |
| tracing/subscriber | Aggregate operational logging without request bodies or audit inputs. |
| rcgen, tempfile | Test-only disposable certificates and storage; not operator certificate provisioning. |

The resolved graph includes proc-macro build code and native cryptography build
scripts (notably ring and aws-lc-sys through selected TLS dependencies). They run at
build time in CI/build containers, never as inspected-package execution. Upgrades
require renewed maintenance/advisory/license review, especially for protocol, archive,
cryptography and SQL boundaries. Dependency availability or successful compilation
is not proof of security.

`deny.toml` admits the licenses observed in this resolved graph. First-party AGPL
exceptions are exact. Target-specific dependencies outside the declared Linux graph
remain in Cargo.lock and the notice inventory; admitting another platform requires
review of its additional licenses and dependencies.
Exception owner is the repository maintainers; review by 2027-01-24 and on version
or graph changes. No advisory suppression is pre-authorized.

Run `cargo audit` with current advisory access and `cargo deny check`. Tool versions
are cargo-audit 0.22.2 and cargo-deny 0.20.2, installed with `--locked`. Scheduled CI
refreshes checks weekly. Current-data failures remain failures. Build image notices
are generated from locked metadata, preserving packaged license and notice files;
the pinned toolchain standard-library copyright inventory and license texts are
included as well. Operating-system packages retain their image-provided copyright
information.
