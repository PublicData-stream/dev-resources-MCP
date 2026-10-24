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
| html5ever | Streaming HTML tokenization without a DOM, scripting, network or rendering. Direct tokenization avoids CSS dependencies and checks budgets between feeds. Raw captures remain unchanged; fixtures cover entities and active content. |
| tantivy 0.27 | Embedded positional search over whole RFCs and immutable crate/version/document shards, avoiding PostgreSQL position limits and a separate daemon. Defaults disabled; enable mmap, stemmer, stopwords and LZ4 only. Trusted index paths/schemas, restricted query syntax and verified immutable manifests contain the boundary. Its indexing, compression, tokenizer and proc-macro graph receives current advisory/license/source checks. |
| base64, tokio-util | Bounded PDF encoding and managed collector/import cancellation. Existing graph packages become direct dependencies; neither enables caller-selected executables. |
| zip 9.0.0, csv-core | ZIP is needed for the official docs.rs all-target HTML bundle; disabling BZIP2/Deflate would exclude supported provider artifacts. Defaults are disabled; enable only deflate and bzip2, with no encryption/extraction. A hand-written ZIP/decompression stack would duplicate security-sensitive parsing. csv-core supplies allocation-free incremental CSV decoding rather than whole-dump deserialization; an additional strict quoting/size layer rejects malformed input before projection. |
| nix | Signal/process features terminate and reap the owned fixed Git process group on cancellation. Killing only the immediate child can leave Git helpers running; no caller-selected executable or package process is admitted. |
| rustsec, semver | Maintained canonical advisory parsing and version matching rather than reimplementing affected ranges. Disable rustsec defaults, including Git, index lookup, and automatic fix support. |
| tracing/subscriber | Aggregate operational logging without request bodies or audit inputs. |

RustSec history reuses the existing external Git/mediated HTTPS boundary without
enabling RustSec crate Git or fix features. OSV import/matching uses bounded serde
JSON and semver with the primary OSV evaluation rules; RustSec's export-oriented
OSV types are not an import matcher. This module adds no dependency packages or
build scripts. Upstream representation notices remain separate from AGPL code.
The adapter's opt-in acceptance probe enables Tokio signal handling to cancel
owned Git work cleanly; the server already enables that feature in this workspace.
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

## Crate corpus dependency boundary

ZIP is pinned to 9.0.0; earlier 8.x candidates failed current advisory admission and
are not suppressed. The selected deflate feature resolves zlib-rs/zopfli; BZIP2
uses bzip2 0.6.1 and its Rust libbz2-rs-sys 0.2.5 backend. These parsers inspect
bounded inert artifacts, including CRCs and central-directory/member identities,
without extracting paths or enabling encrypted archive support. zip is MIT;
csv-core is Unlicense/MIT, bzip2 is MIT/Apache-2.0, and original transitive notices
remain in the build notice inventory. None executes inspected package code.

`deny.toml` contains an exact `libbz2-rs-sys@0.2.5` exception for `bzip2-1.0.6`.
The actual permissive license text requires preserving copyright/source attribution
and its endorsement restrictions. The exception owner is repository maintainers,
reviewed again by 2027-01-24 or on graph changes. It is not a global new license
allowance or an advisory suppression. Current cargo-audit/cargo-deny results must
still be reported separately from compilation and fixture acceptance.

Server images additionally need the fixed Git executable for private index object
processing. Child configuration excludes user/system Git configuration, hooks,
credential helpers and arbitrary remotes; no worktree or package build is created.
Operating-system Git and its notices remain separately licensed image contents.
