# Dependency admission

## S3-compatible archive transport

`aws-sdk-s3 1.157.0` and `aws-sdk-sts 1.124.0` are pinned to the maintained
[AWS Rust SDK](https://github.com/awslabs/aws-sdk-rust). Both require Rust 1.94.1,
below the pinned workspace toolchain. S3 owns SigV4, conditional single-object and
multipart completion, streaming response decoding and bounded retry classification;
STS owns the standard OIDC token exchange. A handwritten signer or S3/XML protocol
implementation would duplicate security-sensitive work. A general `object_store`
abstraction was considered, but this adapter needs explicit conditional multipart
completion, ambiguous-response reconciliation and narrowly selected credential
origins rather than automatic cloud-provider configuration.

Defaults are disabled. S3 enables only `rt-tokio` and `http-1x`; STS enables only
`rt-tokio`. SigV4a, an additional HTTPS implementation, SSO, login, shell credential
processes, profile discovery and instance-metadata credential fallback are not
enabled by this integration. `aws-config` is unnecessary: an explicit
`ProvideCredentials` implementation selects mounted secret files, configured STS,
or a configured container-credential endpoint. Expiring workload credentials retain
the SDK identity-cache refresh contract. The SDK transport uses the existing
reqwest/rustls client through a destination-checked Smithy HTTP bridge; redirects
and reqwest retries are disabled, and the SDK is the single retry owner.

`aws-credential-types`, `aws-smithy-runtime-api`, and `aws-smithy-types` are direct
support dependencies because the adapter implements credential and HTTP ports.
The existing resolved `http`, `http-body`, and `http-body-util` packages become
direct dependencies for streaming that bridge without buffering whole artifacts.
Existing `percent-encoding` becomes direct for transferring SQLx's canonical
database password to libpq runtime variables without changing encoded characters
or placing credentials in subprocess arguments.
Its existing locked version 2.3.2 is MIT OR Apache-2.0, uses default `std`/`alloc`
features, and has no build script or native code. Reusing the URL stack's decoder
avoids a handwritten codec; it adds no resolved package/version or network path.
Tokio's existing `rt-multi-thread` capability also supports the private blocking
archive bridge; it introduces no new executable or network destination.

AWS/Smithy packages are Apache-2.0. Their transitive graph adds maintained protocol,
checksum, cryptographic and encoding support recorded exactly in Cargo.lock. These
features add no new native TLS backend or build-time download mechanism; existing
cryptography build scripts remain part of workspace dependency admission. Preserve
all resolved package license/notice files in generated image notices. SDK source
and build tooling never execute inspected packages. Current advisory, license and
source checks remain mandatory on the integrated locked graph; compilation and
fixture tests alone do not establish passing dependency admission.

Attribution supervision makes the existing locked `tokio-util` cancellation token a
direct application dependency with only `rt` enabled. It adds no package/version,
build script, network destination or executable capability. The existing runtime
was preferred over a second cancellation/retry implementation; source I/O stays in
adapters and request-only audit data stays outside this supervision path.

The committed Cargo.lock is the exact bootstrap graph. Rust is pinned to 1.99.1,
rmcp to 3.9.0, wtransport to 0.7.2, sqlx-core/sqlx-postgres to 0.9.0, and rustsec to 0.33.0.
Manifest semver ranges for support libraries remain bounded by the committed lock;
CI uses locked resolution. No Git dependencies or alternative registries are allowed.

| Group | Need, alternatives, and boundary implications |
| --- | --- |
| rmcp, Axum, Hyper, Tokio, tokio-util, futures | Standard MCP HTTP transport and async runtime; a hand-written HTTP stack would duplicate protocol/security work. Disable rmcp defaults and enable server/HTTP only; no client command execution. |
| wtransport, tokio-rustls, x509-parser | Custom reliable QUIC binding, TLS, exact edge SAN verification. Reuse the reference transport contract instead of inventing framing. wtransport uses ring; rustls provider is selected explicitly where required. |
| serde/json, jsonschema, TOML, URL | Typed schemas, strict configuration, source decoding, and canonical URL construction. Remote schema resolution is disabled. These parsers handle untrusted data under application limits. |
| reqwest | Bounded fixed-source HTTPS with no redirects, gzip auto-expansion, or arbitrary caller URLs. A separate retry owner avoids amplification. rustls+stream plus bounded query encoding, no default features. |
| sqlx-core, sqlx-postgres | PostgreSQL transactions and explicit bound queries; no runtime SQL from callers, no compile-time database access or macros. Memory-only storage would not meet retention requirements. |
| BLAKE3, SHA-2/SHA-1, hex, fs2 | BLAKE3 addresses and verifies service-owned durable content. SHA-2/SHA-1 retain upstream registry/Git checksums, legacy evidence verification, and stable operational lookup names. fs2 provides safe filesystem-space calls rather than adding unsafe local FFI. |
| quick-xml, tar, flate2 | Streaming official RFC metadata and bounded crate/advisory archives. Neither tar extraction nor link following is used. XML general entities and mixed text need parser tests. |
| html5ever | Streaming HTML tokenization without a DOM, scripting, network or rendering. Direct tokenization avoids CSS dependencies and checks budgets between feeds. Raw captures remain unchanged; fixtures cover entities and active content. |
| tantivy 0.27 | Embedded positional search over whole RFCs and immutable crate/version/document shards, avoiding PostgreSQL position limits and a separate daemon. Defaults disabled; enable mmap, stemmer, stopwords and LZ4 only. Trusted index paths/schemas, restricted query syntax and verified immutable manifests contain the boundary. Its indexing, compression, tokenizer and proc-macro graph receives current advisory/license/source checks. |
| base64, tokio-util | Bounded PDF encoding and managed collector/import cancellation. Existing graph packages become direct dependencies; neither enables caller-selected executables. |
| zip 9.0.0, csv-core | ZIP is needed for the official docs.rs all-target HTML bundle; disabling BZIP2/Deflate would exclude supported provider artifacts. Defaults are disabled; enable only deflate and bzip2, with no encryption/extraction. A hand-written ZIP/decompression stack would duplicate security-sensitive parsing. csv-core supplies allocation-free incremental CSV decoding rather than whole-dump deserialization; an additional strict quoting/size layer rejects malformed input before projection. |
| nix | Signal/process features terminate and reap the owned fixed Git process group on cancellation. Killing only the immediate child can leave Git helpers running; no caller-selected executable or package process is admitted. The existing locked package's `fs` feature exposes safe Linux `syncfs` for bounded offline migration batches; no new package or build script is added. |
| rustsec, semver | Maintained canonical advisory parsing and version matching rather than reimplementing affected ranges. Disable rustsec defaults, including Git, index lookup, and automatic fix support. |
| tracing/subscriber | Aggregate operational logging without request bodies or audit inputs. |

RustSec history reuses the existing external Git/mediated HTTPS boundary without
enabling RustSec crate Git or fix features. OSV import/matching uses bounded serde
JSON and semver with the primary OSV evaluation rules; RustSec's export-oriented
OSV types are not an import matcher. This module adds no dependency packages or
build scripts. Upstream representation notices remain separate from AGPL code.
The adapter's opt-in acceptance probe enables Tokio signal handling to cancel
owned Git work cleanly; the server already enables that feature in this workspace.
| rcgen | Test-only disposable certificates; not operator certificate provisioning. |

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

## MCP SDK advisory admission

`rmcp 3.9.0` is the minimum fixed release for
[RUSTSEC-2026-0462](https://github.com/RustSec/advisory-db/blob/main/crates/rmcp/RUSTSEC-2026-0462.md),
which concerns unbounded response buffering in its HTTP clients. This service
keeps defaults disabled and enables only `server` and
`transport-streamable-http-server`; the affected clients remain disabled, but
the pinned package must still pass whole-lockfile admission. Upgrading the
maintained SDK avoids an advisory exception or a transport fork. The Apache-2.0
package requires Rust 1.88, below the pinned workspace toolchain.

The upgrade retains the explicit supported protocol revisions and tools/resources
capabilities. The SDK also corrects HTTP media-type matching, honors zero Accept
weights, and rejects invalid parameter headers. Valid protocol requests retain
their existing contract; malformed media types and headers may now be rejected.
The optional Skills capability is not advertised. SDK digest support reuses the
already locked SHA-2 package without enabling client, authentication, command
execution or new outbound destinations. The existing upstream build script only
configures Git hooks when its upstream workspace directories are present; it is
inactive in the normal registry source layout. Packaged notices remain required,
and protocol/transport fixtures and current dependency admission are separate gates.

## PostgreSQL-only SQLx components

`sqlx-core` and `sqlx-postgres` are both pinned exactly to `0.9.0`. They replace
the `sqlx` umbrella without changing the compiled driver version or PostgreSQL
type identities. The umbrella retained unused SQLite, MySQL and macro packages
in Cargo.lock even with defaults disabled. Its optional SQLite driver requires
`libsqlite3-sys <0.38.0`, excluding the `>=0.39.0` fix for
[RUSTSEC-2026-0459](https://github.com/RustSec/advisory-db/blob/main/crates/libsqlite3-sys/RUSTSEC-2026-0459.md).
SQLite was absent from the active build graph, but the whole lockfile still
requires advisory admission. Removing the unused dependency path avoids an
advisory suppression or a locally maintained upstream fork; no compatible newer
stable SQLx release was available when this change was reviewed.

Upstream treats the component APIs as semver-exempt, so upgrades must keep their
exact versions aligned and review callers and feature forwarding together.
Core explicitly retains `_rt-tokio`, `_tls-rustls-ring-native-roots`, `json` and
the umbrella's implicit `migrate` feature. PostgreSQL retains `json`; defaults
are disabled for both components. The existing Tokio runtime, ring TLS provider,
native certificate roots, JSON encoding and transaction behavior remain intact.
No SQLite/native build, compile-time query macro, new network destination or
inspected-package execution is introduced.

These maintained upstream components are MIT OR Apache-2.0 and have no build
scripts of their own. Existing resolved cryptography build scripts remain;
preserve the components' packaged license/notice texts in generated inventories.
Current advisory, license and source checks must cover the resulting locked
graph, independently of compilation and PostgreSQL fixture acceptance.

## BLAKE3 storage integrity

Offline migration and frozen serving visibility use pinned `redb 4.4.0` with
defaults disabled and only `std` enabled for disposable identity/alias spill
storage. Keeping all historical
references in memory would exhaust the bounded working set on multi-million-node
corpora. A custom on-disk index would duplicate storage-engine correctness work;
per-reference PostgreSQL round trips would retain the measured migration bottleneck.
The maintained upstream package is MIT OR Apache-2.0, requires Rust 1.90, and adds
only the already resolved `libc` on Linux. Its build script declares configuration
flags; it neither downloads nor compiles external code. Version 4.4.0 includes
the upstream page-cache memory-growth fix. See the
[exact upstream source](https://github.com/cberner/redb/tree/v4.4.0).

The explicit file backend has one shared 8 MiB cache and no mmap. Scratch records
are BLAKE3-bound to their exact keys and live only in private `/tmp` storage;
every restart reconstructs them from verified retained evidence. Nonpersistent
transactions apply only to this disposable scratch. Permanent aliases, file
checkpoints and evidence keep their existing durability rules. Cache and iterator
bounds do not establish total process RSS. Existing `tempfile` becomes a direct
runtime dependency for owned scratch cleanup; its resolved version and notices
remain unchanged. Current advisory/license/source admission must cover the new
resolved graph before publication.

Serving reconstructs its private frozen alias generation from a single verified
database snapshot. Namespace views retain the existing SQL filtering semantics;
bounded cache and vector accounting is separate from SQL argument buffers and
process RSS. Corrupt or unavailable scratch fails explicitly.

Offline Linux migration uses the existing `nix 0.30.1` safe `syncfs` wrapper on
kernels at least 5.8, whose writeback-error reporting is required. Two barriers
per bounded batch first persist staged descriptor bytes, then persist published
names and links before the ownership-fenced SQL checkpoint transaction commits.
This replaces repeated individual syncs without relaxing persistence, identity,
history retention or ordinary publication. Unsupported kernels and cross-device
paths retain the existing individual durable-publication path. See the
[Linux syscall contract](https://man7.org/linux/man-pages/man2/sync.2.html).
The alternative direct `rustix` dependency would duplicate an existing safe API;
disabling synchronous writes would weaken the storage contract and is not used.

`blake3 1.8.7` is pinned with default features disabled and only `std` and `pure`
enabled. The [official implementation](https://github.com/BLAKE3-team/BLAKE3/tree/1.8.7)
provides incremental hashing and published test vectors; maintaining a separate
cryptographic implementation would add review and compatibility work. Keeping
SHA-256 as the canonical storage algorithm would not meet the selected BLAKE3
migration. Upstream-defined checksums keep their original algorithms.

`pure` selects Rust hashing implementations rather than the C/assembly hashing
backends. The packaged `build.rs` still runs and can probe C compiler flags on x86;
`cc` remains in the locked build graph. Neither the build script nor its compiler
probes execute inspected source/package contents. `rayon`, `mmap`, optional Serde,
and digest-trait integrations are disabled; hashing uses the existing bounded I/O,
worker, memory and cancellation admission. No PostgreSQL extension or database
image change is needed.

The maintained upstream package is licensed under `CC0-1.0 OR Apache-2.0 OR
Apache-2.0 WITH LLVM-exception`; preserve its packaged license texts and the notices
for its resolved support libraries in the build inventory. The adapter computes
BLAKE3 for immutable files and canonical SQL envelopes; domain contracts remain
independent of concrete storage. Current advisory/license/source admission still
requires `cargo audit` and `cargo deny check` on the resolved graph. This dependency
choice and passing hash fixtures do not establish current admission results.

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

## MDN processing dependencies

`pulldown-cmark 0.13.6` provides bounded pull-event Markdown parsing instead of
inventing a Markdown grammar or running MDN's npm build. It is MIT licensed;
default features are disabled, including executable/HTML-generation/SIMD extras.
Its packaged build script is inactive without the generation-test feature.
The minimum version is 0.13.6 to address
[RUSTSEC-2026-0433](https://github.com/RustSec/advisory-db/blob/main/crates/pulldown-cmark/RUSTSEC-2026-0433.md),
which fixes quadratic parsing of nested image wikilinks. Current MDN, Chromium,
and shared standards parsers leave `ENABLE_WIKILINKS` disabled; the patch retains
their existing Markdown options and projection contracts. The maintained upstream
[0.13.6 patch](https://github.com/pulldown-cmark/pulldown-cmark/compare/v0.13.5...v0.13.6)
changes wikilink handling without adding dependency requirements or build features.
Upgrading the existing parser avoids a replacement parser or an advisory exception.
`yaml-rust2 0.13.0` provides the YAML event interface needed to reject aliases,
duplicate keys, excess nesting and oversized front matter before constructing a
bounded JSON projection. It is MIT OR Apache-2.0, has no build script, and defaults
are disabled (including encoding detection). This avoids the deprecated
serde_yaml implementation and a bespoke YAML parser. Both parse untrusted retained
source only; neither performs network or filesystem access in the projection path.

The locked additions include arraydeque 0.5.1, hashlink 0.12.2 and unicase 2.10.0;
original permissive notices remain in the generated notice inventory. Direct
`sha1 0.11.0` was already resolved in the graph and verifies Git's native object
identity on every raw read; service-owned archive/projection addressing uses BLAKE3.
No Git dependencies, upstream build tools or source-selected executables are added.
Current cargo-audit and cargo-deny admission remains mandatory and separate from
compilation and provider acceptance.

## WHATWG PDF processing dependencies

`lopdf 0.46.0` is pinned with default features disabled. It parses retained PDF
objects and extracts inert page text without a PDF viewer, JavaScript, external
assets, or executing specification/package build tools. Existing HTML tokenization
cannot decode PDF content streams; shelling out to an independently provisioned PDF
renderer would add a larger executable and operating-system dependency boundary.
The maintained MIT-licensed crate and its resolved transitive notices are included
in dependency admission and image notice generation. Optional parallel, image,
date-time integration, and async features are disabled. Its resolved parser,
encoding, compression and cryptography graph still requires current advisory,
license and source checks; compilation alone is not admission.

The new locked graph includes `encoding_rs 0.8.42` (permissive
Apache-2.0/MIT plus BSD-3-Clause notices), `nom 8.0.0`, `rangemap 1.8.0`,
`weezl 0.2.1`, Brotli decompression and the crate's required PDF cryptography
support. `lopdf` has no build script. `encoding_rs` has a compiler-version
configuration build script; `multiversion_no_op` is a compile-time proc macro.
These execute only as trusted build dependencies, never against inspected source.

PDF parsing occurs exclusively in the fixed first-party `devres-pdf-worker`
sibling executable. Input and output are bounded, credentials/environment are
cleared, standard error is suppressed, and the parent cancels/kills/reaps it under
a 60-second deadline. Existing `nix` gains only the `resource` feature to set a
1-GiB address-space limit, CPU limit and zero core size before reading untrusted
bytes. Per-page decompression and overall page/text counts are bounded. Failed,
encrypted, malformed and image-only decoding remain explicit projection gaps;
original public PDF captures stay readable independently.


## Credential broker and private coordination

The broker makes the already resolved `ring 0.17.14` a direct adapter dependency
for AES-256-GCM, authenticated associated data, and operating-system randomness.
Its resolved package manifest declares Apache-2.0 AND ISC. The existing ring
native build script/toolchain was already admitted through transport cryptography;
this change adds no version, new download mechanism, or inspected-package execution.
A maintained AEAD implementation is preferable to handwritten encryption; a separate
crypto stack would duplicate primitives already present in the graph. Persistent
ciphertexts are private broker state, never corpus evidence.

The existing reqwest dependency adds `query` solely for fixed Scaleway IAM listing
parameters. Defaults and automatic redirects remain disabled, and callers cannot
choose IAM endpoints in production. The new executable reuses existing axum,
hyper/hyper-util, tokio-rustls, SQLx, serde and Tokio versions/features for bounded
private HTTPS and a dedicated journal. These dependencies introduce Kubernetes
TokenReview/live identity and Scaleway IAM destinations only through operator
configuration; they do not extend public request URL authority. Dependency versions
remain locked. Advisory, license, source and generated notice checks still apply to
the integrated graph; successful compilation is not current dependency admission.
