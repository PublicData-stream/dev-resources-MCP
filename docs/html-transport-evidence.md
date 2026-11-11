# HTML transport implementation evidence

## Implementation boundary

Implementation commit: `11c5213` (parent `79b55cb`). Acceptance used the same
implementation before committing. It replaces qualified W3C publication/TR-index,
Chromium Page/SitePage and RFC HTML acquisition (including exact attribution
repair) with a direct wreq adapter inspired by Obscura. It does not import or run
Obscura, JavaScript, a renderer or a browser server. The application User-Agent,
request negotiation, immutable captures, license policy and public configuration
and MCP schemas are preserved. Transport retries are explicitly disabled for
both transports; existing admission and retry ownership remain authoritative.

See [dependency admission](dependencies.md#html-acquisition-transport) and
[comparison operation](operations.md#bounded-html-transport-comparison).

## Fixed-record source comparison on 2026-11-11

One exclusive comparison root charged **12 total HTTP attempts**, including the
two W3C metadata requests and both transports. Its persisted ceiling was 20 across
all providers combined; restart does not renew the allowance. Every response was
HTTP 200. No original response body was persisted or published by this probe.

| Fixed record | Existing reqwest | New wreq | Additional evidence |
| --- | --- | --- | --- |
| W3C TR index | 1,087,525 bytes | 1,087,525 bytes | Same body hash; catalog validation not exercised |
| CSS Color 4, CRD 2026-11-03 | 1,056,087 bytes | 1,056,087 bytes | Same body hash; license approved; 149 projected sections |
| Chrome DevTools overview | 180,484 bytes | 180,488 bytes | Both project 19 sections; license qualification not exercised |
| Chromium site Home | 11,657 bytes | 11,657 bytes | Same body hash; 9 projected sections; license qualification not exercised |
| RFC 9000 HTML attribution source | 750,350 bytes | 750,350 bytes | Same body hash; RFC production validation/publication not exercised |

Official W3C metadata selected
`https://www.w3.org/TR/2026/CRD-css-color-4-20261103/`; the comparison freezes this
edition for resumed runs. Receipts retain validated public URLs, observation
times, status, byte counts, body hashes and separate processing outcomes.
The four-byte Chrome response difference was observed, not attributed to a
particular cause. Raw-byte parity is established by deterministic fixtures, not
by assuming a moving live response must be identical.

The final `comparison.json` SHA-256 is
`b3f5f511174cba41ba285b5215ace86de949c05cbe0025daf1bb6efb9a94d16c`.
This run did **not reproduce the prior collection errors in either transport**.
It therefore does not establish that fingerprinting fixes the production failures,
complete source coverage, durable live publication or provider-wide readiness.
New fixed-field stage diagnostics support a later reproduction without logging
source bodies, underlying errors, URLs, credentials or supplied audit inputs.

## Local verification

- Formatting, all-target clippy with warnings denied, and `git diff --check` passed.
- Workspace executable tests: **861 passed, 66 ignored**. The original
  `cargo test --workspace --locked` invocation then failed in rustdoc with E0463
  dependency-loading errors while other builds used the same target directory.
  After those builds finished, `cargo test --workspace --doc --locked` passed
  serially without source changes. The initial failed invocation remains recorded;
  it is not relabeled as a clean complete workspace run.
- The separate HTML comparison example tests passed **3/3**, including retained
  attempt accounting, root ownership and symlink rejection. Transport and broker
  regression tests are included in the workspace result above.
- `scripts/test-postgres.sh`: **49 passed in 25 groups**, including ownership,
  migration/resume, immutable evidence and reader/storage boundaries.
- `scripts/test-oxibelt.sh`: the pinned edge passed HTTP/WebTransport, both protocol
  revisions, private routing and restart scenarios in the owned Docker fixture.
- `scripts/test-minikube.sh`: actual NodePort TCP/UDP, CNI isolation, PVC restart
  and coordinated PostgreSQL/blob restore passed in a newly owned profile. CNI
  timeout outputs are expected negative controls; the suite reached its final
  success marker and cleaned up the profile.

Cargo ran through the privileged channel with target `/tmp/rust/target`; test caches,
roots, logs, Docker data and minikube state were confined to `/tmp`. The native
local platform was Linux amd64. Existing Docker contexts and operator profiles
were not reused or changed.

Current `cargo audit` and `cargo deny check` passed without new exceptions.
Packaged notices were generated for 520 external locked packages, including
`btls-sys`'s bundled BoringSSL license and nested notices. Native build prerequisites
were added to the image and CI source; a hosted release image is a separate claim.

Python discovery ran **794 tests: 6 failures, 9 errors, 4 skips**. All 15 failures
are in the unchanged staging upgrade suite. The exact pre-change HEAD extracted
under `/tmp` reproduced the same 6 failures and 9 errors in that module's 82 tests.
The frozen runtime renderer tests now isolate their library-admission precondition
and separately prove the real Git guard rejects changed tracked source before
creating a candidate. Its five tests pass; the production guard/revision is unchanged.
The Python suite remains a failing baseline gate, not a reported pass.

Independent MCP/API, Upstream/Storage and Security Boundary source reviews closed
with no unresolved findings after explicit no-retry and receipt-provenance fixes.
Agent review is not human GitHub approval. Hosted native amd64/arm64 execution,
production deployment, native ChatGPT UI and the earlier initial storage-startup
failure are outside this evidence. No push, registry publication or production
state change was performed.
