# Chromium implementation validation

Observed on 2026-10-27. This records local implementation acceptance, separately
from full retained corpus completion, hosted CI, publication, and production use.

## Local checks

| Check | Result |
| --- | --- |
| Rust 1.99.1 workspace/all-target compilation | Passed |
| Workspace formatting and strict all-target Clippy | Passed |
| Locked workspace tests with `RUST_TEST_THREADS=2` | Passed |
| Final Chromium source/parser/collector/research tests | 30 passed |
| Chromium live/retained example helper tests | 6 passed |
| Python harness tests | 133 passed |
| Current `cargo audit` | Passed; 476 resolved dependencies scanned |
| `cargo deny check` | Advisories, bans, licenses, and sources passed; existing duplicate-version warnings remain |
| PostgreSQL persistence | Passed, including schema 7→8, older-provider preservation, immutable batch rollback, ownership loss, and restart |
| Pinned OxiBelt Docker acceptance | HTTP/WebTransport checks passed for both MCP revisions |
| Disposable minikube acceptance | NodePort TCP/UDP, CNI isolation, private health, PVC restart, and coordinated restore passed |
| Linux amd64 runtime image | Build, startup, and audit-worker fixture smoke passed |

The initial unconstrained workspace run exceeded existing RustSec fixture deadlines;
the same assertions passed with two test threads. Python wrapper tests also exceeded
their unchanged ten-second deadlines during heavy container I/O and passed on the
subsequent run after pressure subsided. Intermediate collector compilation errors
were corrected before the successful cluster/image runs. No assertions, security
policies, or parser limits were weakened to obtain a pass.

The final collector tests additionally exercise deleted documentation, immutable
historical resources, same-revision revalidation after rebuild, interrupted index
marker publication, and recovery when both retained and pending derived indexes are
corrupt. Rebuild preserves raw evidence and old snapshot IDs and makes no requests.

Shared-cache Cargo commands used `/buildcache/rust/target`. All fixture, Docker,
minikube, and test-generated state used owned directories below `/tmp`. The isolated
daemon used a task-owned ext4 image below `/tmp` because the host temporary filesystem
is virtiofs. Configured operator daemons and cluster profiles were not reused.
The runtime image used the tracked Dockerfile with only its build-target path changed
from `/tmp/rust/target` to `/buildcache/rust/target`; runtime instructions were unchanged.

## Bounded provider evidence

`scripts/live-smoke.sh --live --chromium` completed all four fixed components with
15 total attempts, including the shared retry budget; the ceiling was 20 total.

| Component | Named retained record | Observed revision or source |
| --- | --- | --- |
| `src` | `docs/README.md` and versioned `LICENSE` | `a450081a7b0bf262184a197f58f55a330a9851ed` |
| `site` | `site/Home/index.md` and the observed Home-page notice | `47ee94275c3b0ad9a38c6724bd11eefba4b616ba` |
| `chrome` | DevTools overview HTML and its page notice | `https://developer.chrome.com/docs/devtools/overview?hl=en` |
| `chrome-archive` | `README.md` and versioned `LICENSE` | `51dd7dd5d510ed85d86f5a91cb8fde50b62351c7` |

The original `live-receipt.json` SHA-256 is
`5bd34ccae587e41e4687a3ca3d9904b6752e497eec8808edd0d3588d0adb2028`.
An offline `--replay` rechecked retained hashes, sizes, Git blob IDs, final production
license qualification, and projection for every record. It consumed zero attempts
and preserved the original receipt and count of 15. Its linked `live-replay-v1.json`
SHA-256 is `66f53b8004c7892de2275c2644970f6e110269e1462ef11f8c55626f4671ee9b`.
Public bodies and notices remain in their separately marked retained `/tmp` root;
they are not disposable fixtures or first-party AGPL source files.

Replay identified the real `devsite-content-footer` and Chromium `sidebar-license`
notice regions. Production qualification recognizes these regions while excluding
script, preformatted, and article-code lookalikes. It preserves the actual notice
and separate prose/code terms. A current Home-page notice qualifies that selected
page; it does not establish every historical website revision's terms.

These records have explicit projection diagnostics, including generated/unasserted
anchors, unresolved constructs, and duplicate identifiers. Successful named-record
acquisition does not imply zero processing gaps or complete API extraction.

## Review and remaining proof boundaries

Independent MCP/API, Upstream/Storage, and Security Boundary reviews inspected the
integrated implementation and affected callers. Reported issues were repaired and
reviewers closed their inspected scopes. This is agent review, not human GitHub
approval. Codex Security cloud access checking was not performed.

The resumable frozen-corpus runner is implemented and its ownership/retention
guards are tested. A real full-source current inventory or ancestry backfill was
not executed as part of this acceptance. Unexposed post-migration Chrome website
revisions remain unavailable. Gitiles commit metadata is HTTPS-observed evidence,
not a verified raw Git commit object.

No hosted workflow, ARM64 CI, registry publication, native ChatGPT UI, production
activation, or production capacity claim follows from these local results.
