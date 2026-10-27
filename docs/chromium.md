# Chromium acquisition and research

Chromium research separates four source components:

| Component | Evidence | Default membership |
| --- | --- | --- |
| `src` | Documentation in the official `chromium/src` repository, including Blink and components | Current main documentation |
| `site` | English pages from the official Chromium website source repository | Current site sources |
| `chrome` | English editorial HTML from developer.chrome.com | Latest successfully captured pages |
| `chrome-archive` | Public history of GoogleChrome/developer.chrome.com | Explicit historical selection |

Source repositories and published websites are separate representations. A matching
URL is a relationship, not proof that a website capture came from a particular Git
revision. The archived Chrome repository stopped accepting updates after its 2023
platform migration; the module cannot reconstruct unexposed post-migration revisions.
Missing history remains an explicit coverage gap.

## Acquisition and processing

Chromium source and website discovery use fixed Gitiles endpoints. The archived
Chrome source uses fixed GitHub Git API endpoints, retaining selected documents
rather than a complete repository pack. Current Chrome publications are discovered
from same-host sitemaps and qualified editorial paths. Ordinary links never expand
the set of permitted repositories or hosts. External examples, assets, DEPS,
submodules, hooks, builds, and website generators are never executed or traversed.

Repository-wide Markdown and README-family documents are candidates. Other prose
formats require a documentation namespace or qualified mapping. Test-data,
generated, and vendored content is excluded unless qualified as documentation.
The versioned classifier is part of derived inventory identity.

Current collection precedes resumable ancestry processing. Frozen observations cover
exposed branch, tag, and Chromium release-head refs, excluding review/internal refs.
History follows ordered commit parents, retaining previously observed roots. Every
historical tree participates in discovery, including paths absent from current
trees. Bodies, tree inventories, and unchanged projections are shared by identity.
There is no promise to recover already-unreachable objects or a completion deadline.

Gitiles metadata is retained HTTPS evidence. Decoded Git blobs are checked against
their object IDs; complete representable trees can also be hash-verified. JSON commit
metadata does not establish cryptographic verification of the original commit object.

Markdown, HTML, plain text, and supported documentation syntax are inert projections.
Sections preserve anchors, code examples remain text, and symbols require explicit
documented declarations. Unsupported directives and formats remain coverage gaps
with qualified original evidence. Repository-relative links resolve only within
captured snapshot membership. Includes require bounded same-snapshot dependencies.

## Research and publication

The dedicated tool family provides document catalog/search/get, explicit symbols,
references, snapshots, history, comparisons, and aggregate corpus status. Generic
`search` accepts explicit source `chromium`; omitted sources remain RFC and Cargo.
Generic `fetch` accepts `chromium:<component>/<path>#<anchor>`. Tool discovery owns
the exact strict input schemas.

Published views may be partial. Results identify missing, failed, stale, unsupported,
or license-blocked evidence. A failed refresh preserves previously published evidence.
Archived Chrome content never silently replaces current website content. Historical
snapshots, resource URIs, and cursors retain their original selection after refresh
or processor upgrades. Comparisons describe observations, not API compatibility.

Public research performs local reads and does not launch source requests. List pages
default to 20 and cap at 100; offset paging stops at 10,000 with cursor continuation.
Text and decoded byte pages cap at 32 KiB. Text offsets count UTF-8 bytes. Technical
AND search and English query modes use snapshot-selected BM25 statistics.

Preserve per-revision/page notices and code/prose distinctions. Chromium source,
Chromium website, archived Chrome content, and current Chrome publications do not
share one organization-wide license. Missing license qualification is metadata-only:
no permanent body, excerpt, comparison, symbol, or public capture is admitted.
Source content remains separately licensed from first-party AGPL code.

## Operation and acceptance

Omitting `[chromium]` enables collection. `enabled=false` pauses acquisition without
deleting evidence or disabling historical research. Ref/catalog validation targets
one hour, moving publications one day. Current evidence is stale after 24 hours and
unavailable by default after seven days; explicit history remains readable. Restoring
or reprocessing evidence never changes its upstream validation time.

One shared family attempt per second and one transfer coordinate with destination
host admission and the existing single retry owner. Quota and free-space failures
pause work without deleting archives. Metadata responses, sitemap discovery, parser
work, queues, and write groups are independently bounded.

Schema 8 is forward-only. Coordinated backups include Chromium raw artifacts,
immutable evidence, inventories, projections, checkpoints, and search indexes.
`rebuild-chromium-index CONFIG.toml` rebuilds derived state from retained evidence.

Ordinary acceptance uses synthetic fixtures. The opt-in bounded command
`scripts/live-smoke.sh --live --chromium` tests fixed official records, with at most
20 attempts per provider including retries. `chromium-live-probe --replay OWNED_ROOT`
rechecks retained hashes, source object IDs, production license qualification, and
projection without network requests, preserving the original receipt and attempt count.
It is separate from the retained frozen
corpus runner `scripts/accept-chromium.sh`, which accounts for source obligations
and supports resumption. Neither demonstrates production deployment, hosted native
ARM64 execution, or native ChatGPT UI behavior.

All temporary acceptance state belongs below `/tmp`. Retained public acceptance
evidence has a separate owner marker and survives cleanup; disposable fixture state
must never be used as the permanent source archive. Shared-cache Cargo commands use
the privileged channel and `CARGO_TARGET_DIR=/buildcache/rust/target`, applied after
the temporary-state wrapper. See [Operations](operations.md) for the isolated Docker
and minikube workflow.
