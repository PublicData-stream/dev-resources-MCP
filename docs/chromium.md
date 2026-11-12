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
Gitiles can omit the timezone from its five-token committer display when the server
uses a configured fixed zone. That display is never interpreted as UTC. For `src`
and `site`, collection obtains one additional selected commit with `format=TEXT`,
capped at 1 MiB encoded. It verifies the exact Git commit object ID, tree and ordered
parents against JSON and reads exactly one raw committer epoch. Only that verified
epoch and bounded proof metadata are retained; raw commit bytes, author/committer
names, emails and messages are discarded. Explicit-offset six-token dates and UTC ISO dates retain
their existing path. The extra proof uses the same host, rate and retry owner;
unavailable, oversized or invalid proof preserves the previous published default.

Markdown, HTML, plain text, and supported documentation syntax are inert projections.
Sections preserve anchors, code examples remain text, and symbols require explicit
documented declarations. Unsupported directives and formats remain coverage gaps
with qualified original evidence. Repository-relative links resolve only within
captured snapshot membership. Includes require bounded same-snapshot dependencies.

## Research and publication

Traversal accounting includes both admitted documents and explicitly retained
unsupported-entry obligations. Before publication, their immutable gap manifests
and counts must verify. `accounted` therefore does not imply complete acquisition:
`complete` remains false when traversal or projection gaps exist. A partial default
can expose qualified documents alongside this coverage; an unresolved governing
notice still withholds every affected body.

The dedicated tool family provides document catalog/search/get, explicit symbols,
references, snapshots, history, comparisons, and aggregate corpus status. Generic
`search` includes `chromium` among all nine default source families; an explicit
source list narrows the search to the selected families.
Generic `fetch` accepts `chromium:<component>/<path>#<anchor>`. Tool discovery owns
the exact strict input schemas.

Published views may be partial. Results identify missing, failed, stale, unsupported,
or license-blocked evidence. A failed refresh preserves previously published evidence.
Archived Chrome content never silently replaces current website content. Historical
snapshots, resource URIs, and cursors retain their original selection after refresh
or processor upgrades. Comparisons describe observations, not API compatibility.

Public research performs local reads. Obsolete attribution may queue the supervised
exact-evidence repair described in [the specification](Specification.md); it does
not enroll new corpus sources or change historical selections. List pages
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

Rejected parser observations retain private versioned diagnostics with closed
component/lane/operation/reason identifiers, response time, byte count and BLAKE3
digest. Selected, claimed and computed Git object IDs are included where available.
Rejected bodies, upstream text and URLs are not copied into these records or public
status. Immutable failure observations and their latest private pointers survive
restart; retained-graph verification checks their schema, integrity and references.
HTTP failures remain acquisition failures and retain the existing retry policy.

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

`chromium-live-probe --diagnose-validation OWNED_ROOT` diagnoses only current
`src` and `site` ref, selected commit and root-tree validation, with at most six
attempts per invocation and a persisted total budget of twenty across the same root.
Broker retries count against both limits. It retains only closed diagnostic metadata,
validated selected object IDs and body digests; it does not retain response bodies or
collect documents. `--diagnose-commit-date` fetches only refs and selected commits,
with at most four attempts per invocation under the same twenty-attempt ledger.
That private mode retains only a bounded ASCII date scalar/shape alongside its
validated commit ID and body digest; CLI output omits the scalar. Diagnostic receipts
remain immutable across invocations. Normal live
acceptance also validates selected `src`/`site` commit metadata before trees.
Use `--diagnose-validation OWNED_ROOT --component src` or `--component site` to
verify each component separately: refs, JSON commit, an ambiguous-date raw proof
when needed, then the root tree. All attempts, including retries and raw proofs,
share the root's persisted twenty-attempt limit.

All temporary acceptance state belongs below `/tmp`. Retained public acceptance
evidence has a separate owner marker and survives cleanup; disposable fixture state
must never be used as the permanent source archive. Shared-cache Cargo commands use
the privileged channel and `CARGO_TARGET_DIR=/buildcache/rust/target`, applied after
the temporary-state wrapper. See [Operations](operations.md) for the isolated Docker
and minikube workflow.
