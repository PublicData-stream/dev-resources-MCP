# Service specification

## Capability and status

This service is anonymous and read-only with respect to caller data and upstream
systems. Reads may populate internal public-source caches and permanent archives.
It supports RFC metadata/text, crates.io metadata/published sources, local package
and API research from crates.io/docs.rs captures, MDN content/browser compatibility,
RustSec advisories, WHATWG standards, and supplied
Cargo.lock matching. No public administrative operations,
package execution, dependency resolution, arbitrary URL fetching, or user accounts
are exposed. Missing or unsupported coverage is explicit.

## MCP and transport

Streamable HTTP uses `/mcp`. WebTransport `/mcp-wt/v1` is a custom binding: one
client-opened reliable bidirectional stream, UTF-8 JSON-RPC separated by LF, with
CRLF accepted. Additional application streams and datagrams are rejected. The qualified HTTP/3
edge binding uses Draft02: clients send `sec-webtransport-http3-draft02: 1`, and the
backend accepts with `sec-webtransport-http3-draft: draft02`. The native probe emits
the request marker. These compatibility markers do not change the MCP revision. Both
transports share one tool registry, application services, limits, and cancellation.

Supported MCP revisions are `2026-07-28` and `2025-11-25`. Modern requests use
`server/discover` and per-request metadata. Legacy clients use stateless HTTP
initialization or a connection-initialized WebTransport stream. An initialize
proposal negotiates the legacy revision rather than implying support for the
proposed revision. HTTP metadata/body mismatches fail; WebTransport mixed-era
traffic closes the connection. The path selects the binding version, not MCP era.
No older HTTP+SSE listener, persistent event store, or automatic request replay exists.

Origin is optional for native clients; present origins and authority must satisfy
explicit allowlists. Backend mTLS authenticates OxiBelt, not an individual caller.
Health/metrics are private. Required listener failure stops readiness and triggers
drain; SIGINT/SIGTERM stop admission and perform bounded shutdown.

## Tools

| Tool | Inputs and result |
| --- | --- |
| `server_info` | Identity, supported revisions, licensing and corresponding-source URL |
| `search` | Query, selected `rfc`/`cargo`/`rustsec`/`mdn`/`whatwg` sources, offset/limit; source-specific results/errors; omitted sources remain RFC and Cargo |
| `fetch` | `rfc:<number>`, `crate:<name>@<version>`, `mdn:<slug>`, `mdn-compat:<feature>`, `whatwg:<standard>#<anchor>`, or immutable `devres://` resource URI |
| `rfc_search` | Query and optional status; official index metadata with capture-based paging |
| `rfc_get` | RFC number and byte page; published text |
| `rfc_metadata` | RFC number, optional research snapshot; rich official metadata |
| `rfc_catalog_search` | Metadata query, conjunctive filters and snapshot-based paging |
| `rfc_fulltext_search` | Technical AND tokens or English phrases/OR/exclusions; filters, assurance and pinned snapshot |
| `rfc_format_get` | RFC number, txt/html/xml/pdf, optional capture; source text or base64 PDF byte page |
| `rfc_errata` | RFC number, optional status/type and snapshot; original errata records |
| `rfc_series_get` | STD/BCP/FYI number and snapshot; constituent RFC metadata |
| `rfc_corpus_status` | Aggregate collection, freshness, failures and snapshot coverage; no administrative controls |
| `crate_search` | Query and page; bounded upstream crate search |
| `crate_metadata` | Exact crate name/version; dependency declarations, features, yanked state, checksum |
| `crate_source_list` | Exact crate version; verified source file listing |
| `crate_source_read` | Exact crate version and archive-relative file path; UTF-8 text page |
| `crate_versions` | Captured exact versions for a crate in semantic-version order; snapshot paging |
| `crate_catalog_search` | Local version metadata and conjunctive license/keyword/category/MSRV/yanked filters |
| `crate_document_get` | Exact captured source, manifest, README, license or rustdoc text; bounded byte page |
| `crate_dependencies` | Forward declarations or reverse package-name references; no constraint solving |
| `crate_compare` | Metadata/dependency changes, qualified text/API release changes, or an exact public path |
| `crate_content_search` | Local source and documentation search with snapshot-wide BM25 |
| `crate_api_search` | Observed rustdoc API items across captured versions and targets |
| `crate_api_get` | Exact public path, normalized signature, relationships and capture provenance |
| `crate_corpus_status` | Aggregate acquisition, processing, storage and snapshot coverage; no public controls |
| `advisory_lookup` | Crate/version; matched advisories, withdrawals and informational state |
| `audit_lockfile` | Supplied Cargo.lock text; supported matches, unassessed entries, completeness/freshness |
| `advisory_get` | Canonical advisory ID, representation and optional snapshot; structured metadata and original source byte page |
| `advisory_catalog_search` | Local query, conjunctive metadata/platform filters, representation and snapshot/cursor paging |
| `advisory_history` | Canonical ID, optional exact Git ref and frozen history view; parent-relative changes |
| `advisory_snapshots` | Paginated immutable ref observations or commit snapshots; optional exact ref/representation |
| `advisory_corpus_status` | Aggregate collection, freshness, parsing, storage and history coverage; no administrative controls |
| `mdn_search` | Local English document search, conjunctive metadata filters, technical/English query mode and pinned cursor |
| `mdn_get` | Exactly one slug or repository path; projected text, original source or bytes, optional immutable snapshot and explicit compatibility snapshot |
| `mdn_compat_search` | Local compatibility feature search with browser/status filters and pinned cursor |
| `mdn_compat_get` | Exact BCD feature, original and derived support evidence; bounded browser-statement page |
| `mdn_browser_get` | Captured browser metadata and paged releases/engine mappings |
| `mdn_history` | Parent-relative changes for exactly one path, slug or feature; frozen publication cutoff and cursor |
| `mdn_snapshots` | Commit snapshots or advertised ref observations for content/compat; optional exact ref filter for observations |
| `mdn_corpus_status` | Aggregate acquisition, history, projection, index, freshness and failure state; no administrative controls |

Tool discovery supplies authoritative JSON input schemas. Unknown fields fail.
Retrieval and validation timestamps are Unix seconds.
List pages default to 20 entries and cap at 100. Text pages cap at 32 KiB and count
UTF-8 bytes; offsets must be character boundaries. Reuse returned capture IDs for
stable pagination. Search sources have separate ranking/paging, not one global rank.
Direct dependencies are declarations, not a solved transitive graph.

RFC research filters combine with AND: status, author substring, keyword substring,
stream, area, working group, series membership and inclusive `YYYY-MM` publication
bounds. Missing publication precision cannot satisfy a date bound. RFC query and
filter strings cap at 256 Unicode characters. Generic `search` remains metadata-only.

Full-text defaults to lowercase technical tokens with document-level AND. English
mode adds stemming and stopwords and accepts quoted phrases, `OR`, and minus
exclusions. Field/range/regex/wildcard syntax is unsupported. Reuse the returned
snapshot for stable pages; ranking is score descending then RFC number ascending.
TXT supplies searchable text, with inert XML/HTML fallback; PDF text extraction is
unsupported. Coverage identifies missing or unextractable documents.

Collection starts automatically while serving and is resumable. Serving remains
ready during bootstrap; research exposes immutable partial snapshots. Once a complete
snapshot exists, it remains the default until a newer complete one is published;
status exposes newer partial IDs for explicit selection. Snapshot completeness
describes coverage at publication. An expired default snapshot is unavailable;
explicit historical snapshots remain readable. Rsync evidence has separate provenance
and lower assurance. Research prefers HTTPS and labels rsync fallback; legacy RFC
tools exclusively use HTTPS.

`devres://rfc/<number>/<format>/<capture>` provides typed format resources with
optional offset/limit. PDF pages contain base64-encoded bytes; other formats are
inert source text. Decoded PDF pages cap at 32 KiB. Generic capture resources reject
PDF and archive binaries even if their bytes happen to be valid UTF-8.

`devres://capture/<id>` reads public capture text. `devres://source/...` identifies
verified source content pinned to both metadata and archive captures. Binary
captures require typed tools. Resource reads are bounded; citations never identify
submitted lockfiles or audit reports. Source text remains untrusted content.

## Crate corpus and research

The legacy crate tools retain their request-driven search, sparse-index and
checksum-verified source behavior. Dedicated research tools use captured local
snapshots and do not initiate provider traffic. Collection automatically enumerates
the official Git index, acquires exact archives, imports public database-dump
metadata, and requests docs.rs documentation for every observed version and published
target. Hourly index synchronization and daily metadata/documentation refreshes are
scheduling targets. Missing builds, absent JSON, processing limits and provider
failures remain explicit coverage gaps; collection does not fabricate missing data.

Retained public evidence is permanent, including oversized archives retained
without source inspection. Raw retention, checksum agreement, successful parsing,
search indexing and full-provider coverage are distinct states.
`processing_cumulative` counts retained published processing generations, including
historical representations; it is not a current-version completion percentage. Only observed
representations can be retained; older removed releases or docs.rs builds cannot be
reconstructed. The latest successfully published research snapshot is the default;
its metadata inventory, enrichment and content cutoff are frozen with its index.
Explicit historical snapshots remain fixed evidence. Defaults whose inventory has
not been validated within seven days are unavailable;
historical selection does not imply current freshness.

Research defaults to all captured versions. List pages default to 20 and cap at 100;
text pages cap at 32 KiB. Reuse the returned snapshot and cursor for stable continuation. Search cursors bind
the exact snapshot and query/filters, allow a changed page size, and continue beyond
the bounded 10,000-offset window without silently truncating results.
Ranking is global BM25 over the selected snapshot, then crate name ascending,
semantic version descending, target, path and stable identity. Technical queries use
AND tokens; English queries support phrases, OR and exclusions. Filters combine
with AND; MSRV selects declared minimum versions at or below the requested version,
not build-tested compatibility. Dependency results contain declarations, not a
resolved graph. An omitted target is accepted only when the selected document/API
path is unambiguous.

Documentation is inert text. No HTML scripts/assets, package build steps, repository
links or rustdoc commands are executed. Structured API projections support rustdoc
JSON formats 43, 55, 56 and 61; unsupported formats remain retained raw evidence with an
explicit processing gap. Missing version/target fields in older schemas are reported
as unasserted. Public paths and signatures retain capture-local ID provenance;
IDs from different builds are not stable identities. API comparisons require
qualified per-side projection coverage and compatible schema versions. Changes are
observations, not semantic-version or security certifications.

## Audits and failure

RustSec collection runs independently of public requests: current main metadata and
immutable archives refresh hourly, and full official Git branch/tag ancestry
synchronizes daily. These are scheduling targets. All advisory tools read published
local evidence; bootstrap can therefore return unavailable/incomplete results while
serving remains ready. Failed current processing preserves the last published default.

The default representation is canonical RustSec Markdown/TOML. Explicit OSV
assessments require `format="osv"` and `advisory_snapshot`; representations are never
combined. Historical Git snapshots identify complete commit-tree inventories, their
parents, processing generation and coverage. Development branches and imported
ancestors are historical assessments with `complete=false`. Only fully covered,
freshly validated main/archive or official OSV-tip observations qualify as complete.
Processing/import time does not refresh historical evidence.

New advisory research tools accept `format` (`rustsec` or `osv`) and immutable
`snapshot` selectors where applicable. Existing lookup/audit use `advisory_snapshot`,
including retained legacy head-capture aliases. Explicit historical snapshots remain
readable after seven days and return supported matches with incomplete assessment.
Unsupported historical source remains raw evidence with explicit processing gaps.

Catalog filters combine with AND: exact `name`, canonical `id`, exact `alias`,
`classification`, `category`, `informational`, `os`, `arch`, and inclusive
`date_from`/`date_through` (`YYYY-MM-DD`). OS/architecture selection includes records
without that restriction; unknown applicability is not unrestricted applicability.
Dates use RustSec advisory dates or OSV published dates, not import time. Query
terms use case-insensitive AND substrings. Lists default to 20 and cap at 100;
new tools accept offsets through 10,000 and snapshot/query-bound cursors beyond
that window. Cursor continuation allows a changed page size.

History and snapshot discovery return a frozen integer `history_snapshot` publication
cutoff. History reports changes against each ordered Git parent; absence differs
from withdrawal. Ref observations retain branch/tag movements and deletions.
Full history covers all ancestry reachable from observed advertised branches/tags,
including previously observed roots; it cannot reconstruct already-unreachable
objects. OSV and rendered-site branches are retained, but rendered content is inert.

OSV matching supports crates.io SEMVER event ranges and explicit version lists.
Unsupported range kinds, historical schemas and malformed constraints remain
coverage gaps; supported matches can still be returned without claiming complete
assessment. OSV withdrawal and RustSec informational metadata remain separate from
active vulnerability counts.

`devres://advisory/<format>/<id>/<snapshot>` reads the same original source with
bounded UTF-8 byte paging. Citations retain source revision, member path/hash and
original notices; references are never fetched or executed.

Only supported crates.io registry identities are assessed. Git, local/path, and
alternative registries are unassessed rather than matched by name alone. Reports
identify the advisory snapshot, freshness and coverage. A missing snapshot or one
older than seven days makes assessment incomplete; zero matches is not a guarantee
of security. Withdrawn/informational advisories are not silently counted as active
vulnerabilities. No package builds, fixes, network dependency resolution, or uploads
of lockfiles to third-party audit services occur.

Invalid protocol/schema input is rejected before dispatch. Application failures use
sanitized typed codes such as invalid_input, not_found, unavailable, capacity, and
integrity. Oversized results fail explicitly rather than silently claiming complete
coverage. Cancellation suppresses late responses and releases admission.

## MDN content and compatibility

Serving automatically collects the fixed official `mdn/content` and
`mdn/browser-compat-data` Git repositories. English articles, legacy HTML, redirects,
compatibility features, and browser releases are processed as inert data. All
advertised branches/tags and reachable ancestry are retained, including observed
ref movements/deletions and previously observed roots. Pull-request/internal refs
and already-unreachable upstream objects are outside that acquisition scope.

Current-main collection has priority over resumable ancestry processing. Serving
remains ready during bootstrap; MDN reads can be unavailable until publication.
Every processed commit receives an immutable inventory and research snapshot.
Unchanged raw objects, projections, directory nodes and postings are shared.
Acquisition, raw-member accounting, supported projection, indexing and whole-source
acceptance are separate states. Unsupported formats, malformed metadata, unknown
macros, bounded processing and ambiguous compatibility identities remain explicit
coverage gaps, with original source evidence retained. Deletion never removes
historical evidence. A completed job or zero-result search does not establish
complete rendered-site coverage.

The default view atomically freezes independently validated content-main and
compatibility-main snapshots. Failure preserves the previous view. Successful
online validation marks evidence stale after 24 hours; omitted/default selection
fails beyond seven days. Historical snapshots/views remain readable. Reprocessing
and offline restoration do not refresh source validation time. Historical content
snapshots receive BCD enrichment only with explicit `compatibility_snapshot`;
commit timestamps never infer a cross-repository pairing.

Document projections preserve source metadata, headings, links and inert examples.
Trusted Rust handlers expand common reference/status macros and bounded
same-snapshot includes. Navigation/live-demo/unknown macros and unresolved includes
are labeled gaps. Compatibility expansion uses the explicitly pinned BCD evidence.
No MDN/npm build scripts, template JavaScript, demos, external assets or linked
specifications are executed or fetched. Compatibility results preserve original
statements and separately identify derived mirror mappings from captured browser
release/engine metadata. Flags, prefixes, notes, partial support, removals, unknown
versions and unresolved mirrors are not converted into browser-version verdicts.

MDN search follows the technical/English query conventions above, uses conjunctive
filters, and ranks with BM25 over only the selected snapshot membership. Ties use
slug, source path and projection identity. Search-index gaps do not suppress raw
retrieval or poison later publications. Offset paging accepts at most 10,000;
snapshot/query-bound cursors continue beyond that window and allow a changed limit.
`mdn_history` records changes against each ordered parent, including merges.
Entries label processing generations; normalization upgrades retain older evidence.
Discovery freezes `history_snapshot`; follow `next_cursor` even if a bounded scan
returns no matching records. Lists default to 20 and cap at 100.

`mdn_get` accepts `repository="content"` (default) or `"compat"`. Projected text,
original `source`, and explicit `bytes` pages cap at 32 KiB. UTF-8 text offsets must
be character boundaries. Binary/oversized source uses base64 byte pages, verified
against retained evidence. Resources use
`devres://mdn/<repository>/<snapshot>/<representation>/<base64url-identity>`;
representations include text/source/bytes and typed feature/browser records.
Paired text resources also bind `compatibility_snapshot`. Citations carry source
revision/path, original notices and attribution; MDN material is not relicensed
as first-party AGPL code. Discovery supplies authoritative strict schemas.

## WHATWG standards research

Serving automatically acquires the entire official standards catalog, its approved
source repositories, and full advertised branch/tag ancestry. Current publications
have priority over resumable historical processing. Catalog removals and Git ref
movements/deletions never remove retained history. The separately identified Web
NFC predecessor is acquired while the listed WHATWG publication remains an
independent observation; a placeholder page is not a usable specification.

Automatic additions use the versioned official catalog and explicit source-repository
metadata from its publication pages. GitHub owner/repository identities, admitted
publication destinations and their admission evidence are retained. Ordinary links,
references, tests, scripts and package manifests cannot authorize new destinations.
Public requests perform local evidence research and never initiate collection.

| Tool | Capability |
| --- | --- |
| `whatwg_catalog_search` | Captured standard metadata, publication state and gaps; optional immutable view |
| `whatwg_search` | Selected-snapshot BM25 over specification sections, with technical/English queries and conjunctive standard/edition/path/kind filters |
| `whatwg_get` | Projected text, anchored section, original UTF-8 source or base64 byte pages |
| `whatwg_symbol_search`, `whatwg_symbol_get` | Captured definitions, IDL declarations and explicitly marked algorithms |
| `whatwg_references` | Captured incoming/outgoing references with explicitly qualified local resolution |
| `whatwg_snapshots`, `whatwg_history` | Immutable discovery, frozen history pagination, and ordered-parent changes |
| `whatwg_compare` | Observed source, normalized section or symbol changes between two immutable snapshots |
| `whatwg_corpus_status` | Separate acquisition, ancestry, projection, indexing, freshness and failure state |

A `view` freezes catalog membership, per-standard snapshots and validation observations
with its search reference. A document `snapshot` selects one immutable source revision
or publication representation. These selectors are exclusive. Default evidence becomes
stale after 24 hours and is unavailable beyond seven days; explicitly historical views
and snapshots remain readable. Reprocessing and offline restoration do not refresh
online validation. Unchanged evidence may receive a new successful validation
observation without changing its original representation.

Canonical current publications are the default search membership. Advertised alternate
editions, multipage documents, PDFs, review drafts and commit snapshots retain distinct
identities and are discoverable through snapshots. Original source revisions are not
implicitly paired with published HTML. Missing publication/revision association,
unsupported historic syntax, generated constructs and parsing bounds remain explicit
gaps. Acquisition accounting, supported projection and search coverage are separate.

HTML, Bikeshed, WHATWG source and Markdown are inert data. Sections preserve source
anchors, tables, examples, definitions, IDL text and marked algorithms. IDL extraction
is not semantic compilation; algorithm text is not executed. PDF extraction preserves
page text and raw bytes, with layout/font/image limitations reported. Upstream builds,
JavaScript, demos, stylesheets, external resources and linked specifications are never
executed or fetched by projection or research operations.

Lists default to 20 and cap at 100. Offset paging accepts at most 10,000; bound cursors
continue beyond that window and permit a changed limit. Reuse returned view/snapshot
selectors for continuation. History cursors also carry the frozen `history_snapshot`
cutoff; follow `next_cursor` even when a bounded filtered scan returns no entries.
Text and byte pages cap at 32 KiB; text offsets must be UTF-8 boundaries. Duplicate
anchors and symbols require disambiguation rather than arbitrary selection.

`devres://whatwg/<standard>/<snapshot>/<representation>/<base64url-path>` identifies
immutable text/source/bytes or discriminated symbol resources. Citations preserve
original source URL, revision/path/object identity and applicable versioned notices.
References outside captured evidence remain unresolved; comparison results do not
assert normative, browser-compatibility or conformance consequences.

Generated anchored resources use document-local `section_index` or `symbol_index`
selectors within the immutable snapshot and path. These preserve duplicate identities
and keep resource URIs bounded even for long Unicode anchors or symbol names. Legacy
anchor/name selectors remain readable. Advertised plain text and IDL publications
remain distinct text representations; JSON and other unsupported formats retain
their raw bytes and explicit projection gaps.

`whatwg_history` defaults to revision history. `history_type="refs"` returns paged
advertised branch/tag observations; select an exact captured `repository` and
optionally `ref`. Its cursor freezes both the publication cutoff and position within
an observation. Repository-qualified history avoids guessing a historical repository
from a standard's current mapping. Earlier observations preserve refs subsequently
moved or deleted; absence is not proof that an unreachable object never existed.

Rendered comparisons match anchors after normalizing commit-snapshot and review-draft
URL prefixes; moving a publication beneath a versioned URL does not itself mark every
section as removed and added. Original Git member paths stay exact. A retained member
with failed projection is incomplete comparison evidence, rather than proof that its
previous sections were removed. Original-source comparison remains available.
