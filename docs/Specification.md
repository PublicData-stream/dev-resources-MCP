# Service specification

## Capability and status

This service is anonymous and read-only with respect to caller data and upstream
systems. Reads may populate internal public-source caches and permanent archives.
It supports RFC metadata/text, crates.io metadata/published sources, RustSec
advisories, and supplied Cargo.lock matching. No public administrative operations,
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
| `search` | Query, selected `rfc`/`cargo`/`rustsec` sources, offset/limit; source-specific results/errors |
| `fetch` | `rfc:<number>`, `crate:<name>@<version>`, or immutable `devres://` resource URI |
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
| `advisory_lookup` | Crate/version; matched advisories, withdrawals and informational state |
| `audit_lockfile` | Supplied Cargo.lock text; supported matches, unassessed entries, completeness/freshness |

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

## Audits and failure

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
