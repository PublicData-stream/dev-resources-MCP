# Sources and upstream policy

All provider URLs are constructed by trusted adapters. The HTTP adapter rejects
arbitrary schemes, hosts, credentials, ports, fragments, escaped paths, and redirects.
Requests identify the application and repository. One adapter owns retries: at most
one retry for transient HTTP statuses, respecting bounded Retry-After. Every attempt
reserves its source rate slot. At most two HTTP transfers run concurrently.

| Source | Access and freshness | Permanent evidence |
| --- | --- | --- |
| RFC Editor | [Official XML metadata index](https://www.rfc-editor.org/rfc-index.xml), errata JSON, and advertised TXT/HTML/XML/PDF; default 24-hour refresh | All observed valid bodies, source URL, content hash, observation times and transport assurance |
| crates.io | Search API at most 1 request/second; sparse index for version/dependency/checksum data; CDN for exact archives; one-hour freshness | Index/search/archive captures and provenance |
| RustSec | Fixed official GitHub head then immutable codeload bundle; 24-hour freshness | Head capture/revision, bundle capture, notices |

Defaults are conservative: all allowed HTTP hosts are throttled to at most one
request/second. RFC host aliases share a source budget. API limits must not be
raised beyond the provider's published policy. Cache hits make no source requests;
conditional revalidation records the observation without replacing body content.
Only confirmed 404s receive five-minute negative caching. Network/429/5xx failures
are not recorded as absence. Valid stale public captures can be returned through
seven days with their original validation time; older data is unavailable/incomplete.
RustSec snapshots older than 24 hours are explicitly stale. Requested historical
captures are fixed evidence, not claims of current completeness.

The RFC index endpoint was checked on 2026-10-24: the root `rfc-index.xml`
returns XML; the older `/in-notes/rfc-index.xml` returns 404. Keep endpoint tests
and source profiles aligned with actual official responses.

The errata download is `https://www.rfc-editor.org/api/v1/errata.json`.
On 2026-10-24 the older root `/errata.json` returned 302 to that fixed path.
The adapter constructs the canonical destination directly and continues to reject
redirect responses and arbitrary query destinations.

Legacy RFC search remains metadata search. Dedicated research tools add local
full-text search. Status, updates, and obsolescence
are metadata, not an instruction to replace requested RFC text. Crate source browsing
verifies a published archive against the selected index checksum, rejects unsafe
archive members, and does not follow repository URLs from package metadata.

## Terms and evidence

Follow [crates.io data access](https://crates.io/data-access),
[Cargo index format](https://doc.rust-lang.org/cargo/reference/registry-index.html),
[RFC metadata guidance](https://rpc-wiki.rfc-editor.org/doku.php?id=rfc_metadata_in_the_v3_era),
[IETF Trust provisions](https://trustee.ietf.org/documents/trust-legal-provisions/),
and [RustSec licensing](https://github.com/RustSec/advisory-db/blob/main/LICENSE.txt).
Preserve original notices, including RustSec's per-advisory GHSA attribution.
Do not relicense archived sources as AGPL or infer unrestricted reuse from public
availability. New providers require a profile covering identity, supported operations,
terms, rate limits, freshness, failure semantics, provenance and bounded fixtures.

Synthetic fixtures are labeled as such. Curated upstream captures retain source
provenance, capture hashes, and applicable terms. A bounded live smoke proves only the named
records at its observation time; it is not whole-source coverage, load testing,
provider endorsement, or permission for bulk ingestion. RustSec Git snapshots may start with one 52-byte PAX global commit-comment header.
Only an exact first header matching the captured immutable revision is admitted;
crate archives keep their stricter special-member policy.

RFC Editor has a supervised, resumable corpus collector and immutable local search
snapshots. This exception does not introduce collection daemons for other providers.
The collector enumerates official metadata, constructs fixed source URLs and archives
advertised formats. HTTP failures, unsupported formats and processing bounds remain
explicit gaps; neither a completed sweep nor a zero-result search implies full coverage.

The private opt-in rsync importer uses `rsync.rfc-editor.org::rfcs` as documented in
[official bulk-download guidance](https://www.rfc-editor.org/series/rfc-download/).
Unauthenticated rsync observations have separate source identities and assurance;
they cannot replace HTTPS heads or count as HTTPS verification. Original RFC text
is never modified by applying errata. Only observed versions are retained; collection
cannot reconstruct representations that disappeared before observation.
