# Sources and upstream policy

All provider URLs are constructed by trusted adapters. The HTTP adapter rejects
arbitrary schemes, hosts, credentials, ports, fragments, escaped paths, and redirects.
Requests identify the application and repository. One adapter owns retries: at most
one retry for transient HTTP statuses, respecting bounded Retry-After. Every attempt
reserves its source rate slot. At most two HTTP transfers run concurrently.

| Source | Access and freshness | Permanent evidence |
| --- | --- | --- |
| RFC Editor | [Official XML metadata index](https://www.rfc-editor.org/rfc-index.xml) and selected RFC text; 24-hour freshness | Raw bodies, source URL, content hash, observation times |
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

RFC search is metadata search, not full-body search. Status, updates, and obsolescence
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

No scheduled full crawler,
corpus index, or provider synchronization daemon is part of this foundation.
