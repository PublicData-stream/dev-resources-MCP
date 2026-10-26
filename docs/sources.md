# Sources and upstream policy

All provider URLs are constructed by trusted adapters. The HTTP adapter rejects
arbitrary schemes, hosts, credentials, ports, fragments, escaped paths, and redirects.
Requests identify the application and repository. One adapter owns retries: at most
one retry for transient HTTP statuses, respecting bounded Retry-After. Every attempt
reserves its source rate slot. Foreground retrieval retains two transfer slots;
private crate acquisition defaults to four additional bulk slots. docs.rs has one
shared transfer slot. Both paths share provider host clocks.

| Source | Access and freshness | Permanent evidence |
| --- | --- | --- |
| RFC Editor | [Official XML metadata index](https://www.rfc-editor.org/rfc-index.xml), errata JSON, and advertised TXT/HTML/XML/PDF; default 24-hour refresh | All observed valid bodies, source URL, content hash, observation times and transport assurance |
| crates.io | Search API at most 1 request/second; sparse/index default 1 attempt/second; static CDN default 5 attempts/second; hourly Git inventory and daily public metadata dump | Search/index/Git evidence, exact archive captures and dump provenance |
| docs.rs | Exact-version all-target HTML ZIP and per-target rustdoc JSON; default 1 attempt/second, one transfer, daily revalidation | Raw artifacts, observed formats/targets, inert text/API projections and processing coverage |
| RustSec | Fixed official GitHub head then immutable codeload bundle; hourly revalidation, 24-hour freshness | Head capture/revision, bundle capture, notices |
| RustSec history/OSV | Daily full official HTTPS Git branch/tag synchronization | Ref manifests, all reachable objects/parents, raw representations and notices |

API/docs.rs hosts retain at most one attempt/second. Official Git/sparse-index and
static.crates.io budgets are independently configurable; defaults are one and five
attempts/second respectively. RFC host aliases share a source budget. API limits
must not be raised beyond the provider's published policy. Cache hits make no source requests;
conditional revalidation records the observation without replacing body content.
Legacy crate search/sparse-index captures have one-hour freshness. Exact archives
bound to an index checksum may be reused for one year; this does not extend the
freshness of moving version/yanked metadata.
Only confirmed 404s receive five-minute negative caching. Network/429/5xx failures
are not recorded as absence. Valid stale public captures can be returned through
seven days with their original validation time; older data is unavailable/incomplete.
RustSec snapshots older than 24 hours are explicitly stale. Requested historical
captures are fixed evidence, not claims of current completeness.
RustSec reads use published local snapshots; collection owns provider traffic.
Historical assessment returns supported findings with incomplete coverage rather
than claiming current completeness. Current maintenance requires a successful
validation and does not report stale fallback as refresh success.
Documentation/API freshness uses the original docs.rs capture's validation time,
not the lifetime of its derived text. Default queries reject selected documentation
older than seven days; explicit historical snapshots and capture resources remain
readable. Results expose the original source capture and its 24-hour stale state.

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

## Registry and documentation acquisition

The registry collector incrementally reads the fixed official
[`rust-lang/crates.io-index`](https://github.com/rust-lang/crates.io-index)
repository through a private HTTPS Git relay. Git runs only against an owned bare
repository: no package checkout, hooks, caller configuration, credential helper or
arbitrary remote is admitted. Canonical sparse-index paths supply exact versions,
dependency declarations, checksums and yanked state. A fixed
[`static.crates.io/db-dump.tar.gz`](https://static.crates.io/db-dump.tar.gz)
request supplies public enrichment as described by the
[official dump format](https://github.com/rust-lang/crates.io/blob/main/crates/crates_io_database_dump/src/readme_for_tarball.md).
CSV headers/fields and joins are bounded; archive SQL remains inert.

For each observed exact release, docs.rs routes are constructed from captured
canonical package identity. `/crate/<name>/<version>/menus/platforms/` enumerates
published targets; `/download` supplies one HTML ZIP with the default target at
its root; `/<target>/json.gz` supplies the latest available JSON format for that
target. No `latest`/semver package-version aliases, scraped repository destinations,
external static assets or automatic redirects are followed. See the official
[ZIP](https://docs.rs/about/download) and
[JSON](https://docs.rs/about/rustdoc-json) documentation.

The latest available JSON format per target is collected; every observed format and
representation is retained. Public routes do not enumerate all historical JSON
formats, and collection does not claim to reconstruct unseen builds. JSON generation
started in May 2025; older releases or failed builds may have no JSON. Absent/failed
builds, unknown formats and parsing bounds remain visible processing gaps and are
eligible for later revalidation. A body hash identifies captured HTTPS evidence;
it does not establish an immutable docs.rs build ID or a registry archive checksum.

The docs.rs source/docs inspected do not state a numeric bulk-mirroring allowance.
The configured conservative default is application policy, not provider permission
or an endorsement. Preserve package documentation notices and source licenses;
docs.rs hosting does not relicense packages. HTML and JSON are untrusted data and
never cause local `cargo doc`, rustdoc, package builds or executable loading.

## Terms and evidence

RustSec history uses only `https://github.com/rustsec/advisory-db.git` smart-HTTP
advertisement/upload-pack operations through the private relay. It fetches advertised
branches and tags with full ancestry, excluding pull-request/internal namespaces.
GitHub attempts remain bounded to one per second, sharing the host clock and retry
owner. No repository checkout, submodule, hook, credential helper, bundle redirect,
or arbitrary destination is allowed. Previously observed roots remain retained
after ref movement/deletion; already-unreachable upstream objects are unobserved.

The official `osv` branch is normalized against the
[OSV schema](https://github.com/ossf/osv-schema/blob/main/docs/schema.md), preserving
extensions, original JSON and per-record notices. Only supported crates.io SEMVER
and explicit-version constraints are assessed. Uninterpreted constraints remain
gaps. Canonical RustSec and OSV exports are distinct representations and are never
unioned into duplicate vulnerability findings. Rendered site content remains inert
raw evidence.

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
snapshots. Its collector enumerates official metadata, constructs fixed source URLs and archives
advertised formats. HTTP failures, unsupported formats and processing bounds remain
explicit gaps; neither a completed sweep nor a zero-result search implies full coverage.

The private opt-in rsync importer uses `rsync.rfc-editor.org::rfcs` as documented in
[official bulk-download guidance](https://www.rfc-editor.org/series/rfc-download/).
Unauthenticated rsync observations have separate source identities and assurance;
they cannot replace HTTPS heads or count as HTTPS verification. Original RFC text
is never modified by applying errata. Only observed versions are retained; collection
cannot reconstruct representations that disappeared before observation.

## Mozilla Developer Network

MDN acquisition admits only the official HTTPS Git advertisement/upload-pack
operations for `https://github.com/mdn/content.git` and
`https://github.com/mdn/browser-compat-data.git`. It reuses the private fixed-source
relay and GitHub host admission; no arbitrary remote, automatic redirect, caller
Git configuration, credential helper, checkout, hook or submodule is admitted.
All advertised branch/tag ancestry and future observed roots are retained.
Hourly ref validation is a scheduling target, not a provider endorsement or
completion-time guarantee. Revalidation changes observation time, not old captures.

English prose, guides/references, legacy HTML and redirects come from `content`;
feature support and browser/engine release mappings come from BCD. Other repository
members remain retained raw evidence. Translated repositories and external
specification/baseline/live-demo datasets are not acquired. Source macros, schemas,
links, embedded scripts and package manifests are data, never instructions or
executables. Unknown historical representations remain processing gaps.

Preserve the versioned repository license/notices and source revision/path in
responses and fixtures. [MDN content licensing](https://github.com/mdn/content/blob/main/LICENSE.md)
distinguishes CC-BY-SA 2.5 prose, post-August-20-2010 CC0 examples, and older MIT
examples; do not infer a code example's contribution date from a recent edit.
[BCD](https://github.com/mdn/browser-compat-data/blob/main/LICENSE) is CC0-1.0.
[Its schema](https://github.com/mdn/browser-compat-data/blob/main/schemas/compat-data-schema.md)
and [browser metadata](https://github.com/mdn/browser-compat-data/blob/main/schemas/browsers-schema.md)
define original support evidence. Rust mirror handlers preserve original values,
label derivation and use pinned engine/release mappings; missing/obsolete semantics
are not fabricated. No browser-version compatibility certification is provided.

Ordinary checks use synthetic fixtures with explicit provenance. Bounded live
acceptance and full frozen-observation backfill are separate commands/evidence;
neither authorizes production deployment or demonstrates native client UI support.

## WHATWG standards

The [standards index](https://spec.whatwg.org/) is reconciled with the versioned
[`whatwg/sg` catalog](https://github.com/whatwg/sg/blob/main/db.json). Its standards
are in scope; the separate ideas and bibliography sections are not source admission.
Current mappings use official WHATWG repositories plus the separately labeled
[`w3c-cg/web-nfc`](https://github.com/w3c-cg/web-nfc) predecessor. The listed NFC
publication is retained independently, including its observed placeholder state.

Automatic catalog additions admit validated standard publication hosts and explicit
source-repository metadata from the listed publication, including external GitHub
owners. Admission retains the exact supporting observation. Normal links, reference
lists, test repositories, editor profiles and arbitrary caller URLs do not authorize
collection. Redirects, userinfo, custom ports and unsafe paths remain rejected.
Git uses only the private advertisement/upload-pack relay; no checkout, hook,
submodule or credential helper is admitted.

The collector retains advertised branch/tag ancestry and previously observed roots,
plus advertised HTML editions, multipage documents, review drafts, commit snapshots
and PDFs. Discovery uses publication navigation/indexes, not unrestricted link
crawling. Every frozen observation has finite catalog, ref and publication inventories;
new discoveries belong to later observations. Already-unreachable objects and
unadvertised/disappeared publications cannot be reconstructed.

GitHub attempts share the existing host clock. WHATWG publication attempts have a
shared one-per-second budget with the existing single retry owner. Catalog/ref
validation targets one hour and moving publications one day. These conservative
application defaults do not claim provider endorsement or a bulk-mirroring allowance.

Preserve each representation's versioned license/notices. The WHATWG
[publication policy](https://whatwg.org/workstream-policy#publications) describes
CC-BY-4.0/BSD-3-Clause treatment, while predecessor/community-group material can
carry different original notices. GitHub license detection is not authoritative;
public availability does not relicense captured content as first-party AGPL.

Ordinary checks remain synthetic. Fixed-record smoke and explicitly invoked,
retained full frozen-observation acceptance are separate evidence. Full accounting
never substitutes for successful projection, complete rendered history, measured
capacity, hosted native architecture checks or production deployment.
