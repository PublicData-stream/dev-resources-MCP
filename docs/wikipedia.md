# English Wikipedia

Wikipedia is an English-only public-source provider. The writer automatically
collects current STEM articles; serving readers use retained evidence and delegate
new acquisition to the sole writer. No public operation edits Wikipedia.

## Discovery and coverage

Omitting `[wikipedia]` enables collection. Default category roots are Science,
Technology, Engineering, Mathematics, Artificial intelligence and Computer
architecture. Discovery traverses their descendant category graph with cycle
protection, durable continuation and configurable exclusions. Article bodies are
limited to namespace zero. Demand requests may add other English articles.

This graph is an operational definition of coverage, not an authoritative STEM
classification. Category graphs overlap and can extend beyond STEM. Collection is
resumable and publishes partial local snapshots. Intervals describe scheduling
eligibility, not a completion time or freshness SLA. A daily reconciliation sweep
is resumable; a failed or partial listing does not establish membership removal.
Previously acquired evidence remains permanent when current category membership
changes. Demand-added articles remain tracked.

V1 uses paced API acquisition rather than dump import. Wikimedia recommends
considering dumps for bulk workloads; full-corpus and historical dump import are
outside this implementation. Only fetched representations are retained: a stream
of edits does not imply that every intermediate revision body was acquired.

## Tools

| Tool | Behavior |
| --- | --- |
| `wikipedia.search` | Local literal line matches in page order; explicit `mode="upstream"` returns discovery IDs and links |
| `wikipedia.catalog_search` | Captured article metadata and conjunctive title/category/Current filters |
| `wikipedia.get` | Title/page ID or retained capture; text, Markdown, inert HTML or wikitext |
| `wikipedia.metadata` | Captured identity, formats, categories, freshness and provenance |
| `wikipedia.references` | Inert captured links/citations; destinations are never requested |
| `wikipedia.history` | Observed captures, not a complete upstream revision history |
| `wikipedia.snapshots` | Frozen local corpus publication cutoffs |
| `wikipedia.compare` | Bounded positional text changes or metadata comparison of one page |
| `wikipedia.rg` | Bounded Rust-regex/literal line matching over local readable text |
| `wikipedia.corpus_status` | Partial coverage, acquisition and stream state |

Generic `search` includes local Wikipedia as its ninth source when sources are
omitted. `fetch` accepts `wikipedia:<title>` and immutable typed resources under
`devres://wikipedia/<capture>/<representation>`. Discovery results do not fetch
article bodies automatically; `get` may acquire an absent article through the
writer. All input schemas reject unknown fields and arbitrary source URLs.

Text is the default representation. Markdown is generated from the same retained
HTML, preserving available structure and TeX/math information with explicit
processing gaps. Source HTML/wikitext remain inert. Images, scripts and external
reference destinations are not downloaded or executed. Table projection and
rendering differences are reported rather than represented as lossless conversion.

HTML and wikitext come from separate current-page REST requests. Their captures
are qualified independently by page ID and revision. A missing format at the
selected revision is an explicit gap; retrieval never substitutes another
revision. HTML render changes with an unchanged page revision have distinct body
captures. Explicit snapshot/capture selection stays fixed.

List pages default to 20 and cap at 100; text pages cap at 32 KiB of UTF-8 bytes.
`wikipedia.rg` uses Rust regex syntax or `literal=true`, without a shell command: 4 KiB patterns, 2 MiB compiled
program bounds, one scan worker, a 15-second deadline, 100 MiB scan allowance and
bounded excerpts. Cursors bind query and snapshot; incomplete scans are explicit.

## Freshness and upstream policy

Article bodies use the current MediaWiki REST API, not deprecated RESTBase.
Read-only Action API metadata supplies categories, namespace/revision checks,
Current transclusions and template aliases. One writer-owned EventStreams
`recentchange` connection supplies change observations; filtering happens locally.
The connection is continuous, not one stream or polling interval per article.
Resume IDs, pending work and moderation state are committed durably. Finite replay,
stream outages and visibility uncertainty remain explicit.

Persist HTTP cache evidence and conditional validators. Corrected Age/Date and
`s-maxage`/`max-age`/Expires determine the upstream freshness floor; 304 headers
merge with the stored representation policy. No event, demand request or Current
profile can bypass that floor, rate admission or Retry-After.

| Profile | Event debounce | Minimum fetch spacing | Fallback revalidation |
| --- | --- | --- | --- |
| Ordinary | 300 s | 300 s | 86400 s |
| Current or unknown | 30 s | 60 s | 300 s |

Current state requires revision-consistent template metadata. Incomplete template
or alias evidence remains unknown and uses the conservative profile. These are
application defaults: `Template:Current` provides no Wikimedia TTL exemption.

Default current reads may return labeled stale content for 24 hours after expiry
for ordinary articles, or 15 minutes for Current/unknown articles. Cache directives
can prohibit fallback. `no-store` and `private` responses do not supply new retained
bodies or projections; revalidation restrictions are enforced. Prior immutable
historical evidence is not advertised as a fresh current response.

Default Wikimedia admission is one attempt/second, burst one; configuration accepts
one to three. REST and Action share a maximum of two outstanding API requests,
with Action at most one. Redirects and retries consume attempts. The established
SSE body has a separate single permit; connection attempts are counted. Persisted
admission/cooldown survives writer restart. Observed throttling remains queued for
durable storage when a caller disconnects. Graceful shutdown drains these receipts
and reports persistence failures. Set writer termination grace above its configured
request shutdown timeout plus the 35-second drain; shipped Kubernetes writers use
120 seconds. The client identifies itself with the
project/contact URL, requests gzip, observes Retry-After and backs off failures.
Action requests taking over one second impose the documented five-second pause.

For significant sustained traffic, the operator must also satisfy Wikimedia's
origin-identification rule: publish its outbound CIDRs as downloadable JSON or
use an authenticated API identity. The bounded anonymous smoke check does not
establish bulk-operation permission or an exemption.

The API client follows documented API-specific rules. Wikipedia's wildcard
robots.txt currently disallows the API path prefixes, despite Wikimedia documenting
these APIs for clients. This interpretation is recorded explicitly; it is not a
claim that the documents are fully reconciled. Website crawling must respect
robots directives. The implementation does not recursively fetch website URLs.

## Retention, attribution and moderation

Schema 14 adds owner-fenced Wikipedia evidence and scheduling/visibility tables.
Reader attachment requires schema 14. Stop old readers/writers before activating
an upgraded binary; this feature does not authorize a production upgrade.
BLAKE3-verified blobs precede immutable SQL references and snapshot publication.
Filesystem and S3 archive accounting includes Wikipedia artifacts. Quota/headroom
exhaustion pauses acquisition without evicting historical evidence.

Content-bearing output passes the existing versioned attribution gate. Initial
qualification binds the actual acquisition policy, exact page/revision/body and
returned supported license evidence; arbitrary license URLs do not qualify.
Notices link to Wikipedia and identify projected text/Markdown as adaptations.
Embedded media have separate rights and are not ingested.

Observed reliable deletion/suppression evidence withholds affected public bodies,
including old snapshots, regex/search snippets, comparisons and typed resources.
Generic raw capture URIs cannot bypass the visibility gate. Known attribution
resources also check current visibility. Evidence remains stored internally.
Restoration needs successful public verification; transport failures alone do not
prove deletion. Public events cannot reveal every hidden moderation operation,
so complete instantaneous suppression coverage is not promised.

## Acceptance

Ordinary tests use synthetic REST/SSE responses and disposable storage. Keep all
local test state below `/tmp`, including Kubernetes profiles; use
`CARGO_TARGET_DIR=/tmp/rust/target` after `scripts/with-tmp-state.sh`.

The opt-in live check uses fixed LLM/RISC-V records, at most 20 total Wikimedia
attempts including retries, and one stream connection capped at 30 seconds:

```sh
scripts/with-tmp-state.sh env CARGO_TARGET_DIR=/tmp/rust/target \
  scripts/live-smoke.sh --live --wikipedia
```

Its owned receipt directory preserves the attempt counter on resume; it cannot be
reset to replenish a run. Fresh responses are not forcibly revalidated to obtain a
304. Compilation, mock fixtures, real PostgreSQL, isolated minikube, bounded live
provider checks, hosted native architectures and production activation are
separate evidence.

## Policy references

- [MediaWiki REST reference](https://www.mediawiki.org/wiki/API:REST_API/Reference)
- [REST policies](https://www.mediawiki.org/wiki/API:REST_API/Policies)
- [Robot policy](https://wikitech.wikimedia.org/wiki/Robot_policy)
- [Cross-API limits](https://www.mediawiki.org/wiki/Wikimedia_APIs/Rate_limits)
- [Action API etiquette](https://www.mediawiki.org/wiki/API:Etiquette)
- [EventStreams](https://wikitech.wikimedia.org/wiki/Event_Platform/EventStreams_HTTP_Service)
- [Current template](https://en.wikipedia.org/wiki/Template:Current/doc)
- [Wikipedia robots.txt](https://en.wikipedia.org/robots.txt)
- [Content licensing](https://foundation.wikimedia.org/wiki/Policy:Terms_of_Use#7._Licensing_of_Content)

Pinned historical deployment probes retain their original release/provider scope;
they do not establish Wikipedia acceptance. The Wikipedia probe above is separate.
