# Architecture

The [npm module](npm.md) follows the same dependency direction and ownership fence.
Application ports admit public evidence and operator scheduling state; request-only
npm/pnpm/Yarn input stays in a bounded sibling audit process. Package and advisory
snapshots publish independently through schema 9. Public resources never identify
caller inventories or reports.

The domain crate owns source/capture/request/error representations. Application owns
retrieval policy and Store, Fetcher, Clock ports. Adapters implement fixed-source
HTTPS, PostgreSQL/blob persistence, pure source parsers, archive inspection, and
research use cases. The server owns configuration, tool schemas, shared dispatch,
HTTP/WebTransport framing, TLS, and endpoint lifecycle. Concrete adapters depend on
application contracts; application does not import adapters. Parsers never perform
network or filesystem I/O themselves. The small workspace can be split further
when independent dependencies or ownership justify it.

## Adapter module layout

The adapter crate groups source code, integration tests and examples by provider:
`mdn`, `rfc`, `crates_io`, `rustsec`, `npm`, `w3c`, `whatwg` and `chromium`.
Provider namespaces are the canonical Rust imports; existing flat public module
paths and top-level exports remain supported through re-exports. Shared network,
archive, bulk, storage, research and standards-processing modules remain at the
source root. Provider storage files live beside their provider code but remain
private children of the shared storage module to preserve its ownership boundary.
Cargo test and example target names remain stable despite their grouped paths.

## Retrieval and publication

A trusted provider constructs a bounded FetchRequest with a canonical key and URL.
Application admits work and coalesces requests by key, serves fresh durable cache,
revalidates with HTTP validators, or fetches a new source representation. Upstream
I/O is outside database transactions and application bookkeeping locks. Canceled
owners release their work; request retrieval has no detached refreshes. A waiter can
become the next owner. The HTTPS adapter alone owns bounded retry and throttling.

The writer takes a PostgreSQL session advisory lock at startup and rejects a second
writer owner. Readers hold separate shared lifecycle sessions and SELECT-only
connections. Dedicated sessions never reconnect; losing one fails its participant
until restart. Use one writer replica with Recreate updates and separate serving.
PostgreSQL stores immutable representation records, mutable source heads, and
append-only successful-fetch/revalidation observations. Schema version 2 adds
owner-fenced RFC datasets, resumable jobs, import observations and research snapshot
manifests. Version 3 adds crate inventories, durable acquisition/processing jobs,
artifact provenance, metadata enrichment, content generations and research snapshots.
Version 4 adds owner-fenced advisory observations, deduplicated representations,
ordered snapshot membership, fixed legacy aliases and resumable Git-history state.
Versions 1–9 preserve earlier capture identities. Schema 10 adds explicit BLAKE3
identities and permanent legacy compatibility mappings; older binaries reject it.

Schema 11 adds checksummed attribution policy control, immutable notice generations,
durable repair targets/claims and bounded history-sweep checkpoints. Normal startup
expands active schema 10 atomically before serving, without network acquisition or
bulk backfill. Schemas 1–9 and pending integrity activation keep their offline gates.
A policy epoch/fingerprint prevents serving under an incompatible requirement.
Application policy gates copied-content routes and supervises one repair lane;
adapters construct exact source requests through the existing broker. SQL publication
checks claim ownership and source/policy identity. Source rows and raw bodies remain
immutable, with explicit generation/occurrence bindings outside capture hashes.
Unknown mappings are blocked, never inferred from common body hashes. Audits pass
only public snapshot evidence and never schedule inventory-derived work.

New blobs use `blake3/<64 lowercase hex>` paths in an operator-owned directory;
public hash identifiers use `blake3:<64 lowercase hex>`. Legacy SHA-256 paths remain
retained compatibility evidence. Publication writes a unique staging file, fsyncs
it, hard-links the immutable object without replacing an existing object, fsyncs
the destination and new parent entries, then records BLAKE3 evidence before
committing capture/head/observation records.
Failures can leave unreferenced public blobs or staging files; these are recoverable
artifacts, not missing published history. Cancellation guards remove owned staging files, and exclusive startup removes only
recognized abandoned regular stage files. No automatic history deletion or immutable
blob garbage collection is implemented. Reads verify the complete blob hash. A shared immutable body retains its weighted
read reservation through every cache clone and projection. The store admits at most
128 MiB of outstanding capture bodies (rounded up in MiB), using exact-sized reads
and a stack-byte EOF check; budget exhaustion returns a capacity error. Failed writes and
less than 64 MiB free headroom reject new admissions while preserving archives.

Capture identity binds source key, URL, media type, and body hash. A body changing
and later returning to an earlier representation can reuse that representation's
capture ID; observations preserve the validation events. Capture metadata exposes
the latest retained validation observation while preserving original retrieval time.
Existing resource content
never follows a moving head. Source browsing additionally pins the index capture and
archive capture; checksum verification precedes archive parsing.

## BLAKE3 enforcement and schema 10

Fresh writer stores initialize with enforced BLAKE3, attribution tables, and schema 17. Schemas 1–9 require explicit
private offline migration; serving rejects pre-10 schemas or pending migration.
The maintenance path first excludes readers and writer with the lifecycle fence,
then acquires the exclusive writer fence before any provider
workers or listeners start. It makes no upstream requests and never executes
inspected package code.

BLAKE3 covers capture bodies, bulk artifacts, retained SQL evidence/projections,
content-bearing state, inventories, and index data/manifests. Rust computes and
verifies versioned SQL envelopes binding the record namespace, identity and
payload. The canonical JSON checksum encoding preserves arrays and normalizes
numbers as exact decimal coefficient/exponent pairs, without an `f64` conversion;
SQL constraints require integrity metadata. No PostgreSQL hashing extension is
installed. Request-only lockfiles, dependency graphs and audit reports remain
outside these storage paths.

Private file descriptors under `blob_dir/.devres-integrity` bind exact relative
paths, lengths and BLAKE3 digests. Writers publish them atomically after data fsync
and before database pointers. Nested stores reuse the existing outer integrity
root. These descriptors are permanent backup metadata, not index members or a
public resource. Legacy reads require independently qualified BLAKE3 evidence in
addition to their original checksum. BLAKE3 is verified before retained payloads
are served or processed; missing metadata fails closed rather than qualifying
content implicitly on a public read.

Migration verifies legacy evidence, then reconstructs canonical graphs and indexes
from frozen retained generations. Hash-radix inventories rebuild their routing as
well as their node IDs. Frozen index replay preserves the actual admitted postings,
text, processor/tokenizer version and recorded gaps. Migration occurrence IDs bind
a versioned namespace, original ID and typed frozen evidence, preserving distinct
historical generations that share content. Byte objects may deduplicate without
merging observations, source timestamps or history positions.

Offline graph replay can prepare independent work across all eight providers.
A frozen qualified mapping base and provider-local overlays share one bounded
proof-checked scratch workspace. A lane publishes its original logical SQL stream
in order, including inventory nodes and sequence-bearing rows, through the same
exclusive owner connection. Shared Git-manifest proposals must agree. Ready
index/evidence jobs share command-wide worker and graph-memory admission; provider
coordinators do not reserve a worker while waiting for nested jobs. Serving
reader/writer gates remain unchanged. Prepared immutable index files can precede
their SQL references, but incomplete stages, provider completion receipts and
activation retain their existing fences.
Crate replay records its verified prepared snapshot before publication so a
restart can reuse the same index and occurrence. Receiptless older targets are
claimed in original source order with a frozen candidate cutoff; equal content
cannot cause two retained occurrences to adopt one canonical target.

Original files, records, indexes and selectors remain retained. Namespaced mappings
separate body, capture and provider/entity roles; identical old hash text in two
roles need not identify the same canonical object. Legacy selectors and unversioned
cursors read their frozen compatibility generation and original ordering. New
discovery emits tagged BLAKE3 identities and versioned cursors. Activation promotes
staged canonical selections only after complete verification; interruption resumes
from verified checkpoints. Corruption, missing evidence or an unsupported retained
variant blocks activation. Rollback restores the coordinated pre-upgrade database
and blob backup.

Registry archive checksums, npm SRI, Git OIDs, OCI/release checksums and source bytes
retain their original meaning. SHA-based names for mutable scheduling/cache lookup
keys can remain stable; they are not content addresses or integrity substitutes.
The integrity envelopes detect mismatched retained content, not an administrator
rewriting both content and its digest. Existing freshness, provider budgets,
licensing, request limits and network boundaries remain unchanged.

## RFC corpus

RFC validated retrieval opts into additive closed failure context; other validators
and generic writer-delegate errors retain their existing behavior. Error propagation
preserves existing retry/qualification details, while logs, job persistence and
status project only typed phase/limit/HTTP metadata and allowlisted codes. Schema
16 adds bounded nullable job failure metadata and claim timestamps; it never
assigns phases to old failures or changes sealed captures/snapshot membership.


Application-owned corpus ports separate durable scheduling from PostgreSQL and
source processing. A supervised serving worker owns RFC collection independently
of caller cancellation; it shares retrieval coalescing, provider budgets and the
single storage owner. Provider failures degrade collection status without stopping
serving. Maintenance commands return before workers/listeners start.

Immutable catalogue/errata projections reference original captures. Jobs retain
the latest successful capture across failed refreshes. Snapshot manifests freeze
raw representations, actual searchable sources, coverage, observations and processor
version. A durable database sequence orders publications, including multiple snapshots
within one second. Publication preserves concurrent updates completed during indexing.

Tantivy indexes whole RFCs with positional technical/English fields. A streaming
writer processes one captured representation at a time. Immutable committed segments
and integrity manifests live under `blob_dir/rfc-indexes`; fsync and directory
publication precede the database pointer. Incremental snapshots retain previous
segments; referenced search history is never garbage-collected. Automatic segment
merging is disabled so cancellation cannot leave detached merge writes after ownership
ends; private full rebuild provides compaction. Failures can leave unreferenced derived
directories, never missing published archives. Derived indexes
are rebuildable from captures; corruption fails explicitly.

Offline RFC replay keeps one newly rebuilt and fully verified canonical generation
as a migration-local prototype. Each use re-verifies the frozen source and prototype
and publishes a distinct target with its own integrity evidence; resumed targets
never seed this cache. Capture references retain exact scalar validation semantics
inside the existing 100-representation owner-lock groups.

Rsync imports run privately under the same ownership fence with serving stopped.
They use separate source keys and import observations, never HTTP validation.
Snapshots prefer HTTPS per representation and label lower-assurance fallback.

## Crate corpus

Application ports expose paged inventory/content access and owner-fenced publication;
concrete storage and source processing remain adapters. A supervised collector tracks
all observed crate versions, archives and docs.rs targets while sharing upstream
admission with foreground tools. Git discovery, raw acquisition, CSV enrichment,
content projection and search publication commit independently. A failed projection
never discards its raw capture or makes provisional rows visible.

The index helper operates on an owned bare repository through a private fixed-source
HTTPS relay. It checks out no package trees and disables caller Git configuration,
hooks, credentials and arbitrary destinations. Captured Git evidence/manifests allow
inventory reconstruction; the mutable bare repository is disposable derived state.
Version records retain their Git revision/path/blob identity and original sparse
index capture provenance. Inventory creation and last successful validation are
separate timestamps: an unchanged online revision can become freshly validated,
while restoring offline evidence does not claim a current provider observation.
Unsupported records remain explicit inventory gaps.

Bulk I/O streams bytes to content-addressed files with checksums, quota/free-space
admission, staging cleanup and fsync publication. It does not enlarge generic public
capture reads. Archive checksums bind crates.io archives to captured index records;
docs.rs artifacts have HTTPS/capture provenance without falsely claiming a registry
archive checksum or an immutable build identity. Original package licenses remain.

Raw HTML ZIP and JSON artifacts are never extracted or executed. HTML tokenization
produces inert text/headings/links. Rustdoc JSON uses bounded streaming passes over
an owned expanded staging file, one item at a time, to establish envelope identity,
public paths and normalized signatures. Parent-owned processing generations keep
callback rows invisible until complete validation. Database dumps similarly stream
CSV into artifact-scoped staging; SQL is never executed and publication requires the
complete archive/trailers and required tables to pass.

Immutable crate search shards live under `blob_dir/crate-indexes`. Global BM25 uses
statistics across the whole pinned snapshot, with deterministic semantic-version
and identity tie breaks. Per-document index failures are retained as hashed gap
evidence. A prepared snapshot freezes inventory, content sequence and metadata-dump
enrichment without replacing the serving default; validated index publication then
commits exactly that membership. Background prewarming validates retained shard
files before activation and after restart; foreground cold-open/search work has a
separate 15-second budget. Newer work completed during indexing belongs to a later
snapshot. Requests never rebuild indexes or launch collection work.
They may prioritize attribution repair for already-retained exact sources.

## Privacy and isolation

RustSec has independent supervised current/archive and Git-history lanes. Application
ports own public snapshot/freshness policy; adapters acquire and normalize sources.
Public research and assessment never initiate acquisition. Current archive parsing
must succeed before the default pointer moves. Immutable membership hashes/counts
reject replacement, append and reordering under an existing snapshot ID.

The Git history lane reuses the mediated Git subprocess/transport boundary, with
separate full branch/tag manifests and a bare repository under `rustsec-history`.
Permanent packs/manifests can reconstruct disposable Git state without network.
Ref observations, commit parents and parsing generations remain distinct. Backfill
checkpoints member progress, deduplicates parsed content, and preserves raw records
when supported normalization fails. Acquisition completeness, finished processing,
projection completeness and assessment freshness are separate states.
Normalization upgrades publish immutable processing generations from retained raw
evidence. Existing snapshot IDs and history cursors retain their original projection;
new discovery resolves the latest generation visible at its publication cutoff.

RustSec main archives and OSV exports have separate snapshots/matchers. OSV is used
only when explicitly selected for assessment; an imported ancestor never becomes
fresh because it was processed recently. Research admission bounds concurrent
snapshot materialization; search/parser admission remains held by blocking workers
through cancellation. Captured text and references remain inert.

Audit text goes directly from request dispatch to bounded in-memory parsing and
matching against a public RustSec snapshot in a fixed private analysis helper.
The helper is killed when its owning request is canceled or times out; no package
code or caller-selected executable is run. Submitted text, dependency graphs and
reports never enter Store or resource identifiers. Pagination resubmits the input
and the same public advisory snapshot. Metrics contain aggregate counts only.

Archives are streamed in memory with compressed, expanded, entry, member and output
bounds. Files are never extracted or executed. A SHA-256 checksum demonstrates
agreement with captured registry metadata, not package safety or Git provenance.

Routine tests use mocks, synthetic fixtures, temporary directories and controlled
clocks. Real PostgreSQL, OxiBelt, minikube, and live providers have separate gates.
Backup/restore must coordinate database and blobs while every writer is stopped.

## MDN corpus

Application MDN ports own collection configuration, immutable evidence rows,
source snapshots, combined views and paged discovery. Adapters own fixed Git
transport, pure Markdown/YAML/HTML/BCD projection, persistent path inventories,
PostgreSQL publication and Tantivy search. Schema 5 adds owner-fenced immutable
rows and private resumable state without changing earlier capture identities.

Each commit inventory is a content-addressed tree. Wide directories split into
bounded hash-radix nodes so one changed article does not copy a large directory
map for every historical commit. Raw source, synthetic feature/browser memberships
and ambiguity markers remain distinct. Projection identities include processing
version and source context; unchanged features moved between files cannot collide
with immutable index documents. Includes bind their actual selected-tree inputs;
reverse dependency observations invalidate unchanged callers, including callers
whose earlier include processing failed.
Generation 3 excludes the article's raw Git OID from its stored normalized
projection. Identical normalized documents can share projections and search
postings across formatting edits; the selected inventory member supplies the
public raw OID. Earlier generation captures remain fixed and readable.

Acquisition retains complete packs, commit order, refs and observation manifests.
Bare Git state is reconstructable derived state. Current-main publication and
historical processing share owner-fenced bookkeeping and bounded processing;
source I/O never runs inside database transactions. Completed commit prefixes and
member checkpoints resume after interruption. Processing-version changes restart
backfill without replacing old projections.
Private processing slices reuse a bounded cache of hash-verified immutable nodes.
New nodes enter it only after their write group commits. Public research keeps
its independent storage fencing, and every checkpoint/default publication still
uses the owner connection.
Per-entry staging groups immutable node/projection writes without holding a
database transaction across source I/O. Staged reads stay private and cannot enter
the durable-node cache. The buffer cannot write state or publish views; all groups
must commit before its completed root reaches the caller's checkpoint. Interrupted
groups may leave unreferenced immutable rows, which replay reuses.

Indexes contain unique context-qualified projections, not one repeated full tree
per commit. Immutable linked manifests share shards. Selected-ID filtering applies
before counts, ranking, snippets and paging; native token-count fields and memoized
selected document frequencies keep historical BM25 separate from other revisions.
Shared shard readers avoid duplicating cumulative historical statistics. A durable
index checkpoint precedes mutable manifest/cursor movement, preventing duplicate
postings on replay. Unsupported individual index inputs become explicit gaps.

Only fully accounted, indexed component snapshots can form an atomic default view.
Independent content/BCD revisions and online observation identities are frozen in
that view. Historical pairing requires explicit selection. Offline rebuilding
publishes new derived generations and current views while preserving original
snapshot IDs, including explicitly failing corrupt historical indexes.
If collection is disabled during an upgrade, rebuilding can repair the existing
older-generation default through its own aliases and frozen observations without
renewing validation time or waiting for the new processing generation.

## WHATWG acquisition and research

The WHATWG provider has separate application evidence/configuration contracts and
adapter catalog, Git, inventory, processing, corpus and research modules. It reuses
the mediated Git transport and immutable selected-membership BM25 engine while
keeping provider identities, evidence tables, archive budgets and index roots separate.
Schema 6 adds owner-fenced WHATWG evidence/private state and atomic catalog-view
publication. Existing provider tables, capture identities and behavior are preserved.

Catalog-qualified typed destinations mediate acquisition. Bare Git mirrors are
disposable; retained packs/manifests and observed roots support offline restoration.
Content-addressed inventories and per-section identities share unchanged history.
Raw acquisition, projection, indexing and publication advance through durable
checkpoints; a failed stage does not promote a replacement default.

Publication representations and editable Git revisions have independent identities.
Catalog views freeze per-standard selections, their successful validation observations
and the search reference. Reprocessing changes processing generations rather than
rewriting historical evidence. A fixed first-party subprocess contains PDF parsing;
source-selected programs and build systems are never executed.

WHATWG derived text, sections, symbols, references and ordered/index memberships use
content-addressed PostgreSQL chunks/objects and structurally shared Merkle sequences;
a small manifest identifies each source projection. Schema 6 also maintains exact
aggregate counters transactionally with immutable inserts. Raw publication artifacts
have immutable 4 MiB range proofs so byte pages verify bounded local blocks.

## W3C acquisition and research

Catalog discovery retains immutable page evidence before advancing a versioned
candidate checkpoint. Candidate pages are not research membership. Final catalog
and capture companions precede the catalog pointer update; incomplete discovery
preserves the previous default. The existing evidence/state tables hold these
records, and offline graph verification/migration understands their typed references.

W3C has separate application contracts, source admission, durable state and local
research. Schema 7 adds owner-fenced immutable evidence, processing inventories,
statistics and atomic published views. Existing provider schemas/capture identities
are unchanged. Acquisition I/O remains outside storage transactions; losing the
serving ownership fence fails closed.

A catalog observation records TR identities and version metadata. Qualification
connects publications, editor drafts, repositories and report-specific source paths
to exact official evidence. Current publication work precedes resumable history;
ref movements, catalog removals and failed refreshes preserve earlier captures.
Shared repositories have one mirror and revision-bound per-report inventories.

The private standards-processing engine is shared through a WHATWG compatibility
facade and an independent W3C dispatch/version. W3C adds bounded XML/XHTML and
structured-data projections without expanding WHATWG's dispatch or changing its
serialized output, diagnostics, hashes or processor version. Neither processor
executes upstream content. Search reuses the immutable selected-membership engine.

W3C outbound requests use typed evidence-qualified source descriptors, connection-time
public-address DNS filtering, existing transfer admission and shared host clocks.
License qualification precedes durable body/pack publication. Bounded temporary
preflight cannot create public resources. Catalog metadata and blocked obligations
remain visible when licensing or source mappings are unresolved.

Public tools read published local evidence. Immutable selections and cursors bind
catalog membership, source snapshots, validation observations and index references;
refresh cannot retarget old citations. Rebuild/restoration preserves validation time.
Fallback views identify catalog-latest and effective editions separately. Request-only
audit privacy remains unchanged across resources, storage, logs and errors.

## Chromium documentation corpus

Application Chromium contracts own collection policy and the immutable evidence,
snapshot, view, and storage ports. Provider adapters implement fixed-origin Gitiles,
archived Chrome GitHub API, and current Chrome sitemap/page readers. These feed
owner-fenced schema-8 evidence and durable resumable processing. No whole Chromium
source pack, checkout, dependency traversal, or source-selected executable is needed.

Every retained commit binds ordered parents and a structurally shared documentation
inventory. Tree discovery includes historical deletions; caches bind classifier/path
context. Versioned inert projections and selected-membership search remain isolated
from earlier providers. Chromium-specific link handling does not relax the shared
standards parser's existing behavior. Raw acquisition, processing, indexing, and
publication have separate failure/coverage states.

Collection generation 2 keys traversal work, derived inventories, snapshots and
aliases independently of unchanged projection/classifier version 1. Old work and
pinned snapshots remain retained. Exact Git-tree identity validation precedes
operation-safe path admission; unsupported acquisition paths have durable gap
evidence and cannot trigger outbound requests. Proven classifier exclusions avoid
descending unrelated test/vendor/generated trees. A failed component does not
prevent another qualified component from forming a usable default.

Current and historical lanes share source admission and publication fencing. Partial
views freeze each effective component snapshot and validation observation. Archived
Chrome sources and current website observations remain distinct identities and
licenses. Public APIs read local published evidence; maintenance replays retained
inputs without renewing online observations. See [Chromium](chromium.md).

## Bounded foreground research

HTTP admission waits for the existing four-message buffer reservation within the
input timeout. Waiting and body collection share one deadline; request permits
bound queued work. Memory ceilings and response limits remain unchanged. The
connection watchdog covers the selected tool timeout and I/O allowance. Private
aggregate counters distinguish admission expiry from
application failures without recording request data.

Generic search defaults to all nine source families, validates its complete source
selection before dispatch, keeps at most two source futures active, and returns
results in requested source order. Its default 75-second tool budget permits four
15-second waves; other tools retain their 30-second default. Explicit selections
retain their requested order and provider-specific search behavior.
Each source has at most fifteen seconds, bounded by the caller's absolute deadline
minus the smaller of one second and ten percent of the remaining budget. Completed
sources survive another source's failure; expired or unstarted sources have explicit
errors. Cancellation drops request-owned futures and preserves provider retry and
admission ownership. Source errors do not establish an empty or complete corpus.
Dropping a source future does not forcibly stop a blocking worker; existing worker
deadlines, cancellation checks and owned resource reservations remain in force.

Foreground npm reads validate full retained registry metadata with a bounded scan
while materializing one release at a time. Unselected releases retain identity,
declaration and duplicate-key validation. Selected metadata, tags and timestamp
projections remain charged during the scan; input, nesting, time and output limits
remain independent. Collector inventory parsing retains its existing behavior.

MDN search bounds selection, membership preparation and index work together.
Verified immutable projection memberships can be shared across requests, with
bounded entries, bytes and identifiers. Active readers retain budget accounting
after eviction. Default selection and freshness are checked through owner-fenced
storage for every request; verification handles bypass the cache.


## Optional S3 archive and schema 13

Filesystem publication retains the existing fsync/hardlink contract.
The archive layout introduced in schema 12 retains its immutable format. Schema 13
marks the required reader/writer topology for both backends; filesystem remains
the default. The adapter-owned durable archive mediates permanent file
publication and leased local materialization; application/domain ports remain free
of transport-specific types. PostgreSQL remains authoritative for metadata,
ordering, ownership and immutable logical file bindings. A process-local root
registry is installed only after explicit backend admission; expired S3 handles
fail closed.

Remote BLAKE3 byte objects and path-bound integrity evidence precede owner-fenced
SQL publication. Frozen index members publish before their existing final
manifests and database pointers. Each upload has a durable intent; uncertain
completion retains accounting until remote verification resolves it. Restart
reconciles complete bytes/bindings and aborts only owned unfinished multipart
uploads. Completed orphan objects remain permanent.

Backend epochs and an exclusive database/prefix claim prevent accidental reuse
and stale publication. Byte deduplication does not collapse quota identities:
independent equal-byte files remain separate groups; aliases retain their original
group. Fresh groups use monotonic durable identities rather than reusable cache
inode numbers. Local inode mappings establish equivalence only while an alias
still exists. Eviction never releases permanent quota.

Parsers and Tantivy read fully verified local files through leases. Active readers
pin their members; writable staging directories use separate budgeted handles.
The cache is disposable and bounded, and a fresh cache can reconstruct historical
reads from PostgreSQL and S3. Current/supplied package contents remain inert.
No inspected package code, caller lockfile, inventory or audit report enters S3.

Offline transfer verifies the filesystem closure, freezes the exact inventory,
copies/verifies each permanent file, and atomically activates the backend and
transfer receipt. Original files remain intact. Backup receipts bind PostgreSQL,
object bindings, and verified copies at a separate prefix. A failed restore keeps
a database marker that blocks serving until verification succeeds.

Temporary S3 unavailability pauses durable corpus workers through cancellable
supervision. Replacement attempts retain the same provider budgets and checkpoints.
Crate groups fully drain their owned tasks before owner-fenced interrupted-claim
recovery; fatal processing errors still stop supervision. The independent database
ownership monitor remains authoritative for required process restart.


## Reader, writer, and credential boundaries

Serving has a SELECT-only connection pool and its own non-reconnecting lifecycle
session. It does not acquire the exclusive writer-owner lock. Normal readers and
the sole writer share a lifecycle advisory lock; maintenance requires its exclusive
form before the writer lock. Losing either dedicated session is fatal to its
participant even if a connection pool reconnects. Schema 13 rejects older combined
binaries. Reader admission checks active integrity policy, committed backend and
absence of pending restore without migrations or startup writes.

Filesystem readers share an archive mounted read-only and put scratch outside it.
S3 readers attach by verifying the existing store descriptor and backend epoch;
they neither PUT the descriptor nor recover uploads. Each pod owns a disposable
cache with local leases and accounting. Writer-only publication retains existing
intent, conditional write, integrity, quota and immutable-history rules. Reader
construction also restricts the S3 transport to GET/HEAD before transmission,
including when an operator supplies an overly privileged key. This capability
comes from the runtime open mode, not configuration or an asserted IAM role.
Credential CRUD authority does not enable permanent deletion in application code.

Typed private HTTPS operations delegate public source acquisition, RFC errata
bootstrap, and public attribution enqueueing to the writer. The writer reconstructs
trusted source URLs, limits and validators and returns committed identities.
Reader-side parsing and immutable selection continue to use local read ports.
No arbitrary fetch URL, SQL, publication bytes, or whole-tool proxy crosses this
interface. Request-only audits never cross it, including matched advisory subsets
or audit-derived attribution repairs.

The separate credential broker authenticates audience-scoped projected tokens with
TokenReview and live pod/ServiceAccount UID checks. Fixed profiles select provider
applications; distinct pod-bound issuance journals prevent key sharing between
pods. Returned S3 keys are bearer credentials until expiry/revocation. Scaleway's
adapter creates expiring IAM keys; the generic AWS OIDC mode remains separate.
An operator receipt gates provider confinement and TTL acceptance; local policy
mapping alone cannot prove provider enforcement.

The broker has a dedicated PostgreSQL database, a non-reconnecting singleton
session, bounded issuance/revocation records, and authenticated AES-256-GCM
ciphertexts bound to row and identity. Its secrets/journal never enter public
corpus backups or S3 captures. Native Kubernetes Secret encryption protects mounted
issuer/keyring material at rest; application envelope encryption is an additional
boundary, not a replacement. Missing keys, uncertain issuance, invalid receipts,
provider errors, or expired identity fail closed.

## Wikipedia acquisition

The Wikipedia application/store port separates provider freshness and immutable
article identities from concrete REST/SSE adapters. Schema14 adds append-only
sealed captures/snapshots and atomic mutable work/visibility/checkpoint state.
Metadata and article acquisition use typed, fixed destinations; a dedicated SSE
permit does not occupy an article transfer slot. The sole writer owns acquisition,
and serving demand crosses only typed private writer operations. Public article
bytes and attribution reads consult a live moderation overlay independently of
immutable snapshot membership. See [Wikipedia](wikipedia.md).
