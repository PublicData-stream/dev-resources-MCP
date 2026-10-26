# Architecture

The domain crate owns source/capture/request/error representations. Application owns
retrieval policy and Store, Fetcher, Clock ports. Adapters implement fixed-source
HTTPS, PostgreSQL/blob persistence, pure source parsers, archive inspection, and
research use cases. The server owns configuration, tool schemas, shared dispatch,
HTTP/WebTransport framing, TLS, and endpoint lifecycle. Concrete adapters depend on
application contracts; application does not import adapters. Parsers never perform
network or filesystem I/O themselves. The small workspace can be split further
when independent dependencies or ownership justify it.

## Retrieval and publication

A trusted provider constructs a bounded FetchRequest with a canonical key and URL.
Application admits work and coalesces requests by key, serves fresh durable cache,
revalidates with HTTP validators, or fetches a new source representation. Upstream
I/O is outside database transactions and application bookkeeping locks. Canceled
owners release their work; request retrieval has no detached refreshes. A waiter can
become the next owner. The HTTPS adapter alone owns bounded retry and throttling.

The store takes a PostgreSQL session advisory lock at startup and rejects a second
serving owner. The owner connection never reconnects; losing ownership fails storage
operations until restart. Deployment must use one replica and Recreate updates.
PostgreSQL stores immutable representation records, mutable source heads, and
append-only successful-fetch/revalidation observations. Schema version 2 adds
owner-fenced RFC datasets, resumable jobs, import observations and research snapshot
manifests. Version 3 adds crate inventories, durable acquisition/processing jobs,
artifact provenance, metadata enrichment, content generations and research snapshots.
Version 4 adds owner-fenced advisory observations, deduplicated representations,
ordered snapshot membership, fixed legacy aliases and resumable Git-history state.
Migrations preserve earlier capture identities; older binaries reject newer schemas.

Blobs use SHA-256 filenames in an operator-owned directory. Publication writes a
unique staging file, fsyncs it, hard-links the immutable object without replacing an
existing object, fsyncs the directory, then commits capture/head/observation records.
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

## RFC corpus

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
