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
owners release their work; there are no detached background refreshes. A waiter can
become the next owner. The HTTPS adapter alone owns bounded retry and throttling.

The store takes a PostgreSQL session advisory lock at startup and rejects a second
serving owner. The owner connection never reconnects; losing ownership fails storage
operations until restart. Deployment must use one replica and Recreate updates.
PostgreSQL stores immutable representation records, mutable source heads, and
append-only successful-fetch/revalidation observations. Schema version starts at 1.

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

## Privacy and isolation

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
