# Configuration

The server takes exactly one operator-controlled TOML path. `refresh-advisories`
followed by that path runs private maintenance without starting listeners. Unknown
fields, oversized configuration (over 64 KiB), missing required tables, invalid
limits or access lists fail before serving. Never commit populated credential files.

Required tables are `source`, `http`, `webtransport`, `health`, and `storage`.
`edge_mtls`, `limits`, `rfc`, `crates`, `rustsec`, and `mdn` are optional. See the tracked deployment example for values
and certificate paths appropriate to the harness; supply your own for hosting.

| Setting | Meaning |
| --- | --- |
| `source.url` | Explicit HTTPS corresponding-source offer for the exact running version; no credentials or control characters |
| `http.bind` | Backend Streamable HTTP socket |
| `http.allowed_hosts`, `http.allowed_origins` | Explicit backend authorities and browser origins |
| `http.tls.certificate`, `http.tls.private_key` | Optional HTTP TLS files; required when edge mTLS is enabled |
| `webtransport.bind` | Backend UDP/QUIC socket |
| `webtransport.certificate`, `webtransport.private_key` | Required TLS certificate and key |
| `webtransport.allowed_hosts`, `webtransport.allowed_origins` | Independent authority/origin allowlists |
| `health.bind` | Private plaintext health/metrics socket |
| `storage.database_url` | PostgreSQL connection string; treat as a secret |
| `storage.blob_dir` | Persistent, exclusively owned archive directory |
| `edge_mtls.client_ca_file` | CA for authenticated backend edge clients |
| `edge_mtls.required_client_dns_san` | Exact DNS SAN required on the edge client certificate |

A present Origin must match the allowlist. Native clients may omit Origin. Empty
origin lists reject every present Origin. The source URL is advertised, not fetched
or verified by the server; a syntactically valid offer is not evidence that the
corresponding source is actually available.

## Resource defaults

The optional `[rfc]` table defaults to automatic permanent corpus collection:

| Setting | Default | Meaning |
| --- | --- | --- |
| `enabled` | `true` | Enable supervised collection; false pauses scheduling across restart, preserving jobs and history |
| `index_refresh_secs` | `86400` | Official metadata refresh interval |
| `errata_refresh_secs` | `86400` | Official errata refresh interval |
| `body_refresh_secs` | `86400` | Conditional representation revalidation interval |
| `collection_interval_secs` | `1` | Minimum delay between worker iterations; does not increase shared provider limits |

Intervals must be 1..31622400 seconds. Catalogue and errata refresh continue while
body sweeps are backlogged. A configured interval is a scheduling target rather than
a freshness guarantee. The shared one-attempt/second HTTPS budget and two-transfer
limit remain in force. Foreground tools remain available when collection is paused.
Disposable harnesses explicitly set `enabled=false`, including bounded live checks.
Existing operator configurations that omit `[rfc]` now collect automatically.

RFC index and errata bodies cap at 64 MiB; each document representation and derived
text caps at 16 MiB. Catalogue parsing caps at 50,000 RFCs. Search has one 64 MiB
indexing writer and at most two readers; the writer budget is not a process RSS limit.
Individual tokens must be shorter than 65,530 bytes. Indexes cap at 32 GiB and
10,000 files with a 2 MiB integrity manifest. Processing budget failures are explicit
coverage gaps. Parsing/search workers check 15-second budgets; individual search
engine operations are not preemptible. No full-corpus capacity benchmark is implied.

Errata JSON is streamed with at most 50,000 records, 256 KiB per raw record,
64 top-level fields and bounded nested structure. Unsupported advertised formats
remain visible in metadata and coverage rather than being counted as captured.
HTML extraction feeds 4 KiB chunks, limits unfinished tokens to 16 KiB, attributes
to 128 per tag, nesting to 256, tags to 200,000 and tokens to 500,000. These are
explicit rejection boundaries; scripts, styles and external resources are inert.

## Crate corpus defaults

Omitting `[crates]` enables automatic registry/archive/docs.rs collection. Set
`enabled = false` to pause scheduling while preserving evidence and local research.
Disposable harnesses explicitly disable both collectors. Existing configurations
that omit this table begin crate collection after upgrade.

| `crates` field | Default | Meaning |
| --- | --- | --- |
| `enabled` | `true` | Supervised permanent collection |
| `index_refresh_secs` | `3600` | Incremental official Git-index synchronization |
| `metadata_refresh_secs` | `86400` | Public crates.io database-dump refresh |
| `documentation_refresh_secs` | `86400` | docs.rs representation revalidation |
| `collection_interval_secs` | `1` | Worker iteration delay, separate from provider budgets |
| `publication_interval_secs` | `300` | Research snapshot publication target |
| `static_requests_per_second` | `5` | Shared static.crates.io admission, including foreground archives |
| `index_requests_per_second` | `1` | Shared official Git-index/sparse-index admission |
| `max_bulk_transfers` | `4` | Bulk transfer bound; foreground tools retain two independent slots |
| `max_processing_workers` | `1` | Separate source/docs projection admission; accepts 1..2 |
| `max_artifact_bytes` | `34359738368` | Maximum individual archive/docs/dump bulk HTTP body; 32 GiB |
| `min_free_bytes` | `1073741824` | Free-space reserve for new retained artifacts |
| `max_archive_storage_bytes` | omitted | Optional retained artifact quota; omission has no quota |
| `max_git_bytes` | `68719476736` | Disposable bare-index storage bound |

Intervals accept 1..31622400 seconds, static/index admission accepts 1..1000 attempts
per second, bulk transfers accept 1..32, projection workers accept 1..2, individual
artifact limits accept 1 MiB..32 GiB, and reserved space must be at least 64 MiB. A set
artifact quota must be at least the reserve. Git storage accepts 1 MiB..128 GiB.
A quota or free-space failure pauses admission; it never deletes permanent history.
Operators must review provider policy and actual capacity before increasing limits.
The default rate does not establish permission for bulk mirroring or a completion
schedule. docs.rs/API hosts remain at one attempt per second. docs.rs also has a
single transfer slot across both foreground and bulk admission.

Git synchronization has a one-hour process budget, at most 10,000 evidence files
and 10,000,000 enumerated records. Each sparse-index crate body caps at 16 MiB,
50,000 version records and 1 MiB per record, with a processing deadline. Bounds or
unsupported records are inventory gaps, not fabricated version metadata.

Bulk artifacts stream to bounded staging files rather than the public capture-body
read budget; one artifact defaults to 32 GiB and can be lowered with
`max_artifact_bytes`. This intake setting does not raise inspection limits.
Source and HTML ZIP inspection still cap
compressed input at 32 MiB, expanded input at 256 MiB, members at 20,000 and a selected
source/HTML file at 4 MiB. Oversized raw captures remain retained with processing
coverage. ZIP parsing admits Stored/Deflate/BZIP2 only, without extraction, links or
encryption. JSON expansion caps at 256 MiB, each index item at 1 MiB, index entries at
1,000,000 and nesting at 64. Public-path graph/traversal accounting each caps at
64 MiB, normalized signatures at 1 MiB and processing at 15 seconds. The platform
fragment caps at 1 MiB and 1,000 targets.

Database-dump import caps expanded bytes at 512 GiB, tar members at 1,000, raw CSV
rows at 2 MiB, fields at 1 MiB and columns at 128. Parsing uses 64 KiB chunks and
bounded batches of at most 1,000 rows/8 MiB through a two-batch queue. Imports have a
24-hour cancellation/deadline budget. Unknown/non-public columns are not projected;
SQL files remain inert archive evidence. Only complete validated imports become
metadata enrichment.

Crate search uses one writer with a 64 MiB per-thread indexing budget, immutable
shards of at most 50,000 documents, at most 4,096 shards and 10,000 files/32 GiB per
shard, with a 2 MiB integrity manifest. These are processing limits, not process RSS
or whole-corpus capacity measurements. Unsupported tokens and bounded processing
failures remain explicit search gaps; they do not discard retained source bodies.

## RustSec defaults

Omitting `[rustsec]` enables supervised current-advisory collection and full Git
history processing. `enabled=false` pauses both lanes without deleting retained
evidence; local research and bounded legacy-capture recovery remain available.
Disposable harnesses explicitly disable this collector too. Existing configurations
that omit this table begin RustSec collection after upgrade.

| `rustsec` field | Default | Meaning |
| --- | --- | --- |
| `enabled` | `true` | Supervised collection and history processing |
| `current_refresh_secs` | `3600` | Official main head/archive revalidation target |
| `history_refresh_secs` | `86400` | Full official branch/tag synchronization target |
| `collection_interval_secs` | `1` | Delay between resumable worker iterations |
| `max_git_bytes` | `8589934592` | Disposable bare repository bound, 8 GiB |
| `min_free_bytes` | `1073741824` | Free-space reserve for history acquisition |
| `max_archive_storage_bytes` | omitted | Optional quota for permanent Git-history artifacts |

Intervals accept 1..31622400 seconds; Git storage accepts 1 MiB..128 GiB. The reserve
must be at least 64 MiB; a configured artifact quota must be at least the reserve.
This history-artifact quota excludes PostgreSQL projections and current generic
head/archive captures, which retain their existing storage accounting. Limits pause
new work and never authorize deletion of permanent evidence.

RustSec Git attempts use at most one attempt/second on the shared GitHub host clock,
including retries. History runs one processing worker, with up to 1,000 commits or
15 seconds per iteration and resumable member checkpoints. Git acquisition has a
one-hour budget; manifests cap at 4 MiB, advertised refs at 10,000, commits at
1,000,000 and tree members at 100,000. Advisory records cap at 1 MiB each and 64 MiB
per representation snapshot, with at most 20,000 retained records. Advisory
history queries process at most 100 parents per merge; larger requests fail with
capacity rather than omitting parents. Research admits two concurrent snapshot
readers and bounds cursor tokens to 16 KiB. Raw Git retention and successful projection are
separate coverage states. No full-corpus capacity benchmark is implied.

## Request and storage limits

| `limits` field | Default |
| --- | --- |
| `max_message_bytes` | 8 MiB |
| `max_tool_result_bytes` | 256 KiB |
| `max_buffer_bytes` | 64 MiB |
| `max_in_flight` | 32 |
| `max_connections` | 128 |
| `max_calls_per_connection` | 8 |
| `io_timeout_secs` | 10 |
| `call_timeout_secs` | 30 |
| `idle_timeout_secs` | 60 |
| `shutdown_timeout_secs` | 15 |

`limits.rate_limit` defaults to enabled with 100 calls/second and burst 100.
An optional `verified_tunnel` calls-per-second/burst override requires edge mTLS.
These limits regulate callers, not provider traffic. Upstream attempts have their
own source-specific host budgets. Existing foreground retrieval retains a
two-transfer bound; private crate acquisition has its separately configured bulk
slots and shares the same host clocks. See crate defaults above.

Zero/invalid limits fail startup. Messages are at most 16 MiB; tool output must
fit at most one eighth of the configured message size. Buffer capacity must be at
least four message sizes. Increasing limits must be accompanied by resource and
acceptance review; transport buffer accounting does not measure total process RSS.

Capture bodies also share a separate 128 MiB read budget, retained through
projection and cheap shared clones; it does not count the entire process heap.
Source archive inspection caps compressed data at 32 MiB, expanded data at 256 MiB,
member count at 20,000, and selected file content at 4 MiB, with a parsing deadline.
Text output remains paged to 32 KiB. Supplied lockfiles cap at 1 MiB and 10,000
packages. These are explicit rejection boundaries, not silent truncation rules.

Run one serving replica. Use Recreate updates and stop all writers before backup
or restore. A dedicated database ownership fence prevents a second server; lost
ownership requires restart. Size storage for permanent history and retain at least
64 MiB of free blob headroom. See [Operations](operations.md).

## MDN defaults

Omitting `[mdn]` enables permanent collection and complete advertised branch/tag
ancestry processing for both official repositories. `enabled=false` pauses
scheduling while preserving local research and all evidence. Disposable and bounded
live harnesses explicitly disable MDN as well as the existing collectors.

| `mdn` field | Default | Meaning |
| --- | --- | --- |
| `enabled` | `true` | Supervised current collection and history processing |
| `ref_refresh_secs` | `3600` | Official branch/tag observation target |
| `collection_interval_secs` | `1` | Delay between resumable iterations |
| `publication_interval_secs` | `300` | Historical snapshot/index publication target; current main has priority |
| `max_processing_workers` | `1` | Processing admission ceiling, accepts 1..2; inventory/publication updates are serialized |
| `max_git_bytes` | `8589934592` | Disposable bare storage per repository, 8 GiB |
| `min_free_bytes` | `1073741824` | Archive/Git admission reserve, 1 GiB |
| `max_archive_storage_bytes` | omitted | Shared optional quota for retained content/compat Git artifacts and raw members |

Intervals accept 1..31622400 seconds, Git storage 1 MiB..128 GiB, and the reserve
must be at least 64 MiB. A quota must be at least the reserve. Shared quota
accounting is reconstructed across all three artifact directories at startup.
The quota excludes PostgreSQL, disposable mirrors and derived indexes; monitor
those separately. Limits stop new admissions without deleting permanent objects.
GitHub attempts retain the existing shared one-attempt/second host budget and
single HTTPS retry owner.

Git operations have a one-hour budget; manifests cap at 4 MiB, observed refs at
10,000, retained roots at 100,000 and reachable commits at 1,000,000. Commit-order
evidence caps at 128 MiB. Read operations check 15-second budgets. Unsupported Git
paths/types are retained with reversible path evidence; symlinks and submodules
are never followed.

Article/BCD projections cap input and expanded text at 4 MiB, front matter at
64 KiB, structured nesting at 64, normalized BCD output at 8 MiB and diagnostics at 256,
macros at 10,000, include depth at 16 and included
members at 128. Processing checks a 15-second budget. Larger raw source remains
retained and readable through typed byte pages. Search uses a 64 MiB writer,
50,000-document immutable shards, at most 4,096 shard generations, and two admitted
readers. Per-shard limits remain 32 GiB/10,000 files with 2 MiB integrity manifests.
Selected snapshot membership caps at 1,000,000 members/64 MiB metadata. These are
rejection boundaries, not measured process RSS or whole-corpus capacity.
Immutable database write groups cap at 1,000 rows/16 MiB and commit under the
existing ownership fence before their inventory/checkpoint pointers advance.
Each private processing slice may cache at most 4,096 verified inventory nodes
with 8 MiB of serialized node/key data. This cache excludes publication state and
does not replace storage fencing on public reads.
Per-entry immutable write staging caps at 1,000 rows/8 MiB. A larger valid row
flushes the queue and uses the existing 16 MiB write-group limit directly. An
entry's inventory root advances only after every staged group commits.

Schema 5 is forward-only. Preserve MDN raw artifacts, retained Git evidence,
projection records, inventories and `mdn-indexes` in coordinated backups.
