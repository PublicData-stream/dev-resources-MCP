# Configuration

Run `devres-server serve CONFIG.toml` and `devres-server collect CONFIG.toml` as
separate serving and writer workloads. The old `devres-server CONFIG.toml`
invocation aliases serving only. Each takes one operator-controlled TOML path.
`refresh-advisories` followed by that path runs private maintenance without starting listeners. Unknown
fields, oversized configuration (over 64 KiB), missing required tables, invalid
limits or access lists fail before serving. Never commit populated credential files.

Required tables are `source`, `http`, `webtransport`, `health`, and `storage`.
`edge_mtls`, `limits`, `rfc`, `crates`, `rustsec`, `mdn`, `whatwg`, `w3c`, `chromium`, `npm`, and `wikipedia` are optional. See the tracked deployment example for values
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
| `storage.blob_dir` | Permanent archive root for filesystem (read-only in serving, writer-owned in collection); private disposable cache per pod for S3 |
| `storage.scratch_dir` | Required writable serving scratch root, separate from and outside `blob_dir` |
| `storage.backend` | `filesystem` by default; optional `s3` backend |
| `edge_mtls.client_ca_file` | CA for authenticated backend edge clients |
| `edge_mtls.required_client_dns_san` | Exact DNS SAN required on the edge client certificate |

A present Origin must match the allowlist. Native clients may omit Origin. Empty
origin lists reject every present Origin. The source URL is advertised, not fetched
or verified by the server; a syntactically valid offer is not evidence that the
corresponding source is actually available.

Attribution repair uses existing per-provider `enabled` settings and source budgets;
it adds no public administration endpoint or configuration table. Disabled providers
make no repair requests. Their retained current qualification remains usable, but
obsolete/missing qualification stays unavailable until repair succeeds. Existing
foreground source access retains its separate collector-setting semantics. Source
freshness and attribution policy versions are independent.

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

Database-dump import caps expanded bytes at 512 GiB, tar members at 1,000, raw and
decoded CSV rows at 2 MiB, selected fields at 1 MiB and columns at 128. Ignored
fields are streamed and validated without retaining their values; they may exceed
1 MiB within the same raw/decoded row bounds. The separate `metadata.json` member
remains limited to 1 MiB. Parsing uses 64 KiB chunks and
bounded batches of at most 1,000 rows/8 MiB through a two-batch queue. Imports have a
24-hour cancellation/deadline budget. Unknown/non-public columns are not projected;
SQL files remain inert archive evidence. Only complete validated imports become
metadata enrichment.

The 8 MiB batch bound includes the complete persisted JSON envelope, escaped
identities, integrity digests and array separators. Import progress describes
staged rows/batches and expanded bytes; it is not published metadata or a completion
percentage. Retrying the same retained dump replays bounded gzip/tar validation
and idempotent staging, without exposing partial enrichment.
New imports use a capture-bound `crates-dump-v2` derivation. Existing snapshots
retain their original v1 enrichment; reprocessing never overwrites those rows.

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
| `search_timeout_secs` | 75 |
| `idle_timeout_secs` | 120 |
| `shutdown_timeout_secs` | 15 |

`search_timeout_secs` applies only to generic `search`; other tools and resource
reads use `call_timeout_secs`. Generic search keeps at most two source operations
active and caps each at 15 seconds, so its default permits five waves across all
nine source families. Completed results survive source-local failures. Cancellation
and shorter deadlines can still interrupt work.

Timeout settings accept 1..86400 seconds. Existing explicit overrides remain valid.
Keep connection idle and edge request/read ceilings above the intended search runtime
with room for I/O; an explicitly shorter idle or edge timeout can interrupt a longer
search. Shipped edge examples use 120-second request/read and WebTransport idle
ceilings. Header/body input and stalled-write timeouts retain `io_timeout_secs`.

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

Run serving separately from the single writer replica. Use Recreate writer updates
and stop both readers and writer before backup or restore. Dedicated database
fences prevent a second writer and exclude maintenance while readers remain;
lost lifecycle or writer ownership requires restart. Size storage for permanent history and retain at least
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

## WHATWG defaults

Omitting `[whatwg]` enables current-first permanent collection, full observed Git
ancestry and resumable historical processing. `enabled=false` pauses scheduling
without removing evidence or local research. Disposable harnesses disable it explicitly.

| `whatwg` field | Default | Meaning |
| --- | --- | --- |
| `enabled` | `true` | Supervised collection and history processing |
| `catalog_refresh_secs` | `3600` | Official catalog validation target |
| `ref_refresh_secs` | `3600` | Approved repository branch/tag observation target |
| `publication_refresh_secs` | `86400` | Moving publication validation target |
| `collection_interval_secs` | `1` | Delay between resumable worker iterations |
| `publication_interval_secs` | `300` | Historical publication batching target |
| `max_processing_workers` | `1` | Processing admission ceiling, accepts 1..2 |
| `max_git_bytes` | `8589934592` | Disposable bare storage per repository, 8 GiB |
| `min_free_bytes` | `1073741824` | Free-space admission reserve, 1 GiB |
| `max_archive_storage_bytes` | omitted | Shared optional quota for permanent WHATWG artifacts |

Interval, Git storage, reserve and quota validation follow the MDN ranges above.
Quota/headroom failures pause acquisition without deleting history. The artifact
quota excludes PostgreSQL projections/counters, disposable mirrors and search indexes;
monitor those separately. Shared GitHub
admission and a separate shared one-attempt/second publication budget include retries.
Intervals are scheduling targets, not provider permission or completion guarantees.

Raw publication intake caps at 32 GiB, separately from 64 MiB textual projection inputs. Token, nesting, record, result and processing
bounds are enforced independently; oversized source remains retained and readable as
byte pages. Derived projections use content-addressed PostgreSQL text chunks, section/symbol/
reference objects and persistent Merkle sequences with small per-source manifests;
each projection memoizes at most 131,072 durable object keys and 8 MiB of key text,
with additional container/allocator overhead, to avoid repeating storage lookups.
reconstruction caps at 256 MiB. Search reuses the immutable selected-membership engine with two
concurrent reader operations, 64 MiB indexing writers and bounded shards/manifests. PDF extraction uses
one fixed helper process with a 1 GiB address-space ceiling and 60-second wall deadline;
original PDFs remain retained when extraction fails or is unsupported.

Schema 6 is forward-only. Coordinated backups include WHATWG raw artifacts, Git
evidence, projections, immutable inventories and search indexes. Serving storage
continues to use the configured persistent directory; test/build state follows the
isolated `/tmp` workflow in [Operations](operations.md).
Corpus status labels gap totals as covering all retained snapshot generations;
processor upgrades preserve earlier gaps. A full acceptance receipt verifies its
named processor against the frozen source inventory separately.

## W3C defaults

Omitting `[w3c]` enables supervised current-first collection and resumable historical
acquisition. `enabled=false` pauses scheduling without deleting evidence or disabling
local research. Disposable fixture configurations disable collection explicitly.

| `w3c` field | Default | Meaning |
| --- | --- | --- |
| `enabled` | `true` | Current and history collection |
| `catalog_refresh_secs` | `3600` | Official catalog validation target |
| `ref_refresh_secs` | `3600` | Qualified repository ref validation target |
| `publication_refresh_secs` | `86400` | Moving publication validation target |
| `collection_interval_secs` | `1` | Resumable worker iteration delay |
| `publication_interval_secs` | `300` | Historical publication batching target |
| `max_processing_workers` | `1` | Processing admission, accepts 1..2 |
| `max_git_bytes` | `8589934592` | Disposable Git storage per repository |
| `min_free_bytes` | `1073741824` | Free-space admission reserve |
| `max_archive_storage_bytes` | omitted | Optional permanent-artifact quota |

Validation follows the WHATWG interval/storage ranges. W3C acquisition shares one
attempt/second across its family and the existing destination-host clocks, including
GitHub. Retries consume the same budgets. Quota/headroom failures pause work without
removing history; the quota excludes PostgreSQL, indexes and disposable mirrors.
Intervals and conservative budgets are application policy, not provider permission
or completion guarantees.

Text input caps at 64 MiB and processing at 15 seconds/100,000 items. New structural
projections cap input at 4 MiB, nesting at 64 and individual scalars/cells at 64 KiB;
larger supported text falls back to source-text projection with a coverage gap.
PDF worker and paged reconstruction bounds match WHATWG. Raw intake retains its
separate streaming byte limit; public pages remain at most 32 KiB.

Schema 7 is forward-only. Back up W3C raw captures, qualified Git history,
projections, inventories, state and search indexes together. Reprocessing and
restoration never advance upstream validation. Unknown-license content is metadata
only until its scope is established, including mixed historical Git packs.

Catalog discovery checkpoints one API page per normal current turn. Committed
pages are reused after restart, within the unchanged 8 MiB/page, 1,000-page and
10,000-standard bounds. Only the complete validated candidate replaces the catalog;
its freshness remains the oldest page observation. Failed refresh preserves the
preceding catalog/default and the normal retry delay.

## Chromium defaults

Omitting `[chromium]` enables current-first collection and resumable historical
document discovery. `enabled=false` pauses collection while retained research stays
available. Disposable configurations explicitly disable the collector.

| `chromium` field | Default | Meaning |
| --- | --- | --- |
| `enabled` | `true` | Supervised current/history collection |
| `catalog_refresh_secs` | `3600` | Catalog validation scheduling target |
| `ref_refresh_secs` | `3600` | Fixed source ref observation target |
| `publication_refresh_secs` | `86400` | Moving website inventory/body validation target |
| `collection_interval_secs` | `1` | Delay between bounded processing slices |
| `publication_interval_secs` | `300` | Historical publication batching target |
| `max_processing_workers` | `1` | Processing admission, accepts 1..2 |
| `min_free_bytes` | `1073741824` | Free-space reserve, minimum 64 MiB |
| `max_archive_storage_bytes` | omitted | Optional permanent raw-artifact quota |

Intervals accept 1..31,622,400 seconds. A supplied archive quota must be at least the
free-space reserve. The quota excludes PostgreSQL and derived search data. Exhausted
quota/headroom pauses acquisition without deleting retained evidence.

Documentation-only acquisition does not maintain a full Chromium Git mirror.
Chromium requests share one family attempt/second and one transfer, including
retries, coordinated with destination-host clocks. Text projection inputs cap at
64 MiB and retain existing 15-second parser budgets. Public text/byte pages remain
32 KiB. Discovery and historical queues checkpoint bounded units rather than impose
a fixed total-history cutoff. See [Chromium](chromium.md) for coverage and provenance.

Schema 8 adds isolated Chromium evidence and state. Back up raw artifacts, immutable
inventories/projections, checkpoints, and indexes together. Rebuild/restore does not
advance source validation times.

Chromium collection generation 2 separates traversal accounting from projection
and classifier version 1. Verified trees retain exact Git names; paths that cannot
be fetched safely become explicit traversal gaps without relaxing destination
admission. Subtrees are pruned only when existing classification excludes every
descendant. Prior snapshots/work remain retained; new traversal starts from the
same immutable root and reuses verified source/projection evidence where present.

## npm defaults

Omitting `[npm]` enables collection with an empty public package catalog and an
independent OSV npm advisory lane. `enabled=false` pauses both lanes while retained
research remains readable. `advisories_enabled=false` pauses only advisory refresh.
Disposable harnesses explicitly disable npm collection. Retrieval and audits never
add packages to the operator catalog.

| `npm` field | Default | Meaning |
| --- | --- | --- |
| `enabled` | `true` | Supervised collection |
| `packages` | `[]` | Exact public scoped/unscoped package names |
| `advisories_enabled` | `true` | Independent OSV npm export collection |
| `metadata_refresh_secs` | `3600` | Catalog metadata validation target |
| `advisory_refresh_secs` | `3600` | Advisory export validation target |
| `collection_interval_secs` | `1` | Delay between resumable iterations |
| `publication_interval_secs` | `300` | Research publication batching target |
| `max_processing_workers` | `1` | Processing admission ceiling, 1..2 |
| `registry_requests_per_second` | `1` | Shared foreground/background registry clock |
| `advisory_requests_per_second` | `1` | OSV host clock |
| `min_free_bytes` | `1073741824` | Free-space reserve |
| `max_archive_storage_bytes` | omitted | Optional permanent npm artifact quota |

Intervals accept 1..31,622,400 seconds and rates 1..1,000 attempts/second.
Operators must respect provider policy before changing defaults. The reserve is at
least 64 MiB and a supplied quota must be at least the reserve. Limits pause new
work without removing retained evidence. The artifact quota excludes PostgreSQL
and derived indexes. Schema 9 and processing/privacy limits are described in
[npm](npm.md).


## Optional S3 archive

Existing configurations retain filesystem storage. To store all permanent bodies,
bulk artifacts, retained Git evidence, integrity descriptors, and frozen search
files remotely, select `storage.backend = "s3"` and supply `[storage.s3]`.
PostgreSQL remains required. One writer owns durable publication; serving runs
separately with SELECT-only database access and read-only archive credentials.
Use Recreate updates for the writer. Public tool schemas, capture identities, freshness, source
budgets, licensing, and request-only audit privacy are unchanged.

```toml
[storage]
database_url = "postgres://USER:PASSWORD@postgres/devres"
blob_dir = "/data/blobs"
backend = "s3"

[storage.s3]
endpoint = "https://objects.example.org"
bucket = "devres-archive"
region = "us-east-1"
prefix = "instance-a"
path_style = true
allow_http = false
cache_max_bytes = 68719476736
# ca_file = "/run/secrets/storage-ca.pem"

[storage.s3.credentials]
mode = "files"
access_key_file = "/run/secrets/s3-access-key"
secret_key_file = "/run/secrets/s3-secret-key"
# session_token_file = "/run/secrets/s3-session-token"
```

Endpoint, bucket, region, prefix, cache capacity, and credential mode are required.
The prefix is exclusive to this database; accidental rebinding fails closed.
Path-style addressing defaults to true, plain HTTP defaults to false, and cache
capacity must be at least 64 MiB. Optional `storage_class` accepts `STANDARD` or
`ONEZONE_IA`; omission retains provider defaults. It applies to new single-object
and multipart creation only, never converts existing objects, and has no class
fallback. Production endpoints should use TLS; a custom
CA file adds trust without disabling verification. Plain HTTP requires an explicit
opt-in for the individual controlled private endpoint. URLs reject userinfo,
queries, fragments and redirects. Endpoints and secret paths are operator-only
settings, never public request parameters. Unknown fields fail configuration.

Choose exactly one credential mode. `files` uses the paths above. `oidc` uses
`token_file`, `role_arn`, `session_name`, and `sts_endpoint` to exchange a projected
service-account token. `container` uses `endpoint` and optional
`authorization_token_file`, plus `refresh_before_secs` (default 300, range
1..3600). Container credentials may omit `Token` for expiring provider IAM keys;
expiry is still required. The mounted authorization value is sent verbatim.
Both identity modes support their own optional
`ca_file` and `allow_http` settings. Temporary credentials refresh; failures never
fall through to profiles, instance metadata, external credential commands, or
another identity source. Keep secret values out of TOML and process arguments.

Static Scaleway IAM pairs use the existing `files` mode with separate serving
read-only and writer read/write key files. The optional production deployment
profile, permission templates, restart-based rotation, and acceptance gates are
documented in the [static Scaleway example](../deploy/examples/scaleway-static/README.md).
Changing authentication alone preserves the exact existing archive binding;
static keys do not inherit broker lease expiry or automatic revocation.

The local cache must fit pinned search generations, admitted downloads, and
managed staging. Eviction removes only disposable, unleased materializations.
An oversized working set fails explicitly; public reads retain existing deadlines
and limits. Mutable Git working repositories keep their separate provider byte
limits and free-space reserves. Remote storage has no portable free-space API:
archive quotas retain existing accounting groups and survive cache loss; remote
service quota failures reject new work without deleting history. Operator billing
bytes can differ from these admission quotas because of content deduplication.

S3 requires conditional single-object and multipart-completion writes, streamed
verified reads, and multipart inspection/abort for interrupted application-owned
uploads. No unconditional overwrite fallback or permanent-object deletion is
used. Bucket encryption, replication, object lock, and retention are operator
policies. Storage/credential outages fail closed even with a warm cache and set
readiness false; recovery restores readiness. Losing database ownership requires
restart. See [offline transfer and recovery](operations.md#s3-transfer-and-recovery).

The local materialization registry admits at most 262,144 resident paths. Its
startup reconciliation caps the local walk at 1,048,576 entries, depth 128 and
30 seconds. Explicit S3 artifact quotas admit at most 1,000,000 accounting objects
per shared quota; exceeding these bookkeeping bounds returns capacity errors.
Omitting an optional archive quota does not impose that accounting-object limit
on permanent retention. These bounds are separate from measured process RSS.

Automatic S3 initialization is restricted to a newly initialized database. An
existing filesystem database requires explicit offline transfer even if its
capture table or the selected local directory is empty; selecting a new directory
cannot bypass retained provider data. After cutover, use a separate disposable
cache directory; the migrated source directory is protected from cache eviction.


## Split runtime and credential broker

The split is required for both filesystem and S3. `serve` requires `[writer_client]`
with an explicit HTTPS `/v1/acquire` `endpoint`, absolute `token_file`, and optional
`ca_file`. `collect` requires `[writer_listener]` with `bind`, TLS `certificate` and
`private_key`, `allowed_clients` namespace/service-account pairs, and `[writer_listener.auth]`
Kubernetes API/token/CA/audience settings. The writer exposes private acquisition
and health only; serving owns public MCP and request-only audit computation.
Public selectors, freshness, result limits, and capture-fixed reads are unchanged.

Serving uses SELECT-only PostgreSQL credentials, has no writer-owner lock, and
runs no migration, stage recovery, or collectors. The sole writer initializes and
publishes schema 16 for either backend, including RFC job diagnostics. Existing configuration values and backend
defaults remain; operators must add the role-specific client/listener/scratch
settings and deploy both processes. See the [operator templates](../deploy/examples/scaleway-credential-broker/README.md).

`devres-credential-broker BROKER.toml` serves private HTTPS `/v1/credentials` and
`/healthz`. It maps verified live pod identity to operator profiles; requests cannot
choose role or object scope. Profiles bind namespace/service account, Scaleway
application/project, bucket/prefix, `readonly` or `readwrite`, and admitted policy
digest. Scaleway mode issues expiring IAM API keys, rather than an AWS STS session.
The existing `container` source consumes their key pair and expiry. No broker
identity or credential API is a public MCP tool or edge route.

Broker configuration requires an explicit `organization_id` UUID in every mode,
including fixtures and offline fingerprint commands. It scopes Scaleway API-key
listing and is separate from each profile's `default_project_id`; no organization
lookup is performed. Missing or malformed values fail before network access.
Changing this startup identity during reload fails closed and requires a restart.
The receipt and journal formats are unchanged; they do not add a persistent
organization binding across restarts.

Defaults are `ttl_secs=900`, `refresh_before_secs=300`, `max_pods=16`,
`max_issued_keys=32`, and `quota_reserve=8`. The config names only mounted secret
paths for issuer secret, encryption keyring, and a dedicated per-cluster broker
database URL. The broker pins the trusted API's `kube-system` namespace UID in that
journal; cross-cluster reuse and nonempty unbound journals fail closed. Its RBAC
requires GET for that one Namespace in addition to TokenReview and live identity
reads. Project broker-audience tokens for 3600 seconds to support the default
900-second leases, which are capped at JWT expiry minus five seconds.
An unexpired operator acceptance receipt binds issuer identity and secret fingerprint, exact profiles,
TTL, quota, expiry acceptance, and negative privilege tests. Fixture receipts
cannot authorize production mode. Native cluster Secret encryption is a deployment
prerequisite in addition to authenticated journal encryption. Full configuration,
policy templates, receipt bootstrap, and rotation are documented with the examples.

## Wikipedia defaults

Omitting `[wikipedia]` retains recursive English STEM collection defaults, but
network acquisition requires an explicit operator `user_agent`. `enabled=false`
pauses background acquisition while retaining local evidence. See
[Wikipedia](wikipedia.md) for API policies, intervals and acceptance boundaries.

```toml
[wikipedia]
user_agent = "ExampleBot/1.0 (https://example.org/bot; operator@example.org)"
# Optional operator-provided OAuth2 access token; never put token bytes in TOML.
# oauth2_token_file = "/run/secrets/wikipedia-oauth2-token"
```

There is no built-in Wikipedia User-Agent fallback. A supplied value must contain
an HTTP product/version and a parenthesized contact URL, email address, or
`wikipedia:en; User:Example` identity. It must be printable ASCII and at most 1024
bytes. Invalid supplied values fail configuration validation. Without a value,
startup and eligible local reads remain available; writer acquisition, upstream
discovery, and EventStreams remain paused with `wikipedia_configuration_required`.
Reader processes can delegate acquisition to a configured writer without their
own Wikipedia identity.

`oauth2_token_file` is optional and must be an absolute path. Only the writer
reads the mounted file at startup: at most 16 KiB, with an optional trailing line
ending and no embedded whitespace. Unreadable or invalid configured files fail
writer startup with sanitized errors; readers do not open this file. Omit it for
anonymous API requests. The token is sent only to the fixed Wikipedia API origin,
never EventStreams or other providers. Token acquisition/refresh is external;
rotation or recovery from an authenticated 401/403 requires writer restart. Keep
the file in a runtime Secret and never commit populated credentials.

`category_roots` defaults to the six `Category:` roots Science, Technology,
Engineering, Mathematics, Artificial intelligence and Computer architecture;
`excluded_categories=[]` prunes configured categories. There is no default depth
cutoff. Both category roots (max100) and exclusions (max1000) require category names.

`normal_debounce_secs=300`, `normal_min_refresh_secs=300`,
`normal_fallback_secs=86400`; `current_debounce_secs=30`,
`current_min_refresh_secs=60`, `current_fallback_secs=300`.
`category_reconcile_secs=86400`, `collection_interval_secs=1`,
`publication_interval_secs=300`. Intervals accept 1..31622400 seconds and do not
bypass upstream cache freshness or provider cooldowns. Unknown Current state uses
the Current profile. `requests_per_second=1` accepts 1..3, under shared admission.
`min_free_bytes=1073741824` (minimum64MiB); optional
`max_archive_storage_bytes` must cover the free-space reserve. Quotas pause new
acquisition without deleting permanent bodies. Article representations cap at16MiB;
public text pages remain at most32KiB. Reader attachment requires schema16.
