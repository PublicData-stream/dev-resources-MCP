# Private provider diagnosis

`devres-server diagnose-collection` inspects existing evidence without starting
collectors or listeners, acquiring writer authority, or making provider requests.
Supply reader-only database/S3 credentials through a private configuration file.
Neither configuration nor arbitrary upstream text enters the report. This command
supports active schemas 14 through 18 so diagnosis can precede a rollout.

```sh
devres-server diagnose-collection /etc/devres/reader.toml \
  --provider w3c --latest-failure \
  --max-total-bytes 67108864 --timeout-secs 300 \
  --output /tmp/devres-provider-diagnosis/w3c.json
```

The output parent must be a private directory owned by the current user below
`/tmp`; the command can create that final directory, but never replaces a report.
Directory/file permissions are 0700/0600. Symlinks and traversal are rejected.
Console output contains fixed outcome metadata and counts, never evidence bodies.

The default and maximum metadata/evidence budget is 64 MiB and five minutes.
SQL payloads are size-admitted before loading and checked with existing payload
and occurrence seals. Inspection freezes a sequence cutoff, selects only the
latest failure and referenced candidate pages, and verifies their ancestry.
S3 reads check committed archive bindings and object identities without attaching
the archive cache. Filesystem reads never materialize remote objects. Reports
are limited to 1 MiB and contain closed classifications and public evidence IDs.
Cooperative byte/time budget exhaustion and unavailable attempted bytes produce
explicit incomplete outcomes. If initialization cannot finish or a dependency
cannot stop before the hard deadline, the command instead returns a typed error
and leaves no completed report; an already-created output file can be empty.
An incomplete report does not establish parser compatibility or corpus integrity.

## Selected MDN metadata

Inspect retained MDN heads and pinned history without cloning, reconstructing Git
state, starting collectors or opening serving caches:

```sh
devres-server diagnose-collection /etc/devres/reader.toml \
  --provider mdn --latest-failure \
  --max-total-bytes 67108864 --timeout-secs 300 \
  --output /tmp/devres-mdn-diagnosis/report.json
```

MDN accepts no commit, snapshot, representation-job, attribution-target or dump-scan
selectors. The report freezes the database evidence cutoff and selects at most two
main work records, two pinned history observations, pending count, index/checkpoint,
main prepared/published bindings and default view. It verifies admitted metadata
seals and selected aliases. Selected commit-order artifacts are checked against
their retained digest and byte descriptor, including cursor bounds and newline
boundaries. The existing aggregate byte/time budget applies to the whole command;
missing evidence or exhausted admission produces an explicit incomplete result.

Metadata and cursor verification do not establish index-engine readability,
complete inventory membership, attribution qualification or current source
acceptance. Output contains finite classifications, validated public identities,
counts and timestamps, never source bodies, paths or arbitrary error text. It does
not enqueue repairs or refresh source validation times.

New collection attempts retain private finite phase and outcome records separate
from source evidence. Legacy attempts without these records remain
`legacy_unknown`. Last failure and last successful durable work are separate:
an idle tick, yielded inventory slice or another operation's success cannot resolve
the failure. Committed checkpoints update progress; incomplete slices do not
advance the last completed collection/publication success. Saved activity alone
does not establish that a worker remains active.
If storage prevents recording diagnostics, exact phase evidence may be unavailable;
the original operation failure remains authoritative.

Use frozen evidence to reproduce a selected failure before changing a parser,
storage path, attribution mapping or scheduling policy. A missing default alone
does not justify rebuilding indexes, resetting history or increasing concurrency.
Production diagnosis and later maintenance or deployment are separate actions.

## Selected RustSec metadata

RustSec inspection reads the retained current/history states and both default
descriptors. Optional selectors add exactly one commit's latest visible processing
generation and one exact attribution target:

```sh
devres-server diagnose-collection /etc/devres/reader.toml \
  --provider rustsec --latest-failure \
  --commit COMMIT_SHA --attribution-target blake3:TARGET_HEX \
  --output /tmp/devres-rustsec-diagnosis/report.json
```

Replace the placeholders with the selected lowercase 40-digit Git revision and
64-digit target hash. Omit either selector when it is not needed. RustSec does not
accept RFC job/snapshot selectors or dump scanning. Inspection freezes the advisory
row cutoff, verifies descriptor/capture/occurrence seals and legacy alias bindings,
and reports at most two projection-gap samples per format. It never reads member
bodies, reconstructs Git state, opens serving caches, queues repairs or calls a
provider. Descriptor verification does not prove membership bytes, qualification,
fresh acquisition or complete historical format support.

New writer attempts retain finite stage/failure and exact public capture references
in private `diagnostics-current` and `diagnostics-history` state. These records are
excluded from public status and attribution enumeration. Legacy attempts without
this linkage remain `legacy_unknown`; no cause is inferred from `unavailable`.
Resolution of a history failure requires successful execution of its own stage
and checkpoint. An idle/backoff tick or successful local projection cannot resolve
a remote synchronization failure. Historical unsupported TOML and placeholder
advisories remain retained projection gaps; their presence does not make OSV
coverage incomplete when that independent representation is complete.

For current publication, the default and successful attempt are committed together.
An ambiguous commit response is reconciled through the exact writer session and
sealed attempt, never by default equality alone. Until its outcome is known, no
replacement source attempt is started. Existing public status retains its shape;
private reports contain no raw response, arbitrary URL, configuration or audit data.

Use `--provider chromium` for the component/lane collector states and latest
private validation observation. These observations contain operation/reason,
digest/size, and validated Git IDs. Rejected blob contents are not retained;
an observation alone cannot replay their parser. Public MCP diagnostics retain
their existing phase/limit/HTTP-status schema.

Use `--provider crates` to identify the existing database-dump capture. Explicit
`--scan-retained-dump` allows one legacy-admission diagnostic pass, without
staging or publishing enrichment. The scan caps the artifact at 4 GiB compressed,
expansion at 8 GiB, and the whole operation at thirty minutes. It stops at the
first rejection and reports only a fixed table, numeric row/column, selection
flag, and finite reason/limits. A local prefix scan does not reverify the complete
artifact. A cold S3 object may be downloaded once into private disposable `/tmp`
storage and fully digest-checked before parsing. No provider dump is downloaded.

For missing parser bytes, separately authorized fixed-operation probes must use
the existing broker destination policy and retained attempt accounting. Count
all attempts against the shared twenty-request per-provider ceiling. Chromium's
`chromium-live-probe --diagnose-validation OWNED_ROOT --component src` checks refs,
selected commit metadata and root tree for one component (`src` or `site`). Each
invocation admits at most six attempts, including retries, within the same root's
twenty-attempt total. Five-token Gitiles dates omit their timezone; the collector
verifies the exact raw Git commit object and uses its committer epoch instead of
guessing a zone. That additional bounded request uses the existing host budget
and retry owner. Only safe identities, counts, digests and timestamp proof metadata
are retained. HTTP 500/403 remain acquisition failures with existing retry
ownership; alternative official routes require a separate reviewed decision.

On 2026-11-12, GitHub's repository API identified
[GoogleChrome/developer.chrome.com](https://github.com/GoogleChrome/developer.chrome.com)
as archived. Its [official migration notice](https://github.com/GoogleChrome/developer.chrome.com/blob/main/README.md)
directs current content issues to the migrated site's issue tracker; it does not
identify a replacement public content repository. This supports preserving the
historical-only archive distinction, not substituting it for current Chrome
content. Authenticated connector reads do not prove the anonymous collector can
access GitHub. No replacement route or account credentials are admitted here.

Schema 15 adds immutable crates v2 derivations and private failure evidence.
Selected metadata values and downstream read bounds stay unchanged. Internal snapshot
and index bindings select the exact processor generation; the public enrichment
capture remains the original raw capture. Legacy rows, snapshots and resources
remain retained. Older binaries cannot participate after this schema upgrade;
rollback requires the coordinated pre-upgrade database/blob backup. This document
does not authorize production schema activation or deployment.

For an operator-identified local dump, the standalone `crates-dump-inspect`
example needs no configuration, database or archive client:

```sh
crates-dump-inspect --retained-file /tmp/evidence/BODY_HEX \
  --capture blake3:CAPTURE_HEX --body blake3:BODY_HEX \
  --expected-bytes BYTE_COUNT --measure-first-rejection \
  --output /tmp/devres-dump-diagnosis/report.json
```

Replace the placeholders with validated identities. The file basename must equal
the body digest's hexadecimal part. Without `--measure-first-rejection`, inspection
stops at the first rejection. With it, only that rejected record continues under
the existing 2 MiB raw and decoded row bounds and grammar checks. The report keeps
the original rejection, selected field kind, exact or lower-bound byte counts,
and record completion/validity flags. It never emits field values, stages rows or
changes runtime admission. A stopped prefix scan proves neither the complete
dump's digest nor its gzip trailer, subsequent rows or import completion. Remote
binary transfer and execution require their own explicit operational authority.

## Selected RFC metadata

RFC inspection requires an explicit retained snapshot and one or two distinct,
canonical representation-job keys. Select one failed job and one capture-bearing
job when comparing an acquisition failure with retained evidence:

```sh
devres-server diagnose-collection /etc/devres/reader.toml \
  --provider rfc --snapshot blake3:SNAPSHOT_HEX \
  --job-key rfc:text:5220 --job-key rfc:text:9000 \
  --max-total-bytes 67108864 --timeout-secs 300 \
  --output /tmp/devres-provider-diagnosis/rfc.json
```

Replace `SNAPSHOT_HEX` with the selected 64-digit hexadecimal identity. RFC does
not accept `--latest-failure` or `--scan-retained-dump`. HTTPS TXT keys use
`rfc:text:NUMBER`; other formats use `rfc:format:NUMBER:FORMAT`; rsync jobs retain
`rfc:rsync:NUMBER:FORMAT`. These are separate job identities, not distinct RFCs.

The report checks selected job identity and closed failure metadata, the sealed
snapshot payload, bounded manifest shape, and, for S3, committed SQL bindings
against independent remote binding descriptors. It reads the manifest object,
not the engine member bodies, and reports the number of member bindings checked.
A legacy SHA member digest cannot be equated to a canonical BLAKE3 object binding;
that comparison is explicitly unverified and makes the metadata report incomplete.
Filesystem manifests report shape and a computed digest without claiming remote
binding verification. Neither mode verifies engine/schema readability or member
bytes; these are explicitly `not_checked`, even when metadata inspection completes.

Missing selected jobs/snapshots/bindings, exhausted budgets and invalid integrity
produce finite incomplete outcomes. The transaction is read-only and does not
attach or warm serving caches, acquire writer authority, start collection, request
publication, or enqueue attribution work. Schema 14/15 rows have unknown failure
phases and attempt times; inspection never migrates them or infers a phase from a
coarse error code. Schema 16 adds bounded per-job failure context and claim time;
this does not establish the cause of an older failure or authorize its recovery.
