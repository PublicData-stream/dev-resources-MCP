# Exact retained collection recovery under attribution policy 2

Recovery is private offline maintenance, never an MCP tool. The implementation
adds schema 19 and retains policy 2. It does not authorize production application,
source-provider traffic, a generic SQL reset, or publication of unqualified prose.
The failed [91c7bcb7 deployment](../deploy/production/upgrade-91c7bcb7-evidence.md)
remains failed evidence; these tools do not replay its consumed continuation.

## Durable identities and eligibility

Schema 19 adds immutable npm advisory-job versions, immutable recovery admissions,
and a separate fenced recovery-work queue. The job ID is its acquisition snapshot;
versions bind the exact export, processor, cursor, counters and failure context.
Job replacement and history insertion share the primary owner transaction. Terminal
failure context is recorded with that job, independently of optional diagnostics.
Migration retains only the existing current job and does not invent superseded
history or authenticated failure provenance. Include all three tables in reader
SELECT grants, coordinated backups and integrity verification.

`npm-materialization-deadline-v1` accepts only an exact terminal advisory job with
an authenticated `capacity / materialization / deadline` cause, a compatible
processor (v1 is permanently pinned to processor 1), intact export and verified
committed prefix. A later live scanner requires explicit retained recipe dispatch;
historical journal verification does not follow the live processor constant. Unknown legacy capacity,
missing historical state, integrity/processing/bounds failures, changed evidence,
active participants or ambiguous publication are ineligible. An operator-supplied
cause string, latest diagnostic timestamp or matching artifact hash is insufficient.
The incident's legacy-unknown npm report therefore does not establish eligibility.

Superseded retained jobs can be selected without replacing the current job. Apply
adds a separate recovery operation. Run scans only its exact retained export,
continues its own cursor, and reconciles deterministic partially retained member
writes. It never acquires a newer export or updates acquisition validators. Its
historical publication performs normal membership/integrity/readiness checks but
never promotes `default-advisories` or modifies the newer current job. Snapshot
publication and recovery completion commit together. Select the resulting explicit
snapshot for readback; a newer default is not evidence of historical recovery.

## Private command workflow

Use reader credentials for inspection and writer credentials only for separately
admitted offline changes. Apply/run additionally require offline operator authority
to execute `pg_control_system()` for the checkpoint identity check; runtime database
roles need not be expanded. Configuration supplies credentials; commands never take
provider URLs or passwords. Every invocation selects one exact job/version. All
local inputs and reports require owned private directories below `/tmp`, regular
files, restrictive permissions and no symlink ancestors. Reports are create-new,
mode 0600, bounded to 1 MiB and contain no evidence bodies or request-only inputs.

```sh
devres-server recover-collection verify-evidence /etc/devres/reader.toml \
  --provider npm --job-id blake3:JOB_HEX --revision REVISION \
  --recipe npm-materialization-deadline-v1 \
  --artifact /tmp/recovery/export.zip --output /tmp/recovery/evidence.json

devres-server recover-collection dry-run /etc/devres/reader.toml \
  --provider npm --job-id blake3:JOB_HEX --revision REVISION \
  --recipe npm-materialization-deadline-v1 \
  --evidence /tmp/recovery/evidence.json --output /tmp/recovery/proposal.json
```

Replace every placeholder with an exact retained identity. Evidence verification
hashes the entire local export and checks ZIP/cursor/membership under existing
artifact/scanner bounds. It makes no provider requests or serving-cache writes.
The 64-MiB private diagnostic metadata allowance is not the bulk export ceiling.
Dry-run is metadata-only, repeatable-read, and never hydrates bytes or changes work.
An evidence receipt alone is not authority: apply independently verifies the bytes.

Before apply, stop all serving, collection and maintenance participants and obtain
a coordinated database/archive checkpoint with a successful restore rehearsal.
The private checkpoint JSON contains version 1, schema 19, store ID, archive epoch,
PostgreSQL system identifier, `coordinated=true`, and `restoration_verified=true`.
The CLI hashes the exact receipt bytes; optional `receipt_digest` is replaced with
that digest. Apply checks the current database/archive identity and requires the
operator's checkpoint assertions. It does not independently repeat the backup or
restore rehearsal, and supplies no independent S3 bucket-loss guarantee.

```sh
devres-server recover-collection apply /etc/devres/writer.toml \
  --provider npm --job-id blake3:JOB_HEX --revision REVISION \
  --recipe npm-materialization-deadline-v1 \
  --artifact /tmp/recovery/export.zip --evidence /tmp/recovery/evidence.json \
  --expected-state blake3:STATE_HEX --operation-id blake3:OPERATION_HEX \
  --checkpoint /tmp/recovery/checkpoint.json --output /tmp/recovery/admitted.json

devres-server recover-collection run /etc/devres/writer.toml \
  --provider npm --operation-id blake3:OPERATION_HEX \
  --artifact /tmp/recovery/export.zip --output /tmp/recovery/run-1.json
```

Apply rechecks expected state and publication boundaries inside exclusive
lifecycle/publication ownership, atomically recording immutable admission and
queued work. Repeating the exact operation reconciles its journal; a lost commit
response must be reconciled before a different operation is attempted. Run requires
exclusive offline ownership and executes one bounded scanner slice. A yielded
slice may be continued with the same operation and a new report path. Cancellation
preserves committed progress. A transition or yielded receipt does not establish
successful publication or readable notices.

## RFC and errata boundaries

No proved RFC mapping/compiler defect or positive RFC recovery recipe is currently
registered. Exact RFC selection is available through a read-only dry-run:

```sh
devres-server recover-collection dry-run /etc/devres/reader.toml \
  --provider rfc --snapshot blake3:SNAPSHOT_HEX --job-key rfc:text:9000 \
  --attribution-target blake3:TARGET_HEX --output /tmp/recovery/rfc.json
```

The result is explicitly ineligible. Registering a positive recipe requires the
exact faulty branch, retained source/dependency evidence, a regression proving its
correction, complete qualification, unchanged policy/bounds, and independent review.
Pure mapping compilation or an improved error classification is not qualification.
Unknown failures, payload bounds, missing notices and unqualified errata prose
remain blocked. Ordinary due retries and expired claims retain normal writer
ownership; queue progress alone does not prove their content recovered.

The local [errata evidence validator](rfc-errata-qualification-design.md#local-evidence-validation)
checks packaging and exact selected bytes for review. Policy 2 remains active;
complete packaging still has `publication_authorized=false`. No policy 3 promotion,
new destination admission or source acquisition is implemented by this workflow.

## Acceptance

Fixtures must cover schema-18 preservation on upgrade, immutable history/journals,
atomic cause linkage, wrong expected state/recipe/processor, corrupt/missing bytes,
partial member writes, stale ownership, cancellation/restart and lost-commit
reconciliation. Execute a superseded job and read its historical snapshot while
asserting the newer current job/default remain identical. Keep PostgreSQL, archive
cache-loss/restore, IPv4 HTTP/WebTransport and minikube outcomes distinct from
production repair or whole-corpus acceptance. Production application is separate.

### Optional npm assessment phases

For a new, independently admitted assessment helper, npm `dry-run` accepts
`--phase-file /tmp/npm-assessment-phases/status`. The helper creates this separate
private regular file; it does not pre-create the report. Other recovery actions
reject the flag. Finite CLI events distinguish output/configuration, PostgreSQL
admission/selection, and report serialization/write/fsync. Instrumentation failure
preserves the original assessment result. The maintained helper mirrors only
closed events into a File-only kubelet termination record and records the numeric
child exit separately from READY/hold and container termination. Missing telemetry
is unknown evidence, not eligibility or a reason to retry.

An independently admitted npm assessment with a compatible server image can
also pass `--connect-readiness wait`. The CLI uses its configured reader
connection and authentication settings. It gives PostgreSQL startup up to
30 seconds, with up to three seconds per attempt and waits of 250 ms, 500 ms,
one second, and at most two seconds thereafter. Only transient socket failures
and attempt timeouts are retried. The authenticated session runs the assessment
once. The optional diagnostics record the first retryable failure and the final
connection result. The flag is scoped to npm `dry-run`; the default remains a
single connection attempt.

A status-only listener configuration cannot authorize recovery apply/run,
rebuild/import, migration, activation or object-storage maintenance. Use separately
admitted maintenance configuration and credentials outside the paused phase.
