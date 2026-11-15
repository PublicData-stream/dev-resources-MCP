# Terminal recovery under attribution policy 2

Design recorded for deployment of `0.1.0-build.91c7bcb7`. This document adds no
recovery command, executable recipe, batch authority or public API. The deployment
keeps schema 18, attribution policy 2, existing resource limits and provider budgets.
Its acceptance is separate from recovery of selected retained data. Existing RFC
or npm gaps remain explicit unless the deployment introduces a regression.

## Existing behavior and eligibility

Attribution targets and source-collection jobs are different state machines. A
successful collector tick, new snapshot or queue transition does not prove a
selected historical capture is readable with complete attribution.

| Selected state or cause | Existing behavior in the target release | Recovery disposition |
| --- | --- | --- |
| Current-policy attribution `pending` or `retry`, with due time reached | The normal sole writer can claim work for enabled providers. | Observe ordinary repair; no rearm. Future retries remain scheduled. |
| Attribution `running` with expired lease | The normal writer can issue a new fenced claim; the previous claim cannot publish. | Observe reclamation and completion, preserving identity and attempts. A live lease is ineligible. |
| Attribution `ready` | Existing qualification and public-read checks apply. | Never reset it to diagnose an archive rejection or unrelated blocked subject. |
| RFC representation job `failed` and due | Ordinary HTTPS collection retries its canonical job key, retaining an earlier capture when present. | Observe the existing collector. A current job head does not replace an explicitly selected historical snapshot or capture. |
| RFC source target `blocked / qualification / invalid_evidence` from an older attempt | Historical state remains unchanged. | Unknown legacy cause is ineligible for automatic reinterpretation. Establish the exact failing branch first. |
| RFC errata copied prose without its exact applicable notice dependency | New attempts classify `qualification / unqualified_scope / blocked`; content remains withheld. | Ineligible under this design. Classification repair does not qualify rights or rearm historical rows. |
| RFC dataset target `blocked / mapping / payload_bound` | Retained oversized evidence remains blocked under the unchanged bounds. | Ineligible. A different ready source target does not remove this bound; do not split, truncate or raise limits as recovery. |
| Other RFC `blocked` mapping or qualification target | Public enqueue preserves status and only increases priority. | Candidate for future design only if a reviewed exact recipe can prove support under policy 2 with unchanged subject/evidence and bounds. |
| npm advisory job unfinished, with a newly validated `capacity / materialization / deadline` failure | Existing transient retry preserves the retained artifact and committed cursor. | Observe ordinary resumption after its due time; no job reset or export reacquisition as a retry shortcut. |
| npm advisory job terminal (`done=true`, `failed` set), including historical unclassified capacity | The new exception does not revive it. A later ordinary refresh may acquire a new job/export. | No implemented rearm. A new acquisition is distinct from recovery of the historical job. |
| npm terminal integrity, invalid-input, processing-gap or other deterministic bound failure | Existing terminal treatment remains. | Ineligible without a separately validated cause-specific implementation; missing rights or corrupt evidence cannot be waived. |

Ordinary attribution claims consider only current-policy `pending`, `retry` and
expired `running` rows. Re-enqueueing an existing target does not reset its status,
failure, attempts or generation. The existing exact RustSec recovery command has
its own narrow recipe and cannot operate on RFC or npm subjects; no RustSec apply
is included in this design. See [operations](operations.md#exact-rustsec-attribution-recovery).

## Read-only selection and evidence

Use the released private [provider inspector](provider-diagnostics.md) with
reader-only database/S3 credentials supplied through a private configuration file.
The metadata/evidence budget is at most 64 MiB and five minutes; reports are at
most 1 MiB in owned mode-0700 directories below `/tmp`, with mode-0600 files.
Do not overwrite reports, follow symlinks, attach serving caches or acquire writer
authority. Reports contain bounded public identities and closed diagnostics, not
source bodies, credentials, configuration, raw errors or request-only audit data.

RFC selection requires one immutable snapshot and one or two canonical job keys;
an optional exact attribution-target ID adds state/generation inspection. The
supported forms are `rfc:text:NUMBER`, `rfc:format:NUMBER:FORMAT` and
`rfc:rsync:NUMBER:FORMAT`. RFC rejects `--latest-failure`. Freeze the selected
snapshot's capture/body references separately from current job captures and heads.
Record attempts, classification, due/lease state, sealed subject, policy and stored
generation identity. Verified metadata is distinct from body/engine readability,
origin traversal and public qualification; the inspector leaves unperformed work
explicitly `not_checked`.

npm selection is `--provider npm --latest-failure`; it accepts no exact job,
snapshot or attribution-target selector. It reports bounded current job, retry,
diagnostic, default-publication and referenced-evidence metadata. Legacy phase
evidence remains unknown. It does not download the export or verify every ZIP
member. If the historical terminal job was superseded, this interface cannot
select it; a future recipe must reject missing authoritative historical state
rather than infer it from the current default, a diagnostic timestamp or a reused
artifact hash.

Read-only diagnosis may read retained S3 descriptors/manifests. It performs no
provider acquisition, collection, repair enqueue or publication. The deployment
does not add fixed-provider live probes. Existing automatic collectors retain
their admitted settings and normal budgets.

## Proposed exact-target recipes; not implemented

A future implementation must register immutable, cause-specific recipe versions
and review their actual affected callers before exposing an apply path. A generic
SQL reset, a provider-wide retry switch and a command that accepts arbitrary URLs
are excluded. Dry-run does no repair writes, provider I/O or cache materialization.
It returns eligible/ineligible/incomplete, finite reasons, exact identities and a
digest of the complete authoritative state that apply would consume.

- An npm retained-advisory recipe could consider only an exact terminal job whose
  authenticated failure context proves the corrected materialization-deadline
  case. Bind the job, export digest/size, processing version, snapshot/membership,
  committed cursor and counters, failure/retry state and publication boundary.
  Verify the retained artifact and cursor under existing bounds before proposing
  resumption. Unknown old `capacity` errors, missing job history, incompatible
  processors, partial/unverifiable artifacts and ambiguous existing publication
  are ineligible. Never replay already committed members or replace the export
  with newer bytes.
- An RFC mapping recipe could consider only an exact blocked target with no live
  claim or stored generation, a proven repaired compiler/mapping defect, and
  exact retained source dependencies now supported by the existing policy-2
  compiler. Bind the subject/fingerprint, evidence, policy, prior sealed state,
  source snapshot/capture/body and every required origin dependency. Compilation
  must preserve exact identities, rights checks and bounds. Unknown failures,
  changed evidence, payload bounds, missing notices, unqualified errata prose and
  a request to replace history with a current head are ineligible.

Future apply requires a fresh coordinated database/archive recovery checkpoint,
stopped serving readers, collection writers and maintenance participants, explicit
writer credentials, exclusive lifecycle and publication-owner fences, and an
explicit expected-state digest plus policy/recipe identities from dry-run. Recheck
all admission conditions inside the transaction; any state, priority, cursor,
publication, policy or ownership change invalidates the proposal.

Journal the previous sealed state, recipe, exact identities and operation intent
immutably, and commit that journal with the narrowly defined transition. Retain
attempt history, captures, mappings, generations and notice resources. A unique
target/policy/recipe identity supplies idempotence; a lost commit response must be
reconciled through that identity before retrying. Preserve historical recipe
verification indefinitely. Cancellation, ownership loss or failure must preserve
the previous committed state or expose an uncertain outcome requiring review;
never silently replay an uncertain mutation.

An apply receipt would prove only the transition. Subsequent acquisition and
qualification remain owned by the normal writer and source budgets. Any resumed
moving-source request must satisfy the recipe's exact retained-byte requirements;
newer successful bytes do not repair a different historical capture. Receipt and
journal formats, execution limits, selected-target count and any storage schema
change require a future reviewed implementation and operational authorization.
No apply syntax or runnable reset procedure is supplied here.

## Verification and acceptance boundaries

Future behavior fixtures must cover eligible and ineligible exact subjects,
changed expected state, wrong policy/recipe, missing or corrupt evidence, live
claims, existing generations/publication, stale cursor, changed export, duplicate
members, foreign owner, cancellation, transaction rollback, lost commit response
and idempotent reconciliation. Verify reader-only dry-run, no provider I/O during
selection/apply, no arbitrary destination admission, immutable journals, unchanged
limits and no request-only audit persistence. Test replay after restart and
coordinated restore with historical notices retained. PostgreSQL, S3 cache-loss,
HTTP/WebTransport and minikube fixtures remain separate from production evidence.

For ordinary recovery exercised during this deployment, record the same selected
identities before and after resumption. Require a fenced claim and successful
completion for representative due retries/expired leases when observed; subjects
that do not complete remain incomplete. Require capture-fixed public reads and
all readable-notice pages for claimed content recovery. Compare immutable bytes,
body/generation identities and historical notice readback, separately from current
availability, queue counts or diagnostic classifications. No additional public
provider test traffic or terminal recovery batch is authorized by this document.

RFC errata rights qualification cannot be delivered by this policy-2 recovery
design. The separate [errata qualification proposal](rfc-errata-qualification-design.md)
requires approved applicable rights evidence and a newly registered immutable
policy before positive qualification. Neither public availability, technical
verification status nor an RFC's original notice establishes that permission.
Retain the blocked policy-2 target and its historical evidence. Correctly reported
unavailability is an honest remaining gap, not successful content recovery.
