# 9373f71e deployment execution, 2026-11-16

The separately authorized deployment of `0.1.0-build.9373f71e` failed. Target
writer startup and schema-19 migration passed; its read-only npm assessment CLI
exited with status 1. The supervisor used its one automatic physical schema-18
restore, then started the `91c7bcb7` fallback. Fallback private acceptance failed
on `packages.npm.corpus_status`. Both application roles were withdrawn and all
nine sources remain paused. Neither release completed service acceptance.

This execution used a fresh scope under the
[9373f71e procedure](upgrade-9373f71e.md). Both earlier failed cycles and their
consumed intents remain historical evidence; this result authorizes no replay
or additional production attempt.

## Release and local qualification

The signed tag resolves to commit
`9373f71e06936970b4a8dc4ca30584b9d464a5b9`. GPG verification passed. Native CI
run `43805647144` passed all 12 jobs and image publication run `43813619167`
completed successfully. The accepted digest artifact, all four image families,
12 provenance subjects and eight anonymous platform pulls were independently
qualified. All 827 corresponding-source archive members matched the exact
commit plus the allowed version stamps. Archive SHA-256 was
`f65738d8621fba3c7ad37029d5fb4f4a8844c2bdc91bd2f1671f99e975fd8620`.
Server and probe image indexes are recorded in the procedure. The extracted
amd64 probe passed hash verification and execution with UID/GID 65532 and no
network. Fallback immutable qualification was reused, with fresh archive and
native-binary hash checks; fresh fallback platform pulls are not claimed.

Signed commit `177ee77` records the fresh-cycle renderer and its tests. The
complete 26-source execution manifest was
`5dbf9d3be45cd6222eda9d36cc2d59b0dcd580b65143743933cc5d4b33a23a4b`.
Independent review covered the actual renderer, preparation helpers, lifecycle
units, affected callers and isolation boundaries. The integrated Python suite
passed 1,398 tests with four skips. Rust runtime and transport-client sources
were unchanged from `1d76fbcc`; no new local Rust compilation or dependency
audit is claimed by this execution record.

The local minikube filesystem gate passed on its first attempt. The first S3
credential-broker gate failed with exit 101 during a fixture reader connection
following maintenance shutdown. Its cause was not established. Exactly one
fresh rerun with unchanged sources, harness and binaries passed the S3,
credential-broker, transport, outage, cold-cache and restore checks. The failed
attempt remains evidence; the passing rerun does not identify its cause. Owned
profiles, containers, daemons and network resources were removed. The combined
local gate receipt SHA-256 was
`d41eb50c8f2ceb5534516393ce3ccbab42bc6ad7893ae2c9e2f265eb490a62c0`.

## Fresh checkpoint and actual Restore rehearsal

The initial capacity projection failed the unchanged copy/growth admission
with its 128 GiB reserve. An independently reviewed reclamation removed only
contents of nine completed, owned, previous-cycle test-copy leaves. Their root
identities and all journals, logs, source closures, original golden checkpoints,
baseline caches and preserved production generations were retained. The
selected test trees accounted for 119,838,236,672 allocated bytes before
reclamation. Directory ctime changed;
independent pre/post atime equivalence is not claimed. Protected hashes and
actual capacity were checked afterward, without weakening the dynamic guards.

A fresh clean physical schema-18 checkpoint passed isolated old-writer readiness,
fixed reader bytes, current and historical notices, SQL invariance and cleanup.
The copied writer retained its 64 GiB cache limit. Independent review checked
all 17 checkpoint artifact hashes, source bindings, complete baseline cache
manifests and bounded file samples. Completed-checkpoint SHA-256 was
`48073fd39a46cb12271c44ec3fa95b61e725add7eabec47a1704db008e3e042d`;
initial backup-receipt SHA-256 was
`5fb7aab059507fbbffa93475cb68630652e96c69cf9b033fd3892ac0eb4464c2`.

The actual source-bound Restore class passed a separate real PostgreSQL and
full-cache rehearsal. Its clone-only marker disappeared; database/cache
replacement, restart, cleanup and unchanged production bookends passed all six
checks. Rehearsal receipt SHA-256 was
`1c5af587134aba08107717583762bb03a832d3231ae706bd59dfedaca067988d`.
The revalidated backup bound 20 artifacts with receipt SHA-256
`3bdd71224602d43655b4e0b44e7455b35fddcf4ad85239e884a82fc6ae409723`.
The existing activation verifier passed and main startup followed at a receipt
age of approximately 110 seconds, within the five-minute admission. Independent
postlaunch review digest was
`0474915c4bbaaef91cc28ac6ad4c5019067b08ababa2395ddbd92b5be82308aa`.

These proofs depend on the original immutable S3 archive remaining available.
No independent bucket backup, whole-corpus body rescan or bucket-loss recovery
acceptance is claimed.

## Target and fallback failures

The root supervisor ran once from 08:49:46 to 09:00:56 UTC and exited with status
1. Target apply, writer startup and process-bound schema-19 migration passed.
The npm assessment Pod was admitted, created and started. Its new bounded
failure record identifies `check-pod-status`, Pod phase `Failed`, a terminated
container with exit code 1, zero restarts, reason `Error`, a present container ID
and no OOM indication. The helper failed at its Pod-status assertion. No report,
completion or production deferral receipt exists. CLI stderr was not retained;
the underlying CLI failure remains unproved. No recovery apply/run, queue reset,
rearm or authoritative historical npm cause is claimed.

Read-only policy review found matching backend labels and NetworkPolicy
selectors, matching PostgreSQL ingress admission and a matching CoreDNS target.
The four policies matched the prepared foundation. This excludes the proposed
label-selector mismatch from the observed manifests; it does not prove actual
network reachability, database authentication or configuration success at the
failure instant.

A subsequent local fixture ran the cached first-party CLI as UID/GID 65532
without networking and with a deliberately missing configuration. Both synthetic
root-owned SGID temporary parents, modes 02775 and 02777, admitted a new private
02700 output directory and 0600 report before the expected configuration failure.
Three invalid output controls were refused. This excludes that proposed ancestor
permission difference in the tested environment; the deleted production Pod's
actual temporary-directory mode and other confinement effects were not measured.

The automatic physical restore installed schema 18 and baseline caches while
retaining newer S3 objects and post-task SQL/cache generations. Fallback startup
reached private acceptance. Its retained RPC metadata identifies successful
modern-revision `server/discover` and `tools/list` calls, followed by HTTP 200 for
`packages.npm.corpus_status` with `tool_is_error=true` and error code
`unavailable`. The canonical smoke helper then raised `AssertionError` at its
tool-result check. The underlying failure remains unproved.
This identifies this cycle's failed call; it does not reconstruct the earlier
cycle's missing assertion trace or explain the isolated 15-second timeout.

Source review identified an additional failure path outside npm's own status
implementation. [`Research::qualify_output`](../../crates/adapters/src/research.rs)
adds attribution status to corpus status results; the
[reader attribution runtime](../../crates/application/src/attribution_runtime.rs)
obtains it through the [writer client](../../apps/server/src/writer_rpc.rs).
The reader initializes this gate and delegate even when all providers are paused.
The paused configuration deliberately selects a missing forwarding-token
path and a loopback port-9 endpoint. Reaching this outer step therefore cannot
complete normal writer-backed attribution status. Earlier npm SQL/statistics or
S3-fence errors can also return `unavailable`; retained RPC metadata cannot
distinguish those stages. This is a concrete incompatibility to resolve before
another acceptance cycle, rather than proof of this response's first failure.

No public matrix or stability observation completed. The supervisor reported
`fallback_failed`, `known_complete=false`, `withdrawal_completed=true`; its
independent stop fence reported `fenced=true` and no accepted fallback service.
No further production retry or restore was performed.

## Final restoration and withdrawal

Independent final checks found PostgreSQL ready on schema 18, with its original
system/archive identity and no publication owner. Only PostgreSQL remained as a
Pod; backend and writer replicas were zero. Both role configurations retained all
nine source flags and npm advisory collection disabled. The current controller's
guard and historical bindings passed, all 26 source hashes and all 17 original
checkpoint artifact hashes matched, and no owned assessment Pod or checkpoint/
rehearsal container, network or firewall rule remained.

Complete streamed read-only SQL manifests matched the fresh checkpoint exactly:
374,733 archive rows and 75,499 capture rows. Archive-manifest SHA-256 was
`a256a413faaaa361d51b34ea2764232d4f739f363310959862e787cc7bf7a5c7`;
capture-manifest SHA-256 was
`59d248bf7427d7300a7e9b1cdb1718dd2ccf750af5988afe0b820059d85d8d0a`.
No row or body was printed. This was not a full S3-object or corpus-body rescan.

All 1,192 serving-cache and 231,074 writer-cache baseline paths matched current
kind, size, mode, ownership and symlink-target metadata. Three content-digest
samples per role also matched the baseline. Additional paths were not enumerated
and complete current cache contents were not rehashed; metadata equality and
sample matches do not establish full content equality.

The actual restoration receipt recorded database and baseline-cache replacement,
`preservation=manifest_verified` and `preserved_directory=true`; its SHA-256 was
`19cec79976a6c20d981e2ef689c23d0053db9f6b9023f5ea2dd5bc29f62a59fc`.
The cold post-task schema-19 directory retained its recorded identity. Its
restoration-time manifest covered 1,829 files and 27,475,528,426 bytes; its complete
current content was not rescanned. Preserved production cache generations and
original checkpoints remained retained. The S3 prefix and epoch were not rewound.
Free storage at final review was 169,830,522,880 bytes, above the 128 GiB reserve.
Independent final restoration/withdrawal review SHA-256 was
`4e81ea6726ff03d25464fa8ed0cd71c469810796879446027af27e64d822a399`.

These checks establish restoration and withdrawal, not accepted fallback service.
Local tests, native CI, registry qualification, isolated checkpoint/rehearsal
proofs and production service acceptance remain separate evidence. Full provider
and corpus acceptance and native ChatGPT UI acceptance were not performed.
