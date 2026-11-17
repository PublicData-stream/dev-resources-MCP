# 3dae7d91 deployment execution, 2026-11-17

The single authorized deployment of `0.1.0-build.3dae7d91` failed. Target apply
and writer startup completed, but the migration-before-npm operational proof
failed. The supervisor completed its one automatic physical schema-18 restore
and withdrew both application roles. PostgreSQL remains ready and all nine
sources remain paused. No fallback application was started. Target service
acceptance was not reached.

This execution follows the [3dae7d91 procedure](upgrade-3dae7d91.md). Historical
cycles, consumed intents and failed qualification attempts remain retained. The
approved failure path permits at most one physical schema-18 restoration followed
by PG-only withdrawal, with no fallback application startup or target retry.

## Release and source-bound tooling

The immutable application release remains `0.1.0-build.3dae7d91`, commit
`3dae7d914baa9379abc402c5a3bcf311e0db01bf`. Its accepted references are:

- Server: `ghcr.io/publicdata-stream/dev-resources-server@sha256:49a899c3c4f0b5d13532ff641f7583b329adea930d1e3877de07a3e5fde91d17`.
- Probe: `ghcr.io/publicdata-stream/dev-resources-probe@sha256:de8663204451207ede70d790942fa5903a640ecbd3430967915f806b15dc5f4f`.
- Corresponding-source archive SHA-256: `8fbbe7978c6ebf061d803c38d7b8e79205e68433e0c0ed0eb5a59da2b22e0782`.

The native amd64 probe ELF SHA-256 is
`ba6dd1e1fa8f1ed5c39b71f15479bd90ee9cd971c3ccddc3e59df719503a2ff7`.
This is distinct from its qualification JSON file SHA-256,
`92be56f5f84c61902d7f5474f92d6d04a9a427fde23a4d58c145c558697e5791`.
The execution's complete 29-file source manifest is
`a23b1015e38926627bfe2d8883d3ebe46d9c23dadcbe68ba1695529f0808be5e`.
The separately admitted native edge receipt is
`e1134a7092ac1e05ec97128bda976c174fc25e6b83d98cf9844bee575e57540a`.
Historical edge files and admissions remain preserved; this receipt does not
substitute for target public HTTP or WebTransport acceptance.

The signed release tag and hosted native CI run `43989289915` were qualified,
as was publication run `43989289916`. The accepted release-digest artifact,
all four image families, provenance/source bindings and eight anonymous
amd64/arm64 pulls were checked. These are release/registry evidence; they do
not establish production acceptance.

The tooling history includes GPG-verified signed commits `d991591`, `7a45823`,
`06395d0`, `1c31018`, `55a3935`, `3cec419` and `539dce9`, with the required
`Assisted-by: Codex <codex@openai.com>` trailer. Commit
`3cec419b0844bb2a46ed348a4f03fe1a346bcd96` acknowledges fixture-only PostgreSQL
ownership handoffs. Commit `539dce98f29c1af9d5ef29b88397569057256536` retains late
observer failures within the fixed observation window. These tooling and fixture
changes did not rebuild or replace the frozen production application images.
Independent review covered source binding, affected callers, storage preservation
and security boundaries. Agent review is not a human GitHub approval.

## Local qualification and its limits

The local Rust result was 1,165 passed, zero failed and 105 ignored. The
predeployment Python suite ran 1,752 tests: 1,748 passed and four were skipped.
These are local results;
they do not establish native architecture CI, provider acceptance or deployment.

The exact published server image passed the assessment CLI's 15 cases, comprising
one positive case and 14 negative controls. The qualification exercised admitted
Pod authority, read-only configuration, DNS/PostgreSQL access, API isolation,
AppArmor enforcement and the denied same-volume alias. Owned node prerequisite
changes were restored; the temporary parser was removed, securityfs preimages
and targeted host mounts matched, and PostgreSQL API/CRI/process/shim identities
remained unchanged. Owned profiles, daemon sockets and container metadata were
removed after the combined gate.

The broader S3, cold-cache, cache-loss, database restoration and HTTP/WebTransport
checks passed with the source-equivalent local harness image identified by digest
prefix `20a8`. Those broader transport checks were not a run of the production
`49a899c3` image. The exact-image CLI qualification and production transport
acceptance remain separate evidence; the latter was not reached.

The final local outcome SHA-256 is
`8e89079bc266cbae27958ce86987e35ea931831ecf541225c331f715bde6a8cb`.
The complete gate-log SHA-256 is
`36ede26e25118b39279fa29b2d0de5a89bc100d1ebe32b386ca80ce46766cd0e`.
The exact-image assessment receipt is
`929d77caf6e6a07a89bd4386044f024a295b45ea597522afa92845afd06f54c4`;
node restoration is
`dfa8883a19606774897ed962481c71be90db066cda3b579710cdbb9fa0464efb`.

Paused-observer SQL-permission and S3-unavailable controls returned structured
`unavailable` before attribution forwarding. Their metadata bookends matched,
publication ownership remained absent, authenticated acquisition was denied,
and all 13 restoration steps passed. The final paused-observer receipt is
`519104e4347b0b21aed206245e2a5ce01340aeceb1a60f1de58b34ee1eb02b5d`;
its restoration receipt is
`0f2e39bb9e49c9f7666d3abd5f6e44e57fb609a471548bfce60cc297d0da61af`.
The fixed ten-second observation accepts benign snapshots only after matching
identity checks on both sides. Every fetched forbidden or malformed timing record
fails closed, including at deadline. If the final identity budget expires, the
accepted evidence does not establish a fully verified terminal snapshot.

Earlier ENOSPC, headroom, ownership-handoff and observer-fixture failures remain
retained. The later pass does not identify the cause of the earlier slow control
read; that latency's root cause remains unproved. Recorded zero provider requests
and zero public requests describe the bounded local fixture, not all deployment
or S3 traffic.

## Completed-copy reclamation and fresh checkpoint

A separately reviewed, single-use reclamation removed only the admitted contents
of six completed historical fixture leaves. The selected regular files accounted
for **229,697,740,800 allocated bytes**. Leaf identities, protected metadata,
original golden checkpoints, complete baseline caches and the five separately
admitted retained successor body roots were preserved. The preserved helper,
qualification and journal chains were not overwritten. Existing bounds,
external-hardlink refusal, mount/process checks and source/native boundary guards
remained in force. Directory timestamps changed; atime equivalence and a new
full-content rehash of retained body roots are not claimed.

Reclaim completion SHA-256 is
`fa22953493af48c0b80354e259b63777c8a50205b7f73429cf1015911970677b`;
the final live-boundary receipt is
`28e3ea026319fe53fe25e08f104103c407e21e24a72a2faced5da6f7406d7f0d`.
The dynamic capacity guards retained their 128 GiB reserve.

The fresh public identity, preparation and exact checkpoint approval were bound
before the checkpoint. The native admission helper completed exactly one new
reader GET of the permanent store claim, with receipt
`272754f79ff98d0aef9026cd1394bc9be69d091379324ea8b9ee2f724355aff1`.
That consumed attempt is not replayable. It is a count for this store-claim
helper, not a count of all S3 requests, and it is not an independent S3 backup.

A clean physical schema-18 checkpoint then completed. PostgreSQL was stopped,
its final copy was verified, and the original production PostgreSQL resumed with
a new process identity without restoring production data. The checkpoint covered
1,783 files and 27,415,323,554 bytes; the canonical cache baselines covered
11,701,186,054 bytes. Physical-checkpoint SHA-256 is
`625950a0d53d57a84a704b3849503e71de323ecae40661f472c7cd5b30f45745`.

The isolated old-reader and old-writer proof passed the fixed 1,024-byte readback,
current and historical notices, schema-18 checks, baseline-cache preservation and
owned cleanup, including network-fence removal. It recorded zero source-provider
requests and no production mount. Root and independent file-only review verified
all 17 backup artifact hashes, source/admission bindings and all six backup
checks. Completed-checkpoint SHA-256 is
`4f0721e04ddd03b258d1f49440b3302260ac0ecd06e823f1b5af33261fedbebe`;
initial backup-receipt SHA-256 is
`c2cde81781584cf94ff17060d2640f837fe2c050d8e21d852fc97162405ab2cf`.

## Actual Restore rehearsal

The actual source-bound Restore class passed once against isolated real
PostgreSQL and full baseline-cache copies on verified disk-backed binds. All six
checks, owned cleanup and unchanged production bookends passed. Rehearsal receipt
SHA-256 was
`81aceaa6fcb4468edadd435b7ef27550fe6a69b878c8dbb866e6a0f5ef53ad7c`.
The freshly revalidated backup bound all 20 artifacts with receipt SHA-256
`771e91b91e04497df1666034cdc4e078694eff9ddf0fe7aa3a200623522f8187`.
Root verified the artifacts and source bindings before supervisor startup, which
followed approximately 35 seconds after revalidation, within the 300-second gate.

## Failed target and completed restoration

The root supervisor started once at 17:08:39 UTC. Target apply and writer startup
exited successfully. The next stage, `deploy-migration-before-npm`, returned
`child_failed`, exit 1, without timeout or interruption. Its retained stdout was
`verified=false`, `code=operational_proof_failed`; SHA-256 was
`ecdb77a801e179338cf692e9f94d6148b4511cd1a88752b2ff80b948585616a6`.
This does not establish successful production schema-19 migration or service
acceptance. The npm assessment, observer, paused/public acceptance, activation
and active 900-second observation stages were never reached.

The required operational baseline file and migration-proof output directory were
absent. Source inspection shows that observation loads that baseline before
creating its output directory. The operator omitted the standalone baseline
command before the checkpoint changed PostgreSQL's original process identity.
The consumed tooling and procedure did not enforce this prerequisite at deployment
admission. This is a strongly supported explanation for the generic proof failure;
the exact first exception trace was not retained. No baseline was backfilled and
no failed production stage was retried.

The supervisor consumed its one restoration intent and installed schema 18 and
both complete baseline caches. The restoration receipt SHA-256 is
`bd466f56be125f7f15aed1fc3b55a6a52a54cfdc8cfe37b5fb6a57364961b555`.
It records verified database and baseline-cache restoration and preservation as
`manifest_verified`. Post-task generations remain preserved; the S3 archive was
not rewound. No fallback service was accepted.

Independent file-only review verified the receipt hash and its associated state
and retention metadata: both cache phases were `installed`,
`preserved_directory=true`, `s3_rewound=false` and `fallback_accepted=false`.
This review did not perform a new live content scan or establish full current
cache/body equivalence.

The deployment result records `target_failed_restored_withdrawn`,
`target_deployed=false`, `fallback_deployed=false`, `known_complete=false`,
`schema18_restored=true` and `withdrawal_completed=true`. The deployment-result
file SHA-256 is
`6bcc40099f85336bd5713ad1aa1de8c9d60a8a9c1168c3810e0f87dfb0c3c8a8`.
The failed `deploy-migration-before-npm` stage's separate final-result SHA-256 is
`81f876b556c79f28abb04f72ebc266bfeee277d6771db2d29cdbb620017468f6`.
The independent stop fence completed with `fenced=true`,
`schema18_restored=true` and `fallback_service_accepted=false`. The unit's failed
exit status reflects the failed target attempt, rather than an accepted service.

Separate final read-only SQL and Kubernetes/configuration checks found schema
18, no publication owner, no schema-19 objects, archive epoch 2, policy 2 and the
selected historical generation preserved. Exactly one PostgreSQL Pod was ready,
with its identity matching the restoration receipt. Backend and writer replicas
were zero. Both role configurations retained all nine collector flags and npm
advisory collection disabled. Controller state was `runtime=restored`,
`phase=withdrawn`, `configs=old`. Final free storage was approximately
200,160,169,984 bytes, above the unchanged 128 GiB reserve.

## Future admission correction and remaining authority

Signed commit `fd06857` adds a private-file-only prerequisite shared by supervised
deployment entry and direct controller apply. Missing, malformed, foreign,
nonprivate, linked or source-mismatched operational baselines now stop before
intent, backup-driven process rebind, accepted-backup persistence or application
configuration/image mutation. Baseline production binds the prepared record and
producer sources and requires the stopped original PostgreSQL process before
checkpoint restart. The [procedure](upgrade-3dae7d91.md) now includes that command
and ordering. This correction applies only to future rendered tooling; the
consumed production closure, installed helpers and journals remain unchanged.

Independent review cleared the actual five-file correction across MCP/API,
storage and security boundaries. Its 81 focused tests passed. The final complete
Python suite ran 1,769 tests in 147.898 seconds: 1,765 passed and four were skipped.
Its log SHA-256 is
`8829e6c377468756d771118bdb07ab2b5874f407cebe954ca93b765644b058b1`.
No Rust runtime or production image changed in this correction; the earlier Rust
and minikube results remain separate qualification evidence, not a new deployment
success.

The single target attempt, checkpoint, native admission-helper GET and physical
restoration for this scope are consumed. No additional production attempt,
helper GET, checkpoint, restoration or replay is authorized by this record.
Any new cycle requires separate authority, a fresh source-bound scope and
admission of the actual restored PostgreSQL/process and withdrawn templates.
The [proposed next-cycle plan](upgrade-3dae7d91-next-cycle-plan.md) is unapproved
and does not authorize additional production operations.

These proofs depend on the original immutable S3 archive remaining available.
No independent bucket backup, full corpus-body/S3-object rescan, bucket-loss
recovery acceptance, complete provider acceptance or native ChatGPT UI acceptance
is claimed. Local tests, hosted native CI, registry qualification, isolated
checkpoint/rehearsal proofs and production acceptance are distinct evidence.
