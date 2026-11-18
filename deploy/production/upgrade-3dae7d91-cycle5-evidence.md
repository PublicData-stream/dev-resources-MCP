# Fifth-cycle 3dae7d91 execution, 2026-11-18

The single authorized fifth-cycle deployment of `0.1.0-build.3dae7d91` failed.
Target apply, writer startup and the migration-before-npm proof passed. The actual
published-image npm assessment CLI then failed during SQL connection, before SQL
setup or report generation. The supervisor completed its one physical schema-18
restoration and withdrew both application roles. PostgreSQL remains ready, all
sources remain paused and no fallback application was started. Target service
acceptance was not reached; the underlying connection failure remains unresolved.

The [fifth-cycle procedure](upgrade-3dae7d91-cycle5.md) implements the separately
approved [fresh-cycle plan](upgrade-3dae7d91-next-cycle-plan.md). It permits one
new native helper GET, checkpoint, isolated proof, actual Restore rehearsal and
target attempt. Target failure permits at most one schema-18 physical restoration
followed by PostgreSQL-only withdrawal, with no fallback application or retry.
The [preceding failed execution](upgrade-3dae7d91-evidence.md), frozen source
closures, consumed intents and restoration evidence remain preserved.

## Immutable release and fresh tooling

The release remains `0.1.0-build.3dae7d91`, commit
`3dae7d914baa9379abc402c5a3bcf311e0db01bf`. The pinned server image is
`ghcr.io/publicdata-stream/dev-resources-server@sha256:49a899c3c4f0b5d13532ff641f7583b329adea930d1e3877de07a3e5fde91d17`;
the probe image is
`ghcr.io/publicdata-stream/dev-resources-probe@sha256:de8663204451207ede70d790942fa5903a640ecbd3430967915f806b15dc5f4f`.
Corresponding-source archive SHA-256 is
`8fbbe7978c6ebf061d803c38d7b8e79205e68433e0c0ed0eb5a59da2b22e0782`.
The native amd64 probe ELF hash,
`ba6dd1e1fa8f1ed5c39b71f15479bd90ee9cd971c3ccddc3e59df719503a2ff7`,
is distinct from the qualification JSON hash,
`92be56f5f84c61902d7f5474f92d6d04a9a427fde23a4d58c145c558697e5791`.
The previously qualified signed tag, hosted native CI and image publication remain
release evidence; this cycle did not rebuild either production image or rerun
hosted native CI.

GPG-verified tooling commits
`d3e30f76cb791c3cab0516f663359434410913ae`,
`3e3c8018ced1d6dd4f979e892b14e57ef8209a13`,
`8fe6c538465a05989ac05ed093d0e21307dcaaf9` and
`a719e1336a6fb751316ab6d4d14580ab116e282b` carry the required assistance trailer.
The staged 29-member execution source manifest is
`607307c4dc64c90b9efedc14b709012843e1ee14d1842cb5e2b562b9a089d491`;
render-manifest SHA-256 is
`4a71ef9fad2601c6defa8b2de47415bb6228d2995869aa5aa0c043ed47d43555`.
Controller and checkpoint source hashes are respectively
`53fe422ef58dfd34183a9dc0851ddd6700af9bf1eea2b7b929f5fb71fbc3b9bf`
and `d0538e3072353eb344fe7e31fa1533bd7f23a17c00379209c0a12681e5c93aa7`.
All four historical ledgers and exactly 37 historical dependency sources remain
bound. The unchanged native edge admission is
`e1134a7092ac1e05ec97128bda976c174fc25e6b83d98cf9844bee575e57540a`;
it grants no additional edge drift or target acceptance.

Independent review covered actual generated callers, the read-only frozen
predecessor facade, original class closures and environment, baseline-before-
mutation admission, restored target-image templates versus the legacy isolated
proof image, and preservation of historical desired configuration flags.
Agent review is not a human GitHub approval.

## Local qualification

The retained Rust qualification passed 1,165 tests across 39 targets, with zero
failures and 105 ignored tests. The runtime, Rust workspace and relevant Rust
fixtures match the qualified source. The final integrated Python
suite ran 1,905 tests: 1,901 passed and four skipped in 129.558 seconds. Its log
SHA-256 is
`92ad64618bf6bef8eb6139676caa135f5a6d3ad5c93808fba119a1d1682c7b8b`.
These local results do not substitute for deployment or live provider acceptance.

One fresh combined local gate passed without a retry in 979.163 seconds.
The exact published `49a899c3` image passed its assessment CLI's positive case
and 14 negative controls. The receipt records no provider requests and unchanged
retained metadata. Temporary parser/securityfs changes were restored, with
PostgreSQL API/runtime identities and targeted host-mount projections unchanged.

The broader plain-S3, complete cache-loss, database restoration and HTTP/
WebTransport checks passed using the already qualified, source-equivalent
`20a8cdc5` harness image. They are not broader transport acceptance of the
published `49a899c3` image. Owned containers, profile, scratch directory, daemon
socket, bridge and firewall chain were absent after cleanup. The headroom guard
did not trigger; minimum free storage was 37,563,170,816 bytes.

The local outcome SHA-256 is
`9d27ea895289c9fa0b791eb50e92df63ba0951a9b4a848816e114106b78667da`;
network-cleanup addendum is
`c78b26c82758c00d62e80cbe3aa14e1fe0728847d45132f46e54e435d5f25524`.
The exact-image assessment receipt is
`efb4b9547345d619c9fab0d7d6dee125e29f9e2f1418841276502ad4cc68d7dc`;
node-restoration receipt is
`4d3264f499704c52b7727a578ee192ce1fb50b1e49ff1a1501b66425585b0ee7`.
All 13 paused-observer restoration steps passed. Its bounded observation proves
accepted identity-verified snapshots, not a fully verified terminal snapshot
when the final identity budget expires.

Earlier local headroom, filesystem-authority and fixture failures remain retained.
The earlier slow control-read cause remains unproved. Neither a later passing
fixture nor a read-only preparation correction establishes that cause.

## Production admission and capacity

Staged source, frozen predecessor facade and prerequisite admissions passed.
Checks covered the new probe's actual hash and executable/traversable ownership
boundary, active capacity/certificate timers, the required certificate leaf
margin of at least 24 hours, CA inputs and curl features. These preflights issued
no public HTTP or provider requests and consumed no target attempt.

The final public-identity preparer source identified by prefix `0edef84` passed
preview and wrote the admitted identity with hash prefix `6a8665`. It retained
exactly 37 dependencies and four historical ledger rows/spent native helper GETs.
The original private historical helper and its ownership were preserved; a
byte-identical root-owned private copy was prepared for the new workflow.
These counters describe native store-claim admission GETs, not all S3 traffic.

Bounded reclamation removed contents of eight completed fourth-cycle disposable
roots and increased observed free space by 119,283,585,024 bytes. Independent
checks verified all 205 protected metadata records covering 322,201,640 bytes, 21 directory
memberships, six golden checkpoint/full-baseline bindings and retained body-root
identities. Root directories, production generations and historical evidence
remained preserved. No whole retained-body rehash is inferred from root identity.
The dynamic capacity guards and 128 GiB reserve remain unchanged.

The initial read-only preview refused work-bind versus physical artifact paths;
those aliases had matching inode/hash evidence. A later pre-admission apply was
declined before its intent because global firewall audit bytes had changed, with
no deletion or consumed apply intent. After separately reviewed source, fresh
preview and finite approval, the first admitted apply succeeded. Only firewall
audit hashes were excluded from equality; all three raw command checks remained
mandatory, including token/path checks. No unchanged-firewall-policy claim is made.
These were preparation refusals, not failed production target attempts. The 29
runtime sources remained unchanged.

The admitted reclamation source has hash prefix `c4ada710`. Preview SHA-256 is
`1a8b53edd0b9786f261d23808d2092874b98318ece922339f75a2c13bf338f77`;
completed receipt is
`582bdaaf8e602867ebdb61c18700220a22c53f9c5d4e1b2b470b7ed8717ac08a`;
root live-boundary bookend is
`cbb5fdc518182d74553311bd19b698a2866f99f96ad37b359a0363cf6c690e26`.
That root-produced bookend was subsequently reviewed independently from files;
it was not an independent live probe.

## Baseline and checkpoint

Controller preparation passed with receipt SHA-256
`8ee265de8984d8f7a0901c6300e1e3464c3c500cb5b7c7ce0731e3227a640e0f`.
The schema-18 read check passed. The single new native store-claim GET returned
HTTP 200; its receipt is
`bd88107bc5a98678169640528737810874653ddc078b41cb4bf605bbc40ffa47`.
No additional native helper GET or retry is authorized.

Stop and the actual original-process operational baseline passed before any
PostgreSQL restart. Baseline SHA-256 is
`90ba1a974308864778015190db77e6ad57afae001e447bd55fef98febcb1513e`;
independent review cleared this ordering and its bindings. Fresh disk-backed
checkpoint/rehearsal binds and approval were admitted; approval SHA-256 is
`df88f92fbf34a0310b0626d6fc840ccbd995bc3c38da9f33b5c1f46dff62d10f`.

Checkpoint prepare, clean run and isolated proof have closed successfully with
exit status 0. The full clean schema-18 PostgreSQL checkpoint contains
27,415,323,554 bytes across 1,783 files; full baseline caches contain
11,701,186,054 bytes. The original process restarted from P1 to P2 without a
restore. The isolated `91c7bcb7` reader/writer proof passed fixed 1,024-byte cold
content, current notices and the historical 735-byte, one-page notice with hash
`e3023e4c9c26222fad0449a77d6d7243849a819d3d9ab7af4d2d20a277740156`.
It recorded zero provider requests and owned cleanup.

Clean-checkpoint receipt SHA-256 is
`1b67030099a37b308dd43a7604042c016434e96e2cd26e0125bd006a83ef6393`;
completed proof receipt is
`0bc9cf95ac9f669946ae1826ff854ed0c974d486517bfe174b394095cab7ba43`.
Original backup receipt is
`ab5c30c25c71a9ee961c9a32538c1b991ab73763d02cd66258ecb4b6596a5908`.
All 17 bound metadata artifacts, totaling 313,572,613 bytes, were independently
stream-hash verified.

A separately approved retirement of this cycle's three completed isolated proof
leaves then closed successfully. The exact preview
`828c253108f53513dc1f0d54b456609675400592684c777da5ebb79b1c3ea813`
was bound to source prefix `c4ada710` and a finite approval. No external hardlinks
were admitted. The free-space increase was 39,693,283,328 bytes, reaching
279,303,983,104 bytes. All 135 protected records remained exact: 119 metadata
records covering 318,592,058 bytes, 13 directory memberships and three golden/
full-cache body-root identities. The original backup remained unchanged.
Retirement completed-receipt SHA-256 is
`719618f6143b0a7f4d421395cc957670426fdedde65f2bf6b13041a5f8c589c9`;
root live-boundary bookend is
`dd65959830720878dc825b128685986e477e7ba9a5d22adfd3015397b8ef9cea`.
This root-produced bookend also received subsequent independent file-only review,
not an independent live probe.

## Actual rehearsal and single target failure

The source-bound actual Restore-class rehearsal passed on isolated real
PostgreSQL and full baseline cache copies. It used the unchanged rehearsal/
checkpoint/Restore sources identified by prefixes `36d2a88a`, `d0538e30` and
`b0d5d9da`, with the unchanged 128 GiB reserve. Rehearsal receipt SHA-256 is
`f8b4ea9a0d8c3e4c61d018e79fbe0594f6f042ae05d2a153fb3f0732fccaed02`;
the revalidated 20-artifact backup receipt is
`bfcbf1853580f1d6b55ce46c375c7a00563cf3d3ef27e851bc93d524f18f227f`.
The standalone validator (`fef2ff25`) and source-owned admission passed at a
receipt age of 136.088 seconds, within the 300-second limit. This isolated
rehearsal was separate from the subsequent production restoration.

The independently reviewed launcher (`fc99207d`) reserved an exclusive durable
intent before validation and used the exact approved argv (`77d4ed4d`). The root
supervisor ran once from 04:30:59 to 04:41:41 UTC on 2026-11-18 and exited 1.
The same source (`993470f5`) post-exit fence exited 0 at 04:41:44 UTC. Actual unit
properties matched the oneshot contract: `RemainAfterExit=no`, control-group
kill mode, no restart, a nine-hour start limit and a two-and-a-half-hour stop limit.

Exactly four stages ran. Apply, writer startup and migration-before-npm exited 0;
npm assessment returned `child_failed` with exit 1. It recorded no timeout,
interruption, truncation or descendant-held pipes, and child cleanup and withdrawal
completed. No observer, paused/public acceptance or 900-second active observation
stage ran.

Migration receipt SHA-256 is
`dbf49fe7e19f67df097f03ed4bf5d2b50617cc0b1ee1e4a728ab65eb26ca4947`.
Independent file-only review validated its original baseline, execution sources,
prepared/history authority seals, schema 19, three recovery tables, policy 2,
reader grants and paused flags. Thus this attempt passed the baseline-bound
migration proof that the preceding failed cycle had not completed.

The actual published `49a899c3` CLI executed. Configuration, parsing and output
preparation passed; `sql_connect` recorded error reason `connection` at 1 ms,
then the CLI exited 1 before SQL setup, locks, schema checking or report transfer.
The report directory remained empty and assessment network cleanup removed the
owned resources. Failure receipt SHA-256 is
`b8921e554974d30e6bbe67b49fb38fd90b70a85980770f30584c7e43302171b5`;
final stage receipt is
`aae9e045d0d61c5e7451c12a8db4f048c755913d0845245f5d7d4e45472be5c4`.

The underlying cause remains unresolved. Private DSN, role, Service, TLS and
environment parity were checked without exposing values. These checks do not
establish a hydration or TLS difference, and NetworkPolicy/API intent is not
data-plane connectivity evidence. No network or TLS root cause is asserted.

## Physical restoration and final withdrawal

The one authorized automatic physical schema-18 Restore completed successfully.
The operation restored the database and full baseline caches. It preserved the
post-task PostgreSQL generation with a file manifest and retained both post-task
cache directories with their original device and inode identities. S3 was not
rewound. Restoration receipt SHA-256 is
`3cfa88baff2a2c4f074c066626c2f1bdad5bf3c699603a1733f9c28b3ccad0eb`;
Restore state is
`5ba415bb6226c99e36f2693759e87a0fbbef471c7cec2abad02cac5e0b6817eb`;
final controller state is
`7462e62c802d12bb9bf929956265a3cec63e9249f5944104e389fe4be066855d`.

The finite result reports `target_failed_restored_withdrawn`, target/fallback
false, schema-18 restoration true and withdrawal true. Its SHA-256 is
`6bcc40099f85336bd5713ad1aa1de8c9d60a8a9c1168c3810e0f87dfb0c3c8a8`.
Those summary bytes also occurred in the preceding cycle; the accompanying
fifth-cycle source, path and state bindings establish this result's scope.

Root final live checks passed the exact `53fe422e` controller guard and schema-18
storage guard with no publication owner before and after inspection. Only
PostgreSQL was Running/Ready; application replicas were zero. Archive epoch 2,
policy 2 and both maintenance timers were retained. The finite final-proof
SHA-256 is
`e7854b4b01a0bf142e097a2aa2b3279e9179344ca46aebb131b5b67add610c4a`.
Free storage was 159,962,472,448 bytes, above the unchanged
137,438,953,472-byte reserve.

Independent final file-only review cleared the restoration, Restore/controller
states, finite result and their exact source/prepared/checkpoint/accepted-backup
bindings. It verified the single maximum-one rollback intent,
`f0d80bc83781e7d196713e47a7ccd1494f914ddb2773c6726b8302db2c9bfdf3`,
with no reconciliation/loss marker or later acceptance. Preserved post-task
PostgreSQL/cache device/inode records and newly installed root identities matched;
cache staging was cleared. The restoration-time post-task database manifest
covered 27,369,728,746 bytes and 1,822 entries, with SHA-256
`e8d88344b063feb4da39905f8d05728271b7109553d8aff9fe09226642d76327`.
No final body rehash is claimed.

Closed supervisor stdout SHA-256 is
`2ce94eb401240923fd517d26332ded59585c405258b43c6e81dec5ff648086ee`;
stderr was empty. The root-captured actual unit-properties record,
`197cdf985bf072c875c53b24d627271cc07e11f2436dc0f86cc941b62dd7ba0b`,
binds root execution, the stated lifecycle limits/properties, source and manifest,
main exit 1 and fence exit 0. These final independent checks reviewed retained
files; the final live guard/storage/process checks above were performed by root.

These checks establish restoration and withdrawal, not accepted target or
fallback service. No image rebuild, additional target attempt, fallback startup
or new cycle was performed. Local fixtures, native CI, registry qualification,
isolated checkpoint/rehearsal proof and production acceptance remain distinct.
No independent S3 backup, full-corpus body rescan, whole-provider acceptance or
native ChatGPT UI acceptance is claimed.
