# Production upgrade to 0.1.0-build.5196c629

This 2026-11-12 checkpoint supersedes the running version in the
[previous static deployment record](static-acceptance-evidence.md). The production
server now uses immutable release `5196c629796073203a67b1c11353ee2a616fbd47`.
Application behavior is supplied by that published release; this operation did
not rebuild or modify its Rust binaries, public specification or configuration
contracts. The public endpoint remains
`https://dev-resources.mcp.publicdata.stream/mcp` with WebTransport at
`https://dev-resources.mcp.publicdata.stream/mcp-wt/v1`.

## Release qualification and operator binding

The immutable [release](https://github.com/PublicData-stream/dev-resources-MCP/releases/tag/0.1.0-build.5196c629)
and annotated tag/commit signatures were verified through actual GitHub API reads.
[Publisher 43218338112](https://github.com/PublicData-stream/dev-resources-MCP/actions/runs/43218338112)
passed stamped native amd64/arm64 release tests, promotion, provenance and anonymous
pull gates. Exact-commit [main CI 43204541453](https://github.com/PublicData-stream/dev-resources-MCP/actions/runs/43204541453)
and corroborating [tag CI 43218338139](https://github.com/PublicData-stream/dev-resources-MCP/actions/runs/43218338139)
passed the complete required job set. Current anonymous index/platform/config reads
and constrained index attestation checks independently matched the release assets.

| Artifact | SHA-256 |
| --- | --- |
| Server image index | `bf81462ecdcd0b234091c36cadb66036191fc4fb9a6214c3eb2932b975042927` |
| Probe image index | `f3fa64822917c0e828908d9a2d0eeea14a0b33a2fedaafd466dabcb3cdd93b49` |
| Corresponding source archive | `672d2677720e0352db53e59d8068f9ef1bd55c070be13150120d01779fa66b57` |

Both private runtime configurations advertise the exact new public source URL.
The matching probe was extracted from the qualified amd64 image; its native binary
SHA-256 is `cad3bfa58bc1c9f1c6d14c2e36efb6652cd962e3745fb56ee835d7f12396cd33`.
Published native/fixture qualification is separate from the actual results below.

The generic production renderer/operator remain pinned to the earlier release;
they were not relabeled to manufacture new admission. A separately reviewed,
one-upgrade controller is installed on the server at
`/usr/local/libexec/devres-upgrade-5196c629/upgrade-controller.py`, source SHA-256
`3f4c8fde5ac7adc328d829217896f0a95b32b7138f0337b3f4f708358ba9cc4f`.
Its root-private journal is
`/var/lib/devres-production-upgrades/5196c629-20261112`.
All old runtime/Secret/cluster identities were freshly guarded before mutation.
The controller has exclusive durable intents, no uncertain-operation replay and
no automatic database restore or schema downgrade.

The old frozen capacity and certificate timers retain their admitted bundle and
continue through their independently reviewed call paths. AppArmor, host firewall,
CNI/RBAC, ports, TLS and static S3 credential boundaries are preserved. The earlier
operator's general install/provision/start commands are retired for this runtime;
use a reviewed successor procedure for further lifecycle changes. Its existing
capacity/certificate/emergency withdrawal paths remain available. An old image
cannot be hot-swapped onto the new schema.

## Scoped recovery checkpoint and approved password rotation

The backend stopped before the writer. PostgreSQL was stopped cleanly, its
physical directory was finalized with checksum-based rsync and explicit file and
directory fsync, and the same original Deployment/PV restarted without restore.
The final checkpoint operation took 33.219 seconds. It preserves the PostgreSQL
system identifier, roles, password verifiers, ACLs/default grants and schema 13,
plus a complete ordered archive-binding manifest and original store claim.

The server's 16 GB tmpfs could not hold both approximately 9 GB PG copies and
headroom. The failed pre-copy preflight is retained. A root-private directory on
the production disk backs the logical temporary work root through a bind mount;
no fstab, boot unit or security policy changed. Checkpoint data is retained under
the successor journal's `checkpoint-volume/checkpoint-state/` directory. Test
paths remain under the private logical `/tmp` work root.

Recovery depends on the **original immutable S3 archive remaining available**.
This is a coordinated upgrade rollback checkpoint, not an independently protected
S3 disaster-recovery copy or a recheck of every remote object's checksum. Existing
prefixes, conditional immutable writes and deletion-denying policy were preserved;
10 fresh IAM and six S3 metadata reads matched the previous storage admission.
The original S3 store claim was read successfully with the actual reader pair.
Neither IAM/bucket policy changes nor additional trial keys were needed.

A separate physical PG copy and the old reader-only image proved actual restore
readability: schema 13/system identity, real reader defaults, SELECT on all public
tables, no mutation grants/writer membership, the original fixed RFC page and its
immutable notice. No source-provider acquisition or writer clone ran. The first
two attempts stopped before Docker proof/create intents: one config parser rejected
an inline array, then a subnet parser rejected native Docker `IPAM.Config:null`.
Narrow independently reviewed continuations preserved their directories/intents,
original checkpoint and single actual rehearsal scope. The successful rehearsal
and exact owned container/network cleanup are retained.

| Actual checkpoint evidence | SHA-256 |
| --- | --- |
| Physical checkpoint receipt | `312382ab47b1a34b573c59352c2cf534acc182240a2ca4d047bb0a39566a8437` |
| Complete archive-binding manifest | `d61cf7ee36a5bd667afd68012ed9d19ac257d764801ccbb992c4ccbd7ea30a9c` |
| Final checkpoint/old-reader qualification | `7ad9e5b7a9f94e427e28d25c13ae08c2cbfb1b62fd7a966ca27a1ac112049382` |
| Exact clone cleanup | `8ea0fb1643b804e2e20d14953d9b5657c970ee2b870d671b2daaf58c2a748284` |

A configuration-summary mistake included the two application database URLs in a
tool response. With explicit user approval, both application passwords were
subsequently rotated while applications were stopped. Private server-generated
values were carried only in candidate configurations and stdin. PostgreSQL
[psql password commands](https://www.postgresql.org/docs/18/app-psql.html) performed
client-side SCRAM encryption in one transaction, with session-local logging guards.
Actual native TCP authentication accepted both new passwords and rejected both
old passwords; role attributes remained identical. Rotation receipt SHA-256 is
`cb12a871ddf736b2cfe0af0ee99e50838edea3653eaed19ca80b71f78c7d2bbc`.
The retained schema-13 checkpoint contains the old password verifiers; any future
restore requires fresh rotation before returning applications to service.

## Schema, history and actual runtime acceptance

The paused new writer upgraded schema 13 to 14 before its reader started. Both
Wikipedia tables exist and the real reader retains SELECT access with zero
mutation grants. PostgreSQL system identifier `7706567225121447965`, original S3
store/binding and archive epoch 2 were preserved. Before automatic collectors
resumed, the capture count stayed 31,967 and the archive-file count stayed
176,586; the complete
101,771,296-byte ordered archive-binding manifest matched its pre-upgrade SHA-256
exactly. No provider-budget reset, queue deletion or manual attribution repair ran.

Private HTTP passed both protocol revisions and the exact 98-tool inventory.
Missing/wrong client certificates failed closed with valid-client positive controls;
missing/invalid writer authorization returned 401. Actual reader write attempts
returned SQLSTATE 25006 and 42501 in rolled-back no-op transactions. The edge's
admitted NodePort positive control passed; PostgreSQL, writer and private health
Pod routes remained blocked from the edge. Static reader/writer credentials,
mount separation and read-only transport were preserved under the new images.

Full public HTTP positive/negative and obsolete-name rejection checks passed on
IPv4 and IPv6 for `2025-11-25` and `2026-07-28`. Native released WebTransport probes
passed all four family/revision combinations with unchanged transport settings.
Package tool names now use the published `packages.*` namespace; old aliases are
rejected. Clients must refresh their tool inventory.

The original RFC capture
`blake3:f561023b34507798258530bff923c41bab5d092d71b2cae7da484e6d5ce6d0e0`
retains body
`blake3:58f50168dc03a034edf54305bbf7dd71e1e1f91cb942d5e8e401ab8939890c1a`.
Public and private fixed reads preserve the first page and ready epoch-1 generation
`blake3:254338b7453b0764ba106f0298fd5113f4d90f9aca8028761372660e1614ec81`.
Its immutable 735-byte notice still hashes to
`e3023e4c9c26222fad0449a77d6d7243849a819d3d9ab7af4d2d20a277740156`.
No unpinned replay of this foreground acquisition was issued.

The controller restored the original eight automatic-provider flags, preserving
new passwords and source URL, then restarted writer before reader. Wikipedia
automatic collection is explicitly disabled to preserve the previous continuous
source scope; the new tools remain registered and foreground semantics follow
the release. Both new application Pods each needed one initial startup retry,
matching the earlier observed pattern; its cause remains unproved. One first
post-rollout WebTransport legacy/IPv6 session was rejected. A later complete
four-cell retest passed without edge/config changes; no cause is claimed and the
failure record is preserved. The edge process/profile remained unchanged.

Six guarded read-only samples from **15:03:46.583 to 15:18:50.379 UTC** cover
903.796 monotonic seconds. Every sample showed all three Pods Ready, the same
Pod/container identities and restart counters, PostgreSQL system identity/schema
14, one unchanged writer lock owner, the original S3 store/binding/epoch, complete
reader SELECT grants and zero reader mutation grants. Both runtime configurations
kept all eight original automatic-provider flags true and Wikipedia false. The
edge container/process/profile, certificate and capacity timers stayed unchanged
and active. The minimum sampled free disk space was 881,254,395,904 bytes, above
the existing 128 GiB reserve. Capture count rose from 32,656 to 34,540, while
ready attribution targets rose from 927 to 953.

This is sampled evidence: the maximum gap was 234.456 seconds, not continuous
availability monitoring or a long-term reliability claim. Both application
restart counters were already one at the start and did not increase in these
samples. Public HTTP and released WebTransport matrices passed before the first sample
and again near the end of the sampled window for both address families and
protocol revisions. Active HTTP repetitions used positive and bounded
selector-negative checks; the exhaustive
obsolete-name/Host/Origin negative suite passed separately while automatic
collectors were paused. End-of-window capture-pinned RFC and immutable-notice
reads matched both start records exactly in both revisions. An initial comparison
used `rfc.get` against a `rfc.format_get` response and rejected their different
page metadata shapes despite identical bytes; the matching `rfc.format_get`
comparison passed. Both requests supplied the original capture ID.

At the final sample the global attribution counts were 894,292 pending, 29,439
blocked, 3,775 retry and 953 ready. These are a changing workload snapshot,
not counts of uniformly repairable failures or evidence of full publication.

## Remaining source and proof boundaries

Actual provider status still reports W3C `integrity/catalog_validation` with zero
published standards and Chromium `integrity/source_validation` with zero published
components. Crates inventory import progresses, while metadata CSV parsing pauses
at the existing `csv_field_bytes` limit: maximum 1,048,576 bytes versus observed
1,108,848 bytes. This identifies a concrete bound rather than host-disk exhaustion;
no limit was raised. Other partial coverage and provider job failures also remain;
these three diagnostics are not an exhaustive list. Pending/retry/blocked
attribution remains and is not uniformly
recoverable. Report these source gaps separately from protocol and deployment
acceptance; this operation does not certify a complete corpus or native ChatGPT UI.

The upgrade controller's 23 and checkpoint helper's 28 offline tests passed
independently, including the real same-size/mtime rsync regression. The two narrow
proof continuations passed seven and six tests. Rotation passed 19 offline tests
and a real isolated PostgreSQL fixture: non-TTY prompts, two-role atomicity,
second-role-failure rollback, new/old authentication and no plaintext in server
logs even with global statement/duration logging enabled. Those are separate
from the actual production rotation and checkpoint proofs above. Agent boundary
review is not human GitHub approval. Required published native architecture CI
remains the separate immutable release qualification, not an unexecuted claim of
local Cargo/minikube checks repeated solely for this operational upgrade.
