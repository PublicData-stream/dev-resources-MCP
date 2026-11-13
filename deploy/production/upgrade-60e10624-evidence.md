# Production upgrade to 0.1.0-build.60e10624

This 2026-11-13 checkpoint supersedes the runtime in the
[previous upgrade record](upgrade-5196c629-evidence.md). The requested release is
`60e106241cb3fb6fd84d0dca4ae91017baf39339`. The user corrected the initially
unavailable `2cb89038` target before any production cutover.

## Release and source qualification

Actual privileged GitHub API callbacks verified the signed commit and annotated
tag `5263b252d35f2b5609c3766fd274f03a5649603b`, immutable prerelease and all seven
asset hashes/sizes. Anonymous source bytes matched the exact Git source across
506 regular files, allowing only the eight documented release-stamp surfaces.
Strict provenance verification bound both image subjects to the exact commit,
tag, publisher workflow/run and hosted signer identity.

| Artifact | SHA-256 |
| --- | --- |
| Server image index | `07a69d4f7a4c7302916abd54e0bad322921c50bb684eaf84497f7546cf12b876` |
| Probe image index | `a92d0dbe354f55a3da5fb65bb3f21bf26389dcf8fe817ed789f4964d1f2ebd0b` |
| Corresponding source archive | `71d4148ed0d2c190ea5ae749bd5a4491c6537a0253fe63e8bf58889ad6230e7b` |
| Released native amd64 probe binary | `2512d276c4e2af700ea934a44d427536475c2fc16b9626463bd0cb68ccc85f81` |

The probe's actual bytes were independently linked to the qualified OCI layer
member. Native amd64/arm64 configuration, platform and provenance checks passed.
[Main CI 43337409930](https://github.com/PublicData-stream/dev-resources-MCP/actions/runs/43337409930)
and [tag CI 43344952354](https://github.com/PublicData-stream/dev-resources-MCP/actions/runs/43344952354)
passed all 12 jobs each. [Publisher 43344952352](https://github.com/PublicData-stream/dev-resources-MCP/actions/runs/43344952352)
passed 19 jobs, with only the redundant fresh-CI job skipped after exact-commit CI reuse. These
published native/fixture/minikube/pull gates remain distinct from actual operations.

## Guarded successor and preserved boundaries

The original static deployment's frozen cluster/security guard and capacity,
certificate and emergency-withdrawal paths remain in place. The original anchor
still points to the 5196 journal; that journal gained only the explicit successor
link/phase to the new journal. Its producer revision, source and accepted phase
were preserved. Retired generic install/provision/start commands must not be
used against this upgraded runtime.

The focused controller is installed at
`/usr/local/libexec/devres-upgrade-60e10624/upgrade-controller.py`, SHA-256
`b7c04a128035ec753ec7bdda4788fe0dec2e3ba2c07d02f9fbadecd1313780a9`.
Its private journal is
`/var/lib/devres-production-upgrades/60e10624-20261113`.
The host had rebooted at 00:41:10 UTC. Capture verified unchanged admitted
Deployment/Secret/foundation/Pod UID/image boundaries and adopted fresh processes
only against that verified boot. Preparation pinned a private inventory no older
than 300 seconds; subsequent process, boot, configuration and identity checks
remained strict. Explicit fsynced intents prevent uncertain-operation replay.

Both application database URL/password strings were preserved byte-for-byte;
no password rotation, S3 key, IAM policy or bucket-policy change occurred.
Ten IAM and six S3 metadata reads matched the admitted static binding
`4a59576b1a2977f157ceaf72fbe404f660bd89a44c6246106b65f83989f5c529`.
An actual native GET of the original store claim with the operating reader pair
succeeded. Permanent-version deletion remains denied. AppArmor, firewall,
CNI/RBAC, mounts, ports, TLS and the edge process/profile were preserved.

## Fresh schema-14 recovery checkpoint

Backend stopped before writer. A live precopy was finalized only after clean
PostgreSQL shutdown, using checksum-based rsync and file/directory fsync.
The original PostgreSQL Deployment/PV restarted without restore. The new golden
physical copy contains 13,708,454,671 file bytes and the current password verifiers.
No new maintenance/restore binary was run against the old database: normal target
startup would migrate it to schema 15.

A separate physical copy and the exact old `5196c629` reader image proved actual
schema-14 restore readability, native reader authentication, default read-only,
complete SELECT coverage, zero mutation grants/memberships and the original RFC
capture/notice. All collectors, Wikipedia and writable forwarding were disabled
in the clone. It exposed no host port, mounted no production data and received
only the reader S3 pair. Exact owned clone containers/network were removed.

| Actual evidence | SHA-256 |
| --- | --- |
| Completed checkpoint/rehearsal receipt | `4a6f514f0fc43ed885635e54db0fb469daaa44851fa7d99129510daf058af247` |
| Controller backup acceptance envelope | `c6431a558eb602f94b678d0052ff04902221b833bb04185ede931c926e27f6f2` |
| Complete ordered archive-binding manifest | `696b96643abcea5aad81a62f13b97ddb3e95d8b15402dde54766b08cca1354fe` |

The server's 16 GB tmpfs cannot hold this checkpoint plus rehearsal. A verified
root-private disk copy under the new journal's `checkpoint-volume` backs the
logical temporary work root through a bind mount. No fstab, boot unit or security
policy changed. Logical scratch, clone data and verification paths stay under
`/tmp`; root-private recovery data remains on production disk across reboot.

This is physical PG recovery with the **original immutable S3 retained**.
It is not independent bucket-loss recovery or a reread of every remote object's
checksum. The old schema-13 snapshot is historical, not the current recovery point.
After schema 15/new permanent history exists, an old-image hot swap is invalid.
Any recovery requires a separately reviewed procedure preserving new permanent
captures and mappings; no automatic restore or schema downgrade is provided.

## Schema and actual private/public acceptance

The paused new writer migrated schema 14 to 15 before the reader started.
Three new crates tables and their UNION read view exist, owned by the writer and
readable by the real reader. All public-table SELECT grants remain present;
reader mutation grants and role memberships are zero. The PostgreSQL system
identifier `7706567225121447965`, S3 store/binding and archive epoch 2 remain equal.

Before collection resumed, capture count stayed 45,730 and complete archive-file
count stayed 252,586. The entire 145,949,928-byte ordered archive-binding manifest
matched its pre-upgrade hash exactly. No provider-budget, queue or attribution
reset was performed.

Actual private HTTP passed both `2025-11-25` and `2026-07-28` with the exact
98-tool inventory and corresponding-source offer. Missing/wrong client
certificates failed closed with valid-client positive controls. Missing/invalid
writer authorization returned 401. Rolled-back reader no-op writes returned
SQLSTATE 25006 and 42501; actual reader role defaults were checked separately.
Edge access to PostgreSQL, writer and private health routes was blocked, with an
admitted NodePort positive control.

Public HTTP inventory, positive, selector-negative and obsolete-name checks passed
on IPv4 and IPv6 for both revisions. Shared Host/Origin and private-route
negatives were exercised with the modern revision on each family.
The qualified released WebTransport binary passed all four family/revision cells
with unchanged client transport settings. The public inventory remains 98 tools
and the `packages.*` namespace is unchanged from the preceding runtime.

The original capture
`blake3:f561023b34507798258530bff923c41bab5d092d71b2cae7da484e6d5ce6d0e0`
retains body
`blake3:58f50168dc03a034edf54305bbf7dd71e1e1f91cb942d5e8e401ab8939890c1a`.
Its first 1,024-byte page hashes to
`6026989d1430343743b2c712d7cea16e0fd7a600110623a7a2f9e9cc6944d190`;
ready epoch-1 generation
`blake3:254338b7453b0764ba106f0298fd5113f4d90f9aca8028761372660e1614ec81`
still exposes the immutable 735-byte notice hashing to
`e3023e4c9c26222fad0449a77d6d7243849a819d3d9ab7af4d2d20a277740156`.

The controller restored the eight original automatic-source flags in both roles,
preserving explicit Wikipedia false, then restarted writer before reader.
The paused application Pods each had one initial startup restart; no cause is
claimed. Active-window restart counts and subsequent continuity are recorded below.

Twenty-two guarded samples from **05:05:07.329 to 05:15:37.344 UTC** cover
630.015 monotonic seconds, targeting 30-second intervals; the maximum observed gap was 30.090 seconds
(rounded upward). All samples kept the
same Ready Pod/container identities and restart counters, PostgreSQL identity,
schema 15/four new objects, original store/binding/epoch, one unchanged writer
owner, complete reader SELECT coverage and zero reader mutation grants. Both
roles retained the eight automatic sources enabled and Wikipedia disabled.
The edge/profile and active capacity/certificate timers stayed unchanged and
sampled disk space exceeded the existing 128 GiB reserve. Active application
restart counters were already one at the first sample and did not increase;
PostgreSQL stayed at zero after its planned checkpoint restart. Captures rose
from 45,752 to 46,688.

Active HTTP and released WebTransport repetitions passed early in the observation
and again across its end; the final IPv6 HTTP result at 05:16:21 UTC followed the
last sample.
Active HTTP repetitions used positive and bounded selector-negative checks;
the full negative suite passed separately while collectors were paused.
Start/end capture-pinned RFC page and immutable notice reads matched in both
protocol revisions. Freshness/validation timestamps were not treated as immutable
body identity. This is sampled continuity and bounded endpoint evidence,
not continuous availability, load/failover testing or long-term reliability.

## Operational probe corrections and limits

Independent review caught and fixed unrelated-process adoption during a scale
operation before any production controller execution. The final controller adopts
only the scaled role and rejects all unrelated process drift. Its 46 meaningful
offline fixtures and the checkpoint helper's 35 passed independently.

A migration-envelope builder initially used the small-file reader on the large
archive manifest. Streaming artifact hashing consumed the existing completed
proof; no schema migration or manifest query was replayed. An initial ported
sampler read active candidate flags during the paused phase. Direct live Secret
flags proved both roles remained paused; the corrected sampler reads the guarded
current variant and verifies state consistency. That incorrect snapshot is retained
but explicitly excluded from qualification. Sampler source SHA-256 is
`9c21d7e2b3eb51019fe52798a981336f8775dd69b0a4445d70f480f4ead6820b`;
controller source is separately pinned above.

## Source progress and remaining limits

The final public status snapshot was recorded at **05:15:43 UTC**. W3C now reports
1,721 catalog standards across 18 completed catalog pages, two published standards
and two snapshots. Its current lane subsequently reports `capacity/projection`.
The older catalog-retention failure remains in diagnostics alongside the later
successful catalog-publication timestamp; it is not evidence that the catalog
is still unavailable.

Chromium still reports zero published components/snapshots. Its `src` and `site`
lanes progressed to traversal and have success timestamps newer than their
retained integrity/source-validation failures. Current website acquisition reports
a bulk-operation deadline/capacity failure; the archive lane retains HTTP 403.
These independent lanes and historical failure timestamps do not establish one
shared unresolved parser cause or complete component publication.

Crates inventory import remains active with no published inventory selector yet.
Metadata's latest result remains paused at `csv_parsing/csv_field_bytes`:
1,048,576 bytes maximum versus 1,108,848 observed. The release streams ignored
fields but preserves the selected-field limit; it does not admit this selected
oversized value. Progress is staged work, not completed enrichment. No limit,
retry budget, queue, policy or role was relaxed to obtain a successful status.

These diagnostics are non-exhaustive and collection continues. Pending/retry/
blocked attribution and other provider coverage gaps remain. Source status
progress is separate from a rights-qualified public-body acceptance test or
full-corpus completeness.

Compilation, offline fixtures, published native CI, live source acquisition,
cluster/edge acceptance and production observations are separate evidence.
No full Rust/minikube rerun was claimed solely for these operational artifacts.
Agent review is not human GitHub approval. This checkpoint does not certify
complete corpus publication, continuous availability or native ChatGPT UI.
