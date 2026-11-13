# Production upgrade to 0.1.0-build.65236494

This 2026-11-13 update supersedes the [previous schema-15 runtime](upgrade-60e10624-evidence.md).
The deployed source is `65236494ad7a837243d16c7e92e177df77a7d226`.
The active phase is `collectors_active`, with the original eight sources enabled
and Wikipedia disabled. Schema 15, PostgreSQL's original process, credentials and
permanent captures were preserved. No repository implementation source changed.

## Release and source qualification

The [immutable prerelease](https://github.com/PublicData-stream/dev-resources-MCP/releases/tag/0.1.0-build.65236494)
was published at 10:26:20 UTC. Real privileged GitHub API callbacks verified the
signed commit and annotated tag `2c8578adcb8a25a4d3c3ff9e2c18334f3ced6d7b`.
All seven assets matched their API hashes and sizes. Anonymous corresponding-source
bytes matched both the release asset and publisher artifact. All 508 regular files
matched tagged Git source, allowing only eight established version-stamp surfaces;
inverse stamping restored exact tagged bytes. Source archive data was not executed.

| Artifact | SHA-256 |
| --- | --- |
| Server image index | `efe9f706d82d535b89c18cfe9fbc68d7e7f586e014d534b00828cc8639b2c52d` |
| Probe image index | `62f7798ac151ddd0c9875bb903abe28b1866cc5bcc8e16768697c275861812ca` |
| Corresponding source archive | `ef1836ea6756b8b938a8bc580c4cf12154146ea483f784cb59839ce48d874b9b` |
| Released native amd64 probe binary | `fae2188c9ee003b7d2090deb1e964a52b8497cbe3384b10a0a8cd5d7182f2e92` |

Anonymous raw OCI index/platform/config bytes established native amd64/arm64
identity, revision, version, license, entrypoint and non-root user. Strict
attestation verification covered both indexes and all four server/probe platform
subjects, binding source/signer commit, tag, publisher workflow, GitHub OIDC issuer,
hosted runner and publisher run `43406865012`, attempt 1. The probe's bytes were
independently bound to its exact regular executable layer member.

[Main CI 43392795864](https://github.com/PublicData-stream/dev-resources-MCP/actions/runs/43392795864)
passed all 12 jobs, including native amd64/arm64 Rust, Docker, minikube,
minikube-S3 and edge acceptance.
[Publisher 43406865012](https://github.com/PublicData-stream/dev-resources-MCP/actions/runs/43406865012)
passed 19 jobs; only redundant fresh CI was skipped after exact-revision CI reuse.
Hosted full anonymous pulls and native-image tests passed. The artifact reviewer
independently fetched public metadata and native probe layers, rather than repeating
full server layer pulls. Separate tag CI was still running at the retained release
qualification snapshot; its later result is not claimed or used here.

## Guarded same-schema transition

The controller is installed at
`/usr/local/libexec/devres-upgrade-65236494/upgrade-controller.py`, SHA-256
`24c69b41e586c4bebb4d2a829ae59a40fd87cb3963c65eebd1b643536379504e`.
Its root-private journal is `/var/lib/devres-production-upgrades/65236494-20261113`.
The original and 5196 anchors remain unchanged; the 60e journal gains only the
explicit successor link and phase, retaining its producer identity and accepted
historical state. Retired generic install/start commands must not target this runtime.

Capture and preparation invoked the actual frozen predecessor guard. Subsequent
checks retained exact boot, PostgreSQL/edge processes, Deployment/Secret security
projections, static admission and namespace foundation. Only the role being scaled
could adopt a new Pod projection. Private exclusive fsynced intents, prepared/source
hashes, UID/resourceVersion tests and fresh evidence bound each transition. Secret
patches used stdin. Receipt age was rechecked after hashing and the final live guard.

Only application images, corresponding-source URLs and the temporary pause/resume
of eight existing collector flags changed. Both app database URL/password strings,
actual database role password verifiers/settings/grants, S3/TLS secrets, AppArmor,
firewall, CNI/RBAC, mounts, ports and edge configuration were preserved. Ten IAM
and six S3 metadata reads matched static binding
`4a59576b1a2977f157ceaf72fbe404f660bd89a44c6246106b65f83989f5c529`;
there were no IAM/S3 administrative mutations. Permanent-version deletion remains
denied. No provider-budget, queue or attribution reset occurred.

This update performs no PostgreSQL restart, physical checkpoint, restore,
archive rebind or schema migration. PostgreSQL system identifier
`7706567225121447965`, schema 15, S3 store/binding and archive epoch 2 remain exact.
Full ordered manifests matched across the quiescent and paused-target checkpoints:
**46,751 capture rows and 258,824 complete archive-file rows**. These checks cover
capture records and archive descriptors; they do not reread every remote body or
establish independent bucket-loss recovery.

The first read-only preservation query failed with SQLSTATE 42703 because it
selected `rolconfig` from `pg_authid`. Its failed evidence was retained. The
reviewed v2 helper joined `pg_roles` by OID for settings and retained verifiers only
inside server-private evidence. Its SHA-256 is
`c2c0e538ce94b0c59ac2e63d05fa3be364fb4d75ad6dc717e73ee455381329fa`.
Only the corrected successful checks contributed to acceptance; no data or
permissions changed to obtain the result.

The target writer became Ready at 10:47:24 UTC, followed by the reader at
10:48:00 UTC with collectors paused. Accepted private/public gates preceded
collector reactivation at **11:01:14 UTC**. Both configurations restored RFC,
crates, RustSec, MDN, WHATWG, W3C, Chromium and npm to true. Wikipedia remains
explicitly false, with new `user_agent` and `oauth2_token_file` keys **absent**.
No custom Wikipedia User-Agent, OAuth token or mount was introduced.

Recovery remains a separately reviewed operation preserving current permanent
history and exact configuration preimages. Source review found same-schema
compatibility; an old-image rollback was not rehearsed. Historical schema-14
physical recovery data is not a current schema-15 rollback point. No automatic
restore, downgrade or process rebaseline is provided.

## Actual private and public acceptance

Private mTLS HTTP passed both `2025-11-25` and `2026-07-28`, exact 98-tool inventory
and target corresponding-source offer. Missing/wrong client certificates failed
closed with valid-client positive bookends. Missing/invalid writer tokens returned
401. Actual reader defaults were checked; rolled-back no-op writes produced
SQLSTATE 25006 and 42501. Edge access to PostgreSQL, writer and private health was
blocked, with a successful admitted NodePort control. These checks passed again
after the application restarts used to restore collection.

Public IPv4/IPv6 HTTP passed both revisions and the exact 98-tool namespace,
initialization, discovery, corpus-status shapes and selector checks. The paused
full run additionally covered obsolete/nested names in both revisions and common
Host/Origin/private-route negatives in the modern revision on each family.
Active runs retained the bounded normal contract without repeating that exhaustive
HTTP negative block. The released native WebTransport probe passed both families
and revisions with ordinary negative checks and no transport overrides. Failed
family-specific hosts mounts terminated before probing.

| Completed public pass | Receipt interval, UTC | HTTP logical cells | Native WebTransport cells |
| --- | --- | --- | --- |
| Paused, full HTTP negatives | 10:49:05–10:59:37 | 4 | 4 |
| Active, early | 11:02:23–11:06:06 | 4 | 4 |
| Active, late | 11:09:13–11:13:05 | 4 | 4 |

Intervals are first/last receipt times. The late pass overlapped the final stability
samples; its final IPv6 HTTP receipt followed the final sample. Compact WT receipts
prove the qualified probe's successful checks; exact target version/source assertions
were also exercised through HTTP. No continuous availability or all-provider claim
is inferred from these finite probes.

Baseline, active-start and active-end HTTP reads preserved both revisions of RFC
9000's pinned capture, body, first 1,024-byte page and immutable 735-byte notice:

| Identity | Digest |
| --- | --- |
| Capture | `blake3:f561023b34507798258530bff923c41bab5d092d71b2cae7da484e6d5ce6d0e0` |
| Body | `blake3:58f50168dc03a034edf54305bbf7dd71e1e1f91cb942d5e8e401ab8939890c1a` |
| First page SHA-256 | `6026989d1430343743b2c712d7cea16e0fd7a600110623a7a2f9e9cc6944d190` |
| Notice generation | `blake3:254338b7453b0764ba106f0298fd5113f4d90f9aca8028761372660e1614ec81` |
| Notice SHA-256 | `e3023e4c9c26222fad0449a77d6d7243849a819d3d9ab7af4d2d20a277740156` |

## Observed stability and remaining source gaps

Twenty-two guarded samples from **11:01:35.940 to 11:12:05.954 UTC** covered
**630.013754 monotonic seconds**, with maximum gap **30.055946 seconds**. All roles
remained Ready; exact Pod/container/process, writer-owner, edge/profile,
schema/archive, reader-grant and eight-source/Wikipedia flag identities stayed
stable. Capacity and certificate timers remained active. Minimum free space was
844,973,260,800 bytes (786.94 GiB), with at least 61,678,355 free inodes.

The active writer and backend each had one initial startup restart; PostgreSQL
had zero. Private previous-start logs contained the sanitized “Durable storage
unavailable” error; the underlying cause was not established. No additional
restart or owner drift occurred in the observed window. Capture count rose from
46,754 to 47,225 and complete archive files from 258,862 to 260,858. This bounded
sampled stability result does not establish load, failover or long-term reliability.

The public status bookend begun at 11:12:33 UTC still reports incomplete source
coverage: W3C has 1,721 catalog standards, four published standards/snapshots and a
current `capacity`/`catalog_retention` failure; Chromium has four catalog components,
zero published components/snapshots and `unavailable`/`raw_retention`. The crates
metadata lane is paused at `csv_parsing`: a 1,108,848-byte field exceeds the unchanged
1,048,576-byte bound; inventory restoration is degraded. The final observation
snapshot has 1,635,510 attribution targets pending, 44,694 blocked, 7,432 retry and
4,219 ready. These are dated operational observations, not resolved source/license
gaps or full-corpus acceptance. Wikipedia activation and its requested identity
remain deferred.

## Durable receipt and evidence boundaries

Final server-local closure rehashed both complete before/after manifests, rebound
the accepted private proofs, revalidated all 22 samples, current guard, exact
configuration/credential preservation and public summary: all ten checks passed.
Private production evidence remains root-only on the server. Public-only evidence
contains 27 records plus its manifest; all hashes were checked again after upload.

| Accepted receipt/artifact | SHA-256 |
| --- | --- |
| Public evidence archive | `265baecc0cd6e86592753c18602401a6657d1e475ad848ac16102973ca9cc162` |
| Public evidence summary | `e134625bdce943aa7f583994c7c14dace6c93da63d0b68a251ad242100657ec3` |
| Complete ordered archive manifest | `dc75901095df5964deb9b68ef55e8b04c6e218e1c8370985b8a561920f6a5d4c` |
| Complete ordered capture manifest | `5cd291fbc39317fc9a1dc82f29ad98c570d43d551901d0ceba3b6b3ca7db6f81` |
| Durable production acceptance | `9ef11abd602eeae42d24454e925ca4edb6e3d88f148f324244ee6046e97711b5` |

At 11:21:45 UTC, durable acceptance retained 125 private files (348,680,782
bytes). Its private evidence manifest hashes to
`b01fc69f461e78fc20d48005d1483332a5f54050dcd11eca21459bf26d51836f`.

The journal's durable operational evidence and `production-upgrade-completed.json`
bind acceptance, this document, public evidence and the actual `collectors_active`
phase. Original historical anchors remain preserved. First-party controller
fixtures passed 44 tests under both author and operator invocations; bounded
parser and acceptance/observation mocks also passed. Independent reviews inspected
the integrated source and actual public/private qualification. Agent review is not
a human GitHub approval. No push, new release publication or production evidence
export was performed.

Hosted native CI, operator fixtures, immutable publication, actual cluster/edge
checks, live source coverage and native ChatGPT UI are separate evidence. This
record accepts the scoped operational upgrade; full corpus/attribution completion,
Wikipedia/OAuth readiness, independent S3 backup and native ChatGPT UI were not
accepted. Specification, Configuration and OxiRule behavior were not changed.
