# Static authentication preparation

Checkpoint recorded on 2026-11-10 for `0.1.0-build.a938112b`. This supersedes the
target release and authentication choice in the [earlier checkpoint](acceptance-evidence.md),
not its historical results. The selected fresh deployment uses `scaleway_static`;
the renderer's default remains `broker`. No existing corpus is being migrated.

## Immutable release qualification

The signed commit is `a938112b5af87996661ddd91ae68755dc0d579b9`; the signed
annotated tag object is `a559d2383e71fc9293bf6833243fff7a93ad04d7`.
The [publication run](https://github.com/PublicData-stream/dev-resources-MCP/actions/runs/42805804979)
completed fresh, version-stamped native amd64 and arm64 release checks. Its
accepted digest artifact agrees with the public release assets. The downloaded
[corresponding source](https://github.com/PublicData-stream/dev-resources-MCP/releases/download/0.1.0-build.a938112b/source.tar.gz)
has SHA-256 `98f107f09bc4cb69b519408cbd21518307470f77006597bdc70a3feebe339a06`.

| Published image | Index SHA-256 |
| --- | --- |
| Server | `a966e685fe3d32ffc5625b471d0ab77b71d881827f4ae17e5a16bd2b760016a8` |
| Broker | `15109a00b10b92fd313838ab6caf6444a3c816ed4abbccf1a4ecc67581903ef1` |
| Probe | `8f9df1e095d6538b8244b98ddefd37a4bec8ec486a82b7d8ade35f1292fbd5b7` |

Both hosted architectures passed the reader transport mutation fence, thirteen S3
cases, and the stopped broker-to-static-to-broker scenario preserving archive
binding, epoch and cold historical reads. The direct static-only revoked-key
readiness and stopped pair-rotation branch has retained local amd64 evidence;
the hosted broker scenario does not execute that branch on arm64. These are
fixture results, separate from actual Scaleway enforcement.

Release qualification permits the production operator to admit real static
provider evidence. It does not bypass its eight receipt checks, credential/policy
binding, expiry, stopped-role checks, source/edge acceptance or boot safety gate.
The release qualification does not admit bundles from the previous release.

## Inactive target preparation

The target cached the pinned server/probe images and verified their native amd64
architecture and release revision. Sixteen source files from signed tooling
commit `7c7a24fc7a715833c926398fa02769f083a68d3d` were transferred with individual
hashes and verified before extraction. The transfer archive SHA-256 is
`1b68db7d5a0ea1573826a698e645a11422efe1eaa8e976efe9d2478bdc22e2a2`.

A new root-private static bundle remains in phase `prepared`; both older bundles
were preserved. It contains corpus PostgreSQL initialization and separate mTLS
identities, without a broker keyring or broker PostgreSQL initialization. The
23-resource manifest passed server-side dry-run. PostgreSQL, writer and backend
all render with zero replicas. No resources were applied: the final inventory
found zero devres Deployments, Pods, PVCs and Secrets and zero Docker containers.
Both permanent PostgreSQL directories remain empty. No passing provider receipt
was created, and no workload, public edge or collector was activated.

## Local change verification

After updating the release pins and offline policy tooling, workspace format and
locked all-target clippy with warnings denied passed. The complete locked
workspace test command passed, including documentation tests: 847 non-documentation
tests passed and 66 were ignored. The Python suite ran 768 tests successfully with
four existing skips; the focused offline policy suite contains nine cases.
Current cargo-audit and cargo-deny passed against fetched advisory data.

The focused source qualification helper's seven Rust tests passed without live
source requests. Independent MCP/API, Upstream/Storage and Security Boundary
review closed for inactive preparation. No local infrastructure harness was
rerun for these constant, documentation and offline-policy changes; the exact
runtime's hosted native infrastructure results are recorded above and in the
published run. No public runtime contract, dependency lockfile or database schema
was changed by this preparation.

## Read-only account verification

The operator initially used the authenticated local Scaleway CLI only for reads.
Its credentials were neither printed nor transferred to the deployment host.
API-key identifier hashes matched the two server files to the intended serving
and writer applications and the intended project. Both keys have explicit
provider expiration timestamps. Neither application belongs to a group.

The serving IAM rule has `ObjectStorageObjectsRead` and `ObjectStorageReadOnly`;
the writer rule additionally has `ObjectStorageObjectsWrite` and
`ObjectStorageObjectsDelete`. Both rules are project-scoped and contain exactly
the supplied deployment IPv4-or-IPv6 condition. Successful requests from this
server alone do not prove denial from other egress addresses.

The original key files were narrowed from mode 0664 to 0600 and copied to a
separate root-owned private bootstrap directory. No key value entered arguments,
repository files or diagnostic output. The obsolete issuer is not part of the
static profile and its API-key-list permissions are no longer an admission gate
for this deployment.

Before the approved bucket-policy application, signed S3 reads from the
deployment host returned:

| Request | Serving | Writer |
| --- | --- | --- |
| `production/` list, maximum one key | 403 `AccessDenied` | 403 `AccessDenied` |
| Out-of-prefix list, maximum one key | 403 `AccessDenied` | 403 `AccessDenied` |
| Bucket policy GET | 200 | 200 |

Policy GET is a read operation; this result alone does not establish policy-write
authority. The pre-change bucket policy lacked `s3:ListBucket` for both applications,
granted object access beyond the intended prefix, and permitted writer permanent
object/version deletion. The missing list allowance was the initial blocker,
resolved by the policy application below. Other requirements still need
effective-policy and live-provider acceptance.

## Approved policy application and remaining gates

The [offline policy helper](../../scripts/scaleway-static-policy.py) produces a
fresh private candidate, never an applied policy or a passing receipt. The
candidate made from the observed policy preserves the owner statement and an
unrelated application, replaces only the selected serving/writer principals, and
adds minimal role actions on the selected prefix with TLS and both source IPs.
Its canonical JSON SHA-256 is
`403a6e2d2ea4e4624f886fa8dada3452867a1aebcd20f67916012d0f3d7c20a7`.

Scaleway's current `2023-04-17` bucket policy is an allowlist intersected with IAM
permissions. The corrected examples omit mutation/deletion actions rather than
relying on ineffective Deny statements. Other matching grants and other buckets
still require review. See the official
[bucket policy semantics](https://www.scaleway.com/en/docs/object-storage/api-cli/bucket-policy/)
and [multipart permission mapping](https://www.scaleway.com/en/docs/object-storage/reference-content/s3-iam-permissions-equivalence/).

The user subsequently authorized applying only this bucket-policy candidate with
the CLI. The original policy was re-read and matched the saved preimage before
the single write. Provider readback normalized singleton lists into strings and
reordered set values; an exact comparison initially rejected that shape. A separate
comparison verified all statements, actions, resources, principals and conditions
equal after only those normalizations. There was no second policy write. The
readback's canonical SHA-256 is
`355031577992d58dfb4cf200d76fcb54dd418df0b93ab478193ef18ffa3ca0a0`.

Post-application S3 reads returned 200 with zero keys for `production/` listing
with both roles, and 403 `AccessDenied` for both out-of-prefix list requests.
Bucket policy GET remained 200, consistent with the IAM read-only permission set.
That policy approval authorized no other CLI writes. At that checkpoint no S3
object or multipart upload had been created, and no key or IAM policy had been
changed. The subsequent bounded trial below had separate explicit authority.

## Separately approved real-provider trial

The user authorized one 900-second test key for each existing workload application,
at most two disposable object keys totaling at most 20 MiB under a unique
`production/.acceptance/` run, and exact recorded cleanup. The operating keys,
permanent capture layout and policies were outside the permitted mutation set.

The [live helper](../../scripts/scaleway-static-live-probe.py) was checked with
13 offline tests; the complete Python suite then ran 781 tests successfully with
four existing skips. Independent Security Boundary and Upstream/Storage review
closed for this bounded attempt. The transferred helper's SHA-256 was
`bcf2cf2c28c3dcb4e6ce994d715c8f0b52cb712c5ae2bd113a81c5360809bab4`.
The operator also independently reviewed the private key-lifecycle and exact
cleanup scripts before creating either test key. All local and remote temporary
files were under `/tmp`. Fsynced journals there survive process failure, not a
deployment-host reboot.

Both test keys were created once, with application/project/expiry readback, after
recording the original operating-key inventory. The expected four-pair credential
fingerprint and designated state root were recorded before the first S3 request.
There were no retries, replayed mutations or uncertain outcomes.

| Real Scaleway check | Observed result |
| --- | --- |
| Writer conditional create and overwrite collision | Create 200; collision 412; original content unchanged |
| Reader GET/HEAD/list | Passed against the owned conditional object and run prefix |
| Reader PUT/DELETE and multipart initiation/part/completion/abort | All denied with 403 `AccessDenied` |
| Writer multipart | 17 MiB completion/readback, conditional completion collision, and interrupted upload abort passed |
| New-object storage class | HEAD confirmed `ONEZONE_IA` for small and multipart objects |
| Writer object DELETE | Denied with 403 `AccessDenied` |
| Other-prefix object/list access | Denied for both test identities |
| Test-key revocation | Both API keys deleted and absent in IAM; both then received S3 403 before expiry |
| Operating keys after test-key revocation | GET/list remained 200; original IAM inventory unchanged |
| Exact administrator cleanup | Owned contents verified before deletion; final object and multipart listings empty |

The helper made 35 initial requests and six post-revocation requests. Request
bodies totaled 17,826,267 bytes; the two completed objects totaled 17,825,834 bytes.
At revocation readback, at least 684 seconds remained before the earliest test-key
expiry, separating observed revocation from automatic expiration. Administrator
cleanup used ten additional requests and found zero remaining objects or uploads.
Only the two journal-bound keys were deleted. The bucket policy remained identical
to its approved post-application fingerprint. Revoked-key plaintext files and
transfer archives were removed; retained creation metadata was redacted.

This is partial provider evidence, not a production acceptance receipt. The bucket
was unversioned and returned no actual non-null version ID, so version-deletion
denial was not established. No other bucket or alternate egress probe was
authorized. Administrative mutation denial and a controlled restart rotation of
the operating pairs were not tested. The helper leaves those checks incomplete;
the real production receipt was not emitted, and no workload was activated.

The old RFC integrity failure and its spent requests remain preserved; no source
gate was retried or relabeled as belonging to this release. Public edge, boot
failure denial, certificate reload, ten-minute observation and corpus acceptance
remain separate gates. Backups and full corpus coverage are not claimed.
