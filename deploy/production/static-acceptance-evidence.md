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

## Continuation through fixed-source acceptance

A later continuation on 2026-11-10 installed the static foundation with all three
Deployments stopped. The host guard received explicit k3s/Docker dependencies and
an exact live-rule verifier. Actual starts of each daemon were denied for an
invalid guard file, missing file and missing table: six negative cases. Services
and the guard were restored. The original controller's final check rejected
systemd's native empty `Job` value; a separate locked reconciliation verified the
executed sources, all six logs, quiescent controller/watchdog, effective units,
node readiness and zero workloads before recording genuine acceptance. No fault
was replayed and no reboot was tested.

The same short-lived presigned list requests returned 200 on the target, 403 from
the development KVM, then 200 again on the target before expiry. This is observed
source-address enforcement; it does not establish every allowed IPv6 path.
A separately authorized private empty canary in the other owned project produced
403 `AccessDenied` for both applications' list and native bucket-delete requests,
with production-list positive controls. Administrator cleanup deleted only that
empty bucket and confirmed absence. Its creation CLI had exited 1; ownership,
privacy and empty state were independently reconciled without retrying creation
or claiming CLI success or proven creation causation.

All eight fixed-source parser and rights checks then passed against the selected
release libraries. Every failed attempt remains in the same carried ledger:

| Family | Total spent requests |
| --- | ---: |
| RFC | 4 |
| crates | 3 |
| RustSec | 7 |
| MDN | 5 |
| WHATWG | 5 |
| W3C | 2 |
| Chromium | 5 |
| npm | 3 |

The shared GitHub count was 17 of 20. The unchanged predecessor and every
single-use recovery marker remain retained. Helper corrections cover the actual
RFC header, Git v2 HTTP advertisement/HEAD negotiation, early response retention,
and projection of immutable content provenance for rights qualification. The
released rights compiler still requires one exact target and performs its normal
charged source/license acquisitions. This is bounded fixed-source acceptance,
not full collection or publication of these test artifacts.

Focused source-helper checks passed 19 Rust tests and five wrapper tests; the
production startup changes passed 57 Python tests (two optional skips). A fresh
isolated minikube fixture passed encrypted Secrets, TCP/UDP NodePorts, CNI
isolation, PVC restart/coordinated restore, HTTP MCP and both supported
WebTransport revision checks. Its owned profile, daemons, bridge and firewall
chains were removed. These local results do not replace hosted native release
checks or target acceptance.

Starting fresh target PostgreSQL exposed a separate host regression: kernel
AppArmor audit records refused required interprocess signals to the exact
`//&unconfined` stacked peer. Longer bounded TCP startup checks prevented early
liveness interruption but did not resolve that policy fault. PostgreSQL was
stopped again with its existing data preserved; database bootstrap roles/grants
remain unverified. A dedicated profile proposal received separate host-security
authorization; native application and acceptance were still pending at this
checkpoint. Default profiles and restriction sysctls had not been changed.

The newly approved isolated rotation trial had not created keys or S3 objects.
Preparation failures happened before that boundary; failed temporary state was
retained and owned processes were cleaned up. Exported image indexes, native
platform manifests, configurations and layers were verified cryptographically;
Docker's containerd-backed image-ID representation was recorded separately from
traditional config IDs. Runtime rotation/revocation, version-deletion and
administrative mutation denial, real private/public edge acceptance and the
production observation window remain incomplete. No production storage receipt,
collector activation or public service readiness is claimed.


## Dedicated profile and preserved partial rotation trial

After separate host-security approval, the exact dedicated `devres-runtime`
profile was installed and loaded in enforcing mode. Only the three stopped
static-mode Deployment templates and their canonical bundle were updated. The
runtime-default profiles, restriction sysctls and existing boot settings were
preserved. UID70 and UID65532 isolated signal fixtures passed; their observed
labels were bare, so those fixtures alone do not establish the stacked-peer case.
The actual target PostgreSQL then became Ready with zero restarts under the
selected profile, preserving its system identifier, PV/PVC and existing data.

The interrupted first bootstrap had created the data directory but no application
database or application roles. A separately reviewed reconciliation verified that
absence and the exact original mounted initialization SQL before running it once.
Database roles, grants, default read permissions and reader read-only settings
were checked against the intended initialization. No data was recreated or wiped,
and writer/backend remained stopped.

The approved isolated runtime trial created exactly two 900-second keys and
successfully published its first synthetic capture through the released SDK.
Its observer then stopped because it had omitted the SDK's archived integrity
sidecar and sidecar binding from the expected object inventory. There were five
owned objects totaling 808 bytes, within the approved sixteen-key/four-MiB
ceiling. Owned trial containers and daemon were stopped and removed; the capture,
PostgreSQL data and failed observer evidence were retained. Both exact temporary
keys were explicitly revoked and confirmed absent before their expiry, while the
operating baseline keys remained unchanged. This partial attempt does not prove
runtime rotation or post-revocation cold reads. Additional temporary keys require
a separately approved continuation; the first capture must not be republished.

A fresh read-only IAM snapshot found one direct policy and no groups for each
application. Reader permissions were ObjectStorageObjectsRead and
ObjectStorageReadOnly. Writer additionally had ObjectStorageObjectsWrite and
ObjectStorageObjectsDelete. Both scopes remained the selected project with the
exact two approved source-IP conditions. A representative IAM DELETE request to
an administrator-verified nonexistent policy returned 404, so its strict denial
check stopped before the second role. Administrator readback still found that
sentinel absent. This is inconclusive administration-denial evidence, not a
passing 403 test or a claim about provider authorization ordering.

The integrated optional-profile renderer/operator test run completed successfully:
64 focused Python cases, including two existing optional skips. Independent security/storage review
closed those changes. Source acceptance, local minikube and hosted native release
results above remain separate evidence. Production storage admission, runtime
rotation, version-deletion denial, public edge acceptance, collector activation
and the ten-minute observation gate are still incomplete. Public service remains
inactive; backups, reboot acceptance and full corpus coverage are not claimed.


The subsequent approved PostgreSQL restart replaced only the exact UID-bound Pod.
The replacement belonged to the original Deployment and became Ready with zero
restarts. Its system identifier, PV/PVC identities, roles, grants and reader
read-only behavior matched the pre-restart state; writer/backend remained stopped.
The old runtime container record had already been garbage-collected when checked,
so no old-container exit-code or graceful-shutdown claim is made.

Current direct policy and group API responses also confirmed complete pagination:
one policy and zero groups per application, matching the CLI snapshot. An
independent effective-policy review checked their single project rules, current
permission-set definitions, exact IP conditions and the unchanged approved bucket
policy fingerprint. Neither role had IAM or bucket-administration grants. Fresh
known-existing application GET requests returned 403 `permissions_denied` for
both operating pairs. These controls and the earlier real empty-bucket DELETE
403 support the administration boundary; the absent-policy DELETE 404 remains
inconclusive and is not relabeled as a mutation-denial success.

The partial runtime trial's SDK sidecar accounting was corrected independently:
four keys per capture plus the shared descriptor yield five existing keys or nine
for two captures. Eleven offline cleanup tests, nine continuation-flow tests and
five mocked IAM lifecycle tests passed. The corrected controllers preserve the
original first capture, data, spent requests and failure records, and require a
separate explicit scope for two replacement test keys. No replacement key was
created at this checkpoint, and no production storage admission was emitted.


A later bounded kernel audit scanned 1,580 records since 17:00 UTC without reaching
its 2,000-record cap and found zero signal denials naming the dedicated profile.
PostgreSQL remained Ready with zero restarts. Raw kernel messages were not exported.

The version-deletion probe could not obtain a positive version control. Its first
read-only preflight rejected Scaleway's single empty XML `Status` element before
any object request. A separately reviewed compatibility correction preserved that
failure and its two read-only requests. The fresh preflight accepted the empty
status but its exact-object `GET ?versionId=null` returned 404. A separate regular
GET returned the retained 82-byte body with its expected SHA-256 and ETag. Thus five
administrator reads were spent across the original preflight, diagnostic,
corrected preflight and regular positive control; no workload DELETE was sent.
No actual non-null version was available, so version-deletion acceptance remains
incomplete. A versioned canary would require separate resource/policy/test/cleanup
authorization, with results explicitly scoped to that canary. Neither production
bucket versioning nor its policy was changed.
