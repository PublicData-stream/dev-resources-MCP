# Static authentication deployment

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

## Approved versioned-canary validation on 2026-11-11

The user separately approved a composite validation method and one new private
versioned bucket in the same project and Paris region. The canary used one key
with two fixed synthetic bodies of 82 bytes each. Its workload grants matched the
production actions, IP and TLS conditions after only bucket/prefix substitution;
the sole additional principal was the exact, separately verified administrator,
with authority confined to that canary. No IAM API key or IAM policy was created or
modified, and production bucket versioning was not enabled.

A read-only preparation initially rejected the actual canonical ACL owner format.
Scaleway's [pinned canonical-owner helper](https://github.com/scaleway/terraform-provider-scaleway/blob/ec3786444d5378cda13079383530d065001c9d23/internal/services/object/helpers_object.go#L908)
confirmed `project_id:project_id`,
independently bound to the approved organization by the Account project response.
The original proposal's format assumption, original controller, responses and
counter state remain preserved. A reviewed continuation reused the ten successful
IAM responses and unchanged policy/ACL bytes with their original observation
times. It spent only the remaining reads and did not reset the budget. Creation
dispatched within the bounded inherited-observation age and completed-snapshot
review deadlines; reconstruction time was not presented as a new IAM fetch.

Native policy installation returned HTTP200 with an empty body. The first helper
expected 204 and stopped before any object PUT. A separately reviewed continuation, consistent with the [pinned SDK success handling](https://github.com/aws/aws-sdk-go-v2/blob/service/s3/v1.114.0/service/s3/deserializers.go),
verified that known acknowledgement and the exact installed policy, then performed
only the unattempted tail. Bucket creation, versioning and policy installation
were not repeated. Actual statuses remain recorded; the two compatibility fixes
did not alter workload permissions or relax the required native denial.

Both actual versions had distinct non-null IDs and exact administrator GET/hash
verification before and after the workload checks. Using the existing operating
pairs on the target, both applications returned GET200, prefix LIST200, known
version DELETE403 `AccessDenied`, then GET200 again. Native request IDs, body
hashes, ETags and exact version references remain in private evidence. This was
six workload reads and two denied mutation attempts, with no recreation or retry.

Administrator cleanup used the ordinary exact-version DELETE API without MFA,
retention or bypass overrides: both returned 204 and their subsequent GETs
returned 404 `NoSuchVersion`. Complete bucket-wide object, version, delete-marker
and upload checks were empty. Only the canary policy was removed, with typed
`NoSuchBucketPolicy` readback, and the verified empty owned bucket was deleted.
HEAD404 and qualified project inventory absence confirmed removal.

Fresh final identity, normalized IAM memberships/policies/rules/key metadata and production
policy/ACL/versioning/features matched the before-state. A separate authenticated
target read also confirmed both operating credential-file fingerprints unchanged.
The original single-bucket probe's false version-deletion result and bytes remain
unchanged. Production non-null-version testing is still explicitly unproved;
the new evidence uses the approved production-policy-audit-plus-versioned-canary
method, with final independent composite admission recorded separately.

The administrator used 63 S3 reads, nine S3 mutations and 20 read-only IAM/project
requests, within the respective 64, nine and 24 caps. Data PUTs totaled 164 bytes.
No secret key values or authorization headers were printed, and administrator
credentials remained local. Earlier rotation-trial artifacts and captures were
outside this canary cleanup scope. Actual provider checks, offline helper tests,
runtime rotation, public edge and production activation remain separate evidence.


Final independent source-and-evidence review admitted only the generic
`permanent_deletion_denied` check for the current unchanged production binding.
A separate immutable composite admission links all 92 administrator request
intents/results, eight target requests, final credential-file fingerprints and
the unchanged original false probe; it does not replace any original result.
The production operator's current private-input fingerprint calculation also
matched this binding. No all-check storage receipt or runtime Secret was emitted.
The separately pending runtime rotation/revocation trial still requires its two
replacement-key approval; writer/backend and public activation remain stopped.

## Requested retry under reduced writer IAM on 2026-11-11

The user requested another actual version-deletion trial. Fresh IAM metadata
showed that the writer's `ObjectStorageObjectsDelete` permission set had been
removed; its Read, Write and ReadOnly sets and the serving role's two read sets
remained. The first preparation stopped before any S3 request because the helper
had required the broader writer permission. Independently reviewed continuation
made that previously allowed set optional, retained the required sets and rejected
any other permission. Nine successful IAM responses were preserved and reused
with their original times and spending. The current writer policy fingerprint
differs from the previous admission, which remains unchanged historical evidence.

Two administrator S3 GETs produced no HTTP result. Their original intents remain
unresolved and charged. Each was followed by one separately journaled manual
read with its own label and known native HTTP200 response; neither result was
assigned to the unanswered request. Reviewed continuations retained all file
hashes, counters and original observation times, without replaying a mutation.
The acknowledged bucket creation, private owner ACL, Paris location and separately
verified creation timestamp established ownership before only the unattempted
seed tail resumed. The final continuation used direct verified TLS for
administrator S3 with a 30-second socket timeout; IAM kept its original route
and 20-second timeout. The existing
45-second elapsed response checks remain cooperative checks, not a hard wall-clock
kill. No automatic retry, redirect or TLS verification relaxation was introduced.

Both applications again completed GET200, exact-prefix LIST200, actual non-null
version DELETE403 `AccessDenied`, and GET200 with the unchanged latest body.
All eight native request IDs were captured: six reads and two denied deletion
attempts. This is the intended deletion-confinement success. Before the trial,
authenticated server-side comparisons confirmed the operating credential files
unchanged; no secret values were exported. The current policy and canary
equivalence, source changes and actual target evidence received independent
review. The final helper's 30 offline tests also passed separately.

Administrator post-checks verified both versions and their exact hashes remained.
Both exact version deletions then returned 204 with typed `NoSuchVersion` GET404
readback. Whole-bucket version, object and upload inventories were empty; canary
policy removal and bucket deletion were confirmed by typed policy absence,
HEAD404 and qualified project inventory absence. Fresh final IAM, key inventories
and production bucket metadata matched this retry's before-state. Authenticated
server-side checks also confirmed both operating credential files unchanged.

Total spending was 20 read-only IAM requests, 63 administrator S3 reads and nine
administrator S3 mutations, plus six workload reads and two denied DELETEs.
All 100 attempts were charged: 90 administrator and eight workload HTTP responses
were recorded, with the two unanswered GET intents explicitly retained. Payload
PUTs totaled 164 bytes. Independent final composite review passed; a separate
immutable admission records only `permanent_deletion_denied` for this retry's
current binding and preserves the original producer and historical admission.
No actual production non-null version was tested, and no overall production
receipt or runtime Secret was emitted. Runtime rotation,
multipart acceptance under the reduced IAM policy and public activation remain
separate gates. PostgreSQL remains ready; writer/backend remain stopped.

## Current storage admission on 2026-11-11

The user retained the permanent-deletion prohibition. The writer IAM rule was
restored to its previously reviewed four permission sets so multipart abort works;
the bucket allowlist still omits ordinary and version deletion. No serving grant,
source-IP condition, project scope or bucket-policy statement was broadened.

A fresh 35-request trial used the actual operating reader/writer pairs. It proved
read/list, reader mutation rejection, conditional-write collision handling,
17 MiB multipart completion and abort, ordinary deletion rejection, and both
roles' out-of-prefix read/list rejection. Its two exact disposable objects were
removed through 14 administrative requests after ownership checks. The final
prefix and multipart inventories were empty. Trial result SHA-256 is
`25ff56da90380c6beb2faa70da3dec9609507b0db25a2487dbc2688ebe0e3c03`;
cleanup result SHA-256 is
`41d900d568c5fc29df0aac87fca34b80265d1748fcc6c013b35cde395477d492`.

Both apps rejected a same-value PATCH of a known existing policy with native
HTTP 403 `permissions_denied`. Four administrative GETs confirmed the complete
policy/rule metadata stayed unchanged. This representative mutation rejection
and the complete effective-permission review support the administration gate;
the earlier absent-resource HTTP 404 remains inconclusive. The verified PATCH
receipt SHA-256 is
`391d36e7f11c0adaac2d1ad55c7a8e53d38c55e84ab8795c7043e05f97fa4eef`.

The dedicated project contains only the archive bucket. Current project-scoped
IAM and fresh prefix denials combine with the dated cross-project canary evidence
for the finite other-bucket boundary. This is not a guarantee about future
unmanaged buckets. IAM, bucket-policy or credential changes invalidate the
admission assumptions. Permanent-version deletion admission preserves the earlier
actual versioned-canary evidence and explicitly reviews equivalent current rules;
no non-null version was created in the unversioned production bucket.

The separately approved two-key continuation then completed against the retained
isolated PostgreSQL/archive. Each temporary SDK role started once. Phase 1 was
preserved, only phase 2 was published, final process identities stayed unchanged
across revocation, and cold readers recovered both captures before and after
revocation. IAM confirmed both trial keys absent at least 751 seconds before
expiry; their actual S3 GET/list denials occurred at least 719 seconds before
expiry. This proves explicit revocation rather than natural expiry. It is
synthetic SDK evidence, separate from production writer-RPC delegation.

The continuation has 51 explicit native requests plus 19 carried requests. Ten
new control responses retain native request IDs; 41 inherited observer records
retain status/body hashes without request IDs. Original failed attempts remain
preserved. All owned continuation containers and its exact empty private network
were removed. The final nine objects, including integrity sidecars and bindings,
totalled 1,557 bytes. Exact cleanup used 42 calls, or 52 of the 64-call ceiling
including all preflight reads, with no uncertain response. The prefix and upload
inventory were empty, and the revoked trial credential copies were removed.
Runtime completion SHA-256 is
`bb62a65d19ae3af17ac2d3286fd70c1d958b197ee0ca7288bf7f1c695090b636`;
exact-cleanup completion SHA-256 is
`2c1fd1d9b2cf06f769af6091055f55c1ae1bd6a6726b154a944c83ab9ec63126`.

After cleanup, ten fresh IAM reads and six S3 metadata reads matched the preceding
identity, full effective IAM, bucket state and binding. A separate server-only
calculation confirmed the actual operating files still match that binding.
Independent method and actual-evidence reviews closed all eight storage checks.
The admitted receipt SHA-256 is
`c63b888a5e7a39f2c2be0e8f03a613a37e96e783c8febd45919108eb057d79c2`;
the final metadata snapshot SHA-256 is
`3cd2f9f7918c4320d4a7dfa8d23c47fc57cf3106b4349ef55fd8112337a90bb2`.
This storage receipt alone does not establish public transport, attribution,
collector activation or complete production readiness.

## Public deployment and operational acceptance on 2026-11-11

The immutable `0.1.0-build.a938112b` server image was deployed with
static reader/writer credentials and schema 13. The matching released probe was
used for qualification. The existing PostgreSQL system
identifier, archive binding/epoch and permanent captures were preserved. The
broker is not part of this static runtime. The public endpoints are
`https://dev-resources.mcp.publicdata.stream/mcp` and
`https://dev-resources.mcp.publicdata.stream/mcp-wt/v1`.

Real operating-pair storage admission above was followed by authenticated private
and public acceptance. The actual `devres_reader` connection proved SELECT-only
permissions, no writer membership and read-only default; attempted no-op writes
failed with SQLSTATE 25006 and 42501 in rolled-back transactions. Both private
HTTP protocol revisions exposed the exact 88-tool inventory through mTLS. Missing
or wrong client certificates and missing/invalid writer authorization were denied.
The deployed serving Secret matched the probed reader pair, while the writer S3
Secret was absent from the backend mounts. A bounded second writer process was
refused by the existing single-writer fence; the original owner and workloads
remained unchanged throughout that test.

One actual foreground RFC 9000 text acquisition delegated through the writer and
published a permanent capture. An authenticated reader S3 GET returned its
403,442 bytes in ONEZONE_IA with the exact qualified source digest. The initial
public read remained unavailable while all collectors were disabled because
required attribution work could not be claimed. The receipt admitted actual
writer publication and S3 readback only; it did not relabel this withheld content
as a successful public read.

### IPv6 WebTransport and edge isolation

Unmodified released probes initially reproduced intermittent incomplete IPv6
WebTransport `tools/list` frames on both native KVM and rootless Docker paths.
The TLS handshake itself passed. A bounded diagnostic preserved those failures;
a conservative 1200-byte packetization trial passed. This supported mitigation,
without proving a particular kernel, GSO or MTU cause.

For this transport mitigation, the tracked deployment change sets downstream
QUIC GSO off, initial/minimum MTU and maximum UDP payload to 1200, and MTU discovery off in
[the edge TLS profile](edge-conf/10-tls.toml). Upstream transport, timeouts, TLS,
authorization and private boundaries were preserved. The pinned edge binary
accepted the entire configuration natively before one guarded edge-only recreation.
The installed and live profile SHA-256 is
`99babcd17bef83cb21d96fb2e13fbe8b96bc4e1d5c638939ff9dc719f2706c97`.
The fix received independent source, native-prepare and applied-state review.

After application, the unmodified released client passed WebTransport discovery,
full tool listing and identity on IPv4 and IPv6 for 2025-11-25 and 2026-07-28.
Both formerly failing rootless IPv6 cases also passed. Full public HTTP smoke and
negative cases passed for both families and protocol revisions with 88 tools.
Old failure records remain retained. This is bounded deployment acceptance, not
proof about every client network or packetization mechanism.

Public clients could not obtain private NodePort, PostgreSQL, writer or health
protocol responses. Bare TCP connection establishment through the local KVM's
intermediate gateway was inconclusive and was not counted as direct reachability.
Protocol negatives, actual host listeners and the existing pre-DNAT host guard
were checked together. After the edge recreation, its own backend NodePort
positive control passed and direct Pod/CNI private-service attempts remained
blocked. The earlier real boot-guard receipt retained six refused daemon starts
and successful recovery; the protected boot settings were unchanged.

### Certificates, activation and representative licensed read

One real certificate renewal retained the original key and SANs. External
verified TCP and QUIC readbacks over IPv4 and IPv6 all observed the new leaf
while the same edge process remained running. The normal renewal configuration
was restored unchanged. This actual hot-reload proof predates the later,
intentional transport-only recreation. Certificate and capacity timers remained
active.

Independent integrated review closed all 12 edge admission checks. The unchanged
frozen operator then admitted real source, storage and edge receipts and enabled
all eight normal collectors at 2026-11-11T06:49:38Z. It stopped the backend before
the sole writer and restarted writer before backend. No attribution SQL repair,
provider-budget reset, custom runtime build or content-policy bypass was used.

The enabled worker qualified the already queued RFC capture. Its public
capture-pinned read returned the same capture
`blake3:f561023b34507798258530bff923c41bab5d092d71b2cae7da484e6d5ce6d0e0`
and body
`blake3:58f50168dc03a034edf54305bbf7dd71e1e1f91cb942d5e8e401ab8939890c1a`.
The ready epoch 1 attribution generation was
`blake3:254338b7453b0764ba106f0298fd5113f4d90f9aca8028761372660e1614ec81`.
Read-only SQL confirmed the exact subject, generation, policy and nonempty
notice/evidence receipts. Public `resources/read` and `fetch` of its immutable
notice URI returned identical 735-byte readable notices, SHA-256
`e3023e4c9c26222fad0449a77d6d7243849a819d3d9ab7af4d2d20a277740156`.
The original capture-fixed content resource returned the same first page.
No second unpinned foreground acquisition was issued.

The formal postactivation observation spanned 2026-11-11T06:56:49Z through
07:06:50Z, after the initial licensed read and full public protocol matrix passed.
Ten recorded samples covered 600.883 monotonic seconds. Both roles stayed Ready
with unchanged Pod/container identities, restart counts and exclusive writer
owner. PostgreSQL retained its original system identifier, container and zero
restarts. The archive binding/epoch, pinned RFC capture and ready attribution
generation, edge process/profile, enabled collectors and active timers remained
unchanged. SQL capture inventory increased from 1,108 to 2,640; free space stayed
above 931 GB, exceeding the 128 GiB reserve. Full public HTTP/WebTransport and
capture-pinned content/notice checks passed again at the end, including both
protocol revisions for the content and immutable notice.

Each writer/backend Pod had one failed initial storage startup before its formal
Ready baseline, both during the earlier start and after the authorized activation
rollout. The generic error does not identify its cause; no intentional warm-up
failure is implemented and no root cause was proved. Kubernetes recovered each
process. The formal window had no additional restart; this is not a clean-first-
start or long-term reliability claim.

Independent review closed the bounded operational evidence. The final acceptance
receipt SHA-256 is
`42b83ed82a586b52b835fef6e6c2c6b3c1f069db8fb1bdc07f1ae69ef09d1750`.
The 15-record raw server evidence export SHA-256 is
`8fde36030d7fb440d1b195834554c7bcee25a24de51db081e5fbbcb9ac1b81ec`;
all twelve exported observations matched their authenticated SSH records.

### Verification boundaries

`cargo fmt --all -- --check` passed. Local deployment Python checks passed
64 tests with two existing skips. The actual isolated minikube suite passed NodePort TCP/UDP, CNI isolation, PVC restart and
coordinated restore checks. The pinned OxiBelt Docker fixture suite passed in a
fresh, owned local Docker daemon after an existing shared PostgreSQL image cache
proved incomplete; shared images and unrelated containers were preserved. These
fixture runs are distinct from the actual provider, server and public checks.
Hosted native amd64/arm64 release qualification remains the separate publication
evidence above. Agent review is not human GitHub approval.

Actual version deletion remains deliberately denied with HTTP 403 AccessDenied.
This deployment establishes representative licensed public retrieval and bounded
operational readiness. The observed background state includes pending/blocked
attribution, RFC HTML representation integrity errors, W3C current-lane integrity failures with no
published standards, and Chromium current-lane unavailable failures with no
published components. These are unresolved source-coverage gaps. The sanitized
status codes do not identify a particular validation or storage failure; current
writer logs supplied no further diagnostic lines. This acceptance does not
establish a complete corpus, universal provider readiness, arbitrary
client-network compatibility or native ChatGPT UI acceptance.
