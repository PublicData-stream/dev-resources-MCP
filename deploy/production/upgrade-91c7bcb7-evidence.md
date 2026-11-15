# Production upgrade to 0.1.0-build.91c7bcb7

This 2026-11-15 record covers the attempted deployment of commit
`91c7bcb7aed8eede1627bf87254c0567ef48ab7b` from the admitted
[`33f3c730` runtime](upgrade-33f3c730-evidence.md), following the
[same-schema procedure](upgrade-91c7bcb7.md).

**Deployment acceptance failed.** The initial attempt and one separately reviewed
continuation each passed early acceptance and a fresh 32-sample observation, then
failed a mandatory late public check. The initial HTTP failure's exact cause is
unproved. The continuation failed the released native IPv6 WebTransport probe on
`2026-07-28` with `TimedOut: frame deadline exceeded`; its exact RPC and underlying
cause remain unproved. Neither attempt satisfies final deployment acceptance.

The second guarded withdrawal completed at **10:22:05 UTC**. A fresh guard at
**10:29:12 UTC** confirmed backend/writer replicas **0/0**, PostgreSQL **1 Ready**,
no publication owner, unchanged schema 18/policy 2/archive epoch 2 and database
authority. The application service is stopped. PostgreSQL, permanent history,
the verified checkpoint and both failed attempts' evidence remain preserved.
No restore, old-image rollback, queue reset or further application start occurred.

## Release qualification and local verification

The exact signed tag, immutable release, corresponding source and released images
were qualified independently of production activation. The source archive matched
745 regular source members, each compared with the exact commit plus all eight
established version-stamp surfaces. Twelve
provenance subjects and eight anonymous platform pulls covered server, probe,
audit-worker and credential-broker images on amd64 and arm64. Runtime-only GitHub
API authentication was used where required; registry pulls used no credentials.
No replacement release was built or published.

| Qualified artifact | SHA-256 |
| --- | --- |
| Server image index | `1b1bf21d339920e8ddd69449d82c9895c3423509e8016a72b2df46a38d8e7b6c` |
| Probe image index | `a0ed3b468b3e7e23b395d2227b66878832cdf149aa4aac28738e8e5aca0cb588` |
| Corresponding source archive | `d92b3850074b3155866a376824b0a625151be17a260e4ea7bae058fb46f224a9` |
| Released native amd64 probe | `2fd8e53e3eee3091b6a86a56136233f6adaf3e96cad33a6117361a08069cdd4e` |

[Exact-revision CI 43686872327](https://github.com/PublicData-stream/dev-resources-MCP/actions/runs/43686872327)
passed its twelve jobs, including native architecture gates.
[Publication 43690873417](https://github.com/PublicData-stream/dev-resources-MCP/actions/runs/43690873417)
completed the immutable publication. These hosted results are distinct from the
local amd64 checks below and from the production observations.

| Local gate | Result |
| --- | --- |
| Rust 1.99.1 formatting and strict workspace/all-target Clippy | Passed |
| Locked workspace Rust tests | 1,122 passed; 96 opt-in tests ignored across 37 test binaries |
| Current advisory audit, vendored audit and dependency policy | Passed |
| Complete Python suite | Initial 1,070 and final continuation-integrated 1,111 tests run; four skipped; passed |
| Controller/checkpoint/acceptance fixtures | 83 passed |
| Continuation, trace and runner fixtures | 41 passed |
| PostgreSQL persistence fixtures | 69 passed across 33 test binaries |
| Pinned OxiBelt HTTP/WebTransport fixtures | Passed after staging correction |
| Disposable filesystem minikube acceptance | Passed |
| Disposable S3/credential-broker minikube acceptance | Passed |

Initial OxiBelt and minikube attempts did not establish acceptance. Staged fixture
executables had restrictive permissions; the interrupted cluster attempt and
failed evidence were retained. Corrected executable modes preserved their hashes,
and fresh fixture runs completed without changing production configuration or
weakening assertions. Task-owned clusters, bridge and daemon processes were
removed after acceptance; temporary evidence was retained. All generated test
state used owned temporary directories, with Cargo output at `/tmp/rust/target`.
No fixed-source provider live probe was run as part of these local gates.

Signed commits `cacf001` and `11df075` separate guarded operational implementation
from rollout/recovery documentation. Signed `e5fa8e0` adds the reviewed one-shot
continuation and durable failure logging after the first late-check failure.
Independent reviewers inspected the actual integrated sources and affected callers across MCP/API, Upstream/Storage and
Security Boundaries. Corrected findings included target-image Pod inventory,
withdrawal after uncertain scaling, runtime-bound receipts and honest failed
withdrawal results. Agent review is not human GitHub approval.

## Preserved boundaries and fresh checkpoint

The successor preserves schema 18, attribution policy 2, PostgreSQL system
identifier `7706567225121447965`, original S3 binding/archive epoch 2, static
role-separated S3 authority and existing credentials. The admitted edge, shared
network, explicit gzip/Brotli/Zstd MCP SSE compression, TLS, AppArmor, firewall,
CNI/RBAC and capacity/certificate timer entrypoints are retained. Only application
images, corresponding-source URLs and temporary collection pause/resume settings
change. Frozen predecessor sources and journals remain preserved.

| Reviewed operational source | SHA-256 |
| --- | --- |
| Upgrade controller | `fa1ad0b5a7713787d12a44477b2a8f68ec7a79655c7a847ec4b74a819b8c4100` |
| Schema-18 checkpoint helper | `9d7c3976b9d4ba2d19fd7fa2b22070ff7d5954d481bf2cc8743b4390499b70dc` |
| Ten-source review manifest | `b7dc9fae49b3dbcd27c933c378c4a7f10f05d93c5a844cd8ccf07c270070acfc` |

An independent server-side hash check matched all eleven installed source files,
including the target revision's HTTP smoke client, to the final source manifest.

An initial checkpoint preparation failed because the old server image was absent
from the host's Docker image store. The helper had written only its owner record,
before baseline collection, database copying, PostgreSQL stop or clone creation.
The exact owner-only directory and failure log were preserved as
`checkpoint-preflight-image-missing`. Review checked source/input/owner pins,
locks, unchanged running applications and mount identity before a fresh owned
preflight scope continued after image qualification. No actual checkpoint or
rehearsal attempt was replayed or consumed by that setup failure.

The completed checkpoint used live precopy followed by clean PostgreSQL shutdown,
checksum-based final copy and fsync. Backend stopped before writer. The original
PostgreSQL data directory restarted without a restore. A dedicated disk-backed
temporary mount avoided the host's small temporary tmpfs; the golden checkpoint
and private recovery journal remain on durable storage. Preflight retained the
three-copy allowance and 128-GiB reserve. No cache deletion or rotation was used.

One isolated old-reader rehearsal used a separate database copy, the original S3
store and an initially empty disposable cache. All source collection, npm advisory
collection and effective writer forwarding were disabled in the clone. The proof
verified current policy-2 target/generation retention, exact capture-fixed RFC
bytes, complete current and historical notices, native reader authentication and
unchanged database authority. Complete ordered capture/archive manifests accompany
the checkpoint. Clone resources were removed within their owned scope.

This is PostgreSQL recovery while the original immutable S3 survives. It provides
no independent S3 backup, bucket-loss recovery or verification of every remote
object. Automatic production restore, schema downgrade and old-image rollback
were neither implemented nor performed.

## Paused and early active acceptance

The controller applied the target at **08:59:56 UTC**. Paused writer readiness
followed at **09:00:33 UTC**, reader readiness at **09:02:11 UTC**, and private
runtime admission at **09:05:12 UTC**. Each initially started application required
one startup retry; its underlying cause is not established. The continuation's
fresh writer and reader each also had lifetime restart count 1 at admission.
Those counts remained unchanged throughout its 32 observation samples; the
withdrawn applications have no final running Pods.

Private acceptance passed `2025-11-25` and `2026-07-28`, exact 98-tool inventory
and target source offer. Missing/wrong client certificates were rejected with
valid-client positive controls; missing/invalid writer authorization returned
401. Rolled-back reader no-op writes produced SQLSTATE 25006 and 42501. Edge
access to PostgreSQL, writer and private health was blocked with a successful
admitted NodePort positive control.

Paused public HTTP and released native WebTransport passed IPv4/IPv6 for both
protocol revisions. HTTP additionally covered obsolete/nested tool names,
Host/Origin rejection and private-route denial. All twelve codec/family/revision
cells returned valid decoded SSE with the selected gzip, Brotli or Zstandard
encoding, `Cache-Control: no-store` and `Vary: Accept-Encoding`.

All nine exact original source settings were restored at **09:09:04 UTC**,
returning the controller to `collectors_active`. Early active private/public
checks and all twelve compression cells subsequently passed. The first
observation then passed, but its late public failure prevented completion.

Both protocol revisions preserve RFC 9000 capture
`blake3:f561023b34507798258530bff923c41bab5d092d71b2cae7da484e6d5ce6d0e0`
and body
`blake3:58f50168dc03a034edf54305bbf7dd71e1e1f91cb942d5e8e401ab8939890c1a`.
The first 1,024-byte page hashes to
`6026989d1430343743b2c712d7cea16e0fd7a600110623a7a2f9e9cc6944d190`.
Complete current and historical readable notices retain the original 735 bytes,
SHA-256 `e3023e4c9c26222fad0449a77d6d7243849a819d3d9ab7af4d2d20a277740156`.
Selected positive readback does not qualify the whole corpus.

## First late failure and reviewed continuation

The first active observation passed 32 samples from **09:12:59.342191** through
**09:28:29.309190 UTC**, covering 929.966999 monotonic seconds, maximum gap
30.183583 seconds. The subsequent late private checks, four native WebTransport
cells and IPv4 HTTP checks passed. The late IPv6 HTTP smoke/identity/receipt stage
then returned nonzero before writing its success receipt. The ad-hoc wrapper did
not preserve child stderr; the exact failing call and cause are unproved. Edge
logs retained only client-close warnings associated with successful WebTransport
probes. Deleted application logs were unavailable. No IPv6 routing or particular
provider failure is inferred from the missing receipt.

The controller's known-complete withdrawal at **09:30:43 UTC** stopped both app
roles and retained PostgreSQL, permanent history and checkpoint data. Its original
withdrawal intents were consumed and were not replayed. The original successful
observation remains failed-attempt evidence, not final deployment acceptance.

A separately reviewed single `resume-v1` continuation bound the exact withdrawn
state, immutable preimage, controller/helper/original source pins, prepared plan,
authority baseline and preserved failure artifacts to fresh external admission.
Preflight confirmed the original PostgreSQL process/schema/policy/archive,
credentials/grants, edge/security boundaries, original active source settings and
absence of an application Pod or publication owner. Only writer and backend were
started, with fresh start/withdrawal intents; no image/configuration, PostgreSQL
restart/restore, storage change, queue reset or source-budget change occurred.
The helper verified sole-writer continuity and returned `collectors_active` at
**10:00:52.187972 UTC**.

| Reviewed continuation source | SHA-256 |
| --- | --- |
| Resume helper | `6c271b2c5508b5f6c02eb591b28620bd9724e1db88a491cb258cb31743d993b5` |
| Payload-free public trace producer | `29ef35509c37ed91481e77d10290c082498e6dc8cdae45bac7be167656463985` |
| Versioned receipt aggregator | `0b129c7f1a38f00c7744d1013d1a5dc6cf4fdb2ccb3ac7df714c8b58b4e4c723` |
| Durable acceptance runner | `e8e01c0728b60a5ceb0b9361f0d8e2475a9c86bbb8ff8c13f77d03567021ff99` |

The runner now retains bounded child stdout/stderr, exit/timeout metadata and
payload-free fixed-method/tool exchange stages. Arguments, request/response
payloads, headers and exception messages are excluded from the exchange ledger.
No existing smoke assertion or limit was weakened. Full early negative checks,
private/public matrices and twelve compression cells passed again for the new
processes. The new observation passed 32 guarded samples from
**10:04:50.912269** through **10:20:20.895366 UTC**: 929.983097 monotonic
seconds, maximum gap 30.103317 seconds, minimum free capacity 721,642,377,216
bytes. Capture count advanced from 72,768 to 75,222. Writer ownership, process
identities/restart counts, archive/authority, exact nine source settings and
capacity/certificate timers remained consistent across those finite samples.

The late private checks passed at **10:21:00 UTC**. Three late native
WebTransport cells passed; the fourth, IPv6 with `2026-07-28`, failed at
**10:21:59.004509 UTC**, exit 1, with
`Error: Custom { kind: TimedOut, error: "frame deadline exceeded" }`.
The matrix executes all four WebTransport cells before HTTP, so **no new late
HTTP matrix ran**. Late codec checks, final bookend, aggregate receipt and frozen
controller `finish` did not run. Earlier successful HTTP/codec results do not
replace these missing checks.

The probe's session connection, bidirectional stream opening and local request
write completed before this frame-read error. Its reader allows ten seconds for
the first byte, then ten seconds from the first byte to complete the frame.
Raw I/O errors propagate without an RPC label. The failure therefore does not
identify which request stalled, whether any response bytes arrived, or whether
the cause was backend latency, forwarding, flow control or another condition.
Pinned OxiBelt forwards byte streams without RPC awareness; its 65-second session
idle setting does not by itself explain this ten-second frame deadline.
The two late failures do not establish a common IPv6 cause.

Timestamp-bounded edge logs retained an upstream WebTransport close failure and
stream/datagram task errors at the failing client's exit, followed by a downstream
timeout. These can be consequences of client exit; they do not locate the cause.
Kubernetes events showed only the already known startup readiness refusals.
No application Pod log directories survived withdrawal; the runner did not
snapshot application logs/status before deleting those Pods. Node metrics
collected after withdrawal do not establish resource usage at failure.

The runner retained the failed child's stdout/stderr and result before invoking
the separately admitted withdrawal. At **10:22:05.007333 UTC**, state became
`withdrawn`; its withdrawal receipt followed at **10:22:05.815453 UTC**.
Consumed original and continuation intents were retained, without replay.

## Recovery outcome and preserved failed state

Bounded target-image RFC/npm private diagnosis completed with the existing
64-MiB/five-minute limits. It inspected retained metadata without warming serving
archive caches, fetching source-provider data or acquiring publication ownership.
The root-private RFC report is 6,090 bytes, SHA-256
`e6ef48bd173234a8bdf6d3757ecf1fe63ba896b9706578ecbea8cb68cf6a1e4b`;
the npm report is 3,021 bytes, SHA-256
`49022e4e5f6da430de04785a26d73a3fbd8de783840ea52f9c68948a4933f4ed`.
The inspectors read selected S3 binding descriptors as well as SQL metadata;
they do not establish zero S3 I/O. The selected RFC snapshot remained incomplete.
Its policy-2 target was ready, but engine readability, member-byte export and
public readiness were not checked by the inspector; the separate fixed-body
positive control proves only that selected representation. The npm report
retained a legacy-unknown failure stage/linkage and a truncated sample, with
full membership/export verification unchecked. Completed diagnostic execution
therefore does not establish corpus repair or publication.
Five due attribution retries were selected before deployment; no expired running
claim was present in that sample. Their first-window observations all advanced one attempt while
retaining the same exact identities: MDN 1 to 2, WHATWG 1 to 2, W3C 6 to 7, Chromium 5 to 6 and
RustSec 6 to 7. All remained `retry` with no generation and classification
`acquisition / unclassified / retry`. Successful content recovery was not proved;
the read-only **10:29:12 UTC** continuation-final sample still had the same five
identities and attempt counts, all `retry` with no generation. A missing
expired-lease example is not a successful recovery test.

Ordinary collectors retain their existing budgets and scheduling. No terminal
job reset, manual queue edit, RustSec recovery apply, index rebuild or new rights
policy was performed. Policy-2 RFC errata withholding remains; the separate
[terminal recovery design](../../docs/terminal-recovery-design.md) supplies no
executable rearm or permission to publish unqualified prose.

The fresh withdrawn-state guard verified all fifteen original/continuation
source files against their manifests and the original PostgreSQL Pod, started at
**08:55:34 UTC**, with zero restarts. At **10:29:12 UTC**, retained database
counts were **75,499 captures** and **374,733 complete archive-file records**.
These SQL counts do not prove every remote S3 object or successful publication of
the selected retry subjects.

| Preserved private artifact | SHA-256 |
| --- | --- |
| Coordinated schema-18 checkpoint receipt | `22dec058b5dedb48c5a12235886d38dba7869fa51fb90b92428da11da58ff572` |
| Continuation 32-sample observation summary | `a22d39fc42c9268f006cb0cb56e52fc53b4884f737ab1c0406f363b66699f045` |
| Failed IPv6 modern WebTransport receipt | `c6ded62b3ecb3bc7ef3fdd6b23740a10c673ef27c7702abe3f6f20d7f5a1b041` |
| Late public child outcome | `0778ca03b6107533e88e4aa7f3d52da7cf3f5d5d4a3478fef46d62d5c1427387` |
| Runner failure with completed withdrawal | `04c9e18f04a64f52be82526cc1fb988d767d261c34e88e12ae70bf90652ba38d` |
| Continuation withdrawal receipt | `ea45e63387f41ead130c5347383636690a96bee6a196f1e1385354f6ff240050` |
| Guarded withdrawn state | `18a90fea2812f9293e1e258b27d2ace6fc5f6d81f863ea01757d9122462cad4c` |
| Final selected ordinary-retry sample | `5f4da3ebba5f521ef553b5a859c7ca9503b8720989e7ce3d7fd37a4c3239240a` |
| Timestamp-bounded edge log | `1a00fc6b64152a0bbaaa9b69b160c1ef11f2cfe78b593809ac65602857791df8` |

Private evidence remains on the deployment host; this sanitized record contains
no credentials, supplied lockfiles, request bodies or diagnostic report bodies.
There is no accepted final observation receipt and the controller is not
`complete`. Finite successful samples remain distinct from continuous
availability, load/failover testing, whole-corpus recovery and native ChatGPT UI
acceptance.

## Next diagnostic boundary

Keep both application roles withdrawn while correlating retained evidence.
The smallest next reproduction uses an isolated fixture with the target source's
request sequence, unchanged deadlines/assertions and payload-free RPC/frame
progress tracing. Trace only fixed operation IDs, methods/tool names, stages,
finite result codes, timing and frame-byte counts; exclude arguments, payloads,
headers and exception messages. Verify tracing against controlled stalled and
partial-frame fixtures before any operational use. Preserve the released probe
unchanged for acceptance.

If an isolated reproduction cannot establish the cause, a production diagnostic
would need a separately reviewed exact-target continuation, fresh external
admission and new durable start/withdraw intents. Bind the current withdrawn
preimage and all previous failure evidence, retain existing source/security/data
boundaries, and capture bounded private runtime evidence without delaying the
failure fence. A successful diagnosis is followed by entirely fresh early,
observation and late acceptance; it cannot waive the failed check, extend the
released probe's deadline, skip IPv6, replay either consumed continuation or
retroactively claim these failed attempts succeeded. This record does not
implement or start that further continuation.
