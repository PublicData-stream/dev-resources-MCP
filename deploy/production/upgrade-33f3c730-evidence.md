# Production upgrade to 0.1.0-build.33f3c730

This 2026-11-14 operation deployed commit
`33f3c730123319625fe3a25713988201eb5d82e0`. All nine existing source settings
were restored at 17:23:08 UTC. Final acceptance closed at **17:38:45 UTC**, with
the controller in `complete`, active configuration and one Ready replica of
PostgreSQL, writer and reader. The subsequent final guard passed.
This document separates release qualification, local tests,
checkpoint preservation and production acceptance.

## Qualified release and local checks

The signed tag, immutable release and all seven release assets were verified.
Corresponding-source inspection covered 721 regular files and eight established
version stamp surfaces. All four image families were anonymously pulled for both
architectures; twelve provenance subjects matched the release source and publisher.

| Artifact | SHA-256 |
| --- | --- |
| Server image index | `c13191678b2336f6594521dec7ca040cc97ea55313d098d87726f852eb3f1bde` |
| Probe image index | `8239d387a0120049eef707a6cd474c2286545991bd7f246c8b7773c8f02a1473` |
| Source archive | `46491351a46d4518274982406bc66174908e7559a8a4d6e1bd3f787e2b9b1b0a` |
| Released native amd64 probe | `2a9c5df5117a4d7e4fbcc266f2bf946acd5e335a4864de4bea49dd08bd4ec312` |

[Exact-revision CI](https://github.com/PublicData-stream/dev-resources-MCP/actions/runs/43594501889)
passed twelve jobs, including native amd64 and arm64 checks.
[Image publication](https://github.com/PublicData-stream/dev-resources-MCP/actions/runs/43603750131)
completed. Local target-revision format, clippy, workspace tests, cargo audit,
vendored audit and cargo deny passed. PostgreSQL, exact OxiBelt and filesystem
minikube acceptance passed. The first S3 minikube run hit an etcd Job-creation
timeout despite the Job completing; its failed evidence was retained. A fresh,
unchanged S3 retry passed cache-loss, database-restore and HTTP/WebTransport checks.
Local fixtures do not substitute for native architecture CI or production checks.

## Checkpoint and forward recovery

A clean physical PostgreSQL checkpoint and an isolated restored clone retained
the original system identifier `7706567225121447965`. The original immutable S3
binding remains available; this checkpoint is not independent bucket-loss recovery.
The quiescent checkpoint covered these complete ordered manifests:

| Manifest | Rows/files | SHA-256 |
| --- | --- | --- |
| Captures | 47,277 | `3c95bd449277ef2f11a15976fe9ff999dd677c6962bcd759837bf08b3527d28f` |
| Archive descriptors | 261,368 | `599cf2501ddc05eb25d7043b158f96800b4671a1d5b1b6f42d40f16152a57c16` |

Schema 18 and attribution policy 2 were applied. The first target writer exceeded
the local cache file-count bound: 262,147 ordinary cached files against 262,144.
Disk capacity was available. Both application roles were withdrawn, preserving
PostgreSQL and permanent data. A first recovery preserved the entire original
cache and copied 32 bare Git repositories, but omitted required sibling ownership
and working-state files; target startup therefore failed closed. Its failed
generation and journal remain retained. No old image or schema downgrade ran.

The complete working-state recovery preserves both earlier cache generations,
copies fourteen working/view directory families into distinct inodes, and leaves
only the disposable body and integrity materializations cold. The original trees
are rehashed; exact parent ownership markers and artifact directories are checked.
The restored working state has 84,087 ordinary files, below the unchanged bound.
SQL capture/archive bindings and historical notice generations remain acceptance
conditions. Failed single-use startup or withdrawal intents are never replayed.

The complete recovery reached `writer_ready` at 17:16:39 UTC. The full schema-18
migration comparison preserved both ordered manifests above and the historical
notice generation. Reader readiness followed at 17:17:23 UTC; private runtime
acceptance closed at 17:18:55 UTC. Both roles had one initial startup restart,
with the sanitized `Durable storage unavailable` error retained privately. The
underlying transient cause was not established. The later collector activation
replaced both Pods; those active Pods also each had one initial restart with the
same sanitized error. PostgreSQL had zero restarts after the planned checkpoint.

## Explicit MCP SSE compression scope

The user approved preserving the shared `pdf2md-net` network and existing global
compression settings. Source inspection established that the native default
policy excludes `Cache-Control: no-store` SSE, including MCP responses. The user
then explicitly authorized a separate `devres-mcp-sse` policy and MCP route change
to enable actual gzip, Brotli and Zstandard compression. The transition retains
`no-store`, streaming, TLS and unrelated routes, validates staged configuration
with the exact native binary, and permits one owned edge-container restart.

The source successor retains the original controller, prepared state, plan and
explicit old/new state admission. Guards check actual live edge identity before
and after the bounded historical compatibility checks. Operational observers
report the actual edge process. Public acceptance requires all twelve codec,
IP-family and protocol-revision cells to return their requested encoding with
decoded valid 98-tool SSE payloads and `Vary: Accept-Encoding`.

The native staged check passed before live changes. One same-container edge
restart completed at 17:19:36 UTC; the exact live check and guarded source handoff
passed. The predecessor source SHA-256 remains
`2b18ea9ee326eabbafa1398f0f065c639b9e70fe01962cca31e6d8fc86365a6e`;
the admitted source successor is
`4491b9b05d42f0519be4928cc49bc2490dbc5519c0dc75a6d28310faa172986c`.
The transition helper is
`ec9266e1a40b8d0b10b2fda8c8686c2c1487e4900a277c935dff724e90587a21`.
All twelve actual compression cells passed while paused and again after activation.
Retained response headers independently confirmed `text/event-stream` and
`Cache-Control: no-store` in all twelve cells of both accepted passes.

## Production acceptance and observation

Private acceptance passed both `2025-11-25` and `2026-07-28`, the exact 98-tool
inventory and target source offer. Missing/wrong client certificates were rejected;
missing/invalid writer tokens returned 401. Actual reader no-op transactions were
rolled back with SQLSTATE 25006 and 42501. Edge access to PostgreSQL, writer and
private health was blocked with a successful admitted NodePort control.

Both protocol revisions retained RFC 9000 capture
`blake3:f561023b34507798258530bff923c41bab5d092d71b2cae7da484e6d5ce6d0e0`
and its original 735-byte historical notice, SHA-256
`e3023e4c9c26222fad0449a77d6d7243849a819d3d9ab7af4d2d20a277740156`.
The paused current-policy body read returned explicit attribution unavailability,
as approved for the policy-2 transition; historical notice preservation does not
establish current-policy content availability.

The paused public matrix passed native released WebTransport and HTTP on IPv4
and IPv6 for both revisions. HTTP additionally checked obsolete/nested tool names,
Host/Origin rejection and private-path denial. One first active matrix failed:
the IPv6 legacy WebTransport tool call `packages.npm.corpus_status` returned
`unavailable`, after both IPv4 cells passed. This remains a failed application
acceptance attempt, with its artifacts retained. A subsequent read-only database
snapshot found no ungranted locks; it did not establish the earlier failure's
cause. No transport or application guard was weakened. A fresh unchanged complete
active matrix then passed all HTTP/WebTransport cells, with matching new process
bookends, private acceptance and all twelve compression cells.

The late private bookend successfully read the same RFC capture/body under policy
2 on both revisions. Its current notice generation is
`blake3:28c429829bb8d24f7c10d9ecc13e799a950856390dfaccdf956c2bef780e2abe`;
the original historical notice remained readable and unchanged. This one capture
does not establish current-policy readiness for the whole retained corpus.

| Accepted public pass | First/last receipt times, UTC | HTTP revision/family cells | Native WebTransport cells | Actual codec cells |
| --- | --- | --- | --- | --- |
| Paused, full negatives | 17:20:21–17:21:39 | 4 | 4 | 12 |
| Active, fresh early pass | 17:25:53–17:26:37 | 4 | 4 | 12 |
| Active, late pass | 17:36:07–17:37:00 | 4 | 4 | 12 |

Twenty-two guarded samples from **17:27:31.808 to 17:38:01.723 UTC** covered
**629.915135 monotonic seconds**, with maximum gap **30.167231 seconds**. Actual
Pod/container/process, sole-writer owner, schema/archive, read-only authority,
edge/security/boot and nine-source settings remained stable. Both capacity and
certificate timers remained active. There were **zero additional restarts** in
this interval; active writer/reader lifetime counts remained one each and
PostgreSQL remained zero. Minimum free space was **782,786,793,472 bytes**.
Capture count increased from **47,818 to 49,228**. These finite bookends and samples
establish bounded acceptance, not continuous availability or long-term reliability.

The [complete working-state recovery](cache_working_state_33f3c730.py),
[SSE transition](compression_33f3c730.py) and
[source successor](compression_controller_33f3c730.py) passed independent review.
All 142 upgrade/checkpoint/cache/compression Python tests passed. Private fsynced
intents, original generations, manifests, source preimages and failed attempts
remain on the deployment server. No credentials or request-only audit inputs were
copied into this document or committed.

| Durable acceptance artifact | SHA-256 |
| --- | --- |
| Clean physical checkpoint receipt | `eb8cb3cdeb25b8cfeb61aaf48903846439fe7ace0a0f1e9b04ccfa0f04c3352b` |
| Complete working-state restoration proof | `81ee5174a27828a9fd3ec2d5ff37f8d50535639642e177aeb461692279262c78` |
| Explicit compression/source admission | `c6547cfe426615b0dd24936b2827728819efa1ca46ac00e77dc3b9c7bc4e03b9` |
| Paused activation acceptance | `1f0ee03f58729f7d5b7e9dfdaac33bad579fd5d12b68ebd2870e881404b76a35` |
| Final observation acceptance | `11721bd3a88ad49f829a47bda6c584b10e9b9d6f6226887452f09482d070f4ce` |

Additional upstream live probes were not authorized or run. Existing collectors
resume their normal work; these checks do not establish full-corpus coverage,
load, all-provider acceptance or native ChatGPT UI behavior.
