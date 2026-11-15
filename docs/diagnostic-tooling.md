# Local bounded transport diagnosis

Use these private tools with fixture runtimes. This work's acceptance is IPv4 only;
IPv6 runtime configuration remains supported and unchanged. The two failed
[production attempts](../deploy/production/upgrade-91c7bcb7-evidence.md) remain
failed attempts. Local fault injection demonstrates mechanisms; it cannot identify
the historical cause without matching retained incident evidence.

## Native WebTransport

A leading trace option enables the instrumented build's private mode:

```sh
devres-probe --diagnostic-trace /tmp/diagnostic-owned/wt.jsonl \
  https://FIXTURE_HOST:PORT/mcp-wt/v1 /tmp/fixture-owned/ca.pem 2026-07-28
```

Use fixture trust/Host configuration and the existing positional origin/client
certificate arguments when needed. Both protocol revisions use the same fixed
request sequence and assertions. First-byte and partial-frame completion deadlines
remain ten seconds; tracing never extends them or changes frame/memory limits.
The trace distinguishes connection, stream opening, request writes, frame reads,
response matching and assertions. `FrameReader` exposes only an observational
phase and accumulated frame-byte count; receive cancellation retains its absolute
deadline and charged allocation.

The create-new JSONL file is mode 0600 below an owned private `/tmp` directory.
Events contain ordinal, compiled operation label, fixed stage/result, timing and
frame byte counts, capped at 2 MiB, 8,192 events and 4,096 operations. Arguments,
resource URIs, payloads, headers and raw error messages are excluded. Diagnostic
failure output is fixed text. Record source/binary hashes when comparing diagnostic
runs. Existing released acceptance binaries and their hashes remain independent.

## HTTP smoke sequence

From the repository root:

```sh
mkdir -m 700 /tmp/http-diagnostic-owned
python3 -B -m deploy.diagnostics.smoke \
  --endpoint http://127.0.0.1:PORT/mcp --output-dir /tmp/http-diagnostic-owned
```

The output directory must already exist, be owned by the caller and have mode
0700. The entrypoint accepts only a numeric IPv4 loopback HTTP fixture endpoint. It
imports the canonical HTTP smoke sequence and keeps its assertions, negative
checks, inventory, identity and original request limits. Fixed exchange starts,
responses, assertions and receipt boundaries survive failures without retaining
arguments, resource URIs, response data or exception text. This is a diagnostic
run, not a replacement released acceptance receipt or a public-provider live probe.

## Failure supervision

`deploy.diagnostics.runner.DiagnosticRunner` is a library with explicitly trusted
command, runtime collector and independently admitted fence callbacks. It embeds
no cluster command, destination or production continuation. The collector must
produce its first finite runtime observation before the command starts. Runtime
records allow only fixed roles, readiness/restart/resource counts and finite
application/edge codes; raw Pod specs, Secrets, configuration and log bodies are
not accepted. Collect and reduce runtime events before deleted Pods become
unavailable.

Concurrent stdout/stderr drains retain bounded prefixes and total counts. Only
trusted first-party commands whose outputs already satisfy request-only privacy
may be supplied; this runner does not sanitize arbitrary command output. Timeout,
output overflow, launch failure, interruptions and descendant-held pipes produce
finite outcomes. SIGINT/SIGTERM clean up the process group. Evidence collection,
persistence/fsync and the fence run in separate bounded processes so evidence
failure cannot prevent or delay invoking the fence. A failed fence is reported as
incomplete, never successful withdrawal. SIGKILL protection requires an external
supervisor and is not supplied by this library.

`outcome.json` is explicitly provisional (`final_outcome=false`); only the
returned `RunOutcome` describes the final control outcome. `persisted` acknowledges
provisional capture files rather than a final success receipt.

All artifacts require private owned `/tmp` directories and exclusive files. Do not
reuse old production intent/receipt paths or run consumed continuations. Production
use needs an independently reviewed successor and fresh exact-state admission.

## Verification boundary

Fixtures cover no-byte/partial-frame stalls, fragmentation, flow-control progress,
malformed frames, cancellation, SSE/decode/assertion/receipt failures, output
saturation, pipe leaks, disk errors, collector hangs and failed fencing. Direct
and pinned-edge IPv4 HTTP/WebTransport tests cover both protocol revisions; gzip,
Brotli and Zstandard acceptance retains the existing checks. Missing a required
local test is an incomplete gate. Local amd64, hosted architecture CI, source
provider acceptance, production stability and native ChatGPT UI are separate claims.
