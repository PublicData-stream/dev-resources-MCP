# Configuration

The server takes exactly one operator-controlled TOML path. `refresh-advisories`
followed by that path runs private maintenance without starting listeners. Unknown
fields, oversized configuration (over 64 KiB), missing required tables, invalid
limits or access lists fail before serving. Never commit populated credential files.

Required tables are `source`, `http`, `webtransport`, `health`, and `storage`.
`edge_mtls` and `limits` are optional. See the tracked deployment example for values
and certificate paths appropriate to the harness; supply your own for hosting.

| Setting | Meaning |
| --- | --- |
| `source.url` | Explicit HTTPS corresponding-source offer for the exact running version; no credentials or control characters |
| `http.bind` | Backend Streamable HTTP socket |
| `http.allowed_hosts`, `http.allowed_origins` | Explicit backend authorities and browser origins |
| `http.tls.certificate`, `http.tls.private_key` | Optional HTTP TLS files; required when edge mTLS is enabled |
| `webtransport.bind` | Backend UDP/QUIC socket |
| `webtransport.certificate`, `webtransport.private_key` | Required TLS certificate and key |
| `webtransport.allowed_hosts`, `webtransport.allowed_origins` | Independent authority/origin allowlists |
| `health.bind` | Private plaintext health/metrics socket |
| `storage.database_url` | PostgreSQL connection string; treat as a secret |
| `storage.blob_dir` | Persistent, exclusively owned archive directory |
| `edge_mtls.client_ca_file` | CA for authenticated backend edge clients |
| `edge_mtls.required_client_dns_san` | Exact DNS SAN required on the edge client certificate |

A present Origin must match the allowlist. Native clients may omit Origin. Empty
origin lists reject every present Origin. The source URL is advertised, not fetched
or verified by the server; a syntactically valid offer is not evidence that the
corresponding source is actually available.

## Resource defaults

| `limits` field | Default |
| --- | --- |
| `max_message_bytes` | 8 MiB |
| `max_tool_result_bytes` | 256 KiB |
| `max_buffer_bytes` | 64 MiB |
| `max_in_flight` | 32 |
| `max_connections` | 128 |
| `max_calls_per_connection` | 8 |
| `io_timeout_secs` | 10 |
| `call_timeout_secs` | 30 |
| `idle_timeout_secs` | 60 |
| `shutdown_timeout_secs` | 15 |

`limits.rate_limit` defaults to enabled with 100 calls/second and burst 100.
An optional `verified_tunnel` calls-per-second/burst override requires edge mTLS.
These limits regulate callers, not provider traffic. Upstream attempts have their
own one-request/second host budgets and two-transfer concurrency bound.

Zero/invalid limits fail startup. Messages are at most 16 MiB; tool output must
fit at most one eighth of the configured message size. Buffer capacity must be at
least four message sizes. Increasing limits must be accompanied by resource and
acceptance review; transport buffer accounting does not measure total process RSS.

Capture bodies also share a separate 128 MiB read budget, retained through
projection and cheap shared clones; it does not count the entire process heap.
Source archive inspection caps compressed data at 32 MiB, expanded data at 256 MiB,
member count at 20,000, and selected file content at 4 MiB, with a parsing deadline.
Text output remains paged to 32 KiB. Supplied lockfiles cap at 1 MiB and 10,000
packages. These are explicit rejection boundaries, not silent truncation rules.

Run one serving replica. Use Recreate updates and stop all writers before backup
or restore. A dedicated database ownership fence prevents a second server; lost
ownership requires restart. Size storage for permanent history and retain at least
64 MiB of free blob headroom. See [Operations](operations.md).
