# Formats, identities and evidence selection

Read before auditing, choosing a registry assertion or selecting advisory history.
Live schemas remain authoritative; unknown fields fail validation.

| Input | Tool and selector |
| --- | --- |
| Cargo.lock | `audit.lockfile`, with `lockfile` and optional `advisory_snapshot`/`format`. Default representation is `rustsec`. |
| package-lock.json or npm-shrinkwrap.json | `npm.audit_lockfile`, `lockfile_format="npm"`; supported schemas 1, 2, 3. |
| pnpm-lock.yaml | `npm.audit_lockfile`, `lockfile_format="pnpm"`; supported schemas 5.4, 6.0, 9.0 including multi-document v9. |
| Yarn Classic yarn.lock | `npm.audit_lockfile`, `lockfile_format="yarn_classic"`; supported schema 1. |
| Yarn Berry yarn.lock | `npm.audit_lockfile`, `lockfile_format="yarn_berry"`; supported schemas 4, 6, 8, 10. |

Audit input caps at 1 MiB. npm-family parsers also cap inventory at 10,000 entries.
Unsupported formats fail explicitly; do not rewrite or truncate private input to
force a pass. All dev/optional inventory records are included.

## Package origin

Cargo assessment supports crates.io registry identities. Git, local/path and
alternative registries remain unassessed rather than matched by name alone.

For npm, `registry_context` is a caller assertion: `default` plus a `scopes` map
whose values are `npmjs`, `other` or `unknown`. Request only the necessary origin
assertion when ambiguity affects matching; never request or upload `.npmrc`,
tokens or other credential-bearing configuration. Do not assume `npmjs` to make
an assessment complete. Explicit conflicting custom origins stay unassessed.
Aliases use the real package identity. Workspace, Git, file and unsupported
transformed sources remain unassessed. Patched packages may have base-release
matches while transformed-artifact coverage and overall completeness remain gaps.

## Advisory snapshots

Rust lookup/audit uses `advisory_snapshot`; advisory research tools use `snapshot`
where supplied by their schema. Explicit Rust OSV assessment requires both
`format="osv"` and an OSV `advisory_snapshot`. Do not merge RustSec and OSV
representations or assume their snapshots are interchangeable.

npm matching uses retained public OSV npm evidence. Rust and npm advisory
collection is independent of the private input; auditing does not fetch or enroll
its dependencies. Use corpus-status tools when coverage affects the conclusion.

Selected historical evidence stays historical. Restore/reprocessing time is not
source validation time. npm default evidence becomes stale after 24 hours and
unavailable after seven days; explicit historical selection remains readable.
Rust evidence older than seven days makes assessment incomplete. Preserve each
response's freshness and completeness fields rather than imposing one shared
policy on both ecosystems.

Withdrawals differ from removal/absence in later observations; informational
advisories differ from active vulnerabilities. Unsupported ranges or historical
schemas remain matching gaps. Public advisory sources may carry immutable
`resource_uri` references; these describe advisory evidence, never private audits.
