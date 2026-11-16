# Local paused-status and assessment verification

Verification date: 2026-11-16. This change adds a strictly read-only status
observer, snapshot-scoped attribution observation, and closed assessment phase
evidence. The first failing stage of the historical assessment remains unknown.
Consumed deployment sources and intents were not changed or replayed.

## Completed checks

| Evidence | Result and boundary |
| --- | --- |
| Rust formatting and all-target workspace clippy | Passed with Rust 1.99.1 and locked resolution. |
| Workspace tests | 1,160 passed, 103 ignored; subsequent changes received the targeted checks below. Ignored database/cluster cases are separate gates. |
| Final research boundary tests | Six passed, including the public dispatch future's 32-KiB caller-storage bound. |
| Default-stack crate-pipeline regression | Three PostgreSQL cases passed after heap-pinning dispatch and restricting timing to status calls. |
| Final server regressions | 57 library, 21 CLI and six full research-status tests passed; later dispatch changes are covered by research/SQL checks. |
| Disposable PostgreSQL suite | All 76 executed tests passed with `RUST_MIN_STACK=16777216`, including actual read-only observation, MVCC cutoffs, oversized qualification rows and binding invalidation. |
| Python suite | Final unchanged run: 1,435 tests run, four skipped, no failures. |
| Advisory and dependency admission | Current workspace audit, vendored audit against the same refreshed database, and existing cargo-deny advisory/license/source policy passed. |
| Local edge acceptance | Final harness passed Docker HTTP and native WebTransport acceptance for both supported revisions, without provider requests. |
| Review | Independent MCP/API, Upstream/Storage and Security Boundary reviews inspected integrated changes and affected callers; reported blocking findings were fixed and re-reviewed. This is agent review, not human GitHub approval. |
| Documentation and checkout | Changed local Markdown links and whitespace checked; pre-existing ignore-file edit preserved. |

The first PostgreSQL attempt overflowed the default test-thread stack in an
existing large crate-pipeline test. The changed common research future was a
plausible contributor. Dispatch is now heap-pinned and timing wraps only status;
the unchanged failing filter passed on the default stack. The complete larger-stack
suite is separate evidence and does not replace that regression check.

One Python run missed an existing S3-copy fixture's five-second synchronization
wait. The unchanged test passed in isolation and the unchanged full suite then
passed without competing builds. The original failure is retained; its precise
scheduling cause was not established. No assertion or deadline was relaxed.

The configured Docker cache could not start the pinned PostgreSQL image because
its filesystem lacked `/bin/sh`. A fresh task-owned daemon successfully ran the
same immutable image. Shared daemon configuration was not changed.

## Local image evidence

The final Dockerfile `server` target was built natively for Linux amd64. Its local
OCI index is `sha256:66bf58dbe731dd1583bf2b0b4dac5589433499f79aec251510fb6779faaba384`,
platform manifest is `sha256:af187f5132abb7802d5296aa77f988673c1361fd555fffd268cc8ca853b77e1b`,
and configuration is `sha256:0b57e9c8b525be73031bbd6d274dfcafec254867b9cadc4e01a6b2f663ee4f7c`.
These identify a local worktree build, not a registry release or hosted-CI artifact.
The separate final tooling harness passed local edge checks; it does not substitute
for the server image in assessment qualification.

## Kubernetes gate remains incomplete

The requested isolated minikube run stopped at its `RSRC_DOCKER_STORAGE` startup
guard: the backing filesystem was 98–99 percent used despite several GiB free.
No successful cluster or effective Kubernetes/AppArmor assessment is claimed.
A local override with explicit absolute-space admission and a continuous free-space
reserve was prepared for operator confirmation; it is not part of the tracked
harness and has not been used.

The implemented Kubernetes scenarios remain required before readiness:

- Exact candidate-image CLI assessment with restricted UID/GID, mounts, seccomp,
  enforcing pinned AppArmor, fixture DNS/PostgreSQL-only egress and synthetic
  schema-19 legacy history; validate `legacy_unknown`, framing and cleanup.
- Fourteen controlled assessment cases, including connection/auth/configuration,
  output admission, READY failure, restore marker, lifecycle exclusion, corrupt
  history seal, SELECT denial and unavailable telemetry.
- Complete paused backend-MCP status through authenticated reader-to-observer RPC
  for both revisions, denial of acquisition, zero publication ownership and exact
  retained-row equality across startup and calls.
- Earlier SQL/S3 failures distinguished from attribution forwarding, including
  restoration of fixture roles, object-store availability and original workloads.

Run the owned harness with a separately built server image and retain only
validated receipts, for example:

```sh
DEVRES_E2E_DIAGNOSTICS_DIR=/tmp/devres-acceptance-evidence \
  scripts/test-minikube.sh --image HARNESS_IMAGE \
  --npm-assessment-image SERVER_IMAGE --s3
```

All fixture state belongs below `/tmp`; Cargo target remains `/tmp/rust/target`.
Native arm64 hosted CI, registry publication, live providers, full corpus/body
verification, production activation and a fresh production fallback cycle remain
separate, unexecuted claims. No push, release or deployment was performed.
