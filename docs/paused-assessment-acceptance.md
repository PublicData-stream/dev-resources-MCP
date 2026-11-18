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

## Paused observer CI repair

The filesystem [amd64 job](https://github.com/PublicData-stream/dev-resources-MCP/actions/runs/43892403817/job/133443554093)
failed with `fixture_command_failed`; its [arm64 counterpart](https://github.com/PublicData-stream/dev-resources-MCP/actions/runs/43892403817/job/133443554351)
failed with `observer_timing_event_bound`. The [edge aggregate](https://github.com/PublicData-stream/dev-resources-MCP/actions/runs/43892403817/job/133446894937)
correctly propagated E2E failure. The retained logs came from replacement pods
after restoration, so neither the original amd64 command nor the arm64 event
count can be recovered from that evidence.

The repaired fixture establishes bounded offline `server.info` routing readiness.
Each SQL/S3 fault gets a fresh healthy observer backend and exactly one status
request. The fault request targets its admitted pod IP while preserving the
`backend` Host, TLS hostname, CA validation and client certificate; an S3 outage
may intentionally remove the pod from ready Service endpoints. Healthy public
status acceptance still uses Service DNS and both supported MCP revisions.

Evidence is tied to the exact pod UID, container identity, restart count and IP.
The complete bounded log is polled for ten seconds without host-time filtering.
A 65,537-byte sentinel detects logs over the 65,536-byte allowance. Eight finite
stages remain the limit; malformed, duplicate and later attribution records fail
acceptance. Only evidence retrieval is repeated, never the fault request.

A private create-new `paused-status-failure.json` retains closed phase/case/error
codes, bounded command outcomes and validated stages before restoration replaces
the observer. `paused-status-restoration.json` separately records each attempted
restoration. Both use the maintained receipt validator and retention mechanism;
raw stderr, response bodies, inputs, configuration and credentials are excluded.
The primary error survives diagnostic or restoration failure. A complete success
receipt requires unchanged retained metadata, no publication owner, authenticated
acquisition denial, successful public statuses and completed restoration.

The first local repair run returned the expected SQL `unavailable` result and
retained `saved_state`, `statistics` and nested `kind_inventory` stages, but its
last identity query exhausted the shortened observation budget. The new receipts
localized this to `fault-timing` and proved every restoration succeeded. An
identity timeout exactly at the absolute deadline now ends collection using only
an earlier snapshot verified on both sides of its log read; earlier timeouts and
identity changes still fail. Four regressions cover the boundary and discard an
unverified final snapshot.

Independent agent review covered MCP/API, Upstream/Storage and Security Boundary
changes. Observer regressions passed 33 tests, shared fixture regressions passed
17, CI driver regressions passed 12, and release-selector regressions passed 15. The final full Python suite passed 1,463 tests
with four skipped using an isolated interpreter with the trusted repository root
explicitly admitted. Its initial invocation excluded that root and produced three
import errors; no source change was needed for the corrected run.

Rust 1.99.1 formatting, all-target locked clippy and locked workspace tests passed;
the workspace run reported 1,164 passed and 103 ignored. Current advisory admission,
vendored advisory checks and cargo-deny advisory/license/source policy passed
against a fresh task-owned database with 1,509 advisories. Initial shared-cache
checks encountered Git-object/permission errors; the successful retry changed only
the database location and retained the policy. Ignored database/cluster cases and
hosted native architecture acceptance remain separate gates.

The rebuilt pinned-edge harness passed local HTTP MCP and native WebTransport
acceptance for both revisions. The full disposable PostgreSQL script passed 76
tests on the default thread stack, including all 14 row-pipeline cases. A configured
rootful BuildKit cache first failed on missing overlay snapshots; the successful
run used an idle isolated Docker daemon with its data below `/tmp`, without
changing the broken shared cache or storage guards. These are native Linux amd64
fixture results, not hosted arm64 or production evidence.

Local capacity was recovered from verified inactive compiler incremental caches,
old duplicate test executables, minikube downloads and generated harness build
contexts. Existing profiles, retained corpus data, receipts and sibling evidence
were preserved. All new test state and Cargo targets remained below `/tmp`.

The final native Linux amd64 runs used minikube 1.39.0 and Kubernetes 1.37.0:

| Scenario | Result |
| --- | --- |
| Filesystem | NodePort TCP/UDP, CNI isolation, paused status, PVC restart and coordinated restore passed. |
| Plain S3 | Read-only paused status and SQL/S3 failure ordering, warm-cache outage, static credential rotation, complete cache loss, database/object restore and HTTP/WebTransport passed. |
| Credential-broker S3 | Projected pod identities, encrypted broker restart, distinct S3 roles, outage recovery, coordinated restore and broker/static/broker cutover passed. |

All three scenario scripts exited successfully and their owned profiles were
cleaned up. The broker uses a synthetic IAM fixture and disposable RustFS; these
results do not establish real provider IAM, expiry/quota or production activation.
The CI driver and release selector now require the added plain-S3 scenario on
both native architectures; hosted execution remains a separate gate.

## Kubernetes gate remains incomplete

The initial pre-repair minikube run stopped at `RSRC_DOCKER_STORAGE` with
98–99 percent filesystem use. The repaired filesystem scenario subsequently
passed NodePort TCP/UDP, CNI isolation, PVC restart and coordinated restore under
the normal storage guards. Closed success/restoration receipts separately verify
the paused observer for filesystem and plain S3: both protocol revisions,
SELECT-only startup/calls, unchanged retained rows, absent publication ownership,
and authenticated acquisition denial. SQL denial produced `saved_state`,
`statistics` and nested `kind_inventory` timing stages; S3 unavailability stopped
at `saved_state`, with no attribution forwarding. All restoration steps succeeded.

These base-harness results do not qualify the separate Dockerfile server-image
assessment or effective AppArmor enforcement. The remaining real-image scenarios
require:

- Exact candidate-image CLI assessment with restricted UID/GID, mounts, seccomp,
  enforcing pinned AppArmor, fixture DNS/PostgreSQL-only egress and synthetic
  schema-19 legacy history; validate `legacy_unknown`, framing and cleanup.
- Fourteen controlled assessment cases, including connection/auth/configuration,
  output admission, READY failure, restore marker, lifecycle exclusion, corrupt
  history seal, SELECT denial and unavailable telemetry.

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

## PostgreSQL startup readiness qualification

For a candidate with `--connect-readiness wait`, add
`--npm-assessment-readiness` to the exact-image Minikube command above. This
adds cold-start and persistent ingress-denial cases using the production
assessment label. The fixture also checks that configuration, authentication,
TLS and post-connect failures end the assessment without another connection
attempt. The existing Minikube run establishes the separate AppArmor boundary.

Run the [offline K3s fixture](../scripts/test-k3s-npm-readiness.py) with the
same server image and synthetic seed harness. Load the pinned K3s and PostgreSQL
images into the local rootful Docker daemon with storage below `/tmp`. Download
the official K3s amd64 air-gap archive to a private directory below `/tmp`. The
fixture verifies the archive hash and imports the images into an isolated node.
[K3s v1.37.2+k3s1 artifacts](https://github.com/k3s-io/k3s/releases/tag/v1.37.2%2Bk3s1)

```sh
python3 -B scripts/test-k3s-npm-readiness.py \
  --server-image SERVER_IMAGE --harness-image HARNESS_IMAGE \
  --airgap-images /tmp/OWNED_DIR/k3s-airgap-images-amd64.tar.zst \
  --receipt /tmp/OWNED_DIR/npm-readiness.json
```

The K3s receipt records ten fresh starts in the production policy-before-Pod
order, one controlled delay until the same Pod observes a retryable failure, and
one persistently denied connection. Require one `legacy_unknown` report after
the controlled delay, bounded failure before SQL when denial persists, denial
of an unrelated ready PostgreSQL Service, and identical retained metadata.
The receipt distinguishes API observations from observed node rule membership.
Recovery from a controlled delay establishes the mitigation under those test
conditions. The historical production failure remains unresolved.
