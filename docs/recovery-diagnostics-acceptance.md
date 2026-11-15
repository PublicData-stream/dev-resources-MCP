# Local recovery and diagnostics verification

Verified on 2026-11-15 against the implementation in `f0f2b6d..4bfacc8` on
`main`, including `f0f2b6d`. This record is a documentation-only follow-up. The
implementation commits are signed and carry the Codex assistance trailer. No
push, registry publication, production activation or production recovery was
performed. Existing frozen evidence under `deploy/production/` is unchanged.

## Resulting behavior

- [Native and HTTP diagnostics](diagnostic-tooling.md) retain bounded, private
  progress evidence, preserve the canonical requests/assertions and supervise
  failure independently from evidence persistence. The runner's on-disk outcome
  remains provisional; its returned result owns the final control outcome.
- [Exact collection recovery](terminal-recovery-design.md) retains immutable npm
  job history and admissions under schema 19. A superseded eligible job resumes
  in a separate queue, publishes its explicit historical snapshot, and preserves
  the newer current job, acquisition validators and default snapshot. Recovery
  consumes the same verified private artifact descriptor rather than reopening
  an operator-controlled path. Recipe v1 remains pinned to processor 1.
- Recovery admission requires exact terminal provenance, retained bytes,
  expected-state matching, exclusive ownership and a matching operator checkpoint.
  Legacy unknown provenance remains ineligible. The checkpoint records operator
  backup/restore assertions; the command does not repeat that rehearsal itself.
- RFC attribution policy 2 remains unchanged. The errata command verifies an
  evidence package for review and cannot approve applicability or publication.
  No positive RFC recovery recipe is registered.

## Completed local gates

All temporary test state, including Cargo output, fixture archives, PostgreSQL,
Docker and minikube state, was located below `/tmp`. Cargo used Rust 1.99.1,
locked resolution and `/tmp/rust/target`. The environment is native Linux amd64;
network acceptance for this change is IPv4 only. IPv6 runtime configuration was
not changed.

| Check | Observed result |
| --- | --- |
| `cargo fmt --all -- --check` | Passed. |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | Passed. |
| `cargo test --workspace --locked` | 1,142 passed, zero failed, 102 opt-in ignored across 38 test/doc-test binaries. |
| `python3 -B -m unittest discover -s scripts/tests` | 1,158 run, four skipped, successful. |
| `scripts/test-postgres.sh` | Passed: 75 passing test executions across 35 invocations; counts overlap the workspace suite. |
| `cargo audit` | Passed with 1,509 fetched advisories against 525 locked dependencies. |
| `python3 scripts/audit-vendored.py --no-fetch` | Passed. |
| `cargo deny check` | Advisories, bans, licenses and sources passed. |
| `scripts/build-harness.sh` | Built the local fixture image successfully. |
| `scripts/test-oxibelt.sh --image IMAGE` | Pinned-edge IPv4 HTTP and native WebTransport passed for both protocol revisions. |
| `scripts/test-minikube.sh --image IMAGE` | Filesystem mode passed NodePort TCP/UDP, CNI isolation, PVC restart and coordinated restore. |
| `scripts/test-minikube.sh --image IMAGE --s3 --credential-broker` | Passed S3 isolation, complete cache loss, database restore, HTTP/WebTransport and stopped broker/static/broker credential cutover. |
| Markdown local links and `git diff --check` | Passed, including this record. |

The container gates used a task-owned rootful Docker daemon after the existing
rootless daemon could not execute the pinned fixture image. No acceptance claim
is made for that failed rootless attempt. Fixture staging sets executable mode
only on disposable stripped copies; original Cargo binaries retain their bytes
and modes. Initial schema-18 fixture expectations and private-directory modes
were corrected without weakening the schema-19 or private-file boundaries. Final
gates above passed after those corrections. The dependency graph did not change.

The fixture image configuration digest was
`sha256:78077ed38bc7167ba1ac58ab0428e5b419243e02564625519ad90747610472c5`.
The local manifest-list digest was
`sha256:995c60cec406915cc43c89e2b9342e4eb6670a5012733b44f3c5bf36653c529e`.
These identify a local test image, not a released registry artifact. Minikube
reported Kubernetes 1.37.0 and containerd 2.3.4 with the Docker driver. The owned
minikube profiles and PostgreSQL fixture were removed and the isolated Docker
daemon stopped after successful acceptance. Reproducible compiler intermediates
were cleaned for capacity; compiler cleanup was limited to build artifacts.

## Recovery and failure-specific evidence

The PostgreSQL fixtures exercise schema 18-to-19 migration, owner and row-lock
exclusion, exact current-attempt terminal provenance, isolated superseded recovery,
idempotent completion and preservation of the newer current/default/validator
state. Fourteen graph-corruption cases across two tests check history, admissions,
work, completed snapshots, ready markers and receipts, including missing work.
A simulated future processor version verifies that historical recipe and journal
validation stay pinned while unavailable new execution is rejected before claim
mutation.

The historical recovery fixture also performs a real nonempty `pg_dump` and
`pg_restore` into a separate database after releasing the recovery owner. It checks
history, queued/completed recovery, receipts, snapshots, the newer current/default
state and validators after restore. It reuses the surviving matching filesystem
archive and verifies the retained export hash. This demonstrates database restore
against that archive; it does not demonstrate an independent blob backup or S3
bucket-loss recovery.

Native diagnostic tests cover first-byte and partial-frame deadlines, fragmented
and malformed frames, cancellation, flow-control progress and safe bounded traces.
The diagnostic Python fixtures cover failed HTTP exchanges, output saturation,
descendant-held pipes, evidence/disk/collector failures and independent fencing.
A separate successful runner invocation used real filesystem synchronization,
and a separate failing invocation exercised the independently admitted fixture
fence. These supplement the fault-injection tests rather than replacing them.

The actual errata CLI accepted a synthetic complete private evidence package while
leaving publication and applicability unauthorized, rejected a changed raw member,
and produced private reports without fixture payload markers. Evidence-package
success does not establish archive binding or source rights.

Independent MCP/API, Upstream/Storage and Security Boundary reviews inspected the
integrated changes and affected callers. Reported findings were resolved and
re-reviewed; no open code findings remained. Reviews followed the
[delegation skill](../.agents/skills/subagent-delegation/SKILL.md). Agent review is
not a human GitHub approval, and passing fixtures are not a production admission.

## Local log fingerprints

The logs remain disposable local evidence outside the repository, not published
CI artifacts. These SHA-256 fingerprints identify the completed runs; they do not
replace the checks or independently verifiable hosted receipts.

```text
6d8389359db2b247efa1def1219e1f615ecc2c0935105b917ba762ce78074ac8  workspace-verified.log
d1f90657d0e0d1dd0959bd56121676d8ba629bc52ba58b30ad6ba4fed71ac396  python-verified.log
03be85a3efe3916b22e8157869b3713eb97fb151fb860bc4e7bc0635f5d99866  postgres.log
47ebb7c927f02013e661f34c037272988386025ecab5ab2a60b5f9c436e674da  clippy-verified.log
1a476c345dddb047fe29745dc2475327b82841053af5631ba95538efcf665ad8  audit.log
2e7d20a83e8e3689fa522cc17211d8a40db82f7664c7c2a50d1ce07a447d675c  vendored.log
172609b6ee5bb02a6e2f5e71fc64494fec7402b4cdae41911857320d11c26226  deny.log
6cf9338b0d982d34f64e77a2f267d4a505455f5935049ddcc35651d7a8b79dc7  runner-real-io.log
b32bfe4564782cdbe7b45e38cc5e288ab013c69ff97f8a1961fe1ef2b98a3c0e  errata-cli.log
c359278499f4ea3311aae6561d987be9cea7c1b7a1985793a3a211bb98971ad3  oxibelt.log
e26b8bcf0ebd231619283c697b537b171422e40dec8e89c5990c532f9949df7b  minikube-fs.log
0ecd54e743b815249cd6218339e1eb16ebb3beaf4caf5f8faf920c082354ba3b  minikube-s3.log
```

## Unproved operational boundaries

The original failed production attempts remain failed. Local fault injection and
successful IPv4 fixtures do not determine their historical IPv6/HTTP causes.
Unknown-provenance npm jobs and unqualified RFC errata remain blocked. This work
implements recovery mechanisms; it does not recover the production corpus.

No hosted native arm64 CI result, registry publication, live source-provider
acceptance, full-corpus collection, production stability or native ChatGPT UI
acceptance is claimed. Tests used controlled provider fixtures; opt-in live
source-provider probes were not run. Advisory/index retrieval, pinned image
downloads and local cluster setup did use external network access. S3 fixture
acceptance is separate from an independently retained production bucket backup.

Production use still requires a fresh reviewed successor, exact-state admission,
stopped participants, a coordinated database/archive backup and restore rehearsal,
and independently observed post-activation acceptance under the
[operations contract](operations.md).
