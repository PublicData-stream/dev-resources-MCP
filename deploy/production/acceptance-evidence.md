# Release preparation evidence

Recorded on 2026-11-10 for `0.1.0-build.172d528d`. This is a preparation
checkpoint, not production acceptance. No public service or collector has been
activated. Recheck changing external state before resuming.

## Published release

The signed commit is `172d528d88d16c9ec4fd83a16674280815178930`; its signed
annotated release tag was verified separately. The existing
[main CI run](https://github.com/PublicData-stream/dev-resources-MCP/actions/runs/42635621474)
and [publication run](https://github.com/PublicData-stream/dev-resources-MCP/actions/runs/42642722560)
succeeded, including native amd64/arm64 jobs and anonymous image pulls. These
hosted results apply to the released revision, not subsequent local tooling.

The downloaded
[source archive](https://github.com/PublicData-stream/dev-resources-MCP/releases/download/0.1.0-build.172d528d/source.tar.gz)
has SHA-256 `f3680663c2a1e69dfb12489ba44cc56512759b4068704443d3fb0c98bd7f57b0`.
The renderer pins these published image indexes:

| Artifact | SHA-256 |
| --- | --- |
| server | `da44682428c2ee37568867cb5bf0b0c3d75cb01b4d1c027c00f313bb29cf737f` |
| broker | `4ae4ea7fadeb1076cb387cd82a32ea25419914f32c4a454dbb015391a95e1889` |
| probe | `324c117f72029a4ab153029a6559ccda4d50cf464db164b361ff379a08b3839d` |

No new runtime release or image was published during this preparation.

## Local tooling verification

The source qualification helper is in signed commit `538d966`; the production
renderer/operator and its tests are in signed commit `05684ab`. Both include the
required assistance trailer. Neither tooling commit was pushed.

| Boundary | Observed result |
| --- | --- |
| Rust format and workspace/all-target clippy | Passed with locked dependencies and warnings denied |
| Workspace non-documentation tests | 846 passed, 66 ignored |
| Documentation tests | Initial workspace command failed with missing cached crate metadata (`E0463`); a separate locked workspace doc-test rerun passed without source changes |
| Dependency audit and deny | Passed against fetched advisory data; duplicate-version warnings remain |
| Python suite | 725 tests, successful with two skips; the root ownership-adoption case and actual pinned lego CLI fixtures were exercised separately and passed |
| Alpine PostgreSQL fixture | Pinned production image: initialization, reader write denial, role separation and restart passed |
| Standard PostgreSQL suite | Passed |
| OxiBelt fixture | Both MCP revisions/transports and rejection cases passed |
| Filesystem minikube fixture | NodePorts, persistence, coordinated restore and both transports passed |
| S3/broker minikube fixture | Pod identity, encryption, isolation, broker restart, credential refresh, outage recovery, cache loss and database restore passed |

All disposable fixture state, Docker/minikube storage and the Rust target were
under `/tmp`. The first fixture-image build was interrupted after package mirror
timeouts. The successful local harness reused the matching cached Ubuntu/package
layer and copied freshly built binaries and current scripts into it. The gate
commands and assertions were unchanged. This establishes local fixture behavior;
it does not replace the separate published-image evidence above.

Independent MCP/API, Upstream/Storage and Security Boundary review closed for
preparation only. That review does not authorize activation or constitute human
GitHub approval.

## Target preparation

The target cached the pinned server, broker, probe, Alpine PostgreSQL, OxiBelt and
lego images. Ten final tooling files were transferred with a manifest binding
release revision and tooling commit, verified individually, and placed in a new
root-private candidate directory. The archive SHA-256 is
`6dee2e24f155596503de0368e12f3b200f5cd8441cfa5f51f0a0a798437679c6`.

A separate mode-0700 private bundle contains generated database initialization
material, mTLS identities and journal encryption material. Its phase remains
`prepared`. Server-side Kubernetes dry-run accepted all 36 rendered resources.
The final inventory found zero devres Deployments, Pods, PVCs or Secrets and zero
Docker containers. Both permanent PostgreSQL directories remain uninitialized.
No live edge configuration, renewal timer, global boot dependency or provider
policy was changed.

## Incomplete acceptance

- The latest real issuer probe returned HTTP 200 for its own API-key identity,
  matching the issuer application. Organization-qualified key lists for both
  workload applications returned HTTP 403 `permissions_denied`; the unrelated
  issuer application's list also returned 403. No keys were issued or revoked.
  Successful permitted operations and denial of unrelated key/policy management
  still require real provider evidence before broker startup.
- The fixed-source gate stopped in the RFC family with `integrity` after two
  recorded requests. Other families did not run; there is no passing source
  receipt. Its private evidence and spent budget were retained. An earlier
  initialization-only permissions failure made zero requests and was corrected
  before the bounded live attempt. No automatic budget reset or live retry was
  performed after the RFC failure.
- Boot service ordering does not prove that a failing firewall blocks k3s and
  Docker startup. The operator therefore refuses edge installation without a
  real negative-test receipt. No such receipt exists.
- An empty legacy Traefik LoadBalancer Service remains in kube-system. Its removal
  was rejected by automatic approval review because it is a cluster-level ingress
  change without explicit authority. Removal did not run. New boot dependencies
  were likewise rejected as boot/security changes outside approved scope.
- Real Scaleway/S3 permissions, credential expiry/revocation, representative
  permanent capture, public IPv4/IPv6 HTTP/WebTransport, certificate hot reload
  and the ten-minute observation remain unverified. Local fixtures do not
  establish these results. Full corpus coverage and scheduled backups are not
  claimed.

Resume using the [operator gates](README.md) after obtaining the missing provider
evidence and explicit authority for the remaining host/ingress changes. Preserve
the failed source evidence; investigate it before any separately authorized live
retry. Do not create fixture acceptance receipts for production.
