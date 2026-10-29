# Third-party notices

First-party work is AGPL-3.0-only; this does not relicense retrieved public sources.

## OpenLegal transport adaptation

Generic Rust HTTP/WebTransport, framing, deadlines, TLS client authentication,
progress, and admission modules were adapted from PublicData-stream's
[openlegal4everyoneMCP](https://github.com/PublicData-stream/openlegal4everyoneMCP/tree/7a592e0c7b1ef1518bd9ab47788a4e03697f3e63),
base revision `7a592e0c7b1ef1518bd9ab47788a4e03697f3e63`, AGPL-3.0-only.
The supplied checkout also contained local transport changes. These exact source
snapshots were consumed (SHA-256 before adaptation):

| Module | Source snapshot hash |
| --- | --- |
| HTTP | `e99edd2478c01e28bdc6330f7ab3adb82b8b1ff18a6eaf3d188ffb20a6790942` |
| WebTransport | `e90f91475c3cbc52ad34923c4bb0a1bcce9d6fdd16a9c03a191ed19ce6e94562` |
| HTTP status translation | `8540d400d3fc9decc254a11d183c18917ed2a100bfa476e5ae9472bd78498d5e` |

The upstream contributors retain their rights. Adaptation removes legal-data,
widget, and product composition and connects developer-resource operations.
The complete AGPL license is in [LICENSE](LICENSE).

## OpenLegal release workflow adaptation

The release CI selector and publication flow were adapted from
[OpenLegal at 90dc7fcf](https://github.com/PublicData-stream/openlegal4everyoneMCP/tree/90dc7fcf91db6a1361ab8362466be763921fb826),
revision `90dc7fcf91db6a1361ab8362466be763921fb826`, AGPL-3.0-only.
The adaptation retains this repository's native OCI artifact promotion and
corresponding-source distribution, with developer-resource image families and CI
job completeness checks. Upstream contributors retain their rights.

## OxiBelt reference

Contributor orientation and delegation principles refer to
[OxiBelt](https://github.com/OxiBelt/OxiBelt/tree/4f3154d8db0e0a49bce7a528c0a0f4c36d169040),
revision `4f3154d8db0e0a49bce7a528c0a0f4c36d169040`, Apache-2.0.
OxiBelt is separately built for acceptance; it is not incorporated into the service
runtime. Its original license and notices must accompany redistributed artifacts.

## Retrieved sources and dependencies

Preserve RFC copyright/notices and applicable IETF Trust terms. RustSec data is
CC0-1.0 except explicitly attributed GHSA content under CC-BY-4.0. Crate archive
contents retain each package's own licenses and notices. Index metadata is not a
claim that an entire package has one license or that its source matches its Git repo.
Dependency admission and runtime image notice obligations are recorded in
[dependencies](docs/dependencies.md). Resolve licenses from the locked graph; do
not treat this attribution inventory as a complete generated dependency license bundle.

## Supplemental dependency license texts

Some published crates omit standalone workspace license files. The exact-version
texts in `third-party/licenses` were retrieved from upstream revisions declared in
the published packages' `.cargo_vcs_info.json`. `provenance.json` records package,
repository, revision and path. This is licensing provenance, not proof that archive
contents match a Git tree. The image collector includes these alongside packaged
notices. No dependency implementation is vendored by this supplement.

A small actual RustSec Git snapshot fixture and its original CC0 terms are retained
with [capture provenance](crates/adapters/tests/fixtures/rustsec/README.md). Its
synthetic negative mutations are labeled separately; it is not a full database.

## W3C notice profiles

W3C source notices retain their original terms separately from this repository's
AGPL license. The fixed required Software and Document NOTICE text used by the
W3C adapter is attributed to W3C under its
[2023 Software and Document License](https://www.w3.org/copyright/software-license-2023/).
The exact repository declaration recognized in synthetic license fixtures was
observed in the official
[CSSWG](https://github.com/w3c/csswg-drafts/blob/main/LICENSE.md) and
[Permissions](https://github.com/w3c/permissions/blob/main/LICENSE.md) repositories.
It is a notice template, not a blanket authorization for every W3C artifact or
historical revision. Document-license prose and clearly marked code components
retain their distinct governing notices; unresolved terms remain metadata only.

## Staging AppArmor profiles

The workload profile template in `deploy/staging/apparmor.profile` is adapted
from containerd v2.3.4, revision `db8809540e1a7a9da5d518876894933ff55692ab`,
[`contrib/apparmor/template.go`](https://github.com/containerd/containerd/blob/db8809540e1a7a9da5d518876894933ff55692ab/contrib/apparmor/template.go).
The source file SHA-256 is `f5bef9dd4d785a27aa00b421862c68de973f19bb5b36dd39f4a5d2dd35ac2683`.
Copyright The docker Authors, The Moby Authors, and The containerd Authors.
It remains Apache-2.0; the complete license accompanies the template in
[Apache-2.0.txt](deploy/staging/Apache-2.0.txt).
The adaptation renders two workload-specific names and adds exact same-workload
stacked-label signal permission for the deployment host's AppArmor behavior.
It retains the upstream proc/sys/mount restrictions and confines the change to
these new workloads; existing cluster profiles are not modified.
