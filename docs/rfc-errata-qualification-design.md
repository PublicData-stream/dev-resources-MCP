# Selected RFC errata qualification

Initial design recorded 2026-11-15. The 2026-11-21 review established the
operator-approved policy-3 recipe for one retained member. Production release
and activation require separate authorization.

## Applicable terms

[RFC 5378 section 1(a)](https://www.rfc-editor.org/rfc/rfc5378.html#section-1)
defines IETF Contributions to include communications addressed to the RFC Editor
within IETF activities. Section 4 separately treats non-IETF submissions. This
definition informs the submission-specific review below.

[TLP 5 sections 2 and 3(c)](https://trustee.ietf.org/documents/trust-legal-provisions/tlp-5/)
distinguish applicable dates and permit specified unmodified reproduction with
attribution and notices. Earlier material retains its earlier terms, and section
8 addresses other streams. The corrected text has an effective date of March 25,
2015. Its September 21, 2021 correction concerns the BSD license name. The
[official version archive](https://trustee.ietf.org/documents/trust-legal-provisions/)
is the starting point for identifying earlier provisions; current terms alone
cannot qualify a historical contribution.

The [RFC Editor errata guidance](https://www.rfc-editor.org/series/rfc-errata/)
distinguishes reported, verified, rejected and held reports from the immutable
RFC. Verification status concerns technical review; it is not a licensing
decision. The [RFC usage guidance](https://www.rfc-editor.org/series/rfc-use/)
does not independently establish a blanket grant for all submitted corrections.
These official sources were checked on 2026-11-15. This investigation did not
establish explicit all-era, all-stream submission terms or inspect an individual
historical submission's agreement.

For erratum 8173, the project's reviewed determination treats the 2024-11-11
submission from Shushang Wen as a communication to the RFC Editor in the context
of the IETF activity for RFC 9525. RFC 9525 is an IETF-stream RFC published in
November 2023. Corrected TLP 5 § 2 applies to those dates, and § 3(c)(iii)
supports serving the exact unmodified portions with IETF, source, and authorship
attribution. `orig_text` is covered as a quote from RFC 9525. `correct_text` and
`notes` are covered as verbatim excerpts of the historical erratum contribution.
The member notice includes the RFC's original copyright and legal notices, the
RFC authorship, the contributor attribution and the official source. The operator
approved this interpretation for the capture and member in the table below.
[RFC 9525](https://www.rfc-editor.org/rfc/rfc9525.html) · [RFC Editor disposition](https://mailarchive.ietf.org/arch/msg/uta/YjOHse3Ol_F4XcuTrz76AaUmFxk/)

## Evidence boundary

Use selected errata-member subjects rather than approving the multi-decade export
as one content scope. Bind each member to its aggregate capture, exact export body
digest, errata ID, referenced RFC number and exact retained record digest. Keep
original fields and status values; do not apply corrections to RFC text.

Verify the exact historical export before extracting the selected member. A newer
export cannot establish the bytes of a retained capture. Require retained evidence
of report date, stream and contributor attribution, plus any subsequent editing
or authorship information necessary to establish the selected record's scope.
Missing or ambiguous evidence remains unavailable.

Additional members, captures, streams or versions need their own reviewed
evidence and recipe. A report's technical status and public listing establish
identity and disposition. They supply no independent redistribution grant.

Acquire the applicable version of the terms, evidence supporting applicability,
and the referenced RFC's exact original notice. Preserve their bytes/digests and
acquisition receipts. Cover quoted RFC text and newly contributed correction or
notes text separately. Publish complete readable contributor/source attribution,
applicable terms and original notices in an immutable member generation. Do not
invent an SPDX identifier or silently truncate notices.

Terms acquisition must use reviewed fixed operations and destinations, never
caller-supplied or discovered arbitrary notice URLs. Adding `trustee.ietf.org` to
broker/network admission would require separate Security Boundary review and
network/minikube acceptance. This repair adds no such outbound authority. Receipt
reuse must match exact bytes, applicability and the approved policy.

## RFC 9525 serving and archive inspection

RFC 9525 uses verified member links when the active policy has no ready prose
qualification for the exact member. A ready policy-3 generation supplies the
three exact fields, their capture citation and immutable attribution resources.
Filters, source order, pagination and snapshot selection come from the retained
dataset. The tool checks each selected record against the exact export and
derives its official link from its numeric identity. A snapshot that binds the
same exact export can use the qualified member. The aggregate capture's
attribution and resource reads still use their own gate.

An operator with the configured read-only database and archive role can extract
the original export into an owned private directory under `/tmp`:

```sh
devres-server inspect-rfc-errata-capture /etc/devres/reader.toml \
  --export-capture blake3:EXPORT_CAPTURE_HEX --export-body blake3:EXPORT_BODY_HEX \
  --rfc 9525 --errata-id 8173 --snapshot blake3:SNAPSHOT_HEX \
  --bundle /tmp/PRIVATE-BUNDLE --output /tmp/PRIVATE-BUNDLE/capture.json
```

Omit `--snapshot` to select the highest-ranked snapshot binding the specified
capture. Use fresh output paths in a directory owned by the invoking user with
private permissions. The command checks the sealed binding and full export under
the existing diagnostic bounds, then writes the exact body under its bare digest.
Its sanitized report provides the snapshot and the raw member digest for the
manifest. Use fresh paths after an interrupted write. The export contains all
members and belongs in the private bundle. The report records archive binding
separately from the operator's applicability or publication decision.

Use a mounted static reader identity for a strictly read-only production inspection.
Broker-backed credentials can trigger key issuance or revocation as part of normal
broker operation.

The 2026-11-21 production reader inspection verified the committed S3 object,
its full export checksum, and the selected raw record. The three retained prose
fields matched the official disposition exactly. The operator selected URL-only
serving under policy 2 before approving the exact-member policy-3 interpretation.
[RFC Editor disposition](https://mailarchive.ietf.org/arch/msg/uta/YjOHse3Ol_F4XcuTrz76AaUmFxk/)

| Verified identity | BLAKE3 digest |
| --- | --- |
| Snapshot | `9077e62009237b595fbdb59abecb4dd033a57f695d75ce0ed77da8ee5d2bdbd0` |
| Export capture | `20f58039b1c862f35a4b416b6695a8b51169ce3297bfa21762e1596ba5b59af9` |
| Export body | `c494ef35fddcafebb7d958c2c0ce2d38c1e258e445022ab8a8ae198ef73d8090` |
| Member 8173 | `16bbccf2d5554fd6be2b62ac095e96924ff8c8442c26a5c989380cbf61fc5e43` |
| Exact manifest file pinned by the recipe | `59ad2053833db9bb49c05b43ca0df3a9cc6ca9afd74ca64d879f0ef9452bb939` |
| Canonical manifest in the validation report | `ac2b6eaccf6d8f792ba28055814e8e35a5287fd66e01004157e2df110ea06b34` |

Local packaging recorded `complete_for_review` and all six dependency roles.
The operator's applicability approval and the sealed archive inspection are
separate records. Keep the original manifest bytes when staging the writer bundle.

## Policy 3 and rollout

The global required epoch is 3, with fingerprint
`devres-attribution-v3:verified-forward-origins:member-scopes:rfc-erratum-8173:readable-notices`.
The sole writer activates it through the existing startup fence. The transaction
validates and resets the bounded sweep and origin checkpoints for current-policy
discovery. Policy 1 and 2 generations and notice resources retain their historical
verification rules. All providers requalify via ordinary bounded repair under the
current epoch.
See [rollout acceptance](operations.md#attribution-policy-3-and-rfc-9525-erratum-8173).

The member has a distinct policy-3 target. Its publication uses the reviewed
private evidence bundle and re-reads the exact retained export through existing
archive admission. The writer publishes through sealed attribution storage under
owner fencing. The blocked policy-2 aggregate target and its attempt history
remain available for verification. Same-epoch recovery and bulk operations keep
their separate authorization and review requirements.

Fixtures cover selected-member identity, changed export and wrong member
rejection, missing date/stream/authorship/terms, quoted and contributed text,
complete notices, dependency bounds, cancellation, ownership loss and historical
recipe dispatch. Promotion and restore acceptance must verify readiness on every
provider through fixed records. A verified link demonstrates the fallback
contract. Direct-prose readiness requires the exact fields and notice readback.

## Local evidence validation

`verify-rfc-errata-evidence` implements local packaging checks for review, without
configuration, a database connection, provider acquisition or publication:

```sh
devres-server verify-rfc-errata-evidence /tmp/errata-owned \
  --manifest /tmp/errata-owned/manifest.json \
  --output /tmp/errata-owned/report.json
```

The version-1 manifest contains `export_capture`, `export_body`, `member_body`,
`errata_id`, `rfc`, optional `report_date`, `stream`, `contributor`, and a bounded
`dependencies` list of `{role, body}` records. Hashes use BLAKE3. Bundle files are
named by the bare 64-digit body digest and must be private owned regular files
without links. `member_body` hashes the exact raw JSON member slice, including its
original formatting; the entire export is independently hash checked and parsed
with the existing RFC bounds. Date and contributor assertions must match the
selected record's `submit_date` and `submitter_name`. Required review roles are
`terms`, `applicability`, `original_notice`, `authorship`, `quoted_scope` and
`contributed_scope`. Each dependency is hash checked, not interpreted as authority.

The whole byte allowance is 64 MiB; individual dependencies are at most 1 MiB,
manifest input 64 KiB and output 1 MiB. Missing declared metadata/roles yields
`incomplete`; mismatched bytes/identities or unsafe inputs are rejected. Complete
packaging yields `complete_for_review`, while `publication_authorized`,
`applicability_approved` and `archive_binding_checked` remain false. Declaring a
stream or supplying arbitrary terms bytes proves neither applicability nor an
archive capture binding. Reports omit contributor names, prose, paths and terms
bodies. Policy 2 and all earlier qualification recipes remain unchanged.

Use this validator with the private inspection bundle containing the export body.
For writer startup, build a separate private directory with `manifest.json` and
the six digest-named evidence bodies. The writer reads the export from the
configured archive, so the writer directory needs no export copy. Set
[`rfc.erratum_8173_evidence_dir`](Configuration.md#resource-defaults) on the sole
writer. Keep both directories out of source control and container builds.
