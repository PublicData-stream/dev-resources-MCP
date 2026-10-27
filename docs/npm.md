# npm package research and auditing

The npm module covers public packages in an explicit operator catalog and public
OSV npm advisory evidence. The catalog starts empty. Package retrieval does not
enroll a package, and auditing does not fetch or enroll dependencies. Existing
Cargo tools and generic search defaults are unchanged.

## Public interfaces

`npm_search` queries official registry search. `npm_metadata` selects an exact
release from full registry metadata. `npm_source_list` and `npm_source_read`
verify distribution integrity before inspecting a published archive. Supply both
`metadata_capture` and `archive_capture` to continue against fixed evidence.
`fetch` accepts `npm:is-number@7.0.0` and scoped identities such as
`npm:@types/is-number@7.0.5`. Generic `search` includes npm only when selected.

Local research uses `npm_versions`, `npm_catalog_search`, `npm_document_get`,
`npm_dependencies`, `npm_compare`, `npm_content_search`, and `npm_contract_get`.
`npm_history`, `npm_snapshots`, and `npm_corpus_status` expose retained observations
and coverage. `npm_advisory_lookup`, `npm_advisory_get`, and
`npm_advisory_catalog_search` read public advisory snapshots.
Discovery supplies the exact schemas. Lists default to 20 and cap at 100; text
pages count UTF-8 bytes and cap at 32 KiB. Reuse returned snapshots and cursors.

Dependencies are declarations, including aliases and optional/peer/dev metadata.
They are never resolved. Research covers published source, README/license text,
type declaration text and manifest contracts. Conditional export/import order,
patterns and null targets are retained. Literal paths link only to captured files;
external import declarations remain inert. Observed text or contract changes are
not runtime compatibility or security certifications.

## Collection and permanent evidence

The collector observes full metadata for configured names and attempts every
observable exact release. Metadata, tags, release disappearance, distribution
changes, raw archives and processing generations remain permanent evidence.
Catalog removal stops future acquisition without deleting historical snapshots.
Unseen deleted releases cannot be reconstructed. Status distinguishes retained
raw data, verified integrity, projection, indexing and catalog coverage.

One shared registry transfer and attempt clock covers foreground and background
requests. Retries reserve the same clock. The default one attempt/second is our
conservative application policy, not an official numeric registry allowance.
Only canonical registry destinations are admitted; redirects, credentials,
alternate registries and linked websites do not authorize acquisition.

SRI supports SHA-512, SHA-384, SHA-256 and SHA-1, selecting the strongest supported
algorithm. SHA-1 `dist.shasum` is used only when SRI is absent. Unsupported or
mismatching supplied integrity never silently downgrades. Local SHA-256 identifies
stored content separately from distribution verification assurance.

No package is installed, extracted, built or executed. Archives retain their raw
evidence when inspection is unsupported. Inspection caps compressed input at
32 MiB, expansion at 256 MiB, members at 20,000 and an individual text projection
at 4 MiB. Parser deadlines, JSON depth and index limits remain separate boundaries.
Archives admit one consistent `package/` or historical package-basename root;
scoped names and exact versions must still match the captured package manifest.
Package licenses and original notices remain attached; public availability does
not establish unrestricted reuse rights.

## Local lockfile assessment

`npm_audit_lockfile` requires `lockfile` and `lockfile_format` (`npm`, `pnpm`,
`yarn_classic`, or `yarn_berry`). It accepts `advisory_snapshot`,
`registry_context`, `offset`, and `limit`. Continue by resubmitting the same input
and the returned advisory snapshot. Caller input, inventories and reports remain
in request memory and have no capture/resource identity.

| Format | Supported schema |
| --- | --- |
| npm package-lock or shrinkwrap | 1, 2, 3 |
| pnpm | 5.4, 6.0, 9.0, including multi-document v9 |
| Yarn Classic | 1 |
| Yarn Berry | 4, 6, 8, 10 |

Other schemas fail explicitly. Parsers admit at most 1 MiB and 10,000 inventory
entries. The isolated sibling worker has bounded input/output and a 15-second
deadline; cancellation terminates it. Duplicate keys, unsafe YAML constructs and
excessive nesting fail without reflecting private source text.

Registry context contains a `default` identity and a `scopes` map with values
`npmjs`, `other`, or `unknown`. It is a caller assertion, never credentials or an
uploaded npm configuration. Ambiguous identities remain unassessed unless a caller
assertion establishes public npm origin. An explicit conflicting
custom origin remains unassessed. Aliases match the real package identity.
Workspace, Git, file and unsupported transformed sources remain unassessed.
Patched packages can return base-release matches while the transformed artifact
and overall assessment remain incomplete. All dev/optional records are included;
the result describes the lockfile inventory rather than an installed runtime graph.

## Advisory evidence and freshness

The independent advisory lane captures the fixed OSV npm ecosystem export and
matches locally; no dependency lists or lockfiles are uploaded. Matching supports
explicit versions, SEMVER and npm ECOSYSTEM event ranges, wildcard package
applicability, prereleases, inclusive last-affected and exclusive fixed/limit
boundaries. Unsupported records make affected assessments incomplete.

Withdrawals, malicious-package classification, aliases and original source records
remain distinct evidence. Absence from a later export is not withdrawal.
GHSA and OpenSSF malicious-package records retain their CC-BY-4.0 and Apache-2.0
attribution respectively. Unknown source rights remain explicit gaps.

Default local evidence is stale after 24 hours and unavailable after seven days
without upstream validation. Explicit historical selections remain readable.
Restoration and reprocessing do not advance source-validation times. A fresh
zero-match report is limited to the selected export and supported identities.

## Operations

Artifact quotas cover collector raw artifacts, including advisory exports and
member source. Generic request captures keep the existing shared capture-storage
accounting; PostgreSQL and derived indexes are outside the npm artifact quota.
Status row counts include all retained generations, rather than unique current
releases or a full-registry completion percentage.

Schema 9 is forward-only. Back up PostgreSQL, npm raw artifacts and derived indexes
together with the other corpora. Stop serving before private maintenance or restore;
the existing single-owner fence applies. `rebuild-npm-index CONFIG.toml` rebuilds
derived search from retained public evidence without refreshing provider validation.

Fixture checks, PostgreSQL persistence, image/edge/minikube acceptance, bounded live
provider observations, native architecture CI and production operations are
separate evidence. Live smoke is opt-in and limited to fixed records and at most
20 attempts per provider; it does not establish registry-wide coverage.
See [npm validation evidence](npm-acceptance-evidence.md) for executed checks and
the retained live observations.

Sources: [registry metadata](https://github.com/npm/registry/blob/main/docs/responses/package-metadata.md),
[integrity semantics](https://github.com/npm/ssri),
[Node package contracts](https://nodejs.org/api/packages.html),
[npm crawler policy](https://docs.npmjs.com/policies/crawlers/),
[OSV exports and attribution](https://google.github.io/osv.dev/data/),
[OSV schema](https://ossf.github.io/osv-schema/),
[npm lockfiles](https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/),
[pnpm released format](https://github.com/pnpm/pnpm/blob/91774e72a04d52ce61db06339696a433d383c764/pnpm/docs/lockfile.md),
and [Yarn released format](https://github.com/yarnpkg/berry/blob/75ebe063092f86e47e4afeaf1ae4bdf24402874b/packages/yarnpkg-core/sources/Project.ts).
