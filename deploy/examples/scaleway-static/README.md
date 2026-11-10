# Static Scaleway IAM archive credentials

Use two dedicated Scaleway IAM applications and two API key pairs: serving
read-only and writer read/write. An API key pair contains an access key and a
secret key; it is not an `X-Auth-Token` header sent to the S3 endpoint. Requests use
S3 signing through the existing `files` credential source. There is no runtime IAM
issuance, broker, OIDC exchange, session token or credential fallback.

These examples do not authorize deployment or prove real Scaleway permissions.
The production renderer accepts `"storage_auth": "scaleway_static"` in its JSON
settings; omission retains `broker`. Its current server image pin predates the
role-derived transport guard, so production static provisioning/start/cutover
remain blocked until a separately qualified immutable release updates that gate.

## Applications and effective permissions

Choose separate serving and writer application UUIDs. For a broker-to-static
cutover, create applications distinct from both broker-managed applications so
retiring the broker cannot revoke or widen static credentials. Scope IAM policy to
the intended project/resources and remove broader user/group/application grants.
The key's default project alone does not restrict authorization. Prefer a dedicated
project containing only this archive bucket: IAM grants can otherwise reach other
buckets that lack restrictive bucket policies. If sharing a project, explicitly
restrict access on the other buckets and verify the negative checks before admission.
Provision the private bucket outside the application, with one exclusive
database-bound prefix.

Serving needs `ObjectStorageObjectsRead`. Writer needs
`ObjectStorageObjectsRead`, `ObjectStorageObjectsWrite`, and
`ObjectStorageObjectsDelete`: Scaleway maps `AbortMultipartUpload`, required for
interrupted application-owned uploads, to the Delete permission set. This does not
permit the application to delete permanent evidence. The writer bucket-policy
example allows abort and explicitly denies `s3:DeleteObject` and
`s3:DeleteObjectVersion`; the read-only example also denies object mutation.
Do not grant bucket, IAM or policy administration.

Replace the application UUIDs, bucket and prefix in the
[read-only](readonly-bucket-policy.json) and [read/write](readwrite-bucket-policy.json)
statements and merge them into the bucket's policy. They use Scaleway application
principals and resource syntax. Allow statements alone cannot remove permission
granted elsewhere. Review effective IAM and bucket policies together; validate
other-prefix/bucket denials using the actual account. Do not claim these examples
establish confinement without provider evidence. See
[using IAM keys with Object Storage](https://www.scaleway.com/en/docs/iam/api-cli/using-api-key-object-storage/),
[permission sets](https://www.scaleway.com/en/docs/iam/policies-permissions/permission-sets/),
[S3/IAM permission equivalence](https://www.scaleway.com/en/docs/object-storage/reference-content/s3-iam-permissions-equivalence/)
and [bucket policies](https://www.scaleway.com/en/docs/object-storage/api-cli/bucket-policy/).

## Runtime isolation and rotation

Merge the [serving fragment](serving-fragment.toml.example) and
[writer fragment](writer-fragment.toml.example) into their corresponding normal
configurations. Keep SELECT-only serving PostgreSQL credentials, authenticated
private writer acquisition, the single writer fence, and separate pod caches and
scratch. Both roles must use the same archive endpoint/bucket/region/prefix;
changing credentials does not migrate or rebind stored evidence.

Create the two [Secret templates](secrets.yaml.example) privately, only after
verifying native cluster Secret encryption. Serving mounts only
`devres-serving-s3`; writer mounts only `devres-writer-s3`, read-only at
`/run/devres-s3` with `access-key` and `secret-key`. Neither workload has Secret-read
RBAC or IAM administrative credentials. Keep key values out of TOML, arguments,
logs, public resources, corpus archives and diagnostics. The static production
profile contains no broker database, issuer Secret, broker token or IAM egress
rule. Writer coordination still uses its separate projected Kubernetes identities.

Rotation is controlled: obtain and validate replacement keys, stop serving then
writer, replace the role Secrets and renew the credential-bound private acceptance
evidence, then start writer before serving. Verify authoritative object readback
and readiness before revoking old keys. A Secret projection update alone is not a
hot-rotation guarantee; restart both roles. Missing/revoked credentials and storage
outages fail closed even for cached objects. Static keys do not inherit broker
lease expiry or pod-deletion revocation; revoke them through the provider.

## Production operator workflow

The commands below describe the workflow for a qualified immutable release. The
current production release gate refuses static `provision-runtime`, `start` and
`switch-storage-auth`; rendering templates or computing fingerprints does not
lift that gate. Use a fresh private bundle for each authentication method, an
explicit cluster context for cluster operations, and root-owned private inputs.

Static inputs contain exactly these identity, policy and secret-file references:
`organization_id`, `project_id`, `reader_application_id`, `writer_application_id`,
`reader_policy_sha256`, `writer_policy_sha256`, `reader_access_key_file`,
`reader_secret_key_file`, `writer_access_key_file`, `writer_secret_key_file`, and
`acceptance_receipt_file`. They contain no issuer or IAM administration credential.
The policy digests describe the reviewed effective IAM and bucket policies.

For a fresh empty deployment, use normal preparation and PostgreSQL bootstrap,
then compute the credential/configuration binding before independently obtaining
and admitting the provider receipt:

```sh
python3 -B scripts/production-operator.py --bundle /var/lib/devres-static \
  --settings /tmp/devres-static-settings.json prepare
python3 -B scripts/production-operator.py --context default --bundle /var/lib/devres-static install
python3 -B scripts/production-operator.py --context default --bundle /var/lib/devres-static start-postgres
python3 -B scripts/production-operator.py --context default --bundle /var/lib/devres-static \
  --inputs /var/lib/devres-private/static-inputs.json static-fingerprints
# Independently obtain real provider acceptance and place its receipt privately.
python3 -B scripts/production-operator.py --context default --bundle /var/lib/devres-static \
  --inputs /var/lib/devres-private/static-inputs.json provision-runtime
python3 -B scripts/production-operator.py --context default --bundle /var/lib/devres-static start
```

`static-fingerprints` prints only private binding fingerprints/identity metadata;
it neither contacts the provider nor generates a passing receipt. The receipt uses
`version: 1`, `mode: "scaleway_static"`, `fixture: false`, and `binding` equal to
the command's `binding` output. Set each `checks` field to true only after real
independent provider verification: `reader_read_list`, `reader_mutations_denied`,
`writer_read_conditional_put`, `writer_multipart_complete_abort`,
`permanent_deletion_denied`, `other_bucket_prefix_denied`,
`administration_denied`, and `rotation_revocation_verified`. Include UTC
`verified_at` and `expires_at`; verification must be no more than 31 days old and
the receipt must remain unexpired. Changed keys, applications, policy digests or
archive coordinates require matching renewed evidence. Fixture receipts cannot
authorize production.

Both bundles must pass the existing exact release and cluster identity checks.
An authentication switch does not upgrade the runtime release; admit the broker
deployment to the same qualified release first through the separately reviewed
release procedure.

For a populated broker deployment, stop the source roles first. Source collector
settings must be disabled before `prepare-auth-switch`; preparation refuses an
enabled source. If the source was activated, run `pause-collectors` after stopping
its serving/writer roles. It verifies stopped roles and exact runtime state, then
changes only the eight collector `enabled` flags to false in the two role
configurations/Secrets. Budgets, broker credentials and the running broker remain
unchanged, preserving a restartable rollback bundle; a failed update restores the
original role configurations. Do not reprovision issuer keys or drain the broker
before the actual switch. Prepare a separate pending
target bundle that preserves corpus database credentials/TLS; do not call fresh
`prepare`, `install` or initialization SQL against retained storage:

```sh
python3 -B scripts/production-operator.py --context default --bundle /var/lib/devres-broker stop
# Disable only collector admission; keep the running broker and its keys intact.
python3 -B scripts/production-operator.py --context default --bundle /var/lib/devres-broker pause-collectors
python3 -B scripts/production-operator.py --context default --bundle /var/lib/devres-broker \
  --target-bundle /var/lib/devres-static --settings /tmp/devres-static-settings.json prepare-auth-switch
python3 -B scripts/production-operator.py --context default --bundle /var/lib/devres-static \
  --inputs /var/lib/devres-private/static-inputs.json static-fingerprints
# Obtain the matching real provider receipt before staging the target secrets.
python3 -B scripts/production-operator.py --context default --bundle /var/lib/devres-static \
  --inputs /var/lib/devres-private/static-inputs.json provision-runtime
python3 -B scripts/production-operator.py --context default --bundle /var/lib/devres-broker \
  --target-bundle /var/lib/devres-static switch-storage-auth
python3 -B scripts/production-operator.py --context default --bundle /var/lib/devres-static start-postgres
python3 -B scripts/production-operator.py --context default --bundle /var/lib/devres-static start
```

Pending-target provisioning stages Secrets privately and writes nothing to the
cluster. `switch-storage-auth` validates/drains the source, applies the admitted
target and leaves both roles stopped; target startup is explicit. The source
bundle remains stopped and retired. The switch preserves archive binding and
corpus history, performs no generic resource pruning, and retains the old broker
journal/keyring/database/PV for controlled rollback.

Preparation copies the original edge metadata/snapshots and adoption/renewal
qualification into the target. The retired source records an `auth_successor`;
existing capacity/certificate timers follow its bounded reciprocal binding to
the current active bundle. The switch changes no systemd unit, edge route or
edge process. Target `start` returns to `edge_ready` for reacceptance; separate
source/edge acceptance and collector activation checks remain required.

To roll back, stop the static roles, then run `switch-storage-auth` from the current
static bundle with `--target-bundle /var/lib/devres-broker`; validate the original
broker acceptance remains current. Start the original bundle with `start-postgres`
and `start`. Rollback clears the original bundle's successor so existing timers
resolve the restored active bundle. The resumed broker issues fresh Pod
credentials from its retained journal; static keys remain provider-managed and
require deliberate revocation.
Do not revive the retired source independently or reuse a pending bundle after an
unresolved switch. Inspect private state and preserve stopped roles after failure.

## Acceptance boundary

Use disposable objects outside permanent evidence to verify serving GET/HEAD and
prefix listing, serving PUT/DELETE/multipart denial, writer conditional PUT and
multipart completion/read/list/abort, permanent object/version DELETE denial,
other-prefix/bucket denial and administration denial. Confirm the chosen storage
class and exact endpoint/region separately. Do not issue destructive probes against
permanent captures. Retain only secret-free outcomes in private operator evidence.

Local enforcing fixtures and minikube prove adapter/deployment behavior for their
synthetic store. Real Scaleway policy interaction, conditional multipart support,
revocation and effective permissions require separately obtained provider evidence.
The operator must not synthesize a passing real-provider receipt from fixture
results. Native architecture CI, image publication, cluster activation and native
ChatGPT UI acceptance remain separate claims.
