# Scaleway credential broker operator templates

These templates are inputs for an independently authorized deployment, not evidence
of Scaleway acceptance. Replace every placeholder, use real organization,
application, and project UUIDs, and merge server fragments with the normal
listener/source/provider config.
Run `devres-server serve SERVING.toml`, `devres-server collect WRITER.toml`, and
`devres-credential-broker BROKER.toml` as separate workloads. The old single-config
invocation aliases serving only and requires the serving additions.

The Scaleway integration uses documented expiring IAM API keys rather than
AWS STS `AssumeRole` or `AssumeRoleWithWebIdentity`. Existing `container`
credentials consume the returned key pair and expiry without a session token.
The existing AWS OIDC credential source remains for providers that implement it.

## Identity, policies, and acceptance

Use one dedicated Scaleway application per permission profile: serving readonly,
writer readwrite, and a third application for issuer administration. Both archive
profiles bind the same bucket and archive prefix. Each pod gets a distinct issued
key; a caller cannot select a profile, application, bucket, prefix, or policy.

Set the broker's required `organization_id` to the Organization UUID used for
[Scaleway API-key listing](https://www.scaleway.com/en/developers/api/iam/api-keys#list-api-keys).
It is separate from a profile's `default_project_id` and is never discovered by an
additional API call. All configurations, including fixtures and the offline
fingerprint commands below, require a valid UUID before network access. An
organization change during reload fails closed and requires a controlled restart.
Receipt and journal formats remain unchanged; this setting adds no persistent
organization binding across restarts.

The JSON bucket-policy templates use Scaleway's native application principals and
resource syntax. They grant scoped object access plus prefix-restricted listing.
The writer credential includes CRUD authority, while the application still never
deletes permanent evidence or overwrites immutable objects. Apply compatible IAM
policies as well and remove any broader grants; these Allow statements cannot
remove permissions granted elsewhere. See [Scaleway bucket policies](https://www.scaleway.com/en/docs/object-storage/api-cli/bucket-policy/)
and [S3/IAM equivalence](https://www.scaleway.com/en/docs/object-storage/reference-content/s3-iam-permissions-equivalence/).

Before production activation, an operator must establish all of the following
using isolated disposable objects and the intended Scaleway account/region:

- The issuer can create, inspect, list, and revoke keys only for the two admitted
  applications; an unrelated application and policy-management requests are denied.
  A policy permission-set name or a local allowlist alone does not establish this.
- Expiring keys accept the configured 900-second lifetime and stop authorizing
  object requests after expiry or revocation. Confirm available quota exceeds the
  32 journaled-key budget plus eight reserved keys and other account usage.
- Serving credentials read existing prefix objects but cannot PUT, DELETE, perform
  multipart writes, or access another prefix/bucket. Writer credentials perform
  scoped CRUD and the archive's conditional PUT/multipart-completion operations.
- Multipart listings obey the configured prefix restriction. Newly written objects
  use the explicitly selected storage class and remain fully readable and verified.

Failure of issuer confinement is a deployment blocker: do not grant broad IAM
management as a fallback. These steps are a provider acceptance gate, not a test
already performed by repository fixtures. Never use permanent archive objects for
negative or destructive tests. Retain the bounded, secret-free evidence separately.

After choosing the exact IAM/bucket policy documents, put their admitted digest in
each `policy_fingerprint`. Compute the corresponding profile fingerprints offline:

```sh
devres-credential-broker profile-fingerprints /run/config/broker.toml
devres-credential-broker issuer-fingerprint /run/config/broker.toml
```

The profile command validates configuration and prints application-to-profile
digests; the issuer command prints only the BLAKE3 fingerprint of the mounted
issuer secret. Neither requires a receipt or contacts Kubernetes, PostgreSQL, or
Scaleway. No secret value is printed.
Populate `acceptance-receipt.json.example` with those digests, verified timestamps,
the exact issuer identity and `issuer_secret_fingerprint`, `ttl_secs`, actual available
key budget, and true checks
only after the provider gate succeeds. The receipt must remain unexpired and was
verified no more than 31 days ago. It is operator evidence, not a provider-signed
attestation. Changing application/project, prefix, role, policy digest, or TTL
requires corresponding receipt renewal. Issuer-secret rotation also requires a
new receipt that binds the accepted replacement secret; the binding is checked
again immediately before each provider request. Profile and receipt files reload at
requests and maintenance; changes to organization, identity endpoints, or
secret-file locations require restart.

## Kubernetes prerequisites

Enable [native Kubernetes Secret encryption at rest](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)
before creating issuer, keyring, or database Secrets. Existing Secrets must also be
rewritten and their datastore ciphertext independently checked. K3s deployments
use the corresponding [built-in Secrets encryption](https://docs.k3s.io/security/secrets-encryption)
and verify the live configuration and rewritten records. YAML/base64 encoding and
a manifest field are not encryption evidence. Preserve control-plane encryption
keys through the cluster's normal protected recovery process.

Use explicit projected service-account tokens. Serving and writer each project a
`devres-credential-broker` audience token with `expirationSeconds: 3600` for the
broker; serving projects a separate `devres-writer` audience token for acquisition.
The broker caps key expiry at the caller JWT expiry minus five seconds: a token
with at most 905 seconds remaining cannot obtain a full 900-second lease. Keep
rotation enabled and use the explicit 3600-second production projection rather
than inheriting the 600-second disposable fixture setting.

```yaml
projected:
  defaultMode: 0440
  sources:
    - serviceAccountToken:
        path: token
        audience: devres-credential-broker
        expirationSeconds: 3600
```

Broker and writer use separately projected Kubernetes API tokens for TokenReview and live pod/ServiceAccount GETs.
Keep general token automount disabled. RBAC permits TokenReview creation and only
necessary pod/ServiceAccount identity reads. The broker additionally needs cluster
`get` permission for the core `namespaces` resource with `resourceNames: [kube-system]`;
it needs no namespace-list permission. Serving receives neither Secret-read nor
issuer rights.

Configure TLS trust for the exact internal Service names. NetworkPolicy must keep
both private services off the public edge, restrict callers to their intended
workloads, and restrict broker egress to Kubernetes, its database, and Scaleway IAM.
A valid projected token is checked through TokenReview and current pod/SA UIDs;
deleting or replacing either identity stops issuance. Already issued S3 keys remain
bearer credentials until provider revocation/expiry takes effect; a copied key is
not cryptographically tied to its pod at the S3 endpoint.

## Database and key lifecycle

Use [reader grants](reader-grants.sql) for a separately provisioned serving login;
replace database/writer-owner names as required and do not grant inherited writer
rights. The application additionally makes each reader connection read-only.
Use the [database isolation SQL](broker-database.sql) as an administrator to
provision a dedicated broker PostgreSQL database and login per Kubernetes cluster,
separate from the corpus database. Revoke the default `PUBLIC` connection grant
and explicitly admit only the intended logins; a named-role revoke alone does not
override `PUBLIC`. Verify that corpus serving/writer logins cannot connect to the
broker database and that the broker login cannot connect to the corpus database. The broker owns its journal tables and refuses
a database already containing public corpus captures. It reads the trusted API's
`kube-system` namespace UID and pins that cluster identity in its journal. Restart
must match the stored UID; a different cluster or any nonempty unbound journal
fails closed before issuance or revocation. Only an empty unbound journal can bind
initially; no automatic rebind or migration CLI is provided. It has one dedicated
non-reconnecting owner session; do not deploy a second active broker against that journal.

Mount `keyring_file` as private JSON of the following shape, with an independently
generated 32-byte random key encoded as 64 hexadecimal characters:

```json
{"active_key_id":"2026-11","keys":{"2026-11":"REPLACE_WITH_64_RANDOM_HEX_CHARACTERS"}}
```

Journal secret values use AES-256-GCM with fresh nonces and binding to journal,
cluster, namespace, ServiceAccount, pod and permission profile identity.
Keep keyring and issuer values out of process arguments, logs, source control,
and corpus archives. Back up the broker database as private operational state;
never include it in the corpus `pg_dump`/S3 archive. Protect keyring recovery
separately. Restoring a journal also requires its pinned cluster UID; do not clear identity metadata or old records to force cross-cluster
reuse. Reconcile old provider keys through separately authorized operator recovery
before provisioning a fresh journal for a replacement cluster. To rotate, keep both
old and new keys, change `active_key_id`, wait for
maintenance to reseal all active rows, verify completion, and only then remove an
old key. Do not discard unresolved issuance/revocation records to free quota.

Default sessions last 900 seconds and refresh 300 seconds early. Kubernetes token
validity, provider expiry, current identity, and profile still constrain issuance.
The broker caps pod count and issued/unresolved keys, journals issuance intent
before calling IAM, and reconciles uncertainty before another issuance. An uncertain create
with negative provider listing stays fenced until the requested key expiry plus
60 seconds, unless later reconciliation resolves it. For a 900-second requested
lease, that expiry-based boundary is 960 seconds after the attempt; provider
failures can prolong recovery. Confirm an authoritative archive
read after recovery; broker or routing readiness alone does not establish per-pod
credential recovery.
A failed refresh never falls back to a long-lived key. Pod/profile removal triggers bounded
revocation maintenance; provider errors remain explicit and expiry remains the
outer limit rather than a claim of instantaneous revocation.

For a filesystem backend, retain the default backend but mount the same permanent
archive read-only into serving and writable into the sole writer. Keep serving
`storage.scratch_dir` writable and outside that archive. For S3, use a different
private disposable cache per pod and the same database-bound bucket/prefix. The
`ONEZONE_IA` writer example opts in only for newly created objects; it does not
convert existing objects or fall back to another storage class on failure.

See [operations](../../../docs/operations.md#credential-broker-and-split-runtime-upgrade)
for full-stop upgrade and rollback boundaries. The Kubernetes harness templates
are disposable acceptance inputs; production TLS, namespaces, policies, identities,
secrets encryption, image digests, and source offers require operator provisioning.


The [broker Kubernetes template](../../kubernetes/credential-broker.yaml.example)
contains only operator placeholders and does not create Secret values. Its
`devres-credential-broker` ConfigMap must contain `credential-broker.toml`, mounted
as `/etc/devres/credential-broker.toml`. Its `devres-credential-broker-private`
Secret must contain `tls.crt`, `tls.key`, `database-url`, `keyring.json`,
`issuer-secret-key`, and `acceptance-receipt.json`; those files mount beneath
`/run/devres-broker`, matching `broker.toml.example`. The projected Kubernetes API
volume supplies `/run/devres-kube/token` and `/run/devres-kube/ca.crt`.

The serving/writer fragments require corresponding consumer mounts:

| Consumer | Mounted files | Provisioning |
| --- | --- | --- |
| Serving and writer | `/run/devres-broker-identity/token` | Their own broker-audience projected token, 3600 seconds |
| Serving and writer | `/run/devres-broker-trust/ca.crt` | Public broker CA trust ConfigMap, never the broker private-key Secret |
| Serving | `/run/devres-writer-identity/token` | Separate writer-audience projected token |
| Serving | `/run/devres-writer-trust/ca.crt` | Public writer CA trust ConfigMap |
| Writer | `/run/devres-writer-tls/tls.crt`, `/run/devres-writer-tls/tls.key` | Writer-only TLS Secret with these keys |
| Writer | `/run/devres-kube/token`, `/run/devres-kube/ca.crt` | Kubernetes API projection and cluster CA |

Merge these mounts into the existing serving/writer Deployments; the broker-only
template does not create consumer workload volumes. Replace its
namespace, image digest, destination CIDRs and mounted configurations before use.
For an already provisioned topology, [the runtime control helper](../../../scripts/split-runtime-control.py)
requires explicit context, namespace and storage selection:

```sh
python3 scripts/split-runtime-control.py --context CONTEXT --namespace devres --storage s3 status
# Mutating operations require the corresponding operational authorization:
python3 scripts/split-runtime-control.py --context CONTEXT --namespace devres --storage s3 stop
python3 scripts/split-runtime-control.py --context CONTEXT --namespace devres --storage s3 start
```

The helper preflights all intended deployment names and writer `collect` invocation.
Stopping drains serving and writer; it leaves broker maintenance running. Starting
orders broker, writer, then serving and waits for each rollout. A failure can leave
partial operational progress; inspect status before retrying. This helper does not
provision policies, native Secret encryption, receipts, or schema rollback.
