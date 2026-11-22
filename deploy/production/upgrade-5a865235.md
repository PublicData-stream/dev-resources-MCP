# Preparation for `0.1.0-build.5a865235`

The observed B130E baseline is schema 19, attribution policy 2, backend
`ce5745e0`, writer `49209762`, and nine enabled sources. The target promotes
attribution to policy 3 through sole-writer startup on the same schema. The
source-bound `ce5745e0` cycle is closed and covers a different preimage.
Use the [policy 3 rollout acceptance](../../docs/operations.md#attribution-policy-3-and-rfc-9525-erratum-8173)
for this baseline.

1. Use release `5a865235fb2f673d0bd5c775327f45ab8783005c`, the verified server and
   probe image indexes, and their Linux AMD64 manifests. The independent release
   jobs and digest artifact are in [the publish run](https://github.com/PublicData-stream/dev-resources-MCP/actions/runs/44928464183).
2. Stage the reviewed preflight, renderer, and observer proof sources in a fresh
   root-only directory under the disk-backed rehearsal mount. Verify each SHA-256
   after staging. Stage the private RFC evidence archive separately. Run
   `python3 -EsB rollout_5a865235_preflight.py --evidence-archive WRITER_INPUTS` on
   B130E. It checks the active source images, one publisher, policy 2 and the
   S3 binding before it runs the Kubernetes server-side dry-run. The receipt
   reports hashes, control state and providers with no ready policy-2 row. The
   existence of a ready row still needs a fixed-capture and notice readback.
   The renderer changes both corresponding-source URLs and
   limits the evidence projection to the writer's restricted init container.
3. Use a verified PostgreSQL 18.6 physical copy in
   `/tmp/devres-rehearsal-5a865235/pgdata`. Its disk-backed mount must be on
   `/dev/md1`, separately from the live PVs. The `preimage` operation of
   `rehearse_retained_rows_5a865235.py` runs `pg_verifybackup`, starts a new
   private working copy with Docker networking disabled, and times the retained
   row proof once after PostgreSQL start and twice again in the same process.
   Run `candidate` only with a cleanly stopped, separately attested schema 19
   and policy 3 clone in `candidate-pgdata`. These timing receipts supplement
   the paired-checkpoint and full supervisor rehearsal receipts.

The current scripts prepare input and rehearse the retained-row proof. Before
adding launch authority, the rollout still needs the complete approved
production-scale restore rehearsal, the sealed RFC archive evidence, and an
exact ready capture and historical notice for each active source.

The approved acquisition boundary keeps each existing source rate and uses
elapsed execution time. Bind the rehearsal's measured requalification and
restoration times to the launch record. From the two-hour maintenance window,
reserve the greater of 30 minutes or measured restoration plus 10 minutes.
Finish private requalification early enough for the public checks and 15-minute
observation before that reserve starts. Start the acquisition clock when the
active writer is admitted. The supervisor must stop that writer and confirm
withdrawal at the cutoff if the acceptance gates remain open. An expired run
enters the successor's single-restore path.

After admitting the reviewed successor, gate only `devres/backend` with the
prepared unmatched selector and verify zero EndpointSlice targets. Bind the
exact prior images, configs, caches and verified retained S3 archive to a cold
PostgreSQL checkpoint after both app roles stop and release publication
ownership. Keep the gate closed through policy promotion, private assessment,
observer proof, and nine-source requalification. Verify the RFC 8173 member and
the historical notices before restoring the original selector. Run the dual
protocol and dual IP family public checks and the bounded stability window.
On a failed admission or acceptance, retain both generations and restore the
sealed policy 2 preimage. Verify the exact source writer and backend privately
before reopening the endpoint.
