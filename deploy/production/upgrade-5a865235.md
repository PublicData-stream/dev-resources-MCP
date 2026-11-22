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
   It uses `parallel-4cpu-6g-v1` with four CPUs, 6 GiB of cgroup memory and
   64 MiB of shared memory. Allow an additional 4 GiB of free space on the
   database volume for the leader and three workers. The successor controller
   can select this profile after checking the actual PostgreSQL resources and
   free space.
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

## Rehearsal observed on 2026-11-22

The online PostgreSQL 18.6 physical backup passed `pg_verifybackup`. The
production-sized policy-2 working copy then failed the complete retained-row
proof. A read-only observation at 239 seconds showed the proof transaction
still waiting on `DataFileRead`. The proof process exited 1. A separate isolated
measurement of `devres_mdn_evidence` hashed 5,407,766 rows in 92.885 seconds.

The Kubernetes server-side dry-run passed. The writer package matched the
pinned manifest and six dependency digests. Fresh archive inspection remained
pending after the remote approval gate rejected candidate container execution.
The live indexed check found no ready policy-2 target for crates, Chromium, or
npm. The public endpoint remained on the original backend throughout this
rehearsal.

### Follow-up retained-row proof and source baselines

The schema-19, policy-2 working copy completed the serial diagnostic in
258.07 seconds. On the same copy, `parallel-4cpu-6g-v1` completed in 68.09,
73.70, and 68.06 seconds. All four runs returned the same `sha256-row-multiset-v1`
manifest for 65 tables and 30,471,782 rows. PostgreSQL restarted before the first
parallel measurement, with the host page cache uncontrolled. The cgroup reached
its 6 GiB memory limit including page cache, with no OOM events. PostgreSQL
logged 4,364,181,504 temporary bytes across the three runs. An earlier parallel
trial with a 256 MiB per-process temporary-file limit failed on a retained table.

Two fixed production requests completed policy-2 qualification through ordinary
writer admission. Public MCP returned the same pinned sources and the complete
historic notice resources. Freeze the following arguments for the later comparison.

| Source | Fixed request | Source page SHA-256 | Notice generation | Notice SHA-256 |
| --- | --- | --- | --- | --- |
| Cargo | `packages.crate.source_read` for `itoa` `1.0.15`, `src/lib.rs`, limit `1024`, metadata capture `blake3:c5c33a98b5713a6d1c965af1649a63b8a1f272d9d64422de6765b6b8835af8eb`, archive capture `blake3:925e9e9aed72834351c5d02134a76a7e224b2e80e7ff3428e381bd79be978e68` | `e3c9ee51c4cd00ae8634d13ef0bb590ef9822c61a3374cc49422ee15b0f1bc26` | `blake3:55434c0487078e998eb80b2b2b1769958c8f3f07f7478c9ef57d61f453a942f1` | `e654e4672a23ff8044441cf0a32953dd86df71fcb5dfb5250dbb5d3c3831b744` |
| npm | `packages.npm.advisory_get` for `GHSA-2234-fmw7-43wr`, snapshot `blake3:44632814ca57a87f55cebbf690374546851d3eae9901f4a90b9ed5aef80f3e6f`, representation `source`, limit `1024` | `863f8b3eb953011d2a53577e22d33c37e7e0db54cc4df9749ec6514c237dcdcf` | `blake3:5ea9c43fb109cbda16e4c3140717f4c02b3202dc589b525d2cd3652573f78d0a` | `d7bbd58f853887180f3172f666481485ed17e045c5e55dbe74535640d898ee28` |

Chromium's two retained `site` inventories each had 1,562 members, zero members
with raw source descriptors, and zero searchable projections. The default view
was absent. The private diagnostic returned `attempted_payload_unlinked`, and
the current collector recorded an HTTP 500 during publication acquisition.
A Chromium baseline still requires a published exact snapshot with a qualified
source member and notice readback.
The policy-3 clone, full restore rehearsal, and sealed RFC archive evidence
remain separate admission gates.
