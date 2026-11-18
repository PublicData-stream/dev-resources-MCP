# Approved fresh cycle after the withdrawn 3dae7d91 attempt

Status: approved on 2026-11-18 for the single bounded cycle below. The
[execution record](upgrade-3dae7d91-evidence.md) documents the consumed attempt
and completed schema-18 restoration. This proposal retains the same immutable
server/probe references in the [procedure](upgrade-3dae7d91.md). It permits no
release replacement, fallback application or replay of a consumed stage.

Execution closed on 2026-11-18: the [fifth-cycle record](upgrade-3dae7d91-cycle5-evidence.md)
documents npm assessment failure followed by the single completed schema-18
restoration and PostgreSQL-only withdrawal. This cycle's authority is consumed;
another deployment requires a separately approved fresh plan.

## Scope of the proposed authorization

One fresh source-bound cycle: at most one new native store-claim admission GET,
one new clean physical checkpoint, one isolated old-reader/writer proof, one
actual Restore rehearsal and one supervised target attempt. On target failure,
allow at most one automatic physical schema-18 restore, then withdraw both
application roles. Do not retry a failed stage or automatically start another
cycle. Preserve historical helper-GET accounting; the helper budget does not
represent all S3 traffic.

## Implementation and admission gates

1. Admit the actual restored PostgreSQL process, schema-18 identity, policy 2,
   archive epoch/binding, paused configuration and withdrawn Deployment templates.
   Capture current template image references rather than assuming the old
   predecessor templates survived the failed target apply. Revalidate the exact
   edge admission without broadening its permitted drift. Unexpected drift stops
   the cycle for review.
2. Create fresh work, installation, bundle, output, approval and journal scopes.
   Preserve every historical source closure and consumed intent. Implement and
   independently review any fresh-cycle compatibility and historical dependency
   bindings; never silently drop dependencies, truncate history or bypass source
   count limits. Integrate the baseline admission correction in signed commit
   `fd06857`. Freeze exact source hashes before installation. Review affected
   MCP/API, storage and security boundaries and run the applicable fixture and
   Kubernetes checks before production mutation. No new application image build
   is part of this proposal.
3. Retain the unchanged dynamic copy/growth gates and 128 GiB reserve. Final
   observed free storage after restoration was approximately 200.2 GB; that is
   below the estimated initial admission for a new checkpoint. Qualify any
   reclamation by exact producer, completion, root identity, metadata, hardlink,
   mount and process evidence. Only completed isolated proof/rehearsal data
   copies may be selected. Preserve golden checkpoints, full baseline caches,
   preserved production generations, permanent captures and all journals,
   manifests, logs and receipts. If necessary, qualify the new cycle's completed
   isolated proof copies for reclamation before its Restore rehearsal; verify
   that all required golden/backup artifacts remain. No estimate overrides a
   live capacity gate, and insufficient reclaimable space stops the cycle.
4. After preparation and stop, create and verify the exclusive operational
   baseline while the original prepared PostgreSQL process is still present.
   Require schema 18, stopped phase, old configurations, PostgreSQL only and
   exact source/prepared bindings. Then run the fresh clean checkpoint and
   isolated proof once. Independently verify artifacts and preservation before
   the actual Restore rehearsal. Revalidate the backup and enter the supervisor
   within its existing 300-second freshness gate. Missing prerequisites stop
   before the target attempt; never backfill evidence after restart or startup.
5. Run the pinned target through migration proof, bounded npm assessment, paused
   observer acceptance, controlled activation and active 900-second acceptance.
   Require independent backend/public HTTP and WebTransport checks. Keep local
   qualification, registry/native-CI evidence and actual production acceptance
   distinct. On failure, use the single restoration and stop fence, verify
   schema 18 and PostgreSQL-only withdrawal, retain the outcome and stop.

All disposable test state remains under `/tmp`; durable recovery bundles remain
separate from test artifacts. Cargo output remains `/tmp/rust/target`, with
shared-cache Cargo/pnpm commands using the privileged channel. New commits are
signed on `main` with the required Codex assistance trailer. No GitHub push,
publication, full provider/corpus acceptance or native ChatGPT UI acceptance is
included. The approval authorizes the bounded cycle above, subject to every
admission gate; it does not waive a failed gate or authorize a retry. The earlier
cycle and its execution record remain immutable historical evidence.
