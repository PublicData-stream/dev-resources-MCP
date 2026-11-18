# `0.1.0-build.ce5745e0` production execution, 2026-11-18

The rollout reached schema 19 and passed the production npm assessment. The
read-only observer failed before creation when its retained-row checksum query
hit PostgreSQL's 300-second statement timeout. The supervisor restored schema
18 and left PostgreSQL Ready with backend and writer both at zero replicas.
The deployment result is `target_failed_restored_withdrawn`. Paused and active
MCP acceptance remained unexecuted. [Runbook](upgrade-ce5745e0.md)

## Checkpoint and rehearsal

- Two separate approvals retired only the contents of the eligible isolated
  copies. Historical retirement reclaimed 140,430,467,072 bytes. The retirement
  of three new proof copies reclaimed 39,693,287,424 bytes, bringing free space
  to 263,626,432,512 bytes against the 254,788,482,296-byte rehearsal floor.
  The new proof retirement receipt SHA-256 is
  `c7eebe35d0b64940e6ca89c545ee4e4b43ddf6804d68f5d8e6b3e8637c016a06`.
- The single approved native archive claim returned HTTP 200. An initial stop
  invocation failed before creating its intent because the private target
  directory was missing. Creating the directory let the stop step and original
  process baseline complete. Signed commit `1cefd0d` corrected the runbook.
- The clean checkpoint and isolated reader/writer proof passed. The checkpoint
  restarted the original schema-18 database with the pinned image and owning
  ReplicaSet. Independent review verified all 17 coordinated backup artifacts.
  The completed proof receipt SHA-256 is
  `37b4fb13a125c374167e451d131bd2d42a90843964658f3e86bf2222f949f1e3`.
  The coordinated backup receipt SHA-256 is
  `85db02c439bc132d415b16fb7c07d9348edeae63be7ae5c9b7b067e0a0d3641c`.
- The isolated rehearsal restored a real PostgreSQL copy and both full cache
  baselines. Its receipt SHA-256 is
  `4c62195ea933a30dc5b87028223dd2262a4c5e835c811f5bbb62170a7105e03a`.
  Independent review verified all 20 revalidated backup artifacts and the
  production boundary. The revalidated backup receipt SHA-256 is
  `a58e5909d67c0de5fe5e37f98b6a979c6c4d7a3665f89ff04dd06e9389cef645`.
  The launcher reserved its single intent 0.237 seconds after the rehearsal
  receipt, within the 300-second freshness limit.

## Rollout and failure

The unit invocation `27fda81c4bdb4a85bb385fe829ddd64a` began after the launch
intent at 15:08:18 UTC. Apply, bootstrap writer startup, migration before npm,
and the npm assessment each exited 0. The npm report returned the expected
deferred `legacy_unknown` and recorded known phase telemetry. The cause of the
previous release's SQL connection failure remains unresolved.

Both observer configuration writes completed. During the next application
phase, PostgreSQL logged `canceling statement due to statement timeout` at
15:15:32.231379077 UTC. Two read paths correlated the log records by backend PID
to the repeatable-read, read-only retained-row checksum query. The admitted
observer code sets the query deadline to 300 seconds. The failure occurred
before the observer resource record or observer Deployment existed. This
evidence identifies the timed-out statement, with the cost of individual table
or query operations still unmeasured.

## Restoration and final verification

One physical restoration reinstalled schema 18, both full baseline caches,
the paused Secret preimages, and the original withdrawn Deployment images.
The preserved post-attempt PostgreSQL directory had a verified file manifest,
and both post-attempt cache generations were retained. The S3 archive binding
stayed unchanged. The restored receipt SHA-256 is
`bfd45a0c54f03f20878849fc882b2c942a69589f5f772df3ebb86d26ce02dce7`.

The supervisor exited 1 and its source-bound post-exit fence exited 0 at
15:27:16 UTC. An independent live check verified PostgreSQL-only schema 18,
zero publication owners, the preserved disk identities, and the pinned image
and ReplicaSet. The controller guard passed and both maintenance timers were
active. The final disk read showed 144,484,564,992 available bytes, above the
128 GiB reserve. The single rollout and rollback intents are consumed.

Isolated fixture and rehearsal evidence remains separate from production
acceptance. This rollout stopped before serving the candidate publicly.
