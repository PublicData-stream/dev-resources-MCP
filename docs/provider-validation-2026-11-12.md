# Provider validation repair evidence

This records the source-specific findings behind the W3C, Chromium and crates
repairs. Production was inspected without starting collectors or changing corpus
state. The deployed schema was 14; the implementation introduces schema 15.
Local tests, bounded provider probes and production publication are separate gates.

## W3C

A fixed page-12 API request returned a legitimate `xhtml+voice` shortname. The
old parser rejected row 20 because its shortname grammar omitted literal `+`.
The retained response identity is
`blake3:e21211535362d85b95314432c1d6445958acf0a11d068e58340d80f5154f2caf`.
Replaying those exact bytes after the narrow grammar fix accepted 100 standards
and the next-page link, without another request. This is current compatibility
evidence; it does not identify the original production failure's unlinked bytes.

The fix preserves literal identity through discovery, publication URLs, resources
and cursors. Encoded separators, traversal and malformed identities remain
rejected. Private versioned failed-attempt evidence now associates the operation,
reason and numeric location with the exact attempted retained body. Complete
candidate verification and atomic publication remain required; no row is skipped.

## Chromium

Bounded `src` and `site` probes isolated the commit-date branch at HTTP 200.
Both Gitiles responses used five-token dates without a timezone. Gitiles'
[date formatter](https://gerrit.googlesource.com/gitiles/+/refs/heads/master/java/com/google/gitiles/DateFormatter.java)
supports a configured fixed timezone, so the missing zone cannot safely be treated as UTC.
The collector now requests the exact selected raw Git commit through the existing
fixed-origin broker policy, verifies its Git object ID, tree and ordered parents,
and takes the timestamp from its canonical committer epoch. Normal explicit-zone
dates retain their existing path. Raw commit bodies are not persisted.

The subsequent metadata probes passed refs, JSON commit, raw timestamp proof and
root-tree validation:

| Component | Selected commit | Verified epoch | Attempts |
| --- | --- | --- | --- |
| `src` | `9cc77aa493f25a0b72622c0da522c4e59375f933` | 1794506681 | 4 |
| `site` | `8dc34bc900a80ee817d5e967ef22fb8f30175c5b` | 1794421158 | 4 |

Including the earlier diagnostic attempts, the shared probe ledger used 16 of
20 attempts. Two separate official GitHub archive-research reads were also made;
even counting these conservatively leaves total source requests below twenty.
These checks establish bounded metadata compatibility, not complete
traversal, content rights, a published default or production recovery.

Private immutable validation observations identify component, lane, operation,
closed reason and safe body/object identities. Separate synthetic HTTP 500/403
fixtures verify status/phase, retry ownership and preservation of prior defaults.
The recorded `chrome` HTTP 500 and `chrome-archive` HTTP 403 still require their
own upstream resolution. No credential or replacement route was introduced.

## Crates

The retained production dump association was read without downloading a new
provider dump:

- Capture: `blake3:cf95a76a385c472e61a2139020ab9092f29a9cea2136dba4ccb813a13cc6c1a6`.
- Body: `blake3:f7dd6ec1e2d1f1b8d7a84f8cb470ba6733274051f94e8ee01ca074f881da92de`.
- Retained size: 2,201,367,181 bytes.

An explicitly approved no-network sandbox scan of the retained local file reached
`versions`, record 55,361, column 9. The field is selected metadata; its observed
1,108,848 decoded bytes exceed the former 1 MiB field bound. That observation is
a lower bound, not its complete size. Streaming ignored fields alone therefore
cannot admit this particular record. The prefix scan does not reverify the whole
body digest, gzip trailer or subsequent records.

Ignored fields now stream through grammar, UTF-8 and NUL validation without value
retention, under the existing 2 MiB raw/decoded row bounds. New derivations bind
the raw capture to `crates-dump-v2`; legacy v1 rows and snapshots remain immutable.
Schema 15 adds sealed membership and private failure evidence. Exact selected
values are preserved. Downstream bounded reads and explicit index capacity gaps
remain distinct from import completion. Failed or cancelled imports cannot publish
partial enrichment or replace a previous head.

The opt-in standalone measurement mode completes only the first rejected record
within the existing row bounds. It reports exact/lower-bound counts and validity
without emitting values or staging records. Its separate remote execution and
the resulting selected-field policy are independent acceptance gates.
The runtime selected-field ceiling remains 1 MiB, so this repair does not yet
admit that oversized selected record. The target ceiling is up to 2 MiB only if
measurement proves that the complete valid record fits both unchanged 2 MiB row
bounds. That second measurement has not been performed.

## Verification and delivery

Local native x86-64 verification passed formatting, all-target Clippy, the
workspace suite (1,007 passed / 77 ignored across its groups), isolated-cache
`cargo audit` and `cargo deny check`, and the W3C, Chromium and dump-inspector
example tests. The workspace adapter group passed 839 tests with 61 ignored;
database-dependent tests are separate PostgreSQL evidence, not implicit passes.
The later test-only legacy-downgrade and alias fixtures were verified through
their real PostgreSQL gates and all-target Clippy.
The clean complete `scripts/test-postgres.sh` run then passed all 28 groups
(56 tests), including v1/v2 retention, membership integrity, reader authority,
private diagnosis and the corrected legacy upgrade fixtures.

OxiBelt Docker HTTP/WebTransport acceptance and filesystem minikube acceptance
passed. The latter covered NodePort TCP/UDP, CNI isolation, PVC restart,
coordinated restore and collector-produced pinned W3C/Chromium retrieval.
The separate S3 minikube run also passed static-credential separation, S3
read/write isolation, outage/recovery, complete cache loss, database restore and
HTTP/WebTransport acceptance.

This KVM's cached standard Ubuntu/KIC filesystems could not execute required
tools. Local acceptance used the current binaries and pinned OxiBelt on a runnable
Ubuntu 26.04 fixture OS, rebuilt into a task-owned flat image. The KIC filesystem
was recovered from the native amd64 child of the unchanged pinned official index.
Repository base-image pins were not changed. These local fixture variants do not
establish standard release-image or hosted native amd64/arm64 CI qualification.

The schema change requires stopping older serving readers and coordinating the
database/blob backup before a separately authorized rollout. An older binary
cannot roll back an activated schema 15 database. No production migration,
collection retry, queue reset, release, push or deployment is part of this repair.
Independent agent review is not a human GitHub approval.

See [private diagnosis](provider-diagnostics.md) for bounded operator commands and
[configuration](Configuration.md) for the exact admission and processing limits.
