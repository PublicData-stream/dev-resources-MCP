# Selecting source and historical evidence

Read this reference for history, comparisons or questions combining standards,
documentation and browser support. Discover exact tool fields before calling.

| Family | Selection that changes the conclusion |
| --- | --- |
| RFC | Use metadata/status, series membership and errata alongside published text. `rfc.fulltext_search` searches retained text; generic search is metadata-only. Preserve HTTPS versus lower-assurance rsync provenance. |
| MDN | Historical content receives BCD enrichment only with an explicit `compatibility_snapshot`; content and compatibility commits are independent. Preserve original support statements separately from derived mirror mappings. |
| WHATWG | Default membership uses current captured publications. Alternate editions, review drafts and source revisions have distinct snapshots; do not infer a publication/source pairing. |
| W3C | Default selection is the latest successfully captured published TR, which may differ from the catalog's latest edition. Editor drafts require explicit selection. Use `specification` for the shortname. |
| Chromium | Identify the exact `component` and repository-relative `path`. Components are `src`, `site`, `chrome` and `chrome-archive`; archives require explicit selection. |

For WHATWG, W3C and Chromium, `snapshot` and `view` are exclusive selectors. A
view freezes membership; a document snapshot fixes a representation. For history,
retain the returned frozen `history_snapshot` cutoff as well as continuation.
Match source paths and ordered-parent changes; a failed projection is not proof
that a section or API was removed. Unresolved references remain unresolved.

Technical queries use AND tokens. English mode supports phrases, OR and exclusions;
do not invent regex, field, range or wildcard query syntax. Filters combine with
AND. Keep query/filter selections fixed when continuing a cursor.

Freshness describes validated source evidence, not import or projection time.
MDN, WHATWG, W3C and Chromium defaults become stale after 24 hours and unavailable
after seven days. Explicit historical evidence remains readable, with its original
age and coverage. RFC snapshot completeness is a separate publication property;
use its returned status rather than assuming the same default policy.
