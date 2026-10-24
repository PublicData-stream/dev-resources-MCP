# Curated RustSec Git snapshot fixture

Captured on 2026-10-24 from the official RustSec advisory database at immutable
revision [`84d943a6deeb8cc6c6f632531aaf4f1c62275239`](https://github.com/RustSec/advisory-db/tree/84d943a6deeb8cc6c6f632531aaf4f1c62275239).
The original codeload archive SHA-256 was
`1e8630a97b8310f392bc2056b88363a2bf605aed54b134574f6791ad2f6d222c`.

`git-snapshot-minimal.tar.gz` retains the original first Git PAX global header,
root directory header, and the unmodified header/body for
[`crates/odbc/RUSTSEC-2022-0039.md`](https://github.com/RustSec/advisory-db/blob/84d943a6deeb8cc6c6f632531aaf4f1c62275239/crates/odbc/RUSTSEC-2022-0039.md),
then adds tar end blocks and recompresses with a zero gzip timestamp. It contains
one real public advisory, not the complete database. Its SHA-256 is
`0f60df5813a4eebdbfa386056a92b07472555681d279ed3f59c7a536cc590ca7`.

The first 52-byte metadata body is `52 comment=<40-character revision>\n`.
This reproduces GitHub codeload's non-file metadata without admitting path-setting
PAX fields, archive links, or arbitrary special members. Synthetic negative tests
mutate this bounded fixture; they are not authoritative provider captures.

The selected advisory is dedicated under CC0-1.0 by the upstream
[license notice](LICENSE.txt); the [CC0 terms](LICENSES/CC0-1.0.txt) are retained.
The notice also describes separately licensed GHSA imports, which this selected
advisory does not contain. Repository AGPL licensing does not replace those terms.
