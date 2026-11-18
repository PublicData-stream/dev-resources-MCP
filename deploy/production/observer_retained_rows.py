"""Whole-row equality proof for the paused schema-19 observer."""

import hashlib
import json
import re


_RETAINED_ALGORITHM = 'sha256-row-multiset-v1'
_RETAINED_MAX_TABLES = 256
_RETAINED_NAME = re.compile(r'devres_[a-z0-9_]{1,56}', re.ASCII)
_RETAINED_SHA256 = re.compile(r'[0-9a-f]{64}', re.ASCII)
_RETAINED_COMMIT = 'retained-rows-committed-v1'
_RETAINED_BAD_INVENTORY = 'retained-rows-invalid-inventory'


class RetainedRowsError(RuntimeError):
    """A closed observer proof failure safe to include in operation logs."""


_RETAINED_TABLES = """
SELECT c.oid, c.relname::text AS name, c.relkind, c.relfilenode, a.amname,
       EXISTS (SELECT FROM pg_inherits i WHERE c.oid IN (i.inhrelid, i.inhparent)) AS inherited
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
LEFT JOIN pg_am a ON a.oid = c.relam
WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'f')
"""


def _retained_table_query(relation, name):
    # Binary record framing preserves field types and distinguishes a SQL NULL
    # from a JSON null. Ranking ties can only reorder identical digests.
    return ' '.join(f"""
        WITH ranked AS (
            SELECT h, (row_number() OVER (ORDER BY h) - 1) / 4096 AS group_no
            FROM (
                SELECT sha256(record_send(t)) AS h
                FROM ONLY {relation} t
            ) hashes
        ), groups AS (
            SELECT group_no, count(*) AS rows,
                   sha256(string_agg(h, ''::bytea ORDER BY h)) AS digest
            FROM ranked GROUP BY group_no
        )
        SELECT json_build_object(
            'name', {name}, 'rows', coalesce(sum(rows), 0)::bigint,
            'sha256', encode(sha256(int8send(coalesce(sum(rows), 0)::bigint)
                || coalesce(string_agg(digest, ''::bytea ORDER BY group_no), ''::bytea)), 'hex'))
        FROM groups
        """.split())


def table_query(name):
    """Return the exact per-table statement for an isolated fixture profile."""
    if not isinstance(name, str) or not _RETAINED_NAME.fullmatch(name):
        raise RetainedRowsError('retained_table_inventory_changed')
    return _retained_table_query(f'public."{name}"', f"'{name}'")


def _retained_sql():
    # Generate the per-table commands on the server in the same transaction as
    # the inventory. The psql script submits each command separately via gexec.
    query = _retained_table_query('public.%1$I', '%1$L')
    return rf"""\set VERBOSITY terse
\set SHOW_CONTEXT never
\encoding UTF8
BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL transaction_timeout = '240s';
SET LOCAL lock_timeout = '250ms';
SET LOCAL search_path = pg_catalog;
SET LOCAL row_security = off;
SET LOCAL work_mem = '16MB';
SET LOCAL temp_file_limit = '1GB';
SET LOCAL max_parallel_workers_per_gather = 0;
WITH tables AS ({_RETAINED_TABLES})
SELECT count(*) BETWEEN 1 AND {_RETAINED_MAX_TABLES}
       AND coalesce(bool_and(name COLLATE "C" ~ '^devres_[a-z0-9_]{{1,56}}$'
           AND relkind = 'r' AND amname = 'heap' AND NOT inherited), false) AS inventory_valid
FROM tables
\gset
\if :inventory_valid
WITH tables AS ({_RETAINED_TABLES})
SELECT 'LOCK TABLE ' || string_agg(format('ONLY public.%I', name), ', ' ORDER BY name COLLATE "C")
       || ' IN ACCESS SHARE MODE'
FROM tables
\gexec
WITH tables AS ({_RETAINED_TABLES})
SELECT bool_and(to_regclass(format('public.%I', name))::oid IS NOT DISTINCT FROM oid
           AND pg_relation_filenode(oid) IS NOT DISTINCT FROM relfilenode) AS inventory_locked
FROM tables
\gset
\if :inventory_locked
WITH tables AS ({_RETAINED_TABLES})
SELECT json_agg(name ORDER BY name COLLATE "C") FROM tables;
WITH tables AS ({_RETAINED_TABLES})
SELECT format($retained${query}$retained$, name) FROM tables ORDER BY name COLLATE "C"
\gexec
COMMIT;
\echo {_RETAINED_COMMIT}
\else
ROLLBACK;
\echo {_RETAINED_BAD_INVENTORY}
\endif
\else
ROLLBACK;
\echo {_RETAINED_BAD_INVENTORY}
\endif
""".encode('ascii')


def _retained_json(line):
    def unique(pairs):
        result = dict(pairs)
        if len(result) != len(pairs):
            raise ValueError
        return result

    return json.loads(line, object_pairs_hook=unique)


def _retained_result(output):
    if not isinstance(output, (bytes, str)) or len(output) > 64 * 1024:
        raise RetainedRowsError('retained_row_manifest_invalid')
    if isinstance(output, bytes):
        try:
            output = output.decode('ascii')
        except UnicodeError:
            raise RetainedRowsError('retained_row_manifest_invalid') from None
    if not output.isascii():
        raise RetainedRowsError('retained_row_manifest_invalid')
    lines = output.splitlines()
    if lines == [_RETAINED_BAD_INVENTORY]:
        raise RetainedRowsError('retained_table_inventory_changed')
    if len(lines) < 3 or lines[-1] != _RETAINED_COMMIT:
        raise RetainedRowsError('retained_row_manifest_invalid')
    try:
        names = _retained_json(lines[0])
        if (not isinstance(names, list) or not 1 <= len(names) <= _RETAINED_MAX_TABLES
                or any(not isinstance(name, str) or not _RETAINED_NAME.fullmatch(name) for name in names)
                or sorted(set(names)) != names):
            raise RetainedRowsError('retained_table_inventory_changed')
        rows = [_retained_json(line) for line in lines[1:-1]]
        if len(rows) != len(names) or any(
                type(row) is not dict or set(row) != {'name', 'rows', 'sha256'}
                or row['name'] != name or type(row['rows']) is not int
                or not 0 <= row['rows'] < 2**63 or not isinstance(row['sha256'], str)
                or not _RETAINED_SHA256.fullmatch(row['sha256'])
                for row, name in zip(rows, names)):
            raise ValueError
    except (ValueError, RecursionError):
        raise RetainedRowsError('retained_row_manifest_invalid') from None
    content = json.dumps([_RETAINED_ALGORITHM, rows], sort_keys=True, separators=(',', ':')).encode('ascii')
    return {'algorithm': _RETAINED_ALGORITHM, 'table_count': len(rows),
            'row_count': sum(row['rows'] for row in rows), 'sha256': hashlib.sha256(content).hexdigest()}


def retained_row_manifest(k):
    """Read one complete proof via the controller's admitted PostgreSQL exec."""
    try:
        output = k('exec', '-i', 'deployment/postgres', '-c', 'postgres', '--',
                   'psql', '-X', '-qAt', '-U', 'devres_admin', '-d', 'devres',
                   '-v', 'ON_ERROR_STOP=1', '-f', '-', data=_retained_sql(),
                   request_timeout=260, timeout=270)
    except Exception:
        # Transport failures can carry PostgreSQL stderr and input SQL.
        raise RetainedRowsError('retained_row_manifest_query_failed') from None
    return _retained_result(output)
