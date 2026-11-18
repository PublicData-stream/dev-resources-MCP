#!/usr/bin/env python3
"""Exercise the production retained-row seal in disposable pinned PostgreSQL."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import struct
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / 'deploy/production/observer_retained_rows.py'
POSTGRES = 'postgres:18.6-alpine3.24@sha256:123b17998ccaf47e53b502e8c6a1e79afd8f579c6f3eec83c563da026f957395'
POSTGRES_AMD64_MANIFEST = 'sha256:300ebd02c6d4de9ee27ad7f6855d5d21b4d3a4a5117767c1197d284c635d9736'
POSTGRES_AMD64_CONFIG = 'sha256:38b9ffe2d4c13d7c445b66306be6763dfa6f503689ea0c5b9f84544ccf3ca8e4'
MEMORY_BYTES = 6 * 1024**3
CPUS = 4
FUNCTIONAL_ROWS = 8200
BENCHMARK_NARROW_ROWS = 262144
BENCHMARK_WIDE_ROWS = 65536
BENCHMARK_MAX_SECONDS = 200
BENCHMARK_MIN_FREE_BYTES = 8 * 1024**3
ADVISORY_KEY = 4842210
TABLES = ('devres_empty', 'devres_narrow', 'devres_wide')
SNAPSHOT_START = b'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;'
INVENTORY_ADMITTED = b'\\if :inventory_valid\n'


class FixtureError(RuntimeError):
    pass


def need(condition, code):
    if not condition:
        raise FixtureError(code)


def command(args, *, code, data=None, timeout=20, check=True):
    """Never emit child output or command arguments on failure."""
    try:
        result = subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        raise FixtureError(code) from None
    need(not check or result.returncode == 0, code)
    return result


def docker_client():
    host = os.environ.get('DOCKER_HOST') if not os.environ.get('DOCKER_CONTEXT') else None
    if not host:
        host = command(['docker', 'context', 'inspect', '--format', '{{.Endpoints.docker.Host}}'],
                       code='observer_fixture_docker_context').stdout.decode().strip()
    need(host.startswith('unix:///'), 'observer_fixture_local_docker_required')
    argv = ['docker', '--host', host]
    store = Path(command([*argv, 'info', '--format', '{{.DockerRootDir}}'],
                         code='observer_fixture_docker_info').stdout.decode().strip()).resolve()
    need(Path('/tmp') in store.parents, 'observer_fixture_docker_state_outside_tmp')
    image = command([*argv, 'image', 'inspect', '--platform', 'linux/amd64', '--format',
                     '{{.Id}} {{.Os}}/{{.Architecture}}', POSTGRES],
                    code='observer_fixture_preloaded_pinned_postgres_required').stdout.decode().strip()
    need(image in (POSTGRES_AMD64_MANIFEST + ' linux/amd64', POSTGRES_AMD64_CONFIG + ' linux/amd64'),
         'observer_fixture_native_postgres_identity')
    need(os.uname().machine == 'x86_64', 'observer_fixture_native_amd64_required')
    return argv, store


class Postgres:
    def __init__(self, docker, identity):
        self.docker = docker
        self.identity = identity
        self.exec_returncode = None

    def ready(self):
        expires = time.monotonic() + 90
        while time.monotonic() < expires:
            result = command([*self.docker, 'exec', self.identity, 'pg_isready', '-h', '127.0.0.1',
                              '-U', 'devres_admin', '-d', 'devres'], code='observer_fixture_readiness',
                             timeout=5, check=False)
            if result.returncode == 0:
                return
            time.sleep(1)
        raise FixtureError('observer_fixture_readiness')

    def psql_argv(self):
        return [*self.docker, 'exec', '-i', self.identity, 'psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1',
                '-U', 'devres_admin', '-d', 'devres', '-f', '-']

    def sql(self, statement, *, code='observer_fixture_sql', timeout=30):
        return command(self.psql_argv(), data=statement.encode(), code=code, timeout=timeout).stdout.decode()

    def k(self, *args, data, timeout, request_timeout):
        need(len(args) >= 9 and args[:6] == ('exec', '-i', 'deployment/postgres', '-c', 'postgres', '--')
             and args[6] == 'psql' and args[-2:] == ('-f', '-') and request_timeout < timeout,
             'observer_fixture_kubectl_shape')
        argv = [*self.docker, 'exec', '-i', self.identity, *args[6:]]
        self.exec_returncode = None
        result = command(argv, data=data, code='observer_fixture_postgres_exec', timeout=timeout, check=False)
        self.exec_returncode = result.returncode
        need(result.returncode == 0, 'observer_fixture_postgres_exec')
        return result.stdout

    @contextlib.contextmanager
    def lock(self, statement):
        """Keep a fixture transaction alive while another connection exercises the seal."""
        with subprocess.Popen(self.psql_argv(), stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL) as process:
            try:
                process.stdin.write(('BEGIN; SET LOCAL idle_in_transaction_session_timeout = \'20s\'; '
                                     + statement + ';\n').encode())
                process.stdin.flush()
                yield
            finally:
                try:
                    process.communicate(input=b'ROLLBACK;\n', timeout=10)
                except (BrokenPipeError, subprocess.TimeoutExpired):
                    process.kill()
                    process.communicate(timeout=10)
                need(process.returncode == 0, 'observer_fixture_lock_cleanup')


@contextlib.contextmanager
def isolated_postgres(docker):
    token = 'devres-observer-' + secrets.token_hex(12)

    def owned():
        result = command([*docker, 'inspect', '--type', 'container', '--format',
                          '{{.Id}} {{index .Config.Labels "devres.test-owner"}} {{.Image}} {{.HostConfig.NetworkMode}}',
                          token], code='observer_fixture_container_inspect', check=False)
        if result.returncode:
            matches = command([*docker, 'container', 'ls', '--all', '--filter', f'label=devres.test-owner={token}',
                               '--format', '{{.ID}}'], code='observer_fixture_container_inventory').stdout
            need(not matches.strip(), 'observer_fixture_container_identity')
            return None
        fields = result.stdout.decode().split()
        need(len(fields) == 4 and re.fullmatch('[0-9a-f]{64}', fields[0]) and fields[1] == token,
             'observer_fixture_container_owner')
        return fields[0], fields[2], fields[3]

    try:
        command([*docker, 'run', '--detach', '--pull', 'never', '--platform', 'linux/amd64', '--name', token,
                 '--label', f'devres.test-owner={token}', '--network', 'none', '--log-driver', 'none',
                 '--cpus', str(CPUS), '--memory', str(MEMORY_BYTES),
                 '-e', 'POSTGRES_USER=devres_admin', '-e', 'POSTGRES_DB=devres',
                 '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', POSTGRES],
                code='observer_fixture_container_start', timeout=30)
        found = owned()
        need(found is not None, 'observer_fixture_container_identity')
        identity, image, network = found
        need(network == 'none' and image in (POSTGRES_AMD64_CONFIG, POSTGRES_AMD64_MANIFEST, POSTGRES.split('@')[1]),
             'observer_fixture_container_identity')
        limits = command([*docker, 'exec', identity, 'cat', '/sys/fs/cgroup/memory.max', '/sys/fs/cgroup/cpu.max'],
                         code='observer_fixture_container_limits').stdout.split()
        need(len(limits) == 3 and all(value.isdigit() for value in limits)
             and int(limits[0]) == MEMORY_BYTES and int(limits[1]) == CPUS * int(limits[2]),
             'observer_fixture_container_limits')
        postgres = Postgres(docker, identity)
        postgres.ready()
        yield postgres
    finally:
        found = owned()
        if found:
            command([*docker, 'rm', '--force', '--volumes', found[0]],
                    code='observer_fixture_container_cleanup', timeout=30)
            need(owned() is None, 'observer_fixture_container_cleanup')


def seed(postgres, wide_rows, narrow_rows):
    postgres.sql(rf'''
CREATE TABLE devres_empty (value text);
CREATE TABLE devres_narrow (item integer, payload text);
CREATE TABLE devres_wide (item integer, payload text);
ALTER TABLE devres_wide ALTER COLUMN payload SET STORAGE EXTERNAL;
INSERT INTO devres_narrow
SELECT item, CASE item WHEN 2 THEN NULL WHEN 3 THEN U&'fixture \03BB' ELSE md5(item::text) END
FROM generate_series(1, {narrow_rows}) AS source(item);
INSERT INTO devres_wide
SELECT item, payload FROM generate_series(0, {wide_rows // 2 - 1}) AS source(item)
CROSS JOIN LATERAL (
    SELECT string_agg(md5(item::text || '/' || part::text), '' ORDER BY part) AS payload
    FROM generate_series(1, 192) AS chunks(part)
) AS bodies CROSS JOIN generate_series(1, 2) AS copies;
ANALYZE;
CHECKPOINT;
''', code='observer_fixture_seed', timeout=180)
    metrics = json.loads(postgres.sql('''
SELECT json_agg(json_build_object('name', relname, 'heap_bytes', pg_relation_size(oid),
                     'toast_bytes', CASE WHEN reltoastrelid = 0 THEN 0 ELSE pg_relation_size(reltoastrelid) END,
                     'total_bytes', pg_total_relation_size(oid)) ORDER BY relname COLLATE "C")
FROM pg_class WHERE relnamespace = 'public'::regnamespace AND relkind = 'r';
'''))
    need([table['name'] for table in metrics] == list(TABLES) and metrics[-1]['toast_bytes'] > 0,
         'observer_fixture_toast_required')
    return metrics


def rejected(helper, operation, expected, code):
    try:
        operation()
    except helper.RetainedRowsError as error:
        need(str(error) == expected, code)
        return
    raise FixtureError(code)


def reference_manifest():
    def md5(value):
        return hashlib.md5(value.encode(), usedforsecurity=False).hexdigest()

    def narrow():
        for item in range(1, 9):
            payload = md5(str(item))
            if item == 2:
                payload = None
            elif item == 3:
                payload = 'fixture λ'
            yield {'item': item, 'payload': payload}

    def wide():
        for item in range(FUNCTIONAL_ROWS // 2):
            payload = ''.join(md5(f'{item}/{part}') for part in range(1, 193))
            yield {'item': item, 'payload': payload}
            yield {'item': item, 'payload': payload}

    def row_binary(row):
        # PostgreSQL record binary protocol: field count followed by type OID,
        # byte length and native binary representation for each field.
        payload = row['payload'].encode() if row['payload'] is not None else None
        fields = struct.pack('!i', 2)
        item = struct.pack('!Iii', 23, 4, row['item'])
        text = struct.pack('!Ii', 25, -1 if payload is None else len(payload))
        return fields + item + text + (payload or b'')

    rows = []
    for name, records in zip(TABLES, ((), narrow(), wide())):
        hashes = sorted(hashlib.sha256(row_binary(row)).digest() for row in records)
        groups = [hashlib.sha256(b''.join(hashes[offset:offset + 4096])).digest()
                  for offset in range(0, len(hashes), 4096)]
        table_digest = hashlib.sha256(len(hashes).to_bytes(8, 'big') + b''.join(groups)).hexdigest()
        rows.append({'name': name, 'rows': len(hashes), 'sha256': table_digest})
    algorithm = 'sha256-row-multiset-v1'
    sha256 = hashlib.sha256(json.dumps([algorithm, rows], sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return {'algorithm': algorithm, 'table_count': len(rows), 'row_count': FUNCTIONAL_ROWS + 8, 'sha256': sha256}


def wait_for(postgres, condition, code):
    expires = time.monotonic() + 10
    while time.monotonic() < expires:
        if postgres.sql(condition, timeout=3).strip() == 't':
            return
        time.sleep(.05)
    raise FixtureError(code)


def injected_manifest(postgres, helper, statement, after=SNAPSHOT_START):
    # Intercept the fixture-only transport to arrange a fault before the
    # production SQL continues on the same database connection.
    def k(*args, data, timeout, request_timeout):
        prefix, marker, suffix = data.partition(after)
        need(marker and after not in suffix, 'observer_fixture_injection_marker_required')
        return postgres.k(*args, data=prefix + marker + b'\n' + statement.encode() + b'\n' + suffix,
                          timeout=timeout, request_timeout=request_timeout)
    return helper.retained_row_manifest(k)


def concurrent_change(postgres, helper, change, after):
    barrier = f'DO $$ BEGIN PERFORM pg_advisory_xact_lock({ADVISORY_KEY}); END $$;'
    waiting = f"SET LOCAL lock_timeout='10s'; {barrier} SET LOCAL lock_timeout='250ms';"
    locks = f"FROM pg_locks WHERE locktype='advisory' AND objid={ADVISORY_KEY} AND objsubid=1"
    with ThreadPoolExecutor(max_workers=1) as worker:
        with postgres.lock(barrier.rstrip(';')):
            wait_for(postgres, f'SELECT EXISTS (SELECT {locks} AND granted);', 'observer_fixture_advisory_lock_missing')
            pending = worker.submit(injected_manifest, postgres, helper, waiting, after)
            wait_for(postgres, f'SELECT EXISTS (SELECT {locks} AND NOT granted);', 'observer_fixture_snapshot_barrier_missing')
            postgres.sql(change, timeout=5)
        return pending.result(timeout=20)


def functional(postgres, helper):
    manifest = lambda: helper.retained_row_manifest(postgres.k)
    rejected(helper, manifest, 'retained_table_inventory_changed', 'observer_fixture_empty_inventory_accepted')
    metrics = seed(postgres, FUNCTIONAL_ROWS, 8)
    before = manifest()
    need(before == reference_manifest() and manifest() == before,
         'observer_fixture_unchanged_manifest')

    postgres.sql('CREATE TABLE devres_nullable_json (item integer, payload jsonb); '
                 'INSERT INTO devres_nullable_json VALUES (1, NULL);')
    sql_null = manifest()
    postgres.sql("UPDATE devres_nullable_json SET payload = 'null'::jsonb;")
    json_null = manifest()
    need(sql_null['row_count'] == json_null['row_count'] and sql_null['sha256'] != json_null['sha256'],
         'observer_fixture_sql_null_matches_jsonb_null')
    postgres.sql('DROP TABLE devres_nullable_json;')

    postgres.sql("UPDATE devres_wide SET payload = payload || 'edited' WHERE item = 4099;")
    updated = manifest()
    need(updated['row_count'] == before['row_count'] and updated['sha256'] != before['sha256'],
         'observer_fixture_same_count_edit_undetected')
    postgres.sql("UPDATE devres_wide SET payload = left(payload, -6) WHERE item = 4099;")
    need(manifest() == before, 'observer_fixture_restored_payload_changed')

    postgres.sql('''
DELETE FROM devres_wide WHERE ctid = (SELECT ctid FROM devres_wide WHERE item = 0 LIMIT 1);
INSERT INTO devres_wide SELECT * FROM devres_wide WHERE item = 1 LIMIT 1;
''')
    multiplicity = manifest()
    need(multiplicity['row_count'] == before['row_count'] and multiplicity['sha256'] != before['sha256'],
         'observer_fixture_duplicate_multiplicity_undetected')
    postgres.sql('''
DELETE FROM devres_wide WHERE ctid = (SELECT ctid FROM devres_wide WHERE item = 1 LIMIT 1);
INSERT INTO devres_wide SELECT * FROM devres_wide WHERE item = 0 LIMIT 1;
CREATE TABLE devres_wide_copy (LIKE devres_wide);
INSERT INTO devres_wide_copy SELECT * FROM devres_wide ORDER BY item DESC;
DROP TABLE devres_wide;
ALTER TABLE devres_wide_copy RENAME TO devres_wide;
''')
    need(manifest() == before, 'observer_fixture_physical_rewrite_changed')

    postgres.sql('CREATE TABLE unexpected_observer_table (value text);')
    rejected(helper, manifest, 'retained_table_inventory_changed', 'observer_fixture_unadmitted_table_accepted')
    postgres.sql('DROP TABLE unexpected_observer_table;')
    postgres.sql('CREATE TABLE devres_partitioned (value integer) PARTITION BY RANGE (value);')
    rejected(helper, manifest, 'retained_table_inventory_changed', 'observer_fixture_partitioned_table_accepted')
    postgres.sql('DROP TABLE devres_partitioned;')

    lock_held = "SELECT EXISTS (SELECT FROM pg_locks WHERE relation='devres_wide'::regclass " \
                "AND mode='AccessExclusiveLock' AND granted);"
    with postgres.lock('LOCK TABLE devres_wide IN ACCESS EXCLUSIVE MODE'):
        wait_for(postgres, lock_held, 'observer_fixture_table_lock_missing')
        rejected(helper, manifest, 'retained_row_manifest_query_failed', 'observer_fixture_lock_timeout_accepted')
        need(postgres.exec_returncode == 3, 'observer_fixture_lock_timeout_exit')

    for setting, exit_code in (('statement_timeout', 3), ('transaction_timeout', 2)):
        def cancel():
            return injected_manifest(postgres, helper,
                                     f"SET LOCAL {setting}='50ms'; DO $$ BEGIN PERFORM pg_sleep(1); END $$;")

        postgres.exec_returncode = None
        rejected(helper, cancel, 'retained_row_manifest_query_failed', f'observer_fixture_{setting}_accepted')
        need(postgres.exec_returncode == exit_code, f'observer_fixture_{setting}_exit')

    updated = concurrent_change(postgres, helper,
                                "UPDATE devres_narrow SET payload='fixture-concurrent' WHERE item=1;", SNAPSHOT_START)
    need(updated == before, 'observer_fixture_snapshot_changed_mid_read')
    need(manifest()['sha256'] != before['sha256'], 'observer_fixture_committed_change_undetected')

    rejected(helper, lambda: concurrent_change(postgres, helper, 'TRUNCATE devres_narrow;', INVENTORY_ADMITTED),
             'retained_table_inventory_changed', 'observer_fixture_prelock_rewrite_accepted')
    need(postgres.exec_returncode == 0, 'observer_fixture_prelock_rewrite_guard_exit')
    need(manifest()['row_count'] == FUNCTIONAL_ROWS, 'observer_fixture_post_rewrite_fresh_snapshot')
    return {'tables': metrics, 'initial_manifest': before,
            'cases': ['python_reference', 'multiple_groups', 'empty_inventory', 'empty_table', 'null_and_unicode',
                      'sql_null_and_jsonb_null', 'toast_same_count_edit',
                      'duplicate_multiplicity', 'physical_rewrite', 'unknown_table', 'partitioned_table',
                      'lock_timeout', 'statement_timeout', 'transaction_timeout',
                      'repeatable_read_concurrent_commit', 'prelock_truncate_rejected']}


def profile_table(postgres, helper, name):
    document = json.loads(postgres.sql('''
BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL lock_timeout='250ms';
SET LOCAL statement_timeout='60s';
SET LOCAL search_path=pg_catalog;
SET LOCAL row_security=off;
SET LOCAL timezone='UTC';
SET LOCAL DateStyle='ISO, YMD';
SET LOCAL IntervalStyle='iso_8601';
SET LOCAL extra_float_digits=3;
SET LOCAL bytea_output='hex';
SET LOCAL work_mem='16MB';
SET LOCAL temp_file_limit='1GB';
SET LOCAL max_parallel_workers_per_gather=0;
EXPLAIN (ANALYZE, BUFFERS, TIMING OFF, FORMAT JSON)
''' + helper.table_query(name).rstrip(';') + ';\nCOMMIT;\n',
        timeout=65, code='observer_fixture_profile_failed'))[0]
    plan = document['Plan']
    return {'name': name, 'planning_ms': document['Planning Time'], 'execution_ms': document['Execution Time'],
            'shared_hit_blocks': plan.get('Shared Hit Blocks', 0), 'shared_read_blocks': plan.get('Shared Read Blocks', 0),
            'temp_read_blocks': plan.get('Temp Read Blocks', 0), 'temp_written_blocks': plan.get('Temp Written Blocks', 0)}


def historical_benchmark(postgres):
    """Run the frozen observer's catalog and monolithic UNION ALL queries."""
    def sql(query):
        return json.loads(postgres.sql("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; "
                                      "SET LOCAL statement_timeout='300s'; SET LOCAL lock_timeout='250ms'; "
                                      + query + '; COMMIT;', code='observer_fixture_historical_sql', timeout=330))

    started = time.monotonic()
    names = sql("SELECT json_agg(c.relname ORDER BY c.relname) FROM pg_class c JOIN pg_namespace n "
                "ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p')")
    need(names == list(TABLES), 'observer_fixture_historical_inventory')
    queries = [
        f"SELECT '{name}' AS name,count(*) AS rows,"
        "encode(sha256(convert_to(coalesce(string_agg(h,'' ORDER BY h),''),'UTF8')),'hex') AS sha256 "
        "FROM (SELECT encode(sha256(convert_to(row_to_json(t)::text,'UTF8')),'hex') AS h "
        f'FROM public."{name}" t) hashes' for name in names
    ]
    rows = sql('SELECT json_agg(v ORDER BY v.name) FROM (' + ' UNION ALL '.join(queries) + ') v')
    elapsed = time.monotonic() - started
    counts = (0, BENCHMARK_NARROW_ROWS, BENCHMARK_WIDE_ROWS)
    need(isinstance(rows, list) and len(rows) == len(TABLES) and all(
        isinstance(row, dict) and set(row) == {'name', 'rows', 'sha256'}
        and row['name'] == name and type(row['rows']) is int and row['rows'] == count
        and isinstance(row['sha256'], str) and re.fullmatch('[0-9a-f]{64}', row['sha256'])
        for row, name, count in zip(rows, TABLES, counts)), 'observer_fixture_historical_manifest')
    return {'cache_state': 'after_revised_warm_repeats', 'elapsed_seconds': round(elapsed, 3),
            'table_count': len(rows), 'row_count': sum(counts)}


def benchmark(postgres, helper, store):
    metrics = seed(postgres, BENCHMARK_WIDE_ROWS, BENCHMARK_NARROW_ROWS)
    command([*postgres.docker, 'restart', '--timeout', '30', postgres.identity],
            code='observer_fixture_postgres_restart', timeout=45)
    postgres.ready()
    runs = []
    expected = None
    for label in ('postgres_restart_host_page_cache_uncontrolled', 'warm_repeat_1', 'warm_repeat_2'):
        started = time.monotonic()
        value = helper.retained_row_manifest(postgres.k)
        duration = time.monotonic() - started
        need(value['table_count'] == len(TABLES) and value['row_count'] == BENCHMARK_NARROW_ROWS + BENCHMARK_WIDE_ROWS
             and (expected is None or value == expected), 'observer_fixture_benchmark_manifest_changed')
        need(duration <= BENCHMARK_MAX_SECONDS, 'observer_fixture_benchmark_deadline')
        expected = value
        runs.append({'cache_state': label, 'elapsed_seconds': round(duration, 3), 'free_bytes': shutil.disk_usage(store).free})
    return {'tables': metrics, 'runs': runs, 'manifest': expected,
            'historical': historical_benchmark(postgres),
            'profiles_after_warm_repeats': [profile_table(postgres, helper, name) for name in TABLES]}


def private_receipt(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receipt', required=True, type=Path, help='new file in an owned private directory under /tmp')
    parser.add_argument('--benchmark', action='store_true', help='run the fixed synthetic scale trial instead of correctness checks')
    args = parser.parse_args()

    def interrupt(signum, _frame):
        signal.signal(signum, signal.SIG_IGN)
        raise SystemExit(128 + signum)

    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, interrupt)
    try:
        parent = args.receipt.parent.resolve(strict=True)
        info = parent.stat()
        need(args.receipt.is_absolute() and parent == args.receipt.parent and Path('/tmp') in parent.parents
             and info.st_uid == os.getuid() and not info.st_mode & 0o077 and not os.path.lexists(args.receipt),
             'observer_fixture_private_receipt_path')
        spec = importlib.util.spec_from_file_location('observer_retained_rows', HELPER)
        helper = importlib.util.module_from_spec(spec)
        source = HELPER.read_bytes()
        exec(compile(source, str(HELPER), 'exec'), vars(helper))
        docker, store = docker_client()
        free = shutil.disk_usage(store).free
        if args.benchmark:
            need(free >= BENCHMARK_MIN_FREE_BYTES, 'observer_fixture_benchmark_disk_floor')
        with isolated_postgres(docker) as postgres:
            result = benchmark(postgres, helper, store) if args.benchmark else functional(postgres, helper)
        private_receipt(args.receipt, {'version': 1, 'synthetic': True, 'postgres_image': POSTGRES,
                                      'postgres_platform_manifest': POSTGRES_AMD64_MANIFEST, 'postgres_cpus': CPUS,
                                      'postgres_memory_bytes': MEMORY_BYTES, 'free_bytes_before': free,
                                      'free_bytes_after_cleanup': shutil.disk_usage(store).free,
                                      'helper_sha256': hashlib.sha256(source).hexdigest(),
                                      'result': result, 'cleanup': 'complete'})
    except (RuntimeError, OSError, ValueError, KeyError, IndexError, TypeError) as error:
        print(str(error) if type(error) is FixtureError else 'observer_fixture_unavailable', file=sys.stderr)
        return 1
    print('Pinned PostgreSQL retained-row fixture passed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
