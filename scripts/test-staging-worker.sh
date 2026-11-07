#!/usr/bin/env bash
# Real cooperative cancellation/resume on synthetic data; no retained pairs/providers.
set -euo pipefail
mode=rfc
if [[ $# == 1 && $1 == --crate-replay ]]; then
  mode=crate
elif (( $# != 0 )); then
  echo 'usage: scripts/test-staging-worker.sh [--crate-replay]' >&2
  exit 2
fi
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
export PYTHONDONTWRITEBYTECODE=1
export TMPDIR=/tmp
export DOCKER_HOST="${DEVRES_DOCKER_HOST:-${DOCKER_HOST:-unix:///var/run/docker.sock}}"
unset DOCKER_CONTEXT
python3 - "${DEVRES_SERVER_BINARY:-/tmp/rust/target/debug/devres-server}" \
  "${MIGRATION_BENCHMARK_BINARY:-/tmp/rust/target/debug/examples/migration-benchmark}" "$mode" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tempfile
import time

server, benchmark = (str(Path(arg).resolve(strict=True)) for arg in sys.argv[1:3])
mode = sys.argv[3]
root = Path(tempfile.mkdtemp(prefix='devres-worker-fixture-', dir='/tmp'))
root.chmod(0o700)
name = 'devres-worker-' + root.name.rsplit('-', 1)[1]
image = 'postgres@sha256:ae6c78831cbc35fa3a4aaf4d763ddacf6183d6004774cc2dc28b3920410d1d1a'
worker = None

def execute(args, **kwargs):
    result = subprocess.run(args, capture_output=True, timeout=900, **kwargs)
    if result.returncode:
        (root / 'fixture-failure.stderr').write_bytes(result.stderr)
        raise RuntimeError('fixture_command_failed: ' + Path(args[0]).name)
    return result.stdout

def sql(query, database='devres_benchmark'):
    return execute(['docker', 'exec', name, 'psql', '-X', '-At', '-U', 'devres',
                    '-d', database, '-v', 'ON_ERROR_STOP=1', '-c', query]).decode().strip()

def digest(path):
    with open(path, 'rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()

def offline(command):
    args = [server, command, str(config)]
    if command == 'migrate-storage':
        args += ['--to', 'blake3']
    return args + ['--workers', '8', '--payload-budget-mib', '64', '--graph-memory-budget-mib', '1024']

try:
    (root / 'postgres').mkdir()
    execute(['docker', 'run', '-d', '--name', name, '--label', 'devres.test-owner=' + name,
             '--cpus=2', '--memory=2g', '-e', 'POSTGRES_USER=devres',
             '-e', 'POSTGRES_PASSWORD=fixture-only', '-e', 'POSTGRES_DB=devres_benchmark',
             '-p', '127.0.0.1::5432', '-v', str(root / 'postgres') + ':/var/lib/postgresql', image])
    for attempt in range(60):
        if subprocess.run(['docker', 'exec', name, 'pg_isready', '-h', '127.0.0.1', '-U', 'devres'],
                          capture_output=True, timeout=10).returncode == 0:
            break
        time.sleep(1)
    else:
        raise RuntimeError('fixture_postgres_not_ready')
    port = execute(['docker', 'port', name, '5432/tcp']).decode().strip().rsplit(':', 1)[1]
    if not port.isdigit() or not 0 < int(port) <= 65535:
        raise RuntimeError('fixture_postgres_port_invalid')
    env = dict(os.environ, DEVRES_TEST_DATABASE_URL='postgres://devres:fixture-only@127.0.0.1:'
               + port + '/devres_benchmark')
    blobs = root / 'blobs'
    preparation = ([benchmark, 'prepare-crates', str(blobs), '257', '129'] if mode == 'crate'
                   else [benchmark, 'prepare', str(blobs), '128', '256', '16', '8', '16', '16'])
    (root / 'fixture.json').write_bytes(execute(preparation, env=env))
    config = root / 'backend.toml'
    template = Path('deploy/staging/backend.toml.example').read_text()
    config.write_text(template.replace('REPLACE_WITH_PRIVATE_POSTGRES_URL', env['DEVRES_TEST_DATABASE_URL'])
                      .replace('blob_dir = "/data/blobs"', 'blob_dir = ' + json.dumps(str(blobs))))
    config.chmod(0o600)
    worker = subprocess.Popen(offline('migrate-storage'), stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
    selector = selectors.DefaultSelector()
    selector.register(worker.stderr, selectors.EVENT_READ)
    interrupted = False
    progress = []
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline and worker.poll() is None:
        if not selector.select(1):
            continue
        line = worker.stderr.readline()
        if not line:
            break
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if event.get('event') == 'offline_storage_progress':
            progress.append(event)
            target_phase = 'graph_crate_artifacts' if mode == 'crate' else 'graph_rfc_indexes'
            target_count = 128 if mode == 'crate' else 1
            if event.get('phase') == target_phase and event.get('committed', 0) >= target_count:
                worker.send_signal(signal.SIGTERM)
                interrupted = True
                break
    selector.close()
    if not interrupted:
        raise RuntimeError('fixture_did_not_interrupt_graph_replay')
    stdout, stderr = worker.communicate(timeout=120)
    if worker.returncode != 1 or b'code: "cancelled"' not in stderr:
        raise RuntimeError('fixture_cooperative_cancellation_unconfirmed')
    worker = None
    if sql('SELECT active FROM devres_integrity_control WHERE singleton') != 'f':
        raise RuntimeError('fixture_activated_before_resume')
    checkpoints = sql('SELECT json_build_array(path,digest,bytes,ctid::text)::text '
                      'FROM devres_integrity_files ORDER BY path').splitlines()
    if not checkpoints:
        raise RuntimeError('fixture_checkpoint_missing')
    artifact_sql = ("SELECT json_build_array(capture_id,bytes,provenance_integrity,ctid::text)::text "
                    "FROM devres_crate_artifacts WHERE capture_id LIKE 'blake3:%' ORDER BY capture_id")
    artifacts = sql(artifact_sql).splitlines() if mode == 'crate' else []
    if mode == 'crate' and len(artifacts) < 128:
        raise RuntimeError('fixture_committed_artifact_batch_missing')
    for command in ('migrate-storage', 'verify-storage', 'activate-storage'):
        result = execute(offline(command))
        (root / (command + '.json')).write_bytes(result)
    after = set(sql('SELECT json_build_array(path,digest,bytes,ctid::text)::text '
                    'FROM devres_integrity_files ORDER BY path').splitlines())
    if not set(checkpoints).issubset(after):
        raise RuntimeError('fixture_resume_changed_committed_checkpoints')
    if mode == 'crate' and not set(artifacts).issubset(set(sql(artifact_sql).splitlines())):
        raise RuntimeError('fixture_resume_changed_committed_artifacts')
    if sql('SELECT active FROM devres_integrity_control WHERE singleton') != 't':
        raise RuntimeError('fixture_resume_activation_missing')
    # A separate restored database exercises the fixture's retained graph/query readback.
    dump = execute(['docker', 'exec', name, 'pg_dump', '-U', 'devres', '-d', 'devres_benchmark', '-Fc'])
    sql('CREATE DATABASE devres_benchmark_restored', database='postgres')
    execute(['docker', 'exec', '-i', name, 'pg_restore', '-U', 'devres',
             '-d', 'devres_benchmark_restored', '--exit-on-error'], input=dump)
    restored = dict(env, DEVRES_TEST_DATABASE_URL=env['DEVRES_TEST_DATABASE_URL'] + '_restored')
    readback = json.loads(execute([benchmark, 'check', str(blobs)], env=restored))
    receipt = {'fixture_only': True, 'graph_snapshots': 0 if mode == 'crate' else 16,
               'crate_artifacts': 257 if mode == 'crate' else 0,
               'committed_artifact_tuples_preserved': len(artifacts), 'sigterm_cancelled': True,
               'same_pair_resumed': True, 'committed_checkpoints_preserved': len(checkpoints),
               'verified_and_activated': True, 'restored_query_readback': readback,
               'workers': 8, 'payload_budget_mib': 64, 'graph_memory_budget_mib': 1024,
               'server_sha256': digest(server), 'benchmark_sha256': digest(benchmark),
               'zfs_systemd_or_production_acceptance': False}
    (root / 'receipt.json').write_text(json.dumps(receipt, sort_keys=True) + '\n')
    print(json.dumps(receipt, sort_keys=True))
finally:
    if worker is not None and worker.poll() is None:
        worker.send_signal(signal.SIGTERM)
        try:
            worker.communicate(timeout=120)
        except subprocess.TimeoutExpired:
            worker.kill()
            worker.communicate()
    owner = subprocess.run(['docker', 'inspect', '--format',
                            '{{index .Config.Labels "devres.test-owner"}}', name],
                           capture_output=True, text=True, timeout=30)
    if owner.returncode == 0 and owner.stdout.strip() == name:
        subprocess.run(['docker', 'rm', '-fv', name], check=True, capture_output=True, timeout=120)
    print('Retained synthetic worker evidence: ' + str(root), file=sys.stderr)
PY
