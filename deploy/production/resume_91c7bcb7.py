#!/usr/bin/env python3
"""Single reviewed forward continuation of one withdrawn exact-target deployment.

This helper offers no image/configuration/storage changes, old-intent replay,
queue repair, database restore, source acquisition or self-issued admission.
Fresh complete acceptance and a new observation window remain mandatory.
"""
import argparse
import copy
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

sys.dont_write_bytecode = True
REVISION = '91c7bcb7aed8eede1627bf87254c0567ef48ab7b'
IMAGE = 'ghcr.io/publicdata-stream/dev-resources-server@sha256:1b1bf21d339920e8ddd69449d82c9895c3423509e8016a72b2df46a38d8e7b6c'
PG_IMAGE = 'postgres:18.6-alpine3.24@sha256:123b17998ccaf47e53b502e8c6a1e79afd8f579c6f3eec83c563da026f957395'
WORK = Path('/tmp/devres-upgrade-91c7bcb7-20261115')
BUNDLE = Path('/var/lib/devres-production-upgrades/91c7bcb7-20261115')
CONTROLLER = Path('/usr/local/libexec/devres-upgrade-91c7bcb7/upgrade-controller.py')
CONTROLLER_SHA = 'fa1ad0b5a7713787d12a44477b2a8f68ec7a79655c7a847ec4b74a819b8c4100'
JOURNAL = BUNDLE / 'resume-v1'
BASELINE = WORK / 'operational-baseline.json'
ADMISSION = WORK / 'resume-v1-admission.json'
POLICY = {'format_version': 1, 'required_policy_epoch': 2,
          'required_policy_fingerprint': 'devres-attribution-v2:verified-forward-origins:member-scopes:readable-notices'}
PROVIDERS = ('rfc', 'crates', 'rustsec', 'mdn', 'whatwg', 'w3c', 'chromium', 'npm', 'wikipedia')
SOURCE_URL = 'https://github.com/PublicData-stream/dev-resources-MCP/releases/download/0.1.0-build.91c7bcb7/source.tar.gz'
MAX_JSON = 8 * 1024**2
SOURCE_HASHES = {'acceptance-receipt.py': '602ceadfa774eb834bd48574bba6ab078a30c8b016077f61c43622bf97218231',
 'compressed-probe.py': '3059da11470bbc606d1fc079c2fe6abf9c24a8f4adfd83316fe354ea4fb20329',
 'mcp_smoke.py': '0a7db0771b066e5cb74e08c3a7d01d5098da0eea0962c67ccaa8271d63e7e601',
 'observation-loop.py': 'a05a49241388676bb40100cb9c7c783956bd8ebb9361aaa5460e28b81f4e61c1',
 'operational-proof.py': 'f75f6dd5b042a2dd4989f7afb1e43dd0f7a05f417c0a4fad7d5d936d62d2fc28',
 'phase-driver.py': 'd2a3ec95658624405968ba1e6dfd78533c51cd0083b7c94494d9a40fd992300d',
 'physical-checkpoint.py': '9d7c3976b9d4ba2d19fd7fa2b22070ff7d5954d481bf2cc8743b4390499b70dc',
 'public-matrix.py': 'eea401d57728dd1ec76000b162b4c4d0aae09436731c4490690b9645775fd646',
 'store-claim.py': '99d577d87e18c4fa2e4d93a855990545ba397facc43ecb732f95478f9a855551',
 'target-private-acceptance.py': '9e512e9adad66f8df7ca27cac852e751406352f5248a683d1639d72fb8d0b3bb',
 'upgrade-controller.py': 'fa1ad0b5a7713787d12a44477b2a8f68ec7a79655c7a847ec4b74a819b8c4100'}
RESERVE = 128 * 1024**3
FAILURE_NAMES = ('active-observation/completed.json',
                 'operational-proofs/active-late-before/observation.json',
                 'target-private-acceptance-active-late.json',
                 'active-late-public/http-ipv4.json',
                 'late-failure-edge.log', 'late-failure-pipeline.log', 'late-failure-record.json')
WT_NAMES = tuple('active-late-public/wt-' + family + '-' + revision + '.json'
                 for family in ('ipv4', 'ipv6') for revision in ('2025-11-25', '2026-07-28'))


class Error(RuntimeError):
    pass


def need(value, code):
    if not value:
        raise Error(code)


def sha(value):
    return hashlib.sha256(value).hexdigest()


def enc(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def now():
    return dt.datetime.now(dt.timezone.utc)


def instant(value):
    parsed = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    need(parsed.tzinfo is not None and parsed.utcoffset() == dt.timedelta(0), 'utc_timestamp_required')
    return parsed


def raw(path, private=True):
    path = Path(path)
    need(path.is_absolute() and not any(p.is_symlink() for p in (path, *path.parents)), 'symlink_refused')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and before.st_nlink == 1
             and not before.st_mode & (0o077 if private else 0o022)
             and 0 < before.st_size <= MAX_JSON, 'bounded_owned_file_required')
        result = stream.read(MAX_JSON + 1)
        after = os.fstat(stream.fileno())
        need(len(result) == before.st_size and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
             == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), 'file_changed')
        return result


def load(path):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            need(key not in value, 'duplicate_json_key')
            value[key] = item
        return value
    return json.loads(raw(path), object_pairs_hook=unique)


def private_directory(path):
    path = Path(path)
    need(path.is_absolute() and not any(p.is_symlink() for p in (path, *path.parents)), 'symlink_refused')
    info = path.stat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077,
         'private_directory_required')


def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def save(path, value):
    path = Path(path)
    private_directory(path.parent)
    body = value if isinstance(value, bytes) else enc(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(body); stream.flush(); os.fsync(stream.fileno())
    sync(path.parent)


def helper_sha():
    return sha(raw(Path(__file__).resolve(), private=False))


def controller_module():
    need(sha(raw(CONTROLLER)) == CONTROLLER_SHA, 'frozen_controller_changed')
    spec = importlib.util.spec_from_file_location('immutable_resume_controller', CONTROLLER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    need(module.REVISION == REVISION and module.IMAGE == IMAGE and module.PG_IMAGE == PG_IMAGE
         and module.BUNDLE == str(BUNDLE) and module.WORK == str(WORK), 'fixed_deployment_required')
    return module


AUTH_SQL = """SELECT json_build_object(
'roles',(SELECT json_agg(x ORDER BY x.rolname) FROM
 (SELECT a.oid::text,a.rolname,a.rolsuper,a.rolinherit,a.rolcreaterole,a.rolcreatedb,a.rolcanlogin,
 a.rolreplication,a.rolconnlimit,a.rolvaliduntil::text,a.rolbypassrls,r.rolconfig,
 encode(sha256(convert_to(coalesce(a.rolpassword,''),'UTF8')),'hex') AS verifier_sha256
 FROM pg_authid a JOIN pg_roles r ON r.oid=a.oid
 WHERE a.rolname IN('devres_admin','devres_reader','devres_writer')) x),
'memberships',(SELECT coalesce(json_agg(x ORDER BY x.member,x.roleid),'[]'::json) FROM
 (SELECT member::text,roleid::text,admin_option,inherit_option,set_option FROM pg_auth_members
 WHERE member IN(SELECT oid FROM pg_roles WHERE rolname IN('devres_admin','devres_reader','devres_writer'))) x))"""
IDENTITY_SQL = """SELECT json_build_object(
'system_id',(SELECT system_identifier::text FROM pg_control_system()),
'schema',(SELECT version FROM devres_schema WHERE singleton),'recovery',pg_is_in_recovery(),
'archive',(SELECT json_build_object('backend',backend,'binding',binding,'epoch',epoch,
'pending_binding',pending_binding,'initializing_s3',initializing_s3,'store_id',store_id)
FROM devres_archive_control WHERE singleton),
'control',(SELECT data FROM devres_attribution_control WHERE singleton),
'reader_select_gaps',(SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='public' AND c.relkind IN('r','p','v','m') AND NOT has_table_privilege('devres_reader',c.oid,'SELECT')),
'reader_mutation_tables',(SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='public' AND c.relkind IN('r','p','v','m')
AND has_table_privilege('devres_reader',c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')),
'reader_default_readonly',(SELECT coalesce(rolconfig @> ARRAY['default_transaction_read_only=on'],false)
AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls
FROM pg_roles WHERE rolname='devres_reader'),
'owners',(SELECT coalesce(json_agg(json_build_object('pid',a.pid,'backend_start',a.backend_start::text,
'role',a.usename,'client_addr',host(a.client_addr)) ORDER BY a.pid),'[]'::json)
FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE l.locktype='advisory'
AND l.classid=1835365490 AND l.objid=1 AND l.objsubid=2 AND l.granted AND l.mode='ExclusiveLock'
AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database())))"""


def sql(controller, query):
    need(query in (AUTH_SQL, IDENTITY_SQL), 'fixed_readonly_query_required')
    result = controller.old.k('exec', 'deployment/postgres', '-c', 'postgres', '--', 'psql', '-X', '-q',
        '-U', 'devres_admin', '-d', 'devres', '-At', '-v', 'ON_ERROR_STOP=1', '-c',
        "BEGIN READ ONLY; SET LOCAL statement_timeout='20s'; SET LOCAL lock_timeout='250ms'; " + query + '; COMMIT;',
        timeout=45, request_timeout=40)
    need(len(result) <= MAX_JSON, 'sql_result_bound')
    return json.loads(result)


def database(controller, baseline, writer=None, owner=None):
    identity = sql(controller, IDENTITY_SQL)
    need(identity['system_id'] == baseline['database']['system_id']
         and identity['archive'] == baseline['database']['archive']
         and identity['schema'] == 18 and identity['recovery'] is False and identity['control'] == POLICY,
         'original_database_policy_or_archive_changed')
    need(identity['reader_select_gaps'] == 0 and identity['reader_mutation_tables'] == 0
         and identity['reader_default_readonly'] is True, 'reader_authority_changed')
    authority = sql(controller, AUTH_SQL)
    need(sha(enc(authority)) == baseline['authority_sha256'], 'database_credentials_or_roles_changed')
    owners = identity['owners']
    if writer is None:
        need(owners == [], 'writer_owner_remains')
    else:
        need(len(owners) == 1 and owners[0]['role'] == 'devres_writer'
             and owners[0]['client_addr'] == writer['pod_ip'], 'sole_writer_owner_required')
        if owner is not None:
            need(owners == owner, 'writer_owner_changed')
    return identity


def failure_artifacts():
    manifest_path = WORK / 'source-manifest.json'
    manifest = load(manifest_path)
    need(manifest == SOURCE_HASHES, 'original_source_manifest_changed')
    sources = [{'path': str(manifest_path), 'sha256': sha(raw(manifest_path))}]
    for name, expected in sorted(SOURCE_HASHES.items()):
        path = ((CONTROLLER.parent / name) if name in ('upgrade-controller.py', 'physical-checkpoint.py')
                else (WORK / name))
        actual = sha(raw(path))
        need(actual == expected, 'original_operational_source_changed')
        sources.append({'path': str(path), 'sha256': actual})
    paths = [WORK / name for name in (*FAILURE_NAMES, *WT_NAMES)]
    late = WORK / 'active-late-public/http-ipv6.json'
    need(not late.exists() and not late.is_symlink(), 'unexpected_late_http_ipv6_success')
    record = load(WORK / 'late-failure-record.json')
    need(record.get('version') == 1 and record.get('revision') == REVISION
         and record.get('withdrawal_completed') is True and record.get('root_cause') == 'unproved',
         'failure_context_required')
    summary = load(WORK / 'active-observation/completed.json')
    need(summary.get('revision') == REVISION and summary.get('verified') is True
         and summary.get('sample_count', 0) >= 31 and summary.get('duration_seconds', 0) >= 900,
         'original_observation_context_required')
    for name in WT_NAMES:
        value = load(WORK / name)
        need(value.get('exit') == 0 and value.get('client_transport_override') is False,
             'original_webtransport_context_required')
    return sources + [{'path': str(path), 'sha256': sha(raw(path))} for path in paths]


def target_state(controller):
    controller.guard()
    state = controller.state()
    need(state['phase'] == 'withdrawn' and state['configs'] == 'active'
         and state['replicas'] == {'postgres': 1, 'writer': 0, 'backend': 0}
         and all(type(value) is int for value in state['replicas'].values())
         and set(state['pods']) == {'postgres'} and state['images'] ==
         {'postgres': PG_IMAGE, 'writer': IMAGE, 'backend': IMAGE}
         and 'resume_continuation' not in state, 'known_withdrawn_target_required')
    need(not (WORK / 'observation-receipt.json').exists()
         and not (WORK / 'active-observation-bound.json').exists()
         and not (BUNDLE / 'accepted-observation.json').exists(), 'finish_must_be_unconsumed')
    return state


def unused_resume_intents():
    for label in ('resume-v1-start-writer', 'resume-v1-start-reader',
                  'resume-v1-withdraw-writer', 'resume-v1-withdraw-backend'):
        for suffix in ('-intent.json', '-completed.json'):
            path = BUNDLE / (label + suffix)
            need(not path.exists() and not path.is_symlink(), 'resume_intent_already_exists')


def facts(controller, expected_state):
    state = target_state(controller)
    unused_resume_intents()
    state_body = raw(BUNDLE / 'state.json')
    need(re.fullmatch('[0-9a-f]{64}', expected_state or '') and sha(state_body) == expected_state,
         'expected_withdrawn_state_changed')
    baseline = load(BASELINE)
    need(baseline.get('revision') == REVISION and baseline.get('prepared_sha256') == state['prepared_sha256'],
         'original_baseline_binding')
    identity = database(controller, baseline)
    snapshot = controller.snapshot()
    need(snapshot['pods'] == state['pods'], 'withdrawn_process_changed')
    # Every collector/advisory flag and every other config byte is already bound by
    # the frozen controller's active variant; confirm its intended nine-source scope.
    import tomllib
    configs = load(BUNDLE / 'configs-active.json')
    for role in ('backend', 'writer'):
        value = tomllib.loads(configs[role])
        need(all(value[p]['enabled'] is True for p in PROVIDERS)
             and value['npm']['advisories_enabled'] is True and value['source']['url'] == SOURCE_URL,
             'active_source_settings_required')
    need(os.statvfs('/database/devres').f_favail > 0, 'capacity_inodes_required')
    import shutil
    need(shutil.disk_usage('/database/devres').free >= RESERVE, 'capacity_reserve_required')
    artifacts = failure_artifacts()
    controller.guard()
    need(controller.state() == state and raw(BUNDLE / 'state.json') == state_body, 'preflight_state_drift')
    return {'state_sha256': expected_state, 'helper_sha256': helper_sha(), 'controller_sha256': CONTROLLER_SHA,
            'prepared_sha256': sha(raw(BUNDLE / 'prepared.json')), 'plan_sha256': sha(raw(BUNDLE / 'plan.json')),
            'baseline_sha256': sha(raw(BASELINE)), 'failure_artifacts': artifacts,
            'failure_artifacts_sha256': sha(enc(artifacts)), 'namespace_preimage_sha256': sha(enc(snapshot)),
            'postgres_pod': state['pods']['postgres'],
            'database': identity, 'authority_sha256': baseline['authority_sha256']}, state_body


def inspect(controller, expected_state):
    with controller.locked():
        need(not JOURNAL.exists() and not JOURNAL.is_symlink(), 'fresh_resume_journal_required')
        value, state_body = facts(controller, expected_state)
        private_directory(BUNDLE)
        JOURNAL.mkdir(mode=0o700); sync(BUNDLE)
        save(JOURNAL / 'withdrawn-state.json', state_body)
        preflight = {'version': 1, 'kind': 'exact-target-withdrawn-resume-preflight', 'revision': REVISION,
                     'observed_at': now().isoformat(), **value}
        save(JOURNAL / 'preflight.json', preflight)
    return {'preflight_sha256': sha(raw(JOURNAL / 'preflight.json')), 'state_sha256': expected_state,
            'reviewed_admission_required': True, 'runtime_changed': False}


def checked_admission(preflight, supplied, supplied_sha, fresh=True):
    need(Path(supplied) == ADMISSION and sha(raw(ADMISSION)) == supplied_sha, 'external_admission_hash')
    expected = {key: preflight[key] for key in ('state_sha256', 'helper_sha256', 'controller_sha256',
        'prepared_sha256', 'plan_sha256', 'baseline_sha256', 'failure_artifacts_sha256', 'namespace_preimage_sha256')}
    expected.update(version=1, kind='exact-target-withdrawn-resume-admission', revision=REVISION,
                    reviewed=True, operation='resume-v1', preflight_sha256=sha(raw(JOURNAL / 'preflight.json')))
    need(load(ADMISSION) == expected, 'exact_external_admission_required')
    if fresh:
        age = (now() - instant(preflight['observed_at'])).total_seconds()
        need(-5 <= age <= 300, 'resume_preflight_stale')
    return expected


def withdraw(controller, module, baseline):
    """Fresh intents for this continuation only; uncertain starts remain fenced."""
    controller.boundary_guard(check_pods=False, withdrawing=True)
    for role in ('postgres', 'writer', 'backend'):
        obj = controller.get('deployment', role)
        image = obj['spec']['template']['spec']['containers'][0]['image']
        need(image == (PG_IMAGE if role == 'postgres' else IMAGE), 'resume_withdraw_image_changed')
        need(obj['spec'].get('replicas', 1) == 1 if role == 'postgres' else
             obj['spec'].get('replicas', 1) in (0, 1), 'resume_withdraw_replica_boundary')
    state = controller.state(); state['phase'] = 'resume_v1_withdraw_incomplete'; controller.record(state)
    for role in ('backend', 'writer'):
        obj = controller.get('deployment', role)
        if obj['spec'].get('replicas', 1):
            patch = [{'op': 'test', 'path': '/metadata/uid', 'value': obj['metadata']['uid']},
                     {'op': 'test', 'path': '/metadata/resourceVersion', 'value': obj['metadata']['resourceVersion']},
                     {'op': 'replace', 'path': '/spec/replicas', 'value': 0}]
            controller.mutate('resume-v1-withdraw-' + role, lambda r=role, p=patch:
                controller.old.k('patch', 'deployment', r, '--type=json', '-p', json.dumps(p)))
        controller.old.k('wait', '--for=delete', 'pod', '-l', 'app=' + role, '--timeout=180s',
                         timeout=210, request_timeout=190)
        state = controller.state(); state['replicas'][role] = 0; state['pods'].pop(role, None); controller.record(state)
    pods = controller.pods()
    need(set(pods) == {'postgres'} and pods['postgres'] == controller.state()['pods']['postgres'],
         'resume_withdraw_process_remaining')
    database(controller, baseline)
    state = controller.state(); state['phase'] = 'withdrawn'; controller.record(state)
    controller.guard()
    save(JOURNAL / 'withdrawal.json', {'known_complete': True, 'at': now().isoformat(), 'pods': pods})


def run(controller, module, expected_state, admission, admission_sha):
    with controller.locked():
        private_directory(JOURNAL)
        need(not (JOURNAL / 'admitted.json').exists(), 'one_resume_attempt_only')
        preflight = load(JOURNAL / 'preflight.json')
        need(preflight.get('version') == 1 and preflight.get('revision') == REVISION
             and preflight.get('kind') == 'exact-target-withdrawn-resume-preflight', 'preflight_identity')
        checked_admission(preflight, admission, admission_sha)
        current, state_body = facts(controller, expected_state)
        need(all(current[key] == value for key, value in preflight.items()
                 if key not in ('version', 'kind', 'revision', 'observed_at'))
             and raw(JOURNAL / 'withdrawn-state.json') == state_body, 'resume_preflight_changed')
        checked_admission(preflight, admission, admission_sha)
        save(JOURNAL / 'admission.json', raw(ADMISSION))
        save(JOURNAL / 'admitted.json', {'version': 1, 'operation': 'resume-v1', 'at': now().isoformat(),
             'preflight_sha256': sha(raw(JOURNAL / 'preflight.json')), 'admission_sha256': admission_sha,
             'withdrawn_state_sha256': expected_state, 'maximum_attempts': 1})
        baseline = load(BASELINE)
        try:
            state = controller.state()
            state['phase'] = 'resume_v1_incomplete'
            state['resume_continuation'] = {'version': 1, 'journal': str(JOURNAL), 'preflight_sha256':
                sha(raw(JOURNAL / 'preflight.json')), 'admission_sha256': admission_sha,
                'withdrawn_state_sha256': expected_state, 'acceptance_required': True}
            controller.record(state)
            controller.scale('writer', 1, 'resume-v1-start-writer')
            started = database(controller, baseline, writer=controller.state()['pods']['writer'])
            controller.scale('backend', 1, 'resume-v1-start-reader')
            controller.guard()
            database(controller, baseline, writer=controller.state()['pods']['writer'], owner=started['owners'])
            state = controller.state()
            need(set(state['pods']) == {'postgres', 'writer', 'backend'}, 'resumed_role_set')
            state['phase'] = 'collectors_active'; controller.record(state); controller.guard()
            result = {'known_complete': True, 'phase': 'collectors_active', 'observed_at': now().isoformat(),
                      'fresh_full_acceptance_required': True, 'fresh_observation_required': True,
                      'pods': controller.state()['pods'], 'writer_owner': started['owners']}
            save(JOURNAL / 'resumed.json', result)
        except Exception as error:
            fenced = False
            try:
                withdraw(controller, module, baseline); fenced = True
            except Exception:
                pass
            result = {'known_complete': False, 'withdrawal_completed': fenced, 'observed_at': now().isoformat(),
                      'code': str(error) if isinstance(error, Error) else 'resume_operation_failed',
                      'manual_reconciliation_required': not fenced}
            save(JOURNAL / 'failed.json', result)
        return result


def emergency_withdraw(controller, module, expected_state):
    """Fence this admitted continuation after a later fresh-acceptance failure."""
    with controller.locked():
        private_directory(JOURNAL)
        need(not (JOURNAL / 'emergency-withdraw-intent.json').exists()
             and not (JOURNAL / 'withdrawal.json').exists(), 'one_resume_withdrawal_attempt_only')
        preflight = load(JOURNAL / 'preflight.json')
        admitted = load(JOURNAL / 'admitted.json')
        need(admitted.get('version') == 1 and admitted.get('operation') == 'resume-v1'
             and admitted.get('maximum_attempts') == 1, 'admitted_resume_identity')
        need(preflight.get('version') == 1 and preflight.get('revision') == REVISION
             and preflight.get('kind') == 'exact-target-withdrawn-resume-preflight'
             and preflight['controller_sha256'] == CONTROLLER_SHA
             and preflight['helper_sha256'] == helper_sha(), 'admitted_resume_source_changed')
        need(admitted['preflight_sha256'] == sha(raw(JOURNAL / 'preflight.json'))
             and admitted['withdrawn_state_sha256'] == preflight['state_sha256']
             and sha(raw(JOURNAL / 'withdrawn-state.json')) == preflight['state_sha256']
             and raw(JOURNAL / 'admission.json') == raw(ADMISSION), 'admitted_resume_history_changed')
        checked_admission(preflight, ADMISSION, admitted['admission_sha256'], fresh=False)
        need(sha(raw(BUNDLE / 'prepared.json')) == preflight['prepared_sha256']
             and sha(raw(BUNDLE / 'plan.json')) == preflight['plan_sha256']
             and sha(raw(BASELINE)) == preflight['baseline_sha256']
             and failure_artifacts() == preflight['failure_artifacts'], 'original_resume_boundary_changed')
        state_body = raw(BUNDLE / 'state.json')
        need(re.fullmatch('[0-9a-f]{64}', expected_state or '') and sha(state_body) == expected_state,
             'expected_resume_state_changed')
        state = controller.state()
        need(state['configs'] == 'active' and state['images'] ==
             {'postgres': PG_IMAGE, 'writer': IMAGE, 'backend': IMAGE}
             and state['pods']['postgres'] == preflight['postgres_pod'], 'admitted_resume_runtime_changed')
        continuation = state.get('resume_continuation')
        need(continuation == {'version': 1, 'journal': str(JOURNAL), 'preflight_sha256':
                admitted['preflight_sha256'], 'admission_sha256': admitted['admission_sha256'],
                'withdrawn_state_sha256': preflight['state_sha256'], 'acceptance_required': True},
             'admitted_continuation_metadata_required')
        controller.boundary_guard(check_pods=False, withdrawing=True)
        save(JOURNAL / 'emergency-state.json', state_body)
        save(JOURNAL / 'emergency-withdraw-intent.json', {'version': 1, 'maximum_attempts': 1,
             'at': now().isoformat(), 'state_sha256': expected_state,
             'admission_sha256': admitted['admission_sha256']})
        try:
            withdraw(controller, module, load(BASELINE))
            result = {'known_complete': True, 'withdrawal_completed': True, 'phase': 'withdrawn'}
        except Exception as error:
            result = {'known_complete': False, 'withdrawal_completed': False,
                      'manual_reconciliation_required': True,
                      'code': str(error) if isinstance(error, Error) else 'resume_withdrawal_failed'}
        save(JOURNAL / 'emergency-withdraw-result.json', result)
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('inspect', 'run', 'withdraw'))
    parser.add_argument('--expected-state-sha256', required=True)
    parser.add_argument('--admission', type=Path, default=ADMISSION)
    parser.add_argument('--admission-sha256')
    args = parser.parse_args()
    need(os.geteuid() == 0, 'root_required')
    module = controller_module()
    controller = module.Controller(str(BUNDLE), str(BUNDLE / 'plan.json'), 'default')
    if args.operation == 'inspect':
        result = inspect(controller, args.expected_state_sha256)
    elif args.operation == 'withdraw':
        result = emergency_withdraw(controller, module, args.expected_state_sha256)
    else:
        result = run(controller, module, args.expected_state_sha256, args.admission, args.admission_sha256)
    print(json.dumps({k: v for k, v in result.items() if k not in ('pods', 'writer_owner')}, sort_keys=True))
    return 1 if result.get('known_complete') is False else 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'known_complete': False, 'code': str(error) if isinstance(error, Error)
                          else 'resume_setup_failed', 'runtime_not_claimed': True}))
        raise SystemExit(1)
