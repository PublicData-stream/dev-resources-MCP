#!/usr/bin/env python3
"""Prove public paused npm status through a SELECT-only observation process.

Runs only inside the unique synthetic minikube profile owned by test-minikube.sh.
The normal writer and reader stop before a sealed metadata baseline is taken;
both are restored after the observation fixture, including failures.
"""
import argparse
import base64
import contextlib
import copy
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('npm_assessment_fixture', ROOT / 'scripts/npm-assessment-fixture.py')
base = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(base)
NAMESPACE = 'devres-acceptance'


class Cluster(base.Cluster):
    phase = 'setup'
    fault_case = 'none'

    def argv(self, *args, namespace=NAMESPACE):
        return super().argv(*args, namespace=namespace)

    def k(self, *args, namespace=NAMESPACE, **kwargs):
        check = kwargs.pop('check', True)
        try:
            result = super().k(*args, namespace=namespace, check=False, **kwargs)
        except subprocess.TimeoutExpired:
            raise CommandError('observer_command_timeout', 'timeout') from None
        if check and result.returncode:
            raise CommandError('fixture_command_failed', 'nonzero', result.returncode)
        return result

    def sql(self, statement, *, database='devres'):
        return super().sql(statement, database=database)


class CommandError(base.FixtureError):
    def __init__(self, code, outcome, exit_code=None):
        super().__init__(code)
        self.outcome = outcome
        self.exit_code = exit_code if type(exit_code) is int and 0 <= exit_code <= 255 else None


def capture_failure(cluster, error):
    """Capture only closed metadata while the failing observer still exists."""
    if getattr(cluster, 'failure_recorded', False):
        return
    cluster.failure_recorded = True
    code = str(error) if isinstance(error, base.FixtureError) else 'unknown'
    if isinstance(error, (KeyboardInterrupt, SystemExit)):
        code = 'interrupted'
    base.receipt(cluster, 'paused-status-failure.json', {
        'version': 1, 'synthetic': True, 'phase': cluster.phase, 'case': cluster.fault_case,
        'code': code if code in base.OBSERVER_ERRORS else 'unknown',
        'command_outcome': getattr(error, 'outcome', 'none'),
        'exit_code': getattr(error, 'exit_code', None),
        'stages': getattr(cluster, 'timing_stages', []),
    })


@contextlib.contextmanager
def restoring(cluster, steps):
    """Attempt every restoration without replacing the original failure."""
    primary = None
    try:
        yield
    except BaseException as error:
        primary = error
        capture_failure(cluster, error)
        raise
    finally:
        failed = False
        for name, action in steps:
            try:
                action()
                restored = True
            except BaseException:
                restored = False
                failed = True
            if not hasattr(cluster, 'restoration_steps'):
                cluster.restoration_steps = []
            cluster.restoration_steps.append({'step': name, 'restored': restored})
        if failed and primary is None:
            cluster.phase = 'restore'
            raise base.FixtureError('observer_restoration_failed')


def paused_config(text, listener=False, s3=False):
    text = base.configuration(text, 'postgres://devres_reader:reader-fixture-only@postgres/devres')
    table = 'writer_listener' if listener else 'writer_client'
    header = re.compile(r'(?m)^\[' + table + r'\]\s*$')
    text, count = header.subn('[' + table + ']\naccess = "status_only"', text)
    base.need(count == 1, 'observer_coordination_config_required')
    if listener:
        # Every observer backend needs private writable spill/index state. A
        # permanently read-only corpus cannot double as its scratch directory.
        if re.search(r'(?m)^scratch_dir\s*=', text):
            text, count = re.subn(r'(?m)^scratch_dir\s*=.*$', 'scratch_dir = "/tmp/observer-scratch"', text)
            base.need(count == 1, 'one_observer_scratch_required')
        else:
            text = text.replace('[storage]\n', '[storage]\nscratch_dir = "/tmp/observer-scratch"\n', 1)
    if listener and s3:
        text, count = re.subn(r'(?m)^blob_dir\s*=.*$', 'blob_dir = "/observer-cache"', text)
        base.need(count == 1, 'observer_cache_config_required')
        # A reader has a disposable writable scratch/cache, independent of the
        # read-only permanent corpus mount.
    return text


def secret(name, key, text):
    return {'apiVersion': 'v1', 'kind': 'Secret', 'type': 'Opaque',
            'metadata': {'name': name, 'namespace': NAMESPACE},
            'data': {key: base64.b64encode(text.encode()).decode()}}


def readonly_template(original, s3):
    output = copy.deepcopy(original)
    spec = output['spec']
    mounts = spec['containers'][0]['volumeMounts']
    for mount in mounts:
        if mount['name'] == 'data':
            mount['readOnly'] = True
    if s3:
        found = False
        for volume in spec['volumes']:
            if volume['name'] == 's3':
                volume['secret']['secretName'] = 'devres-serving-s3'
                found = True
        base.need(found, 'observer_s3_mount_required')
        spec['volumes'].append({'name': 'observer-cache', 'emptyDir': {'sizeLimit': '1Gi'}})
        mounts.append({'name': 'observer-cache', 'mountPath': '/observer-cache'})
    return output


def policy_documents(api_addresses):
    dns = {'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': 'kube-system'}},
           'podSelector': {'matchLabels': {'k8s-app': 'kube-dns'}}}
    common = [
        {'to': [dns], 'ports': [{'port': 53, 'protocol': 'TCP'}, {'port': 53, 'protocol': 'UDP'}]},
        {'to': [{'podSelector': {'matchLabels': {'app': 'postgres'}}}], 'ports': [{'port': 5432, 'protocol': 'TCP'}]},
        {'to': [{'podSelector': {'matchLabels': {'app': 'objectstore'}}}], 'ports': [{'port': 9000, 'protocol': 'TCP'}]},
    ]
    documents = []
    for role in ('backend', 'writer'):
        rules = copy.deepcopy(common)
        if role == 'backend':
            rules.append({'to': [{'podSelector': {'matchLabels': {'app': 'writer'}}}], 'ports': [{'port': 9443, 'protocol': 'TCP'}]})
        else:
            rules.append({'to': [{'ipBlock': {'cidr': str(ipaddress.ip_network(address + ('/128' if ':' in address else '/32')))}} for address in api_addresses],
                          'ports': [{'port': port, 'protocol': 'TCP'} for port in (443, 6443, 8443)]})
        documents.append({'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy',
            'metadata': {'name': 'observer-' + role + '-egress', 'namespace': NAMESPACE},
            'spec': {'podSelector': {'matchLabels': {'app': role}}, 'policyTypes': ['Egress'], 'egress': rules}})
    return documents


def snapshot(cluster):
    # The database contains only the small first-party harness corpus. Hash every
    # retained row, including heads/queues/control rows, without exporting bodies.
    return base.retained_rows_snapshot(cluster)


def owner_absent(cluster):
    raw = cluster.sql("SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND classid=1835365490 AND objid=1 AND granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database())")
    base.need(raw.strip() == b'0', 'observer_publication_owner_present')


PUBLIC_PROBE = r'''
import json,sys
sys.path.insert(0,'/harness')
from mcp_smoke import Client, MODERN, LEGACY
client=Client('https://backend:8080/mcp','/fixture/cert/ca.pem','/fixture/cert/edge-client.pem','/fixture/cert/edge-client-key.pem')
results=[]
for revision in (MODERN,LEGACY):
    if revision==MODERN:
        client.call('server/discover',revision=revision)
    else:
        client.call('initialize',{'protocolVersion':revision,'capabilities':{},'clientInfo':{'name':'paused-observer-fixture','version':'1'}},revision)
    result=client.tool('packages.npm.corpus_status',{},revision)
    assert result['collection_enabled'] is False and result['advisories_enabled'] is False
    attribution=result['attribution']
    assert attribution['complete'] is False
    assert attribution['enabled_providers']==[]
    assert isinstance(attribution['scan_gaps'],dict)
    observation=attribution['observation_scan']
    assert observation['state'] in ('pending','running','complete','gap','cancelled','invalidated')
    assert isinstance(observation['providers'],dict)
    assert attribution['repair_complete_for_enqueued_targets'] is False
    results.append({'revision':revision,'observation_state':observation['state'],'scan_gap_count':len(attribution['scan_gaps'])})
print(json.dumps(results))
'''


DENY_PROBE = r'''
import http.client,json,pathlib,ssl
context=ssl.create_default_context(cafile='/fixture/cert/ca.pem')
token=pathlib.Path('/run/devres-writer-identity/token').read_text().strip()
connection=http.client.HTTPSConnection('writer',9443,context=context,timeout=15)
try:
    connection.request('POST','/v1/acquire',json.dumps({'kind':'acquire','source':{'operation':'rfc_representation','number':1,'format':'txt'}}),{'Authorization':'Bearer '+token,'Content-Type':'application/json'})
    response=connection.getresponse()
    assert response.status==403
    assert len(response.read(4097))<=4096
finally:
    connection.close()
print('authenticated acquisition denied')
'''


FAILURE_PROBE = r'''
import http.client,ipaddress,json,socket,sys,types
sys.path.insert(0,'/harness')
import mcp_smoke
from mcp_smoke import Client,MODERN
# The archive fault deliberately withdraws Service readiness. Pin the admitted
# pod destination while preserving the backend Host, SNI and certificate checks.
address=str(ipaddress.ip_address(sys.argv[1]))
class PinnedHTTPS(http.client.HTTPSConnection):
    def connect(self):
        self.sock=socket.create_connection((address,8080),self.timeout)
        self.sock=self._context.wrap_socket(self.sock,server_hostname=self.host)
# Inject only the fixture client's connection factory. Rebinding the stdlib
# class breaks its own super() initialization on supported Python versions.
mcp_smoke.http=types.SimpleNamespace(client=types.SimpleNamespace(
    HTTPSConnection=PinnedHTTPS,HTTPConnection=http.client.HTTPConnection))
client=Client('https://backend:8080/mcp','/fixture/cert/ca.pem','/fixture/cert/edge-client.pem','/fixture/cert/edge-client-key.pem')
status,response=client.exchange('tools/call',{'name':'packages.npm.corpus_status','arguments':{}},MODERN)
assert status==200 and 'error' not in response
result=response['result']
assert result.get('isError') is True
assert result['structuredContent']['code']=='unavailable'
print(json.dumps({'http':200,'structured_error':'unavailable'}))
'''


READY_PROBE = r'''
import sys
sys.path.insert(0,'/harness')
from mcp_smoke import Client,wait_ready
client=Client('https://backend:8080/mcp','/fixture/cert/ca.pem','/fixture/cert/edge-client.pem','/fixture/cert/edge-client-key.pem')
wait_ready(client,30)
print('observer semantic routing ready')
'''


def semantic_ready(cluster):
    cluster.k('exec', '-i', 'trusted-probe', '--', 'python3', '-I', '-B', '-',
              data=READY_PROBE.encode(), timeout=40)


def timing_evidence(payload, *, allow_empty=False):
    """Normalize only compiled finite status fields; discard all other log text."""
    base.need(isinstance(payload, bytes) and len(payload) <= 65536, 'observer_timing_bound')
    output = []
    text = re.sub(r'\x1b\[[0-9;]*m', '', payload.decode('utf-8', errors='replace'))
    for line in text.splitlines():
        if 'status operation' not in line:
            continue
        stage = re.search(r'\bstatus_stage=(?:"([a-z_]+)"|([a-z_]+))(?=\s|$)', line)
        reason = re.search(r'\breason=(?:"([a-z_]*)"|([a-z_]+))(?=\s|$)', line)
        counts = {field: re.search(r'\b' + field + r'=(\d+)(?=\s|$)', line) for field in ('calls', 'failed', 'cancelled')}
        stage_value = (stage[1] or stage[2]) if stage else None
        reason_value = (reason[1] or reason[2] or 'none') if reason else None
        base.need(stage_value in base.OBSERVER_STAGES and reason_value in base.OBSERVER_REASONS
                  and all(counts.values()), 'observer_timing_schema')
        values = {field: int(match[1]) for field, match in counts.items()}
        base.need(all(0 <= value <= 1000000 for value in values.values()), 'observer_timing_count_bound')
        base.need(len(output) < 8, 'observer_timing_overflow')
        base.need(not any(event['stage'] == stage_value for event in output), 'observer_timing_duplicate')
        output.append({'stage': stage_value, 'reason': reason_value, **values})
    base.need(output or allow_empty, 'observer_timing_missing')
    return output


def backend_identity(cluster, *, healthy=False, timeout=5):
    pods = json.loads(cluster.k('get', 'pods', '-l', 'app=backend', '-o', 'json', timeout=timeout).stdout)['items']
    base.need(len(pods) == 1, 'observer_process_unavailable')
    pod = pods[0]
    statuses = pod.get('status', {}).get('containerStatuses', [])
    base.need(len(statuses) == 1 and (not healthy or statuses[0].get('ready') is True)
              and statuses[0].get('containerID') and 'running' in statuses[0].get('state', {})
              and not pod['metadata'].get('deletionTimestamp'), 'observer_process_unavailable')
    address = str(ipaddress.ip_address(pod['status']['podIP']))
    return (pod['metadata']['name'], pod['metadata']['uid'], statuses[0]['name'],
            statuses[0]['containerID'], statuses[0]['restartCount'], address)


def fresh_backend(cluster):
    cluster.phase = 'fault-startup'
    cluster.timing_stages = []
    scale_role(cluster, 'backend', 0)
    scale_role(cluster, 'backend', 1)
    semantic_ready(cluster)
    cluster.observer_identity = backend_identity(cluster, healthy=True)


def fault_timings(cluster, name, *, clock=time.monotonic, pause=time.sleep):
    identity = cluster.observer_identity
    api = base.helper()
    deadline = clock() + 10
    expected = 'statistics' if name == 'sql-permission' else 'saved_state'
    observed_logs = False
    def remaining():
        return max(0, deadline - clock())
    def same_process():
        budget = remaining()
        if budget <= 0:
            return False
        try:
            current = backend_identity(cluster, timeout=min(5, budget))
        except CommandError as error:
            # The last CLI may exhaust its deliberately shortened budget. End
            # the window using only an earlier fully verified snapshot; an
            # early timeout still means process identity is unavailable.
            if error.outcome == 'timeout' and remaining() == 0:
                return False
            raise
        base.need(current == identity, 'observer_process_changed')
        return remaining() > 0
    while clock() < deadline:
        if not same_process():
            break
        try:
            logs = api.report_exchange(cluster.argv('logs', 'pod/' + identity[0], '-c', identity[2],
                '--tail=-1', '--limit-bytes=65537'), timeout=min(2, remaining()))
        except api.AssessmentError:
            logs = None
        verified = same_process()
        evidence = None
        if logs is not None:
            evidence = timing_evidence(logs, allow_empty=True)
            base.need(all(event['stage'] not in ('attribution', 'writer_token', 'writer_transport') for event in evidence),
                      'observer_forwarded_after_storage_failure')
        if not verified:
            break
        if evidence is not None:
            observed_logs = True
            cluster.timing_stages = evidence
            # Emit writes one record per stage; an early snapshot may be a prefix.
            # Accept benign evidence only when bracketed by matching identities.
            # A final shortened identity budget may expire: this window does not
            # promise a fully verified terminal snapshot. Fetched forbidden or
            # malformed timing still fails closed before that boundary exit.
        pause(min(.25, max(0, deadline - clock())))
    base.need(observed_logs, 'observer_timing_unavailable')
    evidence = getattr(cluster, 'timing_stages', [])
    base.need(evidence, 'observer_timing_missing')
    base.need(any(event['stage'] == expected and event['failed'] == 1 and event['reason'] == 'unavailable'
                  for event in evidence), 'observer_earlier_storage_stage_missing')
    return evidence


def earlier_storage_failure(cluster, name):
    cluster.phase = 'fault-probe'
    result = json.loads(cluster.k('exec', '-i', 'trusted-probe', '--', 'python3', '-I', '-B', '-',
        cluster.observer_identity[5], data=FAILURE_PROBE.encode(), timeout=55).stdout)
    base.need(result == {'http': 200, 'structured_error': 'unavailable'}, 'observer_earlier_storage_stage_missing')
    cluster.phase = 'fault-timing'
    evidence = fault_timings(cluster, name)
    return {'case': name, 'result': result, 'stages': evidence, 'attribution_entered': False}


def ordered_storage_faults(cluster, s3):
    results = []
    cluster.fault_case = 'sql-permission'
    fresh_backend(cluster)
    with restoring(cluster, [('sql-grant', lambda: cluster.sql('GRANT SELECT ON devres_npm_evidence TO devres_reader'))]):
        cluster.phase = 'fault-injection'
        cluster.sql('REVOKE SELECT ON devres_npm_evidence FROM devres_reader')
        results.append(earlier_storage_failure(cluster, 'sql-permission'))
    if s3:
        cluster.fault_case = 's3-unavailable'
        fresh_backend(cluster)
        with restoring(cluster, [
            ('objectstore-start', lambda: cluster.k('scale', 'deployment/objectstore', '--replicas=1')),
            ('objectstore-ready', lambda: cluster.k('rollout', 'status', 'deployment/objectstore', '--timeout=180s', timeout=190)),
        ]):
            cluster.phase = 'fault-injection'
            cluster.k('scale', 'deployment/objectstore', '--replicas=0')
            cluster.k('wait', '--for=delete', 'pod', '-l', 'app=objectstore', '--timeout=120s', timeout=130)
            results.append(earlier_storage_failure(cluster, 's3-unavailable'))
    cluster.fault_case = 'none'
    return results


def scale_role(cluster, role, count):
    cluster.k('scale', 'deployment/' + role, '--replicas=' + str(count))
    if count == 0:
        cluster.k('wait', '--for=delete', 'pod', '-l', 'app=' + role, '--timeout=120s', timeout=130)
    else:
        cluster.k('rollout', 'status', 'deployment/' + role, '--timeout=120s', timeout=130)


def scale(cluster, count):
    for role in ('backend', 'writer') if count == 0 else ('writer', 'backend'):
        scale_role(cluster, role, count)


def run(arguments):
    scratch = Path(arguments.scratch).resolve(strict=True)
    base.need(Path('/tmp') in scratch.parents and scratch.stat().st_uid == os.getuid(), 'owned_tmp_fixture_required')
    cluster = Cluster(arguments.profile, scratch)
    try:
        original_writer = (scratch / 'fixture/writer.toml').read_text()
        original_reader = (scratch / 'fixture/backend.toml').read_text()
        deployment = json.loads(cluster.k('get', 'deployment/writer', '-o', 'json').stdout)
        original_template = deployment['spec']['template']
        reader_deployment = json.loads(cluster.k('get', 'deployment/backend', '-o', 'json').stdout)
        reader_template = reader_deployment['spec']['template']
        service = json.loads(cluster.k('get', 'service/kubernetes', '-o', 'json', namespace='default').stdout)
        endpoints = json.loads(cluster.k('get', 'endpointslices', '-l', 'kubernetes.io/service-name=kubernetes', '-o', 'json', namespace='default').stdout)
        addresses = set(service['spec'].get('clusterIPs', [service['spec']['clusterIP']]))
        addresses.update(address for item in endpoints['items'] for endpoint in item['endpoints'] for address in endpoint['addresses'])
        base.need(addresses and len(addresses) <= 16, 'observer_api_destinations_bound')
        for address in addresses:
            ipaddress.ip_address(address)
    except BaseException as error:
        capture_failure(cluster, error)
        raise
    restore = [
        ('backend-stop', lambda: scale_role(cluster, 'backend', 0)),
        ('writer-stop', lambda: scale_role(cluster, 'writer', 0)),
        ('policy-remove', lambda: cluster.k('delete', 'networkpolicy', 'observer-backend-egress', 'observer-writer-egress', '--ignore-not-found')),
        ('writer-config', lambda: cluster.apply(secret('devres-writer-config', 'writer.toml', original_writer))),
        ('reader-config', lambda: cluster.apply(secret('devres-config', 'backend.toml', original_reader))),
        ('writer-template', lambda: cluster.k('patch', 'deployment/writer', '--type=merge', '-p', json.dumps({'spec': {'template': original_template}}))),
        ('reader-template', lambda: cluster.k('patch', 'deployment/backend', '--type=merge', '-p', json.dumps({'spec': {'template': reader_template}}))),
        ('writer-start', lambda: scale_role(cluster, 'writer', 1)),
        ('backend-start', lambda: scale_role(cluster, 'backend', 1)),
        ('semantic-ready', lambda: semantic_ready(cluster)),
    ]
    try:
        with restoring(cluster, restore):
            cluster.phase = 'stop'
            scale(cluster, 0)
            cluster.phase = 'baseline'
            before = snapshot(cluster)
            owner_absent(cluster)
            cluster.phase = 'configure'
            cluster.apply(policy_documents(sorted(addresses)))
            cluster.apply(secret('devres-writer-config', 'writer.toml', paused_config(original_writer, listener=True, s3=arguments.s3)))
            cluster.apply(secret('devres-config', 'backend.toml', paused_config(original_reader)))
            cluster.k('patch', 'deployment/writer', '--type=merge', '-p', json.dumps({'spec': {'template': readonly_template(original_template, arguments.s3)}}))
            diagnostic_reader = copy.deepcopy(reader_template)
            diagnostic_reader['spec']['containers'][0].setdefault('env', []).append({'name': 'DEVRES_PRIVATE_TIMINGS', 'value': '1'})
            cluster.k('patch', 'deployment/backend', '--type=merge', '-p', json.dumps({'spec': {'template': diagnostic_reader}}))
            cluster.phase = 'startup'
            scale(cluster, 1)
            cluster.phase = 'readiness'
            semantic_ready(cluster)
            owner_absent(cluster)
            base.need(snapshot(cluster) == before, 'observer_startup_mutated_metadata')
            faults = ordered_storage_faults(cluster, arguments.s3)
            cluster.timing_stages = []
            cluster.phase = 'readiness'
            semantic_ready(cluster)
            cluster.phase = 'public-status'
            result = json.loads(cluster.k('exec', '-i', 'trusted-probe', '--', 'python3', '-I', '-B', '-', data=PUBLIC_PROBE.encode(), timeout=110).stdout)
            cluster.phase = 'acquisition-denial'
            cluster.k('exec', '-i', 'deployment/backend', '--', 'python3', '-I', '-B', '-', data=DENY_PROBE.encode(), timeout=25)
            cluster.phase = 'invariants'
            owner_absent(cluster)
            base.need(snapshot(cluster) == before, 'observer_status_mutated_metadata')
    except BaseException as error:
        capture_failure(cluster, error)
        raise
    finally:
        base.receipt(cluster, 'paused-status-restoration.json', {
            'version': 1, 'synthetic': True, 'steps': getattr(cluster, 'restoration_steps', []),
        })
    base.receipt(cluster, 'paused-status-receipt.json', {'version': 1, 'synthetic': True,
        'public_status': result, 'provider_requests': 0, 'startup_and_calls_metadata_unchanged': True,
        'publication_owner_absent': True, 'authenticated_acquisition_denied': True,
        's3_readonly_identity': arguments.s3, 'earlier_storage_faults': faults})
    base.need(not getattr(cluster, 'receipt_failures', []), 'fixture_evidence_retention_incomplete')
    print('Paused public npm status passed through SELECT-only observation listener')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', required=True)
    parser.add_argument('--scratch', required=True)
    parser.add_argument('--s3', action='store_true')
    try:
        run(parser.parse_args())
    except base.FixtureError as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
    except Exception:
        print('paused status fixture failed; raw configuration and responses withheld', file=sys.stderr)
        sys.exit(1)
