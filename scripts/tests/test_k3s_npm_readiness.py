import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('k3s_npm_readiness', ROOT / 'scripts/test-k3s-npm-readiness.py')
readiness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(readiness)


def rule(name=readiness.INGRESS, namespace=readiness.NAMESPACE, port=5432, source='ABC',
         protocol='tcp', kind='ingress pods'):
    return (f'-A KUBE-NWPLCY-X -m comment --comment "{namespace}/{name} {kind}" '
            f'-m set --match-set KUBE-SRC-{source} src -m set --match-set KUBE-DST-DB dst '
            f'-p {protocol} -m {protocol} --dport {port} -j MARK --set-xmark 0x10000/0x10000\n'
            ).encode()


def event(phase, outcome, reason='none', elapsed=1):
    return {'phase': phase, 'outcome': outcome, 'reason': reason, 'elapsed_ms': elapsed}


def started():
    return [event('cli_start', 'start'), event('sql_connect', 'start')]


def success():
    return [event('sql_connect', 'ok', elapsed=1300), event('sql_setup', 'start'),
            event('transaction', 'start'), event('report_write', 'ok'), event('cli_exit', 'ok')]


class PolicyProjectionTests(unittest.TestCase):
    def test_select_only_exact_postgres_policy_namespace_and_port(self):
        text = rule(name='seed-postgres-ingress') + rule(namespace='other') + rule(port=80) + rule()
        self.assertEqual(readiness.match_sets(text), ('KUBE-SRC-ABC', 'KUBE-DST-DB'))
        self.assertIsNone(readiness.match_sets(rule(namespace='other') + rule(port=80)
                                                + rule(protocol='udp') + rule(kind='egress pods')))

    def test_duplicate_mark_and_return_pair_do_not_look_ambiguous(self):
        self.assertEqual(readiness.match_sets(rule() * 2), ('KUBE-SRC-ABC', 'KUBE-DST-DB'))
        with self.assertRaisesRegex(readiness.fixture.FixtureError, 'ambiguous_k3s_postgres_rule'):
            readiness.match_sets(rule() + rule(source='OTHER'))

    def test_assessment_egress_limits_database_to_same_namespace_and_named_dns(self):
        spec = readiness.egress(readiness.EGRESS, readiness.APP)['spec']
        self.assertEqual(spec['podSelector'], {'matchLabels': {'app': 'devres-npm-assessment'}})
        self.assertEqual(spec['policyTypes'], ['Ingress', 'Egress'])
        dns, database = spec['egress']
        self.assertEqual(dns['to'][0]['namespaceSelector'], {'matchLabels': {'kubernetes.io/metadata.name': 'kube-system'}})
        self.assertEqual(database, {'to': [{'podSelector': {'matchLabels': {'app': 'postgres'}}}],
                                    'ports': [{'port': 5432, 'protocol': 'TCP'}]})


class AssessmentEvidenceTests(unittest.TestCase):
    def test_peer_probe_requires_no_response_and_an_enforced_profile(self):
        label = f'{readiness.APPARMOR_PROFILE} (enforce)'
        self.assertEqual(readiness.isolation_evidence((label + '\npeer_exit=2\n').encode(), True), label)
        for code in (0, 1, 3, 127):
            with self.assertRaisesRegex(readiness.fixture.FixtureError, 'k3s_unrelated_peer_'):
                readiness.isolation_evidence((label + f'\npeer_exit={code}\n').encode(), True)
        with self.assertRaisesRegex(readiness.fixture.FixtureError, 'k3s_assessment_apparmor_unenforced'):
            readiness.isolation_evidence(b'unconfined\npeer_exit=2\n', True)

    def test_natural_success_and_observed_delay_are_distinct(self):
        self.assertIsNone(readiness.phase_evidence(started() + success(), 'natural')['first_retry'])
        retry = event('sql_connect_retry', 'error', 'connection', 100)
        delayed = readiness.phase_evidence(started() + [retry] + success(), 'delayed')
        self.assertEqual(delayed, {'first_retry': 'connection', 'first_retry_cli_elapsed_ms': 100,
                                  'connect_elapsed_ms': 1300})
        with self.assertRaisesRegex(readiness.fixture.FixtureError, 'k3s_assessment_report_not_single'):
            readiness.phase_evidence(started() + success(), 'delayed')

    def test_reject_duplicate_start_or_connect_outcome(self):
        for repeat in (event('cli_start', 'start'), event('sql_connect', 'ok')):
            with self.assertRaisesRegex(readiness.fixture.FixtureError, 'k3s_assessment_repeated'):
                readiness.phase_evidence(started() + [repeat] + success(), 'natural')

    def test_deadline_keeps_sql_and_report_unstarted(self):
        events = started() + [event('sql_connect_retry', 'error', 'timeout'),
                              event('sql_connect', 'error', 'timeout', 30000), event('cli_exit', 'error')]
        self.assertEqual(readiness.phase_evidence(events, 'denied')['connect_elapsed_ms'], 30000)
        with self.assertRaisesRegex(readiness.fixture.FixtureError, 'k3s_denied_assessment_reached_sql'):
            readiness.phase_evidence(events + [event('sql_setup', 'start')], 'denied')


class PostgresArchiveTests(unittest.TestCase):
    def test_import_requires_canonical_tag_and_exact_native_descriptor(self):
        cluster = mock.Mock()
        canonical = readiness.POSTGRES_LOCAL_TAG
        cluster.node.side_effect = [b'', f'{canonical} manifest {readiness.POSTGRES_AMD64}\n'.encode()]
        cluster.image_status.return_value = {'id': readiness.POSTGRES_CONFIG, 'repoTags': [canonical]}
        result = readiness.import_postgres_archive(cluster, Path('/tmp/postgres.oci.tar'))
        self.assertEqual(result, (canonical, readiness.POSTGRES_CONFIG))
        cluster.node.side_effect = [b'', f'import-2026-11-18:postgres manifest {readiness.POSTGRES_AMD64}\n'.encode()]
        with self.assertRaisesRegex(readiness.fixture.FixtureError, 'k3s_postgres_manifest_identity'):
            readiness.import_postgres_archive(cluster, Path('/tmp/postgres.oci.tar'))

    def test_requires_the_exact_layer_bytes_and_rejects_extra_archive_members(self):
        def entry(data):
            return {'size': len(data), 'digest': 'sha256:' + hashlib.sha256(data).hexdigest()}

        def encode(value):
            return json.dumps(value).encode()

        def blob(descriptor):
            return 'blobs/sha256/' + descriptor['digest'].split(':', 1)[1]

        def save(path, members):
            with tarfile.open(path, 'w') as archive:
                for name, body in members.items():
                    member = tarfile.TarInfo(name)
                    member.size = len(body)
                    archive.addfile(member, io.BytesIO(body))

        layer = b'first-party synthetic layer'
        config = encode({'architecture': 'amd64', 'os': 'linux'})
        manifest = encode({'schemaVersion': 2, 'layers': [entry(layer)], 'config': entry(config)})
        reference = {**entry(manifest), 'mediaType': 'application/vnd.oci.image.manifest.v1+json',
                     'annotations': {'org.opencontainers.image.ref.name': 'postgres'}}
        layer_name = blob(entry(layer))
        members = {'oci-layout': encode({'imageLayoutVersion': '1.0.0'}),
                   'index.json': encode({'schemaVersion': 2, 'manifests': [reference]}),
                   blob(entry(manifest)): manifest, blob(entry(config)): config, layer_name: layer}
        with tempfile.TemporaryDirectory(prefix='devres-k3s-unit-', dir='/tmp') as scratch, \
                mock.patch.object(readiness, 'POSTGRES_AMD64', reference['digest']), \
                mock.patch.object(readiness, 'POSTGRES_CONFIG', entry(config)['digest']):
            path = Path(scratch) / 'image.tar'
            save(path, members)
            readiness.verify_postgres_archive(path)
            copied = Path(scratch) / 'copied.tar'
            readiness.copy_postgres_archive(path, copied)
            readiness.verify_postgres_archive(copied, normalized=True)
            readiness.verify_postgres_archive(path)
            for bad in ({**members, layer_name: b'X' + layer[1:]}, {**members, '../foreign': b'X'}):
                save(path, bad)
                with self.assertRaisesRegex(readiness.fixture.FixtureError, 'official_postgres_oci_archive_required'):
                    readiness.verify_postgres_archive(path)


class DockerStorageTests(unittest.TestCase):
    def test_root_only_path_uses_read_only_lookup_and_requires_temporary_storage(self):
        with mock.patch.object(Path, 'resolve', side_effect=PermissionError), \
                mock.patch.object(readiness, 'command', return_value=b'/tmp/docker/rootful\n') as resolve:
            self.assertEqual(readiness.local_docker_root('/tmp/current-docker-root'), Path('/tmp/docker/rootful'))
            self.assertEqual(resolve.call_args.args[0], ['sudo', '-n', 'realpath', '-e', '--', '/tmp/current-docker-root'])
            resolve.return_value = b'/var/lib/docker\n'
            with self.assertRaisesRegex(readiness.fixture.FixtureError, 'local_rootful_k3s_docker_storage_required'):
                readiness.local_docker_root('/tmp/current-docker-root')

    def test_kubelet_storage_evidence_refuses_host_capacity_or_changed_eviction(self):
        fs = {'node': {'fs': {'capacityBytes': readiness.NODEFS_BYTES},
                       'runtime': {'imageFs': {'capacityBytes': readiness.IMAGEFS_BYTES}}}}
        config = {'kubeletconfig': {'evictionHard': dict(readiness.DEFAULT_HARD_EVICTION),
                                    'evictionMinimumReclaim': dict(readiness.DEFAULT_RECLAIM)}}
        status = {'status': {'conditions': [{'type': 'DiskPressure', 'status': 'False'}]}}

        def kubelet_manifest(*args, code):
            values = {'k3s_storage_stats': fs, 'k3s_eviction_config': config, 'k3s_storage_node': status}
            return subprocess.CompletedProcess(args, 0, stdout=json.dumps(values[code]).encode())

        cluster = mock.Mock()
        cluster.k.side_effect = kubelet_manifest
        self.assertEqual(readiness.storage_evidence(cluster)['imagefs_capacity_bytes'], readiness.IMAGEFS_BYTES)
        config['kubeletconfig']['evictionHard']['nodefs.available'] = '0%'
        with self.assertRaisesRegex(readiness.fixture.FixtureError, 'k3s_fixture_eviction_changed'):
            readiness.storage_evidence(cluster)
        fs['node']['fs']['capacityBytes'] = 540_000_000_000
        with self.assertRaisesRegex(readiness.fixture.FixtureError, 'k3s_fixture_filesystems_not_isolated'):
            readiness.storage_evidence(cluster)


if __name__ == '__main__':
    unittest.main()
