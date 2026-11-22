#!/usr/bin/env python3
"""Read and server-side dry-run the release changes on B130E."""

import argparse
import hashlib
import io
import json
import os
import socket
import stat
import subprocess
import sys
import tarfile

from rollout_5a865235_render import (
    BASELINE_IMAGES, CANDIDATE_IMAGE, EVIDENCE_FILES, GATED_SELECTOR, RESOURCE_FIELDS,
    RenderError, _definition, guarded_patch, render,
)


KUBECTL = ('k3s', 'kubectl', '--context=default', '--namespace=devres', '--request-timeout=20s')
EXPECTED_POLICY = 'devres-attribution-v2:verified-forward-origins:member-scopes:readable-notices'
# SHA-256 transports the already verified seven-file BLAKE3-pinned writer bundle.
EVIDENCE_SHA256 = dict(zip(EVIDENCE_FILES, (
    'c3f54cadf1cc2f30e9d205bbc35bb30ed10d16e35f1e5309f0a1ae330d5e80a9',
    'c145ff6ad1c3d6f95487bbe287e6375b6caf8e0f0c665a22c2e8aaf166a6ae41',
    '69185b2732eb80a9ebd366b6a5669af2faf5425284a7ac4539c90c2c546af948',
    '0cde83c364a85742ad16281ad8d4169987f04ad10b55f2c8a88979a26f12e59c',
    '364eb5dc4c0b9982cd39a0bc47026d8528a33f8888c04353339b11c243a4ed8c',
    '6029c56cc9f82eda8e2d66151d87c87248f7730ca245c0cfbbc9feaf358232dc',
    '0d9d7a938c8ded1108df065942813e86f69698aff31e4f1bf3d04ab1afecd2dc',
), strict=True))
EVIDENCE_LIMIT = 1024 * 1024
EVIDENCE_TRANSPORT = 'be06e4d1d7ab908f91d11e0f4b5c27ffb26cbadbc5383f55608c775bbfc403a6'


def fail_unless(condition, error):
    if not condition:
        raise RuntimeError(error)


def read_evidence(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        attributes = os.fstat(source.fileno())
        fail_unless(stat.S_ISREG(attributes.st_mode) and attributes.st_nlink == 1
                    and attributes.st_uid == os.geteuid() and not attributes.st_mode & 0o077
                    and 0 < attributes.st_size <= EVIDENCE_LIMIT, 'private_evidence_archive_required')
        body = source.read(EVIDENCE_LIMIT + 1)
        fail_unless(len(body) == attributes.st_size
                    and hashlib.sha256(body).hexdigest() == EVIDENCE_TRANSPORT,
                    'evidence_archive_changed')
    files = {}
    with tarfile.open(fileobj=io.BytesIO(body), mode='r:gz') as archive:
        for entry in archive:
            fail_unless(entry.name in EVIDENCE_SHA256 and entry.name not in files and entry.isfile()
                        and 0 < entry.size <= EVIDENCE_LIMIT, 'unexpected_evidence_member')
            with archive.extractfile(entry) as handle:
                content = handle.read(EVIDENCE_LIMIT + 1)
            fail_unless(len(content) == entry.size
                        and hashlib.sha256(content).hexdigest() == EVIDENCE_SHA256[entry.name],
                        'evidence_member_mismatch')
            files[entry.name] = content
    fail_unless(files.keys() == EVIDENCE_SHA256.keys(), 'incomplete_evidence_archive')
    return files


def kubectl(*arguments, document=None):
    data = json.dumps(document).encode() if document is not None else None
    result = subprocess.run([*KUBECTL, *arguments], input=data, capture_output=True, timeout=25)
    fail_unless(result.returncode == 0 and len(result.stdout) <= 4 * EVIDENCE_LIMIT,
                'kubernetes_preflight_command_failed')
    return json.loads(result.stdout)


def production_identity():
    # Read only fixed system/control state. Do not serialize archive identities,
    # store credentials, capture data, or user inputs into the receipt.
    return kubectl('exec', 'deployment/postgres', '-c', 'postgres', '--', 'psql', '-X', '-qAt',
                   '-U', 'devres_admin', '-d', 'devres', '-v', 'ON_ERROR_STOP=1', '-c', f"""
        BEGIN READ ONLY;
        SET LOCAL statement_timeout = '3s';
        SELECT json_build_object(
            'schema', (SELECT version FROM devres_schema WHERE singleton),
            'required_policy', (SELECT data->>'required_policy_epoch' FROM devres_attribution_control WHERE singleton),
            'fingerprint_ok', (SELECT data->>'required_policy_fingerprint' = '{EXPECTED_POLICY}'
                FROM devres_attribution_control WHERE singleton),
            'archive_ready', (SELECT backend = 's3' AND binding IS NOT NULL AND pending_binding IS NULL
                AND NOT initializing_s3 FROM devres_archive_control WHERE singleton),
            'publication_owners', (SELECT count(*) FROM pg_locks WHERE locktype = 'advisory'
                AND classid = 1835365490 AND objid = 1 AND objsubid = 2 AND granted
                AND database = (SELECT oid FROM pg_database WHERE datname = current_database())));
        ROLLBACK;
        """)


def read_baseline():
    snapshot = {key: kubectl('get', field[1].lower(), field[2], '-o', 'json')
                for key, field in RESOURCE_FIELDS.items()}
    for name, image in BASELINE_IMAGES.items():
        deployment = snapshot[name]
        spec = deployment['spec']
        status = deployment['status']
        fail_unless(spec['replicas'] == status.get('readyReplicas') == 1
                    and status.get('observedGeneration') == deployment['metadata']['generation']
                    and spec['template']['spec']['containers'][0]['image'] == image,
                    'application_baseline_not_ready_or_changed')
    selector = ','.join(f'{key}={value}' for key, value in GATED_SELECTOR.items())
    matched = kubectl('get', 'pods', '-l', selector, '-o', 'json')['items']
    fail_unless(not matched, 'maintenance_selector_matches_live_pods')
    identity = production_identity()
    fail_unless(identity == {'schema': 19, 'required_policy': '2', 'fingerprint_ok': True,
                             'archive_ready': True, 'publication_owners': 1},
                'production_storage_baseline_changed')
    return snapshot, identity


def dry_run(snapshot, evidence):
    changes = render(snapshot, evidence)
    for key, change in changes['changes'].items():
        _, kind, name, _ = RESOURCE_FIELDS[key]
        patch = guarded_patch(snapshot[key], change, dry_run=True)
        dry = kubectl('patch', kind.lower(), name, '--type=json', '--patch-file=/dev/stdin',
                      '--dry-run=server', '-o', 'json', document=patch)
        admitted = _definition(dry, key)
        expected = change['after']
        admitted['metadata']['resourceVersion'] = expected['metadata']['resourceVersion']
        fail_unless(admitted == expected, 'dry_run_admission_changed_' + key)
    secret = kubectl('create', '--dry-run=server', '-f', '-', '-o', 'json',
                     document=changes['evidence_secret'])
    expected = changes['evidence_secret']
    admitted = {field: secret[field] for field in ('apiVersion', 'kind', 'type', 'immutable', 'data')}
    admitted['metadata'] = {field: secret['metadata'][field] for field in ('name', 'namespace')}
    fail_unless(admitted == expected, 'rfc_secret_dry_run_admission_changed')
    return changes['digests']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence-archive', help='private archive containing the pinned writer inputs')
    options = parser.parse_args()
    fail_unless(os.geteuid() == 0 and socket.gethostname().lower() == 'publicdatamcp-b130e',
                'b130e_root_context_required')
    evidence = read_evidence(options.evidence_archive) if options.evidence_archive else None
    snapshot, identity = read_baseline()
    receipt = {'baseline': identity, 'candidate': CANDIDATE_IMAGE}
    if evidence is not None:
        receipt['server_dry_run'] = dry_run(snapshot, evidence)
    print(json.dumps(receipt, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, RenderError, tarfile.TarError, subprocess.SubprocessError,
            KeyError, TypeError, ValueError) as error:
        code = str(error) if type(error) in (RuntimeError, RenderError) else type(error).__name__
        print(json.dumps({'passed': False, 'code': code}), file=sys.stderr)
        sys.exit(1)
