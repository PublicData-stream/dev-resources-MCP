#!/usr/bin/env python3
"""Explicit-context lifecycle control for an operator-provisioned split runtime."""
import argparse
import json
import subprocess


def run(context, namespace, operation, storage):
    base = ['kubectl', '--context', context, '--namespace', namespace, '--request-timeout=30s']

    def call(*args):
        return subprocess.check_output([*base, *args], timeout=180)

    names = ('credential-broker', 'writer', 'backend') if storage == 's3' else ('writer', 'backend')
    # Inspect all intended names before any scale mutation, avoiding partial
    # execution against an old combined deployment or a misspelled namespace.
    deployments = {}
    for name in names:
        value = json.loads(call('get', 'deployment', name, '-o', 'json'))
        if value['metadata']['name'] != name or value['metadata']['namespace'] != namespace:
            raise ValueError('Unexpected runtime identity')
        deployments[name] = value
    writer = deployments['writer']['spec']['template']['spec']['containers'][0]
    invocation = [*writer.get('command', []), *writer.get('args', [])]
    if 'collect' not in invocation:
        raise ValueError('Writer deployment is not configured for split runtime')
    if operation == 'status':
        return {name: {'replicas': item['spec'].get('replicas', 1),
                       'ready': item.get('status', {}).get('readyReplicas', 0)}
                for name, item in deployments.items()}
    if operation == 'stop':
        for name in ('backend', 'writer'):
            call('scale', 'deployment/' + name, '--replicas=0')
            call('wait', '--for=delete', 'pod', '-l', 'app=' + name, '--timeout=120s')
        return {'serving_stopped': True, 'writer_stopped': True}
    for name in names:
        call('scale', 'deployment/' + name, '--replicas=1')
        call('rollout', 'status', 'deployment/' + name, '--timeout=120s')
    return {'runtime_started': True}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', required=True)
    parser.add_argument('--namespace', required=True)
    parser.add_argument('--storage', choices=('filesystem', 's3'), required=True)
    parser.add_argument('operation', choices=('status', 'stop', 'start'))
    args = parser.parse_args()
    try:
        result = run(args.context, args.namespace, args.operation, args.storage)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        raise SystemExit('Split runtime operation failed; inspect workload status before retrying.') from None
    print(json.dumps(result, sort_keys=True))
