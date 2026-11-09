#!/usr/bin/env python3
"""Wire real projected identities to the enforcing disposable broker fixture."""
import json
from pathlib import Path
import re
import sys


def configure(root):
    root = Path(root).resolve(strict=True)
    if Path('/tmp') not in root.parents:
        raise ValueError('Expected an isolated /tmp fixture')
    for name in ('backend', 'writer'):
        path = root / 'fixture' / (name + '.toml')
        text = path.read_text()
        pattern = r'(?ms)^\[storage\.s3\.credentials\]\s*\n.*?(?=^\[|\Z)'
        replacement = '''[storage.s3.credentials]
mode = "container"
endpoint = "https://credential-broker:8444/v1/credentials"
authorization_token_file = "/run/devres-broker-identity/token"
ca_file = "/fixture/cert/ca.pem"
refresh_before_secs = 10

'''
        text, count = re.subn(pattern, replacement, text)
        if count != 1:
            raise ValueError('Expected exactly one credential table')
        # This generic RustFS fixture proves authorization. Explicit ONEZONE_IA
        # request propagation is covered by SDK tests and Scaleway acceptance.
        path.write_text(text)
    corpus = root / 'fixture/broker/corpus-url'
    corpus.write_text('postgres://devres_reader:reader-fixture-only@postgres/devres')
    corpus.chmod(0o600)
    iam = root / 'fixture/broker/iam-fixture.json'
    value = json.loads(iam.read_text())
    # Kubernetes uses the S3 harness's objectstore Secret. The standalone Docker
    # fixture generates its own root identity; do not use that second identity
    # against the independently initialized Kubernetes RustFS deployment.
    value['access_key'] = (root / 'fixture/s3/access-key').read_text().strip()
    value['secret_key'] = (root / 'fixture/s3/secret-key').read_text().strip()
    value['state_file'] = '/fixture/broker-state/iam-state.json'
    iam.write_text(json.dumps(value))


def workloads(path):
    path = Path(path)
    text = path.read_text()
    # These are the exact legacy root-credential mounts added by the --s3
    # fixture. Consumers of the broker must not receive them.
    text = text.replace('            - {name: s3, mountPath: /fixture/s3, readOnly: true}\n', '')
    text = text.replace('        - name: s3\n          secret: {secretName: devres-s3-credentials, defaultMode: 0440}\n', '')
    marker = '            - {name: tmp, mountPath: /tmp}\n'
    # Foundation also contains postgres/edge volumes: select the workload by its
    # unique pod identity mount rather than changing every document.
    documents = text.split('\n---\n')
    changed = 0
    for i, document in enumerate(documents):
        if not any('serviceAccountName: ' + name in document for name in ('devres-serving', 'devres-writer')):
            continue
        if document.count(marker) != 1:
            raise ValueError('Expected exactly one workload scratch mount')
        document = document.replace(marker, marker + '            - {name: broker-identity, mountPath: /run/devres-broker-identity, readOnly: true}\n')
        volume_marker = '      volumes:\n'
        if document.count(volume_marker) != 1:
            raise ValueError('Expected one workload volume list')
        documents[i] = document.replace(volume_marker, volume_marker + '''        - name: broker-identity
          projected:
            defaultMode: 0440
            sources:
              - serviceAccountToken:
                  path: token
                  audience: devres-credential-broker
                  expirationSeconds: 600
''')
        changed += 1
    if changed != 1:
        raise ValueError('Expected one broker-consuming workload')
    path.write_text('\n---\n'.join(documents))


def manifests(image, reviewer):
    def resource(kind, name, spec=None):
        version = 'apps/v1' if kind == 'Deployment' else 'v1'
        if kind in ('ClusterRole', 'ClusterRoleBinding', 'RoleBinding'):
            version = 'rbac.authorization.k8s.io/v1'
        if kind == 'NetworkPolicy':
            version = 'networking.k8s.io/v1'
        value = {'apiVersion': version, 'kind': kind, 'metadata': {'name': name}}
        if spec is not None:
            value['spec'] = spec
        return value

    account = resource('ServiceAccount', 'devres-credential-broker')
    account['automountServiceAccountToken'] = False
    review = resource('ClusterRoleBinding', reviewer + '-broker')
    review.update({'roleRef': {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'ClusterRole', 'name': reviewer},
                   'subjects': [{'kind': 'ServiceAccount', 'name': 'devres-credential-broker', 'namespace': 'devres-acceptance'}]})
    cluster_identity_name = reviewer + '-broker-cluster-id'
    cluster_identity = resource('ClusterRole', cluster_identity_name)
    cluster_identity['rules'] = [{'apiGroups': [''], 'resources': ['namespaces'],
                                  'resourceNames': ['kube-system'], 'verbs': ['get']}]
    cluster_identity_binding = resource('ClusterRoleBinding', cluster_identity_name)
    cluster_identity_binding.update({
        'roleRef': {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'ClusterRole', 'name': cluster_identity_name},
        'subjects': [{'kind': 'ServiceAccount', 'name': 'devres-credential-broker', 'namespace': 'devres-acceptance'}]})
    identities = resource('RoleBinding', 'devres-broker-identities')
    identities.update({'roleRef': {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'Role', 'name': 'devres-live-identities'},
                       'subjects': [{'kind': 'ServiceAccount', 'name': 'devres-credential-broker'}]})
    security = {'runAsNonRoot': True, 'runAsUser': 65532, 'runAsGroup': 65532, 'fsGroup': 65532,
                'seccompProfile': {'type': 'RuntimeDefault'}}
    container_security = {'readOnlyRootFilesystem': True, 'allowPrivilegeEscalation': False,
                          'capabilities': {'drop': ['ALL']}}
    broker = resource('Deployment', 'credential-broker', {
        'replicas': 1, 'strategy': {'type': 'Recreate'}, 'selector': {'matchLabels': {'app': 'credential-broker'}},
        'template': {'metadata': {'labels': {'app': 'credential-broker'}}, 'spec': {
            'automountServiceAccountToken': False, 'serviceAccountName': 'devres-credential-broker', 'securityContext': security,
            'containers': [{'name': 'broker', 'image': image, 'imagePullPolicy': 'Never',
                            'command': ['devres-credential-broker', '/fixture/broker/broker.toml'],
                            'securityContext': container_security, 'ports': [{'name': 'credentials', 'containerPort': 8444}],
                            'readinessProbe': {'httpGet': {'path': '/healthz', 'port': 'credentials', 'scheme': 'HTTPS'}},
                            'resources': {'requests': {'cpu': '50m', 'memory': '64Mi'}, 'limits': {'cpu': '1', 'memory': '256Mi'}},
                            'volumeMounts': [{'name': 'private', 'mountPath': '/fixture/broker', 'readOnly': True},
                                             {'name': 'tls', 'mountPath': '/fixture/cert', 'readOnly': True},
                                             {'name': 'kube', 'mountPath': '/run/kube-api', 'readOnly': True}]}],
            'volumes': [{'name': 'private', 'secret': {'secretName': 'devres-broker-private', 'defaultMode': 0o440}},
                        {'name': 'tls', 'secret': {'secretName': 'devres-tls', 'defaultMode': 0o440}},
                        {'name': 'kube', 'projected': {'defaultMode': 0o440, 'sources': [
                            {'serviceAccountToken': {'path': 'token', 'expirationSeconds': 3600}},
                            {'configMap': {'name': 'kube-root-ca.crt', 'items': [{'key': 'ca.crt', 'path': 'ca.crt'}]}}]}}]}}})
    service = resource('Service', 'credential-broker', {'selector': {'app': 'credential-broker'},
                        'ports': [{'name': 'credentials', 'port': 8444, 'targetPort': 'credentials'}]})
    facade = resource('Deployment', 'iam-fixture', {'replicas': 1,
        'selector': {'matchLabels': {'app': 'iam-fixture'}},
        'template': {'metadata': {'labels': {'app': 'iam-fixture'}}, 'spec': {
            'automountServiceAccountToken': False, 'securityContext': security,
            'containers': [{'name': 'iam', 'image': image, 'imagePullPolicy': 'Never',
                            'command': ['python3', '/harness/scaleway-iam-fixture.py', '/fixture/broker/iam-fixture.json'],
                            'securityContext': container_security, 'ports': [{'containerPort': 8001}],
                            'readinessProbe': {'tcpSocket': {'port': 8001}},
                            'volumeMounts': [{'name': 'private', 'mountPath': '/fixture/broker', 'readOnly': True},
                                             {'name': 'state', 'mountPath': '/fixture/broker-state'}]}],
            'volumes': [{'name': 'private', 'secret': {'secretName': 'devres-iam-fixture', 'defaultMode': 0o440}},
                        {'name': 'state', 'emptyDir': {}}]}}})
    facade_service = resource('Service', 'iam-fixture', {'selector': {'app': 'iam-fixture'},
                        'ports': [{'port': 8001, 'targetPort': 8001}]})
    policies = []
    for name, app, callers, port in (
            ('broker-workloads-only', 'credential-broker', ['backend', 'writer'], 8444),
            ('iam-broker-only', 'iam-fixture', ['credential-broker'], 8001),
            ('objectstore-iam-fixture', 'objectstore', ['iam-fixture'], 9000)):
        policies.append(resource('NetworkPolicy', name, {'podSelector': {'matchLabels': {'app': app}},
            'policyTypes': ['Ingress'], 'ingress': [{'from': [{'podSelector': {'matchLabels': {'app': item}}} for item in callers],
                                                    'ports': [{'port': port, 'protocol': 'TCP'}]}]}))
    return {'apiVersion': 'v1', 'kind': 'List', 'items': [account, review, cluster_identity,
            cluster_identity_binding, identities, broker, service, facade, facade_service, *policies]}


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] in ('configure', 'workloads'):
        (configure if sys.argv[1] == 'configure' else workloads)(sys.argv[2])
    elif len(sys.argv) == 4 and sys.argv[1] == 'manifests':
        print(json.dumps(manifests(sys.argv[2], sys.argv[3])))
    else:
        raise SystemExit('usage: broker-kubernetes-fixture.py configure ROOT | workloads FILE | manifests IMAGE REVIEWER')
