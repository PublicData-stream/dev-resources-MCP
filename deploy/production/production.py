#!/usr/bin/env python3
"""Render dedicated production assets without credentials or cluster mutations."""
import argparse
import ipaddress
import json
from pathlib import Path
import re


VERSION = '0.1.0-build.172d528d'
REVISION = '172d528d88d16c9ec4fd83a16674280815178930'
SERVER = 'ghcr.io/publicdata-stream/dev-resources-server@sha256:da44682428c2ee37568867cb5bf0b0c3d75cb01b4d1c027c00f313bb29cf737f'
BROKER = 'ghcr.io/publicdata-stream/dev-resources-credential-broker@sha256:4ae4ea7fadeb1076cb387cd82a32ea25419914f32c4a454dbb015391a95e1889'
PROBE = 'ghcr.io/publicdata-stream/dev-resources-probe@sha256:324c117f72029a4ab153029a6559ccda4d50cf464db164b361ff379a08b3839d'
SOURCE_SHA256 = 'f3680663c2a1e69dfb12489ba44cc56512759b4068704443d3fb0c98bd7f57b0'
OXIBELT = 'ghcr.io/oxibelt/oxibelt@sha256:9f8aa1715586a5c15e26fe48ab982b43c28abe49dc2f09b78c1450ffa01b33d1'
LEGO = 'goacme/lego@sha256:6f1583fc026a455ea46a7a5858c576105bb69c2e2de69db391cab7f14750350c'
POSTGRES = 'postgres:18.6-alpine3.24@sha256:123b17998ccaf47e53b502e8c6a1e79afd8f579c6f3eec83c563da026f957395'
HOST = 'dev-resources.mcp.publicdata.stream'
NAMESPACE = 'devres'
PROVIDERS = ('rfc', 'crates', 'rustsec', 'mdn', 'whatwg', 'w3c', 'chromium', 'npm')
HERE = Path(__file__).resolve().parent
RESERVED_IPV4 = ('0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
                 '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24',
                 '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24',
                 '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4')


def resource(kind, name, spec=None, **fields):
    api = {'Deployment': 'apps/v1', 'NetworkPolicy': 'networking.k8s.io/v1',
           'Role': 'rbac.authorization.k8s.io/v1', 'RoleBinding': 'rbac.authorization.k8s.io/v1',
           'ClusterRole': 'rbac.authorization.k8s.io/v1',
           'ClusterRoleBinding': 'rbac.authorization.k8s.io/v1'}.get(kind, 'v1')
    result = {'apiVersion': api, 'kind': kind, 'metadata': {'name': name}}
    if kind not in ('Namespace', 'PersistentVolume', 'ClusterRole', 'ClusterRoleBinding'):
        result['metadata']['namespace'] = NAMESPACE
    if spec is not None:
        result['spec'] = spec
    result.update(fields)
    return result


def settings_checked(settings):
    allowed = {'node_name', 'node_ipv4', 'kube_api_cidrs', 'iam_cidrs', 'edge_image', 'oxibelt_digest'}
    if set(settings) - allowed:
        raise ValueError('Unknown production setting')
    result = {'node_name': 'publicdatamcp-b130e', 'node_ipv4': '62.210.240.40', **settings}
    if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?', result['node_name']):
        raise ValueError('Invalid Kubernetes node name')
    ipaddress.IPv4Address(result['node_ipv4'])
    for key in ('kube_api_cidrs', 'iam_cidrs'):
        if not isinstance(result.get(key), list) or not result[key]:
            raise ValueError('Explicit Kubernetes API and IAM CIDRs are required')
        networks = [ipaddress.ip_network(value, strict=True) for value in result[key]]
        if any(value.version != 4 or value.prefixlen < 24 for value in networks):
            raise ValueError('Use narrow explicit IPv4 API/IAM destination CIDRs')
        if key == 'iam_cidrs' and any(not value.is_global for value in networks):
            raise ValueError('IAM must use public IPv4 destinations')
        result[key] = sorted({str(value) for value in networks})
    if 'oxibelt_digest' in result:
        digest = result['oxibelt_digest'].removeprefix('sha256:')
        if not re.fullmatch('[0-9a-f]{64}', digest):
            raise ValueError('Invalid OxiBelt digest')
        image = 'ghcr.io/oxibelt/oxibelt@sha256:' + digest
        if result.get('edge_image', image) != image:
            raise ValueError('Conflicting OxiBelt identities')
        result['edge_image'] = image
    edge = result.get('edge_image')
    if edge is not None and not re.fullmatch(r'ghcr\.io/oxibelt/oxibelt@sha256:[0-9a-f]{64}', edge):
        raise ValueError('Edge image must be an immutable qualified OxiBelt digest')
    return result


def projected(name, audience=None):
    token = {'path': 'token', 'expirationSeconds': 3600}
    if audience:
        token['audience'] = audience
    sources = [{'serviceAccountToken': token}]
    if not audience:
        sources.append({'configMap': {'name': 'kube-root-ca.crt', 'items': [{'key': 'ca.crt', 'path': 'ca.crt'}]}})
    return {'name': name, 'projected': {'defaultMode': 0o440, 'sources': sources}}


def secret(name, secret_name):
    return {'name': name, 'secret': {'secretName': secret_name, 'defaultMode': 0o440}}


def mount(name, path, readonly=False, subpath=None):
    value = {'name': name, 'mountPath': path}
    if readonly:
        value['readOnly'] = True
    if subpath:
        value['subPath'] = subpath
    return value


def deployment(name, image, command, requests, limits, volumes, mounts, ports, settings,
               service_account=None, database=False):
    uid = 70 if database else 65532
    container = {'name': name, 'image': image, 'imagePullPolicy': 'IfNotPresent',
                 'ports': ports, 'resources': {'requests': requests, 'limits': limits},
                 'securityContext': {'readOnlyRootFilesystem': True, 'allowPrivilegeEscalation': False,
                                     'capabilities': {'drop': ['ALL']}}, 'volumeMounts': mounts}
    if command:
        container['command'] = command
    pod = {'automountServiceAccountToken': False,
           'nodeSelector': {'kubernetes.io/hostname': settings['node_name']},
           'securityContext': {'runAsNonRoot': True, 'runAsUser': uid, 'runAsGroup': uid,
                               'fsGroup': uid, 'seccompProfile': {'type': 'RuntimeDefault'}},
           'containers': [container], 'volumes': volumes}
    if service_account:
        pod['serviceAccountName'] = service_account
    if database:
        db = 'devres_broker' if name == 'broker-postgres' else 'devres'
        container['env'] = [{'name': 'POSTGRES_USER', 'value': 'devres_admin'},
                            {'name': 'POSTGRES_DB', 'value': db},
                            {'name': 'PGDATA', 'value': '/var/lib/postgresql/18/docker'},
                            {'name': 'POSTGRES_PASSWORD_FILE', 'value': '/run/postgres-private/postgres-password'}]
        probe = {'exec': {'command': ['pg_isready', '-U', 'devres_admin', '-d', db]}}
        container['readinessProbe'] = probe
        container['livenessProbe'] = {**probe, 'initialDelaySeconds': 20}
    elif name == 'credential-broker':
        container['readinessProbe'] = {'httpGet': {'path': '/healthz', 'port': 'credentials', 'scheme': 'HTTPS'}}
        # Dependency outages withhold readiness without forcing issuer restart loops.
        container['livenessProbe'] = {'tcpSocket': {'port': 'credentials'}, 'initialDelaySeconds': 20}
    else:
        container['readinessProbe'] = {'httpGet': {'path': '/ready', 'port': 'health'}}
        container['livenessProbe'] = {'httpGet': {'path': '/live', 'port': 'health'}, 'initialDelaySeconds': 30}
    return resource('Deployment', name, {'replicas': 0, 'strategy': {'type': 'Recreate'},
                    'selector': {'matchLabels': {'app': name}},
                    'template': {'metadata': {'labels': {'app': name}}, 'spec': pod}})


def service(name, ports, nodeport=False):
    spec = {'selector': {'app': name}, 'ports': ports}
    if nodeport:
        spec.update(type='NodePort', externalTrafficPolicy='Local')
    return resource('Service', name, spec)


def peer(app):
    return {'podSelector': {'matchLabels': {'app': app}}}


def rule(peers, ports, direction='to'):
    return {direction: peers, 'ports': [{'port': port, 'protocol': protocol} for port, protocol in ports]}


def manifests(settings):
    node = settings['node_name']
    namespace = resource('Namespace', NAMESPACE)
    namespace['metadata']['labels'] = {'pod-security.kubernetes.io/' + key: 'restricted'
                                       for key in ('enforce', 'audit', 'warn')}
    items = [namespace]
    for name in ('devres-serving', 'devres-writer', 'devres-credential-broker'):
        items.append(resource('ServiceAccount', name, automountServiceAccountToken=False))
    for name, path, capacity in (('corpus-postgres', '/database/devres/corpus', '256Gi'),
                                 ('broker-postgres', '/database/devres/broker', '16Gi'),
                                 ('serving-cache', '/var/cache/devres/serving', '32Gi'),
                                 ('writer-cache', '/var/cache/devres/writer', '64Gi')):
        pv = 'devres-' + name
        items.append(resource('PersistentVolume', pv, {'capacity': {'storage': capacity},
                     'volumeMode': 'Filesystem', 'accessModes': ['ReadWriteOnce'],
                     'persistentVolumeReclaimPolicy': 'Retain', 'storageClassName': '',
                     'claimRef': {'name': name, 'namespace': NAMESPACE}, 'local': {'path': path},
                     'nodeAffinity': {'required': {'nodeSelectorTerms': [{'matchExpressions': [
                         {'key': 'kubernetes.io/hostname', 'operator': 'In', 'values': [node]}]}]}}}))
        items.append(resource('PersistentVolumeClaim', name, {'accessModes': ['ReadWriteOnce'],
                     'storageClassName': '', 'volumeName': pv, 'resources': {'requests': {'storage': capacity}}}))
    for name, database_volume, memory, cpu, request_memory, request_cpu in (
            ('postgres', 'corpus-postgres', '6Gi', '4', '4Gi', '1'),
            ('broker-postgres', 'broker-postgres', '1Gi', '1', '512Mi', '250m')):
        config_secret = 'devres-' + database_volume
        volumes = [{'name': 'data', 'persistentVolumeClaim': {'claimName': database_volume}},
                   secret('private', config_secret), {'name': 'tmp', 'emptyDir': {'sizeLimit': '256Mi'}},
                   {'name': 'run', 'emptyDir': {'medium': 'Memory', 'sizeLimit': '32Mi'}}]
        mounts = [mount('data', '/var/lib/postgresql'), mount('private', '/run/postgres-private', True),
                  mount('private', '/docker-entrypoint-initdb.d/10-init.sql', True, 'init.sql'),
                  mount('tmp', '/tmp'), mount('run', '/var/run/postgresql')]
        items.append(deployment(name, POSTGRES, None, {'cpu': request_cpu, 'memory': request_memory},
                                {'cpu': cpu, 'memory': memory}, volumes, mounts,
                                [{'name': 'postgres', 'containerPort': 5432}], settings, database=True))
        items.append(service(name, [{'name': 'postgres', 'port': 5432, 'targetPort': 'postgres'}]))
    for sa in ('devres-writer', 'devres-credential-broker'):
        name = sa + '-reviewer'
        rules = [{'apiGroups': ['authentication.k8s.io'], 'resources': ['tokenreviews'], 'verbs': ['create']}]
        if sa.endswith('broker'):
            rules.append({'apiGroups': [''], 'resources': ['namespaces'], 'resourceNames': ['kube-system'], 'verbs': ['get']})
        items.append(resource('ClusterRole', name, rules=rules))
        items.append(resource('ClusterRoleBinding', name,
                              roleRef={'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'ClusterRole', 'name': name},
                              subjects=[{'kind': 'ServiceAccount', 'name': sa, 'namespace': NAMESPACE}]))
        items.append(resource('Role', name, rules=[{'apiGroups': [''], 'resources': ['pods', 'serviceaccounts'], 'verbs': ['get']}]))
        items.append(resource('RoleBinding', name,
                              roleRef={'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'Role', 'name': name},
                              subjects=[{'kind': 'ServiceAccount', 'name': sa, 'namespace': NAMESPACE}]))
    for name, sa, cache, memory, cpu, request_memory, request_cpu in (
            ('writer', 'devres-writer', 'writer-cache', '12Gi', '6', '8Gi', '2'),
            ('backend', 'devres-serving', 'serving-cache', '4Gi', '3', '2Gi', '1')):
        writer = name == 'writer'
        config_name = 'writer' if writer else 'serving'
        volumes = [secret('config', 'devres-' + config_name + '-config'), secret('backend-tls', 'devres-backend-tls'),
                   secret('writer-tls', 'devres-writer-tls'), secret('broker-trust', 'devres-broker-trust'),
                   {'name': 'cache', 'persistentVolumeClaim': {'claimName': cache}},
                   {'name': 'tmp', 'emptyDir': {'sizeLimit': '4Gi' if writer else '2Gi'}},
                   projected('broker-identity', 'devres-credential-broker')]
        mounts = [mount('config', '/etc/devres/config', True), mount('backend-tls', '/etc/devres/tls', True),
                  mount('writer-tls', '/run/devres-writer-tls', True),
                  mount('broker-trust', '/run/devres-broker-trust', True), mount('cache', '/data/cache'),
                  mount('tmp', '/tmp'), mount('broker-identity', '/run/devres-broker-identity', True)]
        if writer:
            volumes.append(projected('kube'))
            mounts.append(mount('kube', '/run/devres-kube', True))
            ports = [{'name': 'coordination', 'containerPort': 9443}]
        else:
            # Serving receives the trust root, never the writer's private key.
            next(value for value in volumes if value['name'] == 'writer-tls')['secret']['items'] = [
                {'key': 'ca.crt', 'path': 'ca.crt'}]
            volumes.append(projected('writer-identity', 'devres-writer'))
            mounts.append(mount('writer-identity', '/run/devres-writer-identity', True))
            ports = [{'name': 'http', 'containerPort': 8080}, {'name': 'wt', 'containerPort': 4433, 'protocol': 'UDP'}]
        ports.append({'name': 'health', 'containerPort': 9090})
        items.append(deployment(name, SERVER, ['devres-server', 'collect' if writer else 'serve',
                                '/etc/devres/config/' + config_name + '.toml'],
                                {'cpu': request_cpu, 'memory': request_memory}, {'cpu': cpu, 'memory': memory},
                                volumes, mounts, ports, settings, service_account=sa))
    items.append(service('writer', [{'name': 'coordination', 'port': 9443, 'targetPort': 'coordination'}]))
    items.append(service('backend', [{'name': 'http', 'port': 8080, 'targetPort': 'http', 'nodePort': 30081},
                                    {'name': 'wt', 'port': 4433, 'targetPort': 'wt', 'nodePort': 30434, 'protocol': 'UDP'}], True))
    items.append(deployment('credential-broker', BROKER,
                            ['devres-credential-broker', '/etc/devres/config/credential-broker.toml'],
                            {'cpu': '100m', 'memory': '128Mi'}, {'cpu': '1', 'memory': '512Mi'},
                            [secret('config', 'devres-credential-broker-config'),
                             secret('private', 'devres-credential-broker-private'), projected('kube'),
                             {'name': 'tmp', 'emptyDir': {'sizeLimit': '64Mi'}}],
                            [mount('config', '/etc/devres/config', True), mount('private', '/run/devres-broker', True),
                             mount('kube', '/run/devres-kube', True), mount('tmp', '/tmp')],
                            [{'name': 'credentials', 'containerPort': 9444}], settings,
                            service_account='devres-credential-broker'))
    items.append(service('credential-broker', [{'name': 'credentials', 'port': 9444, 'targetPort': 'credentials'}]))
    items.append(resource('NetworkPolicy', 'default-deny', {'podSelector': {}, 'policyTypes': ['Ingress', 'Egress']}))
    dns = rule([{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': 'kube-system'}},
                 'podSelector': {'matchLabels': {'k8s-app': 'kube-dns'}}}], [(53, 'UDP'), (53, 'TCP')])
    api = rule([{'ipBlock': {'cidr': value}} for value in settings['kube_api_cidrs']], [(443, 'TCP'), (6443, 'TCP')])
    excluded = sorted({*RESERVED_IPV4, settings['node_ipv4'] + '/32'})
    public_https = rule([{'ipBlock': {'cidr': '0.0.0.0/0', 'except': excluded}}], [(443, 'TCP')])
    policies = {
        'backend': ([rule([{'ipBlock': {'cidr': '10.0.0.3/32'}}], [(8080, 'TCP'), (4433, 'UDP')], 'from')],
                    [dns, public_https, rule([peer('postgres')], [(5432, 'TCP')]),
                     rule([peer('writer')], [(9443, 'TCP')]), rule([peer('credential-broker')], [(9444, 'TCP')])]),
        'writer': ([rule([peer('backend')], [(9443, 'TCP')], 'from')],
                   [dns, api, public_https, rule([peer('postgres')], [(5432, 'TCP')]),
                    rule([peer('credential-broker')], [(9444, 'TCP')])]),
        'credential-broker': ([rule([peer('backend'), peer('writer')], [(9444, 'TCP')], 'from')],
                              [dns, api, rule([peer('broker-postgres')], [(5432, 'TCP')]),
                               rule([{'ipBlock': {'cidr': value}} for value in settings['iam_cidrs']], [(443, 'TCP')])]),
        'postgres': ([rule([peer('backend'), peer('writer')], [(5432, 'TCP')], 'from')], []),
        'broker-postgres': ([rule([peer('credential-broker')], [(5432, 'TCP')], 'from')], [])}
    for name, (ingress, egress) in policies.items():
        items.append(resource('NetworkPolicy', name + '-boundary', {'podSelector': peer(name)['podSelector'],
                     'policyTypes': ['Ingress', 'Egress'], 'ingress': ingress, 'egress': egress}))
    return {'apiVersion': 'v1', 'kind': 'List', 'items': items}


def runtime_config(writer=False):
    role = 'WRITER' if writer else 'READER'
    sections = ['# PRIVATE TEMPLATE: substitute credentials locally; never commit the result.',
                '[source]', f'url = "https://github.com/PublicData-stream/dev-resources-MCP/releases/download/{VERSION}/source.tar.gz"']
    for provider in PROVIDERS:
        sections.extend([f'[{provider}]', 'enabled = false'])
        if provider == 'npm':
            sections.extend(['packages = []', 'advisories_enabled = true'])
    sections.append(f'''
[http]
bind = "0.0.0.0:8080"
allowed_hosts = ["devres-k8s:30081"]
allowed_origins = ["https://chatgpt.com", "https://{HOST}"]
[http.tls]
certificate = "/etc/devres/tls/backend.pem"
private_key = "/etc/devres/tls/backend-key.pem"
[webtransport]
bind = "0.0.0.0:4433"
certificate = "/etc/devres/tls/backend.pem"
private_key = "/etc/devres/tls/backend-key.pem"
allowed_hosts = ["devres-k8s:30434"]
allowed_origins = ["https://chatgpt.com", "https://{HOST}"]
[health]
bind = "0.0.0.0:9090"
[edge_mtls]
client_ca_file = "/etc/devres/tls/client-ca.pem"
required_client_dns_san = "devres-edge.internal"
[storage]
database_url = "postgres://devres_{role.lower()}:@CORPUS_{role}_PASSWORD@@postgres/devres"
blob_dir = "/data/cache"
backend = "s3"''')
    if not writer:
        sections.append('scratch_dir = "/tmp/devres-serving"')
    sections.append(f'''
[storage.s3]
endpoint = "https://s3.fr-par.scw.cloud"
bucket = "dev-resources-mcp"
region = "fr-par"
prefix = "production"
path_style = true
storage_class = "ONEZONE_IA"
cache_max_bytes = {68719476736 if writer else 34359738368}
[storage.s3.credentials]
mode = "container"
endpoint = "https://credential-broker.devres.svc:9444/v1/credentials"
authorization_token_file = "/run/devres-broker-identity/token"
ca_file = "/run/devres-broker-trust/ca.crt"
refresh_before_secs = 300''')
    if writer:
        sections.append('''
[writer_listener]
bind = "0.0.0.0:9443"
certificate = "/run/devres-writer-tls/tls.crt"
private_key = "/run/devres-writer-tls/tls.key"
allowed_clients = [{namespace = "devres", service_account = "devres-serving"}]
[writer_listener.auth]
kube_api_url = "https://kubernetes.default.svc"
kube_token_file = "/run/devres-kube/token"
kube_ca_file = "/run/devres-kube/ca.crt"
audience = "devres-writer"''')
    else:
        sections.append('''
[writer_client]
endpoint = "https://writer.devres.svc:9443/v1/acquire"
token_file = "/run/devres-writer-identity/token"
ca_file = "/run/devres-writer-tls/ca.crt"''')
    return '\n'.join(sections) + '\n'


def broker_config():
    value = (HERE.parent / 'examples/scaleway-credential-broker/broker.toml.example').read_text()
    replacements = {'REPLACE_ISSUER_ACCESS_KEY_ID': '@ISSUER_ACCESS_KEY@',
                    '00000000-0000-0000-0000-000000000001': '@ISSUER_APPLICATION_ID@',
                    '00000000-0000-0000-0000-000000000002': '@READER_APPLICATION_ID@',
                    '00000000-0000-0000-0000-000000000003': '@WRITER_APPLICATION_ID@',
                    '00000000-0000-0000-0000-000000000004': '@PROJECT_ID@',
                    'devres-archive': 'dev-resources-mcp'}
    for old, new in replacements.items():
        value = value.replace(old, new)
    value = re.sub(r'(?m)^organization_id = .*$', 'organization_id = "@ORGANIZATION_ID@"', value)
    value = value.replace('REPLACE_WITH_64_HEX_POLICY_DIGEST', '@READER_POLICY_SHA256@', 1)
    return value.replace('REPLACE_WITH_64_HEX_POLICY_DIGEST', '@WRITER_POLICY_SHA256@', 1)


def edge_compose(settings):
    image = settings.get('edge_image', OXIBELT)
    return {'services': {'oxibelt': {'image': image, 'user': '10001:10001', 'container_name': 'oxibelt',
            'mem_limit': '1g', 'cpus': 1,
            'restart': 'unless-stopped', 'read_only': True, 'security_opt': ['no-new-privileges:true'],
            'cap_drop': ['ALL'], 'cap_add': ['NET_BIND_SERVICE'],
            'tmpfs': ['/tmp:rw,noexec,nosuid,size=64m,gid=10001,uid=10001',
                      '/run:rw,noexec,nosuid,size=16m,gid=10001,uid=10001'],
            'ports': ['443:443/tcp', '443:443/udp'],
            'volumes': ['/serve/oxibelt.toml:/etc/oxibelt/config/oxibelt.toml:ro',
                        '/serve/oxibelt-conf:/etc/oxibelt/config/oxibelt-conf:ro',
                        '/serve/lego/data/certificates:/etc/oxibelt/cert:ro'],
            'extra_hosts': ['devres-k8s:10.0.0.1'], 'networks': {'devres-net': {'ipv4_address': '10.0.0.3'}}}},
            'networks': {'devres-net': {'name': 'devres-net', 'driver': 'bridge',
                         'ipam': {'config': [{'subnet': '10.0.0.0/16', 'gateway': '10.0.0.1'}]},
                         'driver_opts': {'com.docker.network.bridge.name': 'devres-edge0'}}}}


def render(output_dir: Path, settings: dict):
    """Write nonsecret assets; settings contain only node/destination/image metadata."""
    settings = settings_checked(settings)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    values = {'kubernetes.json': json.dumps(manifests(settings), indent=2, sort_keys=True) + '\n',
              'serving.toml.example': runtime_config(), 'writer.toml.example': runtime_config(True),
              'credential-broker.toml.example': broker_config(),
              'edge-compose.json': json.dumps(edge_compose(settings), indent=2, sort_keys=True) + '\n',
              'release.json': json.dumps({'version': VERSION, 'revision': REVISION, 'server': SERVER,
                                         'broker': BROKER, 'probe': PROBE, 'postgres': POSTGRES,
                                         'source_sha256': SOURCE_SHA256}, indent=2, sort_keys=True) + '\n',
              'edge.toml': 'include = ["oxibelt-conf/*.toml"]\n'}
    for template in (HERE / 'edge-conf').glob('*.toml'):
        values['edge-conf/' + template.name] = template.read_text()
    paths = {}
    for name, value in sorted(values.items()):
        path = output_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value)
        paths[name] = path
    return paths


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--settings', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    render(args.output, json.loads(args.settings.read_text()))
