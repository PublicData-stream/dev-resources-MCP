#!/usr/bin/env python3
"""Guarded schema18 successor of the admitted Wikipedia production activation.

Permanent PostgreSQL/S3 evidence is preserved; this controller never restores or
downgrades data. Every mutation consumes a private fsynced single-use intent.
"""
import argparse
import base64
import contextlib
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
import tomllib

OLD_OPERATOR = '/usr/local/libexec/devres-production-candidate-a938112b-apparmor-v1/scripts/production-operator.py'
OLD_SHA = '58501767e3d130af1a05e1f6493f89ee8f287e1582f0f35fa2b1e74c23f5e3da'
OLD_BUNDLE = '/var/lib/devres-production-preparation/a938112b-7c7a24f'
PRIOR_BUNDLE = '/var/lib/devres-production-activations/wikipedia-65236494-20261113'
PRIOR_CONTROLLER = '/usr/local/libexec/devres-wikipedia-enable-65236494/activation-controller.py'
PRIOR_CONTROLLER_SHA = 'd9699971623a9d828ff119f80d6fe23055f7107427375957231015b17168dc56'
WORK = '/tmp/devres-upgrade-33f3c730-20261114'
PRIOR_REVISION = '65236494ad7a837243d16c7e92e177df77a7d226'
BUNDLE = '/var/lib/devres-production-upgrades/33f3c730-20261114'
REVISION = '33f3c730123319625fe3a25713988201eb5d82e0'
VERSION = '0.1.0-build.33f3c730'
OLD_IMAGE = 'ghcr.io/publicdata-stream/dev-resources-server@sha256:efe9f706d82d535b89c18cfe9fbc68d7e7f586e014d534b00828cc8639b2c52d'
IMAGE = 'ghcr.io/publicdata-stream/dev-resources-server@sha256:c13191678b2336f6594521dec7ca040cc97ea55313d098d87726f852eb3f1bde'
PG_IMAGE = 'postgres:18.6-alpine3.24@sha256:123b17998ccaf47e53b502e8c6a1e79afd8f579c6f3eec83c563da026f957395'
SOURCE_URL = 'https://github.com/PublicData-stream/dev-resources-MCP/releases/download/' + VERSION + '/source.tar.gz'
SOURCE_SHA = '46491351a46d4518274982406bc66174908e7559a8a4d6e1bd3f787e2b9b1b0a'
PROBE_IMAGE = 'ghcr.io/publicdata-stream/dev-resources-probe@sha256:8239d387a0120049eef707a6cd474c2286545991bd7f246c8b7773c8f02a1473'
PROFILE_SHA = '99babcd17bef83cb21d96fb2e13fbe8b96bc4e1d5c638939ff9dc719f2706c97'
STORE_BINDING = '4a59576b1a2977f157ceaf72fbe404f660bd89a44c6246106b65f83989f5c529'
PROVIDERS = ('rfc', 'crates', 'rustsec', 'mdn', 'whatwg', 'w3c', 'chromium', 'npm', 'wikipedia')
ROLES = {'backend': ('devres-serving-config', 'serving.toml'),
         'writer': ('devres-writer-config', 'writer.toml')}
PROFILES = ('/serve/oxibelt-conf/10-tls.toml', OLD_BUNDLE + '/edge-conf/10-tls.toml')
FENCES = ('capacity_fenced', 'withdrawn', 'withdraw_incomplete', 'stopped', 'stop_failed')


# Explicitly authorized, externally completed shared-edge network change. These
# pins describe the observed change; they never authorize another recreation.
EDGE_COMPOSE = '/serve/docker-compose.yml'
OLD_COMPOSE_SHA = '2326b3356a99efe0f45a46894b2494d9c090d15d8419d7a398aeca303abdfb3a'
NEW_COMPOSE_SHA = '986c3a1986974071986fccddd9dffd78bff95fb3bba5f5faaa27061ab38b3406'
OLD_EDGE_ID = '2bea104aec8b9ae368dcce5e18c91b00d1c993bdb4706326f2df22e3127bce78'
NEW_EDGE_ID = '36e3ad39478bade960690a4bdb14e409b9899140fa6735ecca8400d79afeaeff'
EDGE_IMAGE = 'sha256:9f8aa1715586a5c15e26fe48ab982b43c28abe49dc2f09b78c1450ffa01b33d1'
OLD_COMPOSE_CONFIG = '1629b848b188a7dd4d7a4e810c5d012961358a9e11b508c927316cf188b5bd7d'
NEW_COMPOSE_CONFIG = '3144ecd1981dcf105efac63eec9596848d2af98d2c1a7728b457988f1c8c3d71'
OLD_DEVRES_MAC = '8a:a1:0c:9b:0a:c3'
NEW_DEVRES_MAC = 'ee:13:17:aa:71:ea'
PDF_NETWORK = {'IPAddress': '172.19.0.2', 'IPPrefixLen': 16, 'Gateway': '172.19.0.1',
    'GlobalIPv6Address': '', 'GlobalIPv6PrefixLen': 0, 'IPv6Gateway': '',
    'MacAddress': '42:32:66:39:05:52', 'Aliases': ['oxibelt', 'oxibelt'],
    'DNSNames': ['oxibelt', NEW_EDGE_ID[:12]], 'IPAMConfig': {}, 'DriverOpts': None, 'Links': None}
NETWORK_IDS = {'devres-net': 'c437bd5de32ebfad6fdeac4ea849a6c4a775e1e2ad1747f2bf17da1ce1f325ac',
    'pdf2md-net': '979c94def752a88bd9ed1da4d3ae92013827245f94cce37e16bad1fce2414e9e'}
NETWORK_ENDPOINTS = {'devres-net': 'f300a236bb39af07ee8b3eed51054842ae6cbc5cb1395481bae78b1b8ba966c8',
    'pdf2md-net': '47dca947ef260309e7787e3ca6455616c40ae21af9d047986fafe806c43d8a5d'}
NETWORK_LABEL_HASHES = {'devres-net': '50a76bc2c92662b13b3e41236406cefe37f6573f9472b385ed483a7ceaf15ec3',
    'pdf2md-net': '14dadebdce79934b165a2d522278b1b3bade6a0a40e20ce17ec7e485d3bd182e'}
NETWORK_FIELDS = ('Name', 'Id', 'Driver', 'Scope', 'EnableIPv6', 'Internal', 'IPAM',
    'Options', 'Labels', 'ConfigOnly', 'Ingress')


EDGE_CONF = Path('/serve/oxibelt-conf')
# Only these already-authorized metadata/content differences may be reversed.
CONF_FILE_RULES = {
    '10-tls.toml': {'inode': 13107217, 'old_size': 1210, 'new_size': 1210,
        'old_sha': PROFILE_SHA, 'new_sha': PROFILE_SHA, 'old_mtime': 1794378633630782462,
        'new_mtime': 1794658726895668662},
    '20-proxy.toml': {'inode': 13107240, 'old_size': 1146, 'new_size': 1116,
        'old_sha': 'a2894792a6761e22c1c4921e90d24530012dea0dfba94af2244123f8cd5673c2',
        'new_sha': 'bd544f46640edab8890ac677f1d100ab807e9a1d20959c5143ea83db750d89d7',
        'new_mtime': 1794632754921703091},
    '40-compression.toml': {'inode': 13107210, 'old_size': 955, 'new_size': 835,
        'old_sha': 'ecf63a7dd2284f41786d5fb6e37016a556b92b7a8a8a9f24807e29893a539c5c',
        'new_sha': 'cf0c5b06bd104166990173e6e3abd931b8f80dd2ae19dcb5c839110cbd585a29',
        'new_mtime': 1794632318220912288},
    '62-route-devres.toml': {'inode': 13107219, 'old_size': 759, 'new_size': 763,
        'old_sha': 'a417bdae885508b4895125c37b18021236100141ecbeea4f95418c788afacb7b',
        'new_sha': '31071b3d409cf2895356af672a5b0a0e0cb50aa243bdb2b3cd05dbba6dd4fa6c',
        'new_mtime': 1794632495354418998}}
CURRENT_COMPRESSION = {'compression': {'enabled': True, 'gzip': True, 'deflate': False,
    'zstd': True, 'br': True, 'min_size_bytes': 256, 'statuses': [200],
    'mime_types': ['text/*', 'application/json', 'application/*+json', 'application/javascript',
        'application/xml', 'application/*+xml', 'application/xhtml+xml', 'application/rss+xml',
        'application/atom+xml', 'font/opentype', 'font/ttf', 'font/eot', 'font/otf', 'image/svg+xml'],
    'level': 5, 'vary': True, 'proxied': ['any'], 'upstream_accept_encoding': 'strip',
    'max_concurrent_responses': 0}}


class Error(RuntimeError):
    pass


def require(value, code):
    if not value:
        raise Error(code)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def utc_now():
    return dt.datetime.now(dt.timezone.utc)


def stamp():
    return utc_now().isoformat()


def read(path, maximum=8 * 1024**2):
    path = Path(path)
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'symlink_refused')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                and not info.st_mode & 0o077 and info.st_nlink == 1
                and info.st_size <= maximum, 'unsafe_private_file')
        value = stream.read(maximum + 1)
    require(len(value) <= maximum, 'private_file_bound')
    return value


def syncdir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def save(path, value, replace=False):
    path = Path(path)
    raw = value if isinstance(value, bytes) else encoded(value)
    require(path.is_absolute() and not any(p.is_symlink() for p in (path, *path.parents)), 'symlink_refused')
    parent = path.parent.stat()
    require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid()
            and not parent.st_mode & 0o077, 'unsafe_private_directory')
    temporary = path.parent / ('.' + path.name + '.tmp') if replace else path
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    if replace:
        os.replace(temporary, path)
    syncdir(path.parent)
    syncdir(path.parent.parent)


def load(path):
    return json.loads(read(path))


def configuration(original, active):
    """Only explicit admission switches and source URL change; credentials are byte-carried."""
    before = tomllib.loads(original)
    expected = copy.deepcopy(before)
    text = original
    for provider in PROVIDERS:
        require(type(before.get(provider, {}).get('enabled')) is bool, 'explicit_flags_required')
        wanted = before[provider]['enabled'] if active else False
        pattern = rf'(?m)(^\[{provider}\][ \t]*\n(?:[ \t]*#[^\n]*\n)*[ \t]*enabled[ \t]*=[ \t]*)(?:true|false)([ \t]*(?:#[^\n]*)?$)'
        text, count = re.subn(pattern, lambda m: m[1] + str(wanted).lower() + m[2], text)
        require(count == 1, 'collector_shape')
        expected[provider]['enabled'] = wanted
    old_url = before.get('source', {}).get('url')
    require(old_url == 'https://github.com/PublicData-stream/dev-resources-MCP/releases/download/0.1.0-build.65236494/source.tar.gz', 'old_source_url')
    require(text.count(old_url) == 1, 'source_url_shape')
    text = text.replace(old_url, SOURCE_URL)
    expected['source']['url'] = SOURCE_URL
    require(tomllib.loads(text) == expected, 'configuration_semantic_drift')
    return text


def deployment_projection(value):
    spec = copy.deepcopy(value['spec'])
    spec.pop('replicas', None)
    containers = spec['template']['spec']['containers']
    require(len(containers) == 1, 'one_container_required')
    image = containers[0].pop('image')
    return {'uid': value['metadata']['uid'], 'spec': spec}, image


def secret_projection(value):
    return {'uid': value['metadata']['uid'], 'type': value.get('type'),
            'immutable': value.get('immutable', False), 'data': value.get('data', {})}


def pod_projection(value):
    require(value.get('status', {}).get('phase') == 'Running'
            and not value['metadata'].get('deletionTimestamp'), 'pod_not_running')
    statuses = value['status'].get('containerStatuses', [])
    require(len(statuses) == 1 and statuses[0].get('ready') is True, 'pod_not_ready')
    status = statuses[0]
    require(status.get('containerID') and status.get('imageID')
            and status.get('state', {}).get('running', {}).get('startedAt'), 'pod_process_missing')
    return {'uid': value['metadata']['uid'], 'container_id': status['containerID'],
            'image_id': status['imageID'], 'started_at': status['state']['running']['startedAt'],
            'restarts': status['restartCount'], 'owner': value['metadata'].get('ownerReferences', []),
            'name': value['metadata']['name'], 'pod_ip': value['status']['podIP']}


def foundation_projection(items):
    result = []
    for item in items:
        meta = item['metadata']
        # ServiceAccount token references may rotate independently; UID/labels remain protected.
        result.append({'kind': item['kind'], 'name': meta['name'], 'uid': meta['uid'],
                       'labels': meta.get('labels', {}), 'spec': item.get('spec'),
                       'rules': item.get('rules'), 'subjects': item.get('subjects'),
                       'roleRef': item.get('roleRef'), 'automountServiceAccountToken': item.get('automountServiceAccountToken')})
    return sorted(result, key=lambda v: (v['kind'], v['name']))


def target_identity():
    require(re.fullmatch('[0-9a-f]{40}', REVISION) and re.fullmatch('[0-9a-f]{64}', SOURCE_SHA)
            and re.fullmatch('ghcr.io/publicdata-stream/dev-resources-server@sha256:[0-9a-f]{64}', IMAGE)
            and re.fullmatch('ghcr.io/publicdata-stream/dev-resources-probe@sha256:[0-9a-f]{64}', PROBE_IMAGE), 'target_pins_unqualified')
    return {'revision': REVISION, 'version': VERSION, 'server': IMAGE,
            'probe': PROBE_IMAGE,
            'source_url': SOURCE_URL, 'source_sha256': SOURCE_SHA, 'schema': 18}


def predecessor(context):
    require(digest(read(PRIOR_CONTROLLER)) == PRIOR_CONTROLLER_SHA, 'prior_controller_changed')
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location('frozen_wikipedia_65236494', PRIOR_CONTROLLER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.Activation(PRIOR_BUNDLE, context)


def instant(value):
    try:
        parsed = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
        require(parsed.tzinfo is not None and parsed.utcoffset() == dt.timedelta(0), 'utc_timestamp_required')
        return parsed
    except (ValueError, TypeError, AttributeError):
        raise Error('invalid_timestamp') from None


def compose_delta(raw):
    require(len(raw) == 5311 and digest(raw) == NEW_COMPOSE_SHA, 'current_compose_identity')
    text = raw.decode()
    index = text.index('\n{') + 1
    value = json.loads(text[index:])
    require(value['services']['oxibelt']['networks'].get('pdf2md-net') == {}
            and value['networks'].get('pdf2md-net') == {'driver': 'bridge', 'name': 'pdf2md-net'}, 'pdf_network_compose_delta')
    historical = copy.deepcopy(value)
    del historical['services']['oxibelt']['networks']['pdf2md-net']
    del historical['networks']['pdf2md-net']
    old_raw = (text[:index] + json.dumps(historical, indent=2)).encode()
    require(len(old_raw) == 5204 and digest(old_raw) == OLD_COMPOSE_SHA
            and raw == (text[:index] + json.dumps(value, indent=2) + '\n').encode(), 'historical_compose_reconstruction')


def public_config_read(path, size, sha):
    path = Path(path)
    require(path.is_absolute() and not any(p.is_symlink() for p in (path, *path.parents)), 'public_config_path')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and info.st_nlink == 1
                and info.st_size == size and not info.st_mode & 0o022 and size <= 65536, 'public_config_permissions')
        raw = stream.read(65537)
        require(len(raw) == size and digest(raw) == sha, 'public_config_identity')
    return raw


def normalized_conf_delta(historical, actual):
    old_tree, new_tree = historical['conf_tree'], actual['conf_tree']
    require(set(old_tree) == set(new_tree), 'unlisted_conf_tree_entry')
    normalized = copy.deepcopy(new_tree)
    for name, rule in CONF_FILE_RULES.items():
        before, after = old_tree[name], new_tree[name]
        require(set(before) == set(after)
                and all(before[k] == v and after[k] == v for k, v in
                    {'uid': 0, 'gid': 0, 'mode': 0o644, 'device': 2305, 'inode': rule['inode'], 'kind': 'file'}.items())
                and before['size'] == rule['old_size'] and before['sha256'] == rule['old_sha']
                and after['size'] == rule['new_size'] and after['sha256'] == rule['new_sha']
                and after['mtime_ns'] == rule['new_mtime'], 'authorized_conf_file_delta')
        if 'old_mtime' in rule:
            require(before['mtime_ns'] == rule['old_mtime'], 'historical_tls_metadata_changed')
        expected = copy.deepcopy(before)
        expected.update(size=rule['new_size'], sha256=rule['new_sha'], mtime_ns=rule['new_mtime'])
        require(after == expected, 'unlisted_conf_file_metadata')
        for key in ('size', 'sha256', 'mtime_ns'):
            normalized[name][key] = before[key]
    require(normalized == old_tree, 'unlisted_conf_tree_delta')
    contents = actual['conf_contents']
    require(set(contents) == {'20-proxy.toml', '40-compression.toml', '62-route-devres.toml'}
            and set(historical['conf_preimages']) == {'20-proxy.toml', '62-route-devres.toml'}, 'conf_content_set')
    current, prior = {}, {}
    for name, text in contents.items():
        raw = base64.b64decode(text, validate=True)
        rule = CONF_FILE_RULES[name]
        require(len(raw) == rule['new_size'] and digest(raw) == rule['new_sha'], 'current_conf_content_changed')
        current[name] = tomllib.loads(raw.decode())
    for name, text in historical['conf_preimages'].items():
        raw = base64.b64decode(text, validate=True)
        rule = CONF_FILE_RULES[name]
        require(len(raw) == rule['old_size'] and digest(raw) == rule['old_sha'], 'historical_conf_preimage_changed')
        prior[name] = tomllib.loads(raw.decode())
    expected_proxy = copy.deepcopy(prior['20-proxy.toml'])
    require(expected_proxy.pop('compression', None) == {'enabled': False}, 'historical_proxy_compression')
    require(encoded(current['20-proxy.toml']) == encoded(expected_proxy), 'unlisted_proxy_semantic_delta')
    expected_route = copy.deepcopy(prior['62-route-devres.toml'])
    require(expected_route['routes'][0]['compression'] == 'off', 'historical_route_compression')
    expected_route['routes'][0]['compression'] = 'default'
    require(encoded(current['62-route-devres.toml']) == encoded(expected_route), 'unlisted_route_semantic_delta')
    # Original 40-compression bytes are unavailable. Preserve its historical hash
    # and independently verify the explicitly approved complete current policy.
    require(encoded(current['40-compression.toml']) == encoded(CURRENT_COMPRESSION), 'current_compression_policy_changed')
    return normalized


def normalized_edge_delta(historical, actual, compose_raw):
    """Validate the complete difference, then reverse only the admitted fields."""
    compose_delta(compose_raw)
    old, new = historical['edge'], actual['edge']
    require(old['id'] == OLD_EDGE_ID and new == {'id': NEW_EDGE_ID, 'pid': 1898071,
        'pid_start_ticks': '12826648', 'started': '2026-11-14T12:18:56.706543666Z',
        'restarts': 0, 'image': EDGE_IMAGE} and old['image'] == EDGE_IMAGE and old['restarts'] == 0,
        'authorized_edge_process_delta')
    normalized_process = copy.deepcopy(new)
    for key in ('id', 'pid', 'pid_start_ticks', 'started'):
        normalized_process[key] = old[key]
    require(normalized_process == old, 'unexpected_edge_process_delta')
    before, after = historical['docker'], actual['docker']
    require(before['id'] == OLD_EDGE_ID and after['id'] == NEW_EDGE_ID
            and before['image'] == after['image'] == EDGE_IMAGE
            and before['restart_count'] == after['restart_count'] == 0, 'authorized_edge_container_delta')
    normalized_docker = copy.deepcopy(after)
    normalized_docker['id'] = before['id']
    require(before['config']['Hostname'] == OLD_EDGE_ID[:12]
            and after['config']['Hostname'] == NEW_EDGE_ID[:12], 'edge_hostname_delta')
    normalized_docker['config']['Hostname'] = before['config']['Hostname']
    for key, old_value, new_value in (
            ('com.docker.compose.config-hash', OLD_COMPOSE_CONFIG, NEW_COMPOSE_CONFIG),
            ('com.docker.compose.version', '5.7.0', '5.7.1')):
        require(before['config']['Labels'].get(key) == old_value
                and after['config']['Labels'].get(key) == new_value, 'compose_runtime_label_delta')
        normalized_docker['config']['Labels'][key] = old_value
    for key in ('Dns', 'DnsOptions', 'DnsSearch'):
        require(before['host_config'].get(key) == [] and key in after['host_config']
                and after['host_config'][key] is None, 'compose_dns_default_delta')
        normalized_docker['host_config'][key] = []
    require(set(before['networks']) == {'devres-net'}
            and set(after['networks']) == {'devres-net', 'pdf2md-net'}
            and after['networks']['pdf2md-net'] == PDF_NETWORK, 'edge_network_set_delta')
    old_network, new_network = before['networks']['devres-net'], after['networks']['devres-net']
    require(old_network['MacAddress'] == OLD_DEVRES_MAC and new_network['MacAddress'] == NEW_DEVRES_MAC
            and old_network['DNSNames'] == ['oxibelt', OLD_EDGE_ID[:12]]
            and new_network['DNSNames'] == ['oxibelt', NEW_EDGE_ID[:12]], 'edge_devres_endpoint_delta')
    normalized_docker['networks']['devres-net']['MacAddress'] = OLD_DEVRES_MAC
    normalized_docker['networks']['devres-net']['DNSNames'] = old_network['DNSNames']
    del normalized_docker['networks']['pdf2md-net']
    require(normalized_docker == before, 'unlisted_edge_docker_delta')
    old_files, new_files = historical['files'], actual['files']
    require(set(new_files) == set(old_files) and EDGE_COMPOSE in old_files, 'edge_base_file_set')
    old_compose, new_compose = old_files[EDGE_COMPOSE], new_files[EDGE_COMPOSE]
    require(old_compose['sha256'] == OLD_COMPOSE_SHA and old_compose['size'] == 5204
            and new_compose['sha256'] == NEW_COMPOSE_SHA and new_compose['size'] == 5311,
            'compose_file_metadata_identity')
    require(set(old_compose) == set(new_compose)
            and all(new_compose[k] == v for k, v in old_compose.items()
                    if k not in ('inode', 'mtime_ns', 'size', 'sha256')), 'compose_file_security_changed')
    normalized_files = copy.deepcopy(new_files)
    for key in ('inode', 'mtime_ns', 'size', 'sha256'):
        normalized_files[EDGE_COMPOSE][key] = old_compose[key]
    require(normalized_files == old_files, 'unlisted_edge_file_delta')
    networks = actual['networks']
    require(set(networks) == set(NETWORK_IDS), 'edge_network_inventory')
    for name, subnet, gateway, mac, address in (
            ('devres-net', '10.0.0.0/16', '10.0.0.1', NEW_DEVRES_MAC, '10.0.0.3/16'),
            ('pdf2md-net', '172.19.0.0/16', '172.19.0.1', PDF_NETWORK['MacAddress'], '172.19.0.2/16')):
        value = networks[name]
        require(value['Name'] == name and value['Id'] == NETWORK_IDS[name]
                and value['Driver'] == 'bridge' and value['Scope'] == 'local'
                and value['EnableIPv6'] is False and value['Internal'] is False
                and value['ConfigOnly'] is False and value['Ingress'] is False
                and value['IPAM'] == {'Config': [{'Gateway': gateway, 'Subnet': subnet}], 'Driver': 'default', 'Options': None},
                'edge_network_identity')
        require(value.get('Options') == ({'com.docker.network.bridge.name': 'devres-edge0'} if name == 'devres-net' else {})
                and value.get('Labels') == {'com.docker.compose.config-hash': NETWORK_LABEL_HASHES[name],
                    'com.docker.compose.network': name, 'com.docker.compose.project': 'serve',
                    'com.docker.compose.version': '5.7.0' if name == 'devres-net' else '5.7.1'}, 'edge_network_policy_changed')
        member = value['edge_member']
        require(member['Name'] == 'oxibelt' and member['MacAddress'] == mac
                and member['IPv4Address'] == address and member['IPv6Address'] == ''
                and member['EndpointID'] == NETWORK_ENDPOINTS[name], 'edge_network_membership')
    return {'edge': normalized_process, 'docker': normalized_docker, 'files': normalized_files,
            'conf_tree': normalized_conf_delta(historical, actual)}


class Controller:
    def __init__(self, bundle, plan, context):
        require(str(Path(bundle)) == BUNDLE, 'fixed_bundle_required')
        self.root = Path(bundle)
        self.prior = Path(PRIOR_BUNDLE)
        self.context = context
        self.plan_raw = read(plan)
        self.plan = json.loads(self.plan_raw)
        require(set(self.plan) == {'version', 'context', 'store_binding_sha256', 'preserve_application_passwords', 'target', 'prior', 'inventory', 'edge_admission'}
                and self.plan.get('version') == 1 and self.plan.get('context') == context
                and self.plan.get('store_binding_sha256') == STORE_BINDING
                and self.plan.get('preserve_application_passwords') is True
                and self.plan.get('target') == target_identity(), 'plan_identity')
        self.activation = predecessor(context)
        self.base = self.activation.base
        self.module, self.old = self.base.module, self.base.old
        self.attach_edge_admission(self.plan['edge_admission'])


    def native_edge_snapshot(self):
        # Do not call Activation.edge_docker after adapting base.edge: that
        # method would attempt to inspect the retired historical container ID.
        edge = self.edge()
        value = json.loads(self.module.call(['docker', 'inspect', edge['id']]))[0]
        status = value['State']
        require(value['Id'] == edge['id'] and status['Running'] is True and not status.get('Dead')
                and not status.get('Paused') and not status.get('Restarting'), 'edge_not_running')
        keys = ('IPAddress', 'IPPrefixLen', 'Gateway', 'GlobalIPv6Address', 'GlobalIPv6PrefixLen',
                'IPv6Gateway', 'MacAddress', 'Aliases', 'DNSNames', 'IPAMConfig', 'DriverOpts', 'Links')
        docker = {'id': value['Id'], 'image': value['Image'], 'config': value['Config'], 'host_config': value['HostConfig'],
            'mounts': value['Mounts'], 'restart_count': value['RestartCount'], 'health': status.get('Health', {}).get('Status'),
            'networks': {name: {key: network.get(key) for key in keys}
                         for name, network in value['NetworkSettings']['Networks'].items()}, 'ports': value['NetworkSettings']['Ports']}
        inspected = json.loads(self.module.call(['docker', 'network', 'inspect', 'devres-net', 'pdf2md-net']))
        require(len(inspected) == 2, 'edge_network_inventory')
        networks = {n['Name']: {**{k: n.get(k) for k in NETWORK_FIELDS},
                    'edge_member': n.get('Containers', {}).get(edge['id'])} for n in inspected}
        files = self._native_edge_files()
        fd = os.open(EDGE_COMPOSE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                    and info.st_nlink == 1 and info.st_size == 5311 and not info.st_mode & 0o022, 'compose_public_file_bound')
            raw = stream.read(65537)
            require(len(raw) == info.st_size, 'compose_read_changed')
        require(files == self._native_edge_files(), 'edge_files_changed_during_read')
        conf_tree = self._native_conf_tree()
        conf_contents = {}
        for name in ('20-proxy.toml', '40-compression.toml', '62-route-devres.toml'):
            rule = CONF_FILE_RULES[name]
            body = public_config_read(EDGE_CONF / name, rule['new_size'], rule['new_sha'])
            conf_contents[name] = base64.b64encode(body).decode()
        require(conf_tree == self._native_conf_tree(), 'current_conf_tree_changed_during_read')
        return {'edge': edge, 'docker': docker, 'files': files, 'networks': networks,
                'conf_tree': conf_tree, 'conf_contents': conf_contents}, raw

    def historical_edge_snapshot(self, state, prepared):
        docker = copy.deepcopy(prepared['edge_docker'])
        if state.get('source_history') is not None:
            evidence = self.activation.source_history(state, prepared)
            docker['networks']['devres-net']['MacAddress'] = evidence['new_mac']
            require(state['edge'] == evidence['new_edge'], 'historical_edge_admission_changed')
        tree = copy.deepcopy(prepared['edge_conf_tree'])
        require(isinstance(state.get('new_conf'), dict) and not set(tree) & set(state['new_conf']), 'historical_conf_tree_shape')
        tree.update(state['new_conf'])
        preimages = {}
        for name in ('20-proxy.toml', '62-route-devres.toml'):
            rule = CONF_FILE_RULES[name]
            body = public_config_read(Path(OLD_BUNDLE) / 'edge-conf' / name, rule['old_size'], rule['old_sha'])
            preimages[name] = base64.b64encode(body).decode()
        return {'edge': state['edge'], 'docker': docker, 'files': prepared['edge_base_files'],
                'conf_tree': tree, 'conf_preimages': preimages}

    def edge_admission_fresh(self, value):
        age = (utc_now() - instant(value.get('observed_at'))).total_seconds()
        require(-5 <= age <= 300, 'edge_admission_stale')

    def attach_edge_admission(self, reference, value=None):
        if not hasattr(self, '_native_edge_files'):
            self._native_edge_files = self.activation.edge_files
        if not hasattr(self, '_native_conf_tree'):
            self._native_conf_tree = self.activation.conf_tree
        self.edge_admission_reference = reference
        if reference is not None:
            require(set(reference) == {'path', 'sha256'} and Path(reference['path']).parent == Path(WORK), 'edge_admission_reference')
            raw = read(reference['path'])
            require(digest(raw) == reference['sha256'], 'edge_admission_hash')
            value = json.loads(raw)
        require(isinstance(value, dict), 'edge_admission_required')
        self.edge_admission_value = value
        self.verify_edge_admission()
        # These adapters reverse only the delta validated in full immediately
        # before each use. New-controller snapshots continue using native edge().
        self.activation.edge_files = lambda: self.verify_edge_admission()['files']
        self.activation.edge_docker = lambda: self.verify_edge_admission()['docker']
        self.activation.conf_tree = lambda: self.verify_edge_admission()['conf_tree']
        self.base.edge = lambda: self.verify_edge_admission()['edge']

    def verify_edge_admission(self):
        value = self.edge_admission_value
        if self.edge_admission_reference is not None:
            require(digest(read(self.edge_admission_reference['path'])) == self.edge_admission_reference['sha256'], 'edge_admission_changed')
        require(value.get('version') == 1 and value.get('kind') == 'explicit-pdf2md-compression-edge-admission'
                and value.get('revision') == REVISION and value.get('verified') is True
                and value.get('controller_sha256') == digest(Path(__file__).read_bytes())
                and value.get('predecessor_controller_sha256') == PRIOR_CONTROLLER_SHA
                and digest(read(PRIOR_CONTROLLER)) == PRIOR_CONTROLLER_SHA
                and digest(read(self.prior / 'prepared.json')) == value.get('predecessor_prepared_sha256')
                and digest(encoded(value['historical_state'])) == value.get('predecessor_state_sha256'), 'edge_admission_identity')
        expected = copy.deepcopy(value['historical_state'])
        if (self.root / 'state.json').exists():
            state = self.state()
            if state['chain_phase'] is not None:
                expected.update(upgrade_successor=str(self.root), upgrade_successor_phase=state['chain_phase'])
        require(self.activation.state() == expected, 'edge_admission_predecessor_changed')
        require(self.boot() == value['boot'], 'edge_admission_boot_changed')
        require(value.get('native_check', {}).get('verified') is True
                and value['native_check'].get('container') == NEW_EDGE_ID
                and re.fullmatch('[a-f0-9]{64}', value['native_check'].get('stdout_sha256', '')), 'edge_admission_native_check')
        historical = self.historical_edge_snapshot(value['historical_state'], load(self.prior / 'prepared.json'))
        require(historical == value['historical'], 'edge_admission_history_changed')
        actual, raw = self.native_edge_snapshot()
        require(actual == value['actual'], 'admitted_current_edge_changed')
        return normalized_edge_delta(historical, actual, raw)

    def admit_edge(self, path):
        require(not self.root.exists() and Path(path).is_absolute() and Path(path).parent == Path(WORK), 'edge_admission_output')
        self._native_edge_files = self.activation.edge_files
        self._native_conf_tree = self.activation.conf_tree
        save(str(path) + '.intent.json', {'version': 1, 'operation': 'admit-edge', 'at': stamp(),
             'maximum_attempts': 1, 'controller_sha256': digest(Path(__file__).read_bytes())})
        self.safety()
        state = self.activation.state()
        require(state['phase'] == 'enabled' and state['edge_phase'] == 'published'
                and not state.get('upgrade_successor'), 'edge_admission_predecessor_phase')
        prepared = load(self.prior / 'prepared.json')
        historical = self.historical_edge_snapshot(state, prepared)
        actual, raw = self.native_edge_snapshot()
        normalized_edge_delta(historical, actual, raw)
        # Check current actual mounts/configuration in the running native image;
        # preserve the historical check artifact byte-for-byte.
        output = self.module.call(['docker', 'exec', actual['edge']['id'], '/usr/local/bin/oxibelt',
            '--config', '/etc/oxibelt/config/oxibelt.toml', '--check'], timeout=45)
        value = {'version': 1, 'kind': 'explicit-pdf2md-compression-edge-admission', 'revision': REVISION,
            'controller_sha256': digest(Path(__file__).read_bytes()), 'predecessor_controller_sha256': PRIOR_CONTROLLER_SHA,
            'predecessor_state_sha256': digest(read(self.prior / 'state.json')),
            'predecessor_prepared_sha256': digest(read(self.prior / 'prepared.json')),
            'historical_state': state, 'historical': historical, 'actual': actual, 'boot': self.boot(),
            'observed_at': stamp(), 'verified': True,
            'native_check': {'verified': True, 'container': actual['edge']['id'], 'stdout_sha256': digest(output)}}
        self.attach_edge_admission(None, value)
        self.activation.guard()
        self.verify_edge_admission()
        self.edge_admission_fresh(value)
        save(path, value)
        save(str(path) + '.completed.json', {'version': 1, 'known_complete': True, 'sha256': digest(encoded(value))})

    @contextlib.contextmanager
    def locked(self):
        with self.module.bundle_lock(self.old.bundle):
            with self.module.bundle_lock(self.old.bundle, '.certificate.lock'):
                yield

    def state(self):
        value = load(self.root / 'state.json')
        require(value['revision'] == REVISION and value['plan_sha256'] == digest(self.plan_raw)
                and value['source_sha256'] == digest(Path(__file__).read_bytes()), 'journal_identity')
        require(value.get('version') == 1 and value.get('configs') in ('old', 'paused', 'active')
                and value.get('chain_phase') in (None, 'runtime_upgrade_stopped', 'runtime_upgraded')
                and set(value.get('images', {})) == {'postgres', 'writer', 'backend'}
                and value['images']['postgres'] == PG_IMAGE
                and all(value['images'][role] in (OLD_IMAGE, IMAGE) for role in ('writer', 'backend'))
                and set(value.get('replicas', {})) == {'postgres', 'writer', 'backend'}
                and value['replicas']['postgres'] == 1
                and all(type(value['replicas'][role]) is int and value['replicas'][role] in (0, 1) for role in ('writer', 'backend'))
                and set(value.get('pods', {})) == {role for role, count in value['replicas'].items() if count}, 'journal_shape')
        return value

    def record(self, value):
        save(self.root / 'state.json', value, replace=True)

    def get(self, kind, name):
        return json.loads(self.old.k('get', kind, name, '-o', 'json'))

    def pods(self):
        values = json.loads(self.old.k('get', 'pods', '-o', 'json'))['items']
        images = (self.state()['images'] if (self.root / 'state.json').exists()
                  else {'postgres': PG_IMAGE, 'writer': OLD_IMAGE, 'backend': OLD_IMAGE})
        result = {}
        for name in ('postgres', 'writer', 'backend'):
            selected = [v for v in values if v['metadata'].get('labels', {}).get('app') == name]
            require(len(selected) <= 1, 'multiple_role_pods')
            if selected:
                spec = selected[0]['spec']
                require(len(spec['containers']) == 1 and spec['containers'][0]['image'] == images[name]
                        and spec.get('nodeName') == self.old.settings()['node_name'], 'pod_image_or_node_changed')
                result[name] = pod_projection(selected[0])
        require('postgres' in result, 'postgres_missing')
        require(len(values) == len(result), 'unexpected_namespace_pod')
        return result

    def edge(self):
        ids = self.module.call(['docker', 'compose', '-f', '/serve/docker-compose.yml', 'ps', '-q', 'oxibelt']).decode().split()
        require(len(ids) == 1, 'one_edge_required')
        value = json.loads(self.module.call(['docker', 'inspect', ids[0]]))[0]
        require(value['State']['Running'] and value['State']['Pid'] > 0, 'edge_not_running')
        pid = value['State']['Pid']
        fields = Path('/proc/' + str(pid) + '/stat').read_text().rsplit(')', 1)[1].split()
        require(len(fields) > 19 and fields[19].isdigit(), 'edge_process_identity')
        return {'id': value['Id'], 'pid': pid, 'pid_start_ticks': fields[19], 'started': value['State']['StartedAt'],
                'restarts': value['RestartCount'], 'image': value['Image']}

    def foundation(self):
        raw = self.old.k('get', 'networkpolicies,roles,rolebindings,serviceaccounts,services,persistentvolumeclaims', '-o', 'json')
        return foundation_projection(json.loads(raw)['items'])

    def profiles(self):
        result = {}
        for name in PROFILES:
            path = Path(name)
            require(not any(p.is_symlink() for p in (path, *path.parents)), 'profile_symlink')
            info = path.stat()
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022, 'unsafe_profile')
            require(info.st_size <= 65536, 'profile_bound')
            raw = path.read_bytes()
            require(digest(raw) == PROFILE_SHA, 'edge_profile_changed')
            result[name] = raw
        return result

    def boot(self):
        boot_id = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        require(re.fullmatch('[a-f0-9-]{36}', boot_id), 'boot_identity')
        values = [line.split()[1] for line in Path('/proc/stat').read_text().splitlines() if line.startswith('btime ')]
        require(len(values) == 1 and values[0].isdigit(), 'boot_time')
        return {'boot_id': boot_id, 'boot_at': dt.datetime.fromtimestamp(int(values[0]), dt.timezone.utc).isoformat()}

    def prior_artifacts(self):
        paths = {'state': self.prior / 'state.json', 'prepared': self.prior / 'prepared.json',
                 'controller': Path(PRIOR_CONTROLLER), 'active': self.prior / 'configs-enabled.json',
                 'route': self.prior / 'route-candidate.toml', 'cidrs': self.prior / 'cidr-candidate.json',
                 'edge_check': self.prior / 'edge-config-check.json',
                 'cidr_receipt': self.prior / 'cidr-activation-receipt.json',
                 'cidr_validation': self.prior / 'cidr-activation-validation.json'}
        state = self.activation.state()
        if state.get('source_history') is not None:
            for name in ('resume-pre-state.json', 'edge-mac-admission.json', 'resume-approval.json', 'source-adoption.json'):
                paths[name] = self.prior / name
        return {name: {'path': str(path), 'sha256': digest(read(path))} for name, path in paths.items()}

    def admitted_prior(self, expected=None, allow_successor=False):
        artifacts = self.prior_artifacts()
        if expected is not None:
            require(set(artifacts) == set(expected), 'prior_artifact_set')
            for name, actual in artifacts.items():
                require(actual['path'] == expected[name]['path'], 'prior_artifact_path')
                if name != 'state' or not allow_successor:
                    require(actual['sha256'] == expected[name]['sha256'], 'prior_artifact_changed')
        require(artifacts['controller']['sha256'] == PRIOR_CONTROLLER_SHA, 'prior_controller_changed')
        state = self.activation.state()
        prepared = load(self.prior / 'prepared.json')
        require(state.get('revision') == PRIOR_REVISION and state.get('phase') == 'enabled'
                and state.get('configs') == 'enabled' and state.get('edge_phase') == 'published'
                and state.get('base_link_phase') == 'wikipedia_enabled'
                and state.get('source_sha256') == PRIOR_CONTROLLER_SHA
                and state.get('prepared_sha256') == artifacts['prepared']['sha256']
                and state.get('replicas') == {'postgres': 1, 'writer': 1, 'backend': 1}, 'prior_state_identity')
        require(allow_successor or not state.get('upgrade_successor'), 'prior_successor_exists')
        require(prepared.get('revision') == PRIOR_REVISION and prepared.get('kind') == 'wikipedia-activation'
                and prepared.get('enabled_config_sha256') == artifacts['active']['sha256'], 'prior_prepared_identity')
        # Preserve the independently admitted original -> upgrade -> activation chain.
        self.activation.admit()
        require(self.activation.artifact_hashes() == prepared['base_artifacts'], 'historical_artifact_changed')
        self.activation.cidr_copies(prepared, state)
        self.activation.edge_guard(prepared, state)
        return artifacts, state, prepared, {}

    def safety(self):
        # The frozen activation is the live predecessor; its pre-Wikipedia guard
        # cannot be reused after its deliberately admitted configuration changes.
        self.base.safety()
        prepared = load(self.prior / 'prepared.json')
        require(self.activation.artifact_hashes() == prepared['base_artifacts'], 'historical_artifact_changed')
        self.activation.admit()

    def snapshot(self):
        deployments = {}
        for name in ('postgres', 'writer', 'backend'):
            obj = self.get('deployment', name)
            projection, image = deployment_projection(obj)
            deployments[name] = {'projection': projection, 'image': image, 'replicas': obj['spec'].get('replicas', 1)}
        # Freeze every namespace Secret, including any separately mounted identity.
        secrets = json.loads(self.old.k('get', 'secrets', '-o', 'json'))['items']
        return {'boot': self.boot(), 'deployments': deployments,
                'secrets': {value['metadata']['name']: secret_projection(value) for value in secrets},
                'pods': self.pods(), 'edge': self.edge(), 'foundation': self.foundation(),
                'edge_conf_tree': self._native_conf_tree() if hasattr(self, '_native_conf_tree') else None,
                'profiles': {name: digest(raw) for name, raw in self.profiles().items()}}

    def boundary_before_prepare(self, snapshot, prior_state, prior_prepared, completion):
        # Admission must prove the currently enabled/published Wikipedia state.
        self.activation.guard()
        require(set(snapshot['pods']) == {'postgres', 'writer', 'backend'}
                and snapshot['pods'] == prior_state['pods'], 'prior_process_changed')
        admitted = self.activation.snapshot()
        for key in ('boot', 'foundation', 'profiles', 'deployments', 'pods'):
            require(snapshot[key] == admitted[key], 'prior_runtime_changed')
        require(snapshot['edge'] == self.edge_admission_value['actual']['edge']
                and admitted['edge'] == self.edge_admission_value['historical']['edge']
                and snapshot['edge_conf_tree'] == self.edge_admission_value['actual']['conf_tree'], 'admitted_edge_projection')
        require(all(snapshot['secrets'].get(name) == value for name, value in admitted['secrets'].items()),
                'prior_secret_boundary_changed')
        require(snapshot['deployments']['postgres']['image'] == PG_IMAGE
                and all(snapshot['deployments'][role]['image'] == OLD_IMAGE for role in ROLES), 'old_image_identity')

    def guard(self, pg_rebind=None):
        self.safety()
        if not self.root.exists():
            self.admitted_prior(self.plan['prior'])
            return
        state = self.state()
        prepared = load(self.root / 'prepared.json')
        require(digest(read(self.root / 'prepared.json')) == state['prepared_sha256'], 'prepared_changed')
        if hasattr(self, 'edge_admission_reference'):
            require(prepared.get('edge_admission') == self.edge_admission_reference
                    and prepared.get('edge_conf_tree') == self._native_conf_tree(), 'prepared_edge_admission_changed')
        self.admitted_prior(prepared['prior_artifacts'], allow_successor=True)
        expected_prior = copy.deepcopy(prepared['prior_state'])
        if state['chain_phase'] is not None:
            expected_prior.update(upgrade_successor=str(self.root), upgrade_successor_phase=state['chain_phase'])
        require(load(self.prior / 'state.json') == expected_prior, 'prior_chain_changed')
        require(self.boot() == prepared['boot'], 'boot_changed')
        require(self.edge() == prepared['edge'] and self.foundation() == prepared['foundation']
                and {name: digest(raw) for name, raw in self.profiles().items()} == prepared['profiles'], 'protected_runtime_changed')
        for name in ('postgres', 'writer', 'backend'):
            current = self.get('deployment', name)
            projection, image = deployment_projection(current)
            require(projection == prepared['deployments'][name]['projection'], 'deployment_boundary_changed')
            require(image == state['images'][name] and current['spec'].get('replicas', 1) == state['replicas'][name], 'deployment_state_changed')
        current_secrets = json.loads(self.old.k('get', 'secrets', '-o', 'json'))['items']
        require({v['metadata']['name'] for v in current_secrets} == set(prepared['secrets']), 'namespace_secret_set_changed')
        for name, original in prepared['secrets'].items():
            current = secret_projection(self.get('secret', name))
            expected = copy.deepcopy(original)
            for role, (secret, key) in ROLES.items():
                if name == secret and state['configs'] != 'old':
                    configs = load(self.root / ('configs-' + state['configs'] + '.json'))
                    require(digest(read(self.root / ('configs-' + state['configs'] + '.json'))) == prepared['config_hashes'][state['configs']], 'candidate_changed')
                    expected['data'][key] = base64.b64encode(configs[role].encode()).decode()
            require(current == expected, 'secret_boundary_changed')
        require(self.module.read_json(self.old.bundle / 'state.json') == prepared['old_anchor'], 'original_anchor_changed')
        expected_pods = copy.deepcopy(state['pods'])
        if pg_rebind is not None:
            require(state['phase'] == 'stopped' and set(expected_pods) == {'postgres'}, 'pg_rebind_phase')
            expected_pods['postgres'] = pg_rebind
        require(self.pods() == expected_pods, 'process_identity_changed')

    def capture(self, inventory_path, plan_path):
        require(not self.root.exists(), 'bundle_already_exists')
        require(Path(inventory_path).is_absolute() and Path(inventory_path).parent == Path(WORK)
                and Path(plan_path).is_absolute() and Path(plan_path).parent == Path(WORK)
                and Path(inventory_path) != Path(plan_path), 'capture_output_path')
        require(not any(p.is_symlink() for p in (Path(WORK), *Path(WORK).parents)), 'symlink_refused')
        work = Path(WORK).stat()
        require(stat.S_ISDIR(work.st_mode) and work.st_uid == os.geteuid()
                and not work.st_mode & 0o077, 'unsafe_private_directory')
        self.edge_admission_fresh(self.edge_admission_value)
        self.safety()
        self.activation.guard()
        self.old.admit_storage_receipt()
        artifacts, state, prepared, completion = self.admitted_prior()
        snapshot = self.snapshot()
        self.boundary_before_prepare(snapshot, state, prepared, completion)
        require(self.snapshot() == snapshot, 'capture_runtime_changed')
        inventory = {'version': 1, 'revision': REVISION, 'context': self.context,
                     'captured_at': stamp(), 'snapshot': snapshot, 'edge_admission': self.edge_admission_reference}
        plan = {'version': 1, 'context': self.context, 'store_binding_sha256': STORE_BINDING,
                'preserve_application_passwords': True, 'target': target_identity(), 'prior': artifacts,
                'inventory': {'path': str(inventory_path), 'sha256': digest(encoded(inventory))},
                'edge_admission': self.edge_admission_reference}
        save(inventory_path, inventory)
        save(plan_path, plan)

    def prepare(self):
        require(not self.root.exists() and not self.root.is_symlink(), 'bundle_already_exists')
        self.edge_admission_fresh(self.edge_admission_value)
        self.guard()
        self.activation.guard()
        self.old.admit_storage_receipt()
        inventory_raw = read(self.plan['inventory']['path'])
        require(digest(inventory_raw) == self.plan['inventory']['sha256'], 'inventory_changed')
        inventory = json.loads(inventory_raw)
        require(inventory.get('version') == 1 and inventory.get('revision') == REVISION
                and inventory.get('context') == self.context
                and inventory.get('edge_admission') == self.plan['edge_admission'], 'inventory_identity')
        age = (dt.datetime.now(dt.timezone.utc) - instant(inventory.get('captured_at'))).total_seconds()
        require(-5 <= age <= 300, 'inventory_stale')
        artifacts, prior_state, prior_prepared, completion = self.admitted_prior(self.plan['prior'])
        snapshot = self.snapshot()
        require(snapshot == inventory['snapshot'], 'inventory_runtime_changed')
        self.boundary_before_prepare(snapshot, prior_state, prior_prepared, completion)
        pods = snapshot['pods']
        deployments = {}
        for name in ('postgres', 'writer', 'backend'):
            obj = self.get('deployment', name)
            projection, image = deployment_projection(obj)
            require(snapshot['deployments'][name] == {'projection': projection, 'image': image, 'replicas': obj['spec'].get('replicas', 1)}, 'prepare_runtime_changed')
            deployments[name] = {'projection': projection, 'manifest': obj}
        secrets = snapshot['secrets']
        configs = {'paused': {}, 'active': {}}
        for role, (name, key) in ROLES.items():
            old_text = base64.b64decode(secrets[name]['data'][key], validate=True).decode()
            for variant in configs:
                configs[variant][role] = configuration(old_text, variant == 'active')
        prepared = {'version': 1, 'revision': REVISION, 'at': stamp(), 'deployments': deployments,
                    'secrets': secrets, 'edge': snapshot['edge'], 'foundation': snapshot['foundation'], 'boot': snapshot['boot'],
                    'old_anchor': self.module.read_json(self.old.bundle / 'state.json'), 'profiles': snapshot['profiles'],
                    'edge_conf_tree': snapshot['edge_conf_tree'],
                    'old_pods': pods, 'store_binding_sha256': STORE_BINDING,
                    'prior_artifacts': artifacts, 'prior_state': prior_state, 'edge_admission': self.edge_admission_reference,
                    'config_hashes': {key: digest(encoded(value)) for key, value in configs.items()}}
        require(self.snapshot() == snapshot, 'prepare_runtime_changed')
        self.module.safe_directory(self.root.parent, create=True)
        self.root.mkdir(mode=0o700)
        syncdir(self.root.parent)
        save(self.root / 'plan.json', self.plan_raw)
        for key, value in configs.items():
            save(self.root / ('configs-' + key + '.json'), value)
        for index, raw in enumerate(self.profiles().values()):
            save(self.root / ('profile-' + str(index) + '.toml'), raw)
        save(self.root / 'prepared.json', prepared)
        state = {'version': 1, 'revision': REVISION, 'phase': 'prepared', 'chain_phase': None,
                 'plan_sha256': digest(self.plan_raw), 'source_sha256': digest(Path(__file__).read_bytes()),
                 'prepared_sha256': digest(encoded(prepared)), 'images': {'postgres': PG_IMAGE, 'writer': OLD_IMAGE, 'backend': OLD_IMAGE},
                 'replicas': {'postgres': 1, 'writer': 1, 'backend': 1}, 'configs': 'old', 'pods': pods}
        save(self.root / 'state.json', state)
        self.guard()

    def chain_record(self, phase):
        require(phase in ('runtime_upgrade_stopped', 'runtime_upgraded'), 'chain_phase')
        self.guard()
        prepared = load(self.root / 'prepared.json')
        current = load(self.prior / 'state.json')
        updated = copy.deepcopy(current)
        updated.update(upgrade_successor=str(self.root), upgrade_successor_phase=phase)
        self.mutate('chain-' + phase, lambda: save(self.prior / 'state.json', updated, replace=True))
        state = self.state()
        state['chain_phase'] = phase
        self.record(state)

    def receipt_fresh(self, value):
        observed = instant(value.get('observed_at'))
        age = (utc_now() - observed).total_seconds()
        require(instant(load(self.root / 'prepared.json')['at']) <= observed and -5 <= age <= 300, 'receipt_stale')

    def receipt(self, path, sha, kind, checks):
        raw = read(path)
        require(re.fullmatch('[a-f0-9]{64}', sha or '') and digest(raw) == sha, 'receipt_hash')
        value = json.loads(raw)
        state = self.state()
        require(value.get('version') == 1 and value.get('kind') == kind
                and value.get('prepared_sha256') == state['prepared_sha256']
                and value.get('revision') == REVISION and value.get('verified') is True
                and value.get('store_binding_sha256') == STORE_BINDING, 'receipt_identity')
        require(all(value.get('checks', {}).get(key) is True for key in checks), 'receipt_checks')
        self.receipt_fresh(value)
        artifacts = value.get('artifacts', [])
        require(isinstance(artifacts, list) and artifacts, 'receipt_artifacts_required')
        for item in artifacts:
            # Large backup artifacts are verified streaming without loading or exporting them.
            path = Path(item['path'])
            require(path.is_absolute() and not any(p.is_symlink() for p in (path, *path.parents)), 'artifact_path')
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            h = hashlib.sha256()
            with os.fdopen(fd, 'rb') as stream:
                info = os.fstat(stream.fileno())
                require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                        and not info.st_mode & 0o077 and info.st_nlink == 1 and info.st_size > 0, 'artifact_private')
                for block in iter(lambda: stream.read(1024**2), b''):
                    h.update(block)
            require(h.hexdigest() == item['sha256'], 'artifact_changed')
        self.receipt_fresh(value)
        return value, raw

    def approval(self, path, sha, operation):
        raw = read(path)
        require(digest(raw) == sha, 'approval_hash')
        value = json.loads(raw)
        state = self.state()
        require(value == {'version': 1, 'operation': operation, 'reviewed': True,
                          'source_sha256': state['source_sha256'], 'prepared_sha256': state['prepared_sha256']}, 'approval_binding')

    def mutate(self, label, function):
        path = self.root / (label + '-intent.json')
        save(path, {'version': 1, 'label': label, 'at': stamp(), 'maximum_attempts': 1})
        function()
        save(self.root / (label + '-completed.json'), {'known': True, 'at': stamp()})

    def scale(self, name, count, label):
        self.guard()
        before = self.state()
        require(name in ('writer', 'backend'), 'postgres_scaling_refused')
        require(name in before['replicas'] and count in (0, 1)
                and before['replicas'][name] == 1 - count, 'scale_transition')
        require(self.pods() == before['pods'], 'scale_preimage_process_changed')
        current = self.get('deployment', name)
        prepared = load(self.root / 'prepared.json')
        projection, image = deployment_projection(current)
        require(projection == prepared['deployments'][name]['projection'] and image == before['images'][name]
                and current['spec'].get('replicas', 1) == before['replicas'][name], 'scale_preimage_deployment_changed')
        patch = [{'op': 'test', 'path': '/metadata/uid', 'value': current['metadata']['uid']},
                 {'op': 'test', 'path': '/metadata/resourceVersion', 'value': current['metadata']['resourceVersion']},
                 {'op': 'replace', 'path': '/spec/replicas', 'value': count}]
        def execute():
            self.old.k('patch', 'deployment', name, '--type=json', '-p', json.dumps(patch))
            if count:
                self.old.k('rollout', 'status', 'deployment/' + name, '--timeout=180s', timeout=210, request_timeout=190)
            else:
                self.old.k('wait', '--for=delete', 'pod', '-l', 'app=' + name, '--timeout=180s', timeout=210, request_timeout=190)
        self.mutate(label, execute)
        current_pods = self.pods()
        expected_roles = set(before['pods']) - {name}
        if count:
            expected_roles.add(name)
        require(set(current_pods) == expected_roles, 'scale_result_role_set')
        require(all(current_pods[role] == projection for role, projection in before['pods'].items() if role != name),
                'unrelated_role_process_changed')
        state = self.state()
        require(state == before, 'scale_journal_changed')
        state['replicas'][name] = count
        state['pods'] = current_pods
        self.record(state)

    def change_config(self, variant, label):
        self.guard()
        require(set(self.pods()) == {'postgres'}, 'config_requires_quiescent_roles')
        prepared = load(self.root / 'prepared.json')
        raw = read(self.root / ('configs-' + variant + '.json'))
        require(digest(raw) == prepared['config_hashes'][variant], 'candidate_changed')
        configs = json.loads(raw)
        for role, (name, key) in ROLES.items():
            require(self.pods() == self.state()['pods'], 'config_process_changed')
            obj = self.get('secret', name)
            expected = copy.deepcopy(prepared['secrets'][name])
            current_variant = self.state()['configs']
            if current_variant != 'old':
                previous_raw = read(self.root / ('configs-' + current_variant + '.json'))
                require(digest(previous_raw) == prepared['config_hashes'][current_variant], 'candidate_changed')
                expected['data'][key] = base64.b64encode(json.loads(previous_raw)[role].encode()).decode()
            require(secret_projection(obj) == expected, 'secret_preimage_changed')
            data = copy.deepcopy(obj['data'])
            data[key] = base64.b64encode(configs[role].encode()).decode()
            patch = [{'op': 'test', 'path': '/metadata/uid', 'value': obj['metadata']['uid']},
                     {'op': 'test', 'path': '/metadata/resourceVersion', 'value': obj['metadata']['resourceVersion']},
                     {'op': 'replace', 'path': '/data', 'value': data}]
            # Secret data is supplied on stdin, never in argv or diagnostic text.
            self.mutate(label + '-' + role, lambda n=name, p=patch: self.old.k('patch', 'secret', n, '--type=json', '--patch-file=/dev/stdin', data=encoded(p)))
            expected['data'] = data
            require(secret_projection(self.get('secret', name)) == expected, 'secret_patch_readback')
        state = self.state()
        state['configs'] = variant
        self.record(state)

    def run(self, operation, approval, approval_sha, receipt=None, receipt_sha=None):
        if operation == 'prepare':
            self.prepare()
            return
        self.approval(approval, approval_sha, operation)
        if operation == 'withdraw':
            self.withdraw()
            return
        state = self.state()
        phases = {'stop': 'prepared', 'apply': 'stopped', 'start-writer': 'applied',
                  'start-reader': 'writer_ready', 'runtime-ready': 'reader_ready',
                  'activate-existing': 'runtime_ready', 'finish': 'collectors_active'}
        require(state['phase'] == phases[operation], 'operation_phase')
        accepted = None
        if operation == 'apply':
            accepted, raw = self.receipt(receipt, receipt_sha, 'coordinated-schema15-backup',
                ('coordinated_pg_s3', 'old_clone_verified', 'roles_stopped', 'pg_restarted_without_restore', 'credentials_preserved'))
            require(accepted.get('recovery_scope') == 'physical_pg_checkpoint_original_immutable_s3_retained'
                    and accepted.get('independent_s3_backup') is False, 'backup_scope')
            require(accepted.get('schema') == 15 and re.fullmatch('[0-9]+', str(accepted.get('system_identifier', ''))), 'backup_schema_identity')
            require(accepted.get('old_pg_pod') == state['pods']['postgres'], 'backup_old_pg_identity')
            require(accepted.get('postgres_deployment_sha256') == digest(encoded(load(self.root / 'prepared.json')['deployments']['postgres']['projection'])), 'backup_pg_template')
            new_pg = accepted.get('new_pg_pod')
            require(isinstance(new_pg, dict) and new_pg.get('uid') and new_pg.get('container_id')
                    and new_pg.get('image_id') and new_pg.get('started_at'), 'backup_new_pg_identity')
            require(set(new_pg) == set(state['pods']['postgres'])
                    and new_pg['owner'] == state['pods']['postgres']['owner']
                    and new_pg['image_id'] == state['pods']['postgres']['image_id'], 'backup_pg_runtime_boundary')
            self.guard(pg_rebind=new_pg)
            require(set(self.pods()) == {'postgres'}, 'backup_roles_not_stopped')
            state['pods']['postgres'] = new_pg
            self.record(state)
            save(self.root / 'accepted-backup.json', raw)
        else:
            self.guard()
        if operation in ('start-reader', 'runtime-ready', 'activate-existing'):
            kind, checks = {
                'start-reader': ('migration18', ('schema18', 'policy2', 'sole_writer', 'new_table_reader_grants', 'history_preserved', 'archive_binding_preserved', 'historical_notices_preserved')),
                'runtime-ready': ('target-private-acceptance', ('schema18', 'policy2', 'sole_writer', 'read_only_serving', 'private_boundary', 'capture_notice_preserved', 'tool_contract98')),
                'activate-existing': ('target-activation-acceptance', ('schema18', 'policy2', 'sole_writer', 'private_boundary', 'public_http_both_families_revisions', 'public_wt_both_families_revisions', 'public_compression_gzip_br_zstd', 'capture_notice_preserved'))}[operation]
            accepted, raw = self.receipt(receipt, receipt_sha, kind, checks)
            require(accepted.get('schema') == 18, 'target_schema_receipt')
            save(self.root / ('accepted-' + operation + '.json'), raw)
        if operation == 'finish':
            accepted, raw = self.receipt(receipt, receipt_sha, 'target-observation-acceptance',
                ('schema18', 'policy2', 'sole_writer', 'read_only_serving', 'private_boundary',
                 'public_http_both_families_revisions', 'public_wt_both_families_revisions', 'public_compression_gzip_br_zstd',
                 'nine_source_settings_preserved', 'capture_notice_preserved', 'timers_preserved', 'stable_processes'))
            require(accepted.get('schema') == 18
                    and type(accepted.get('duration_seconds')) in (int, float) and accepted['duration_seconds'] >= 600
                    and type(accepted.get('sample_count')) is int and accepted['sample_count'] >= 21
                    and type(accepted.get('maximum_gap_seconds')) in (int, float)
                    and 0 < accepted['maximum_gap_seconds'] <= 45, 'observation_interval')
            save(self.root / 'accepted-observation.json', raw)
        # Artifact verification may be slow; repeat live protection immediately before dispatch.
        self.guard()
        if accepted is not None:
            self.receipt_fresh(accepted)
        state = self.state()
        state['phase'] = operation + '_incomplete'
        self.record(state)
        if operation == 'stop':
            self.scale('backend', 0, 'stop-backend')
            self.scale('writer', 0, 'stop-writer')
            require(set(self.pods()) == {'postgres'}, 'owner_remaining')
            self.chain_record('runtime_upgrade_stopped')
        elif operation == 'apply':
            self.change_config('paused', 'paused-config')
            for name in ('writer', 'backend'):
                self.guard()
                obj = self.get('deployment', name)
                patch = [{'op': 'test', 'path': '/metadata/uid', 'value': obj['metadata']['uid']},
                         {'op': 'test', 'path': '/metadata/resourceVersion', 'value': obj['metadata']['resourceVersion']},
                         {'op': 'test', 'path': '/spec/template/spec/containers/0/image', 'value': OLD_IMAGE},
                         {'op': 'replace', 'path': '/spec/template/spec/containers/0/image', 'value': IMAGE}]
                self.mutate('target-image-' + name, lambda n=name, p=patch: self.old.k('patch', 'deployment', n, '--type=json', '-p', json.dumps(p)))
                require(self.get('deployment', name)['spec']['template']['spec']['containers'][0]['image'] == IMAGE, 'image_readback')
                state = self.state()
                state['images'][name] = IMAGE
                self.record(state)
            self.chain_record('runtime_upgraded')
        elif operation == 'start-writer':
            self.scale('writer', 1, 'start-paused-writer')
        elif operation == 'start-reader':
            self.scale('backend', 1, 'start-paused-reader')
        elif operation == 'activate-existing':
            self.scale('backend', 0, 'activation-stop-backend')
            self.scale('writer', 0, 'activation-stop-writer')
            require(set(self.pods()) == {'postgres'}, 'owner_remaining')
            self.change_config('active', 'active-config')
            self.scale('writer', 1, 'activation-start-writer')
            self.scale('backend', 1, 'activation-start-backend')
        final = {'stop': 'stopped', 'apply': 'applied', 'start-writer': 'writer_ready',
                 'start-reader': 'reader_ready', 'runtime-ready': 'runtime_ready',
                 'activate-existing': 'collectors_active', 'finish': 'complete'}[operation]
        self.guard()
        state = self.state()
        state['phase'] = final
        state['updated_at'] = stamp()
        self.record(state)


    def withdraw(self):
        """Fence admitted application Deployments without restoring permanent data.

        This path accepts an interrupted phase/partial known config or image
        transition; it never adopts unrecognized templates or credential bytes.
        Failed/Pending Pods need not be ready to stop their owning Deployment.
        """
        state = self.state()
        prepared = load(self.root / 'prepared.json')
        require(digest(read(self.root / 'prepared.json')) == state['prepared_sha256'], 'prepared_changed')
        self.safety()
        self.admitted_prior(prepared['prior_artifacts'], allow_successor=True)
        expected_prior = copy.deepcopy(prepared['prior_state'])
        if state['chain_phase'] is not None:
            expected_prior.update(upgrade_successor=str(self.root), upgrade_successor_phase=state['chain_phase'])
        require(load(self.prior / 'state.json') == expected_prior, 'prior_chain_changed')
        require(self.boot() == prepared['boot'] and self.foundation() == prepared['foundation'], 'protected_runtime_changed')
        require(self.module.read_json(self.old.bundle / 'state.json') == prepared['old_anchor'], 'original_anchor_changed')
        for name, original in prepared['secrets'].items():
            current = secret_projection(self.get('secret', name))
            candidates = [copy.deepcopy(original)]
            for role, (secret, key) in ROLES.items():
                if name == secret:
                    for variant in ('paused', 'active'):
                        raw = read(self.root / ('configs-' + variant + '.json'))
                        require(digest(raw) == prepared['config_hashes'][variant], 'candidate_changed')
                        candidate = copy.deepcopy(original)
                        candidate['data'][key] = base64.b64encode(json.loads(raw)[role].encode()).decode()
                        candidates.append(candidate)
            require(current in candidates, 'secret_boundary_changed')
        for role in ('postgres', 'writer', 'backend'):
            obj = self.get('deployment', role)
            projection, image = deployment_projection(obj)
            require(projection == prepared['deployments'][role]['projection'], 'deployment_boundary_changed')
            require(image == PG_IMAGE if role == 'postgres' else image in (OLD_IMAGE, IMAGE), 'deployment_image_changed')
            require(type(obj['spec'].get('replicas')) is int and obj['spec']['replicas'] in (0, 1), 'deployment_replica_changed')
        state['phase'] = 'withdraw_incomplete'
        self.record(state)
        for role in ('backend', 'writer'):
            obj = self.get('deployment', role)
            patch = [{'op': 'test', 'path': '/metadata/uid', 'value': obj['metadata']['uid']},
                     {'op': 'test', 'path': '/metadata/resourceVersion', 'value': obj['metadata']['resourceVersion']},
                     {'op': 'replace', 'path': '/spec/replicas', 'value': 0}]
            self.mutate('withdraw-' + role, lambda r=role, p=patch:
                self.old.k('patch', 'deployment', r, '--type=json', '-p', json.dumps(p)))
            self.old.k('wait', '--for=delete', 'pod', '-l', 'app=' + role, '--timeout=180s', timeout=210, request_timeout=190)
            state = self.state()
            state['replicas'][role] = 0
            state['pods'].pop(role, None)
            self.record(state)
        require(not any(v['metadata'].get('labels', {}).get('app') in ROLES
                        for v in json.loads(self.old.k('get', 'pods', '-o', 'json'))['items']), 'application_pod_remaining')
        state = self.state()
        state['phase'] = 'withdrawn'
        state['updated_at'] = stamp()
        self.record(state)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--bundle', default=BUNDLE)
    parser.add_argument('--plan')
    parser.add_argument('--context', required=True)
    parser.add_argument('--inventory')
    parser.add_argument('--edge-admission')
    parser.add_argument('--edge-admission-sha256')
    parser.add_argument('--approval')
    parser.add_argument('--approval-sha256')
    parser.add_argument('--receipt')
    parser.add_argument('--receipt-sha256')
    parser.add_argument('operation', choices=('admit-edge', 'capture', 'prepare', 'stop', 'apply', 'start-writer', 'start-reader', 'runtime-ready', 'activate-existing', 'finish', 'withdraw'))
    args = parser.parse_args()
    try:
        require(os.geteuid() == 0, 'root_required')
        if args.operation in ('admit-edge', 'capture'):
            require(args.bundle == BUNDLE and args.edge_admission, 'edge_admission_inputs')
            require(args.operation == 'admit-edge' or (args.inventory and args.plan and args.edge_admission_sha256), 'capture_inputs')
            controller = Controller.__new__(Controller)
            controller.root = Path(BUNDLE)
            controller.prior = Path(PRIOR_BUNDLE)
            controller.context = args.context
            controller.activation = predecessor(args.context)
            controller.base = controller.activation.base
            controller.module, controller.old = controller.base.module, controller.base.old
            with controller.locked():
                if args.operation == 'admit-edge':
                    controller.admit_edge(Path(args.edge_admission))
                else:
                    controller.attach_edge_admission({'path': args.edge_admission, 'sha256': args.edge_admission_sha256})
                    controller.capture(Path(args.inventory), Path(args.plan))
            print(json.dumps({'operation': args.operation, 'known_complete': True, 'private_data_export_allowed': False}))
        else:
            require(args.plan, 'plan_required')
            controller = Controller(args.bundle, args.plan, args.context)
            with controller.locked():
                controller.run(args.operation, args.approval, args.approval_sha256, args.receipt, args.receipt_sha256)
            print(json.dumps({'operation': args.operation, 'phase': controller.state()['phase'], 'known_complete': True}))
    except Exception as error:
        # Never print subprocess output, private configuration, SQL URLs or exception repr.
        code = str(error) if isinstance(error, Error) and re.fullmatch('[a-z0-9_]+', str(error)) else 'upgrade_operation_failed'
        print(json.dumps({'operation': args.operation, 'known_complete': False, 'code': code}), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
