#!/usr/bin/env python3
"""Fixed private restored-MDN HTTP readback; no database writes or acquisition.

The operator pins this first-party reader and the existing retained baseline in
its protected attribution manifest. Credentials are read only from private TLS
files; neither arguments nor diagnostics contain them or retained source bodies.
"""
import base64
import hashlib
import http.client
import ipaddress
import json
from pathlib import Path
import re
import signal
import socket
import ssl
import sys
import urllib.parse

MODERN = '2026-07-28'
LEGACY = '2025-11-25'
MAX_RESPONSE = 8 * 1024 * 1024
RELEASE = '0.1.0-build.78c2e9c5'
BASELINE = Path('/usr/local/libexec/devres-staging-attribution/mdn-baseline.json')
BASELINE_SHA256 = 'd424de09bd6e859b0c252f9b9cc75b3edc01692b43b452a5e81d872718ba4cad'


def baseline():
    with BASELINE.open('rb') as stream:
        raw = stream.read(1024 * 1024 + 1)
    assert len(raw) <= 1024 * 1024 and hashlib.sha256(raw).hexdigest() == BASELINE_SHA256
    return json.loads(raw)


def decode_response(response, request_id):
    """Read one bounded JSON/SSE RPC response, without waiting for SSE EOF."""
    if response.getheader("content-type", "").startswith("text/event-stream"):
        remaining = MAX_RESPONSE
        while remaining > 0:
            line = response.readline(remaining + 1)
            remaining -= len(line)
            if remaining < 0:
                raise ValueError("response exceeds bound")
            if not line:
                break
            if line.startswith(b"data:"):
                value = json.loads(line[5:].strip())
                if value.get("id") == request_id:
                    return value
        raise ValueError("SSE response did not contain this request's result")
    raw = response.read(MAX_RESPONSE + 1)
    if len(raw) > MAX_RESPONSE:
        raise ValueError("response exceeds bound")
    return json.loads(raw) if raw else None

class Client:
    def __init__(self, url, ca=None, cert=None, key=None, origin="https://client.example"):
        self.url = urllib.parse.urlsplit(url)
        if self.url.scheme not in ("http", "https") or not self.url.hostname:
            raise ValueError("HTTP(S) URL required")
        self.context = ssl.create_default_context(cafile=ca)
        if cert:
            self.context.load_cert_chain(cert, key)
        self.origin = origin
        self.ident = 0
        self.timeout = 45

    def exchange(self, method, params=None, revision=MODERN, path=None, host=None, origin=None):
        self.ident += 1
        params = dict(params or {})
        if revision == MODERN:
            params.setdefault("_meta", {}).update({
                "io.modelcontextprotocol/protocolVersion": revision,
                "io.modelcontextprotocol/clientInfo": {"name": "devres-smoke", "version": "1"},
                "io.modelcontextprotocol/clientCapabilities": {},
            })
        body = {"jsonrpc": "2.0", "id": self.ident, "method": method, "params": params}
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                   "MCP-Protocol-Version": revision, "Origin": origin or self.origin}
        if host:
            headers["Host"] = host
        if revision == MODERN:
            headers["Mcp-Method"] = method
            if "name" in params:
                headers["Mcp-Name"] = params["name"]
            elif "uri" in params:
                headers["Mcp-Name"] = params["uri"]
        args = (self.url.hostname, self.url.port)
        connection = (http.client.HTTPSConnection(*args, context=self.context, timeout=self.timeout)
                      if self.url.scheme == "https" else http.client.HTTPConnection(*args, timeout=self.timeout))
        try:
            connection.request("POST", path or self.url.path or "/mcp", json.dumps(body), headers)
            response = connection.getresponse()
            status = response.status
            if response.getheader("content-type", "").startswith(("application/json", "text/event-stream")):
                value = decode_response(response, self.ident)
            else:
                response.read(MAX_RESPONSE + 1)
                value = None
            return status, value
        finally:
            connection.close()

    def call(self, method, params=None, revision=MODERN):
        status, value = self.exchange(method, params, revision)
        if status != 200 or not value or "error" in value:
            raise AssertionError(f"{method}: expected successful RPC, HTTP {status}")
        return value["result"]

    def tool(self, name, arguments, revision=MODERN):
        result = self.call("tools/call", {"name": name, "arguments": arguments}, revision)
        if result.get("isError"):
            error = result.get("structuredContent", {})
            # Server contract guarantees sanitized errors. Never log arguments,
            # entire response bodies, submitted lockfiles, or dependency graphs.
            raise AssertionError(f"tool {name} failed: {error.get('code')}: {error.get('message')}")
        return result.get("structuredContent", result)

POLICY = 'devres-attribution-v1:exact-reacquisition:member-scopes:readable-notices'
_NOTICE_CACHE = {}


def qualified(client, value, revision, resource=False):
    a = value['attribution']
    assert a['status'] == 'ready' and a['policy_epoch'] == 1
    assert a['policy_fingerprint'] == POLICY
    generations = a['generations']
    assert isinstance(generations, list) and 1 <= len(generations) <= 128
    uris, entries, seen = [], [], set()
    for generation in generations:
        identity = generation['id']
        assert re.fullmatch(r'blake3:[0-9a-f]{64}', identity)
        assert generation['subject']['provider'] in ('rfc', 'mdn')
        uri = 'devres://attribution/' + identity
        uris.append(uri)
        notices = generation['notices']
        assert isinstance(notices, list) and notices
        own = []
        own_seen = set()
        for notice in notices:
            assert isinstance(notice['text'], str) and notice['text'].strip()
            assert notice['source_url'].startswith('https://')
            entry = notice['source_url'] + '\n' + notice['text']
            if entry not in own_seen:
                own.append(entry); own_seen.add(entry)
            if entry not in seen:
                entries.append(entry); seen.add(entry)
        expected = '\n\n'.join(own).encode()
        assert 0 < len(expected) <= 4 * 1024 * 1024
        cache = (revision, uri)
        if cache in _NOTICE_CACHE:
            assert _NOTICE_CACHE[cache] == expected
            continue
        assert len(_NOTICE_CACHE) < 256
        content, offset = bytearray(), 0
        for _ in range(129):
            page = client.call('resources/read', {'uri':uri+'?offset='+str(offset)+'&limit=32768'}, revision)
            assert len(page['contents']) == 1
            item = page['contents'][0]; meta = item['_meta']; attr = meta['attribution']
            assert item['uri'] == uri and item['mimeType'] == 'text/plain'
            assert attr['id'] == identity and attr['subject'] == generation['subject'] and attr['policy_epoch'] == 1
            assert meta['offset'] == offset and meta['total_bytes'] == len(expected)
            chunk = item['text'].encode(); assert chunk
            content.extend(chunk); assert len(content) <= len(expected)
            following = meta['next_offset']
            if following is None:
                assert bytes(content) == expected
                _NOTICE_CACHE[cache] = expected
                break
            assert type(following) is int and following == len(content) and following > offset
            offset = following
        else:
            raise AssertionError('notice pagination bound exceeded')
    assert a['resource_uris'] == uris and a['resource_uri'] == uris[0]
    readable = '\n\n'.join(entries)
    assert a['readable_notice'] == readable
    if resource:
        assert len(value['contents']) == 2
        first, appended = value['contents']
        metadata = first['_meta']['attribution']
        assert metadata['status'] == 'ready' and metadata['policy_epoch'] == 1
        assert metadata['policy_fingerprint'] == POLICY and metadata['resource_uris'] == uris
        assert 'readable_notice' not in metadata
        assert appended == {'uri':uris[0], 'mimeType':'text/plain', 'text':readable}
    return value

def verify(client, operator):
    before = baseline()
    legacy = before['snapshot']
    projection = before['projection']
    assert re.fullmatch(r'[0-9a-f]{64}', legacy)
    assert re.fullmatch(r'[0-9a-f]{64}', projection)
    query = ("SELECT json_object_agg(namespace,canonical) FROM devres_content_aliases WHERE "
             "(namespace='mdn:snapshots' AND legacy='" + legacy + "') OR "
             "(namespace='mdn:projections' AND legacy='" + projection + "')")
    aliases = json.loads(operator.k('exec', 'deployment/postgres', '--', 'psql', '-X',
                                   '-U', 'devres_admin', '-d', 'devres', '-Atc', query))
    assert set(aliases) == {'mdn:snapshots', 'mdn:projections'}
    assert all(re.fullmatch(r'blake3:[0-9a-f]{64}', value) for value in aliases.values())
    canonical = aliases['mdn:snapshots']
    for revision in ('2026-07-28', '2025-11-25'):
        old = before['revisions'][revision]
        for snapshot in (legacy, canonical):
            for representation in ('text', 'bytes'):
                value = client.tool('mdn.get', {
                    'repository': 'content', 'snapshot': snapshot, 'path': before['path'],
                    'representation': representation, 'limit': 32768,
                }, revision)
                qualified(client, value, revision)
                expected = old[representation]
                for key in ('path', 'oid', 'source_url', 'gaps', 'license', 'representation'):
                    assert value[key] == expected[key], 'retained MDN metadata changed: ' + key
                assert value['snapshot'] == snapshot
                assert value['provenance']['snapshot'] == snapshot
                assert value['provenance']['revision'] == expected['provenance']['revision']
                page = value['page']
                for key in ('offset', 'next_offset', 'total_bytes'):
                    assert page[key] == expected['page'][key]
                if representation == 'text':
                    data = page['text']
                    assert data == expected['page']['text']
                else:
                    data = base64.b64decode(page['data'], validate=True)
                    assert data == base64.b64decode(expected['page']['data'], validate=True)
                result = client.call('resources/read', {'uri': value['resource_uri']}, revision)
                qualified(client, result, revision, resource=True)
                resource = result['contents'][0]
                assert resource['uri'] == value['resource_uri']
                observed = (resource['text'] if representation == 'text' else
                            base64.b64decode(resource['blob'], validate=True))
                assert observed == data, 'retained MDN resource content changed'
            found = client.tool('mdn.search', {
                'snapshot': snapshot, 'path': before['path'], 'limit': 1,
            }, revision)
            qualified(client, found, revision)
            assert found['total'] == 1 and len(found['results']) == 1
            item, expected = found['results'][0], old['search']['results'][0]
            for key in ('path', 'slug', 'title', 'snippet', 'kind', 'metadata'):
                assert item[key] == expected[key], 'retained MDN search changed: ' + key
            assert item['id'] == (projection if snapshot == legacy else aliases['mdn:projections'])
            assert found['snapshot'] == snapshot
        cutoff = old['history']['history_snapshot']
        frozen = client.tool('mdn.snapshots', {
            'repository': 'content', 'limit': 1, 'history_snapshot': cutoff,
        }, revision)
        qualified(client, frozen, revision)
        assert frozen['history_snapshot'] == cutoff
        assert frozen['results'] == old['history']['results'], 'frozen MDN history changed'
        current = client.tool('mdn.snapshots', {'repository': 'content', 'limit': 1}, revision)
        qualified(client, current, revision)
        assert current['results'] and all(
            re.fullmatch(r'blake3:[0-9a-f]{64}', value['id']) for value in current['results'])
    return {'mdn_retained': True, 'protocol_revisions': 2,
            'legacy_and_canonical': True, 'text_and_bytes_resources': True,
            'search': True, 'frozen_history': True}


class Aliases:
    def __init__(self, values):
        assert set(values) == {'mdn:snapshots', 'mdn:projections'}
        assert all(isinstance(v,str) and re.fullmatch(r'blake3:[0-9a-f]{64}',v) for v in values.values())
        self.values = values
    def k(self, *args):
        before = baseline()
        expected = ("SELECT json_object_agg(namespace,canonical) FROM devres_content_aliases WHERE "
                    "(namespace='mdn:snapshots' AND legacy='" + before['snapshot'] + "') OR "
                    "(namespace='mdn:projections' AND legacy='" + before['projection'] + "')")
        assert args == ('exec','deployment/postgres','--','psql','-X','-U','devres_admin','-d','devres','-Atc',expected)
        return json.dumps(self.values)


def main():
    assert len(sys.argv) == 1 and __debug__
    def deadline(_signum, _frame):
        raise TimeoutError('fixed_reader_deadline')
    signal.signal(signal.SIGALRM,deadline);signal.alarm(175)
    raw=sys.stdin.buffer.read(16385)
    assert len(raw)<=16384
    context=json.loads(raw)
    assert set(context)=={'ip','private_dir','release','baseline_sha256','mdn_aliases'}
    assert context['release']==RELEASE and context['baseline_sha256']==BASELINE_SHA256
    address=ipaddress.IPv4Address(context['ip'])
    assert str(address)==context['ip'] and address.is_private and not (address.is_loopback or address.is_multicast or address.is_unspecified or address.is_link_local)
    private=Path(context['private_dir']);assert private==Path('/etc/devres-staging')
    aliases=Aliases(context['mdn_aliases'])
    class PrivateClient(Client):
        def exchange(self,*args,**kwargs):
            kwargs.setdefault('host','devres-k8s:30081')
            return super().exchange(*args,**kwargs)
    original=socket.getaddrinfo
    def resolve(host,port,*args,**kwargs):
        assert host=='devres-k8s' and port==8080
        return original(str(address),port,*args,**kwargs)
    socket.getaddrinfo=resolve
    try:
        client=PrivateClient('https://devres-k8s:8080/mcp',str(private/'backend-ca.pem'),
                 str(private/'edge-client.pem'),str(private/'edge-client-key.pem'),origin='https://chatgpt.com')
        client.timeout=15
        for revision in (MODERN,LEGACY):
            info=client.tool('server.info',{},revision)
            assert info['version']==RELEASE
            assert info['sourceUrl']=='https://github.com/PublicData-stream/dev-resources-MCP/releases/download/'+RELEASE+'/source.tar.gz'
            for provider in ('rfc','crate','mdn','whatwg','w3c','chromium','npm'):
                name={'crate':'crate.corpus_status','advisory':'advisory.corpus_status'}.get(provider,provider+'.corpus_status')
                assert client.tool(name,{},revision)['collection_enabled'] is False
        result=verify(client,aliases)
        assert result['mdn_retained'] is True
    finally:
        socket.getaddrinfo=original
    signal.alarm(0)
    # RFC is checked separately by Drill.check before this reader is invoked.
    return {'version':1,'release':RELEASE,'schema':11,'retained_mdn':True,
            'notices_verified':True,'no_acquisition':True,'mdn_baseline_sha256':BASELINE_SHA256}


if __name__=='__main__':
    try:
        print(json.dumps(main(),sort_keys=True))
    except Exception:
        print('retained_restore_verification_failed',file=sys.stderr)
        raise SystemExit(1) from None
