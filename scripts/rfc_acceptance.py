#!/usr/bin/env python3
"""Opt-in RFC-only connected HTTPS acceptance; all evidence stays below /tmp.

Usage: PYTHONDONTWRITEBYTECODE=1 python3 scripts/rfc_acceptance.py --live --url HTTPS_MCP_URL
       --output-dir /tmp/OWNED_DIRECTORY [--connector-observations /tmp/FILE]
Ordinary reads can refresh retained public evidence; collector settings stay unchanged.
"""
import argparse
import base64
import collections
import hashlib
import http.client
import json
from pathlib import Path
import re
import signal
import ssl
import time
import urllib.parse
import xml.etree.ElementTree as ET

from mcp_smoke import Client, MODERN, LEGACY

REVISIONS = (MODERN, LEGACY)
RFC_TOOLS = frozenset('rfc.search rfc.get rfc.metadata rfc.catalog_search '
                      'rfc.fulltext_search rfc.format_get rfc.errata '
                      'rfc.series_get rfc.corpus_status'.split())
REFERENCE_URLS = {'index': 'https://www.rfc-editor.org/rfc-index.xml',
                  'errata': 'https://www.rfc-editor.org/api/v1/errata.json',
                  **{fmt: f'https://www.rfc-editor.org/rfc/rfc9000.{fmt}'
                     for fmt in ('txt', 'html', 'xml', 'pdf')}}
MAX_REFERENCE = 64 * 1024 * 1024
PAGE_SIZE = 1024
MAX_MCP_CALLS = 160
DEADLINE_SECONDS = 900
CONTENT_ID = re.compile(r'^(?:blake3:)?[0-9a-f]{64}$')
SAFE_CODE = re.compile(r'^[a-zA-Z0-9_.:-]{1,80}$')


class CheckFailure(Exception):
    """A fixed, non-source-controlled explanation suitable for a report."""


class Unverified(Exception):
    """A bounded operational/dependency gap rather than a passing success path."""


def require(condition, message):
    if not condition:
        raise CheckFailure(message)


def content_id(value):
    return isinstance(value, str) and CONTENT_ID.fullmatch(value) is not None


def safe_code(value):
    return value if isinstance(value, str) and SAFE_CODE.fullmatch(value) else 'unclassified'


def utc_now():
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


def tmp_path(value):
    path = Path(value).resolve()
    if path == Path('/tmp') or Path('/tmp') not in path.parents:
        raise ValueError('evidence path must resolve below /tmp')
    return path


def endpoint(value):
    parsed = urllib.parse.urlsplit(value)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment):
        raise ValueError('a credential-free HTTPS MCP endpoint is required')
    return value


class Budget:
    def __init__(self, clock=time.monotonic, seconds=DEADLINE_SECONDS,
                 maximum=MAX_MCP_CALLS):
        self.clock = clock
        self.end = clock() + seconds
        self.maximum = maximum
        self.calls = 0

    def remaining(self):
        remaining = self.end - self.clock()
        if remaining <= 0:
            raise Unverified('overall_deadline')
        return remaining

    def admit(self):
        self.remaining()
        if self.calls >= self.maximum:
            raise Unverified('mcp_request_budget')
        self.calls += 1


class Report:
    def __init__(self, url):
        self.url = url
        self.started_at = utc_now()
        self.checks = []
        self.references = []
        self.connector = []
        self.identities = []
        self.operational = []
        self.connector_calls = 0

    def add(self, name, status, detail='', revision=None, **evidence):
        row = {'check': name, 'path': 'https', 'status': status}
        if revision:
            row['revision'] = revision
        if detail:
            row['detail'] = detail
        for field in ('capture', 'snapshot'):
            if content_id(evidence.get(field)):
                row[field] = evidence[field]
        self.checks.append(row)

    def add_connector(self, name, result, arguments=None):
        """Sanitize one connector result; returns a record without copied content.

        Connector calls are made by the host, independently of this HTTPS script.
        Connector success covers envelope shape only until semantic evidence is
        recorded separately; it is never substituted for an HTTPS success.
        """
        require(name in RFC_TOOLS | {'server.info', 'search', 'fetch'},
                'unsupported connector observation')
        row = {'tool': name, 'path': 'connector'}
        try:
            data = tool_payload(result)
            connector_semantics(name, data, arguments or {})
            row['status'] = 'envelope_passed'
            for key in ('capture', 'snapshot'):
                value = data.get(key)
                if isinstance(value, dict):
                    value = value.get('id')
                if content_id(value):
                    row[key] = value
            if name == 'server.info':
                version = data.get('version')
                require(isinstance(version, str) and SAFE_CODE.fullmatch(version),
                        'invalid server version')
                row['version'] = version
        except Unverified as error:
            row.update(status='unverified', code=safe_code(str(error)))
        except (CheckFailure, TypeError, ValueError, AttributeError, KeyError, IndexError):
            row.update(status='failed', code='invalid_envelope')
        self.connector.append(row)
        return row

    def include_connector(self, rows):
        require(isinstance(rows, list) and len(rows) <= 20, 'invalid connector observations')
        for source in rows:
            require(isinstance(source, dict) and source.get('tool') in
                    RFC_TOOLS | {'server.info', 'search', 'fetch'}, 'invalid connector tool')
            require(source.get('status') in ('envelope_passed', 'unverified', 'failed'),
                    'invalid connector status')
            row = {'tool': source['tool'], 'path': 'connector', 'status': source['status']}
            for key in ('capture', 'snapshot'):
                if content_id(source.get(key)):
                    row[key] = source[key]
            for key in ('code', 'version'):
                if isinstance(source.get(key), str) and SAFE_CODE.fullmatch(source[key]):
                    row[key] = source[key]
            self.connector.append(row)

    def as_dict(self, budget):
        counts = dict(collections.Counter(row['status'] for row in self.checks))
        passed = bool(self.checks) and all(row['status'] == 'passed' for row in self.checks)
        if self.connector:
            expected = RFC_TOOLS | {'server.info', 'search', 'fetch'}
            passed = passed and expected <= {row['tool'] for row in self.connector}
            passed = passed and all(row['status'] == 'envelope_passed' for row in self.connector)
            infos = [row for row in self.connector if row['tool'] == 'server.info']
            passed = passed and len(infos) == 2 and infos[0].get('version') == infos[1].get('version')
            if infos and self.identities:
                passed = passed and all(row.get('version') == infos[0].get('version') for row in self.identities)
        return {'schema': 'devres-rfc-acceptance-v1', 'endpoint': self.url,
                'started_at': self.started_at, 'finished_at': utc_now(),
                'acceptance_passed': passed, 'counts': counts, 'mcp_requests': budget.calls,
                'limits': {'mcp_requests': MAX_MCP_CALLS, 'deadline_seconds': DEADLINE_SECONDS,
                           'request_seconds': 45, 'direct_provider_attempts': 20},
                'identities': self.identities, 'official_references': self.references,
                'connector_mcp_requests': self.connector_calls, 'operational_observations': self.operational,
                'connector_observations': self.connector, 'checks': self.checks,
                'limitations': ['Only sampled representation pages are byte-compared.',
                    'Current official references do not independently establish historical bytes.',
                    'Background collector and server-side retry traffic are outside this client budget.',
                    'Connector observations do not prove raw transport or native ChatGPT UI behavior.',
                    'Host connector observations precede the HTTPS deadline; their calls count toward the shared call cap.',
                    'No WebTransport, cluster, full-corpus or production recovery qualification.']}

    def write(self, directory, budget):
        directory = tmp_path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        require(not any((directory / name).exists() or (directory / name).is_symlink()
                        for name in ('report.json', 'report.md')), 'report files must not already exist')
        data = self.as_dict(budget)
        with (directory / 'report.json').open('x') as output:
            output.write(json.dumps(data, indent=2) + '\n')
        lines = ['# Connected RFC acceptance', '',
                 'Acceptance: ' + ('passed' if data['acceptance_passed'] else 'incomplete'),
                 '', f"MCP requests: {budget.calls}/{MAX_MCP_CALLS}", '',
                 '| Check | Revision | Result | Detail |', '| --- | --- | --- | --- |']
        for row in self.checks:
            lines.append('| ' + ' | '.join(str(row.get(key, '')) for key in
                         ('check', 'revision', 'status', 'detail')) + ' |')
        lines += ['', '## Connector observations', '']
        for row in self.connector:
            lines.append(f"- {row['tool']}: {row['status']} ({row.get('code', 'shape only')})")
        lines += ['', '## Limits', ''] + ['- ' + item for item in data['limitations']]
        with (directory / 'report.md').open('x') as output:
            output.write('\n'.join(lines) + '\n')
        return data


def rpc_payload(status, value, ident, revision, expected_error=None):
    if expected_error is None and status in (429, 502, 503, 504):
        raise Unverified('http_' + str(status))
    require(isinstance(value, dict) and value.get('jsonrpc') == '2.0',
            'invalid JSON-RPC envelope')
    require(type(value.get('id')) is int and value['id'] == ident, 'JSON-RPC request ID mismatch')
    require(('result' in value) != ('error' in value), 'result/error exclusivity violated')
    if expected_error is not None:
        error = value.get('error')
        require(status == (400 if revision == MODERN else 200), 'invalid rejection HTTP status')
        require(isinstance(error, dict) and error.get('code') == expected_error
                and isinstance(error.get('message'), str), 'invalid RPC rejection')
        return error
    if status in (429, 502, 503, 504):
        raise Unverified('http_' + str(status))
    require(status == 200, 'unexpected HTTP status')
    if 'error' in value:
        error = value['error']
        require(isinstance(error, dict) and type(error.get('code')) is int
                and isinstance(error.get('message'), str), 'invalid RPC error')
        require(error['code'] not in (-32600, -32601, -32602), 'valid call rejected by RPC contract')
        raise Unverified('rpc_' + str(error['code']))
    require(isinstance(value['result'], dict), 'RPC result must be an object')
    return value['result']


def owned_links(data):
    candidates = [data, data.get('capture'), data.get('metadata_capture'), data.get('attribution')]
    attribution = data.get('attribution', {})
    if isinstance(attribution, dict):
        candidates += attribution.get('generations', [])
        candidates += [{'resource_uri': uri} for uri in attribution.get('resource_uris', [])]
    candidates += data.get('files', [])
    links = set()
    for value in candidates:
        if isinstance(value, dict):
            uri = value.get('resource_uri')
            if isinstance(uri, str) and uri.startswith(('devres://capture/', 'devres://source/',
                                                       'devres://rfc/', 'devres://attribution/')):
                links.add(uri)
    return links


def copied_content(value, depth=0):
    if depth > 24:
        return True
    if isinstance(value, dict):
        fields = {'text', 'body', 'description', 'summary', 'title', 'abstract', 'abstract_text',
                  'snippet', 'excerpt', 'content', 'original', 'orig_text', 'correct_text', 'notes', 'data', 'blob'}
        return any((key in fields and bool(child)) or copied_content(child, depth + 1)
                   for key, child in value.items() if key != 'attribution')
    if isinstance(value, list):
        return any(copied_content(child, depth + 1) for child in value)
    return False


def tool_payload(result):
    require(isinstance(result, dict), 'tool result must be an object')
    require(type(result.get('isError', False)) is bool, 'invalid isError flag')
    data = result.get('structuredContent')
    require(isinstance(data, dict), 'missing structured tool content')
    blocks = result.get('content')
    require(isinstance(blocks, list) and blocks and isinstance(blocks[0], dict)
            and blocks[0].get('type') == 'text', 'missing structured native text')
    try:
        parsed = json.loads(blocks[0].get('text', ''))
    except (TypeError, ValueError) as error:
        raise CheckFailure('invalid native structured JSON text') from error
    require(parsed == data, 'native structured text differs from structuredContent')
    if result.get('isError'):
        require(isinstance(data.get('code'), str) and isinstance(data.get('message'), str)
                and not any(key in data for key in ('page', 'items', 'contents')),
                'invalid structured tool error')
        raise Unverified(safe_code(data['code']))
    if copied_content(data):
        attribution_ready(data)
    attribution = data.get('attribution')
    require(attribution is None or isinstance(attribution, dict), 'invalid attribution object')
    if attribution and attribution.get('status') == 'ready':
        notice = attribution.get('readable_notice')
        require(isinstance(notice, str) and notice.strip(), 'missing readable attribution')
        require(any(block.get('type') == 'text' and block.get('text') == notice
                    for block in blocks[1:] if isinstance(block, dict)), 'missing native attribution notice')
    actual = {block.get('uri') for block in blocks if isinstance(block, dict)
              and block.get('type') == 'resource_link'}
    require(owned_links(data) == actual, 'native resource links differ from owned provenance')
    return data


def page_bytes(data, fmt, offset=0):
    require(data.get('id') == 'rfc:9000', 'wrong RFC identity')
    page = data.get('page')
    require(isinstance(page, dict) and page.get('offset') == offset,
            'invalid representation page offset')
    require(type(page.get('total_bytes')) is int and page['total_bytes'] >= 0,
            'invalid total byte count')
    if fmt == 'pdf':
        require(page.get('encoding') == 'base64' and isinstance(page.get('data'), str),
                'invalid PDF page encoding')
        try:
            chunk = base64.b64decode(page['data'], validate=True)
        except (ValueError, TypeError) as error:
            raise CheckFailure('invalid PDF base64') from error
    else:
        require(isinstance(page.get('text'), str), 'missing UTF-8 representation page')
        chunk = page['text'].encode('utf-8')
    end = offset + len(chunk)
    require(len(chunk) <= PAGE_SIZE and end <= page['total_bytes'], 'page exceeds byte bounds')
    require(page.get('next_offset') == (end if end < page['total_bytes'] else None),
            'invalid representation continuation')
    require(chunk or offset == page['total_bytes'], 'empty nonterminal representation page')
    return chunk


def attribution_ready(data):
    attribution = data.get('attribution', {})
    require(attribution.get('status') == 'ready' and
            isinstance(attribution.get('readable_notice'), str) and
            bool(attribution['readable_notice'].strip()), 'content attribution is not ready')
    uris = attribution.get('resource_uris', [])
    require(isinstance(uris, list) and 1 <= len(uris) <= 20 and
            all(isinstance(uri, str) and uri.startswith('devres://attribution/') and len(uri) < 256
                for uri in uris), 'missing immutable attribution resources')
    return attribution


def parse_index(raw):
    require(b'<!DOCTYPE' not in raw.upper() and b'<!ENTITY' not in raw.upper(),
            'reference XML declarations are forbidden')
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as error:
        raise CheckFailure('invalid official index XML') from error
    local = lambda tag: tag.rsplit('}', 1)[-1]
    require(local(root.tag) == 'rfc-index', 'invalid official index root')
    rows = []
    for entry in root:
        if local(entry.tag) != 'rfc-entry':
            continue
        fields = collections.defaultdict(list)
        for element in entry:
            fields[local(element.tag)].append(element)
        text = lambda key: ' '.join(''.join(element.itertext()).split()) if (
            element := next(iter(fields.get(key, [])), None)) is not None else ''
        number = text('doc-id')
        require(re.fullmatch(r'RFC[0-9]{1,6}', number) is not None, 'invalid official RFC identity')
        series = [''.join(child.itertext()).strip() for key in ('is-also', 'see-also')
                  for group in fields.get(key, []) for child in group if local(child.tag) == 'doc-id']
        rows.append({'number': int(number[3:]), 'title': text('title'),
                     'status': text('current-status'), 'stream': text('stream'),
                     'series': [re.sub(r'^(STD|BCP|FYI)0*', r'\1', item) for item in series]})
    require(any(row['number'] == 9000 for row in rows), 'official index lacks RFC 9000')
    return rows


def parse_reference(name, raw):
    if name == 'index':
        return parse_index(raw)
    if name == 'errata':
        try:
            records = json.loads(raw)
        except (ValueError, UnicodeError) as error:
            raise CheckFailure('invalid official errata JSON') from error
        require(isinstance(records, list) and all(isinstance(item, dict) for item in records),
                'invalid official errata records')
        return [record for record in records if record.get('doc-id') == 'RFC9000']
    if name == 'pdf':
        require(raw.startswith(b'%PDF-') and b'%%EOF' in raw[-2048:], 'invalid official PDF')
    else:
        try:
            text = raw.decode('utf-8')
        except UnicodeError as error:
            raise CheckFailure('official source is not UTF-8') from error
        require('9000' in text and 'QUIC' in text, 'official representation lacks RFC identity')
        require('cf-chl-' not in text.lower() and 'just a moment...' not in text.lower(),
                'official reference is a challenge page')
        if name == 'txt':
            require(not text.lstrip().startswith('<'), 'official TXT returned markup')
        if name == 'xml':
            require(b'<!ENTITY' not in raw.upper(), 'official XML entity declarations forbidden')
            # Published RFC XML may retain a DOCTYPE; ElementTree does not fetch external DTDs.
            try:
                root = ET.fromstring(raw)
            except ET.ParseError as error:
                raise CheckFailure('invalid official RFC XML') from error
            require(root.tag.rsplit('}', 1)[-1] == 'rfc', 'invalid official RFC XML root')
        if name == 'html':
            require('<html' in text.lower(), 'invalid official RFC HTML')
    return raw


class References:
    def __init__(self, report, budget, connection=http.client.HTTPSConnection, sleep=time.sleep):
        self.report = report
        self.budget = budget
        self.connection = connection
        self.sleep = sleep
        self.attempts = 0
        self.last_attempt = None
        self.values = {}

    def collect(self):
        for name, url in REFERENCE_URLS.items():
            item = {'name': name, 'url': url, 'observed_at': utc_now()}
            try:
                self.budget.remaining()
                require(self.attempts < 20, 'direct provider attempt budget exceeded')
                if self.last_attempt is not None:
                    delay = max(0, 1 - (self.budget.clock() - self.last_attempt))
                    if delay:
                        self.sleep(min(delay, self.budget.remaining()))
                self.budget.remaining()
                self.last_attempt = self.budget.clock()
                self.attempts += 1
                parsed = urllib.parse.urlsplit(url)
                connection = self.connection(parsed.hostname, timeout=min(45, self.budget.remaining()),
                                             context=ssl.create_default_context())
                try:
                    connection.request('GET', parsed.path, headers={
                        'Accept-Encoding': 'identity', 'User-Agent': 'devres-rfc-acceptance/1'})
                    response = connection.getresponse()
                    item['http_status'] = response.status
                    if response.status != 200:
                        raise Unverified('reference_http_' + str(response.status))
                    require(response.getheader('Content-Encoding', 'identity') in ('', 'identity'),
                            'unsupported encoded official reference')
                    raw = bytearray()
                    while True:
                        self.budget.remaining()
                        chunk = response.read(min(65536, MAX_REFERENCE + 1 - len(raw)))
                        if not chunk:
                            break
                        raw.extend(chunk)
                        require(len(raw) <= MAX_REFERENCE, 'official reference exceeds byte bound')
                    raw = bytes(raw)
                    item.update(sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw))
                    for header in ('ETag', 'Last-Modified'):
                        value = response.getheader(header)
                        if isinstance(value, str) and len(value) <= 256:
                            item[header.lower()] = value
                    self.values[name] = parse_reference(name, raw)
                    item['status'] = 'passed'
                    self.report.add('official.' + name, 'passed')
                finally:
                    connection.close()
            except Unverified as error:
                item.update(status='unverified', code=safe_code(str(error)))
                self.report.add('official.' + name, 'unverified', safe_code(str(error)))
            except (OSError, http.client.HTTPException, CheckFailure, ValueError) as error:
                item.update(status='unverified', code=type(error).__name__)
                self.report.add('official.' + name, 'unverified', 'reference acquisition or validation failed')
            self.report.references.append(item)
        return self.values


class Acceptance:
    def __init__(self, client, report, budget, references=None):
        self.client = client
        self.report = report
        self.budget = budget
        self.references = references or {}
        self.notices_seen = set()

    def step(self, name, revision, operation):
        try:
            value = operation()
            evidence = {}
            if isinstance(value, dict):
                evidence = {'capture': value.get('capture', {}).get('id')
                            if isinstance(value.get('capture'), dict) else None,
                            'snapshot': value.get('snapshot')}
            self.report.add(name, 'passed', revision=revision, **evidence)
            return value
        except Unverified as error:
            self.report.add(name, 'unverified', safe_code(str(error)), revision)
        except CheckFailure as error:
            self.report.add(name, 'failed', str(error), revision)
        except (OSError, http.client.HTTPException, TimeoutError):
            self.report.add(name, 'unverified', 'transport_unavailable', revision)
        except (KeyError, TypeError, ValueError, AttributeError, IndexError):
            self.report.add(name, 'failed', 'unexpected result shape', revision)
        return None

    def rpc(self, method, arguments, revision, expected_error=None):
        self.budget.admit()
        self.client.timeout = min(45, self.budget.remaining())
        status, value = self.client.exchange(method, arguments, revision)
        return rpc_payload(status, value, self.client.ident, revision, expected_error)

    def tool(self, name, arguments, revision):
        result = self.rpc('tools/call', {'name': name, 'arguments': arguments}, revision)
        try:
            return tool_payload(result)
        except Unverified as error:
            self.report.add(name + '.error_envelope', 'passed', safe_code(str(error)), revision)
            raise

    def dependent(self, value):
        if value is None:
            raise Unverified('dependency_unavailable')
        return value

    def content(self, value, fmt, offset=0):
        attribution_ready(value)
        require(content_id(value.get('capture', {}).get('id')), 'missing capture identity')
        chunk = page_bytes(value, fmt, offset)
        return chunk

    def official_page(self, value, fmt, offset=0):
        chunk = self.content(value, fmt, offset)
        reference = self.references.get(fmt)
        if reference is None:
            raise Unverified('official_reference_unavailable')
        if chunk != reference[offset:offset + len(chunk)] or value['page']['total_bytes'] != len(reference):
            raise Unverified('current_reference_differs_from_capture')
        return value

    def identity(self, revision):
        value = self.tool('server.info', {}, revision)
        require(value.get('product') == 'dev-resources-MCP' and isinstance(value.get('version'), str)
                and SAFE_CODE.fullmatch(value['version']) is not None
                and isinstance(value.get('sourceUrl'), str) and len(value['sourceUrl']) <= 512
                and value['sourceUrl'].isascii() and not any(ord(c) < 32 for c in value['sourceUrl'])
                and set(REVISIONS) <= set(value.get('protocolVersions', [])), 'unexpected server identity')
        row = {key: value[key] for key in ('product', 'version', 'sourceUrl', 'protocolVersions') if key in value}
        self.report.identities.append(row)
        return row

    def inventory(self, revision):
        value = self.rpc('tools/list', {}, revision)
        tools = value.get('tools')
        require(isinstance(tools, list), 'tool inventory missing')
        names = [tool.get('name') for tool in tools]
        require(len(names) == len(set(names)) and RFC_TOOLS <= set(names), 'RFC tool inventory incomplete')
        for tool in tools:
            if tool.get('name') in RFC_TOOLS:
                schema = tool.get('inputSchema', {})
                require(schema.get('type') == 'object' and schema.get('additionalProperties') is False,
                        'RFC schema is not a closed object')
        return value

    def same_capture(self, first, second):
        require(second.get('capture', {}).get('id') == first.get('capture', {}).get('id'),
                'capture-pinned selection changed')

    def same_snapshot(self, value, snapshot):
        require(value.get('snapshot') == snapshot and content_id(snapshot), 'snapshot-pinned selection changed')
        return value

    def list_page(self, value, offset=0, limit=3):
        require(isinstance(value.get('items'), list) and len(value['items']) <= limit
                and type(value.get('total')) is int and value['total'] >= len(value['items'])
                and value.get('offset') == offset, 'invalid list page')
        require(value.get('next_offset') == (offset + limit if offset + limit < value['total'] else None),
                'invalid list continuation')
        return value

    def search(self, revision):
        value = self.tool('rfc.search', {'query': 'QUIC', 'limit': 3}, revision)
        self.list_page(value)
        require(value.get('search_scope') == 'official_index_metadata' and value['items'],
                'RFC metadata search missing results or scope')
        require(value.get('capture', {}).get('source_url') == REFERENCE_URLS['index'],
                'RFC search canonical index source changed')
        numbers = [item['metadata']['number'] for item in value['items']]
        require(numbers == sorted(numbers), 'RFC metadata search is not in index order')
        return value

    def search_page(self, first, revision):
        self.dependent(first)
        capture = first['capture']['id']
        value = self.tool('rfc.search', {'query': 'QUIC', 'capture': capture, 'offset': 0, 'limit': 1}, revision)
        self.same_capture(first, value)
        self.list_page(value, limit=1)
        require(value['items'] == first['items'][:1], 'capture-pinned metadata page changed')
        next_page = self.tool('rfc.search', {'query': 'QUIC', 'capture': capture, 'offset': 1, 'limit': 1}, revision)
        self.same_capture(first, next_page)
        self.list_page(next_page, offset=1, limit=1)
        require(next_page['items'] == first['items'][1:2], 'capture-pinned next metadata page changed')
        return value

    def metadata(self, revision):
        value = self.tool('rfc.metadata', {'number': 9000}, revision)
        require(content_id(value.get('snapshot')) and value.get('metadata', {}).get('number') == 9000,
                'RFC metadata identity or snapshot missing')
        require('QUIC' in value['metadata'].get('title', ''), 'RFC 9000 title differs')
        return value

    def official_metadata(self, value):
        self.dependent(value)
        rows = self.references.get('index')
        if rows is None:
            raise Unverified('official_index_unavailable')
        reference = next(row for row in rows if row['number'] == 9000)
        require(all(value['metadata'].get(key) == reference[key] for key in ('number', 'title', 'status', 'stream')),
                'RFC metadata differs from current official index')
        return value

    def research(self, tool, arguments, snapshot, revision):
        if snapshot is None:
            raise Unverified('research_snapshot_unavailable')
        value = self.tool(tool, dict(arguments, snapshot=snapshot), revision)
        return self.same_snapshot(value, snapshot)

    def catalog(self, snapshot, revision):
        value = self.research('rfc.catalog_search', {'query': 'rfc9000',
                              'filters': {'stream': 'IETF', 'published_from': '2021-05',
                                          'published_through': '2021-05'}, 'limit': 3}, snapshot, revision)
        self.list_page(value)
        require([item['metadata']['number'] for item in value['items']] == [9000],
                'catalog AND filters or RFC identity changed')
        return value

    def errata(self, snapshot, revision):
        value = self.research('rfc.errata', {'number': 9000, 'limit': 3}, snapshot, revision)
        self.list_page(value)
        require(all(item.get('doc-id') == 'RFC9000' for item in value['items']), 'errata RFC identity changed')
        reference = self.references.get('errata')
        if reference is None:
            raise Unverified('official_errata_unavailable')
        if value['total'] != len(reference) or any(item not in reference for item in value['items']):
            raise Unverified('current_errata_differs_from_snapshot')
        return value

    def series(self, snapshot, revision):
        value = self.research('rfc.series_get', {'series': 'BCP', 'number': 14, 'limit': 100}, snapshot, revision)
        self.list_page(value, limit=100)
        require(value.get('series') == 'BCP14', 'series identity changed')
        rows = self.references.get('index')
        if rows is None:
            raise Unverified('official_index_unavailable')
        expected = [row['number'] for row in rows if 'BCP14' in row['series']]
        require([item.get('number') for item in value['items']] == expected and bool(expected),
                'BCP 14 constituent RFC identities differ from official index')
        return value

    def fulltext(self, snapshot, revision, mode):
        value = self.research('rfc.fulltext_search', {'query': 'multiplexed', 'mode': mode, 'limit': 3},
                              snapshot, revision)
        self.list_page(value)
        require(isinstance(value.get('coverage'), dict), 'fulltext coverage missing')
        if not value['items']:
            raise Unverified('fulltext_success_not_demonstrated')
        ordering = [(-item['score'], item['number']) for item in value['items']]
        require(ordering == sorted(ordering), 'fulltext ranking is not score/number order')
        page = self.research('rfc.fulltext_search', {'query': 'multiplexed', 'mode': mode,
                             'offset': 1, 'limit': 1}, snapshot, revision)
        self.list_page(page, 1, 1)
        require(page['items'] == value['items'][1:2], 'pinned fulltext page changed')
        return value

    def generic_search(self, revision):
        value = self.tool('search', {'query': 'QUIC', 'sources': ['rfc'], 'limit': 3}, revision)
        sources = value.get('sources')
        require(isinstance(sources, list) and len(sources) == 1 and sources[0].get('source') == 'rfc',
                'generic search did not remain RFC-only')
        row = sources[0]
        if row.get('error'):
            require(isinstance(row['error'], dict) and isinstance(row['error'].get('code'), str),
                    'invalid source-local RFC error')
            self.report.add('search.rfc.error_envelope', 'passed', safe_code(row['error']['code']), revision)
            raise Unverified('rfc_source_unavailable')
        result = row.get('result')
        require(isinstance(result, dict), 'missing source-local RFC result')
        self.list_page(result)
        require(result.get('search_scope') == 'official_index_metadata', 'generic RFC search changed scope')
        return value

    def representation(self, fmt, revision):
        value = self.tool('rfc.format_get', {'number': 9000, 'format': fmt, 'limit': PAGE_SIZE}, revision)
        require(value.get('format') == fmt and value.get('media_type') ==
                {'txt': 'text/plain', 'html': 'text/html', 'xml': 'application/xml', 'pdf': 'application/pdf'}[fmt],
                'RFC representation format or media type changed')
        require(value.get('capture', {}).get('source_url') == REFERENCE_URLS[fmt],
                'RFC representation source URL changed')
        self.content(value, fmt)
        return value

    def replay(self, first, fmt, revision):
        self.dependent(first)
        value = self.tool('rfc.format_get', {'number': 9000, 'format': fmt, 'limit': PAGE_SIZE,
                          'capture': first['capture']['id']}, revision)
        self.same_capture(first, value)
        require(self.content(first, fmt) == self.content(value, fmt), 'capture-pinned bytes changed')
        offset = first['page']['next_offset']
        if offset is not None:
            second = self.tool('rfc.format_get', {'number': 9000, 'format': fmt, 'limit': PAGE_SIZE,
                               'offset': offset, 'capture': first['capture']['id']}, revision)
            self.same_capture(first, second)
            self.official_page(second, fmt, offset)
        return value

    def resource(self, first, fmt, revision, via_fetch=False):
        self.dependent(first)
        uri = first.get('resource_uri')
        require(isinstance(uri, str) and uri.startswith('devres://rfc/9000/' + fmt + '/'),
                'typed RFC resource identity changed')
        if via_fetch:
            value = self.tool('fetch', {'id': uri}, revision)
        else:
            value = self.rpc('resources/read', {'uri': uri}, revision)
        contents = value.get('contents')
        require(isinstance(contents, list) and len(contents) >= 2, 'resource omitted content or notices')
        content = contents[0]
        require(content.get('uri') == uri and content.get('mimeType') ==
                ('application/pdf' if fmt == 'pdf' else 'text/plain'), 'resource URI or media type changed')
        raw = base64.b64decode(content['blob'], validate=True) if fmt == 'pdf' else content['text'].encode()
        require(raw == self.content(first, fmt), 'resource bytes differ from selected page')
        metadata = content.get('_meta', {})
        require(metadata.get('source_evidence', {}).get('capture', {}).get('id') == first['capture']['id'],
                'resource lost capture identity')
        selected = attribution_ready(first)
        require(metadata.get('attribution', {}).get('status') == 'ready' and
                metadata['attribution'].get('resource_uris') == selected['resource_uris'] and
                [item.get('text') for item in contents[1:]] == [selected['readable_notice']],
                'resource attribution differs from selected evidence')
        return value

    def selected_notices(self, first, revision):
        self.dependent(first)
        if not copied_content(first) and first.get('attribution', {}).get('status') == 'metadata_only':
            return first
        return self.notices(first, revision)

    def notices(self, first, revision):
        self.dependent(first)
        attribution = attribution_ready(first)
        generations = attribution.get('generations', [])
        expected = {}
        for generation in generations:
            require(content_id(generation.get('id')), 'invalid attribution generation')
            entries = []
            for notice in generation.get('notices', []):
                require(isinstance(notice.get('source_url'), str) and isinstance(notice.get('text'), str),
                        'original notice evidence missing')
                entry = notice['source_url'] + '\n' + notice['text']
                if entry not in entries:
                    entries.append(entry)
            expected['devres://attribution/' + generation['id']] = '\n\n'.join(entries)
        require(set(expected) == set(attribution['resource_uris']), 'attribution generation references differ')
        for uri, text in expected.items():
            require(text and len(text.encode()) <= 65536, 'notice exceeds bounded verification')
            if (revision, uri) in self.notices_seen:
                continue
            raw = bytearray()
            for _ in range(3):
                value = self.rpc('resources/read', {'uri': uri + '?offset=' + str(len(raw)) + '&limit=32768'}, revision)
                contents = value.get('contents')
                require(isinstance(contents, list) and len(contents) == 1, 'invalid notice resource')
                item = contents[0]
                meta = item.get('_meta', {})
                require(item.get('uri') == uri and meta.get('offset') == len(raw)
                        and meta.get('total_bytes') == len(text.encode()), 'notice page binding differs')
                chunk = item.get('text', '').encode()
                require(chunk and len(chunk) <= 32768, 'invalid notice page bytes')
                raw.extend(chunk)
                require(len(raw) <= 65536, 'notice verification exceeds byte budget')
                if meta.get('next_offset') is None:
                    break
                require(meta['next_offset'] == len(raw), 'invalid notice continuation')
            require(bytes(raw) == text.encode(), 'notice resource differs from original evidence')
            self.notices_seen.add((revision, uri))
        return first

    def get(self, revision):
        value = self.tool('rfc.get', {'number': 9000, 'limit': PAGE_SIZE}, revision)
        self.content(value, 'txt')
        require(b'QUIC' in page_bytes(value, 'txt'), 'RFC 9000 text lacks QUIC title')
        return value

    def fetch_rfc(self, revision):
        value = self.tool('fetch', {'id': 'rfc:9000', 'limit': PAGE_SIZE}, revision)
        self.content(value, 'txt')
        return value

    def get_parity(self, first, representation, fetched, revision):
        self.dependent(first)
        self.dependent(representation)
        self.dependent(fetched)
        require(self.content(first, 'txt') == self.content(representation, 'txt'),
                'RFC get and TXT format bytes differ')
        require(self.content(fetched, 'txt') == self.content(first, 'txt'), 'generic RFC fetch bytes differ')
        pinned = self.tool('rfc.get', {'number': 9000, 'limit': PAGE_SIZE,
                           'capture': first['capture']['id']}, revision)
        self.same_capture(first, pinned)
        require(self.content(pinned, 'txt') == self.content(first, 'txt'), 'pinned RFC get bytes differ')
        return fetched

    def open_revision(self, revision):
        method = 'initialize' if revision == LEGACY else 'server/discover'
        arguments = ({'protocolVersion': revision, 'capabilities': {},
                      'clientInfo': {'name': 'devres-rfc-acceptance', 'version': '1'}}
                     if revision == LEGACY else {})
        value = self.rpc(method, arguments, revision)
        if revision == MODERN:
            require(value.get('supportedVersions') == list(REVISIONS),
                    'discovery supported revisions differ')
        else:
            require(value.get('protocolVersion') == revision, 'initialization negotiated wrong revision')
        capabilities = value.get('capabilities', {})
        require(capabilities.get('tools') == {} and capabilities.get('resources') == {},
                'discovery tools/resources capabilities missing')
        return value

    def run_revision(self, revision):
        self.step('initialize' if revision == LEGACY else 'discover', revision,
                  lambda: self.open_revision(revision))
        self.step('tools.list', revision, lambda: self.inventory(revision))
        self.step('server.info', revision, lambda: self.identity(revision))
        self.step('rfc.corpus_status', revision, lambda: self.status(revision))
        searched = self.step('rfc.search', revision, lambda: self.search(revision))
        self.step('rfc.search.pagination', revision, lambda: self.search_page(searched, revision))
        self.step('search.rfc', revision, lambda: self.generic_search(revision))
        metadata = self.step('rfc.metadata', revision, lambda: self.metadata(revision))
        self.step('rfc.metadata.official', revision, lambda: self.official_metadata(metadata))
        snapshot = metadata.get('snapshot') if metadata else None
        catalog = self.step('rfc.catalog_search', revision, lambda: self.catalog(snapshot, revision))
        errata = self.step('rfc.errata', revision, lambda: self.errata(snapshot, revision))
        series = self.step('rfc.series_get', revision, lambda: self.series(snapshot, revision))
        for label, selected in (('metadata', metadata), ('catalog', catalog), ('errata', errata), ('series', series)):
            self.step('attribution.resources.' + label, revision,
                      lambda selected=selected: self.selected_notices(selected, revision))
        for mode in ('technical', 'english'):
            self.step('rfc.fulltext_search.' + mode, revision,
                      lambda mode=mode: self.fulltext(snapshot, revision, mode))
        text = self.step('rfc.get', revision, lambda: self.get(revision))
        fetched = self.step('fetch.rfc', revision, lambda: self.fetch_rfc(revision))
        formats = {}
        for fmt in ('txt', 'html', 'xml', 'pdf'):
            first = self.step('rfc.format_get.' + fmt, revision, lambda fmt=fmt: self.representation(fmt, revision))
            formats[fmt] = first
            self.step('official.page.' + fmt, revision,
                      lambda first=first, fmt=fmt: self.official_page(self.dependent(first), fmt))
            self.step('capture.replay.' + fmt, revision, lambda first=first, fmt=fmt: self.replay(first, fmt, revision))
            self.step('resources.read.' + fmt, revision, lambda first=first, fmt=fmt: self.resource(first, fmt, revision))
            self.step('fetch.resource.' + fmt, revision,
                      lambda first=first, fmt=fmt: self.resource(first, fmt, revision, via_fetch=True))
            self.step('attribution.resources.' + fmt, revision, lambda first=first: self.notices(first, revision))
        self.step('rfc.get.fetch_parity', revision, lambda: self.get_parity(text, formats.get('txt'), fetched, revision))
        for label, name, args in (
            ('unknown_argument', 'rfc.get', {'number': 9000, 'url': 'https://untrusted.invalid'}),
            ('invalid_limit', 'rfc.get', {'number': 9000, 'limit': 0}),
            ('invalid_number', 'rfc.get', {'number': 0}),
            ('invalid_query', 'rfc.fulltext_search', {'query': ''})):
            self.step('reject.' + label, revision, lambda name=name, args=args:
                      self.rpc('tools/call', {'name': name, 'arguments': args}, revision, -32602))
        self.step('reject.capture_binding', revision,
                  lambda: self.reject_binding(formats.get('txt'), revision))
        self.step('reject.resource_selector', revision, lambda:
                  self.rpc('resources/read', {'uri': 'devres://rfc/9000/txt/invalid?limit=0'}, revision, -32602))

    def reject_binding(self, first, revision):
        self.dependent(first)
        return self.rpc('tools/call', {'name': 'rfc.format_get', 'arguments':
                        {'number': 9001, 'format': 'txt', 'capture': first['capture']['id'], 'limit': PAGE_SIZE}},
                        revision, -32602)

    def status(self, revision):
        value = self.tool('rfc.corpus_status', {}, revision)
        require(type(value.get('collection_enabled')) is bool and
                type(value.get('captured_rfc_numbers')) is int and isinstance(value.get('collector'), dict),
                'RFC corpus operational status missing')
        collector = value['collector']
        # Operational failure is evidence, not permission to change collector state.
        failure = collector.get('failure')
        if failure:
            self.report.operational.append({'path': 'https', 'revision': revision,
                'collector_failure': safe_code(failure.get('code')),
                'phase': safe_code(failure.get('phase'))})
        return value

    def run(self):
        before = self.step('identity.before', MODERN, lambda: self.identity(MODERN))
        for revision in REVISIONS:
            self.run_revision(revision)
        after = self.step('identity.after', MODERN, lambda: self.identity(MODERN))
        self.step('identity.stable', MODERN, lambda: self.stable_identity(before, after))

    def stable_identity(self, before, after):
        self.dependent(before)
        self.dependent(after)
        require(before == after, 'server build changed during acceptance')
        return after


def connector_semantics(name, data, arguments):
    if name == 'server.info':
        require(data.get('product') == 'dev-resources-MCP', 'invalid connector identity')
    elif name == 'rfc.corpus_status':
        require(type(data.get('collection_enabled')) is bool, 'invalid connector corpus status')
    elif name == 'rfc.metadata':
        require(data.get('metadata', {}).get('number') == 9000 and
                'QUIC' in data['metadata'].get('title', '') and content_id(data.get('snapshot')),
                'invalid connector RFC metadata')
    elif name in ('rfc.get', 'rfc.format_get', 'fetch'):
        page_bytes(data, arguments.get('format', 'txt'), arguments.get('offset', 0))
    elif name == 'search':
        sources = data.get('sources')
        require(isinstance(sources, list) and len(sources) == 1 and sources[0].get('source') == 'rfc',
                'connector generic search scope changed')
        if sources[0].get('error'):
            raise Unverified('rfc_source_unavailable')
        require(sources[0].get('result', {}).get('search_scope') == 'official_index_metadata',
                'connector generic search result missing')
    else:
        require(isinstance(data.get('items'), list) and type(data.get('total')) is int,
                'connector list result invalid')
        if name in ('rfc.catalog_search', 'rfc.fulltext_search', 'rfc.errata', 'rfc.series_get'):
            require(content_id(data.get('snapshot')), 'connector research snapshot missing')
            if arguments.get('snapshot'):
                require(data['snapshot'] == arguments['snapshot'], 'connector research snapshot changed')
        if name == 'rfc.catalog_search':
            require([item.get('metadata', {}).get('number') for item in data['items']] == [9000],
                    'connector catalog identity changed')
        if name == 'rfc.series_get':
            require(data.get('series') == 'BCP14' and
                    [item.get('number') for item in data['items']] == [2119, 8174],
                    'connector BCP 14 identities changed')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--live', action='store_true', required=True)
    parser.add_argument('--url', required=True, type=endpoint)
    parser.add_argument('--output-dir', required=True, type=tmp_path)
    connector = parser.add_mutually_exclusive_group()
    connector.add_argument('--connector-input', type=tmp_path,
                        help='bounded raw connector evidence from the host; sanitized before reporting')
    connector.add_argument('--connector-observations', type=tmp_path,
                        help='sanitized observations produced by Report.add_connector')
    options = parser.parse_args(argv)
    options.output_dir.mkdir(parents=True, exist_ok=True)
    require(not any((options.output_dir / name).exists() or (options.output_dir / name).is_symlink()
                    for name in ('report.json', 'report.md')), 'report files must not already exist')
    report = Report(options.url)
    budget = Budget()
    if options.connector_observations:
        with options.connector_observations.open('rb') as source:
            raw = source.read(65537)
        require(len(raw) <= 65536, 'connector observations exceed bound')
        report.include_connector(json.loads(raw))
        for _ in report.connector:
            budget.admit()
            report.connector_calls += 1
    if options.connector_input:
        with options.connector_input.open('rb') as source:
            raw = source.read(8 * 1024 * 1024 + 1)
        require(len(raw) <= 8 * 1024 * 1024, 'connector input exceeds bound')
        rows = json.loads(raw)
        require(isinstance(rows, list) and len(rows) <= 20, 'invalid connector input')
        mapping = {name.replace('.', '_'): name for name in RFC_TOOLS | {'server.info', 'search', 'fetch'}}
        for row in rows:
            require(isinstance(row, dict) and row.get('name') in mapping, 'invalid connector input tool')
            report.add_connector(mapping[row['name']], row.get('result'), row.get('args', {}))
            budget.admit()
            report.connector_calls += 1
        report.checks.append({'check': 'connector.sample', 'path': 'connector',
            'status': 'passed' if all(row['status'] == 'envelope_passed' for row in report.connector)
                else 'unverified', 'detail': 'connector envelopes; semantic coverage remains path-specific'})
    if not report.connector:
        report.checks.append({'check': 'connector.sample', 'path': 'connector',
                              'status': 'unverified', 'detail': 'host connector observations not supplied'})
    client = Client(options.url, origin='https://chatgpt.com')
    previous = signal.getsignal(signal.SIGALRM)
    def expired(_signal, _frame):
        raise Unverified('overall_deadline')
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(DEADLINE_SECONDS)
    try:
        references = References(report, budget).collect()
        Acceptance(client, report, budget, references).run()
    except Unverified:
        report.add('attempt.deadline', 'unverified', 'overall_deadline')
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
        data = report.write(options.output_dir, budget)
    print(json.dumps({'acceptance_passed': data['acceptance_passed'], 'counts': data['counts'],
                      'mcp_requests': budget.calls}))
    return 0 if data['acceptance_passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
