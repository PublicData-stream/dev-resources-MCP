"""Run the unchanged complete HTTP smoke against an IPv4 loopback fixture only.

Usage: python3 -B -m deploy.diagnostics.smoke --endpoint http://127.0.0.1:PORT/mcp
       --output-dir /tmp/PRIVATE
No live switch, source calls, arbitrary destinations, certificates or credentials.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import sys
import time
import urllib.parse

from .evidence import EvidenceError, private_root

CANONICAL_PATH = Path(__file__).resolve().parents[2] / 'scripts' / 'mcp_smoke.py'
_spec = importlib.util.spec_from_file_location('devres_diagnostic_canonical_smoke', CANONICAL_PATH)
canonical = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(canonical)
METHODS = {'server/discover', 'initialize', 'tools/list', 'tools/call'}
OBSOLETE = (canonical.OBSOLETE_PACKAGE_TOOLS
            | {name.replace('.', '_', 1) for name in canonical.OBSOLETE_PACKAGE_TOOLS}
            | {'server_info', 'rfc_catalog_search', 'rfc.catalog.search', 'packages.crate.api.search',
               'packages.npm.advisory.get', 'packages.crates.search'})
EVENTS = {'begin', 'response', 'decode', 'complete', 'failure'}
CODES = {'ok', 'transport', 'decode', 'assertion', 'receipt', 'trace', 'input'}


class DiagnosticSmokeError(RuntimeError):
    pass


def loopback_endpoint(endpoint: str):
    try:
        parsed = urllib.parse.urlsplit(endpoint)
        valid = (parsed.scheme == 'http' and parsed.hostname == '127.0.0.1'
                 and parsed.username is None and parsed.password is None
                 and parsed.path == '/mcp' and not parsed.query and not parsed.fragment
                 and parsed.port is not None and 1 <= parsed.port <= 65535
                 and parsed.netloc == '127.0.0.1:' + str(parsed.port))
    except (ValueError, TypeError):
        valid = False
    if not valid:
        raise DiagnosticSmokeError('input')
    return parsed


class SmokeTrace:
    """Closed event vocabulary; source arguments and error messages never enter it."""
    def __init__(self, root: Path, *, limit=2 * 1024**2):
        if type(limit) is not int or not 1 <= limit <= 2 * 1024**2:
            raise EvidenceError('trace_bound')
        self.root = private_root(root)
        self.fd = None
        try:
            self.fd = os.open('smoke-trace.jsonl', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                              0o600, dir_fd=self.root)
            os.fsync(self.root)
        except BaseException:
            if self.fd is not None:
                os.close(self.fd)
            os.close(self.root)
            raise
        self.limit, self.written = limit, 0
        self.failed = False
        self.started = time.monotonic_ns()
        self.stage = 'smoke'
        self.digest = hashlib.sha256()

    def emit(self, event, *, method='none', tool='none', revision='none', operation=0,
             status=None, code='ok'):
        if self.failed:
            raise EvidenceError('trace_sink_failed')
        if (event not in EVENTS or self.stage not in {'smoke', 'identity', 'receipt'}
            or method not in METHODS | {'none'} or tool not in canonical.EXPECTED_TOOLS | {'none', 'obsolete'}
            or revision not in {canonical.LEGACY, canonical.MODERN, 'none'} or code not in CODES
            or type(operation) is not int or not 0 <= operation <= 4096
            or (status is not None and (type(status) is not int or not 100 <= status <= 599))):
            raise EvidenceError('trace_value_refused')
        row = {'version':1, 'family':'ipv4', 'stage':self.stage, 'event':event,
               'method':method, 'tool':tool, 'revision':revision, 'operation':operation,
               'status':status, 'code':code, 'elapsed_ns':time.monotonic_ns()-self.started}
        body = (json.dumps(row, sort_keys=True, separators=(',', ':'))+'\n').encode()
        if self.written + len(body) > self.limit:
            raise EvidenceError('trace_bound')
        self.written += len(body)
        try:
            with os.fdopen(os.dup(self.fd), 'ab') as stream:
                stream.write(body)
                stream.flush()
                # Every event reaches the kernel before its request proceeds.
                # Bound synchronous durability to stage bookends and failures.
                if method == 'none' or event == 'failure':
                    os.fsync(stream.fileno())
        except BaseException:
            self.failed = True
            raise EvidenceError('trace_sink_failed') from None
        self.digest.update(body)

    def receipt(self):
        if self.failed:
            raise EvidenceError('trace_sink_failed')
        value = {'version':1, 'kind':'local-http-diagnostic', 'family':'ipv4', 'smoke_passed':True,
                 'negative_checks':True, 'protocols':[canonical.MODERN,canonical.LEGACY],
                 'tool_inventory':98, 'trace_prefix_sha256':self.digest.hexdigest(),
                 'canonical_smoke_sha256':hashlib.sha256(CANONICAL_PATH.read_bytes()).hexdigest(),
                 'production_acceptance':False, 'source_acquisition':False}
        fd = os.open('smoke-receipt.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=self.root)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(json.dumps(value, sort_keys=True).encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(self.root)

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            os.close(self.root)
            self.fd = None


def fixed_request(method, params, revision, path, host, origin):
    if method not in METHODS or revision not in {canonical.MODERN,canonical.LEGACY}:
        return False
    if sum(v is not None for v in (path,host,origin)) > 1:
        return False
    if (path not in {None,'/live','/ready','/metrics'} or host not in {None,'untrusted.invalid'}
        or origin not in {None,'https://untrusted.invalid'}):
        return False
    if any(v is not None for v in (path,host,origin)) and method != 'tools/list':
        return False
    if method == 'initialize':
        return revision == canonical.LEGACY and params == {'protocolVersion':canonical.LEGACY,
            'capabilities':{},'clientInfo':{'name':'devres-smoke','version':'1'}}
    if method in {'server/discover','tools/list'}:
        return params is None or params == {}
    if not isinstance(params,dict) or set(params) != {'name','arguments'}:
        return False
    name,arguments = params['name'],params['arguments']
    status_tools = {'packages.npm.corpus_status','whatwg.corpus_status','chromium.corpus_status',
                    'w3c.corpus_status','mdn.corpus_status','packages.crate.advisory_corpus_status',
                    'packages.crate.corpus_status','server.info'}
    if name in status_tools | OBSOLETE:
        return arguments == {}
    schema_negatives = {
        'packages.npm.metadata':{'name':'fixture','version':'1.0.0','url':'https://untrusted.invalid'},
        'whatwg.get':{'standard':'fixture','url':'https://untrusted.invalid'},
        'chromium.get':{'component':'src','path':'docs/fixture.html','url':'https://untrusted.invalid'},
        'w3c.get':{'specification':'fixture','url':'https://untrusted.invalid'},
        'mdn.get':{'slug':'Web/Fixture','url':'https://untrusted.invalid'},
    }
    return name in schema_negatives and arguments == schema_negatives[name]


class TracedClient(canonical.Client):
    """The canonical wire construction/decoder, instrumented around its stages."""
    def __init__(self, endpoint, trace, timeout=45):
        loopback_endpoint(endpoint)
        if type(timeout) not in (int,float) or not 0.02 <= timeout <= 45:
            raise DiagnosticSmokeError('input')
        super().__init__(endpoint)
        self.trace, self.timeout = trace, timeout

    def exchange(self, method, params=None, revision=canonical.MODERN, path=None, host=None, origin=None):
        # Only the fixed requests in canonical.smoke are accepted. Negative
        # destination strings in tool arguments stay request data, never routing.
        name = params.get('name') if isinstance(params,dict) else None
        if not fixed_request(method,params,revision,path,host,origin) or self.ident >= 4096:
            raise DiagnosticSmokeError('input')
        self.ident += 1
        operation = self.ident
        tool = name if name in canonical.EXPECTED_TOOLS else ('obsolete' if name is not None else 'none')
        status = None
        def emit(event, code='ok'):
            self.trace.emit(event, method=method, tool=tool, revision=revision,
                            operation=operation, status=status, code=code)
        emit('begin')
        connection = None
        code = 'transport'
        try:
            # Preserve scripts/mcp_smoke.py::Client.exchange request semantics.
            params = dict(params or {})
            if revision == canonical.MODERN:
                params.setdefault('_meta', {}).update({
                    'io.modelcontextprotocol/protocolVersion':revision,
                    'io.modelcontextprotocol/clientInfo':{'name':'devres-smoke','version':'1'},
                    'io.modelcontextprotocol/clientCapabilities':{},
                })
            body = {'jsonrpc':'2.0','id':self.ident,'method':method,'params':params}
            headers = {'Content-Type':'application/json','Accept':'application/json, text/event-stream',
                       'MCP-Protocol-Version':revision,'Origin':origin or self.origin}
            if host:
                headers['Host'] = host
            if revision == canonical.MODERN:
                headers['Mcp-Method'] = method
                if 'name' in params:
                    headers['Mcp-Name'] = params['name']
                elif 'uri' in params:
                    headers['Mcp-Name'] = params['uri']
            connection = http.client.HTTPConnection(self.url.hostname,self.url.port,timeout=self.timeout)
            connection.request('POST',path or self.url.path or '/mcp',json.dumps(body),headers)
            response = connection.getresponse()
            status = response.status
            emit('response')
            code = 'decode'
            if response.getheader('content-type','').startswith(('application/json','text/event-stream')):
                value = canonical.decode_response(response,self.ident)
            else:
                response.read(canonical.MAX_RESPONSE+1)
                value = None
            emit('decode')
            emit('complete')
            return status,value
        except BaseException as error:
            try:
                emit('failure', code)
            except BaseException:
                pass
            # Canonical call/tool assertion exceptions are sanitized by diagnose.
            raise DiagnosticSmokeError(code) from None
        finally:
            if connection is not None:
                connection.close()


def diagnose(endpoint: str, output: Path, *, timeout=45, receipt_check=None):
    """Execute unchanged full smoke assertions; no synthetic/live acquisition paths.

    receipt_check is a trusted local fault-injection hook, not a CLI option.
    Success here is local diagnostic evidence, never production acceptance.
    """
    if not __debug__:
        raise DiagnosticSmokeError('input')
    loopback_endpoint(endpoint)
    trace = None
    code = 'trace'
    try:
        trace = SmokeTrace(output)
        client = TracedClient(endpoint,trace,timeout)
        trace.emit('begin')
        code = 'assertion'
        canonical.smoke(client,negative=True)
        trace.emit('complete')
        trace.stage = 'identity'
        trace.emit('begin')
        for revision in (canonical.MODERN,canonical.LEGACY):
            info = client.tool('server.info',{},revision)
            assert info.get('product') == 'dev-resources-MCP'
            assert info.get('license') == 'AGPL-3.0-only'
            assert info.get('sourceUrl','').startswith('https://')
        trace.emit('complete')
        trace.stage = 'receipt'
        trace.emit('begin')
        code = 'receipt'
        if receipt_check is not None and receipt_check() is not True:
            raise DiagnosticSmokeError('receipt')
        trace.receipt()
        trace.emit('complete')
        return {'known_complete':True,'code':'ok','family':'ipv4','production_acceptance':False}
    except BaseException as error:
        if isinstance(error,DiagnosticSmokeError) and str(error) in CODES:
            code = str(error)
        if trace is not None:
            try:
                trace.emit('failure',code=code)
            except BaseException:
                pass
        raise DiagnosticSmokeError(code) from None
    finally:
        if trace:
            trace.close()


class ClosedParser(argparse.ArgumentParser):
    def error(self, _message):
        raise DiagnosticSmokeError('input')


def main(argv=None):
    parser = ClosedParser(description=__doc__)
    parser.add_argument('--endpoint',required=True)
    parser.add_argument('--output-dir',type=Path,required=True)
    try:
        args = parser.parse_args(argv)
        result = diagnose(args.endpoint,args.output_dir)
    except SystemExit as error:
        return 0 if error.code == 0 else 1
    except BaseException as error:
        code = str(error) if isinstance(error,DiagnosticSmokeError) and str(error) in CODES else 'trace'
        print(json.dumps({'known_complete':False,'code':code,'family':'ipv4','production_acceptance':False}))
        return 1
    print(json.dumps(result,sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
