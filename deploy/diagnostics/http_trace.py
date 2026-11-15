"""Fixed-operation IPv4 fixture HTTP tracing; transport is explicitly injected.

This module opens no network connections. An injected transport is responsible for
its own fixed destination, response/deadline bounds and cancellation. Neither a
URI nor caller arguments, headers or arbitrary RPC methods are accepted here.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import json
import time

from .evidence import EventRecorder


class Operation(Enum):
    DISCOVER = 'discover'
    INITIALIZE = 'initialize'
    LIST_TOOLS = 'list_tools'
    SERVER_INFO = 'server_info'


@dataclass(frozen=True)
class FixedRequest:
    operation: Operation
    revision: str

    @property
    def method(self):
        return {Operation.DISCOVER: 'server/discover', Operation.INITIALIZE: 'initialize',
                Operation.LIST_TOOLS: 'tools/list', Operation.SERVER_INFO: 'tools/call'}[self.operation]

    @property
    def tool(self):
        return 'server.info' if self.operation is Operation.SERVER_INFO else 'none'


class HttpProbeError(RuntimeError):
    pass


class FixedHttpProbe:
    def __init__(self, recorder: EventRecorder, exchange, *, assert_response, response_limit=8 * 1024**2):
        if type(response_limit) is not int or not 1 <= response_limit <= 8 * 1024**2:
            raise ValueError('response_bound')
        if not callable(exchange) or not callable(assert_response):
            raise ValueError('trusted_callbacks_required')
        self.recorder, self.exchange, self.response_limit = recorder, exchange, response_limit
        self.assert_response = assert_response

    def run(self, operation: Operation, revision: str):
        if not isinstance(operation, Operation) or revision not in {'2025-11-25', '2026-07-28'}:
            raise ValueError('fixed_operation_required')
        request = FixedRequest(operation, revision)
        started = time.monotonic_ns()
        status = None

        def trace(stage, code='ok'):
            try:
                self.recorder.record('http', {'family': 'ipv4', 'revision': revision,
                    'operation': operation.value, 'method': request.method, 'tool': request.tool,
                    'stage': stage, 'code': code, 'status': status,
                    'elapsed_ns': time.monotonic_ns() - started})
            except BaseException:
                raise HttpProbeError('trace') from None

        trace('start')
        code = 'transport'
        try:
            status, body = self.exchange(request)
            if type(status) is not int or not 100 <= status <= 599:
                status = None
                raise HttpProbeError('http_status')
            trace('response')
            code = 'http_status'
            if status != 200:
                raise HttpProbeError(code)
            code = 'response_bound'
            if not isinstance(body, bytes) or len(body) > self.response_limit:
                raise HttpProbeError(code)
            code = 'decode'
            # SSE fixtures must contain exactly one JSON message. Ignore only
            # comments and framing fields; no response text enters the ledger.
            stripped = body.lstrip()
            if stripped.startswith((b'data:', b':', b'event:')):
                values = [line[5:].lstrip() for line in body.splitlines() if line.startswith(b'data:')]
                if len(values) != 1:
                    raise HttpProbeError(code)
                stripped = values[0]
            value = json.loads(stripped)
            trace('decode')
            code = 'assertion'
            if not isinstance(value, dict) or value.get('jsonrpc') != '2.0' or 'error' in value or not isinstance(value.get('result'), dict):
                raise HttpProbeError(code)
            result = value['result']
            if operation is Operation.LIST_TOOLS and not isinstance(result.get('tools'), list):
                raise HttpProbeError(code)
            if operation is Operation.SERVER_INFO and (result.get('isError') is True or not isinstance(result.get('structuredContent'), dict)):
                raise HttpProbeError(code)
            # The original trusted smoke assertion owns inventory/identity and
            # all semantic checks. Shape checks alone cannot issue a receipt.
            if self.assert_response(request, value) is not True:
                raise HttpProbeError(code)
            trace('assertion')
            trace('receipt')
            return value
        except BaseException as error:
            if isinstance(error, HttpProbeError) and str(error) == 'trace':
                code = 'trace'
            try:
                trace('failure', 'cancelled' if isinstance(error, (KeyboardInterrupt, SystemExit)) else code)
            except BaseException:
                pass
            # Never propagate a transport/decode exception message containing a
            # response, URL, headers or private inputs.
            raise HttpProbeError(code) from None
