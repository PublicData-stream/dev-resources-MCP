"""Embed the observer proof in a new controller before generating its source pin."""

import ast
from pathlib import Path

from observer_retained_rows import RETAINED_PARALLEL_PROFILE, RETAINED_SERIAL_PROFILE


def _observer_replace(source, before, after):
    if source.count(before) != 1:
        raise ValueError('expected_one_observer_controller_site')
    return source.replace(before, after, 1)


def render_observer_controller(source, *, profile=RETAINED_SERIAL_PROFILE):
    """Transform the reviewed controller shape without changing its frozen input."""
    if profile not in (RETAINED_SERIAL_PROFILE, RETAINED_PARALLEL_PROFILE):
        raise ValueError('unsupported_retained_row_profile')
    tree = ast.parse(source)
    methods = [method for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'Controller'
               for method in node.body if isinstance(method, ast.FunctionDef)
               and method.name == '_retained_row_manifest']
    if len(methods) != 1:
        raise ValueError('expected_one_retained_row_manifest')
    method = methods[0]
    lines = source.splitlines(keepends=True)
    proof_call = 'retained_row_manifest(self.old.k)'
    if profile == RETAINED_PARALLEL_PROFILE:
        proof_call = 'retained_row_manifest(self.old.k, profile=RETAINED_PARALLEL_PROFILE)'
    source = (''.join(lines[:method.lineno - 1])
              + f'    def _retained_row_manifest(self):\n        return {proof_call}\n'
              + ''.join(lines[method.end_lineno:]))

    source = _observer_replace(source,
        "            self.change_config('observer', 'observer-config')\n"
        "            baseline = self._sql_fingerprint()\n"
        "            retained_rows = self._retained_row_manifest()\n",
        "            baseline = self._sql_fingerprint()\n"
        "            retained_rows = self._retained_row_manifest()\n"
        "            self.guard()\n"
        "            require(self.state() == state and self._sql_fingerprint() == baseline,\n"
        "                    'observer_baseline_identity_changed')\n"
        "            self.change_config('observer', 'observer-config')\n")
    source = _observer_replace(source,
        "        if verify:\n"
        "            self.observer_proof()\n"
        "            current = self._retained_row_manifest()\n"
        "            require(current == record['retained_rows'], 'observer_retained_rows_changed')\n",
        "        if verify:\n"
        "            proof = self.observer_proof()\n"
        "            current = self._retained_row_manifest()\n"
        "            require(current == record['retained_rows'], 'observer_retained_rows_changed')\n"
        "            require(self.observer_proof() == proof, 'observer_identity_changed_during_proof')\n")

    # Embedding avoids importing runtime modules from mutable Python search
    # paths. The successor's existing controller digest covers the helper too.
    helper = Path(__file__).with_name('observer_retained_rows.py').read_text(encoding='utf-8')
    rendered = _observer_replace(source, '\ndef main():\n', '\n' + helper + '\n\ndef main():\n')
    ast.parse(rendered)
    return rendered
