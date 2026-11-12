#!/usr/bin/env python3
"""Read exactly the two synthetic, collector-produced acceptance selections."""
import argparse
import json
from pathlib import Path
from mcp_smoke import Client, MODERN, LEGACY


def load_receipts(path):
    with Path(path).open('rb') as source:
        raw = source.read(65537)
    if len(raw) > 65536:
        raise ValueError('collector receipts exceed bound')
    receipts = json.loads(raw)
    if not isinstance(receipts, list) or len(receipts) != 2:
        raise ValueError('two collector receipts required')
    if {r.get('provider') for r in receipts if isinstance(r, dict)} != {'w3c', 'chromium'}:
        raise ValueError('unexpected collector fixture providers')
    for receipt in receipts:
        if set(receipt) != {'provider', 'tool', 'arguments', 'resource', 'expected'}:
            raise ValueError('invalid collector receipt fields')
        provider = receipt['provider']
        args = receipt['arguments']
        if receipt['tool'] != provider + '.get' or not isinstance(args, dict):
            raise ValueError('unexpected collector fixture tool')
        snapshot = args.get('snapshot', '')
        digest = snapshot.removeprefix('blake3:') if isinstance(snapshot, str) else ''
        if len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
            raise ValueError('capture-fixed collector snapshot required')
        resource = receipt['resource']
        if not isinstance(resource, str) or not resource.startswith('devres://' + provider + '/') or len(resource) > 8192:
            raise ValueError('unexpected collector fixture resource')
        expected = receipt['expected']
        if not isinstance(expected, str) or not 1 <= len(expected) <= 256:
            raise ValueError('invalid collector content token')
    return receipts


def verify(client, receipts):
    for revision in (MODERN, LEGACY):
        if revision == LEGACY:
            client.call('initialize', {'protocolVersion': revision,
                        'clientInfo': {'name': 'devres-collector-smoke', 'version': '1'},
                        'capabilities': {}}, revision)
        for receipt in receipts:
            detail = client.tool(receipt['tool'], receipt['arguments'], revision)
            assert receipt['expected'] in detail.get('page', {}).get('text', ''), 'collector tool content changed'
            assert detail.get('attribution', {}).get('readable_notice'), 'collector tool notice missing'
            assert detail.get('selection', {}).get('snapshot') == receipt['arguments']['snapshot'], 'collector snapshot changed'
            resource = client.call('resources/read', {'uri': receipt['resource']}, revision)
            contents = resource.get('contents', [])
            assert contents and receipt['expected'] in contents[0].get('text', ''), 'collector resource content changed'
            assert contents[0].get('_meta', {}).get('license'), 'collector resource license missing'
            assert any(isinstance(item.get('text'), str) and item['text'].strip()
                       for item in contents[1:]), 'collector resource readable attribution missing'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', required=True)
    parser.add_argument('--ca', required=True)
    parser.add_argument('--receipts', required=True)
    args = parser.parse_args()
    verify(Client(args.url, args.ca), load_receipts(args.receipts))
    print('Collector-produced W3C/Chromium pinned content and attribution verified over HTTP')


if __name__ == '__main__':
    main()
