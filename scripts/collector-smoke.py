#!/usr/bin/env python3
"""Read fixed synthetic collector selections and retained RFC generations."""
import argparse
import json
from pathlib import Path
from mcp_smoke import Client, MODERN, LEGACY

RFC_BODY = 'First-party synthetic fixturetransport historicalfixturebody. Not official RFC content.\n'
RFC_NOTICE = 'https://fixtures.invalid/devres/rfc-retained\nFirst-party synthetic retained RFC acceptance by dev-resources-MCP contributors, AGPL-3.0-only. This is not upstream source or upstream licensing evidence.'


def load_receipts(path):
    with Path(path).open('rb') as source:
        raw = source.read(65537)
    if len(raw) > 65536:
        raise ValueError('collector receipts exceed bound')
    receipts = json.loads(raw)
    if not isinstance(receipts, list) or len(receipts) not in (2, 3):
        raise ValueError('two or three fixture receipts required')
    providers = {r.get('provider') for r in receipts if isinstance(r, dict)}
    expected_providers = {'w3c', 'chromium'} if len(receipts) == 2 else {'w3c', 'chromium', 'rfc'}
    if providers != expected_providers:
        raise ValueError('unexpected collector fixture providers')
    for receipt in receipts:
        if set(receipt) != {'provider', 'tool', 'arguments', 'resource', 'expected'}:
            raise ValueError('invalid collector receipt fields')
        provider = receipt['provider']
        args = receipt['arguments']
        expected_tool = 'rfc.fulltext_search' if provider == 'rfc' else provider + '.get'
        if receipt['tool'] != expected_tool or not isinstance(args, dict):
            raise ValueError('unexpected collector fixture tool')
        snapshot = args.get('snapshot', '')
        digest = snapshot.removeprefix('blake3:') if isinstance(snapshot, str) else ''
        if len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
            raise ValueError('capture-fixed collector snapshot required')
        resource = receipt['resource']
        if not isinstance(resource, str) or not resource.startswith('devres://' + provider + '/') or len(resource) > 8192:
            raise ValueError('unexpected collector fixture resource')
        if provider == 'rfc':
            prefix = 'devres://rfc/9000/txt/'
            capture = resource.removeprefix(prefix).removeprefix('blake3:')
            if (args.get('query') != 'fixturetransport' or not resource.startswith(prefix)
                    or len(capture) != 64 or any(c not in '0123456789abcdef' for c in capture)):
                raise ValueError('invalid retained RFC fixture selection')
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
            if receipt['provider'] == 'rfc':
                verify_rfc(client, receipt, detail, revision)
            else:
                assert receipt['expected'] in detail.get('page', {}).get('text', ''), 'collector tool content changed'
                assert detail.get('selection', {}).get('snapshot') == receipt['arguments']['snapshot'], 'collector snapshot changed'
            assert detail.get('attribution', {}).get('readable_notice'), 'fixture tool notice missing'
            resource = client.call('resources/read', {'uri': receipt['resource']}, revision)
            contents = resource.get('contents', [])
            assert contents and receipt['expected'] in contents[0].get('text', ''), 'collector resource content changed'
            if receipt['provider'] == 'rfc':
                assert contents[0].get('text') == RFC_BODY, 'RFC resource bytes changed'
                assert [item.get('text') for item in contents[1:]] == [RFC_NOTICE], 'RFC resource notice bytes changed'
                metadata = contents[0].get('_meta', {})
                capture = receipt['resource'].rsplit('/', 1)[-1]
                assert metadata.get('source_evidence', {}).get('capture', {}).get('id') == capture, 'RFC resource capture evidence changed'
                attribution = metadata.get('attribution', {})
                assert attribution.get('status') == 'ready', 'RFC resource attribution unqualified'
                generations = attribution.get('generations', [])
                assert generations, 'RFC resource attribution generations missing'
                for generation in generations:
                    notices = generation.get('notices', [])
                    assert notices and all(notice.get('license') == 'AGPL-3.0-only' for notice in notices), 'RFC resource fixture license missing'
            else:
                assert contents[0].get('_meta', {}).get('license'), 'collector resource license missing'
            assert any(isinstance(item.get('text'), str) and item['text'].strip()
                       for item in contents[1:]), 'collector resource readable attribution missing'


def verify_rfc(client, receipt, pinned, revision):
    args = receipt['arguments']
    capture = receipt['resource'].rsplit('/', 1)[-1]
    assert pinned.get('snapshot') == args['snapshot'], 'RFC selected snapshot changed'
    assert pinned.get('coverage', {}).get('acquisition_complete') is False, 'RFC partial coverage hidden'
    assert pinned.get('coverage', {}).get('searchable_documents') == 2, 'RFC search coverage changed'
    assert [item['number'] for item in pinned.get('items', [])] == [9000, 9001], 'RFC pinned order/membership changed'
    assert pinned['items'][0]['capture']['id'] == capture, 'RFC historical capture changed'
    assert receipt['expected'] in pinned['items'][0]['excerpt'], 'RFC historical snippet changed'
    unpinned_args = dict(args)
    del unpinned_args['snapshot']
    current = client.tool(receipt['tool'], unpinned_args, revision)
    assert current.get('snapshot') != args['snapshot'], 'RFC current snapshot did not advance'
    assert current.get('total') == 2, 'RFC partial search disappeared'
    current_item = next(item for item in current['items'] if item['number'] == 9000)
    assert current_item['capture']['id'] != capture, 'RFC current capture did not advance'
    page = client.tool(receipt['tool'], dict(args, offset=1, limit=1), revision)
    assert [item['number'] for item in page['items']] == [9001], 'RFC pinned pagination changed'
    assert page.get('next_offset') is None, 'RFC pinned final page changed'
    historical = client.tool('rfc.format_get', {'number': 9000, 'format': 'txt', 'capture': capture}, revision)
    assert historical.get('page', {}).get('text') == RFC_BODY, 'RFC historical body bytes changed'
    assert historical.get('attribution', {}).get('readable_notice') == RFC_NOTICE, 'RFC historical notice bytes changed'
    assert pinned.get('attribution', {}).get('readable_notice') == RFC_NOTICE, 'RFC pinned notice bytes changed'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', required=True)
    parser.add_argument('--ca', required=True)
    parser.add_argument('--receipts', required=True)
    args = parser.parse_args()
    verify(Client(args.url, args.ca), load_receipts(args.receipts))
    print('Selected collector content, retained history and notices verified over HTTP')


if __name__ == '__main__':
    main()
