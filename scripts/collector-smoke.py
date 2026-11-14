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
    if not isinstance(receipts, list) or not 2 <= len(receipts) <= 4:
        raise ValueError('two to four fixture receipts required')
    providers = {r.get('provider') for r in receipts if isinstance(r, dict)}
    if (not {'w3c', 'chromium'} <= providers or not providers <= {'w3c', 'chromium', 'rfc', 'rustsec'}
            or len(providers) != len(receipts)):
        raise ValueError('unexpected collector fixture providers')
    for receipt in receipts:
        if set(receipt) != {'provider', 'tool', 'arguments', 'resource', 'expected'}:
            raise ValueError('invalid collector receipt fields')
        provider = receipt['provider']
        args = receipt['arguments']
        expected_tool = ('rfc.fulltext_search' if provider == 'rfc' else
                         'packages.crate.advisory_get' if provider == 'rustsec' else provider + '.get')
        if receipt['tool'] != expected_tool or not isinstance(args, dict):
            raise ValueError('unexpected collector fixture tool')
        snapshot = args.get('snapshot', '')
        digest = snapshot.removeprefix('blake3:') if isinstance(snapshot, str) else ''
        if len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
            raise ValueError('capture-fixed collector snapshot required')
        resource = receipt['resource']
        prefix = 'devres://advisory/rustsec/' if provider == 'rustsec' else 'devres://' + provider + '/'
        if not isinstance(resource, str) or not resource.startswith(prefix) or len(resource) > 8192:
            raise ValueError('unexpected collector fixture resource')
        if provider == 'rfc':
            prefix = 'devres://rfc/9000/txt/'
            capture = resource.removeprefix(prefix).removeprefix('blake3:')
            if (args.get('query') != 'fixturetransport' or not resource.startswith(prefix)
                    or len(capture) != 64 or any(c not in '0123456789abcdef' for c in capture)):
                raise ValueError('invalid retained RFC fixture selection')
        if provider == 'rustsec' and (args.get('id') != 'RUSTSEC-2026-9001'
                or resource != 'devres://advisory/rustsec/' + args['id'] + '/' + snapshot):
            raise ValueError('invalid RustSec fixture selection')
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
            elif receipt['provider'] == 'rustsec':
                assert detail.get('snapshot', {}).get('id') == receipt['arguments']['snapshot'], 'RustSec snapshot changed'
                assert detail.get('resource_uri') == receipt['resource'], 'RustSec resource changed'
                assert receipt['expected'] in detail.get('page', {}).get('text', ''), 'RustSec source changed'
                assert detail.get('attribution', {}).get('status') == 'ready', 'RustSec attribution unqualified'
                catalog = client.tool('packages.crate.advisory_catalog_search',
                                      {'snapshot': receipt['arguments']['snapshot'], 'limit': 1}, revision)
                assert catalog.get('snapshot', {}).get('id') == receipt['arguments']['snapshot'], 'RustSec catalog snapshot changed'
                assert [row.get('id') for row in catalog.get('items', [])] == [receipt['arguments']['id']], 'RustSec catalog membership changed'
                assert catalog.get('attribution', {}).get('status') == 'ready' and catalog['attribution'].get('readable_notice'), 'RustSec catalog attribution missing'
                verify_rustsec_notices(client, detail['attribution'], revision)
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
            elif receipt['provider'] == 'rustsec':
                assert contents[0].get('_meta', {}).get('attribution', {}).get('status') == 'ready', 'RustSec resource unqualified'
                evidence = contents[0].get('_meta', {}).get('source_evidence', {})
                assert evidence.get('snapshot', {}).get('id') == receipt['arguments']['snapshot'], 'RustSec resource snapshot changed'
            else:
                assert contents[0].get('_meta', {}).get('license'), 'collector resource license missing'
            assert any(isinstance(item.get('text'), str) and item['text'].strip()
                       for item in contents[1:]), 'collector resource readable attribution missing'


def verify_rustsec_notices(client, attribution, revision):
    uris = attribution.get('resource_uris', [])
    assert isinstance(uris, list) and 1 <= len(uris) <= 8 and len(set(uris)) == len(uris), 'RustSec notice resources missing'
    generations = attribution.get('generations', [])
    assert isinstance(generations, list) and len(generations) == len(uris), 'notice generations missing'
    expected = {}
    for generation in generations:
        entries = []
        for notice in generation.get('notices', []):
            assert isinstance(notice.get('source_url'), str) and isinstance(notice.get('text'), str), 'invalid original notice'
            entry = notice['source_url'] + '\n' + notice['text']
            if entry not in entries:
                entries.append(entry)
        text = '\n\n'.join(entries)
        uri = 'devres://attribution/' + generation.get('id', '')
        assert text and len(text.encode()) <= 65536 and uri not in expected, 'invalid notice generation'
        expected[uri] = text
    assert set(expected) == set(uris), 'notice generation identity mismatch'
    combined = []
    for uri in uris:
        assert isinstance(uri, str) and uri.startswith('devres://attribution/blake3:') and len(uri) <= 128, 'invalid notice resource'
        offset, text = 0, []
        for _ in range(64):
            result = client.call('resources/read', {'uri': uri + '?offset=' + str(offset) + '&limit=1024'}, revision)
            page = result.get('contents', [])
            assert len(page) == 1 and isinstance(page[0].get('text'), str), 'notice page missing'
            metadata = page[0].get('_meta', {})
            chunk = page[0]['text']
            end = offset + len(chunk.encode('utf-8'))
            assert page[0].get('uri') == uri and metadata.get('attribution', {}).get('id') == uri.rsplit('/', 1)[-1], 'notice generation changed'
            assert metadata.get('offset') == offset and metadata.get('total_bytes') == len(expected[uri].encode()) and end <= metadata['total_bytes'], 'notice byte offset changed'
            assert metadata.get('attribution', {}).get('policy_epoch') == 1, 'notice policy changed'
            text.append(chunk)
            next_offset = metadata.get('next_offset')
            if next_offset is None:
                assert end == metadata['total_bytes'], 'notice truncated'
                break
            assert isinstance(next_offset, int) and next_offset == end and next_offset > offset, 'notice pagination failed'
            offset = next_offset
        else:
            raise AssertionError('notice pagination exceeded fixture bound')
        text = ''.join(text)
        assert text == expected[uri], 'original notice bytes changed'
        combined.append(text)
    text = '\n'.join(combined)
    for required in ('First-party synthetic RustSec fixture notice', 'CC-BY-4.0', 'GHSA-synthetic-fixture', '원문'):
        assert required in text, 'original RustSec fixture notice or terms missing'


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
