#!/usr/bin/env python3
"""Build a private Scaleway 2023 bucket-policy candidate entirely offline.

This tool neither applies policies nor proves identities, IAM grants or provider
acceptance. Only explicit supplied application principals are replaced.
"""
import argparse
import copy
from datetime import datetime
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys
import uuid


VERSION = '2023-04-17'
MAX_BYTES = 1024 * 1024
FIELDS = {'reader_application_id', 'writer_application_id', 'bucket', 'prefix', 'source_ips'}
SIDS = ('devresStaticReaderObjects', 'devresStaticReaderListing',
        'devresStaticWriterObjects', 'devresStaticWriterListing')
STRING_OPERATORS = {'StringEquals', 'StringNotEquals', 'StringEqualsIgnoreCase',
                    'StringNotEqualsIgnoreCase', 'StringLike', 'StringNotLike'}
DATE_OPERATORS = {'DateGreaterThan', 'DateGreaterThanEquals', 'DateLessThan', 'DateLessThanEquals'}


class PolicyError(ValueError):
    """Fixed diagnostics only; input policy/identities never enter error text."""


def canonical_uuid(value):
    if not isinstance(value, str):
        raise PolicyError('invalid_application_identifier')
    try:
        parsed = uuid.UUID(value)
    except ValueError as error:
        raise PolicyError('invalid_application_identifier') from error
    if str(parsed) != value or parsed.int == 0:
        raise PolicyError('invalid_application_identifier')
    return value


def strings(value, maximum=128):
    values = [value] if isinstance(value, str) else value
    if (not isinstance(values, list) or not 1 <= len(values) <= maximum
            or any(not isinstance(item, str) or not item or len(item) > 1024
                   or any(ord(char) < 32 or ord(char) == 127 for char in item) for item in values)
            or len(set(values)) != len(values)):
        raise PolicyError('unsupported_policy_value')
    return values


def networks(value):
    values = strings(value, maximum=16)
    result = []
    for item in values:
        try:
            network = ipaddress.ip_network(item, strict=True)
        except ValueError as error:
            raise PolicyError('invalid_source_ip') from error
        if network.prefixlen == 0:
            raise PolicyError('unrestricted_source_ip_refused')
        result.append(str(network))
    if len(set(result)) != len(result):
        raise PolicyError('duplicate_source_ip')
    return sorted(result, key=lambda item: (ipaddress.ip_network(item).version,
                                           int(ipaddress.ip_network(item).network_address),
                                           ipaddress.ip_network(item).prefixlen))


def checked_config(config):
    if not isinstance(config, dict) or set(config) != FIELDS:
        raise PolicyError('unexpected_configuration_fields')
    result = copy.deepcopy(config)
    for role in ('reader', 'writer'):
        canonical_uuid(result[role + '_application_id'])
    if result['reader_application_id'] == result['writer_application_id']:
        raise PolicyError('distinct_applications_required')
    bucket, prefix = result['bucket'], result['prefix']
    if (not isinstance(bucket, str) or not re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', bucket)
            or '..' in bucket or any(part.startswith('-') or part.endswith('-') for part in bucket.split('.'))):
        raise PolicyError('invalid_bucket')
    try:
        ipaddress.ip_address(bucket)
    except ValueError:
        pass
    else:
        raise PolicyError('invalid_bucket')
    if (not isinstance(prefix, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/-]{0,511}', prefix)
            or any(part in ('', '.', '..') for part in prefix.split('/'))):
        raise PolicyError('invalid_prefix')
    if not isinstance(result['source_ips'], list):
        raise PolicyError('explicit_source_ips_required')
    result['source_ips'] = networks(result['source_ips'])
    return result


def principals(value):
    if not isinstance(value, dict) or set(value) != {'SCW'}:
        raise PolicyError('ambiguous_principal_refused')
    values = strings(value['SCW'])
    for item in values:
        match = re.fullmatch(r'(application_id|user_id):(.+)', item)
        if match is None:
            raise PolicyError('wildcard_or_unsupported_principal')
        canonical_uuid(match[2])
    return values


def condition_checked(condition):
    if not isinstance(condition, dict) or not condition:
        raise PolicyError('unsupported_condition')
    for operator, fields in condition.items():
        if not isinstance(fields, dict) or not fields:
            raise PolicyError('unsupported_condition')
        if operator == 'Bool':
            if set(fields) != {'aws:SecureTransport'} or fields['aws:SecureTransport'] not in ('true', 'false'):
                raise PolicyError('unsupported_condition')
        elif operator in ('IpAddress', 'NotIpAddress'):
            if set(fields) != {'aws:SourceIp'}:
                raise PolicyError('unsupported_condition')
            networks(fields['aws:SourceIp'])
        elif operator in STRING_OPERATORS:
            if not set(fields) <= {'s3:prefix', 'aws:Referer'}:
                raise PolicyError('unsupported_condition')
            for value in fields.values():
                strings(value)
        elif operator in DATE_OPERATORS:
            if set(fields) != {'aws:CurrentTime'} or not isinstance(fields['aws:CurrentTime'], str):
                raise PolicyError('unsupported_condition')
            try:
                stamp = datetime.fromisoformat(fields['aws:CurrentTime'].replace('Z', '+00:00'))
                if stamp.utcoffset() is None:
                    raise ValueError()
            except ValueError as error:
                raise PolicyError('unsupported_condition') from error
        else:
            raise PolicyError('unsupported_condition')


def role_statements(config):
    result = []
    for role, offset in (('reader', 0), ('writer', 2)):
        condition = {'Bool': {'aws:SecureTransport': 'true'},
                     'IpAddress': {'aws:SourceIp': config['source_ips']}}
        principal = {'SCW': 'application_id:' + config[role + '_application_id']}
        objects = ['s3:GetObject']
        listing = ['s3:ListBucket']
        if role == 'writer':
            objects += ['s3:PutObject', 's3:AbortMultipartUpload', 's3:ListMultipartUploadParts']
            listing += ['s3:ListBucketMultipartUploads']
        result.append({'Sid': SIDS[offset], 'Effect': 'Allow', 'Principal': copy.deepcopy(principal),
                       'Action': objects, 'Resource': [config['bucket'] + '/' + config['prefix'] + '/*'],
                       'Condition': copy.deepcopy(condition)})
        condition['StringLike'] = {'s3:prefix': [config['prefix'] + '/*']}
        result.append({'Sid': SIDS[offset + 1], 'Effect': 'Allow', 'Principal': copy.deepcopy(principal),
                       'Action': listing, 'Resource': [config['bucket']], 'Condition': condition})
    return result


def merge_policy(current, config):
    config = checked_config(config)
    if (not isinstance(current, dict) or set(current) - {'Version', 'Id', 'Statement'}
            or current.get('Version') != VERSION or not isinstance(current.get('Statement'), list)
            or len(current['Statement']) > 256):
        raise PolicyError('unsupported_bucket_policy')
    if 'Id' in current and (not isinstance(current['Id'], str) or len(current['Id']) > 280):
        raise PolicyError('unsupported_bucket_policy')
    selected = {'application_id:' + config[role + '_application_id'] for role in ('reader', 'writer')}
    retained, seen_sids = [], set()
    for statement in current['Statement']:
        if (not isinstance(statement, dict) or set(statement) - {'Sid', 'Effect', 'Principal', 'Action', 'Resource', 'Condition'}
                or statement.get('Effect') != 'Allow'):
            raise PolicyError('unsupported_statement')
        members = principals(statement.get('Principal'))
        for action in strings(statement.get('Action')):
            if not re.fullmatch(r'(?:\*|s3:[A-Za-z0-9*?]+)', action):
                raise PolicyError('unsupported_action')
        for resource in strings(statement.get('Resource')):
            if not (resource == '*' or resource == config['bucket'] or resource.startswith(config['bucket'] + '/')):
                raise PolicyError('unexpected_bucket_resource')
        if 'Condition' in statement:
            condition_checked(statement['Condition'])
        sid = statement.get('Sid')
        if sid is not None:
            if not isinstance(sid, str) or not sid or len(sid) > 280 or sid in seen_sids:
                raise PolicyError('duplicate_or_invalid_statement_id')
            seen_sids.add(sid)
        remainder = [member for member in members if member not in selected]
        if not remainder:
            continue
        preserved = copy.deepcopy(statement)
        if remainder != members:
            preserved['Principal']['SCW'] = remainder if isinstance(statement['Principal']['SCW'], list) else remainder[0]
        retained.append(preserved)
    if any(statement.get('Sid') in SIDS for statement in retained):
        raise PolicyError('generated_statement_id_conflict')
    candidate = copy.deepcopy(current)
    candidate['Statement'] = retained + role_statements(config)
    return candidate


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError('duplicate_json_key')
        result[key] = value
    return result


def private_parent(path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts or any(item.is_symlink() for item in (path, *path.parents)):
        raise PolicyError('unsafe_private_path')
    info = path.parent.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise PolicyError('private_parent_required')
    return path


def read_json(path):
    path = private_parent(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077
                or info.st_nlink != 1 or info.st_size > MAX_BYTES):
            raise PolicyError('unsafe_private_input')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            value = stream.read(MAX_BYTES + 1)
        if len(value) > MAX_BYTES:
            raise PolicyError('private_input_too_large')
    finally:
        os.close(descriptor)
    return json.loads(value, object_pairs_hook=unique_object,
                      parse_constant=lambda _: (_ for _ in ()).throw(PolicyError('invalid_json_constant')))


def render(current_path, inputs_path, output_path):
    candidate = merge_policy(read_json(current_path), read_json(inputs_path))
    output_path = private_parent(output_path)
    encoded = (json.dumps(candidate, indent=2, ensure_ascii=True) + '\n').encode()
    if len(encoded) > MAX_BYTES:
        raise PolicyError('candidate_too_large')
    descriptor = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, 'wb', closefd=False) as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        directory = os.open(output_path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        output_path.unlink(missing_ok=True)
        raise
    finally:
        os.close(descriptor)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--current-policy', required=True, type=Path)
    parser.add_argument('--inputs', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    render(args.current_policy, args.inputs, args.output)
    print('Private policy candidate created; provider application and acceptance remain separate.')


if __name__ == '__main__':
    try:
        main()
    except (PolicyError, OSError, ValueError, TypeError, RecursionError):
        print('Policy candidate refused; inspect private inputs before retrying.', file=sys.stderr)
        raise SystemExit(1) from None
