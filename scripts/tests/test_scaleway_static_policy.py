"""Offline merge invariants; synthetic policies and all temporary state use /tmp."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('scaleway_static_policy', ROOT / 'scripts/scaleway-static-policy.py')
policy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(policy)
READER = '11111111-1111-4111-8111-111111111111'
WRITER = '22222222-2222-4222-8222-222222222222'
OWNER = '33333333-3333-4333-8333-333333333333'
OTHER = '44444444-4444-4444-8444-444444444444'


class StaticPolicyTests(unittest.TestCase):
    def setUp(self):
        self.config = {'reader_application_id': READER, 'writer_application_id': WRITER,
                       'bucket': 'devres-archive', 'prefix': 'production',
                       'source_ips': ['2001:db8::1/128', '192.0.2.1/32']}
        self.owner = {'Sid': 'owner', 'Effect': 'Allow', 'Principal': {'SCW': 'user_id:' + OWNER},
                      'Action': '*', 'Resource': ['devres-archive', 'devres-archive/*'],
                      'Condition': {'Bool': {'aws:SecureTransport': 'true'}}}
        self.shared = {'Sid': 'shared-reader', 'Effect': 'Allow',
                       'Principal': {'SCW': ['application_id:' + READER, 'application_id:' + OTHER]},
                       'Action': ['s3:GetObject', 's3:DeleteObject'], 'Resource': ['devres-archive/*'],
                       'Condition': {'IpAddress': {'aws:SourceIp': '192.0.2.0/24'}}}
        self.broad = {'Sid': 'old-writer', 'Effect': 'Allow',
                      'Principal': {'SCW': ['application_id:' + WRITER, 'application_id:' + READER]},
                      'Action': ['s3:*'], 'Resource': ['devres-archive', 'devres-archive/*']}
        self.current = {'Version': policy.VERSION, 'Id': 'existing-private-policy',
                        'Statement': [copy.deepcopy(self.owner), copy.deepcopy(self.shared), copy.deepcopy(self.broad)]}
        self.temporary = tempfile.TemporaryDirectory(dir='/tmp')
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def private(self, name, value):
        path = self.directory / name
        path.write_text(value if isinstance(value, str) else json.dumps(value))
        path.chmod(0o600)
        return path

    def test_mixed_principals_preserve_owner_and_all_unrelated_grants_exactly(self):
        original = copy.deepcopy(self.current)
        result = policy.merge_policy(self.current, self.config)
        self.assertEqual(self.current, original)
        self.assertEqual(result['Id'], original['Id'])
        self.assertEqual(result['Statement'][0], self.owner)
        self.assertEqual(result['Statement'][1], {**self.shared, 'Principal': {'SCW': ['application_id:' + OTHER]}})
        self.assertNotIn('old-writer', [statement.get('Sid') for statement in result['Statement']])
        self.assertEqual(len(result['Statement']), 6)
        for statement in result['Statement'][:2]:
            self.assertFalse(set(policy.principals(statement['Principal'])) & {'application_id:' + READER,
                                                                            'application_id:' + WRITER})

    def test_selected_roles_have_only_exact_prefix_tls_ip_actions(self):
        result = policy.merge_policy(self.current, self.config)
        for role, app in (('reader', READER), ('writer', WRITER)):
            statements = [statement for statement in result['Statement']
                          if policy.principals(statement['Principal']) == ['application_id:' + app]]
            self.assertEqual(len(statements), 2)
            actions = {action for statement in statements for action in statement['Action']}
            expected = {'s3:GetObject', 's3:ListBucket'}
            if role == 'writer':
                expected |= {'s3:PutObject', 's3:AbortMultipartUpload', 's3:ListMultipartUploadParts', 's3:ListBucketMultipartUploads'}
            self.assertEqual(actions, expected)
            self.assertFalse(actions & {'s3:DeleteObject', 's3:DeleteObjectVersion'})
            for statement in statements:
                self.assertEqual(statement['Effect'], 'Allow')
                self.assertEqual(statement['Condition']['Bool'], {'aws:SecureTransport': 'true'})
                self.assertEqual(statement['Condition']['IpAddress']['aws:SourceIp'], ['192.0.2.1/32', '2001:db8::1/128'])
                if statement['Resource'] == ['devres-archive']:
                    self.assertEqual(statement['Condition']['StringLike'], {'s3:prefix': ['production/*']})
                else:
                    self.assertEqual(statement['Resource'], ['devres-archive/production/*'])

    def test_wildcard_is_never_waived_even_for_owner_or_source_ip_condition(self):
        for principal in ('*', {'SCW': '*'}, {'SCW': ['user_id:' + OWNER, '*']},
                          {'SCW': 'application_id:*'}, {'AWS': 'owner'}, {'SCW': 'organization_id:' + OWNER}):
            candidate = copy.deepcopy(self.current)
            candidate['Statement'][0]['Principal'] = principal
            with self.subTest(principal=principal), self.assertRaises(policy.PolicyError):
                policy.merge_policy(candidate, self.config)

    def test_unsupported_version_effect_condition_and_sid_conflicts_refuse(self):
        cases = []
        old = copy.deepcopy(self.current)
        old['Version'] = '2012-10-17'
        cases.append(old)
        for changes in ({'Effect': 'Deny'}, {'NotPrincipal': {'SCW': 'application_id:' + READER}},
                        {'Condition': {'Null': {'s3:prefix': 'true'}}},
                        {'Condition': {'Bool': {'unknown:Key': 'true'}}},
                        {'Sid': policy.SIDS[0]}):
            candidate = copy.deepcopy(self.current)
            candidate['Statement'][0].update(changes)
            cases.append(candidate)
        for candidate in cases:
            with self.subTest(candidate=candidate), self.assertRaises(policy.PolicyError):
                policy.merge_policy(candidate, self.config)

    def test_duplicate_and_unsafe_config_values_refuse(self):
        for changes in ({'reader_application_id': WRITER}, {'reader_application_id': 'not-an-application'},
                        {'prefix': ''}, {'prefix': '/production'}, {'prefix': 'production/../outside'},
                        {'prefix': 'production/*'}, {'bucket': 'another/bucket'}, {'bucket': '127.0.0.1'},
                        {'source_ips': []}, {'source_ips': ['0.0.0.0/0']}, {'source_ips': ['::/0']},
                        {'source_ips': ['192.0.2.1', '192.0.2.1/32']}, {'secret_key': 'unsupported'}):
            with self.subTest(changes=changes), self.assertRaises(policy.PolicyError):
                policy.merge_policy(self.current, {**self.config, **changes})
        duplicate = copy.deepcopy(self.current)
        duplicate['Statement'].append(copy.deepcopy(self.owner))
        with self.assertRaises(policy.PolicyError):
            policy.merge_policy(duplicate, self.config)
        duplicate = copy.deepcopy(self.current)
        duplicate['Statement'][1]['Principal']['SCW'].append('application_id:' + READER)
        with self.assertRaises(policy.PolicyError):
            policy.merge_policy(duplicate, self.config)

    def test_fresh_output_is_private_and_existing_output_never_replaced(self):
        current = self.private('current.json', self.current)
        inputs = self.private('inputs.json', self.config)
        output = self.directory / 'candidate.json'
        policy.render(current, inputs, output)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assertEqual(output.stat().st_uid, os.geteuid())
        first = output.read_bytes()
        with self.assertRaises(FileExistsError):
            policy.render(current, inputs, output)
        self.assertEqual(output.read_bytes(), first)

    def test_duplicate_json_key_or_invalid_policy_produces_no_output(self):
        inputs = self.private('inputs.json', self.config)
        output = self.directory / 'candidate.json'
        for content in ('{"Version":"2023-04-17","Version":"2023-04-17","Statement":[]}',
                        '{"Version":"2023-04-17","Statement":[],"value":NaN}',
                        json.dumps({**self.current, 'Version': 'unknown'})):
            current = self.private('current.json', content)
            with self.subTest(content=content), self.assertRaises(policy.PolicyError):
                policy.render(current, inputs, output)
            self.assertFalse(output.exists())

    def test_symlink_hardlink_or_public_input_output_parent_refused(self):
        current = self.private('current.json', self.current)
        inputs = self.private('inputs.json', self.config)
        output = self.directory / 'candidate.json'
        output.symlink_to(current)
        with self.assertRaises(policy.PolicyError):
            policy.render(current, inputs, output)
        self.assertEqual(json.loads(current.read_text()), self.current)
        output.unlink()
        link = self.directory / 'linked-input.json'
        os.link(inputs, link)
        with self.assertRaises(policy.PolicyError):
            policy.render(current, inputs, output)
        link.unlink()
        inputs.chmod(0o644)
        with self.assertRaises(policy.PolicyError):
            policy.render(current, inputs, output)
        inputs.chmod(0o600)
        public = self.directory / 'public'
        public.mkdir(mode=0o755)
        with self.assertRaises(policy.PolicyError):
            policy.render(current, inputs, public / 'candidate.json')
        self.assertFalse((public / 'candidate.json').exists())

    def test_examples_use_only_current_allowlist_actions(self):
        for role in ('readonly', 'readwrite'):
            example = json.loads((ROOT / 'deploy/examples/scaleway-static' / (role + '-bucket-policy.json')).read_text())
            self.assertEqual(example['Version'], policy.VERSION)
            self.assertEqual({statement['Effect'] for statement in example['Statement']}, {'Allow'})
            actions = {action for statement in example['Statement'] for action in statement['Action']}
            self.assertFalse(actions & {'s3:DeleteObject', 's3:DeleteObjectVersion'})
            if role == 'readonly':
                self.assertFalse(actions & {'s3:PutObject', 's3:AbortMultipartUpload'})


if __name__ == '__main__':
    unittest.main()
