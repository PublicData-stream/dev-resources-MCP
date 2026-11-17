"""Source fragment embedded in the fresh controller, before its CLI entrypoint.

All names below refer to the source-bound controller's globals. This file is not
a standalone production command and never imports a consumed controller itself.
"""


def set_field(text, section, key, value):
    """Edit one scalar, rejecting duplicate sections/keys and semantic drift."""
    before = tomllib.loads(text)
    expected = copy.deepcopy(before)
    expected.setdefault(section, {})[key] = value
    pattern = r'(?m)^\[' + re.escape(section) + r'\][^\n]*\n'
    matches = list(re.finditer(pattern, text))
    require(len(matches) == 1, 'one_configuration_section_required')
    start = matches[0].end()
    following = re.search(r'(?m)^\[', text[start:])
    end = start + following.start() if following else len(text)
    body = text[start:end]
    field = r'(?m)^' + re.escape(key) + r'\s*=.*$'
    replacement = key + ' = ' + json.dumps(value)
    if key in before[section]:
        body, count = re.subn(field, lambda _: replacement, body)
        require(count == 1, 'one_configuration_field_required')
    else:
        body = replacement + '\n' + body
    result = text[:start] + body + text[end:]
    require(tomllib.loads(result) == expected, 'observer_configuration_drift')
    return result


def observer_variants(variants):
    reader = variants['paused']['backend']
    active_reader = tomllib.loads(variants['active']['backend'])
    for key in ('endpoint', 'token_file', 'ca_file'):
        reader = set_field(reader, 'writer_client', key, active_reader['writer_client'][key])
    reader = set_field(reader, 'writer_client', 'access', 'status_only')
    observer = variants['paused']['writer']
    observer = set_field(observer, 'storage', 'database_url', active_reader['storage']['database_url'])
    observer = set_field(observer, 'storage', 'blob_dir', '/tmp/devres-observer/cache')
    observer = set_field(observer, 'storage', 'scratch_dir', '/tmp/devres-observer/scratch')
    observer = set_field(observer, 'writer_listener', 'access', 'status_only')
    observer = set_field(observer, 'writer_listener', 'observation_max_pass_secs', 900)
    value = tomllib.loads(observer)
    require(all(value[p]['enabled'] is False for p in PROVIDERS)
            and value['npm']['advisories_enabled'] is False, 'observer_collectors_enabled')
    variants['observer'] = {'backend': reader, 'writer': observer}


def cycle4_edge_bridge():
    """Bind the new bridge and separate receipt before any historical constructor."""
    expected = os.environ.get('DEVRES_ACCEPTANCE_SOURCE_MANIFEST_SHA256', '')
    body = read(Path(WORK) / 'source-manifest.json')
    require(re.fullmatch('[0-9a-f]{64}', expected) and digest(body) == expected, 'edge_external_source_manifest_required')
    manifest = json.loads(body)
    path = Path(__file__).parent / 'edge-readmission.py'
    require(digest(read(path)) == manifest.get('edge-readmission.py'), 'edge_bridge_source_changed')
    receipt_sha = os.environ.get('DEVRES_EDGE_READMISSION_SHA256', '')
    require(re.fullmatch('[0-9a-f]{64}', receipt_sha), 'edge_receipt_pin_required')
    spec = importlib.util.spec_from_file_location('cycle4_exact_edge_bridge', path)
    value = importlib.util.module_from_spec(spec); sys.modules[spec.name] = value; spec.loader.exec_module(value)
    return value, receipt_sha


_Cycle4BaseController = Controller


def admitted_pod_spec(actual, expected, node):
    """Check actual runtime authority, including fields absent from the template."""
    require(actual.get('nodeName') == node and actual.get('nodeSelector') == expected.get('nodeSelector'), 'participant_node_changed')
    for key in ('hostNetwork', 'hostPID', 'hostIPC', 'shareProcessNamespace'):
        require(actual.get(key, False) == expected.get(key, False) and not actual.get(key), 'participant_host_authority_changed')
    for key in ('initContainers', 'ephemeralContainers'):
        require(not actual.get(key), 'participant_extra_container_refused')
    for key in ('serviceAccountName', 'automountServiceAccountToken', 'securityContext', 'volumes'):
        require(actual.get(key) == expected.get(key), 'participant_identity_or_volume_changed')
    require(len(actual.get('containers', [])) == len(expected.get('containers', [])) == 1, 'one_participant_container_required')
    observed, wanted = actual['containers'][0], expected['containers'][0]
    for key in ('image', 'command', 'args', 'env', 'envFrom', 'securityContext', 'volumeMounts', 'lifecycle', 'ports'):
        require(observed.get(key) == wanted.get(key), 'participant_container_authority_changed')


def validate_operational_baseline(value, state, prepared, sources, manifest_sha):
    """Validate a pre-checkpoint baseline using private files only, never SQL."""
    code = 'pre_upgrade_operational_baseline_required'
    require(type(value) is dict and value.get('version') == 1
            and value.get('kind') == 'pre-upgrade-operational-baseline'
            and value.get('revision') == REVISION
            and value.get('prepared_sha256') == state['prepared_sha256']
            and value.get('source_manifest_sha256') == manifest_sha
            and value.get('sources') == {name: sources[name] for name in
                ('upgrade-controller.py', 'physical-checkpoint.py', 'operational-proof.py')}, code)
    require(state['runtime'] == 'target' and state['phase'] == 'stopped' and state['configs'] == 'old'
            and state['replicas'] == {'postgres': 1, 'writer': 0, 'backend': 0}
            and state['pods'] == prepared['old_pods'] and set(state['pods']) == {'postgres'}
            and value.get('pre_upgrade') == {'phase': 'stopped', 'configs': 'old',
                'replicas': state['replicas'], 'pods': prepared['old_pods']}, code)
    database = value['database']
    require(type(database) is dict and database.get('schema') == 18
            and database.get('system_id') == '7706567225121447965'
            and database.get('control') == {'format_version': 1, 'required_policy_epoch': 2,
                'required_policy_fingerprint': 'devres-attribution-v2:verified-forward-origins:member-scopes:readable-notices'}, code)
    archive = database['archive']
    require({key: archive[key] for key in ('backend', 'binding', 'epoch', 'pending_binding', 'initializing_s3')} == {
                'backend': 's3', 'binding': 'blake3:7cf193132e3e32eb53c877dfcce166453e5bbb1b0d3f9a39f922f194f82f38e3',
                'epoch': 2, 'pending_binding': None, 'initializing_s3': False}
            and re.fullmatch('[0-9a-f]{32}', archive['store_id']), code)
    fingerprint = lambda record: digest(json.dumps(record, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode())
    authority = value['authority']
    require(type(authority) is dict and set(authority) == {'roles', 'memberships'}
            and type(authority['roles']) is list and len(authority['roles']) == 3
            and {role['rolname'] for role in authority['roles']} == {'devres_admin', 'devres_reader', 'devres_writer'}
            and all(re.fullmatch('[0-9a-f]{64}', role['verifier_sha256']) for role in authority['roles'])
            and type(authority['memberships']) is list
            and value.get('authority_sha256') == fingerprint(authority), code)
    generation = database['pinned_generation']
    require(type(generation) is dict and generation.get('id') == 'blake3:254338b7453b0764ba106f0298fd5113f4d90f9aca8028761372660e1614ec81'
            and generation.get('data', {}).get('policy_epoch') == 1
            and type(generation['data'].get('notices')) is list and generation['data']['notices']
            and re.fullmatch('blake3:[0-9a-f]{64}', generation.get('data_integrity', ''))
            and value.get('generation_sha256') == fingerprint(generation), code)
    for key in ('collectors', 'observed_preimage_collectors'):
        flags = value[key]
        require(type(flags) is dict and set(flags) == set(ROLES)
                and all(type(row) is dict and set(row) == set(PROVIDERS)
                    and all(type(flag) is bool for flag in row.values()) for row in flags.values()), code)
    require(not any(flag for row in value['observed_preimage_collectors'].values() for flag in row.values()), code)
    require(instant(prepared['at']) <= instant(value['observed_at']) <= utc_now() + dt.timedelta(seconds=5), code)
    return value


class Controller(_Cycle4BaseController):
    """Preserve the original guards while admitting exact temporary resources."""

    def require_operational_baseline(self):
        """No constructor, query, baseline creation or production mutation here."""
        try:
            state = self.state()
            manifest_body = read(Path(WORK) / 'source-manifest.json')
            manifest_sha = digest(manifest_body)
            require(manifest_sha == os.environ.get('DEVRES_ACCEPTANCE_SOURCE_MANIFEST_SHA256'),
                    'pre_upgrade_operational_baseline_required')
            sources = json.loads(manifest_body)
            paths = {'upgrade-controller.py': Path(__file__),
                'physical-checkpoint.py': Path(__file__).parent / 'physical-checkpoint.py',
                'operational-proof.py': Path(WORK) / 'operational-proof.py'}
            require(all(re.fullmatch('[0-9a-f]{64}', sources[name]) and digest(read(path)) == sources[name]
                    for name, path in paths.items()) and state['source_sha256'] == sources['upgrade-controller.py'],
                    'pre_upgrade_operational_baseline_required')
            prepared_body = read(self.root / 'prepared.json')
            require(digest(prepared_body) == state['prepared_sha256'], 'pre_upgrade_operational_baseline_required')
            path = Path(WORK) / 'operational-baseline.json'
            body = read(path)
            def unique(pairs):
                result = {}
                for key, item in pairs:
                    require(key not in result, 'pre_upgrade_operational_baseline_required')
                    result[key] = item
                return result
            value = json.loads(body, object_pairs_hook=unique)
            validate_operational_baseline(value, state, json.loads(prepared_body), sources, manifest_sha)
            require(read(path) == body and read(self.root / 'prepared.json') == prepared_body
                    and read(Path(WORK) / 'source-manifest.json') == manifest_body and self.state() == state,
                    'pre_upgrade_operational_baseline_required')
            return {'verified': True, 'sha256': digest(body)}
        except Exception:
            require(False, 'pre_upgrade_operational_baseline_required')

    def run(self, operation, approval, approval_sha, receipt=None, receipt_sha=None):
        # This also protects direct controller/phase-driver entry, before PG
        # rebind, accepted-backup persistence, configuration or image mutation.
        if operation == 'apply':
            self.require_operational_baseline()
        return super().run(operation, approval, approval_sha, receipt, receipt_sha)

    def helper(self, name, alias):
        manifest = load(Path(WORK) / 'source-manifest.json')
        path = Path(__file__).parent / name
        require(digest(read(path)) == manifest[name], 'cycle4_helper_source_changed')
        spec = importlib.util.spec_from_file_location(alias, path)
        value = importlib.util.module_from_spec(spec)
        sys.modules[alias] = value
        spec.loader.exec_module(value)
        return value

    def edge(self):
        bridge, receipt_sha = cycle4_edge_bridge()
        return bridge.native_guard(receipt_sha)['edge']

    def pods(self):
        values = json.loads(self.old.k('get', 'pods', '-o', 'json'))['items']
        state = self.state() if (self.root / 'state.json').exists() else None
        images = state['images'] if state else {'postgres': PG_IMAGE, 'writer': OLD_IMAGE, 'backend': OLD_IMAGE}
        result = {}
        allowed = {**images, 'status-observer': IMAGE}
        maintenance = []
        if (self.root / 'npm-assessment-pod-admission.json').exists():
            admission = load(self.root / 'npm-assessment-pod-admission.json')
            maintenance = [v for v in values if v['metadata']['name'] == admission['name']]
            if maintenance:
                require(len(maintenance) == 1, 'one_admitted_assessment_required')
                current, expected = maintenance[0], admission['pod']
                identity = self.root / 'npm-assessment-pod-identity.json'
                require(identity.exists() and current['metadata']['uid'] == load(identity)['uid'], 'assessment_uid_required')
                require(current['metadata'].get('labels') == expected['metadata']['labels'], 'assessment_labels_changed')
                actual_spec = current['spec']
                if current.get('status', {}).get('phase') == 'Pending' and actual_spec.get('nodeName') is None:
                    actual_spec = copy.deepcopy(actual_spec)
                    actual_spec['nodeName'] = self.old.settings()['node_name']
                admitted_pod_spec(actual_spec, expected['spec'], self.old.settings()['node_name'])
        values = [v for v in values if v not in maintenance]
        for role, image in allowed.items():
            selected = [v for v in values if v['metadata'].get('labels', {}).get('app') == role]
            require(len(selected) <= 1, 'multiple_role_pods')
            if not selected:
                continue
            obj = selected[0]
            require(len(obj['spec']['containers']) == 1 and obj['spec']['containers'][0]['image'] == image
                    and obj['spec'].get('nodeName') == self.old.settings()['node_name'], 'pod_image_or_node_changed')
            if role == 'status-observer':
                self.observer_deployment_guard()
                expected = load(self.root / 'observer-resource.json')
                require(obj['metadata'].get('ownerReferences', [{}])[0].get('kind') == 'ReplicaSet'
                        and obj['metadata']['labels'].get('devres-cycle') == VERSION,
                        'observer_pod_owner_or_scope_changed')
                require(expected['deployment']['uid'], 'observer_deployment_identity_missing')
                owners = obj['metadata'].get('ownerReferences', [])
                require(len(owners) == 1 and owners[0].get('controller') is True, 'observer_replicaset_owner_required')
                replica = self.get('replicaset', owners[0]['name'])
                require(replica['metadata']['uid'] == owners[0]['uid']
                        and replica['metadata'].get('ownerReferences') == [{'apiVersion': 'apps/v1',
                            'kind': 'Deployment', 'name': 'status-observer', 'uid': expected['deployment']['uid'],
                            'controller': True, 'blockOwnerDeletion': True}], 'observer_deployment_owner_changed')
                wanted_spec = copy.deepcopy(expected['deployment']['manifest']['spec']['template']['spec'])
                wanted_spec['containers'][0]['image'] = IMAGE
                admitted_pod_spec(obj['spec'], wanted_spec, self.old.settings()['node_name'])
            result[role] = pod_projection(obj)
        require(len(values) == len(result) and 'postgres' in result, 'unexpected_namespace_pod')
        return result

    def protected_snapshot(self):
        value = super().protected_snapshot()
        value['edge'] = self.edge()
        foundation = value['foundation']
        if (self.root / 'npm-assessment-network-admission.json').exists():
            helper = self.helper('npm-recovery.py', 'cycle4_network_assessment')
            own = helper.network_guard(self)
            foundation = [v for v in foundation if not (v['kind'] == 'NetworkPolicy' and v['name'] in own)]
        path = self.root / 'observer-resource.json'
        if path.exists():
            record = load(path)
            require(record['revision'] == REVISION, 'observer_resource_revision')
            own = set(record['policies'])
            for name, entry in record['policies'].items():
                matching = [v for v in foundation if v['kind'] == 'NetworkPolicy' and v['name'] == name]
                if record['phase'] == 'removed':
                    require(not matching, 'removed_observer_policy_remaining')
                if matching:
                    obj = self.get('networkpolicy', name)
                    require(obj['spec'] == entry['manifest']['spec']
                            and obj['metadata'].get('labels') == entry['manifest']['metadata']['labels']
                            and (not entry.get('uid') or obj['metadata']['uid'] == entry['uid']),
                            'observer_policy_changed')
                    require(entry.get('uid') or (record['phase'] == 'installing' and
                        (self.root / ('target-observer-create-' + name + '-intent.json')).exists()), 'observer_policy_create_intent_required')
                else:
                    require(record['phase'] in ('installing', 'removing', 'removed'), 'observer_policy_missing')
            foundation = [v for v in foundation if not (v['kind'] == 'NetworkPolicy' and v['name'] in own)]
            service = [v for v in foundation if v['kind'] == 'Service' and v['name'] == 'writer']
            require(len(service) == 1, 'private_writer_service_missing')
            current = service[0]
            require(current == record['service']['preimage'] or current == record['service']['observer'],
                    'observer_service_changed')
            if record['phase'] == 'running':
                require(current == record['service']['observer'], 'observer_service_not_selected')
            if current == record['service']['observer']:
                require((self.root / 'target-observer-service-select-intent.json').exists(), 'observer_service_intent_required')
            if record['phase'] == 'removed':
                require(current == record['service']['preimage'], 'removed_observer_service_changed')
                self.observer_resources_absent(record)
            foundation = [record['service']['preimage'] if v is current else v for v in foundation]
        value['foundation'] = foundation
        return value

    def observer_deployment_guard(self):
        record = load(self.root / 'observer-resource.json')
        obj = self.get('deployment', 'status-observer')
        projection, image = deployment_projection(obj)
        expected = record['deployment']
        require(image == IMAGE and projection['spec'] == expected['manifest']['spec']
                and (not expected.get('uid') or projection['uid'] == expected['uid']), 'observer_deployment_changed')
        require(expected.get('uid') or (self.root / 'target-observer-create-intent.json').exists(), 'observer_deployment_intent_required')
        return obj

    def observer_resources_absent(self, record):
        items = json.loads(self.old.k('get', 'deployments,replicasets,pods', '-o', 'json'))['items']
        uid = record['deployment'].get('uid')
        for obj in items:
            meta = obj['metadata']
            require(not (obj['kind'] == 'Deployment' and meta['name'] == 'status-observer')
                    and meta.get('labels', {}).get('app') != 'status-observer'
                    and not any(v.get('uid') == uid for v in meta.get('ownerReferences', []) if uid),
                    'removed_observer_resource_remaining')

    def boundary_guard(self, *args, **kwargs):
        bridge, receipt_sha = cycle4_edge_bridge()
        bridge.native_guard(receipt_sha)
        result = super().boundary_guard(*args, **kwargs)
        require(result.get('edge_readmission_sha256') == receipt_sha, 'prepared_edge_receipt_changed')
        record = self.root / 'observer-resource.json'
        if record.exists() and load(record)['phase'] == 'running':
            obj = self.observer_deployment_guard()
            require(obj['spec'].get('replicas') == 1, 'observer_replicas_changed')
        bridge.native_guard(receipt_sha)
        return result

    def npm_assess(self):
        return self.npm_recovery()

    def cleanup_maintenance(self):
        if any((self.root / name).exists() for name in (
                'npm-assessment-pod-admission.json', 'npm-assessment-network-admission.json')):
            self.helper('npm-recovery.py', 'cycle4_maintenance_cleanup').cleanup(self)

    def _sql_fingerprint(self):
        # SQL authority and tuple counters cover queues/checkpoints and retained
        # data, including startup. Only closed metadata hashes leave PostgreSQL.
        query = "SELECT json_build_object('tables',(SELECT json_agg(json_build_array(relid::text,n_tup_ins,n_tup_upd,n_tup_del) ORDER BY relid) FROM pg_stat_user_tables),'captures',(SELECT count(*) FROM devres_captures),'archive',(SELECT count(*) FROM devres_archive_file),'owners',(SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND classid=1835365490 AND objid=1 AND objsubid=2 AND granted),'reader_readonly',(SELECT rolconfig @> ARRAY['default_transaction_read_only=on'] FROM pg_roles WHERE rolname='devres_reader'),'reader_mutation_tables',(SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m') AND has_table_privilege('devres_reader',c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')))"
        value = json.loads(self.old.k('exec', 'deployment/postgres', '-c', 'postgres', '--', 'psql', '-X', '-q',
            '-U', 'devres_admin', '-d', 'devres', '-At', '-v', 'ON_ERROR_STOP=1', '-c',
            "BEGIN READ ONLY; SET LOCAL statement_timeout='20s'; " + query + '; COMMIT;'))
        require(value['owners'] == 0 and value['reader_readonly'] is True
                and value['reader_mutation_tables'] == 0, 'observer_readonly_authority_changed')
        return {'sha256': digest(encoded(value)), 'captures': value['captures'], 'archive': value['archive']}

    def _retained_row_manifest(self):
        """Hash every first-party retained SQL table in one read-only snapshot.

        PostgreSQL returns counts and SHA-256 values only, never rows or bodies.
        Table identifiers come from the server catalog and are strictly admitted.
        """
        def sql(query):
            return json.loads(self.old.k('exec', 'deployment/postgres', '-c', 'postgres', '--', 'psql', '-X', '-q',
                '-U', 'devres_admin', '-d', 'devres', '-At', '-v', 'ON_ERROR_STOP=1', '-c',
                "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET LOCAL statement_timeout='300s'; SET LOCAL lock_timeout='250ms'; "
                + query + '; COMMIT;', timeout=330, request_timeout=320))
        names = sql("SELECT json_agg(c.relname ORDER BY c.relname) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p')")
        require(isinstance(names, list) and 0 < len(names) <= 256
                and all(re.fullmatch('devres_[a-z0-9_]+', name) for name in names), 'retained_table_inventory_changed')
        pieces = ["SELECT '" + name + "' AS name,count(*) AS rows,encode(sha256(convert_to(coalesce(string_agg(h,'' ORDER BY h),''),'UTF8')),'hex') AS sha256 FROM (SELECT encode(sha256(convert_to(row_to_json(t)::text,'UTF8')),'hex') AS h FROM public.\"" + name + '\" t) hashes' for name in names]
        rows = sql('SELECT json_agg(v ORDER BY v.name) FROM (' + ' UNION ALL '.join(pieces) + ') v')
        require(len(rows) == len(names) and all(type(v['rows']) is int and v['rows'] >= 0
                and re.fullmatch('[0-9a-f]{64}', v['sha256']) for v in rows), 'retained_row_manifest_invalid')
        return {'table_count': len(rows), 'row_count': sum(v['rows'] for v in rows), 'sha256': digest(encoded(rows))}

    def start_observer(self):
        with self.locked():
            self.guard()
            state = self.state()
            require(state['phase'] == 'writer_ready' and state['configs'] == 'paused'
                    and set(state['pods']) == {'postgres'}, 'observer_requires_stopped_bootstrap')
            require((self.root / 'npm-assessment-completed.json').exists(), 'assessment_required')
            self.storage_guard(19, owner=False)
            self.change_config('observer', 'observer-config')
            baseline = self._sql_fingerprint()
            retained_rows = self._retained_row_manifest()
            template = copy.deepcopy(self.get('deployment', 'writer')['spec'])
            template['replicas'] = 1
            template['selector'] = {'matchLabels': {'app': 'status-observer'}}
            template['template']['metadata'] = {'labels': {'app': 'status-observer', 'devres-cycle': VERSION}}
            spec = template['template']['spec']
            mounts = spec['containers'][0]['volumeMounts']
            volumes = {v['name']: v for v in spec['volumes']}
            volumes = {k: v for k, v in volumes.items() if 'persistentVolumeClaim' not in v}
            volumes['s3'] = {'name': 's3', 'secret': {'secretName': 'devres-serving-s3', 'defaultMode': 288}}
            volumes['tmp'] = {'name': 'tmp', 'emptyDir': {'sizeLimit': '32Gi'}}
            spec['volumes'] = list(volumes.values())
            spec['containers'][0]['volumeMounts'] = [v for v in mounts if v['name'] in volumes]
            spec['containers'][0]['name'] = 'status-observer'
            require(all('persistentVolumeClaim' not in v and 'hostPath' not in v for v in spec['volumes']), 'observer_persistent_mount_refused')
            service = next(v for v in self.protected_snapshot()['foundation'] if v['kind'] == 'Service' and v['name'] == 'writer')
            replacement = copy.deepcopy(service)
            replacement['spec']['selector'] = {'app': 'status-observer'}
            peer = lambda name: {'podSelector': {'matchLabels': {'app': name}}}
            dns = {'to': [{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': 'kube-system'}},
                'podSelector': {'matchLabels': {'k8s-app': 'kube-dns'}}}], 'ports': [{'port': 53, 'protocol': p} for p in ('TCP', 'UDP')]}
            writer_policy = self.get('networkpolicy', 'writer-boundary')['spec']
            egress = copy.deepcopy(writer_policy['egress'])
            import ipaddress
            import socket
            import urllib.parse
            config = tomllib.loads(load(self.root / 'configs-observer.json')['writer'])
            endpoint = urllib.parse.urlsplit(config['storage']['s3']['endpoint'])
            require(endpoint.scheme == 'https' and endpoint.hostname and not endpoint.username
                    and not endpoint.password and endpoint.port in (None, 443), 'observer_archive_endpoint_required')
            addresses = sorted({v[4][0] for v in socket.getaddrinfo(endpoint.hostname, 443, socket.AF_INET, socket.SOCK_STREAM)})
            require(0 < len(addresses) <= 8 and all(ipaddress.ip_address(v).is_global for v in addresses), 'observer_archive_address_admission')
            broad = [v for v in egress if any(p.get('ipBlock', {}).get('cidr') == '0.0.0.0/0' for p in v.get('to', []))]
            require(len(broad) == 1 and broad[0]['ports'] == [{'port': 443, 'protocol': 'TCP'}], 'observer_archive_egress_shape')
            broad[0]['to'] = [{'ipBlock': {'cidr': v + '/32'}} for v in addresses]
            manifests = {
                'cycle4-observer-boundary': {'podSelector': peer('status-observer')['podSelector'], 'policyTypes': ['Ingress', 'Egress'],
                    'ingress': [{'from': [peer('backend')], 'ports': [{'port': 9443, 'protocol': 'TCP'}]}], 'egress': egress},
                'cycle4-observer-postgres': {'podSelector': peer('postgres')['podSelector'], 'policyTypes': ['Ingress'],
                    'ingress': [{'from': [peer('status-observer')], 'ports': [{'port': 5432, 'protocol': 'TCP'}]}]},
                'cycle4-backend-observer': {'podSelector': peer('backend')['podSelector'], 'policyTypes': ['Egress'],
                    'egress': [{'to': [peer('status-observer')], 'ports': [{'port': 9443, 'protocol': 'TCP'}]}]},
            }
            foundation = self.protected_snapshot()['foundation']
            require(not any(v['name'] in manifests for v in foundation), 'observer_policy_collision')
            all_deployments = json.loads(self.old.k('get', 'deployments', '-o', 'json'))['items']
            require(not any(v['metadata']['name'] == 'status-observer' for v in all_deployments), 'observer_deployment_collision')
            manifest = {'apiVersion': 'apps/v1', 'kind': 'Deployment',
                'metadata': {'name': 'status-observer', 'namespace': 'devres', 'labels': {'devres-cycle': VERSION}}, 'spec': template}
            expected_template = copy.deepcopy(template); expected_template.pop('replicas')
            expected_template['template']['spec']['containers'][0].pop('image')
            record = {'revision': REVISION, 'phase': 'installing', 'sql': baseline, 'retained_rows': retained_rows, 'archive_addresses': addresses,
                'configuration_sha256': digest(read(self.root / 'configs-observer.json')),
                'service': {'preimage': service, 'observer': replacement},
                'deployment': {'manifest': {'spec': expected_template}, 'uid': None},
                'policies': {name: {'manifest': {'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy',
                    'metadata': {'name': name, 'namespace': 'devres', 'labels': {'devres-cycle': VERSION}}, 'spec': body}, 'uid': None}
                    for name, body in manifests.items()}}
            save(self.root / 'observer-resource.json', record)
            for name, entry in record['policies'].items():
                self.mutate('observer-create-' + name, lambda e=entry: self.old.k('create', '-f', '-', data=encoded(e['manifest'])))
                entry['uid'] = self.get('networkpolicy', name)['metadata']['uid']
                save(self.root / 'observer-resource.json', record, replace=True)
            obj = self.get('service', 'writer')
            patch = [{'op': 'test', 'path': '/metadata/uid', 'value': obj['metadata']['uid']},
                {'op': 'test', 'path': '/metadata/resourceVersion', 'value': obj['metadata']['resourceVersion']},
                {'op': 'replace', 'path': '/spec/selector', 'value': {'app': 'status-observer'}}]
            self.mutate('observer-service-select', lambda: self.old.k('patch', 'service', 'writer', '--type=json', '-p', json.dumps(patch)))
            self.mutate('observer-create', lambda: self.old.k('create', '-f', '-', data=encoded(manifest)))
            record['deployment']['uid'] = self.get('deployment', 'status-observer')['metadata']['uid']
            save(self.root / 'observer-resource.json', record, replace=True)
            self.old.k('rollout', 'status', 'deployment/status-observer', '--timeout=180s', timeout=210, request_timeout=190)
            state = self.state(); state['observer'] = True; state['pods'] = self.pods(); self.record(state)
            record['phase'] = 'running'; save(self.root / 'observer-resource.json', record, replace=True)
            self.guard()
            self.scale('backend', 1, 'observer-start-reader')
            state = self.state(); state['phase'] = 'reader_ready'; self.record(state)
            self.observer_proof()

    def observer_proof(self):
        self.guard()
        state = self.state(); record = load(self.root / 'observer-resource.json')
        require(record['phase'] == 'running' and state['configs'] == 'observer'
                and set(state['pods']) == {'postgres', 'backend', 'status-observer'}, 'paused_observer_required')
        require(self._sql_fingerprint() == record['sql'], 'observer_retained_sql_changed')
        self.storage_guard(19, owner=False)
        endpoints = json.loads(self.old.k('get', 'endpointslices', '-l', 'kubernetes.io/service-name=writer', '-o', 'json'))['items']
        ready = [e for s in endpoints for e in s.get('endpoints', []) if e.get('conditions', {}).get('ready') is True]
        require(len(ready) == 1 and ready[0].get('targetRef', {}).get('uid') == state['pods']['status-observer']['uid'],
                'observer_endpoint_identity_changed')
        return {'verified': True, 'no_publication_owner': True, 'retained_sql_unchanged': True,
            'no_provider_requests': True, 'no_repairs_or_queue_writes': True,
            'configuration_sha256': record['configuration_sha256'], 'process': state['pods']['status-observer'],
            'sql_metadata_sha256': record['sql']['sha256'], 'evidence_scope': 'released_readonly_mode_sql_authority_tuple_counters'}

    def stop_observer(self, verify=True):
        path = self.root / 'observer-resource.json'
        if not path.exists() or load(path)['phase'] == 'removed':
            return
        record = load(path)
        if verify:
            self.observer_proof()
            current = self._retained_row_manifest()
            require(current == record['retained_rows'], 'observer_retained_rows_changed')
            save(self.root / 'observer-retained-rows-completed.json', {'verified': True,
                'before': record['retained_rows'], 'after': current, 'process': self.state()['pods']['status-observer']})
        if self.state()['replicas']['backend']:
            self.scale('backend', 0, 'observer-stop-reader')
        record['phase'] = 'removing'; save(path, record, replace=True)
        if record['deployment'].get('uid'):
            obj = self.observer_deployment_guard()
            delete = {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {'uid': obj['metadata']['uid']},
                'propagationPolicy': 'Foreground'}
            # kubectl delete --raw retains the API UID precondition on the body.
            self.mutate('observer-delete', lambda: self.old.k('delete', '--raw',
                '/apis/apps/v1/namespaces/devres/deployments/status-observer', '-f', '-', data=encoded(delete)))
            self.old.k('wait', '--for=delete', 'pod', '-l', 'app=status-observer', '--timeout=180s', timeout=210, request_timeout=190)
            self.old.k('wait', '--for=delete', 'deployment/status-observer', '--timeout=180s', timeout=210, request_timeout=190)
        else:
            # A lost create response may be reconciled only against its exact
            # admitted projection and consumed create intent; never mark a live
            # deployment removed without acquiring its actual UID for deletion.
            all_deployments = json.loads(self.old.k('get', 'deployments', '-o', 'json'))['items']
            require(not any(v['metadata']['name'] == 'status-observer' for v in all_deployments), 'observer_create_identity_reconciliation_required')
        state = self.state(); state.pop('observer', None); state['pods'] = self.pods(); self.record(state)
        obj = self.get('service', 'writer')
        if obj['spec']['selector'] != record['service']['preimage']['spec']['selector']:
            patch = [{'op': 'test', 'path': '/metadata/uid', 'value': obj['metadata']['uid']},
                {'op': 'test', 'path': '/metadata/resourceVersion', 'value': obj['metadata']['resourceVersion']},
                {'op': 'replace', 'path': '/spec/selector', 'value': record['service']['preimage']['spec']['selector']}]
            self.mutate('observer-service-restore', lambda: self.old.k('patch', 'service', 'writer', '--type=json', '-p', json.dumps(patch)))
        for name, entry in record['policies'].items():
            if entry.get('uid'):
                obj = self.get('networkpolicy', name)
                require(obj['metadata']['uid'] == entry['uid'] and obj['spec'] == entry['manifest']['spec'], 'observer_policy_cleanup_changed')
                delete = {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {'uid': entry['uid']}}
                self.mutate('observer-delete-' + name, lambda n=name, d=delete: self.old.k('delete', '--raw',
                    '/apis/networking.k8s.io/v1/namespaces/devres/networkpolicies/' + n, '-f', '-', data=encoded(d)))
                self.old.k('wait', '--for=delete', 'networkpolicy/' + name, '--timeout=30s', timeout=45)
        self.observer_resources_absent(record)
        current_policies = json.loads(self.old.k('get', 'networkpolicies', '-o', 'json'))['items']
        require(not any(v['metadata']['name'] in record['policies'] for v in current_policies), 'observer_policy_cleanup_incomplete')
        record['phase'] = 'removed'; save(path, record, replace=True)
        # Config changes are quiescent and restore normal paused candidates first.
        self.change_config('paused', 'observer-paused-config-restore')

    def renew_active_migration(self):
        manifest = load(Path(WORK) / 'source-manifest.json')
        path = Path(WORK) / 'operational-proof.py'
        require(digest(read(path)) == manifest[path.name], 'active_migration_source_changed')
        spec = importlib.util.spec_from_file_location('cycle4_active_migration', path)
        proof = importlib.util.module_from_spec(spec); sys.modules[spec.name] = proof; spec.loader.exec_module(proof)
        checkpoint = self.helper('physical-checkpoint.py', 'cycle4_active_checkpoint')
        proof.observation(sys.modules[self.__class__.__module__], checkpoint, 'migration-active',
            'migration-active', locked_controller=self)

    def runtime_schema(self):
        return 18 if self.state()['runtime'] == 'restored' else super().runtime_schema()

    def withdraw(self):
        # Stop all participants before inspecting diagnostic persistence. An
        # uncertain create/delete is never retried; explicit reconciliation is required.
        failures = []
        for role in ('backend', 'writer', 'status-observer'):
            if role == 'status-observer' and (not (self.root / 'observer-resource.json').exists()
                    or load(self.root / 'observer-resource.json')['phase'] == 'removed'):
                continue
            try:
                if role == 'status-observer':
                    deployments = json.loads(self.old.k('get', 'deployments', '-o', 'json'))['items']
                    if not any(v['metadata']['name'] == role for v in deployments):
                        continue
                obj = self.get('deployment', role)
                if role == 'status-observer':
                    self.observer_deployment_guard()
                else:
                    projection, image = deployment_projection(obj)
                    expected = load(self.root / 'prepared.json')['deployments'][role]['projection']
                    require(projection == expected and image in (OLD_IMAGE, IMAGE), 'withdraw_deployment_boundary')
                if obj['spec'].get('replicas', 1):
                    patch = [{'op': 'test', 'path': '/metadata/uid', 'value': obj['metadata']['uid']},
                        {'op': 'test', 'path': '/metadata/resourceVersion', 'value': obj['metadata']['resourceVersion']},
                        {'op': 'replace', 'path': '/spec/replicas', 'value': 0}]
                    self.mutate('cycle4-fence-' + role, lambda r=role, p=patch: self.old.k('patch', 'deployment', r, '--type=json', '-p', json.dumps(p)))
            except Exception:
                failures.append(role)
        try:
            self.cleanup_maintenance()
        except Exception:
            failures.append('maintenance')
        for role in ('backend', 'writer', 'status-observer'):
            if role == 'status-observer' and (not (self.root / 'observer-resource.json').exists()
                    or load(self.root / 'observer-resource.json')['phase'] == 'removed'):
                continue
            try:
                self.old.k('wait', '--for=delete', 'pod', '-l', 'app=' + role, '--timeout=180s', timeout=210, request_timeout=190)
            except Exception:
                failures.append(role + '-wait')
        require(not failures, 'cycle4_withdrawal_incomplete')
        state = self.state(); state['replicas'] = {'postgres': 1, 'writer': 0, 'backend': 0}
        state.pop('observer', None); state['pods'] = self.pods(); self.record(state)
        self.stop_observer(verify=False)
        self.storage_guard(None, owner=False)
        state = self.state(); state['phase'] = 'withdrawn'; self.record(state)

    def restore_record(self, receipt):
        require(receipt.get('schema') == 18 and receipt.get('database_restored') is True, 'verified_restore_required')
        if self.state()['runtime'] == 'restored':
            require(self.state()['phase'] == 'withdrawn'
                    and self.state().get('restore_receipt_sha256') == digest(encoded(receipt)), 'restoration_receipt_changed')
            self.guard(); self.storage_guard(18, owner=False)
            return
        self.restore_guard(); self.storage_guard(18, owner=False)
        # Restore the exact captured paused Secret bytes, not reconstructed defaults.
        prepared = load(self.root / 'prepared.json')
        for role, (name, key) in ROLES.items():
            obj = self.get('secret', name)
            wanted = prepared['secrets'][name]['data']
            patch = [{'op': 'test', 'path': '/metadata/uid', 'value': obj['metadata']['uid']},
                {'op': 'test', 'path': '/metadata/resourceVersion', 'value': obj['metadata']['resourceVersion']},
                {'op': 'replace', 'path': '/data', 'value': wanted}]
            self.mutate('restore-preimage-' + role, lambda n=name, p=patch: self.old.k('patch', 'secret', n,
                '--type=json', '--patch-file=/dev/stdin', data=encoded(p)))
        state = self.state(); state.update(runtime='restored', phase='withdrawn', configs='old',
            replicas={'postgres': 1, 'writer': 0, 'backend': 0}, pods=self.pods(), restore_receipt_sha256=digest(encoded(receipt)))
        state.pop('observer', None); self.record(state)
        self.guard()

    def prepare_fallback(self):
        raise Error('fallback_service_not_authorized')

    def rollback(self):
        import subprocess
        require(self.state()['runtime'] == 'target', 'one_target_rollback_only')
        with self.locked():
            self.withdraw()
            require(not (self.root / 'rollback-intent.json').exists(), 'rollback_intent_consumed')
            save(self.root / 'rollback-intent.json', {'source_sha256': self.state()['source_sha256'], 'at': stamp(), 'maximum_attempts': 1})
        manifest = load(Path(WORK) / 'source-manifest.json')
        helper = Path(__file__).parent / 'restore-controller.py'
        require(digest(read(helper)) == manifest[helper.name], 'restore_source_changed')
        result = subprocess.run([sys.executable, '-B', str(helper), '--controller-sha256', self.state()['source_sha256'],
            '--checkpoint-sha256', manifest['physical-checkpoint.py'], 'restore'], capture_output=True, timeout=7200)
        require(result.returncode == 0 and self.state()['runtime'] == 'restored'
                and self.state()['phase'] == 'withdrawn', 'automatic_restore_incomplete')
        return {'database_restored': True, 'withdrawn': True, 'fallback_service_accepted': False}
