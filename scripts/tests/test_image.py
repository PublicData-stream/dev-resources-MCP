import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import shutil
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("image_fixture", ROOT / "scripts/image-fixture.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


def image_record(architecture="amd64", target="server"):
    binary = "server" if target == "runtime" else target
    return {"Id": "sha256:" + "a" * 64, "Os": "linux", "Architecture": architecture,
            "Config": {"User": "65532:65532", "Entrypoint": [f"/usr/local/bin/devres-{binary}"],
                       "Cmd": ["/etc/devres/server.toml"] if binary == "server" else None}}


def manifest(config="a", layer="b"):
    return json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                       "config": {"digest": "sha256:" + config * 64},
                       "layers": [{"digest": "sha256:" + layer * 64}]}).encode()


class FixtureTests(unittest.TestCase):
    def test_private_fixture_is_never_accepted_in_worker_output(self):
        reflected = json.dumps({"Err": {"code": "invalid_input", "message": fixture.SENTINEL}}).encode()
        with self.assertRaisesRegex(ValueError, "reflected"):
            fixture.check_worker("invalid", reflected, b"")
        with self.assertRaisesRegex(ValueError, "stderr"):
            fixture.check_worker("invalid", b'{"Err":{"code":"invalid_input"}}', b"diagnostic")

    def test_worker_requires_assessment_and_structured_failure(self):
        fixture.check_worker("valid", b'{"Ok":{"assessed_count":1,"vulnerability_count":1}}', b"")
        fixture.check_worker("invalid", b'{"Err":{"code":"invalid_input"}}', b"")
        for output in (b'{"Ok":{"assessed_count":0,"vulnerability_count":1}}', b'{"Err":{"code":"unavailable"}}'):
            with self.assertRaises(ValueError):
                fixture.check_worker("valid", output, b"")

    def test_image_identity_architecture_and_entrypoint_are_checked(self):
        fixture.inspect_image([image_record()], "linux/amd64", "server")
        for mutation in (lambda item: item.update(Architecture="arm64"),
                         lambda item: item["Config"].update(User="0"),
                         lambda item: item["Config"].update(Entrypoint=["sh"])):
            record = image_record()
            mutation(record)
            with self.assertRaises(ValueError):
                fixture.inspect_image([record], "linux/amd64", "server")

    def test_export_metadata_binds_archive_and_single_image_contents(self):
        with tempfile.TemporaryDirectory() as path:
            directory = Path(path)
            (directory / "image.oci.tar").write_bytes(b"synthetic archive")
            raw = manifest()
            fixture.export_metadata(directory, raw, [image_record()], "linux/amd64", "server")
            metadata = json.loads((directory / "metadata.json").read_text())
            self.assertEqual(metadata["archive_sha256"], hashlib.sha256(b"synthetic archive").hexdigest())
            self.assertEqual(metadata["manifest_digest"], "sha256:" + hashlib.sha256(raw).hexdigest())
            self.assertEqual(metadata["config_digest"], "sha256:" + "a" * 64)
            self.assertEqual(metadata["layer_digests"], ["sha256:" + "b" * 64])
            with self.assertRaisesRegex(ValueError, "differs"):
                fixture.export_metadata(directory, manifest(config="c"), [image_record()], "linux/amd64", "server")
            with self.assertRaisesRegex(ValueError, "single image"):
                fixture.manifest_parts(b'{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}')

    def test_export_rejects_daemon_config_mismatch(self):
        record = image_record()
        record["Id"] = "sha256:" + "c" * 64
        with self.assertRaisesRegex(ValueError, "differs"):
            fixture.export_metadata(Path("/unused"), manifest(), [record], "linux/amd64", "server")

    def test_modern_docker_descriptor_id_is_manifest_not_config_digest(self):
        record = image_record()
        record["Id"] = "sha256:" + hashlib.sha256(manifest()).hexdigest()
        record["Descriptor"] = {"mediaType": fixture.MANIFEST_TYPES[0], "digest": record["Id"]}
        with tempfile.TemporaryDirectory() as path:
            directory = Path(path)
            (directory / "image.oci.tar").write_bytes(b"fixture")
            fixture.export_metadata(directory, manifest(), [record], "linux/amd64", "server")
            self.assertEqual(json.loads((directory / "metadata.json").read_text())["config_digest"], "sha256:" + "a" * 64)
            for changed in (manifest(config="c"), manifest(layer="c")):
                with self.assertRaisesRegex(ValueError, "differs"):
                    fixture.export_metadata(directory, changed, [record], "linux/amd64", "server")
        for descriptor in ({"mediaType": "application/vnd.oci.image.index.v1+json", "digest": record["Id"]},
                           {"mediaType": fixture.MANIFEST_TYPES[0], "digest": "sha256:" + "d" * 64},
                           {"config": {"digest": "sha256:" + "a" * 64}}):
            record["Descriptor"] = descriptor
            with self.assertRaisesRegex(ValueError, "descriptor"):
                fixture.inspect_image([record], "linux/amd64", "server")


MOCK_DOCKER = r'''#!/usr/bin/env python3
import hashlib,json,os,sys
from pathlib import Path
args=sys.argv[1:]
with open(os.environ['MOCK_LOG'],'a') as log:log.write(json.dumps(args)+'\n')
state_path=Path(os.environ['MOCK_STATE'])
state=json.loads(state_path.read_text()) if state_path.exists() else {}
def save():state_path.write_text(json.dumps(state))
if args and (args[0]=='build' or args[:2]==['buildx','build']):
    state['built']=args[args.index('-t')+1]
    state['owner']=next(value.split('=',1)[1] for value in args if value.startswith('devres.test-owner='))
    if args[0]=='buildx':
        destination=args[args.index('--output')+1].removeprefix('type=oci,dest=')
        Path(destination).write_bytes(b'synthetic archive')
        state['loaded']=False
    save()
elif args and args[0]=='load':
    if os.environ.get('MOCK_LOAD_FAILURE'):sys.exit(1)
    state['loaded']=True;save()
elif args[:2]==['image','rm']:pass
elif args[:2]==['image','inspect'] and '--format' in args:
    if args[-1]!=state.get('built'):sys.exit(1)
    print(state['owner'])
elif args[:2]==['image','inspect']:
    if args[-1].startswith('devres-image-check-') and args[-1]!=state.get('built'):sys.exit(1)
    target=os.environ.get('MOCK_TARGET','server')
    binary='server' if target=='runtime' else target
    record={'Id':'sha256:'+'a'*64,'Os':'linux','Architecture':os.environ.get('MOCK_ARCH','amd64'),
       'Config':{'User':'65532:65532','Entrypoint':['/usr/local/bin/devres-'+binary],
       'Cmd':['/etc/devres/server.toml'] if binary=='server' else None}}
    if 'loaded' in state:
        if not state['loaded']:sys.exit(1)
        raw=json.dumps({'schemaVersion':2,'mediaType':'application/vnd.oci.image.manifest.v1+json',
                        'config':{'digest':'sha256:'+'a'*64},'layers':[{'digest':'sha256:'+'b'*64}]}).encode()
        record['Id']='sha256:'+hashlib.sha256(raw).hexdigest()
        if os.environ.get('MOCK_LOADED_ID_DRIFT'):record['Id']='sha256:'+'d'*64
        record['Descriptor']={'mediaType':'application/vnd.oci.image.manifest.v1+json','digest':record['Id']}
    print(json.dumps([record]))
elif args and args[0]=='info':print('linux/'+os.environ.get('MOCK_ARCH','amd64'))
elif args and args[0]=='run':
    code=int(os.environ.get('MOCK_RUN_STATUS','0'))
    if code:sys.exit(code)
    binary=args[args.index('--entrypoint')+1]
    if binary.endswith('devres-probe'):
        print('Error: usage: devres-probe URL CA_PATH REVISION',file=sys.stderr);sys.exit(1)
    if binary.endswith('devres-server'):
        print('Error: No such file or directory',file=sys.stderr);sys.exit(1)
    request=json.load(sys.stdin)
    if 'SYNTHETIC_PRIVATE_INPUT_SENTINEL' in request['lockfile']:print('{"Err":{"code":"invalid_input"}}')
    else:print('{"Ok":{"assessed_count":1,"vulnerability_count":1}}')
else:sys.exit(1)
'''

MOCK_SKOPEO = r'''#!/usr/bin/env python3
import json,os,sys
from pathlib import Path
args=sys.argv[1:]
with open(os.environ['MOCK_LOG'],'a') as log:log.write(json.dumps(['skopeo',*args])+'\n')
if args[0]=='inspect':
    assert args[-1].startswith('oci-archive:')
    print(json.dumps({'schemaVersion':2,'mediaType':'application/vnd.oci.image.manifest.v1+json',
                     'config':{'digest':'sha256:'+'a'*64},'layers':[{'digest':'sha256:'+'b'*64}]}),end='')
else:sys.exit(1)
'''


class ScriptTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        directory = Path(self.scratch.name)
        self.log = directory / "docker.log"
        for name, source in (("docker", MOCK_DOCKER), ("skopeo", MOCK_SKOPEO)):
            command = directory / name
            command.write_text(source)
            command.chmod(0o755)
        self.env = dict(os.environ, PATH=f'{directory}:{os.environ["PATH"]}', MOCK_LOG=str(self.log),
                        MOCK_STATE=str(directory / "state.json"))
        self.env.pop("DOCKER_HOST", None)
        self.env.pop("DOCKER_CONTEXT", None)

    def run_script(self, *arguments, **environment):
        return subprocess.run([str(ROOT / "scripts/test-image.sh"), *arguments], cwd=ROOT,
                              env=dict(self.env, **environment), capture_output=True, timeout=15)

    def test_external_image_smokes_all_shipped_binaries_without_removing_image(self):
        result = self.run_script("--image", "external:fixed", "--target", "runtime", "--platform", "linux/arm64",
                                 MOCK_TARGET="runtime", MOCK_ARCH="arm64")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        runs = [call for call in calls if call[0] == "run"]
        self.assertEqual(len(runs), 4)
        self.assertFalse(any(call[:2] == ["image", "rm"] or call[0] == "build" for call in calls))
        for call in runs:
            self.assertEqual(call[call.index("--platform") + 1], "linux/arm64")
            self.assertIn("sha256:" + "a" * 64, call)
            self.assertIn("--read-only", call)
            self.assertEqual(call[call.index("--network") + 1], "none")

    def test_wrong_image_architecture_stops_before_execution(self):
        result = self.run_script("--image", "external:fixed", "--target", "server", "--platform", "linux/arm64")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(json.loads(line)[0] == "run" for line in self.log.read_text().splitlines()))

    def test_external_image_smoke_works_from_source_archive_without_git(self):
        root = Path(self.scratch.name) / "source"
        scripts = root / "scripts"
        scripts.mkdir(parents=True)
        for name in ("test-image.sh", "image-fixture.py"):
            shutil.copy2(ROOT / "scripts" / name, scripts / name)
        result = subprocess.run([str(scripts / "test-image.sh"), "--image", "external:fixed",
                                 "--target", "server", "--platform", "linux/amd64"],
                                cwd=root, env=self.env, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_docker_failure_and_timeout_cannot_pass_negative_smoke(self):
        for status in (124, 125, 126, 127):
            with self.subTest(status=status):
                result = self.run_script("--image", "external:fixed", "--target", "server", "--platform", "linux/amd64",
                                         MOCK_RUN_STATUS=str(status))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"failed to run", result.stderr)

    def test_build_explicitly_disables_implicit_attestation_indexes(self):
        result = self.run_script("--target", "probe", "--platform", "linux/amd64", MOCK_TARGET="probe")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        build = next(call for call in calls if call[0] == "build")
        self.assertIn("--provenance=false", build)
        self.assertIn("--sbom=false", build)

    def test_canonical_artifact_is_built_then_loaded_before_smoke(self):
        output = Path(self.scratch.name) / "export"
        result = self.run_script("--target", "server", "--platform", "linux/amd64", "--oci-output", str(output))
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        build_index = next(index for index, call in enumerate(calls) if call[:2] == ["buildx", "build"])
        load_index = next(index for index, call in enumerate(calls) if call[0] == "load")
        smoke_index = next(index for index, call in enumerate(calls) if call[0] == "run")
        self.assertLess(build_index, load_index)
        self.assertLess(load_index, smoke_index)
        build = calls[build_index]
        self.assertIn("--provenance=false", build)
        self.assertIn("--sbom=false", build)
        self.assertTrue(build[build.index("--output") + 1].startswith("type=oci,dest="))
        self.assertTrue((output / "metadata.json").is_file())
        metadata = json.loads((output / "metadata.json").read_text())
        self.assertIn(metadata["manifest_digest"], calls[smoke_index])
        self.assertFalse(any(call[:2] == ["skopeo", "copy"] or any(arg.startswith("docker-daemon:") for arg in call)
                             for call in calls))

    def test_external_image_export_is_rejected_before_any_docker_operation(self):
        output = Path(self.scratch.name) / "export"
        result = self.run_script("--image", "external:fixed", "--target", "server", "--platform", "linux/amd64",
                                 "--oci-output", str(output))
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"smoke-only", result.stderr)
        self.assertFalse(self.log.exists())
        self.assertFalse(output.exists())

    def test_failed_import_or_changed_loaded_manifest_produces_no_artifact(self):
        for mode in ("MOCK_LOAD_FAILURE", "MOCK_LOADED_ID_DRIFT", "MOCK_RUN_STATUS"):
            with self.subTest(mode=mode):
                self.log.write_text("")
                output = Path(self.scratch.name) / ("export-" + mode)
                result = self.run_script("--target", "server", "--platform", "linux/amd64", "--oci-output", str(output),
                                         **{mode: "125" if mode == "MOCK_RUN_STATUS" else "1"})
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(output.exists())
                if mode != "MOCK_RUN_STATUS":
                    calls = [json.loads(line) for line in self.log.read_text().splitlines()]
                    self.assertFalse(any(call[0] == "run" for call in calls))

    def test_native_guard_rejects_wrong_compiler_or_daemon(self):
        directory = Path(self.scratch.name)
        for name, text in (("uname", '#!/bin/sh\nif [ "$1" = -s ]; then echo Linux; else echo aarch64; fi\n'),
                           ("rustc", '#!/bin/sh\necho "host: ${MOCK_RUST_HOST:-aarch64-unknown-linux-gnu}"\n')):
            command = directory / name
            command.write_text(text)
            command.chmod(0o755)
        for extra, expected in (({"MOCK_ARCH": "arm64"}, 0),
                                ({"MOCK_ARCH": "arm64", "MOCK_RUST_HOST": "x86_64-unknown-linux-gnu"}, 1),
                                ({"MOCK_ARCH": "amd64"}, 1)):
            result = subprocess.run([str(ROOT / "scripts/check-native-platform.sh"), "linux/arm64"],
                                    env=dict(self.env, **extra), capture_output=True, timeout=5)
            self.assertEqual(result.returncode, expected, result.stderr)
