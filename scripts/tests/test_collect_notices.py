"""Vendored path dependencies retain their packaged license texts in images."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "collect_notices", Path(__file__).parents[1] / "collect-notices.py")
notices = importlib.util.module_from_spec(spec)
spec.loader.exec_module(notices)


class CollectNoticesTests(unittest.TestCase):
    def test_path_dependency_included_but_workspace_package_excluded(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            root = Path(temporary)
            packages = []
            for name, source in (("first-party", None), ("vendored", None),
                                 ("registry", "registry+https://example.invalid")):
                directory = root / name
                directory.mkdir()
                (directory / "Cargo.toml").write_text("[package]\n")
                (directory / "LICENSE").write_text(name + " original license\n")
                packages.append({"id": name, "name": name, "version": "1.0.0",
                                 "source": source, "license": "MIT",
                                 "manifest_path": str(directory / "Cargo.toml")})
            metadata = {"packages": packages, "workspace_members": ["first-party"]}
            standard = root / "toolchain/share/doc/rust"
            (standard / "licenses").mkdir(parents=True)
            (standard / "COPYRIGHT-library.html").write_text("standard notices")
            (standard / "licenses/MIT.txt").write_text("standard license")

            def command(arguments, **_):
                if arguments[0] == "cargo":
                    return json.dumps(metadata)
                self.assertEqual(arguments, ["rustc", "--print", "sysroot"])
                return str(root / "toolchain")

            destination = root / "notices"
            with patch.object(notices.subprocess, "check_output", side_effect=command):
                notices.collect(destination)
            index = json.loads((destination / "index.json").read_text())
            self.assertEqual({item["name"] for item in index}, {"vendored", "registry"})
            self.assertEqual((destination / "vendored-1.0.0/LICENSE").read_text(),
                             "vendored original license\n")
            self.assertFalse((destination / "first-party-1.0.0").exists())
