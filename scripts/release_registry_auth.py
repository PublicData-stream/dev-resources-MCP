#!/usr/bin/env python3
"""Bridge isolated GHCR credentials to the pinned attestation action safely."""
from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys


MAX_CONFIG_BYTES = 65_536


def identity(value: os.stat_result) -> list[int]:
    return [value.st_dev, value.st_ino]


def present(path: Path) -> os.stat_result | None:
    try:
        return path.lstat()
    except FileNotFoundError:
        return None


def owned_directory(path: Path, *, private: bool = False) -> os.stat_result:
    value = path.lstat()
    if (not stat.S_ISDIR(value.st_mode) or value.st_uid != os.getuid()
            or stat.S_IMODE(value.st_mode) & 0o022
            or (private and stat.S_IMODE(value.st_mode) != 0o700)):
        raise ValueError("Unsafe registry authentication directory")
    return value


def owned_file(path: Path, *, private: bool = False, links: tuple[int, ...] = (1,)) -> os.stat_result:
    value = path.lstat()
    if (not stat.S_ISREG(value.st_mode) or value.st_uid != os.getuid()
            or value.st_nlink not in links
            or (private and stat.S_IMODE(value.st_mode) != 0o600)):
        raise ValueError("Unsafe registry authentication file")
    return value


class RegistryAuth:
    def __init__(self, scratch: Path, home: Path):
        self.scratch = Path(scratch)
        self.home = Path(home)
        self.auth = self.scratch / "auth"
        self.docker = self.auth / "docker" / "config.json"
        self.registry = self.auth / "registry-auth.json"
        self.journal = self.auth / "state.json"
        self.backup = self.auth / "original-config.json"
        self.attest = self.scratch / "attest"
        self.home_docker = self.home / ".docker"
        self.default = self.home_docker / "config.json"

    def _scratch(self, *, create: bool = False, missing_ok: bool = False) -> bool:
        if (not self.scratch.is_absolute() or ".." in self.scratch.parts
                or self.scratch == Path("/tmp")
                or not self.scratch.is_relative_to("/tmp")):
            raise ValueError("Registry authentication state must be below /tmp")
        current = Path("/tmp")
        if not stat.S_ISDIR(current.lstat().st_mode):
            raise ValueError("Unsafe temporary directory")
        for part in self.scratch.relative_to("/tmp").parts:
            current = current / part
            if present(current) is None:
                if create:
                    current.mkdir(mode=0o700)
                elif missing_ok:
                    return False
            owned_directory(current)
        if (not self.home.is_absolute() or ".." in self.home.parts
                or self.home.is_relative_to(self.scratch)
                or self.scratch.is_relative_to(self.home_docker)):
            raise ValueError("Unsafe registry authentication home")
        # Do not follow a symlink in the runner-home ancestry either.
        current = Path(self.home.anchor)
        for part in self.home.parts[1:]:
            current = current / part
            if not stat.S_ISDIR(current.lstat().st_mode):
                raise ValueError("Unsafe registry authentication home")
        owned_directory(self.home)
        return True

    def _save(self, state: dict) -> None:
        temporary = self.auth / "state.new"
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            json.dump(state, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, self.journal)
        descriptor = os.open(self.auth, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _load(self) -> dict:
        owned_directory(self.auth, private=True)
        value = owned_file(self.journal, private=True)
        if value.st_size > MAX_CONFIG_BYTES:
            raise ValueError("Invalid registry authentication journal")
        state = json.loads(self.journal.read_text())
        expected = {"version", "uid", "home", "auth", "original", "docker_directory", "created_docker", "bridge", "attest"}
        if (not isinstance(state, dict) or set(state) != expected
                or state["version"] != 1 or state["uid"] != os.getuid()
                or state["home"] != str(self.home)
                or state["auth"] != identity(self.auth.lstat())
                or type(state["created_docker"]) is not bool):
            raise ValueError("Invalid registry authentication journal")
        for key in ("auth", "original", "docker_directory", "bridge", "attest"):
            value = state[key]
            if value is not None and (not isinstance(value, list) or len(value) != 2
                    or any(type(item) is not int or item < 0 for item in value)):
                raise ValueError("Invalid registry authentication journal")
        return state

    def _configuration(self, path: Path) -> str:
        value = owned_file(path, private=True)
        if value.st_size > MAX_CONFIG_BYTES:
            raise ValueError("Invalid registry authentication configuration")
        config = json.loads(path.read_text())
        auths = config.get("auths") if isinstance(config, dict) else None
        entry = auths.get("ghcr.io") if isinstance(auths, dict) else None
        encoded = entry.get("auth") if isinstance(entry, dict) else None
        if not isinstance(encoded, str):
            raise ValueError("Missing inline GHCR credentials")
        try:
            user, password = base64.b64decode(encoded, validate=True).split(b":", 1)
        except (ValueError, TypeError):
            raise ValueError("Invalid inline GHCR credentials") from None
        if not user or not password:
            raise ValueError("Invalid inline GHCR credentials")
        return encoded

    def _login(self, client: str, token: str, actor: str) -> None:
        environment = {key: value for key, value in os.environ.items()
                       if key not in {"REGISTRY_TOKEN", "GH_TOKEN", "GITHUB_TOKEN", "DOCKER_AUTH_CONFIG"}
                       and value != token}
        environment["DOCKER_CONFIG"] = str(self.docker.parent)
        environment["REGISTRY_AUTH_FILE"] = str(self.registry)
        try:
            result = subprocess.run(
                [client, "login", "--username", actor, "--password-stdin", "ghcr.io"],
                input=token.encode(), env=environment, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=60, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            raise ValueError("Registry login failed") from None
        if result.returncode:
            raise ValueError("Registry login failed")

    def prepare(self, token: str, actor: str) -> None:
        if not token or not actor or any(character in actor for character in "\r\n\0"):
            raise ValueError("Missing or invalid registry login input")
        self._scratch(create=True)
        if present(self.auth) is not None or present(self.attest) is not None:
            raise ValueError("Registry authentication state already exists; cleanup required")
        home_directory = present(self.home_docker)
        if home_directory is not None:
            home_directory = owned_directory(self.home_docker)
        original = present(self.default) if home_directory is not None else None
        if original is not None:
            original = owned_file(self.default)
        parent = home_directory if home_directory is not None else self.home.lstat()
        if parent.st_dev != self.scratch.lstat().st_dev:
            raise ValueError("Registry authentication backup requires the same filesystem")

        self.auth.mkdir(mode=0o700)
        state = {"version": 1, "uid": os.getuid(), "home": str(self.home),
                 "auth": identity(self.auth.lstat()),
                 "original": identity(original) if original is not None else None,
                 "docker_directory": identity(home_directory) if home_directory is not None else None,
                 "created_docker": home_directory is None, "bridge": None, "attest": None}
        try:
            self._save(state)
            self.docker.parent.mkdir(mode=0o700)
            for path in (self.docker, self.registry):
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(descriptor, "w") as stream:
                    stream.write('{"auths":{}}\n')
            self._login("docker", token, actor)
            self._login("skopeo", token, actor)
            owned_directory(self.docker.parent, private=True)
            expected_auth = base64.b64encode(f"{actor}:{token}".encode()).decode()
            if (self._configuration(self.docker) != expected_auth
                    or self._configuration(self.registry) != expected_auth):
                raise ValueError("Registry clients produced inconsistent GHCR credentials")

            # Stage inode identities before moving anything into the runner home.
            staged_attest = self.auth / "attest-directory"
            staged_attest.mkdir(mode=0o700)
            state["attest"] = identity(staged_attest.lstat())
            staged_bridge = self.auth / "bridge-link"
            staged_bridge.symlink_to(self.docker)
            state["bridge"] = identity(staged_bridge.lstat())
            self._save(state)
            os.rename(staged_attest, self.attest)
            if state["created_docker"]:
                # mkdir refuses an existing directory, unlike rename. If the
                # process stops before its inode is journaled, cleanup leaves
                # this directory alone and no home config has been touched.
                self.home_docker.mkdir(mode=0o700)
                state["docker_directory"] = identity(self.home_docker.lstat())
                self._save(state)
            elif identity(owned_directory(self.home_docker)) != state["docker_directory"]:
                raise ValueError("Runner Docker directory changed during authentication")
            current = present(self.default)
            if state["original"] is not None:
                if current is None or identity(owned_file(self.default)) != state["original"]:
                    raise ValueError("Runner Docker configuration changed during authentication")
                os.rename(self.default, self.backup)
            elif current is not None:
                raise ValueError("Runner Docker configuration changed during authentication")
            # Linking the staged symlink is exclusive and retains the journaled
            # inode, including if interrupted before its staging link is removed.
            os.link(staged_bridge, self.default, follow_symlinks=False)
            staged_bridge.unlink()
            self.check()
        except Exception:
            try:
                self.cleanup()
            except Exception:
                # Preserve protected backup/journal state when recovery is unsafe.
                pass
            raise ValueError("Registry authentication preparation failed") from None

    def _bridge(self, value: os.stat_result | None, state: dict) -> bool:
        return (value is not None and stat.S_ISLNK(value.st_mode)
                and value.st_uid == os.getuid() and identity(value) == state["bridge"]
                and os.readlink(self.default) == str(self.docker))

    def check(self) -> None:
        self._scratch()
        state = self._load()
        if (identity(owned_directory(self.home_docker)) != state["docker_directory"]
                or not self._bridge(present(self.default), state)
                or identity(owned_directory(self.attest, private=True)) != state["attest"]):
            raise ValueError("Registry authentication bridge is not intact")
        owned_directory(self.docker.parent, private=True)
        if self._configuration(self.docker) != self._configuration(self.registry):
            raise ValueError("Registry clients have inconsistent GHCR credentials")
        if state["original"] is not None:
            if identity(owned_file(self.backup)) != state["original"]:
                raise ValueError("Registry authentication backup is not intact")
        elif present(self.backup) is not None:
            raise ValueError("Unexpected registry authentication backup")

    def cleanup(self) -> None:
        if not self._scratch(missing_ok=True):
            return
        if present(self.auth) is None:
            return
        state = self._load()
        unrecorded_directory = state["created_docker"] and state["docker_directory"] is None
        current_directory = present(self.home_docker)
        if current_directory is not None:
            if (not unrecorded_directory
                    and identity(owned_directory(self.home_docker)) != state["docker_directory"]):
                raise ValueError("Refusing cleanup of a changed runner Docker directory")
        elif not state["created_docker"]:
            raise ValueError("Refusing cleanup of a missing runner Docker directory")
        attest = present(self.attest)
        if attest is not None and identity(owned_directory(self.attest, private=True)) != state["attest"]:
            raise ValueError("Refusing cleanup of changed attestation state")
        current = present(self.default) if current_directory is not None else None
        backup = present(self.backup)
        if unrecorded_directory:
            if backup is not None or state["original"] is not None:
                raise ValueError("Unexpected protected backup before directory setup")
            # Authentication never reached home-config mutation. Preserve any
            # directory/config created during the unjournaled mkdir window.
            if attest is not None:
                shutil.rmtree(self.attest)
            shutil.rmtree(self.auth)
            return
        if backup is not None:
            backup = owned_file(self.backup, links=(1, 2))
            if state["original"] is None or identity(backup) != state["original"]:
                raise ValueError("Refusing cleanup of a changed protected backup")
            if current_directory is None:
                raise ValueError("Refusing to restore credentials into a missing directory")
            restored = (current is not None and stat.S_ISREG(current.st_mode)
                        and identity(current) == state["original"])
            if backup.st_nlink == 2:
                if not restored or owned_file(self.default, links=(2,)).st_nlink != 2:
                    raise ValueError("Refusing cleanup of unexpected protected backup links")
            else:
                if current is not None:
                    if not self._bridge(current, state):
                        raise ValueError("Refusing to overwrite changed runner Docker credentials")
                    self.default.unlink()
                # Exclusive restoration cannot overwrite a newly created config.
                # Interruption after this link is recovered by the two-link case.
                os.link(self.backup, self.default, follow_symlinks=False)
            self.backup.unlink()
        elif state["original"] is not None:
            if current is None or identity(owned_file(self.default)) != state["original"]:
                raise ValueError("Protected registry authentication backup is missing")
        elif current is not None:
            if not self._bridge(current, state):
                raise ValueError("Refusing to remove changed runner Docker credentials")
            self.default.unlink()
        if state["created_docker"] and current_directory is not None:
            # Other content belongs to its creator and must be left untouched.
            if not any(self.home_docker.iterdir()):
                self.home_docker.rmdir()
        if attest is not None:
            shutil.rmtree(self.attest)
        shutil.rmtree(self.auth)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("prepare", "check", "cleanup"))
    arguments = parser.parse_args()
    try:
        auth = RegistryAuth(Path(os.environ["RELEASE_SCRATCH"]), Path.home())
        if arguments.operation == "prepare":
            if (os.environ.get("GITHUB_ACTIONS") != "true"
                    or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):
                raise ValueError("Registry credential bridging requires a disposable hosted runner")
            auth.prepare(os.environ["REGISTRY_TOKEN"], os.environ["GITHUB_ACTOR"])
        elif arguments.operation == "check":
            auth.check()
        else:
            auth.cleanup()
    except (ValueError, KeyError, TypeError, OSError):
        message = f"Release registry authentication {arguments.operation} failed"
        if arguments.operation == "cleanup":
            message += "; protected recovery state is not discarded on unsafe cleanup"
        print(message, file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
