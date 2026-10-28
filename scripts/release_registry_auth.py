#!/usr/bin/env python3
"""Prepare isolated GHCR credentials for disposable hosted publishing jobs."""
from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys


MAX_CONFIG_BYTES = 65_536
FAILURE_CODES = frozenset({
    "environment", "hosted-runner", "login-input", "scratch", "existing-state",
    "initialize", "docker-login", "skopeo-login", "credentials", "preflight",
    "cleanup", "unexpected",
})


class AuthFailure(ValueError):
    """Only fixed codes, never untrusted exception or client text, cross the CLI."""

    def __init__(self, code: str, *, cleanup_failed: bool = False):
        self.code = code if code in FAILURE_CODES else "unexpected"
        self.cleanup_failed = cleanup_failed
        super().__init__(self.code)


@contextmanager
def phase(code: str):
    try:
        yield
    except AuthFailure:
        raise
    except Exception:
        raise AuthFailure(code) from None


def identity(value: os.stat_result) -> list[int]:
    return [value.st_dev, value.st_ino]


def present(path: Path) -> os.stat_result | None:
    try:
        return path.lstat()
    except FileNotFoundError:
        return None


def directory(value: os.stat_result, *, private: bool = False) -> os.stat_result:
    if (not stat.S_ISDIR(value.st_mode) or value.st_uid != os.getuid()
            or stat.S_IMODE(value.st_mode) & 0o022
            or (private and stat.S_IMODE(value.st_mode) != 0o700)):
        raise ValueError("Unsafe authentication directory")
    return value


def owned_directory(path: Path, *, private: bool = False) -> os.stat_result:
    return directory(path.lstat(), private=private)


def private_file(value: os.stat_result) -> None:
    if (not stat.S_ISREG(value.st_mode) or value.st_uid != os.getuid()
            or value.st_nlink != 1 or stat.S_IMODE(value.st_mode) != 0o600
            or value.st_size > MAX_CONFIG_BYTES):
        raise ValueError("Unsafe authentication file")


def read_json(name: str, parent: int) -> object:
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    try:
        private_file(os.fstat(descriptor))
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(MAX_CONFIG_BYTES + 1)
        if len(data) > MAX_CONFIG_BYTES:
            raise ValueError("Oversized authentication file")
        return json.loads(data)
    finally:
        os.close(descriptor)


class RegistryAuth:
    def __init__(self, scratch: Path):
        self.scratch = Path(scratch)
        self.auth = self.scratch / "auth"
        self.home = self.auth / "home"
        self.docker = self.home / ".docker" / "config.json"
        self.registry = self.auth / "registry-auth.json"
        self.journal = self.auth / "state.json"
        self.attest = self.auth / "attest"

    def _scratch(self, *, create: bool = False, missing_ok: bool = False) -> bool:
        if (not self.scratch.is_absolute() or ".." in self.scratch.parts
                or self.scratch == Path("/tmp")
                or not self.scratch.is_relative_to("/tmp")):
            raise ValueError("Authentication state must be below /tmp")
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
        return True

    def _save(self, state: dict) -> None:
        descriptor = os.open(self.journal, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            json.dump(state, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        descriptor = os.open(self.auth, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @contextmanager
    def _root(self):
        # Pin both directories, and read the marker relative to the pinned root.
        scratch_fd = os.open(self.scratch, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            directory(os.fstat(scratch_fd))
            auth_fd = os.open("auth", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=scratch_fd)
            try:
                value = directory(os.fstat(auth_fd), private=True)
                state = read_json("state.json", auth_fd)
                if (not isinstance(state, dict) or set(state) != {"version", "uid", "auth"}
                        or type(state["version"]) is not int or state["version"] != 2
                        or type(state["uid"]) is not int or state["uid"] != os.getuid()
                        or not isinstance(state["auth"], list) or len(state["auth"]) != 2
                        or any(type(item) is not int or item < 0 for item in state["auth"])
                        or state["auth"] != identity(value)):
                    raise ValueError("Invalid authentication ownership marker")
                self._still_owned(scratch_fd, auth_fd, state)
                yield scratch_fd, auth_fd, state
            finally:
                os.close(auth_fd)
        finally:
            os.close(scratch_fd)

    def _still_owned(self, scratch_fd: int, auth_fd: int, state: dict) -> None:
        if (identity(owned_directory(self.scratch)) != identity(os.fstat(scratch_fd))
                or identity(directory(os.stat("auth", dir_fd=scratch_fd, follow_symlinks=False), private=True)) != state["auth"]
                or identity(directory(os.fstat(auth_fd), private=True)) != state["auth"]):
            raise ValueError("Authentication root changed")

    def _configuration(self, name: str, parent: int) -> str:
        config = read_json(name, parent)
        # No credential helpers or unrelated registry entries may escape isolation.
        auths = config.get("auths") if isinstance(config, dict) else None
        entry = auths.get("ghcr.io") if isinstance(auths, dict) else None
        encoded = entry.get("auth") if isinstance(entry, dict) else None
        if (not isinstance(config, dict) or set(config) != {"auths"}
                or not isinstance(auths, dict) or set(auths) != {"ghcr.io"}
                or not isinstance(entry, dict) or set(entry) != {"auth"}
                or not isinstance(encoded, str)):
            raise ValueError("Invalid isolated GHCR credentials")
        user, password = base64.b64decode(encoded, validate=True).split(b":", 1)
        if not user or not password:
            raise ValueError("Invalid inline GHCR credentials")
        return encoded

    def _login(self, client: str, token: str, actor: str) -> None:
        environment = {key: value for key, value in os.environ.items()
                       if key not in {"REGISTRY_TOKEN", "GH_TOKEN", "GITHUB_TOKEN", "DOCKER_AUTH_CONFIG"}
                       and value != token}
        environment["DOCKER_CONFIG"] = str(self.docker.parent)
        environment["REGISTRY_AUTH_FILE"] = str(self.registry)
        with phase(client + "-login"):
            result = subprocess.run(
                [client, "login", "--username", actor, "--password-stdin", "ghcr.io"],
                input=token.encode(), env=environment, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=60, check=False,
            )
            if result.returncode:
                raise ValueError("Registry login failed")

    def prepare(self, token: str, actor: str) -> None:
        with phase("login-input"):
            if (not token or not actor or any(character in actor for character in "\r\n\0")
                    or any(character in token for character in "\r\n\0")):
                raise ValueError("Missing or invalid registry login input")
        with phase("scratch"):
            self._scratch(create=True)
        with phase("existing-state"):
            # Never clean up state belonging to a previous invocation on rejection.
            self.auth.mkdir(mode=0o700)
        try:
            with phase("initialize"):
                self._save({"version": 2, "uid": os.getuid(), "auth": identity(self.auth.lstat())})
                self.home.mkdir(mode=0o700)
                self.docker.parent.mkdir(mode=0o700)
                self.attest.mkdir(mode=0o700)
                for path in (self.docker, self.registry):
                    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    with os.fdopen(descriptor, "w") as stream:
                        # A nonempty auth map prevents Docker's automatic native
                        # credential-store discovery before the inline preflight.
                        initial = {"auths": {"ghcr.io": {}} if path == self.docker else {}}
                        json.dump(initial, stream)
                        stream.write("\n")
            self._login("docker", token, actor)
            self._login("skopeo", token, actor)
            with phase("credentials"):
                self.check()
                if self._credentials() != base64.b64encode(f"{actor}:{token}".encode()).decode():
                    raise ValueError("Registry clients produced unexpected credentials")
        except Exception as error:
            cleanup_failed = False
            try:
                self.cleanup()
            except Exception:
                cleanup_failed = True
            code = error.code if isinstance(error, AuthFailure) else "unexpected"
            raise AuthFailure(code, cleanup_failed=cleanup_failed) from None

    def _credentials(self) -> str:
        with self._root() as (_scratch_fd, auth_fd, _state):
            with self._directory("home", auth_fd) as home_fd:
                with self._directory(".docker", home_fd) as docker_fd:
                    encoded = self._configuration("config.json", docker_fd)
            if encoded != self._configuration("registry-auth.json", auth_fd):
                raise ValueError("Registry clients produced inconsistent credentials")
            with self._directory("attest", auth_fd):
                pass
            return encoded

    @contextmanager
    def _directory(self, name: str, parent: int):
        descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            directory(os.fstat(descriptor), private=True)
            yield descriptor
        finally:
            os.close(descriptor)

    def check(self) -> None:
        with phase("preflight"):
            self._scratch()
            self._credentials()

    def cleanup(self) -> None:
        with phase("cleanup"):
            if not self._scratch(missing_ok=True) or present(self.auth) is None:
                return
            if not shutil.rmtree.avoids_symlink_attacks:
                raise ValueError("Descriptor-safe cleanup is required")
            with self._root() as (scratch_fd, auth_fd, state):
                # Keep the ownership marker through interrupted subtree removal.
                if set(os.listdir(auth_fd)) - {"state.json", "home", "registry-auth.json", "attest"}:
                    raise ValueError("Unexpected authentication state")
                for name in ("home", "registry-auth.json", "attest"):
                    self._still_owned(scratch_fd, auth_fd, state)
                    try:
                        value = os.stat(name, dir_fd=auth_fd, follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    if stat.S_ISDIR(value.st_mode):
                        shutil.rmtree(name, dir_fd=auth_fd)
                    else:
                        os.unlink(name, dir_fd=auth_fd)
                self._still_owned(scratch_fd, auth_fd, state)
                if set(os.listdir(auth_fd)) != {"state.json"}:
                    raise ValueError("Authentication state changed during cleanup")
                os.unlink("state.json", dir_fd=auth_fd)
                self._still_owned(scratch_fd, auth_fd, state)
                # A crash here leaves an empty, unmarked root: fail closed on retry.
                os.rmdir("auth", dir_fd=scratch_fd)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("prepare", "check", "cleanup"))
    arguments = parser.parse_args()
    try:
        with phase("environment"):
            auth = RegistryAuth(Path(os.environ["RELEASE_SCRATCH"]))
        if arguments.operation == "prepare":
            if (os.environ.get("GITHUB_ACTIONS") != "true"
                    or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):
                raise AuthFailure("hosted-runner")
            with phase("login-input"):
                token, actor = os.environ["REGISTRY_TOKEN"], os.environ["GITHUB_ACTOR"]
            auth.prepare(token, actor)
        elif arguments.operation == "check":
            auth.check()
        else:
            auth.cleanup()
    except Exception as error:
        code = error.code if isinstance(error, AuthFailure) else "unexpected"
        message = f"Release registry authentication {arguments.operation} failed [{code}]"
        if isinstance(error, AuthFailure) and error.cleanup_failed:
            message += "; cleanup failed [cleanup]; ownership state retained"
        if arguments.operation == "cleanup":
            message += "; unverifiable state is not discarded"
        print(message, file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
