#!/usr/bin/env python3
"""Build offline customer packages for an operator-supplied dev-resources endpoint.

The maintained frontmatter subset is deliberately small: a plain name and one
JSON-quoted description. JSON strings are valid YAML scalars, so packaging needs
no YAML dependency. Skill Creator validation remains an independent author check.
"""
from __future__ import annotations

import argparse
import copy
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tempfile
from urllib.parse import unquote, urlsplit
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "plugins" / "dev-resources"
SERVER = "dev-resources"
TARGETS = ("openai", "claude-code", "claude-skills")
# Claude's custom-skill upload surface has a tighter limit than developer tools.
# https://support.claude.com/en/articles/12512198-how-to-create-custom-skills
CLAUDE_UPLOAD_DESCRIPTION_LIMIT = 200
SKILLS = {
    "devres-standards-research": ("Standards Research", "Research standards and browser evidence",
                                "research a standards or browser behavior question"),
    "devres-package-research": ("Package Research", "Research exact Rust and npm package releases",
                              "investigate an exact Rust or npm package release"),
    "devres-lockfile-audit": ("Lockfile Audit", "Assess lockfiles with qualified advisory evidence",
                            "assess my supplied lockfile using MCP advisory evidence"),
}
LINK = re.compile(r"\[[^\]\n]*\]\(([^\s)]+)(?:\s+\"[^\"]*\")?\)")


def endpoint(value: str) -> str:
    if any(character.isspace() or ord(character) < 32 or character in "\\<>{}$" for character in value):
        raise ValueError("endpoint contains whitespace, control characters, or placeholders")
    try:
        parsed = urlsplit(value)
        port = parsed.port
        host = parsed.hostname
    except ValueError as error:
        raise ValueError("invalid endpoint authority") from error
    if (parsed.scheme != "https" or not host or parsed.username is not None
            or parsed.password is not None or parsed.path != "/mcp"
            or parsed.query or parsed.fragment or "?" in value or "#" in value
            or (port is not None and not 1 <= port <= 65535)):
        raise ValueError("endpoint must be an HTTPS /mcp URL without credentials, query, or fragment")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if len(host) > 253 or any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                                  for label in host.split(".")):
            raise ValueError("endpoint requires an IP address or ASCII DNS hostname") from None
    if parsed.netloc.endswith(":"):
        raise ValueError("endpoint has an empty port")
    return value


def regular(path: Path) -> bytes:
    if any(part.is_symlink() for part in (path, *path.parents)) or not path.is_file():
        raise ValueError("package sources must be regular files without symlink ancestors")
    if path.stat().st_size > 1024 * 1024:
        raise ValueError("package source exceeds 1 MiB")
    data = path.read_bytes()
    data.decode("utf-8")
    return data


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def frontmatter(data: bytes, expected: str, *, description_limit: int = 1024) -> None:
    match = re.match(r'\A---\nname: ([a-z0-9-]+)\ndescription: ("[^\n]+")\n---(?:\n|\Z)', data.decode())
    if not match or match[1] != expected:
        raise ValueError("skill must have matching name and a single JSON-quoted description")
    description = json.loads(match[2])
    if not description.strip() or len(description) > description_limit:
        raise ValueError(f"skill description must contain 1..{description_limit} characters")


def skill_files(source: Path, name: str, *, description_limit: int = 1024) -> dict[str, bytes]:
    folder = source / "skills" / name
    if not folder.is_dir() or folder.is_symlink():
        raise ValueError("missing skill directory")
    files = {}
    for path in sorted(folder.rglob("*")):
        if path.is_symlink():
            raise ValueError("skill contains a symlink")
        if path.is_dir():
            continue
        relative = path.relative_to(folder).as_posix()
        if relative != "SKILL.md" and not (relative.startswith("references/") and relative.endswith(".md")):
            raise ValueError("unexpected skill component; only SKILL.md and Markdown references are packaged")
        files[relative] = regular(path)
    if "SKILL.md" not in files:
        raise ValueError("missing SKILL.md")
    frontmatter(files["SKILL.md"], name, description_limit=description_limit)
    for relative, data in files.items():
        for target in LINK.findall(data.decode()):
            parsed = urlsplit(target)
            if parsed.scheme == "https":
                continue
            if parsed.scheme or parsed.netloc or parsed.query:
                raise ValueError("unsupported reference URL")
            if not parsed.path:
                continue
            path = PurePosixPath(unquote(parsed.path))
            if path.is_absolute() or ".." in path.parts or "\\" in str(path):
                raise ValueError("reference escapes its standalone skill")
            resolved = (PurePosixPath(relative).parent / path).as_posix()
            if resolved not in files:
                raise ValueError("missing local reference")
    return files


def yaml_metadata(name: str, url: str) -> bytes:
    display, short, task = SKILLS[name]
    # Quote values as JSON strings, a subset of YAML, without needing a YAML writer.
    quote = json.dumps
    return (f"interface:\n  display_name: {quote(display)}\n"
            f"  short_description: {quote(short)}\n"
            f"  default_prompt: {quote('Use $' + name + ' to ' + task + '.')}\n"
            "policy:\n  allow_implicit_invocation: true\n"
            "dependencies:\n  tools:\n    - type: \"mcp\"\n"
            f"      value: {quote(SERVER)}\n"
            "      description: \"Anonymous developer evidence MCP server\"\n"
            "      transport: \"streamable_http\"\n"
            f"      url: {quote(url)}\n").encode()


def package_files(target: str, manifest: dict, skills: dict, license_body: bytes, url: str) -> dict:
    common = {f"skills/{name}/{relative}": data
              for name, files in skills.items() for relative, data in files.items()}
    common["LICENSE"] = license_body
    http = {"mcpServers": {SERVER: {"type": "http", "url": url}}}
    identity = {key: copy.deepcopy(manifest[key]) for key in
                ("name", "version", "description", "author", "repository", "license")}
    if target == "openai":
        portable_mcp = {
            "$schema": "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
            "mcpServers": {SERVER: {"type": "streamable-http", "url": url,
                                   "extensions": {"com.openai": {"auth": {"type": "none"}}}}},
        }
        compatibility = {**identity, "skills": "./skills/", "mcpServers": "./.mcp.json",
                         "interface": copy.deepcopy(manifest["extensions"]["com.openai"]["interface"])}
        common.update({"plugin.json": json_bytes(manifest), "mcp.json": json_bytes(portable_mcp),
                       ".codex-plugin/plugin.json": json_bytes(compatibility), ".mcp.json": json_bytes(http)})
        common.update({f"skills/{name}/agents/openai.yaml": yaml_metadata(name, url) for name in skills})
    elif target == "claude-code":
        common.update({".claude-plugin/plugin.json": json_bytes(identity), ".mcp.json": json_bytes(http)})
    else:
        raise ValueError("unknown plugin target")
    return common


def write_bundle(directory: Path, archive: Path, files: dict[str, bytes]) -> None:
    directory.mkdir(mode=0o700)
    for relative, data in sorted(files.items()):
        path = directory / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED) as output:
        for relative, data in sorted(files.items()):
            member = zipfile.ZipInfo(f"{directory.name}/{relative}", date_time=(1980, 1, 1, 0, 0, 0))
            member.compress_type = zipfile.ZIP_DEFLATED
            member.external_attr = 0o100644 << 16
            output.writestr(member, data)
    # Verify the final artifact rather than just the inputs to the archive writer.
    with zipfile.ZipFile(archive) as output:
        expected = {f"{directory.name}/{relative}": data for relative, data in files.items()}
        if output.testzip() is not None or set(output.namelist()) != set(expected):
            raise ValueError("archive component verification failed")
        if any(output.read(relative) != data for relative, data in expected.items()):
            raise ValueError("archive content verification failed")


def reserve_output(output: Path) -> None:
    """Create a private output through owned, non-writable parent directories.

    Walk from /tmp with directory descriptors so a newly inserted symlink cannot
    redirect directory creation. The sticky system /tmp itself is the exception
    to the rule that writable ancestors must be owned exclusively by this user.
    """
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parent = os.open("/tmp", flags)
    try:
        info = os.fstat(parent)
        if (info.st_uid not in (0, os.geteuid())
                or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX)):
            raise ValueError("unsafe temporary root")
        for component in output.relative_to("/tmp").parts[:-1]:
            try:
                os.mkdir(component, mode=0o700, dir_fd=parent)
            except FileExistsError:
                pass
            child = os.open(component, flags, dir_fd=parent)
            info = os.fstat(child)
            if info.st_uid != os.geteuid() or info.st_mode & 0o022:
                os.close(child)
                raise ValueError("output ancestors must be owned by this user and not writable by others")
            os.close(parent)
            parent = child
        os.mkdir(output.name, mode=0o700, dir_fd=parent)
    finally:
        os.close(parent)


def verify_directory(directory: Path, files: dict[str, bytes]) -> None:
    members = list(directory.rglob("*"))
    if any(path.is_symlink() for path in members):
        raise ValueError("expanded package contains a symlink")
    actual = {path.relative_to(directory).as_posix() for path in members if path.is_file()}
    if actual != set(files) or any(regular(directory / name) != data for name, data in files.items()):
        raise ValueError("expanded package content verification failed")


def build(url: str, output: Path, target: str = "all", *, source: Path = SOURCE,
          license_path: Path = ROOT / "LICENSE") -> list[Path]:
    url = endpoint(url)
    if target not in (*TARGETS, "all"):
        raise ValueError("unknown package target")
    output = output.absolute()
    if any(path.is_symlink() for path in (output, *output.parents)):
        raise ValueError("output must not have symlink ancestors")
    output = output.resolve()
    if Path("/tmp") not in output.parents or output.exists():
        raise ValueError("output must be a new directory below /tmp")
    if output.is_relative_to(source.resolve()):
        raise ValueError("output cannot be inside package sources")
    manifest = json.loads(regular(source / "plugin.json"))
    if (manifest.get("$schema") != "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"
            or manifest.get("name") != SERVER
            or not re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)",
                                manifest.get("version", ""))):
        raise ValueError("invalid canonical plugin identity")
    description_limit = CLAUDE_UPLOAD_DESCRIPTION_LIMIT if target in ("all", "claude-skills") else 1024
    skills = {name: skill_files(source, name, description_limit=description_limit) for name in SKILLS}
    license_body = regular(license_path)
    targets = TARGETS if target == "all" else (target,)
    # Validate source and plans before publishing anything at the requested path.
    bundles = []
    for selected in targets:
        if selected == "claude-skills":
            bundles.extend((selected, name, {**files, "LICENSE": license_body}) for name, files in skills.items())
        else:
            bundles.append((selected, SERVER, package_files(selected, manifest, skills, license_body, url)))
    reserve_output(output)
    try:
        with tempfile.TemporaryDirectory(prefix=".devres-package-", dir=output) as scratch:
            staging = Path(scratch)
            for selected, name, files in bundles:
                folder = staging / selected
                folder.mkdir(mode=0o700, exist_ok=True)
                write_bundle(folder / name, folder / (name + ".zip"), files)
            for child in staging.iterdir():
                child.rename(output / child.name)
            for selected, name, files in bundles:
                verify_directory(output / selected / name, files)
    except BaseException:
        shutil.rmtree(output)
        raise
    return [output / selected / (name + ".zip") for selected, name, _ in bundles]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mcp-url", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target", choices=(*TARGETS, "all"), default="all")
    args = parser.parse_args()
    try:
        archives = build(args.mcp_url, args.output, args.target)
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, zipfile.BadZipFile):
        # Do not echo a rejected URL or source data: either could contain credentials.
        parser.exit(1, "package validation failed; check endpoint, sources, and new /tmp output path\n")
    for archive in archives:
        print(archive)


if __name__ == "__main__":
    main()
