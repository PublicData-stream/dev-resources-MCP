#!/usr/bin/env python3
"""Bounded, secret-free IAM inspection and explicit disposable-key qualification.

This tool does not create broker acceptance receipts. Object-policy, expiry,
quota, and independent negative-operation evidence remain separate gates.
"""
import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, quote
from urllib.request import HTTPRedirectHandler, Request, build_opener
import uuid


BASE = "https://api.scaleway.com/iam/v1alpha1/"


class PreflightError(RuntimeError):
    """Fixed diagnostic codes only."""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise PreflightError("iam_redirect_refused")


def private_read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size > 65536):
            raise PreflightError("unsafe_private_input")
        with os.fdopen(fd, "rb", closefd=False) as source:
            return source.read(65537)
    finally:
        os.close(fd)


def settings(path):
    value = json.loads(private_read(path))
    for name in ("organization_id", "project_id", "issuer_application_id",
                 "reader_application_id", "writer_application_id"):
        if str(uuid.UUID(value[name])) != value[name]:
            raise PreflightError("invalid_scope_identifier")
    if len({value[k] for k in ("issuer_application_id", "reader_application_id", "writer_application_id")}) != 3:
        raise PreflightError("distinct_applications_required")
    for field in ("issuer_access_key_file", "issuer_secret_file"):
        credential = private_read(value[field]).decode().strip()
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,256}", credential):
            raise PreflightError("invalid_credential_file")
        value["access" if field.endswith("access_key_file") else "secret"] = credential
    return value


class IAM:
    def __init__(self, config):
        self.config = config
        self.opener = build_opener(NoRedirect())
        self.next_request = 0.0

    def request(self, method, path, body=None):
        # There is deliberately no network retry owner here.
        time.sleep(max(0, self.next_request - time.monotonic()))
        self.next_request = time.monotonic() + 1
        payload = None if body is None else json.dumps(body).encode()
        request = Request(BASE + path, data=payload, method=method,
                          headers={"X-Auth-Token": self.config["secret"], "Content-Type": "application/json"})
        try:
            with self.opener.open(request, timeout=20) as response:
                raw = response.read(2 * 1024**2 + 1)
                if len(raw) > 2 * 1024**2:
                    raise PreflightError("iam_response_too_large")
                return response.status, json.loads(raw) if raw else {}
        except HTTPError as error:
            # Provider diagnostics are not copied: they may reflect private input.
            return error.code, {}
        except (OSError, ValueError, URLError) as error:
            raise PreflightError("iam_request_uncertain") from error

    def list_path(self, app, description=None):
        query = {"organization_id": self.config["organization_id"], "bearer_id": app,
                 "page_size": "100", "page": "1"}
        if description is not None:
            query["description"] = description
        return "api-keys?" + urlencode(query)


def inspect(iam):
    config = iam.config
    status, identity = iam.request("GET", "api-keys/" + quote(config["access"], safe=""))
    results = {"issuer_identity": {"status": status,
               "matched": status == 200 and identity.get("application_id") == config["issuer_application_id"]}}
    for role in ("reader", "writer"):
        status, response = iam.request("GET", iam.list_path(config[role + "_application_id"]))
        results[role + "_list"] = {"status": status, "bounded": status == 200
                                   and type(response.get("total_count")) is int
                                   and 0 <= response["total_count"] <= 100
                                   and isinstance(response.get("api_keys"), list)
                                   and len(response["api_keys"]) <= 100}
    ready = results["issuer_identity"]["matched"] and all(results[r + "_list"]["bounded"] for r in ("reader", "writer"))
    return {"positive_reads_passed": ready, "checks": results, "acceptance_complete": False}


def persist(path, value):
    # New names only: interruption or an uncertain create must not be replayed.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as output:
        json.dump(value, output)
        output.flush()
        os.fsync(output.fileno())
    fd = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def checked_expiry(value, maximum):
    try:
        actual = datetime.fromisoformat(value["expires_at"].replace("Z", "+00:00"))
        deadline = datetime.fromisoformat(maximum.replace("Z", "+00:00"))
        if not datetime.now(timezone.utc) < actual <= deadline:
            raise ValueError()
        return actual
    except (KeyError, ValueError, TypeError, AttributeError) as error:
        raise PreflightError("issued_key_expiry_not_accepted") from error


def issue(iam, root):
    root = Path(root).absolute()
    if Path("/tmp") not in root.parents or root.exists() or root.is_symlink():
        raise PreflightError("new_owned_tmp_root_required")
    if root.parent.resolve() != root.parent:
        raise PreflightError("symlink_parent_refused")
    for parent in (root.parent, *root.parent.parents):
        if parent == Path("/tmp"):
            info = parent.stat()
            if info.st_uid != 0 or not info.st_mode & stat.S_ISVTX:
                raise PreflightError("unsafe_tmp_parent")
            break
        info = parent.stat()
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise PreflightError("unsafe_state_parent")
    root.mkdir(mode=0o700)
    config = iam.config
    result = inspect(iam)
    persist(root / "reads.json", result)
    if not result["positive_reads_passed"]:
        raise PreflightError("positive_issuer_reads_required")
    token = uuid.uuid4().hex
    expires = (datetime.now(timezone.utc) + timedelta(seconds=900)).isoformat(timespec="seconds").replace("+00:00", "Z")
    for role in ("reader", "writer"):
        description = "devres-acceptance-" + token + "-" + role
        body = {"application_id": config[role + "_application_id"],
                "default_project_id": config["project_id"], "description": description,
                "expires_at": expires}
        # Record intent BEFORE the only create call. Never automatically retry it.
        persist(root / (role + "-intent.json"), body)
        status, key = iam.request("POST", "api-keys", body)
        if status != 200:
            persist(root / (role + "-status.json"), {"status": status})
            raise PreflightError("admitted_key_create_failed")
        persist(root / (role + "-key.json"), key)
        if (key.get("application_id") != body["application_id"] or not key.get("secret_key")
                or key.get("description") != description
                or key.get("default_project_id") != config["project_id"]
                or not re.fullmatch(r"[A-Za-z0-9._-]{1,256}", key.get("access_key", ""))):
            raise PreflightError("unexpected_issued_key")
        actual_expiry = checked_expiry(key, expires)
        status, readback = iam.request("GET", "api-keys/" + key["access_key"])
        if (status != 200 or readback.get("application_id") != body["application_id"]
                or readback.get("access_key") != key["access_key"]
                or readback.get("description") != description
                or readback.get("default_project_id") != config["project_id"]
                or checked_expiry(readback, expires) != actual_expiry):
            raise PreflightError("issued_key_readback_failed")
        status, found = iam.request("GET", iam.list_path(body["application_id"], description))
        if (status != 200 or type(found.get("total_count")) is not int
                or found["total_count"] != 1 or len(found.get("api_keys", [])) != 1
                or found["api_keys"][0].get("access_key") != key["access_key"]):
            raise PreflightError("issued_key_reconciliation_failed")
    result = {"admitted_create_get_list_passed": True, "ttl_requested_seconds": 900,
              "acceptance_complete": False, "requires_s3_expiry_quota_and_negative_tests": True}
    persist(root / "issued.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", required=True, type=Path)
    parser.add_argument("--state-root", type=Path)
    parser.add_argument("operation", choices=("inspect", "issue"))
    args = parser.parse_args()
    client = IAM(settings(args.inputs))
    if args.operation == "issue":
        if args.state_root is None:
            parser.error("issue requires a new --state-root below /tmp")
        result = issue(client, args.state_root)
    else:
        result = inspect(client)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (PreflightError, OSError, ValueError, KeyError, TypeError):
        print("Issuer preflight failed; inspect private state before another attempt.", file=sys.stderr)
        raise SystemExit(1) from None
