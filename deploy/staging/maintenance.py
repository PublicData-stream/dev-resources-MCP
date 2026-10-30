#!/usr/bin/env python3
"""Owner-scoped, coordinated staging snapshots and a latched capacity fence.

Run as root on the deployment host. State and lock live outside the snapshotted
datasets. Only an explicit ``resume`` may clear an interrupted operation or a
capacity fence. No database credentials or caller data are read by this tool.
"""

import argparse
import contextlib
from datetime import datetime, timedelta, timezone
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time


NAMESPACE = "devres-staging"
DATASET = "cachepool/devres-staging"
POOL = "cachepool"
GIB = 1024**3
QUOTA = 1536 * GIB
CURRENT_LIMITS = {DATASET + "/postgres": 256 * GIB,
                  DATASET + "/evidence": 768 * GIB}
SNAPSHOT_HIGH_WATER = 400 * GIB
POOL_MIN_FREE = 128 * GIB
SNAPSHOT_RE = re.compile(r"devres-\d{8}T\d{6}Z(?:-[a-z][a-z0-9-]{0,31})?\Z")
LABEL_RE = re.compile(r"[a-z][a-z0-9-]{0,31}\Z")
STATE_ROOT = Path("/var/lib/devres-staging")
POSTGRES_IMAGE = "postgres@sha256:ae6c78831cbc35fa3a4aaf4d763ddacf6183d6004774cc2dc28b3920410d1d1a"


def upgrade_module():
    path = Path(__file__).resolve().parent / 'upgrade.py'
    if not path.exists():
        return None
    spec = importlib.util.spec_from_file_location('devres_upgrade_guard', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def require_no_upgrade():
    module = upgrade_module()
    if module is not None and module.active(STATE_ROOT):
        raise MaintenanceError('upgrade_in_progress')


class MaintenanceError(RuntimeError):
    """Fixed-code operator failure; external command output is never echoed."""


def execute(args):
    try:
        result = subprocess.run(args, text=True, capture_output=True, timeout=240,
                                check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise MaintenanceError("command_unavailable_or_timed_out") from error
    if result.returncode:
        raise MaintenanceError("command_failed")
    if len(result.stdout) > 1024 * 1024:
        raise MaintenanceError("command_output_exceeds_bound")
    return result.stdout.strip()


def snapshot_name(value):
    if not SNAPSHOT_RE.fullmatch(value):
        raise MaintenanceError("invalid_snapshot_name")
    try:
        datetime.strptime(value[7:23], "%Y%m%dT%H%M%SZ")
    except ValueError as error:
        raise MaintenanceError("invalid_snapshot_time") from error
    return value


class State:
    """Atomic private metadata with fsync; never follow state or lock symlinks."""

    def __init__(self, root=STATE_ROOT):
        self.root = Path(root)

    def prepare(self):
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.root.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077):
            raise MaintenanceError("unsafe_state_directory")

    @contextlib.contextmanager
    def locked(self):
        self.prepare()
        fd = os.open(self.root / "maintenance.lock",
                     os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_mode & 0o077 or info.st_nlink != 1):
                raise MaintenanceError("unsafe_lock_file")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise MaintenanceError("maintenance_busy") from error
            yield
        finally:
            os.close(fd)

    def load(self):
        try:
            fd = os.open(self.root / "state.json", os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return {"version": 1, "fence": None, "operation": None, "verified": []}
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_mode & 0o077 or info.st_nlink != 1
                    or info.st_size > 1024 * 1024):
                raise MaintenanceError("unsafe_state_file")
            with os.fdopen(fd, encoding="utf-8", closefd=False) as stream:
                value = json.load(stream)
            if (value.get("version") != 1 or not isinstance(value.get("verified"), list)
                    or any(not isinstance(v, str) or not SNAPSHOT_RE.fullmatch(v)
                           for v in value["verified"])):
                raise MaintenanceError("invalid_state")
            return value
        except (ValueError, AttributeError) as error:
            raise MaintenanceError("invalid_state") from error
        finally:
            os.close(fd)

    def save(self, value):
        fd, temporary = tempfile.mkstemp(prefix=".state-", dir=self.root)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", closefd=False) as stream:
                json.dump(value, stream, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, self.root / "state.json")
        directory = os.open(self.root, os.O_DIRECTORY | os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


class Maintenance:
    def __init__(self, state, run=execute, now=None, sleep=time.sleep,
                 monotonic=time.monotonic):
        self.state = state
        self.run = run
        self.now = now or (lambda: datetime.now(timezone.utc))
        self.sleep = sleep
        self.monotonic = monotonic

    def k(self, *args):
        return self.run(["k3s", "kubectl", "--request-timeout=30s", "-n", NAMESPACE,
                         *args])

    def replicas(self, deployment):
        result = self.k("get", "deployment", deployment,
                        "-o", "jsonpath={.spec.replicas}")
        if result not in ("0", "1"):
            raise MaintenanceError("unexpected_replica_count")
        return int(result)

    def scale(self, deployment, replicas):
        self.k("scale", "deployment/" + deployment, "--replicas=" + str(replicas))

    def stopped(self, deployment):
        deadline = self.monotonic() + 180
        while self.k("get", "pods", "-l", "app=" + deployment, "-o", "name"):
            if self.monotonic() >= deadline:
                raise MaintenanceError("writer_termination_unconfirmed")
            self.sleep(1)
        if self.replicas(deployment) != 0:
            raise MaintenanceError("writer_replica_fence_changed")

    def start(self, deployment, replicas):
        self.scale(deployment, replicas)
        if replicas:
            self.k("rollout", "status", "deployment/" + deployment, "--timeout=180s")

    def metrics(self):
        output = self.run(["zfs", "list", "-Hp", "-r", "-o",
                           "name,used,referenced,usedbysnapshots,quota,refquota", DATASET])
        rows = {}
        try:
            for line in output.splitlines():
                name, *values = line.split("\t")
                if len(values) != 5 or name in rows:
                    raise ValueError
                rows[name] = tuple(int(v) for v in values)
            if set(rows) != {DATASET, *CURRENT_LIMITS}:
                raise ValueError
            if rows[DATASET][3] != QUOTA:
                raise ValueError
            if any(rows[name][4] != limit for name, limit in CURRENT_LIMITS.items()):
                raise ValueError
            pool_free = int(self.run(["zpool", "list", "-Hp", "-o", "free", POOL]))
            if pool_free < 0 or any(v < 0 for values in rows.values() for v in values):
                raise ValueError
        except ValueError as error:
            raise MaintenanceError("storage_layout_or_counters_invalid") from error
        return {"dataset_used": rows[DATASET][0],
                "current_referenced": sum(rows[name][1] for name in CURRENT_LIMITS),
                "postgres_referenced": rows[DATASET + "/postgres"][1],
                "evidence_referenced": rows[DATASET + "/evidence"][1],
                "snapshot_used": sum(values[2] for values in rows.values()),
                "pool_free": pool_free}

    @staticmethod
    def capacity_reason(metrics):
        if metrics["snapshot_used"] >= SNAPSHOT_HIGH_WATER:
            return "snapshot_high_water"
        if metrics["dataset_used"] * 10 >= QUOTA * 9:
            return "dataset_high_water"
        if metrics["pool_free"] <= POOL_MIN_FREE:
            return "pool_low_free"
        for child in ("postgres", "evidence"):
            if metrics[child + "_referenced"] * 10 >= CURRENT_LIMITS[DATASET + "/" + child] * 9:
                return child + "_high_water"
        if metrics["current_referenced"] >= 1024 * GIB:
            return "current_data_high_water"
        return None

    def guard(self):
        value = self.state.load()
        counters = None
        try:
            counters = self.metrics()
            reason = self.capacity_reason(counters)
        except MaintenanceError:
            reason = "storage_counters_unavailable"
        if reason and not value.get("fence"):
            # Save desired state before scaling; a later run must not replace it with 0.
            desired = self.replicas("backend")
            value["fence"] = {"reason": reason, "backend": desired}
            self.state.save(value)
        if value.get("fence") or value.get("operation"):
            self.scale("backend", 0)
            self.stopped("backend")
        if value.get("fence"):
            module = upgrade_module()
            owned = module.owned_containers(STATE_ROOT) if module is not None else None
            if owned:
                names = self.run(['docker', 'ps', '-a', '--filter',
                                  'label=' + owned['label'] + '=' + owned['token'],
                                  '--format', '{{.Names}}']).splitlines()
                for name in names:
                    if not name.startswith(owned['prefix'] + '-') or not re.fullmatch(r'[a-z0-9-]+', name):
                        raise MaintenanceError('upgrade_container_inventory_changed')
                    self.run(['docker', 'stop', '--time', '30', name])
        return {"fenced": bool(value.get("fence") or value.get("operation")),
                "reason": value.get("fence", {}).get("reason") if value.get("fence") else None,
                "counters": counters}

    def snapshots(self):
        output = self.run(["zfs", "list", "-Hp", "-r", "-t", "snapshot", "-o",
                           "name,creation", DATASET])
        found = {}
        try:
            for line in output.splitlines():
                if not line:
                    continue
                full_name, created = line.split("\t")
                dataset, name = full_name.split("@", 1)
                if dataset in {DATASET, *CURRENT_LIMITS} and SNAPSHOT_RE.fullmatch(name):
                    found.setdefault(name, {})[dataset] = int(created)
        except ValueError as error:
            raise MaintenanceError("snapshot_inventory_invalid") from error
        return {name: parts[DATASET] for name, parts in found.items()
                if set(parts) == {DATASET, *CURRENT_LIMITS}}

    def restore_replicas(self, operation):
        self.start("postgres", operation["postgres"])
        self.start("backend", operation["backend"])

    def postgres_shut_down(self):
        result = self.run([
            "docker", "run", "--rm", "--network", "none", "--read-only",
            "--user", "999:999", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "-e", "LC_ALL=C",
            "--entrypoint", "pg_controldata", "-v",
            "/mnt/devres-staging/postgres:/pgdata:ro", POSTGRES_IMAGE,
            "/pgdata/18/docker",
        ])
        states = [line.partition(":")[2].strip() for line in result.splitlines()
                  if line.startswith("Database cluster state:")]
        if states != ["shut down"]:
            raise MaintenanceError("postgres_clean_shutdown_unconfirmed")

    def snapshot(self, label=None, *, upgrade=False):
        if not upgrade:
            require_no_upgrade()
        if label is not None and not LABEL_RE.fullmatch(label):
            raise MaintenanceError("invalid_snapshot_label")
        value = self.state.load()
        if value.get("fence") or value.get("operation"):
            raise MaintenanceError("explicit_resume_required")
        if self.capacity_reason(self.metrics()):
            self.guard()
            raise MaintenanceError("capacity_fence_active")
        name = "devres-" + self.now().strftime("%Y%m%dT%H%M%SZ")
        if label:
            name += "-" + label
        snapshot_name(name)
        if name in self.snapshots():
            raise MaintenanceError("snapshot_already_exists")
        operation = {"backend": self.replicas("backend"),
                     "postgres": self.replicas("postgres"), "snapshot": name,
                     "phase": "draining_backend"}
        if operation["backend"] and not operation["postgres"]:
            raise MaintenanceError("postgres_not_running")
        value["operation"] = operation
        self.state.save(value)
        drained = False
        restoring = False
        try:
            self.scale("backend", 0)
            self.stopped("backend")
            operation["phase"] = "draining_postgres"
            self.state.save(value)
            self.scale("postgres", 0)
            self.stopped("postgres")
            operation["phase"] = "checking_postgres_shutdown"
            self.state.save(value)
            self.postgres_shut_down()
            drained = True
            operation["phase"] = "snapshotting"
            self.state.save(value)
            self.run(["zfs", "snapshot", "-r", DATASET + "@" + name])
            operation["phase"] = "resuming"
            self.state.save(value)
            restoring = True
            self.restore_replicas(operation)
            value["operation"] = None
            self.state.save(value)
        except Exception:
            # Only recover automatically when both drains were proved and no resume
            # has failed. Partial drains and restart failures require operator review.
            if drained and not restoring:
                try:
                    if not self.capacity_reason(self.metrics()):
                        self.restore_replicas(operation)
                        value["operation"] = None
                        self.state.save(value)
                except Exception:
                    pass
            if restoring:
                try:
                    self.scale("backend", 0)
                    self.stopped("backend")
                except Exception:
                    pass
            raise
        return {"snapshot": name, "verified": False}

    def mark_verified(self, name):
        name = snapshot_name(name)
        snapshots = self.snapshots()
        if name not in snapshots:
            raise MaintenanceError("complete_snapshot_not_found")
        value = self.state.load()
        if name not in value["verified"]:
            value["verified"].append(name)
            self.state.save(value)
        # Seven-day target. Delete only old owned complete snapshots explicitly
        # verified by a restore drill. Keep the newest verified point regardless.
        candidates = {n: snapshots[n] for n in value["verified"] if n in snapshots}
        newest = max(candidates, key=candidates.get)
        cutoff = int((self.now() - timedelta(days=7)).timestamp())
        removed = []
        for old, created in sorted(candidates.items(), key=lambda item: item[1]):
            if old != newest and created < cutoff:
                self.run(["zfs", "destroy", "-r", DATASET + "@" + old])
                value["verified"].remove(old)
                self.state.save(value)
                removed.append(old)
        return {"verified": name, "expired_verified_snapshots_removed": len(removed)}

    def resume(self):
        require_no_upgrade()
        value = self.state.load()
        if not value.get("fence") and not value.get("operation"):
            raise MaintenanceError("no_recovery_pending")
        if self.capacity_reason(self.metrics()):
            raise MaintenanceError("capacity_still_unsafe")
        operation = value.get("operation")
        try:
            if operation:
                self.restore_replicas(operation)
            elif value.get("fence"):
                if self.replicas("postgres") != 1:
                    raise MaintenanceError("postgres_not_running")
                self.start("backend", value["fence"]["backend"])
        except Exception:
            try:
                self.scale("backend", 0)
                self.stopped("backend")
            except Exception:
                pass
            raise
        value["operation"] = None
        value["fence"] = None
        self.state.save(value)
        return {"resumed": True}

    def status(self):
        value = self.state.load()
        return {"fence": value.get("fence"), "operation": value.get("operation"),
                "verified_snapshot_count": len(value["verified"]), "counters": self.metrics()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    snapshot = subparsers.add_parser("snapshot")
    snapshot.add_argument("--label")
    for command in ("guard", "status", "resume"):
        subparsers.add_parser(command)
    verify = subparsers.add_parser("mark-verified")
    verify.add_argument("snapshot")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.exit(1, "root_required\n")
    state = State()
    try:
        with state.locked():
            maintenance = Maintenance(state)
            if args.command == "snapshot":
                result = maintenance.snapshot(args.label)
            elif args.command == "mark-verified":
                result = maintenance.mark_verified(args.snapshot)
            else:
                result = getattr(maintenance, args.command)()
        print(json.dumps(result, sort_keys=True))
    except (MaintenanceError, OSError, ValueError) as error:
        code = str(error) if isinstance(error, MaintenanceError) else "maintenance_failed"
        print(code, file=sys.stderr)
        return 75 if code == "maintenance_busy" else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
