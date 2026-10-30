import importlib.util
import json
import os
from pathlib import Path
import tempfile
from datetime import datetime, timezone
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("staging_maintenance", ROOT / "deploy/staging/maintenance.py")
maintenance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(maintenance)
NOW = datetime(2026, 10, 29, 12, 0, tzinfo=timezone.utc)
NAME = "devres-20261029T120000Z"


class MemoryState:
    def __init__(self):
        self.value = {"version": 1, "fence": None, "operation": None, "verified": []}
        self.saved = []

    def load(self):
        return json.loads(json.dumps(self.value))

    def save(self, value):
        self.value = json.loads(json.dumps(value))
        self.saved.append(self.load())


class FakeHost:
    def __init__(self):
        self.commands = []
        self.replicas = {"backend": 1, "postgres": 1}
        self.snapshots = {}
        self.used = 12 * maintenance.GIB
        self.snap_used = 0
        self.current = {"postgres": 0, "evidence": 0}
        self.pool_free = 2000 * maintenance.GIB
        self.fail = lambda args: False
        self.pending_backend = False
        self.pg_clean = True
        self.clock = 0

    def run(self, args):
        self.commands.append(tuple(args))
        if self.fail(args):
            raise maintenance.MaintenanceError("injected_failure")
        if args[:2] == ["zpool", "list"]:
            return str(self.pool_free)
        if args[:2] == ["zfs", "list"] and "snapshot" in args:
            return "\n".join(
                f"{dataset}@{name}\t{created}"
                for name, created in self.snapshots.items()
                for dataset in (maintenance.DATASET, *maintenance.CURRENT_LIMITS)
            )
        if args[:2] == ["zfs", "list"]:
            return "\n".join((
                f"{maintenance.DATASET}\t{self.used}\t0\t0\t{maintenance.QUOTA}\t0",
                f"{maintenance.DATASET}/postgres\t0\t{self.current['postgres']}\t0\t0\t{256 * maintenance.GIB}",
                f"{maintenance.DATASET}/evidence\t0\t{self.current['evidence']}\t{self.snap_used}\t0\t{768 * maintenance.GIB}",
            ))
        if args[:2] == ["zfs", "snapshot"]:
            assert self.replicas == {"backend": 0, "postgres": 0}
            self.snapshots[args[-1].split("@")[1]] = int(NOW.timestamp())
            return ""
        if args[:2] == ["zfs", "destroy"]:
            del self.snapshots[args[-1].split("@")[1]]
            return ""
        if args[:2] == ["docker", "run"]:
            assert self.replicas == {"backend": 0, "postgres": 0}
            return "Database cluster state:               " + ("shut down" if self.pg_clean else "in production")
        if args[:2] == ["k3s", "kubectl"]:
            assert args[3:5] == ["-n", "devres-staging"]
            command = args[5:]
            if command[:2] == ["get", "deployment"]:
                return str(self.replicas[command[2]])
            if command[0] == "scale":
                self.replicas[command[1].split("/")[1]] = int(command[2].split("=")[1])
                return ""
            if command[:2] == ["get", "pods"]:
                return "pod/still-terminating" if self.pending_backend and command[3] == "app=backend" else ""
            if command[:2] == ["rollout", "status"]:
                return ""
        raise AssertionError(args)

    def sleep(self, seconds):
        self.clock += seconds


class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.host = FakeHost()
        self.state = MemoryState()
        self.tool = maintenance.Maintenance(
            self.state, self.host.run, now=lambda: NOW,
            sleep=self.host.sleep, monotonic=lambda: self.host.clock,
        )

    def test_snapshot_stops_every_writer_before_atomic_snapshot_and_restores_in_order(self):
        result = self.tool.snapshot("pre-activation")
        self.assertEqual(result, {"snapshot": NAME + "-pre-activation", "verified": False})
        self.assertEqual(self.host.replicas, {"backend": 1, "postgres": 1})
        mutations = [c[5:] if c[0] == "k3s" else c for c in self.host.commands
                     if "scale" in c or c[:2] == ("zfs", "snapshot")]
        self.assertEqual(mutations, [
            ("scale", "deployment/backend", "--replicas=0"),
            ("scale", "deployment/postgres", "--replicas=0"),
            ("zfs", "snapshot", "-r", maintenance.DATASET + "@" + NAME + "-pre-activation"),
            ("scale", "deployment/postgres", "--replicas=1"),
            ("scale", "deployment/backend", "--replicas=1"),
        ])
        self.assertIsNone(self.state.value["operation"])
        self.assertEqual(self.state.value["verified"], [])

    def test_active_upgrade_blocks_snapshot_and_generic_resume(self):
        from unittest.mock import patch
        with patch.object(maintenance, 'upgrade_module') as upgrade:
            upgrade.return_value.active.return_value = True
            for entrypoint in (self.tool.snapshot, self.tool.resume):
                with self.assertRaisesRegex(maintenance.MaintenanceError, 'upgrade_in_progress'):
                    entrypoint()
        self.assertFalse(self.host.commands)

    def test_capacity_fence_stops_only_owned_upgrade_containers(self):
        from unittest.mock import patch
        token = 'a' * 24
        prefix = 'devres-staging-restore-' + token
        original = self.host.run
        def run(args):
            if args[:3] == ['docker', 'ps', '-a']:
                self.assertIn('label=devres.restore-owner=' + token, args)
                return prefix + '-postgres\n' + prefix + '-offline-1'
            if args[:2] == ['docker', 'stop']:
                self.host.commands.append(tuple(args))
                return ''
            return original(args)
        self.tool.run = run
        self.host.pool_free = maintenance.POOL_MIN_FREE
        with patch.object(maintenance, 'upgrade_module') as upgrade:
            upgrade.return_value.owned_containers.return_value = {
                'token': token, 'label': 'devres.restore-owner', 'prefix': prefix}
            self.assertTrue(self.tool.guard()['fenced'])
        stopped = [c[-1] for c in self.host.commands if c[:2] == ('docker', 'stop')]
        self.assertEqual(stopped, [prefix + '-postgres', prefix + '-offline-1'])

    def test_snapshot_preserves_original_zero_replicas(self):
        self.host.replicas = {"backend": 0, "postgres": 0}
        self.tool.snapshot()
        self.assertEqual(self.host.replicas, {"backend": 0, "postgres": 0})

    def test_uncertain_backend_drain_never_stops_postgres_or_snapshots(self):
        self.host.pending_backend = True
        with self.assertRaisesRegex(maintenance.MaintenanceError, "writer_termination"):
            self.tool.snapshot()
        self.assertEqual(self.host.replicas, {"backend": 0, "postgres": 1})
        self.assertFalse(self.host.snapshots)
        self.assertEqual(self.state.value["operation"]["phase"], "draining_backend")
        with self.assertRaisesRegex(maintenance.MaintenanceError, "explicit_resume"):
            self.tool.snapshot()

    def test_failed_snapshot_restores_counts_only_after_confirmed_complete_drain(self):
        self.host.fail = lambda args: args[:2] == ["zfs", "snapshot"]
        with self.assertRaisesRegex(maintenance.MaintenanceError, "injected_failure"):
            self.tool.snapshot()
        self.assertEqual(self.host.replicas, {"backend": 1, "postgres": 1})
        self.assertIsNone(self.state.value["operation"])

    def test_unclean_postgres_state_keeps_both_stopped_and_refuses_snapshot(self):
        self.host.pg_clean = False
        with self.assertRaisesRegex(maintenance.MaintenanceError, "postgres_clean_shutdown_unconfirmed"):
            self.tool.snapshot()
        self.assertEqual(self.host.replicas, {"backend": 0, "postgres": 0})
        self.assertFalse(self.host.snapshots)
        self.assertEqual(self.state.value["operation"]["phase"], "checking_postgres_shutdown")
        inspector = next(c for c in self.host.commands if c[:2] == ("docker", "run"))
        self.assertIn("/mnt/devres-staging/postgres:/pgdata:ro", inspector)
        self.assertIn(maintenance.POSTGRES_IMAGE, inspector)

    def test_restart_failure_fences_backend_and_preserves_snapshot_for_explicit_recovery(self):
        self.host.fail = lambda args: "rollout" in args and "deployment/backend" in args
        with self.assertRaises(maintenance.MaintenanceError):
            self.tool.snapshot()
        self.assertEqual(self.host.replicas["backend"], 0)
        self.assertIn(NAME, self.host.snapshots)
        self.assertEqual(self.state.value["operation"]["backend"], 1)
        self.host.fail = lambda args: False
        self.tool.resume()
        self.assertEqual(self.host.replicas["backend"], 1)
        self.assertIsNone(self.state.value["operation"])

    def test_capacity_fence_persists_after_capacity_recovers_until_explicit_resume(self):
        self.host.snap_used = maintenance.SNAPSHOT_HIGH_WATER
        self.assertTrue(self.tool.guard()["fenced"])
        self.assertEqual(self.host.replicas["backend"], 0)
        self.assertEqual(self.state.value["fence"]["backend"], 1)
        self.tool.guard()
        self.assertEqual(self.state.value["fence"]["backend"], 1)
        with self.assertRaisesRegex(maintenance.MaintenanceError, "capacity_still_unsafe"):
            self.tool.resume()
        self.host.snap_used = 0
        self.assertTrue(self.tool.guard()["fenced"])
        self.assertEqual(self.host.replicas["backend"], 0)
        self.tool.resume()
        self.assertEqual(self.host.replicas["backend"], 1)
        self.assertIsNone(self.state.value["fence"])

    def test_counter_failure_stops_foreground_writes_too(self):
        self.host.fail = lambda args: args[:2] == ["zpool", "list"]
        result = self.tool.guard()
        self.assertEqual(result["reason"], "storage_counters_unavailable")
        self.assertEqual(self.host.replicas["backend"], 0)

    def test_each_child_fences_at_ninety_percent_even_below_total_capacity(self):
        for child in ("postgres", "evidence"):
            with self.subTest(child=child):
                self.setUp()
                limit = maintenance.CURRENT_LIMITS[maintenance.DATASET + "/" + child]
                threshold = (limit * 9 + 9) // 10
                self.host.current[child] = threshold - 1
                counters = self.tool.metrics()
                self.assertEqual(counters[child + "_referenced"], threshold - 1)
                self.assertLess(counters["current_referenced"], 1024 * maintenance.GIB)
                self.assertFalse(self.tool.guard()["fenced"])
                self.assertEqual(self.host.replicas["backend"], 1)
                self.host.current[child] = threshold
                result = self.tool.guard()
                self.assertTrue(result["fenced"])
                self.assertEqual(result["reason"], child + "_high_water")
                self.assertEqual(self.host.replicas["backend"], 0)
                with self.assertRaisesRegex(maintenance.MaintenanceError, "capacity_still_unsafe"):
                    self.tool.resume()

    def test_snapshot_refuses_capacity_failure_before_draining_postgres(self):
        self.host.pool_free = maintenance.POOL_MIN_FREE
        with self.assertRaisesRegex(maintenance.MaintenanceError, "capacity_fence_active"):
            self.tool.snapshot()
        self.assertEqual(self.host.replicas, {"backend": 0, "postgres": 1})
        self.assertFalse(self.host.snapshots)

    def test_collision_and_invalid_names_do_not_mutate(self):
        self.host.snapshots[NAME] = int(NOW.timestamp())
        with self.assertRaisesRegex(maintenance.MaintenanceError, "already_exists"):
            self.tool.snapshot()
        for label in ("../outside", "a;echo", "", "UPPER"):
            with self.assertRaisesRegex(maintenance.MaintenanceError, "invalid_snapshot_label"):
                self.tool.snapshot(label)
        for name in ("cachepool/other@" + NAME, "devres-20260230T120000Z", "devres-20261029T120000Z/other"):
            with self.assertRaises(maintenance.MaintenanceError):
                self.tool.mark_verified(name)
        self.assertFalse(any("scale" in c for c in self.host.commands))

    def test_retention_removes_only_old_verified_and_preserves_latest_verified(self):
        old = "devres-20261001T120000Z"
        unverified = "devres-20260901T120000Z"
        self.host.snapshots = {old: int(NOW.timestamp()) - 28 * 86400,
                               unverified: int(NOW.timestamp()) - 58 * 86400,
                               NAME: int(NOW.timestamp())}
        self.state.value["verified"] = [old]
        result = self.tool.mark_verified(NAME)
        self.assertEqual(result["expired_verified_snapshots_removed"], 1)
        self.assertEqual(set(self.host.snapshots), {NAME, unverified})
        self.assertEqual(self.state.value["verified"], [NAME])
        self.host.snapshots = {old: int(NOW.timestamp()) - 28 * 86400}
        self.state.value["verified"] = []
        self.tool.mark_verified(old)
        self.assertIn(old, self.host.snapshots)

    def test_mark_verified_requires_complete_existing_snapshot(self):
        with self.assertRaisesRegex(maintenance.MaintenanceError, "complete_snapshot_not_found"):
            self.tool.mark_verified(NAME)
        self.assertFalse(self.state.saved)

    def test_guard_reasserts_interrupted_operation_fence(self):
        self.state.value["operation"] = {"backend": 1, "postgres": 1, "phase": "snapshotting"}
        self.assertTrue(self.tool.guard()["fenced"])
        self.assertEqual(self.host.replicas["backend"], 0)

    def test_failed_explicit_resume_keeps_backend_stopped_and_original_fence(self):
        self.state.value["fence"] = {"reason": "pool_low_free", "backend": 1}
        self.host.replicas["backend"] = 0
        self.host.fail = lambda args: "rollout" in args and "deployment/backend" in args
        with self.assertRaises(maintenance.MaintenanceError):
            self.tool.resume()
        self.assertEqual(self.host.replicas["backend"], 0)
        self.assertEqual(self.state.value["fence"], {"reason": "pool_low_free", "backend": 1})


class PrivateStateTests(unittest.TestCase):
    def test_atomic_state_roundtrip_and_private_files(self):
        with tempfile.TemporaryDirectory(prefix="devres-maintenance-test.", dir="/tmp") as root:
            state = maintenance.State(root)
            with state.locked():
                value = state.load()
                value["verified"].append(NAME)
                state.save(value)
                self.assertEqual(state.load(), value)
            self.assertEqual((Path(root) / "state.json").stat().st_mode & 0o777, 0o600)

    def test_symlink_state_and_lock_cannot_redirect_reads_or_writes(self):
        with tempfile.TemporaryDirectory(prefix="devres-maintenance-test.", dir="/tmp") as root:
            state = maintenance.State(root)
            outside = Path(root) / "outside"
            outside.write_text("private")
            (Path(root) / "state.json").symlink_to(outside)
            with self.assertRaises(OSError):
                state.load()
            (Path(root) / "maintenance.lock").symlink_to(outside)
            with self.assertRaises(OSError):
                with state.locked():
                    self.fail("lock followed symlink")
            self.assertEqual(outside.read_text(), "private")

    def test_group_writable_directory_refused(self):
        with tempfile.TemporaryDirectory(prefix="devres-maintenance-test.", dir="/tmp") as root:
            os.chmod(root, 0o770)
            with self.assertRaisesRegex(maintenance.MaintenanceError, "unsafe_state_directory"):
                with maintenance.State(root).locked():
                    self.fail("unsafe state accepted")

    def test_overlapping_operations_are_refused_by_host_flock(self):
        with tempfile.TemporaryDirectory(prefix="devres-maintenance-test.", dir="/tmp") as root:
            with maintenance.State(root).locked():
                with self.assertRaisesRegex(maintenance.MaintenanceError, "maintenance_busy"):
                    with maintenance.State(root).locked():
                        self.fail("concurrent maintenance accepted")


class TimerContractTests(unittest.TestCase):
    def test_busy_is_temporary_but_real_failures_remain_failures(self):
        import contextlib
        import io
        from unittest.mock import patch
        for code, expected in (("maintenance_busy", 75), ("unsafe_state_file", 1)):
            with patch.object(maintenance.sys, 'argv', ['maintenance.py', 'guard']), patch.object(maintenance.os, 'geteuid', return_value=0), patch.object(maintenance, 'State') as state, contextlib.redirect_stderr(io.StringIO()):
                state.return_value.locked.return_value.__enter__.side_effect = maintenance.MaintenanceError(code)
                self.assertEqual(maintenance.main(), expected)


if __name__ == "__main__":
    unittest.main()
