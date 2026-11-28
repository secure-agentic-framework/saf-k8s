"""Exercise the guest preparation transaction using simulated command responses."""

from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from unittest import TestCase, main
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "candidate"))
import mig_setup as setup
from mig_inventory import MigPrecondition, RESOURCE

GPU = "GPU-10000000-0000-0000-0000-000000000000"
MIG_A = "MIG-20000000-0000-0000-0000-000000000001"
MIG_B = "MIG-20000000-0000-0000-0000-000000000002"
NODE = "saf-a100-0000000001"
BOOT = "30000000-0000-0000-0000-000000000001"
SOURCE = b"deterministic fixture input"
SHA = sha256(SOURCE).hexdigest()
PROFILE = "NVIDIA A100-SXM4-40GB, 580.178.04, Enabled, Enabled"
PLUGIN = {"kind": "DaemonSet", "apiVersion": "apps/v1",
          "metadata": {"name": setup.PLUGIN, "namespace": setup.NAMESPACE},
          "spec": {"template": {"spec": {"runtimeClassName": "nvidia"}}}}


class Fixture:
    def __init__(self):
        self.installed = False
        self.plugin = None
        self.partial = False
        self.driver_creation_requested = 0
        self.plugin_creation_requested = 0
        self.interruption = None
        self.empty_status = 6
        self.free_slots = 7
        self.node = {"metadata": {"name": NODE, "uid": "fixture-node-uid"},
                     "status": {"nodeInfo": {"bootID": BOOT}, "allocatable": {RESOURCE: "2"},
                                "capacity": {RESOURCE: "2", "nvidia.com/gpu": "0"}}}

    def command(self, *args, check=True, **kwargs):
        code, stderr = 0, ""
        if args[1].startswith("--query-gpu="):
            out = PROFILE
        elif args[1:] == ("-L",):
            out = f"GPU 0: A100-SXM4-40GB (UUID: {GPU})\n"
            if self.installed:
                out += f"  MIG 1g.5gb  Device  0: (UUID: {MIG_A})\n"
                out += f"  MIG 1g.5gb  Device  1: (UUID: {MIG_B})\n"
        elif "-lgi" in args:
            if self.installed or self.partial:
                out = "GPU instances:\n|  0 MIG 1g.5gb  19  7 0:1  |\n"
                if self.installed:
                    out += "|  0 MIG 1g.5gb  19  8 1:1  |\n"
            else:
                code, out = self.empty_status, "No GPU instances found: Not Found\n"
        elif "-lci" in args:
            out = "Compute instances:\n| 0  7 MIG 1g.5gb  0  0 |\n| 0  8 MIG 1c.1g.5gb  0  0 |\n"
        elif "-lgip" in args:
            out = f"GPU instance profiles:\n| 0 MIG 1g.5gb 19 {self.free_slots}/7 4.75 No 14 0 0 |\n"
        elif "-cgi" in args:
            self.driver_creation_requested += 1
            self.installed = True
            if self.interruption == "driver":
                raise subprocess.TimeoutExpired(args, 1)
            out = ""
        else:
            raise AssertionError(f"Unexpected command: {args}")
        if check and code:
            raise RuntimeError(f"Fixture command returned {code}: {stderr}")
        return subprocess.CompletedProcess(args, code, out, stderr)

    def kubectl(self, *args, data=None, **kwargs):
        if args[:2] == ("get", "nodes"):
            result = {"items": [self.node]}
        elif args[:2] == ("get", "node"):
            result = self.node
        elif "pods" in args:
            return ""
        elif "daemonset" in args:
            return json.dumps(self.plugin) if self.plugin else ""
        elif "set" in args:
            if data.encode() != SOURCE:
                raise AssertionError("Unexpected fixture manifest bytes")
            result = PLUGIN
        elif args[0] == "create":
            result = json.loads(data)
            result["metadata"]["uid"] = "fixture-plugin-uid"
            result["spec"]["revisionHistoryLimit"] = 10
            if "--dry-run=server" not in args:
                self.plugin_creation_requested += 1
                self.plugin = result
                if self.interruption == "plugin":
                    raise subprocess.TimeoutExpired(args, 1)
        elif "rollout" in args:
            return "fixture rollout ready"
        else:
            raise AssertionError(f"Unexpected kubectl arguments: {args}")
        return json.dumps(result)


class PreparationTest(TestCase):
    def setUp(self):
        self.fixture = Fixture()
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        (self.root / setup.SOURCE_NAME).write_bytes(SOURCE)
        for target, value in (("SOURCE_SHA", SHA), ("command", self.fixture.command), ("k", self.fixture.kubectl)):
            mocked = patch.object(setup, target, value)
            mocked.start()
            self.addCleanup(mocked.stop)

    def run_attempt(self, name="first"):
        receipt = self.root / (name + ".json")
        setup.prepare(self.root, receipt, NODE, BOOT)
        return json.loads(receipt.read_text())

    def assert_no_mutations(self):
        self.assertEqual((self.fixture.driver_creation_requested, self.fixture.plugin_creation_requested), (0, 0))
        self.assertFalse((self.root / setup.RESERVATION).exists())

    def test_cold_setup_and_retry_do_not_repeat_mutations(self):
        first = self.run_attempt()
        second = self.run_attempt("retry")
        self.assertTrue(first["slice_creation_requested"])
        self.assertFalse(second["slice_creation_requested"])
        self.assertTrue(second["existing_plugin_reused"])
        self.assertEqual(first["geometry_ref"], second["geometry_ref"])
        self.assertEqual((self.fixture.driver_creation_requested, self.fixture.plugin_creation_requested), (1, 1))

    def test_reconcile_creation_that_completed_before_response_was_lost(self):
        self.fixture.interruption = "driver"
        with self.assertRaises(subprocess.TimeoutExpired):
            self.run_attempt()
        self.fixture.interruption = None
        retry = self.run_attempt("retry")
        self.assertTrue(retry["reservation_reused"])
        self.assertFalse(retry["slice_creation_requested"])
        self.assertEqual((self.fixture.driver_creation_requested, self.fixture.plugin_creation_requested), (1, 1))

    def test_reconcile_plugin_creation_that_completed_before_response_was_lost(self):
        self.fixture.interruption = "plugin"
        with self.assertRaises(subprocess.TimeoutExpired):
            self.run_attempt()
        self.fixture.interruption = None
        self.assertTrue(self.run_attempt("retry")["existing_plugin_reused"])
        self.assertEqual((self.fixture.driver_creation_requested, self.fixture.plugin_creation_requested), (1, 1))

    def test_reject_partial_geometry(self):
        self.fixture.partial = True
        with self.assertRaisesRegex(MigPrecondition, "partial GPU instances"):
            self.run_attempt()
        self.assert_no_mutations()

    def test_never_adopt_unreserved_complete_geometry(self):
        self.fixture.installed = True
        with self.assertRaisesRegex(MigPrecondition, "no matching reservation"):
            self.run_attempt()
        self.assert_no_mutations()

    def test_reject_return_code_for_permission_denied_even_with_empty_text(self):
        self.fixture.empty_status = 4
        with self.assertRaisesRegex(MigPrecondition, "inventory query failed"):
            self.run_attempt()
        self.assert_no_mutations()

    def test_reject_empty_report_without_full_free_capacity(self):
        self.fixture.free_slots = 6
        with self.assertRaisesRegex(MigPrecondition, "all-placements-free readback"):
            self.run_attempt()
        self.assert_no_mutations()

    def test_reject_unreserved_plugin(self):
        self.fixture.plugin = deepcopy(PLUGIN)
        with self.assertRaisesRegex(MigPrecondition, "no matching reservation"):
            self.run_attempt()
        self.assert_no_mutations()

    def test_reject_drifted_reserved_plugin_without_modifying_it(self):
        self.run_attempt()
        self.fixture.plugin["spec"]["template"]["spec"]["runtimeClassName"] = "changed"
        with self.assertRaisesRegex(MigPrecondition, "differs from the reserved"):
            self.run_attempt("retry")
        self.assertEqual((self.fixture.driver_creation_requested, self.fixture.plugin_creation_requested), (1, 1))


class ModeRequestTest(TestCase):
    def execute(self, profile, mode):
        request = Path(__file__).resolve().parents[1] / "candidate" / "request-mig-mode.sh"
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            trace = root / "trace"
            for name, cmd in {
                "id": "echo 0",
                "hostname": f"echo {NODE}",
                "fuser": "exit 99",
                "nvidia-smi": (
                    'case "$1" in\n'
                    '  --query-gpu=name,driver_version) echo "$MIG_FIXTURE_PROFILE";;\n'
                    '  --query-gpu=mig.mode.current,mig.mode.pending) echo "$MIG_FIXTURE_MODE";;\n'
                    '  *) echo unexpected >>"$MIG_FIXTURE_TRACE"; exit 99;;\n'
                    'esac'),
            }.items():
                script = root / name
                script.write_text("#!/bin/sh\n" + cmd + "\n")
                script.chmod(0o700)
            result = subprocess.run(["bash", str(request)], capture_output=True, text=True, timeout=8,
                                    env={**os.environ, "PATH": f"{tmp}:{os.environ['PATH']}",
                                         "MIG_FIXTURE_PROFILE": profile, "MIG_FIXTURE_MODE": mode,
                                         "MIG_FIXTURE_TRACE": str(trace)})
            self.assertFalse(trace.exists())
            return result

    def test_preserve_already_active_mig(self):
        result = self.execute("NVIDIA A100-SXM4-40GB, 580.178.04", "Enabled, Enabled")
        self.assertEqual(result.returncode, 0)
        self.assertIn("preserve the existing", result.stdout)

    def test_preserve_pending_mig_request(self):
        result = self.execute("NVIDIA A100-SXM4-40GB, 580.178.04", "Disabled, Enabled")
        self.assertEqual(result.returncode, 4)
        self.assertIn("preserve the request", result.stdout)

    def test_reject_unapproved_model_before_writes(self):
        result = self.execute("NVIDIA A100-SXM4-80GB, 580.178.04", "Disabled, Disabled")
        self.assertEqual(result.returncode, 1)


if __name__ == "__main__":
    main()
