"""Exercise terminal status and cleanup reporting without starting a cluster."""

import contextlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import lab


CONTROL = "SAF-K8S-0000-001"


class LabStatusTest(unittest.TestCase):
    def run_case(self, mode, *, deletion_fails):
        def run_fixture(instance):
            if mode == "assertion_failure":
                instance.check("red", "fixture check failed", False, {})
            if mode == "handled_assertion_failure":
                try:
                    instance.check("red", "handled fixture check failed", False, {})
                except lab.CheckFailed:
                    pass
            else:
                instance.check("red", "comparison", True, {})
            instance.check("green", "matched comparison", True, {})
            if mode != "missing_phase":
                instance.check("positive", "permitted operation", True, {})

        def command(*args, **kwargs):
            output = ""
            if args[:3] == ("docker", "context", "inspect"):
                output = "unix:///fixture/docker.sock"
            if args[0] == "kubectl" and "version" in args:
                output = json.dumps({"serverVersion": {"gitVersion": "v1.36.1"}})
            if args[:3] == ("kind", "delete", "cluster") and deletion_fails:
                raise lab.InfrastructureError("fixture deletion failed")
            return SimpleNamespace(stdout=output, stderr="", returncode=0)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            case = SimpleNamespace(SCOPE="local status fixture", __file__=str(root / "case.py"),
                                   run=run_fixture)
            index = {"revision": "fixture", "sha256": "0" * 64,
                     "controls": {CONTROL: {"sha256": "1" * 64}}}
            output = io.StringIO()
            with (patch.object(lab, "ROOT", root), patch.object(lab.Lab, "command", new=staticmethod(command)),
                  contextlib.redirect_stdout(output)):
                code = lab.run(CONTROL, case, index, "fixture")
            receipt, = (root / "evidence" / CONTROL).glob("*/result.json")
            return code, json.loads(receipt.read_text()), output.getvalue()

    def test_terminal_status_and_cleanup(self):
        checks = [
            ("success", False, 0, "passed", "deleted", None),
            ("assertion_failure", False, 1, "failed", "deleted", "fixture check failed"),
            ("missing_phase", False, 3, "blocked", "deleted",
             "A passing case must record red, green and positive observations"),
            ("handled_assertion_failure", False, 1, "failed", "deleted",
             "The case returned with an unmatched or invalid check"),
            ("success", True, 3, "blocked", "failed", "Cluster cleanup failed after case checks passed"),
            ("assertion_failure", True, 3, "failed", "failed", "fixture check failed"),
        ]
        for mode, deletion_fails, exit_code, status, cleanup, error in checks:
            with self.subTest(mode=mode, deletion_fails=deletion_fails):
                actual_code, receipt, output = self.run_case(mode, deletion_fails=deletion_fails)
                self.assertEqual(actual_code, exit_code)
                self.assertEqual(receipt["status"], status)
                self.assertEqual(receipt["cleanup"], cleanup)
                self.assertEqual(receipt.get("error"), error)
                self.assertEqual(receipt.get("cleanup_error"), "fixture deletion failed" if deletion_fails else None)
                self.assertIn(f"{status.upper()}  {CONTROL}", output.splitlines())
                if status != "passed":
                    self.assertNotIn(f"PASSED  {CONTROL}", output.splitlines())


if __name__ == "__main__":
    unittest.main()
