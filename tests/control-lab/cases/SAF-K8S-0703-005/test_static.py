"""Static-only checks; no kind, kubectl, Docker, or live API is invoked."""
import importlib.util
import ast
from pathlib import Path
import unittest

import yaml


HERE = Path(__file__).parent
SPEC = importlib.util.spec_from_file_location("saf_0703_005_bounds", HERE / "bounds.py")
bounds = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bounds)


class LocalWorkerModelTests(unittest.TestCase):
    def test_accepts_input_at_limit_and_rejects_over_limit_without_queue_use(self):
        worker = bounds.BoundedWorker(max_pending=2, max_input_bytes=16)
        self.assertTrue(worker.submit("at-limit", b"0123456789abcdef").accepted)
        decision = worker.submit("too-large", b"0123456789abcdefg")
        self.assertEqual((decision.accepted, decision.reason), (False, "input-too-large"))
        self.assertEqual(worker.pending_ids, ("at-limit",))

    def test_queue_capacity_returns_deterministic_backpressure_and_recovers(self):
        worker = bounds.BoundedWorker(max_pending=2, max_input_bytes=16)
        self.assertTrue(worker.submit("one", b"a").accepted)
        self.assertTrue(worker.submit("two", b"b").accepted)
        blocked = worker.submit("three", b"c")
        self.assertEqual((blocked.accepted, blocked.reason, blocked.retry_after_seconds),
                         (False, "queue-full", 1))
        self.assertEqual(worker.complete_next(), ("one", b"a"))
        self.assertTrue(worker.submit("three", b"c").accepted)
        self.assertEqual(worker.pending_ids, ("two", "three"))

    def test_rejects_duplicates_and_non_byte_payloads(self):
        worker = bounds.BoundedWorker()
        self.assertTrue(worker.submit("same", b"data").accepted)
        self.assertEqual(worker.submit("same", b"other").reason, "duplicate-job-id")
        with self.assertRaises(TypeError):
            worker.submit("text", "not bytes")


class KubernetesFixtureTests(unittest.TestCase):
    def test_future_live_case_is_valid_python_without_executing_it(self):
        source = (HERE / "case.py").read_text()
        ast.parse(source, filename=str(HERE / "case.py"))

    def test_limit_range_defaults_and_ceiling_are_fixed(self):
        manifest = yaml.safe_load((HERE / "limit-range.yaml").read_text())
        self.assertEqual(manifest["kind"], "LimitRange")
        container_limit = next(item for item in manifest["spec"]["limits"]
                               if item["type"] == "Container")
        self.assertEqual(container_limit["defaultRequest"]["memory"], "16Mi")
        self.assertEqual(container_limit["default"]["memory"], "32Mi")
        self.assertEqual(container_limit["max"]["memory"], "64Mi")
        pvc_limit = next(item for item in manifest["spec"]["limits"]
                         if item["type"] == "PersistentVolumeClaim")
        self.assertEqual(pvc_limit["max"]["storage"], "8Mi")

    def test_namespace_quota_caps_aggregate_pvc_requests(self):
        manifest = yaml.safe_load((HERE / "resource-quota.yaml").read_text())
        self.assertEqual(manifest["spec"]["hard"]["requests.storage"], "16Mi")
        self.assertEqual(manifest["spec"]["hard"]["persistentvolumeclaims"], "3")

    def test_owned_job_has_small_fixed_resources_and_job_level_deadline(self):
        job = yaml.safe_load((HERE / "deadline-job.yaml").read_text())
        self.assertEqual(job["kind"], "Job")
        self.assertEqual(job["spec"]["activeDeadlineSeconds"], 20)
        self.assertEqual(job["spec"]["backoffLimit"], 0)
        self.assertEqual(job["spec"]["parallelism"], 1)
        self.assertEqual(job["spec"]["template"]["spec"]["containers"][0]
                         ["resources"]["limits"]["memory"], "32Mi")
        self.assertEqual(job["spec"]["template"]["spec"]["containers"][0]
                         ["resources"]["requests"]["memory"], "16Mi")
        self.assertEqual(job["spec"]["template"]["spec"]["automountServiceAccountToken"], False)
        self.assertIn("@sha256:", job["spec"]["template"]["spec"]["containers"][0]["image"])
        self.assertEqual(job["metadata"]["labels"]["saf-k8s.example/control"],
                         "SAF-K8S-0703-005")


if __name__ == "__main__":
    unittest.main()
