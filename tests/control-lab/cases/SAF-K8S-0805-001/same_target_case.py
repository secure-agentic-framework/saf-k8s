"""Exercise the shared same-exporter contract using deliberately synthetic telemetry."""

from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = spec_from_file_location("saf_visibility_transition", HERE / "visibility_transition.py")
transition = module_from_spec(spec)
spec.loader.exec_module(transition)

SOURCE_LABELS = {"namespace": "owned-visibility", "pod": "sample-workload", "container": "zero",
                 "pod_uid": "1a057cec-3d36-4519-b46e-46fb08f7050f", "UUID": "GPU-fixture-only"}
SOURCE = """
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Fixture(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/metrics":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.end_headers()
        self.wfile.write(METRIC)


ThreadingHTTPServer(("0.0.0.0", 9400), Fixture).serve_forever()
"""


class IsolatedCase:
    namespace = "saf-same-target-visibility"

    def __init__(self, lab):
        self.lab = lab

    def kubectl(self, *args, timeout=45, **kwargs):
        return self.lab.command("kubectl", "--kubeconfig", str(self.lab.kubeconfig),
                                "--context", f"kind-{self.lab.cluster}", "--namespace", self.namespace,
                                f"--request-timeout={timeout - 5}s", *args, timeout=timeout, **kwargs)

    def create(self, manifest):
        self.kubectl("create", "-f", "-", payload=json.dumps(manifest))


def run(lab):
    case = IsolatedCase(lab)
    directory = lab.evidence / "same-target-visibility"
    directory.mkdir(mode=0o700)
    sample = ",".join(f"{key}={json.dumps(value)}" for key, value in SOURCE_LABELS.items())
    metric = f'{transition.METRIC}{{{sample}}} 0\n'
    fixture = "same-target-exporter"
    asset = fixture + "-config"
    case.kubectl("create", "namespace", case.namespace)
    case.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": asset},
                 "immutable": True, "data": {"server.py": f"METRIC = {metric.encode()!r}\n" + SOURCE}})
    transition.route.create_pod(case, fixture, transition.route.PYTHON, ["python", "-B", "/fixture/server.py"],
                                9400, config_name=asset, readiness="/metrics")
    address = case.kubectl("get", "pod", fixture, "-o", "jsonpath={.status.podIP}").stdout
    source = (address + ":9400", SOURCE_LABELS, "e" * 64, 0)
    try:
        result = transition.exercise(case, directory, source, lambda: source)
    except transition.VisibilityBlocked as exc:
        lab.block(str(exc))
    transition.checkpoint(lab.evidence, "same-target-visibility.json", {
        "schema": "saf-0805-001-same-target-visibility-v1", "status": "passed",
        "source": "synthetic_http_workload_metrics", **result})
    lab.check("same-target-visibility",
              "An exact source in a case-owned monitor fails the scrape and becomes absent in separate jobs while the healthy job retains measured zero and both alerts route",
              result["failed_target_http_404"] and result["vanished_target_absent"]
              and result["healthy_measured_zero"]["framebuffer_mib"] == 0 and len(result["route_receipts"]) == 2,
              {"failed_and_absent_jobs_were_previously_healthy_for_the_exact_same_target": True,
               "failed_job_returns_404_and_keeps_up_zero": True, "absent_job_has_no_up_or_metric_series": True,
               "healthy_job_retains_a_fresh_measured_zero_with_same_source_identity": True,
               "two_exact_alerts_reached_case_receiver": True, "telemetry_fixture_is_synthetic": True,
               "evidence": "same-target-visibility.json"})
