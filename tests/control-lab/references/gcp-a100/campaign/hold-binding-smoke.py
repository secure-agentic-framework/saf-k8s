"""Run the exact hold-monitor join in Kind using synthetic framebuffer samples."""

import argparse
from contextlib import ExitStack, contextmanager
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
from unittest.mock import patch

NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
RUN = "a100ef12"
SOURCE = "saf-fixture-source"
NAMESPACE = "saf-hold-binding-fixture"
SERVER = """
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

class Metrics(BaseHTTPRequestHandler):
    def do_GET(self):
        value = high if Path("/scratch/allocated").exists() else baseline
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.end_headers()
        self.wfile.write(value.encode())

ThreadingHTTPServer(("0.0.0.0", 9400), Metrics).serve_forever()
"""


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def verify_source_checks(live):
    pod = {"metadata": {"uid": "fixture-workload"}, "spec": {"nodeName": "fixture-node"}}
    exporter = {"metadata": {"uid": "fixture-exporter", "name": "fixture-exporter"},
                "status": {"podIP": "192.0.2.10"}}
    profile = {"hardware": {"model": "fixture-A100", "driver": "fixture-reviewed-driver"},
               "kubernetes": {"node_uid_sha256": live.sha("fixture-node")},
               "exporter": {"pod_uid_sha256": live.sha("fixture-exporter"),
                            "image": "fixture-reviewed-image", "image_id": "fixture-reviewed-image-id"}}
    @contextmanager
    def provided(driver, uid, image_id):
        live_exporter = {**exporter, "metadata": {**exporter["metadata"], "uid": uid}}
        with patch.object(live, "ensure_pod_profile", return_value=(pod, {}, {})), \
                patch.object(live, "nvidia_device", return_value=(pod, "fixture-device", "fixture-A100", driver)), \
                patch.object(live, "find_exporter", return_value=(
                    live_exporter, {"image": "fixture-reviewed-image"}, {"imageID": image_id})), \
                patch.object(live, "kube_json", return_value={"metadata": {"uid": "fixture-node"}}):
            yield

    def capture():
        return live.approved_source("fixture-kubectl", None, None, profile, "fixture-selector")

    with provided("fixture-reviewed-driver", "fixture-exporter", "fixture-reviewed-image-id"):
        require(capture()["device_id"] == "fixture-device", "The exact reviewed source did not pass")
    for values in (("different-driver", "fixture-exporter", "fixture-reviewed-image-id"),
                   ("fixture-reviewed-driver", "different-exporter", "fixture-reviewed-image-id"),
                   ("fixture-reviewed-driver", "fixture-exporter", "different-image-id")):
        with provided(*values):
            try:
                capture()
            except live.Blocked:
                continue
            raise RuntimeError("Driver, exporter UID or exporter image drift was accepted")



def smoke(live, kubeconfig, port):
    gate = live.gate
    labels = {"namespace": live.WORKLOAD_NS, "pod": live.WORKLOAD_POD, "container": live.WORKLOAD_CONTAINER,
              "UUID": "GPU-fixture-only", "pod_uid": "00000000-0000-0000-0000-00000000001a"}
    selectors = ",".join(f"{key}={json.dumps(value)}" for key, value in labels.items())
    baseline, high = [f'{live.METRIC}{{{selectors}}} {number}\n' for number in (0, 556)]
    server = f"baseline = {baseline!r}\nhigh = {high!r}\n" + SERVER
    profile = {"hardware": {"gpu_uuid_sha256": live.sha(labels["UUID"])},
               "workload": {"uid_sha256": live.sha(labels["pod_uid"])},
               "kubernetes": {"node_uid_sha256": live.sha("fixture-node")},
               "exporter": {"pod_uid_sha256": live.sha("fixture-exporter")}}

    def request(*args, obj=None, allow_failure=False, timeout=20):
        data = json.dumps(obj).encode() if obj is not None else None
        result = live.kube("kubectl", kubeconfig, *args, input_bytes=data, timeout=timeout,
                           allow_failure=allow_failure, stderr_pipe=True)
        return subprocess.CompletedProcess(args, result.returncode, result.stdout.decode(), result.stderr.decode())

    with gate.OwnedResources(request) as owned, ExitStack() as processes:
        owned.create({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": NAMESPACE}})
        owned.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": SOURCE, "namespace": NAMESPACE},
                      "immutable": True, "data": {"exporter.py": server}})
        pod, = live.pod_resource(SOURCE, live.PYTHON_IMAGE, ["python", "-B", "/fixture/exporter.py"], SOURCE,
                                 "exporter", 9400, readiness_path="/metrics", service=False)
        pod["metadata"]["namespace"] = NAMESPACE
        owned.create(pod)
        request("-n", NAMESPACE, "wait", "--for=condition=Ready", "pod/"+SOURCE, "--timeout=80s", timeout=85)
        ip = request("-n", NAMESPACE, "get", "pod", SOURCE, "-o", "jsonpath={.status.podIP}").stdout.strip()
        prefix = live.deploy_monitors("kubectl", kubeconfig, owned, RUN, ip, profile, 128)
        for name, local, remote in (("prometheus", port, 9090), ("receiver", port+1, 18082)):
            proxy = live.start_forward("kubectl", kubeconfig, prefix, f"{prefix}-{name}", local, remote)
            processes.callback(live.stop_forward, proxy)
        query = selectors + f',job="{live.JOB}",instance="{ip}:9400"'
        source_labels = {**labels, "job": live.JOB, "instance": f"{ip}:9400",
                         "exporter_uid_ref": profile["exporter"]["pod_uid_sha256"],
                         "node_uid_ref": profile["kubernetes"]["node_uid_sha256"]}
        b = live.wait_for(lambda: live.query_metric(port, query), seconds=40)
        require(b and b["value_mib"] == 0, "Synthetic framebuffer baseline missing")
        require(live.get_json(f"http://127.0.0.1:{port+1}/events") == [], "Receiver was not initially empty")
        earliest = time.time()
        request("-n", NAMESPACE, "exec", f"pod/{SOURCE}", "--", "touch", "/scratch/allocated")

        def captured():
            sample = live.query_metric(port, query)
            firing = live.alert_state(port)
            events = live.get_json(f"http://127.0.0.1:{port+1}/events")
            if sample and sample["value_mib"] == 556 and firing and len(firing) == 1 and len(events) == 1:
                return sample, firing[0], events[0]
            return None

        actual = live.wait_for(captured, seconds=55)
        require(actual, "Synthetic high framebuffer alert was not delivered")
        sample, firing, event = actual
        alerts = live.manager_alerts(request, prefix)
        require(live.present_sample(sample, source_labels, earliest), "Expected fresh exact fixture source labels")
        require(live.bound_delivery(event, firing, alerts, labels, RUN, 128, earliest),
                "Exact Alertmanager delivery and Prometheus firing alert did not match")
        wrong_event = dict(event, capture_ref="another-run")
        require(not live.bound_delivery(wrong_event, firing, alerts, labels, RUN, 128, earliest),
                "Wrong capture reference unexpectedly accepted")
        wrong_event = dict(event, fingerprint_sha256="0" * 64)
        require(not live.bound_delivery(wrong_event, firing, alerts, labels, RUN, 128, earliest),
                "Wrong Alertmanager fingerprint unexpectedly accepted")
        wrong_source = dict(sample, labels={**sample["labels"], "exporter_uid_ref": "0" * 64})
        require(not live.present_sample(wrong_source, source_labels, earliest), "Wrong exporter unexpectedly accepted")
        wrong_source = dict(sample, timestamp=earliest - 1)
        require(not live.present_sample(wrong_source, source_labels, earliest), "Pre-trigger sample unexpectedly accepted")
    return {"schema": "saf-a100-hold-synthetic-monitor-v1", "status": "passed",
            "scope": "Synthetic metrics on fresh Kind with real Prometheus and Alertmanager",
            "baseline_zero_and_receiver_empty": True, "current_exact_threshold_alert_bound_to_receiver": True,
            "wrong_capture_and_fingerprint_denied": True, "wrong_exporter_and_pretrigger_sample_denied": True,
            "monitor_resources_removed": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True, help="Verified staged code directory")
    parser.add_argument("--output", type=Path, required=True, help="New receipt path")
    parser.add_argument("--port", default=19540, type=int)
    args = parser.parse_args()
    require(args.output.is_absolute() and not args.output.exists(), "Expected a new absolute evidence path")
    sys.path.insert(0, str(args.bundle.resolve()))
    import live_catch_hold as live

    verify_source_checks(live)
    cluster = "saf-hold-binding-" + secrets.token_hex(4)
    env = {**os.environ, "DOCKER_CONTEXT": "desktop-linux", "KIND_EXPERIMENTAL_PROVIDER": "docker"}
    with TemporaryDirectory(prefix=cluster) as temp:
        kubeconfig = Path(temp) / "kubeconfig"
        try:
            subprocess.run(["kind", "create", "cluster", "--name", cluster, "--image", NODE_IMAGE,
                            "--kubeconfig", str(kubeconfig), "--wait", "90s"], env=env, check=True, timeout=120)
            output = smoke(live, kubeconfig, args.port)
        finally:
            subprocess.run(["kind", "delete", "cluster", "--name", cluster], env=env, check=True, timeout=60)
    live.write_checkpoint(args.output, {**output, "cluster_deleted": True, "live_source_drift_cases_rejected_offline": 3})
    print(json.dumps(output, sort_keys=True))


if __name__ == "__main__":
    main()
